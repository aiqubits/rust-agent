use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    fmt,
    fs::{File, OpenOptions},
    io::{self, Write as _},
    mem::offset_of,
    os::unix::process::ExitStatusExt as _,
    path::Path,
    process::{Command, Stdio},
};

use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, LandlockStatus, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus,
};
use nix::{
    sys::resource::{Resource, getrlimit, rlim_t, setrlimit},
    sys::signal::{Signal, raise},
    unistd::{getpgrp, getpid},
};
use rust_agent_core::Digest;
use rust_agent_policy::process::{EnforcementPrimitives, FilesystemAccess, NetworkAccess};
use seccompy::{
    Filter, FilterAction, FilterArgs, FilterFlags,
    bpf::{
        Architecture, BpfInstruction,
        instruction::Instruction,
        primitive::{AddressingMode, Condition, Operand, ReturnValue, Size},
    },
    set_filter, set_no_new_privileges,
};

use super::protocol::{SetupAcknowledgement, encode_setup_header};
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

#[derive(Debug)]
pub(super) enum LauncherError {
    Protocol,
    ResourceLimit,
    ProcessGroup,
    Landlock,
    Seccomp,
    Report,
    Exec(io::Error),
}

impl fmt::Display for LauncherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Protocol => "launcher protocol is invalid",
            Self::ResourceLimit => "resource limits could not be applied",
            Self::ProcessGroup => "launcher is not the process-group leader",
            Self::Landlock => "Landlock policy could not be fully enforced",
            Self::Seccomp => "seccomp policy could not be fully enforced",
            Self::Report => "setup acknowledgement could not be written",
            Self::Exec(_) => "target executable could not be started",
        })?;
        if let Self::Exec(error) = self {
            write!(formatter, ": {error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for LauncherError {}

#[derive(Debug)]
struct Request {
    policy_digest: Digest,
    required_primitives: EnforcementPrimitives,
    filesystem: FilesystemAccess,
    network: NetworkAccess,
    max_processes: u64,
    max_memory_bytes: u64,
    terminal_fd: Option<i32>,
    runtime_read_paths: Vec<String>,
    allowed_executables: Vec<String>,
    target: String,
    arguments: Vec<String>,
}

pub(super) fn run() -> Result<(), LauncherError> {
    let request = parse(env::args_os().skip(1))?;
    let terminal = open_terminal(request.terminal_fd)?;
    apply_resource_limits(&request)?;
    if getpid() != getpgrp() {
        return Err(LauncherError::ProcessGroup);
    }
    if let Some(terminal) = &terminal {
        rustix::process::ioctl_tiocsctty(terminal).map_err(|_| LauncherError::ProcessGroup)?;
    }
    set_no_new_privileges().map_err(|_| LauncherError::Seccomp)?;
    apply_landlock(&request)?;
    apply_seccomp(request.network)?;
    let applied_primitives = applied_primitives(request.network);
    if !applied_primitives.contains(request.required_primitives) {
        return Err(LauncherError::Protocol);
    }
    let interactive = terminal.is_some();
    let mut command = Command::new(&request.target);
    command.args(&request.arguments);
    if let Some(terminal) = terminal {
        command
            .stdin(Stdio::from(
                terminal.try_clone().map_err(LauncherError::Exec)?,
            ))
            .stdout(Stdio::from(
                terminal.try_clone().map_err(LauncherError::Exec)?,
            ))
            .stderr(Stdio::from(terminal));
    } else {
        command
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
    }
    let mut target = command.spawn().map_err(LauncherError::Exec)?;

    let header = encode_setup_header(SetupAcknowledgement {
        policy_digest: request.policy_digest,
        applied_primitives,
    });
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&header)
        .and_then(|()| stdout.flush())
        .map_err(|_| LauncherError::Report)?;
    drop(stdout);
    if interactive && target.stdout.is_some() {
        return Err(LauncherError::Protocol);
    }
    if !interactive {
        let mut target_stdout =
            target
                .stdout
                .take()
                .ok_or(LauncherError::Exec(io::Error::other(
                    "target stdout pipe was unavailable",
                )))?;
        io::copy(&mut target_stdout, &mut io::stdout()).map_err(|_| LauncherError::Report)?;
    }
    let status = target.wait().map_err(LauncherError::Exec)?;
    if let Some(code) = status.code() {
        std::process::exit(code);
    }
    if let Some(signal) = status
        .signal()
        .and_then(|signal| Signal::try_from(signal).ok())
    {
        raise(signal).map_err(|_| LauncherError::Exec(io::Error::other("signal relay failed")))?;
    }
    Err(LauncherError::Exec(io::Error::other(
        "target exit status was unavailable",
    )))
}

fn open_terminal(descriptor: Option<i32>) -> Result<Option<File>, LauncherError> {
    descriptor
        .map(|descriptor| {
            if descriptor < 3 {
                return Err(LauncherError::Protocol);
            }
            let terminal = OpenOptions::new()
                .read(true)
                .write(true)
                .open(format!("/proc/self/fd/{descriptor}"))
                .map_err(|_| LauncherError::Protocol)?;
            rustix::termios::tcgetwinsize(&terminal).map_err(|_| LauncherError::Protocol)?;
            Ok(terminal)
        })
        .transpose()
}

fn parse(arguments: impl Iterator<Item = OsString>) -> Result<Request, LauncherError> {
    let arguments = arguments
        .map(|value| value.into_string().map_err(|_| LauncherError::Protocol))
        .collect::<Result<Vec<_>, _>>()?;
    let mut cursor = 0_usize;
    let policy_digest = Digest::from_lower_hex(value(&arguments, &mut cursor, "--policy-digest")?)
        .map_err(|_| LauncherError::Protocol)?;
    let required_primitives = value(&arguments, &mut cursor, "--required-primitives")?
        .parse::<u16>()
        .ok()
        .and_then(EnforcementPrimitives::from_bits)
        .ok_or(LauncherError::Protocol)?;
    let filesystem = match value(&arguments, &mut cursor, "--filesystem")? {
        "none" => FilesystemAccess::None,
        "read-only" => FilesystemAccess::ReadOnly,
        "read-write" => FilesystemAccess::ReadWrite,
        _ => return Err(LauncherError::Protocol),
    };
    let network = match value(&arguments, &mut cursor, "--network")? {
        "deny" => NetworkAccess::Deny,
        "outbound" => NetworkAccess::Outbound,
        _ => return Err(LauncherError::Protocol),
    };
    let max_processes = value(&arguments, &mut cursor, "--max-processes")?
        .parse()
        .map_err(|_| LauncherError::Protocol)?;
    let max_memory_bytes = value(&arguments, &mut cursor, "--max-memory-bytes")?
        .parse()
        .map_err(|_| LauncherError::Protocol)?;
    if max_processes == 0 || max_memory_bytes == 0 {
        return Err(LauncherError::Protocol);
    }
    let terminal_fd = if arguments
        .get(cursor)
        .is_some_and(|value| value == "--terminal-fd")
    {
        let descriptor = value(&arguments, &mut cursor, "--terminal-fd")?
            .parse()
            .map_err(|_| LauncherError::Protocol)?;
        if descriptor < 3 {
            return Err(LauncherError::Protocol);
        }
        Some(descriptor)
    } else {
        None
    };
    let mut runtime_read_paths = Vec::new();
    while arguments
        .get(cursor)
        .is_some_and(|value| value == "--runtime-read")
    {
        cursor += 1;
        runtime_read_paths.push(
            arguments
                .get(cursor)
                .ok_or(LauncherError::Protocol)?
                .clone(),
        );
        cursor += 1;
    }
    let mut allowed_executables = Vec::new();
    while arguments
        .get(cursor)
        .is_some_and(|value| value == "--allow-exec")
    {
        cursor += 1;
        allowed_executables.push(
            arguments
                .get(cursor)
                .ok_or(LauncherError::Protocol)?
                .clone(),
        );
        cursor += 1;
    }
    if arguments.get(cursor).is_none_or(|value| value != "--") {
        return Err(LauncherError::Protocol);
    }
    cursor += 1;
    let target = arguments
        .get(cursor)
        .ok_or(LauncherError::Protocol)?
        .clone();
    cursor += 1;
    if target != super::SANDBOX_TARGET
        || !runtime_read_paths.windows(2).all(|pair| pair[0] < pair[1])
        || !allowed_executables.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(LauncherError::Protocol);
    }
    Ok(Request {
        policy_digest,
        required_primitives,
        filesystem,
        network,
        max_processes,
        max_memory_bytes,
        terminal_fd,
        runtime_read_paths,
        allowed_executables,
        target,
        arguments: arguments[cursor..].to_vec(),
    })
}

fn value<'a>(
    arguments: &'a [String],
    cursor: &mut usize,
    expected: &str,
) -> Result<&'a str, LauncherError> {
    if arguments.get(*cursor).is_none_or(|value| value != expected) {
        return Err(LauncherError::Protocol);
    }
    *cursor += 1;
    let value = arguments.get(*cursor).ok_or(LauncherError::Protocol)?;
    *cursor += 1;
    Ok(value)
}

fn apply_resource_limits(request: &Request) -> Result<(), LauncherError> {
    set_narrow_limit(
        Resource::RLIMIT_NPROC,
        request
            .max_processes
            .checked_add(1)
            .ok_or(LauncherError::ResourceLimit)?,
    )?;
    set_narrow_limit(Resource::RLIMIT_AS, request.max_memory_bytes)?;
    setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(|_| LauncherError::ResourceLimit)
}

fn set_narrow_limit(resource: Resource, requested: u64) -> Result<(), LauncherError> {
    let (_, current_hard) = getrlimit(resource).map_err(|_| LauncherError::ResourceLimit)?;
    let requested = rlim_t::try_from(requested).map_err(|_| LauncherError::ResourceLimit)?;
    let effective = requested.min(current_hard);
    if effective == 0 {
        return Err(LauncherError::ResourceLimit);
    }
    setrlimit(resource, effective, effective).map_err(|_| LauncherError::ResourceLimit)
}

fn apply_landlock(request: &Request) -> Result<(), LauncherError> {
    let abi = if request.filesystem == FilesystemAccess::ReadWrite {
        ABI::V2
    } else {
        ABI::V1
    };
    let read = AccessFs::from_read(abi) & !AccessFs::Execute;
    let writable = AccessFs::from_all(abi) & !AccessFs::Execute;
    let executable = (AccessFs::from_file(abi) & read) | AccessFs::Execute;
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|_| LauncherError::Landlock)?
        .create()
        .map_err(|_| LauncherError::Landlock)?;

    for path in &request.runtime_read_paths {
        let metadata = std::fs::metadata(path).map_err(|_| LauncherError::Landlock)?;
        let access = if metadata.is_dir() {
            read
        } else if metadata.is_file() {
            AccessFs::from_file(abi) & read
        } else {
            return Err(LauncherError::Landlock);
        };
        ruleset = ruleset
            .add_rule(PathBeneath::new(
                PathFd::new(path).map_err(|_| LauncherError::Landlock)?,
                access,
            ))
            .map_err(|_| LauncherError::Landlock)?;
    }
    match request.filesystem {
        FilesystemAccess::None => {}
        FilesystemAccess::ReadOnly => {
            ruleset = ruleset
                .add_rule(PathBeneath::new(
                    PathFd::new(super::SANDBOX_WORKSPACE).map_err(|_| LauncherError::Landlock)?,
                    read,
                ))
                .map_err(|_| LauncherError::Landlock)?;
        }
        FilesystemAccess::ReadWrite => {
            ruleset = ruleset
                .add_rule(PathBeneath::new(
                    PathFd::new(super::SANDBOX_WORKSPACE).map_err(|_| LauncherError::Landlock)?,
                    writable,
                ))
                .map_err(|_| LauncherError::Landlock)?;
        }
    }
    let executables = request
        .allowed_executables
        .iter()
        .map(String::as_str)
        .chain([request.target.as_str()])
        .collect::<BTreeSet<_>>();
    for path in executables {
        if !Path::new(path).is_file() {
            return Err(LauncherError::Landlock);
        }
        ruleset = ruleset
            .add_rule(PathBeneath::new(
                PathFd::new(path).map_err(|_| LauncherError::Landlock)?,
                executable,
            ))
            .map_err(|_| LauncherError::Landlock)?;
    }
    let status = ruleset
        .set_compatibility(CompatLevel::HardRequirement)
        .restrict_self()
        .map_err(|_| LauncherError::Landlock)?;
    if status.ruleset != RulesetStatus::FullyEnforced
        || !matches!(status.landlock, LandlockStatus::Available { .. })
        || !status.no_new_privs
    {
        return Err(LauncherError::Landlock);
    }
    Ok(())
}

fn apply_seccomp(network: NetworkAccess) -> Result<(), LauncherError> {
    set_filter(FilterFlags::default(), &architecture_safety_filter())
        .map_err(|_| LauncherError::Seccomp)?;
    let mut filter = Filter::new(FilterArgs {
        default_action: FilterAction::Allow,
        arch_mismatch_action: FilterAction::KillProcess,
        ..FilterArgs::default()
    });
    let mut forbidden = vec![
        libc::SYS_add_key,
        libc::SYS_bpf,
        libc::SYS_chroot,
        libc::SYS_delete_module,
        libc::SYS_finit_module,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fsopen,
        libc::SYS_fspick,
        libc::SYS_init_module,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_io_uring_setup,
        libc::SYS_kexec_load,
        libc::SYS_keyctl,
        libc::SYS_mount,
        libc::SYS_mount_setattr,
        libc::SYS_move_mount,
        libc::SYS_name_to_handle_at,
        libc::SYS_open_by_handle_at,
        libc::SYS_open_tree,
        libc::SYS_perf_event_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_pivot_root,
        libc::SYS_process_vm_writev,
        libc::SYS_ptrace,
        libc::SYS_reboot,
        libc::SYS_request_key,
        libc::SYS_setpgid,
        libc::SYS_setsid,
        libc::SYS_setns,
        libc::SYS_swapoff,
        libc::SYS_swapon,
        libc::SYS_umount2,
        libc::SYS_unshare,
        libc::SYS_userfaultfd,
    ];
    if network == NetworkAccess::Deny {
        forbidden.extend([
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_bind,
            libc::SYS_connect,
            libc::SYS_listen,
            libc::SYS_recvfrom,
            libc::SYS_recvmmsg,
            libc::SYS_sendmmsg,
            libc::SYS_sendto,
            libc::SYS_socket,
            libc::SYS_socketpair,
        ]);
    } else {
        forbidden.extend([
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_bind,
            libc::SYS_listen,
        ]);
    }
    forbidden.sort_unstable();
    forbidden.dedup();
    filter.add_syscall_group(
        &forbidden
            .into_iter()
            .map(syscall_number)
            .collect::<Vec<_>>(),
        FilterAction::Errno {
            errno: errno_code(libc::EPERM),
        },
    );
    filter.add_syscall_group(
        &[syscall_number(libc::SYS_clone3)],
        FilterAction::Errno {
            errno: errno_code(libc::ENOSYS),
        },
    );
    let program = filter.compile().map_err(|_| LauncherError::Seccomp)?;
    set_filter(FilterFlags::default(), &program).map_err(|_| LauncherError::Seccomp)
}

fn architecture_safety_filter() -> Vec<BpfInstruction> {
    let deny = u32::from(FilterAction::Errno {
        errno: errno_code(libc::EPERM),
    });
    let mut instructions = vec![
        load_word(offset_of!(libc::seccomp_data, arch)),
        jump_equal(Architecture::compile_time_arch() as u32, 1, 0),
        return_action(FilterAction::KillProcess),
        load_word(offset_of!(libc::seccomp_data, nr)),
    ];
    #[cfg(target_arch = "x86_64")]
    instructions.extend([jump_bit_set(X32_SYSCALL_BIT, 0, 1), return_immediate(deny)]);
    instructions.push(return_action(FilterAction::Allow));
    instructions.into_iter().map(BpfInstruction::from).collect()
}

fn syscall_number(number: libc::c_long) -> u32 {
    u32::try_from(number).expect("Linux syscall numbers fit u32")
}

fn errno_code(errno: libc::c_int) -> u16 {
    u16::try_from(errno).expect("Linux errno values fit u16")
}

fn load_word(offset: usize) -> Instruction {
    Instruction::LoadAccumulator {
        addressing_mode: AddressingMode::ProgramInput,
        size: Size::Word,
        data: u32::try_from(offset).expect("seccomp data offset fits u32"),
    }
}

fn jump_equal(data: u32, jump_if_true: u8, jump_if_false: u8) -> Instruction {
    Instruction::Jump {
        condition: Condition::Equal,
        operand: Operand::Immediate,
        data,
        jump_offset_if_true: jump_if_true,
        jump_offset_if_false: jump_if_false,
    }
}

#[cfg(target_arch = "x86_64")]
fn jump_bit_set(data: u32, jump_if_true: u8, jump_if_false: u8) -> Instruction {
    Instruction::Jump {
        condition: Condition::BitSet,
        operand: Operand::Immediate,
        data,
        jump_offset_if_true: jump_if_true,
        jump_offset_if_false: jump_if_false,
    }
}

fn return_action(action: FilterAction) -> Instruction {
    return_immediate(u32::from(action))
}

fn return_immediate(data: u32) -> Instruction {
    Instruction::Return {
        return_value: ReturnValue::Immediate,
        data,
    }
}

fn applied_primitives(network: NetworkAccess) -> EnforcementPrimitives {
    let mut applied = EnforcementPrimitives::NO_NEW_PRIVILEGES
        | EnforcementPrimitives::MOUNT_NAMESPACE
        | EnforcementPrimitives::PID_NAMESPACE
        | EnforcementPrimitives::SECCOMP
        | EnforcementPrimitives::LANDLOCK
        | EnforcementPrimitives::PROCESS_GROUP
        | EnforcementPrimitives::RESOURCE_LIMITS;
    if network == NetworkAccess::Deny {
        applied = applied | EnforcementPrimitives::NETWORK_NAMESPACE;
    }
    applied
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_rejects_missing_and_unknown_protocol_fields() {
        assert!(parse(std::iter::empty()).is_err());
        assert!(parse([OsString::from("--unknown")].into_iter()).is_err());

        let base = [
            "--policy-digest".to_owned(),
            Digest::from_bytes([0; Digest::LEN]).to_lower_hex(),
            "--required-primitives".to_owned(),
            EnforcementPrimitives::all().bits().to_string(),
            "--filesystem".to_owned(),
            "none".to_owned(),
            "--network".to_owned(),
            "deny".to_owned(),
            "--max-processes".to_owned(),
            "2".to_owned(),
            "--max-memory-bytes".to_owned(),
            "1048576".to_owned(),
        ];
        let mut terminal = base.to_vec();
        terminal.extend([
            "--terminal-fd".to_owned(),
            "7".to_owned(),
            "--".to_owned(),
            super::super::SANDBOX_TARGET.to_owned(),
        ]);
        assert_eq!(
            parse(terminal.into_iter().map(OsString::from))
                .unwrap()
                .terminal_fd,
            Some(7)
        );

        let mut stdio_alias = base.to_vec();
        stdio_alias.extend([
            "--terminal-fd".to_owned(),
            "2".to_owned(),
            "--".to_owned(),
            super::super::SANDBOX_TARGET.to_owned(),
        ]);
        assert!(parse(stdio_alias.into_iter().map(OsString::from)).is_err());
    }
}
