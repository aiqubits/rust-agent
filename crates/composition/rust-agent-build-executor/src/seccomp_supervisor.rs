use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, IoSlice, IoSliceMut},
    mem::{MaybeUninit, offset_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::{
        fd::{AsFd as _, AsRawFd as _, OwnedFd},
        unix::{
            ffi::{OsStrExt as _, OsStringExt as _},
            fs::{FileExt as _, MetadataExt as _},
            net::UnixStream,
            process::CommandExt as _,
            process::ExitStatusExt as _,
        },
    },
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use nix::{
    errno::Errno,
    sys::{
        ptrace,
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::Pid,
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    net::{
        RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
        SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
    },
};
use seccompy::{
    Filter, FilterAction, FilterArgs, FilterFlags, FilterWithListenerFlags,
    bpf::{
        Architecture, BpfInstruction,
        instruction::Instruction,
        primitive::{AddressingMode, Condition, Operand, ReturnValue, Size},
    },
    check_validity, continue_syscall, fail_syscall, receive_notification, return_syscall,
    send_response, set_filter, set_filter_with_listener, set_no_new_privileges,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    LandlockExecutionPolicy, LandlockLauncherError, LinuxSandboxAnonymousSocketpair,
    apply_landlock_execution_policy,
};
use rust_agent_composition::{
    canonical,
    snapshot::{READ_ONLY_EPOCH_V1_DIRECTORY_MODE, READ_ONLY_EPOCH_V1_FILE_MODE},
};

const MAX_EXEC_PATH_BYTES: usize = 4096;
const MAX_EXEC_ARGUMENTS: usize = 4096;
const MAX_EXEC_ARGUMENT_BYTES: usize = 1024 * 1024;
const MAX_EXECUTIONS: usize = 16_384;
const MAX_REPORT_JSON_BYTES: usize = 16 * 1024 * 1024;
const PIPE_ONLY_CREDENTIAL_HELPER: &str = "/rust-agent/fetch-tools/credential-helper";
const CANONICAL_BLOCK_SIZE: u64 = 4096;
const SECTOR_BYTES: u64 = 512;
const MAX_DIRECTORY_ENTRIES: usize = 100_000;
const MAX_GETDENTS_BYTES: usize = 1024 * 1024;
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const FREEZE_TIMEOUT: Duration = Duration::from_secs(1);
const SUPERVISOR_POLL: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: 10_000_000,
};

#[derive(Debug, Error)]
pub enum SeccompSupervisorError {
    #[error("seccomp supervisor protocol is invalid")]
    Protocol,
    #[error("seccomp setup failed: {0}")]
    Setup(String),
    #[error("seccomp notification failed: {0}")]
    Notification(String),
    #[error("seccomp exec memory freeze failed: {0}")]
    Freeze(String),
    #[error("seccomp supervisor I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("seccomp execution report is invalid")]
    InvalidReport,
    #[error("seccomp execution report JSON is invalid: {0}")]
    ReportJson(#[from] serde_json::Error),
    #[error("canonical seccomp execution report encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
    #[error("Landlock setup failed: {0}")]
    Landlock(#[from] LandlockLauncherError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeccompExecutedCommand {
    pub executable: String,
    pub arguments: Vec<String>,
    #[serde(rename = "working-directory")]
    pub working_directory: String,
    #[serde(rename = "executable-sha256")]
    pub executable_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeccompExecutionReport {
    pub schema: u32,
    #[serde(rename = "landlock-policy-digest")]
    pub landlock_policy_digest: String,
    pub executions: Vec<SeccompExecutedCommand>,
    #[serde(rename = "exit-code")]
    pub exit_code: i32,
    pub digest: String,
}

#[derive(Serialize)]
struct SeccompExecutionReportProjection<'a> {
    schema: u32,
    landlock_policy_digest: &'a str,
    executions: &'a [SeccompExecutedCommand],
    exit_code: i32,
}

pub fn supervise_landlock_command(
    launcher_path: &Path,
    policy_path: &Path,
    policy: &LandlockExecutionPolicy,
    command: &OsStr,
    arguments: Vec<OsString>,
) -> Result<(ExitStatus, SeccompExecutionReport), SeccompSupervisorError> {
    policy.verify()?;
    if !policy.command_allowed(Path::new(command)) {
        return Err(SeccompSupervisorError::Landlock(
            LandlockLauncherError::CommandNotAllowed(command.to_string_lossy().into_owned()),
        ));
    }
    let (parent_socket, child_socket) = UnixStream::pair()?;
    let mut child = Command::new(launcher_path)
        .arg("--seccomp-child")
        .arg("--policy")
        .arg(policy_path)
        .arg("--")
        .arg(command)
        .args(arguments)
        .stdin(Stdio::from(OwnedFd::from(child_socket)))
        .process_group(0)
        .spawn()?;
    let listener = match receive_descriptor(&parent_socket) {
        Ok(listener) => listener,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    drop(parent_socket);
    match supervise_notifications(&mut child, &listener, policy) {
        Ok((status, executions)) => {
            let report = SeccompExecutionReport::new(policy, status, executions)?;
            Ok((status, report))
        }
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(error)
        }
    }
}

pub fn run_seccomp_child(
    policy: &LandlockExecutionPolicy,
    command: &OsStr,
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<std::convert::Infallible, SeccompSupervisorError> {
    policy.verify()?;
    reject_preexisting_shared_writable_mappings()?;
    let socket = UnixStream::from(rustix::io::dup(io::stdin()).map_err(rustix_error)?);
    let listener = install_filter()?;
    send_descriptor(&socket, &listener)?;
    drop(socket);
    drop(listener);
    let null_input = File::open("/dev/null")?;
    rustix::stdio::dup2_stdin(&null_input).map_err(rustix_error)?;
    drop(null_input);
    reject_inherited_nonstandard_descriptors()?;
    apply_landlock_execution_policy(policy, Path::new(command))?;
    let error = Command::new(command).args(arguments).exec();
    Err(SeccompSupervisorError::Io(error))
}

fn install_filter() -> Result<OwnedFd, SeccompSupervisorError> {
    let mut filter = Filter::new(FilterArgs {
        default_action: FilterAction::Allow,
        ..FilterArgs::default()
    });
    let mut notification_syscalls = [
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_getdents64,
        libc::SYS_getdents,
        libc::SYS_lseek,
        libc::SYS_ioctl,
        libc::SYS_close,
        libc::SYS_close_range,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_dup3,
        libc::SYS_fcntl,
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_sendto,
    ]
    .map(syscall_number)
    .to_vec();
    #[cfg(target_arch = "x86_64")]
    notification_syscalls.extend([
        syscall_number(libc::SYS_stat),
        syscall_number(libc::SYS_lstat),
    ]);
    notification_syscalls.sort_unstable();
    filter.add_syscall_group(&notification_syscalls, FilterAction::UserNotif);
    let forbidden_syscalls = [
        libc::SYS_add_key,
        libc::SYS_bpf,
        libc::SYS_chroot,
        libc::SYS_delete_module,
        libc::SYS_fgetxattr,
        libc::SYS_flistxattr,
        libc::SYS_fremovexattr,
        libc::SYS_fsetxattr,
        libc::SYS_fstatfs,
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
        libc::SYS_quotactl,
        libc::SYS_reboot,
        libc::SYS_request_key,
        libc::SYS_setpgid,
        libc::SYS_setsid,
        libc::SYS_setns,
        libc::SYS_getxattr,
        libc::SYS_lgetxattr,
        libc::SYS_listxattr,
        libc::SYS_llistxattr,
        libc::SYS_lremovexattr,
        libc::SYS_lsetxattr,
        libc::SYS_removexattr,
        libc::SYS_setxattr,
        libc::SYS_shmat,
        libc::SYS_shmget,
        libc::SYS_statfs,
        libc::SYS_swapoff,
        libc::SYS_swapon,
        libc::SYS_umount2,
        libc::SYS_unshare,
        libc::SYS_userfaultfd,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendmmsg,
    ]
    .map(syscall_number);
    filter.add_syscall_group(
        &forbidden_syscalls,
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
    set_no_new_privileges().map_err(|error| SeccompSupervisorError::Setup(error.to_string()))?;
    set_filter(
        FilterFlags {
            sync_threads: true,
            ..FilterFlags::default()
        },
        &conditional_safety_filter(),
    )
    .map_err(|error| SeccompSupervisorError::Setup(error.to_string()))?;
    let program = filter
        .compile()
        .map_err(|error| SeccompSupervisorError::Setup(error.to_string()))?;
    set_filter_with_listener(
        FilterWithListenerFlags {
            sync_threads: true,
            ..FilterWithListenerFlags::default()
        },
        &program,
    )
    .map_err(|error| SeccompSupervisorError::Setup(error.to_string()))
}

fn conditional_safety_filter() -> Vec<BpfInstruction> {
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
    instructions.extend([
        // Shared mappings would let a non-thread CLONE_VM child mutate an
        // execve pathname while the supervisor has the caller blocked.
        jump_equal(syscall_number(libc::SYS_mmap), 0, 3),
        load_word(offset_of!(libc::seccomp_data, args) + 3 * size_of_u64()),
        jump_bit_set(
            u32::try_from(libc::MAP_SHARED).expect("MAP_SHARED is non-negative"),
            0,
            1,
        ),
        return_immediate(deny),
        // Ordinary threads are frozen at execve. vfork is safe because the
        // parent remains suspended until the shared-VM child execs or exits.
        jump_equal(syscall_number(libc::SYS_clone), 0, 4),
        load_word(offset_of!(libc::seccomp_data, args)),
        jump_bit_set(
            u32::try_from(libc::CLONE_VM).expect("CLONE_VM is non-negative"),
            0,
            2,
        ),
        jump_bit_set(
            u32::try_from(libc::CLONE_THREAD | libc::CLONE_VFORK)
                .expect("clone flags are non-negative"),
            1,
            0,
        ),
        return_immediate(deny),
        return_action(FilterAction::Allow),
    ]);
    instructions.into_iter().map(BpfInstruction::from).collect()
}

fn syscall_number(number: libc::c_long) -> u32 {
    u32::try_from(number).expect("Linux syscall numbers are non-negative u32 values")
}

fn errno_code(errno: libc::c_int) -> u16 {
    u16::try_from(errno).expect("Linux errno values fit in u16")
}

const fn size_of_u64() -> usize {
    std::mem::size_of::<u64>()
}

fn load_word(offset: usize) -> Instruction {
    Instruction::LoadAccumulator {
        addressing_mode: AddressingMode::ProgramInput,
        size: Size::Word,
        data: u32::try_from(offset).expect("seccomp_data offset fits in u32"),
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

fn supervise_notifications(
    child: &mut Child,
    listener: &OwnedFd,
    policy: &LandlockExecutionPolicy,
) -> Result<(ExitStatus, Vec<SeccompExecutedCommand>), SeccompSupervisorError> {
    let mut state = NotificationState::default();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok((status, state.executions));
        }
        let mut fds = [PollFd::new(
            listener,
            PollFlags::IN | PollFlags::HUP | PollFlags::ERR,
        )];
        poll(&mut fds, Some(&SUPERVISOR_POLL)).map_err(rustix_error)?;
        if fds[0].revents().contains(PollFlags::IN) {
            let notification = receive_notification(listener.as_raw_fd())
                .map_err(|error| SeccompSupervisorError::Notification(error.to_string()))?;
            handle_notification(listener, notification, policy, &mut state)?;
        }
    }
}

fn handle_notification(
    listener: &OwnedFd,
    notification: seccompy::SeccompNotif,
    policy: &LandlockExecutionPolicy,
    state: &mut NotificationState,
) -> Result<(), SeccompSupervisorError> {
    let syscall = i64::from(notification.data.nr);
    if syscall == libc::SYS_execve {
        return decide_execve(listener, notification, policy, state);
    }
    if syscall == libc::SYS_fstat
        || syscall == libc::SYS_newfstatat
        || syscall == libc::SYS_statx
        || is_legacy_stat_syscall(syscall)
    {
        return emulate_metadata_syscall(listener, notification, policy);
    }
    if syscall == libc::SYS_getdents64
        || syscall == libc::SYS_getdents
        || syscall == libc::SYS_lseek
    {
        return emulate_directory_syscall(listener, notification, policy, state);
    }
    if syscall == libc::SYS_ioctl {
        return emulate_metadata_ioctl(listener, notification);
    }
    if syscall == libc::SYS_close || syscall == libc::SYS_close_range {
        state.forget_descriptors(notification.pid, syscall, &notification.data.args)?;
        return send_response(listener.as_raw_fd(), continue_syscall(notification))
            .map_err(|error| SeccompSupervisorError::Notification(error.to_string()));
    }
    if syscall == libc::SYS_dup
        || syscall == libc::SYS_dup2
        || syscall == libc::SYS_dup3
        || syscall == libc::SYS_fcntl
    {
        return constrain_descriptor_duplication(listener, notification);
    }
    if syscall == libc::SYS_socket
        || syscall == libc::SYS_socketpair
        || syscall == libc::SYS_connect
        || syscall == libc::SYS_sendto
    {
        return constrain_network_syscall(listener, notification, policy, state);
    }
    let response = if syscall == libc::SYS_execveat {
        fail_syscall(notification, errno_code(libc::EACCES))
    } else {
        fail_syscall(notification, errno_code(libc::EPERM))
    };
    send_response(listener.as_raw_fd(), response)
        .map_err(|error| SeccompSupervisorError::Notification(error.to_string()))
}

fn constrain_network_syscall(
    listener: &OwnedFd,
    notification: seccompy::SeccompNotif,
    policy: &LandlockExecutionPolicy,
    state: &NotificationState,
) -> Result<(), SeccompSupervisorError> {
    let caller_tid =
        i32::try_from(notification.pid).map_err(|_| SeccompSupervisorError::Protocol)?;
    let supervisor_pid =
        i32::try_from(std::process::id()).map_err(|_| SeccompSupervisorError::Protocol)?;
    let frozen = freeze_related_threads(caller_tid, supervisor_pid)?;
    let decision = (|| {
        if !check_validity(listener.as_raw_fd(), &notification)
            .map_err(|error| SeccompSupervisorError::Notification(error.to_string()))?
        {
            return Ok(NetworkSyscallDecision::Deny(libc::EPERM));
        }
        if state.pipe_only_process(caller_tid)? {
            return Ok(NetworkSyscallDecision::Deny(libc::EPERM));
        }
        let syscall = i64::from(notification.data.nr);
        Ok(if syscall == libc::SYS_socket {
            if socket_allowed(&notification, policy)
                || inert_nss_unix_socket_allowed(&notification, policy)
            {
                NetworkSyscallDecision::Continue
            } else {
                NetworkSyscallDecision::Deny(libc::EPERM)
            }
        } else if syscall == libc::SYS_socketpair {
            if anonymous_socketpair_allowed(&notification, policy) {
                NetworkSyscallDecision::Continue
            } else {
                NetworkSyscallDecision::Deny(libc::EPERM)
            }
        } else if syscall == libc::SYS_connect {
            connect_decision(&notification, policy)
        } else if syscall == libc::SYS_sendto {
            if notification.data.args[4] == 0 && notification.data.args[5] == 0 {
                NetworkSyscallDecision::Continue
            } else {
                NetworkSyscallDecision::Deny(libc::EPERM)
            }
        } else {
            NetworkSyscallDecision::Deny(libc::EPERM)
        })
    })();
    let response = match decision {
        Ok(NetworkSyscallDecision::Continue) => continue_syscall(notification),
        Ok(NetworkSyscallDecision::Deny(errno)) => fail_syscall(notification, errno_code(errno)),
        Err(error) => {
            let _ = send_response(
                listener.as_raw_fd(),
                fail_syscall(notification, errno_code(libc::EPERM)),
            );
            detach_all(&frozen);
            return Err(error);
        }
    };
    let result = send_response(listener.as_raw_fd(), response)
        .map_err(|error| SeccompSupervisorError::Notification(error.to_string()));
    detach_all(&frozen);
    result
}

enum NetworkSyscallDecision {
    Continue,
    Deny(libc::c_int),
}

fn anonymous_socketpair_allowed(
    notification: &seccompy::SeccompNotif,
    policy: &LandlockExecutionPolicy,
) -> bool {
    let Ok(domain) = syscall_i32(notification.data.args[0]) else {
        return false;
    };
    let Ok(socket_type) = syscall_i32(notification.data.args[1]) else {
        return false;
    };
    let Ok(protocol) = syscall_i32(notification.data.args[2]) else {
        return false;
    };
    anonymous_socketpair_shape_allowed(domain, socket_type, protocol, &policy.anonymous_socketpairs)
}

fn anonymous_socketpair_shape_allowed(
    domain: libc::c_int,
    socket_type: libc::c_int,
    protocol: libc::c_int,
    classes: &[LinuxSandboxAnonymousSocketpair],
) -> bool {
    if domain != libc::AF_UNIX || protocol != 0 {
        return false;
    }
    let base_type = socket_type & !(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK);
    let flags = socket_type & (libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK);
    let unknown = socket_type & !(base_type | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK);
    unknown == 0
        && classes.iter().any(|class| match class {
            LinuxSandboxAnonymousSocketpair::StreamWakeup => base_type == libc::SOCK_STREAM,
            LinuxSandboxAnonymousSocketpair::RustSpawnError => {
                base_type == libc::SOCK_SEQPACKET && flags == libc::SOCK_CLOEXEC
            }
        })
}

fn inert_nss_unix_socket_allowed(
    notification: &seccompy::SeccompNotif,
    policy: &LandlockExecutionPolicy,
) -> bool {
    if policy.network_endpoints.is_empty() {
        return false;
    }
    let Ok(domain) = syscall_i32(notification.data.args[0]) else {
        return false;
    };
    let Ok(socket_type) = syscall_i32(notification.data.args[1]) else {
        return false;
    };
    let Ok(protocol) = syscall_i32(notification.data.args[2]) else {
        return false;
    };
    let base_type = socket_type & !(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK);
    let known_flags = base_type | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    domain == libc::AF_UNIX
        && base_type == libc::SOCK_STREAM
        && socket_type & !known_flags == 0
        && protocol == 0
}

fn socket_allowed(notification: &seccompy::SeccompNotif, policy: &LandlockExecutionPolicy) -> bool {
    let Ok(domain) = syscall_i32(notification.data.args[0]) else {
        return false;
    };
    let Ok(socket_type) = syscall_i32(notification.data.args[1]) else {
        return false;
    };
    let Ok(protocol) = syscall_i32(notification.data.args[2]) else {
        return false;
    };
    let base_type = socket_type & !(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK);
    let known_flags = base_type | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    let family_allowed = match domain {
        libc::AF_INET => policy
            .network_endpoints
            .iter()
            .flat_map(|endpoint| &endpoint.addresses)
            .any(IpAddr::is_ipv4),
        libc::AF_INET6 => policy
            .network_endpoints
            .iter()
            .flat_map(|endpoint| &endpoint.addresses)
            .any(IpAddr::is_ipv6),
        _ => false,
    };
    family_allowed
        && base_type == libc::SOCK_STREAM
        && socket_type & !known_flags == 0
        && (protocol == 0 || protocol == libc::IPPROTO_TCP)
}

fn connect_decision(
    notification: &seccompy::SeccompNotif,
    policy: &LandlockExecutionPolicy,
) -> NetworkSyscallDecision {
    let Ok(length) = usize::try_from(notification.data.args[2]) else {
        return NetworkSyscallDecision::Deny(libc::EPERM);
    };
    let Ok(bytes) = read_process_bytes(
        notification.pid,
        notification.data.args[1],
        length,
        std::mem::size_of::<libc::sockaddr_storage>(),
    ) else {
        return NetworkSyscallDecision::Deny(libc::EPERM);
    };
    if parse_socket_address(&bytes)
        .is_some_and(|(address, port)| policy.network_endpoint_allowed(address, port))
    {
        NetworkSyscallDecision::Continue
    } else if !policy.network_endpoints.is_empty() && exact_nscd_socket_address(&bytes) {
        NetworkSyscallDecision::Deny(libc::ENOENT)
    } else {
        NetworkSyscallDecision::Deny(libc::EPERM)
    }
}

fn exact_nscd_socket_address(bytes: &[u8]) -> bool {
    const PATH: &[u8] = b"/var/run/nscd/socket\0";
    let family = u16::try_from(libc::AF_UNIX).expect("AF_UNIX fits u16");
    bytes.len() >= 2 + PATH.len()
        && bytes.len() <= std::mem::size_of::<libc::sockaddr_un>()
        && bytes.get(..2) == Some(family.to_ne_bytes().as_slice())
        && bytes.get(2..2 + PATH.len()) == Some(PATH)
}

fn parse_socket_address(bytes: &[u8]) -> Option<(IpAddr, u16)> {
    let family = u16::from_ne_bytes(bytes.get(0..2)?.try_into().ok()?);
    let port = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
    if family == u16::try_from(libc::AF_INET).ok()? && bytes.len() >= 16 {
        let octets: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
        Some((IpAddr::V4(Ipv4Addr::from(octets)), port))
    } else if family == u16::try_from(libc::AF_INET6).ok()? && bytes.len() >= 28 {
        let flow = u32::from_ne_bytes(bytes.get(4..8)?.try_into().ok()?);
        let octets: [u8; 16] = bytes.get(8..24)?.try_into().ok()?;
        let scope = u32::from_ne_bytes(bytes.get(24..28)?.try_into().ok()?);
        (flow == 0 && scope == 0).then_some((IpAddr::V6(Ipv6Addr::from(octets)), port))
    } else {
        None
    }
}

#[cfg(target_arch = "x86_64")]
fn is_legacy_stat_syscall(syscall: i64) -> bool {
    syscall == libc::SYS_stat || syscall == libc::SYS_lstat
}

#[cfg(not(target_arch = "x86_64"))]
fn is_legacy_stat_syscall(_syscall: i64) -> bool {
    false
}

struct MetadataReply {
    address: u64,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct NotificationState {
    directory_cursors: BTreeMap<DirectoryKey, usize>,
    executions: Vec<SeccompExecutedCommand>,
    process_executables: BTreeMap<i32, String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DirectoryKey {
    process: i32,
    descriptor: i32,
    logical_path: PathBuf,
}

struct DirectoryEntryView {
    name: Vec<u8>,
    inode: u64,
    file_type: u8,
}

impl NotificationState {
    fn pipe_only_process(&self, tid: i32) -> Result<bool, SeccompSupervisorError> {
        let mut process = read_thread_group_id(tid)?;
        for _ in 0..32 {
            if self
                .process_executables
                .get(&process)
                .is_some_and(|path| path == PIPE_ONLY_CREDENTIAL_HELPER)
            {
                return Ok(true);
            }
            let status = fs::read_to_string(format!("/proc/{process}/status"))?;
            let parent = status
                .lines()
                .find_map(|line| line.strip_prefix("PPid:\t"))
                .and_then(|value| value.trim().parse::<i32>().ok())
                .ok_or(SeccompSupervisorError::Protocol)?;
            if parent <= 1 || parent == process {
                break;
            }
            process = read_thread_group_id(parent)?;
        }
        Ok(false)
    }

    fn forget_descriptors(
        &mut self,
        pid: u32,
        syscall: i64,
        arguments: &[u64; 6],
    ) -> Result<(), SeccompSupervisorError> {
        let process = read_thread_group_id(
            i32::try_from(pid).map_err(|_| SeccompSupervisorError::Protocol)?,
        )?;
        if syscall == libc::SYS_close {
            let descriptor =
                syscall_i32(arguments[0]).map_err(|_| SeccompSupervisorError::Protocol)?;
            self.directory_cursors
                .retain(|key, _| key.process != process || key.descriptor != descriptor);
        } else {
            let first =
                u32::try_from(arguments[0]).map_err(|_| SeccompSupervisorError::Protocol)?;
            let last = u32::try_from(arguments[1]).map_err(|_| SeccompSupervisorError::Protocol)?;
            self.directory_cursors.retain(|key, _| {
                if key.process != process {
                    return true;
                }
                let Ok(descriptor) = u32::try_from(key.descriptor) else {
                    return false;
                };
                descriptor < first || descriptor > last
            });
        }
        Ok(())
    }
}

fn emulate_metadata_ioctl(
    listener: &OwnedFd,
    notification: seccompy::SeccompNotif,
) -> Result<(), SeccompSupervisorError> {
    let request = notification.data.args[1];
    let response = if request == libc::FS_IOC_GETVERSION || request == libc::FS_IOC_GETFLAGS {
        let reply = MetadataReply {
            address: notification.data.args[2],
            bytes: vec![0_u8; std::mem::size_of::<libc::c_long>()],
        };
        match write_process_memory(notification.pid, &reply) {
            Ok(()) => return_syscall(notification, 0),
            Err(errno) => fail_syscall(notification, errno_code(errno)),
        }
    } else {
        continue_syscall(notification)
    };
    send_response(listener.as_raw_fd(), response)
        .map_err(|error| SeccompSupervisorError::Notification(error.to_string()))
}

fn emulate_directory_syscall(
    listener: &OwnedFd,
    notification: seccompy::SeccompNotif,
    policy: &LandlockExecutionPolicy,
    state: &mut NotificationState,
) -> Result<(), SeccompSupervisorError> {
    let caller_tid =
        i32::try_from(notification.pid).map_err(|_| SeccompSupervisorError::Protocol)?;
    let supervisor_pid =
        i32::try_from(std::process::id()).map_err(|_| SeccompSupervisorError::Protocol)?;
    let frozen = freeze_related_threads(caller_tid, supervisor_pid)?;
    let result = (|| {
        if !check_validity(listener.as_raw_fd(), &notification)
            .map_err(|error| SeccompSupervisorError::Notification(error.to_string()))?
        {
            return Ok(());
        }
        let syscall = i64::from(notification.data.nr);
        let response = if syscall == libc::SYS_getdents {
            fail_syscall(notification, errno_code(libc::ENOSYS))
        } else {
            let descriptor = match syscall_i32(notification.data.args[0]) {
                Ok(descriptor) => descriptor,
                Err(errno) => {
                    return send_response(
                        listener.as_raw_fd(),
                        fail_syscall(notification, errno_code(errno)),
                    )
                    .map_err(|error| SeccompSupervisorError::Notification(error.to_string()));
                }
            };
            let resolved = match resolve_descriptor_metadata(notification.pid, descriptor) {
                Ok(resolved) if resolved.metadata.is_dir() => resolved,
                Ok(_) if syscall == libc::SYS_lseek => {
                    return send_response(listener.as_raw_fd(), continue_syscall(notification))
                        .map_err(|error| SeccompSupervisorError::Notification(error.to_string()));
                }
                Ok(_) => {
                    return send_response(
                        listener.as_raw_fd(),
                        fail_syscall(notification, errno_code(libc::ENOTDIR)),
                    )
                    .map_err(|error| SeccompSupervisorError::Notification(error.to_string()));
                }
                Err(errno) => {
                    return send_response(
                        listener.as_raw_fd(),
                        fail_syscall(notification, errno_code(errno)),
                    )
                    .map_err(|error| SeccompSupervisorError::Notification(error.to_string()));
                }
            };
            let logical_path = resolved
                .logical_path
                .unwrap_or_else(|| PathBuf::from(format!("/proc-fd-{descriptor}")));
            let process = read_thread_group_id(caller_tid)?;
            let key = DirectoryKey {
                process,
                descriptor,
                logical_path,
            };
            if syscall == libc::SYS_lseek {
                let offset = notification.data.args[1].cast_signed();
                let whence = syscall_i32(notification.data.args[2]).unwrap_or(-1);
                if offset == 0 && whence == libc::SEEK_SET {
                    state.directory_cursors.insert(key, 0);
                    return_syscall(notification, 0)
                } else {
                    fail_syscall(notification, errno_code(libc::EINVAL))
                }
            } else {
                match prepare_getdents_reply(notification, policy, state, key) {
                    Ok(reply) => {
                        let count = i64::try_from(reply.bytes.len())
                            .map_err(|_| SeccompSupervisorError::Protocol)?;
                        match write_process_memory(notification.pid, &reply) {
                            Ok(()) => return_syscall(notification, count),
                            Err(errno) => fail_syscall(notification, errno_code(errno)),
                        }
                    }
                    Err(errno) => fail_syscall(notification, errno_code(errno)),
                }
            }
        };
        send_response(listener.as_raw_fd(), response)
            .map_err(|error| SeccompSupervisorError::Notification(error.to_string()))
    })();
    detach_all(&frozen);
    result
}

fn prepare_getdents_reply(
    notification: seccompy::SeccompNotif,
    policy: &LandlockExecutionPolicy,
    state: &mut NotificationState,
    key: DirectoryKey,
) -> Result<MetadataReply, libc::c_int> {
    let address = notification.data.args[1];
    if address == 0 {
        return Err(libc::EFAULT);
    }
    let requested = usize::try_from(notification.data.args[2]).map_err(|_| libc::EINVAL)?;
    if requested == 0 {
        return Err(libc::EINVAL);
    }
    let capacity = requested.min(MAX_GETDENTS_BYTES);
    let canonical = policy.canonical_metadata_visible(&key.logical_path);
    let entries = read_directory_entries(
        notification.pid,
        key.descriptor,
        &key.logical_path,
        canonical,
    )?;
    let cursor = state.directory_cursors.entry(key).or_default();
    *cursor = (*cursor).min(entries.len());
    let mut bytes = Vec::with_capacity(capacity);
    while let Some(entry) = entries.get(*cursor) {
        let record_length = (19_usize + entry.name.len() + 1).next_multiple_of(8);
        if record_length > capacity.saturating_sub(bytes.len()) {
            if bytes.is_empty() {
                return Err(libc::EINVAL);
            }
            break;
        }
        let start = bytes.len();
        bytes.resize(start + record_length, 0);
        write_field(&mut bytes, start, entry.inode.to_ne_bytes())?;
        write_field(
            &mut bytes,
            start + 8,
            i64::try_from(*cursor + 1)
                .map_err(|_| libc::EOVERFLOW)?
                .to_ne_bytes(),
        )?;
        write_field(
            &mut bytes,
            start + 16,
            u16::try_from(record_length)
                .map_err(|_| libc::EOVERFLOW)?
                .to_ne_bytes(),
        )?;
        bytes[start + 18] = entry.file_type;
        bytes[start + 19..start + 19 + entry.name.len()].copy_from_slice(&entry.name);
        *cursor += 1;
    }
    Ok(MetadataReply { address, bytes })
}

fn read_directory_entries(
    pid: u32,
    descriptor: i32,
    logical_path: &Path,
    canonical: bool,
) -> Result<Vec<DirectoryEntryView>, libc::c_int> {
    let directory_path = PathBuf::from(format!("/proc/{pid}/fd/{descriptor}"));
    let directory_metadata = fs::metadata(&directory_path).map_err(|error| io_errno(&error))?;
    let parent_metadata =
        fs::metadata(directory_path.join("..")).map_err(|error| io_errno(&error))?;
    let mut entries = vec![
        DirectoryEntryView {
            name: b".".to_vec(),
            inode: if canonical {
                canonical_dirent_inode(logical_path, b".")
            } else {
                directory_metadata.ino()
            },
            file_type: libc::DT_DIR,
        },
        DirectoryEntryView {
            name: b"..".to_vec(),
            inode: if canonical {
                canonical_dirent_inode(logical_path, b"..")
            } else {
                parent_metadata.ino()
            },
            file_type: libc::DT_DIR,
        },
    ];
    for entry in fs::read_dir(directory_path).map_err(|error| io_errno(&error))? {
        let entry = entry.map_err(|error| io_errno(&error))?;
        let name = entry.file_name().as_bytes().to_vec();
        if name.contains(&0) || name.len() > 255 {
            return Err(libc::EIO);
        }
        let file_type = entry.file_type().map_err(|error| io_errno(&error))?;
        let file_type = if file_type.is_dir() {
            libc::DT_DIR
        } else if file_type.is_file() {
            libc::DT_REG
        } else if file_type.is_symlink() {
            libc::DT_LNK
        } else {
            libc::DT_UNKNOWN
        };
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| io_errno(&error))?;
        entries.push(DirectoryEntryView {
            inode: if canonical {
                canonical_dirent_inode(logical_path, &name)
            } else {
                metadata.ino()
            },
            name,
            file_type,
        });
        if entries.len() > MAX_DIRECTORY_ENTRIES + 2 {
            return Err(libc::EOVERFLOW);
        }
    }
    entries[2..].sort_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

fn canonical_dirent_inode(directory: &Path, name: &[u8]) -> u64 {
    // Linux libc treats d_ino=0 as a deleted entry and hides it. This
    // domain-separated FNV-1a projection is the schema-1 dirent sentinel;
    // stat/statx retain the canonical metadata contract's inode value of 0.
    let mut value = 0xcbf2_9ce4_8422_2325_u64;
    for byte in directory
        .as_os_str()
        .as_bytes()
        .iter()
        .copied()
        .chain([0])
        .chain(name.iter().copied())
    {
        value ^= u64::from(byte);
        value = value.wrapping_mul(0x0000_0100_0000_01b3);
    }
    value.max(1)
}

fn constrain_descriptor_duplication(
    listener: &OwnedFd,
    notification: seccompy::SeccompNotif,
) -> Result<(), SeccompSupervisorError> {
    let syscall = i64::from(notification.data.nr);
    let descriptor = syscall_i32(notification.data.args[0]).unwrap_or(-1);
    let duplicates = syscall != libc::SYS_fcntl
        || syscall_i32(notification.data.args[1])
            .is_ok_and(|command| command == libc::F_DUPFD || command == libc::F_DUPFD_CLOEXEC);
    let directory = duplicates
        && descriptor >= 0
        && fs::metadata(format!("/proc/{}/fd/{descriptor}", notification.pid))
            .is_ok_and(|metadata| metadata.is_dir());
    let response = if directory {
        fail_syscall(notification, errno_code(libc::EPERM))
    } else {
        continue_syscall(notification)
    };
    send_response(listener.as_raw_fd(), response)
        .map_err(|error| SeccompSupervisorError::Notification(error.to_string()))
}

fn read_thread_group_id(tid: i32) -> Result<i32, SeccompSupervisorError> {
    let status = fs::read_to_string(format!("/proc/{tid}/status"))?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:\t"))
        .and_then(|value| value.trim().parse().ok())
        .ok_or(SeccompSupervisorError::Protocol)
}

struct ResolvedMetadata {
    logical_path: Option<PathBuf>,
    metadata: fs::Metadata,
}

fn emulate_metadata_syscall(
    listener: &OwnedFd,
    notification: seccompy::SeccompNotif,
    policy: &LandlockExecutionPolicy,
) -> Result<(), SeccompSupervisorError> {
    let caller_tid =
        i32::try_from(notification.pid).map_err(|_| SeccompSupervisorError::Protocol)?;
    let supervisor_pid =
        i32::try_from(std::process::id()).map_err(|_| SeccompSupervisorError::Protocol)?;
    let frozen = freeze_related_threads(caller_tid, supervisor_pid)?;
    let result = (|| {
        if !check_validity(listener.as_raw_fd(), &notification)
            .map_err(|error| SeccompSupervisorError::Notification(error.to_string()))?
        {
            return Ok(());
        }
        let response = match prepare_metadata_reply(notification, policy) {
            Ok(reply) => match write_process_memory(notification.pid, &reply) {
                Ok(()) => return_syscall(notification, 0),
                Err(errno) => fail_syscall(notification, errno_code(errno)),
            },
            Err(errno) => fail_syscall(notification, errno_code(errno)),
        };
        send_response(listener.as_raw_fd(), response)
            .map_err(|error| SeccompSupervisorError::Notification(error.to_string()))
    })();
    detach_all(&frozen);
    result
}

fn prepare_metadata_reply(
    notification: seccompy::SeccompNotif,
    policy: &LandlockExecutionPolicy,
) -> Result<MetadataReply, libc::c_int> {
    let syscall = i64::from(notification.data.nr);
    let (resolved, address, statx) = if syscall == libc::SYS_fstat {
        (
            resolve_descriptor_metadata(notification.pid, syscall_i32(notification.data.args[0])?)?,
            notification.data.args[1],
            false,
        )
    } else if syscall == libc::SYS_newfstatat {
        let flags = syscall_i32(notification.data.args[3])?;
        validate_at_flags(flags, false)?;
        (
            resolve_path_metadata(
                notification.pid,
                syscall_i32(notification.data.args[0])?,
                notification.data.args[1],
                flags,
                policy,
            )?,
            notification.data.args[2],
            false,
        )
    } else if syscall == libc::SYS_statx {
        let flags = syscall_i32(notification.data.args[2])?;
        validate_at_flags(flags, true)?;
        (
            resolve_path_metadata(
                notification.pid,
                syscall_i32(notification.data.args[0])?,
                notification.data.args[1],
                flags,
                policy,
            )?,
            notification.data.args[4],
            true,
        )
    } else if is_legacy_stat_syscall(syscall) {
        let no_follow = legacy_lstat(syscall);
        (
            resolve_path_metadata(
                notification.pid,
                libc::AT_FDCWD,
                notification.data.args[0],
                if no_follow {
                    libc::AT_SYMLINK_NOFOLLOW
                } else {
                    0
                },
                policy,
            )?,
            notification.data.args[1],
            false,
        )
    } else {
        return Err(libc::ENOSYS);
    };
    if address == 0 {
        return Err(libc::EFAULT);
    }
    let canonical = resolved
        .logical_path
        .as_ref()
        .is_some_and(|path| policy.canonical_metadata_visible(path));
    let bytes = if statx {
        encode_statx(&resolved.metadata, canonical)?
    } else {
        encode_stat(&resolved.metadata, canonical)?
    };
    Ok(MetadataReply { address, bytes })
}

#[cfg(target_arch = "x86_64")]
fn legacy_lstat(syscall: i64) -> bool {
    syscall == libc::SYS_lstat
}

#[cfg(not(target_arch = "x86_64"))]
fn legacy_lstat(_syscall: i64) -> bool {
    false
}

fn syscall_i32(argument: u64) -> Result<i32, libc::c_int> {
    u32::try_from(argument)
        .map(u32::cast_signed)
        .map_err(|_| libc::EINVAL)
}

fn validate_at_flags(flags: i32, statx: bool) -> Result<(), libc::c_int> {
    let mut allowed = libc::AT_EMPTY_PATH | libc::AT_NO_AUTOMOUNT | libc::AT_SYMLINK_NOFOLLOW;
    if statx {
        allowed |=
            libc::AT_STATX_FORCE_SYNC | libc::AT_STATX_DONT_SYNC | libc::AT_STATX_SYNC_AS_STAT;
    }
    if flags & !allowed == 0 {
        Ok(())
    } else {
        Err(libc::EINVAL)
    }
}

fn resolve_descriptor_metadata(pid: u32, descriptor: i32) -> Result<ResolvedMetadata, libc::c_int> {
    if descriptor < 0 {
        return Err(libc::EBADF);
    }
    let descriptor_path = format!("/proc/{pid}/fd/{descriptor}");
    let logical_path = fs::read_link(&descriptor_path)
        .ok()
        .and_then(|path| normalize_absolute_path(&path));
    let metadata = fs::metadata(descriptor_path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            libc::EBADF
        } else {
            io_errno(&error)
        }
    })?;
    Ok(ResolvedMetadata {
        logical_path,
        metadata,
    })
}

fn resolve_path_metadata(
    pid: u32,
    directory_descriptor: i32,
    path_address: u64,
    flags: i32,
    policy: &LandlockExecutionPolicy,
) -> Result<ResolvedMetadata, libc::c_int> {
    let path_bytes = read_c_bytes(pid, path_address)?;
    if path_bytes.is_empty() {
        if flags & libc::AT_EMPTY_PATH == 0 {
            return Err(libc::ENOENT);
        }
        return resolve_descriptor_metadata(pid, directory_descriptor);
    }
    let path = PathBuf::from(OsString::from_vec(path_bytes));
    let logical_path = if path.is_absolute() {
        normalize_absolute_path(&path)
    } else {
        let base = if directory_descriptor == libc::AT_FDCWD {
            fs::read_link(format!("/proc/{pid}/cwd"))
        } else if directory_descriptor < 0 {
            return Err(libc::EBADF);
        } else {
            fs::read_link(format!("/proc/{pid}/fd/{directory_descriptor}"))
        }
        .map_err(|error| io_errno(&error))?;
        normalize_absolute_path(&base.join(path))
    }
    .ok_or(libc::EINVAL)?;
    if !policy.path_visible(&logical_path) {
        return Err(libc::EACCES);
    }
    let observed_path = Path::new(&format!("/proc/{pid}/root"))
        .join(logical_path.strip_prefix("/").map_err(|_| libc::EINVAL)?);
    let metadata = if flags & libc::AT_SYMLINK_NOFOLLOW == 0 {
        fs::metadata(observed_path)
    } else {
        fs::symlink_metadata(observed_path)
    }
    .map_err(|error| io_errno(&error))?;
    Ok(ResolvedMetadata {
        logical_path: Some(logical_path),
        metadata,
    })
}

fn normalize_absolute_path(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut normalized = PathBuf::from("/");
    for component in path.components().skip(1) {
        match component {
            Component::Normal(component) => normalized.push(component),
            Component::ParentDir => {
                if normalized == Path::new("/") {
                    return None;
                }
                normalized.pop();
            }
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

fn read_c_bytes(pid: u32, address: u64) -> Result<Vec<u8>, libc::c_int> {
    if address == 0 {
        return Err(libc::EFAULT);
    }
    let memory = File::open(format!("/proc/{pid}/mem")).map_err(|_| libc::EFAULT)?;
    let mut bytes = Vec::with_capacity(128);
    for offset in 0..MAX_EXEC_PATH_BYTES {
        let mut byte = [0_u8; 1];
        memory
            .read_exact_at(
                &mut byte,
                address + u64::try_from(offset).expect("path offset fits"),
            )
            .map_err(|_| libc::EFAULT)?;
        if byte[0] == 0 {
            return Ok(bytes);
        }
        bytes.push(byte[0]);
    }
    Err(libc::ENAMETOOLONG)
}

fn read_process_bytes(
    pid: u32,
    address: u64,
    length: usize,
    maximum: usize,
) -> Result<Vec<u8>, libc::c_int> {
    if address == 0 || length == 0 || length > maximum {
        return Err(libc::EFAULT);
    }
    let memory = File::open(format!("/proc/{pid}/mem")).map_err(|_| libc::EFAULT)?;
    let mut bytes = vec![0_u8; length];
    memory
        .read_exact_at(&mut bytes, address)
        .map_err(|_| libc::EFAULT)?;
    Ok(bytes)
}

fn write_process_memory(pid: u32, reply: &MetadataReply) -> Result<(), libc::c_int> {
    let memory = OpenOptions::new()
        .write(true)
        .open(format!("/proc/{pid}/mem"))
        .map_err(|_| libc::EFAULT)?;
    memory
        .write_all_at(&reply.bytes, reply.address)
        .map_err(|_| libc::EFAULT)
}

fn io_errno(error: &io::Error) -> libc::c_int {
    error.raw_os_error().unwrap_or(libc::EIO)
}

struct MetadataValues {
    device: u64,
    inode: u64,
    links: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    special_device: u64,
    size: i64,
    block_size: u64,
    blocks: i64,
    atime: i64,
    atime_nanos: i64,
    mtime: i64,
    mtime_nanos: i64,
    ctime: i64,
    ctime_nanos: i64,
}

fn metadata_values(
    metadata: &fs::Metadata,
    canonical: bool,
) -> Result<MetadataValues, libc::c_int> {
    let size = i64::try_from(metadata.size()).map_err(|_| libc::EOVERFLOW)?;
    if canonical {
        let permissions = if metadata.is_file() {
            READ_ONLY_EPOCH_V1_FILE_MODE
        } else if metadata.is_dir() {
            READ_ONLY_EPOCH_V1_DIRECTORY_MODE
        } else {
            return Err(libc::EPERM);
        };
        let blocks = metadata.size().div_ceil(SECTOR_BYTES);
        Ok(MetadataValues {
            device: 0,
            inode: 0,
            links: 1,
            mode: metadata.mode() & libc::S_IFMT | permissions,
            uid: 0,
            gid: 0,
            special_device: 0,
            size,
            block_size: CANONICAL_BLOCK_SIZE,
            blocks: i64::try_from(blocks).map_err(|_| libc::EOVERFLOW)?,
            atime: 0,
            atime_nanos: 0,
            mtime: 0,
            mtime_nanos: 0,
            ctime: 0,
            ctime_nanos: 0,
        })
    } else {
        Ok(MetadataValues {
            device: metadata.dev(),
            inode: metadata.ino(),
            links: metadata.nlink(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            special_device: metadata.rdev(),
            size,
            block_size: metadata.blksize(),
            blocks: i64::try_from(metadata.blocks()).map_err(|_| libc::EOVERFLOW)?,
            atime: metadata.atime(),
            atime_nanos: metadata.atime_nsec(),
            mtime: metadata.mtime(),
            mtime_nanos: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nanos: metadata.ctime_nsec(),
        })
    }
}

fn encode_stat(metadata: &fs::Metadata, canonical: bool) -> Result<Vec<u8>, libc::c_int> {
    let values = metadata_values(metadata, canonical)?;
    let mut bytes = vec![0_u8; std::mem::size_of::<libc::stat>()];
    write_field(
        &mut bytes,
        offset_of!(libc::stat, st_dev),
        values.device.to_ne_bytes(),
    )?;
    write_field(
        &mut bytes,
        offset_of!(libc::stat, st_ino),
        values.inode.to_ne_bytes(),
    )?;
    #[cfg(target_arch = "x86_64")]
    write_field(
        &mut bytes,
        offset_of!(libc::stat, st_nlink),
        values.links.to_ne_bytes(),
    )?;
    #[cfg(target_arch = "aarch64")]
    write_field(
        &mut bytes,
        offset_of!(libc::stat, st_nlink),
        u32::try_from(values.links)
            .map_err(|_| libc::EOVERFLOW)?
            .to_ne_bytes(),
    )?;
    write_field(
        &mut bytes,
        offset_of!(libc::stat, st_mode),
        values.mode.to_ne_bytes(),
    )?;
    write_field(
        &mut bytes,
        offset_of!(libc::stat, st_uid),
        values.uid.to_ne_bytes(),
    )?;
    write_field(
        &mut bytes,
        offset_of!(libc::stat, st_gid),
        values.gid.to_ne_bytes(),
    )?;
    write_field(
        &mut bytes,
        offset_of!(libc::stat, st_rdev),
        values.special_device.to_ne_bytes(),
    )?;
    write_field(
        &mut bytes,
        offset_of!(libc::stat, st_size),
        values.size.to_ne_bytes(),
    )?;
    #[cfg(target_arch = "x86_64")]
    write_field(
        &mut bytes,
        offset_of!(libc::stat, st_blksize),
        i64::try_from(values.block_size)
            .map_err(|_| libc::EOVERFLOW)?
            .to_ne_bytes(),
    )?;
    #[cfg(target_arch = "aarch64")]
    write_field(
        &mut bytes,
        offset_of!(libc::stat, st_blksize),
        i32::try_from(values.block_size)
            .map_err(|_| libc::EOVERFLOW)?
            .to_ne_bytes(),
    )?;
    write_field(
        &mut bytes,
        offset_of!(libc::stat, st_blocks),
        values.blocks.to_ne_bytes(),
    )?;
    for (offset, value) in [
        (offset_of!(libc::stat, st_atime), values.atime),
        (offset_of!(libc::stat, st_atime_nsec), values.atime_nanos),
        (offset_of!(libc::stat, st_mtime), values.mtime),
        (offset_of!(libc::stat, st_mtime_nsec), values.mtime_nanos),
        (offset_of!(libc::stat, st_ctime), values.ctime),
        (offset_of!(libc::stat, st_ctime_nsec), values.ctime_nanos),
    ] {
        write_field(&mut bytes, offset, value.to_ne_bytes())?;
    }
    Ok(bytes)
}

fn encode_statx(metadata: &fs::Metadata, canonical: bool) -> Result<Vec<u8>, libc::c_int> {
    let values = metadata_values(metadata, canonical)?;
    let mut bytes = vec![0_u8; std::mem::size_of::<libc::statx>()];
    let mut mask = libc::STATX_BASIC_STATS;
    if canonical {
        mask |= libc::STATX_BTIME | libc::STATX_MNT_ID;
    }
    write_field(
        &mut bytes,
        offset_of!(libc::statx, stx_mask),
        mask.to_ne_bytes(),
    )?;
    write_field(
        &mut bytes,
        offset_of!(libc::statx, stx_blksize),
        u32::try_from(values.block_size)
            .map_err(|_| libc::EOVERFLOW)?
            .to_ne_bytes(),
    )?;
    write_field(
        &mut bytes,
        offset_of!(libc::statx, stx_nlink),
        u32::try_from(values.links)
            .map_err(|_| libc::EOVERFLOW)?
            .to_ne_bytes(),
    )?;
    write_field(
        &mut bytes,
        offset_of!(libc::statx, stx_uid),
        values.uid.to_ne_bytes(),
    )?;
    write_field(
        &mut bytes,
        offset_of!(libc::statx, stx_gid),
        values.gid.to_ne_bytes(),
    )?;
    write_field(
        &mut bytes,
        offset_of!(libc::statx, stx_mode),
        u16::try_from(values.mode)
            .map_err(|_| libc::EOVERFLOW)?
            .to_ne_bytes(),
    )?;
    write_field(
        &mut bytes,
        offset_of!(libc::statx, stx_ino),
        values.inode.to_ne_bytes(),
    )?;
    write_field(
        &mut bytes,
        offset_of!(libc::statx, stx_size),
        u64::try_from(values.size)
            .map_err(|_| libc::EOVERFLOW)?
            .to_ne_bytes(),
    )?;
    write_field(
        &mut bytes,
        offset_of!(libc::statx, stx_blocks),
        u64::try_from(values.blocks)
            .map_err(|_| libc::EOVERFLOW)?
            .to_ne_bytes(),
    )?;
    write_statx_timestamp(
        &mut bytes,
        offset_of!(libc::statx, stx_atime),
        values.atime,
        values.atime_nanos,
    )?;
    write_statx_timestamp(
        &mut bytes,
        offset_of!(libc::statx, stx_mtime),
        values.mtime,
        values.mtime_nanos,
    )?;
    write_statx_timestamp(
        &mut bytes,
        offset_of!(libc::statx, stx_ctime),
        values.ctime,
        values.ctime_nanos,
    )?;
    write_statx_timestamp(&mut bytes, offset_of!(libc::statx, stx_btime), 0, 0)?;
    if !canonical {
        let (device_major, device_minor) = linux_device_parts(values.device);
        let (special_major, special_minor) = linux_device_parts(values.special_device);
        for (offset, value) in [
            (offset_of!(libc::statx, stx_dev_major), device_major),
            (offset_of!(libc::statx, stx_dev_minor), device_minor),
            (offset_of!(libc::statx, stx_rdev_major), special_major),
            (offset_of!(libc::statx, stx_rdev_minor), special_minor),
        ] {
            write_field(&mut bytes, offset, value.to_ne_bytes())?;
        }
    }
    Ok(bytes)
}

fn write_statx_timestamp(
    bytes: &mut [u8],
    base: usize,
    seconds: i64,
    nanoseconds: i64,
) -> Result<(), libc::c_int> {
    write_field(
        bytes,
        base + offset_of!(libc::statx_timestamp, tv_sec),
        seconds.to_ne_bytes(),
    )?;
    write_field(
        bytes,
        base + offset_of!(libc::statx_timestamp, tv_nsec),
        u32::try_from(nanoseconds)
            .map_err(|_| libc::EOVERFLOW)?
            .to_ne_bytes(),
    )
}

fn linux_device_parts(device: u64) -> (u32, u32) {
    let major = (device >> 8 & 0x0fff) | (device >> 32 & 0xffff_f000);
    let minor = (device & 0x00ff) | (device >> 12 & 0xffff_ff00);
    (
        u32::try_from(major).expect("Linux major device number fits in u32"),
        u32::try_from(minor).expect("Linux minor device number fits in u32"),
    )
}

fn write_field<const N: usize>(
    bytes: &mut [u8],
    offset: usize,
    value: [u8; N],
) -> Result<(), libc::c_int> {
    let destination = bytes
        .get_mut(offset..offset.checked_add(N).ok_or(libc::EOVERFLOW)?)
        .ok_or(libc::EOVERFLOW)?;
    destination.copy_from_slice(&value);
    Ok(())
}

fn decide_execve(
    listener: &OwnedFd,
    notification: seccompy::SeccompNotif,
    policy: &LandlockExecutionPolicy,
    state: &mut NotificationState,
) -> Result<(), SeccompSupervisorError> {
    let caller = Pid::from_raw(
        i32::try_from(notification.pid).map_err(|_| SeccompSupervisorError::Protocol)?,
    );
    let process = read_thread_group_id(caller.as_raw())?;
    let pipe_only_caller = state.pipe_only_process(caller.as_raw())?;
    let supervisor_pid =
        i32::try_from(std::process::id()).map_err(|_| SeccompSupervisorError::Protocol)?;
    let frozen = freeze_related_threads(caller.as_raw(), supervisor_pid)?;
    let allowed = (|| {
        if !check_validity(listener.as_raw_fd(), &notification)
            .map_err(|error| SeccompSupervisorError::Notification(error.to_string()))?
        {
            return Ok(None);
        }
        let path = read_c_string(notification.pid, notification.data.args[0])?;
        if pipe_only_caller
            || !policy.command_allowed(Path::new(&path))
            || state.executions.len() >= MAX_EXECUTIONS
        {
            return Ok(None);
        }
        let arguments = read_exec_arguments(notification.pid, notification.data.args[1])?;
        let working_directory = fs::read_link(format!("/proc/{}/cwd", notification.pid))?
            .into_os_string()
            .into_string()
            .map_err(|_| SeccompSupervisorError::Protocol)?;
        let executable_sha256 = executable_digest(Path::new(&path))?;
        Ok(Some(SeccompExecutedCommand {
            executable: path,
            arguments,
            working_directory,
            executable_sha256,
        }))
    })();
    match allowed {
        Ok(Some(execution)) => {
            if let Err(error) = ptrace::seize(caller, ptrace::Options::PTRACE_O_TRACEEXEC) {
                let _ = send_response(
                    listener.as_raw_fd(),
                    fail_syscall(notification, errno_code(libc::EPERM)),
                );
                detach_all(&frozen);
                return Err(SeccompSupervisorError::Freeze(error.to_string()));
            }
            send_response(listener.as_raw_fd(), continue_syscall(notification))
                .map_err(|error| SeccompSupervisorError::Notification(error.to_string()))?;
            let boundary = wait_for_exec_boundary(caller);
            let _ = ptrace::detach(caller, None);
            detach_all(&frozen);
            boundary?;
            state
                .process_executables
                .insert(process, execution.executable.clone());
            state.executions.push(execution);
            Ok(())
        }
        Ok(None) => {
            send_response(
                listener.as_raw_fd(),
                fail_syscall(notification, errno_code(libc::EACCES)),
            )
            .map_err(|error| SeccompSupervisorError::Notification(error.to_string()))?;
            detach_all(&frozen);
            Ok(())
        }
        Err(error) => {
            let _ = send_response(
                listener.as_raw_fd(),
                fail_syscall(notification, errno_code(libc::EPERM)),
            );
            detach_all(&frozen);
            Err(error)
        }
    }
}

impl SeccompExecutionReport {
    fn new(
        policy: &LandlockExecutionPolicy,
        status: ExitStatus,
        executions: Vec<SeccompExecutedCommand>,
    ) -> Result<Self, SeccompSupervisorError> {
        let mut report = Self {
            schema: 1,
            landlock_policy_digest: policy.digest.clone(),
            executions,
            exit_code: exit_status_code(status),
            digest: String::new(),
        };
        report.digest = report.recompute_digest()?;
        report.verify(policy, report.exit_code)?;
        Ok(report)
    }

    pub fn from_json(input: &[u8]) -> Result<Self, SeccompSupervisorError> {
        if input.is_empty() || input.len() > MAX_REPORT_JSON_BYTES {
            return Err(SeccompSupervisorError::InvalidReport);
        }
        let report: Self = serde_json::from_slice(input)?;
        if canonical::jcs_bytes(&report)? != input {
            return Err(SeccompSupervisorError::InvalidReport);
        }
        Ok(report)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SeccompSupervisorError> {
        let bytes = canonical::jcs_bytes(self)?;
        if bytes.len() > MAX_REPORT_JSON_BYTES {
            return Err(SeccompSupervisorError::InvalidReport);
        }
        Ok(bytes)
    }

    pub fn verify(
        &self,
        policy: &LandlockExecutionPolicy,
        exit_code: i32,
    ) -> Result<(), SeccompSupervisorError> {
        let valid = self.schema == 1
            && self.landlock_policy_digest == policy.digest
            && self.exit_code == exit_code
            && !self.executions.is_empty()
            && self.executions.len() <= MAX_EXECUTIONS
            && self.executions.iter().all(|execution| {
                policy.command_allowed(Path::new(&execution.executable))
                    && Path::new(&execution.working_directory).is_absolute()
                    && execution.arguments.len() <= MAX_EXEC_ARGUMENTS
                    && execution.arguments.iter().map(String::len).sum::<usize>()
                        <= MAX_EXEC_ARGUMENT_BYTES
                    && is_digest(&execution.executable_sha256)
            })
            && self.recompute_digest()? == self.digest;
        if valid {
            Ok(())
        } else {
            Err(SeccompSupervisorError::InvalidReport)
        }
    }

    fn recompute_digest(&self) -> Result<String, SeccompSupervisorError> {
        Ok(hex::encode(canonical::domain_hash(
            b"rust-agent-seccomp-execution-report-v1\0",
            &SeccompExecutionReportProjection {
                schema: self.schema,
                landlock_policy_digest: &self.landlock_policy_digest,
                executions: &self.executions,
                exit_code: self.exit_code,
            },
        )?))
    }
}

fn exit_status_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(125)
}

fn executable_digest(path: &Path) -> Result<String, SeccompSupervisorError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(SeccompSupervisorError::Protocol);
    }
    let bytes = fs::read(path)?;
    if !bytes.starts_with(b"\x7fELF") {
        return Err(SeccompSupervisorError::Protocol);
    }
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn read_exec_arguments(pid: u32, address: u64) -> Result<Vec<String>, SeccompSupervisorError> {
    if address == 0 {
        return Err(SeccompSupervisorError::Protocol);
    }
    let memory = File::open(format!("/proc/{pid}/mem"))?;
    let mut arguments = Vec::new();
    let mut total = 0_usize;
    for index in 0..=MAX_EXEC_ARGUMENTS {
        let mut pointer = [0_u8; std::mem::size_of::<u64>()];
        let offset = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(pointer.len() as u64))
            .and_then(|offset| address.checked_add(offset))
            .ok_or(SeccompSupervisorError::Protocol)?;
        memory.read_exact_at(&mut pointer, offset)?;
        let pointer = u64::from_ne_bytes(pointer);
        if pointer == 0 {
            return if arguments.is_empty() {
                Err(SeccompSupervisorError::Protocol)
            } else {
                Ok(arguments)
            };
        }
        if index == MAX_EXEC_ARGUMENTS {
            return Err(SeccompSupervisorError::Protocol);
        }
        let argument = read_c_string_from(&memory, pointer, MAX_EXEC_ARGUMENT_BYTES - total)?;
        total = total
            .checked_add(argument.len())
            .ok_or(SeccompSupervisorError::Protocol)?;
        arguments.push(argument);
    }
    Err(SeccompSupervisorError::Protocol)
}

fn freeze_related_threads(
    caller_tid: i32,
    supervisor_pid: i32,
) -> Result<Vec<Pid>, SeccompSupervisorError> {
    let mut frozen = Vec::new();
    let mut seen = BTreeSet::from([caller_tid, supervisor_pid]);
    let mut process_groups = vec![caller_tid];
    let parent = read_parent_pid(caller_tid)?;
    if parent > 0 && parent != supervisor_pid {
        process_groups.push(parent);
    }
    loop {
        let mut discovered = false;
        for process in &process_groups {
            for tid in list_threads(*process)? {
                if !seen.insert(tid) {
                    continue;
                }
                if *process == parent && vfork_parent_is_kernel_suspended(tid) {
                    continue;
                }
                discovered = true;
                let pid = Pid::from_raw(tid);
                match ptrace::seize(pid, ptrace::Options::empty()) {
                    Ok(()) => {}
                    Err(Errno::ESRCH) => continue,
                    Err(error) => {
                        detach_all(&frozen);
                        return Err(SeccompSupervisorError::Freeze(error.to_string()));
                    }
                }
                if let Err(error) = ptrace::interrupt(pid) {
                    let _ = ptrace::detach(pid, None);
                    if error == Errno::ESRCH {
                        continue;
                    }
                    detach_all(&frozen);
                    return Err(SeccompSupervisorError::Freeze(error.to_string()));
                }
                if wait_for_ptrace_stop(pid)? {
                    frozen.push(pid);
                }
            }
        }
        if !discovered {
            return Ok(frozen);
        }
    }
}

fn vfork_parent_is_kernel_suspended(tid: i32) -> bool {
    let Ok(syscall) = fs::read_to_string(format!("/proc/{tid}/syscall")) else {
        return false;
    };
    let mut fields = syscall.split_whitespace();
    let Some(number) = fields.next().and_then(parse_proc_integer) else {
        return false;
    };
    if number == libc::SYS_vfork as u64 {
        return true;
    }
    if number != libc::SYS_clone as u64 {
        return false;
    }
    fields
        .next()
        .and_then(parse_proc_integer)
        .is_some_and(|flags| {
            flags & (libc::CLONE_VM | libc::CLONE_VFORK) as u64
                == (libc::CLONE_VM | libc::CLONE_VFORK) as u64
        })
}

fn parse_proc_integer(value: &str) -> Option<u64> {
    value.strip_prefix("0x").map_or_else(
        || value.parse().ok(),
        |hex| u64::from_str_radix(hex, 16).ok(),
    )
}

fn read_parent_pid(tid: i32) -> Result<i32, SeccompSupervisorError> {
    let status = fs::read_to_string(format!("/proc/{tid}/status"))?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:\t"))
        .and_then(|value| value.trim().parse().ok())
        .ok_or(SeccompSupervisorError::Protocol)
}

fn wait_for_ptrace_stop(pid: Pid) -> Result<bool, SeccompSupervisorError> {
    let deadline = Instant::now() + FREEZE_TIMEOUT;
    loop {
        match waitpid(pid, Some(WaitPidFlag::__WALL | WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Stopped(_, _) | WaitStatus::PtraceEvent(_, _, _)) => return Ok(true),
            Ok(WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _))
            | Err(Errno::ECHILD | Errno::ESRCH) => return Ok(false),
            Ok(_) => {}
            Err(error) => return Err(SeccompSupervisorError::Freeze(error.to_string())),
        }
        if Instant::now() >= deadline {
            let _ = ptrace::detach(pid, None);
            return Err(SeccompSupervisorError::Freeze(format!(
                "thread {pid} did not enter ptrace stop"
            )));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn list_threads(tid: i32) -> Result<Vec<i32>, SeccompSupervisorError> {
    let mut tids = Vec::new();
    for entry in fs::read_dir(format!("/proc/{tid}/task"))? {
        let entry = entry?;
        if let Some(tid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        {
            tids.push(tid);
        }
    }
    tids.sort_unstable();
    Ok(tids)
}

fn detach_all(tids: &[Pid]) {
    for tid in tids {
        let _ = ptrace::detach(*tid, None);
    }
}

fn wait_for_exec_boundary(caller: Pid) -> Result<(), SeccompSupervisorError> {
    let deadline = Instant::now() + FREEZE_TIMEOUT;
    loop {
        match waitpid(caller, Some(WaitPidFlag::__WALL | WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::PtraceEvent(_, _, libc::PTRACE_EVENT_EXEC)) => return Ok(()),
            Ok(WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _))
            | Err(Errno::ECHILD | Errno::ESRCH) => {
                return Err(SeccompSupervisorError::Freeze(format!(
                    "exec caller {caller} exited before a confirmed exec boundary"
                )));
            }
            Ok(WaitStatus::Stopped(_, signal)) => {
                ptrace::cont(caller, signal).map_err(|error| {
                    SeccompSupervisorError::Freeze(format!(
                        "could not continue exec caller {caller}: {error}"
                    ))
                })?;
            }
            Ok(_) => {}
            Err(error) => return Err(SeccompSupervisorError::Freeze(error.to_string())),
        }
        if Instant::now() >= deadline {
            let _ = nix::sys::signal::kill(caller, nix::sys::signal::Signal::SIGKILL);
            return Err(SeccompSupervisorError::Freeze(format!(
                "exec caller {caller} did not reach a confirmed exec boundary"
            )));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn read_c_string(pid: u32, address: u64) -> Result<String, SeccompSupervisorError> {
    if address == 0 {
        return Err(SeccompSupervisorError::Protocol);
    }
    let memory = File::open(format!("/proc/{pid}/mem"))?;
    read_c_string_from(&memory, address, MAX_EXEC_PATH_BYTES)
}

fn read_c_string_from(
    memory: &File,
    address: u64,
    maximum: usize,
) -> Result<String, SeccompSupervisorError> {
    if address == 0 || maximum == 0 {
        return Err(SeccompSupervisorError::Protocol);
    }
    let mut bytes = Vec::with_capacity(128);
    for offset in 0..maximum {
        let mut byte = [0_u8; 1];
        memory.read_exact_at(&mut byte, address + offset as u64)?;
        if byte[0] == 0 {
            return String::from_utf8(bytes).map_err(|_| SeccompSupervisorError::Protocol);
        }
        bytes.push(byte[0]);
    }
    Err(SeccompSupervisorError::Protocol)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn reject_preexisting_shared_writable_mappings() -> Result<(), SeccompSupervisorError> {
    let maps = fs::read_to_string("/proc/self/maps")?;
    if maps.lines().any(|line| {
        line.split_whitespace()
            .nth(1)
            .is_some_and(|permissions| permissions.len() >= 4 && &permissions[1..4] == "w-s")
    }) {
        Err(SeccompSupervisorError::Setup(
            "launcher has a pre-existing shared writable mapping".into(),
        ))
    } else {
        Ok(())
    }
}

fn reject_inherited_nonstandard_descriptors() -> Result<(), SeccompSupervisorError> {
    let descriptors = fs::read_dir("/proc/self/fd")?
        .map(|entry| {
            entry?
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<i32>().ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid descriptor"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if descriptors.into_iter().any(|descriptor| {
        descriptor > 2 && fs::metadata(format!("/proc/self/fd/{descriptor}")).is_ok()
    }) {
        Err(SeccompSupervisorError::Setup(
            "launcher inherited a nonstandard file descriptor".into(),
        ))
    } else {
        Ok(())
    }
}

fn send_descriptor(
    socket: &UnixStream,
    descriptor: &OwnedFd,
) -> Result<(), SeccompSupervisorError> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    let descriptors = [descriptor.as_fd()];
    if !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors)) {
        return Err(SeccompSupervisorError::Protocol);
    }
    let payload = [1_u8];
    let sent = sendmsg(
        socket,
        &[IoSlice::new(&payload)],
        &mut ancillary,
        SendFlags::empty(),
    )
    .map_err(rustix_error)?;
    if sent == payload.len() {
        Ok(())
    } else {
        Err(SeccompSupervisorError::Protocol)
    }
}

fn receive_descriptor(socket: &UnixStream) -> Result<OwnedFd, SeccompSupervisorError> {
    let mut payload = [0_u8; 1];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = {
        let mut iov = [IoSliceMut::new(&mut payload)];
        recvmsg(socket, &mut iov, &mut ancillary, RecvFlags::empty()).map_err(rustix_error)?
    };
    if received.bytes != 1 || payload != [1] {
        return Err(SeccompSupervisorError::Protocol);
    }
    for message in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(mut descriptors) = message
            && let Some(descriptor) = descriptors.next()
        {
            if descriptors.next().is_some() {
                return Err(SeccompSupervisorError::Protocol);
            }
            return Ok(descriptor);
        }
    }
    Err(SeccompSupervisorError::Protocol)
}

fn rustix_error(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FilterInput {
        architecture: u32,
        syscall: u32,
        arguments: [u32; 6],
    }

    #[test]
    fn conditional_filter_rejects_shared_vm_escape_primitives() {
        let allow = u32::from(FilterAction::Allow);
        let deny = u32::from(FilterAction::Errno {
            errno: errno_code(libc::EPERM),
        });
        let architecture = Architecture::compile_time_arch() as u32;

        assert_eq!(
            evaluate(&FilterInput::new(architecture, libc::SYS_getpid)),
            allow
        );
        assert_eq!(
            evaluate(&FilterInput::new(architecture, libc::SYS_mmap)),
            allow
        );
        let mut shared_mapping = FilterInput::new(architecture, libc::SYS_mmap);
        shared_mapping.arguments[3] =
            u32::try_from(libc::MAP_SHARED).expect("MAP_SHARED is non-negative");
        assert_eq!(evaluate(&shared_mapping), deny);

        let mut separate_clone = FilterInput::new(architecture, libc::SYS_clone);
        separate_clone.arguments[0] =
            u32::try_from(libc::SIGCHLD).expect("SIGCHLD is non-negative");
        assert_eq!(evaluate(&separate_clone), allow);
        let mut unsafe_shared_vm = FilterInput::new(architecture, libc::SYS_clone);
        unsafe_shared_vm.arguments[0] =
            u32::try_from(libc::CLONE_VM).expect("CLONE_VM is non-negative");
        assert_eq!(evaluate(&unsafe_shared_vm), deny);
        let mut thread_clone = FilterInput::new(architecture, libc::SYS_clone);
        thread_clone.arguments[0] = u32::try_from(libc::CLONE_VM | libc::CLONE_THREAD)
            .expect("clone flags are non-negative");
        assert_eq!(evaluate(&thread_clone), allow);
        let mut vfork_clone = FilterInput::new(architecture, libc::SYS_clone);
        vfork_clone.arguments[0] = u32::try_from(libc::CLONE_VM | libc::CLONE_VFORK)
            .expect("clone flags are non-negative");
        assert_eq!(evaluate(&vfork_clone), allow);

        assert_eq!(
            evaluate(&FilterInput::new(architecture ^ 1, libc::SYS_getpid)),
            u32::from(FilterAction::KillProcess)
        );
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            evaluate(&FilterInput::raw(
                architecture,
                syscall_number(libc::SYS_getpid) | X32_SYSCALL_BIT,
            )),
            deny
        );
    }

    #[test]
    fn nscd_probe_match_uses_kernel_pathname_semantics() {
        const PATH: &[u8] = b"/var/run/nscd/socket\0";
        let family = u16::try_from(libc::AF_UNIX).unwrap().to_ne_bytes();
        let mut address = vec![0_u8; std::mem::size_of::<libc::sockaddr_un>()];
        address[..2].copy_from_slice(&family);
        address[2..2 + PATH.len()].copy_from_slice(PATH);

        assert!(exact_nscd_socket_address(&address[..2 + PATH.len()]));
        address[2 + PATH.len()..].fill(0xa5);
        assert!(exact_nscd_socket_address(&address));

        let mut wrong_path = address.clone();
        wrong_path[2 + PATH.len() - 2] = b'x';
        assert!(!exact_nscd_socket_address(&wrong_path));
        let mut abstract_address = address.clone();
        abstract_address[2] = 0;
        assert!(!exact_nscd_socket_address(&abstract_address));
        assert!(!exact_nscd_socket_address(&address[..2 + PATH.len() - 1]));

        let mut oversized = address;
        oversized.push(0);
        assert!(!exact_nscd_socket_address(&oversized));
    }

    #[test]
    fn anonymous_socketpair_shapes_are_exact_and_class_scoped() {
        use LinuxSandboxAnonymousSocketpair::{RustSpawnError, StreamWakeup};

        assert!(anonymous_socketpair_shape_allowed(
            libc::AF_UNIX,
            libc::SOCK_STREAM,
            0,
            &[StreamWakeup]
        ));
        assert!(anonymous_socketpair_shape_allowed(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
            &[StreamWakeup]
        ));
        assert!(!anonymous_socketpair_shape_allowed(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            &[StreamWakeup]
        ));
        assert!(anonymous_socketpair_shape_allowed(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            &[RustSpawnError]
        ));
        for socket_type in [
            libc::SOCK_SEQPACKET,
            libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
        ] {
            assert!(!anonymous_socketpair_shape_allowed(
                libc::AF_UNIX,
                socket_type,
                0,
                &[RustSpawnError]
            ));
        }
        assert!(!anonymous_socketpair_shape_allowed(
            libc::AF_INET,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            &[RustSpawnError]
        ));
        assert!(!anonymous_socketpair_shape_allowed(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            libc::IPPROTO_TCP,
            &[RustSpawnError]
        ));
    }

    impl FilterInput {
        fn new(architecture: u32, syscall: libc::c_long) -> Self {
            Self {
                architecture,
                syscall: syscall_number(syscall),
                arguments: [0; 6],
            }
        }

        fn raw(architecture: u32, syscall: u32) -> Self {
            Self {
                architecture,
                syscall,
                arguments: [0; 6],
            }
        }
    }

    fn evaluate(input: &FilterInput) -> u32 {
        let program = conditional_safety_filter();
        let mut accumulator = 0_u32;
        let mut pc = 0_usize;
        loop {
            let instruction = program.get(pc).expect("BPF program returns");
            let code = u32::from(instruction.code);
            if code == (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) {
                accumulator = load_filter_word(input, usize::try_from(instruction.k).unwrap());
                pc += 1;
            } else if code == (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) {
                pc += 1 + usize::from(if accumulator == instruction.k {
                    instruction.jt
                } else {
                    instruction.jf
                });
            } else if code == (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) {
                pc += 1 + usize::from(if accumulator & instruction.k != 0 {
                    instruction.jt
                } else {
                    instruction.jf
                });
            } else if code == (libc::BPF_RET | libc::BPF_K) {
                return instruction.k;
            } else {
                panic!("unexpected BPF opcode {code:#x}");
            }
        }
    }

    fn load_filter_word(input: &FilterInput, offset: usize) -> u32 {
        if offset == offset_of!(libc::seccomp_data, nr) {
            input.syscall
        } else if offset == offset_of!(libc::seccomp_data, arch) {
            input.architecture
        } else {
            let arguments = offset_of!(libc::seccomp_data, args);
            let index = offset
                .checked_sub(arguments)
                .filter(|offset| offset % size_of_u64() == 0)
                .map(|offset| offset / size_of_u64())
                .expect("filter only loads aligned seccomp arguments");
            input.arguments[index]
        }
    }
}
