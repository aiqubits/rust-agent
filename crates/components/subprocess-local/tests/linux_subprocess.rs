#![cfg(target_os = "linux")]

use std::{
    fs,
    future::Future,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    path::Path,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
    thread,
};

use rust_agent_core::{Digest, SecurityEffects};
use rust_agent_fs::AgentPath;
use rust_agent_policy::process::{
    FilesystemAccess, NetworkAccess, ProcessResourceLimits, SandboxPolicy, SandboxPolicyCeiling,
};
use rust_agent_process::{
    ConfinementAuthority, ConfinementIssuerBinding, ConfinementVerifierBinding, ProcessEnvironment,
    ProcessError, ProcessExecutable, ProcessExit, ProcessSpec, SandboxBinding, SubprocessBinding,
    TerminalBytes, TerminalReadRequest, TerminalSize,
};
use rust_agent_runtime_api::{
    CancellationToken, RuntimePrimitiveBindings, RuntimePrimitiveKind, Shutdown,
};
use rust_agent_subprocess_local::{Config, Dependencies, RuntimeSymlink};
use sha2::{Digest as _, Sha256};

struct ThreadWake(thread::Thread);

impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
    let mut context = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => thread::park(),
        }
    }
}

fn sha256(path: &Path) -> String {
    let digest: [u8; 32] = Sha256::digest(fs::read(path).unwrap()).into();
    Digest::from_bytes(digest).to_lower_hex()
}

fn policy(filesystem: FilesystemAccess, output: usize, wall_millis: u64) -> SandboxPolicy {
    SandboxPolicy::new(
        filesystem,
        NetworkAccess::Deny,
        ProcessResourceLimits::checked(
            NonZeroU32::new(32).unwrap(),
            NonZeroU64::new(512 * 1024 * 1024).unwrap(),
            NonZeroUsize::new(output).unwrap(),
            NonZeroU64::new(wall_millis).unwrap(),
        )
        .unwrap(),
    )
}

fn process(executable: &str, arguments: &[&str], input: &[u8]) -> ProcessSpec {
    ProcessSpec::checked(
        ProcessExecutable::absolute(executable).unwrap(),
        arguments.iter().map(|value| (*value).to_owned()),
        AgentPath::root(),
        ProcessEnvironment::empty(),
        input.to_vec(),
    )
    .unwrap()
}

fn terminal_process(executable: &str, size: TerminalSize) -> ProcessSpec {
    ProcessSpec::checked_terminal(
        ProcessExecutable::absolute(executable).unwrap(),
        std::iter::empty(),
        AgentPath::root(),
        ProcessEnvironment::checked([("TERM".to_owned(), "xterm".to_owned())]).unwrap(),
        size,
    )
    .unwrap()
}

fn bindings(
    config: &Config,
    ceiling: SandboxPolicy,
) -> (SandboxBinding, SubprocessBinding, Arc<dyn Shutdown>) {
    let (issuer, verifier) = ConfinementAuthority::new(SandboxPolicyCeiling::new(ceiling)).unwrap();
    let sandbox = rust_agent_sandbox_linux::build(
        &rust_agent_sandbox_linux::Config,
        rust_agent_sandbox_linux::Dependencies {
            confinement_issuer: ConfinementIssuerBinding::from_generated_authority(issuer),
        },
        RuntimePrimitiveBindings::none(),
    )
    .unwrap()
    .into_service();
    let runtime = rust_agent_runtime_tokio::create_runtime_primitives().unwrap();
    let subprocess = rust_agent_subprocess_local::build(
        config,
        Dependencies {
            confinement_verifier: ConfinementVerifierBinding::from_generated_authority(verifier),
        },
        RuntimePrimitiveBindings::projected(
            runtime,
            &[RuntimePrimitiveKind::Clock, RuntimePrimitiveKind::Sleep],
        )
        .unwrap(),
    )
    .unwrap();
    block_on(subprocess.initializer().unwrap().initialize()).unwrap();
    let subprocess_service = subprocess.service().clone();
    let shutdown = subprocess.shutdown_hook().unwrap().clone();
    (
        SandboxBinding::from_generated_component(
            "sandbox-linux",
            SecurityEffects::empty(),
            sandbox,
        )
        .unwrap(),
        SubprocessBinding::from_generated_component(
            "subprocess-local",
            SecurityEffects::READ_LOCAL
                | SecurityEffects::WRITE_LOCAL
                | SecurityEffects::PROCESS_EXEC,
            subprocess_service,
        )
        .unwrap(),
        shutdown,
    )
}

#[test]
#[ignore = "requires Landlock and an enabled unprivileged bubblewrap namespace runner"]
fn real_linux_subprocess_enforces_anchor_handshake_budget_and_cancellation() {
    let owner = tempfile::tempdir().unwrap();
    let workspace = owner.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("value.txt"), b"anchored").unwrap();
    let launcher = Path::new(env!("CARGO_BIN_EXE_rust-agent-subprocess-launcher"));
    let bubblewrap = Path::new("/usr/bin/bwrap");
    let dynamic_loader = fs::canonicalize("/lib64/ld-linux-x86-64.so.2").unwrap();
    let config = Config::checked(
        workspace.to_str().unwrap(),
        bubblewrap.to_str().unwrap(),
        sha256(bubblewrap),
        launcher.to_str().unwrap(),
        sha256(launcher),
        vec!["/usr/lib".into(), "/usr/lib64".into()],
        vec![dynamic_loader.to_str().unwrap().into()],
        vec![
            RuntimeSymlink::checked("/lib", "usr/lib").unwrap(),
            RuntimeSymlink::checked("/lib64", "usr/lib64").unwrap(),
        ],
    )
    .unwrap();
    let ceiling = policy(FilesystemAccess::ReadWrite, 4096, 30_000);
    let (sandbox, subprocess, shutdown) = bindings(&config, ceiling.clone());

    let moved = owner.path().join("workspace-moved");
    fs::rename(&workspace, &moved).unwrap();
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("value.txt"), b"replacement").unwrap();
    let read_policy = policy(FilesystemAccess::ReadOnly, 1024, 10_000);
    let confined =
        block_on(sandbox.confine(process("/usr/bin/cat", &["value.txt"], b""), read_policy))
            .unwrap();
    let handle = block_on(subprocess.spawn(confined, CancellationToken::new())).unwrap();
    assert!(
        handle
            .enforcement_report()
            .applied_primitives()
            .contains(rust_agent_policy::process::EnforcementPrimitives::LANDLOCK)
    );
    let output = block_on(handle.wait(CancellationToken::new())).unwrap();
    assert_eq!(output.exit(), ProcessExit::Code(0));
    assert_eq!(output.stdout(), b"anchored");

    let tiny = policy(FilesystemAccess::None, 64, 10_000);
    let confined = block_on(sandbox.confine(process("/usr/bin/yes", &[], b""), tiny)).unwrap();
    let handle = block_on(subprocess.spawn(confined, CancellationToken::new())).unwrap();
    assert_eq!(
        block_on(handle.wait(CancellationToken::new())).unwrap_err(),
        ProcessError::OutputBudgetExceeded
    );

    let confined =
        block_on(sandbox.confine(process("/usr/bin/sleep", &["10"], b""), ceiling.clone()))
            .unwrap();
    let handle = block_on(subprocess.spawn(confined, CancellationToken::new())).unwrap();
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert_eq!(
        block_on(handle.wait(cancellation)).unwrap_err(),
        ProcessError::Cancelled
    );
    assert_eq!(
        block_on(handle.wait(CancellationToken::new())).unwrap_err(),
        ProcessError::Cancelled
    );
    assert_eq!(block_on(handle.terminate_tree()), Ok(()));

    let shell = fs::canonicalize("/bin/sh").unwrap();
    let initial_size = TerminalSize::checked(80, 24).unwrap();
    let confined = block_on(sandbox.confine(
        terminal_process(shell.to_str().unwrap(), initial_size),
        ceiling.clone(),
    ))
    .unwrap();
    let handle = block_on(subprocess.spawn(confined, CancellationToken::new())).unwrap();
    assert!(handle.is_terminal());
    block_on(handle.resize_terminal(TerminalSize::checked(101, 31).unwrap())).unwrap();
    block_on(
        handle.write_terminal(
            TerminalBytes::checked(
                b"test -t 0 && test -t 1 && test -t 2 && echo tty-ok; stty size; exit\n".to_vec(),
            )
            .unwrap(),
        ),
    )
    .unwrap();
    let mut terminal_output = Vec::new();
    for _ in 0..100 {
        let bytes = block_on(handle.read_terminal(
            TerminalReadRequest::checked(NonZeroUsize::new(4096).unwrap()).unwrap(),
        ))
        .unwrap();
        terminal_output.extend_from_slice(bytes.as_slice());
        if terminal_output
            .windows(b"tty-ok".len())
            .any(|window| window == b"tty-ok")
            && terminal_output
                .windows(b"31 101".len())
                .any(|window| window == b"31 101")
        {
            break;
        }
        thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        terminal_output
            .windows(b"tty-ok".len())
            .any(|window| window == b"tty-ok")
    );
    assert!(
        terminal_output
            .windows(b"31 101".len())
            .any(|window| window == b"31 101")
    );
    assert_eq!(
        block_on(handle.wait(CancellationToken::new()))
            .unwrap()
            .exit(),
        ProcessExit::Code(0)
    );

    let confined =
        block_on(sandbox.confine(process("/usr/bin/sleep", &["10"], b""), ceiling)).unwrap();
    let handle = block_on(subprocess.spawn(confined, CancellationToken::new())).unwrap();
    assert_eq!(block_on(shutdown.shutdown()), Ok(()));
    assert_eq!(
        block_on(handle.wait(CancellationToken::new())).unwrap_err(),
        ProcessError::Cancelled
    );
}
