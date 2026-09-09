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
};
use rust_agent_runtime_api::{CancellationToken, RuntimePrimitiveBindings, RuntimePrimitiveKind};
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

fn bindings(config: &Config, ceiling: SandboxPolicy) -> (SandboxBinding, SubprocessBinding) {
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
    .unwrap()
    .into_service();
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
            subprocess,
        )
        .unwrap(),
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
    let (sandbox, subprocess) = bindings(&config, ceiling.clone());

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
        block_on(sandbox.confine(process("/usr/bin/sleep", &["10"], b""), ceiling)).unwrap();
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
}
