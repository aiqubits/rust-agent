use std::{
    future::Future,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

use rust_agent_core::Digest;
use rust_agent_fs::AgentPath;
use rust_agent_policy::process::{
    FilesystemAccess, NetworkAccess, ProcessResourceLimits, SandboxPolicy, SandboxPolicyCeiling,
};
use rust_agent_process::{
    ConfinedProcessSpec, ConfinementAuthority, ConfinementIssuerBinding,
    ConfinementVerifierBinding, EnforcementReport, ProcessControl, ProcessEnvironment,
    ProcessError, ProcessExit, Sandbox, SandboxError, ShellBinding, Subprocess,
    VerifiedProcessSpec,
};
use rust_agent_runtime_api::RuntimePrimitiveKind;
use rust_agent_sandbox_linux::{Config as SandboxConfig, Dependencies as SandboxDependencies};

use super::*;

fn ready<T>(mut future: ProcessFuture<'_, T>) -> T {
    let mut context = Context::from_waker(Waker::noop());
    match Future::poll(future.as_mut(), &mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("test future unexpectedly pending"),
    }
}

fn policy(output: usize) -> SandboxPolicy {
    SandboxPolicy::new(
        FilesystemAccess::ReadWrite,
        NetworkAccess::Deny,
        ProcessResourceLimits::checked(
            NonZeroU32::new(2).unwrap(),
            NonZeroU64::new(256 * 1024 * 1024).unwrap(),
            NonZeroUsize::new(output).unwrap(),
            NonZeroU64::new(30_000).unwrap(),
        )
        .unwrap(),
    )
}

fn request(command: &str, output: usize) -> ShellRequest {
    ShellRequest::checked(
        command,
        AgentPath::new("workspace/subdir").unwrap(),
        ProcessEnvironment::checked([
            ("LANG".to_owned(), "C".to_owned()),
            ("MODE".to_owned(), "test".to_owned()),
        ])
        .unwrap(),
        b"input".to_vec(),
        policy(output),
    )
    .unwrap()
}

#[derive(Debug)]
struct FakeControl {
    output: ProcessOutput,
    waits: AtomicUsize,
    terminations: Arc<AtomicUsize>,
    wait_error: Mutex<Option<ProcessError>>,
}

impl ProcessControl for FakeControl {
    fn wait(
        &self,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ProcessOutput, ProcessError>> {
        self.waits.fetch_add(1, Ordering::SeqCst);
        let result = if cancellation.is_cancelled() {
            Err(ProcessError::Cancelled)
        } else if let Some(error) = self
            .wait_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            Err(error)
        } else {
            Ok(self.output.clone())
        };
        Box::pin(async move { result })
    }

    fn terminate_tree(&self) -> ProcessFuture<'_, Result<(), ProcessError>> {
        self.terminations.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

#[derive(Debug)]
struct FakeSubprocess {
    verifier: ConfinementVerifierBinding,
    spawns: AtomicUsize,
    observed: Mutex<Vec<ObservedProcess>>,
    terminations: Arc<AtomicUsize>,
    invalid_report: AtomicBool,
    spawn_error: Mutex<Option<ProcessError>>,
    wait_error: Mutex<Option<ProcessError>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedProcess {
    executable: String,
    arguments: Vec<String>,
    cwd: AgentPath,
    environment: ProcessEnvironment,
    stdin: Vec<u8>,
}

impl FakeSubprocess {
    fn new(verifier: ConfinementVerifierBinding) -> Self {
        Self {
            verifier,
            spawns: AtomicUsize::new(0),
            observed: Mutex::new(Vec::new()),
            terminations: Arc::new(AtomicUsize::new(0)),
            invalid_report: AtomicBool::new(false),
            spawn_error: Mutex::new(None),
            wait_error: Mutex::new(None),
        }
    }

    fn handle(&self, verified: &VerifiedProcessSpec) -> Result<ProcessHandle, ProcessError> {
        let output_budget = verified
            .effective_policy()
            .limits()
            .max_output_bytes()
            .get();
        let report = EnforcementReport::after_child_setup(
            if self.invalid_report.load(Ordering::SeqCst) {
                Digest::from_bytes([9; 32])
            } else {
                verified.policy_digest()
            },
            verified.backend_plan().kind(),
            verified.backend_plan().required_primitives(),
            41,
        )?;
        let control = Arc::new(FakeControl {
            output: ProcessOutput::checked(
                ProcessExit::Code(0),
                b"stdout".to_vec(),
                b"stderr".to_vec(),
                output_budget,
            )?,
            waits: AtomicUsize::new(0),
            terminations: Arc::clone(&self.terminations),
            wait_error: Mutex::new(
                self.wait_error
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take(),
            ),
        });
        ProcessHandle::from_enforced(report, output_budget, control)
    }
}

impl Subprocess for FakeSubprocess {
    fn provider_key(&self) -> CanonicalId {
        CanonicalId::new("fake-subprocess").unwrap()
    }

    fn effects(&self) -> SecurityEffects {
        SecurityEffects::READ_LOCAL | SecurityEffects::WRITE_LOCAL | SecurityEffects::PROCESS_EXEC
    }

    fn spawn(
        &self,
        spec: ConfinedProcessSpec,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ProcessHandle, ProcessError>> {
        self.spawns.fetch_add(1, Ordering::SeqCst);
        let result = if cancellation.is_cancelled() {
            Err(ProcessError::Cancelled)
        } else if let Some(error) = self
            .spawn_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            Err(error)
        } else {
            self.verifier.verify(spec).and_then(|verified| {
                self.observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(ObservedProcess {
                        executable: verified.process().executable().as_str().to_owned(),
                        arguments: verified
                            .process()
                            .arguments()
                            .iter()
                            .map(ToString::to_string)
                            .collect(),
                        cwd: verified.process().cwd().clone(),
                        environment: verified.process().environment().clone(),
                        stdin: verified.process().stdin().to_vec(),
                    });
                self.handle(&verified)
            })
        };
        Box::pin(async move { result })
    }
}

#[derive(Debug)]
struct RejectingSandbox {
    calls: Arc<AtomicUsize>,
}

impl Sandbox for RejectingSandbox {
    fn provider_key(&self) -> CanonicalId {
        CanonicalId::new("rejecting-sandbox").unwrap()
    }

    fn effects(&self) -> SecurityEffects {
        SecurityEffects::empty()
    }

    fn confine(
        &self,
        _process: ProcessSpec,
        _policy: SandboxPolicy,
    ) -> ProcessFuture<'_, Result<ConfinedProcessSpec, SandboxError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(SandboxError::UnsupportedPolicy) })
    }
}

fn bindings() -> (ShellBinding, Arc<FakeSubprocess>) {
    let ceiling = policy(4096);
    let (issuer, verifier) = ConfinementAuthority::new(SandboxPolicyCeiling::new(ceiling)).unwrap();
    let sandbox = rust_agent_sandbox_linux::build(
        &SandboxConfig,
        SandboxDependencies {
            confinement_issuer: ConfinementIssuerBinding::from_generated_authority(issuer),
        },
        RuntimePrimitiveBindings::none(),
    )
    .unwrap()
    .into_service();
    let subprocess = Arc::new(FakeSubprocess::new(
        ConfinementVerifierBinding::from_generated_authority(verifier),
    ));
    let shell = build(
        &Config::checked("/bin/sh").unwrap(),
        Dependencies {
            subprocess: SubprocessBinding::from_provider(Arc::clone(&subprocess)),
            sandbox: SandboxBinding::from_provider(sandbox),
        },
        RuntimePrimitiveBindings::none(),
    )
    .unwrap()
    .into_service();
    (
        ShellBinding::from_generated_component(
            "shell-local",
            SecurityEffects::READ_LOCAL
                | SecurityEffects::WRITE_LOCAL
                | SecurityEffects::PROCESS_EXEC,
            shell,
        )
        .unwrap(),
        subprocess,
    )
}

#[test]
fn resolves_exact_shell_process_and_preserves_enforcement_evidence() {
    let (shell, subprocess) = bindings();
    assert_eq!(shell.provider_key(), PROVIDER_KEY);
    assert_eq!(
        shell.effects(),
        SecurityEffects::READ_LOCAL | SecurityEffects::WRITE_LOCAL | SecurityEffects::PROCESS_EXEC
    );
    let request = request("printf '%s' ok", 128);
    let expected_environment = request.environment().clone();
    let spec = shell.resolve(request).unwrap();
    let result = ready(shell.run(spec, CancellationToken::new())).unwrap();
    assert_eq!(result.provider_key(), PROVIDER_KEY);
    assert_eq!(result.output().exit(), ProcessExit::Code(0));
    assert_eq!(result.output().stdout(), b"stdout");
    assert_eq!(result.output().stderr(), b"stderr");
    assert_eq!(result.enforcement_report().unwrap().process_id(), 41);
    assert_eq!(subprocess.spawns.load(Ordering::SeqCst), 1);
    assert_eq!(
        subprocess
            .observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_slice(),
        [ObservedProcess {
            executable: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), "printf '%s' ok".to_owned()],
            cwd: AgentPath::new("workspace/subdir").unwrap(),
            environment: expected_environment,
            stdin: b"input".to_vec(),
        }]
    );
}

#[test]
fn start_delegates_wait_and_tree_termination_without_process_bypass() {
    let (shell, subprocess) = bindings();
    let spec = shell.resolve(request("sleep 1", 128)).unwrap();
    let process = ready(shell.start(spec, CancellationToken::new())).unwrap();
    assert_eq!(process.provider_key(), PROVIDER_KEY);
    ready(process.terminate_tree()).unwrap();
    assert_eq!(subprocess.terminations.load(Ordering::SeqCst), 1);
    let result = ready(process.wait(CancellationToken::new())).unwrap();
    assert_eq!(result.output().stdout(), b"stdout");
    assert!(result.enforcement_report().is_some());
}

#[test]
fn cancellation_and_sandbox_rejection_stop_before_subprocess_spawn() {
    let (shell, subprocess) = bindings();
    let spec = shell.resolve(request("ignored", 128)).unwrap();
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert_eq!(
        ready(shell.run(spec, cancellation)),
        Err(ShellError::Cancelled)
    );
    assert_eq!(subprocess.spawns.load(Ordering::SeqCst), 0);

    let calls = Arc::new(AtomicUsize::new(0));
    let shell = build(
        &Config::checked("/bin/sh").unwrap(),
        Dependencies {
            subprocess: SubprocessBinding::from_provider(Arc::clone(&subprocess)),
            sandbox: SandboxBinding::from_provider(Arc::new(RejectingSandbox {
                calls: Arc::clone(&calls),
            })),
        },
        RuntimePrimitiveBindings::none(),
    )
    .unwrap()
    .into_service();
    let shell = ShellBinding::from_provider(shell);
    let spec = shell.resolve(request("ignored", 128)).unwrap();
    assert_eq!(
        ready(shell.run(spec, CancellationToken::new())),
        Err(ShellError::ResolveFailed)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(subprocess.spawns.load(Ordering::SeqCst), 0);
}

#[test]
fn process_failures_and_provider_contracts_remain_typed_and_bounded() {
    let (shell, subprocess) = bindings();
    *subprocess
        .spawn_error
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ProcessError::SpawnFailed);
    let spec = shell.resolve(request("ignored", 128)).unwrap();
    assert_eq!(
        ready(shell.run(spec, CancellationToken::new())),
        Err(ShellError::Process(ProcessError::SpawnFailed))
    );

    *subprocess
        .wait_error
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ProcessError::WaitFailed);
    let spec = shell.resolve(request("ignored", 128)).unwrap();
    assert_eq!(
        ready(shell.run(spec, CancellationToken::new())),
        Err(ShellError::Process(ProcessError::WaitFailed))
    );

    subprocess.invalid_report.store(true, Ordering::SeqCst);
    let spec = shell.resolve(request("ignored", 128)).unwrap();
    assert_eq!(
        ready(shell.run(spec, CancellationToken::new())),
        Err(ShellError::Process(ProcessError::InvalidEnforcementReport))
    );
    assert_eq!(subprocess.terminations.load(Ordering::SeqCst), 1);
}

#[test]
fn factory_is_pure_closed_and_deterministic() {
    for invalid in ["", "bin/sh", "/bin/../sh", "/bin//sh"] {
        assert!(Config::checked(invalid).is_err());
    }
    let config = Config::checked("/bin/sh").unwrap();
    assert_eq!(config.executable(), "/bin/sh");
    assert!(
        validate_runtime_primitives(&[RuntimePrimitiveKind::Clock]).is_err(),
        "undeclared runtime primitives must be rejected"
    );

    let (shell, subprocess) = bindings();
    let boundary = "x".repeat(MAX_LOCAL_SHELL_COMMAND_BYTES);
    assert!(shell.resolve(request(&boundary, 128)).is_ok());
    let oversized = "x".repeat(MAX_LOCAL_SHELL_COMMAND_BYTES + 1);
    assert!(matches!(
        shell.resolve(request(&oversized, 128)),
        Err(ShellError::InvalidCommand)
    ));
    assert_eq!(subprocess.spawns.load(Ordering::SeqCst), 0);
}
