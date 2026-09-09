use std::{
    collections::VecDeque,
    future::Future,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

use rust_agent_fs::AgentPath;
use rust_agent_policy::process::{
    FilesystemAccess, NetworkAccess, ProcessResourceLimits, SandboxPolicy, SandboxPolicyCeiling,
};
use rust_agent_process::{
    ConfinedProcessSpec, ConfinementAuthority, ConfinementIssuerBinding,
    ConfinementVerifierBinding, EnforcementReport, ProcessControl, ProcessEnvironment, ProcessExit,
    ProcessOutput, Sandbox, SandboxError, Subprocess, TerminalBinding, VerifiedProcessSpec,
};
use rust_agent_runtime_api::RuntimePrimitiveKind;
use rust_agent_sandbox_linux::{Config as SandboxConfig, Dependencies as SandboxDependencies};

use super::*;

fn ready<T>(mut future: impl Future<Output = T> + Unpin) -> T {
    let mut context = Context::from_waker(Waker::noop());
    match Future::poll(std::pin::Pin::new(&mut future), &mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("test future unexpectedly pending"),
    }
}

fn policy(output: usize) -> SandboxPolicy {
    SandboxPolicy::new(
        FilesystemAccess::ReadWrite,
        NetworkAccess::Deny,
        ProcessResourceLimits::checked(
            NonZeroU32::new(4).unwrap(),
            NonZeroU64::new(256 * 1024 * 1024).unwrap(),
            NonZeroUsize::new(output).unwrap(),
            NonZeroU64::new(30_000).unwrap(),
        )
        .unwrap(),
    )
}

fn terminal_spec() -> TerminalSpec {
    TerminalSpec::new(
        AgentPath::new("workspace/child").unwrap(),
        ProcessEnvironment::checked([
            ("LANG".to_owned(), "C.UTF-8".to_owned()),
            ("TERM".to_owned(), "xterm-256color".to_owned()),
        ])
        .unwrap(),
        policy(4096),
        TerminalSize::checked(80, 24).unwrap(),
    )
}

#[derive(Debug)]
struct FakeTerminalState {
    bytes: Mutex<VecDeque<u8>>,
    size: Mutex<TerminalSize>,
    terminations: AtomicUsize,
}

#[derive(Debug)]
struct FakeControl {
    state: Arc<FakeTerminalState>,
}

impl ProcessControl for FakeControl {
    fn wait(
        &self,
        _cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ProcessOutput, ProcessError>> {
        Box::pin(async {
            ProcessOutput::checked(ProcessExit::Code(0), Vec::new(), Vec::new(), 4096)
        })
    }

    fn terminate_tree(&self) -> ProcessFuture<'_, Result<(), ProcessError>> {
        self.state.terminations.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }

    fn write_terminal(&self, data: TerminalBytes) -> ProcessFuture<'_, Result<(), ProcessError>> {
        self.state
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(data.as_slice().iter().copied());
        Box::pin(async { Ok(()) })
    }

    fn read_terminal(
        &self,
        request: TerminalReadRequest,
    ) -> ProcessFuture<'_, Result<Vec<u8>, ProcessError>> {
        let mut bytes = self
            .state
            .bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = request.max_bytes().get().min(bytes.len());
        let result = bytes.drain(..count).collect();
        Box::pin(async move { Ok(result) })
    }

    fn resize_terminal(&self, size: TerminalSize) -> ProcessFuture<'_, Result<(), ProcessError>> {
        *self
            .state
            .size
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = size;
        Box::pin(async { Ok(()) })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedProcess {
    executable: String,
    arguments: Vec<String>,
    cwd: AgentPath,
    environment: ProcessEnvironment,
    terminal_size: Option<TerminalSize>,
    stdin: Vec<u8>,
}

#[derive(Debug)]
struct FakeSubprocess {
    verifier: ConfinementVerifierBinding,
    state: Arc<FakeTerminalState>,
    spawns: AtomicUsize,
    observed: Mutex<Vec<ObservedProcess>>,
    return_captured_handle: AtomicBool,
    cancel_after_handle: AtomicBool,
}

impl FakeSubprocess {
    fn handle(&self, verified: &VerifiedProcessSpec) -> Result<ProcessHandle, ProcessError> {
        let output_budget = verified
            .effective_policy()
            .limits()
            .max_output_bytes()
            .get();
        let report = EnforcementReport::after_child_setup(
            verified.policy_digest(),
            verified.backend_plan().kind(),
            verified.backend_plan().required_primitives(),
            73,
        )?;
        let control = Arc::new(FakeControl {
            state: Arc::clone(&self.state),
        });
        if self.return_captured_handle.load(Ordering::SeqCst) {
            ProcessHandle::from_enforced(report, output_budget, control)
        } else {
            ProcessHandle::from_enforced_terminal(report, output_budget, control)
        }
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
                        terminal_size: verified.process().terminal_size(),
                        stdin: verified.process().stdin().to_vec(),
                    });
                self.handle(&verified)
            })
        };
        if self.cancel_after_handle.load(Ordering::SeqCst) && result.is_ok() {
            cancellation.cancel();
        }
        Box::pin(async move { result })
    }
}

#[derive(Debug)]
struct RejectingSandbox {
    calls: Arc<AtomicUsize>,
}

#[derive(Debug)]
struct PendingSandbox;

impl Sandbox for PendingSandbox {
    fn provider_key(&self) -> CanonicalId {
        CanonicalId::new("pending-sandbox").unwrap()
    }

    fn effects(&self) -> SecurityEffects {
        SecurityEffects::empty()
    }

    fn confine(
        &self,
        _process: ProcessSpec,
        _policy: SandboxPolicy,
    ) -> ProcessFuture<'_, Result<ConfinedProcessSpec, SandboxError>> {
        Box::pin(std::future::pending())
    }
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

fn output() -> (ComponentOutput<LocalTerminal>, Arc<FakeSubprocess>) {
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
    let state = Arc::new(FakeTerminalState {
        bytes: Mutex::new(VecDeque::new()),
        size: Mutex::new(TerminalSize::checked(80, 24).unwrap()),
        terminations: AtomicUsize::new(0),
    });
    let subprocess = Arc::new(FakeSubprocess {
        verifier: ConfinementVerifierBinding::from_generated_authority(verifier),
        state,
        spawns: AtomicUsize::new(0),
        observed: Mutex::new(Vec::new()),
        return_captured_handle: AtomicBool::new(false),
        cancel_after_handle: AtomicBool::new(false),
    });
    let output = build(
        &Config::checked("/bin/sh").unwrap(),
        Dependencies {
            subprocess: SubprocessBinding::from_provider(Arc::clone(&subprocess)),
            sandbox: SandboxBinding::from_provider(sandbox),
        },
        RuntimePrimitiveBindings::none(),
    )
    .unwrap();
    (output, subprocess)
}

#[test]
fn opens_only_a_confined_interactive_process_and_delegates_terminal_io() {
    let (output, subprocess) = output();
    ready(output.initializer().unwrap().initialize()).unwrap();
    let terminal = TerminalBinding::from_generated_component(
        "terminal-local",
        SecurityEffects::READ_LOCAL | SecurityEffects::WRITE_LOCAL | SecurityEffects::PROCESS_EXEC,
        output.service().clone(),
    )
    .unwrap();
    let spec = terminal_spec();
    let expected_environment = spec.environment().clone();
    let id = ready(terminal.open(spec, CancellationToken::new())).unwrap();
    assert_eq!(terminal.provider_key(), PROVIDER_KEY);
    assert_eq!(subprocess.spawns.load(Ordering::SeqCst), 1);
    assert_eq!(
        subprocess
            .observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_slice(),
        [ObservedProcess {
            executable: "/bin/sh".to_owned(),
            arguments: Vec::new(),
            cwd: AgentPath::new("workspace/child").unwrap(),
            environment: expected_environment,
            terminal_size: Some(TerminalSize::checked(80, 24).unwrap()),
            stdin: Vec::new(),
        }]
    );

    ready(terminal.write(
        id.clone(),
        TerminalBytes::checked(b"abcd".to_vec()).unwrap(),
    ))
    .unwrap();
    let first = ready(terminal.read(
        id.clone(),
        TerminalReadRequest::checked(NonZeroUsize::new(3).unwrap()).unwrap(),
    ))
    .unwrap();
    assert_eq!(first.as_slice(), b"abc");
    let resized = TerminalSize::checked(132, 43).unwrap();
    ready(terminal.resize(id.clone(), resized)).unwrap();
    assert_eq!(
        *subprocess
            .state
            .size
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        resized
    );
    let close = terminal.close(id.clone());
    ready(terminal.write(id.clone(), TerminalBytes::checked(b"e".to_vec()).unwrap())).unwrap();
    ready(close).unwrap();
    assert_eq!(subprocess.state.terminations.load(Ordering::SeqCst), 1);
    assert_eq!(
        ready(terminal.close(id)),
        Err(TerminalError::ForeignTerminal)
    );
}

#[test]
fn lifecycle_cancellation_and_sandbox_rejection_stop_before_spawn() {
    let (output, subprocess) = output();
    let terminal = TerminalBinding::from_provider(output.service().clone());
    assert_eq!(
        ready(terminal.open(terminal_spec(), CancellationToken::new())),
        Err(TerminalError::OpenFailed)
    );
    ready(output.initializer().unwrap().initialize()).unwrap();
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert_eq!(
        ready(terminal.open(terminal_spec(), cancellation)),
        Err(TerminalError::Cancelled)
    );
    assert_eq!(subprocess.spawns.load(Ordering::SeqCst), 0);

    let calls = Arc::new(AtomicUsize::new(0));
    let rejected = build(
        &Config::checked("/bin/sh").unwrap(),
        Dependencies {
            subprocess: SubprocessBinding::from_provider(Arc::clone(&subprocess)),
            sandbox: SandboxBinding::from_provider(Arc::new(RejectingSandbox {
                calls: Arc::clone(&calls),
            })),
        },
        RuntimePrimitiveBindings::none(),
    )
    .unwrap();
    ready(rejected.initializer().unwrap().initialize()).unwrap();
    let rejected = TerminalBinding::from_provider(rejected.into_service());
    assert_eq!(
        ready(rejected.open(terminal_spec(), CancellationToken::new())),
        Err(TerminalError::OpenFailed)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(subprocess.spawns.load(Ordering::SeqCst), 0);

    let id = ready(terminal.open(terminal_spec(), CancellationToken::new())).unwrap();
    ready(output.shutdown_hook().unwrap().shutdown()).unwrap();
    assert_eq!(subprocess.state.terminations.load(Ordering::SeqCst), 1);
    assert_eq!(
        ready(terminal.read(id, TerminalReadRequest::checked(NonZeroUsize::MIN).unwrap(),)),
        Err(TerminalError::Cancelled)
    );
    assert_eq!(
        ready(terminal.open(terminal_spec(), CancellationToken::new())),
        Err(TerminalError::Cancelled)
    );
}

#[test]
fn captured_handle_drift_is_terminated_before_a_terminal_id_escapes() {
    let (output, subprocess) = output();
    ready(output.initializer().unwrap().initialize()).unwrap();
    subprocess
        .return_captured_handle
        .store(true, Ordering::SeqCst);
    let terminal = TerminalBinding::from_provider(output.into_service());
    assert_eq!(
        ready(terminal.open(terminal_spec(), CancellationToken::new())),
        Err(TerminalError::OpenFailed)
    );
    assert_eq!(subprocess.state.terminations.load(Ordering::SeqCst), 1);
}

#[test]
fn cancellation_racing_with_spawn_terminates_before_a_terminal_id_escapes() {
    let (output, subprocess) = output();
    ready(output.initializer().unwrap().initialize()).unwrap();
    subprocess.cancel_after_handle.store(true, Ordering::SeqCst);
    let terminal = TerminalBinding::from_provider(output.into_service());
    assert_eq!(
        ready(terminal.open(terminal_spec(), CancellationToken::new())),
        Err(TerminalError::Cancelled)
    );
    assert_eq!(subprocess.state.terminations.load(Ordering::SeqCst), 1);
}

#[test]
fn dropped_open_future_releases_its_bounded_reservation() {
    let (_unused, subprocess) = output();
    let pending = build(
        &Config::checked("/bin/sh").unwrap(),
        Dependencies {
            subprocess: SubprocessBinding::from_provider(subprocess),
            sandbox: SandboxBinding::from_provider(Arc::new(PendingSandbox)),
        },
        RuntimePrimitiveBindings::none(),
    )
    .unwrap();
    ready(pending.initializer().unwrap().initialize()).unwrap();
    let terminal = TerminalBinding::from_provider(pending.service().clone());
    let mut future = terminal.open(terminal_spec(), CancellationToken::new());
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    assert_eq!(
        pending
            .service()
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .opening,
        1
    );
    drop(future);
    assert_eq!(
        pending
            .service()
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .opening,
        0
    );
}

#[test]
fn open_capacity_and_identity_exhaustion_fail_before_subprocess_effects() {
    let (managed, subprocess) = output();
    ready(managed.initializer().unwrap().initialize()).unwrap();
    let terminal = TerminalBinding::from_provider(managed.service().clone());
    for _ in 0..MAX_OPEN_TERMINALS {
        ready(terminal.open(terminal_spec(), CancellationToken::new())).unwrap();
    }
    assert_eq!(subprocess.spawns.load(Ordering::SeqCst), MAX_OPEN_TERMINALS);
    assert_eq!(
        ready(terminal.open(terminal_spec(), CancellationToken::new())),
        Err(TerminalError::OpenFailed)
    );
    assert_eq!(subprocess.spawns.load(Ordering::SeqCst), MAX_OPEN_TERMINALS);
    ready(managed.shutdown_hook().unwrap().shutdown()).unwrap();
    assert_eq!(
        subprocess.state.terminations.load(Ordering::SeqCst),
        MAX_OPEN_TERMINALS
    );

    let (exhausted, subprocess) = output();
    ready(exhausted.initializer().unwrap().initialize()).unwrap();
    exhausted
        .service()
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .next_identity = u64::MAX;
    let terminal = TerminalBinding::from_provider(exhausted.into_service());
    assert_eq!(
        ready(terminal.open(terminal_spec(), CancellationToken::new())),
        Err(TerminalError::OpenFailed)
    );
    assert_eq!(subprocess.spawns.load(Ordering::SeqCst), 0);
}

#[test]
fn factory_is_io_free_bounded_and_runtime_exact() {
    let (output, _subprocess) = output();
    assert!(output.initializer().is_some());
    assert!(output.shutdown_hook().is_some());
    assert_eq!(ready(output.initializer().unwrap().initialize()), Ok(()));
    assert_eq!(
        ready(output.initializer().unwrap().initialize()),
        Err(InitializeError::AlreadyInitialized)
    );
    assert!(Config::checked("bin/sh").is_err());
    assert!(Config::checked("/bin/../bin/sh").is_err());

    assert!(validate_runtime_primitives(&[RuntimePrimitiveKind::Clock]).is_err());
}

#[test]
fn process_error_mapping_preserves_terminal_categories() {
    assert_eq!(
        map_open_error(ProcessError::Cancelled),
        TerminalError::Cancelled
    );
    assert_eq!(
        map_read_error(ProcessError::DeadlineExceeded),
        TerminalError::DeadlineExceeded
    );
    assert_eq!(
        map_write_error(ProcessError::OutputBudgetExceeded),
        TerminalError::IoBudgetExceeded
    );
    assert_eq!(
        map_resize_error(ProcessError::InteractiveIoFailed),
        TerminalError::ResizeFailed
    );
}
