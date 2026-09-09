use std::{
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::{Arc, Mutex, atomic::AtomicUsize, atomic::Ordering},
    task::{Context, Poll, Waker},
};

use rust_agent_core::{CanonicalId, Digest, SecurityEffects};
use rust_agent_fs::AgentPath;
use rust_agent_policy::process::{
    BackendKind, BackendPlan, EnforcementPrimitives, FilesystemAccess, MAX_PROCESS_OUTPUT_BYTES,
    NetworkAccess, ProcessResourceLimits, SandboxPolicy, SandboxPolicyCeiling,
};
use rust_agent_runtime_api::CancellationToken;

use super::*;

fn ready<T>(mut future: ProcessFuture<'_, T>) -> T {
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("test future unexpectedly remained pending"),
    }
}

fn limits(processes: u32, output: usize) -> ProcessResourceLimits {
    ProcessResourceLimits::checked(
        NonZeroU32::new(processes).unwrap(),
        NonZeroU64::new(256 * 1024 * 1024).unwrap(),
        NonZeroUsize::new(output).unwrap(),
        NonZeroU64::new(30_000).unwrap(),
    )
    .unwrap()
}

fn policy(filesystem: FilesystemAccess, network: NetworkAccess, output: usize) -> SandboxPolicy {
    SandboxPolicy::new(filesystem, network, limits(4, output))
}

fn process_spec() -> ProcessSpec {
    ProcessSpec::checked(
        ProcessExecutable::absolute("/bin/sh").unwrap(),
        ["-c".to_owned(), "printf ok".to_owned()],
        AgentPath::root(),
        ProcessEnvironment::checked([
            ("TERM".to_owned(), "xterm".to_owned()),
            ("LANG".to_owned(), "C.UTF-8".to_owned()),
        ])
        .unwrap(),
        Vec::new(),
    )
    .unwrap()
}

#[test]
fn process_specs_are_canonical_bounded_and_credential_scrubbed() {
    let spec = process_spec();
    assert_eq!(spec.executable().as_str(), "/bin/sh");
    assert_eq!(spec.cwd(), &AgentPath::root());
    assert_eq!(spec.environment().entries()[0].0.as_ref(), "LANG");
    assert_eq!(spec.environment().entries()[1].0.as_ref(), "TERM");
    let debug = format!("{spec:?}");
    assert!(!debug.contains("/bin/sh"));
    assert!(!debug.contains("printf ok"));
    assert!(!debug.contains("C.UTF-8"));
    assert_eq!(
        ProcessExecutable::absolute("/bin/../bin/sh"),
        Err(ProcessSpecError::InvalidExecutable)
    );
    assert_eq!(
        ProcessEnvironment::checked([
            ("LANG".to_owned(), "C".to_owned()),
            ("LANG".to_owned(), "other".to_owned()),
        ]),
        Err(ProcessSpecError::DuplicateEnvironmentName)
    );
    assert_eq!(
        ProcessEnvironment::checked([("API_TOKEN".to_owned(), "secret".to_owned())]),
        Err(ProcessSpecError::CredentialEnvironmentDenied)
    );
    assert_eq!(
        ProcessSpec::checked(
            ProcessExecutable::absolute("/bin/sh").unwrap(),
            std::iter::repeat_n(String::new(), MAX_PROCESS_ARGUMENTS + 1),
            AgentPath::root(),
            ProcessEnvironment::empty(),
            Vec::new(),
        ),
        Err(ProcessSpecError::TooManyArguments)
    );
    assert_eq!(
        ProcessOutput::checked(
            ProcessExit::Code(0),
            Vec::new(),
            Vec::new(),
            MAX_PROCESS_OUTPUT_BYTES + 1,
        ),
        Err(ProcessError::OutputBudgetExceeded)
    );
}

fn authority(ceiling: SandboxPolicy) -> (ConfinementIssuerBinding, ConfinementVerifierBinding) {
    let (issuer, verifier) = ConfinementAuthority::new(SandboxPolicyCeiling::new(ceiling)).unwrap();
    (
        ConfinementIssuerBinding::from_generated_authority(issuer),
        ConfinementVerifierBinding::from_generated_authority(verifier),
    )
}

#[cfg(target_os = "linux")]
fn confine(
    issuer: &ConfinementIssuerBinding,
    spec: ProcessSpec,
    requested: &SandboxPolicy,
) -> Result<ConfinedProcessSpec, SandboxError> {
    let projection = issuer.project(requested);
    let plan =
        BackendPlan::linux(projection.effective_policy(), EnforcementPrimitives::all()).unwrap();
    issuer.seal(spec, projection, plan)
}

#[cfg(target_os = "linux")]
#[test]
fn confinement_authority_is_pair_exact_and_policy_digest_bound() {
    let ceiling = policy(FilesystemAccess::ReadOnly, NetworkAccess::Deny, 1024);
    let requested = policy(FilesystemAccess::ReadWrite, NetworkAccess::Outbound, 4096);
    let (issuer, verifier) = authority(ceiling.clone());
    let confined = confine(&issuer, process_spec(), &requested).unwrap();
    assert_eq!(confined.output_budget(), 1024);
    let checked_spec = verifier.verify(confined).unwrap();
    assert_eq!(
        checked_spec.effective_policy().filesystem(),
        FilesystemAccess::ReadOnly
    );
    assert_eq!(
        checked_spec.effective_policy().network(),
        NetworkAccess::Deny
    );
    assert_eq!(checked_spec.policy_digest(), ceiling.digest());

    let (foreign_issuer, foreign_verifier) = authority(ceiling);
    let foreign_projection = foreign_issuer.project(&requested);
    let foreign_plan = BackendPlan::linux(
        foreign_projection.effective_policy(),
        EnforcementPrimitives::all(),
    )
    .unwrap();
    assert!(matches!(
        issuer.seal(process_spec(), foreign_projection, foreign_plan),
        Err(SandboxError::AuthorityMismatch)
    ));
    let confined = confine(&foreign_issuer, process_spec(), &requested).unwrap();
    assert!(matches!(
        verifier.verify(confined),
        Err(ProcessError::AuthorityMismatch)
    ));

    let projection = issuer.project(&requested);
    let wrong_policy = policy(FilesystemAccess::None, NetworkAccess::Deny, 512);
    let wrong_plan = BackendPlan::linux(&wrong_policy, EnforcementPrimitives::all()).unwrap();
    assert!(matches!(
        issuer.seal(process_spec(), projection, wrong_plan),
        Err(SandboxError::PolicyDigestMismatch)
    ));

    let confined = confine(&foreign_issuer, process_spec(), &requested).unwrap();
    assert!(foreign_verifier.verify(confined).is_ok());
}

#[derive(Debug)]
struct FixedControl {
    output: ProcessOutput,
    terminations: Arc<AtomicUsize>,
}

#[derive(Debug)]
struct InteractiveControl {
    reads: Mutex<Vec<u8>>,
    writes: Arc<AtomicUsize>,
}

impl ProcessControl for InteractiveControl {
    fn wait(
        &self,
        _cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ProcessOutput, ProcessError>> {
        Box::pin(async {
            ProcessOutput::checked(ProcessExit::Code(0), Vec::new(), Vec::new(), 1024)
        })
    }

    fn terminate_tree(&self) -> ProcessFuture<'_, Result<(), ProcessError>> {
        Box::pin(async { Ok(()) })
    }

    fn write_terminal(&self, data: TerminalBytes) -> ProcessFuture<'_, Result<(), ProcessError>> {
        self.writes.fetch_add(data.len(), Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }

    fn read_terminal(
        &self,
        _request: TerminalReadRequest,
    ) -> ProcessFuture<'_, Result<Vec<u8>, ProcessError>> {
        let bytes = self
            .reads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        Box::pin(async move { Ok(bytes) })
    }

    fn resize_terminal(&self, _size: TerminalSize) -> ProcessFuture<'_, Result<(), ProcessError>> {
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn process_terminal_mode_and_handle_io_are_exact_and_bounded() {
    let size = TerminalSize::checked(80, 24).unwrap();
    let spec = ProcessSpec::checked_terminal(
        ProcessExecutable::absolute("/bin/sh").unwrap(),
        std::iter::empty(),
        AgentPath::root(),
        ProcessEnvironment::empty(),
        size,
    )
    .unwrap();
    assert_eq!(spec.terminal_size(), Some(size));
    assert!(spec.stdin().is_empty());

    let report = EnforcementReport::after_child_setup(
        Digest::from_bytes([3; Digest::LEN]),
        BackendKind::Linux,
        EnforcementPrimitives::all(),
        11,
    )
    .unwrap();
    let writes = Arc::new(AtomicUsize::new(0));
    let control = Arc::new(InteractiveControl {
        reads: Mutex::new(b"oversized".to_vec()),
        writes: Arc::clone(&writes),
    });
    let handle = ProcessHandle::from_enforced_terminal(report.clone(), 1024, control).unwrap();
    assert!(handle.is_terminal());
    ready(handle.write_terminal(TerminalBytes::checked(b"abc".to_vec()).unwrap())).unwrap();
    assert_eq!(writes.load(Ordering::SeqCst), 3);
    assert_eq!(
        ready(
            handle.read_terminal(
                TerminalReadRequest::checked(NonZeroUsize::new(4).unwrap()).unwrap(),
            )
        ),
        Err(ProcessError::ProviderContractViolation)
    );
    ready(handle.resize_terminal(TerminalSize::checked(132, 40).unwrap())).unwrap();

    let captured = ProcessHandle::from_enforced(
        report,
        1024,
        Arc::new(FixedControl {
            output: ProcessOutput::checked(ProcessExit::Code(0), Vec::new(), Vec::new(), 1024)
                .unwrap(),
            terminations: Arc::new(AtomicUsize::new(0)),
        }),
    )
    .unwrap();
    assert!(!captured.is_terminal());
    assert_eq!(
        ready(captured.write_terminal(TerminalBytes::checked(Vec::new()).unwrap())),
        Err(ProcessError::InteractiveIoUnavailable)
    );
}

impl ProcessControl for FixedControl {
    fn wait(
        &self,
        _cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ProcessOutput, ProcessError>> {
        let output = self.output.clone();
        Box::pin(async move { Ok(output) })
    }

    fn terminate_tree(&self) -> ProcessFuture<'_, Result<(), ProcessError>> {
        self.terminations.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct IssuingSandbox {
    issuer: ConfinementIssuerBinding,
}

#[cfg(target_os = "linux")]
impl Sandbox for IssuingSandbox {
    fn provider_key(&self) -> CanonicalId {
        CanonicalId::new("sandbox-linux").unwrap()
    }

    fn effects(&self) -> SecurityEffects {
        SecurityEffects::PROCESS_EXEC | SecurityEffects::READ_LOCAL
    }

    fn confine(
        &self,
        process: ProcessSpec,
        policy: SandboxPolicy,
    ) -> ProcessFuture<'_, Result<ConfinedProcessSpec, SandboxError>> {
        Box::pin(async move { confine(&self.issuer, process, &policy) })
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct VerifyingSubprocess {
    verifier: ConfinementVerifierBinding,
    calls: Arc<AtomicUsize>,
    terminations: Arc<AtomicUsize>,
    report_mode: ReportMode,
    effects: SecurityEffects,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
enum ReportMode {
    Exact,
    WrongDigest,
    MissingPrimitive,
    WrongOutputBudget,
}

#[cfg(target_os = "linux")]
impl Subprocess for VerifyingSubprocess {
    fn provider_key(&self) -> CanonicalId {
        CanonicalId::new("subprocess-local").unwrap()
    }

    fn effects(&self) -> SecurityEffects {
        self.effects
    }

    fn spawn(
        &self,
        spec: ConfinedProcessSpec,
        _cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ProcessHandle, ProcessError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let verified = self.verifier.verify(spec)?;
            let output_budget = verified
                .effective_policy()
                .limits()
                .max_output_bytes()
                .get();
            let report_digest = if matches!(self.report_mode, ReportMode::WrongDigest) {
                rust_agent_core::Digest::from_bytes([9; 32])
            } else {
                verified.policy_digest()
            };
            let applied_primitives = if matches!(self.report_mode, ReportMode::MissingPrimitive) {
                EnforcementPrimitives::empty()
            } else {
                EnforcementPrimitives::all()
            };
            let report = EnforcementReport::after_child_setup(
                report_digest,
                verified.backend_plan().kind(),
                applied_primitives,
                42,
            )?;
            let reported_output_budget =
                if matches!(self.report_mode, ReportMode::WrongOutputBudget) {
                    output_budget + 1
                } else {
                    output_budget
                };
            ProcessHandle::from_enforced(
                report,
                reported_output_budget,
                Arc::new(FixedControl {
                    output: ProcessOutput::checked(
                        ProcessExit::Code(0),
                        b"ok".to_vec(),
                        Vec::new(),
                        output_budget,
                    )?,
                    terminations: Arc::clone(&self.terminations),
                }),
            )
        })
    }
}

#[cfg(target_os = "linux")]
#[test]
fn sandbox_and_subprocess_pipeline_has_no_raw_or_cancelled_spawn_bypass() {
    let ceiling = policy(FilesystemAccess::ReadOnly, NetworkAccess::Deny, 1024);
    let (issuer, verifier) = authority(ceiling.clone());
    let sandbox = SandboxBinding::from_generated_component(
        "sandbox-linux",
        SecurityEffects::PROCESS_EXEC | SecurityEffects::READ_LOCAL,
        Arc::new(IssuingSandbox { issuer }),
    )
    .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let terminations = Arc::new(AtomicUsize::new(0));
    let subprocess = SubprocessBinding::from_generated_component(
        "subprocess-local",
        SecurityEffects::PROCESS_EXEC,
        Arc::new(VerifyingSubprocess {
            verifier,
            calls: Arc::clone(&calls),
            terminations: Arc::clone(&terminations),
            report_mode: ReportMode::Exact,
            effects: SecurityEffects::PROCESS_EXEC,
        }),
    )
    .unwrap();
    let confined = ready(sandbox.confine(process_spec(), ceiling.clone())).unwrap();
    let handle = ready(subprocess.spawn(confined, CancellationToken::new())).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(handle.enforcement_report().process_id(), 42);
    assert_eq!(
        ready(handle.wait(CancellationToken::new()))
            .unwrap()
            .stdout(),
        b"ok"
    );
    assert_eq!(ready(handle.terminate_tree()), Ok(()));
    assert_eq!(terminations.load(Ordering::SeqCst), 1);

    let confined = ready(sandbox.confine(process_spec(), ceiling.clone())).unwrap();
    let handle = ready(subprocess.spawn(confined, CancellationToken::new())).unwrap();
    let cancelled_wait = CancellationToken::new();
    cancelled_wait.cancel();
    assert_eq!(
        ready(handle.wait(cancelled_wait)),
        Err(ProcessError::Cancelled)
    );
    assert_eq!(terminations.load(Ordering::SeqCst), 2);

    let confined = ready(sandbox.confine(process_spec(), ceiling)).unwrap();
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(matches!(
        ready(subprocess.spawn(confined, cancelled)),
        Err(ProcessError::Cancelled)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[cfg(target_os = "linux")]
#[test]
fn subprocess_rejects_effect_and_enforcement_report_drift() {
    let ceiling = policy(FilesystemAccess::ReadOnly, NetworkAccess::Deny, 1024);
    for report_mode in [
        ReportMode::WrongDigest,
        ReportMode::MissingPrimitive,
        ReportMode::WrongOutputBudget,
    ] {
        let (issuer, verifier) = authority(ceiling.clone());
        let sandbox = SandboxBinding::from_provider(Arc::new(IssuingSandbox { issuer }));
        let terminations = Arc::new(AtomicUsize::new(0));
        let subprocess = SubprocessBinding::from_provider(Arc::new(VerifyingSubprocess {
            verifier,
            calls: Arc::new(AtomicUsize::new(0)),
            terminations: Arc::clone(&terminations),
            report_mode,
            effects: SecurityEffects::PROCESS_EXEC,
        }));
        let confined = ready(sandbox.confine(process_spec(), ceiling.clone())).unwrap();
        assert!(matches!(
            ready(subprocess.spawn(confined, CancellationToken::new())),
            Err(ProcessError::InvalidEnforcementReport)
        ));
        assert_eq!(terminations.load(Ordering::SeqCst), 1);
    }

    let (_, verifier) = authority(ceiling);
    assert!(matches!(
        SubprocessBinding::from_generated_component(
            "subprocess-local",
            SecurityEffects::PROCESS_EXEC,
            Arc::new(VerifyingSubprocess {
                verifier,
                calls: Arc::new(AtomicUsize::new(0)),
                terminations: Arc::new(AtomicUsize::new(0)),
                report_mode: ReportMode::Exact,
                effects: SecurityEffects::PROCESS_EXEC | SecurityEffects::NETWORK,
            }),
        ),
        Err(ProcessError::ProviderContractViolation)
    ));
}

#[derive(Debug)]
struct FixedShell {
    calls: Arc<AtomicUsize>,
    oversized: bool,
    provider_key: &'static str,
    terminations: Arc<AtomicUsize>,
    wrong_start_budget: bool,
}

#[derive(Debug)]
struct FixedShellControl {
    provider_key: CanonicalId,
    output_budget: usize,
    terminations: Arc<AtomicUsize>,
}

impl ShellProcessControl for FixedShellControl {
    fn wait(
        &self,
        _cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ShellResult, ShellError>> {
        let provider_key = self.provider_key.clone();
        let output_budget = self.output_budget;
        Box::pin(async move {
            ShellResult::from_provider(
                provider_key,
                ProcessExit::Code(0),
                Vec::new(),
                Vec::new(),
                output_budget,
                None,
            )
        })
    }

    fn terminate_tree(&self) -> ProcessFuture<'_, Result<(), ShellError>> {
        self.terminations.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

impl Shell for FixedShell {
    fn provider_key(&self) -> CanonicalId {
        CanonicalId::new(self.provider_key).unwrap()
    }

    fn effects(&self) -> SecurityEffects {
        SecurityEffects::PROCESS_EXEC
    }

    fn normalize(&self, request: ShellRequest) -> Result<ShellRequest, ShellError> {
        Ok(request)
    }

    fn run(
        &self,
        spec: ShellSpec,
        _cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ShellResult, ShellError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let provider_key = self.provider_key();
        let output_len = if self.oversized {
            spec.output_budget() + 1
        } else {
            2
        };
        Box::pin(async move {
            ShellResult::from_provider(
                provider_key,
                ProcessExit::Code(0),
                vec![b'x'; output_len],
                Vec::new(),
                output_len,
                None,
            )
        })
    }

    fn start(
        &self,
        spec: ShellSpec,
        _cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ShellProcess, ShellError>> {
        let provider_key = self.provider_key();
        let output_budget = if self.wrong_start_budget {
            spec.output_budget() + 1
        } else {
            spec.output_budget()
        };
        let terminations = Arc::clone(&self.terminations);
        Box::pin(async move {
            ShellProcess::from_provider(
                provider_key.clone(),
                output_budget,
                Arc::new(FixedShellControl {
                    provider_key,
                    output_budget,
                    terminations,
                }),
            )
        })
    }
}

fn shell_request(output: usize) -> ShellRequest {
    let request = ShellRequest::checked(
        "printf ok",
        AgentPath::root(),
        ProcessEnvironment::empty(),
        Vec::new(),
        policy(FilesystemAccess::ReadOnly, NetworkAccess::Deny, output),
    )
    .unwrap();
    assert!(!format!("{request:?}").contains("printf ok"));
    request
}

#[test]
fn shell_binding_rejects_foreign_cancelled_and_oversized_results_before_escape() {
    let calls = Arc::new(AtomicUsize::new(0));
    let terminations = Arc::new(AtomicUsize::new(0));
    let shell = ShellBinding::from_provider(Arc::new(FixedShell {
        calls: Arc::clone(&calls),
        oversized: false,
        provider_key: "shell-test",
        terminations: Arc::clone(&terminations),
        wrong_start_budget: false,
    }));
    let spec = shell.resolve(shell_request(16)).unwrap();
    let result = ready(shell.run(spec, CancellationToken::new())).unwrap();
    assert_eq!(result.output().stdout(), b"xx");
    let process = ready(shell.start(
        shell.resolve(shell_request(16)).unwrap(),
        CancellationToken::new(),
    ))
    .unwrap();
    let cancelled_wait = CancellationToken::new();
    cancelled_wait.cancel();
    assert_eq!(
        ready(process.wait(cancelled_wait)),
        Err(ShellError::Cancelled)
    );
    assert_eq!(terminations.load(Ordering::SeqCst), 1);

    let foreign = ShellBinding::from_provider(Arc::new(FixedShell {
        calls: Arc::new(AtomicUsize::new(0)),
        oversized: false,
        provider_key: "shell-test",
        terminations: Arc::new(AtomicUsize::new(0)),
        wrong_start_budget: false,
    }))
    .resolve(shell_request(16))
    .unwrap();
    assert_eq!(
        ready(shell.run(foreign, CancellationToken::new())),
        Err(ShellError::ForeignSpec)
    );
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let spec = shell.resolve(shell_request(16)).unwrap();
    assert_eq!(
        ready(shell.run(spec, cancelled)),
        Err(ShellError::Cancelled)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let oversized = ShellBinding::from_provider(Arc::new(FixedShell {
        calls,
        oversized: true,
        provider_key: "shell-test",
        terminations,
        wrong_start_budget: false,
    }));
    let spec = oversized.resolve(shell_request(16)).unwrap();
    assert_eq!(
        ready(oversized.run(spec, CancellationToken::new())),
        Err(ShellError::ProviderContractViolation)
    );

    let terminations = Arc::new(AtomicUsize::new(0));
    let wrong_start = ShellBinding::from_provider(Arc::new(FixedShell {
        calls: Arc::new(AtomicUsize::new(0)),
        oversized: false,
        provider_key: "shell-test",
        terminations: Arc::clone(&terminations),
        wrong_start_budget: true,
    }));
    let spec = wrong_start.resolve(shell_request(16)).unwrap();
    assert!(matches!(
        ready(wrong_start.start(spec, CancellationToken::new())),
        Err(ShellError::ProviderContractViolation)
    ));
    assert_eq!(terminations.load(Ordering::SeqCst), 1);
}

#[derive(Debug)]
struct FixedTerminal {
    calls: Arc<AtomicUsize>,
    provider_key: &'static str,
}

impl TerminalManager for FixedTerminal {
    fn provider_key(&self) -> CanonicalId {
        CanonicalId::new(self.provider_key).unwrap()
    }

    fn effects(&self) -> SecurityEffects {
        SecurityEffects::PROCESS_EXEC
    }

    fn open_provider(
        &self,
        _spec: TerminalSpec,
        _cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<NonZeroU64, TerminalError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(NonZeroU64::MIN) })
    }

    fn write(
        &self,
        _id: TerminalId,
        _data: TerminalBytes,
    ) -> ProcessFuture<'_, Result<(), TerminalError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }

    fn read(
        &self,
        _id: TerminalId,
        _request: TerminalReadRequest,
    ) -> ProcessFuture<'_, Result<TerminalBytes, TerminalError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { TerminalBytes::checked(vec![0; 8]) })
    }

    fn resize(
        &self,
        _id: TerminalId,
        _size: TerminalSize,
    ) -> ProcessFuture<'_, Result<(), TerminalError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }

    fn close(&self, _id: TerminalId) -> ProcessFuture<'_, Result<(), TerminalError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn terminal_ids_and_io_are_provider_bound_and_bounded() {
    let calls = Arc::new(AtomicUsize::new(0));
    let terminal = TerminalBinding::from_provider(Arc::new(FixedTerminal {
        calls: Arc::clone(&calls),
        provider_key: "terminal-test",
    }));
    let spec = TerminalSpec::new(
        AgentPath::root(),
        ProcessEnvironment::empty(),
        policy(FilesystemAccess::ReadOnly, NetworkAccess::Deny, 1024),
        TerminalSize::checked(80, 24).unwrap(),
    );
    let id = ready(terminal.open(spec, CancellationToken::new())).unwrap();
    assert_eq!(
        ready(terminal.read(
            id.clone(),
            TerminalReadRequest::checked(NonZeroUsize::new(4).unwrap()).unwrap(),
        )),
        Err(TerminalError::ProviderContractViolation)
    );
    let foreign = ready(
        TerminalBinding::from_provider(Arc::new(FixedTerminal {
            calls: Arc::new(AtomicUsize::new(0)),
            provider_key: "terminal-test",
        }))
        .open(
            TerminalSpec::new(
                AgentPath::root(),
                ProcessEnvironment::empty(),
                policy(FilesystemAccess::ReadOnly, NetworkAccess::Deny, 1024),
                TerminalSize::checked(80, 24).unwrap(),
            ),
            CancellationToken::new(),
        ),
    )
    .unwrap();
    assert_eq!(
        ready(terminal.close(foreign)),
        Err(TerminalError::ForeignTerminal)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        TerminalSize::checked(0, 24),
        Err(TerminalError::InvalidSize)
    );
    assert_eq!(
        TerminalBytes::checked(vec![0; MAX_TERMINAL_IO_BYTES + 1]),
        Err(TerminalError::IoBudgetExceeded)
    );
}
