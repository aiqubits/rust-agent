use std::{fmt, sync::Arc};

use rust_agent_core::{CanonicalId, Digest, MaybeSendSync, SecurityEffects};
use rust_agent_policy::process::{
    BackendKind, EnforcementPrimitives, MAX_PROCESS_OUTPUT_BYTES, SandboxPolicy, SandboxPolicyError,
};
use rust_agent_runtime_api::CancellationToken;

use crate::{
    ConfinedProcessSpec, ProcessFuture, ProcessSpec, TerminalBytes, TerminalReadRequest,
    TerminalSize,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessExit {
    Code(i32),
    Signal(i32),
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProcessOutput {
    exit: ProcessExit,
    stdout: Arc<[u8]>,
    stderr: Arc<[u8]>,
}

impl fmt::Debug for ProcessOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessOutput")
            .field("exit", &self.exit)
            .field("stdout_len", &self.stdout.len())
            .field("stderr_len", &self.stderr.len())
            .finish()
    }
}

impl ProcessOutput {
    pub fn checked(
        exit: ProcessExit,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        byte_budget: usize,
    ) -> Result<Self, ProcessError> {
        let total = stdout
            .len()
            .checked_add(stderr.len())
            .ok_or(ProcessError::OutputBudgetExceeded)?;
        if byte_budget == 0 || byte_budget > MAX_PROCESS_OUTPUT_BYTES || total > byte_budget {
            return Err(ProcessError::OutputBudgetExceeded);
        }
        Ok(Self {
            exit,
            stdout: Arc::from(stdout),
            stderr: Arc::from(stderr),
        })
    }

    pub const fn exit(&self) -> ProcessExit {
        self.exit
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    pub fn encoded_bytes(&self) -> usize {
        self.stdout.len() + self.stderr.len()
    }
}

/// Immutable evidence returned only after child setup has acknowledged enforcement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcementReport {
    policy_digest: Digest,
    backend: BackendKind,
    applied_primitives: EnforcementPrimitives,
    process_id: u32,
}

impl EnforcementReport {
    #[doc(hidden)]
    pub fn after_child_setup(
        policy_digest: Digest,
        backend: BackendKind,
        applied_primitives: EnforcementPrimitives,
        process_id: u32,
    ) -> Result<Self, ProcessError> {
        if process_id == 0 {
            return Err(ProcessError::InvalidEnforcementReport);
        }
        Ok(Self {
            policy_digest,
            backend,
            applied_primitives,
            process_id,
        })
    }

    pub const fn policy_digest(&self) -> Digest {
        self.policy_digest
    }

    pub const fn backend(&self) -> BackendKind {
        self.backend
    }

    pub const fn applied_primitives(&self) -> EnforcementPrimitives {
        self.applied_primitives
    }

    pub const fn process_id(&self) -> u32 {
        self.process_id
    }
}

pub trait ProcessControl: MaybeSendSync {
    fn wait(
        &self,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ProcessOutput, ProcessError>>;

    fn terminate_tree(&self) -> ProcessFuture<'_, Result<(), ProcessError>>;

    fn write_terminal(&self, _data: TerminalBytes) -> ProcessFuture<'_, Result<(), ProcessError>> {
        Box::pin(async { Err(ProcessError::InteractiveIoUnavailable) })
    }

    fn read_terminal(
        &self,
        _request: TerminalReadRequest,
    ) -> ProcessFuture<'_, Result<Vec<u8>, ProcessError>> {
        Box::pin(async { Err(ProcessError::InteractiveIoUnavailable) })
    }

    fn resize_terminal(&self, _size: TerminalSize) -> ProcessFuture<'_, Result<(), ProcessError>> {
        Box::pin(async { Err(ProcessError::InteractiveIoUnavailable) })
    }
}

/// Owned process mechanics returned only after the provider's setup handshake succeeds.
pub struct ProcessHandle {
    report: EnforcementReport,
    output_budget: usize,
    terminal: bool,
    control: Arc<dyn ProcessControl>,
}

impl ProcessHandle {
    #[doc(hidden)]
    pub fn from_enforced<T>(
        report: EnforcementReport,
        output_budget: usize,
        control: Arc<T>,
    ) -> Result<Self, ProcessError>
    where
        T: ProcessControl + 'static,
    {
        if output_budget == 0 || output_budget > MAX_PROCESS_OUTPUT_BYTES {
            return Err(ProcessError::InvalidEnforcementReport);
        }
        Ok(Self {
            report,
            output_budget,
            terminal: false,
            control,
        })
    }

    #[doc(hidden)]
    pub fn from_enforced_terminal<T>(
        report: EnforcementReport,
        output_budget: usize,
        control: Arc<T>,
    ) -> Result<Self, ProcessError>
    where
        T: ProcessControl + 'static,
    {
        let mut handle = Self::from_enforced(report, output_budget, control)?;
        handle.terminal = true;
        Ok(handle)
    }

    pub const fn enforcement_report(&self) -> &EnforcementReport {
        &self.report
    }

    pub const fn output_budget(&self) -> usize {
        self.output_budget
    }

    pub const fn is_terminal(&self) -> bool {
        self.terminal
    }

    pub fn wait(
        &self,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ProcessOutput, ProcessError>> {
        if cancellation.is_cancelled() {
            let termination = self.control.terminate_tree();
            return Box::pin(async move {
                termination.await?;
                Err(ProcessError::Cancelled)
            });
        }
        let output_budget = self.output_budget;
        let future = self.control.wait(cancellation);
        Box::pin(async move {
            let output = future.await?;
            if output.encoded_bytes() > output_budget {
                return Err(ProcessError::ProviderContractViolation);
            }
            Ok(output)
        })
    }

    pub fn terminate_tree(&self) -> ProcessFuture<'_, Result<(), ProcessError>> {
        self.control.terminate_tree()
    }

    pub fn write_terminal(
        &self,
        data: TerminalBytes,
    ) -> ProcessFuture<'_, Result<(), ProcessError>> {
        if !self.terminal {
            return Box::pin(async { Err(ProcessError::InteractiveIoUnavailable) });
        }
        self.control.write_terminal(data)
    }

    pub fn read_terminal(
        &self,
        request: TerminalReadRequest,
    ) -> ProcessFuture<'_, Result<TerminalBytes, ProcessError>> {
        if !self.terminal {
            return Box::pin(async { Err(ProcessError::InteractiveIoUnavailable) });
        }
        let max_bytes = request.max_bytes().get();
        let future = self.control.read_terminal(request);
        Box::pin(async move {
            let bytes = future.await?;
            if bytes.len() > max_bytes {
                return Err(ProcessError::ProviderContractViolation);
            }
            TerminalBytes::checked(bytes).map_err(|_| ProcessError::ProviderContractViolation)
        })
    }

    pub fn resize_terminal(
        &self,
        size: TerminalSize,
    ) -> ProcessFuture<'_, Result<(), ProcessError>> {
        if !self.terminal {
            return Box::pin(async { Err(ProcessError::InteractiveIoUnavailable) });
        }
        self.control.resize_terminal(size)
    }
}

impl fmt::Debug for ProcessHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessHandle")
            .field("report", &self.report)
            .field("output_budget", &self.output_budget)
            .field("terminal", &self.terminal)
            .finish_non_exhaustive()
    }
}

pub trait Sandbox: MaybeSendSync {
    fn provider_key(&self) -> CanonicalId;

    fn effects(&self) -> SecurityEffects;

    fn confine(
        &self,
        process: ProcessSpec,
        policy: SandboxPolicy,
    ) -> ProcessFuture<'_, Result<ConfinedProcessSpec, SandboxError>>;
}

#[derive(Clone)]
pub struct SandboxBinding {
    component_identity: Option<CanonicalId>,
    provider_key: CanonicalId,
    effects: SecurityEffects,
    provider: Arc<dyn Sandbox>,
}

impl SandboxBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: Sandbox + 'static,
    {
        Self {
            component_identity: None,
            provider_key: provider.provider_key(),
            effects: provider.effects(),
            provider,
        }
    }

    #[doc(hidden)]
    pub fn from_generated_component<T>(
        component_identity: impl Into<String>,
        effective_effects: SecurityEffects,
        provider: Arc<T>,
    ) -> Result<Self, SandboxError>
    where
        T: Sandbox + 'static,
    {
        let component_identity = CanonicalId::new(component_identity.into())
            .map_err(|_| SandboxError::InvalidProviderIdentity)?;
        if !provider.effects().is_subset_of(effective_effects) {
            return Err(SandboxError::ProviderContractViolation);
        }
        Ok(Self {
            component_identity: Some(component_identity),
            provider_key: provider.provider_key(),
            effects: effective_effects,
            provider,
        })
    }

    pub fn provider_key(&self) -> &str {
        self.provider_key.as_str()
    }

    pub const fn effects(&self) -> SecurityEffects {
        self.effects
    }

    pub fn confine(
        &self,
        process: ProcessSpec,
        policy: SandboxPolicy,
    ) -> ProcessFuture<'_, Result<ConfinedProcessSpec, SandboxError>> {
        self.provider.confine(process, policy)
    }
}

impl fmt::Debug for SandboxBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SandboxBinding")
            .field("component_identity", &self.component_identity)
            .field("provider_key", &self.provider_key)
            .field("effects", &self.effects)
            .finish_non_exhaustive()
    }
}

pub trait Subprocess: MaybeSendSync {
    fn provider_key(&self) -> CanonicalId;

    fn effects(&self) -> SecurityEffects;

    fn spawn(
        &self,
        spec: ConfinedProcessSpec,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ProcessHandle, ProcessError>>;
}

#[derive(Clone)]
pub struct SubprocessBinding {
    component_identity: Option<CanonicalId>,
    provider_key: CanonicalId,
    effects: SecurityEffects,
    provider: Arc<dyn Subprocess>,
}

impl SubprocessBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: Subprocess + 'static,
    {
        Self {
            component_identity: None,
            provider_key: provider.provider_key(),
            effects: provider.effects(),
            provider,
        }
    }

    #[doc(hidden)]
    pub fn from_generated_component<T>(
        component_identity: impl Into<String>,
        effective_effects: SecurityEffects,
        provider: Arc<T>,
    ) -> Result<Self, ProcessError>
    where
        T: Subprocess + 'static,
    {
        let component_identity = CanonicalId::new(component_identity.into())
            .map_err(|_| ProcessError::InvalidProviderIdentity)?;
        if !provider.effects().is_subset_of(effective_effects) {
            return Err(ProcessError::ProviderContractViolation);
        }
        Ok(Self {
            component_identity: Some(component_identity),
            provider_key: provider.provider_key(),
            effects: effective_effects,
            provider,
        })
    }

    pub fn provider_key(&self) -> &str {
        self.provider_key.as_str()
    }

    pub const fn effects(&self) -> SecurityEffects {
        self.effects
    }

    pub fn spawn(
        &self,
        spec: ConfinedProcessSpec,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ProcessHandle, ProcessError>> {
        if cancellation.is_cancelled() {
            return Box::pin(async { Err(ProcessError::Cancelled) });
        }
        let expected_digest = spec.policy_digest();
        let expected_backend = spec.backend_kind();
        let required_primitives = spec.required_primitives();
        let expected_output_budget = spec.output_budget();
        let expected_terminal = spec.is_terminal();
        let future = self.provider.spawn(spec, cancellation);
        Box::pin(async move {
            let handle = future.await?;
            let report = handle.enforcement_report();
            if report.policy_digest() != expected_digest
                || report.backend() != expected_backend
                || !report.applied_primitives().contains(required_primitives)
                || handle.output_budget() != expected_output_budget
                || handle.is_terminal() != expected_terminal
            {
                handle.terminate_tree().await?;
                return Err(ProcessError::InvalidEnforcementReport);
            }
            Ok(handle)
        })
    }
}

impl fmt::Debug for SubprocessBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubprocessBinding")
            .field("component_identity", &self.component_identity)
            .field("provider_key", &self.provider_key)
            .field("effects", &self.effects)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxError {
    AuthorityExhausted,
    AuthorityMismatch,
    PolicyExceedsCeiling,
    PolicyDigestMismatch,
    UnsupportedPolicy,
    InvalidProviderIdentity,
    ProviderContractViolation,
}

impl SandboxError {
    pub(crate) const fn from_policy(error: SandboxPolicyError) -> Self {
        match error {
            SandboxPolicyError::PolicyDigestMismatch => Self::PolicyDigestMismatch,
            SandboxPolicyError::LimitExceedsHardMaximum | SandboxPolicyError::UnsupportedPolicy => {
                Self::UnsupportedPolicy
            }
        }
    }
}

impl fmt::Display for SandboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AuthorityExhausted => "confinement authority identities are exhausted",
            Self::AuthorityMismatch => "confinement issuer authority does not match",
            Self::PolicyExceedsCeiling => "effective sandbox policy exceeds its immutable ceiling",
            Self::PolicyDigestMismatch => "sandbox policy and backend plan digest do not match",
            Self::UnsupportedPolicy => "sandbox backend cannot enforce the effective policy",
            Self::InvalidProviderIdentity => "sandbox provider identity is invalid",
            Self::ProviderContractViolation => "sandbox provider violated its binding contract",
        })
    }
}

impl std::error::Error for SandboxError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessError {
    Cancelled,
    DeadlineExceeded,
    AuthorityMismatch,
    PolicyExceedsCeiling,
    PolicyDigestMismatch,
    UnsupportedPolicy,
    SetupFailed,
    SpawnFailed,
    WaitFailed,
    TerminationFailed,
    OutputBudgetExceeded,
    InteractiveIoUnavailable,
    InteractiveIoFailed,
    InvalidEnforcementReport,
    InvalidProviderIdentity,
    ProviderContractViolation,
}

impl ProcessError {
    pub(crate) const fn from_policy(error: SandboxPolicyError) -> Self {
        match error {
            SandboxPolicyError::PolicyDigestMismatch => Self::PolicyDigestMismatch,
            SandboxPolicyError::LimitExceedsHardMaximum | SandboxPolicyError::UnsupportedPolicy => {
                Self::UnsupportedPolicy
            }
        }
    }
}

impl fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Cancelled => "process operation was cancelled",
            Self::DeadlineExceeded => "process operation deadline was exceeded",
            Self::AuthorityMismatch => "confined process authority does not match",
            Self::PolicyExceedsCeiling => "confined process policy exceeds its ceiling",
            Self::PolicyDigestMismatch => "confined process policy digest does not match",
            Self::UnsupportedPolicy => "subprocess backend does not support the policy",
            Self::SetupFailed => "child confinement setup failed before execution",
            Self::SpawnFailed => "process spawn failed",
            Self::WaitFailed => "process wait failed",
            Self::TerminationFailed => "process tree termination failed",
            Self::OutputBudgetExceeded => "process output exceeds its shared byte budget",
            Self::InteractiveIoUnavailable => "process has no interactive terminal",
            Self::InteractiveIoFailed => "interactive process I/O failed",
            Self::InvalidEnforcementReport => "process enforcement report is invalid",
            Self::InvalidProviderIdentity => "subprocess provider identity is invalid",
            Self::ProviderContractViolation => "subprocess provider violated its binding contract",
        })
    }
}

impl std::error::Error for ProcessError {}
