use std::{fmt, sync::Arc};

use rust_agent_core::{CanonicalId, MaybeSendSync, SecurityEffects};
use rust_agent_fs::AgentPath;
use rust_agent_policy::process::{MAX_PROCESS_OUTPUT_BYTES, SandboxPolicy};
use rust_agent_runtime_api::CancellationToken;

use crate::{
    EnforcementReport, MAX_PROCESS_INPUT_BYTES, ProcessEnvironment, ProcessError, ProcessExit,
    ProcessFuture, ProcessOutput,
};

pub const MAX_SHELL_COMMAND_BYTES: usize = 64 * 1024;

#[derive(Clone, Eq, PartialEq)]
pub struct ShellRequest {
    command: Arc<str>,
    cwd: AgentPath,
    environment: ProcessEnvironment,
    stdin: Arc<[u8]>,
    policy: SandboxPolicy,
}

impl fmt::Debug for ShellRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShellRequest")
            .field("command_len", &self.command.len())
            .field("cwd", &self.cwd)
            .field("environment", &self.environment)
            .field("stdin_len", &self.stdin.len())
            .field("policy", &self.policy)
            .finish()
    }
}

impl ShellRequest {
    pub fn checked(
        command: impl Into<String>,
        cwd: AgentPath,
        environment: ProcessEnvironment,
        stdin: Vec<u8>,
        policy: SandboxPolicy,
    ) -> Result<Self, ShellError> {
        let command = command.into();
        if command.is_empty()
            || command.len() > MAX_SHELL_COMMAND_BYTES
            || command.bytes().any(|byte| byte == 0)
        {
            return Err(ShellError::InvalidCommand);
        }
        if stdin.len() > MAX_PROCESS_INPUT_BYTES {
            return Err(ShellError::InputTooLarge);
        }
        Ok(Self {
            command: Arc::from(command),
            cwd,
            environment,
            stdin: Arc::from(stdin),
            policy,
        })
    }

    pub fn command(&self) -> &str {
        &self.command
    }

    pub const fn cwd(&self) -> &AgentPath {
        &self.cwd
    }

    pub const fn environment(&self) -> &ProcessEnvironment {
        &self.environment
    }

    pub fn stdin(&self) -> &[u8] {
        &self.stdin
    }

    pub const fn policy(&self) -> &SandboxPolicy {
        &self.policy
    }
}

/// Binding-issued provider-resolved shell spec. It cannot be constructed by a consumer.
#[derive(Clone)]
pub struct ShellSpec {
    provider_key: CanonicalId,
    binding_authority: Option<Arc<()>>,
    request: ShellRequest,
}

impl ShellSpec {
    pub fn provider_key(&self) -> &str {
        self.provider_key.as_str()
    }

    pub const fn request(&self) -> &ShellRequest {
        &self.request
    }

    pub const fn output_budget(&self) -> usize {
        self.request.policy.limits().max_output_bytes().get()
    }
}

impl fmt::Debug for ShellSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShellSpec")
            .field("provider_key", &self.provider_key)
            .field("request", self.request())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellResult {
    provider_key: CanonicalId,
    output: ProcessOutput,
    enforcement_report: Option<EnforcementReport>,
}

impl ShellResult {
    #[doc(hidden)]
    pub fn from_provider(
        provider_key: CanonicalId,
        exit: ProcessExit,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        byte_budget: usize,
        enforcement_report: Option<EnforcementReport>,
    ) -> Result<Self, ShellError> {
        let output = ProcessOutput::checked(exit, stdout, stderr, byte_budget)
            .map_err(ShellError::from_process)?;
        Ok(Self {
            provider_key,
            output,
            enforcement_report,
        })
    }

    pub fn provider_key(&self) -> &str {
        self.provider_key.as_str()
    }

    pub const fn output(&self) -> &ProcessOutput {
        &self.output
    }

    pub const fn enforcement_report(&self) -> Option<&EnforcementReport> {
        self.enforcement_report.as_ref()
    }
}

pub trait ShellProcessControl: MaybeSendSync {
    fn wait(
        &self,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ShellResult, ShellError>>;

    fn terminate_tree(&self) -> ProcessFuture<'_, Result<(), ShellError>>;
}

pub struct ShellProcess {
    provider_key: CanonicalId,
    output_budget: usize,
    control: Arc<dyn ShellProcessControl>,
}

impl ShellProcess {
    #[doc(hidden)]
    pub fn from_provider<T>(
        provider_key: CanonicalId,
        output_budget: usize,
        control: Arc<T>,
    ) -> Result<Self, ShellError>
    where
        T: ShellProcessControl + 'static,
    {
        if output_budget == 0 || output_budget > MAX_PROCESS_OUTPUT_BYTES {
            return Err(ShellError::ProviderContractViolation);
        }
        Ok(Self {
            provider_key,
            output_budget,
            control,
        })
    }

    pub fn provider_key(&self) -> &str {
        self.provider_key.as_str()
    }

    pub fn wait(
        &self,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ShellResult, ShellError>> {
        if cancellation.is_cancelled() {
            let termination = self.control.terminate_tree();
            return Box::pin(async move {
                termination.await?;
                Err(ShellError::Cancelled)
            });
        }
        let provider_key = self.provider_key.clone();
        let output_budget = self.output_budget;
        let future = self.control.wait(cancellation);
        Box::pin(async move {
            let result = future.await?;
            if result.provider_key != provider_key || result.output.encoded_bytes() > output_budget
            {
                return Err(ShellError::ProviderContractViolation);
            }
            Ok(result)
        })
    }

    pub fn terminate_tree(&self) -> ProcessFuture<'_, Result<(), ShellError>> {
        self.control.terminate_tree()
    }
}

impl fmt::Debug for ShellProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShellProcess")
            .field("provider_key", &self.provider_key)
            .field("output_budget", &self.output_budget)
            .finish_non_exhaustive()
    }
}

pub trait Shell: MaybeSendSync {
    fn provider_key(&self) -> CanonicalId;

    fn effects(&self) -> SecurityEffects;

    /// Applies provider-specific defaults and caps before the binding seals the result.
    fn normalize(&self, request: ShellRequest) -> Result<ShellRequest, ShellError>;

    fn resolve(&self, request: ShellRequest) -> Result<ShellSpec, ShellError> {
        let request = self.normalize(request)?;
        Ok(ShellSpec {
            provider_key: self.provider_key(),
            binding_authority: None,
            request,
        })
    }

    fn run(
        &self,
        spec: ShellSpec,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ShellResult, ShellError>>;

    fn start(
        &self,
        spec: ShellSpec,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ShellProcess, ShellError>>;
}

#[derive(Clone)]
pub struct ShellBinding {
    component_identity: Option<CanonicalId>,
    provider_key: CanonicalId,
    effects: SecurityEffects,
    binding_authority: Arc<()>,
    provider: Arc<dyn Shell>,
}

impl ShellBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: Shell + 'static,
    {
        Self {
            component_identity: None,
            provider_key: provider.provider_key(),
            effects: provider.effects(),
            binding_authority: Arc::new(()),
            provider,
        }
    }

    #[doc(hidden)]
    pub fn from_generated_component<T>(
        component_identity: impl Into<String>,
        effective_effects: SecurityEffects,
        provider: Arc<T>,
    ) -> Result<Self, ShellError>
    where
        T: Shell + 'static,
    {
        let component_identity = CanonicalId::new(component_identity.into())
            .map_err(|_| ShellError::InvalidProviderIdentity)?;
        if !provider.effects().is_subset_of(effective_effects) {
            return Err(ShellError::ProviderContractViolation);
        }
        Ok(Self {
            component_identity: Some(component_identity),
            provider_key: provider.provider_key(),
            effects: effective_effects,
            binding_authority: Arc::new(()),
            provider,
        })
    }

    pub fn provider_key(&self) -> &str {
        self.provider_key.as_str()
    }

    pub const fn effects(&self) -> SecurityEffects {
        self.effects
    }

    pub fn resolve(&self, request: ShellRequest) -> Result<ShellSpec, ShellError> {
        let mut spec = self.provider.resolve(request)?;
        if spec.provider_key != self.provider_key || spec.binding_authority.is_some() {
            return Err(ShellError::ProviderContractViolation);
        }
        spec.binding_authority = Some(Arc::clone(&self.binding_authority));
        Ok(spec)
    }

    pub fn run(
        &self,
        spec: ShellSpec,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ShellResult, ShellError>> {
        if cancellation.is_cancelled() {
            return Box::pin(async { Err(ShellError::Cancelled) });
        }
        if spec.provider_key != self.provider_key
            || !spec
                .binding_authority
                .as_ref()
                .is_some_and(|authority| Arc::ptr_eq(authority, &self.binding_authority))
        {
            return Box::pin(async { Err(ShellError::ForeignSpec) });
        }
        let provider_key = self.provider_key.clone();
        let output_budget = spec.output_budget();
        let future = self.provider.run(spec, cancellation);
        Box::pin(async move {
            let result = future.await?;
            if result.provider_key != provider_key || result.output.encoded_bytes() > output_budget
            {
                return Err(ShellError::ProviderContractViolation);
            }
            Ok(result)
        })
    }

    pub fn start(
        &self,
        spec: ShellSpec,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ShellProcess, ShellError>> {
        if cancellation.is_cancelled() {
            return Box::pin(async { Err(ShellError::Cancelled) });
        }
        if spec.provider_key != self.provider_key
            || !spec
                .binding_authority
                .as_ref()
                .is_some_and(|authority| Arc::ptr_eq(authority, &self.binding_authority))
        {
            return Box::pin(async { Err(ShellError::ForeignSpec) });
        }
        let provider_key = self.provider_key.clone();
        let output_budget = spec.output_budget();
        let future = self.provider.start(spec, cancellation);
        Box::pin(async move {
            let process = future.await?;
            if process.provider_key != provider_key || process.output_budget != output_budget {
                process.terminate_tree().await?;
                return Err(ShellError::ProviderContractViolation);
            }
            Ok(process)
        })
    }
}

impl fmt::Debug for ShellBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShellBinding")
            .field("component_identity", &self.component_identity)
            .field("provider_key", &self.provider_key)
            .field("effects", &self.effects)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShellError {
    InvalidCommand,
    InputTooLarge,
    Cancelled,
    DeadlineExceeded,
    ForeignSpec,
    ResolveFailed,
    Process(ProcessError),
    InvalidProviderIdentity,
    ProviderContractViolation,
}

impl ShellError {
    const fn from_process(error: ProcessError) -> Self {
        Self::Process(error)
    }
}

impl fmt::Display for ShellError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Process(error) => write!(formatter, "shell process failed: {error}"),
            other => formatter.write_str(match other {
                Self::InvalidCommand => "shell command is empty, invalid, or too large",
                Self::InputTooLarge => "shell standard input exceeds the hard maximum",
                Self::Cancelled => "shell operation was cancelled",
                Self::DeadlineExceeded => "shell operation deadline was exceeded",
                Self::ForeignSpec => "shell spec belongs to a different provider",
                Self::ResolveFailed => "shell request resolution failed",
                Self::InvalidProviderIdentity => "shell provider identity is invalid",
                Self::ProviderContractViolation => "shell provider violated its binding contract",
                Self::Process(_) => unreachable!(),
            }),
        }
    }
}

impl std::error::Error for ShellError {}
