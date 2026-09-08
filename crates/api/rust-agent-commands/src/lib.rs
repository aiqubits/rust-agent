//! Command DTOs, the Phase 2 empty guarded dispatcher, and opaque Tool delegation authority.

use std::{
    fmt,
    future::Future,
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    pin::Pin,
    sync::{Arc, Weak},
};

use rust_agent_core::{AgentId, Digest, SecurityEffects};
use rust_agent_runtime_api::{
    AgentLifecycleNonce, CancellationToken, CommandAdmissionError, CommandAdmissionGate,
    RuntimeInstant, RuntimePrimitiveBindings,
};

pub const MAX_COMMAND_ARGUMENT_BYTES: usize = 64 * 1024;
pub const MAX_COMMAND_TOOL_CALLS: usize = 64;
pub const MAX_COMMAND_TOOL_COST_UNITS: usize = 4 * 1024;
pub const MAX_COMMAND_TOOL_OUTPUT_BYTES: usize = 256 * 1024;

#[cfg(not(target_arch = "wasm32"))]
pub type CommandFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type CommandFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: String,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CommandInvocationId {
    agent_id: AgentId,
    lifecycle: AgentLifecycleNonce,
    sequence: NonZeroU64,
}

impl CommandInvocationId {
    #[doc(hidden)]
    pub const fn from_agent(
        agent_id: AgentId,
        lifecycle: AgentLifecycleNonce,
        sequence: NonZeroU64,
    ) -> Self {
        Self {
            agent_id,
            lifecycle,
            sequence,
        }
    }

    pub const fn agent_id(self) -> AgentId {
        self.agent_id
    }

    pub const fn lifecycle(self) -> AgentLifecycleNonce {
        self.lifecycle
    }

    pub const fn sequence(self) -> u64 {
        self.sequence.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandToolBudget {
    calls: NonZeroUsize,
    cost_units: NonZeroUsize,
    output_bytes: NonZeroUsize,
}

impl CommandToolBudget {
    pub fn checked(
        max_calls: NonZeroUsize,
        max_cost_units: NonZeroUsize,
        max_output_bytes: NonZeroUsize,
    ) -> Result<Self, CommandDelegationError> {
        if max_calls.get() > MAX_COMMAND_TOOL_CALLS {
            return Err(CommandDelegationError::BudgetExceeded("max_calls"));
        }
        if max_cost_units.get() > MAX_COMMAND_TOOL_COST_UNITS {
            return Err(CommandDelegationError::BudgetExceeded("max_cost_units"));
        }
        if max_output_bytes.get() > MAX_COMMAND_TOOL_OUTPUT_BYTES {
            return Err(CommandDelegationError::BudgetExceeded("max_output_bytes"));
        }
        Ok(Self {
            calls: max_calls,
            cost_units: max_cost_units,
            output_bytes: max_output_bytes,
        })
    }

    pub const fn max_calls(self) -> NonZeroUsize {
        self.calls
    }

    pub const fn max_cost_units(self) -> NonZeroUsize {
        self.cost_units
    }

    pub const fn max_output_bytes(self) -> NonZeroUsize {
        self.output_bytes
    }
}

struct CommandAuthority {
    invocation_id: CommandInvocationId,
    caller_digest: Digest,
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
    tool_budget: CommandToolBudget,
    effect_ceiling: SecurityEffects,
    tool_executor_digest: Digest,
    runtime: RuntimePrimitiveBindings,
}

/// Opaque authority created only by guarded command dispatch after its journal gate.
pub struct CommandPermit {
    authority: Arc<CommandAuthority>,
}

impl fmt::Debug for CommandPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandPermit")
            .field("invocation_id", &self.authority.invocation_id)
            .finish_non_exhaustive()
    }
}

/// Immutable execution context paired with the current opaque command permit.
pub struct CommandContext {
    authority: Arc<CommandAuthority>,
}

impl fmt::Debug for CommandContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandContext")
            .field("invocation_id", &self.authority.invocation_id)
            .finish_non_exhaustive()
    }
}

impl CommandContext {
    pub fn invocation_id(&self) -> CommandInvocationId {
        self.authority.invocation_id
    }

    pub fn caller_digest(&self) -> Digest {
        self.authority.caller_digest
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.authority.cancellation.clone()
    }

    pub fn deadline(&self) -> Option<RuntimeInstant> {
        self.authority.deadline
    }
}

/// Tool authority borrowed from the exact current command permit and context.
pub struct CommandToolGrant<'a> {
    permit: &'a CommandPermit,
    _authority: PhantomData<&'a mut &'a ()>,
}

impl fmt::Debug for CommandToolGrant<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandToolGrant")
            .field("invocation_id", &self.permit.authority.invocation_id)
            .finish_non_exhaustive()
    }
}

impl CommandToolGrant<'_> {
    pub fn invocation_id(&self) -> CommandInvocationId {
        self.permit.authority.invocation_id
    }

    pub fn caller_digest(&self) -> Digest {
        self.permit.authority.caller_digest
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.permit.authority.cancellation.clone()
    }

    pub fn deadline(&self) -> Option<RuntimeInstant> {
        self.permit.authority.deadline
    }

    pub fn tool_budget(&self) -> CommandToolBudget {
        self.permit.authority.tool_budget
    }

    pub fn effect_ceiling(&self) -> SecurityEffects {
        self.permit.authority.effect_ceiling
    }

    pub fn tool_executor_digest(&self) -> Digest {
        self.permit.authority.tool_executor_digest
    }

    pub fn matches_runtime(&self, runtime: &RuntimePrimitiveBindings) -> bool {
        self.permit
            .authority
            .runtime
            .same_projection_identity(runtime)
    }
}

impl CommandPermit {
    pub fn delegate_tools<'a>(
        &'a self,
        context: &'a CommandContext,
    ) -> Result<CommandToolGrant<'a>, CommandDelegationError> {
        if !Arc::ptr_eq(&self.authority, &context.authority) {
            return Err(CommandDelegationError::AuthorityMismatch);
        }
        if self.authority.cancellation.is_cancelled() {
            return Err(CommandDelegationError::Cancelled);
        }
        if let Some(deadline) = self.authority.deadline
            && self
                .authority
                .runtime
                .now()
                .map_err(|_| CommandDelegationError::RuntimeUnavailable)?
                >= deadline
        {
            return Err(CommandDelegationError::DeadlineExceeded);
        }
        Ok(CommandToolGrant {
            permit: self,
            _authority: PhantomData,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandDelegationError {
    BudgetExceeded(&'static str),
    AuthorityMismatch,
    Cancelled,
    DeadlineExceeded,
    RuntimeUnavailable,
}

impl fmt::Display for CommandDelegationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExceeded(field) => {
                write!(
                    formatter,
                    "command tool budget `{field}` exceeds its hard ceiling"
                )
            }
            Self::AuthorityMismatch => {
                formatter.write_str("command context does not match the current permit")
            }
            Self::Cancelled => formatter.write_str("command tool delegation was cancelled"),
            Self::DeadlineExceeded => {
                formatter.write_str("command tool delegation deadline exceeded")
            }
            Self::RuntimeUnavailable => {
                formatter.write_str("command tool delegation runtime is unavailable")
            }
        }
    }
}

impl std::error::Error for CommandDelegationError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandRequest {
    invocation_id: CommandInvocationId,
    name: String,
    arguments: String,
    caller_digest: Digest,
}

impl CommandRequest {
    pub fn new(
        invocation_id: CommandInvocationId,
        name: impl Into<String>,
        arguments: impl Into<String>,
        caller_digest: Digest,
    ) -> Result<Self, CommandError> {
        let name = name.into();
        let arguments = arguments.into();
        if name.is_empty() || name.len() > 128 || !name.is_ascii() {
            return Err(CommandError::InvalidRequest("invalid command name"));
        }
        if arguments.len() > MAX_COMMAND_ARGUMENT_BYTES {
            return Err(CommandError::InvalidRequest(
                "command arguments are too large",
            ));
        }
        Ok(Self {
            invocation_id,
            name,
            arguments,
            caller_digest,
        })
    }

    pub const fn invocation_id(&self) -> CommandInvocationId {
        self.invocation_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn arguments(&self) -> &str {
        &self.arguments
    }

    pub const fn caller_digest(&self) -> Digest {
        self.caller_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandResult {
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandError {
    InvalidRequest(&'static str),
    UnsupportedOperation,
    UnknownCommand(String),
    Closed,
    Busy,
    StaleLifecycle,
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(reason) => write!(formatter, "invalid command request: {reason}"),
            Self::UnsupportedOperation => {
                formatter.write_str("commands are not compiled into this Agent")
            }
            Self::UnknownCommand(name) => write!(formatter, "unknown command `{name}`"),
            Self::Closed => formatter.write_str("command dispatcher is closed"),
            Self::Busy => formatter.write_str("Agent is busy"),
            Self::StaleLifecycle => formatter.write_str("command lifecycle is stale"),
        }
    }
}

impl std::error::Error for CommandError {}

pub struct CommandDispatcher {
    agent_id: AgentId,
    lifecycle: AgentLifecycleNonce,
    gate: Weak<dyn CommandAdmissionGate>,
    definitions: Arc<[CommandDefinition]>,
}

impl fmt::Debug for CommandDispatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandDispatcher")
            .field("agent_id", &self.agent_id)
            .field("lifecycle", &self.lifecycle)
            .field("definition_count", &self.definitions.len())
            .finish_non_exhaustive()
    }
}

impl CommandDispatcher {
    #[doc(hidden)]
    pub fn empty_guarded(
        agent_id: AgentId,
        lifecycle: AgentLifecycleNonce,
        gate: Weak<dyn CommandAdmissionGate>,
    ) -> Self {
        Self {
            agent_id,
            lifecycle,
            gate,
            definitions: Arc::from([]),
        }
    }

    pub fn definitions(&self) -> Arc<[CommandDefinition]> {
        Arc::clone(&self.definitions)
    }

    pub fn execute(
        &self,
        request: CommandRequest,
    ) -> CommandFuture<'_, Result<CommandResult, CommandError>> {
        Box::pin(async move {
            if request.invocation_id.agent_id != self.agent_id
                || request.invocation_id.lifecycle != self.lifecycle
            {
                return Err(CommandError::StaleLifecycle);
            }
            let gate = self.gate.upgrade().ok_or(CommandError::Closed)?;
            gate.admit_command(self.agent_id, self.lifecycle)
                .map_err(|error| match error {
                    CommandAdmissionError::Closed => CommandError::Closed,
                    CommandAdmissionError::Busy => CommandError::Busy,
                    CommandAdmissionError::StaleLifecycle => CommandError::StaleLifecycle,
                })?;
            drop((request.name, request.arguments, request.caller_digest));
            Err(CommandError::UnsupportedOperation)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        num::NonZeroU64,
        sync::Arc,
        task::{Context, Poll, Wake, Waker},
        thread,
    };

    use super::*;

    struct ThreadWake(thread::Thread);

    impl Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }

    fn run<F: Future>(future: F) -> F::Output {
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

    struct Gate(Result<(), CommandAdmissionError>);

    impl CommandAdmissionGate for Gate {
        fn admit_command(
            &self,
            _agent_id: AgentId,
            _lifecycle: AgentLifecycleNonce,
        ) -> Result<(), CommandAdmissionError> {
            self.0
        }
    }

    fn agent(value: u128) -> AgentId {
        AgentId::from_nonzero_u128(value).unwrap()
    }

    fn lifecycle(value: u64) -> AgentLifecycleNonce {
        AgentLifecycleNonce::from_nonzero(NonZeroU64::new(value).unwrap())
    }

    fn request(
        agent_id: AgentId,
        lifecycle: AgentLifecycleNonce,
    ) -> Result<CommandRequest, CommandError> {
        CommandRequest::new(
            CommandInvocationId::from_agent(agent_id, lifecycle, NonZeroU64::new(1).unwrap()),
            "missing",
            "{}",
            Digest::from_bytes([1; 32]),
        )
    }

    fn command_authority(cancellation: CancellationToken) -> Arc<CommandAuthority> {
        Arc::new(CommandAuthority {
            invocation_id: CommandInvocationId::from_agent(
                agent(1),
                lifecycle(1),
                NonZeroU64::new(9).unwrap(),
            ),
            caller_digest: Digest::from_bytes([7; 32]),
            cancellation,
            deadline: None,
            tool_budget: CommandToolBudget::checked(
                NonZeroUsize::new(4).unwrap(),
                NonZeroUsize::new(16).unwrap(),
                NonZeroUsize::new(4096).unwrap(),
            )
            .unwrap(),
            effect_ceiling: SecurityEffects::READ_LOCAL,
            tool_executor_digest: Digest::from_bytes([8; 32]),
            runtime: RuntimePrimitiveBindings::none(),
        })
    }

    #[test]
    fn command_tool_budget_and_exact_permit_delegation_are_bounded() {
        assert_eq!(
            command_authority(CancellationToken::new())
                .tool_budget
                .max_cost_units()
                .get(),
            16
        );
        assert_eq!(
            CommandToolBudget::checked(
                NonZeroUsize::new(MAX_COMMAND_TOOL_CALLS + 1).unwrap(),
                NonZeroUsize::new(1).unwrap(),
                NonZeroUsize::new(1).unwrap(),
            ),
            Err(CommandDelegationError::BudgetExceeded("max_calls"))
        );
        assert_eq!(
            CommandToolBudget::checked(
                NonZeroUsize::new(1).unwrap(),
                NonZeroUsize::new(MAX_COMMAND_TOOL_COST_UNITS + 1).unwrap(),
                NonZeroUsize::new(1).unwrap(),
            ),
            Err(CommandDelegationError::BudgetExceeded("max_cost_units"))
        );
        assert_eq!(
            CommandToolBudget::checked(
                NonZeroUsize::new(1).unwrap(),
                NonZeroUsize::new(1).unwrap(),
                NonZeroUsize::new(MAX_COMMAND_TOOL_OUTPUT_BYTES + 1).unwrap(),
            ),
            Err(CommandDelegationError::BudgetExceeded("max_output_bytes"))
        );

        let authority = command_authority(CancellationToken::new());
        let permit = CommandPermit {
            authority: Arc::clone(&authority),
        };
        let context = CommandContext {
            authority: Arc::clone(&authority),
        };
        let grant = permit.delegate_tools(&context).unwrap();
        assert_eq!(grant.invocation_id(), authority.invocation_id);
        assert_eq!(grant.caller_digest(), authority.caller_digest);
        assert_eq!(grant.effect_ceiling(), SecurityEffects::READ_LOCAL);
        assert_eq!(grant.tool_executor_digest(), Digest::from_bytes([8; 32]));
        assert_eq!(grant.tool_budget(), authority.tool_budget);
        assert!(grant.deadline().is_none());
        assert!(!grant.cancellation().is_cancelled());
        assert!(grant.matches_runtime(&authority.runtime));

        let foreign = CommandContext {
            authority: command_authority(CancellationToken::new()),
        };
        assert!(matches!(
            permit.delegate_tools(&foreign),
            Err(CommandDelegationError::AuthorityMismatch)
        ));

        let cancellation = CancellationToken::new();
        let cancelled_authority = command_authority(cancellation.clone());
        let cancelled_permit = CommandPermit {
            authority: Arc::clone(&cancelled_authority),
        };
        let cancelled_context = CommandContext {
            authority: cancelled_authority,
        };
        cancellation.cancel();
        assert!(matches!(
            cancelled_permit.delegate_tools(&cancelled_context),
            Err(CommandDelegationError::Cancelled)
        ));
    }

    #[test]
    fn empty_dispatcher_checks_lifecycle_and_admission_before_lookup() {
        let gate: Arc<dyn CommandAdmissionGate> = Arc::new(Gate(Ok(())));
        let dispatcher =
            CommandDispatcher::empty_guarded(agent(1), lifecycle(1), Arc::downgrade(&gate));
        assert!(dispatcher.definitions().is_empty());
        assert_eq!(
            run(dispatcher.execute(request(agent(1), lifecycle(1)).unwrap())),
            Err(CommandError::UnsupportedOperation)
        );
        assert_eq!(
            run(dispatcher.execute(request(agent(2), lifecycle(1)).unwrap())),
            Err(CommandError::StaleLifecycle)
        );

        let busy: Arc<dyn CommandAdmissionGate> = Arc::new(Gate(Err(CommandAdmissionError::Busy)));
        let dispatcher =
            CommandDispatcher::empty_guarded(agent(1), lifecycle(1), Arc::downgrade(&busy));
        assert_eq!(
            run(dispatcher.execute(request(agent(1), lifecycle(1)).unwrap())),
            Err(CommandError::Busy)
        );
        drop(busy);
        assert_eq!(
            run(dispatcher.execute(request(agent(1), lifecycle(1)).unwrap())),
            Err(CommandError::Closed)
        );
    }
}
