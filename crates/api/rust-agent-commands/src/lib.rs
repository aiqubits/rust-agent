//! Command DTOs and the Phase 2 empty guarded dispatcher.

use std::{
    fmt,
    future::Future,
    num::NonZeroU64,
    pin::Pin,
    sync::{Arc, Weak},
};

use rust_agent_core::{AgentId, Digest};
use rust_agent_runtime_api::{AgentLifecycleNonce, CommandAdmissionError, CommandAdmissionGate};

pub const MAX_COMMAND_ARGUMENT_BYTES: usize = 64 * 1024;

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
    UnknownCommand(String),
    Closed,
    Busy,
    StaleLifecycle,
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(reason) => write!(formatter, "invalid command request: {reason}"),
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
            Err(CommandError::UnknownCommand(request.name))
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

    #[test]
    fn empty_dispatcher_checks_lifecycle_and_admission_before_lookup() {
        let gate: Arc<dyn CommandAdmissionGate> = Arc::new(Gate(Ok(())));
        let dispatcher =
            CommandDispatcher::empty_guarded(agent(1), lifecycle(1), Arc::downgrade(&gate));
        assert!(dispatcher.definitions().is_empty());
        assert_eq!(
            run(dispatcher.execute(request(agent(1), lifecycle(1)).unwrap())),
            Err(CommandError::UnknownCommand("missing".into()))
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
