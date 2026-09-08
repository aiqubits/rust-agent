use std::{fmt, sync::Arc};

use rust_agent_commands::CommandInvocationId;
use rust_agent_core::{CallId, CanonicalId, Digest, MaybeSendSync, SecurityEffects};
use rust_agent_runtime_api::{CancellationToken, RuntimeInstant};

use crate::{StepId, ToolExecutionError, ToolExecutionResult, ToolFuture, ToolSafety};

pub const MAX_TOOL_EXECUTION_MIDDLEWARE: usize = 64;
pub const MAX_TOOL_MIDDLEWARE_ERROR_BYTES: usize = 4 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolAroundExecutionPhase {
    Before,
    After,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolPrePolicyDecision {
    Continue,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolPostPolicyDecision {
    Accept,
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolMiddlewareStage {
    PreToolPolicy,
    AroundToolExecutionBefore,
    AroundToolExecutionAfter,
    PostToolPolicy,
    ToolResultObserver,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolMiddlewareErrorKind {
    Policy,
    Execution,
    Observer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolExecutionOrigin {
    ModelStep(StepId),
    Command {
        invocation_id: CommandInvocationId,
        caller_digest: Digest,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolMiddlewareError {
    kind: ToolMiddlewareErrorKind,
    message: Arc<str>,
}

impl ToolMiddlewareError {
    pub fn new(kind: ToolMiddlewareErrorKind, message: impl Into<String>) -> Self {
        let mut message = message.into();
        if message.len() > MAX_TOOL_MIDDLEWARE_ERROR_BYTES {
            message.truncate(floor_char_boundary(
                &message,
                MAX_TOOL_MIDDLEWARE_ERROR_BYTES,
            ));
        }
        Self {
            kind,
            message: Arc::from(message),
        }
    }

    pub const fn kind(&self) -> ToolMiddlewareErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ToolMiddlewareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "tool middleware {:?}: {}",
            self.kind, self.message
        )
    }
}

impl std::error::Error for ToolMiddlewareError {}

fn floor_char_boundary(value: &str, mut index: usize) -> usize {
    index = index.min(value.len());
    while !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

/// Immutable call projection. Middleware cannot replace arguments, effects, deadline, or signal.
#[derive(Clone, Debug)]
pub struct ToolMiddlewareContext {
    call_id: CallId,
    origin: ToolExecutionOrigin,
    tool_name: Arc<str>,
    arguments_digest: Digest,
    safety: ToolSafety,
    effects: SecurityEffects,
    concurrency_digest: Digest,
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
}

pub(crate) struct ToolMiddlewareContextInput {
    pub(crate) call_id: CallId,
    pub(crate) origin: ToolExecutionOrigin,
    pub(crate) tool_name: Arc<str>,
    pub(crate) arguments_digest: Digest,
    pub(crate) safety: ToolSafety,
    pub(crate) effects: SecurityEffects,
    pub(crate) concurrency_digest: Digest,
    pub(crate) cancellation: CancellationToken,
    pub(crate) deadline: Option<RuntimeInstant>,
}

impl ToolMiddlewareContext {
    pub(crate) fn from_guarded_call(input: ToolMiddlewareContextInput) -> Self {
        Self {
            call_id: input.call_id,
            origin: input.origin,
            tool_name: input.tool_name,
            arguments_digest: input.arguments_digest,
            safety: input.safety,
            effects: input.effects,
            concurrency_digest: input.concurrency_digest,
            cancellation: input.cancellation,
            deadline: input.deadline,
        }
    }

    pub const fn call_id(&self) -> CallId {
        self.call_id
    }

    pub const fn origin(&self) -> ToolExecutionOrigin {
        self.origin
    }

    pub const fn step(&self) -> Option<StepId> {
        match self.origin {
            ToolExecutionOrigin::ModelStep(step) => Some(step),
            ToolExecutionOrigin::Command { .. } => None,
        }
    }

    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    pub const fn arguments_digest(&self) -> Digest {
        self.arguments_digest
    }

    pub const fn safety(&self) -> ToolSafety {
        self.safety
    }

    pub const fn effects(&self) -> SecurityEffects {
        self.effects
    }

    pub const fn concurrency_digest(&self) -> Digest {
        self.concurrency_digest
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub(crate) fn cancellation_guard(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub const fn deadline(&self) -> Option<RuntimeInstant> {
        self.deadline
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ToolMiddlewareOutcome<'a> {
    Success(&'a ToolExecutionResult),
    Failure(&'a ToolExecutionError),
}

/// Typed execution extension. Default hooks are inert and cannot fabricate Tool output.
pub trait ToolExecutionMiddleware: MaybeSendSync {
    fn id(&self) -> &'static str;

    fn order(&self) -> i32;

    /// Runs after proof, permission, and approval. `Deny` short-circuits before the provider.
    fn pre_tool_policy<'a>(
        &'a self,
        _context: &'a ToolMiddlewareContext,
    ) -> ToolFuture<'a, Result<ToolPrePolicyDecision, ToolMiddlewareError>> {
        Box::pin(async { Ok(ToolPrePolicyDecision::Continue) })
    }

    /// Entry is called in ascending order and exit in reverse order.
    fn around_tool_execution<'a>(
        &'a self,
        _context: &'a ToolMiddlewareContext,
        _phase: ToolAroundExecutionPhase,
        _outcome: Option<ToolMiddlewareOutcome<'a>>,
    ) -> ToolFuture<'a, Result<(), ToolMiddlewareError>> {
        Box::pin(async { Ok(()) })
    }

    /// Runs only for a valid provider result. Reject/failure suppresses the successful result.
    fn post_tool_policy<'a>(
        &'a self,
        _context: &'a ToolMiddlewareContext,
        _result: &'a ToolExecutionResult,
    ) -> ToolFuture<'a, Result<ToolPostPolicyDecision, ToolMiddlewareError>> {
        Box::pin(async { Ok(ToolPostPolicyDecision::Accept) })
    }

    /// Best-effort observation. Failure never changes the already determined result.
    fn observe_tool_result<'a>(
        &'a self,
        _context: &'a ToolMiddlewareContext,
        _outcome: ToolMiddlewareOutcome<'a>,
    ) -> ToolFuture<'a, Result<(), ToolMiddlewareError>> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Clone)]
pub struct ToolExecutionMiddlewareBinding {
    id: &'static str,
    order: i32,
    provider: Arc<dyn ToolExecutionMiddleware>,
}

impl ToolExecutionMiddlewareBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: ToolExecutionMiddleware + 'static,
    {
        let id = provider.id();
        let order = provider.order();
        Self {
            id,
            order,
            provider,
        }
    }

    pub fn id(&self) -> &str {
        self.id
    }

    pub const fn order(&self) -> i32 {
        self.order
    }

    pub(crate) fn pre_tool_policy<'a>(
        &'a self,
        context: &'a ToolMiddlewareContext,
    ) -> ToolFuture<'a, Result<ToolPrePolicyDecision, ToolMiddlewareError>> {
        self.provider.pre_tool_policy(context)
    }

    pub(crate) fn around_tool_execution<'a>(
        &'a self,
        context: &'a ToolMiddlewareContext,
        phase: ToolAroundExecutionPhase,
        outcome: Option<ToolMiddlewareOutcome<'a>>,
    ) -> ToolFuture<'a, Result<(), ToolMiddlewareError>> {
        self.provider.around_tool_execution(context, phase, outcome)
    }

    pub(crate) fn post_tool_policy<'a>(
        &'a self,
        context: &'a ToolMiddlewareContext,
        result: &'a ToolExecutionResult,
    ) -> ToolFuture<'a, Result<ToolPostPolicyDecision, ToolMiddlewareError>> {
        self.provider.post_tool_policy(context, result)
    }

    pub(crate) fn observe_tool_result<'a>(
        &'a self,
        context: &'a ToolMiddlewareContext,
        outcome: ToolMiddlewareOutcome<'a>,
    ) -> ToolFuture<'a, Result<(), ToolMiddlewareError>> {
        self.provider.observe_tool_result(context, outcome)
    }
}

impl fmt::Debug for ToolExecutionMiddlewareBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolExecutionMiddlewareBinding")
            .field("id", &self.id)
            .field("order", &self.order)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolMiddlewareBuildError {
    InvalidIdentity,
    DuplicateIdentity,
    CountLimitExceeded,
}

impl fmt::Display for ToolMiddlewareBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentity => "invalid tool middleware identity",
            Self::DuplicateIdentity => "duplicate tool middleware identity",
            Self::CountLimitExceeded => "tool middleware count limit exceeded",
        })
    }
}

impl std::error::Error for ToolMiddlewareBuildError {}

#[derive(Debug)]
pub(crate) struct ToolMiddlewareChain {
    entries: Arc<[ToolExecutionMiddlewareBinding]>,
}

impl ToolMiddlewareChain {
    pub(crate) fn from_bindings(
        bindings: &[ToolExecutionMiddlewareBinding],
    ) -> Result<Self, ToolMiddlewareBuildError> {
        if bindings.len() > MAX_TOOL_EXECUTION_MIDDLEWARE {
            return Err(ToolMiddlewareBuildError::CountLimitExceeded);
        }
        let mut entries = bindings.to_vec();
        for entry in &entries {
            CanonicalId::new(entry.id.to_owned())
                .map_err(|_| ToolMiddlewareBuildError::InvalidIdentity)?;
        }
        entries.sort_by(|left, right| {
            left.order
                .cmp(&right.order)
                .then_with(|| left.id.cmp(right.id))
        });
        let mut identities = entries.iter().map(|entry| entry.id).collect::<Vec<_>>();
        identities.sort_unstable();
        if identities.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ToolMiddlewareBuildError::DuplicateIdentity);
        }
        Ok(Self {
            entries: entries.into(),
        })
    }

    pub(crate) fn entries(&self) -> &[ToolExecutionMiddlewareBinding] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct NoopMiddleware {
        id: &'static str,
        order: i32,
    }

    impl ToolExecutionMiddleware for NoopMiddleware {
        fn id(&self) -> &'static str {
            self.id
        }

        fn order(&self) -> i32 {
            self.order
        }
    }

    fn binding(id: &'static str, order: i32) -> ToolExecutionMiddlewareBinding {
        ToolExecutionMiddlewareBinding::from_provider(Arc::new(NoopMiddleware { id, order }))
    }

    #[test]
    fn chain_is_bounded_identity_checked_and_deterministically_ordered() {
        let chain = ToolMiddlewareChain::from_bindings(&[
            binding("z-last", 10),
            binding("b-same-order", 0),
            binding("a-same-order", 0),
        ])
        .unwrap();
        assert_eq!(
            chain
                .entries()
                .iter()
                .map(ToolExecutionMiddlewareBinding::id)
                .collect::<Vec<_>>(),
            ["a-same-order", "b-same-order", "z-last"]
        );
        assert_eq!(
            ToolMiddlewareChain::from_bindings(&[binding("same", 0), binding("same", 1)])
                .unwrap_err(),
            ToolMiddlewareBuildError::DuplicateIdentity
        );
        assert_eq!(
            ToolMiddlewareChain::from_bindings(&[binding("NotCanonical", 0)]).unwrap_err(),
            ToolMiddlewareBuildError::InvalidIdentity
        );
        assert_eq!(
            ToolMiddlewareChain::from_bindings(&vec![
                binding("bounded", 0);
                MAX_TOOL_EXECUTION_MIDDLEWARE + 1
            ])
            .unwrap_err(),
            ToolMiddlewareBuildError::CountLimitExceeded
        );
    }

    #[test]
    fn middleware_error_is_utf8_safely_bounded() {
        let error = ToolMiddlewareError::new(
            ToolMiddlewareErrorKind::Observer,
            "界".repeat(MAX_TOOL_MIDDLEWARE_ERROR_BYTES),
        );
        assert!(error.message().len() <= MAX_TOOL_MIDDLEWARE_ERROR_BYTES);
        assert!(error.message().is_char_boundary(error.message().len()));
    }
}
