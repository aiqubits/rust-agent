//! Effect-free permission decisions and approval capability contracts.

use std::{fmt, future::Future, pin::Pin, sync::Arc};

use rust_agent_core::{CanonicalId, Digest, MaybeSendSync, SecurityEffects};
use rust_agent_runtime_api::{CancellationToken, RuntimeInstant};

#[cfg(not(target_arch = "wasm32"))]
pub type ApprovalFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type ApprovalFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Closed action classes understood by permission providers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionKind {
    Tool,
    Command,
    Process,
    Network,
    Storage,
}

/// Monotonic risk classification supplied by the guarded capability owner.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ActionRisk {
    ReadOnly,
    Mutating,
    Sensitive,
    Unknown,
}

/// Bounded, immutable projection evaluated before an external action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Action {
    kind: ActionKind,
    subject: CanonicalId,
    risk: ActionRisk,
    effects: SecurityEffects,
    input_digest: Digest,
}

impl Action {
    pub fn new(
        kind: ActionKind,
        subject: impl Into<String>,
        risk: ActionRisk,
        effects: SecurityEffects,
        input_digest: Digest,
    ) -> Result<Self, ActionError> {
        let subject = CanonicalId::new(subject.into()).map_err(|_| ActionError::InvalidSubject)?;
        Ok(Self {
            kind,
            subject,
            risk,
            effects,
            input_digest,
        })
    }

    pub const fn kind(&self) -> ActionKind {
        self.kind
    }

    pub fn subject(&self) -> &str {
        self.subject.as_str()
    }

    pub const fn risk(&self) -> ActionRisk {
        self.risk
    }

    pub const fn effects(&self) -> SecurityEffects {
        self.effects
    }

    pub const fn input_digest(&self) -> Digest {
        self.input_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionError {
    InvalidSubject,
}

impl fmt::Display for ActionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid permission action subject")
    }
}

impl std::error::Error for ActionError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionDecision {
    Allow,
    Ask,
    Deny,
}

pub trait PermissionPolicy: MaybeSendSync {
    fn evaluate(&self, action: &Action) -> PermissionDecision;
}

/// Consumer-facing binding that does not expose the raw policy provider.
#[derive(Clone)]
pub struct PermissionPolicyBinding {
    provider: Arc<dyn PermissionPolicy>,
}

impl PermissionPolicyBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: PermissionPolicy + 'static,
    {
        Self { provider }
    }

    pub fn evaluate(&self, action: &Action) -> PermissionDecision {
        self.provider.evaluate(action)
    }
}

impl fmt::Debug for PermissionPolicyBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PermissionPolicyBinding")
            .finish_non_exhaustive()
    }
}

/// Exact request presented to the optional human approval boundary.
#[derive(Clone, Debug)]
pub struct ApprovalRequest {
    action: Action,
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
}

impl ApprovalRequest {
    pub fn new(
        action: Action,
        cancellation: CancellationToken,
        deadline: Option<RuntimeInstant>,
    ) -> Self {
        Self {
            action,
            cancellation,
            deadline,
        }
    }

    pub const fn action(&self) -> &Action {
        &self.action
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub const fn deadline(&self) -> Option<RuntimeInstant> {
        self.deadline
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    AllowOnce,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalError {
    Unavailable,
    Cancelled,
    DeadlineExceeded,
    InvalidResponse,
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "approval provider is unavailable",
            Self::Cancelled => "approval request was cancelled",
            Self::DeadlineExceeded => "approval request deadline exceeded",
            Self::InvalidResponse => "approval provider returned an invalid response",
        })
    }
}

impl std::error::Error for ApprovalError {}

pub trait Approval: MaybeSendSync {
    fn request(
        &self,
        request: ApprovalRequest,
    ) -> ApprovalFuture<'_, Result<ApprovalDecision, ApprovalError>>;
}

/// Consumer-facing binding that keeps Host approval implementations opaque.
#[derive(Clone)]
pub struct ApprovalBinding {
    provider: Arc<dyn Approval>,
}

impl ApprovalBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: Approval + 'static,
    {
        Self { provider }
    }

    pub fn request(
        &self,
        request: ApprovalRequest,
    ) -> ApprovalFuture<'_, Result<ApprovalDecision, ApprovalError>> {
        self.provider.request(request)
    }
}

impl fmt::Debug for ApprovalBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalBinding")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll, Waker};

    use super::*;

    #[derive(Debug)]
    struct AllowPolicy;

    impl PermissionPolicy for AllowPolicy {
        fn evaluate(&self, _action: &Action) -> PermissionDecision {
            PermissionDecision::Allow
        }
    }

    fn action() -> Action {
        Action::new(
            ActionKind::Tool,
            "test-tool",
            ActionRisk::ReadOnly,
            SecurityEffects::READ_LOCAL,
            Digest::from_bytes([7; 32]),
        )
        .unwrap()
    }

    #[test]
    fn action_is_canonical_and_binding_keeps_provider_opaque() {
        assert_eq!(
            Action::new(
                ActionKind::Tool,
                "Not Canonical",
                ActionRisk::ReadOnly,
                SecurityEffects::empty(),
                Digest::from_bytes([0; 32]),
            ),
            Err(ActionError::InvalidSubject)
        );
        let action = action();
        assert_eq!(action.subject(), "test-tool");
        assert_eq!(action.effects(), SecurityEffects::READ_LOCAL);
        let binding = PermissionPolicyBinding::from_provider(Arc::new(AllowPolicy));
        assert_eq!(binding.evaluate(&action), PermissionDecision::Allow);
    }

    #[test]
    fn approval_request_preserves_cancellation_deadline_and_action() {
        let cancellation = CancellationToken::new();
        let request = ApprovalRequest::new(action(), cancellation.clone(), None);
        assert_eq!(request.action().subject(), "test-tool");
        assert!(!request.cancellation().is_cancelled());
        cancellation.cancel();
        assert!(request.cancellation().is_cancelled());
        assert_eq!(request.deadline(), None);
    }

    #[derive(Debug)]
    struct UnavailableApproval;

    impl Approval for UnavailableApproval {
        fn request(
            &self,
            _request: ApprovalRequest,
        ) -> ApprovalFuture<'_, Result<ApprovalDecision, ApprovalError>> {
            Box::pin(async { Err(ApprovalError::Unavailable) })
        }
    }

    #[test]
    fn approval_binding_preserves_typed_failure() {
        let binding = ApprovalBinding::from_provider(Arc::new(UnavailableApproval));
        let mut future = binding.request(ApprovalRequest::new(
            action(),
            CancellationToken::new(),
            None,
        ));
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(
            future.as_mut().poll(&mut context),
            Poll::Ready(Err(ApprovalError::Unavailable))
        );
    }
}
