use std::{
    collections::BTreeSet,
    fmt,
    future::{Future, poll_fn},
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    task::Poll,
};

use rust_agent_core::{
    AgentId, CallId, CompositionHash, Digest, MaybeSendSync, RequestId, SecurityEffects, SessionId,
};
use rust_agent_policy::{
    Action, ActionKind, ActionRisk, ApprovalBinding, ApprovalDecision, ApprovalError,
    ApprovalRequest, PermissionDecision, PermissionPolicyBinding,
};
use rust_agent_runtime_api::{
    AgentLifecycleNonce, CancellationToken, RuntimeInstant, RuntimePrimitives,
    ToolCallJournalProjection, ToolCallJournalProof, ToolCallJournalVerifier,
};
use serde_json::Value as JsonValue;

use crate::{
    JsonKind, MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_OUTPUT_ITEMS, MAX_TOOL_OUTPUT_JSON_DEPTH,
    ToolArgumentPredicate, ToolConcurrencyRule, ToolDefinition, ToolError,
    ToolMiddlewareBuildError, ToolMiddlewareContext, ToolMiddlewareError, ToolMiddlewareOutcome,
    ToolMiddlewareStage, ToolOutputError, ToolPostPolicyDecision, ToolPrePolicyDecision,
    ToolProviderBinding, ToolProviderError, ToolSafety, ToolValue, ToolValueItem, hash_parts,
    middleware::{
        ToolAroundExecutionPhase, ToolExecutionMiddlewareBinding, ToolMiddlewareChain,
        ToolMiddlewareContextInput,
    },
    output::ToolOutputLimits,
    registry::{RegisteredTool, ToolRegistry},
};

pub const MAX_TOOL_ARGUMENT_BYTES: usize = 64 * 1024;
pub const MAX_TOOL_ARGUMENT_DEPTH: usize = 16;
pub const MAX_TOOL_CALLS_PER_STEP: usize = 128;
pub const MAX_ACTIVE_TOOL_SESSIONS: usize = 64;
pub const MAX_NESTED_TOOL_DEPTH: u8 = 8;
pub const MAX_NESTED_TOOL_CALLS: usize = 64;

/// Stable model-step coordinate supplied by the driver.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StepId {
    request_id: RequestId,
    ordinal: NonZeroU64,
}

impl StepId {
    pub const fn new(request_id: RequestId, ordinal: NonZeroU64) -> Self {
        Self {
            request_id,
            ordinal,
        }
    }

    pub const fn request_id(self) -> RequestId {
        self.request_id
    }

    pub const fn ordinal(self) -> u64 {
        self.ordinal.get()
    }

    fn digest(self) -> Digest {
        hash_parts(&[
            b"rust-agent-tool-step-v1\0",
            &self.request_id.to_canonical_v1_bytes(),
            &self.ordinal.get().to_be_bytes(),
        ])
    }
}

/// Scope-owned model-origin execution parameters. Fields cannot be replaced by a driver.
#[derive(Clone, Debug)]
pub struct ToolScope {
    agent_id: AgentId,
    lifecycle: AgentLifecycleNonce,
    session_id: Option<SessionId>,
    composition: CompositionHash,
    catalog: Digest,
}

impl ToolScope {
    #[doc(hidden)]
    pub const fn for_generated_agent(
        agent_id: AgentId,
        lifecycle: AgentLifecycleNonce,
        session_id: Option<SessionId>,
        composition: CompositionHash,
        catalog: Digest,
    ) -> Self {
        Self {
            agent_id,
            lifecycle,
            session_id,
            composition,
            catalog,
        }
    }

    pub const fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    pub const fn lifecycle(&self) -> AgentLifecycleNonce {
        self.lifecycle
    }

    pub const fn session_id(&self) -> Option<SessionId> {
        self.session_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolExecutionRequest {
    call_id: CallId,
    tool_name: Arc<str>,
    arguments: JsonValue,
    provider_call_id: Option<Arc<str>>,
}

impl ToolExecutionRequest {
    pub fn new(
        call_id: CallId,
        tool_name: impl Into<String>,
        arguments: JsonValue,
    ) -> Result<Self, ToolExecutionError> {
        let tool_name = tool_name.into();
        rust_agent_core::CanonicalId::new(tool_name.clone())
            .map_err(|_| ToolExecutionError::InvalidRequest("invalid tool name"))?;
        if !arguments.is_object() {
            return Err(ToolExecutionError::InvalidRequest(
                "tool arguments must be a JSON object",
            ));
        }
        if json_depth(&arguments) > MAX_TOOL_ARGUMENT_DEPTH {
            return Err(ToolExecutionError::InvalidRequest(
                "tool arguments exceed the depth limit",
            ));
        }
        let bytes = serde_json::to_vec(&arguments)
            .map_err(|_| ToolExecutionError::InvalidRequest("invalid tool arguments"))?
            .len();
        if bytes > MAX_TOOL_ARGUMENT_BYTES {
            return Err(ToolExecutionError::InvalidRequest(
                "tool arguments exceed the byte limit",
            ));
        }
        Ok(Self {
            call_id,
            tool_name: Arc::from(tool_name),
            arguments,
            provider_call_id: None,
        })
    }

    pub fn with_provider_call_id(
        mut self,
        provider_call_id: impl Into<String>,
    ) -> Result<Self, ToolExecutionError> {
        let provider_call_id = provider_call_id.into();
        if provider_call_id.is_empty()
            || provider_call_id.len() > 256
            || provider_call_id.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(ToolExecutionError::InvalidRequest(
                "invalid provider tool call id",
            ));
        }
        self.provider_call_id = Some(Arc::from(provider_call_id));
        Ok(self)
    }

    pub const fn call_id(&self) -> CallId {
        self.call_id
    }

    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    pub const fn arguments(&self) -> &JsonValue {
        &self.arguments
    }

    pub fn provider_call_id(&self) -> Option<&str> {
        self.provider_call_id.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolExecutionResult {
    call_id: CallId,
    tool_name: Arc<str>,
    value: ToolValue,
}

impl ToolExecutionResult {
    pub const fn call_id(&self) -> CallId {
        self.call_id
    }

    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    pub const fn value(&self) -> &ToolValue {
        &self.value
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolExecutionError {
    InvalidRequest(&'static str),
    InvalidSchema,
    SchemaMismatch,
    UnknownTool(Arc<str>),
    Provider(ToolProviderError),
    EffectCeilingExceeded,
    JournalAuthorityMismatch,
    JournalProofMismatch,
    PermissionDenied,
    ApprovalRequired,
    Approval(ApprovalError),
    Cancelled,
    DeadlineExceeded,
    RuntimeUnavailable,
    CallLimitExceeded,
    DuplicateCallId,
    SessionLimitExceeded,
    NestedAuthorityMismatch,
    NestedDepthLimitExceeded,
    NestedCycleDetected,
    Closed,
    MiddlewareConfiguration(ToolMiddlewareBuildError),
    MiddlewareDenied {
        middleware_id: Arc<str>,
        stage: ToolMiddlewareStage,
    },
    Middleware {
        middleware_id: Arc<str>,
        stage: ToolMiddlewareStage,
        error: ToolMiddlewareError,
    },
    InternalStateUnavailable,
    InvalidOutput(ToolOutputError),
    Tool(ToolError),
}

impl fmt::Display for ToolExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(reason) => write!(formatter, "invalid tool request: {reason}"),
            Self::InvalidSchema => formatter.write_str("tool has an unsupported input schema"),
            Self::SchemaMismatch => formatter.write_str("tool arguments do not match the schema"),
            Self::UnknownTool(name) => write!(formatter, "unknown tool `{name}`"),
            Self::Provider(error) => write!(formatter, "tool provider error: {error}"),
            Self::EffectCeilingExceeded => {
                formatter.write_str("classified tool effects exceed the sealed ceiling")
            }
            Self::JournalAuthorityMismatch => {
                formatter.write_str("tool scope does not match the journal authority")
            }
            Self::JournalProofMismatch => formatter.write_str("tool journal proof mismatch"),
            Self::PermissionDenied => formatter.write_str("tool call denied by permission policy"),
            Self::ApprovalRequired => {
                formatter.write_str("tool call requires an unavailable approval capability")
            }
            Self::Approval(error) => write!(formatter, "tool approval failed: {error}"),
            Self::Cancelled => formatter.write_str("tool call cancelled"),
            Self::DeadlineExceeded => formatter.write_str("tool call deadline exceeded"),
            Self::RuntimeUnavailable => formatter.write_str("tool runtime primitive unavailable"),
            Self::CallLimitExceeded => formatter.write_str("tool call count limit exceeded"),
            Self::DuplicateCallId => formatter.write_str("duplicate normalized tool call id"),
            Self::SessionLimitExceeded => {
                formatter.write_str("active tool execution session limit exceeded")
            }
            Self::NestedAuthorityMismatch => {
                formatter.write_str("nested tool authority does not match the current Tool context")
            }
            Self::NestedDepthLimitExceeded => {
                formatter.write_str("nested tool depth limit exceeded")
            }
            Self::NestedCycleDetected => formatter.write_str("nested tool call cycle detected"),
            Self::Closed => formatter.write_str("guarded tool executor is closed"),
            Self::MiddlewareConfiguration(error) => {
                write!(formatter, "tool middleware configuration failed: {error}")
            }
            Self::MiddlewareDenied {
                middleware_id,
                stage,
            } => write!(
                formatter,
                "tool middleware `{middleware_id}` denied call at {stage:?}"
            ),
            Self::Middleware {
                middleware_id,
                stage,
                error,
            } => write!(
                formatter,
                "tool middleware `{middleware_id}` failed at {stage:?}: {error}"
            ),
            Self::InternalStateUnavailable => {
                formatter.write_str("tool execution state unavailable")
            }
            Self::InvalidOutput(error) => write!(formatter, "invalid tool output: {error}"),
            Self::Tool(error) => write!(formatter, "tool failed: {error}"),
        }
    }
}

impl std::error::Error for ToolExecutionError {}

impl From<ToolProviderError> for ToolExecutionError {
    fn from(value: ToolProviderError) -> Self {
        Self::Provider(value)
    }
}

#[derive(Clone, Debug)]
struct ClassifiedCall {
    safety: ToolSafety,
    effects: SecurityEffects,
    concurrency_digest: Digest,
}

/// Immutable plan produced without touching permission, approval, or raw handlers.
#[allow(missing_debug_implementations)]
pub struct ToolCallPlan {
    session_identity: Arc<SessionIdentity>,
    verifier: ToolCallJournalVerifier,
    registered: RegisteredTool,
    request: ToolExecutionRequest,
    step_digest: Digest,
    arguments_digest: Digest,
    effects_digest: Digest,
    plan_digest: Digest,
    classified: ClassifiedCall,
}

impl ToolCallPlan {
    pub fn journal_projection(&self) -> ToolCallJournalProjection {
        ToolCallJournalProjection::from_tool_plan(
            self.request.call_id,
            self.step_digest,
            self.registered.identity_digest(),
            self.session_identity.snapshot_digest,
            self.arguments_digest,
            self.effects_digest,
        )
    }

    pub const fn record_digest(&self) -> Digest {
        self.plan_digest
    }

    pub fn seal(self, proof: ToolCallJournalProof) -> Result<PreparedToolCall, ToolExecutionError> {
        if !self
            .verifier
            .verifies(&proof, &self.journal_projection(), self.plan_digest)
            || proof.output_budget().get() > MAX_TOOL_OUTPUT_BYTES
        {
            return Err(ToolExecutionError::JournalProofMismatch);
        }
        Ok(PreparedToolCall { plan: self, proof })
    }
}

/// Prepared model-origin call. Its fields are private and it is not serializable.
#[allow(missing_debug_implementations)]
pub struct PreparedToolCall {
    plan: ToolCallPlan,
    proof: ToolCallJournalProof,
}

#[derive(Debug)]
struct SessionIdentity {
    snapshot_digest: Digest,
}

#[derive(Debug)]
struct NestedCallBudget {
    admitted: Mutex<BTreeSet<CallId>>,
}

#[derive(Debug)]
pub(crate) struct NestedToolAuthority {
    owner: Weak<GuardedToolExecutorInner>,
    step: StepId,
    root_call_id: CallId,
    depth: u8,
    calls: Arc<NestedCallBudget>,
    effect_ceiling: SecurityEffects,
    chain: Arc<[Arc<str>]>,
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
    output_budget: std::num::NonZeroUsize,
    runtime: RuntimePrimitives,
}

impl NestedToolAuthority {
    pub(crate) const fn root_call_id(&self) -> CallId {
        self.root_call_id
    }
}

/// Raw execution session available only while borrowing the current execution authority.
pub struct BorrowedToolExecutionSession<'a> {
    owner: Weak<GuardedToolExecutorInner>,
    definitions: Arc<[ToolDefinition]>,
    step: StepId,
    root_call_id: CallId,
    depth: u8,
    calls: Arc<NestedCallBudget>,
    effect_ceiling: SecurityEffects,
    chain: Arc<[Arc<str>]>,
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
    output_budget: std::num::NonZeroUsize,
    runtime: RuntimePrimitives,
    _authority: PhantomData<&'a mut &'a ()>,
}

impl fmt::Debug for BorrowedToolExecutionSession<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BorrowedToolExecutionSession")
            .field("root_call_id", &self.root_call_id)
            .field("depth", &self.depth)
            .finish_non_exhaustive()
    }
}

impl BorrowedToolExecutionSession<'_> {
    pub fn definitions(&self) -> Arc<[ToolDefinition]> {
        Arc::clone(&self.definitions)
    }

    pub fn execute(
        &self,
        request: ToolExecutionRequest,
    ) -> crate::ToolFuture<'_, Result<ToolExecutionResult, ToolExecutionError>> {
        Box::pin(async move {
            if self.depth > MAX_NESTED_TOOL_DEPTH {
                return Err(ToolExecutionError::NestedDepthLimitExceeded);
            }
            let owner = self.owner.upgrade().ok_or(ToolExecutionError::Closed)?;
            check_guard(&self.cancellation, self.deadline, &self.runtime)?;
            let registered = owner
                .registry
                .lookup(request.tool_name())
                .ok_or_else(|| ToolExecutionError::UnknownTool(Arc::clone(&request.tool_name)))?
                .clone();
            validate_schema(registered.definition().input_schema(), request.arguments())?;
            let classified = classify(registered.definition(), request.arguments())?;
            if !classified
                .effects
                .is_subset_of(registered.effective_ceiling())
                || !classified.effects.is_subset_of(self.effect_ceiling)
            {
                return Err(ToolExecutionError::EffectCeilingExceeded);
            }
            if self
                .chain
                .iter()
                .any(|name| name.as_ref() == request.tool_name())
            {
                return Err(ToolExecutionError::NestedCycleDetected);
            }
            {
                let mut admitted = self
                    .calls
                    .admitted
                    .lock()
                    .map_err(|_| ToolExecutionError::InternalStateUnavailable)?;
                if admitted.len() == MAX_NESTED_TOOL_CALLS {
                    return Err(ToolExecutionError::CallLimitExceeded);
                }
                if request.call_id == self.root_call_id || !admitted.insert(request.call_id) {
                    return Err(ToolExecutionError::DuplicateCallId);
                }
            }

            let arguments = serde_json::to_vec(request.arguments())
                .map_err(|_| ToolExecutionError::InvalidRequest("invalid tool arguments"))?;
            let arguments_digest = hash_parts(&[b"rust-agent-tool-arguments-v1\0", &arguments]);
            let action = Action::new(
                ActionKind::Tool,
                request.tool_name().to_owned(),
                action_risk(classified.safety),
                classified.effects,
                arguments_digest,
            )
            .map_err(|_| ToolExecutionError::InvalidRequest("invalid permission subject"))?;
            match owner.permission.evaluate(&action) {
                PermissionDecision::Allow => {}
                PermissionDecision::Deny => return Err(ToolExecutionError::PermissionDenied),
                PermissionDecision::Ask => {
                    let approval = owner
                        .approval
                        .as_ref()
                        .ok_or(ToolExecutionError::ApprovalRequired)?;
                    let decision = await_guarded(
                        approval.request(ApprovalRequest::new(
                            action.clone(),
                            self.cancellation.clone(),
                            self.deadline,
                        )),
                        self.cancellation.clone(),
                        self.deadline,
                        &self.runtime,
                    )
                    .await?
                    .map_err(ToolExecutionError::Approval)?;
                    if decision != ApprovalDecision::AllowOnce {
                        return Err(ToolExecutionError::PermissionDenied);
                    }
                }
            }
            check_guard(&self.cancellation, self.deadline, &self.runtime)?;

            let middleware_context =
                ToolMiddlewareContext::from_guarded_call(ToolMiddlewareContextInput {
                    call_id: request.call_id,
                    step: self.step,
                    tool_name: Arc::clone(&request.tool_name),
                    arguments_digest,
                    safety: classified.safety,
                    effects: classified.effects,
                    concurrency_digest: classified.concurrency_digest,
                    cancellation: self.cancellation.clone(),
                    deadline: self.deadline,
                });
            owner
                .run_pre_middleware(&middleware_context, &self.runtime)
                .await?;
            owner
                .run_around_before(&middleware_context, &self.runtime)
                .await?;

            let limits = ToolOutputLimits::checked(
                MAX_TOOL_OUTPUT_ITEMS,
                self.output_budget,
                MAX_TOOL_OUTPUT_JSON_DEPTH,
            )
            .map_err(ToolExecutionError::InvalidOutput)?;
            let mut chain = self.chain.to_vec();
            chain.push(Arc::clone(&request.tool_name));
            let authority = Arc::new(NestedToolAuthority {
                owner: Arc::downgrade(&owner),
                step: self.step,
                root_call_id: self.root_call_id,
                depth: self.depth,
                calls: Arc::clone(&self.calls),
                effect_ceiling: classified.effects,
                chain: chain.into(),
                cancellation: self.cancellation.clone(),
                deadline: self.deadline,
                output_budget: self.output_budget,
                runtime: self.runtime.clone(),
            });
            let context = crate::ToolContext {
                cancellation: self.cancellation.clone(),
                deadline: self.deadline,
                output_limits: limits,
                authority: Arc::clone(&authority),
            };
            let permit = crate::ExecutionPermit { authority };
            let mut outcome = execute_registered(
                &registered,
                request,
                &permit,
                &context,
                RawExecutionGuard {
                    cancellation: self.cancellation.clone(),
                    deadline: self.deadline,
                    runtime: &self.runtime,
                    output_budget: self.output_budget,
                },
            )
            .await;

            if let Err(error) = owner
                .run_around_after(&middleware_context, &outcome, &self.runtime)
                .await
                && outcome.is_ok()
            {
                outcome = Err(error);
            }
            if let Ok(result) = &outcome
                && let Err(error) = owner
                    .run_post_middleware(&middleware_context, result, &self.runtime)
                    .await
            {
                outcome = Err(error);
            }
            owner
                .observe_middleware(&middleware_context, &outcome, &self.runtime)
                .await;
            outcome
        })
    }
}

pub(crate) fn prepare_nested<'a>(
    context: &'a crate::ToolContext,
    parent: &'a crate::ExecutionPermit,
) -> Result<BorrowedToolExecutionSession<'a>, ToolExecutionError> {
    if !Arc::ptr_eq(&context.authority, &parent.authority) {
        return Err(ToolExecutionError::NestedAuthorityMismatch);
    }
    let authority = &context.authority;
    check_guard(
        &authority.cancellation,
        authority.deadline,
        &authority.runtime,
    )?;
    let depth = authority
        .depth
        .checked_add(1)
        .ok_or(ToolExecutionError::NestedDepthLimitExceeded)?;
    if depth > MAX_NESTED_TOOL_DEPTH {
        return Err(ToolExecutionError::NestedDepthLimitExceeded);
    }
    let owner = authority
        .owner
        .upgrade()
        .ok_or(ToolExecutionError::Closed)?;
    let definitions = owner.registry.definitions();
    drop(owner);
    Ok(BorrowedToolExecutionSession {
        owner: authority.owner.clone(),
        definitions,
        step: authority.step,
        root_call_id: authority.root_call_id,
        depth,
        calls: Arc::clone(&authority.calls),
        effect_ceiling: authority.effect_ceiling,
        chain: Arc::clone(&authority.chain),
        cancellation: authority.cancellation.clone(),
        deadline: authority.deadline,
        output_budget: authority.output_budget,
        runtime: authority.runtime.clone(),
        _authority: PhantomData,
    })
}

#[cfg(test)]
pub(crate) fn test_nested_authority() -> Arc<NestedToolAuthority> {
    Arc::new(NestedToolAuthority {
        owner: Weak::new(),
        step: StepId::new(
            RequestId::from_nonzero_u128(1).unwrap(),
            NonZeroU64::new(1).unwrap(),
        ),
        root_call_id: CallId::from_nonzero_u128(1).unwrap(),
        depth: 0,
        calls: Arc::new(NestedCallBudget {
            admitted: Mutex::new(BTreeSet::new()),
        }),
        effect_ceiling: SecurityEffects::empty(),
        chain: Arc::from([]),
        cancellation: CancellationToken::new(),
        deadline: None,
        output_budget: std::num::NonZeroUsize::new(1).unwrap(),
        runtime: RuntimePrimitives::new(
            rust_agent_runtime_api::RuntimeAdapterIdentity::checked("test-runtime").unwrap(),
        ),
    })
}

/// Model-origin session: it intentionally has no raw `execute` method.
pub struct ToolExecutionSession {
    owner: Arc<GuardedToolExecutorInner>,
    identity: Arc<SessionIdentity>,
    verifier: ToolCallJournalVerifier,
    step: StepId,
    planned_calls: Mutex<BTreeSet<CallId>>,
}

impl fmt::Debug for ToolExecutionSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolExecutionSession")
            .field("step", &self.step)
            .finish_non_exhaustive()
    }
}

impl ToolExecutionSession {
    pub fn definitions(&self) -> Arc<[ToolDefinition]> {
        self.owner.registry.definitions()
    }

    pub fn plan_call(
        &self,
        request: ToolExecutionRequest,
    ) -> Result<ToolCallPlan, ToolExecutionError> {
        let registered = self
            .owner
            .registry
            .lookup(request.tool_name())
            .ok_or_else(|| ToolExecutionError::UnknownTool(Arc::clone(&request.tool_name)))?
            .clone();
        validate_schema(registered.definition().input_schema(), request.arguments())?;
        let classified = classify(registered.definition(), request.arguments())?;
        if !classified
            .effects
            .is_subset_of(registered.effective_ceiling())
        {
            return Err(ToolExecutionError::EffectCeilingExceeded);
        }
        let arguments = serde_json::to_vec(request.arguments())
            .map_err(|_| ToolExecutionError::InvalidRequest("invalid tool arguments"))?;
        let arguments_digest = hash_parts(&[b"rust-agent-tool-arguments-v1\0", &arguments]);
        let effects_digest = hash_parts(&[
            b"rust-agent-tool-effects-v1\0",
            &[classified.safety as u8],
            &classified.effects.bits().to_be_bytes(),
            classified.concurrency_digest.as_bytes(),
        ]);
        let provider_call_id_digest = match request.provider_call_id() {
            Some(value) => {
                hash_parts(&[b"rust-agent-provider-tool-call-id-v1\0", value.as_bytes()])
            }
            None => hash_parts(&[b"rust-agent-provider-tool-call-id-absent-v1\0"]),
        };
        let step_digest = self.step.digest();
        let plan_digest = hash_parts(&[
            b"rust-agent-tool-plan-v1\0",
            &request.call_id.to_canonical_v1_bytes(),
            step_digest.as_bytes(),
            registered.identity_digest().as_bytes(),
            self.identity.snapshot_digest.as_bytes(),
            arguments_digest.as_bytes(),
            effects_digest.as_bytes(),
            provider_call_id_digest.as_bytes(),
        ]);
        let mut planned_calls = self
            .planned_calls
            .lock()
            .map_err(|_| ToolExecutionError::InternalStateUnavailable)?;
        if planned_calls.len() == MAX_TOOL_CALLS_PER_STEP {
            return Err(ToolExecutionError::CallLimitExceeded);
        }
        if !planned_calls.insert(request.call_id) {
            return Err(ToolExecutionError::DuplicateCallId);
        }
        drop(planned_calls);
        Ok(ToolCallPlan {
            session_identity: Arc::clone(&self.identity),
            verifier: self.verifier.clone(),
            registered,
            request,
            step_digest,
            arguments_digest,
            effects_digest,
            plan_digest,
            classified,
        })
    }

    pub fn execute_prepared(
        &self,
        call: PreparedToolCall,
    ) -> crate::ToolFuture<'_, Result<ToolExecutionResult, ToolExecutionError>> {
        Box::pin(async move {
            if !Arc::ptr_eq(&self.identity, &call.plan.session_identity)
                || !self.verifier.verifies(
                    &call.proof,
                    &call.plan.journal_projection(),
                    call.plan.plan_digest,
                )
            {
                return Err(ToolExecutionError::JournalProofMismatch);
            }
            let cancellation = call.proof.cancellation();
            let deadline = call.proof.deadline();
            let runtime = call.proof.runtime().clone();
            check_guard(&cancellation, deadline, &runtime)?;

            let action = Action::new(
                ActionKind::Tool,
                call.plan.request.tool_name().to_owned(),
                action_risk(call.plan.classified.safety),
                call.plan.classified.effects,
                call.plan.arguments_digest,
            )
            .map_err(|_| ToolExecutionError::InvalidRequest("invalid permission subject"))?;
            match self.owner.permission.evaluate(&action) {
                PermissionDecision::Allow => {}
                PermissionDecision::Deny => return Err(ToolExecutionError::PermissionDenied),
                PermissionDecision::Ask => {
                    let approval = self
                        .owner
                        .approval
                        .as_ref()
                        .ok_or(ToolExecutionError::ApprovalRequired)?;
                    let decision = await_guarded(
                        approval.request(ApprovalRequest::new(
                            action.clone(),
                            cancellation.clone(),
                            deadline,
                        )),
                        cancellation.clone(),
                        deadline,
                        &runtime,
                    )
                    .await?
                    .map_err(ToolExecutionError::Approval)?;
                    if decision != ApprovalDecision::AllowOnce {
                        return Err(ToolExecutionError::PermissionDenied);
                    }
                }
            }
            check_guard(&cancellation, deadline, &runtime)?;

            let middleware_context =
                ToolMiddlewareContext::from_guarded_call(ToolMiddlewareContextInput {
                    call_id: call.plan.request.call_id,
                    step: self.step,
                    tool_name: Arc::clone(&call.plan.request.tool_name),
                    arguments_digest: call.plan.arguments_digest,
                    safety: call.plan.classified.safety,
                    effects: call.plan.classified.effects,
                    concurrency_digest: call.plan.classified.concurrency_digest,
                    cancellation: cancellation.clone(),
                    deadline,
                });
            self.owner
                .run_pre_middleware(&middleware_context, &runtime)
                .await?;
            self.owner
                .run_around_before(&middleware_context, &runtime)
                .await?;

            let limits = ToolOutputLimits::checked(
                MAX_TOOL_OUTPUT_ITEMS,
                call.proof.output_budget(),
                MAX_TOOL_OUTPUT_JSON_DEPTH,
            )
            .map_err(ToolExecutionError::InvalidOutput)?;
            let authority = Arc::new(NestedToolAuthority {
                owner: Arc::downgrade(&self.owner),
                step: self.step,
                root_call_id: call.plan.request.call_id,
                depth: 0,
                calls: Arc::new(NestedCallBudget {
                    admitted: Mutex::new(BTreeSet::new()),
                }),
                effect_ceiling: call.plan.classified.effects,
                chain: Arc::from([Arc::clone(&call.plan.request.tool_name)]),
                cancellation: cancellation.clone(),
                deadline,
                output_budget: call.proof.output_budget(),
                runtime: runtime.clone(),
            });
            let context = crate::ToolContext {
                cancellation: cancellation.clone(),
                deadline,
                output_limits: limits,
                authority: Arc::clone(&authority),
            };
            let permit = crate::ExecutionPermit { authority };
            let mut outcome = execute_registered(
                &call.plan.registered,
                call.plan.request,
                &permit,
                &context,
                RawExecutionGuard {
                    cancellation,
                    deadline,
                    runtime: &runtime,
                    output_budget: call.proof.output_budget(),
                },
            )
            .await;

            if let Err(error) = self
                .owner
                .run_around_after(&middleware_context, &outcome, &runtime)
                .await
                && outcome.is_ok()
            {
                outcome = Err(error);
            }
            if let Ok(result) = &outcome
                && let Err(error) = self
                    .owner
                    .run_post_middleware(&middleware_context, result, &runtime)
                    .await
            {
                outcome = Err(error);
            }
            self.owner
                .observe_middleware(&middleware_context, &outcome, &runtime)
                .await;
            outcome
        })
    }
}

impl GuardedToolExecutorInner {
    async fn run_pre_middleware(
        &self,
        context: &ToolMiddlewareContext,
        runtime: &RuntimePrimitives,
    ) -> Result<(), ToolExecutionError> {
        for middleware in self.middleware.entries() {
            check_guard(&context.cancellation_guard(), context.deadline(), runtime)?;
            let decision = await_guarded(
                middleware.pre_tool_policy(context),
                context.cancellation_guard(),
                context.deadline(),
                runtime,
            )
            .await?
            .map_err(|error| {
                middleware_error(middleware, ToolMiddlewareStage::PreToolPolicy, error)
            })?;
            if decision == ToolPrePolicyDecision::Deny {
                return Err(ToolExecutionError::MiddlewareDenied {
                    middleware_id: Arc::from(middleware.id()),
                    stage: ToolMiddlewareStage::PreToolPolicy,
                });
            }
        }
        Ok(())
    }

    async fn run_around_before(
        &self,
        context: &ToolMiddlewareContext,
        runtime: &RuntimePrimitives,
    ) -> Result<(), ToolExecutionError> {
        for middleware in self.middleware.entries() {
            check_guard(&context.cancellation_guard(), context.deadline(), runtime)?;
            await_guarded(
                middleware.around_tool_execution(context, ToolAroundExecutionPhase::Before, None),
                context.cancellation_guard(),
                context.deadline(),
                runtime,
            )
            .await?
            .map_err(|error| {
                middleware_error(
                    middleware,
                    ToolMiddlewareStage::AroundToolExecutionBefore,
                    error,
                )
            })?;
        }
        Ok(())
    }

    async fn run_around_after(
        &self,
        context: &ToolMiddlewareContext,
        outcome: &Result<ToolExecutionResult, ToolExecutionError>,
        runtime: &RuntimePrimitives,
    ) -> Result<(), ToolExecutionError> {
        let outcome = middleware_outcome(outcome);
        for middleware in self.middleware.entries().iter().rev() {
            check_guard(&context.cancellation_guard(), context.deadline(), runtime)?;
            await_guarded(
                middleware.around_tool_execution(
                    context,
                    ToolAroundExecutionPhase::After,
                    Some(outcome),
                ),
                context.cancellation_guard(),
                context.deadline(),
                runtime,
            )
            .await?
            .map_err(|error| {
                middleware_error(
                    middleware,
                    ToolMiddlewareStage::AroundToolExecutionAfter,
                    error,
                )
            })?;
        }
        Ok(())
    }

    async fn run_post_middleware(
        &self,
        context: &ToolMiddlewareContext,
        result: &ToolExecutionResult,
        runtime: &RuntimePrimitives,
    ) -> Result<(), ToolExecutionError> {
        for middleware in self.middleware.entries() {
            check_guard(&context.cancellation_guard(), context.deadline(), runtime)?;
            let decision = await_guarded(
                middleware.post_tool_policy(context, result),
                context.cancellation_guard(),
                context.deadline(),
                runtime,
            )
            .await?
            .map_err(|error| {
                middleware_error(middleware, ToolMiddlewareStage::PostToolPolicy, error)
            })?;
            if decision == ToolPostPolicyDecision::Reject {
                return Err(ToolExecutionError::MiddlewareDenied {
                    middleware_id: Arc::from(middleware.id()),
                    stage: ToolMiddlewareStage::PostToolPolicy,
                });
            }
        }
        Ok(())
    }

    async fn observe_middleware(
        &self,
        context: &ToolMiddlewareContext,
        outcome: &Result<ToolExecutionResult, ToolExecutionError>,
        runtime: &RuntimePrimitives,
    ) {
        let outcome = middleware_outcome(outcome);
        for middleware in self.middleware.entries() {
            if check_guard(&context.cancellation_guard(), context.deadline(), runtime).is_err() {
                break;
            }
            if await_guarded(
                middleware.observe_tool_result(context, outcome),
                context.cancellation_guard(),
                context.deadline(),
                runtime,
            )
            .await
            .is_err()
            {
                break;
            }
        }
    }
}

fn middleware_outcome(
    outcome: &Result<ToolExecutionResult, ToolExecutionError>,
) -> ToolMiddlewareOutcome<'_> {
    match outcome {
        Ok(result) => ToolMiddlewareOutcome::Success(result),
        Err(error) => ToolMiddlewareOutcome::Failure(error),
    }
}

fn middleware_error(
    middleware: &ToolExecutionMiddlewareBinding,
    stage: ToolMiddlewareStage,
    error: ToolMiddlewareError,
) -> ToolExecutionError {
    ToolExecutionError::Middleware {
        middleware_id: Arc::from(middleware.id()),
        stage,
        error,
    }
}

impl Drop for ToolExecutionSession {
    fn drop(&mut self) {
        self.owner.active_sessions.fetch_sub(1, Ordering::AcqRel);
    }
}

pub trait ToolExecutor: MaybeSendSync {
    fn prepare_model_step(
        &self,
        scope: &ToolScope,
        step: StepId,
    ) -> Result<Arc<ToolExecutionSession>, ToolExecutionError>;
}

#[derive(Clone)]
pub struct ToolExecutorBinding {
    provider: Arc<dyn ToolExecutor>,
}

impl ToolExecutorBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: ToolExecutor + 'static,
    {
        Self { provider }
    }

    pub fn prepare_model_step(
        &self,
        scope: &ToolScope,
        step: StepId,
    ) -> Result<Arc<ToolExecutionSession>, ToolExecutionError> {
        self.provider.prepare_model_step(scope, step)
    }
}

impl fmt::Debug for ToolExecutorBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolExecutorBinding")
            .finish_non_exhaustive()
    }
}

struct GuardedToolExecutorInner {
    registry: ToolRegistry,
    permission: PermissionPolicyBinding,
    approval: Option<ApprovalBinding>,
    middleware: ToolMiddlewareChain,
    verifier: ToolCallJournalVerifier,
    active_sessions: AtomicUsize,
}

impl fmt::Debug for GuardedToolExecutorInner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuardedToolExecutorInner")
            .field("registry", &self.registry)
            .field("approval_present", &self.approval.is_some())
            .field("middleware_count", &self.middleware.entries().len())
            .finish_non_exhaustive()
    }
}

/// Opaque guarded reference monitor assembled by `guarded_component::build`.
#[derive(Debug)]
pub struct GuardedToolExecutor {
    inner: Arc<GuardedToolExecutorInner>,
}

impl GuardedToolExecutor {
    pub(crate) fn build(
        providers: &[ToolProviderBinding],
        permission: PermissionPolicyBinding,
        approval: Option<ApprovalBinding>,
        middleware: &[ToolExecutionMiddlewareBinding],
        verifier: ToolCallJournalVerifier,
    ) -> Result<Self, ToolExecutionError> {
        Ok(Self {
            inner: Arc::new(GuardedToolExecutorInner {
                registry: ToolRegistry::from_bindings(providers)?,
                permission,
                approval,
                middleware: ToolMiddlewareChain::from_bindings(middleware)
                    .map_err(ToolExecutionError::MiddlewareConfiguration)?,
                verifier,
                active_sessions: AtomicUsize::new(0),
            }),
        })
    }
}

impl ToolExecutor for GuardedToolExecutor {
    fn prepare_model_step(
        &self,
        scope: &ToolScope,
        step: StepId,
    ) -> Result<Arc<ToolExecutionSession>, ToolExecutionError> {
        let authority = self.inner.verifier.scope();
        if authority.agent_id() != scope.agent_id
            || authority.lifecycle() != scope.lifecycle
            || authority.session_id() != scope.session_id
            || authority.composition() != scope.composition
            || authority.catalog() != scope.catalog
        {
            return Err(ToolExecutionError::JournalAuthorityMismatch);
        }
        self.inner
            .active_sessions
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_ACTIVE_TOOL_SESSIONS).then_some(active + 1)
            })
            .map_err(|_| ToolExecutionError::SessionLimitExceeded)?;
        Ok(Arc::new(ToolExecutionSession {
            owner: Arc::clone(&self.inner),
            identity: Arc::new(SessionIdentity {
                snapshot_digest: self.inner.registry.snapshot_digest(),
            }),
            verifier: self.inner.verifier.clone(),
            step,
            planned_calls: Mutex::new(BTreeSet::new()),
        }))
    }
}

fn action_risk(safety: ToolSafety) -> ActionRisk {
    match safety {
        ToolSafety::ReadOnly => ActionRisk::ReadOnly,
        ToolSafety::Mutating => ActionRisk::Mutating,
        ToolSafety::Sensitive => ActionRisk::Sensitive,
        ToolSafety::Unknown => ActionRisk::Unknown,
    }
}

fn classify(
    definition: &ToolDefinition,
    arguments: &JsonValue,
) -> Result<ClassifiedCall, ToolExecutionError> {
    let mut safety = definition.static_safety();
    let mut effects = definition.static_effects();
    for rule in definition.call_policy().rules() {
        if rule
            .predicates()
            .iter()
            .all(|predicate| predicate_matches(predicate, arguments))
        {
            safety = safety.max(rule.raise_to());
            effects |= rule.add_effects();
        }
    }
    let concurrency_digest = match definition.call_policy().concurrency() {
        ToolConcurrencyRule::Exclusive => {
            hash_parts(&[b"rust-agent-tool-concurrency-exclusive-v1\0"])
        }
        ToolConcurrencyRule::ParallelSafe => {
            hash_parts(&[b"rust-agent-tool-concurrency-parallel-v1\0"])
        }
        ToolConcurrencyRule::ExclusiveByScalar { prefix, pointer } => {
            let value = arguments
                .pointer(pointer.as_str())
                .filter(|value| is_scalar(value))
                .ok_or(ToolExecutionError::InvalidRequest(
                    "exclusive-key argument is missing or non-scalar",
                ))?;
            let value = serde_json::to_vec(value).map_err(|_| {
                ToolExecutionError::InvalidRequest("invalid exclusive-key argument")
            })?;
            hash_parts(&[
                b"rust-agent-tool-concurrency-key-v1\0",
                prefix.as_str().as_bytes(),
                &value,
            ])
        }
    };
    Ok(ClassifiedCall {
        safety,
        effects,
        concurrency_digest,
    })
}

fn predicate_matches(predicate: &ToolArgumentPredicate, arguments: &JsonValue) -> bool {
    match predicate {
        ToolArgumentPredicate::Present { pointer } => arguments.pointer(pointer.as_str()).is_some(),
        ToolArgumentPredicate::TypeIs { pointer, kind } => arguments
            .pointer(pointer.as_str())
            .is_some_and(|value| json_kind(value) == *kind),
        ToolArgumentPredicate::ScalarEquals { pointer, value } => arguments
            .pointer(pointer.as_str())
            .is_some_and(|actual| actual == value.as_json()),
    }
}

fn json_kind(value: &JsonValue) -> JsonKind {
    match value {
        JsonValue::Null => JsonKind::Null,
        JsonValue::Bool(_) => JsonKind::Boolean,
        JsonValue::Number(_) => JsonKind::Number,
        JsonValue::String(_) => JsonKind::String,
        JsonValue::Array(_) => JsonKind::Array,
        JsonValue::Object(_) => JsonKind::Object,
    }
}

fn is_scalar(value: &JsonValue) -> bool {
    matches!(
        value,
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_)
    )
}

fn validate_schema(schema: &JsonValue, value: &JsonValue) -> Result<(), ToolExecutionError> {
    validate_schema_shape(schema)?;
    match_schema_value(schema, value)
}

fn validate_schema_shape(schema: &JsonValue) -> Result<(), ToolExecutionError> {
    let object = schema
        .as_object()
        .ok_or(ToolExecutionError::InvalidSchema)?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "type"
                | "properties"
                | "required"
                | "additionalProperties"
                | "enum"
                | "items"
                | "description"
        ) {
            return Err(ToolExecutionError::InvalidSchema);
        }
    }
    if let Some(expected) = object.get("type") {
        let expected = expected.as_str().ok_or(ToolExecutionError::InvalidSchema)?;
        if !matches!(
            expected,
            "null" | "boolean" | "number" | "integer" | "string" | "array" | "object"
        ) {
            return Err(ToolExecutionError::InvalidSchema);
        }
    }
    if let Some(choices) = object.get("enum") {
        let choices = choices
            .as_array()
            .ok_or(ToolExecutionError::InvalidSchema)?;
        if choices.is_empty() {
            return Err(ToolExecutionError::InvalidSchema);
        }
    }
    if let Some(required) = object.get("required") {
        let required = required
            .as_array()
            .ok_or(ToolExecutionError::InvalidSchema)?;
        let mut names = BTreeSet::new();
        for name in required {
            let name = name.as_str().ok_or(ToolExecutionError::InvalidSchema)?;
            if !names.insert(name) {
                return Err(ToolExecutionError::InvalidSchema);
            }
        }
    }
    if let Some(properties) = object.get("properties") {
        let properties = properties
            .as_object()
            .ok_or(ToolExecutionError::InvalidSchema)?;
        for property_schema in properties.values() {
            validate_schema_shape(property_schema)?;
        }
    }
    if let Some(items) = object.get("items") {
        validate_schema_shape(items)?;
    }
    if object
        .get("additionalProperties")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(ToolExecutionError::InvalidSchema);
    }
    if object
        .get("description")
        .is_some_and(|value| !value.is_string())
    {
        return Err(ToolExecutionError::InvalidSchema);
    }
    Ok(())
}

fn match_schema_value(schema: &JsonValue, value: &JsonValue) -> Result<(), ToolExecutionError> {
    let object = schema
        .as_object()
        .ok_or(ToolExecutionError::InvalidSchema)?;
    if let Some(expected) = object.get("type") {
        let expected = expected.as_str().ok_or(ToolExecutionError::InvalidSchema)?;
        let matches = match expected {
            "null" => value.is_null(),
            "boolean" => value.is_boolean(),
            "number" => value.is_number(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "string" => value.is_string(),
            "array" => value.is_array(),
            "object" => value.is_object(),
            _ => false,
        };
        if !matches {
            return Err(ToolExecutionError::SchemaMismatch);
        }
    }
    if let Some(choices) = object.get("enum")
        && !choices
            .as_array()
            .ok_or(ToolExecutionError::InvalidSchema)?
            .contains(value)
    {
        return Err(ToolExecutionError::SchemaMismatch);
    }
    if let Some(required) = object.get("required") {
        let value = value
            .as_object()
            .ok_or(ToolExecutionError::SchemaMismatch)?;
        for name in required
            .as_array()
            .ok_or(ToolExecutionError::InvalidSchema)?
        {
            let name = name.as_str().ok_or(ToolExecutionError::InvalidSchema)?;
            if !value.contains_key(name) {
                return Err(ToolExecutionError::SchemaMismatch);
            }
        }
    }
    if let Some(properties) = object.get("properties") {
        let properties = properties
            .as_object()
            .ok_or(ToolExecutionError::InvalidSchema)?;
        let value = value
            .as_object()
            .ok_or(ToolExecutionError::SchemaMismatch)?;
        for (name, property_schema) in properties {
            if let Some(property_value) = value.get(name) {
                match_schema_value(property_schema, property_value)?;
            }
        }
        if object.get("additionalProperties") == Some(&JsonValue::Bool(false))
            && value.keys().any(|name| !properties.contains_key(name))
        {
            return Err(ToolExecutionError::SchemaMismatch);
        }
    } else if object.get("additionalProperties") == Some(&JsonValue::Bool(false))
        && value.as_object().is_some_and(|value| !value.is_empty())
    {
        return Err(ToolExecutionError::SchemaMismatch);
    }
    if let Some(items) = object.get("items") {
        let values = value.as_array().ok_or(ToolExecutionError::SchemaMismatch)?;
        for item in values {
            match_schema_value(items, item)?;
        }
    }
    Ok(())
}

fn validate_output(value: &ToolValue, output_budget: usize) -> Result<(), ToolExecutionError> {
    if value.items().len() > MAX_TOOL_OUTPUT_ITEMS || value.encoded_bytes() > output_budget {
        return Err(ToolExecutionError::InvalidOutput(
            ToolOutputError::ByteLimitExceeded,
        ));
    }
    for item in value.items() {
        if let ToolValueItem::Structured(value) = item
            && json_depth(value) > MAX_TOOL_OUTPUT_JSON_DEPTH
        {
            return Err(ToolExecutionError::InvalidOutput(
                ToolOutputError::JsonDepthExceeded,
            ));
        }
    }
    Ok(())
}

fn json_depth(value: &JsonValue) -> usize {
    match value {
        JsonValue::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or_default(),
        JsonValue::Object(values) => 1 + values.values().map(json_depth).max().unwrap_or_default(),
        _ => 1,
    }
}

fn check_guard(
    cancellation: &CancellationToken,
    deadline: Option<RuntimeInstant>,
    runtime: &RuntimePrimitives,
) -> Result<(), ToolExecutionError> {
    if cancellation.is_cancelled() {
        return Err(ToolExecutionError::Cancelled);
    }
    if let Some(deadline) = deadline
        && runtime
            .now()
            .map_err(|_| ToolExecutionError::RuntimeUnavailable)?
            >= deadline
    {
        return Err(ToolExecutionError::DeadlineExceeded);
    }
    Ok(())
}

async fn await_guarded<F, T>(
    future: F,
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
    runtime: &RuntimePrimitives,
) -> Result<T, ToolExecutionError>
where
    F: Future<Output = T>,
{
    let mut future = std::pin::pin!(future);
    let mut cancelled = Box::pin(cancellation.cancelled());
    let mut deadline_wait = deadline
        .map(|value| runtime.sleep_until(value))
        .transpose()
        .map_err(|_| ToolExecutionError::RuntimeUnavailable)?;
    poll_fn(move |context| {
        if let Poll::Ready(value) = future.as_mut().poll(context) {
            return Poll::Ready(Ok(value));
        }
        if cancelled.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(ToolExecutionError::Cancelled));
        }
        if let Some(wait) = deadline_wait.as_mut()
            && wait.as_mut().poll(context).is_ready()
        {
            return Poll::Ready(Err(ToolExecutionError::DeadlineExceeded));
        }
        Poll::Pending
    })
    .await
}

struct RawExecutionGuard<'a> {
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
    runtime: &'a RuntimePrimitives,
    output_budget: NonZeroUsize,
}

async fn execute_registered(
    registered: &RegisteredTool,
    request: ToolExecutionRequest,
    permit: &crate::ExecutionPermit,
    context: &crate::ToolContext,
    guard: RawExecutionGuard<'_>,
) -> Result<ToolExecutionResult, ToolExecutionError> {
    let ToolExecutionRequest {
        call_id,
        tool_name,
        arguments,
        provider_call_id: _,
    } = request;
    let value = await_guarded(
        registered.handler().execute(permit, context, arguments),
        guard.cancellation.clone(),
        guard.deadline,
        guard.runtime,
    )
    .await?;
    check_guard(&guard.cancellation, guard.deadline, guard.runtime)?;
    let value = value.map_err(ToolExecutionError::Tool)?;
    validate_output(&value, guard.output_budget.get())?;
    Ok(ToolExecutionResult {
        call_id,
        tool_name,
        value,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        num::{NonZeroU64, NonZeroUsize},
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
        thread,
    };

    use rust_agent_policy::{Approval, ApprovalFuture, PermissionPolicy};
    use rust_agent_runtime_api::{
        RuntimeAdapterIdentity, ToolCallJournalAuthority, ToolCallScopeIdentity,
    };
    use serde_json::json;

    use super::*;
    use crate::{
        Tool, ToolCallPolicy, ToolContribution, ToolFuture, ToolRegistration,
        ToolRegistrationSnapshot, ToolRiskRule,
    };

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
                Poll::Ready(output) => return output,
                Poll::Pending => thread::park(),
            }
        }
    }

    #[derive(Debug)]
    struct CountingTool {
        calls: Arc<AtomicUsize>,
        policy: ToolCallPolicy,
        schema: JsonValue,
    }

    impl Tool for CountingTool {
        fn definition(&self) -> ToolDefinition {
            ToolDefinition::new(
                "counting",
                "counts guarded dispatches",
                self.schema.clone(),
                ToolSafety::ReadOnly,
                SecurityEffects::READ_LOCAL,
                self.policy.clone(),
            )
            .unwrap()
        }

        fn execute<'a>(
            &'a self,
            _permit: &'a crate::ExecutionPermit,
            context: &'a crate::ToolContext,
            _input: JsonValue,
        ) -> ToolFuture<'a, Result<ToolValue, ToolError>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let mut output = context.output_builder();
                output.append_text("ok")?;
                Ok(output.build())
            })
        }
    }

    #[derive(Debug)]
    struct NamedCountingTool {
        name: &'static str,
        calls: Arc<AtomicUsize>,
        safety: ToolSafety,
        effects: SecurityEffects,
    }

    impl Tool for NamedCountingTool {
        fn definition(&self) -> ToolDefinition {
            ToolDefinition::new(
                self.name,
                "nested counting tool",
                json!({"type": "object", "additionalProperties": false}),
                self.safety,
                self.effects,
                simple_policy(),
            )
            .unwrap()
        }

        fn execute<'a>(
            &'a self,
            _permit: &'a crate::ExecutionPermit,
            context: &'a crate::ToolContext,
            _input: JsonValue,
        ) -> ToolFuture<'a, Result<ToolValue, ToolError>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let mut output = context.output_builder();
                output.append_text("nested-ok")?;
                Ok(output.build())
            })
        }
    }

    #[derive(Debug)]
    struct NestedCallerTool {
        target: &'static str,
        attempts: usize,
        cancel_before_nested: bool,
        observed_error: Arc<Mutex<Option<ToolExecutionError>>>,
        expected_root: CallId,
    }

    impl Tool for NestedCallerTool {
        fn definition(&self) -> ToolDefinition {
            ToolDefinition::new(
                "parent",
                "calls another tool through the borrowed nested session",
                json!({"type": "object", "additionalProperties": false}),
                ToolSafety::ReadOnly,
                SecurityEffects::READ_LOCAL,
                simple_policy(),
            )
            .unwrap()
        }

        fn execute<'a>(
            &'a self,
            permit: &'a crate::ExecutionPermit,
            context: &'a crate::ToolContext,
            _input: JsonValue,
        ) -> ToolFuture<'a, Result<ToolValue, ToolError>> {
            Box::pin(async move {
                assert_eq!(context.root_call_id(), self.expected_root);
                let nested = context
                    .prepare_nested(permit)
                    .map_err(|error| ToolError::provider("nested", error.to_string()))?;
                if self.cancel_before_nested {
                    context.cancellation().cancel();
                }
                assert!(
                    nested
                        .definitions()
                        .iter()
                        .any(|tool| tool.name() == self.target)
                );
                for index in 0..self.attempts {
                    let request = ToolExecutionRequest::new(
                        CallId::from_nonzero_u128(6_000 + index as u128).unwrap(),
                        self.target,
                        json!({}),
                    )
                    .unwrap();
                    if let Err(error) = nested.execute(request).await {
                        *self.observed_error.lock().unwrap() = Some(error);
                        break;
                    }
                }
                let mut output = context.output_builder();
                output.append_text("parent-ok")?;
                Ok(output.build())
            })
        }
    }

    #[derive(Debug)]
    struct FixedContribution {
        version: NonZeroU64,
        registration: ToolRegistration,
    }

    #[derive(Debug)]
    struct MultipleContribution {
        registrations: Vec<ToolRegistration>,
    }

    impl ToolContribution for MultipleContribution {
        fn snapshot(&self) -> Result<ToolRegistrationSnapshot, ToolProviderError> {
            ToolRegistrationSnapshot::new(
                "nested-fixture-provider",
                NonZeroU64::new(1).unwrap(),
                self.registrations.clone(),
            )
        }
    }

    impl ToolContribution for FixedContribution {
        fn snapshot(&self) -> Result<ToolRegistrationSnapshot, ToolProviderError> {
            ToolRegistrationSnapshot::new(
                "fixture-provider",
                self.version,
                vec![self.registration.clone()],
            )
        }
    }

    #[derive(Debug)]
    struct CountingPermission {
        calls: Arc<AtomicUsize>,
        decision: PermissionDecision,
        observed_effects: Arc<AtomicU64>,
    }

    impl PermissionPolicy for CountingPermission {
        fn evaluate(&self, action: &Action) -> PermissionDecision {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.observed_effects
                .store(action.effects().bits(), Ordering::SeqCst);
            self.decision
        }
    }

    #[derive(Debug)]
    struct CountingApproval {
        calls: Arc<AtomicUsize>,
        decision: ApprovalDecision,
    }

    #[derive(Debug)]
    struct RecordingMiddleware {
        id: &'static str,
        order: i32,
        events: Arc<Mutex<Vec<String>>>,
        pre: ToolPrePolicyDecision,
        post: ToolPostPolicyDecision,
        fail_before: bool,
        fail_observer: bool,
    }

    impl crate::ToolExecutionMiddleware for RecordingMiddleware {
        fn id(&self) -> &'static str {
            self.id
        }

        fn order(&self) -> i32 {
            self.order
        }

        fn pre_tool_policy<'a>(
            &'a self,
            context: &'a ToolMiddlewareContext,
        ) -> ToolFuture<'a, Result<ToolPrePolicyDecision, ToolMiddlewareError>> {
            assert!(matches!(
                context.tool_name(),
                "counting" | "parent" | "child"
            ));
            assert_eq!(context.effects(), SecurityEffects::READ_LOCAL);
            self.events.lock().unwrap().push(format!("{}:pre", self.id));
            let decision = self.pre;
            Box::pin(async move { Ok(decision) })
        }

        fn around_tool_execution<'a>(
            &'a self,
            _context: &'a ToolMiddlewareContext,
            phase: ToolAroundExecutionPhase,
            outcome: Option<ToolMiddlewareOutcome<'a>>,
        ) -> ToolFuture<'a, Result<(), ToolMiddlewareError>> {
            let label = match phase {
                ToolAroundExecutionPhase::Before => {
                    assert!(outcome.is_none());
                    "before"
                }
                ToolAroundExecutionPhase::After => {
                    assert!(matches!(outcome, Some(ToolMiddlewareOutcome::Success(_))));
                    "after"
                }
            };
            self.events
                .lock()
                .unwrap()
                .push(format!("{}:{label}", self.id));
            let fail = self.fail_before && phase == ToolAroundExecutionPhase::Before;
            Box::pin(async move {
                if fail {
                    Err(ToolMiddlewareError::new(
                        crate::ToolMiddlewareErrorKind::Execution,
                        "before failed",
                    ))
                } else {
                    Ok(())
                }
            })
        }

        fn post_tool_policy<'a>(
            &'a self,
            _context: &'a ToolMiddlewareContext,
            _result: &'a ToolExecutionResult,
        ) -> ToolFuture<'a, Result<ToolPostPolicyDecision, ToolMiddlewareError>> {
            self.events
                .lock()
                .unwrap()
                .push(format!("{}:post", self.id));
            let decision = self.post;
            Box::pin(async move { Ok(decision) })
        }

        fn observe_tool_result<'a>(
            &'a self,
            _context: &'a ToolMiddlewareContext,
            outcome: ToolMiddlewareOutcome<'a>,
        ) -> ToolFuture<'a, Result<(), ToolMiddlewareError>> {
            let label = match outcome {
                ToolMiddlewareOutcome::Success(_) => "observe-success",
                ToolMiddlewareOutcome::Failure(_) => "observe-failure",
            };
            self.events
                .lock()
                .unwrap()
                .push(format!("{}:{label}", self.id));
            let fail = self.fail_observer;
            Box::pin(async move {
                if fail {
                    Err(ToolMiddlewareError::new(
                        crate::ToolMiddlewareErrorKind::Observer,
                        "observer failed",
                    ))
                } else {
                    Ok(())
                }
            })
        }
    }

    fn recording_middleware(
        id: &'static str,
        order: i32,
        events: Arc<Mutex<Vec<String>>>,
    ) -> ToolExecutionMiddlewareBinding {
        ToolExecutionMiddlewareBinding::from_provider(Arc::new(RecordingMiddleware {
            id,
            order,
            events,
            pre: ToolPrePolicyDecision::Continue,
            post: ToolPostPolicyDecision::Accept,
            fail_before: false,
            fail_observer: false,
        }))
    }

    impl Approval for CountingApproval {
        fn request(
            &self,
            _request: ApprovalRequest,
        ) -> ApprovalFuture<'_, Result<ApprovalDecision, ApprovalError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let decision = self.decision;
            Box::pin(async move { Ok(decision) })
        }
    }

    fn simple_policy() -> ToolCallPolicy {
        ToolCallPolicy::builder(ToolConcurrencyRule::ParallelSafe)
            .build()
            .unwrap()
    }

    fn dynamic_policy() -> ToolCallPolicy {
        let mut risk = ToolRiskRule::builder(ToolSafety::Sensitive, SecurityEffects::NETWORK);
        risk.try_push_predicate(ToolArgumentPredicate::ScalarEquals {
            pointer: crate::BoundedJsonPointer::new("/remote").unwrap(),
            value: crate::BoundedJsonScalar::boolean(true),
        })
        .unwrap();
        let mut policy = ToolCallPolicy::builder(ToolConcurrencyRule::Exclusive);
        policy.try_push_rule(risk.build().unwrap()).unwrap();
        policy.build().unwrap()
    }

    fn provider(calls: Arc<AtomicUsize>, policy: ToolCallPolicy) -> ToolProviderBinding {
        let tool = Arc::new(CountingTool {
            calls,
            policy,
            schema: json!({
                "type": "object",
                "properties": {"remote": {"type": "boolean"}},
                "additionalProperties": false
            }),
        });
        ToolProviderBinding::from_provider(Arc::new(FixedContribution {
            version: NonZeroU64::new(1).unwrap(),
            registration: ToolRegistration::new(tool).unwrap(),
        }))
    }

    fn nested_provider(
        target: &'static str,
        attempts: usize,
        target_safety: ToolSafety,
        target_effects: SecurityEffects,
        child_calls: Arc<AtomicUsize>,
        observed_error: Arc<Mutex<Option<ToolExecutionError>>>,
    ) -> ToolProviderBinding {
        nested_provider_with_cancellation(
            target,
            attempts,
            target_safety,
            target_effects,
            child_calls,
            observed_error,
            false,
        )
    }

    fn nested_provider_with_cancellation(
        target: &'static str,
        attempts: usize,
        target_safety: ToolSafety,
        target_effects: SecurityEffects,
        child_calls: Arc<AtomicUsize>,
        observed_error: Arc<Mutex<Option<ToolExecutionError>>>,
        cancel_before_nested: bool,
    ) -> ToolProviderBinding {
        let parent = Arc::new(NestedCallerTool {
            target,
            attempts,
            cancel_before_nested,
            observed_error,
            expected_root: CallId::from_nonzero_u128(5_000).unwrap(),
        });
        let child = Arc::new(NamedCountingTool {
            name: target,
            calls: child_calls,
            safety: target_safety,
            effects: target_effects,
        });
        let mut registrations = vec![ToolRegistration::new(parent).unwrap()];
        if target != "parent" {
            registrations.push(ToolRegistration::new(child).unwrap());
        }
        ToolProviderBinding::from_provider(Arc::new(MultipleContribution { registrations }))
    }

    struct Harness {
        scope: ToolScope,
        issuer: rust_agent_runtime_api::ToolCallJournalIssuer,
        executor: GuardedToolExecutor,
        permission_calls: Arc<AtomicUsize>,
        observed_effects: Arc<AtomicU64>,
    }

    fn harness(
        agent: u128,
        providers: &[ToolProviderBinding],
        decision: PermissionDecision,
        approval: Option<ApprovalBinding>,
    ) -> Harness {
        harness_with_middleware(agent, providers, decision, approval, &[])
    }

    fn harness_with_middleware(
        agent: u128,
        providers: &[ToolProviderBinding],
        decision: PermissionDecision,
        approval: Option<ApprovalBinding>,
        middleware: &[ToolExecutionMiddlewareBinding],
    ) -> Harness {
        let agent_id = AgentId::from_nonzero_u128(agent).unwrap();
        let lifecycle = AgentLifecycleNonce::from_nonzero(NonZeroU64::new(1).unwrap());
        let composition = CompositionHash::from_digest(Digest::from_bytes([2; 32]));
        let catalog = Digest::from_bytes([3; 32]);
        let scope = ToolScope::for_generated_agent(agent_id, lifecycle, None, composition, catalog);
        let (issuer, verifier) = ToolCallJournalAuthority::issue_for_generated_scope(
            ToolCallScopeIdentity::for_generated_agent(
                agent_id,
                lifecycle,
                None,
                composition,
                catalog,
            ),
        )
        .unwrap();
        let permission_calls = Arc::new(AtomicUsize::new(0));
        let observed_effects = Arc::new(AtomicU64::new(0));
        let permission = PermissionPolicyBinding::from_provider(Arc::new(CountingPermission {
            calls: Arc::clone(&permission_calls),
            decision,
            observed_effects: Arc::clone(&observed_effects),
        }));
        Harness {
            scope,
            issuer,
            executor: GuardedToolExecutor::build(
                providers, permission, approval, middleware, verifier,
            )
            .unwrap(),
            permission_calls,
            observed_effects,
        }
    }

    fn step() -> StepId {
        StepId::new(
            RequestId::from_nonzero_u128(10).unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
    }

    fn request(call: u128, remote: bool) -> ToolExecutionRequest {
        ToolExecutionRequest::new(
            CallId::from_nonzero_u128(call).unwrap(),
            "counting",
            json!({"remote": remote}),
        )
        .unwrap()
    }

    fn seal(
        issuer: &rust_agent_runtime_api::ToolCallJournalIssuer,
        plan: ToolCallPlan,
        cancellation: CancellationToken,
    ) -> PreparedToolCall {
        let proof = issuer
            .seal_committed_record(
                plan.journal_projection(),
                plan.record_digest(),
                cancellation,
                None,
                NonZeroUsize::new(1024).unwrap(),
                RuntimePrimitives::new(RuntimeAdapterIdentity::checked("test-runtime").unwrap()),
            )
            .unwrap();
        plan.seal(proof).unwrap()
    }

    fn execute_parent(harness: &Harness) -> Result<ToolExecutionResult, ToolExecutionError> {
        let session = harness
            .executor
            .prepare_model_step(&harness.scope, step())
            .unwrap();
        let plan = session
            .plan_call(
                ToolExecutionRequest::new(
                    CallId::from_nonzero_u128(5_000).unwrap(),
                    "parent",
                    json!({}),
                )
                .unwrap(),
            )
            .unwrap();
        let prepared = seal(&harness.issuer, plan, CancellationToken::new());
        run(session.execute_prepared(prepared))
    }

    #[test]
    fn sessionless_committed_proof_reaches_only_guarded_dispatch() {
        let tool_calls = Arc::new(AtomicUsize::new(0));
        let harness = harness(
            1,
            &[provider(Arc::clone(&tool_calls), dynamic_policy())],
            PermissionDecision::Allow,
            None,
        );
        let session = harness
            .executor
            .prepare_model_step(&harness.scope, step())
            .unwrap();
        assert_eq!(session.definitions().len(), 1);
        let plan = session.plan_call(request(20, true)).unwrap();
        assert_eq!(tool_calls.load(Ordering::SeqCst), 0);
        assert_eq!(harness.permission_calls.load(Ordering::SeqCst), 0);
        let prepared = seal(&harness.issuer, plan, CancellationToken::new());
        let result = run(session.execute_prepared(prepared)).unwrap();
        assert_eq!(result.call_id(), CallId::from_nonzero_u128(20).unwrap());
        assert_eq!(result.value().items(), &[ToolValueItem::Text("ok".into())]);
        assert_eq!(tool_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.permission_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            harness.observed_effects.load(Ordering::SeqCst),
            (SecurityEffects::READ_LOCAL | SecurityEffects::NETWORK).bits()
        );
    }

    #[test]
    fn wrong_proof_and_cross_agent_scope_fail_before_callbacks() {
        let tool_calls = Arc::new(AtomicUsize::new(0));
        let harness = harness(
            1,
            &[provider(Arc::clone(&tool_calls), simple_policy())],
            PermissionDecision::Allow,
            None,
        );
        let session = harness
            .executor
            .prepare_model_step(&harness.scope, step())
            .unwrap();
        let plan = session.plan_call(request(21, false)).unwrap();
        let (foreign_issuer, _) = ToolCallJournalAuthority::issue_for_generated_scope(
            ToolCallScopeIdentity::for_generated_agent(
                harness.scope.agent_id,
                harness.scope.lifecycle,
                None,
                harness.scope.composition,
                harness.scope.catalog,
            ),
        )
        .unwrap();
        let proof = foreign_issuer
            .seal_committed_record(
                plan.journal_projection(),
                plan.record_digest(),
                CancellationToken::new(),
                None,
                NonZeroUsize::new(1024).unwrap(),
                RuntimePrimitives::new(RuntimeAdapterIdentity::checked("test-runtime").unwrap()),
            )
            .unwrap();
        assert!(matches!(
            plan.seal(proof),
            Err(ToolExecutionError::JournalProofMismatch)
        ));
        let foreign_scope = ToolScope::for_generated_agent(
            AgentId::from_nonzero_u128(2).unwrap(),
            harness.scope.lifecycle,
            None,
            harness.scope.composition,
            harness.scope.catalog,
        );
        assert!(matches!(
            harness.executor.prepare_model_step(&foreign_scope, step()),
            Err(ToolExecutionError::JournalAuthorityMismatch)
        ));
        assert_eq!(tool_calls.load(Ordering::SeqCst), 0);
        assert_eq!(harness.permission_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn schema_permission_approval_and_cancellation_reject_before_provider() {
        let tool_calls = Arc::new(AtomicUsize::new(0));
        let denied = harness(
            1,
            &[provider(Arc::clone(&tool_calls), simple_policy())],
            PermissionDecision::Deny,
            None,
        );
        let session = denied
            .executor
            .prepare_model_step(&denied.scope, step())
            .unwrap();
        assert!(matches!(
            session.plan_call(
                ToolExecutionRequest::new(
                    CallId::from_nonzero_u128(22).unwrap(),
                    "counting",
                    json!({"unexpected": true}),
                )
                .unwrap()
            ),
            Err(ToolExecutionError::SchemaMismatch)
        ));

        let malformed_schema = ToolProviderBinding::from_provider(Arc::new(FixedContribution {
            version: NonZeroU64::new(1).unwrap(),
            registration: ToolRegistration::new(Arc::new(CountingTool {
                calls: Arc::clone(&tool_calls),
                policy: simple_policy(),
                schema: json!({
                    "type": "object",
                    "properties": {"unused": {"oneOf": [{"type": "string"}]}}
                }),
            }))
            .unwrap(),
        }));
        let malformed = harness(2, &[malformed_schema], PermissionDecision::Allow, None);
        let malformed_session = malformed
            .executor
            .prepare_model_step(&malformed.scope, step())
            .unwrap();
        assert!(matches!(
            malformed_session.plan_call(request(23, false)),
            Err(ToolExecutionError::InvalidSchema)
        ));

        let closed_empty_schema = ToolProviderBinding::from_provider(Arc::new(FixedContribution {
            version: NonZeroU64::new(1).unwrap(),
            registration: ToolRegistration::new(Arc::new(CountingTool {
                calls: Arc::clone(&tool_calls),
                policy: simple_policy(),
                schema: json!({"type": "object", "additionalProperties": false}),
            }))
            .unwrap(),
        }));
        let closed_empty = harness(3, &[closed_empty_schema], PermissionDecision::Allow, None);
        let closed_empty_session = closed_empty
            .executor
            .prepare_model_step(&closed_empty.scope, step())
            .unwrap();
        assert!(matches!(
            closed_empty_session.plan_call(request(24, false)),
            Err(ToolExecutionError::SchemaMismatch)
        ));

        let prepared = seal(
            &denied.issuer,
            session.plan_call(request(25, false)).unwrap(),
            CancellationToken::new(),
        );
        assert_eq!(
            run(session.execute_prepared(prepared)),
            Err(ToolExecutionError::PermissionDenied)
        );
        assert_eq!(tool_calls.load(Ordering::SeqCst), 0);

        let missing_approval = harness(
            1,
            &[provider(Arc::clone(&tool_calls), simple_policy())],
            PermissionDecision::Ask,
            None,
        );
        let session = missing_approval
            .executor
            .prepare_model_step(&missing_approval.scope, step())
            .unwrap();
        let prepared = seal(
            &missing_approval.issuer,
            session.plan_call(request(26, false)).unwrap(),
            CancellationToken::new(),
        );
        assert_eq!(
            run(session.execute_prepared(prepared)),
            Err(ToolExecutionError::ApprovalRequired)
        );
        assert_eq!(tool_calls.load(Ordering::SeqCst), 0);

        let approval_calls = Arc::new(AtomicUsize::new(0));
        let approval = ApprovalBinding::from_provider(Arc::new(CountingApproval {
            calls: Arc::clone(&approval_calls),
            decision: ApprovalDecision::Deny,
        }));
        let asking = harness(
            1,
            &[provider(Arc::clone(&tool_calls), simple_policy())],
            PermissionDecision::Ask,
            Some(approval),
        );
        let session = asking
            .executor
            .prepare_model_step(&asking.scope, step())
            .unwrap();
        let prepared = seal(
            &asking.issuer,
            session.plan_call(request(27, false)).unwrap(),
            CancellationToken::new(),
        );
        assert_eq!(
            run(session.execute_prepared(prepared)),
            Err(ToolExecutionError::PermissionDenied)
        );
        assert_eq!(approval_calls.load(Ordering::SeqCst), 1);
        assert_eq!(tool_calls.load(Ordering::SeqCst), 0);

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let prepared = seal(
            &asking.issuer,
            session.plan_call(request(28, false)).unwrap(),
            cancellation,
        );
        assert_eq!(
            run(session.execute_prepared(prepared)),
            Err(ToolExecutionError::Cancelled)
        );
        assert_eq!(approval_calls.load(Ordering::SeqCst), 1);
        assert_eq!(tool_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn empty_registry_is_valid_and_generated_effect_ceiling_is_enforced() {
        let empty = harness(1, &[], PermissionDecision::Allow, None);
        let session = empty
            .executor
            .prepare_model_step(&empty.scope, step())
            .unwrap();
        assert!(session.definitions().is_empty());
        assert!(matches!(
            session.plan_call(request(26, false)),
            Err(ToolExecutionError::UnknownTool(_))
        ));

        let tool_calls = Arc::new(AtomicUsize::new(0));
        let contribution = Arc::new(FixedContribution {
            version: NonZeroU64::new(1).unwrap(),
            registration: ToolRegistration::new(Arc::new(CountingTool {
                calls: tool_calls,
                policy: simple_policy(),
                schema: json!({"type": "object"}),
            }))
            .unwrap(),
        });
        let binding = ToolProviderBinding::from_generated_component(
            "tool-fixture",
            SecurityEffects::empty(),
            contribution,
        )
        .unwrap();
        let (_, verifier) = ToolCallJournalAuthority::issue_for_generated_scope(
            ToolCallScopeIdentity::for_generated_agent(
                empty.scope.agent_id,
                empty.scope.lifecycle,
                None,
                empty.scope.composition,
                empty.scope.catalog,
            ),
        )
        .unwrap();
        let permission = PermissionPolicyBinding::from_provider(Arc::new(CountingPermission {
            calls: Arc::new(AtomicUsize::new(0)),
            decision: PermissionDecision::Allow,
            observed_effects: Arc::new(AtomicU64::new(0)),
        }));
        assert!(matches!(
            GuardedToolExecutor::build(&[binding], permission, None, &[], verifier),
            Err(ToolExecutionError::Provider(
                ToolProviderError::EffectCeilingExceeded
            ))
        ));
    }

    #[test]
    fn prepared_calls_are_bound_to_the_exact_session_instance() {
        let tool_calls = Arc::new(AtomicUsize::new(0));
        let harness = harness(
            1,
            &[provider(Arc::clone(&tool_calls), simple_policy())],
            PermissionDecision::Allow,
            None,
        );
        let first = harness
            .executor
            .prepare_model_step(&harness.scope, step())
            .unwrap();
        let second = harness
            .executor
            .prepare_model_step(&harness.scope, step())
            .unwrap();
        let prepared = seal(
            &harness.issuer,
            first.plan_call(request(27, false)).unwrap(),
            CancellationToken::new(),
        );
        assert_eq!(
            run(second.execute_prepared(prepared)),
            Err(ToolExecutionError::JournalProofMismatch)
        );
        assert_eq!(tool_calls.load(Ordering::SeqCst), 0);
        assert_eq!(harness.permission_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn session_and_per_step_call_retention_are_hard_bounded() {
        let empty_harness = harness(1, &[], PermissionDecision::Allow, None);
        let mut sessions = (0..MAX_ACTIVE_TOOL_SESSIONS)
            .map(|index| {
                empty_harness
                    .executor
                    .prepare_model_step(
                        &empty_harness.scope,
                        StepId::new(
                            RequestId::from_nonzero_u128(100 + index as u128).unwrap(),
                            NonZeroU64::new(1).unwrap(),
                        ),
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            empty_harness
                .executor
                .prepare_model_step(&empty_harness.scope, step()),
            Err(ToolExecutionError::SessionLimitExceeded)
        ));
        sessions.pop();
        assert!(
            empty_harness
                .executor
                .prepare_model_step(&empty_harness.scope, step())
                .is_ok()
        );

        let tool_calls = Arc::new(AtomicUsize::new(0));
        let harness = harness(
            2,
            &[provider(tool_calls, simple_policy())],
            PermissionDecision::Allow,
            None,
        );
        let session = harness
            .executor
            .prepare_model_step(&harness.scope, step())
            .unwrap();
        session.plan_call(request(1_000, false)).unwrap();
        assert!(matches!(
            session.plan_call(request(1_000, false)),
            Err(ToolExecutionError::DuplicateCallId)
        ));
        for call in 1..MAX_TOOL_CALLS_PER_STEP {
            session
                .plan_call(request(1_000 + call as u128, false))
                .unwrap();
        }
        assert!(matches!(
            session.plan_call(request(2_000, false)),
            Err(ToolExecutionError::CallLimitExceeded)
        ));
        assert_eq!(harness.permission_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn provider_protocol_call_id_is_bounded_and_journal_committed() {
        assert!(
            request(3_000, false)
                .with_provider_call_id("x".repeat(257))
                .is_err()
        );
        let harness = harness(
            1,
            &[provider(Arc::new(AtomicUsize::new(0)), simple_policy())],
            PermissionDecision::Allow,
            None,
        );
        let first = harness
            .executor
            .prepare_model_step(&harness.scope, step())
            .unwrap();
        let second = harness
            .executor
            .prepare_model_step(&harness.scope, step())
            .unwrap();
        let without = first.plan_call(request(3_001, false)).unwrap();
        let with = second
            .plan_call(
                request(3_001, false)
                    .with_provider_call_id("provider-call-1")
                    .unwrap(),
            )
            .unwrap();
        assert_ne!(without.record_digest(), with.record_digest());
    }

    #[test]
    fn nested_calls_reuse_the_guarded_pipeline_and_enforce_authority_budgets() {
        let child_calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(Mutex::new(None));
        let events = Arc::new(Mutex::new(Vec::new()));
        let nested_middleware = recording_middleware("nested", 0, Arc::clone(&events));
        let approval_calls = Arc::new(AtomicUsize::new(0));
        let approval = ApprovalBinding::from_provider(Arc::new(CountingApproval {
            calls: Arc::clone(&approval_calls),
            decision: ApprovalDecision::AllowOnce,
        }));
        let successful = harness_with_middleware(
            1,
            &[nested_provider(
                "child",
                1,
                ToolSafety::ReadOnly,
                SecurityEffects::READ_LOCAL,
                Arc::clone(&child_calls),
                Arc::clone(&observed),
            )],
            PermissionDecision::Ask,
            Some(approval),
            &[nested_middleware],
        );
        assert!(execute_parent(&successful).is_ok());
        assert_eq!(child_calls.load(Ordering::SeqCst), 1);
        assert_eq!(successful.permission_calls.load(Ordering::SeqCst), 2);
        assert_eq!(approval_calls.load(Ordering::SeqCst), 2);
        assert_eq!(*observed.lock().unwrap(), None);
        assert_eq!(
            *events.lock().unwrap(),
            [
                "nested:pre",
                "nested:before",
                "nested:pre",
                "nested:before",
                "nested:after",
                "nested:post",
                "nested:observe-success",
                "nested:after",
                "nested:post",
                "nested:observe-success",
            ]
        );

        let cycle_calls = Arc::new(AtomicUsize::new(0));
        let cycle = Arc::new(Mutex::new(None));
        let cyclic = harness(
            2,
            &[nested_provider(
                "parent",
                1,
                ToolSafety::ReadOnly,
                SecurityEffects::READ_LOCAL,
                cycle_calls,
                Arc::clone(&cycle),
            )],
            PermissionDecision::Allow,
            None,
        );
        assert!(execute_parent(&cyclic).is_ok());
        assert_eq!(
            *cycle.lock().unwrap(),
            Some(ToolExecutionError::NestedCycleDetected)
        );
        assert_eq!(cyclic.permission_calls.load(Ordering::SeqCst), 1);

        let escalated_calls = Arc::new(AtomicUsize::new(0));
        let escalated = Arc::new(Mutex::new(None));
        let escalated_harness = harness(
            3,
            &[nested_provider(
                "network-child",
                1,
                ToolSafety::Mutating,
                SecurityEffects::NETWORK,
                Arc::clone(&escalated_calls),
                Arc::clone(&escalated),
            )],
            PermissionDecision::Allow,
            None,
        );
        assert!(execute_parent(&escalated_harness).is_ok());
        assert_eq!(
            *escalated.lock().unwrap(),
            Some(ToolExecutionError::EffectCeilingExceeded)
        );
        assert_eq!(escalated_calls.load(Ordering::SeqCst), 0);
        assert_eq!(escalated_harness.permission_calls.load(Ordering::SeqCst), 1);

        let bounded_calls = Arc::new(AtomicUsize::new(0));
        let bounded = Arc::new(Mutex::new(None));
        let bounded_harness = harness(
            4,
            &[nested_provider(
                "bounded-child",
                MAX_NESTED_TOOL_CALLS + 1,
                ToolSafety::ReadOnly,
                SecurityEffects::READ_LOCAL,
                Arc::clone(&bounded_calls),
                Arc::clone(&bounded),
            )],
            PermissionDecision::Allow,
            None,
        );
        assert!(execute_parent(&bounded_harness).is_ok());
        assert_eq!(
            *bounded.lock().unwrap(),
            Some(ToolExecutionError::CallLimitExceeded)
        );
        assert_eq!(bounded_calls.load(Ordering::SeqCst), MAX_NESTED_TOOL_CALLS);
        assert_eq!(
            bounded_harness.permission_calls.load(Ordering::SeqCst),
            MAX_NESTED_TOOL_CALLS + 1
        );

        let cancelled_calls = Arc::new(AtomicUsize::new(0));
        let cancelled = Arc::new(Mutex::new(None));
        let cancelled_harness = harness(
            5,
            &[nested_provider_with_cancellation(
                "child",
                1,
                ToolSafety::ReadOnly,
                SecurityEffects::READ_LOCAL,
                Arc::clone(&cancelled_calls),
                Arc::clone(&cancelled),
                true,
            )],
            PermissionDecision::Allow,
            None,
        );
        assert_eq!(
            execute_parent(&cancelled_harness),
            Err(ToolExecutionError::Cancelled)
        );
        assert_eq!(
            *cancelled.lock().unwrap(),
            Some(ToolExecutionError::Cancelled)
        );
        assert_eq!(cancelled_calls.load(Ordering::SeqCst), 0);
        assert_eq!(cancelled_harness.permission_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn nested_session_requires_the_exact_permit_and_enforces_depth_before_dispatch() {
        let harness = harness(1, &[], PermissionDecision::Allow, None);
        let authority = Arc::new(NestedToolAuthority {
            owner: Arc::downgrade(&harness.executor.inner),
            step: step(),
            root_call_id: CallId::from_nonzero_u128(5_001).unwrap(),
            depth: MAX_NESTED_TOOL_DEPTH,
            calls: Arc::new(NestedCallBudget {
                admitted: Mutex::new(BTreeSet::new()),
            }),
            effect_ceiling: SecurityEffects::READ_LOCAL,
            chain: Arc::from([Arc::from("parent")]),
            cancellation: CancellationToken::new(),
            deadline: None,
            output_budget: NonZeroUsize::new(1024).unwrap(),
            runtime: RuntimePrimitives::new(
                RuntimeAdapterIdentity::checked("test-runtime").unwrap(),
            ),
        });
        let context = crate::ToolContext {
            cancellation: CancellationToken::new(),
            deadline: None,
            output_limits: ToolOutputLimits::checked(
                MAX_TOOL_OUTPUT_ITEMS,
                NonZeroUsize::new(1024).unwrap(),
                MAX_TOOL_OUTPUT_JSON_DEPTH,
            )
            .unwrap(),
            authority: Arc::clone(&authority),
        };
        let matching = crate::ExecutionPermit {
            authority: Arc::clone(&authority),
        };
        assert!(matches!(
            context.prepare_nested(&matching),
            Err(ToolExecutionError::NestedDepthLimitExceeded)
        ));

        let foreign = crate::ExecutionPermit {
            authority: Arc::new(NestedToolAuthority {
                owner: authority.owner.clone(),
                step: authority.step,
                root_call_id: authority.root_call_id,
                depth: authority.depth,
                calls: Arc::clone(&authority.calls),
                effect_ceiling: authority.effect_ceiling,
                chain: Arc::clone(&authority.chain),
                cancellation: authority.cancellation.clone(),
                deadline: authority.deadline,
                output_budget: authority.output_budget,
                runtime: authority.runtime.clone(),
            }),
        };
        assert!(matches!(
            context.prepare_nested(&foreign),
            Err(ToolExecutionError::NestedAuthorityMismatch)
        ));

        let closed_authority = test_nested_authority();
        let closed_context = crate::ToolContext {
            cancellation: closed_authority.cancellation.clone(),
            deadline: closed_authority.deadline,
            output_limits: ToolOutputLimits::checked(
                MAX_TOOL_OUTPUT_ITEMS,
                NonZeroUsize::new(1).unwrap(),
                MAX_TOOL_OUTPUT_JSON_DEPTH,
            )
            .unwrap(),
            authority: Arc::clone(&closed_authority),
        };
        let closed_permit = crate::ExecutionPermit {
            authority: closed_authority,
        };
        assert!(matches!(
            closed_context.prepare_nested(&closed_permit),
            Err(ToolExecutionError::Closed)
        ));
    }

    #[test]
    fn typed_middleware_order_wraps_only_proof_authorized_dispatch() {
        let tool_calls = Arc::new(AtomicUsize::new(0));
        let events = Arc::new(Mutex::new(Vec::new()));
        let late = recording_middleware("late", 10, Arc::clone(&events));
        let early = ToolExecutionMiddlewareBinding::from_provider(Arc::new(RecordingMiddleware {
            id: "early",
            order: -10,
            events: Arc::clone(&events),
            pre: ToolPrePolicyDecision::Continue,
            post: ToolPostPolicyDecision::Accept,
            fail_before: false,
            fail_observer: true,
        }));
        let harness = harness_with_middleware(
            1,
            &[provider(Arc::clone(&tool_calls), simple_policy())],
            PermissionDecision::Allow,
            None,
            &[late, early],
        );
        let session = harness
            .executor
            .prepare_model_step(&harness.scope, step())
            .unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = seal(
            &harness.issuer,
            session.plan_call(request(3_999, false)).unwrap(),
            cancellation,
        );
        assert_eq!(
            run(session.execute_prepared(cancelled)),
            Err(ToolExecutionError::Cancelled)
        );
        assert!(events.lock().unwrap().is_empty());
        assert_eq!(harness.permission_calls.load(Ordering::SeqCst), 0);
        assert_eq!(tool_calls.load(Ordering::SeqCst), 0);

        let plan = session.plan_call(request(4_000, false)).unwrap();
        assert!(events.lock().unwrap().is_empty());
        let prepared = seal(&harness.issuer, plan, CancellationToken::new());
        assert!(run(session.execute_prepared(prepared)).is_ok());
        assert_eq!(tool_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *events.lock().unwrap(),
            [
                "early:pre",
                "late:pre",
                "early:before",
                "late:before",
                "late:after",
                "early:after",
                "early:post",
                "late:post",
                "early:observe-success",
                "late:observe-success",
            ]
        );
    }

    #[test]
    fn middleware_failure_policies_are_stage_exact() {
        let tool_calls = Arc::new(AtomicUsize::new(0));
        let events = Arc::new(Mutex::new(Vec::new()));
        let denied = ToolExecutionMiddlewareBinding::from_provider(Arc::new(RecordingMiddleware {
            id: "deny",
            order: 0,
            events: Arc::clone(&events),
            pre: ToolPrePolicyDecision::Deny,
            post: ToolPostPolicyDecision::Accept,
            fail_before: false,
            fail_observer: false,
        }));
        let harness = harness_with_middleware(
            1,
            &[provider(Arc::clone(&tool_calls), simple_policy())],
            PermissionDecision::Allow,
            None,
            &[denied],
        );
        let session = harness
            .executor
            .prepare_model_step(&harness.scope, step())
            .unwrap();
        let prepared = seal(
            &harness.issuer,
            session.plan_call(request(4_001, false)).unwrap(),
            CancellationToken::new(),
        );
        assert!(matches!(
            run(session.execute_prepared(prepared)),
            Err(ToolExecutionError::MiddlewareDenied {
                stage: ToolMiddlewareStage::PreToolPolicy,
                ..
            })
        ));
        assert_eq!(tool_calls.load(Ordering::SeqCst), 0);

        let failed_events = Arc::new(Mutex::new(Vec::new()));
        let failed = ToolExecutionMiddlewareBinding::from_provider(Arc::new(RecordingMiddleware {
            id: "failed",
            order: 0,
            events: failed_events,
            pre: ToolPrePolicyDecision::Continue,
            post: ToolPostPolicyDecision::Accept,
            fail_before: true,
            fail_observer: false,
        }));
        let failed_harness = harness_with_middleware(
            2,
            &[provider(Arc::clone(&tool_calls), simple_policy())],
            PermissionDecision::Allow,
            None,
            &[failed],
        );
        let session = failed_harness
            .executor
            .prepare_model_step(&failed_harness.scope, step())
            .unwrap();
        let prepared = seal(
            &failed_harness.issuer,
            session.plan_call(request(4_002, false)).unwrap(),
            CancellationToken::new(),
        );
        assert!(matches!(
            run(session.execute_prepared(prepared)),
            Err(ToolExecutionError::Middleware {
                stage: ToolMiddlewareStage::AroundToolExecutionBefore,
                ..
            })
        ));
        assert_eq!(tool_calls.load(Ordering::SeqCst), 0);

        let post_events = Arc::new(Mutex::new(Vec::new()));
        let post_reject =
            ToolExecutionMiddlewareBinding::from_provider(Arc::new(RecordingMiddleware {
                id: "post-reject",
                order: 0,
                events: Arc::clone(&post_events),
                pre: ToolPrePolicyDecision::Continue,
                post: ToolPostPolicyDecision::Reject,
                fail_before: false,
                fail_observer: false,
            }));
        let post_harness = harness_with_middleware(
            3,
            &[provider(Arc::clone(&tool_calls), simple_policy())],
            PermissionDecision::Allow,
            None,
            &[post_reject],
        );
        let session = post_harness
            .executor
            .prepare_model_step(&post_harness.scope, step())
            .unwrap();
        let prepared = seal(
            &post_harness.issuer,
            session.plan_call(request(4_003, false)).unwrap(),
            CancellationToken::new(),
        );
        assert!(matches!(
            run(session.execute_prepared(prepared)),
            Err(ToolExecutionError::MiddlewareDenied {
                stage: ToolMiddlewareStage::PostToolPolicy,
                ..
            })
        ));
        assert_eq!(tool_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            post_events.lock().unwrap().last().map(String::as_str),
            Some("post-reject:observe-failure")
        );
    }
}
