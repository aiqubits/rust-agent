//! Effect-free runtime primitives and shared lifecycle protocol types.

use std::{
    any::Any,
    collections::BTreeMap,
    fmt,
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    ops::Add,
    pin::Pin,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

pub use rust_agent_core::{
    AgentId, AgentLifecycleOperationId, AgentLifecycleOperationIdKind, AgentOperationRecoveryKey,
    CallId, CompositionHash, Digest, MaybeSendSync, RequestId, SessionId,
};

/// Adapter-relative monotonic timestamp used by runtime-controlled deadlines.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RuntimeInstant(Duration);

impl RuntimeInstant {
    #[doc(hidden)]
    pub const fn from_monotonic_duration(value: Duration) -> Self {
        Self(value)
    }

    #[doc(hidden)]
    pub const fn monotonic_duration(self) -> Duration {
        self.0
    }

    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }

    pub fn checked_sub(self, duration: Duration) -> Option<Self> {
        self.0.checked_sub(duration).map(Self)
    }

    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.0.saturating_sub(earlier.0)
    }
}

impl Add<Duration> for RuntimeInstant {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0 + rhs)
    }
}

/// Cloneable cooperative cancellation signal owned by a runtime scope.
struct CancellationState {
    cancelled: AtomicBool,
    next_waiter: AtomicU64,
    waiters: Mutex<BTreeMap<u64, Waker>>,
}

impl Default for CancellationState {
    fn default() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            next_waiter: AtomicU64::new(1),
            waiters: Mutex::new(BTreeMap::new()),
        }
    }
}

#[derive(Clone, Default)]
pub struct CancellationToken(Arc<CancellationState>);

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) -> bool {
        if self.0.cancelled.swap(true, Ordering::AcqRel) {
            return false;
        }
        let waiters = std::mem::take(
            &mut *self
                .0
                .waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for waiter in waiters.into_values() {
            waiter.wake();
        }
        true
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::Acquire)
    }

    pub fn cancelled(&self) -> CancellationFuture {
        CancellationFuture {
            token: self.clone(),
            waiter_id: None,
        }
    }
}

#[derive(Debug)]
pub struct CancellationFuture {
    token: CancellationToken,
    waiter_id: Option<u64>,
}

impl Future for CancellationFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.token.is_cancelled() {
            self.unregister();
            return Poll::Ready(());
        }
        let waiter_id = match self.waiter_id {
            Some(waiter_id) => waiter_id,
            None => match self.token.0.next_waiter.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |value| value.checked_add(1),
            ) {
                Ok(waiter_id) if waiter_id != 0 => {
                    self.waiter_id = Some(waiter_id);
                    waiter_id
                }
                _ => {
                    self.token.cancel();
                    return Poll::Ready(());
                }
            },
        };
        let mut waiters = self
            .token
            .0
            .waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.token.is_cancelled() {
            return Poll::Ready(());
        }
        match waiters.get_mut(&waiter_id) {
            Some(waiter) if waiter.will_wake(context.waker()) => {}
            Some(waiter) => waiter.clone_from(context.waker()),
            None => {
                waiters.insert(waiter_id, context.waker().clone());
            }
        }
        Poll::Pending
    }
}

impl CancellationFuture {
    fn unregister(&mut self) {
        let Some(waiter_id) = self.waiter_id.take() else {
            return;
        };
        self.token
            .0
            .waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&waiter_id);
    }
}

impl Drop for CancellationFuture {
    fn drop(&mut self) {
        self.unregister();
    }
}

impl fmt::Debug for CancellationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

/// Monotonic identity of one in-process Agent incarnation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AgentLifecycleNonce(NonZeroU64);

impl AgentLifecycleNonce {
    #[doc(hidden)]
    pub const fn from_nonzero(value: NonZeroU64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Identity sealed into one generated model-caller scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelCallScopeIdentity {
    agent_id: AgentId,
    lifecycle: AgentLifecycleNonce,
    session_id: Option<SessionId>,
    composition: CompositionHash,
    catalog: Digest,
}

impl ModelCallScopeIdentity {
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

    pub const fn composition(&self) -> CompositionHash {
        self.composition
    }

    pub const fn catalog(&self) -> Digest {
        self.catalog
    }
}

/// Immutable, provider-neutral projection written before a model side effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelCallJournalProjection {
    request_id: RequestId,
    plan_digest: Digest,
    request_digest: Digest,
    route_digest: Digest,
}

impl ModelCallJournalProjection {
    #[doc(hidden)]
    pub const fn from_model_plan(
        request_id: RequestId,
        plan_digest: Digest,
        request_digest: Digest,
        route_digest: Digest,
    ) -> Self {
        Self {
            request_id,
            plan_digest,
            request_digest,
            route_digest,
        }
    }

    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    pub const fn plan_digest(&self) -> Digest {
        self.plan_digest
    }

    pub const fn request_digest(&self) -> Digest {
        self.request_digest
    }

    pub const fn route_digest(&self) -> Digest {
        self.route_digest
    }
}

struct ModelJournalAuthorityWitness {
    tag: NonZeroU64,
    scope: ModelCallScopeIdentity,
}

/// The owned half of a generated request-journal authority.
///
/// It is deliberately neither `Clone` nor serializable.
#[allow(missing_debug_implementations)]
pub struct ModelRequestJournalIssuer {
    witness: Arc<ModelJournalAuthorityWitness>,
    next_record: AtomicU64,
}

/// The cloneable read-only half sealed into one model consumer binding.
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct ModelRequestJournalVerifier {
    witness: Arc<ModelJournalAuthorityWitness>,
}

/// Opaque proof that the exact model request reached its required journal level.
#[allow(missing_debug_implementations)]
pub struct RequestJournalProof {
    witness: Arc<ModelJournalAuthorityWitness>,
    record_sequence: NonZeroU64,
    projection: ModelCallJournalProjection,
    record_digest: Digest,
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
    output_budget: NonZeroUsize,
    runtime: RuntimePrimitives,
}

impl RequestJournalProof {
    pub const fn request_id(&self) -> RequestId {
        self.projection.request_id()
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub const fn deadline(&self) -> Option<RuntimeInstant> {
        self.deadline
    }

    pub const fn output_budget(&self) -> NonZeroUsize {
        self.output_budget
    }

    #[doc(hidden)]
    pub fn runtime(&self) -> &RuntimePrimitives {
        &self.runtime
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalAuthorityError {
    AuthorityExhausted,
    RecordSequenceExhausted,
}

impl fmt::Display for JournalAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthorityExhausted => formatter.write_str("model journal authority exhausted"),
            Self::RecordSequenceExhausted => {
                formatter.write_str("model journal record sequence exhausted")
            }
        }
    }
}

impl std::error::Error for JournalAuthorityError {}

static NEXT_MODEL_JOURNAL_AUTHORITY: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct ModelRequestJournalAuthority;

impl ModelRequestJournalAuthority {
    fn issue_for_generated_scope(
        scope: ModelCallScopeIdentity,
    ) -> Result<(ModelRequestJournalIssuer, ModelRequestJournalVerifier), JournalAuthorityError>
    {
        let tag = NEXT_MODEL_JOURNAL_AUTHORITY
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| JournalAuthorityError::AuthorityExhausted)
            .and_then(|value| {
                NonZeroU64::new(value).ok_or(JournalAuthorityError::AuthorityExhausted)
            })?;
        let witness = Arc::new(ModelJournalAuthorityWitness { tag, scope });
        Ok((
            ModelRequestJournalIssuer {
                witness: Arc::clone(&witness),
                next_record: AtomicU64::new(1),
            },
            ModelRequestJournalVerifier { witness },
        ))
    }
}

impl ModelRequestJournalIssuer {
    #[doc(hidden)]
    pub fn seal_committed_record(
        &self,
        projection: ModelCallJournalProjection,
        record_digest: Digest,
        cancellation: CancellationToken,
        deadline: Option<RuntimeInstant>,
        output_budget: NonZeroUsize,
        runtime: RuntimePrimitives,
    ) -> Result<RequestJournalProof, JournalAuthorityError> {
        let record_sequence = self
            .next_record
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| JournalAuthorityError::RecordSequenceExhausted)
            .and_then(|value| {
                NonZeroU64::new(value).ok_or(JournalAuthorityError::RecordSequenceExhausted)
            })?;
        Ok(RequestJournalProof {
            witness: Arc::clone(&self.witness),
            record_sequence,
            projection,
            record_digest,
            cancellation,
            deadline,
            output_budget,
            runtime,
        })
    }

    #[doc(hidden)]
    pub fn scope(&self) -> &ModelCallScopeIdentity {
        &self.witness.scope
    }
}

impl ModelRequestJournalVerifier {
    #[doc(hidden)]
    pub fn verifies(
        &self,
        proof: &RequestJournalProof,
        projection: &ModelCallJournalProjection,
        record_digest: Digest,
    ) -> bool {
        Arc::ptr_eq(&self.witness, &proof.witness)
            && self.witness.tag == proof.witness.tag
            && self.witness.scope == proof.witness.scope
            && proof.record_sequence.get() != 0
            && &proof.projection == projection
            && proof.record_digest == record_digest
    }

    #[doc(hidden)]
    pub fn scope(&self) -> &ModelCallScopeIdentity {
        &self.witness.scope
    }
}

/// Identity sealed into the model-origin tool journal for one generated Agent scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolCallScopeIdentity {
    agent_id: AgentId,
    lifecycle: AgentLifecycleNonce,
    session_id: Option<SessionId>,
    composition: CompositionHash,
    catalog: Digest,
}

impl ToolCallScopeIdentity {
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

    pub const fn composition(&self) -> CompositionHash {
        self.composition
    }

    pub const fn catalog(&self) -> Digest {
        self.catalog
    }
}

/// Exact provider-neutral fields committed before a model-origin tool side effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolCallJournalProjection {
    call_id: CallId,
    step_digest: Digest,
    tool_digest: Digest,
    snapshot_digest: Digest,
    arguments_digest: Digest,
    effects_digest: Digest,
}

impl ToolCallJournalProjection {
    #[doc(hidden)]
    pub const fn from_tool_plan(
        call_id: CallId,
        step_digest: Digest,
        tool_digest: Digest,
        snapshot_digest: Digest,
        arguments_digest: Digest,
        effects_digest: Digest,
    ) -> Self {
        Self {
            call_id,
            step_digest,
            tool_digest,
            snapshot_digest,
            arguments_digest,
            effects_digest,
        }
    }

    pub const fn call_id(&self) -> CallId {
        self.call_id
    }

    pub const fn step_digest(&self) -> Digest {
        self.step_digest
    }

    pub const fn tool_digest(&self) -> Digest {
        self.tool_digest
    }

    pub const fn snapshot_digest(&self) -> Digest {
        self.snapshot_digest
    }

    pub const fn arguments_digest(&self) -> Digest {
        self.arguments_digest
    }

    pub const fn effects_digest(&self) -> Digest {
        self.effects_digest
    }
}

struct ToolJournalAuthorityWitness {
    tag: NonZeroU64,
    scope: ToolCallScopeIdentity,
}

/// Owned journal authority retained by the generated Agent request-journal facade.
#[allow(missing_debug_implementations)]
pub struct ToolCallJournalIssuer {
    witness: Arc<ToolJournalAuthorityWitness>,
    next_record: AtomicU64,
}

/// Cloneable verifier installed only on the matching model-origin `ToolExecutor` edge.
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct ToolCallJournalVerifier {
    witness: Arc<ToolJournalAuthorityWitness>,
}

/// Opaque evidence that the exact `ToolCall` checkpoint was confirmed committed.
#[allow(missing_debug_implementations)]
pub struct ToolCallJournalProof {
    witness: Arc<ToolJournalAuthorityWitness>,
    record_sequence: NonZeroU64,
    projection: ToolCallJournalProjection,
    record_digest: Digest,
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
    output_budget: NonZeroUsize,
    runtime: RuntimePrimitives,
}

impl ToolCallJournalProof {
    pub const fn call_id(&self) -> CallId {
        self.projection.call_id()
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub const fn deadline(&self) -> Option<RuntimeInstant> {
        self.deadline
    }

    pub const fn output_budget(&self) -> NonZeroUsize {
        self.output_budget
    }

    #[doc(hidden)]
    pub fn runtime(&self) -> &RuntimePrimitives {
        &self.runtime
    }
}

/// Allocates paired tool journal authority for generated scope assembly.
#[derive(Debug)]
pub struct ToolCallJournalAuthority;

static NEXT_TOOL_JOURNAL_AUTHORITY: AtomicU64 = AtomicU64::new(1);

impl ToolCallJournalAuthority {
    #[doc(hidden)]
    pub fn issue_for_generated_scope(
        scope: ToolCallScopeIdentity,
    ) -> Result<(ToolCallJournalIssuer, ToolCallJournalVerifier), JournalAuthorityError> {
        let tag = NEXT_TOOL_JOURNAL_AUTHORITY
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| JournalAuthorityError::AuthorityExhausted)
            .and_then(|value| {
                NonZeroU64::new(value).ok_or(JournalAuthorityError::AuthorityExhausted)
            })?;
        let witness = Arc::new(ToolJournalAuthorityWitness { tag, scope });
        Ok((
            ToolCallJournalIssuer {
                witness: Arc::clone(&witness),
                next_record: AtomicU64::new(1),
            },
            ToolCallJournalVerifier { witness },
        ))
    }
}

impl ToolCallJournalIssuer {
    #[doc(hidden)]
    pub fn seal_committed_record(
        &self,
        projection: ToolCallJournalProjection,
        record_digest: Digest,
        cancellation: CancellationToken,
        deadline: Option<RuntimeInstant>,
        output_budget: NonZeroUsize,
        runtime: RuntimePrimitives,
    ) -> Result<ToolCallJournalProof, JournalAuthorityError> {
        let record_sequence = self
            .next_record
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| JournalAuthorityError::RecordSequenceExhausted)
            .and_then(|value| {
                NonZeroU64::new(value).ok_or(JournalAuthorityError::RecordSequenceExhausted)
            })?;
        Ok(ToolCallJournalProof {
            witness: Arc::clone(&self.witness),
            record_sequence,
            projection,
            record_digest,
            cancellation,
            deadline,
            output_budget,
            runtime,
        })
    }

    #[doc(hidden)]
    pub fn scope(&self) -> &ToolCallScopeIdentity {
        &self.witness.scope
    }
}

impl ToolCallJournalVerifier {
    #[doc(hidden)]
    pub fn verifies(
        &self,
        proof: &ToolCallJournalProof,
        projection: &ToolCallJournalProjection,
        record_digest: Digest,
    ) -> bool {
        Arc::ptr_eq(&self.witness, &proof.witness)
            && self.witness.tag == proof.witness.tag
            && self.witness.scope == proof.witness.scope
            && proof.record_sequence.get() != 0
            && &proof.projection == projection
            && proof.record_digest == record_digest
    }

    #[doc(hidden)]
    pub fn scope(&self) -> &ToolCallScopeIdentity {
        &self.witness.scope
    }
}

const MAX_PHASE2_MODEL_PROVIDERS: usize = 64;

/// Closed generated plan for the Phase 2 model consumer edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedModelBindingPlan {
    consumer: Arc<str>,
    provider_identities: Arc<[(Arc<str>, Arc<str>)]>,
    provider_keys: Arc<[Arc<str>]>,
    lifecycle_observer_identities: Arc<[Arc<str>]>,
    runtime_primitives: Arc<[RuntimePrimitiveKind]>,
}

impl GeneratedModelBindingPlan {
    #[doc(hidden)]
    pub fn checked(
        consumer: impl Into<Arc<str>>,
        provider_identities: Vec<(Arc<str>, Arc<str>)>,
        lifecycle_observer_identities: Vec<Arc<str>>,
        runtime_primitives: Vec<RuntimePrimitiveKind>,
    ) -> Result<Self, BindingAssemblyError> {
        let consumer = consumer.into();
        if !valid_kebab_id(&consumer) {
            return Err(BindingAssemblyError::InvalidIdentity("consumer"));
        }
        if provider_identities.is_empty() || provider_identities.len() > MAX_PHASE2_MODEL_PROVIDERS
        {
            return Err(BindingAssemblyError::InvalidProviderSet);
        }
        if !provider_identities
            .windows(2)
            .all(|pair| pair[0].1 < pair[1].1)
            || provider_identities
                .iter()
                .any(|(component, key)| !valid_kebab_id(component) || !valid_kebab_id(key))
        {
            return Err(BindingAssemblyError::InvalidProviderSet);
        }
        let mut components = provider_identities
            .iter()
            .map(|(component, _)| component.as_ref())
            .collect::<Vec<_>>();
        components.sort_unstable();
        if components.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(BindingAssemblyError::InvalidProviderSet);
        }
        if !runtime_primitives.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(BindingAssemblyError::InvalidPrimitiveProjection);
        }
        let mut observer_set = lifecycle_observer_identities
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<&str>>();
        observer_set.sort_unstable();
        if lifecycle_observer_identities.len() > MAX_PHASE2_MODEL_PROVIDERS
            || lifecycle_observer_identities
                .iter()
                .any(|observer| !valid_kebab_id(observer))
            || observer_set.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(BindingAssemblyError::InvalidProviderSet);
        }
        let provider_keys = provider_identities
            .iter()
            .map(|(_, key)| Arc::clone(key))
            .collect::<Vec<_>>();
        Ok(Self {
            consumer,
            provider_identities: provider_identities.into(),
            provider_keys: provider_keys.into(),
            lifecycle_observer_identities: lifecycle_observer_identities.into(),
            runtime_primitives: runtime_primitives.into(),
        })
    }

    #[inline]
    pub fn consumer(&self) -> &str {
        &self.consumer
    }

    #[inline]
    pub fn provider_keys(&self) -> &[Arc<str>] {
        &self.provider_keys
    }

    #[inline]
    pub fn provider_identities(&self) -> &[(Arc<str>, Arc<str>)] {
        &self.provider_identities
    }

    #[inline]
    pub fn lifecycle_observer_identities(&self) -> &[Arc<str>] {
        &self.lifecycle_observer_identities
    }

    #[inline]
    pub fn runtime_primitives(&self) -> &[RuntimePrimitiveKind] {
        &self.runtime_primitives
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindingAssemblyError {
    InvalidIdentity(&'static str),
    InvalidProviderSet,
    InvalidPrimitiveProjection,
    RuntimeOwnerUnavailable,
    RuntimeOwnerAlreadyClaimed,
    RuntimeOwnerMismatch,
    CompositionMismatch,
    CatalogMismatch,
    ConsumerMismatch,
    ProviderSetMismatch,
    ObserverSetMismatch,
    ScopeMismatch,
    AlreadyBound,
    Incomplete,
}

impl fmt::Display for BindingAssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentity(field) => return write!(formatter, "invalid {field} identity"),
            Self::InvalidProviderSet => "invalid generated model provider set",
            Self::InvalidPrimitiveProjection => "invalid runtime primitive projection",
            Self::RuntimeOwnerUnavailable => "runtime bundle cannot own a composition root",
            Self::RuntimeOwnerAlreadyClaimed => "runtime bundle already owns a composition root",
            Self::RuntimeOwnerMismatch => "binding assembly runtime owner mismatch",
            Self::CompositionMismatch => "binding assembly composition mismatch",
            Self::CatalogMismatch => "binding assembly catalog mismatch",
            Self::ConsumerMismatch => "binding assembly consumer mismatch",
            Self::ProviderSetMismatch => "binding assembly provider set mismatch",
            Self::ObserverSetMismatch => "binding assembly observer set mismatch",
            Self::ScopeMismatch => "binding assembly scope mismatch",
            Self::AlreadyBound => "binding assembly edge was already bound",
            Self::Incomplete => "binding assembly is incomplete",
        })
    }
}

impl std::error::Error for BindingAssemblyError {}

#[derive(Debug)]
struct CompositionAssemblyIdentity;

/// Single-use ownership authority for one generated App composition root.
///
/// It is deliberately neither `Clone` nor serializable. A runtime bundle can
/// issue it only once, bound to the generated composition and catalog identity.
#[allow(missing_debug_implementations)]
pub struct RuntimeOwner {
    composition: CompositionHash,
    catalog: Digest,
    model_plan: GeneratedModelBindingPlan,
    bundle_identity: Arc<RuntimePrimitiveBundleIdentity>,
}

/// One fresh generated App-root assembly transaction.
#[allow(missing_debug_implementations)]
pub struct CompositionAssemblyBuilder {
    composition: CompositionHash,
    catalog: Digest,
    model_plan: GeneratedModelBindingPlan,
    identity: Arc<CompositionAssemblyIdentity>,
    runtime_bundle_identity: Arc<RuntimePrimitiveBundleIdentity>,
}

/// Starts an isolated generated composition assembly.
#[doc(hidden)]
#[inline]
pub fn begin_composition_assembly(
    runtime_owner: RuntimeOwner,
    composition: CompositionHash,
    catalog: Digest,
) -> Result<CompositionAssemblyBuilder, BindingAssemblyError> {
    if runtime_owner.composition != composition {
        return Err(BindingAssemblyError::CompositionMismatch);
    }
    if runtime_owner.catalog != catalog {
        return Err(BindingAssemblyError::CatalogMismatch);
    }
    Ok(CompositionAssemblyBuilder {
        composition,
        catalog,
        model_plan: runtime_owner.model_plan,
        identity: Arc::new(CompositionAssemblyIdentity),
        runtime_bundle_identity: runtime_owner.bundle_identity,
    })
}

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct BindingAssemblyOwner {
    composition: CompositionHash,
    catalog: Digest,
    model_plan: GeneratedModelBindingPlan,
    identity: Arc<CompositionAssemblyIdentity>,
    runtime_bundle_identity: Arc<RuntimePrimitiveBundleIdentity>,
}

impl CompositionAssemblyBuilder {
    #[inline]
    pub fn finish(self) -> BindingAssemblyOwner {
        BindingAssemblyOwner {
            composition: self.composition,
            catalog: self.catalog,
            model_plan: self.model_plan,
            identity: self.identity,
            runtime_bundle_identity: self.runtime_bundle_identity,
        }
    }
}

#[allow(missing_debug_implementations)]
pub struct BindingAssembly {
    owner: BindingAssemblyOwner,
    scope: ModelCallScopeIdentity,
    authority: Option<GeneratedScopeCallAuthority>,
}

impl BindingAssemblyOwner {
    #[doc(hidden)]
    #[inline]
    pub fn verify_generated_root(
        &self,
        composition: CompositionHash,
        catalog: Digest,
        provider_identities: &[(Arc<str>, Arc<str>)],
        lifecycle_observer_identities: &[Arc<str>],
        runtime: &RuntimePrimitives,
    ) -> Result<(), BindingAssemblyError> {
        if self.composition != composition {
            return Err(BindingAssemblyError::CompositionMismatch);
        }
        if self.catalog != catalog {
            return Err(BindingAssemblyError::CatalogMismatch);
        }
        if !Arc::ptr_eq(&self.runtime_bundle_identity, &runtime.bundle_identity) {
            return Err(BindingAssemblyError::RuntimeOwnerMismatch);
        }
        if self.model_plan.provider_identities() != provider_identities {
            return Err(BindingAssemblyError::ProviderSetMismatch);
        }
        if self.model_plan.lifecycle_observer_identities() != lifecycle_observer_identities {
            return Err(BindingAssemblyError::ObserverSetMismatch);
        }
        if self
            .model_plan
            .runtime_primitives()
            .iter()
            .any(|primitive| !runtime.has(*primitive))
        {
            return Err(BindingAssemblyError::InvalidPrimitiveProjection);
        }
        Ok(())
    }

    #[inline]
    pub fn begin_binding_assembly(
        &self,
        scope: ModelCallScopeIdentity,
    ) -> Result<BindingAssembly, BindingAssemblyError> {
        if scope.composition() != self.composition {
            return Err(BindingAssemblyError::CompositionMismatch);
        }
        if scope.catalog() != self.catalog {
            return Err(BindingAssemblyError::CatalogMismatch);
        }
        Ok(BindingAssembly {
            owner: self.clone(),
            scope,
            authority: None,
        })
    }

    #[inline]
    pub fn model_plan(&self) -> &GeneratedModelBindingPlan {
        &self.model_plan
    }
}

/// Opaque paired journal authority emitted only by a finished binding assembly.
#[allow(missing_debug_implementations)]
pub struct GeneratedScopeCallAuthority {
    assembly_identity: Arc<CompositionAssemblyIdentity>,
    issuer: ModelRequestJournalIssuer,
    verifier: ModelRequestJournalVerifier,
}

impl BindingAssembly {
    pub fn bind_model_consumer(
        &mut self,
        consumer: &str,
        provider_keys: &[Arc<str>],
    ) -> Result<(), BindingAssemblyError> {
        if self.authority.is_some() {
            return Err(BindingAssemblyError::AlreadyBound);
        }
        if consumer != self.owner.model_plan.consumer() {
            return Err(BindingAssemblyError::ConsumerMismatch);
        }
        if provider_keys != self.owner.model_plan.provider_keys() {
            return Err(BindingAssemblyError::ProviderSetMismatch);
        }
        let (issuer, verifier) =
            ModelRequestJournalAuthority::issue_for_generated_scope(self.scope.clone())
                .map_err(|_| BindingAssemblyError::Incomplete)?;
        self.authority = Some(GeneratedScopeCallAuthority {
            assembly_identity: Arc::clone(&self.owner.identity),
            issuer,
            verifier,
        });
        Ok(())
    }

    pub fn finish(mut self) -> Result<GeneratedScopeCallAuthority, BindingAssemblyError> {
        self.authority
            .take()
            .ok_or(BindingAssemblyError::Incomplete)
    }
}

impl GeneratedScopeCallAuthority {
    #[doc(hidden)]
    pub fn into_journal_parts(
        self,
        owner: &BindingAssemblyOwner,
    ) -> Result<(ModelRequestJournalIssuer, ModelRequestJournalVerifier), BindingAssemblyError>
    {
        if !Arc::ptr_eq(&self.assembly_identity, &owner.identity) {
            return Err(BindingAssemblyError::ScopeMismatch);
        }
        Ok((self.issuer, self.verifier))
    }
}

/// Host-owned resource wrapper used by audited shared-handle App Components.
///
/// Clones preserve a private wrapper identity. Constructing a second wrapper,
/// even around the same service `Arc`, intentionally creates a different
/// identity so a Host cannot substitute a reopen for a handoff.
pub struct SharedHostHandle<T: ?Sized> {
    inner: Arc<T>,
    identity: Arc<SharedHostHandleIdentity>,
}

impl<T: ?Sized> Clone for SharedHostHandle<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            identity: Arc::clone(&self.identity),
        }
    }
}

#[derive(Debug)]
struct SharedHostHandleIdentity;

impl<T: ?Sized> SharedHostHandle<T> {
    pub fn new(inner: Arc<T>) -> Self {
        Self {
            inner,
            identity: Arc::new(SharedHostHandleIdentity),
        }
    }

    pub fn service(&self) -> Arc<T> {
        Arc::clone(&self.inner)
    }

    pub fn same_identity(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
    }
}

impl<T: ?Sized> fmt::Debug for SharedHostHandle<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SharedHostHandle(<opaque>)")
    }
}

pub const MAX_SHARED_HOST_HANDOFF_FIELDS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppHandoffMode {
    Concurrent,
    StopOldApp,
}

#[derive(Clone)]
pub struct SharedHostFieldIdentity {
    path: &'static str,
    identity: Arc<SharedHostHandleIdentity>,
}

impl SharedHostFieldIdentity {
    pub const fn path(&self) -> &'static str {
        self.path
    }

    fn same_identity(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
    }
}

impl fmt::Debug for SharedHostFieldIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedHostFieldIdentity")
            .field("path", &self.path)
            .field("identity", &"<opaque>")
            .finish()
    }
}

pub fn seal_shared_host_handle<T: ?Sized>(
    path: &'static str,
    handle: &SharedHostHandle<T>,
) -> Result<SharedHostFieldIdentity, AppHandoffError> {
    if !valid_shared_host_field_path(path) {
        return Err(AppHandoffError::InvalidSharedFieldPath(path));
    }
    Ok(SharedHostFieldIdentity {
        path,
        identity: Arc::clone(&handle.identity),
    })
}

#[derive(Clone)]
pub struct AppHandoffSeal {
    mode: AppHandoffMode,
    composition_hash: &'static str,
    catalog_digest: &'static str,
    shared_fields: Arc<[SharedHostFieldIdentity]>,
}

impl AppHandoffSeal {
    pub fn new(
        mode: AppHandoffMode,
        composition_hash: &'static str,
        catalog_digest: &'static str,
        shared_fields: Vec<SharedHostFieldIdentity>,
    ) -> Result<Self, AppHandoffError> {
        if !is_sha256(composition_hash) {
            return Err(AppHandoffError::InvalidIdentity("composition-hash"));
        }
        if !is_sha256(catalog_digest) {
            return Err(AppHandoffError::InvalidIdentity("catalog-digest"));
        }
        if shared_fields.len() > MAX_SHARED_HOST_HANDOFF_FIELDS {
            return Err(AppHandoffError::TooManySharedFields {
                actual: shared_fields.len(),
                maximum: MAX_SHARED_HOST_HANDOFF_FIELDS,
            });
        }
        if !shared_fields
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
        {
            return Err(AppHandoffError::NonCanonicalSharedFields);
        }
        Ok(Self {
            mode,
            composition_hash,
            catalog_digest,
            shared_fields: shared_fields.into(),
        })
    }

    pub const fn mode(&self) -> AppHandoffMode {
        self.mode
    }

    pub fn verify_concurrent_handoff_from(&self, old: &Self) -> Result<(), AppHandoffError> {
        if self.mode != AppHandoffMode::Concurrent || old.mode != AppHandoffMode::Concurrent {
            return Err(AppHandoffError::ConcurrentHandoffUnavailable);
        }
        if self.composition_hash != old.composition_hash {
            return Err(AppHandoffError::CompositionMismatch);
        }
        if self.catalog_digest != old.catalog_digest {
            return Err(AppHandoffError::CatalogMismatch);
        }
        if self.shared_fields.len() != old.shared_fields.len()
            || self
                .shared_fields
                .iter()
                .zip(old.shared_fields.iter())
                .any(|(new, old)| new.path != old.path)
        {
            return Err(AppHandoffError::SharedFieldSetMismatch);
        }
        if let Some(field) = self
            .shared_fields
            .iter()
            .zip(old.shared_fields.iter())
            .find_map(|(new, old)| (!new.same_identity(old)).then_some(new.path))
        {
            return Err(AppHandoffError::SharedIdentityMismatch(field));
        }
        Ok(())
    }
}

impl fmt::Debug for AppHandoffSeal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppHandoffSeal")
            .field("mode", &self.mode)
            .field("composition_hash", &self.composition_hash)
            .field("catalog_digest", &self.catalog_digest)
            .field("shared_fields", &self.shared_fields)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppHandoffError {
    InvalidIdentity(&'static str),
    InvalidSharedFieldPath(&'static str),
    TooManySharedFields { actual: usize, maximum: usize },
    NonCanonicalSharedFields,
    ConcurrentHandoffUnavailable,
    CompositionMismatch,
    CatalogMismatch,
    SharedFieldSetMismatch,
    SharedIdentityMismatch(&'static str),
}

impl fmt::Display for AppHandoffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity(field) => write!(formatter, "invalid handoff {field}"),
            Self::InvalidSharedFieldPath(path) => {
                write!(formatter, "invalid shared Host field path `{path}`")
            }
            Self::TooManySharedFields { actual, maximum } => write!(
                formatter,
                "handoff has {actual} shared Host fields; maximum is {maximum}"
            ),
            Self::NonCanonicalSharedFields => {
                formatter.write_str("shared Host fields are duplicated or not in canonical order")
            }
            Self::ConcurrentHandoffUnavailable => {
                formatter.write_str("concurrent App handoff is unavailable")
            }
            Self::CompositionMismatch => formatter.write_str("App composition identity mismatch"),
            Self::CatalogMismatch => formatter.write_str("App catalog identity mismatch"),
            Self::SharedFieldSetMismatch => {
                formatter.write_str("App shared Host field set mismatch")
            }
            Self::SharedIdentityMismatch(path) => {
                write!(
                    formatter,
                    "shared Host handle identity mismatch for `{path}`"
                )
            }
        }
    }
}

impl std::error::Error for AppHandoffError {}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_shared_host_field_path(value: &str) -> bool {
    let Some((component, field)) = value.split_once('.') else {
        return false;
    };
    !field.contains('.')
        && valid_kebab_id(component)
        && !field.is_empty()
        && field.len() <= 128
        && field
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte == b'_')
        && field
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_kebab_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && !bytes.windows(2).any(|pair| pair == b"--")
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// Opaque identity of the runtime adapter that created a primitive bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAdapterIdentity(Arc<str>);

impl RuntimeAdapterIdentity {
    pub fn checked(value: impl Into<Arc<str>>) -> Result<Self, RuntimePrimitiveError> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 || !value.is_ascii() {
            return Err(RuntimePrimitiveError::InvalidAdapterIdentity);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub type RuntimeFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type RuntimeFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RuntimePrimitiveKind {
    Clock,
    Sleep,
    Spawn,
}

pub trait RuntimeClock: MaybeSendSync {
    fn now(&self) -> RuntimeInstant;
}

pub trait RuntimeSleeper: MaybeSendSync {
    fn sleep_until(&self, deadline: RuntimeInstant) -> RuntimeFuture<'static, ()>;
}

#[derive(Debug)]
struct RuntimeTaskOwnerIdentity {
    id: NonZeroU64,
    draining: AtomicBool,
    admission: Mutex<()>,
}

/// Opaque owner identity used to account and drain spawned runtime work.
#[derive(Clone)]
pub struct RuntimeTaskOwner {
    bundle_identity: Arc<RuntimePrimitiveBundleIdentity>,
    identity: Arc<RuntimeTaskOwnerIdentity>,
}

impl fmt::Debug for RuntimeTaskOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeTaskOwner")
            .field("id", &self.identity.id)
            .finish_non_exhaustive()
    }
}

impl RuntimeTaskOwner {
    #[doc(hidden)]
    pub fn id(&self) -> u64 {
        self.identity.id.get()
    }

    #[doc(hidden)]
    pub fn is_draining(&self) -> bool {
        self.identity.draining.load(Ordering::Acquire)
    }

    fn begin_drain(&self) {
        self.identity.draining.store(true, Ordering::Release);
    }
}

pub trait RuntimeSpawner: MaybeSendSync {
    fn spawn(
        &self,
        owner: RuntimeTaskOwner,
        task: RuntimeFuture<'static, ()>,
    ) -> Result<(), RuntimePrimitiveError>;

    fn drain(&self, owner: RuntimeTaskOwner) -> RuntimeFuture<'static, ()>;
}

/// An owned, explicit runtime primitive bundle.
#[derive(Clone)]
pub struct RuntimePrimitives {
    adapter: RuntimeAdapterIdentity,
    bundle_identity: Arc<RuntimePrimitiveBundleIdentity>,
    owner: Option<Arc<dyn Any + Send + Sync>>,
    clock: Option<Arc<dyn RuntimeClock>>,
    sleeper: Option<Arc<dyn RuntimeSleeper>>,
    spawner: Option<Arc<dyn RuntimeSpawner>>,
    next_task_owner: Arc<AtomicU64>,
}

#[derive(Debug)]
struct RuntimePrimitiveBundleIdentity {
    composition_root_claimed: AtomicBool,
}

impl RuntimePrimitiveBundleIdentity {
    fn new() -> Self {
        Self {
            composition_root_claimed: AtomicBool::new(false),
        }
    }
}

impl RuntimePrimitives {
    /// Identity-only constructor retained for Phase 1A contract fixtures.
    pub fn new(adapter: RuntimeAdapterIdentity) -> Self {
        Self {
            adapter,
            bundle_identity: Arc::new(RuntimePrimitiveBundleIdentity::new()),
            owner: None,
            clock: None,
            sleeper: None,
            spawner: None,
            next_task_owner: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Owned identity-only constructor retained for non-runtime Phase 1A fixtures.
    pub fn new_owned<T>(adapter: RuntimeAdapterIdentity, owner: Arc<T>) -> Self
    where
        T: Any + Send + Sync,
    {
        Self {
            adapter,
            bundle_identity: Arc::new(RuntimePrimitiveBundleIdentity::new()),
            owner: Some(owner),
            clock: None,
            sleeper: None,
            spawner: None,
            next_task_owner: Arc::new(AtomicU64::new(1)),
        }
    }

    #[doc(hidden)]
    pub fn from_adapter<T>(
        adapter: RuntimeAdapterIdentity,
        owner: Arc<T>,
        clock: Arc<dyn RuntimeClock>,
        sleeper: Arc<dyn RuntimeSleeper>,
        spawner: Arc<dyn RuntimeSpawner>,
    ) -> Self
    where
        T: Any + Send + Sync,
    {
        Self {
            adapter,
            bundle_identity: Arc::new(RuntimePrimitiveBundleIdentity::new()),
            owner: Some(owner),
            clock: Some(clock),
            sleeper: Some(sleeper),
            spawner: Some(spawner),
            next_task_owner: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn adapter(&self) -> &RuntimeAdapterIdentity {
        &self.adapter
    }

    pub fn same_bundle_identity(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.bundle_identity, &other.bundle_identity)
    }

    pub fn has_owned_driver(&self) -> bool {
        self.owner.is_some()
    }

    /// Claims the single generated composition root owned by this runtime bundle.
    #[doc(hidden)]
    #[inline]
    pub fn claim_generated_composition_owner(
        &self,
        composition: CompositionHash,
        catalog: Digest,
        model_plan: GeneratedModelBindingPlan,
    ) -> Result<RuntimeOwner, BindingAssemblyError> {
        if !self.has_owned_driver()
            || [
                RuntimePrimitiveKind::Clock,
                RuntimePrimitiveKind::Sleep,
                RuntimePrimitiveKind::Spawn,
            ]
            .into_iter()
            .any(|primitive| !self.has(primitive))
        {
            return Err(BindingAssemblyError::RuntimeOwnerUnavailable);
        }
        if model_plan
            .runtime_primitives()
            .iter()
            .any(|primitive| !self.has(*primitive))
        {
            return Err(BindingAssemblyError::InvalidPrimitiveProjection);
        }
        self.bundle_identity
            .composition_root_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| BindingAssemblyError::RuntimeOwnerAlreadyClaimed)?;
        Ok(RuntimeOwner {
            composition,
            catalog,
            model_plan,
            bundle_identity: Arc::clone(&self.bundle_identity),
        })
    }

    pub fn has(&self, primitive: RuntimePrimitiveKind) -> bool {
        match primitive {
            RuntimePrimitiveKind::Clock => self.clock.is_some(),
            RuntimePrimitiveKind::Sleep => self.sleeper.is_some(),
            RuntimePrimitiveKind::Spawn => self.spawner.is_some(),
        }
    }

    pub fn now(&self) -> Result<RuntimeInstant, RuntimePrimitiveError> {
        self.clock
            .as_ref()
            .map(|clock| clock.now())
            .ok_or(RuntimePrimitiveError::MissingPrimitive(
                RuntimePrimitiveKind::Clock,
            ))
    }

    pub fn sleep_until(
        &self,
        deadline: RuntimeInstant,
    ) -> Result<RuntimeFuture<'static, ()>, RuntimePrimitiveError> {
        self.sleeper
            .as_ref()
            .map(|sleeper| sleeper.sleep_until(deadline))
            .ok_or(RuntimePrimitiveError::MissingPrimitive(
                RuntimePrimitiveKind::Sleep,
            ))
    }

    pub fn new_task_owner(&self) -> Result<RuntimeTaskOwner, RuntimePrimitiveError> {
        if self.spawner.is_none() {
            return Err(RuntimePrimitiveError::MissingPrimitive(
                RuntimePrimitiveKind::Spawn,
            ));
        }
        let id = self
            .next_task_owner
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| RuntimePrimitiveError::TaskOwnerExhausted)
            .and_then(|value| {
                NonZeroU64::new(value).ok_or(RuntimePrimitiveError::TaskOwnerExhausted)
            })?;
        Ok(RuntimeTaskOwner {
            bundle_identity: Arc::clone(&self.bundle_identity),
            identity: Arc::new(RuntimeTaskOwnerIdentity {
                id,
                draining: AtomicBool::new(false),
                admission: Mutex::new(()),
            }),
        })
    }

    pub fn spawn(
        &self,
        owner: RuntimeTaskOwner,
        task: RuntimeFuture<'static, ()>,
    ) -> Result<(), RuntimePrimitiveError> {
        if !Arc::ptr_eq(&self.bundle_identity, &owner.bundle_identity) {
            return Err(RuntimePrimitiveError::TaskOwnerMismatch);
        }
        let spawner = self
            .spawner
            .as_ref()
            .ok_or(RuntimePrimitiveError::MissingPrimitive(
                RuntimePrimitiveKind::Spawn,
            ))?;
        let identity = Arc::clone(&owner.identity);
        let _admission = identity
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if owner.is_draining() {
            return Err(RuntimePrimitiveError::TaskOwnerClosed);
        }
        spawner.spawn(owner, task)
    }

    pub fn drain(
        &self,
        owner: RuntimeTaskOwner,
    ) -> Result<RuntimeFuture<'static, ()>, RuntimePrimitiveError> {
        if !Arc::ptr_eq(&self.bundle_identity, &owner.bundle_identity) {
            return Err(RuntimePrimitiveError::TaskOwnerMismatch);
        }
        let spawner = self
            .spawner
            .as_ref()
            .ok_or(RuntimePrimitiveError::MissingPrimitive(
                RuntimePrimitiveKind::Spawn,
            ))?;
        let identity = Arc::clone(&owner.identity);
        let _admission = identity
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        owner.begin_drain();
        Ok(spawner.drain(owner))
    }
}

impl fmt::Debug for RuntimePrimitives {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimePrimitives")
            .field("adapter", &self.adapter)
            .field("has_owned_driver", &self.has_owned_driver())
            .field(
                "primitives",
                &[
                    self.has(RuntimePrimitiveKind::Clock)
                        .then_some(RuntimePrimitiveKind::Clock),
                    self.has(RuntimePrimitiveKind::Sleep)
                        .then_some(RuntimePrimitiveKind::Sleep),
                    self.has(RuntimePrimitiveKind::Spawn)
                        .then_some(RuntimePrimitiveKind::Spawn),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl PartialEq for RuntimePrimitives {
    fn eq(&self, other: &Self) -> bool {
        self.adapter == other.adapter
            && Arc::ptr_eq(&self.bundle_identity, &other.bundle_identity)
            && match (&self.owner, &other.owner) {
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                (None, None) => true,
                _ => false,
            }
            && match (&self.clock, &other.clock) {
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                (None, None) => true,
                _ => false,
            }
            && match (&self.sleeper, &other.sleeper) {
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                (None, None) => true,
                _ => false,
            }
            && match (&self.spawner, &other.spawner) {
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                (None, None) => true,
                _ => false,
            }
    }
}

impl Eq for RuntimePrimitives {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimePrimitiveError {
    InvalidAdapterIdentity,
    AdapterMismatch { expected: String, actual: String },
    DriverConstructionFailed,
    MissingPrimitive(RuntimePrimitiveKind),
    TaskOwnerExhausted,
    TaskOwnerMismatch,
    TaskOwnerClosed,
    SpawnFailed,
}

impl fmt::Display for RuntimePrimitiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAdapterIdentity => formatter.write_str("invalid runtime adapter identity"),
            Self::AdapterMismatch { expected, actual } => {
                write!(
                    formatter,
                    "runtime adapter mismatch: expected {expected}, got {actual}"
                )
            }
            Self::DriverConstructionFailed => {
                formatter.write_str("runtime driver construction failed")
            }
            Self::MissingPrimitive(primitive) => {
                write!(formatter, "missing runtime primitive {primitive:?}")
            }
            Self::TaskOwnerExhausted => formatter.write_str("runtime task owner ids exhausted"),
            Self::TaskOwnerMismatch => {
                formatter.write_str("runtime task owner belongs to another primitive bundle")
            }
            Self::TaskOwnerClosed => formatter.write_str("runtime task owner is draining"),
            Self::SpawnFailed => formatter.write_str("runtime task spawn failed"),
        }
    }
}

impl std::error::Error for RuntimePrimitiveError {}

/// Exact primitive projection passed to one Component factory.
#[derive(Clone, Debug, Default)]
pub struct RuntimePrimitiveBindings {
    runtime: Option<RuntimePrimitives>,
    allowed: Arc<[RuntimePrimitiveKind]>,
}

impl RuntimePrimitiveBindings {
    pub fn none() -> Self {
        Self {
            runtime: None,
            allowed: Arc::new([]),
        }
    }

    pub fn projected(
        runtime: RuntimePrimitives,
        allowed: &[RuntimePrimitiveKind],
    ) -> Result<Self, RuntimePrimitiveError> {
        if !allowed.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(RuntimePrimitiveError::DriverConstructionFailed);
        }
        for primitive in allowed {
            if !runtime.has(*primitive) {
                return Err(RuntimePrimitiveError::MissingPrimitive(*primitive));
            }
        }
        Ok(Self {
            runtime: Some(runtime),
            allowed: Arc::from(allowed),
        })
    }

    pub fn allowed(&self) -> &[RuntimePrimitiveKind] {
        &self.allowed
    }

    pub fn has(&self, primitive: RuntimePrimitiveKind) -> bool {
        self.allowed.binary_search(&primitive).is_ok()
    }

    pub fn now(&self) -> Result<RuntimeInstant, RuntimePrimitiveError> {
        self.require(RuntimePrimitiveKind::Clock)?.now()
    }

    pub fn sleep_until(
        &self,
        deadline: RuntimeInstant,
    ) -> Result<RuntimeFuture<'static, ()>, RuntimePrimitiveError> {
        self.require(RuntimePrimitiveKind::Sleep)?
            .sleep_until(deadline)
    }

    pub fn new_task_owner(&self) -> Result<RuntimeTaskOwner, RuntimePrimitiveError> {
        self.require(RuntimePrimitiveKind::Spawn)?.new_task_owner()
    }

    pub fn spawn(
        &self,
        owner: RuntimeTaskOwner,
        task: RuntimeFuture<'static, ()>,
    ) -> Result<(), RuntimePrimitiveError> {
        self.require(RuntimePrimitiveKind::Spawn)?
            .spawn(owner, task)
    }

    pub fn drain(
        &self,
        owner: RuntimeTaskOwner,
    ) -> Result<RuntimeFuture<'static, ()>, RuntimePrimitiveError> {
        self.require(RuntimePrimitiveKind::Spawn)?.drain(owner)
    }

    fn require(
        &self,
        primitive: RuntimePrimitiveKind,
    ) -> Result<&RuntimePrimitives, RuntimePrimitiveError> {
        if !self.has(primitive) {
            return Err(RuntimePrimitiveError::MissingPrimitive(primitive));
        }
        self.runtime
            .as_ref()
            .ok_or(RuntimePrimitiveError::MissingPrimitive(primitive))
    }
}

/// Factory result that keeps a concrete Component owner alive.
#[derive(Debug)]
pub struct ComponentOutput<T> {
    service: Arc<T>,
}

impl<T> ComponentOutput<T> {
    pub fn stateless(service: T) -> Self {
        Self {
            service: Arc::new(service),
        }
    }

    pub fn service(&self) -> &Arc<T> {
        &self.service
    }

    pub fn into_service(self) -> Arc<T> {
        self.service
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComponentBuildError {
    InvalidConfig(String),
    MissingDependency(&'static str),
    Runtime(RuntimePrimitiveError),
}

impl fmt::Display for ComponentBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => {
                write!(formatter, "invalid component config: {message}")
            }
            Self::MissingDependency(field) => {
                write!(formatter, "missing component dependency {field}")
            }
            Self::Runtime(error) => write!(formatter, "runtime primitive error: {error}"),
        }
    }
}

impl std::error::Error for ComponentBuildError {}

/// Canonical lifecycle intent shared by the Agent and persistence seams.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentLifecycleOperationIntent {
    CreateSessionless,
    CreateEphemeral,
    CreateDurable,
    ResumeDurable { session_id: SessionId },
}

/// Error returned when a lifecycle reservation contains a non-canonical field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleReservationEncodingError {
    InvalidCanonicalField(&'static str),
}

impl fmt::Display for LifecycleReservationEncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCanonicalField(field) => {
                write!(
                    formatter,
                    "invalid canonical lifecycle reservation field `{field}`"
                )
            }
        }
    }
}

impl std::error::Error for LifecycleReservationEncodingError {}

/// A complete projected request passed atomically to a persistent allocator.
/// Fields stay private so a backend can inspect, but cannot rewrite, the seal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleOperationReservationDraft {
    recovery_key: AgentOperationRecoveryKey,
    intent: AgentLifecycleOperationIntent,
    request_fingerprint: Digest,
    projected_authority_digest: Digest,
    projected_plan_digest: Digest,
    composition: CompositionHash,
    catalog: Digest,
}

impl LifecycleOperationReservationDraft {
    #[doc(hidden)]
    pub fn from_projected_request(
        recovery_key: AgentOperationRecoveryKey,
        intent: AgentLifecycleOperationIntent,
        request_fingerprint: Digest,
        projected_authority_digest: Digest,
        projected_plan_digest: Digest,
        composition: CompositionHash,
        catalog: Digest,
    ) -> Result<Self, LifecycleReservationEncodingError> {
        if !matches!(
            intent,
            AgentLifecycleOperationIntent::CreateDurable
                | AgentLifecycleOperationIntent::ResumeDurable { .. }
        ) {
            return Err(LifecycleReservationEncodingError::InvalidCanonicalField(
                "intent",
            ));
        }
        Ok(Self {
            recovery_key,
            intent,
            request_fingerprint,
            projected_authority_digest,
            projected_plan_digest,
            composition,
            catalog,
        })
    }

    pub fn recovery_key(&self) -> &AgentOperationRecoveryKey {
        &self.recovery_key
    }

    pub const fn intent(&self) -> &AgentLifecycleOperationIntent {
        &self.intent
    }

    pub const fn request_fingerprint(&self) -> &Digest {
        &self.request_fingerprint
    }

    pub const fn projected_authority_digest(&self) -> &Digest {
        &self.projected_authority_digest
    }

    pub const fn projected_plan_digest(&self) -> &Digest {
        &self.projected_plan_digest
    }

    pub const fn composition(&self) -> &CompositionHash {
        &self.composition
    }

    pub const fn catalog(&self) -> &Digest {
        &self.catalog
    }
}

/// The authoritative reservation committed with a persistent operation id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleOperationReservation {
    operation_id: AgentLifecycleOperationId,
    draft: LifecycleOperationReservationDraft,
    reserved_session_id: SessionId,
}

impl LifecycleOperationReservation {
    #[doc(hidden)]
    pub fn from_committed_allocation(
        draft: LifecycleOperationReservationDraft,
        operation_id: &AgentLifecycleOperationId,
    ) -> Result<Self, LifecycleReservationEncodingError> {
        if operation_id.kind() != AgentLifecycleOperationIdKind::Persistent {
            return Err(LifecycleReservationEncodingError::InvalidCanonicalField(
                "operation-id",
            ));
        }
        let reserved_session_id = match draft.intent {
            AgentLifecycleOperationIntent::CreateDurable => {
                SessionId::from_persistent_operation(*operation_id).map_err(|_| {
                    LifecycleReservationEncodingError::InvalidCanonicalField("operation-id")
                })?
            }
            AgentLifecycleOperationIntent::ResumeDurable { session_id } => session_id,
            AgentLifecycleOperationIntent::CreateSessionless
            | AgentLifecycleOperationIntent::CreateEphemeral => {
                return Err(LifecycleReservationEncodingError::InvalidCanonicalField(
                    "intent",
                ));
            }
        };
        Ok(Self {
            operation_id: *operation_id,
            draft,
            reserved_session_id,
        })
    }

    pub const fn operation_id(&self) -> AgentLifecycleOperationId {
        self.operation_id
    }

    pub const fn draft(&self) -> &LifecycleOperationReservationDraft {
        &self.draft
    }

    pub const fn reserved_session_id(&self) -> &SessionId {
        &self.reserved_session_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentOperationAllocationError {
    UnsupportedIntent,
    AppClosed,
    OwnerClosed,
    OwnerMismatch,
    StoreUnavailable,
    IssuerStateCorrupt,
    CounterExhausted,
    ReservationConflict,
    OperationConflict,
    OperationNotFound,
    ReservationStatusUnknown,
    UnsupportedRecovery,
    ResourceExhausted,
}

impl fmt::Display for AgentOperationAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}",
            match self {
                Self::UnsupportedIntent => "unsupported lifecycle operation intent",
                Self::AppClosed => "App is closed",
                Self::OwnerClosed => "operation owner is closed",
                Self::OwnerMismatch => "operation owner does not match",
                Self::StoreUnavailable => "lifecycle store is unavailable",
                Self::IssuerStateCorrupt => "lifecycle issuer state is corrupt",
                Self::CounterExhausted => "lifecycle operation counter is exhausted",
                Self::ReservationConflict =>
                    "lifecycle reservation conflicts with an existing request",
                Self::OperationConflict => "lifecycle operation conflicts with an existing request",
                Self::OperationNotFound => "lifecycle operation was not found",
                Self::ReservationStatusUnknown => "lifecycle reservation status is unknown",
                Self::UnsupportedRecovery => "lifecycle operation cannot be recovered",
                Self::ResourceExhausted => "lifecycle operation capacity is exhausted",
            }
        )
    }
}

impl std::error::Error for AgentOperationAllocationError {}

#[derive(Debug)]
struct VolatileLifecycleWitness {
    generation: NonZeroU64,
}

/// An unforgeable capability for one process-bound lifecycle operation.
///
/// The canonical id is observable, but this capability is not cloneable or
/// serializable and is required to consume the allocation.
#[allow(missing_debug_implementations)]
pub struct VolatileLifecycleOperation {
    id: AgentLifecycleOperationId,
    witness: Arc<VolatileLifecycleWitness>,
}

impl VolatileLifecycleOperation {
    pub const fn id(&self) -> AgentLifecycleOperationId {
        self.id
    }
}

/// A complete, process-local create reservation sealed around one volatile
/// lifecycle capability. The capability is consumed with the reservation and
/// cannot be reconstructed from its observable operation id.
#[allow(missing_debug_implementations)]
pub struct VolatileLifecycleOperationReservation {
    operation: VolatileLifecycleOperation,
    proposed_session_id: SessionId,
    request_fingerprint: Digest,
    projected_authority_digest: Digest,
    projected_plan_digest: Digest,
    composition: CompositionHash,
    catalog: Digest,
}

impl VolatileLifecycleOperationReservation {
    #[doc(hidden)]
    pub fn from_projected_request(
        operation: VolatileLifecycleOperation,
        proposed_session_id: SessionId,
        request_fingerprint: Digest,
        projected_authority_digest: Digest,
        projected_plan_digest: Digest,
        composition: CompositionHash,
        catalog: Digest,
    ) -> Result<Self, LifecycleReservationEncodingError> {
        if SessionId::from_canonical_v1_bytes(operation.id().to_canonical_v1_bytes())
            != Ok(proposed_session_id)
        {
            return Err(LifecycleReservationEncodingError::InvalidCanonicalField(
                "proposed-session-id",
            ));
        }
        Ok(Self {
            operation,
            proposed_session_id,
            request_fingerprint,
            projected_authority_digest,
            projected_plan_digest,
            composition,
            catalog,
        })
    }

    pub const fn operation(&self) -> &VolatileLifecycleOperation {
        &self.operation
    }

    pub const fn proposed_session_id(&self) -> SessionId {
        self.proposed_session_id
    }

    pub const fn request_fingerprint(&self) -> Digest {
        self.request_fingerprint
    }

    pub const fn projected_authority_digest(&self) -> Digest {
        self.projected_authority_digest
    }

    pub const fn projected_plan_digest(&self) -> Digest {
        self.projected_plan_digest
    }

    pub const fn composition(&self) -> CompositionHash {
        self.composition
    }

    pub const fn catalog(&self) -> Digest {
        self.catalog
    }
}

/// Process-local, monotonic lifecycle operation issuer.
#[allow(missing_debug_implementations)]
pub struct VolatileLifecycleOperationIssuer {
    witness: Arc<VolatileLifecycleWitness>,
    next: AtomicU64,
}

static NEXT_VOLATILE_ISSUER_GENERATION: AtomicU64 = AtomicU64::new(1);

impl VolatileLifecycleOperationIssuer {
    #[doc(hidden)]
    pub fn for_generated_app() -> Result<Self, AgentOperationAllocationError> {
        let generation = NEXT_VOLATILE_ISSUER_GENERATION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| AgentOperationAllocationError::CounterExhausted)
            .and_then(|value| {
                NonZeroU64::new(value).ok_or(AgentOperationAllocationError::IssuerStateCorrupt)
            })?;
        Ok(Self {
            witness: Arc::new(VolatileLifecycleWitness { generation }),
            next: AtomicU64::new(1),
        })
    }

    #[doc(hidden)]
    pub fn allocate(&self) -> Result<VolatileLifecycleOperation, AgentOperationAllocationError> {
        let counter = self
            .next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| AgentOperationAllocationError::CounterExhausted)
            .and_then(|value| {
                NonZeroU64::new(value).ok_or(AgentOperationAllocationError::IssuerStateCorrupt)
            })?;
        let mut bytes = [0_u8; AgentLifecycleOperationId::ENCODED_LEN];
        bytes[0] = AgentLifecycleOperationId::VERSION;
        bytes[1] = 1;
        bytes[2..24].copy_from_slice(b"rust-agent-volatile-v1");
        bytes[26..34].copy_from_slice(&self.witness.generation.get().to_be_bytes());
        bytes[34..42].copy_from_slice(&self.witness.generation.get().to_be_bytes());
        bytes[42..50].copy_from_slice(&counter.get().to_be_bytes());
        let id = AgentLifecycleOperationId::from_canonical_v1_bytes(bytes)
            .map_err(|_| AgentOperationAllocationError::IssuerStateCorrupt)?;
        Ok(VolatileLifecycleOperation {
            id,
            witness: Arc::clone(&self.witness),
        })
    }

    #[doc(hidden)]
    pub fn recover(
        &self,
        id: AgentLifecycleOperationId,
    ) -> Result<VolatileLifecycleOperation, AgentOperationAllocationError> {
        if id.kind() != AgentLifecycleOperationIdKind::Volatile {
            return Err(AgentOperationAllocationError::UnsupportedRecovery);
        }
        let bytes = id.to_canonical_v1_bytes();
        let generation = self.witness.generation.get().to_be_bytes();
        let counter = u64::from_be_bytes(
            bytes[42..50]
                .try_into()
                .map_err(|_| AgentOperationAllocationError::IssuerStateCorrupt)?,
        );
        if &bytes[2..24] != b"rust-agent-volatile-v1"
            || bytes[24..26] != [0, 0]
            || bytes[26..34] != generation
            || bytes[34..42] != generation
            || counter == 0
            || counter >= self.next.load(Ordering::Acquire)
        {
            return Err(AgentOperationAllocationError::OperationNotFound);
        }
        Ok(VolatileLifecycleOperation {
            id,
            witness: Arc::clone(&self.witness),
        })
    }

    #[doc(hidden)]
    pub fn owns(&self, operation: &VolatileLifecycleOperation) -> bool {
        Arc::ptr_eq(&self.witness, &operation.witness)
            && operation.id.kind() == AgentLifecycleOperationIdKind::Volatile
    }
}

/// Lifecycle-bound identity for one Host-visible Agent turn.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AgentRequestId {
    agent_id: AgentId,
    lifecycle: AgentLifecycleNonce,
    sequence: NonZeroU64,
}

impl AgentRequestId {
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

/// Bounded public event-feed cursor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AgentEventCursor {
    agent_id: AgentId,
    lifecycle: AgentLifecycleNonce,
    sequence: NonZeroU64,
}

impl AgentEventCursor {
    #[doc(hidden)]
    pub const fn from_parts(
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

    pub const fn value(self) -> u64 {
        self.sequence.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentEventFeedBudgetResource {
    SubscriberCount,
    BufferedEvents,
    BufferedBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentEventFeedError {
    StaleLifecycle,
    CursorFromDifferentAgent,
    CursorExpired {
        oldest_available: Option<AgentEventCursor>,
    },
    InvalidLimit,
    AdmissionBudgetExceeded {
        resource: AgentEventFeedBudgetResource,
        requested: u64,
        limit: u64,
    },
    UnsupportedReplay,
    RuntimeUnavailable,
    Closed,
}

impl fmt::Display for AgentEventFeedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleLifecycle => formatter.write_str("event cursor lifecycle is stale"),
            Self::CursorFromDifferentAgent => {
                formatter.write_str("event cursor belongs to a different Agent")
            }
            Self::CursorExpired { .. } => formatter.write_str("event cursor has expired"),
            Self::InvalidLimit => formatter.write_str("event feed limits are invalid"),
            Self::AdmissionBudgetExceeded {
                resource,
                requested,
                limit,
            } => write!(
                formatter,
                "event feed {resource:?} budget exceeded: requested {requested}, limit {limit}"
            ),
            Self::UnsupportedReplay => formatter.write_str("event replay is unsupported"),
            Self::RuntimeUnavailable => formatter.write_str("event feed runtime is unavailable"),
            Self::Closed => formatter.write_str("event feed publisher is closed"),
        }
    }
}

impl std::error::Error for AgentEventFeedError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentPublicStatus {
    Ready,
    Closing,
    RecoveryRequired,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentEventKind {
    RequestStarted,
    OutputDelta,
    OutputFinal,
    Usage,
    RequestCompleted,
    RequestCancelled,
    RequestFailed,
    StatusChanged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentEventEnvelope {
    pub cursor: AgentEventCursor,
    pub request_id: Option<AgentRequestId>,
    pub kind: AgentEventKind,
    pub payload: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishedSessionMode {
    Sessionless,
    Ephemeral,
    Durable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationState {
    PublishedAdmissionClosed,
    Ready,
    Closing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationEntry {
    agent_id: AgentId,
    lifecycle: AgentLifecycleNonce,
    session_id: Option<SessionId>,
    mode: PublishedSessionMode,
    state: PublicationState,
}

impl PublicationEntry {
    pub const fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    pub const fn lifecycle(&self) -> AgentLifecycleNonce {
        self.lifecycle
    }

    pub const fn session_id(&self) -> Option<SessionId> {
        self.session_id
    }

    pub const fn mode(&self) -> PublishedSessionMode {
        self.mode
    }

    pub const fn state(&self) -> PublicationState {
        self.state
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationSnapshot {
    generation: u64,
    entries: Arc<[PublicationEntry]>,
}

impl PublicationSnapshot {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn entries(&self) -> &[PublicationEntry] {
        &self.entries
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationCandidate {
    entry: PublicationEntry,
}

impl PublicationCandidate {
    #[doc(hidden)]
    pub const fn for_generated_agent(
        agent_id: AgentId,
        lifecycle: AgentLifecycleNonce,
        session_id: Option<SessionId>,
        mode: PublishedSessionMode,
    ) -> Self {
        Self {
            entry: PublicationEntry {
                agent_id,
                lifecycle,
                session_id,
                mode,
                state: PublicationState::PublishedAdmissionClosed,
            },
        }
    }

    pub const fn agent_id(&self) -> AgentId {
        self.entry.agent_id
    }

    pub const fn session_id(&self) -> Option<SessionId> {
        self.entry.session_id
    }

    pub const fn mode(&self) -> PublishedSessionMode {
        self.entry.mode
    }
}

#[derive(Debug)]
pub struct PublicationTransactionView<'a> {
    previous: &'a PublicationSnapshot,
    candidate: &'a PublicationCandidate,
}

impl PublicationTransactionView<'_> {
    pub const fn previous(&self) -> &PublicationSnapshot {
        self.previous
    }

    pub const fn candidate(&self) -> &PublicationCandidate {
        self.candidate
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationEvent {
    pub generation: u64,
    pub entry: PublicationEntry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisposalEvent {
    pub generation: u64,
    pub entry: PublicationEntry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationDirectoryError {
    AlreadyPublished,
    NotPublished,
    StaleLifecycle,
    GenerationExhausted,
    InvalidStateTransition,
    SessionModeMismatch,
}

impl fmt::Display for PublicationDirectoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyPublished => "Agent is already published",
            Self::NotPublished => "Agent is not published",
            Self::StaleLifecycle => "Agent lifecycle is stale",
            Self::GenerationExhausted => "publication generation is exhausted",
            Self::InvalidStateTransition => "publication state transition is invalid",
            Self::SessionModeMismatch => "publication Session mode does not match its identity",
        })
    }
}

impl std::error::Error for PublicationDirectoryError {}

#[derive(Debug, Default)]
struct PublicationDirectoryState {
    generation: u64,
    entries: BTreeMap<AgentId, PublicationEntry>,
}

#[derive(Clone, Debug)]
pub struct PublicationDirectory {
    state: Arc<RwLock<PublicationDirectoryState>>,
}

pub struct PublicationDirectoryWriteHandle {
    state: Arc<RwLock<PublicationDirectoryState>>,
}

impl fmt::Debug for PublicationDirectoryWriteHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicationDirectoryWriteHandle(<opaque>)")
    }
}

#[doc(hidden)]
pub fn new_publication_directory() -> (PublicationDirectory, PublicationDirectoryWriteHandle) {
    let state = Arc::new(RwLock::new(PublicationDirectoryState::default()));
    (
        PublicationDirectory {
            state: Arc::clone(&state),
        },
        PublicationDirectoryWriteHandle { state },
    )
}

impl PublicationDirectory {
    pub fn snapshot(&self) -> PublicationSnapshot {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        PublicationSnapshot {
            generation: state.generation,
            entries: state.entries.values().cloned().collect(),
        }
    }
}

impl PublicationDirectoryWriteHandle {
    #[doc(hidden)]
    pub fn transaction_view<'a>(
        &self,
        previous: &'a PublicationSnapshot,
        candidate: &'a PublicationCandidate,
    ) -> PublicationTransactionView<'a> {
        PublicationTransactionView {
            previous,
            candidate,
        }
    }

    #[doc(hidden)]
    pub fn publish(
        &self,
        candidate: PublicationCandidate,
    ) -> Result<(PublicationEvent, PublicationSnapshot), PublicationDirectoryError> {
        if matches!(candidate.entry.mode, PublishedSessionMode::Sessionless)
            != candidate.entry.session_id.is_none()
        {
            return Err(PublicationDirectoryError::SessionModeMismatch);
        }
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.entries.contains_key(&candidate.entry.agent_id) {
            return Err(PublicationDirectoryError::AlreadyPublished);
        }
        let remaining_transitions = state.entries.values().try_fold(0_u64, |total, entry| {
            total.checked_add(match entry.state {
                PublicationState::PublishedAdmissionClosed => 3,
                PublicationState::Ready => 2,
                PublicationState::Closing => 1,
            })
        });
        if remaining_transitions
            .and_then(|remaining| remaining.checked_add(4))
            .and_then(|required| state.generation.checked_add(required))
            .is_none()
        {
            return Err(PublicationDirectoryError::GenerationExhausted);
        }
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(PublicationDirectoryError::GenerationExhausted)?;
        state
            .entries
            .insert(candidate.entry.agent_id, candidate.entry.clone());
        let event = PublicationEvent {
            generation: state.generation,
            entry: candidate.entry,
        };
        let snapshot = PublicationSnapshot {
            generation: state.generation,
            entries: state.entries.values().cloned().collect(),
        };
        Ok((event, snapshot))
    }

    #[doc(hidden)]
    pub fn mark_ready(
        &self,
        agent_id: AgentId,
        lifecycle: AgentLifecycleNonce,
    ) -> Result<PublicationSnapshot, PublicationDirectoryError> {
        self.update(agent_id, lifecycle, Some(PublicationState::Ready))
            .map(|(_, snapshot)| snapshot)
    }

    #[doc(hidden)]
    pub fn mark_closing(
        &self,
        agent_id: AgentId,
        lifecycle: AgentLifecycleNonce,
    ) -> Result<PublicationSnapshot, PublicationDirectoryError> {
        self.update(agent_id, lifecycle, Some(PublicationState::Closing))
            .map(|(_, snapshot)| snapshot)
    }

    #[doc(hidden)]
    pub fn remove(
        &self,
        agent_id: AgentId,
        lifecycle: AgentLifecycleNonce,
    ) -> Result<(DisposalEvent, PublicationSnapshot), PublicationDirectoryError> {
        let (entry, snapshot) = self.update(agent_id, lifecycle, None)?;
        Ok((
            DisposalEvent {
                generation: snapshot.generation,
                entry,
            },
            snapshot,
        ))
    }

    fn update(
        &self,
        agent_id: AgentId,
        lifecycle: AgentLifecycleNonce,
        next_state: Option<PublicationState>,
    ) -> Result<(PublicationEntry, PublicationSnapshot), PublicationDirectoryError> {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = state
            .entries
            .get(&agent_id)
            .ok_or(PublicationDirectoryError::NotPublished)?;
        if entry.lifecycle != lifecycle {
            return Err(PublicationDirectoryError::StaleLifecycle);
        }
        if let Some(next_state) = next_state {
            let valid = matches!(
                (entry.state, next_state),
                (
                    PublicationState::PublishedAdmissionClosed,
                    PublicationState::Ready
                ) | (PublicationState::Ready, PublicationState::Closing)
            );
            if !valid {
                return Err(PublicationDirectoryError::InvalidStateTransition);
            }
        }
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(PublicationDirectoryError::GenerationExhausted)?;
        let entry = if let Some(next_state) = next_state {
            let entry = state
                .entries
                .get_mut(&agent_id)
                .expect("validated entry remains present while holding the write lock");
            entry.state = next_state;
            entry.clone()
        } else {
            state
                .entries
                .remove(&agent_id)
                .expect("validated entry remains present while holding the write lock")
        };
        let snapshot = PublicationSnapshot {
            generation: state.generation,
            entries: state.entries.values().cloned().collect(),
        };
        Ok((entry, snapshot))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationVeto {
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleObserverError {
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct LifecycleNotificationContext {
    cancellation: CancellationToken,
    deadline: RuntimeInstant,
    runtime: RuntimePrimitives,
}

impl LifecycleNotificationContext {
    #[doc(hidden)]
    pub fn new(
        cancellation: CancellationToken,
        deadline: RuntimeInstant,
        runtime: RuntimePrimitives,
    ) -> Self {
        Self {
            cancellation,
            deadline,
            runtime,
        }
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub fn is_expired(&self) -> bool {
        self.runtime.now().map_or(true, |now| now >= self.deadline)
    }

    pub fn remaining(&self) -> Duration {
        self.runtime.now().map_or(Duration::ZERO, |now| {
            self.deadline.saturating_duration_since(now)
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub type LifecycleObserverFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), LifecycleObserverError>> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type LifecycleObserverFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), LifecycleObserverError>> + 'a>>;

pub trait LifecycleObserver: MaybeSendSync {
    fn before_publish(
        &self,
        event: &PublicationCandidate,
        view: &PublicationTransactionView<'_>,
    ) -> Result<(), PublicationVeto>;

    fn published<'a>(
        &'a self,
        context: LifecycleNotificationContext,
        event: &'a PublicationEvent,
        snapshot: &'a PublicationSnapshot,
    ) -> LifecycleObserverFuture<'a>;

    fn disposed<'a>(
        &'a self,
        context: LifecycleNotificationContext,
        event: &'a DisposalEvent,
        snapshot: &'a PublicationSnapshot,
    ) -> LifecycleObserverFuture<'a>;
}

#[derive(Clone)]
pub struct LifecycleObserverBinding {
    component: Option<Arc<str>>,
    observer: Arc<dyn LifecycleObserver>,
}

impl fmt::Debug for LifecycleObserverBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LifecycleObserverBinding(<opaque>)")
    }
}

impl LifecycleObserverBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: LifecycleObserver + 'static,
    {
        Self {
            component: None,
            observer: provider,
        }
    }

    #[doc(hidden)]
    pub fn from_generated_component(
        component: impl Into<Arc<str>>,
        provider: Arc<dyn LifecycleObserver>,
    ) -> Result<Self, BindingAssemblyError> {
        let component = component.into();
        if !valid_kebab_id(&component) {
            return Err(BindingAssemblyError::InvalidIdentity("lifecycle observer"));
        }
        Ok(Self {
            component: Some(component),
            observer: provider,
        })
    }

    #[doc(hidden)]
    #[inline]
    pub fn generated_component_identity(&self) -> Option<&str> {
        self.component.as_deref()
    }

    #[doc(hidden)]
    #[inline]
    pub fn into_generated_parts(
        self,
    ) -> Result<(Arc<str>, Arc<dyn LifecycleObserver>), BindingAssemblyError> {
        let component = self
            .component
            .ok_or(BindingAssemblyError::InvalidIdentity("lifecycle observer"))?;
        Ok((component, self.observer))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandAdmissionError {
    Closed,
    Busy,
    StaleLifecycle,
}

impl fmt::Display for CommandAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Closed => "command admission is closed",
            Self::Busy => "Agent is busy",
            Self::StaleLifecycle => "command lifecycle is stale",
        })
    }
}

impl std::error::Error for CommandAdmissionError {}

/// Weakly held admission seam used by the command dispatcher without importing
/// the Agent or Session API crates.
pub trait CommandAdmissionGate: MaybeSendSync {
    fn admit_command(
        &self,
        agent_id: AgentId,
        lifecycle: AgentLifecycleNonce,
    ) -> Result<(), CommandAdmissionError>;
}

/// Session query cursor shared without importing an Agent API crate.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SessionQueryCursor(u64);

impl SessionQueryCursor {
    pub const fn initial() -> Self {
        Self(0)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Error returned by a generated composition build.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildError {
    Component(ComponentBuildError),
    InvalidRuntime(RuntimePrimitiveError),
    InvalidHandoff(AppHandoffError),
    InvalidComposition(&'static str),
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Component(error) => write!(formatter, "component build failed: {error}"),
            Self::InvalidRuntime(error) => write!(formatter, "invalid runtime: {error}"),
            Self::InvalidHandoff(error) => write!(formatter, "invalid App handoff: {error}"),
            Self::InvalidComposition(message) => {
                write!(formatter, "invalid composition: {message}")
            }
        }
    }
}

impl std::error::Error for BuildError {}

impl From<ComponentBuildError> for BuildError {
    fn from(error: ComponentBuildError) -> Self {
        Self::Component(error)
    }
}

impl From<AppHandoffError> for BuildError {
    fn from(error: AppHandoffError) -> Self {
        Self::InvalidHandoff(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct TestRuntimeDriver {
        tasks: Arc<AtomicU64>,
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[derive(Debug)]
    struct BlockingRegistrationDriver {
        spawn_entered: std::sync::Barrier,
        release_spawn: std::sync::Barrier,
        registered: AtomicBool,
        drain_saw_registration: AtomicBool,
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl BlockingRegistrationDriver {
        fn new() -> Self {
            Self {
                spawn_entered: std::sync::Barrier::new(2),
                release_spawn: std::sync::Barrier::new(2),
                registered: AtomicBool::new(false),
                drain_saw_registration: AtomicBool::new(false),
            }
        }
    }

    impl RuntimeClock for TestRuntimeDriver {
        fn now(&self) -> RuntimeInstant {
            RuntimeInstant::from_monotonic_duration(Duration::ZERO)
        }
    }

    impl RuntimeSleeper for TestRuntimeDriver {
        fn sleep_until(&self, _deadline: RuntimeInstant) -> RuntimeFuture<'static, ()> {
            Box::pin(async {})
        }
    }

    impl RuntimeSpawner for TestRuntimeDriver {
        fn spawn(
            &self,
            _owner: RuntimeTaskOwner,
            _task: RuntimeFuture<'static, ()>,
        ) -> Result<(), RuntimePrimitiveError> {
            self.tasks.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn drain(&self, _owner: RuntimeTaskOwner) -> RuntimeFuture<'static, ()> {
            let tasks = Arc::clone(&self.tasks);
            Box::pin(async move {
                tasks.store(0, Ordering::Release);
            })
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl RuntimeClock for BlockingRegistrationDriver {
        fn now(&self) -> RuntimeInstant {
            RuntimeInstant::from_monotonic_duration(Duration::ZERO)
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl RuntimeSleeper for BlockingRegistrationDriver {
        fn sleep_until(&self, _deadline: RuntimeInstant) -> RuntimeFuture<'static, ()> {
            Box::pin(async {})
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl RuntimeSpawner for BlockingRegistrationDriver {
        fn spawn(
            &self,
            _owner: RuntimeTaskOwner,
            _task: RuntimeFuture<'static, ()>,
        ) -> Result<(), RuntimePrimitiveError> {
            self.spawn_entered.wait();
            self.release_spawn.wait();
            self.registered.store(true, Ordering::Release);
            Ok(())
        }

        fn drain(&self, _owner: RuntimeTaskOwner) -> RuntimeFuture<'static, ()> {
            self.drain_saw_registration
                .store(self.registered.load(Ordering::Acquire), Ordering::Release);
            Box::pin(async {})
        }
    }

    fn explicit_runtime() -> RuntimePrimitives {
        let driver = Arc::new(TestRuntimeDriver::default());
        let clock: Arc<dyn RuntimeClock> = driver.clone();
        let sleeper: Arc<dyn RuntimeSleeper> = driver.clone();
        let spawner: Arc<dyn RuntimeSpawner> = driver.clone();
        RuntimePrimitives::from_adapter(
            RuntimeAdapterIdentity::checked("test-explicit-runtime").unwrap(),
            driver,
            clock,
            sleeper,
            spawner,
        )
    }

    #[test]
    fn runtime_identity_is_checked_and_owned() {
        assert!(RuntimeAdapterIdentity::checked("").is_err());
        let identity = RuntimeAdapterIdentity::checked("fixture-runtime").unwrap();
        let runtime = RuntimePrimitives::new(identity);
        assert_eq!(runtime.adapter().as_str(), "fixture-runtime");
    }

    #[test]
    fn explicit_runtime_primitives_are_projected_and_owner_tasks_drain() {
        let runtime = explicit_runtime();
        let projection = RuntimePrimitiveBindings::projected(
            runtime.clone(),
            &[RuntimePrimitiveKind::Clock, RuntimePrimitiveKind::Spawn],
        )
        .unwrap();
        assert!(projection.has(RuntimePrimitiveKind::Clock));
        assert!(!projection.has(RuntimePrimitiveKind::Sleep));
        assert!(projection.now().is_ok());
        assert!(matches!(
            projection.sleep_until(runtime.now().unwrap()),
            Err(RuntimePrimitiveError::MissingPrimitive(
                RuntimePrimitiveKind::Sleep
            ))
        ));
        let owner = runtime.new_task_owner().unwrap();
        runtime.spawn(owner.clone(), Box::pin(async {})).unwrap();
        run_ready(runtime.drain(owner.clone()).unwrap());
        assert_eq!(
            runtime.spawn(owner, Box::pin(async {})),
            Err(RuntimePrimitiveError::TaskOwnerClosed)
        );

        let foreign = explicit_runtime();
        let foreign_owner = foreign.new_task_owner().unwrap();
        assert_eq!(
            runtime.spawn(foreign_owner, Box::pin(async {})),
            Err(RuntimePrimitiveError::TaskOwnerMismatch)
        );
        let foreign_owner = foreign.new_task_owner().unwrap();
        assert!(matches!(
            runtime.drain(foreign_owner),
            Err(RuntimePrimitiveError::TaskOwnerMismatch)
        ));
        assert!(
            RuntimePrimitiveBindings::projected(
                runtime,
                &[RuntimePrimitiveKind::Spawn, RuntimePrimitiveKind::Clock]
            )
            .is_err()
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn drain_cannot_overtake_an_in_flight_task_registration() {
        let driver = Arc::new(BlockingRegistrationDriver::new());
        let clock: Arc<dyn RuntimeClock> = driver.clone();
        let sleeper: Arc<dyn RuntimeSleeper> = driver.clone();
        let spawner: Arc<dyn RuntimeSpawner> = driver.clone();
        let runtime = RuntimePrimitives::from_adapter(
            RuntimeAdapterIdentity::checked("blocking-registration-runtime").unwrap(),
            driver.clone(),
            clock,
            sleeper,
            spawner,
        );
        let owner = runtime.new_task_owner().unwrap();

        let spawn_runtime = runtime.clone();
        let spawn_owner = owner.clone();
        let spawn =
            std::thread::spawn(move || spawn_runtime.spawn(spawn_owner, Box::pin(async {})));
        driver.spawn_entered.wait();
        assert!(owner.identity.admission.try_lock().is_err());

        let drain_runtime = runtime.clone();
        let drain_owner = owner.clone();
        let drain = std::thread::spawn(move || drain_runtime.drain(drain_owner));
        driver.release_spawn.wait();

        spawn.join().unwrap().unwrap();
        run_ready(drain.join().unwrap().unwrap());
        assert!(driver.drain_saw_registration.load(Ordering::Acquire));
        assert_eq!(
            runtime.spawn(owner, Box::pin(async {})),
            Err(RuntimePrimitiveError::TaskOwnerClosed)
        );
    }

    #[test]
    fn lifecycle_notification_deadlines_use_the_projected_monotonic_clock() {
        let runtime = explicit_runtime();
        let context = LifecycleNotificationContext::new(
            CancellationToken::new(),
            RuntimeInstant::from_monotonic_duration(Duration::from_secs(1)),
            runtime,
        );
        assert!(!context.is_expired());
        assert_eq!(context.remaining(), Duration::from_secs(1));

        let unavailable = LifecycleNotificationContext::new(
            CancellationToken::new(),
            RuntimeInstant::from_monotonic_duration(Duration::from_secs(1)),
            RuntimePrimitives::new(RuntimeAdapterIdentity::checked("no-clock").unwrap()),
        );
        assert!(unavailable.is_expired());
        assert_eq!(unavailable.remaining(), Duration::ZERO);
    }

    fn run_ready<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test future unexpectedly pending"),
        }
    }

    #[test]
    fn shared_host_handle_identity_survives_clone_but_not_rewrap() {
        let service = Arc::new(String::from("host-owned"));
        let first = SharedHostHandle::new(Arc::clone(&service));
        let clone = first.clone();
        let second_wrapper = SharedHostHandle::new(service);

        assert!(first.same_identity(&clone));
        assert!(!first.same_identity(&second_wrapper));
        assert_eq!(first.service().as_str(), "host-owned");
        assert_eq!(format!("{first:?}"), "SharedHostHandle(<opaque>)");
    }

    #[test]
    fn app_handoff_seal_checks_mode_composition_catalog_field_set_and_identity() {
        const COMPOSITION: &str =
            "0000000000000000000000000000000000000000000000000000000000000000";
        const OTHER_COMPOSITION: &str =
            "1111111111111111111111111111111111111111111111111111111111111111";
        const CATALOG: &str = "2222222222222222222222222222222222222222222222222222222222222222";
        const OTHER_CATALOG: &str =
            "3333333333333333333333333333333333333333333333333333333333333333";

        let service = Arc::new(String::from("host-owned"));
        let handle = SharedHostHandle::new(Arc::clone(&service));
        let same = handle.clone();
        let second_wrapper = SharedHostHandle::new(service);
        let seal = |composition, catalog, field: SharedHostFieldIdentity| {
            AppHandoffSeal::new(
                AppHandoffMode::Concurrent,
                composition,
                catalog,
                vec![field],
            )
            .unwrap()
        };
        let old = seal(
            COMPOSITION,
            CATALOG,
            seal_shared_host_handle("fixture-model.shared", &handle).unwrap(),
        );
        let matching = seal(
            COMPOSITION,
            CATALOG,
            seal_shared_host_handle("fixture-model.shared", &same).unwrap(),
        );
        matching.verify_concurrent_handoff_from(&old).unwrap();

        let wrong_wrapper = seal(
            COMPOSITION,
            CATALOG,
            seal_shared_host_handle("fixture-model.shared", &second_wrapper).unwrap(),
        );
        assert_eq!(
            wrong_wrapper.verify_concurrent_handoff_from(&old),
            Err(AppHandoffError::SharedIdentityMismatch(
                "fixture-model.shared"
            ))
        );
        let wrong_field = seal(
            COMPOSITION,
            CATALOG,
            seal_shared_host_handle("fixture-model.other", &same).unwrap(),
        );
        assert_eq!(
            wrong_field.verify_concurrent_handoff_from(&old),
            Err(AppHandoffError::SharedFieldSetMismatch)
        );
        let wrong_composition = seal(
            OTHER_COMPOSITION,
            CATALOG,
            seal_shared_host_handle("fixture-model.shared", &same).unwrap(),
        );
        assert_eq!(
            wrong_composition.verify_concurrent_handoff_from(&old),
            Err(AppHandoffError::CompositionMismatch)
        );
        let wrong_catalog = seal(
            COMPOSITION,
            OTHER_CATALOG,
            seal_shared_host_handle("fixture-model.shared", &same).unwrap(),
        );
        assert_eq!(
            wrong_catalog.verify_concurrent_handoff_from(&old),
            Err(AppHandoffError::CatalogMismatch)
        );
        let stopped =
            AppHandoffSeal::new(AppHandoffMode::StopOldApp, COMPOSITION, CATALOG, Vec::new())
                .unwrap();
        assert_eq!(
            matching.verify_concurrent_handoff_from(&stopped),
            Err(AppHandoffError::ConcurrentHandoffUnavailable)
        );
    }

    #[test]
    fn app_handoff_seal_rejects_invalid_identity_path_order_and_field_bound() {
        const IDENTITY: &str = "0000000000000000000000000000000000000000000000000000000000000000";
        let handle = SharedHostHandle::new(Arc::new(()));
        assert!(matches!(
            seal_shared_host_handle("invalid", &handle),
            Err(AppHandoffError::InvalidSharedFieldPath("invalid"))
        ));
        let field = seal_shared_host_handle("fixture-model.shared", &handle).unwrap();
        assert!(matches!(
            AppHandoffSeal::new(AppHandoffMode::Concurrent, "INVALID", IDENTITY, Vec::new()),
            Err(AppHandoffError::InvalidIdentity("composition-hash"))
        ));
        assert!(matches!(
            AppHandoffSeal::new(
                AppHandoffMode::Concurrent,
                IDENTITY,
                IDENTITY,
                vec![field.clone(), field.clone()]
            ),
            Err(AppHandoffError::NonCanonicalSharedFields)
        ));
        assert!(matches!(
            AppHandoffSeal::new(
                AppHandoffMode::Concurrent,
                IDENTITY,
                IDENTITY,
                vec![field; MAX_SHARED_HOST_HANDOFF_FIELDS + 1]
            ),
            Err(AppHandoffError::TooManySharedFields { .. })
        ));
    }

    #[test]
    fn public_cursors_are_bound_to_agent_and_lifecycle() {
        let agent = AgentId::from_nonzero_u128(1).unwrap();
        let lifecycle = AgentLifecycleNonce::from_nonzero(NonZeroU64::new(2).unwrap());
        let cursor = AgentEventCursor::from_parts(agent, lifecycle, NonZeroU64::new(3).unwrap());
        assert_eq!(cursor.agent_id(), agent);
        assert_eq!(cursor.lifecycle(), lifecycle);
        assert_eq!(cursor.value(), 3);
        assert_eq!(SessionQueryCursor::initial().value(), 0);
    }

    fn model_scope() -> ModelCallScopeIdentity {
        ModelCallScopeIdentity::for_generated_agent(
            AgentId::from_nonzero_u128(1).unwrap(),
            AgentLifecycleNonce::from_nonzero(NonZeroU64::new(1).unwrap()),
            None,
            CompositionHash::from_digest(Digest::from_bytes([2; 32])),
            Digest::from_bytes([3; 32]),
        )
    }

    fn model_projection() -> ModelCallJournalProjection {
        ModelCallJournalProjection::from_model_plan(
            RequestId::from_nonzero_u128(4).unwrap(),
            Digest::from_bytes([5; 32]),
            Digest::from_bytes([6; 32]),
            Digest::from_bytes([7; 32]),
        )
    }

    fn tool_scope(agent: u128) -> ToolCallScopeIdentity {
        ToolCallScopeIdentity::for_generated_agent(
            AgentId::from_nonzero_u128(agent).unwrap(),
            AgentLifecycleNonce::from_nonzero(NonZeroU64::new(1).unwrap()),
            None,
            CompositionHash::from_digest(Digest::from_bytes([2; 32])),
            Digest::from_bytes([3; 32]),
        )
    }

    fn tool_projection(call: u128) -> ToolCallJournalProjection {
        ToolCallJournalProjection::from_tool_plan(
            CallId::from_nonzero_u128(call).unwrap(),
            Digest::from_bytes([4; 32]),
            Digest::from_bytes([5; 32]),
            Digest::from_bytes([6; 32]),
            Digest::from_bytes([7; 32]),
            Digest::from_bytes([8; 32]),
        )
    }

    #[test]
    fn request_journal_proof_is_exact_and_scope_bound() {
        let (issuer, verifier) =
            ModelRequestJournalAuthority::issue_for_generated_scope(model_scope()).unwrap();
        let projection = model_projection();
        let record_digest = Digest::from_bytes([8; 32]);
        let proof = issuer
            .seal_committed_record(
                projection.clone(),
                record_digest,
                CancellationToken::new(),
                None,
                NonZeroUsize::new(1024).unwrap(),
                RuntimePrimitives::new(RuntimeAdapterIdentity::checked("test-runtime").unwrap()),
            )
            .unwrap();
        assert!(verifier.verifies(&proof, &projection, record_digest));
        assert!(!verifier.verifies(&proof, &projection, Digest::from_bytes([9; 32])));

        let (_, foreign) =
            ModelRequestJournalAuthority::issue_for_generated_scope(model_scope()).unwrap();
        assert!(!foreign.verifies(&proof, &projection, record_digest));
    }

    #[test]
    fn tool_journal_proof_is_exact_authority_and_agent_bound() {
        let (issuer, verifier) =
            ToolCallJournalAuthority::issue_for_generated_scope(tool_scope(1)).unwrap();
        let projection = tool_projection(9);
        let record_digest = Digest::from_bytes([10; 32]);
        let proof = issuer
            .seal_committed_record(
                projection.clone(),
                record_digest,
                CancellationToken::new(),
                None,
                NonZeroUsize::new(1024).unwrap(),
                RuntimePrimitives::new(RuntimeAdapterIdentity::checked("test-runtime").unwrap()),
            )
            .unwrap();

        assert!(verifier.verifies(&proof, &projection, record_digest));
        assert!(!verifier.verifies(&proof, &tool_projection(10), record_digest));
        assert!(!verifier.verifies(&proof, &projection, Digest::from_bytes([11; 32])));

        let (_, foreign_authority) =
            ToolCallJournalAuthority::issue_for_generated_scope(tool_scope(1)).unwrap();
        assert!(!foreign_authority.verifies(&proof, &projection, record_digest));
        let (_, foreign_agent) =
            ToolCallJournalAuthority::issue_for_generated_scope(tool_scope(2)).unwrap();
        assert!(!foreign_agent.verifies(&proof, &projection, record_digest));
    }

    #[test]
    fn binding_assembly_accepts_only_the_exact_manifest_plan() {
        let scope = model_scope();
        let observer_identities = [Arc::<str>::from("observer-a")];
        let plan = GeneratedModelBindingPlan::checked(
            "driver-direct",
            vec![
                (Arc::<str>::from("model-host"), Arc::<str>::from("host")),
                (Arc::<str>::from("model-replay"), Arc::<str>::from("replay")),
            ],
            observer_identities.to_vec(),
            vec![RuntimePrimitiveKind::Clock],
        )
        .unwrap();
        let incomplete_runtime = RuntimePrimitives::new_owned(
            RuntimeAdapterIdentity::checked("incomplete-runtime").unwrap(),
            Arc::new(()),
        );
        assert!(matches!(
            incomplete_runtime.claim_generated_composition_owner(
                scope.composition(),
                scope.catalog(),
                plan.clone(),
            ),
            Err(BindingAssemblyError::RuntimeOwnerUnavailable)
        ));
        let runtime = explicit_runtime();
        let runtime_owner = runtime
            .claim_generated_composition_owner(scope.composition(), scope.catalog(), plan.clone())
            .unwrap();
        let owner = begin_composition_assembly(runtime_owner, scope.composition(), scope.catalog())
            .unwrap()
            .finish();
        let identities = [
            (Arc::<str>::from("model-host"), Arc::<str>::from("host")),
            (Arc::<str>::from("model-replay"), Arc::<str>::from("replay")),
        ];
        owner
            .verify_generated_root(
                scope.composition(),
                scope.catalog(),
                &identities,
                &observer_identities,
                &runtime,
            )
            .unwrap();
        assert!(matches!(
            owner.verify_generated_root(
                CompositionHash::from_digest(Digest::from_bytes([99; 32])),
                scope.catalog(),
                &identities,
                &observer_identities,
                &explicit_runtime(),
            ),
            Err(BindingAssemblyError::CompositionMismatch)
        ));
        assert!(matches!(
            owner.verify_generated_root(
                scope.composition(),
                scope.catalog(),
                &identities,
                &observer_identities,
                &RuntimePrimitives::new(RuntimeAdapterIdentity::checked("identity-only").unwrap()),
            ),
            Err(BindingAssemblyError::RuntimeOwnerMismatch)
        ));
        assert!(matches!(
            runtime.claim_generated_composition_owner(
                scope.composition(),
                scope.catalog(),
                plan.clone(),
            ),
            Err(BindingAssemblyError::RuntimeOwnerAlreadyClaimed)
        ));
        let substituted = [
            (Arc::<str>::from("attacker-host"), Arc::<str>::from("host")),
            (Arc::<str>::from("model-replay"), Arc::<str>::from("replay")),
        ];
        assert!(matches!(
            owner.verify_generated_root(
                scope.composition(),
                scope.catalog(),
                &substituted,
                &observer_identities,
                &runtime,
            ),
            Err(BindingAssemblyError::ProviderSetMismatch)
        ));
        assert!(matches!(
            owner.verify_generated_root(
                scope.composition(),
                scope.catalog(),
                &identities,
                &[Arc::<str>::from("observer-b")],
                &runtime,
            ),
            Err(BindingAssemblyError::ObserverSetMismatch)
        ));
        let mut assembly = owner.begin_binding_assembly(scope.clone()).unwrap();
        assert_eq!(
            assembly.bind_model_consumer(
                "driver-direct",
                &[Arc::<str>::from("replay"), Arc::<str>::from("host")]
            ),
            Err(BindingAssemblyError::ProviderSetMismatch)
        );
        assembly
            .bind_model_consumer(
                "driver-direct",
                &[Arc::<str>::from("host"), Arc::<str>::from("replay")],
            )
            .unwrap();
        let authority = assembly.finish().unwrap();
        let foreign_runtime = explicit_runtime();
        let foreign_plan = GeneratedModelBindingPlan::checked(
            "driver-direct",
            identities.to_vec(),
            observer_identities.to_vec(),
            vec![RuntimePrimitiveKind::Clock],
        )
        .unwrap();
        let foreign_runtime_owner = foreign_runtime
            .claim_generated_composition_owner(scope.composition(), scope.catalog(), foreign_plan)
            .unwrap();
        let foreign_owner =
            begin_composition_assembly(foreign_runtime_owner, scope.composition(), scope.catalog())
                .unwrap()
                .finish();
        assert!(matches!(
            authority.into_journal_parts(&foreign_owner),
            Err(BindingAssemblyError::ScopeMismatch)
        ));
        let wrong_scope = ModelCallScopeIdentity::for_generated_agent(
            scope.agent_id(),
            scope.lifecycle(),
            None,
            CompositionHash::from_digest(Digest::from_bytes([99; 32])),
            scope.catalog(),
        );
        assert!(matches!(
            owner.begin_binding_assembly(wrong_scope),
            Err(BindingAssemblyError::CompositionMismatch)
        ));
    }

    #[test]
    fn volatile_lifecycle_operations_are_unique_and_issuer_bound() {
        let issuer = VolatileLifecycleOperationIssuer::for_generated_app().unwrap();
        let first = issuer.allocate().unwrap();
        let second = issuer.allocate().unwrap();
        assert_ne!(first.id(), second.id());
        assert!(issuer.owns(&first));
        assert!(first.id().to_durable_canonical_v1_bytes().is_err());

        let foreign = VolatileLifecycleOperationIssuer::for_generated_app().unwrap();
        assert!(!foreign.owns(&first));
    }

    #[test]
    fn volatile_session_reservation_seals_the_complete_projected_request() {
        let issuer = VolatileLifecycleOperationIssuer::for_generated_app().unwrap();
        let volatile_operation = issuer.allocate().unwrap();
        let proposed_session_id =
            SessionId::from_canonical_v1_bytes(volatile_operation.id().to_canonical_v1_bytes())
                .unwrap();
        let reservation = VolatileLifecycleOperationReservation::from_projected_request(
            volatile_operation,
            proposed_session_id,
            Digest::from_bytes([1; 32]),
            Digest::from_bytes([2; 32]),
            Digest::from_bytes([3; 32]),
            CompositionHash::from_digest(Digest::from_bytes([4; 32])),
            Digest::from_bytes([5; 32]),
        )
        .unwrap();
        assert_eq!(reservation.proposed_session_id(), proposed_session_id);
        assert_eq!(
            reservation.request_fingerprint(),
            Digest::from_bytes([1; 32])
        );
        assert!(issuer.owns(reservation.operation()));

        let volatile_operation = issuer.allocate().unwrap();
        let foreign_session = SessionId::from_persistent_operation(operation(2, 8)).unwrap();
        assert!(matches!(
            VolatileLifecycleOperationReservation::from_projected_request(
                volatile_operation,
                foreign_session,
                Digest::from_bytes([1; 32]),
                Digest::from_bytes([2; 32]),
                Digest::from_bytes([3; 32]),
                CompositionHash::from_digest(Digest::from_bytes([4; 32])),
                Digest::from_bytes([5; 32]),
            ),
            Err(LifecycleReservationEncodingError::InvalidCanonicalField(
                "proposed-session-id"
            ))
        ));
    }

    #[test]
    fn publication_directory_commits_and_removes_a_whole_entry_atomically() {
        let (directory, writer) = new_publication_directory();
        let agent = AgentId::from_nonzero_u128(10).unwrap();
        let lifecycle = AgentLifecycleNonce::from_nonzero(NonZeroU64::new(11).unwrap());
        let candidate = PublicationCandidate::for_generated_agent(
            agent,
            lifecycle,
            None,
            PublishedSessionMode::Sessionless,
        );
        let before = directory.snapshot();
        let view = writer.transaction_view(&before, &candidate);
        assert!(view.previous().entries().is_empty());
        assert_eq!(view.candidate().agent_id(), agent);

        let (_, published) = writer.publish(candidate).unwrap();
        assert_eq!(published.generation(), 1);
        assert_eq!(published.entries().len(), 1);
        let ready = writer.mark_ready(agent, lifecycle).unwrap();
        assert_eq!(ready.entries()[0].state(), PublicationState::Ready);
        let closing = writer.mark_closing(agent, lifecycle).unwrap();
        assert_eq!(closing.entries()[0].state(), PublicationState::Closing);
        let (_, removed) = writer.remove(agent, lifecycle).unwrap();
        assert!(removed.entries().is_empty());
        assert_eq!(removed.generation(), 4);
    }

    #[test]
    fn publication_directory_reserves_terminal_generation_capacity_before_publish() {
        let (directory, writer) = new_publication_directory();
        let agent = AgentId::from_nonzero_u128(12).unwrap();
        let lifecycle = AgentLifecycleNonce::from_nonzero(NonZeroU64::new(13).unwrap());
        let candidate = PublicationCandidate::for_generated_agent(
            agent,
            lifecycle,
            None,
            PublishedSessionMode::Sessionless,
        );
        writer
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .generation = u64::MAX - 3;
        assert_eq!(
            writer.publish(candidate.clone()),
            Err(PublicationDirectoryError::GenerationExhausted)
        );
        let unchanged = directory.snapshot();
        assert_eq!(unchanged.generation(), u64::MAX - 3);
        assert!(unchanged.entries().is_empty());

        writer
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .generation = u64::MAX - 4;
        writer.publish(candidate).unwrap();
        assert_eq!(
            writer.mark_closing(agent, lifecycle),
            Err(PublicationDirectoryError::InvalidStateTransition)
        );
        writer.mark_ready(agent, lifecycle).unwrap();
        writer.mark_closing(agent, lifecycle).unwrap();
        writer.remove(agent, lifecycle).unwrap();
        let terminal = directory.snapshot();
        assert_eq!(terminal.generation(), u64::MAX);
        assert!(terminal.entries().is_empty());
    }

    fn recovery_key() -> AgentOperationRecoveryKey {
        let mut bytes = [0_u8; AgentOperationRecoveryKey::ENCODED_LEN];
        bytes[0] = AgentOperationRecoveryKey::VERSION;
        bytes[1] = 1;
        AgentOperationRecoveryKey::from_canonical_v1_bytes(bytes).unwrap()
    }

    fn operation(kind: u8, counter: u8) -> AgentLifecycleOperationId {
        let mut bytes = [0_u8; AgentLifecycleOperationId::ENCODED_LEN];
        bytes[0] = AgentLifecycleOperationId::VERSION;
        bytes[1] = kind;
        bytes[2] = 1;
        bytes[41] = 1;
        bytes[49] = counter;
        AgentLifecycleOperationId::from_canonical_v1_bytes(bytes).unwrap()
    }

    fn draft(intent: AgentLifecycleOperationIntent) -> LifecycleOperationReservationDraft {
        LifecycleOperationReservationDraft::from_projected_request(
            recovery_key(),
            intent,
            Digest::from_bytes([1; 32]),
            Digest::from_bytes([2; 32]),
            Digest::from_bytes([3; 32]),
            CompositionHash::from_digest(Digest::from_bytes([4; 32])),
            Digest::from_bytes([5; 32]),
        )
        .unwrap()
    }

    #[test]
    fn persistent_create_reservation_binds_all_projected_fields() {
        let operation = operation(2, 7);
        let reservation = LifecycleOperationReservation::from_committed_allocation(
            draft(AgentLifecycleOperationIntent::CreateDurable),
            &operation,
        )
        .unwrap();
        assert_eq!(
            reservation.reserved_session_id().to_canonical_v1_bytes(),
            operation.to_canonical_v1_bytes()
        );
        assert_eq!(reservation.operation_id(), operation);
        assert_eq!(
            reservation.draft().request_fingerprint(),
            &Digest::from_bytes([1; 32])
        );
        assert_eq!(
            reservation.draft().projected_authority_digest(),
            &Digest::from_bytes([2; 32])
        );
        assert_eq!(
            reservation.draft().projected_plan_digest(),
            &Digest::from_bytes([3; 32])
        );
    }

    #[test]
    fn resume_keeps_exact_existing_session_and_volatile_paths_fail_closed() {
        let existing = SessionId::from_persistent_operation(operation(2, 8)).unwrap();
        let reservation = LifecycleOperationReservation::from_committed_allocation(
            draft(AgentLifecycleOperationIntent::ResumeDurable {
                session_id: existing,
            }),
            &operation(2, 9),
        )
        .unwrap();
        assert_eq!(reservation.reserved_session_id(), &existing);

        assert!(
            LifecycleOperationReservationDraft::from_projected_request(
                recovery_key(),
                AgentLifecycleOperationIntent::CreateEphemeral,
                Digest::from_bytes([1; 32]),
                Digest::from_bytes([2; 32]),
                Digest::from_bytes([3; 32]),
                CompositionHash::from_digest(Digest::from_bytes([4; 32])),
                Digest::from_bytes([5; 32]),
            )
            .is_err()
        );
        assert!(
            LifecycleOperationReservation::from_committed_allocation(
                draft(AgentLifecycleOperationIntent::CreateDurable),
                &operation(1, 1),
            )
            .is_err()
        );
    }
}
