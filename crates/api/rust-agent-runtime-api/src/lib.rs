//! Effect-free runtime primitives and shared lifecycle protocol types.

use std::{
    any::Any,
    collections::BTreeMap,
    fmt,
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

pub use rust_agent_core::{
    AgentId, AgentLifecycleOperationId, AgentLifecycleOperationIdKind, AgentOperationRecoveryKey,
    CompositionHash, Digest, MaybeSendSync, RequestId, SessionId,
};

/// Cloneable cooperative cancellation signal owned by a runtime scope.
#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) -> bool {
        !self.0.swap(true, Ordering::AcqRel)
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
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
    deadline: Option<Instant>,
    output_budget: NonZeroUsize,
}

impl RequestJournalProof {
    pub const fn request_id(&self) -> RequestId {
        self.projection.request_id()
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub const fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub const fn output_budget(&self) -> NonZeroUsize {
        self.output_budget
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
pub struct ModelRequestJournalAuthority;

impl ModelRequestJournalAuthority {
    #[doc(hidden)]
    pub fn issue_for_generated_scope(
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
        deadline: Option<Instant>,
        output_budget: NonZeroUsize,
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

/// An owned runtime primitive bundle. Phase 1A fixtures carry identity only.
#[derive(Clone)]
pub struct RuntimePrimitives {
    adapter: RuntimeAdapterIdentity,
    bundle_identity: Arc<RuntimePrimitiveBundleIdentity>,
    owner: Option<Arc<dyn Any + Send + Sync>>,
}

#[derive(Debug, Eq, PartialEq)]
struct RuntimePrimitiveBundleIdentity;

impl RuntimePrimitives {
    pub fn new(adapter: RuntimeAdapterIdentity) -> Self {
        Self {
            adapter,
            bundle_identity: Arc::new(RuntimePrimitiveBundleIdentity),
            owner: None,
        }
    }

    pub fn new_owned<T>(adapter: RuntimeAdapterIdentity, owner: Arc<T>) -> Self
    where
        T: Any + Send + Sync,
    {
        Self {
            adapter,
            bundle_identity: Arc::new(RuntimePrimitiveBundleIdentity),
            owner: Some(owner),
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
}

impl fmt::Debug for RuntimePrimitives {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimePrimitives")
            .field("adapter", &self.adapter)
            .field("has_owned_driver", &self.has_owned_driver())
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
    }
}

impl Eq for RuntimePrimitives {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimePrimitiveError {
    InvalidAdapterIdentity,
    AdapterMismatch { expected: String, actual: String },
    DriverConstructionFailed,
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
        }
    }
}

impl std::error::Error for RuntimePrimitiveError {}

/// Primitive projection passed to a Component factory.
#[derive(Clone, Debug, Default)]
pub struct RuntimePrimitiveBindings {
    runtime: Option<RuntimePrimitives>,
}

impl RuntimePrimitiveBindings {
    pub fn none() -> Self {
        Self { runtime: None }
    }

    pub fn runtime(runtime: RuntimePrimitives) -> Self {
        Self {
            runtime: Some(runtime),
        }
    }

    pub fn get(&self) -> Option<&RuntimePrimitives> {
        self.runtime.as_ref()
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
    draft: LifecycleOperationReservationDraft,
    reserved_session_id: Option<SessionId>,
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
            draft,
            reserved_session_id: Some(reserved_session_id),
        })
    }

    pub const fn draft(&self) -> &LifecycleOperationReservationDraft {
        &self.draft
    }

    pub const fn reserved_session_id(&self) -> Option<&SessionId> {
        self.reserved_session_id.as_ref()
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
    pub fn owns(&self, operation: &VolatileLifecycleOperation) -> bool {
        Arc::ptr_eq(&self.witness, &operation.witness)
            && operation.id.kind() == AgentLifecycleOperationIdKind::Volatile
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
    Closed,
}

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
    RequestCompleted,
    RequestCancelled,
    StatusChanged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentEventEnvelope {
    pub cursor: AgentEventCursor,
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
    SessionModeMismatch,
}

impl fmt::Display for PublicationDirectoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyPublished => "Agent is already published",
            Self::NotPublished => "Agent is not published",
            Self::StaleLifecycle => "Agent lifecycle is stale",
            Self::GenerationExhausted => "publication generation is exhausted",
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
    deadline: Instant,
}

impl LifecycleNotificationContext {
    #[doc(hidden)]
    pub fn new(cancellation: CancellationToken, deadline: Instant) -> Self {
        Self {
            cancellation,
            deadline,
        }
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandAdmissionError {
    Closed,
    Busy,
    StaleLifecycle,
}

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

    #[test]
    fn runtime_identity_is_checked_and_owned() {
        assert!(RuntimeAdapterIdentity::checked("").is_err());
        let identity = RuntimeAdapterIdentity::checked("fixture-runtime").unwrap();
        let runtime = RuntimePrimitives::new(identity);
        assert_eq!(runtime.adapter().as_str(), "fixture-runtime");
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
            )
            .unwrap();
        assert!(verifier.verifies(&proof, &projection, record_digest));
        assert!(!verifier.verifies(&proof, &projection, Digest::from_bytes([9; 32])));

        let (_, foreign) =
            ModelRequestJournalAuthority::issue_for_generated_scope(model_scope()).unwrap();
        assert!(!foreign.verifies(&proof, &projection, record_digest));
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
        let (_, removed) = writer.remove(agent, lifecycle).unwrap();
        assert!(removed.entries().is_empty());
        assert_eq!(removed.generation(), 3);
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
            reservation
                .reserved_session_id()
                .unwrap()
                .to_canonical_v1_bytes(),
            operation.to_canonical_v1_bytes()
        );
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
        assert_eq!(reservation.reserved_session_id(), Some(&existing));

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
