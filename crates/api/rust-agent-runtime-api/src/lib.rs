//! Effect-free runtime primitives and shared lifecycle protocol types.

use std::{fmt, sync::Arc};

pub use rust_agent_core::{
    AgentLifecycleOperationId, AgentLifecycleOperationIdKind, AgentOperationRecoveryKey,
    CompositionHash, Digest, SessionId,
};

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePrimitives {
    adapter: RuntimeAdapterIdentity,
    bundle_identity: Arc<RuntimePrimitiveBundleIdentity>,
}

#[derive(Debug, Eq, PartialEq)]
struct RuntimePrimitiveBundleIdentity;

impl RuntimePrimitives {
    pub fn new(adapter: RuntimeAdapterIdentity) -> Self {
        Self {
            adapter,
            bundle_identity: Arc::new(RuntimePrimitiveBundleIdentity),
        }
    }

    pub fn adapter(&self) -> &RuntimeAdapterIdentity {
        &self.adapter
    }

    pub fn same_bundle_identity(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.bundle_identity, &other.bundle_identity)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimePrimitiveError {
    InvalidAdapterIdentity,
    AdapterMismatch { expected: String, actual: String },
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

/// Bounded public event-feed cursor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AgentEventCursor(u64);

impl AgentEventCursor {
    pub const fn initial() -> Self {
        Self(0)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentEventFeedError {
    Lagged { next_available: AgentEventCursor },
    Closed,
    InvalidCursor,
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
    fn public_cursors_start_at_zero() {
        assert_eq!(AgentEventCursor::initial().value(), 0);
        assert_eq!(SessionQueryCursor::initial().value(), 0);
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
