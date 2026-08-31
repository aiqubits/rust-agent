//! Effect-free runtime primitives and shared lifecycle protocol types.

use std::{fmt, sync::Arc};

pub use rust_agent_core::{
    AgentLifecycleOperationId, AgentLifecycleOperationIdKind, AgentOperationRecoveryKey,
    CompositionHash, Digest, SessionId,
};

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
}

impl RuntimePrimitives {
    pub fn new(adapter: RuntimeAdapterIdentity) -> Self {
        Self { adapter }
    }

    pub fn adapter(&self) -> &RuntimeAdapterIdentity {
        &self.adapter
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
    InvalidComposition(&'static str),
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Component(error) => write!(formatter, "component build failed: {error}"),
            Self::InvalidRuntime(error) => write!(formatter, "invalid runtime: {error}"),
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
