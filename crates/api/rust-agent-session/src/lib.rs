//! Lightweight Session API.
//!
//! Phase 2 intentionally defines only bounded journal, persistence-admin,
//! read-store and query seams. No Session Component or storage backend lives in
//! this crate.

use std::{
    fmt,
    future::Future,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    pin::Pin,
    sync::Arc,
};

use rust_agent_core::{
    AgentLifecycleOperationId, CompositionHash, Digest, MaybeSendSync, SessionId,
};
use rust_agent_runtime_api::{
    AgentOperationAllocationError, LifecycleOperationReservation,
    LifecycleOperationReservationDraft, VolatileLifecycleOperationReservation,
};

#[cfg(not(target_arch = "wasm32"))]
pub type SessionFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type SessionFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionPersistenceError {
    Closed,
    StoreUnavailable,
    SessionNotFound {
        session: SessionId,
    },
    WriterConflict {
        session: SessionId,
    },
    StaleWriter,
    OperationConflict {
        operation: AgentLifecycleOperationId,
    },
    CursorInvalidPosition,
    CursorExpired,
    CursorBackendMismatch,
    CursorSessionMismatch,
    CorruptStore {
        diagnostic: String,
    },
    InvalidReservation,
    CommitStatusUnknown,
    Unsupported,
}

impl fmt::Display for SessionPersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("Session persistence is closed"),
            Self::StoreUnavailable => formatter.write_str("Session store is unavailable"),
            Self::SessionNotFound { .. } => formatter.write_str("Session was not found"),
            Self::WriterConflict { .. } => formatter.write_str("Session already has a live writer"),
            Self::StaleWriter => formatter.write_str("Session writer lease is stale"),
            Self::OperationConflict { .. } => {
                formatter.write_str("Session lifecycle operation conflicts with stored state")
            }
            Self::CursorInvalidPosition => {
                formatter.write_str("Session cursor position is invalid")
            }
            Self::CursorExpired => formatter.write_str("Session cursor snapshot has expired"),
            Self::CursorBackendMismatch => {
                formatter.write_str("Session cursor belongs to a different backend")
            }
            Self::CursorSessionMismatch => {
                formatter.write_str("Session cursor belongs to a different Session")
            }
            Self::CorruptStore { diagnostic } => {
                write!(formatter, "Session store is corrupt: {diagnostic}")
            }
            Self::InvalidReservation => formatter.write_str("Session reservation is invalid"),
            Self::CommitStatusUnknown => formatter.write_str("Session commit status is unknown"),
            Self::Unsupported => formatter.write_str("Session operation is unsupported"),
        }
    }
}

impl std::error::Error for SessionPersistenceError {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionSequence(u64);

impl SessionSequence {
    pub const fn value(self) -> u64 {
        self.0
    }

    #[doc(hidden)]
    pub const fn from_committed(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventBatchId(NonZeroU64);

impl EventBatchId {
    #[doc(hidden)]
    pub const fn from_nonzero(value: NonZeroU64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventRange {
    pub first: SessionSequence,
    pub last: SessionSequence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppendDurability {
    Buffered,
    Durable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppendOutcome {
    Committed(EventRange),
    NotCommitted,
    CommitStatusUnknown(EventBatchId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchCommitStatus {
    Committed(EventRange),
    NotCommitted,
    CommitStatusUnknown(EventBatchId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewSessionEventBatch {
    id: EventBatchId,
    canonical_bytes: Arc<[u8]>,
}

impl NewSessionEventBatch {
    #[doc(hidden)]
    pub fn from_canonical_runtime_event(id: EventBatchId, canonical_bytes: Arc<[u8]>) -> Self {
        Self {
            id,
            canonical_bytes,
        }
    }

    pub const fn id(&self) -> EventBatchId {
        self.id
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventPageRequest {
    pub after: Option<SessionSequence>,
    pub max_events: NonZeroU32,
    pub max_bytes: NonZeroUsize,
    pub captured_high_water: Option<SessionSequence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredEventEnvelope {
    pub sequence: SessionSequence,
    pub canonical_bytes: Arc<[u8]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventPage {
    pub events: Vec<StoredEventEnvelope>,
    pub next: Option<SessionSequence>,
    pub observed_high_water: SessionSequence,
}

pub trait SessionLog: MaybeSendSync {
    fn append(
        &self,
        batch: NewSessionEventBatch,
        durability: AppendDurability,
    ) -> SessionFuture<'_, Result<AppendOutcome, SessionPersistenceError>>;

    fn resolve_batch(
        &self,
        batch_id: EventBatchId,
    ) -> SessionFuture<'_, Result<BatchCommitStatus, SessionPersistenceError>>;

    fn read_page(
        &self,
        request: EventPageRequest,
    ) -> SessionFuture<'_, Result<EventPage, SessionPersistenceError>>;

    fn flush(&self) -> SessionFuture<'_, Result<(), SessionPersistenceError>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleOperationKind {
    Create,
    Resume,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleOperationLocation {
    Absent,
    Reserved {
        reservation: LifecycleOperationReservation,
    },
    Located {
        session_id: SessionId,
        kind: LifecycleOperationKind,
        reservation: LifecycleOperationReservation,
        terminal: Option<LifecycleTerminalSummary>,
    },
    CommitStatusUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleTerminalKind {
    CreationCompleted,
    CreationFailed,
    ResumeCompleted,
    ResumeFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleTerminalSummary {
    pub kind: LifecycleTerminalKind,
    pub batch_id: EventBatchId,
    pub diagnostic: Option<Arc<str>>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FencingGeneration(NonZeroU64);

impl FencingGeneration {
    #[doc(hidden)]
    pub const fn from_nonzero(value: NonZeroU64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriterLeaseIdentity {
    session_id: SessionId,
    generation: FencingGeneration,
    owner: Digest,
}

impl WriterLeaseIdentity {
    #[doc(hidden)]
    pub const fn from_backend(
        session_id: SessionId,
        generation: FencingGeneration,
        owner: Digest,
    ) -> Self {
        Self {
            session_id,
            generation,
            owner,
        }
    }

    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub const fn generation(&self) -> FencingGeneration {
        self.generation
    }

    pub const fn owner(&self) -> Digest {
        self.owner
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriterLeaseReleaseOutcome {
    Released,
    ReleaseStatusUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriterLeaseStatus {
    Owned,
    Released,
    Superseded {
        current_generation: FencingGeneration,
    },
}

pub trait PreparedSessionJournal: MaybeSendSync {
    fn session_id(&self) -> SessionId;
    fn generation(&self) -> FencingGeneration;
    fn writer_lease(&self) -> WriterLeaseIdentity;
    fn log(&self) -> Arc<dyn SessionLog>;
    fn release_writer_lease(
        &self,
    ) -> SessionFuture<'_, Result<WriterLeaseReleaseOutcome, SessionPersistenceError>>;
    fn resolve_writer_lease_status(
        &self,
    ) -> SessionFuture<'_, Result<WriterLeaseStatus, SessionPersistenceError>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EphemeralGenesisCommitOutcome {
    Committed(EventRange),
    NotCommitted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EphemeralGenesisCommitError {
    Closed,
    StoreUnavailable,
    InvalidReservation,
    CorruptStore { diagnostic: String },
    NotEphemeral,
}

impl fmt::Display for EphemeralGenesisCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("prepared Session transaction is closed"),
            Self::StoreUnavailable => formatter.write_str("Session store is unavailable"),
            Self::InvalidReservation => formatter.write_str("Session reservation is invalid"),
            Self::CorruptStore { diagnostic } => {
                write!(formatter, "Session store is corrupt: {diagnostic}")
            }
            Self::NotEphemeral => {
                formatter.write_str("prepared Session transaction is not ephemeral")
            }
        }
    }
}

impl std::error::Error for EphemeralGenesisCommitError {}

/// An unpublished new-Session transaction. Implementations must abort it on
/// drop unless the route has reached its authoritative commit point.
pub trait PreparedNewSessionJournal: PreparedSessionJournal {
    fn abort_unpublished(&self) -> SessionFuture<'_, Result<(), SessionPersistenceError>>;

    /// Atomically publishes an ephemeral genesis, its batch index and Session
    /// summary. The closed outcome deliberately cannot represent an unknown
    /// commit status.
    fn commit_ephemeral_genesis_and_index(
        &self,
        genesis: NewSessionEventBatch,
    ) -> SessionFuture<'_, Result<EphemeralGenesisCommitOutcome, EphemeralGenesisCommitError>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionCreationMode {
    Ephemeral,
    Durable,
}

enum NewSessionAllocation {
    Ephemeral(VolatileLifecycleOperationReservation),
    Durable(LifecycleOperationReservation),
}

#[allow(missing_debug_implementations)]
pub struct NewSessionReservation {
    operation_id: AgentLifecycleOperationId,
    proposed_session_id: SessionId,
    mode: SessionCreationMode,
    allocation: NewSessionAllocation,
    request_fingerprint: Digest,
    composition: CompositionHash,
    catalog: Digest,
    initial_authority_digest: Digest,
    initial_plan_digest: Digest,
}

impl NewSessionReservation {
    #[doc(hidden)]
    pub fn from_lifecycle(
        operation_id: AgentLifecycleOperationId,
        reservation: LifecycleOperationReservation,
        initial_authority_digest: Digest,
        initial_plan_digest: Digest,
    ) -> Result<Self, SessionPersistenceError> {
        let proposed_session_id = *reservation.reserved_session_id();
        let draft = reservation.draft();
        if reservation.operation_id() != operation_id
            || draft.intent()
                != &rust_agent_runtime_api::AgentLifecycleOperationIntent::CreateDurable
            || draft.projected_authority_digest() != &initial_authority_digest
            || draft.projected_plan_digest() != &initial_plan_digest
            || SessionId::from_persistent_operation(operation_id).ok() != Some(proposed_session_id)
        {
            return Err(SessionPersistenceError::InvalidReservation);
        }
        Ok(Self {
            operation_id,
            proposed_session_id,
            mode: SessionCreationMode::Durable,
            request_fingerprint: *draft.request_fingerprint(),
            composition: *draft.composition(),
            catalog: *draft.catalog(),
            initial_authority_digest,
            initial_plan_digest,
            allocation: NewSessionAllocation::Durable(reservation),
        })
    }

    #[doc(hidden)]
    pub fn from_volatile(reservation: VolatileLifecycleOperationReservation) -> Self {
        Self {
            operation_id: reservation.operation().id(),
            proposed_session_id: reservation.proposed_session_id(),
            mode: SessionCreationMode::Ephemeral,
            request_fingerprint: reservation.request_fingerprint(),
            composition: reservation.composition(),
            catalog: reservation.catalog(),
            initial_authority_digest: reservation.projected_authority_digest(),
            initial_plan_digest: reservation.projected_plan_digest(),
            allocation: NewSessionAllocation::Ephemeral(reservation),
        }
    }

    pub const fn mode(&self) -> SessionCreationMode {
        self.mode
    }

    pub const fn durable_lifecycle(&self) -> Option<&LifecycleOperationReservation> {
        match &self.allocation {
            NewSessionAllocation::Durable(reservation) => Some(reservation),
            NewSessionAllocation::Ephemeral(_) => None,
        }
    }

    pub const fn volatile_lifecycle(&self) -> Option<&VolatileLifecycleOperationReservation> {
        match &self.allocation {
            NewSessionAllocation::Ephemeral(reservation) => Some(reservation),
            NewSessionAllocation::Durable(_) => None,
        }
    }

    pub const fn operation_id(&self) -> AgentLifecycleOperationId {
        self.operation_id
    }

    pub const fn proposed_session_id(&self) -> SessionId {
        self.proposed_session_id
    }

    pub const fn request_fingerprint(&self) -> Digest {
        self.request_fingerprint
    }

    pub const fn composition(&self) -> CompositionHash {
        self.composition
    }

    pub const fn catalog(&self) -> Digest {
        self.catalog
    }

    pub const fn initial_authority_digest(&self) -> Digest {
        self.initial_authority_digest
    }

    pub const fn initial_plan_digest(&self) -> Digest {
        self.initial_plan_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExistingSessionReservation {
    session_id: SessionId,
    operation_id: AgentLifecycleOperationId,
    reservation: LifecycleOperationReservation,
    composition: CompositionHash,
    catalog: Digest,
}

impl ExistingSessionReservation {
    #[doc(hidden)]
    pub fn checked(
        session_id: SessionId,
        operation_id: AgentLifecycleOperationId,
        reservation: LifecycleOperationReservation,
        expected_draft: &LifecycleOperationReservationDraft,
    ) -> Result<Self, SessionPersistenceError> {
        if reservation.operation_id() != operation_id
            || reservation.reserved_session_id() != &session_id
            || reservation.draft() != expected_draft
            || expected_draft.intent()
                != &(rust_agent_runtime_api::AgentLifecycleOperationIntent::ResumeDurable {
                    session_id,
                })
        {
            return Err(SessionPersistenceError::InvalidReservation);
        }
        let composition = *expected_draft.composition();
        let catalog = *expected_draft.catalog();
        Ok(Self {
            session_id,
            operation_id,
            reservation,
            composition,
            catalog,
        })
    }

    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub const fn operation_id(&self) -> AgentLifecycleOperationId {
        self.operation_id
    }

    pub const fn lifecycle(&self) -> &LifecycleOperationReservation {
        &self.reservation
    }

    pub const fn composition(&self) -> CompositionHash {
        self.composition
    }

    pub const fn catalog(&self) -> Digest {
        self.catalog
    }
}

pub trait SessionPersistenceAdmin: MaybeSendSync {
    fn allocate_lifecycle_operation(
        &self,
        draft: LifecycleOperationReservationDraft,
    ) -> SessionFuture<'_, Result<AgentLifecycleOperationId, AgentOperationAllocationError>>;

    fn locate_lifecycle_operation(
        &self,
        operation_id: AgentLifecycleOperationId,
    ) -> SessionFuture<'_, Result<LifecycleOperationLocation, SessionPersistenceError>>;

    fn prepare_new(
        &self,
        reservation: NewSessionReservation,
    ) -> SessionFuture<'_, Result<Arc<dyn PreparedNewSessionJournal>, SessionPersistenceError>>;

    fn prepare_existing(
        &self,
        reservation: ExistingSessionReservation,
    ) -> SessionFuture<'_, Result<Arc<dyn PreparedSessionJournal>, SessionPersistenceError>>;
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionIndexHighWater(u64);

impl SessionIndexHighWater {
    #[doc(hidden)]
    pub const fn from_committed(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

/// The complete stable ordering key of one committed Session index entry.
///
/// Store implementations order entries by creation commit order and use the
/// canonical Session identity as the deterministic tie-breaker.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionIndexOrderingKey {
    creation_commit_order: u64,
    session_id: SessionId,
}

impl SessionIndexOrderingKey {
    #[doc(hidden)]
    pub const fn from_committed(creation_commit_order: u64, session_id: SessionId) -> Self {
        Self {
            creation_commit_order,
            session_id,
        }
    }

    pub const fn creation_commit_order(self) -> u64 {
        self.creation_commit_order
    }

    pub const fn session_id(self) -> SessionId {
        self.session_id
    }
}

/// An opaque, versioned continuation token for one captured Session index
/// snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionIndexCursor {
    schema_version: u32,
    backend: Digest,
    captured_high_water: SessionIndexHighWater,
    position: SessionIndexOrderingKey,
}

impl SessionIndexCursor {
    pub const SCHEMA_VERSION: u32 = 1;

    #[doc(hidden)]
    pub const fn from_store(
        backend: Digest,
        captured_high_water: SessionIndexHighWater,
        position: SessionIndexOrderingKey,
    ) -> Result<Self, SessionCursorError> {
        if position.creation_commit_order() > captured_high_water.value() {
            return Err(SessionCursorError::InvalidPosition);
        }
        Ok(Self {
            schema_version: Self::SCHEMA_VERSION,
            backend,
            captured_high_water,
            position,
        })
    }

    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub const fn backend(&self) -> Digest {
        self.backend
    }

    pub const fn captured_high_water(&self) -> SessionIndexHighWater {
        self.captured_high_water
    }

    pub const fn position(&self) -> SessionIndexOrderingKey {
        self.position
    }

    pub fn validate_backend(&self, backend: Digest) -> Result<(), SessionCursorError> {
        if self.backend != backend {
            return Err(SessionCursorError::BackendMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSessionListPageRequest {
    pub after: Option<SessionIndexCursor>,
    pub max_items: NonZeroU32,
    pub max_bytes: NonZeroUsize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionCompatibility {
    Compatible,
    IncompatibleComposition {
        stored_composition: CompositionHash,
        current_composition: CompositionHash,
        stored_catalog: Digest,
        current_catalog: Digest,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoredSessionMode {
    Ephemeral,
    Durable,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SessionEventSchemaVersion(NonZeroU32);

impl SessionEventSchemaVersion {
    #[doc(hidden)]
    pub const fn from_nonzero(value: NonZeroU32) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u32 {
        self.0.get()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSessionSummary {
    pub session_id: SessionId,
    pub mode: StoredSessionMode,
    pub compatibility: SessionCompatibility,
    pub high_water: SessionSequence,
    pub terminal: Option<LifecycleTerminalSummary>,
    pub composition: CompositionHash,
    pub catalog: Digest,
    pub event_schema: SessionEventSchemaVersion,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSessionListPage {
    pub sessions: Vec<StoredSessionSummary>,
    pub next: Option<SessionIndexCursor>,
    pub captured_index_high_water: SessionIndexHighWater,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionCursorError {
    InvalidPosition,
    BackendMismatch,
    SessionMismatch,
}

impl fmt::Display for SessionCursorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPosition => "Session cursor position exceeds its captured high-water",
            Self::BackendMismatch => "Session cursor belongs to a different backend",
            Self::SessionMismatch => "Session cursor belongs to a different Session",
        })
    }
}

impl std::error::Error for SessionCursorError {}

impl From<SessionCursorError> for SessionPersistenceError {
    fn from(error: SessionCursorError) -> Self {
        match error {
            SessionCursorError::InvalidPosition => Self::CursorInvalidPosition,
            SessionCursorError::BackendMismatch => Self::CursorBackendMismatch,
            SessionCursorError::SessionMismatch => Self::CursorSessionMismatch,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionEventCursor {
    backend: Digest,
    session_id: SessionId,
    captured_high_water: SessionSequence,
    position: SessionSequence,
}

impl SessionEventCursor {
    #[doc(hidden)]
    pub fn from_store(
        backend: Digest,
        session_id: SessionId,
        captured_high_water: SessionSequence,
        position: SessionSequence,
    ) -> Result<Self, SessionCursorError> {
        if position > captured_high_water {
            return Err(SessionCursorError::InvalidPosition);
        }
        Ok(Self {
            backend,
            session_id,
            captured_high_water,
            position,
        })
    }

    pub const fn backend(&self) -> Digest {
        self.backend
    }

    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub const fn captured_high_water(&self) -> SessionSequence {
        self.captured_high_water
    }

    pub const fn position(&self) -> SessionSequence {
        self.position
    }

    pub fn validate_scope(
        &self,
        backend: Digest,
        session_id: SessionId,
    ) -> Result<(), SessionCursorError> {
        if self.backend != backend {
            return Err(SessionCursorError::BackendMismatch);
        }
        if self.session_id != session_id {
            return Err(SessionCursorError::SessionMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredEventPageRequest {
    pub after: Option<SessionEventCursor>,
    pub max_events: NonZeroU32,
    pub max_bytes: NonZeroUsize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredEventPage {
    pub events: Vec<StoredEventEnvelope>,
    pub next: Option<SessionEventCursor>,
    pub captured_high_water: SessionSequence,
}

pub trait SessionReadStore: MaybeSendSync {
    fn list_sessions_page(
        &self,
        request: StoredSessionListPageRequest,
    ) -> SessionFuture<'_, Result<StoredSessionListPage, SessionPersistenceError>>;

    fn read_session_page(
        &self,
        session_id: SessionId,
        request: StoredEventPageRequest,
    ) -> SessionFuture<'_, Result<StoredEventPage, SessionPersistenceError>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionQueryError {
    InvalidLimit,
    CursorInvalidPosition,
    CursorExpired,
    CursorBackendMismatch,
    CursorSessionMismatch,
    SessionNotFound {
        session: SessionId,
    },
    IncompatibleComposition {
        session: SessionId,
        stored_composition: CompositionHash,
        current_composition: CompositionHash,
        stored_catalog: Digest,
        current_catalog: Digest,
    },
    UnsupportedProjectionEvent {
        kind: String,
        payload_version: u32,
    },
    CorruptStore {
        diagnostic: String,
    },
    Closed,
}

impl fmt::Display for SessionQueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit => formatter.write_str("Session query limits are invalid"),
            Self::CursorInvalidPosition => {
                formatter.write_str("Session query cursor position is invalid")
            }
            Self::CursorExpired => formatter.write_str("Session query cursor has expired"),
            Self::CursorBackendMismatch => {
                formatter.write_str("Session query cursor belongs to a different backend")
            }
            Self::CursorSessionMismatch => {
                formatter.write_str("Session query cursor belongs to a different Session")
            }
            Self::SessionNotFound { .. } => formatter.write_str("Session was not found"),
            Self::IncompatibleComposition { .. } => {
                formatter.write_str("Session belongs to an incompatible composition")
            }
            Self::UnsupportedProjectionEvent {
                kind,
                payload_version,
            } => write!(
                formatter,
                "Session event `{kind}` version {payload_version} is unsupported by the projection"
            ),
            Self::CorruptStore { diagnostic } => {
                write!(formatter, "Session store is corrupt: {diagnostic}")
            }
            Self::Closed => formatter.write_str("Session query is closed"),
        }
    }
}

impl std::error::Error for SessionQueryError {}

impl From<SessionCursorError> for SessionQueryError {
    fn from(error: SessionCursorError) -> Self {
        match error {
            SessionCursorError::InvalidPosition => Self::CursorInvalidPosition,
            SessionCursorError::BackendMismatch => Self::CursorBackendMismatch,
            SessionCursorError::SessionMismatch => Self::CursorSessionMismatch,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionProjectionCursor {
    backend: Digest,
    session_id: SessionId,
    captured_high_water: SessionSequence,
    at: SessionSequence,
}

impl SessionProjectionCursor {
    #[doc(hidden)]
    pub fn from_store(
        backend: Digest,
        session_id: SessionId,
        captured_high_water: SessionSequence,
        at: SessionSequence,
    ) -> Result<Self, SessionCursorError> {
        if at > captured_high_water {
            return Err(SessionCursorError::InvalidPosition);
        }
        Ok(Self {
            backend,
            session_id,
            captured_high_water,
            at,
        })
    }

    pub const fn backend(&self) -> Digest {
        self.backend
    }

    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub const fn captured_high_water(&self) -> SessionSequence {
        self.captured_high_water
    }

    pub const fn at(&self) -> SessionSequence {
        self.at
    }

    pub fn validate_scope(
        &self,
        backend: Digest,
        session_id: SessionId,
    ) -> Result<(), SessionCursorError> {
        if self.backend != backend {
            return Err(SessionCursorError::BackendMismatch);
        }
        if self.session_id != session_id {
            return Err(SessionCursorError::SessionMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionRequest {
    pub at: Option<SessionProjectionCursor>,
    pub max_bytes: NonZeroUsize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionSnapshot {
    pub session_id: SessionId,
    pub high_water: SessionSequence,
    pub cursor: SessionProjectionCursor,
    pub canonical_bytes: Arc<[u8]>,
}

pub trait SessionQuery: MaybeSendSync {
    fn list_sessions(
        &self,
        request: StoredSessionListPageRequest,
    ) -> SessionFuture<'_, Result<StoredSessionListPage, SessionQueryError>>;

    fn read_events(
        &self,
        session_id: SessionId,
        request: StoredEventPageRequest,
    ) -> SessionFuture<'_, Result<StoredEventPage, SessionQueryError>>;

    fn read_projection(
        &self,
        session_id: SessionId,
        request: ProjectionRequest,
    ) -> SessionFuture<'_, Result<ProjectionSnapshot, SessionQueryError>>;
}

#[derive(Clone)]
pub struct SessionQueryHandle(Arc<dyn SessionQuery>);

impl fmt::Debug for SessionQueryHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionQueryHandle(<read-only>)")
    }
}

impl SessionQueryHandle {
    #[doc(hidden)]
    pub fn from_read_only(query: Arc<dyn SessionQuery>) -> Self {
        Self(query)
    }

    pub fn list_sessions(
        &self,
        request: StoredSessionListPageRequest,
    ) -> SessionFuture<'_, Result<StoredSessionListPage, SessionQueryError>> {
        self.0.list_sessions(request)
    }

    pub fn read_events(
        &self,
        session_id: SessionId,
        request: StoredEventPageRequest,
    ) -> SessionFuture<'_, Result<StoredEventPage, SessionQueryError>> {
        self.0.read_events(session_id, request)
    }

    pub fn read_projection(
        &self,
        session_id: SessionId,
        request: ProjectionRequest,
    ) -> SessionFuture<'_, Result<ProjectionSnapshot, SessionQueryError>> {
        self.0.read_projection(session_id, request)
    }
}

#[cfg(test)]
mod tests {
    use rust_agent_core::{AgentLifecycleOperationId, AgentOperationRecoveryKey};
    use rust_agent_runtime_api::{
        AgentLifecycleOperationIntent, LifecycleOperationReservation,
        LifecycleOperationReservationDraft, VolatileLifecycleOperationIssuer,
        VolatileLifecycleOperationReservation,
    };

    use super::*;

    fn operation(counter: u8) -> AgentLifecycleOperationId {
        let mut bytes = [0_u8; AgentLifecycleOperationId::ENCODED_LEN];
        bytes[0] = AgentLifecycleOperationId::VERSION;
        bytes[1] = 2;
        bytes[2] = 1;
        bytes[41] = 1;
        bytes[49] = counter;
        AgentLifecycleOperationId::from_canonical_v1_bytes(bytes).unwrap()
    }

    fn recovery_key() -> AgentOperationRecoveryKey {
        let mut bytes = [0_u8; AgentOperationRecoveryKey::ENCODED_LEN];
        bytes[0] = AgentOperationRecoveryKey::VERSION;
        bytes[1] = 1;
        AgentOperationRecoveryKey::from_canonical_v1_bytes(bytes).unwrap()
    }

    fn reservation(
        operation_id: AgentLifecycleOperationId,
        intent: AgentLifecycleOperationIntent,
        composition: CompositionHash,
        catalog: Digest,
    ) -> LifecycleOperationReservation {
        let draft = LifecycleOperationReservationDraft::from_projected_request(
            recovery_key(),
            intent,
            Digest::from_bytes([1; 32]),
            Digest::from_bytes([2; 32]),
            Digest::from_bytes([3; 32]),
            composition,
            catalog,
        )
        .unwrap();
        LifecycleOperationReservation::from_committed_allocation(draft, &operation_id).unwrap()
    }

    #[test]
    fn lightweight_api_types_do_not_need_a_backend() {
        let session_id = SessionId::from_persistent_operation(operation(9)).unwrap();
        let cursor = SessionEventCursor::from_store(
            Digest::from_bytes([9; 32]),
            session_id,
            SessionSequence::from_committed(7),
            SessionSequence::from_committed(3),
        )
        .unwrap();
        let request = StoredEventPageRequest {
            after: Some(cursor),
            max_events: NonZeroU32::new(16).unwrap(),
            max_bytes: NonZeroUsize::new(4096).unwrap(),
        };
        assert_eq!(request.after.unwrap().position().value(), 3);
        assert_eq!(request.max_events.get(), 16);
    }

    #[test]
    fn lower_level_session_dtos_are_identity_complete_and_require_nonzero_limits() {
        assert!(NonZeroU32::new(0).is_none());
        assert!(NonZeroUsize::new(0).is_none());
        let high_water = SessionIndexHighWater::from_committed(9);
        let schema = SessionEventSchemaVersion::from_nonzero(NonZeroU32::new(1).unwrap());
        let session_id = SessionId::from_persistent_operation(operation(8)).unwrap();
        let position = SessionIndexOrderingKey::from_committed(4, session_id);
        let cursor =
            SessionIndexCursor::from_store(Digest::from_bytes([3; 32]), high_water, position)
                .unwrap();
        assert_eq!(high_water.value(), 9);
        assert_eq!(schema.value(), 1);
        assert_eq!(cursor.schema_version(), SessionIndexCursor::SCHEMA_VERSION);
        assert_eq!(cursor.captured_high_water(), high_water);
        assert_eq!(cursor.position(), position);
        assert_eq!(cursor.position().creation_commit_order(), 4);
        assert_eq!(cursor.position().session_id(), session_id);
        let tied_session = SessionId::from_persistent_operation(operation(9)).unwrap();
        let tied_position = SessionIndexOrderingKey::from_committed(4, tied_session);
        assert_eq!(position.cmp(&tied_position), session_id.cmp(&tied_session));
        assert_eq!(
            cursor.validate_backend(Digest::from_bytes([99; 32])),
            Err(SessionCursorError::BackendMismatch)
        );
        assert_eq!(
            SessionIndexCursor::from_store(
                Digest::from_bytes([3; 32]),
                SessionIndexHighWater::from_committed(4),
                SessionIndexOrderingKey::from_committed(5, session_id),
            ),
            Err(SessionCursorError::InvalidPosition)
        );
        let projection_cursor = SessionProjectionCursor::from_store(
            Digest::from_bytes([8; 32]),
            session_id,
            SessionSequence::from_committed(9),
            SessionSequence::from_committed(7),
        )
        .unwrap();
        let projection = ProjectionRequest {
            at: Some(projection_cursor),
            max_bytes: NonZeroUsize::new(4096).unwrap(),
        };
        assert_eq!(projection.max_bytes.get(), 4096);

        let composition = CompositionHash::from_digest(Digest::from_bytes([4; 32]));
        let catalog = Digest::from_bytes([5; 32]);
        let create_operation = operation(1);
        assert_eq!(
            SessionPersistenceError::OperationConflict {
                operation: create_operation
            }
            .to_string(),
            "Session lifecycle operation conflicts with stored state"
        );
        let create = reservation(
            create_operation,
            AgentLifecycleOperationIntent::CreateDurable,
            composition,
            catalog,
        );
        assert!(
            NewSessionReservation::from_lifecycle(
                create_operation,
                create.clone(),
                Digest::from_bytes([2; 32]),
                Digest::from_bytes([3; 32]),
            )
            .is_ok()
        );
        assert!(
            NewSessionReservation::from_lifecycle(
                operation(2),
                create,
                Digest::from_bytes([2; 32]),
                Digest::from_bytes([3; 32]),
            )
            .is_err()
        );

        let issuer = VolatileLifecycleOperationIssuer::for_generated_app().unwrap();
        let volatile_operation = issuer.allocate().unwrap();
        let proposed_session_id =
            SessionId::from_canonical_v1_bytes(volatile_operation.id().to_canonical_v1_bytes())
                .unwrap();
        let volatile = VolatileLifecycleOperationReservation::from_projected_request(
            volatile_operation,
            proposed_session_id,
            Digest::from_bytes([1; 32]),
            Digest::from_bytes([2; 32]),
            Digest::from_bytes([3; 32]),
            composition,
            catalog,
        )
        .unwrap();
        let ephemeral = NewSessionReservation::from_volatile(volatile);
        assert_eq!(ephemeral.mode(), SessionCreationMode::Ephemeral);
        assert_eq!(ephemeral.proposed_session_id(), proposed_session_id);
        assert_eq!(ephemeral.request_fingerprint(), Digest::from_bytes([1; 32]));
        assert!(ephemeral.volatile_lifecycle().is_some());
        assert!(ephemeral.durable_lifecycle().is_none());

        let existing = SessionId::from_persistent_operation(operation(3)).unwrap();
        let resume_operation = operation(4);
        let resume = reservation(
            resume_operation,
            AgentLifecycleOperationIntent::ResumeDurable {
                session_id: existing,
            },
            composition,
            catalog,
        );
        let expected_resume = resume.draft().clone();
        assert!(
            ExistingSessionReservation::checked(
                existing,
                resume_operation,
                resume.clone(),
                &expected_resume,
            )
            .is_ok()
        );
        let conflicting_projection = LifecycleOperationReservationDraft::from_projected_request(
            recovery_key(),
            AgentLifecycleOperationIntent::ResumeDurable {
                session_id: existing,
            },
            Digest::from_bytes([1; 32]),
            Digest::from_bytes([2; 32]),
            Digest::from_bytes([99; 32]),
            composition,
            catalog,
        )
        .unwrap();
        assert!(
            ExistingSessionReservation::checked(
                existing,
                resume_operation,
                resume,
                &conflicting_projection,
            )
            .is_err()
        );
    }

    #[test]
    fn existing_session_reservation_requires_the_exact_projected_draft() {
        let composition = CompositionHash::from_digest(Digest::from_bytes([40; 32]));
        let catalog = Digest::from_bytes([41; 32]);
        let session_id = SessionId::from_persistent_operation(operation(20)).unwrap();
        let operation_id = operation(21);
        let committed = reservation(
            operation_id,
            AgentLifecycleOperationIntent::ResumeDurable { session_id },
            composition,
            catalog,
        );
        let expected = committed.draft().clone();
        assert!(
            ExistingSessionReservation::checked(
                session_id,
                operation_id,
                committed.clone(),
                &expected,
            )
            .is_ok()
        );

        let wrong_authority = LifecycleOperationReservationDraft::from_projected_request(
            recovery_key(),
            AgentLifecycleOperationIntent::ResumeDurable { session_id },
            *expected.request_fingerprint(),
            Digest::from_bytes([99; 32]),
            *expected.projected_plan_digest(),
            composition,
            catalog,
        )
        .unwrap();
        assert_eq!(
            ExistingSessionReservation::checked(
                session_id,
                operation_id,
                committed,
                &wrong_authority,
            ),
            Err(SessionPersistenceError::InvalidReservation)
        );
    }

    #[test]
    fn event_and_projection_cursors_reject_foreign_backend_and_session_scopes() {
        let backend = Digest::from_bytes([20; 32]);
        let foreign_backend = Digest::from_bytes([99; 32]);
        let session_id = SessionId::from_persistent_operation(operation(10)).unwrap();
        let foreign_session = SessionId::from_persistent_operation(operation(11)).unwrap();
        let high_water = SessionSequence::from_committed(12);
        let position = SessionSequence::from_committed(7);
        let event =
            SessionEventCursor::from_store(backend, session_id, high_water, position).unwrap();
        let projection =
            SessionProjectionCursor::from_store(backend, session_id, high_water, position).unwrap();

        assert_eq!(event.validate_scope(backend, session_id), Ok(()));
        assert_eq!(projection.validate_scope(backend, session_id), Ok(()));
        assert_eq!(
            event.validate_scope(foreign_backend, session_id),
            Err(SessionCursorError::BackendMismatch)
        );
        assert_eq!(
            projection.validate_scope(foreign_backend, session_id),
            Err(SessionCursorError::BackendMismatch)
        );
        assert_eq!(
            event.validate_scope(backend, foreign_session),
            Err(SessionCursorError::SessionMismatch)
        );
        assert_eq!(
            projection.validate_scope(backend, foreign_session),
            Err(SessionCursorError::SessionMismatch)
        );
        assert_eq!(
            SessionQueryError::from(SessionCursorError::BackendMismatch),
            SessionQueryError::CursorBackendMismatch
        );
        assert_eq!(
            SessionQueryError::from(SessionCursorError::SessionMismatch),
            SessionQueryError::CursorSessionMismatch
        );
        assert_eq!(
            SessionQueryError::from(SessionCursorError::InvalidPosition),
            SessionQueryError::CursorInvalidPosition
        );
        assert_eq!(
            SessionPersistenceError::from(SessionCursorError::InvalidPosition),
            SessionPersistenceError::CursorInvalidPosition
        );
        assert_eq!(
            SessionPersistenceError::from(SessionCursorError::BackendMismatch),
            SessionPersistenceError::CursorBackendMismatch
        );
        assert_eq!(
            SessionPersistenceError::from(SessionCursorError::SessionMismatch),
            SessionPersistenceError::CursorSessionMismatch
        );
        assert_eq!(
            SessionPersistenceError::CursorExpired.to_string(),
            "Session cursor snapshot has expired"
        );
        assert_eq!(event.captured_high_water(), high_water);
        assert_eq!(projection.captured_high_water(), high_water);
        assert!(SessionEventCursor::from_store(backend, session_id, position, high_water).is_err());
        assert!(
            SessionProjectionCursor::from_store(backend, session_id, position, high_water).is_err()
        );
    }

    #[test]
    fn prepared_new_session_api_has_abort_and_known_outcome_ephemeral_commit() {
        fn assert_api(prepared: &dyn PreparedNewSessionJournal, genesis: NewSessionEventBatch) {
            let abort: SessionFuture<'_, Result<(), SessionPersistenceError>> =
                prepared.abort_unpublished();
            drop(abort);
            let commit: SessionFuture<
                '_,
                Result<EphemeralGenesisCommitOutcome, EphemeralGenesisCommitError>,
            > = prepared.commit_ephemeral_genesis_and_index(genesis);
            drop(commit);
        }

        fn known_outcome_is_closed(outcome: EphemeralGenesisCommitOutcome) -> bool {
            match outcome {
                EphemeralGenesisCommitOutcome::Committed(_) => true,
                EphemeralGenesisCommitOutcome::NotCommitted => false,
            }
        }

        let _ = assert_api;
        assert!(known_outcome_is_closed(
            EphemeralGenesisCommitOutcome::Committed(EventRange {
                first: SessionSequence::from_committed(1),
                last: SessionSequence::from_committed(1),
            })
        ));
        assert!(!known_outcome_is_closed(
            EphemeralGenesisCommitOutcome::NotCommitted
        ));
    }
}
