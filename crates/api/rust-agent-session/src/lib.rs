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
    LifecycleOperationReservationDraft,
};

#[cfg(not(target_arch = "wasm32"))]
pub type SessionFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type SessionFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionPersistenceError {
    Closed,
    StoreUnavailable,
    SessionNotFound { session: SessionId },
    WriterConflict { session: SessionId },
    StaleWriter,
    CorruptStore { diagnostic: String },
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
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
    },
    CommitStatusUnknown,
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
    fn log(&self) -> Arc<dyn SessionLog>;
    fn release_writer_lease(
        &self,
    ) -> SessionFuture<'_, Result<WriterLeaseReleaseOutcome, SessionPersistenceError>>;
    fn resolve_writer_lease_status(
        &self,
    ) -> SessionFuture<'_, Result<WriterLeaseStatus, SessionPersistenceError>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewSessionReservation {
    reservation: LifecycleOperationReservation,
}

impl NewSessionReservation {
    #[doc(hidden)]
    pub fn from_lifecycle(reservation: LifecycleOperationReservation) -> Self {
        Self { reservation }
    }

    pub const fn lifecycle(&self) -> &LifecycleOperationReservation {
        &self.reservation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExistingSessionReservation {
    pub session_id: SessionId,
    pub composition: CompositionHash,
    pub catalog: Digest,
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
    ) -> SessionFuture<'_, Result<Arc<dyn PreparedSessionJournal>, SessionPersistenceError>>;

    fn prepare_existing(
        &self,
        reservation: ExistingSessionReservation,
    ) -> SessionFuture<'_, Result<Arc<dyn PreparedSessionJournal>, SessionPersistenceError>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionIndexCursor {
    backend: Digest,
    captured_high_water: u64,
    position: u64,
}

impl SessionIndexCursor {
    #[doc(hidden)]
    pub const fn from_store(backend: Digest, captured_high_water: u64, position: u64) -> Self {
        Self {
            backend,
            captured_high_water,
            position,
        }
    }

    pub const fn backend(&self) -> Digest {
        self.backend
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSessionSummary {
    pub session_id: SessionId,
    pub compatibility: SessionCompatibility,
    pub high_water: SessionSequence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSessionListPage {
    pub sessions: Vec<StoredSessionSummary>,
    pub next: Option<SessionIndexCursor>,
    pub captured_index_high_water: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredEventPageRequest {
    pub after: Option<SessionSequence>,
    pub max_events: NonZeroU32,
    pub max_bytes: NonZeroUsize,
    pub captured_high_water: Option<SessionSequence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredEventPage {
    pub events: Vec<StoredEventEnvelope>,
    pub next: Option<SessionSequence>,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lightweight_api_types_do_not_need_a_backend() {
        let sequence = SessionSequence::from_committed(7);
        let request = StoredEventPageRequest {
            after: Some(sequence),
            max_events: NonZeroU32::new(16).unwrap(),
            max_bytes: NonZeroUsize::new(4096).unwrap(),
            captured_high_water: Some(sequence),
        };
        assert_eq!(request.after.unwrap().value(), 7);
        assert_eq!(request.max_events.get(), 16);
    }
}
