//! Public Agent ownership, factory, admission, cancellation and observation APIs.

mod event;
mod observer;

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    pin::Pin,
    sync::{
        Arc, Condvar, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

pub use event::{
    AgentEventBaseline, AgentEventFeed, AgentEventFeedRequest, AgentEventStream,
    AgentEventStreamItem, AgentLiveBaseline,
};
pub use rust_agent_runtime_api::{AgentLifecycleOperationIntent, AgentOperationAllocationError};

use rust_agent_commands::{
    CommandDefinition, CommandDispatcher, CommandError, CommandInvocationId, CommandRequest,
    CommandResult,
};
use rust_agent_core::{
    AgentId, CompositionHash, ContentBlock, Digest, MaybeSendSync, RequestId, Usage,
};
use rust_agent_model::{
    ModelCallPlan, ModelError, ModelRegistry, ModelRegistryBinding, PreparedModelCall,
};
use rust_agent_runtime_api::{
    AgentEventFeedError, AgentEventKind, AgentLifecycleNonce, AgentPublicStatus, AppHandoffError,
    AppHandoffSeal, CancellationToken, CommandAdmissionError, CommandAdmissionGate,
    ComponentBuildError, LifecycleObserver, ModelCallScopeIdentity, ModelRequestJournalAuthority,
    ModelRequestJournalIssuer, PublicationCandidate, PublicationDirectory,
    PublicationDirectoryError, PublicationDirectoryWriteHandle, PublicationVeto,
    PublishedSessionMode, RuntimePrimitives, VolatileLifecycleOperation,
    VolatileLifecycleOperationIssuer, new_publication_directory,
};
use rust_agent_session::{SessionPersistenceError, SessionQueryHandle};
use sha2::{Digest as _, Sha256};

use crate::{
    event::EventPublisher,
    observer::{
        NotificationReservation, ObserverDispatcher, dispose_notification, publish_notification,
    },
};

pub const MAX_AGENT_INPUT_BYTES: usize = 256 * 1024;
const MAX_VOLATILE_JOURNAL_RECORDS: usize = 256;
const LIFECYCLE_NOTIFICATION_CAPACITY: usize = 256;

#[cfg(not(target_arch = "wasm32"))]
pub type AgentFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type AgentFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentInput(String);

impl AgentInput {
    pub fn text(value: impl Into<String>) -> Result<Self, AgentError> {
        let value = value.into();
        if value.len() > MAX_AGENT_INPUT_BYTES {
            return Err(AgentError::InvalidRequest("Agent input is too large"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentSendRequest {
    request_id: AgentRequestId,
    input: AgentInput,
    caller_digest: Digest,
    deadline: Option<Instant>,
}

impl AgentSendRequest {
    pub fn new(
        request_id: AgentRequestId,
        input: AgentInput,
        caller_digest: Digest,
        deadline: Option<Instant>,
    ) -> Self {
        Self {
            request_id,
            input,
            caller_digest,
            deadline,
        }
    }

    pub const fn request_id(&self) -> AgentRequestId {
        self.request_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRequest {
    request_id: AgentRequestId,
    input: AgentInput,
    caller_digest: Digest,
}

impl AgentRequest {
    pub const fn request_id(&self) -> AgentRequestId {
        self.request_id
    }

    pub const fn caller_digest(&self) -> Digest {
        self.caller_digest
    }

    pub fn input(&self) -> &AgentInput {
        &self.input
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentOutput {
    pub text: String,
    pub usage: Usage,
}

impl AgentOutput {
    pub fn from_model_response(
        response: rust_agent_model::ModelResponse,
    ) -> Result<Self, AgentError> {
        let mut text = String::new();
        for block in response.message.content {
            match block {
                ContentBlock::Text(value) => text.push_str(&value),
                ContentBlock::ImageReference { .. } | ContentBlock::Structured { .. } => {
                    return Err(AgentError::Model(ModelError::ProtocolViolation(
                        "driver-direct expected text-only output",
                    )));
                }
            }
        }
        Ok(Self {
            text,
            usage: response.usage,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentError {
    InvalidRequest(&'static str),
    Busy,
    Closed,
    RequestConflict,
    RequestExpired,
    OutcomeUnknown,
    Cancelled,
    JournalUnavailable,
    Model(ModelError),
}

impl fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(reason) => write!(formatter, "invalid Agent request: {reason}"),
            Self::Busy => formatter.write_str("Agent admission queue is full"),
            Self::Closed => formatter.write_str("Agent is closed"),
            Self::RequestConflict => formatter.write_str("Agent request identity conflicts"),
            Self::RequestExpired => formatter.write_str("Agent request identity expired"),
            Self::OutcomeUnknown => formatter.write_str("Agent request outcome is unknown"),
            Self::Cancelled => formatter.write_str("Agent request was cancelled"),
            Self::JournalUnavailable => formatter.write_str("request journal is unavailable"),
            Self::Model(error) => write!(formatter, "model call failed: {error}"),
        }
    }
}

impl std::error::Error for AgentError {}

impl From<ModelError> for AgentError {
    fn from(error: ModelError) -> Self {
        if error == ModelError::Cancelled {
            Self::Cancelled
        } else {
            Self::Model(error)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CancelCause {
    User,
    Deadline,
    Superseded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CancelOutcome {
    CancelledActive,
    AlreadyCancelling { first_cause: CancelCause },
    AlreadyTerminal,
    NotActive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentCancelError {
    ForeignRequest { request: AgentRequestId },
    StaleLifecycle { request: AgentRequestId },
    Closed,
}

pub trait Agent: MaybeSendSync {
    fn send(&self, request: AgentSendRequest) -> AgentFuture<'_, Result<AgentOutput, AgentError>>;
    fn cancel(
        &self,
        request_id: AgentRequestId,
        cause: CancelCause,
    ) -> Result<CancelOutcome, AgentCancelError>;
}

pub trait AgentDriver: MaybeSendSync {
    fn run<'a>(
        &'a self,
        context: &'a AgentContext,
        request: AgentRequest,
    ) -> AgentFuture<'a, Result<AgentOutput, AgentError>>;
}

#[derive(Clone)]
pub struct AgentDriverBinding(Arc<dyn AgentDriver>);

impl fmt::Debug for AgentDriverBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AgentDriverBinding(<opaque>)")
    }
}

impl AgentDriverBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: AgentDriver + 'static,
    {
        Self(provider)
    }

    fn run<'a>(
        &'a self,
        context: &'a AgentContext,
        request: AgentRequest,
    ) -> AgentFuture<'a, Result<AgentOutput, AgentError>> {
        self.0.run(context, request)
    }
}

pub trait AgentScopeFactory: MaybeSendSync {
    fn build_driver(
        &self,
        model: ModelRegistryBinding,
        runtime: RuntimePrimitives,
    ) -> Result<AgentDriverBinding, ComponentBuildError>;
}

struct RequestJournalFacade {
    issuer: ModelRequestJournalIssuer,
    records: Mutex<VecDeque<Digest>>,
}

struct TurnExecution {
    cancellation: CancellationToken,
    deadline: Option<Instant>,
}

pub struct AgentContext {
    journal: Arc<RequestJournalFacade>,
    execution: Mutex<Option<TurnExecution>>,
    next_model_request: AtomicU64,
}

impl fmt::Debug for AgentContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AgentContext(<journal-bound>)")
    }
}

impl AgentContext {
    fn new(issuer: ModelRequestJournalIssuer) -> Self {
        Self {
            journal: Arc::new(RequestJournalFacade {
                issuer,
                records: Mutex::new(VecDeque::new()),
            }),
            execution: Mutex::new(None),
            next_model_request: AtomicU64::new(1),
        }
    }

    fn begin_turn(&self, cancellation: CancellationToken, deadline: Option<Instant>) {
        *self
            .execution
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(TurnExecution {
            cancellation,
            deadline,
        });
    }

    fn end_turn(&self) {
        self.execution
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }

    pub fn allocate_model_request(&self) -> Result<RequestId, AgentError> {
        let value = self
            .next_model_request
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| AgentError::JournalUnavailable)?;
        RequestId::from_nonzero_u128(u128::from(value)).map_err(|_| AgentError::JournalUnavailable)
    }

    pub fn prepare_model_call(
        &self,
        plan: ModelCallPlan,
    ) -> AgentFuture<'_, Result<PreparedModelCall, AgentError>> {
        Box::pin(async move {
            let (cancellation, deadline) = {
                let execution = self
                    .execution
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let execution = execution.as_ref().ok_or(AgentError::JournalUnavailable)?;
                if execution.cancellation.is_cancelled() {
                    return Err(AgentError::Cancelled);
                }
                (execution.cancellation.clone(), execution.deadline)
            };
            let output_budget =
                NonZeroUsize::new(64 * 1024).expect("fixed output budget is nonzero");
            let projection = plan.journal_projection();
            let record_digest = plan.record_digest();
            {
                let mut records = self
                    .journal
                    .records
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if records.len() >= MAX_VOLATILE_JOURNAL_RECORDS {
                    return Err(AgentError::JournalUnavailable);
                }
                records.push_back(record_digest);
            }
            let proof = self
                .journal
                .issuer
                .seal_committed_record(
                    projection,
                    record_digest,
                    cancellation,
                    deadline,
                    output_budget,
                )
                .map_err(|_| AgentError::JournalUnavailable)?;
            plan.seal(proof).map_err(AgentError::from)
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionMode {
    None,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentOperationDraft {
    mode: SessionMode,
}

impl AgentOperationDraft {
    pub const fn sessionless() -> Self {
        Self {
            mode: SessionMode::None,
        }
    }
}

#[allow(missing_debug_implementations)]
pub struct SealedAgentOperationDraft {
    app_identity: Arc<AppIdentity>,
    mode: SessionMode,
    fingerprint: Digest,
}

#[allow(missing_debug_implementations)]
pub struct AllocatedAgentOperation {
    app_identity: Arc<AppIdentity>,
    operation: VolatileLifecycleOperation,
    mode: SessionMode,
    fingerprint: Digest,
}

impl AllocatedAgentOperation {
    pub fn into_create_request(self) -> CreateAgentRequest {
        CreateAgentRequest { allocated: self }
    }
}

#[allow(missing_debug_implementations)]
pub struct CreateAgentRequest {
    allocated: AllocatedAgentOperation,
}

#[allow(missing_debug_implementations)]
pub struct ResumeAgentRequest {
    _private: (),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentOperationSealError {
    AppClosed,
    UnsupportedMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentLifecycleError {
    UnsupportedOperation,
    OperationConflict,
    Construction(ComponentBuildError),
    Publication(PublicationDirectoryError),
    PublicationVeto(String),
    NotificationCapacityExceeded,
    AppClosed,
    JournalAuthority,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentShutdownError {
    SessionFlushFailed { reason: SessionPersistenceError },
    Publication(PublicationDirectoryError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppBuildError {
    Model(ModelError),
    Component(ComponentBuildError),
    Handoff(AppHandoffError),
    RuntimeAdapterMismatch,
    LifecycleIssuer,
}

impl From<ModelError> for AppBuildError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<ComponentBuildError> for AppBuildError {
    fn from(error: ComponentBuildError) -> Self {
        Self::Component(error)
    }
}

impl From<AppHandoffError> for AppBuildError {
    fn from(error: AppHandoffError) -> Self {
        Self::Handoff(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppShutdownError {
    Agent(AgentShutdownError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppStatus {
    Ready,
    Closing,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedOperation {
    SessionQuery,
    DurableAgent,
}

pub trait AgentFactory: MaybeSendSync {
    fn seal_operation(
        &self,
        draft: AgentOperationDraft,
    ) -> AgentFuture<'_, Result<SealedAgentOperationDraft, AgentOperationSealError>>;
    fn allocate_operation(
        &self,
        draft: SealedAgentOperationDraft,
    ) -> AgentFuture<'_, Result<AllocatedAgentOperation, AgentOperationAllocationError>>;
    fn create(
        &self,
        request: CreateAgentRequest,
    ) -> AgentFuture<'_, Result<AgentHandle, AgentLifecycleError>>;
    fn resume(
        &self,
        request: ResumeAgentRequest,
    ) -> AgentFuture<'_, Result<AgentHandle, AgentLifecycleError>>;
}

struct AppIdentity {
    generation: NonZeroU64,
}

struct AppState {
    status: AppStatus,
    agents: BTreeMap<AgentId, Weak<AgentInner>>,
    operations: BTreeMap<rust_agent_core::AgentLifecycleOperationId, Digest>,
}

struct AppInner {
    identity: Arc<AppIdentity>,
    composition: CompositionHash,
    catalog: Digest,
    handoff: AppHandoffSeal,
    runtime: RuntimePrimitives,
    model: ModelRegistry,
    scope_factory: Arc<dyn AgentScopeFactory>,
    observers: Arc<[Arc<dyn LifecycleObserver>]>,
    dispatcher: ObserverDispatcher,
    directory: PublicationDirectory,
    directory_writer: PublicationDirectoryWriteHandle,
    operation_issuer: VolatileLifecycleOperationIssuer,
    next_agent: AtomicU64,
    state: Mutex<AppState>,
}

struct MinimalAgentFactory {
    app: Weak<AppInner>,
}

#[derive(Clone)]
pub struct AppHandle {
    inner: Arc<AppInner>,
    factory: Arc<dyn AgentFactory>,
}

impl fmt::Debug for AppHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppHandle")
            .field("status", &self.status())
            .field(
                "publication_generation",
                &self.publication_snapshot().generation(),
            )
            .finish_non_exhaustive()
    }
}

static NEXT_APP_IDENTITY: AtomicU64 = AtomicU64::new(1);
static NEXT_AGENT_LIFECYCLE: AtomicU64 = AtomicU64::new(1);

impl AppHandle {
    #[doc(hidden)]
    pub fn from_generated(
        composition: CompositionHash,
        catalog: Digest,
        handoff: AppHandoffSeal,
        runtime: RuntimePrimitives,
        model: ModelRegistry,
        scope_factory: Arc<dyn AgentScopeFactory>,
        observers: Vec<Arc<dyn LifecycleObserver>>,
    ) -> Result<Self, AppBuildError> {
        let generation = NEXT_APP_IDENTITY
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .ok()
            .and_then(NonZeroU64::new)
            .ok_or(AppBuildError::LifecycleIssuer)?;
        let operation_issuer = VolatileLifecycleOperationIssuer::for_generated_app()
            .map_err(|_| AppBuildError::LifecycleIssuer)?;
        let (directory, directory_writer) = new_publication_directory();
        let observers: Arc<[Arc<dyn LifecycleObserver>]> = observers.into();
        let dispatcher =
            ObserverDispatcher::new(Arc::clone(&observers), LIFECYCLE_NOTIFICATION_CAPACITY);
        let identity = Arc::new(AppIdentity { generation });
        let inner = Arc::new(AppInner {
            identity,
            composition,
            catalog,
            handoff,
            runtime,
            model,
            scope_factory,
            observers,
            dispatcher,
            directory,
            directory_writer,
            operation_issuer,
            next_agent: AtomicU64::new(1),
            state: Mutex::new(AppState {
                status: AppStatus::Ready,
                agents: BTreeMap::new(),
                operations: BTreeMap::new(),
            }),
        });
        let factory: Arc<dyn AgentFactory> = Arc::new(MinimalAgentFactory {
            app: Arc::downgrade(&inner),
        });
        Ok(Self { inner, factory })
    }

    pub fn seal_agent_operation(
        &self,
        draft: AgentOperationDraft,
    ) -> AgentFuture<'_, Result<SealedAgentOperationDraft, AgentOperationSealError>> {
        self.factory.seal_operation(draft)
    }

    pub fn allocate_agent_operation(
        &self,
        draft: SealedAgentOperationDraft,
    ) -> AgentFuture<'_, Result<AllocatedAgentOperation, AgentOperationAllocationError>> {
        self.factory.allocate_operation(draft)
    }

    pub fn create_agent(
        &self,
        request: CreateAgentRequest,
    ) -> AgentFuture<'_, Result<AgentHandle, AgentLifecycleError>> {
        self.factory.create(request)
    }

    pub fn resume_agent(
        &self,
        request: ResumeAgentRequest,
    ) -> AgentFuture<'_, Result<AgentHandle, AgentLifecycleError>> {
        self.factory.resume(request)
    }

    pub fn publication_snapshot(&self) -> rust_agent_runtime_api::PublicationSnapshot {
        self.inner.directory.snapshot()
    }

    pub fn session_query(&self) -> Result<SessionQueryHandle, UnsupportedOperation> {
        Err(UnsupportedOperation::SessionQuery)
    }

    pub fn verify_concurrent_handoff_from(&self, old: &Self) -> Result<(), AppHandoffError> {
        self.inner
            .handoff
            .verify_concurrent_handoff_from(&old.inner.handoff)
    }

    pub fn status(&self) -> AppStatus {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .status
    }

    pub fn shutdown(&self) -> AgentFuture<'_, Result<(), AppShutdownError>> {
        Box::pin(async move {
            let agents = {
                let mut state = self
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match state.status {
                    AppStatus::Closed => return Ok(()),
                    AppStatus::Ready => state.status = AppStatus::Closing,
                    AppStatus::Closing => {}
                }
                state
                    .agents
                    .values()
                    .filter_map(Weak::upgrade)
                    .collect::<Vec<_>>()
            };
            for agent in agents {
                agent
                    .shutdown_inner()
                    .await
                    .map_err(AppShutdownError::Agent)?;
            }
            self.inner.dispatcher.shutdown();
            self.inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .status = AppStatus::Closed;
            Ok(())
        })
    }
}

impl AgentFactory for MinimalAgentFactory {
    fn seal_operation(
        &self,
        draft: AgentOperationDraft,
    ) -> AgentFuture<'_, Result<SealedAgentOperationDraft, AgentOperationSealError>> {
        Box::pin(async move {
            let app = self
                .app
                .upgrade()
                .ok_or(AgentOperationSealError::AppClosed)?;
            if app
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .status
                != AppStatus::Ready
            {
                return Err(AgentOperationSealError::AppClosed);
            }
            if draft.mode != SessionMode::None {
                return Err(AgentOperationSealError::UnsupportedMode);
            }
            let fingerprint = operation_fingerprint(app.composition, app.catalog, draft.mode);
            Ok(SealedAgentOperationDraft {
                app_identity: Arc::clone(&app.identity),
                mode: draft.mode,
                fingerprint,
            })
        })
    }

    fn allocate_operation(
        &self,
        draft: SealedAgentOperationDraft,
    ) -> AgentFuture<'_, Result<AllocatedAgentOperation, AgentOperationAllocationError>> {
        Box::pin(async move {
            let app = self
                .app
                .upgrade()
                .ok_or(AgentOperationAllocationError::AppClosed)?;
            if !Arc::ptr_eq(&draft.app_identity, &app.identity) {
                return Err(AgentOperationAllocationError::OwnerMismatch);
            }
            if app
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .status
                != AppStatus::Ready
            {
                return Err(AgentOperationAllocationError::AppClosed);
            }
            let operation = app.operation_issuer.allocate()?;
            app.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .operations
                .insert(operation.id(), draft.fingerprint);
            Ok(AllocatedAgentOperation {
                app_identity: draft.app_identity,
                operation,
                mode: draft.mode,
                fingerprint: draft.fingerprint,
            })
        })
    }

    fn create(
        &self,
        request: CreateAgentRequest,
    ) -> AgentFuture<'_, Result<AgentHandle, AgentLifecycleError>> {
        Box::pin(async move {
            let app = self.app.upgrade().ok_or(AgentLifecycleError::AppClosed)?;
            create_sessionless_agent(&app, request)
        })
    }

    fn resume(
        &self,
        _request: ResumeAgentRequest,
    ) -> AgentFuture<'_, Result<AgentHandle, AgentLifecycleError>> {
        Box::pin(async { Err(AgentLifecycleError::UnsupportedOperation) })
    }
}

struct ActiveRequest {
    id: AgentRequestId,
    cancellation: CancellationToken,
    first_cause: Option<CancelCause>,
}

struct AgentState {
    status: AgentPublicStatus,
    next_request: u64,
    next_command: u64,
    active: Option<ActiveRequest>,
    completed: VecDeque<AgentRequestId>,
    removed: bool,
}

struct AgentInner {
    id: AgentId,
    lifecycle: AgentLifecycleNonce,
    driver: AgentDriverBinding,
    context: AgentContext,
    publisher: Arc<EventPublisher>,
    commands: Mutex<Option<Arc<CommandDispatcher>>>,
    app: Weak<AppInner>,
    notification: Mutex<Option<NotificationReservation>>,
    state: Mutex<AgentState>,
    quiescence: Condvar,
}

#[derive(Clone)]
pub struct AgentHandle {
    inner: Arc<AgentInner>,
}

impl fmt::Debug for AgentHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentHandle")
            .field("id", &self.id())
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

impl AgentHandle {
    pub fn id(&self) -> AgentId {
        self.inner.id
    }

    pub fn status(&self) -> AgentPublicStatus {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .status
    }

    pub fn allocate_turn_request(&self) -> Result<AgentRequestId, AgentError> {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.status != AgentPublicStatus::Ready {
            return Err(AgentError::Closed);
        }
        let sequence = NonZeroU64::new(state.next_request).ok_or(AgentError::RequestExpired)?;
        state.next_request = state
            .next_request
            .checked_add(1)
            .ok_or(AgentError::RequestExpired)?;
        Ok(AgentRequestId::from_agent(
            self.inner.id,
            self.inner.lifecycle,
            sequence,
        ))
    }

    pub fn send(
        &self,
        request: AgentSendRequest,
    ) -> AgentFuture<'_, Result<AgentOutput, AgentError>> {
        self.inner.send(request)
    }

    pub fn cancel(
        &self,
        request_id: AgentRequestId,
        cause: CancelCause,
    ) -> Result<CancelOutcome, AgentCancelError> {
        self.inner.cancel(request_id, cause)
    }

    pub fn open_event_feed(
        &self,
        request: AgentEventFeedRequest,
    ) -> AgentFuture<'_, Result<AgentEventFeed, AgentEventFeedError>> {
        Box::pin(async move {
            let state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let baseline = AgentLiveBaseline {
                lifecycle: self.inner.lifecycle,
                status: state.status,
                active_request: state.active.as_ref().map(|active| active.id),
            };
            drop(state);
            self.inner.publisher.open(request, baseline)
        })
    }

    pub fn command_definitions(&self) -> Arc<[CommandDefinition]> {
        self.inner
            .commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .expect("published Agent has a command dispatcher")
            .definitions()
    }

    pub fn allocate_command_invocation(&self) -> Result<CommandInvocationId, CommandError> {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.status != AgentPublicStatus::Ready {
            return Err(CommandError::Closed);
        }
        let sequence = NonZeroU64::new(state.next_command).ok_or(CommandError::Closed)?;
        state.next_command = state
            .next_command
            .checked_add(1)
            .ok_or(CommandError::Closed)?;
        Ok(CommandInvocationId::from_agent(
            self.inner.id,
            self.inner.lifecycle,
            sequence,
        ))
    }

    pub fn execute_command(
        &self,
        request: CommandRequest,
    ) -> AgentFuture<'_, Result<CommandResult, CommandError>> {
        Box::pin(async move {
            let dispatcher = self
                .inner
                .commands
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .expect("published Agent has a command dispatcher")
                .clone();
            dispatcher.execute(request).await
        })
    }

    pub fn shutdown(&self) -> AgentFuture<'_, Result<(), AgentShutdownError>> {
        self.inner.shutdown_inner()
    }
}

impl Agent for AgentInner {
    fn send(&self, request: AgentSendRequest) -> AgentFuture<'_, Result<AgentOutput, AgentError>> {
        Box::pin(async move {
            if request.request_id.agent_id != self.id {
                return Err(AgentError::RequestConflict);
            }
            if request.request_id.lifecycle != self.lifecycle {
                return Err(AgentError::RequestExpired);
            }
            let cancellation = CancellationToken::new();
            {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.status != AgentPublicStatus::Ready {
                    return Err(AgentError::Closed);
                }
                if request.request_id.sequence() >= state.next_request {
                    return Err(AgentError::RequestConflict);
                }
                if state.completed.contains(&request.request_id) {
                    return Err(AgentError::RequestExpired);
                }
                if state.active.is_some() {
                    return Err(AgentError::Busy);
                }
                state.active = Some(ActiveRequest {
                    id: request.request_id,
                    cancellation: cancellation.clone(),
                    first_cause: None,
                });
            }
            self.publisher.publish(
                AgentEventKind::RequestStarted,
                request.request_id.sequence().to_string(),
            );
            self.context
                .begin_turn(cancellation.clone(), request.deadline);
            let result = self
                .driver
                .run(
                    &self.context,
                    AgentRequest {
                        request_id: request.request_id,
                        input: request.input,
                        caller_digest: request.caller_digest,
                    },
                )
                .await;
            self.context.end_turn();
            let cancelled = cancellation.is_cancelled();
            {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.active = None;
                state.completed.push_back(request.request_id);
                while state.completed.len() > 128 {
                    state.completed.pop_front();
                }
            }
            if cancelled {
                self.publisher.publish(
                    AgentEventKind::RequestCancelled,
                    request.request_id.sequence().to_string(),
                );
            } else {
                self.publisher.publish(
                    AgentEventKind::RequestCompleted,
                    request.request_id.sequence().to_string(),
                );
            }
            self.quiescence.notify_all();
            if cancelled {
                Err(AgentError::Cancelled)
            } else {
                result
            }
        })
    }

    fn cancel(
        &self,
        request_id: AgentRequestId,
        cause: CancelCause,
    ) -> Result<CancelOutcome, AgentCancelError> {
        if request_id.agent_id != self.id {
            return Err(AgentCancelError::ForeignRequest {
                request: request_id,
            });
        }
        if request_id.lifecycle != self.lifecycle {
            return Err(AgentCancelError::StaleLifecycle {
                request: request_id,
            });
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.status == AgentPublicStatus::Closed {
            return Err(AgentCancelError::Closed);
        }
        if let Some(active) = state.active.as_mut()
            && active.id == request_id
        {
            if let Some(first_cause) = &active.first_cause {
                return Ok(CancelOutcome::AlreadyCancelling {
                    first_cause: first_cause.clone(),
                });
            }
            active.first_cause = Some(cause);
            active.cancellation.cancel();
            return Ok(CancelOutcome::CancelledActive);
        }
        if state.completed.contains(&request_id) {
            Ok(CancelOutcome::AlreadyTerminal)
        } else {
            Ok(CancelOutcome::NotActive)
        }
    }
}

impl CommandAdmissionGate for AgentInner {
    fn admit_command(
        &self,
        agent_id: AgentId,
        lifecycle: AgentLifecycleNonce,
    ) -> Result<(), CommandAdmissionError> {
        if agent_id != self.id || lifecycle != self.lifecycle {
            return Err(CommandAdmissionError::StaleLifecycle);
        }
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.status != AgentPublicStatus::Ready {
            return Err(CommandAdmissionError::Closed);
        }
        if state.active.is_some() {
            return Err(CommandAdmissionError::Busy);
        }
        Ok(())
    }
}

impl AgentInner {
    fn shutdown_inner(&self) -> AgentFuture<'_, Result<(), AgentShutdownError>> {
        Box::pin(async move {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.status == AgentPublicStatus::Closed {
                return Ok(());
            }
            state.status = AgentPublicStatus::Closing;
            if let Some(active) = state.active.as_mut() {
                active.cancellation.cancel();
            }
            while state.active.is_some() {
                state = self
                    .quiescence
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            if !state.removed {
                state.removed = true;
                drop(state);
                if let Some(app) = self.app.upgrade() {
                    let _ = app.directory_writer.mark_closing(self.id, self.lifecycle);
                    let (event, snapshot) = app
                        .directory_writer
                        .remove(self.id, self.lifecycle)
                        .map_err(AgentShutdownError::Publication)?;
                    if let Some(mut reservation) = self
                        .notification
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take()
                    {
                        dispose_notification(&mut reservation, event, snapshot);
                    }
                    app.state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .agents
                        .remove(&self.id);
                }
                state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            state.status = AgentPublicStatus::Closed;
            drop(state);
            self.publisher.close(AgentPublicStatus::Closed);
            Ok(())
        })
    }
}

fn create_sessionless_agent(
    app: &Arc<AppInner>,
    request: CreateAgentRequest,
) -> Result<AgentHandle, AgentLifecycleError> {
    let allocated = request.allocated;
    if !Arc::ptr_eq(&allocated.app_identity, &app.identity)
        || !app.operation_issuer.owns(&allocated.operation)
        || allocated.mode != SessionMode::None
    {
        return Err(AgentLifecycleError::OperationConflict);
    }
    {
        let state = app
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.status != AppStatus::Ready {
            return Err(AgentLifecycleError::AppClosed);
        }
        if state.operations.get(&allocated.operation.id()) != Some(&allocated.fingerprint) {
            return Err(AgentLifecycleError::OperationConflict);
        }
    }
    let agent_sequence = app
        .next_agent
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .map_err(|_| AgentLifecycleError::OperationConflict)?;
    let agent_value =
        (u128::from(app.identity.generation.get()) << 64) | u128::from(agent_sequence);
    let agent_id = AgentId::from_nonzero_u128(agent_value)
        .map_err(|_| AgentLifecycleError::OperationConflict)?;
    let lifecycle_value = NEXT_AGENT_LIFECYCLE
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .map_err(|_| AgentLifecycleError::OperationConflict)?;
    let lifecycle = AgentLifecycleNonce::from_nonzero(
        NonZeroU64::new(lifecycle_value).ok_or(AgentLifecycleError::OperationConflict)?,
    );
    let scope = ModelCallScopeIdentity::for_generated_agent(
        agent_id,
        lifecycle,
        None,
        app.composition,
        app.catalog,
    );
    let (issuer, verifier) = ModelRequestJournalAuthority::issue_for_generated_scope(scope)
        .map_err(|_| AgentLifecycleError::JournalAuthority)?;
    let model = app.model.bind_generated_scope(verifier);
    let driver = app
        .scope_factory
        .build_driver(model, app.runtime.clone())
        .map_err(AgentLifecycleError::Construction)?;
    let publisher = EventPublisher::new(agent_id, lifecycle);
    let reservation = app
        .dispatcher
        .reserve_pair()
        .ok_or(AgentLifecycleError::NotificationCapacityExceeded)?;
    let agent = Arc::new(AgentInner {
        id: agent_id,
        lifecycle,
        driver,
        context: AgentContext::new(issuer),
        publisher,
        commands: Mutex::new(None),
        app: Arc::downgrade(app),
        notification: Mutex::new(Some(reservation)),
        state: Mutex::new(AgentState {
            status: AgentPublicStatus::Closing,
            next_request: 1,
            next_command: 1,
            active: None,
            completed: VecDeque::new(),
            removed: false,
        }),
        quiescence: Condvar::new(),
    });
    let gate: Arc<dyn CommandAdmissionGate> = agent.clone();
    let dispatcher = Arc::new(CommandDispatcher::empty_guarded(
        agent_id,
        lifecycle,
        Arc::downgrade(&gate),
    ));
    *agent
        .commands
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(dispatcher);
    let candidate = PublicationCandidate::for_generated_agent(
        agent_id,
        lifecycle,
        None,
        PublishedSessionMode::Sessionless,
    );
    let previous = app.directory.snapshot();
    let view = app.directory_writer.transaction_view(&previous, &candidate);
    for observer in app.observers.iter() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            observer.before_publish(&candidate, &view)
        }));
        match result {
            Ok(Ok(())) => {}
            Ok(Err(PublicationVeto { reason })) => {
                return Err(AgentLifecycleError::PublicationVeto(reason));
            }
            Err(_) => {
                return Err(AgentLifecycleError::PublicationVeto(
                    "observer panic".into(),
                ));
            }
        }
    }
    let (event, snapshot) = app
        .directory_writer
        .publish(candidate)
        .map_err(AgentLifecycleError::Publication)?;
    if let Some(reservation) = agent
        .notification
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
    {
        publish_notification(reservation, event, snapshot);
    }
    if let Err(error) = app.directory_writer.mark_ready(agent_id, lifecycle) {
        if let Ok((event, snapshot)) = app.directory_writer.remove(agent_id, lifecycle)
            && let Some(reservation) = agent
                .notification
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
        {
            dispose_notification(reservation, event, snapshot);
        }
        return Err(AgentLifecycleError::Publication(error));
    }
    agent
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .status = AgentPublicStatus::Ready;
    agent
        .publisher
        .publish(AgentEventKind::StatusChanged, String::from("ready"));
    app.state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .agents
        .insert(agent_id, Arc::downgrade(&agent));
    Ok(AgentHandle { inner: agent })
}

fn operation_fingerprint(
    composition: CompositionHash,
    catalog: Digest,
    mode: SessionMode,
) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"rust-agent-volatile-operation-v1\0");
    hasher.update(composition.digest().as_bytes());
    hasher.update(catalog.as_bytes());
    hasher.update([match mode {
        SessionMode::None => 0,
    }]);
    Digest::from_bytes(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Barrier,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
        thread,
        time::Duration,
    };

    use futures_core::Stream;
    use rust_agent_core::{Message, MessageRole};
    use rust_agent_model::{
        LanguageModel, ModelCallContext, ModelCallDraft, ModelEvent, ModelFuture, ModelId,
        ModelParams, ModelProviderBinding, ModelRequest, ModelRequestPurpose, ModelResponse,
        ModelRouteSelection, ModelStream, ProviderKey,
    };
    use rust_agent_runtime_api::{
        AppHandoffMode, DisposalEvent, LifecycleNotificationContext, LifecycleObserverFuture,
        PublicationEvent, PublicationSnapshot, PublicationState, PublicationTransactionView,
        RuntimeAdapterIdentity,
    };

    use super::*;

    struct ThreadWake(thread::Thread);

    impl Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }

        fn wake_by_ref(self: &Arc<Self>) {
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

    struct TestStream(VecDeque<Result<ModelEvent, ModelError>>);

    impl Stream for TestStream {
        type Item = Result<ModelEvent, ModelError>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.0.pop_front())
        }
    }

    struct EchoModel {
        calls: Arc<AtomicUsize>,
    }

    impl LanguageModel for EchoModel {
        fn provider_key(&self) -> ProviderKey {
            ProviderKey::new("echo").unwrap()
        }

        fn model_id(&self) -> ModelId {
            ModelId::new("echo-v1").unwrap()
        }

        fn stream(
            &self,
            _context: ModelCallContext,
            request: ModelRequest,
        ) -> ModelFuture<'_, Result<ModelStream, ModelError>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                let ContentBlock::Text(input) = &request.messages[0].content[0] else {
                    return Err(ModelError::InvalidRequest("text required"));
                };
                Ok(Box::pin(TestStream(VecDeque::from([
                    Ok(ModelEvent::Delta(format!("echo:{input}"))),
                    Ok(ModelEvent::Completed(Usage {
                        input_tokens: 1,
                        output_tokens: 1,
                    })),
                ]))) as ModelStream)
            })
        }
    }

    struct DirectTestDriver {
        model: ModelRegistryBinding,
    }

    impl AgentDriver for DirectTestDriver {
        fn run<'a>(
            &'a self,
            context: &'a AgentContext,
            request: AgentRequest,
        ) -> AgentFuture<'a, Result<AgentOutput, AgentError>> {
            Box::pin(async move {
                let plan = self.model.plan_call(ModelCallDraft {
                    request_id: context.allocate_model_request()?,
                    purpose: ModelRequestPurpose::AgentTurn,
                    route: ModelRouteSelection::ConfiguredDefault,
                    request: ModelRequest {
                        messages: vec![Message {
                            role: MessageRole::User,
                            content: vec![ContentBlock::Text(request.input().as_str().to_owned())],
                        }],
                        system: None,
                        tools: Vec::new(),
                        params: ModelParams::default(),
                    },
                    linked_from: None,
                })?;
                let prepared = context.prepare_model_call(plan).await?;
                let response: ModelResponse = self.model.complete_prepared(prepared).await?;
                AgentOutput::from_model_response(response)
            })
        }
    }

    #[derive(Debug)]
    struct TestScopeFactory;

    impl AgentScopeFactory for TestScopeFactory {
        fn build_driver(
            &self,
            model: ModelRegistryBinding,
            _runtime: RuntimePrimitives,
        ) -> Result<AgentDriverBinding, ComponentBuildError> {
            Ok(AgentDriverBinding::from_provider(Arc::new(
                DirectTestDriver { model },
            )))
        }
    }

    fn app(calls: Arc<AtomicUsize>, observers: Vec<Arc<dyn LifecycleObserver>>) -> AppHandle {
        app_with_model(
            ModelProviderBinding::from_provider(Arc::new(EchoModel { calls })),
            observers,
        )
    }

    fn app_with_model(
        model: ModelProviderBinding,
        observers: Vec<Arc<dyn LifecycleObserver>>,
    ) -> AppHandle {
        let model = ModelRegistry::from_compiled(vec![model], None).unwrap();
        let handoff = AppHandoffSeal::new(
            AppHandoffMode::Concurrent,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "1111111111111111111111111111111111111111111111111111111111111111",
            Vec::new(),
        )
        .unwrap();
        AppHandle::from_generated(
            CompositionHash::from_digest(Digest::from_bytes([0; 32])),
            Digest::from_bytes([1; 32]),
            handoff,
            RuntimePrimitives::new(RuntimeAdapterIdentity::checked("runtime-test").unwrap()),
            model,
            Arc::new(TestScopeFactory),
            observers,
        )
        .unwrap()
    }

    #[test]
    fn request_language_model_response_and_publication_lifecycle() {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = app(Arc::clone(&calls), Vec::new());
        assert!(app.publication_snapshot().entries().is_empty());
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
        let snapshot = app.publication_snapshot();
        assert_eq!(snapshot.entries().len(), 1);
        assert_eq!(snapshot.entries()[0].state(), PublicationState::Ready);

        let request_id = agent.allocate_turn_request().unwrap();
        let result = run(agent.send(AgentSendRequest::new(
            request_id,
            AgentInput::text("hello").unwrap(),
            Digest::from_bytes([9; 32]),
            None,
        )))
        .unwrap();
        assert_eq!(result.text, "echo:hello");
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        run(agent.shutdown()).unwrap();
        assert!(app.publication_snapshot().entries().is_empty());
        run(app.shutdown()).unwrap();
    }

    struct VetoObserver;

    impl LifecycleObserver for VetoObserver {
        fn before_publish(
            &self,
            _event: &PublicationCandidate,
            view: &PublicationTransactionView<'_>,
        ) -> Result<(), PublicationVeto> {
            assert!(view.previous().entries().is_empty());
            Err(PublicationVeto {
                reason: "test veto".into(),
            })
        }

        fn published<'a>(
            &'a self,
            _context: LifecycleNotificationContext,
            _event: &'a PublicationEvent,
            _snapshot: &'a PublicationSnapshot,
        ) -> LifecycleObserverFuture<'a> {
            Box::pin(async { Ok(()) })
        }

        fn disposed<'a>(
            &'a self,
            _context: LifecycleNotificationContext,
            _event: &'a DisposalEvent,
            _snapshot: &'a PublicationSnapshot,
        ) -> LifecycleObserverFuture<'a> {
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn observer_veto_rolls_back_without_publication_or_model_side_effect() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observer: Arc<dyn LifecycleObserver> = Arc::new(VetoObserver);
        let app = app(Arc::clone(&calls), vec![observer]);
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        assert!(matches!(
            run(app.create_agent(allocated.into_create_request())),
            Err(AgentLifecycleError::PublicationVeto(reason)) if reason == "test veto"
        ));
        let snapshot = app.publication_snapshot();
        assert_eq!(snapshot.generation(), 0);
        assert!(snapshot.entries().is_empty());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        run(app.shutdown()).unwrap();
    }

    struct SlowModel {
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
    }

    impl LanguageModel for SlowModel {
        fn provider_key(&self) -> ProviderKey {
            ProviderKey::new("slow").unwrap()
        }

        fn model_id(&self) -> ModelId {
            ModelId::new("slow-v1").unwrap()
        }

        fn stream(
            &self,
            context: ModelCallContext,
            _request: ModelRequest,
        ) -> ModelFuture<'_, Result<ModelStream, ModelError>> {
            let entered = Arc::clone(&self.entered);
            let release = Arc::clone(&self.release);
            Box::pin(async move {
                entered.wait();
                while !context.cancellation().is_cancelled() {
                    thread::sleep(Duration::from_millis(1));
                }
                release.wait();
                Err(ModelError::Cancelled)
            })
        }
    }

    #[test]
    fn targeted_cancel_is_exact_idempotent_and_preserves_first_cause() {
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let app = app_with_model(
            ModelProviderBinding::from_provider(Arc::new(SlowModel {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            })),
            Vec::new(),
        );
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
        let request_id = agent.allocate_turn_request().unwrap();
        let foreign = AgentRequestId::from_agent(
            AgentId::from_nonzero_u128(999).unwrap(),
            request_id.lifecycle(),
            NonZeroU64::new(request_id.sequence()).unwrap(),
        );
        assert!(matches!(
            agent.cancel(foreign, CancelCause::User),
            Err(AgentCancelError::ForeignRequest { .. })
        ));
        let stale = AgentRequestId::from_agent(
            request_id.agent_id(),
            AgentLifecycleNonce::from_nonzero(
                NonZeroU64::new(request_id.lifecycle().get() + 1).unwrap(),
            ),
            NonZeroU64::new(request_id.sequence()).unwrap(),
        );
        assert!(matches!(
            agent.cancel(stale, CancelCause::User),
            Err(AgentCancelError::StaleLifecycle { .. })
        ));

        let worker_agent = agent.clone();
        let worker = thread::spawn(move || {
            run(worker_agent.send(AgentSendRequest::new(
                request_id,
                AgentInput::text("wait").unwrap(),
                Digest::from_bytes([4; 32]),
                None,
            )))
        });
        entered.wait();
        assert_eq!(
            agent.cancel(request_id, CancelCause::User),
            Ok(CancelOutcome::CancelledActive)
        );
        assert_eq!(
            agent.cancel(request_id, CancelCause::Deadline),
            Ok(CancelOutcome::AlreadyCancelling {
                first_cause: CancelCause::User
            })
        );
        release.wait();
        assert_eq!(worker.join().unwrap(), Err(AgentError::Cancelled));
        assert_eq!(
            agent.cancel(request_id, CancelCause::Superseded),
            Ok(CancelOutcome::AlreadyTerminal)
        );
        run(agent.shutdown()).unwrap();
        run(app.shutdown()).unwrap();
    }
}
