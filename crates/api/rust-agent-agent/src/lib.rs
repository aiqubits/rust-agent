//! Public Agent ownership, factory, admission, cancellation and observation APIs.

mod event;
mod observer;

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    future::{Future, poll_fn},
    num::{NonZeroU64, NonZeroUsize},
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    task::{Poll, Waker},
    time::Duration,
};

pub use event::{
    AgentEventBaseline, AgentEventFeed, AgentEventFeedRequest, AgentEventStream,
    AgentEventStreamItem, AgentLiveBaseline, MAX_AGENT_EVENT_PAYLOAD_BYTES,
};
pub use observer::LifecycleObserverDiagnostics;
pub use rust_agent_model::{ModelRouteSelection, ProviderKey};
pub use rust_agent_runtime_api::{
    AgentLifecycleOperationIntent, AgentOperationAllocationError, AgentRequestId, RuntimeInstant,
};

use rust_agent_commands::{
    CommandDefinition, CommandDispatcher, CommandError, CommandInvocationId, CommandRequest,
    CommandResult,
};
use rust_agent_core::{
    AgentId, CanonicalId, CompositionHash, ContentBlock, Digest, MaybeSendSync, RequestId, Usage,
};
use rust_agent_model::{
    ModelCallPlan, ModelError, ModelRegistry, ModelRegistryBinding, ModelResponse,
    PreparedModelCall, StreamCollectionError, try_collect_stream_with,
};
use rust_agent_runtime_api::{
    AgentEventFeedError, AgentLifecycleNonce, AgentPublicStatus, AppHandoffError, AppHandoffSeal,
    BindingAssemblyOwner, CancellationToken, CommandAdmissionError, CommandAdmissionGate,
    ComponentBuildError, GeneratedToolConsumerBinding, LifecycleObserver, LifecycleObserverBinding,
    ModelCallScopeIdentity, ModelRequestJournalIssuer, PublicationCandidate, PublicationDirectory,
    PublicationDirectoryError, PublicationDirectoryWriteHandle, PublicationVeto,
    PublishedSessionMode, RuntimePrimitives, ToolCallJournalIssuer, ToolCallJournalProjection,
    ToolCallJournalProof, ToolCallScopeIdentity, VolatileLifecycleOperation,
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
pub const MAX_MODEL_ORIGIN_TOOL_OUTPUT_BYTES: usize = 256 * 1024;
const MAX_VOLATILE_JOURNAL_RECORDS: usize = 256;
const MAX_ADMISSION_QUEUE: usize = 32;
const MAX_REQUEST_WAITERS: usize = 32;
const MAX_COMPLETED_REQUESTS: usize = 128;
const MAX_ALLOCATED_UNSUBMITTED_REQUESTS: usize = MAX_COMPLETED_REQUESTS + MAX_ADMISSION_QUEUE + 1;
const MAX_PENDING_LIFECYCLE_OPERATIONS: usize = 256;
const PENDING_LIFECYCLE_OPERATION_TTL: Duration = Duration::from_mins(1);
pub const MAX_LIVE_AGENTS_HARD: usize = 128;
pub const MAX_LIFECYCLE_NOTIFICATION_PENDING_HARD: usize = 4_096;
pub const MAX_LIFECYCLE_OBSERVER_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_APP_SHUTDOWN_TIMEOUT: Duration = Duration::from_mins(5);
pub const MAX_EVENT_FEED_SUBSCRIBERS_HARD: u32 = 16;
pub const MAX_EVENT_FEED_BUFFERED_EVENTS_HARD: u32 = 1_024;
pub const MAX_EVENT_FEED_BUFFERED_BYTES_HARD: usize = 1024 * 1024;
pub const MAX_EVENT_FEED_IDLE_TIMEOUT: Duration = Duration::from_mins(5);

type ShutdownWaiterSlot = Mutex<Option<Waker>>;
type ShutdownWaiter = Weak<ShutdownWaiterSlot>;

fn register_shutdown_waiter(
    waiters: &mut Vec<ShutdownWaiter>,
    slot: &Arc<ShutdownWaiterSlot>,
    waker: &Waker,
) {
    *slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(waker.clone());
    waiters.retain(|waiter| waiter.strong_count() != 0);
    let slot = Arc::downgrade(slot);
    if !waiters.iter().any(|waiter| waiter.ptr_eq(&slot)) {
        waiters.push(slot);
    }
}

fn unregister_shutdown_waiter(waiters: &mut Vec<ShutdownWaiter>, slot: &Arc<ShutdownWaiterSlot>) {
    let slot = Arc::downgrade(slot);
    waiters.retain(|waiter| waiter.strong_count() != 0 && !waiter.ptr_eq(&slot));
}

fn take_shutdown_waiters(waiters: &mut Vec<ShutdownWaiter>) -> Vec<Waker> {
    std::mem::take(waiters)
        .into_iter()
        .filter_map(|waiter| waiter.upgrade())
        .filter_map(|slot| {
            slot.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
        })
        .collect()
}

trait ShutdownWaiterState {
    fn shutdown_waiters(&mut self) -> &mut Vec<ShutdownWaiter>;
}

struct ShutdownWaiterRegistration<'a, State: ShutdownWaiterState> {
    state: &'a Mutex<State>,
    slot: Arc<ShutdownWaiterSlot>,
    registered: bool,
}

impl<'a, State: ShutdownWaiterState> ShutdownWaiterRegistration<'a, State> {
    fn new(state: &'a Mutex<State>) -> Self {
        Self {
            state,
            slot: Arc::new(Mutex::new(None)),
            registered: false,
        }
    }

    fn register(&mut self, waiters: &mut Vec<ShutdownWaiter>, waker: &Waker) {
        register_shutdown_waiter(waiters, &self.slot, waker);
        self.registered = true;
    }

    fn unregister(&mut self, waiters: &mut Vec<ShutdownWaiter>) {
        unregister_shutdown_waiter(waiters, &self.slot);
        self.registered = false;
    }
}

impl<State: ShutdownWaiterState> Drop for ShutdownWaiterRegistration<'_, State> {
    fn drop(&mut self) {
        if !self.registered {
            return;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        unregister_shutdown_waiter(state.shutdown_waiters(), &self.slot);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Phase2RuntimeConfigError {
    Zero(&'static str),
    AboveHardCeiling {
        field: &'static str,
        requested: u128,
        maximum: u128,
    },
    NotificationCapacityTooSmall {
        requested: usize,
        minimum: usize,
    },
    ObserverTimeoutExceedsShutdown,
}

impl fmt::Display for Phase2RuntimeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero(field) => write!(formatter, "runtime field `{field}` must be non-zero"),
            Self::AboveHardCeiling {
                field,
                requested,
                maximum,
            } => write!(
                formatter,
                "runtime field `{field}` value {requested} exceeds hard ceiling {maximum}"
            ),
            Self::NotificationCapacityTooSmall { requested, minimum } => write!(
                formatter,
                "lifecycle notification capacity {requested} is smaller than required {minimum}"
            ),
            Self::ObserverTimeoutExceedsShutdown => {
                formatter.write_str("lifecycle observer timeout exceeds App shutdown timeout")
            }
        }
    }
}

impl std::error::Error for Phase2RuntimeConfigError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentResourceBudget {
    max_event_feed_subscribers: u32,
    max_event_feed_buffered_events_total: u32,
    max_event_feed_buffered_bytes_total: usize,
    event_feed_idle_timeout: Duration,
}

impl AgentResourceBudget {
    pub fn checked(
        max_event_feed_subscribers: u32,
        max_event_feed_buffered_events_total: u32,
        max_event_feed_buffered_bytes_total: usize,
        event_feed_idle_timeout: Duration,
    ) -> Result<Self, Phase2RuntimeConfigError> {
        check_nonzero_ceiling(
            "max_event_feed_subscribers",
            u128::from(max_event_feed_subscribers),
            u128::from(MAX_EVENT_FEED_SUBSCRIBERS_HARD),
        )?;
        check_nonzero_ceiling(
            "max_event_feed_buffered_events_total",
            u128::from(max_event_feed_buffered_events_total),
            u128::from(MAX_EVENT_FEED_BUFFERED_EVENTS_HARD),
        )?;
        check_nonzero_ceiling(
            "max_event_feed_buffered_bytes_total",
            max_event_feed_buffered_bytes_total as u128,
            MAX_EVENT_FEED_BUFFERED_BYTES_HARD as u128,
        )?;
        check_duration_ceiling(
            "event_feed_idle_timeout_ms",
            event_feed_idle_timeout,
            MAX_EVENT_FEED_IDLE_TIMEOUT,
        )?;
        Ok(Self {
            max_event_feed_subscribers,
            max_event_feed_buffered_events_total,
            max_event_feed_buffered_bytes_total,
            event_feed_idle_timeout,
        })
    }

    pub const fn max_event_feed_subscribers(&self) -> u32 {
        self.max_event_feed_subscribers
    }

    pub const fn max_event_feed_buffered_events_total(&self) -> u32 {
        self.max_event_feed_buffered_events_total
    }

    pub const fn max_event_feed_buffered_bytes_total(&self) -> usize {
        self.max_event_feed_buffered_bytes_total
    }

    pub const fn event_feed_idle_timeout(&self) -> Duration {
        self.event_feed_idle_timeout
    }
}

impl Default for AgentResourceBudget {
    fn default() -> Self {
        Self::checked(
            MAX_EVENT_FEED_SUBSCRIBERS_HARD,
            MAX_EVENT_FEED_BUFFERED_EVENTS_HARD,
            MAX_EVENT_FEED_BUFFERED_BYTES_HARD,
            Duration::from_secs(30),
        )
        .expect("compiled Phase 2 Agent resource defaults are valid")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Phase2RuntimeConfig {
    shutdown_timeout: Duration,
    max_live_agents: usize,
    lifecycle_observer_timeout: Duration,
    lifecycle_notification_max_pending: usize,
    agent_resource_budget: AgentResourceBudget,
}

impl Phase2RuntimeConfig {
    pub fn checked(
        shutdown_timeout: Duration,
        max_live_agents: usize,
        lifecycle_observer_timeout: Duration,
        lifecycle_notification_max_pending: usize,
        agent_resource_budget: AgentResourceBudget,
    ) -> Result<Self, Phase2RuntimeConfigError> {
        check_duration_ceiling(
            "shutdown_timeout_ms",
            shutdown_timeout,
            MAX_APP_SHUTDOWN_TIMEOUT,
        )?;
        check_nonzero_ceiling(
            "max_live_agents",
            max_live_agents as u128,
            MAX_LIVE_AGENTS_HARD as u128,
        )?;
        check_duration_ceiling(
            "lifecycle_observer_timeout_ms",
            lifecycle_observer_timeout,
            MAX_LIFECYCLE_OBSERVER_TIMEOUT,
        )?;
        check_nonzero_ceiling(
            "lifecycle_notification_max_pending",
            lifecycle_notification_max_pending as u128,
            MAX_LIFECYCLE_NOTIFICATION_PENDING_HARD as u128,
        )?;
        let minimum =
            max_live_agents
                .checked_mul(2)
                .ok_or(Phase2RuntimeConfigError::AboveHardCeiling {
                    field: "max_live_agents",
                    requested: max_live_agents as u128,
                    maximum: MAX_LIVE_AGENTS_HARD as u128,
                })?;
        if lifecycle_notification_max_pending < minimum {
            return Err(Phase2RuntimeConfigError::NotificationCapacityTooSmall {
                requested: lifecycle_notification_max_pending,
                minimum,
            });
        }
        if lifecycle_observer_timeout > shutdown_timeout {
            return Err(Phase2RuntimeConfigError::ObserverTimeoutExceedsShutdown);
        }
        Ok(Self {
            shutdown_timeout,
            max_live_agents,
            lifecycle_observer_timeout,
            lifecycle_notification_max_pending,
            agent_resource_budget,
        })
    }

    pub const fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }

    pub const fn max_live_agents(&self) -> usize {
        self.max_live_agents
    }

    pub const fn lifecycle_observer_timeout(&self) -> Duration {
        self.lifecycle_observer_timeout
    }

    pub const fn lifecycle_notification_max_pending(&self) -> usize {
        self.lifecycle_notification_max_pending
    }

    pub const fn agent_resource_budget(&self) -> &AgentResourceBudget {
        &self.agent_resource_budget
    }
}

impl Default for Phase2RuntimeConfig {
    fn default() -> Self {
        Self::checked(
            Duration::from_secs(30),
            32,
            Duration::from_secs(1),
            128,
            AgentResourceBudget::default(),
        )
        .expect("compiled Phase 2 runtime defaults are valid")
    }
}

fn check_nonzero_ceiling(
    field: &'static str,
    requested: u128,
    maximum: u128,
) -> Result<(), Phase2RuntimeConfigError> {
    if requested == 0 {
        return Err(Phase2RuntimeConfigError::Zero(field));
    }
    if requested > maximum {
        return Err(Phase2RuntimeConfigError::AboveHardCeiling {
            field,
            requested,
            maximum,
        });
    }
    Ok(())
}

fn check_duration_ceiling(
    field: &'static str,
    requested: Duration,
    maximum: Duration,
) -> Result<(), Phase2RuntimeConfigError> {
    if requested.is_zero() {
        return Err(Phase2RuntimeConfigError::Zero(field));
    }
    if requested > maximum {
        return Err(Phase2RuntimeConfigError::AboveHardCeiling {
            field,
            requested: duration_millis_ceil(requested),
            maximum: maximum.as_millis(),
        });
    }
    Ok(())
}

fn duration_millis_ceil(value: Duration) -> u128 {
    value.as_millis() + u128::from(!value.subsec_nanos().is_multiple_of(1_000_000))
}

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

#[derive(Clone, Debug)]
pub struct AgentSendRequest {
    request_id: AgentRequestId,
    input: AgentInput,
    caller_digest: Digest,
    route: ModelRouteSelection,
    deadline: Option<RuntimeInstant>,
    cancellation: CancellationToken,
}

impl AgentSendRequest {
    pub fn new(
        request_id: AgentRequestId,
        input: AgentInput,
        caller_digest: Digest,
        deadline: Option<RuntimeInstant>,
    ) -> Self {
        Self {
            request_id,
            input,
            caller_digest,
            route: ModelRouteSelection::ConfiguredDefault,
            deadline,
            cancellation: CancellationToken::new(),
        }
    }

    pub const fn request_id(&self) -> AgentRequestId {
        self.request_id
    }

    #[must_use]
    pub fn with_model_route(mut self, route: ModelRouteSelection) -> Self {
        self.route = route;
        self
    }

    #[must_use]
    pub fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = cancellation;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRequest {
    request_id: AgentRequestId,
    input: AgentInput,
    caller_digest: Digest,
    route: ModelRouteSelection,
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

    pub fn model_route(&self) -> &ModelRouteSelection {
        &self.route
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
    DeadlineExceeded,
    OutcomeUnknown,
    Cancelled,
    JournalUnavailable,
    EventPublicationFailed,
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
            Self::DeadlineExceeded => formatter.write_str("Agent request deadline exceeded"),
            Self::OutcomeUnknown => formatter.write_str("Agent request outcome is unknown"),
            Self::Cancelled => formatter.write_str("Agent request was cancelled"),
            Self::JournalUnavailable => formatter.write_str("request journal is unavailable"),
            Self::EventPublicationFailed => formatter.write_str("Agent event publication failed"),
            Self::Model(error) => write!(formatter, "model call failed: {error}"),
        }
    }
}

impl std::error::Error for AgentError {}

impl From<ModelError> for AgentError {
    fn from(error: ModelError) -> Self {
        match error {
            ModelError::Cancelled => Self::Cancelled,
            ModelError::DeadlineExceeded => Self::DeadlineExceeded,
            other => Self::Model(other),
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

impl fmt::Display for AgentCancelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForeignRequest { .. } => {
                formatter.write_str("request belongs to a different Agent")
            }
            Self::StaleLifecycle { .. } => formatter.write_str("request lifecycle is stale"),
            Self::Closed => formatter.write_str("Agent is closed"),
        }
    }
}

impl std::error::Error for AgentCancelError {}

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
pub struct AgentDriverBinding {
    component: Option<Arc<str>>,
    driver: Arc<dyn AgentDriver>,
}

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
        Self {
            component: None,
            driver: provider,
        }
    }

    #[doc(hidden)]
    pub fn from_generated_component<T>(
        component: impl Into<String>,
        provider: Arc<T>,
    ) -> Result<Self, ComponentBuildError>
    where
        T: AgentDriver + 'static,
    {
        let component = component.into();
        CanonicalId::new(component.clone()).map_err(|_| {
            ComponentBuildError::InvalidConfig("invalid driver component identity".into())
        })?;
        Ok(Self {
            component: Some(Arc::from(component)),
            driver: provider,
        })
    }

    #[doc(hidden)]
    pub fn generated_component_identity(&self) -> Option<&str> {
        self.component.as_deref()
    }

    fn run<'a>(
        &'a self,
        context: &'a AgentContext,
        request: AgentRequest,
    ) -> AgentFuture<'a, Result<AgentOutput, AgentError>> {
        self.driver.run(context, request)
    }
}

pub trait AgentScopeFactory: MaybeSendSync {
    fn driver_component_identity(&self) -> &'static str;

    fn tool_consumer_edge(&self) -> Option<(&'static str, &'static str)> {
        None
    }

    fn build_driver(
        &self,
        model: ModelRegistryBinding,
        runtime: RuntimePrimitives,
    ) -> Result<AgentDriverBinding, ComponentBuildError>;

    #[doc(hidden)]
    fn build_driver_with_tools(
        &self,
        model: ModelRegistryBinding,
        tool_binding: Option<GeneratedToolConsumerBinding>,
        runtime: RuntimePrimitives,
    ) -> Result<AgentDriverBinding, ComponentBuildError> {
        if tool_binding.is_some() {
            return Err(ComponentBuildError::InvalidConfig(
                "driver does not consume cap:tool-executor".into(),
            ));
        }
        self.build_driver(model, runtime)
    }
}

struct RequestJournalFacade {
    model_issuer: ModelRequestJournalIssuer,
    tool_issuer: Option<ToolCallJournalIssuer>,
    records: Mutex<VecDeque<Digest>>,
}

struct TurnExecution {
    request_id: AgentRequestId,
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
}

struct TurnExecutionGuard<'a> {
    context: &'a AgentContext,
}

impl Drop for TurnExecutionGuard<'_> {
    fn drop(&mut self) {
        self.context.end_turn();
    }
}

pub struct AgentContext {
    journal: Arc<RequestJournalFacade>,
    execution: Mutex<Option<TurnExecution>>,
    next_model_request: AtomicU64,
    runtime: RuntimePrimitives,
    publisher: Arc<EventPublisher>,
}

impl fmt::Debug for AgentContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AgentContext(<journal-bound>)")
    }
}

impl AgentContext {
    /// Returns the exact generated Tool journal scope paired with this Agent context.
    pub fn tool_call_scope_identity(&self) -> Result<&ToolCallScopeIdentity, AgentError> {
        self.journal
            .tool_issuer
            .as_ref()
            .map(ToolCallJournalIssuer::scope)
            .ok_or(AgentError::JournalUnavailable)
    }

    fn new(
        model_issuer: ModelRequestJournalIssuer,
        tool_issuer: Option<ToolCallJournalIssuer>,
        runtime: RuntimePrimitives,
        publisher: Arc<EventPublisher>,
    ) -> Self {
        Self {
            journal: Arc::new(RequestJournalFacade {
                model_issuer,
                tool_issuer,
                records: Mutex::new(VecDeque::new()),
            }),
            execution: Mutex::new(None),
            next_model_request: AtomicU64::new(1),
            runtime,
            publisher,
        }
    }

    fn begin_turn(
        &self,
        request_id: AgentRequestId,
        cancellation: CancellationToken,
        deadline: Option<RuntimeInstant>,
    ) {
        *self
            .execution
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(TurnExecution {
            request_id,
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
            let output_budget = plan.output_budget();
            let projection = plan.journal_projection();
            let record_digest = plan.record_digest();
            {
                let mut records = self
                    .journal
                    .records
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                records.push_back(record_digest);
                while records.len() > MAX_VOLATILE_JOURNAL_RECORDS {
                    records.pop_front();
                }
            }
            let proof = self
                .journal
                .model_issuer
                .seal_committed_record(
                    projection,
                    record_digest,
                    cancellation,
                    deadline,
                    output_budget,
                    self.runtime.clone(),
                )
                .map_err(|_| AgentError::JournalUnavailable)?;
            plan.seal(proof).map_err(AgentError::from)
        })
    }

    pub fn prepare_tool_call(
        &self,
        projection: ToolCallJournalProjection,
    ) -> AgentFuture<'_, Result<ToolCallJournalProof, AgentError>> {
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
            let issuer = self
                .journal
                .tool_issuer
                .as_ref()
                .ok_or(AgentError::JournalUnavailable)?;
            let record_digest = projection.record_digest();
            {
                let mut records = self
                    .journal
                    .records
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                records.push_back(record_digest);
                while records.len() > MAX_VOLATILE_JOURNAL_RECORDS {
                    records.pop_front();
                }
            }
            issuer
                .seal_committed_record(
                    projection,
                    record_digest,
                    cancellation,
                    deadline,
                    NonZeroUsize::new(MAX_MODEL_ORIGIN_TOOL_OUTPUT_BYTES)
                        .expect("model-origin Tool output ceiling is nonzero"),
                    self.runtime.clone(),
                )
                .map_err(|_| AgentError::JournalUnavailable)
        })
    }

    pub fn complete_model_call<'a>(
        &'a self,
        model: &'a ModelRegistryBinding,
        prepared: PreparedModelCall,
    ) -> AgentFuture<'a, Result<ModelResponse, AgentError>> {
        Box::pin(async move {
            let request_id = self
                .execution
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .ok_or(AgentError::JournalUnavailable)?
                .request_id;
            let output_budget = prepared.output_budget().get();
            let stream = model.stream_prepared(prepared).await?;
            let publisher = Arc::clone(&self.publisher);
            match try_collect_stream_with(stream, output_budget, move |delta| {
                publisher.output_delta(request_id, delta.to_owned())
            })
            .await
            {
                Ok(response) => Ok(response),
                Err(StreamCollectionError::Model(error)) => Err(AgentError::from(error)),
                Err(StreamCollectionError::Consumer(_)) => Err(AgentError::EventPublicationFailed),
            }
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
    pub const fn operation_id(&self) -> rust_agent_core::AgentLifecycleOperationId {
        self.operation.id()
    }

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

impl fmt::Display for AgentOperationSealError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AppClosed => "App is closed",
            Self::UnsupportedMode => "Agent Session mode is unsupported",
        })
    }
}

impl std::error::Error for AgentOperationSealError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentLifecycleError {
    UnsupportedOperation,
    OperationConflict,
    Construction(ComponentBuildError),
    Publication(PublicationDirectoryError),
    PublicationVeto(String),
    NotificationCapacityExceeded,
    EventPublicationFailed,
    AppClosed,
    JournalAuthority,
}

impl fmt::Display for AgentLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedOperation => formatter.write_str("Agent operation is unsupported"),
            Self::OperationConflict => formatter.write_str("Agent operation conflicts"),
            Self::Construction(error) => write!(formatter, "Agent construction failed: {error}"),
            Self::Publication(error) => write!(formatter, "Agent publication failed: {error}"),
            Self::PublicationVeto(reason) => {
                write!(formatter, "Agent publication was vetoed: {reason}")
            }
            Self::NotificationCapacityExceeded => {
                formatter.write_str("lifecycle notification capacity is exhausted")
            }
            Self::EventPublicationFailed => formatter.write_str("Agent event publication failed"),
            Self::AppClosed => formatter.write_str("App is closed"),
            Self::JournalAuthority => {
                formatter.write_str("request journal authority assembly failed")
            }
        }
    }
}

impl std::error::Error for AgentLifecycleError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentShutdownError {
    SessionFlushFailed { reason: SessionPersistenceError },
    Publication(PublicationDirectoryError),
    Runtime(rust_agent_runtime_api::RuntimePrimitiveError),
}

impl fmt::Display for AgentShutdownError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionFlushFailed { reason } => {
                write!(formatter, "Session flush failed: {reason}")
            }
            Self::Publication(error) => write!(formatter, "Agent removal failed: {error}"),
            Self::Runtime(error) => write!(formatter, "Agent runtime drain failed: {error}"),
        }
    }
}

impl std::error::Error for AgentShutdownError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppBuildError {
    Model(ModelError),
    Component(ComponentBuildError),
    BindingAssembly(rust_agent_runtime_api::BindingAssemblyError),
    Handoff(AppHandoffError),
    Runtime(rust_agent_runtime_api::RuntimePrimitiveError),
    RuntimeConfig(Phase2RuntimeConfigError),
    RuntimeAdapterMismatch,
    PanicContainmentUnavailable,
    LifecycleIssuer,
    ObserverDispatcher,
}

impl fmt::Display for AppBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model(error) => write!(formatter, "model assembly failed: {error}"),
            Self::Component(error) => write!(formatter, "Component build failed: {error}"),
            Self::BindingAssembly(error) => write!(formatter, "binding assembly failed: {error}"),
            Self::Handoff(error) => write!(formatter, "App handoff validation failed: {error}"),
            Self::Runtime(error) => write!(formatter, "runtime construction failed: {error}"),
            Self::RuntimeConfig(error) => write!(formatter, "runtime config is invalid: {error}"),
            Self::RuntimeAdapterMismatch => {
                formatter.write_str("runtime adapter identity mismatch")
            }
            Self::PanicContainmentUnavailable => {
                formatter.write_str("lifecycle observers require panic unwind containment")
            }
            Self::LifecycleIssuer => {
                formatter.write_str("lifecycle operation issuer construction failed")
            }
            Self::ObserverDispatcher => {
                formatter.write_str("lifecycle observer dispatcher construction failed")
            }
        }
    }
}

impl std::error::Error for AppBuildError {}

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

impl From<rust_agent_runtime_api::BindingAssemblyError> for AppBuildError {
    fn from(error: rust_agent_runtime_api::BindingAssemblyError) -> Self {
        Self::BindingAssembly(error)
    }
}

impl From<rust_agent_runtime_api::RuntimePrimitiveError> for AppBuildError {
    fn from(error: rust_agent_runtime_api::RuntimePrimitiveError) -> Self {
        Self::Runtime(error)
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

impl fmt::Display for AppShutdownError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Agent(error) => write!(formatter, "Agent shutdown failed: {error}"),
        }
    }
}

impl std::error::Error for AppShutdownError {}

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

impl fmt::Display for UnsupportedOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SessionQuery => "Session query is not compiled into this App",
            Self::DurableAgent => "durable Agent operations are not compiled into this App",
        })
    }
}

impl std::error::Error for UnsupportedOperation {}

pub trait AgentFactory: MaybeSendSync {
    fn seal_operation(
        &self,
        draft: AgentOperationDraft,
    ) -> AgentFuture<'_, Result<SealedAgentOperationDraft, AgentOperationSealError>>;
    fn allocate_operation(
        &self,
        draft: SealedAgentOperationDraft,
    ) -> AgentFuture<'_, Result<AllocatedAgentOperation, AgentOperationAllocationError>>;
    fn recover_operation(
        &self,
        operation_id: rust_agent_core::AgentLifecycleOperationId,
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
    agents: BTreeMap<AgentId, Arc<AgentInner>>,
    operations: BTreeMap<rust_agent_core::AgentLifecycleOperationId, PendingLifecycleOperation>,
    creations_in_flight: usize,
    shutdown_waiters: Vec<ShutdownWaiter>,
    teardown_started: bool,
}

impl ShutdownWaiterState for AppState {
    fn shutdown_waiters(&mut self) -> &mut Vec<ShutdownWaiter> {
        &mut self.shutdown_waiters
    }
}

struct PendingLifecycleOperation {
    fingerprint: Digest,
    expires_at: RuntimeInstant,
}

struct AppInner {
    identity: Arc<AppIdentity>,
    composition: CompositionHash,
    catalog: Digest,
    handoff: AppHandoffSeal,
    runtime: RuntimePrimitives,
    runtime_config: Phase2RuntimeConfig,
    model: ModelRegistry,
    binding_assembly: BindingAssemblyOwner,
    scope_factory: Arc<dyn AgentScopeFactory>,
    observers: Arc<[Arc<dyn LifecycleObserver>]>,
    dispatcher: ObserverDispatcher,
    directory: PublicationDirectory,
    directory_writer: PublicationDirectoryWriteHandle,
    publication: Mutex<()>,
    operation_issuer: VolatileLifecycleOperationIssuer,
    next_agent: AtomicU64,
    state: Mutex<AppState>,
}

struct AppTeardownLease<'a> {
    app: &'a AppInner,
    completed: bool,
}

impl AppTeardownLease<'_> {
    fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for AppTeardownLease<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let waiters = {
            let mut state = self
                .app
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.status != AppStatus::Closed {
                state.teardown_started = false;
            }
            take_shutdown_waiters(&mut state.shutdown_waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }
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
    #[allow(clippy::too_many_arguments)]
    pub fn from_generated(
        composition: CompositionHash,
        catalog: Digest,
        handoff: AppHandoffSeal,
        runtime_config: Phase2RuntimeConfig,
        runtime: RuntimePrimitives,
        model: ModelRegistry,
        binding_assembly: BindingAssemblyOwner,
        scope_factory: Arc<dyn AgentScopeFactory>,
        observer_bindings: Vec<LifecycleObserverBinding>,
    ) -> Result<Self, AppBuildError> {
        if !observer_bindings.is_empty() && !cfg!(panic = "unwind") {
            return Err(AppBuildError::PanicContainmentUnavailable);
        }
        let observer_bindings = observer_bindings
            .into_iter()
            .map(LifecycleObserverBinding::into_generated_parts)
            .collect::<Result<Vec<_>, _>>()?;
        let (lifecycle_observer_identities, observers): (Vec<_>, Vec<_>) =
            observer_bindings.into_iter().unzip();
        binding_assembly.verify_generated_root(
            composition,
            catalog,
            &model.generated_provider_identities(),
            &lifecycle_observer_identities,
            &runtime,
        )?;
        for primitive in [
            rust_agent_runtime_api::RuntimePrimitiveKind::Clock,
            rust_agent_runtime_api::RuntimePrimitiveKind::Sleep,
            rust_agent_runtime_api::RuntimePrimitiveKind::Spawn,
        ] {
            if !runtime.has(primitive) {
                return Err(AppBuildError::Runtime(
                    rust_agent_runtime_api::RuntimePrimitiveError::MissingPrimitive(primitive),
                ));
            }
        }
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
        let dispatcher = ObserverDispatcher::new(
            Arc::clone(&observers),
            runtime.clone(),
            runtime_config.lifecycle_notification_max_pending(),
            runtime_config.lifecycle_observer_timeout(),
            runtime_config.shutdown_timeout(),
        )
        .map_err(|_| AppBuildError::ObserverDispatcher)?;
        let identity = Arc::new(AppIdentity { generation });
        let inner = Arc::new(AppInner {
            identity,
            composition,
            catalog,
            handoff,
            runtime,
            runtime_config,
            model,
            binding_assembly,
            scope_factory,
            observers,
            dispatcher,
            directory,
            directory_writer,
            publication: Mutex::new(()),
            operation_issuer,
            next_agent: AtomicU64::new(1),
            state: Mutex::new(AppState {
                status: AppStatus::Ready,
                agents: BTreeMap::new(),
                operations: BTreeMap::new(),
                creations_in_flight: 0,
                shutdown_waiters: Vec::new(),
                teardown_started: false,
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

    pub fn recover_agent_operation(
        &self,
        operation_id: rust_agent_core::AgentLifecycleOperationId,
        draft: SealedAgentOperationDraft,
    ) -> AgentFuture<'_, Result<AllocatedAgentOperation, AgentOperationAllocationError>> {
        self.factory.recover_operation(operation_id, draft)
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

    pub fn lifecycle_observer_diagnostics(&self) -> LifecycleObserverDiagnostics {
        self.inner.dispatcher.diagnostics()
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
            let mut waiter = ShutdownWaiterRegistration::new(&self.inner.state);
            let agents_to_close = {
                let mut state = self
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.status == AppStatus::Ready {
                    state.status = AppStatus::Closing;
                    state.agents.values().cloned().collect::<Vec<_>>()
                } else {
                    Vec::new()
                }
            };
            for agent in agents_to_close {
                agent.begin_shutdown();
            }
            let owns_teardown = poll_fn(|context| {
                let mut state = self
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match state.status {
                    AppStatus::Closed => {
                        waiter.unregister(&mut state.shutdown_waiters);
                        return Poll::Ready(false);
                    }
                    AppStatus::Ready => state.status = AppStatus::Closing,
                    AppStatus::Closing => {}
                }
                if state.creations_in_flight == 0 && !state.teardown_started {
                    state.teardown_started = true;
                    waiter.unregister(&mut state.shutdown_waiters);
                    return Poll::Ready(true);
                }
                waiter.register(&mut state.shutdown_waiters, context.waker());
                Poll::Pending
            })
            .await;
            if !owns_teardown {
                return Ok(());
            }
            let mut teardown = AppTeardownLease {
                app: &self.inner,
                completed: false,
            };
            let agents = self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .agents
                .values()
                .cloned()
                .collect::<Vec<_>>();
            for agent in &agents {
                agent.begin_shutdown();
            }
            for agent in agents {
                agent
                    .shutdown_inner()
                    .await
                    .map_err(AppShutdownError::Agent)?;
            }
            self.inner.dispatcher.shutdown();
            let waiters = {
                let mut state = self
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.status = AppStatus::Closed;
                take_shutdown_waiters(&mut state.shutdown_waiters)
            };
            teardown.complete();
            for waiter in waiters {
                waiter.wake();
            }
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
            let now = app
                .runtime
                .now()
                .map_err(|_| AgentOperationAllocationError::StoreUnavailable)?;
            let mut state = app
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.status != AppStatus::Ready {
                return Err(AgentOperationAllocationError::AppClosed);
            }
            state
                .operations
                .retain(|_, pending| pending.expires_at > now);
            if state.operations.len() >= MAX_PENDING_LIFECYCLE_OPERATIONS {
                return Err(AgentOperationAllocationError::ResourceExhausted);
            }
            let operation = app.operation_issuer.allocate()?;
            let expires_at = now
                .checked_add(PENDING_LIFECYCLE_OPERATION_TTL)
                .ok_or(AgentOperationAllocationError::CounterExhausted)?;
            state.operations.insert(
                operation.id(),
                PendingLifecycleOperation {
                    fingerprint: draft.fingerprint,
                    expires_at,
                },
            );
            Ok(AllocatedAgentOperation {
                app_identity: draft.app_identity,
                operation,
                mode: draft.mode,
                fingerprint: draft.fingerprint,
            })
        })
    }

    fn recover_operation(
        &self,
        operation_id: rust_agent_core::AgentLifecycleOperationId,
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
            let now = app
                .runtime
                .now()
                .map_err(|_| AgentOperationAllocationError::StoreUnavailable)?;
            let mut state = app
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.status != AppStatus::Ready {
                return Err(AgentOperationAllocationError::AppClosed);
            }
            state
                .operations
                .retain(|_, pending| pending.expires_at > now);
            let pending = state
                .operations
                .get(&operation_id)
                .ok_or(AgentOperationAllocationError::OperationNotFound)?;
            if pending.fingerprint != draft.fingerprint {
                return Err(AgentOperationAllocationError::OperationConflict);
            }
            let operation = app.operation_issuer.recover(operation_id)?;
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
            create_sessionless_agent(&app, request).await
        })
    }

    fn resume(
        &self,
        _request: ResumeAgentRequest,
    ) -> AgentFuture<'_, Result<AgentHandle, AgentLifecycleError>> {
        Box::pin(async { Err(AgentLifecycleError::UnsupportedOperation) })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RequestFingerprint {
    digest: Digest,
}

#[derive(Clone)]
struct AdmittedRequest {
    request: AgentRequest,
    deadline: Option<RuntimeInstant>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestExecutor {
    Waiter(u64),
    Runtime,
}

enum RequestPhase {
    Queued,
    Active {
        executor: RequestExecutor,
        first_cause: Option<CancelCause>,
    },
    Finalizing,
    Completed(Result<AgentOutput, AgentError>),
}

struct RequestSlot {
    fingerprint: RequestFingerprint,
    admitted: AdmittedRequest,
    cancellation: CancellationToken,
    admission_cancellation: CancellationToken,
    phase: RequestPhase,
    waiters: BTreeMap<u64, Option<Waker>>,
}

struct AgentState {
    status: AgentPublicStatus,
    next_request: u64,
    next_command: u64,
    active: Option<AgentRequestId>,
    queue: VecDeque<AgentRequestId>,
    requests: BTreeMap<AgentRequestId, RequestSlot>,
    completed: VecDeque<AgentRequestId>,
    expired_through: u64,
    allocated_unsubmitted: BTreeSet<u64>,
    next_waiter: u64,
    shutdown_waiters: Vec<ShutdownWaiter>,
    teardown_started: bool,
    directory_closing: bool,
    removed: bool,
}

impl ShutdownWaiterState for AgentState {
    fn shutdown_waiters(&mut self) -> &mut Vec<ShutdownWaiter> {
        &mut self.shutdown_waiters
    }
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
    request_task_owner: Mutex<Option<rust_agent_runtime_api::RuntimeTaskOwner>>,
    state: Mutex<AgentState>,
}

#[derive(Clone)]
struct PromotedRequest {
    request_id: AgentRequestId,
    admitted: AdmittedRequest,
    cancellation: CancellationToken,
    admission_cancellation: CancellationToken,
}

struct AgentTeardownLease<'a> {
    agent: &'a AgentInner,
    completed: bool,
}

impl AgentTeardownLease<'_> {
    fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for AgentTeardownLease<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let waiters = {
            let mut state = self
                .agent
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.status != AgentPublicStatus::Closed {
                state.teardown_started = false;
            }
            take_shutdown_waiters(&mut state.shutdown_waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }
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
        if state.allocated_unsubmitted.len() >= MAX_ALLOCATED_UNSUBMITTED_REQUESTS {
            return Err(AgentError::Busy);
        }
        let sequence = NonZeroU64::new(state.next_request).ok_or(AgentError::RequestExpired)?;
        state.next_request = state
            .next_request
            .checked_add(1)
            .ok_or(AgentError::RequestExpired)?;
        state.allocated_unsubmitted.insert(sequence.get());
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
        AgentInner::send_arc(&self.inner, request)
    }

    pub fn cancel(
        &self,
        request_id: AgentRequestId,
        cause: CancelCause,
    ) -> Result<CancelOutcome, AgentCancelError> {
        self.inner.cancel_request(request_id, cause)
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
            if state.status != AgentPublicStatus::Ready {
                return Err(AgentEventFeedError::Closed);
            }
            self.inner.publisher.open(request)
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

enum AdmissionAction {
    Execute(AdmittedRequest, CancellationToken, CancellationToken),
    Completed(Result<AgentOutput, AgentError>),
    WaiterCancelled,
    WaiterDeadlineExceeded,
}

struct AdmissionTicket {
    waiter_id: u64,
    execution_deadline: Option<RuntimeInstant>,
    is_first_admission: bool,
}

struct SendWaiterGuard {
    agent: Arc<AgentInner>,
    request_id: AgentRequestId,
    waiter_id: u64,
    resolved: bool,
}

impl SendWaiterGuard {
    fn resolve(&mut self) {
        if !self.resolved {
            self.resolved = true;
            self.agent.release_waiter(self.request_id, self.waiter_id);
        }
    }
}

impl Drop for SendWaiterGuard {
    fn drop(&mut self) {
        if !self.resolved {
            self.agent.abandon_waiter(self.request_id, self.waiter_id);
        }
    }
}

impl Agent for AgentHandle {
    fn send(&self, request: AgentSendRequest) -> AgentFuture<'_, Result<AgentOutput, AgentError>> {
        AgentInner::send_arc(&self.inner, request)
    }

    fn cancel(
        &self,
        request_id: AgentRequestId,
        cause: CancelCause,
    ) -> Result<CancelOutcome, AgentCancelError> {
        self.inner.cancel_request(request_id, cause)
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
    fn send_arc(
        agent: &Arc<Self>,
        request: AgentSendRequest,
    ) -> AgentFuture<'_, Result<AgentOutput, AgentError>> {
        let agent = Arc::clone(agent);
        Box::pin(async move {
            if request.request_id.agent_id() != agent.id {
                return Err(AgentError::RequestConflict);
            }
            if request.request_id.lifecycle() != agent.lifecycle {
                return Err(AgentError::RequestExpired);
            }
            let caller_cancellation = request.cancellation.clone();
            let request_id = request.request_id;
            let fingerprint = RequestFingerprint {
                digest: request_fingerprint(&request),
            };
            let waiter_deadline = request.deadline;
            let admitted = AdmittedRequest {
                request: AgentRequest {
                    request_id,
                    input: request.input,
                    caller_digest: request.caller_digest,
                    route: request.route,
                },
                deadline: request.deadline,
            };
            let ticket = agent.admit_request(
                request_id,
                fingerprint,
                admitted,
                caller_cancellation.clone(),
            )?;
            let waiter_id = ticket.waiter_id;
            let mut guard = SendWaiterGuard {
                agent: Arc::clone(&agent),
                request_id,
                waiter_id,
                resolved: false,
            };
            let mut waiter_cancelled = Box::pin(caller_cancellation.cancelled());
            let mut execution_deadline = ticket
                .execution_deadline
                .map(|deadline| agent.context.runtime.sleep_until(deadline))
                .transpose()
                .map_err(|_| AgentError::Model(ModelError::RuntimeUnavailable))?;
            let mut waiter_deadline = (!ticket.is_first_admission
                && waiter_deadline != ticket.execution_deadline)
                .then_some(waiter_deadline)
                .flatten()
                .map(|deadline| agent.context.runtime.sleep_until(deadline))
                .transpose()
                .map_err(|_| AgentError::Model(ModelError::RuntimeUnavailable))?;
            let action = poll_fn(|context| {
                let waiter_is_cancelled = waiter_cancelled.as_mut().poll(context).is_ready();
                let execution_deadline_expired = execution_deadline
                    .as_mut()
                    .is_some_and(|wait| wait.as_mut().poll(context).is_ready());
                let waiter_deadline_expired = waiter_deadline
                    .as_mut()
                    .is_some_and(|wait| wait.as_mut().poll(context).is_ready());
                let mut state = agent
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let Some(slot) = state.requests.get_mut(&request_id) else {
                    return Poll::Ready(AdmissionAction::Completed(Err(
                        AgentError::RequestExpired,
                    )));
                };
                match &mut slot.phase {
                    RequestPhase::Completed(result) => {
                        return Poll::Ready(AdmissionAction::Completed(result.clone()));
                    }
                    RequestPhase::Queued
                    | RequestPhase::Active { .. }
                    | RequestPhase::Finalizing => {}
                }
                match &mut slot.phase {
                    RequestPhase::Active {
                        executor: RequestExecutor::Waiter(executor),
                        ..
                    } if *executor == waiter_id => {
                        return Poll::Ready(AdmissionAction::Execute(
                            slot.admitted.clone(),
                            slot.cancellation.clone(),
                            slot.admission_cancellation.clone(),
                        ));
                    }
                    RequestPhase::Queued
                    | RequestPhase::Active { .. }
                    | RequestPhase::Finalizing => {}
                    RequestPhase::Completed(result) => {
                        return Poll::Ready(AdmissionAction::Completed(result.clone()));
                    }
                }
                if execution_deadline_expired {
                    drop(state);
                    agent.enforce_request_deadline(request_id);
                    context.waker().wake_by_ref();
                    return Poll::Pending;
                }
                if waiter_deadline_expired {
                    return Poll::Ready(AdmissionAction::WaiterDeadlineExceeded);
                }
                if waiter_is_cancelled {
                    return Poll::Ready(AdmissionAction::WaiterCancelled);
                }
                slot.waiters
                    .insert(waiter_id, Some(context.waker().clone()));
                Poll::Pending
            })
            .await;
            let result = match action {
                AdmissionAction::WaiterCancelled => return Err(AgentError::Cancelled),
                AdmissionAction::WaiterDeadlineExceeded => {
                    return Err(AgentError::DeadlineExceeded);
                }
                AdmissionAction::Completed(result) => result,
                AdmissionAction::Execute(admitted, cancellation, admission_cancellation) => {
                    let result = agent
                        .execute_request(admitted, cancellation, admission_cancellation)
                        .await;
                    agent.complete_request(request_id, result)
                }
            };
            guard.resolve();
            result
        })
    }

    fn admit_request(
        &self,
        request_id: AgentRequestId,
        fingerprint: RequestFingerprint,
        admitted: AdmittedRequest,
        admission_cancellation: CancellationToken,
    ) -> Result<AdmissionTicket, AgentError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.status != AgentPublicStatus::Ready {
            return Err(AgentError::Closed);
        }
        if request_id.sequence() >= state.next_request {
            return Err(AgentError::RequestConflict);
        }
        if !state.requests.contains_key(&request_id)
            && request_id.sequence() <= state.expired_through
            && !state.allocated_unsubmitted.contains(&request_id.sequence())
        {
            return Err(AgentError::RequestExpired);
        }
        let (existing, execution_deadline) = if let Some(slot) = state.requests.get(&request_id) {
            if slot.fingerprint != fingerprint {
                return Err(AgentError::RequestConflict);
            }
            if slot.waiters.len() >= MAX_REQUEST_WAITERS {
                return Err(AgentError::Busy);
            }
            (true, slot.admitted.deadline)
        } else {
            if state.active.is_some() && state.queue.len() >= MAX_ADMISSION_QUEUE {
                return Err(AgentError::Busy);
            }
            (false, None)
        };
        let waiter_id = state.next_waiter;
        state.next_waiter = state
            .next_waiter
            .checked_add(1)
            .ok_or(AgentError::RequestExpired)?;
        if existing {
            let slot = state
                .requests
                .get_mut(&request_id)
                .expect("validated request slot remains present while state is locked");
            slot.waiters.insert(waiter_id, None);
            return Ok(AdmissionTicket {
                waiter_id,
                execution_deadline,
                is_first_admission: false,
            });
        }
        let phase = if state.active.is_none() {
            state.active = Some(request_id);
            RequestPhase::Active {
                executor: RequestExecutor::Waiter(waiter_id),
                first_cause: None,
            }
        } else {
            state.queue.push_back(request_id);
            RequestPhase::Queued
        };
        state.allocated_unsubmitted.remove(&request_id.sequence());
        state.requests.insert(
            request_id,
            RequestSlot {
                fingerprint,
                admitted,
                cancellation: CancellationToken::new(),
                admission_cancellation,
                phase,
                waiters: BTreeMap::from([(waiter_id, None)]),
            },
        );
        Ok(AdmissionTicket {
            waiter_id,
            execution_deadline: state.requests[&request_id].admitted.deadline,
            is_first_admission: true,
        })
    }

    async fn execute_request(
        &self,
        admitted: AdmittedRequest,
        cancellation: CancellationToken,
        admission_cancellation: CancellationToken,
    ) -> Result<AgentOutput, AgentError> {
        let request_id = admitted.request.request_id();
        if self.publisher.begin_request(request_id).is_err() {
            self.enter_recovery_required();
            return Err(AgentError::EventPublicationFailed);
        }
        self.context
            .begin_turn(request_id, cancellation.clone(), admitted.deadline);
        let _turn_execution = TurnExecutionGuard {
            context: &self.context,
        };
        let mut driver = self.driver.run(&self.context, admitted.request);
        let mut targeted_cancelled = Box::pin(cancellation.cancelled());
        let mut admission_cancelled = Box::pin(admission_cancellation.cancelled());
        let Ok(mut deadline_wait) = admitted
            .deadline
            .map(|deadline| self.context.runtime.sleep_until(deadline))
            .transpose()
        else {
            return Err(AgentError::Model(ModelError::RuntimeUnavailable));
        };
        let mut result = poll_fn(|context| {
            if targeted_cancelled.as_mut().poll(context).is_ready() {
                return Poll::Ready(Err(AgentError::Cancelled));
            }
            if admission_cancelled.as_mut().poll(context).is_ready() {
                self.record_cancel_cause(request_id, CancelCause::User);
                return Poll::Ready(Err(AgentError::Cancelled));
            }
            if deadline_wait
                .as_mut()
                .is_some_and(|wait| wait.as_mut().poll(context).is_ready())
            {
                self.record_cancel_cause(request_id, CancelCause::Deadline);
                return Poll::Ready(Err(AgentError::DeadlineExceeded));
            }
            driver.as_mut().poll(context)
        })
        .await;
        if result == Err(AgentError::Cancelled)
            && self.first_cancel_cause(request_id) == Some(CancelCause::Deadline)
        {
            result = Err(AgentError::DeadlineExceeded);
        }
        result
    }

    fn record_cancel_cause(&self, request_id: AgentRequestId, cause: CancelCause) {
        let cancellation = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(slot) = state.requests.get_mut(&request_id) else {
                return;
            };
            let RequestPhase::Active { first_cause, .. } = &mut slot.phase else {
                return;
            };
            if first_cause.is_none() {
                *first_cause = Some(cause);
            }
            slot.cancellation.clone()
        };
        cancellation.cancel();
    }

    fn enforce_request_deadline(&self, request_id: AgentRequestId) {
        let mut wake = Vec::new();
        let mut cancellation = None;
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut completed_queued = false;
            if let Some(slot) = state.requests.get_mut(&request_id) {
                match &mut slot.phase {
                    RequestPhase::Queued => {
                        slot.phase = RequestPhase::Completed(Err(AgentError::DeadlineExceeded));
                        wake.extend(slot.waiters.values_mut().filter_map(Option::take));
                        completed_queued = true;
                    }
                    RequestPhase::Active { first_cause, .. } => {
                        if first_cause.is_none() {
                            *first_cause = Some(CancelCause::Deadline);
                        }
                        cancellation = Some(slot.cancellation.clone());
                    }
                    RequestPhase::Finalizing | RequestPhase::Completed(_) => {}
                }
            }
            if completed_queued {
                state.queue.retain(|queued| *queued != request_id);
                state.completed.push_back(request_id);
                expire_completed_requests(&mut state);
            }
        }
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
        for waiter in wake {
            waiter.wake();
        }
    }

    fn first_cancel_cause(&self, request_id: AgentRequestId) -> Option<CancelCause> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let slot = state.requests.get(&request_id)?;
        match &slot.phase {
            RequestPhase::Active { first_cause, .. } => first_cause.clone(),
            RequestPhase::Queued | RequestPhase::Finalizing | RequestPhase::Completed(_) => None,
        }
    }

    fn complete_request(
        self: &Arc<Self>,
        request_id: AgentRequestId,
        result: Result<AgentOutput, AgentError>,
    ) -> Result<AgentOutput, AgentError> {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(slot) = state.requests.get_mut(&request_id) {
                slot.phase = RequestPhase::Finalizing;
            }
        }
        let final_result = if self.publisher.finish_request(request_id, &result).is_ok() {
            result
        } else {
            self.enter_recovery_required();
            Err(AgentError::EventPublicationFailed)
        };
        self.commit_finalized_request(request_id, &final_result);
        final_result
    }

    fn enter_recovery_required(&self) {
        let mut wake = Vec::new();
        let (became_recovery_required, cancellation) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.status == AgentPublicStatus::Ready {
                state.status = AgentPublicStatus::RecoveryRequired;
                let queued = std::mem::take(&mut state.queue);
                for request_id in queued {
                    if let Some(slot) = state.requests.get_mut(&request_id) {
                        slot.phase = RequestPhase::Completed(Err(AgentError::Closed));
                        wake.extend(slot.waiters.values_mut().filter_map(Option::take));
                        state.completed.push_back(request_id);
                    }
                }
                expire_completed_requests(&mut state);
                let cancellation = state
                    .active
                    .and_then(|active| state.requests.get(&active))
                    .map(|slot| slot.cancellation.clone());
                (true, cancellation)
            } else {
                (false, None)
            }
        };
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
        if became_recovery_required {
            self.publisher.close(AgentPublicStatus::RecoveryRequired);
        }
        for waiter in wake {
            waiter.wake();
        }
    }

    fn commit_finalized_request(
        self: &Arc<Self>,
        request_id: AgentRequestId,
        result: &Result<AgentOutput, AgentError>,
    ) {
        let mut wake = Vec::new();
        let promoted = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(slot) = state.requests.get_mut(&request_id)
                && matches!(slot.phase, RequestPhase::Finalizing)
            {
                slot.phase = RequestPhase::Completed(result.clone());
                wake.extend(slot.waiters.values_mut().filter_map(Option::take));
            }
            if state.active == Some(request_id) {
                state.active = None;
            }
            state.completed.push_back(request_id);
            expire_completed_requests(&mut state);
            let promoted = promote_next(&mut state, &mut wake);
            wake.extend(take_shutdown_waiters(&mut state.shutdown_waiters));
            promoted
        };
        if let Some(promoted) = promoted {
            self.spawn_promoted_request(promoted);
        }
        for waiter in wake {
            waiter.wake();
        }
    }

    fn spawn_promoted_request(self: &Arc<Self>, promoted: PromotedRequest) {
        let owner_result = {
            let mut owner = self
                .request_task_owner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(existing) = owner.as_ref() {
                Ok(existing.clone())
            } else {
                match self.context.runtime.new_task_owner() {
                    Ok(created) => {
                        *owner = Some(created.clone());
                        Ok(created)
                    }
                    Err(error) => Err(error),
                }
            }
        };
        let Ok(owner) = owner_result else {
            self.fail_promoted_request(promoted.request_id);
            return;
        };
        let agent = Arc::clone(self);
        let request_id = promoted.request_id;
        let task = Box::pin(async move {
            let result = agent
                .execute_request(
                    promoted.admitted,
                    promoted.cancellation,
                    promoted.admission_cancellation,
                )
                .await;
            let _ = agent.complete_request(request_id, result);
        });
        if self.context.runtime.spawn(owner, task).is_err() {
            self.fail_promoted_request(request_id);
        }
    }

    fn fail_promoted_request(self: &Arc<Self>, request_id: AgentRequestId) {
        let result = if self.publisher.begin_request(request_id).is_ok() {
            Err(AgentError::Model(ModelError::RuntimeUnavailable))
        } else {
            Err(AgentError::EventPublicationFailed)
        };
        let _ = self.complete_request(request_id, result);
    }

    fn release_waiter(&self, request_id: AgentRequestId, waiter_id: u64) {
        if let Some(slot) = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .requests
            .get_mut(&request_id)
        {
            slot.waiters.remove(&waiter_id);
        }
    }

    fn abandon_waiter(self: &Arc<Self>, request_id: AgentRequestId, waiter_id: u64) {
        let mut abandoned_active = false;
        let mut cancellation = None;
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut remove_queued = false;
            if let Some(slot) = state.requests.get_mut(&request_id) {
                slot.waiters.remove(&waiter_id);
                match &slot.phase {
                    RequestPhase::Queued => remove_queued = slot.waiters.is_empty(),
                    RequestPhase::Active {
                        executor: RequestExecutor::Waiter(executor),
                        ..
                    } if *executor == waiter_id => {
                        cancellation = Some(slot.cancellation.clone());
                        slot.phase = RequestPhase::Finalizing;
                        abandoned_active = true;
                    }
                    RequestPhase::Active { .. }
                    | RequestPhase::Finalizing
                    | RequestPhase::Completed(_) => {}
                }
            }
            if remove_queued {
                state.queue.retain(|queued| *queued != request_id);
                state.requests.remove(&request_id);
                state.allocated_unsubmitted.insert(request_id.sequence());
            }
        }
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
        if abandoned_active {
            let mut result = Err(AgentError::OutcomeUnknown);
            if self.publisher.finish_request(request_id, &result).is_err() {
                self.enter_recovery_required();
                result = Err(AgentError::EventPublicationFailed);
            }
            self.commit_finalized_request(request_id, &result);
        }
    }

    fn cancel_request(
        &self,
        request_id: AgentRequestId,
        cause: CancelCause,
    ) -> Result<CancelOutcome, AgentCancelError> {
        if request_id.agent_id() != self.id {
            return Err(AgentCancelError::ForeignRequest {
                request: request_id,
            });
        }
        if request_id.lifecycle() != self.lifecycle {
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
        let Some(slot) = state.requests.get_mut(&request_id) else {
            return Ok(CancelOutcome::NotActive);
        };
        let (outcome, cancellation) = match &mut slot.phase {
            RequestPhase::Active { first_cause, .. } => {
                if let Some(first_cause) = first_cause {
                    return Ok(CancelOutcome::AlreadyCancelling {
                        first_cause: first_cause.clone(),
                    });
                }
                *first_cause = Some(cause);
                (
                    CancelOutcome::CancelledActive,
                    Some(slot.cancellation.clone()),
                )
            }
            RequestPhase::Finalizing | RequestPhase::Completed(_) => {
                (CancelOutcome::AlreadyTerminal, None)
            }
            RequestPhase::Queued => (CancelOutcome::NotActive, None),
        };
        drop(state);
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
        Ok(outcome)
    }

    fn shutdown_inner(&self) -> AgentFuture<'_, Result<(), AgentShutdownError>> {
        Box::pin(async move {
            let mut waiter = ShutdownWaiterRegistration::new(&self.state);
            self.begin_shutdown();
            let owns_teardown = poll_fn(|context| {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.status == AgentPublicStatus::Closed {
                    waiter.unregister(&mut state.shutdown_waiters);
                    return Poll::Ready(false);
                }
                if state.active.is_none() && !state.teardown_started {
                    state.teardown_started = true;
                    waiter.unregister(&mut state.shutdown_waiters);
                    return Poll::Ready(true);
                }
                waiter.register(&mut state.shutdown_waiters, context.waker());
                Poll::Pending
            })
            .await;
            if !owns_teardown {
                return Ok(());
            }
            let mut teardown = AgentTeardownLease {
                agent: self,
                completed: false,
            };
            let should_mark_closing = {
                let state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                !state.directory_closing && !state.removed
            };
            if should_mark_closing && let Some(app) = self.app.upgrade() {
                let _publication = app
                    .publication
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                app.directory_writer
                    .mark_closing(self.id, self.lifecycle)
                    .map_err(AgentShutdownError::Publication)?;
                self.state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .directory_closing = true;
            }
            let request_task_owner = self
                .request_task_owner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(owner) = request_task_owner {
                self.context
                    .runtime
                    .drain(owner)
                    .map_err(AgentShutdownError::Runtime)?
                    .await;
            }
            self.publisher.close(AgentPublicStatus::Closed);
            self.publisher
                .drain()
                .await
                .map_err(AgentShutdownError::Runtime)?;
            let should_remove = {
                let state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                !state.removed
            };
            if should_remove && let Some(app) = self.app.upgrade() {
                let _publication = app
                    .publication
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                self.state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .removed = true;
            }
            let waiters = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.status = AgentPublicStatus::Closed;
                take_shutdown_waiters(&mut state.shutdown_waiters)
            };
            if let Some(app) = self.app.upgrade() {
                app.state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .agents
                    .remove(&self.id);
            }
            teardown.complete();
            for waiter in waiters {
                waiter.wake();
            }
            Ok(())
        })
    }

    fn begin_shutdown(&self) {
        let mut wake = Vec::new();
        let (became_closing, cancellation) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if matches!(
                state.status,
                AgentPublicStatus::Ready | AgentPublicStatus::RecoveryRequired
            ) {
                state.status = AgentPublicStatus::Closing;
                let queued = std::mem::take(&mut state.queue);
                for request_id in queued {
                    if let Some(slot) = state.requests.get_mut(&request_id) {
                        slot.phase = RequestPhase::Completed(Err(AgentError::Closed));
                        wake.extend(slot.waiters.values_mut().filter_map(Option::take));
                        state.completed.push_back(request_id);
                    }
                }
                expire_completed_requests(&mut state);
                let cancellation = state
                    .active
                    .and_then(|active| state.requests.get(&active))
                    .map(|slot| slot.cancellation.clone());
                (true, cancellation)
            } else {
                (false, None)
            }
        };
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
        if became_closing {
            let _ = self.publisher.set_status(AgentPublicStatus::Closing);
        }
        for waiter in wake {
            waiter.wake();
        }
    }
}

fn expire_completed_requests(state: &mut AgentState) {
    while state.completed.len() > MAX_COMPLETED_REQUESTS {
        if let Some(expired) = state.completed.pop_front() {
            state.expired_through = state.expired_through.max(expired.sequence());
            state.requests.remove(&expired);
        }
    }
}

fn promote_next(state: &mut AgentState, wake: &mut Vec<Waker>) -> Option<PromotedRequest> {
    while let Some(request_id) = state.queue.pop_front() {
        let Some(slot) = state.requests.get_mut(&request_id) else {
            continue;
        };
        if slot.waiters.is_empty() {
            state.requests.remove(&request_id);
            state.allocated_unsubmitted.insert(request_id.sequence());
            continue;
        }
        slot.phase = RequestPhase::Active {
            executor: RequestExecutor::Runtime,
            first_cause: None,
        };
        let promoted = PromotedRequest {
            request_id,
            admitted: slot.admitted.clone(),
            cancellation: slot.cancellation.clone(),
            admission_cancellation: slot.admission_cancellation.clone(),
        };
        wake.extend(slot.waiters.values_mut().filter_map(Option::take));
        state.active = Some(request_id);
        return Some(promoted);
    }
    None
}

async fn create_sessionless_agent(
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
    let _creation =
        CreationReservation::begin(app, allocated.operation.id(), allocated.fingerprint)?;
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
    let mut binding_assembly = app
        .binding_assembly
        .begin_binding_assembly(scope)
        .map_err(|_| AgentLifecycleError::JournalAuthority)?;
    let provider_keys = app.model.generated_provider_keys();
    let driver_component_identity = app.scope_factory.driver_component_identity();
    binding_assembly
        .bind_model_consumer(driver_component_identity, &provider_keys)
        .map_err(|_| AgentLifecycleError::JournalAuthority)?;
    if let Some((consumer, provider)) = app.scope_factory.tool_consumer_edge() {
        binding_assembly
            .bind_tool_consumer(consumer, provider)
            .map_err(|_| AgentLifecycleError::JournalAuthority)?;
    }
    let (model_issuer, model_verifier, tool_issuer, tool_binding) = binding_assembly
        .finish()
        .and_then(|authority| authority.into_agent_journal_parts(&app.binding_assembly))
        .map_err(|_| AgentLifecycleError::JournalAuthority)?;
    let model = app.model.bind_generated_scope(model_verifier);
    let driver = app
        .scope_factory
        .build_driver_with_tools(model, tool_binding, app.runtime.clone())
        .map_err(AgentLifecycleError::Construction)?;
    if driver.generated_component_identity() != Some(driver_component_identity) {
        return Err(AgentLifecycleError::JournalAuthority);
    }
    let reservation = app
        .dispatcher
        .reserve_pair()
        .ok_or(AgentLifecycleError::NotificationCapacityExceeded)?;
    let publisher = EventPublisher::new(
        agent_id,
        lifecycle,
        AgentPublicStatus::Closing,
        app.runtime_config.agent_resource_budget().clone(),
        app.runtime.clone(),
    )
    .map_err(|error| AgentLifecycleError::Construction(ComponentBuildError::Runtime(error)))?;
    let agent = Arc::new(AgentInner {
        id: agent_id,
        lifecycle,
        driver,
        context: AgentContext::new(
            model_issuer,
            tool_issuer,
            app.runtime.clone(),
            Arc::clone(&publisher),
        ),
        publisher,
        commands: Mutex::new(None),
        app: Arc::downgrade(app),
        notification: Mutex::new(Some(reservation)),
        request_task_owner: Mutex::new(None),
        state: Mutex::new(AgentState {
            status: AgentPublicStatus::Closing,
            next_request: 1,
            next_command: 1,
            active: None,
            queue: VecDeque::new(),
            requests: BTreeMap::new(),
            completed: VecDeque::new(),
            expired_through: 0,
            allocated_unsubmitted: BTreeSet::new(),
            next_waiter: 1,
            shutdown_waiters: Vec::new(),
            teardown_started: false,
            directory_closing: false,
            removed: false,
        }),
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
    if let Err(error) = publish_constructed_agent(app, &agent, candidate) {
        return Err(rollback_constructed_agent(&agent, error).await);
    }
    Ok(AgentHandle { inner: agent })
}

fn publish_constructed_agent(
    app: &AppInner,
    agent: &Arc<AgentInner>,
    candidate: PublicationCandidate,
) -> Result<(), AgentLifecycleError> {
    let _publication = app
        .publication
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if app
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .status
        != AppStatus::Ready
    {
        return Err(AgentLifecycleError::AppClosed);
    }
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
                app.dispatcher.record_callback_panic();
                return Err(AgentLifecycleError::PublicationVeto(
                    "observer panic".into(),
                ));
            }
        }
    }
    let mut app_state = app
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if app_state.status != AppStatus::Ready {
        return Err(AgentLifecycleError::AppClosed);
    }
    let (event, snapshot) = match app.directory_writer.publish(candidate) {
        Ok(directory_update) => directory_update,
        Err(error) => return Err(AgentLifecycleError::Publication(error)),
    };
    if let Some(reservation) = agent
        .notification
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
    {
        publish_notification(reservation, event, snapshot);
    }
    if let Err(error) = app.directory_writer.mark_ready(agent.id, agent.lifecycle) {
        rollback_agent_publication(app, agent).map_err(AgentLifecycleError::Publication)?;
        return Err(AgentLifecycleError::Publication(error));
    }
    if agent
        .publisher
        .set_status(AgentPublicStatus::Ready)
        .is_err()
    {
        rollback_agent_publication(app, agent).map_err(AgentLifecycleError::Publication)?;
        return Err(AgentLifecycleError::EventPublicationFailed);
    }
    agent
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .status = AgentPublicStatus::Ready;
    app_state.agents.insert(agent.id, Arc::clone(agent));
    Ok(())
}

fn rollback_agent_publication(
    app: &AppInner,
    agent: &AgentInner,
) -> Result<(), PublicationDirectoryError> {
    let (event, snapshot) = app.directory_writer.remove(agent.id, agent.lifecycle)?;
    if let Some(reservation) = agent
        .notification
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
    {
        dispose_notification(reservation, event, snapshot);
    }
    Ok(())
}

async fn rollback_constructed_agent(
    agent: &Arc<AgentInner>,
    original: AgentLifecycleError,
) -> AgentLifecycleError {
    agent.publisher.close(AgentPublicStatus::Closed);
    match agent.publisher.drain().await {
        Ok(()) => original,
        Err(error) => AgentLifecycleError::Construction(ComponentBuildError::Runtime(error)),
    }
}

struct CreationReservation {
    app: Weak<AppInner>,
}

impl CreationReservation {
    fn begin(
        app: &Arc<AppInner>,
        operation_id: rust_agent_core::AgentLifecycleOperationId,
        fingerprint: Digest,
    ) -> Result<Self, AgentLifecycleError> {
        let mut state = app
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.status != AppStatus::Ready {
            return Err(AgentLifecycleError::AppClosed);
        }
        let now = app.runtime.now().map_err(|error| {
            AgentLifecycleError::Construction(ComponentBuildError::Runtime(error))
        })?;
        let Some(pending) = state.operations.get(&operation_id) else {
            return Err(AgentLifecycleError::OperationConflict);
        };
        if pending.fingerprint != fingerprint || pending.expires_at <= now {
            state.operations.remove(&operation_id);
            return Err(AgentLifecycleError::OperationConflict);
        }
        let live_or_constructing = state
            .agents
            .len()
            .checked_add(state.creations_in_flight)
            .ok_or(AgentLifecycleError::OperationConflict)?;
        if live_or_constructing >= app.runtime_config.max_live_agents() {
            return Err(AgentLifecycleError::Construction(
                ComponentBuildError::InvalidConfig("maximum live Agent count reached".into()),
            ));
        }
        state.operations.remove(&operation_id);
        state.creations_in_flight = state
            .creations_in_flight
            .checked_add(1)
            .ok_or(AgentLifecycleError::OperationConflict)?;
        Ok(Self {
            app: Arc::downgrade(app),
        })
    }
}

impl Drop for CreationReservation {
    fn drop(&mut self) {
        let Some(app) = self.app.upgrade() else {
            return;
        };
        let waiters = {
            let mut state = app
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.creations_in_flight = state.creations_in_flight.saturating_sub(1);
            take_shutdown_waiters(&mut state.shutdown_waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }
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

fn request_fingerprint(request: &AgentSendRequest) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"rust-agent-live-request-v1\0");
    hasher.update(request.request_id.agent_id().to_canonical_v1_bytes());
    hasher.update(request.request_id.lifecycle().get().to_be_bytes());
    hasher.update(request.request_id.sequence().to_be_bytes());
    hasher.update(request.caller_digest.as_bytes());
    match &request.route {
        ModelRouteSelection::ConfiguredDefault => hasher.update([0]),
        ModelRouteSelection::Explicit(provider) => {
            hasher.update([1]);
            hasher.update((provider.as_str().len() as u64).to_be_bytes());
            hasher.update(provider.as_str().as_bytes());
        }
    }
    hasher.update((request.input.as_str().len() as u64).to_be_bytes());
    hasher.update(request.input.as_str().as_bytes());
    Digest::from_bytes(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        num::{NonZeroU32, NonZeroUsize},
        sync::{
            Barrier,
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc,
        },
        task::{Context, Poll, Wake, Waker},
        thread,
        time::{Duration, Instant},
    };

    use futures_core::Stream;
    use rust_agent_core::{Message, MessageRole};
    use rust_agent_model::{
        LanguageModel, ModelCallContext, ModelCallDraft, ModelEvent, ModelFuture, ModelId,
        ModelParams, ModelProviderBinding, ModelRequest, ModelRequestPurpose, ModelResponse,
        ModelRouteSelection, ModelStream, ProviderKey,
    };
    use rust_agent_runtime_api::{
        AgentEventEnvelope, AgentEventKind, AppHandoffMode, CallId, DisposalEvent,
        GeneratedModelBindingPlan, GeneratedToolConsumerBinding, LifecycleNotificationContext,
        LifecycleObserverFuture, PublicationEvent, PublicationSnapshot, PublicationState,
        PublicationTransactionView, RuntimeAdapterIdentity, RuntimeClock, RuntimeFuture,
        RuntimePrimitiveError, RuntimeSleeper, RuntimeSpawner, RuntimeTaskOwner,
        ToolCallJournalProjection, ToolCallJournalVerifier, begin_composition_assembly,
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

    #[derive(Debug)]
    struct TestRuntime {
        drains: AtomicUsize,
        origin: Instant,
    }

    impl Default for TestRuntime {
        fn default() -> Self {
            Self {
                drains: AtomicUsize::new(0),
                origin: Instant::now(),
            }
        }
    }

    impl RuntimeClock for TestRuntime {
        fn now(&self) -> RuntimeInstant {
            RuntimeInstant::from_monotonic_duration(self.origin.elapsed())
        }
    }

    struct TestSleep {
        deadline: Instant,
        armed: bool,
    }

    impl Future for TestSleep {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            if Instant::now() >= self.deadline {
                return Poll::Ready(());
            }
            if !self.armed {
                self.armed = true;
                let deadline = self.deadline;
                let waker = context.waker().clone();
                thread::spawn(move || {
                    thread::sleep(deadline.saturating_duration_since(Instant::now()));
                    waker.wake();
                });
            }
            Poll::Pending
        }
    }

    impl RuntimeSleeper for TestRuntime {
        fn sleep_until(&self, deadline: RuntimeInstant) -> RuntimeFuture<'static, ()> {
            let remaining = deadline.saturating_duration_since(self.now());
            Box::pin(TestSleep {
                deadline: Instant::now() + remaining,
                armed: false,
            })
        }
    }

    impl RuntimeSpawner for TestRuntime {
        fn spawn(
            &self,
            _owner: RuntimeTaskOwner,
            task: RuntimeFuture<'static, ()>,
        ) -> Result<(), RuntimePrimitiveError> {
            thread::spawn(move || run(task));
            Ok(())
        }

        fn drain(&self, _owner: RuntimeTaskOwner) -> RuntimeFuture<'static, ()> {
            self.drains.fetch_add(1, Ordering::AcqRel);
            Box::pin(async {})
        }
    }

    fn test_runtime() -> RuntimePrimitives {
        test_runtime_with_driver().0
    }

    fn test_runtime_with_driver() -> (RuntimePrimitives, Arc<TestRuntime>) {
        let runtime = Arc::new(TestRuntime::default());
        let clock: Arc<dyn RuntimeClock> = runtime.clone();
        let sleeper: Arc<dyn RuntimeSleeper> = runtime.clone();
        let spawner: Arc<dyn RuntimeSpawner> = runtime.clone();
        (
            RuntimePrimitives::from_adapter(
                RuntimeAdapterIdentity::checked("runtime-test").unwrap(),
                runtime.clone(),
                clock,
                sleeper,
                spawner,
            ),
            runtime,
        )
    }

    #[derive(Debug)]
    struct GatedDrainRuntime {
        drain_started: AtomicBool,
        release: CancellationToken,
        origin: Instant,
    }

    impl Default for GatedDrainRuntime {
        fn default() -> Self {
            Self {
                drain_started: AtomicBool::new(false),
                release: CancellationToken::new(),
                origin: Instant::now(),
            }
        }
    }

    impl RuntimeClock for GatedDrainRuntime {
        fn now(&self) -> RuntimeInstant {
            RuntimeInstant::from_monotonic_duration(self.origin.elapsed())
        }
    }

    impl RuntimeSleeper for GatedDrainRuntime {
        fn sleep_until(&self, deadline: RuntimeInstant) -> RuntimeFuture<'static, ()> {
            let remaining = deadline.saturating_duration_since(self.now());
            Box::pin(TestSleep {
                deadline: Instant::now() + remaining,
                armed: false,
            })
        }
    }

    impl RuntimeSpawner for GatedDrainRuntime {
        fn spawn(
            &self,
            _owner: RuntimeTaskOwner,
            task: RuntimeFuture<'static, ()>,
        ) -> Result<(), RuntimePrimitiveError> {
            thread::spawn(move || run(task));
            Ok(())
        }

        fn drain(&self, _owner: RuntimeTaskOwner) -> RuntimeFuture<'static, ()> {
            self.drain_started.store(true, Ordering::Release);
            let release = self.release.clone();
            Box::pin(async move { release.cancelled().await })
        }
    }

    fn gated_drain_runtime() -> (RuntimePrimitives, Arc<GatedDrainRuntime>) {
        let runtime = Arc::new(GatedDrainRuntime::default());
        (
            RuntimePrimitives::from_adapter(
                RuntimeAdapterIdentity::checked("runtime-gated-drain").unwrap(),
                Arc::clone(&runtime),
                runtime.clone(),
                runtime.clone(),
                runtime.clone(),
            ),
            runtime,
        )
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

    struct RoutedEchoModel {
        key: &'static str,
    }

    impl LanguageModel for RoutedEchoModel {
        fn provider_key(&self) -> ProviderKey {
            ProviderKey::new(self.key).unwrap()
        }

        fn model_id(&self) -> ModelId {
            ModelId::new(format!("{}-v1", self.key)).unwrap()
        }

        fn stream(
            &self,
            _context: ModelCallContext,
            request: ModelRequest,
        ) -> ModelFuture<'_, Result<ModelStream, ModelError>> {
            let key = self.key;
            Box::pin(async move {
                let ContentBlock::Text(input) = &request.messages[0].content[0] else {
                    return Err(ModelError::InvalidRequest("text required"));
                };
                Ok(Box::pin(TestStream(VecDeque::from([
                    Ok(ModelEvent::Delta(format!("{key}:{input}"))),
                    Ok(ModelEvent::Completed(Usage::default())),
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
                    route: request.model_route().clone(),
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
                let response: ModelResponse =
                    context.complete_model_call(&self.model, prepared).await?;
                AgentOutput::from_model_response(response)
            })
        }
    }

    struct ToolAwareTestDriver {
        model: ModelRegistryBinding,
        verifier: ToolCallJournalVerifier,
        proofs: Arc<AtomicUsize>,
    }

    impl AgentDriver for ToolAwareTestDriver {
        fn run<'a>(
            &'a self,
            context: &'a AgentContext,
            request: AgentRequest,
        ) -> AgentFuture<'a, Result<AgentOutput, AgentError>> {
            Box::pin(async move {
                let projection = ToolCallJournalProjection::from_tool_plan(
                    CallId::from_nonzero_u128(1).unwrap(),
                    Digest::from_bytes([41; 32]),
                    Digest::from_bytes([42; 32]),
                    Digest::from_bytes([43; 32]),
                    Digest::from_bytes([44; 32]),
                    Digest::from_bytes([45; 32]),
                    Digest::from_bytes([46; 32]),
                );
                let record_digest = projection.record_digest();
                let proof = context.prepare_tool_call(projection.clone()).await?;
                if !self.verifier.verifies(&proof, &projection, record_digest) {
                    return Err(AgentError::JournalUnavailable);
                }
                self.proofs.fetch_add(1, Ordering::SeqCst);
                let plan = self.model.plan_call(ModelCallDraft {
                    request_id: context.allocate_model_request()?,
                    purpose: ModelRequestPurpose::AgentTurn,
                    route: request.model_route().clone(),
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
                let response = context.complete_model_call(&self.model, prepared).await?;
                AgentOutput::from_model_response(response)
            })
        }
    }

    #[derive(Debug)]
    struct TestScopeFactory;

    impl AgentScopeFactory for TestScopeFactory {
        fn driver_component_identity(&self) -> &'static str {
            "test-scope-factory"
        }

        fn build_driver(
            &self,
            model: ModelRegistryBinding,
            _runtime: RuntimePrimitives,
        ) -> Result<AgentDriverBinding, ComponentBuildError> {
            AgentDriverBinding::from_generated_component(
                self.driver_component_identity(),
                Arc::new(DirectTestDriver { model }),
            )
        }
    }

    #[derive(Debug)]
    struct ToolAwareScopeFactory {
        proofs: Arc<AtomicUsize>,
    }

    impl AgentScopeFactory for ToolAwareScopeFactory {
        fn driver_component_identity(&self) -> &'static str {
            "driver-tools"
        }

        fn tool_consumer_edge(&self) -> Option<(&'static str, &'static str)> {
            Some(("driver-tools", "tool-executor-guarded"))
        }

        fn build_driver(
            &self,
            _model: ModelRegistryBinding,
            _runtime: RuntimePrimitives,
        ) -> Result<AgentDriverBinding, ComponentBuildError> {
            Err(ComponentBuildError::InvalidConfig(
                "tool-aware driver requires its exact generated binding".into(),
            ))
        }

        fn build_driver_with_tools(
            &self,
            model: ModelRegistryBinding,
            tool_binding: Option<GeneratedToolConsumerBinding>,
            _runtime: RuntimePrimitives,
        ) -> Result<AgentDriverBinding, ComponentBuildError> {
            let binding = tool_binding.ok_or_else(|| {
                ComponentBuildError::InvalidConfig(
                    "tool-aware driver is missing its generated binding".into(),
                )
            })?;
            let verifier = binding
                .into_verifier_for_edge(self.driver_component_identity(), "tool-executor-guarded")
                .map_err(|error| ComponentBuildError::InvalidConfig(error.to_string()))?;
            AgentDriverBinding::from_generated_component(
                self.driver_component_identity(),
                Arc::new(ToolAwareTestDriver {
                    model,
                    verifier,
                    proofs: Arc::clone(&self.proofs),
                }),
            )
        }
    }

    #[derive(Debug)]
    struct MismatchedDriverScopeFactory;

    impl AgentScopeFactory for MismatchedDriverScopeFactory {
        fn driver_component_identity(&self) -> &'static str {
            "expected-driver"
        }

        fn build_driver(
            &self,
            model: ModelRegistryBinding,
            _runtime: RuntimePrimitives,
        ) -> Result<AgentDriverBinding, ComponentBuildError> {
            AgentDriverBinding::from_generated_component(
                "substituted-driver",
                Arc::new(DirectTestDriver { model }),
            )
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
        app_with_model_config(model, observers, Phase2RuntimeConfig::default())
    }

    fn app_with_model_config(
        model: ModelProviderBinding,
        observers: Vec<Arc<dyn LifecycleObserver>>,
        runtime_config: Phase2RuntimeConfig,
    ) -> AppHandle {
        app_with_model_config_and_runtime(model, observers, runtime_config, test_runtime())
    }

    fn app_with_model_config_and_runtime(
        model: ModelProviderBinding,
        observers: Vec<Arc<dyn LifecycleObserver>>,
        runtime_config: Phase2RuntimeConfig,
        runtime: RuntimePrimitives,
    ) -> AppHandle {
        let model = ModelRegistry::from_compiled(vec![model], None).unwrap();
        app_with_registry_config_and_runtime(model, observers, runtime_config, runtime)
    }

    fn app_with_registry_config_and_runtime(
        model: ModelRegistry,
        observers: Vec<Arc<dyn LifecycleObserver>>,
        runtime_config: Phase2RuntimeConfig,
        runtime: RuntimePrimitives,
    ) -> AppHandle {
        app_with_registry_config_runtime_and_factory(
            model,
            observers,
            runtime_config,
            runtime,
            Arc::new(TestScopeFactory),
        )
    }

    fn app_with_registry_config_runtime_and_factory(
        model: ModelRegistry,
        observers: Vec<Arc<dyn LifecycleObserver>>,
        runtime_config: Phase2RuntimeConfig,
        runtime: RuntimePrimitives,
        scope_factory: Arc<dyn AgentScopeFactory>,
    ) -> AppHandle {
        let composition = CompositionHash::from_digest(Digest::from_bytes([0; 32]));
        let catalog = Digest::from_bytes([1; 32]);
        let observer_bindings = observers
            .into_iter()
            .enumerate()
            .map(|(index, observer)| {
                LifecycleObserverBinding::from_generated_component(
                    Arc::<str>::from(format!("test-observer-{index}")),
                    observer,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let observer_identities = observer_bindings
            .iter()
            .map(|binding| {
                Arc::<str>::from(
                    binding
                        .generated_component_identity()
                        .expect("test observer bindings carry generated identity"),
                )
            })
            .collect::<Vec<_>>();
        let mut plan = GeneratedModelBindingPlan::checked(
            scope_factory.driver_component_identity(),
            model.generated_provider_identities(),
            observer_identities.clone(),
            Vec::new(),
        )
        .unwrap();
        if let Some((consumer, provider)) = scope_factory.tool_consumer_edge() {
            plan = plan.with_tool_consumer_edge(consumer, provider).unwrap();
        }
        let runtime_owner = runtime
            .claim_generated_composition_owner(composition, catalog, plan)
            .unwrap();
        let binding_assembly = begin_composition_assembly(runtime_owner, composition, catalog)
            .unwrap()
            .finish();
        let handoff = AppHandoffSeal::new(
            AppHandoffMode::Concurrent,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "1111111111111111111111111111111111111111111111111111111111111111",
            Vec::new(),
        )
        .unwrap();
        AppHandle::from_generated(
            composition,
            catalog,
            handoff,
            runtime_config,
            runtime,
            model,
            binding_assembly,
            scope_factory,
            observer_bindings,
        )
        .unwrap()
    }

    #[test]
    fn generated_driver_binding_must_match_the_claimed_consumer_identity() {
        let model = ModelRegistry::from_compiled(
            vec![ModelProviderBinding::from_provider(Arc::new(EchoModel {
                calls: Arc::new(AtomicUsize::new(0)),
            }))],
            None,
        )
        .unwrap();
        let app = app_with_registry_config_runtime_and_factory(
            model,
            Vec::new(),
            Phase2RuntimeConfig::default(),
            test_runtime(),
            Arc::new(MismatchedDriverScopeFactory),
        );
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        assert!(matches!(
            run(app.create_agent(allocated.into_create_request())),
            Err(AgentLifecycleError::JournalAuthority)
        ));
        assert!(app.publication_snapshot().entries().is_empty());
        run(app.shutdown()).unwrap();
    }

    #[test]
    fn generated_agent_context_issues_only_the_exact_tool_edge_proof() {
        let proofs = Arc::new(AtomicUsize::new(0));
        let model = ModelRegistry::from_compiled(
            vec![ModelProviderBinding::from_provider(Arc::new(EchoModel {
                calls: Arc::new(AtomicUsize::new(0)),
            }))],
            None,
        )
        .unwrap();
        let app = app_with_registry_config_runtime_and_factory(
            model,
            Vec::new(),
            Phase2RuntimeConfig::default(),
            test_runtime(),
            Arc::new(ToolAwareScopeFactory {
                proofs: Arc::clone(&proofs),
            }),
        );
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
        let request_id = agent.allocate_turn_request().unwrap();
        let output = run(agent.send(AgentSendRequest::new(
            request_id,
            AgentInput::text("tool-aware").unwrap(),
            Digest::from_bytes([47; 32]),
            None,
        )))
        .unwrap();
        assert_eq!(output.text, "echo:tool-aware");
        assert_eq!(proofs.load(Ordering::SeqCst), 1);
        run(agent.shutdown()).unwrap();
        run(app.shutdown()).unwrap();
    }

    #[test]
    fn agent_context_without_generated_tool_edge_rejects_proof() {
        let app = app(Arc::new(AtomicUsize::new(0)), Vec::new());
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
        assert!(matches!(
            agent.inner.context.tool_call_scope_identity(),
            Err(AgentError::JournalUnavailable)
        ));
        let request_id = agent.allocate_turn_request().unwrap();
        agent
            .inner
            .context
            .begin_turn(request_id, CancellationToken::new(), None);
        let projection = ToolCallJournalProjection::from_tool_plan(
            CallId::from_nonzero_u128(2).unwrap(),
            Digest::from_bytes([51; 32]),
            Digest::from_bytes([52; 32]),
            Digest::from_bytes([53; 32]),
            Digest::from_bytes([54; 32]),
            Digest::from_bytes([55; 32]),
            Digest::from_bytes([56; 32]),
        );
        assert!(matches!(
            run(agent.inner.context.prepare_tool_call(projection)),
            Err(AgentError::JournalUnavailable)
        ));
        assert!(
            agent
                .inner
                .context
                .journal
                .records
                .lock()
                .unwrap()
                .is_empty()
        );
        agent.inner.context.end_turn();
        run(agent.shutdown()).unwrap();
        run(app.shutdown()).unwrap();
    }

    #[test]
    fn request_language_model_response_and_publication_lifecycle() {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = app(Arc::clone(&calls), Vec::new());
        assert!(app.publication_snapshot().entries().is_empty());
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
        assert!(
            app.inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .operations
                .is_empty()
        );
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

    #[test]
    fn model_stream_deltas_are_published_before_final_output() {
        let app = app(Arc::new(AtomicUsize::new(0)), Vec::new());
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
        let mut feed = run(agent.open_event_feed(AgentEventFeedRequest {
            after: None,
            max_buffered_events: NonZeroU32::new(8).unwrap(),
            max_buffered_bytes: NonZeroUsize::new(4096).unwrap(),
        }))
        .unwrap();
        let request_id = agent.allocate_turn_request().unwrap();

        let output = run(agent.send(AgentSendRequest::new(
            request_id,
            AgentInput::text("hello").unwrap(),
            Digest::from_bytes([29; 32]),
            None,
        )))
        .unwrap();
        assert_eq!(output.text, "echo:hello");

        let events = (0..5)
            .map(|_| {
                match run(poll_fn(|context| {
                    Pin::new(&mut feed.stream).poll_next(context)
                })) {
                    Some(Ok(AgentEventStreamItem::Event(event))) => event,
                    other => panic!("expected request event, got {other:?}"),
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            events[0].kind,
            rust_agent_runtime_api::AgentEventKind::RequestStarted
        );
        assert_eq!(
            events[1].kind,
            rust_agent_runtime_api::AgentEventKind::OutputDelta
        );
        assert_eq!(events[1].request_id, Some(request_id));
        assert_eq!(events[1].payload, "echo:hello");
        assert_eq!(
            events[2].kind,
            rust_agent_runtime_api::AgentEventKind::OutputFinal
        );
        assert_eq!(events[2].request_id, Some(request_id));

        drop(feed);
        run(agent.shutdown()).unwrap();
        run(app.shutdown()).unwrap();
    }

    #[test]
    fn explicit_per_request_route_reaches_the_selected_compiled_provider() {
        let model = ModelRegistry::from_compiled(
            vec![
                ModelProviderBinding::from_provider(Arc::new(RoutedEchoModel { key: "alpha" })),
                ModelProviderBinding::from_provider(Arc::new(RoutedEchoModel { key: "beta" })),
            ],
            Some(rust_agent_model::ModelRoutingMode::ExplicitPerRequest),
        )
        .unwrap();
        let app = app_with_registry_config_and_runtime(
            model,
            Vec::new(),
            Phase2RuntimeConfig::default(),
            test_runtime(),
        );
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();

        let missing_route = AgentSendRequest::new(
            agent.allocate_turn_request().unwrap(),
            AgentInput::text("missing").unwrap(),
            Digest::from_bytes([30; 32]),
            None,
        );
        assert_eq!(
            run(agent.send(missing_route)),
            Err(AgentError::Model(ModelError::ModelRouteRequired))
        );

        let explicit_id = agent.allocate_turn_request().unwrap();
        let explicit = AgentSendRequest::new(
            explicit_id,
            AgentInput::text("hello").unwrap(),
            Digest::from_bytes([31; 32]),
            None,
        )
        .with_model_route(ModelRouteSelection::Explicit(
            ProviderKey::new("beta").unwrap(),
        ));
        assert_eq!(run(agent.send(explicit)).unwrap().text, "beta:hello");
        let conflicting_route = AgentSendRequest::new(
            explicit_id,
            AgentInput::text("hello").unwrap(),
            Digest::from_bytes([31; 32]),
            None,
        )
        .with_model_route(ModelRouteSelection::Explicit(
            ProviderKey::new("alpha").unwrap(),
        ));
        assert_eq!(
            run(agent.send(conflicting_route)),
            Err(AgentError::RequestConflict)
        );
        run(agent.shutdown()).unwrap();
        run(app.shutdown()).unwrap();
    }

    #[test]
    fn volatile_lifecycle_operation_table_is_bounded_and_consumed() {
        let app = app(Arc::new(AtomicUsize::new(0)), Vec::new());
        for _ in 0..MAX_PENDING_LIFECYCLE_OPERATIONS {
            let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
            run(app.allocate_agent_operation(sealed)).unwrap();
        }
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        assert!(matches!(
            run(app.allocate_agent_operation(sealed)),
            Err(AgentOperationAllocationError::ResourceExhausted)
        ));
        run(app.shutdown()).unwrap();
    }

    #[test]
    fn volatile_lifecycle_operation_recovery_is_exact_and_single_consumption() {
        let app_handle = app(Arc::new(AtomicUsize::new(0)), Vec::new());
        let sealed =
            run(app_handle.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app_handle.allocate_agent_operation(sealed)).unwrap();
        let operation_id = allocated.operation_id();
        drop(allocated);

        let foreign_app = app(Arc::new(AtomicUsize::new(0)), Vec::new());
        let foreign_draft =
            run(foreign_app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        assert!(matches!(
            run(app_handle.recover_agent_operation(operation_id, foreign_draft)),
            Err(AgentOperationAllocationError::OwnerMismatch)
        ));

        let exact_draft =
            run(app_handle.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let recovered = run(app_handle.recover_agent_operation(operation_id, exact_draft)).unwrap();
        assert_eq!(recovered.operation_id(), operation_id);
        let agent = run(app_handle.create_agent(recovered.into_create_request())).unwrap();

        let consumed_draft =
            run(app_handle.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        assert!(matches!(
            run(app_handle.recover_agent_operation(operation_id, consumed_draft)),
            Err(AgentOperationAllocationError::OperationNotFound)
        ));
        run(agent.shutdown()).unwrap();
        run(app_handle.shutdown()).unwrap();
        run(foreign_app.shutdown()).unwrap();
    }

    struct CountingPublicationObserver {
        published: Arc<AtomicUsize>,
        disposed: Arc<AtomicUsize>,
    }

    impl LifecycleObserver for CountingPublicationObserver {
        fn before_publish(
            &self,
            _event: &PublicationCandidate,
            _view: &PublicationTransactionView<'_>,
        ) -> Result<(), PublicationVeto> {
            Ok(())
        }

        fn published<'a>(
            &'a self,
            _context: LifecycleNotificationContext,
            _event: &'a PublicationEvent,
            _snapshot: &'a PublicationSnapshot,
        ) -> LifecycleObserverFuture<'a> {
            Box::pin(async move {
                self.published.fetch_add(1, Ordering::AcqRel);
                Ok(())
            })
        }

        fn disposed<'a>(
            &'a self,
            _context: LifecycleNotificationContext,
            _event: &'a DisposalEvent,
            _snapshot: &'a PublicationSnapshot,
        ) -> LifecycleObserverFuture<'a> {
            Box::pin(async move {
                self.disposed.fetch_add(1, Ordering::AcqRel);
                Ok(())
            })
        }
    }

    #[test]
    fn ready_event_failure_rolls_back_directory_and_notification_pair() {
        let published = Arc::new(AtomicUsize::new(0));
        let disposed = Arc::new(AtomicUsize::new(0));
        let observer: Arc<dyn LifecycleObserver> = Arc::new(CountingPublicationObserver {
            published: Arc::clone(&published),
            disposed: Arc::clone(&disposed),
        });
        let app = app(Arc::new(AtomicUsize::new(0)), vec![observer]);
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();

        {
            let _publication = app
                .inner
                .publication
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            app.inner
                .directory_writer
                .mark_closing(agent.id(), agent.inner.lifecycle)
                .unwrap();
            let (event, snapshot) = app
                .inner
                .directory_writer
                .remove(agent.id(), agent.inner.lifecycle)
                .unwrap();
            let mut reservation = agent
                .inner
                .notification
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .unwrap();
            dispose_notification(&mut reservation, event, snapshot);
            assert!(
                app.inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .agents
                    .remove(&agent.id())
                    .is_some()
            );
        }
        {
            let mut state = agent
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.status = AgentPublicStatus::Closing;
            state.removed = false;
        }
        *agent
            .inner
            .notification
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(app.inner.dispatcher.reserve_pair().unwrap());
        agent.inner.publisher.set_next_sequence_for_test(u64::MAX);

        let candidate = PublicationCandidate::for_generated_agent(
            agent.id(),
            agent.inner.lifecycle,
            None,
            PublishedSessionMode::Sessionless,
        );
        let error = publish_constructed_agent(&app.inner, &agent.inner, candidate).unwrap_err();
        assert!(matches!(
            &error,
            AgentLifecycleError::EventPublicationFailed
        ));
        assert!(app.publication_snapshot().entries().is_empty());
        assert_eq!(agent.status(), AgentPublicStatus::Closing);
        assert!(
            !app.inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .agents
                .contains_key(&agent.id())
        );
        assert!(matches!(
            run(rollback_constructed_agent(&agent.inner, error)),
            AgentLifecycleError::EventPublicationFailed
        ));

        run(app.shutdown()).unwrap();
        assert_eq!(published.load(Ordering::Acquire), 2);
        assert_eq!(disposed.load(Ordering::Acquire), 2);
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
        let (runtime, runtime_driver) = test_runtime_with_driver();
        let app = app_with_model_config_and_runtime(
            ModelProviderBinding::from_provider(Arc::new(EchoModel {
                calls: Arc::clone(&calls),
            })),
            vec![observer],
            Phase2RuntimeConfig::default(),
            runtime,
        );
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
        assert_eq!(runtime_driver.drains.load(Ordering::Acquire), 1);
        run(app.shutdown()).unwrap();
    }

    struct BeforePublishPanicObserver;

    impl LifecycleObserver for BeforePublishPanicObserver {
        fn before_publish(
            &self,
            _event: &PublicationCandidate,
            _view: &PublicationTransactionView<'_>,
        ) -> Result<(), PublicationVeto> {
            panic!("contained before-publish panic")
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
    fn observer_before_publish_panic_is_diagnosed_and_rolls_back() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observer: Arc<dyn LifecycleObserver> = Arc::new(BeforePublishPanicObserver);
        let (runtime, runtime_driver) = test_runtime_with_driver();
        let app = app_with_model_config_and_runtime(
            ModelProviderBinding::from_provider(Arc::new(EchoModel {
                calls: Arc::clone(&calls),
            })),
            vec![observer],
            Phase2RuntimeConfig::default(),
            runtime,
        );
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();

        assert!(matches!(
            run(app.create_agent(allocated.into_create_request())),
            Err(AgentLifecycleError::PublicationVeto(reason)) if reason == "observer panic"
        ));
        assert!(app.publication_snapshot().entries().is_empty());
        assert_eq!(app.lifecycle_observer_diagnostics().callback_panics(), 1);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(runtime_driver.drains.load(Ordering::Acquire), 1);
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

    struct AgentStateLockProbe {
        agent: Arc<AgentInner>,
        woke: AtomicBool,
        woke_while_locked: AtomicBool,
    }

    impl AgentStateLockProbe {
        fn observe(&self) {
            self.woke.store(true, Ordering::Release);
            if matches!(
                self.agent.state.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ) {
                self.woke_while_locked.store(true, Ordering::Release);
            }
        }
    }

    impl Wake for AgentStateLockProbe {
        fn wake(self: Arc<Self>) {
            self.observe();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.observe();
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
        assert_eq!(
            agent.cancel(request_id, CancelCause::User),
            Ok(CancelOutcome::NotActive)
        );
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
        let active_cancellation = agent
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .requests[&request_id]
            .cancellation
            .clone();
        let probe = Arc::new(AgentStateLockProbe {
            agent: Arc::clone(&agent.inner),
            woke: AtomicBool::new(false),
            woke_while_locked: AtomicBool::new(false),
        });
        let probe_waker = Waker::from(Arc::clone(&probe));
        let mut probe_context = Context::from_waker(&probe_waker);
        let mut cancellation_wait = Box::pin(active_cancellation.cancelled());
        assert!(
            cancellation_wait
                .as_mut()
                .poll(&mut probe_context)
                .is_pending()
        );
        assert_eq!(
            agent.cancel(request_id, CancelCause::User),
            Ok(CancelOutcome::CancelledActive)
        );
        assert!(probe.woke.load(Ordering::Acquire));
        assert!(!probe.woke_while_locked.load(Ordering::Acquire));
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
        assert_eq!(
            agent.cancel(request_id, CancelCause::User),
            Err(AgentCancelError::Closed)
        );
        run(app.shutdown()).unwrap();
    }

    #[test]
    fn dropped_shutdown_future_releases_teardown_ownership() {
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
        let sending_agent = agent.clone();
        let send = thread::spawn(move || {
            run(sending_agent.send(AgentSendRequest::new(
                request_id,
                AgentInput::text("wait").unwrap(),
                Digest::from_bytes([4; 32]),
                None,
            )))
        });
        entered.wait();
        let queued_id = agent.allocate_turn_request().unwrap();
        let queued_agent = agent.clone();
        let queued = thread::spawn(move || {
            run(queued_agent.send(AgentSendRequest::new(
                queued_id,
                AgentInput::text("queued").unwrap(),
                Digest::from_bytes([44; 32]),
                None,
            )))
        });
        while agent
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .queue
            .is_empty()
        {
            thread::yield_now();
        }

        let mut agent_shutdown = agent.shutdown();
        let mut context = Context::from_waker(Waker::noop());
        assert!(agent_shutdown.as_mut().poll(&mut context).is_pending());
        {
            let state = agent
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(state.completed.contains(&queued_id));
            assert!(matches!(
                state.requests.get(&queued_id).map(|slot| &slot.phase),
                Some(RequestPhase::Completed(Err(AgentError::Closed)))
            ));
            assert_eq!(state.shutdown_waiters.len(), 1);
        }
        assert!(matches!(
            run(agent.open_event_feed(AgentEventFeedRequest {
                after: None,
                max_buffered_events: NonZeroU32::new(1).unwrap(),
                max_buffered_bytes: NonZeroUsize::new(1024).unwrap(),
            })),
            Err(AgentEventFeedError::Closed)
        ));
        drop(agent_shutdown);
        assert!(
            agent
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .shutdown_waiters
                .is_empty()
        );

        let mut app_shutdown = app.shutdown();
        assert!(app_shutdown.as_mut().poll(&mut context).is_pending());
        drop(app_shutdown);
        assert!(
            agent
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .shutdown_waiters
                .is_empty()
        );
        assert!(
            app.inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .shutdown_waiters
                .is_empty()
        );

        release.wait();
        assert_eq!(send.join().unwrap(), Err(AgentError::Cancelled));
        assert_eq!(queued.join().unwrap(), Err(AgentError::Closed));
        run(app.shutdown()).unwrap();
        assert_eq!(agent.status(), AgentPublicStatus::Closed);
    }

    #[test]
    fn dropped_app_shutdown_waiter_is_unregistered_before_teardown_ownership() {
        let app = app(Arc::new(AtomicUsize::new(0)), Vec::new());
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let creation =
            CreationReservation::begin(&app.inner, allocated.operation.id(), allocated.fingerprint)
                .unwrap();

        for _ in 0..3 {
            let mut shutdown = app.shutdown();
            let mut context = Context::from_waker(Waker::noop());
            assert!(shutdown.as_mut().poll(&mut context).is_pending());
            assert_eq!(
                app.inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .shutdown_waiters
                    .len(),
                1
            );
            drop(shutdown);
            assert!(
                app.inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .shutdown_waiters
                    .is_empty()
            );
        }

        drop(creation);
        drop(allocated);
        run(app.shutdown()).unwrap();
        assert_eq!(app.status(), AppStatus::Closed);
    }

    struct FirstCallWaitsForCancellation {
        calls: Arc<AtomicUsize>,
    }

    impl LanguageModel for FirstCallWaitsForCancellation {
        fn provider_key(&self) -> ProviderKey {
            ProviderKey::new("wait-first").unwrap()
        }

        fn model_id(&self) -> ModelId {
            ModelId::new("wait-first-v1").unwrap()
        }

        fn stream(
            &self,
            context: ModelCallContext,
            _request: ModelRequest,
        ) -> ModelFuture<'_, Result<ModelStream, ModelError>> {
            let call = self.calls.fetch_add(1, Ordering::AcqRel);
            Box::pin(async move {
                if call == 0 {
                    context.cancellation().cancelled().await;
                    return Err(ModelError::Cancelled);
                }
                Ok(Box::pin(TestStream(VecDeque::from([
                    Ok(ModelEvent::Delta("queued-result".into())),
                    Ok(ModelEvent::Completed(Usage::default())),
                ]))) as ModelStream)
            })
        }
    }

    struct ReleaseModel {
        calls: Arc<AtomicUsize>,
        release: CancellationToken,
    }

    impl LanguageModel for ReleaseModel {
        fn provider_key(&self) -> ProviderKey {
            ProviderKey::new("release").unwrap()
        }

        fn model_id(&self) -> ModelId {
            ModelId::new("release-v1").unwrap()
        }

        fn stream(
            &self,
            _context: ModelCallContext,
            _request: ModelRequest,
        ) -> ModelFuture<'_, Result<ModelStream, ModelError>> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            let release = self.release.clone();
            Box::pin(async move {
                release.cancelled().await;
                Ok(Box::pin(TestStream(VecDeque::from([
                    Ok(ModelEvent::Delta("released".into())),
                    Ok(ModelEvent::Completed(Usage::default())),
                ]))) as ModelStream)
            })
        }
    }

    #[test]
    fn retry_deadlines_are_waiter_local_while_first_admission_fixes_execution_deadline() {
        let calls = Arc::new(AtomicUsize::new(0));
        let release = CancellationToken::new();
        let app = app_with_model(
            ModelProviderBinding::from_provider(Arc::new(ReleaseModel {
                calls: Arc::clone(&calls),
                release: release.clone(),
            })),
            Vec::new(),
        );
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();

        let request_id = agent.allocate_turn_request().unwrap();
        let first_agent = agent.clone();
        let first = thread::spawn(move || {
            run(first_agent.send(AgentSendRequest::new(
                request_id,
                AgentInput::text("same").unwrap(),
                Digest::from_bytes([51; 32]),
                None,
            )))
        });
        while calls.load(Ordering::Acquire) == 0 {
            thread::yield_now();
        }
        let retry_deadline = agent.inner.context.runtime.now().unwrap() + Duration::from_millis(20);
        assert_eq!(
            run(agent.send(AgentSendRequest::new(
                request_id,
                AgentInput::text("same").unwrap(),
                Digest::from_bytes([51; 32]),
                Some(retry_deadline),
            ))),
            Err(AgentError::DeadlineExceeded)
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
        release.cancel();
        assert_eq!(first.join().unwrap().unwrap().text, "released");

        run(agent.shutdown()).unwrap();
        run(app.shutdown()).unwrap();

        let app = app_with_model(
            ModelProviderBinding::from_provider(Arc::new(NeverCompletesModel)),
            Vec::new(),
        );
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
        let first_deadline_id = agent.allocate_turn_request().unwrap();
        let first_deadline = agent.inner.context.runtime.now().unwrap() + Duration::from_millis(50);
        let first_agent = agent.clone();
        let first = thread::spawn(move || {
            run(first_agent.send(AgentSendRequest::new(
                first_deadline_id,
                AgentInput::text("first-deadline").unwrap(),
                Digest::from_bytes([52; 32]),
                Some(first_deadline),
            )))
        });
        while !agent
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .requests
            .contains_key(&first_deadline_id)
        {
            thread::yield_now();
        }
        let later_deadline = agent.inner.context.runtime.now().unwrap() + Duration::from_secs(1);
        let retry_agent = agent.clone();
        let retry = thread::spawn(move || {
            run(retry_agent.send(AgentSendRequest::new(
                first_deadline_id,
                AgentInput::text("first-deadline").unwrap(),
                Digest::from_bytes([52; 32]),
                Some(later_deadline),
            )))
        });
        assert_eq!(first.join().unwrap(), Err(AgentError::DeadlineExceeded));
        assert_eq!(retry.join().unwrap(), Err(AgentError::DeadlineExceeded));

        run(agent.shutdown()).unwrap();
        run(app.shutdown()).unwrap();
    }

    struct CompletionPromotionProbe {
        agent: Arc<AgentInner>,
        next_request: AgentRequestId,
        armed: AtomicBool,
        observed_early_promotion: AtomicBool,
    }

    impl CompletionPromotionProbe {
        fn observe(&self) {
            if self.armed.load(Ordering::Acquire)
                && self
                    .agent
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .active
                    == Some(self.next_request)
            {
                self.observed_early_promotion.store(true, Ordering::Release);
            }
        }
    }

    impl Wake for CompletionPromotionProbe {
        fn wake(self: Arc<Self>) {
            self.observe();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.observe();
        }
    }

    #[test]
    fn terminal_publication_linearizes_before_next_request_promotion() {
        let calls = Arc::new(AtomicUsize::new(0));
        let release = CancellationToken::new();
        let app = app_with_model(
            ModelProviderBinding::from_provider(Arc::new(ReleaseModel {
                calls: Arc::clone(&calls),
                release: release.clone(),
            })),
            Vec::new(),
        );
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
        let mut feed = run(agent.open_event_feed(AgentEventFeedRequest {
            after: None,
            max_buffered_events: NonZeroU32::new(16).unwrap(),
            max_buffered_bytes: NonZeroUsize::new(16 * 1024).unwrap(),
        }))
        .unwrap();

        let first_id = agent.allocate_turn_request().unwrap();
        let first_agent = agent.clone();
        let first = thread::spawn(move || {
            run(first_agent.send(AgentSendRequest::new(
                first_id,
                AgentInput::text("first").unwrap(),
                Digest::from_bytes([53; 32]),
                None,
            )))
        });
        while calls.load(Ordering::Acquire) == 0 {
            thread::yield_now();
        }
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            Pin::new(&mut feed.stream).poll_next(&mut context),
            Poll::Ready(Some(Ok(AgentEventStreamItem::Event(AgentEventEnvelope {
                kind: AgentEventKind::RequestStarted,
                ..
            }))))
        ));

        let second_id = agent.allocate_turn_request().unwrap();
        let second_agent = agent.clone();
        let second = thread::spawn(move || {
            run(second_agent.send(AgentSendRequest::new(
                second_id,
                AgentInput::text("second").unwrap(),
                Digest::from_bytes([54; 32]),
                None,
            )))
        });
        while agent
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .queue
            .is_empty()
        {
            thread::yield_now();
        }
        let probe = Arc::new(CompletionPromotionProbe {
            agent: Arc::clone(&agent.inner),
            next_request: second_id,
            armed: AtomicBool::new(true),
            observed_early_promotion: AtomicBool::new(false),
        });
        let probe_waker = Waker::from(Arc::clone(&probe));
        let mut probe_context = Context::from_waker(&probe_waker);
        assert!(
            Pin::new(&mut feed.stream)
                .poll_next(&mut probe_context)
                .is_pending()
        );
        release.cancel();

        assert!(first.join().unwrap().is_ok());
        assert!(second.join().unwrap().is_ok());
        assert!(!probe.observed_early_promotion.load(Ordering::Acquire));
        run(agent.shutdown()).unwrap();
        run(app.shutdown()).unwrap();
    }

    #[test]
    fn event_sequence_exhaustion_fails_admission_before_provider_side_effect() {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = app(Arc::clone(&calls), Vec::new());
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
        let mut feed = run(agent.open_event_feed(AgentEventFeedRequest {
            after: None,
            max_buffered_events: NonZeroU32::new(4).unwrap(),
            max_buffered_bytes: NonZeroUsize::new(4096).unwrap(),
        }))
        .unwrap();
        agent.inner.publisher.set_next_sequence_for_test(u64::MAX);
        let request_id = agent.allocate_turn_request().unwrap();
        let request = AgentSendRequest::new(
            request_id,
            AgentInput::text("never-dispatched").unwrap(),
            Digest::from_bytes([55; 32]),
            None,
        );
        assert_eq!(
            run(agent.send(request.clone())),
            Err(AgentError::EventPublicationFailed)
        );
        assert_eq!(run(agent.send(request)), Err(AgentError::Closed));
        assert_eq!(agent.status(), AgentPublicStatus::RecoveryRequired);
        assert_eq!(agent.allocate_turn_request(), Err(AgentError::Closed));
        assert_eq!(
            run(poll_fn(
                |context| Pin::new(&mut feed.stream).poll_next(context)
            )),
            Some(Ok(AgentEventStreamItem::Closed {
                final_status: AgentPublicStatus::RecoveryRequired,
            }))
        );
        assert_eq!(calls.load(Ordering::Acquire), 0);
        run(agent.shutdown()).unwrap();
        assert_eq!(agent.status(), AgentPublicStatus::Closed);

        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
        agent
            .inner
            .publisher
            .set_next_sequence_for_test(u64::MAX - 2);
        let request_id = agent.allocate_turn_request().unwrap();
        let request = AgentSendRequest::new(
            request_id,
            AgentInput::text("terminal-publication-fails").unwrap(),
            Digest::from_bytes([56; 32]),
            None,
        );
        assert_eq!(
            run(agent.send(request.clone())),
            Err(AgentError::EventPublicationFailed)
        );
        assert_eq!(run(agent.send(request)), Err(AgentError::Closed));
        assert_eq!(agent.status(), AgentPublicStatus::RecoveryRequired);
        assert_eq!(agent.allocate_turn_request(), Err(AgentError::Closed));
        assert_eq!(calls.load(Ordering::Acquire), 1);
        run(agent.shutdown()).unwrap();
        assert_eq!(agent.status(), AgentPublicStatus::Closed);
        run(app.shutdown()).unwrap();
    }

    #[test]
    fn publication_failure_closes_queued_admission_without_promotion() {
        let calls = Arc::new(AtomicUsize::new(0));
        let release = CancellationToken::new();
        let app = app_with_model(
            ModelProviderBinding::from_provider(Arc::new(ReleaseModel {
                calls: Arc::clone(&calls),
                release: release.clone(),
            })),
            Vec::new(),
        );
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
        agent
            .inner
            .publisher
            .set_next_sequence_for_test(u64::MAX - 2);

        let active_id = agent.allocate_turn_request().unwrap();
        let active_agent = agent.clone();
        let active = thread::spawn(move || {
            run(active_agent.send(AgentSendRequest::new(
                active_id,
                AgentInput::text("active").unwrap(),
                Digest::from_bytes([58; 32]),
                None,
            )))
        });
        while calls.load(Ordering::Acquire) == 0 {
            thread::yield_now();
        }

        let queued_id = agent.allocate_turn_request().unwrap();
        let queued_agent = agent.clone();
        let queued = thread::spawn(move || {
            run(queued_agent.send(AgentSendRequest::new(
                queued_id,
                AgentInput::text("queued").unwrap(),
                Digest::from_bytes([59; 32]),
                None,
            )))
        });
        while agent
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .queue
            .is_empty()
        {
            thread::yield_now();
        }

        release.cancel();
        assert_eq!(
            active.join().unwrap(),
            Err(AgentError::EventPublicationFailed)
        );
        assert_eq!(queued.join().unwrap(), Err(AgentError::Closed));
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(agent.status(), AgentPublicStatus::RecoveryRequired);
        run(agent.shutdown()).unwrap();
        run(app.shutdown()).unwrap();
    }

    #[test]
    fn rejected_request_admission_does_not_consume_waiter_authority() {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = app(Arc::clone(&calls), Vec::new());
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
        let request_id = agent.allocate_turn_request().unwrap();
        let request = AgentSendRequest::new(
            request_id,
            AgentInput::text("accepted").unwrap(),
            Digest::from_bytes([57; 32]),
            None,
        );
        assert_eq!(
            run(agent.send(request.clone())).unwrap().text,
            "echo:accepted"
        );

        agent
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .next_waiter = u64::MAX - 1;
        let conflict = AgentSendRequest::new(
            request_id,
            AgentInput::text("conflict").unwrap(),
            Digest::from_bytes([57; 32]),
            None,
        );
        assert_eq!(run(agent.send(conflict)), Err(AgentError::RequestConflict));
        assert_eq!(
            agent
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .next_waiter,
            u64::MAX - 1
        );

        {
            let mut state = agent
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let slot = state.requests.get_mut(&request_id).unwrap();
            slot.waiters = (1..=MAX_REQUEST_WAITERS as u64)
                .map(|waiter| (waiter, None))
                .collect();
        }
        assert_eq!(run(agent.send(request.clone())), Err(AgentError::Busy));
        {
            let mut state = agent
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(state.next_waiter, u64::MAX - 1);
            state.requests.get_mut(&request_id).unwrap().waiters.clear();
        }

        assert_eq!(run(agent.send(request)).unwrap().text, "echo:accepted");
        assert_eq!(
            agent
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .next_waiter,
            u64::MAX
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
        run(agent.shutdown()).unwrap();
        run(app.shutdown()).unwrap();
    }

    struct NeverCompletesModel;

    impl LanguageModel for NeverCompletesModel {
        fn provider_key(&self) -> ProviderKey {
            ProviderKey::new("never-completes").unwrap()
        }

        fn model_id(&self) -> ModelId {
            ModelId::new("never-completes-v1").unwrap()
        }

        fn stream(
            &self,
            _context: ModelCallContext,
            _request: ModelRequest,
        ) -> ModelFuture<'_, Result<ModelStream, ModelError>> {
            Box::pin(std::future::pending())
        }
    }

    struct QueuedRetryCancellationModel {
        calls: Arc<AtomicUsize>,
        release_second: CancellationToken,
    }

    impl LanguageModel for QueuedRetryCancellationModel {
        fn provider_key(&self) -> ProviderKey {
            ProviderKey::new("queued-retry").unwrap()
        }

        fn model_id(&self) -> ModelId {
            ModelId::new("queued-retry-v1").unwrap()
        }

        fn stream(
            &self,
            context: ModelCallContext,
            _request: ModelRequest,
        ) -> ModelFuture<'_, Result<ModelStream, ModelError>> {
            let call = self.calls.fetch_add(1, Ordering::AcqRel);
            let release_second = self.release_second.clone();
            Box::pin(async move {
                if call == 0 {
                    context.cancellation().cancelled().await;
                    return Err(ModelError::Cancelled);
                }
                release_second.cancelled().await;
                Ok(Box::pin(TestStream(VecDeque::from([
                    Ok(ModelEvent::Delta("retry-result".into())),
                    Ok(ModelEvent::Completed(Usage::default())),
                ]))) as ModelStream)
            })
        }
    }

    #[test]
    fn first_admission_cancellation_lineage_survives_queued_retry_promotion() {
        let calls = Arc::new(AtomicUsize::new(0));
        let release_second = CancellationToken::new();
        let app = app_with_model(
            ModelProviderBinding::from_provider(Arc::new(QueuedRetryCancellationModel {
                calls: Arc::clone(&calls),
                release_second: release_second.clone(),
            })),
            Vec::new(),
        );
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();

        let blocker_id = agent.allocate_turn_request().unwrap();
        let blocker_agent = agent.clone();
        let blocker = thread::spawn(move || {
            run(blocker_agent.send(AgentSendRequest::new(
                blocker_id,
                AgentInput::text("blocker").unwrap(),
                Digest::from_bytes([40; 32]),
                None,
            )))
        });
        while calls.load(Ordering::Acquire) == 0 {
            thread::yield_now();
        }

        let target_id = agent.allocate_turn_request().unwrap();
        let base = AgentSendRequest::new(
            target_id,
            AgentInput::text("target").unwrap(),
            Digest::from_bytes([41; 32]),
            None,
        );
        let first_token = CancellationToken::new();
        let mut first_waiter =
            Box::pin(agent.send(base.clone().with_cancellation(first_token.clone())));
        let mut context = Context::from_waker(Waker::noop());
        assert!(first_waiter.as_mut().poll(&mut context).is_pending());

        let retry_token = CancellationToken::new();
        let retry_wait_token = retry_token.clone();
        let replay_request = base.clone();
        let retry_agent = agent.clone();
        let retry =
            thread::spawn(move || run(retry_agent.send(base.with_cancellation(retry_wait_token))));
        while agent
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .requests
            .get(&target_id)
            .is_none_or(|slot| slot.waiters.len() < 2)
        {
            thread::yield_now();
        }
        drop(first_waiter);

        assert_eq!(
            agent.cancel(blocker_id, CancelCause::User),
            Ok(CancelOutcome::CancelledActive)
        );
        assert_eq!(blocker.join().unwrap(), Err(AgentError::Cancelled));
        while calls.load(Ordering::Acquire) < 2 {
            thread::yield_now();
        }
        retry_token.cancel();
        assert_eq!(retry.join().unwrap(), Err(AgentError::Cancelled));
        release_second.cancel();
        assert_eq!(
            run(agent.send(replay_request)).unwrap().text,
            "retry-result"
        );
        assert!(!first_token.is_cancelled());

        run(agent.shutdown()).unwrap();
        run(app.shutdown()).unwrap();
    }

    #[test]
    fn dropped_active_executors_obey_the_completed_result_window() {
        let app = app_with_model(
            ModelProviderBinding::from_provider(Arc::new(NeverCompletesModel)),
            Vec::new(),
        );
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
        let mut first_request = None;
        let mut context = Context::from_waker(Waker::noop());

        for sequence in 0..=MAX_COMPLETED_REQUESTS {
            let request_id = agent.allocate_turn_request().unwrap();
            let request = AgentSendRequest::new(
                request_id,
                AgentInput::text(format!("request-{sequence}")).unwrap(),
                Digest::from_bytes([42; 32]),
                None,
            );
            if first_request.is_none() {
                first_request = Some(request.clone());
            }
            let mut send = agent.send(request);
            assert!(send.as_mut().poll(&mut context).is_pending());
            drop(send);
            assert!(
                agent
                    .inner
                    .context
                    .execution
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_none()
            );
        }

        let state = agent
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(state.completed.len(), MAX_COMPLETED_REQUESTS);
        assert_eq!(state.requests.len(), MAX_COMPLETED_REQUESTS);
        assert_eq!(state.expired_through, 1);
        drop(state);
        assert_eq!(
            run(agent.send(first_request.unwrap())),
            Err(AgentError::RequestExpired)
        );

        run(agent.shutdown()).unwrap();
        run(app.shutdown()).unwrap();
    }

    #[test]
    fn allocated_unsubmitted_requests_survive_out_of_order_completion_eviction() {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = app(Arc::clone(&calls), Vec::new());
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
        let delayed = agent.allocate_turn_request().unwrap();

        for sequence in 0..=MAX_COMPLETED_REQUESTS {
            let request_id = agent.allocate_turn_request().unwrap();
            run(agent.send(AgentSendRequest::new(
                request_id,
                AgentInput::text(format!("completed-{sequence}")).unwrap(),
                Digest::from_bytes([43; 32]),
                None,
            )))
            .unwrap();
        }

        assert!(
            agent
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .expired_through
                >= 2
        );
        assert_eq!(
            run(agent.send(AgentSendRequest::new(
                delayed,
                AgentInput::text("delayed").unwrap(),
                Digest::from_bytes([44; 32]),
                None,
            )))
            .unwrap()
            .text,
            "echo:delayed"
        );
        assert_eq!(calls.load(Ordering::Acquire), MAX_COMPLETED_REQUESTS + 2);

        run(agent.shutdown()).unwrap();
        run(app.shutdown()).unwrap();
    }

    #[test]
    fn unsubmitted_request_identity_reservations_are_bounded() {
        let app = app(Arc::new(AtomicUsize::new(0)), Vec::new());
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
        let mut first = None;
        for _ in 0..MAX_ALLOCATED_UNSUBMITTED_REQUESTS {
            let request_id = agent.allocate_turn_request().unwrap();
            first.get_or_insert(request_id);
        }
        assert_eq!(agent.allocate_turn_request(), Err(AgentError::Busy));

        run(agent.send(AgentSendRequest::new(
            first.unwrap(),
            AgentInput::text("release-reservation").unwrap(),
            Digest::from_bytes([45; 32]),
            None,
        )))
        .unwrap();
        assert!(agent.allocate_turn_request().is_ok());

        run(agent.shutdown()).unwrap();
        run(app.shutdown()).unwrap();
    }

    #[test]
    fn admission_retry_completion_deadline_and_shutdown_are_bounded() {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = app_with_model(
            ModelProviderBinding::from_provider(Arc::new(FirstCallWaitsForCancellation {
                calls: Arc::clone(&calls),
            })),
            Vec::new(),
        );
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();

        let first_id = agent.allocate_turn_request().unwrap();
        let first_request = AgentSendRequest::new(
            first_id,
            AgentInput::text("first").unwrap(),
            Digest::from_bytes([6; 32]),
            None,
        );
        let first_agent = agent.clone();
        let first_copy = first_request.clone();
        let first = thread::spawn(move || run(first_agent.send(first_copy)));
        while calls.load(Ordering::Acquire) == 0 {
            thread::yield_now();
        }

        let retry_agent = agent.clone();
        let retry_copy = first_request.clone();
        let retry = thread::spawn(move || run(retry_agent.send(retry_copy)));
        let second_id = agent.allocate_turn_request().unwrap();
        let second_request = AgentSendRequest::new(
            second_id,
            AgentInput::text("second").unwrap(),
            Digest::from_bytes([7; 32]),
            None,
        );
        let second_agent = agent.clone();
        let second = thread::spawn(move || run(second_agent.send(second_request)));
        while agent
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .queue
            .is_empty()
        {
            thread::yield_now();
        }
        let cancelled_id = agent.allocate_turn_request().unwrap();
        let waiter_cancellation = CancellationToken::new();
        let cancelled_request = AgentSendRequest::new(
            cancelled_id,
            AgentInput::text("cancel-while-queued").unwrap(),
            Digest::from_bytes([10; 32]),
            None,
        )
        .with_cancellation(waiter_cancellation.clone());
        let cancelled_agent = agent.clone();
        let cancelled = thread::spawn(move || run(cancelled_agent.send(cancelled_request)));
        while agent
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .queue
            .len()
            < 2
        {
            thread::yield_now();
        }
        waiter_cancellation.cancel();
        assert_eq!(cancelled.join().unwrap(), Err(AgentError::Cancelled));
        assert_eq!(
            agent
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .queue
                .len(),
            1
        );

        let queued_deadline_id = agent.allocate_turn_request().unwrap();
        let queued_deadline = AgentSendRequest::new(
            queued_deadline_id,
            AgentInput::text("deadline-while-queued").unwrap(),
            Digest::from_bytes([11; 32]),
            Some(agent.inner.context.runtime.now().unwrap() + Duration::from_millis(20)),
        );
        let deadline_agent = agent.clone();
        let expired = thread::spawn(move || run(deadline_agent.send(queued_deadline)));
        assert_eq!(expired.join().unwrap(), Err(AgentError::DeadlineExceeded));
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(
            agent
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .queue
                .len(),
            1
        );
        assert_eq!(
            agent.cancel(second_id, CancelCause::User),
            Ok(CancelOutcome::NotActive)
        );
        assert_eq!(
            agent.cancel(first_id, CancelCause::User),
            Ok(CancelOutcome::CancelledActive)
        );
        assert_eq!(first.join().unwrap(), Err(AgentError::Cancelled));
        assert_eq!(retry.join().unwrap(), Err(AgentError::Cancelled));
        assert_eq!(second.join().unwrap().unwrap().text, "queued-result");
        assert_eq!(calls.load(Ordering::Acquire), 2);
        assert_eq!(
            run(agent.send(first_request.clone())),
            Err(AgentError::Cancelled)
        );
        let conflict = AgentSendRequest::new(
            first_id,
            AgentInput::text("different").unwrap(),
            Digest::from_bytes([6; 32]),
            None,
        );
        assert_eq!(run(agent.send(conflict)), Err(AgentError::RequestConflict));

        let deadline_id = agent.allocate_turn_request().unwrap();
        let deadline = AgentSendRequest::new(
            deadline_id,
            AgentInput::text("expired").unwrap(),
            Digest::from_bytes([8; 32]),
            Some(
                agent
                    .inner
                    .context
                    .runtime
                    .now()
                    .unwrap()
                    .checked_sub(Duration::from_millis(1))
                    .unwrap(),
            ),
        );
        assert_eq!(run(agent.send(deadline)), Err(AgentError::DeadlineExceeded));
        assert_eq!(calls.load(Ordering::Acquire), 2);
        run(agent.shutdown()).unwrap();
        run(app.shutdown()).unwrap();
    }

    #[test]
    fn runtime_config_and_agent_resource_budgets_fail_closed() {
        assert!(matches!(
            AgentResourceBudget::checked(0, 1, 1, Duration::from_millis(1)),
            Err(Phase2RuntimeConfigError::Zero("max_event_feed_subscribers"))
        ));
        assert!(AgentResourceBudget::checked(1, 1, 1, MAX_EVENT_FEED_IDLE_TIMEOUT,).is_ok());
        assert!(matches!(
            AgentResourceBudget::checked(
                1,
                1,
                1,
                MAX_EVENT_FEED_IDLE_TIMEOUT + Duration::from_nanos(1),
            ),
            Err(Phase2RuntimeConfigError::AboveHardCeiling {
                field: "event_feed_idle_timeout_ms",
                ..
            })
        ));
        let budget = AgentResourceBudget::checked(1, 4, 4096, Duration::from_secs(1)).unwrap();
        assert!(
            Phase2RuntimeConfig::checked(
                MAX_APP_SHUTDOWN_TIMEOUT,
                1,
                MAX_LIFECYCLE_OBSERVER_TIMEOUT,
                2,
                budget.clone(),
            )
            .is_ok()
        );
        assert!(matches!(
            Phase2RuntimeConfig::checked(
                MAX_APP_SHUTDOWN_TIMEOUT + Duration::from_nanos(1),
                1,
                MAX_LIFECYCLE_OBSERVER_TIMEOUT,
                2,
                budget.clone(),
            ),
            Err(Phase2RuntimeConfigError::AboveHardCeiling {
                field: "shutdown_timeout_ms",
                ..
            })
        ));
        assert!(matches!(
            Phase2RuntimeConfig::checked(
                MAX_APP_SHUTDOWN_TIMEOUT,
                1,
                MAX_LIFECYCLE_OBSERVER_TIMEOUT + Duration::from_nanos(1),
                2,
                budget.clone(),
            ),
            Err(Phase2RuntimeConfigError::AboveHardCeiling {
                field: "lifecycle_observer_timeout_ms",
                ..
            })
        ));
        assert!(matches!(
            Phase2RuntimeConfig::checked(
                Duration::from_secs(1),
                1,
                Duration::from_millis(10),
                1,
                budget.clone(),
            ),
            Err(Phase2RuntimeConfigError::NotificationCapacityTooSmall { minimum: 2, .. })
        ));
        let config = Phase2RuntimeConfig::checked(
            Duration::from_secs(1),
            1,
            Duration::from_millis(10),
            2,
            budget,
        )
        .unwrap();
        let app = app_with_model_config(
            ModelProviderBinding::from_provider(Arc::new(EchoModel {
                calls: Arc::new(AtomicUsize::new(0)),
            })),
            Vec::new(),
            config,
        );
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        assert!(matches!(
            run(app.create_agent(allocated.into_create_request())),
            Err(AgentLifecycleError::Construction(
                ComponentBuildError::InvalidConfig(_)
            ))
        ));
        run(agent.shutdown()).unwrap();
        run(app.shutdown()).unwrap();
    }

    struct BlockingPublishObserver {
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
    }

    impl LifecycleObserver for BlockingPublishObserver {
        fn before_publish(
            &self,
            _event: &PublicationCandidate,
            _view: &PublicationTransactionView<'_>,
        ) -> Result<(), PublicationVeto> {
            self.entered.wait();
            self.release.wait();
            Ok(())
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
    fn app_owner_retains_agents_and_create_shutdown_race_rolls_back() {
        let calls = Arc::new(AtomicUsize::new(0));
        let first_app = app(Arc::clone(&calls), Vec::new());
        let sealed =
            run(first_app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(first_app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(first_app.create_agent(allocated.into_create_request())).unwrap();
        drop(agent);
        assert_eq!(first_app.publication_snapshot().entries().len(), 1);
        run(first_app.shutdown()).unwrap();
        assert!(first_app.publication_snapshot().entries().is_empty());

        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let observer: Arc<dyn LifecycleObserver> = Arc::new(BlockingPublishObserver {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        let app = app(calls, vec![observer]);
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let create_app = app.clone();
        let create =
            thread::spawn(move || run(create_app.create_agent(allocated.into_create_request())));
        entered.wait();
        let shutdown_app = app.clone();
        let shutdown = thread::spawn(move || run(shutdown_app.shutdown()));
        let deadline = Instant::now() + Duration::from_secs(1);
        while app.status() == AppStatus::Ready && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(app.status(), AppStatus::Closing);
        release.wait();
        assert!(matches!(
            create.join().unwrap(),
            Err(AgentLifecycleError::AppClosed)
        ));
        assert_eq!(shutdown.join().unwrap(), Ok(()));
        assert!(app.publication_snapshot().entries().is_empty());
    }

    #[test]
    fn app_owner_retains_an_agent_until_concurrent_teardown_has_drained() {
        let calls = Arc::new(AtomicUsize::new(0));
        let published = Arc::new(AtomicUsize::new(0));
        let disposed = Arc::new(AtomicUsize::new(0));
        let observer: Arc<dyn LifecycleObserver> = Arc::new(CountingPublicationObserver {
            published: Arc::clone(&published),
            disposed: Arc::clone(&disposed),
        });
        let (runtime, drain) = gated_drain_runtime();
        let app = app_with_model_config_and_runtime(
            ModelProviderBinding::from_provider(Arc::new(EchoModel { calls })),
            vec![observer],
            Phase2RuntimeConfig::default(),
            runtime,
        );
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
        let agent_id = agent.id();
        let shutdown_agent = agent.clone();
        let agent_shutdown = thread::spawn(move || run(shutdown_agent.shutdown()));

        while !drain.drain_started.load(Ordering::Acquire) {
            thread::yield_now();
        }
        assert!(
            app.inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .agents
                .contains_key(&agent_id)
        );
        let snapshot = app.publication_snapshot();
        assert_eq!(snapshot.entries().len(), 1);
        assert_eq!(snapshot.entries()[0].state(), PublicationState::Closing);
        assert_eq!(disposed.load(Ordering::Acquire), 0);

        let (result_sender, result_receiver) = mpsc::channel();
        let shutdown_app = app.clone();
        let app_shutdown = thread::spawn(move || {
            result_sender.send(run(shutdown_app.shutdown())).unwrap();
        });
        assert!(matches!(
            result_receiver.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        drain.release.cancel();
        assert_eq!(agent_shutdown.join().unwrap(), Ok(()));
        assert_eq!(
            result_receiver.recv_timeout(Duration::from_secs(1)),
            Ok(Ok(()))
        );
        app_shutdown.join().unwrap();
        assert!(app.publication_snapshot().entries().is_empty());
        assert_eq!(published.load(Ordering::Acquire), 1);
        assert_eq!(disposed.load(Ordering::Acquire), 1);
        assert_eq!(agent.status(), AgentPublicStatus::Closed);
        assert_eq!(app.status(), AppStatus::Closed);
    }

    #[test]
    fn app_shutdown_closes_admission_for_all_agents_before_draining_any_agent() {
        let calls = Arc::new(AtomicUsize::new(0));
        let (runtime, drain) = gated_drain_runtime();
        let app = app_with_model_config_and_runtime(
            ModelProviderBinding::from_provider(Arc::new(EchoModel { calls })),
            Vec::new(),
            Phase2RuntimeConfig::default(),
            runtime,
        );
        let first_sealed =
            run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let first_allocated = run(app.allocate_agent_operation(first_sealed)).unwrap();
        let first = run(app.create_agent(first_allocated.into_create_request())).unwrap();
        let second_sealed =
            run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let second_allocated = run(app.allocate_agent_operation(second_sealed)).unwrap();
        let second = run(app.create_agent(second_allocated.into_create_request())).unwrap();
        let in_flight_sealed =
            run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let in_flight = run(app.allocate_agent_operation(in_flight_sealed)).unwrap();
        let creation =
            CreationReservation::begin(&app.inner, in_flight.operation.id(), in_flight.fingerprint)
                .unwrap();
        let shutdown_app = app.clone();
        let shutdown = thread::spawn(move || run(shutdown_app.shutdown()));

        let closing_deadline = Instant::now() + Duration::from_secs(1);
        while (first.status() == AgentPublicStatus::Ready
            || second.status() == AgentPublicStatus::Ready)
            && Instant::now() < closing_deadline
        {
            thread::yield_now();
        }

        assert_eq!(app.status(), AppStatus::Closing);
        assert_eq!(first.status(), AgentPublicStatus::Closing);
        assert_eq!(second.status(), AgentPublicStatus::Closing);
        assert!(!drain.drain_started.load(Ordering::Acquire));
        assert_eq!(second.allocate_turn_request(), Err(AgentError::Closed));
        assert_eq!(
            second.allocate_command_invocation(),
            Err(CommandError::Closed)
        );
        assert!(matches!(
            run(second.open_event_feed(AgentEventFeedRequest {
                after: None,
                max_buffered_events: NonZeroU32::new(1).unwrap(),
                max_buffered_bytes: NonZeroUsize::new(1024).unwrap(),
            })),
            Err(AgentEventFeedError::Closed)
        ));

        drop(creation);
        drop(in_flight);
        while !drain.drain_started.load(Ordering::Acquire) {
            thread::yield_now();
        }
        drain.release.cancel();
        assert_eq!(shutdown.join().unwrap(), Ok(()));
        assert_eq!(first.status(), AgentPublicStatus::Closed);
        assert_eq!(second.status(), AgentPublicStatus::Closed);
        assert_eq!(app.status(), AppStatus::Closed);
    }
}
