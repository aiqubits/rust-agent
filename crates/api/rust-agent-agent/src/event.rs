use std::{
    collections::VecDeque,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll, Waker},
};

use futures_core::Stream;
use rust_agent_core::AgentId;
use rust_agent_runtime_api::{
    AgentEventCursor, AgentEventEnvelope, AgentEventFeedBudgetResource, AgentEventFeedError,
    AgentEventKind, AgentLifecycleNonce, AgentPublicStatus, CancellationToken, RuntimeInstant,
    RuntimePrimitiveError, RuntimePrimitives, RuntimeTaskOwner,
};

use crate::{AgentError, AgentOutput, AgentRequestId, AgentResourceBudget};

const HISTORY_EVENTS: usize = 128;
const HISTORY_BYTES: usize = 256 * 1024;
const EVENT_ENVELOPE_ACCOUNTING_BYTES: usize = 64;
pub const MAX_AGENT_EVENT_PAYLOAD_BYTES: usize = HISTORY_BYTES - EVENT_ENVELOPE_ACCOUNTING_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventPublishError {
    Closed,
    SequenceExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentEventFeedRequest {
    pub after: Option<AgentEventCursor>,
    pub max_buffered_events: NonZeroU32,
    pub max_buffered_bytes: NonZeroUsize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentLiveBaseline {
    pub lifecycle: AgentLifecycleNonce,
    pub status: AgentPublicStatus,
    pub active_request: Option<AgentRequestId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentEventBaseline {
    Sessionless {
        live: AgentLiveBaseline,
        first_live: AgentEventCursor,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentEventStreamItem {
    Event(AgentEventEnvelope),
    Lagged {
        last_delivered: Option<AgentEventCursor>,
    },
    Closed {
        final_status: AgentPublicStatus,
    },
}

pub struct AgentEventFeed {
    pub baseline: AgentEventBaseline,
    pub stream: AgentEventStream,
}

impl std::fmt::Debug for AgentEventFeed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentEventFeed")
            .field("baseline", &self.baseline)
            .field("stream", &self.stream)
            .finish()
    }
}

pub struct AgentEventStream {
    queue: Arc<FeedQueue>,
    publisher: Weak<EventPublisher>,
    id: u64,
}

impl std::fmt::Debug for AgentEventStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AgentEventStream(<bounded>)")
    }
}

impl Stream for AgentEventStream {
    type Item = Result<AgentEventStreamItem, AgentEventFeedError>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut state = self
            .queue
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(publisher) = self.publisher.upgrade()
            && let Ok(now) = publisher.runtime.now()
        {
            state.last_polled_at = now;
        }
        if state.done {
            return Poll::Ready(None);
        }
        if let Some(item) = state.items.pop_front() {
            state.buffered_bytes = state
                .buffered_bytes
                .saturating_sub(stream_item_bytes(&item));
            if let AgentEventStreamItem::Event(event) = &item {
                state.last_delivered = Some(event.cursor);
            }
            return Poll::Ready(Some(Ok(item)));
        }
        if let Some(item) = state.terminal.take() {
            state.done = true;
            return Poll::Ready(Some(Ok(item)));
        }
        if self.publisher.strong_count() == 0 {
            Poll::Ready(None)
        } else {
            state.waker = Some(context.waker().clone());
            Poll::Pending
        }
    }
}

impl Drop for AgentEventStream {
    fn drop(&mut self) {
        if let Some(publisher) = self.publisher.upgrade() {
            publisher.release(self.id);
        }
    }
}

struct FeedQueue {
    state: Mutex<FeedQueueState>,
    max_events: usize,
    max_bytes: usize,
}

struct FeedQueueState {
    items: VecDeque<AgentEventStreamItem>,
    buffered_bytes: usize,
    terminal: Option<AgentEventStreamItem>,
    done: bool,
    last_delivered: Option<AgentEventCursor>,
    last_polled_at: RuntimeInstant,
    waker: Option<Waker>,
}

struct Subscriber {
    id: u64,
    queue: Weak<FeedQueue>,
    reserved_events: u64,
    reserved_bytes: u64,
}

struct PublisherState {
    next_sequence: u64,
    next_subscriber: u64,
    history: VecDeque<AgentEventEnvelope>,
    history_bytes: usize,
    subscribers: Vec<Subscriber>,
    reserved_events: u64,
    reserved_bytes: u64,
    closed: bool,
    live: AgentLiveBaseline,
}

pub(crate) struct EventPublisher {
    agent_id: AgentId,
    lifecycle: AgentLifecycleNonce,
    budget: AgentResourceBudget,
    runtime: RuntimePrimitives,
    task_owner: RuntimeTaskOwner,
    shutdown: CancellationToken,
    state: Mutex<PublisherState>,
}

impl Drop for EventPublisher {
    fn drop(&mut self) {
        let mut wake = Vec::new();
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.closed {
            close_locked(state, AgentPublicStatus::Closed, &mut wake);
        }
        self.shutdown.cancel();
        wake_all(wake);
    }
}

impl EventPublisher {
    pub(crate) fn new(
        agent_id: AgentId,
        lifecycle: AgentLifecycleNonce,
        status: AgentPublicStatus,
        budget: AgentResourceBudget,
        runtime: RuntimePrimitives,
    ) -> Result<Arc<Self>, RuntimePrimitiveError> {
        let task_owner = runtime.new_task_owner()?;
        let publisher = Arc::new(Self {
            agent_id,
            lifecycle,
            budget,
            runtime,
            task_owner,
            shutdown: CancellationToken::new(),
            state: Mutex::new(PublisherState {
                next_sequence: 1,
                next_subscriber: 1,
                history: VecDeque::new(),
                history_bytes: 0,
                subscribers: Vec::new(),
                reserved_events: 0,
                reserved_bytes: 0,
                closed: false,
                live: AgentLiveBaseline {
                    lifecycle,
                    status,
                    active_request: None,
                },
            }),
        });
        publisher.spawn_idle_reaper()?;
        Ok(publisher)
    }

    #[cfg(test)]
    pub(crate) fn publish(&self, kind: AgentEventKind, payload: String) {
        let mut wake = Vec::new();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.publish_locked(&mut state, None, kind, payload, &mut wake)
            .expect("test publisher must remain open");
        drop(state);
        wake_all(wake);
    }

    pub(crate) fn begin_request(
        &self,
        request_id: AgentRequestId,
    ) -> Result<(), EventPublishError> {
        let mut wake = Vec::new();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.live.active_request = Some(request_id);
        let result = self.publish_locked(
            &mut state,
            Some(request_id),
            AgentEventKind::RequestStarted,
            String::new(),
            &mut wake,
        );
        drop(state);
        if result.is_err() {
            self.shutdown.cancel();
        }
        wake_all(wake);
        result
    }

    pub(crate) fn output_delta(
        &self,
        request_id: AgentRequestId,
        payload: String,
    ) -> Result<(), EventPublishError> {
        let mut wake = Vec::new();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = self.publish_locked(
            &mut state,
            Some(request_id),
            AgentEventKind::OutputDelta,
            payload,
            &mut wake,
        );
        drop(state);
        if result.is_err() {
            self.shutdown.cancel();
        }
        wake_all(wake);
        result
    }

    pub(crate) fn finish_request(
        &self,
        request_id: AgentRequestId,
        result: &Result<AgentOutput, AgentError>,
    ) -> Result<(), EventPublishError> {
        let mut wake = Vec::new();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let publish_result = match result {
            Ok(output) => (|| {
                if !output.text.is_empty() {
                    self.publish_locked(
                        &mut state,
                        Some(request_id),
                        AgentEventKind::OutputFinal,
                        output.text.clone(),
                        &mut wake,
                    )?;
                }
                self.publish_locked(
                    &mut state,
                    Some(request_id),
                    AgentEventKind::Usage,
                    format!(
                        "input={};output={}",
                        output.usage.input_tokens, output.usage.output_tokens
                    ),
                    &mut wake,
                )?;
                self.publish_locked(
                    &mut state,
                    Some(request_id),
                    AgentEventKind::RequestCompleted,
                    String::new(),
                    &mut wake,
                )
            })(),
            Err(AgentError::Cancelled | AgentError::DeadlineExceeded) => self.publish_locked(
                &mut state,
                Some(request_id),
                AgentEventKind::RequestCancelled,
                String::new(),
                &mut wake,
            ),
            Err(error) => self.publish_locked(
                &mut state,
                Some(request_id),
                AgentEventKind::RequestFailed,
                error.to_string(),
                &mut wake,
            ),
        };
        if publish_result.is_ok() && state.live.active_request == Some(request_id) {
            state.live.active_request = None;
        }
        drop(state);
        if publish_result.is_err() {
            self.shutdown.cancel();
        }
        wake_all(wake);
        publish_result
    }

    pub(crate) fn set_status(&self, status: AgentPublicStatus) -> Result<(), EventPublishError> {
        let mut wake = Vec::new();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.live.status = status;
        let result = self.publish_locked(
            &mut state,
            None,
            AgentEventKind::StatusChanged,
            format!("{status:?}"),
            &mut wake,
        );
        drop(state);
        if result.is_err() {
            self.shutdown.cancel();
        }
        wake_all(wake);
        result
    }

    fn publish_locked(
        &self,
        state: &mut PublisherState,
        request_id: Option<AgentRequestId>,
        kind: AgentEventKind,
        mut payload: String,
        wake: &mut Vec<Waker>,
    ) -> Result<(), EventPublishError> {
        if state.closed {
            return Err(EventPublishError::Closed);
        }
        let Some(sequence) = NonZeroU64::new(state.next_sequence) else {
            close_locked(state, AgentPublicStatus::RecoveryRequired, wake);
            return Err(EventPublishError::SequenceExhausted);
        };
        let Some(next_sequence) = state.next_sequence.checked_add(1) else {
            close_locked(state, AgentPublicStatus::RecoveryRequired, wake);
            return Err(EventPublishError::SequenceExhausted);
        };
        state.next_sequence = next_sequence;
        truncate_utf8(&mut payload, MAX_AGENT_EVENT_PAYLOAD_BYTES);
        let event = AgentEventEnvelope {
            cursor: AgentEventCursor::from_parts(self.agent_id, self.lifecycle, sequence),
            request_id,
            kind,
            payload,
        };
        state.history_bytes = state.history_bytes.saturating_add(event_bytes(&event));
        state.history.push_back(event.clone());
        while state.history.len() > HISTORY_EVENTS || state.history_bytes > HISTORY_BYTES {
            if let Some(removed) = state.history.pop_front() {
                state.history_bytes = state.history_bytes.saturating_sub(event_bytes(&removed));
            } else {
                break;
            }
        }
        let subscribers = std::mem::take(&mut state.subscribers);
        for subscriber in subscribers {
            let Some(queue) = subscriber.queue.upgrade() else {
                state.reserved_events = state
                    .reserved_events
                    .saturating_sub(subscriber.reserved_events);
                state.reserved_bytes = state
                    .reserved_bytes
                    .saturating_sub(subscriber.reserved_bytes);
                continue;
            };
            let (keep, waker) = enqueue_event(&queue, event.clone());
            wake.extend(waker);
            if keep {
                state.subscribers.push(subscriber);
            } else {
                state.reserved_events = state
                    .reserved_events
                    .saturating_sub(subscriber.reserved_events);
                state.reserved_bytes = state
                    .reserved_bytes
                    .saturating_sub(subscriber.reserved_bytes);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn set_next_sequence_for_test(&self, next_sequence: u64) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .next_sequence = next_sequence;
    }

    pub(crate) fn open(
        self: &Arc<Self>,
        request: AgentEventFeedRequest,
    ) -> Result<AgentEventFeed, AgentEventFeedError> {
        let requested_events = u64::from(request.max_buffered_events.get());
        let requested_bytes = u64::try_from(request.max_buffered_bytes.get()).unwrap_or(u64::MAX);
        let now = self
            .runtime
            .now()
            .map_err(|_| AgentEventFeedError::RuntimeUnavailable)?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let subscribers = std::mem::take(&mut state.subscribers);
        for subscriber in subscribers {
            if subscriber.queue.strong_count() == 0 {
                state.reserved_events = state
                    .reserved_events
                    .saturating_sub(subscriber.reserved_events);
                state.reserved_bytes = state
                    .reserved_bytes
                    .saturating_sub(subscriber.reserved_bytes);
            } else {
                state.subscribers.push(subscriber);
            }
        }
        if state.closed {
            return Err(AgentEventFeedError::Closed);
        }
        check_budget(
            AgentEventFeedBudgetResource::SubscriberCount,
            state.subscribers.len() as u64 + 1,
            u64::from(self.budget.max_event_feed_subscribers()),
        )?;
        check_budget(
            AgentEventFeedBudgetResource::BufferedEvents,
            state.reserved_events.saturating_add(requested_events),
            u64::from(self.budget.max_event_feed_buffered_events_total()),
        )?;
        check_budget(
            AgentEventFeedBudgetResource::BufferedBytes,
            state.reserved_bytes.saturating_add(requested_bytes),
            self.budget.max_event_feed_buffered_bytes_total() as u64,
        )?;
        if let Some(after) = request.after {
            if after.agent_id() != self.agent_id {
                return Err(AgentEventFeedError::CursorFromDifferentAgent);
            }
            if after.lifecycle() != self.lifecycle {
                return Err(AgentEventFeedError::StaleLifecycle);
            }
            if after.value() >= state.next_sequence {
                return Err(AgentEventFeedError::InvalidLimit);
            }
            let requested_next = after.value().saturating_add(1);
            match state.history.front() {
                Some(oldest) if requested_next < oldest.cursor.value() => {
                    return Err(AgentEventFeedError::CursorExpired {
                        oldest_available: Some(oldest.cursor),
                    });
                }
                None if requested_next < state.next_sequence => {
                    return Err(AgentEventFeedError::CursorExpired {
                        oldest_available: None,
                    });
                }
                Some(_) | None => {}
            }
        }
        let id = state.next_subscriber;
        state.next_subscriber = state
            .next_subscriber
            .checked_add(1)
            .ok_or(AgentEventFeedError::Closed)?;
        let queue = Arc::new(FeedQueue {
            state: Mutex::new(FeedQueueState {
                items: VecDeque::new(),
                buffered_bytes: 0,
                terminal: None,
                done: false,
                last_delivered: request.after,
                last_polled_at: now,
                waker: None,
            }),
            max_events: request.max_buffered_events.get() as usize,
            max_bytes: request.max_buffered_bytes.get(),
        });
        let sequence = NonZeroU64::new(state.next_sequence).ok_or(AgentEventFeedError::Closed)?;
        let mut wake = Vec::new();
        if let Some(after) = request.after {
            for event in state
                .history
                .iter()
                .filter(|event| event.cursor.value() > after.value())
            {
                let (keep, waker) = enqueue_event(&queue, event.clone());
                wake.extend(waker);
                if !keep {
                    break;
                }
            }
        }
        let replay_lagged = queue
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .terminal
            .is_some();
        if !replay_lagged {
            state.reserved_events = state.reserved_events.saturating_add(requested_events);
            state.reserved_bytes = state.reserved_bytes.saturating_add(requested_bytes);
            state.subscribers.push(Subscriber {
                id,
                queue: Arc::downgrade(&queue),
                reserved_events: requested_events,
                reserved_bytes: requested_bytes,
            });
        }
        let feed = AgentEventFeed {
            baseline: AgentEventBaseline::Sessionless {
                live: state.live.clone(),
                first_live: AgentEventCursor::from_parts(self.agent_id, self.lifecycle, sequence),
            },
            stream: AgentEventStream {
                queue: Arc::clone(&queue),
                publisher: Arc::downgrade(self),
                id: if replay_lagged { 0 } else { id },
            },
        };
        drop(state);
        wake_all(wake);
        Ok(feed)
    }

    pub(crate) fn close(&self, final_status: AgentPublicStatus) {
        let mut wake = Vec::new();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.closed {
            close_locked(&mut state, final_status, &mut wake);
        }
        drop(state);
        self.shutdown.cancel();
        wake_all(wake);
    }

    pub(crate) async fn drain(&self) -> Result<(), RuntimePrimitiveError> {
        self.shutdown.cancel();
        self.runtime.drain(self.task_owner.clone())?.await;
        Ok(())
    }

    fn release(&self, id: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(index) = state.subscribers.iter().position(|value| value.id == id) {
            let subscriber = state.subscribers.remove(index);
            state.reserved_events = state
                .reserved_events
                .saturating_sub(subscriber.reserved_events);
            state.reserved_bytes = state
                .reserved_bytes
                .saturating_sub(subscriber.reserved_bytes);
        }
    }

    fn spawn_idle_reaper(self: &Arc<Self>) -> Result<(), RuntimePrimitiveError> {
        let publisher = Arc::downgrade(self);
        let runtime = self.runtime.clone();
        let task_runtime = runtime.clone();
        let shutdown = self.shutdown.clone();
        let task = Box::pin(async move {
            loop {
                let Some(publisher) = publisher.upgrade() else {
                    return;
                };
                let Ok(now) = task_runtime.now() else {
                    return;
                };
                let deadline = publisher.reap_idle(now);
                drop(publisher);
                if shutdown.is_cancelled() {
                    return;
                }
                let Ok(sleep) = task_runtime.sleep_until(deadline) else {
                    return;
                };
                let mut sleep = sleep;
                let mut cancelled = Box::pin(shutdown.cancelled());
                let stopped = std::future::poll_fn(|context| {
                    if cancelled.as_mut().poll(context).is_ready() {
                        return Poll::Ready(true);
                    }
                    sleep.as_mut().poll(context).map(|()| false)
                })
                .await;
                if stopped {
                    return;
                }
            }
        });
        runtime.spawn(self.task_owner.clone(), task)
    }

    fn reap_idle(&self, now: RuntimeInstant) -> RuntimeInstant {
        let mut wake = Vec::new();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let final_status = state.live.status;
        let idle_timeout = self.budget.event_feed_idle_timeout();
        let mut next_deadline = now.checked_add(idle_timeout).unwrap_or(now);
        let subscribers = std::mem::take(&mut state.subscribers);
        for subscriber in subscribers {
            let Some(queue) = subscriber.queue.upgrade() else {
                release_subscriber_budget(&mut state, &subscriber);
                continue;
            };
            let mut queue_state = queue
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if queue_state.done || queue_state.terminal.is_some() {
                release_subscriber_budget(&mut state, &subscriber);
                continue;
            }
            let deadline = queue_state
                .last_polled_at
                .checked_add(idle_timeout)
                .unwrap_or(queue_state.last_polled_at);
            if now >= deadline {
                queue_state.terminal = Some(AgentEventStreamItem::Closed { final_status });
                if let Some(waker) = queue_state.waker.take() {
                    wake.push(waker);
                }
                release_subscriber_budget(&mut state, &subscriber);
            } else {
                next_deadline = next_deadline.min(deadline);
                drop(queue_state);
                state.subscribers.push(subscriber);
            }
        }
        drop(state);
        wake_all(wake);
        next_deadline
    }
}

fn truncate_utf8(value: &mut String, maximum: usize) {
    if value.len() <= maximum {
        return;
    }
    let mut boundary = maximum;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
}

fn release_subscriber_budget(state: &mut PublisherState, subscriber: &Subscriber) {
    state.reserved_events = state
        .reserved_events
        .saturating_sub(subscriber.reserved_events);
    state.reserved_bytes = state
        .reserved_bytes
        .saturating_sub(subscriber.reserved_bytes);
}

fn close_locked(
    state: &mut PublisherState,
    final_status: AgentPublicStatus,
    wake: &mut Vec<Waker>,
) {
    state.closed = true;
    state.live.status = final_status;
    let subscribers = std::mem::take(&mut state.subscribers);
    for subscriber in subscribers {
        if let Some(queue) = subscriber.queue.upgrade() {
            let mut queue_state = queue
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if queue_state.terminal.is_none() {
                queue_state.terminal = Some(AgentEventStreamItem::Closed { final_status });
                if let Some(waker) = queue_state.waker.take() {
                    wake.push(waker);
                }
            }
        }
        state.reserved_events = state
            .reserved_events
            .saturating_sub(subscriber.reserved_events);
        state.reserved_bytes = state
            .reserved_bytes
            .saturating_sub(subscriber.reserved_bytes);
    }
}

fn enqueue_event(queue: &FeedQueue, event: AgentEventEnvelope) -> (bool, Option<Waker>) {
    let mut state = queue
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.terminal.is_some() {
        return (false, None);
    }
    let bytes = event_bytes(&event);
    if state.items.len() >= queue.max_events
        || state.buffered_bytes.saturating_add(bytes) > queue.max_bytes
    {
        let last_delivered = state.last_delivered;
        state.items.clear();
        state.buffered_bytes = 0;
        state.terminal = Some(AgentEventStreamItem::Lagged { last_delivered });
    } else {
        state.buffered_bytes = state.buffered_bytes.saturating_add(bytes);
        state.items.push_back(AgentEventStreamItem::Event(event));
    }
    let keep = state.terminal.is_none();
    let waker = state.waker.take();
    drop(state);
    (keep, waker)
}

fn wake_all(wakers: Vec<Waker>) {
    for waker in wakers {
        waker.wake();
    }
}

fn check_budget(
    resource: AgentEventFeedBudgetResource,
    requested: u64,
    limit: u64,
) -> Result<(), AgentEventFeedError> {
    if requested > limit {
        Err(AgentEventFeedError::AdmissionBudgetExceeded {
            resource,
            requested,
            limit,
        })
    } else {
        Ok(())
    }
}

fn event_bytes(event: &AgentEventEnvelope) -> usize {
    event
        .payload
        .len()
        .saturating_add(EVENT_ENVELOPE_ACCOUNTING_BYTES)
}

fn stream_item_bytes(item: &AgentEventStreamItem) -> usize {
    match item {
        AgentEventStreamItem::Event(event) => event_bytes(event),
        AgentEventStreamItem::Lagged { .. } | AgentEventStreamItem::Closed { .. } => {
            EVENT_ENVELOPE_ACCOUNTING_BYTES
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        task::Wake,
        thread,
        time::Duration,
    };

    use rust_agent_runtime_api::{
        RuntimeAdapterIdentity, RuntimeClock, RuntimeFuture, RuntimeSleeper, RuntimeSpawner,
    };

    use super::*;

    fn publisher(agent_id: AgentId, lifecycle: AgentLifecycleNonce) -> Arc<EventPublisher> {
        EventPublisher::new(
            agent_id,
            lifecycle,
            AgentPublicStatus::Ready,
            AgentResourceBudget::default(),
            rust_agent_runtime_tokio::create_runtime_primitives().unwrap(),
        )
        .unwrap()
    }

    fn agent(value: u128) -> AgentId {
        AgentId::from_nonzero_u128(value).unwrap()
    }

    fn lifecycle(value: u64) -> AgentLifecycleNonce {
        AgentLifecycleNonce::from_nonzero(NonZeroU64::new(value).unwrap())
    }

    fn request(
        after: Option<AgentEventCursor>,
        events: u32,
        bytes: usize,
    ) -> AgentEventFeedRequest {
        AgentEventFeedRequest {
            after,
            max_buffered_events: NonZeroU32::new(events).unwrap(),
            max_buffered_bytes: NonZeroUsize::new(bytes).unwrap(),
        }
    }

    fn poll(
        stream: &mut AgentEventStream,
    ) -> Poll<Option<Result<AgentEventStreamItem, AgentEventFeedError>>> {
        let mut context = Context::from_waker(std::task::Waker::noop());
        Pin::new(stream).poll_next(&mut context)
    }

    struct LockProbeWake {
        publisher: Weak<EventPublisher>,
        queue: Weak<FeedQueue>,
        observed_unlocked: AtomicBool,
    }

    impl LockProbeWake {
        fn observe(&self) {
            let publisher_unlocked = self
                .publisher
                .upgrade()
                .is_some_and(|publisher| publisher.state.try_lock().is_ok());
            let queue_unlocked = self
                .queue
                .upgrade()
                .is_some_and(|queue| queue.state.try_lock().is_ok());
            self.observed_unlocked
                .store(publisher_unlocked && queue_unlocked, Ordering::Release);
        }
    }

    impl Wake for LockProbeWake {
        fn wake(self: Arc<Self>) {
            self.observe();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.observe();
        }
    }

    #[derive(Debug)]
    struct CountingRuntime {
        spawns: AtomicUsize,
    }

    impl RuntimeClock for CountingRuntime {
        fn now(&self) -> RuntimeInstant {
            RuntimeInstant::from_monotonic_duration(Duration::ZERO)
        }
    }

    impl RuntimeSleeper for CountingRuntime {
        fn sleep_until(&self, _deadline: RuntimeInstant) -> RuntimeFuture<'static, ()> {
            Box::pin(std::future::pending())
        }
    }

    impl RuntimeSpawner for CountingRuntime {
        fn spawn(
            &self,
            _owner: RuntimeTaskOwner,
            _task: RuntimeFuture<'static, ()>,
        ) -> Result<(), RuntimePrimitiveError> {
            self.spawns.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn drain(&self, _owner: RuntimeTaskOwner) -> RuntimeFuture<'static, ()> {
            Box::pin(async {})
        }
    }

    #[test]
    fn feed_churn_uses_one_owner_scoped_idle_reaper() {
        let driver = Arc::new(CountingRuntime {
            spawns: AtomicUsize::new(0),
        });
        let runtime = RuntimePrimitives::from_adapter(
            RuntimeAdapterIdentity::checked("runtime-counting").unwrap(),
            Arc::clone(&driver),
            driver.clone(),
            driver.clone(),
            driver.clone(),
        );
        let publisher = EventPublisher::new(
            agent(1),
            lifecycle(1),
            AgentPublicStatus::Ready,
            AgentResourceBudget::default(),
            runtime,
        )
        .unwrap();
        for _ in 0..100 {
            drop(publisher.open(request(None, 1, 64)).unwrap());
        }
        assert_eq!(driver.spawns.load(Ordering::Acquire), 1);
        publisher.close(AgentPublicStatus::Closed);
    }

    #[test]
    fn publisher_wakes_feeds_only_after_releasing_registry_and_queue_locks() {
        let driver = Arc::new(CountingRuntime {
            spawns: AtomicUsize::new(0),
        });
        let runtime = RuntimePrimitives::from_adapter(
            RuntimeAdapterIdentity::checked("runtime-lock-probe").unwrap(),
            Arc::clone(&driver),
            driver.clone(),
            driver.clone(),
            driver,
        );
        let publisher = EventPublisher::new(
            agent(1),
            lifecycle(1),
            AgentPublicStatus::Ready,
            AgentResourceBudget::default(),
            runtime,
        )
        .unwrap();
        let mut feed = publisher.open(request(None, 2, 1024)).unwrap();
        let probe = Arc::new(LockProbeWake {
            publisher: Arc::downgrade(&publisher),
            queue: Arc::downgrade(&feed.stream.queue),
            observed_unlocked: AtomicBool::new(false),
        });
        let waker = Waker::from(Arc::clone(&probe));
        let mut context = Context::from_waker(&waker);

        assert!(
            Pin::new(&mut feed.stream)
                .poll_next(&mut context)
                .is_pending()
        );
        publisher.publish(AgentEventKind::OutputDelta, "one".into());
        assert!(probe.observed_unlocked.load(Ordering::Acquire));
        assert!(matches!(
            poll(&mut feed.stream),
            Poll::Ready(Some(Ok(AgentEventStreamItem::Event(_))))
        ));

        probe.observed_unlocked.store(false, Ordering::Release);
        assert!(
            Pin::new(&mut feed.stream)
                .poll_next(&mut context)
                .is_pending()
        );
        publisher.close(AgentPublicStatus::Closed);
        assert!(probe.observed_unlocked.load(Ordering::Acquire));
    }

    #[test]
    fn feed_admission_is_aggregate_bounded_and_drop_releases_capacity() {
        let publisher = publisher(agent(1), lifecycle(1));
        let mut feeds = Vec::new();
        for _ in 0..crate::MAX_EVENT_FEED_SUBSCRIBERS_HARD {
            feeds.push(publisher.open(request(None, 1, 64)).unwrap());
        }
        assert!(matches!(
            publisher.open(request(None, 1, 64)),
            Err(AgentEventFeedError::AdmissionBudgetExceeded {
                resource: AgentEventFeedBudgetResource::SubscriberCount,
                ..
            })
        ));
        feeds.pop();
        assert!(publisher.open(request(None, 1, 64)).is_ok());
        assert!(matches!(
            publisher.open(request(None, 1025, 64)),
            Err(AgentEventFeedError::AdmissionBudgetExceeded {
                resource: AgentEventFeedBudgetResource::BufferedEvents,
                ..
            })
        ));
    }

    #[test]
    fn event_payload_is_bounded_before_history_and_feed_publication() {
        let publisher = publisher(agent(1), lifecycle(1));
        let mut feed = publisher
            .open(request(None, 1, MAX_AGENT_EVENT_PAYLOAD_BYTES + 64))
            .unwrap();
        publisher.publish(
            AgentEventKind::RequestFailed,
            "界".repeat(MAX_AGENT_EVENT_PAYLOAD_BYTES),
        );
        let Poll::Ready(Some(Ok(AgentEventStreamItem::Event(event)))) = poll(&mut feed.stream)
        else {
            panic!("bounded event was not delivered");
        };
        assert!(event.payload.len() <= MAX_AGENT_EVENT_PAYLOAD_BYTES);
        assert!(event.payload.is_char_boundary(event.payload.len()));
    }

    #[test]
    fn maximum_event_remains_replayable_after_older_history_is_evicted() {
        let publisher = publisher(agent(1), lifecycle(1));
        let mut initial = publisher.open(request(None, 1, HISTORY_BYTES)).unwrap();
        publisher.publish(AgentEventKind::OutputDelta, "first".into());
        let first = match poll(&mut initial.stream) {
            Poll::Ready(Some(Ok(AgentEventStreamItem::Event(event)))) => event.cursor,
            other => panic!("unexpected initial event result: {other:?}"),
        };
        drop(initial);

        publisher.publish(
            AgentEventKind::OutputFinal,
            "x".repeat(MAX_AGENT_EVENT_PAYLOAD_BYTES),
        );
        let mut resumed = publisher
            .open(request(Some(first), 1, HISTORY_BYTES))
            .unwrap();
        match poll(&mut resumed.stream) {
            Poll::Ready(Some(Ok(AgentEventStreamItem::Event(event)))) => {
                assert_eq!(event.cursor.value(), first.value() + 1);
                assert_eq!(event.payload.len(), MAX_AGENT_EVENT_PAYLOAD_BYTES);
            }
            other => panic!("maximum event was not replayed: {other:?}"),
        }
    }

    #[test]
    fn lagged_cursor_reports_only_events_delivered_to_the_host() {
        let publisher = publisher(agent(1), lifecycle(1));
        let mut feed = publisher.open(request(None, 1, 1024)).unwrap();
        publisher.publish(AgentEventKind::OutputDelta, "one".into());
        publisher.publish(AgentEventKind::OutputDelta, "two".into());
        assert_eq!(
            poll(&mut feed.stream),
            Poll::Ready(Some(Ok(AgentEventStreamItem::Lagged {
                last_delivered: None
            })))
        );
        assert_eq!(poll(&mut feed.stream), Poll::Ready(None));

        let mut feed = publisher.open(request(None, 1, 1024)).unwrap();
        publisher.publish(AgentEventKind::OutputDelta, "three".into());
        let delivered = match poll(&mut feed.stream) {
            Poll::Ready(Some(Ok(AgentEventStreamItem::Event(event)))) => event.cursor,
            other => panic!("unexpected poll: {other:?}"),
        };
        publisher.publish(AgentEventKind::OutputDelta, "four".into());
        publisher.publish(AgentEventKind::OutputDelta, "five".into());
        assert_eq!(
            poll(&mut feed.stream),
            Poll::Ready(Some(Ok(AgentEventStreamItem::Lagged {
                last_delivered: Some(delivered)
            })))
        );
    }

    #[test]
    fn cursor_scope_replay_and_close_are_fail_closed() {
        let publisher = publisher(agent(1), lifecycle(1));
        publisher.publish(AgentEventKind::StatusChanged, "ready".into());
        let foreign =
            AgentEventCursor::from_parts(agent(2), lifecycle(1), NonZeroU64::new(1).unwrap());
        assert!(matches!(
            publisher.open(request(Some(foreign), 1, 1024)),
            Err(AgentEventFeedError::CursorFromDifferentAgent)
        ));
        let stale =
            AgentEventCursor::from_parts(agent(1), lifecycle(2), NonZeroU64::new(1).unwrap());
        assert!(matches!(
            publisher.open(request(Some(stale), 1, 1024)),
            Err(AgentEventFeedError::StaleLifecycle)
        ));
        let future =
            AgentEventCursor::from_parts(agent(1), lifecycle(1), NonZeroU64::new(2).unwrap());
        assert!(matches!(
            publisher.open(request(Some(future), 1, 1024)),
            Err(AgentEventFeedError::InvalidLimit)
        ));

        let mut feed = publisher.open(request(None, 1, 1024)).unwrap();
        publisher.close(AgentPublicStatus::Closed);
        assert_eq!(
            poll(&mut feed.stream),
            Poll::Ready(Some(Ok(AgentEventStreamItem::Closed {
                final_status: AgentPublicStatus::Closed
            })))
        );
        assert_eq!(poll(&mut feed.stream), Poll::Ready(None));
    }

    #[test]
    fn registration_and_baseline_are_one_linearization_point() {
        let publisher = publisher(agent(1), lifecycle(1));
        let mut feed = publisher.open(request(None, 4, 4096)).unwrap();
        let request_id =
            AgentRequestId::from_agent(agent(1), lifecycle(1), NonZeroU64::new(1).unwrap());
        publisher.begin_request(request_id).unwrap();
        let AgentEventBaseline::Sessionless { live, first_live } = feed.baseline;
        assert_eq!(live.active_request, None);
        let event = match poll(&mut feed.stream) {
            Poll::Ready(Some(Ok(AgentEventStreamItem::Event(event)))) => event,
            other => panic!("unexpected feed result: {other:?}"),
        };
        assert_eq!(event.cursor, first_live);
        assert_eq!(event.request_id, Some(request_id));

        let second = publisher.open(request(None, 4, 4096)).unwrap();
        let AgentEventBaseline::Sessionless { live, .. } = second.baseline;
        assert_eq!(live.active_request, Some(request_id));
    }

    #[test]
    fn shutdown_preserves_unread_events_before_one_closed_terminal() {
        let publisher = publisher(agent(1), lifecycle(1));
        let mut feed = publisher.open(request(None, 4, 4096)).unwrap();
        publisher.publish(AgentEventKind::OutputDelta, "one".into());
        publisher.publish(AgentEventKind::OutputDelta, "two".into());
        publisher.close(AgentPublicStatus::Closed);
        for expected in ["one", "two"] {
            match poll(&mut feed.stream) {
                Poll::Ready(Some(Ok(AgentEventStreamItem::Event(event)))) => {
                    assert_eq!(event.payload, expected);
                }
                other => panic!("unexpected feed result: {other:?}"),
            }
        }
        assert_eq!(
            poll(&mut feed.stream),
            Poll::Ready(Some(Ok(AgentEventStreamItem::Closed {
                final_status: AgentPublicStatus::Closed
            })))
        );
        assert_eq!(poll(&mut feed.stream), Poll::Ready(None));
    }

    #[test]
    fn forced_publisher_drop_preserves_unread_events_before_closed() {
        let driver = Arc::new(CountingRuntime {
            spawns: AtomicUsize::new(0),
        });
        let runtime = RuntimePrimitives::from_adapter(
            RuntimeAdapterIdentity::checked("runtime-counting").unwrap(),
            Arc::clone(&driver),
            driver.clone(),
            driver.clone(),
            driver,
        );
        let publisher = EventPublisher::new(
            agent(1),
            lifecycle(1),
            AgentPublicStatus::Ready,
            AgentResourceBudget::default(),
            runtime,
        )
        .unwrap();
        let mut feed = publisher.open(request(None, 4, 4096)).unwrap();
        publisher.publish(AgentEventKind::OutputDelta, "one".into());

        drop(publisher);

        match poll(&mut feed.stream) {
            Poll::Ready(Some(Ok(AgentEventStreamItem::Event(event)))) => {
                assert_eq!(event.payload, "one");
            }
            other => panic!("unexpected feed result: {other:?}"),
        }
        assert_eq!(
            poll(&mut feed.stream),
            Poll::Ready(Some(Ok(AgentEventStreamItem::Closed {
                final_status: AgentPublicStatus::Closed
            })))
        );
        assert_eq!(poll(&mut feed.stream), Poll::Ready(None));
    }

    #[test]
    fn idle_feed_expires_and_releases_its_aggregate_reservation() {
        let budget = AgentResourceBudget::checked(1, 4, 4096, Duration::from_millis(10)).unwrap();
        let publisher = EventPublisher::new(
            agent(1),
            lifecycle(1),
            AgentPublicStatus::Ready,
            budget,
            rust_agent_runtime_tokio::create_runtime_primitives().unwrap(),
        )
        .unwrap();
        let mut feed = publisher.open(request(None, 4, 4096)).unwrap();
        thread::sleep(Duration::from_millis(30));
        assert_eq!(
            poll(&mut feed.stream),
            Poll::Ready(Some(Ok(AgentEventStreamItem::Closed {
                final_status: AgentPublicStatus::Ready,
            })))
        );
        assert!(publisher.open(request(None, 4, 4096)).is_ok());
        publisher.close(AgentPublicStatus::Closed);
    }
}
