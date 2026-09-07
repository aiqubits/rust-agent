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
    AgentEventKind, AgentLifecycleNonce, AgentPublicStatus,
};

use crate::AgentRequestId;

const MAX_SUBSCRIBERS: u64 = 16;
const MAX_AGGREGATE_EVENTS: u64 = 1_024;
const MAX_AGGREGATE_BYTES: u64 = 1024 * 1024;
const HISTORY_EVENTS: usize = 128;
const HISTORY_BYTES: usize = 256 * 1024;

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
        if let Some(item) = state.items.pop_front() {
            state.buffered_bytes = state
                .buffered_bytes
                .saturating_sub(stream_item_bytes(&item));
            if let AgentEventStreamItem::Event(event) = &item {
                state.last_delivered = Some(event.cursor);
            }
            return Poll::Ready(Some(Ok(item)));
        }
        if state.terminal {
            return Poll::Ready(None);
        }
        state.waker = Some(context.waker().clone());
        Poll::Pending
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
    terminal: bool,
    last_delivered: Option<AgentEventCursor>,
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
}

pub(crate) struct EventPublisher {
    agent_id: AgentId,
    lifecycle: AgentLifecycleNonce,
    state: Mutex<PublisherState>,
}

impl EventPublisher {
    pub(crate) fn new(agent_id: AgentId, lifecycle: AgentLifecycleNonce) -> Arc<Self> {
        Arc::new(Self {
            agent_id,
            lifecycle,
            state: Mutex::new(PublisherState {
                next_sequence: 1,
                next_subscriber: 1,
                history: VecDeque::new(),
                history_bytes: 0,
                subscribers: Vec::new(),
                reserved_events: 0,
                reserved_bytes: 0,
                closed: false,
            }),
        })
    }

    pub(crate) fn publish(&self, kind: AgentEventKind, payload: String) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed {
            return;
        }
        let Some(sequence) = NonZeroU64::new(state.next_sequence) else {
            state.closed = true;
            return;
        };
        state.next_sequence = state.next_sequence.saturating_add(1);
        let event = AgentEventEnvelope {
            cursor: AgentEventCursor::from_parts(self.agent_id, self.lifecycle, sequence),
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
            enqueue_event(&queue, event.clone());
            state.subscribers.push(subscriber);
        }
    }

    pub(crate) fn open(
        self: &Arc<Self>,
        request: AgentEventFeedRequest,
        baseline: AgentLiveBaseline,
    ) -> Result<AgentEventFeed, AgentEventFeedError> {
        let requested_events = u64::from(request.max_buffered_events.get());
        let requested_bytes = u64::try_from(request.max_buffered_bytes.get()).unwrap_or(u64::MAX);
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
            MAX_SUBSCRIBERS,
        )?;
        check_budget(
            AgentEventFeedBudgetResource::BufferedEvents,
            state.reserved_events.saturating_add(requested_events),
            MAX_AGGREGATE_EVENTS,
        )?;
        check_budget(
            AgentEventFeedBudgetResource::BufferedBytes,
            state.reserved_bytes.saturating_add(requested_bytes),
            MAX_AGGREGATE_BYTES,
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
            if let Some(oldest) = state.history.front()
                && after.value().saturating_add(1) < oldest.cursor.value()
            {
                return Err(AgentEventFeedError::CursorExpired {
                    oldest_available: Some(oldest.cursor),
                });
            }
        }
        let queue = Arc::new(FeedQueue {
            state: Mutex::new(FeedQueueState {
                items: VecDeque::new(),
                buffered_bytes: 0,
                terminal: false,
                last_delivered: request.after,
                waker: None,
            }),
            max_events: request.max_buffered_events.get() as usize,
            max_bytes: request.max_buffered_bytes.get(),
        });
        if let Some(after) = request.after {
            for event in state
                .history
                .iter()
                .filter(|event| event.cursor.value() > after.value())
            {
                enqueue_event(&queue, event.clone());
            }
        }
        let id = state.next_subscriber;
        state.next_subscriber = state.next_subscriber.saturating_add(1);
        state.reserved_events = state.reserved_events.saturating_add(requested_events);
        state.reserved_bytes = state.reserved_bytes.saturating_add(requested_bytes);
        state.subscribers.push(Subscriber {
            id,
            queue: Arc::downgrade(&queue),
            reserved_events: requested_events,
            reserved_bytes: requested_bytes,
        });
        let sequence = NonZeroU64::new(state.next_sequence).ok_or(AgentEventFeedError::Closed)?;
        Ok(AgentEventFeed {
            baseline: AgentEventBaseline::Sessionless {
                live: baseline,
                first_live: AgentEventCursor::from_parts(self.agent_id, self.lifecycle, sequence),
            },
            stream: AgentEventStream {
                queue,
                publisher: Arc::downgrade(self),
                id,
            },
        })
    }

    pub(crate) fn close(&self, final_status: AgentPublicStatus) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed {
            return;
        }
        state.closed = true;
        for subscriber in &state.subscribers {
            if let Some(queue) = subscriber.queue.upgrade() {
                let mut queue_state = queue
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !queue_state.terminal {
                    queue_state.items.clear();
                    queue_state.buffered_bytes = 0;
                    queue_state
                        .items
                        .push_back(AgentEventStreamItem::Closed { final_status });
                    queue_state.terminal = true;
                    if let Some(waker) = queue_state.waker.take() {
                        waker.wake();
                    }
                }
            }
        }
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
}

fn enqueue_event(queue: &FeedQueue, event: AgentEventEnvelope) {
    let mut state = queue
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.terminal {
        return;
    }
    let bytes = event_bytes(&event);
    if state.items.len() >= queue.max_events
        || state.buffered_bytes.saturating_add(bytes) > queue.max_bytes
    {
        let last_delivered = state.last_delivered;
        state.items.clear();
        state.buffered_bytes = 0;
        state
            .items
            .push_back(AgentEventStreamItem::Lagged { last_delivered });
        state.terminal = true;
    } else {
        state.buffered_bytes = state.buffered_bytes.saturating_add(bytes);
        state.items.push_back(AgentEventStreamItem::Event(event));
    }
    if let Some(waker) = state.waker.take() {
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
    event.payload.len().saturating_add(64)
}

fn stream_item_bytes(item: &AgentEventStreamItem) -> usize {
    match item {
        AgentEventStreamItem::Event(event) => event_bytes(event),
        AgentEventStreamItem::Lagged { .. } | AgentEventStreamItem::Closed { .. } => 64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn baseline(lifecycle: AgentLifecycleNonce) -> AgentLiveBaseline {
        AgentLiveBaseline {
            lifecycle,
            status: AgentPublicStatus::Ready,
            active_request: None,
        }
    }

    fn poll(
        stream: &mut AgentEventStream,
    ) -> Poll<Option<Result<AgentEventStreamItem, AgentEventFeedError>>> {
        let mut context = Context::from_waker(std::task::Waker::noop());
        Pin::new(stream).poll_next(&mut context)
    }

    #[test]
    fn feed_admission_is_aggregate_bounded_and_drop_releases_capacity() {
        let publisher = EventPublisher::new(agent(1), lifecycle(1));
        let mut feeds = Vec::new();
        for _ in 0..MAX_SUBSCRIBERS {
            feeds.push(
                publisher
                    .open(request(None, 1, 64), baseline(lifecycle(1)))
                    .unwrap(),
            );
        }
        assert!(matches!(
            publisher.open(request(None, 1, 64), baseline(lifecycle(1))),
            Err(AgentEventFeedError::AdmissionBudgetExceeded {
                resource: AgentEventFeedBudgetResource::SubscriberCount,
                ..
            })
        ));
        feeds.pop();
        assert!(
            publisher
                .open(request(None, 1, 64), baseline(lifecycle(1)))
                .is_ok()
        );
        assert!(matches!(
            publisher.open(request(None, 1025, 64), baseline(lifecycle(1))),
            Err(AgentEventFeedError::AdmissionBudgetExceeded {
                resource: AgentEventFeedBudgetResource::BufferedEvents,
                ..
            })
        ));
    }

    #[test]
    fn lagged_cursor_reports_only_events_delivered_to_the_host() {
        let publisher = EventPublisher::new(agent(1), lifecycle(1));
        let mut feed = publisher
            .open(request(None, 1, 1024), baseline(lifecycle(1)))
            .unwrap();
        publisher.publish(AgentEventKind::OutputDelta, "one".into());
        publisher.publish(AgentEventKind::OutputDelta, "two".into());
        assert_eq!(
            poll(&mut feed.stream),
            Poll::Ready(Some(Ok(AgentEventStreamItem::Lagged {
                last_delivered: None
            })))
        );
        assert_eq!(poll(&mut feed.stream), Poll::Ready(None));

        let mut feed = publisher
            .open(request(None, 1, 1024), baseline(lifecycle(1)))
            .unwrap();
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
        let publisher = EventPublisher::new(agent(1), lifecycle(1));
        publisher.publish(AgentEventKind::StatusChanged, "ready".into());
        let foreign =
            AgentEventCursor::from_parts(agent(2), lifecycle(1), NonZeroU64::new(1).unwrap());
        assert!(matches!(
            publisher.open(request(Some(foreign), 1, 1024), baseline(lifecycle(1))),
            Err(AgentEventFeedError::CursorFromDifferentAgent)
        ));
        let stale =
            AgentEventCursor::from_parts(agent(1), lifecycle(2), NonZeroU64::new(1).unwrap());
        assert!(matches!(
            publisher.open(request(Some(stale), 1, 1024), baseline(lifecycle(1))),
            Err(AgentEventFeedError::StaleLifecycle)
        ));
        let future =
            AgentEventCursor::from_parts(agent(1), lifecycle(1), NonZeroU64::new(2).unwrap());
        assert!(matches!(
            publisher.open(request(Some(future), 1, 1024), baseline(lifecycle(1))),
            Err(AgentEventFeedError::InvalidLimit)
        ));

        let mut feed = publisher
            .open(request(None, 1, 1024), baseline(lifecycle(1)))
            .unwrap();
        publisher.close(AgentPublicStatus::Closed);
        assert_eq!(
            poll(&mut feed.stream),
            Poll::Ready(Some(Ok(AgentEventStreamItem::Closed {
                final_status: AgentPublicStatus::Closed
            })))
        );
        assert_eq!(poll(&mut feed.stream), Poll::Ready(None));
    }
}
