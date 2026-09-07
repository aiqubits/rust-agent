use rust_agent_runtime_api::{DisposalEvent, PublicationEvent, PublicationSnapshot};

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::{
        future::Future,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        task::{Context, Poll, Wake, Waker},
        thread,
        time::{Duration, Instant},
    };

    use rust_agent_runtime_api::{
        CancellationToken, DisposalEvent, LifecycleNotificationContext, LifecycleObserver,
        PublicationEvent, PublicationSnapshot,
    };

    const CALLBACK_TIMEOUT: Duration = Duration::from_millis(250);

    enum Notification {
        Published(PublicationEvent, PublicationSnapshot),
        Disposed(DisposalEvent, PublicationSnapshot),
        Stop,
    }

    struct DispatcherInner {
        sender: mpsc::Sender<Notification>,
        reserved: AtomicUsize,
        capacity: usize,
    }

    pub(crate) struct ObserverDispatcher {
        inner: Arc<DispatcherInner>,
        worker: Mutex<Option<thread::JoinHandle<()>>>,
    }

    pub(crate) struct NotificationReservation {
        inner: Arc<DispatcherInner>,
        published_pending: bool,
        disposed_pending: bool,
    }

    impl ObserverDispatcher {
        pub(crate) fn new(observers: Arc<[Arc<dyn LifecycleObserver>]>, capacity: usize) -> Self {
            let (sender, receiver) = mpsc::channel();
            let inner = Arc::new(DispatcherInner {
                sender,
                reserved: AtomicUsize::new(0),
                capacity,
            });
            let worker_inner = Arc::clone(&inner);
            let worker = thread::Builder::new()
                .name("rust-agent-lifecycle-observers".into())
                .spawn(move || run_worker(&receiver, &observers, &worker_inner))
                .expect("the lifecycle observer worker must be constructible");
            Self {
                inner,
                worker: Mutex::new(Some(worker)),
            }
        }

        pub(crate) fn reserve_pair(&self) -> Option<NotificationReservation> {
            self.inner
                .reserved
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current
                        .checked_add(2)
                        .filter(|next| *next <= self.inner.capacity)
                })
                .ok()?;
            Some(NotificationReservation {
                inner: Arc::clone(&self.inner),
                published_pending: true,
                disposed_pending: true,
            })
        }

        pub(crate) fn shutdown(&self) {
            let _ = self.inner.sender.send(Notification::Stop);
            if let Some(worker) = self
                .worker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                let _ = worker.join();
            }
        }
    }

    impl Drop for ObserverDispatcher {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    impl NotificationReservation {
        pub(super) fn published(&mut self, event: PublicationEvent, snapshot: PublicationSnapshot) {
            if self.published_pending {
                self.published_pending = false;
                if self
                    .inner
                    .sender
                    .send(Notification::Published(event, snapshot))
                    .is_err()
                {
                    self.inner.reserved.fetch_sub(1, Ordering::AcqRel);
                }
            }
        }

        pub(super) fn disposed(&mut self, event: DisposalEvent, snapshot: PublicationSnapshot) {
            if self.disposed_pending {
                self.disposed_pending = false;
                if self
                    .inner
                    .sender
                    .send(Notification::Disposed(event, snapshot))
                    .is_err()
                {
                    self.inner.reserved.fetch_sub(1, Ordering::AcqRel);
                }
            }
        }
    }

    impl Drop for NotificationReservation {
        fn drop(&mut self) {
            let pending = usize::from(self.published_pending) + usize::from(self.disposed_pending);
            if pending != 0 {
                self.inner.reserved.fetch_sub(pending, Ordering::AcqRel);
            }
        }
    }

    fn run_worker(
        receiver: &mpsc::Receiver<Notification>,
        observers: &[Arc<dyn LifecycleObserver>],
        inner: &DispatcherInner,
    ) {
        while let Ok(notification) = receiver.recv() {
            match notification {
                Notification::Published(event, snapshot) => {
                    for observer in observers {
                        let cancellation = CancellationToken::new();
                        let deadline = Instant::now() + CALLBACK_TIMEOUT;
                        let context =
                            LifecycleNotificationContext::new(cancellation.clone(), deadline);
                        let future = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            observer.published(context, &event, &snapshot)
                        }));
                        if let Ok(future) = future {
                            let _ = run_until(future, deadline, &cancellation);
                        }
                    }
                    inner.reserved.fetch_sub(1, Ordering::AcqRel);
                }
                Notification::Disposed(event, snapshot) => {
                    for observer in observers {
                        let cancellation = CancellationToken::new();
                        let deadline = Instant::now() + CALLBACK_TIMEOUT;
                        let context =
                            LifecycleNotificationContext::new(cancellation.clone(), deadline);
                        let future = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            observer.disposed(context, &event, &snapshot)
                        }));
                        if let Ok(future) = future {
                            let _ = run_until(future, deadline, &cancellation);
                        }
                    }
                    inner.reserved.fetch_sub(1, Ordering::AcqRel);
                }
                Notification::Stop => break,
            }
        }
    }

    struct ThreadWake(thread::Thread);

    impl Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }

    fn run_until<F: Future>(
        future: F,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Option<F::Output> {
        let mut future = std::pin::pin!(future);
        let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
        let mut context = Context::from_waker(&waker);
        loop {
            let polled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Pin::as_mut(&mut future).poll(&mut context)
            }));
            match polled {
                Ok(Poll::Ready(value)) => return Some(value),
                Ok(Poll::Pending) if Instant::now() < deadline => {
                    thread::park_timeout(deadline.saturating_duration_since(Instant::now()));
                }
                Ok(Poll::Pending) | Err(_) => {
                    cancellation.cancel();
                    return None;
                }
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use std::sync::Arc;

    use rust_agent_runtime_api::{
        DisposalEvent, LifecycleObserver, PublicationEvent, PublicationSnapshot,
    };

    pub(crate) struct ObserverDispatcher;
    pub(crate) struct NotificationReservation;

    impl ObserverDispatcher {
        pub(crate) fn new(_observers: Arc<[Arc<dyn LifecycleObserver>]>, _capacity: usize) -> Self {
            Self
        }

        pub(crate) fn reserve_pair(&self) -> Option<NotificationReservation> {
            Some(NotificationReservation)
        }

        pub(crate) fn shutdown(&self) {}
    }

    impl NotificationReservation {
        pub(super) fn published(
            &mut self,
            _event: PublicationEvent,
            _snapshot: PublicationSnapshot,
        ) {
        }

        pub(super) fn disposed(&mut self, _event: DisposalEvent, _snapshot: PublicationSnapshot) {}
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) use browser::{NotificationReservation, ObserverDispatcher};
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use native::{NotificationReservation, ObserverDispatcher};

pub(crate) fn publish_notification(
    reservation: &mut NotificationReservation,
    event: PublicationEvent,
    snapshot: PublicationSnapshot,
) {
    reservation.published(event, snapshot);
}

pub(crate) fn dispose_notification(
    reservation: &mut NotificationReservation,
    event: DisposalEvent,
    snapshot: PublicationSnapshot,
) {
    reservation.disposed(event, snapshot);
}
