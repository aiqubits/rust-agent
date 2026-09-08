use rust_agent_runtime_api::{DisposalEvent, PublicationEvent, PublicationSnapshot};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ObserverDispatcherBuildError;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LifecycleObserverDiagnostics {
    callback_errors: u64,
    callback_timeouts: u64,
    callback_panics: u64,
    forced_callback_cancellations: u64,
    runtime_failures: u64,
    dropped_notifications: u64,
    worker_panics: u64,
}

impl LifecycleObserverDiagnostics {
    pub const fn callback_errors(self) -> u64 {
        self.callback_errors
    }

    pub const fn callback_timeouts(self) -> u64 {
        self.callback_timeouts
    }

    pub const fn callback_panics(self) -> u64 {
        self.callback_panics
    }

    pub const fn forced_callback_cancellations(self) -> u64 {
        self.forced_callback_cancellations
    }

    pub const fn runtime_failures(self) -> u64 {
        self.runtime_failures
    }

    pub const fn dropped_notifications(self) -> u64 {
        self.dropped_notifications
    }

    pub const fn worker_panics(self) -> u64 {
        self.worker_panics
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::{
        future::Future,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
            mpsc::{self, Receiver, SyncSender, TrySendError},
        },
        task::{Context, Poll, Wake, Waker},
        thread,
        time::Duration,
    };

    use rust_agent_runtime_api::{
        CancellationToken, DisposalEvent, LifecycleNotificationContext, LifecycleObserver,
        PublicationEvent, PublicationSnapshot, RuntimePrimitives,
    };

    enum Notification {
        Published(PublicationEvent, PublicationSnapshot),
        Disposed(DisposalEvent, PublicationSnapshot),
    }

    #[derive(Default)]
    struct ObserverDiagnosticCounters {
        callback_errors: AtomicU64,
        callback_timeouts: AtomicU64,
        callback_panics: AtomicU64,
        forced_callback_cancellations: AtomicU64,
        runtime_failures: AtomicU64,
        dropped_notifications: AtomicU64,
        worker_panics: AtomicU64,
    }

    impl ObserverDiagnosticCounters {
        fn increment(counter: &AtomicU64) {
            let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_add(1))
            });
        }

        fn snapshot(&self) -> super::LifecycleObserverDiagnostics {
            super::LifecycleObserverDiagnostics {
                callback_errors: self.callback_errors.load(Ordering::Acquire),
                callback_timeouts: self.callback_timeouts.load(Ordering::Acquire),
                callback_panics: self.callback_panics.load(Ordering::Acquire),
                forced_callback_cancellations: self
                    .forced_callback_cancellations
                    .load(Ordering::Acquire),
                runtime_failures: self.runtime_failures.load(Ordering::Acquire),
                dropped_notifications: self.dropped_notifications.load(Ordering::Acquire),
                worker_panics: self.worker_panics.load(Ordering::Acquire),
            }
        }
    }

    struct DispatcherInner {
        sender: SyncSender<Notification>,
        reserved: AtomicUsize,
        capacity: usize,
        closing: AtomicBool,
        force_stop: AtomicBool,
        active_cancellation: Mutex<Option<CancellationToken>>,
        runtime: RuntimePrimitives,
        callback_timeout: Duration,
        shutdown_timeout: Duration,
        diagnostics: ObserverDiagnosticCounters,
    }

    pub(crate) struct ObserverDispatcher {
        inner: Arc<DispatcherInner>,
        worker: Mutex<Option<thread::JoinHandle<()>>>,
        done: Mutex<Receiver<()>>,
    }

    pub(crate) struct NotificationReservation {
        inner: Arc<DispatcherInner>,
        published_pending: bool,
        disposed_pending: bool,
    }

    impl ObserverDispatcher {
        pub(crate) fn new(
            observers: Arc<[Arc<dyn LifecycleObserver>]>,
            runtime: RuntimePrimitives,
            capacity: usize,
            callback_timeout: Duration,
            shutdown_timeout: Duration,
        ) -> Result<Self, super::ObserverDispatcherBuildError> {
            let (sender, receiver) = mpsc::sync_channel(capacity);
            let (done_sender, done) = mpsc::sync_channel(1);
            let inner = Arc::new(DispatcherInner {
                sender,
                reserved: AtomicUsize::new(0),
                capacity,
                closing: AtomicBool::new(false),
                force_stop: AtomicBool::new(false),
                active_cancellation: Mutex::new(None),
                runtime,
                callback_timeout,
                shutdown_timeout,
                diagnostics: ObserverDiagnosticCounters::default(),
            });
            let worker_inner = Arc::clone(&inner);
            let worker = thread::Builder::new()
                .name("rust-agent-lifecycle-observers".into())
                .spawn(move || {
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        run_worker(&receiver, &observers, &worker_inner);
                    }))
                    .is_err()
                    {
                        ObserverDiagnosticCounters::increment(
                            &worker_inner.diagnostics.worker_panics,
                        );
                    }
                    let _ = done_sender.try_send(());
                })
                .map_err(|_| super::ObserverDispatcherBuildError)?;
            Ok(Self {
                inner,
                worker: Mutex::new(Some(worker)),
                done: Mutex::new(done),
            })
        }

        pub(crate) fn reserve_pair(&self) -> Option<NotificationReservation> {
            if self.inner.closing.load(Ordering::Acquire) {
                return None;
            }
            self.inner
                .reserved
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current
                        .checked_add(2)
                        .filter(|next| *next <= self.inner.capacity)
                })
                .ok()?;
            if self.inner.closing.load(Ordering::Acquire) {
                self.inner.reserved.fetch_sub(2, Ordering::AcqRel);
                return None;
            }
            Some(NotificationReservation {
                inner: Arc::clone(&self.inner),
                published_pending: true,
                disposed_pending: true,
            })
        }

        pub(crate) fn shutdown(&self) {
            self.stop(true);
        }

        pub(crate) fn diagnostics(&self) -> super::LifecycleObserverDiagnostics {
            self.inner.diagnostics.snapshot()
        }

        pub(crate) fn record_callback_panic(&self) {
            ObserverDiagnosticCounters::increment(&self.inner.diagnostics.callback_panics);
        }

        fn stop(&self, graceful: bool) {
            let worker = self
                .worker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            let Some(worker) = worker else {
                return;
            };
            self.inner.closing.store(true, Ordering::Release);
            let completed = graceful
                && self
                    .done
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .recv_timeout(self.inner.shutdown_timeout)
                    .is_ok();
            if !completed {
                self.inner.force_stop.store(true, Ordering::Release);
                if let Some(cancellation) = self
                    .inner
                    .active_cancellation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .as_ref()
                {
                    cancellation.cancel();
                }
                worker.thread().unpark();
                return;
            }
            let _ = worker.join();
        }
    }

    impl Drop for ObserverDispatcher {
        fn drop(&mut self) {
            self.stop(false);
        }
    }

    impl NotificationReservation {
        pub(super) fn published(&mut self, event: PublicationEvent, snapshot: PublicationSnapshot) {
            if self.published_pending {
                self.published_pending = false;
                enqueue_reserved(&self.inner, Notification::Published(event, snapshot));
            }
        }

        pub(super) fn disposed(&mut self, event: DisposalEvent, snapshot: PublicationSnapshot) {
            if self.disposed_pending {
                self.disposed_pending = false;
                enqueue_reserved(&self.inner, Notification::Disposed(event, snapshot));
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
        receiver: &Receiver<Notification>,
        observers: &[Arc<dyn LifecycleObserver>],
        inner: &DispatcherInner,
    ) {
        loop {
            if inner.force_stop.load(Ordering::Acquire) {
                drain_without_callbacks(receiver, inner);
                break;
            }
            let notification = match receiver.recv_timeout(Duration::from_millis(10)) {
                Ok(notification) => notification,
                Err(mpsc::RecvTimeoutError::Timeout)
                    if inner.closing.load(Ordering::Acquire)
                        && inner.reserved.load(Ordering::Acquire) == 0 =>
                {
                    break;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };
            match notification {
                Notification::Published(event, snapshot) => {
                    for observer in observers {
                        if inner.force_stop.load(Ordering::Acquire) {
                            ObserverDiagnosticCounters::increment(
                                &inner.diagnostics.dropped_notifications,
                            );
                            break;
                        }
                        run_callback(inner, |context| {
                            observer.published(context, &event, &snapshot)
                        });
                    }
                    inner.reserved.fetch_sub(1, Ordering::AcqRel);
                }
                Notification::Disposed(event, snapshot) => {
                    for observer in observers {
                        if inner.force_stop.load(Ordering::Acquire) {
                            ObserverDiagnosticCounters::increment(
                                &inner.diagnostics.dropped_notifications,
                            );
                            break;
                        }
                        run_callback(inner, |context| {
                            observer.disposed(context, &event, &snapshot)
                        });
                    }
                    inner.reserved.fetch_sub(1, Ordering::AcqRel);
                }
            }
        }
    }

    fn enqueue_reserved(inner: &DispatcherInner, notification: Notification) {
        if inner.closing.load(Ordering::Acquire) {
            inner.reserved.fetch_sub(1, Ordering::AcqRel);
            ObserverDiagnosticCounters::increment(&inner.diagnostics.dropped_notifications);
            return;
        }
        match inner.sender.try_send(notification) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                inner.reserved.fetch_sub(1, Ordering::AcqRel);
                ObserverDiagnosticCounters::increment(&inner.diagnostics.dropped_notifications);
            }
        }
    }

    fn drain_without_callbacks(receiver: &Receiver<Notification>, inner: &DispatcherInner) {
        while receiver.try_recv().is_ok() {
            inner.reserved.fetch_sub(1, Ordering::AcqRel);
            ObserverDiagnosticCounters::increment(&inner.diagnostics.dropped_notifications);
        }
    }

    enum CallbackRunOutcome<T> {
        Completed(T),
        TimedOut,
        Cancelled,
        Panicked,
    }

    fn run_callback<'a, F>(inner: &DispatcherInner, create: F)
    where
        F: FnOnce(
            LifecycleNotificationContext,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<(), rust_agent_runtime_api::LifecycleObserverError>>
                    + Send
                    + 'a,
            >,
        >,
    {
        let cancellation = CancellationToken::new();
        *inner
            .active_cancellation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cancellation.clone());
        if inner.force_stop.load(Ordering::Acquire) {
            cancellation.cancel();
        }
        let Ok(runtime_now) = inner.runtime.now() else {
            cancellation.cancel();
            ObserverDiagnosticCounters::increment(&inner.diagnostics.runtime_failures);
            inner
                .active_cancellation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            return;
        };
        let Some(runtime_deadline) = runtime_now.checked_add(inner.callback_timeout) else {
            cancellation.cancel();
            ObserverDiagnosticCounters::increment(&inner.diagnostics.runtime_failures);
            inner
                .active_cancellation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            return;
        };
        let Ok(deadline_wait) = inner.runtime.sleep_until(runtime_deadline) else {
            cancellation.cancel();
            ObserverDiagnosticCounters::increment(&inner.diagnostics.runtime_failures);
            inner
                .active_cancellation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            return;
        };
        let context = LifecycleNotificationContext::new(
            cancellation.clone(),
            runtime_deadline,
            inner.runtime.clone(),
        );
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let future = create(context);
            run_until(future, deadline_wait, &cancellation)
        }));
        match outcome {
            Ok(CallbackRunOutcome::Completed(Ok(()))) => {}
            Ok(CallbackRunOutcome::Completed(Err(_))) => {
                ObserverDiagnosticCounters::increment(&inner.diagnostics.callback_errors);
            }
            Ok(CallbackRunOutcome::TimedOut) => {
                ObserverDiagnosticCounters::increment(&inner.diagnostics.callback_timeouts);
            }
            Ok(CallbackRunOutcome::Cancelled) => {
                ObserverDiagnosticCounters::increment(
                    &inner.diagnostics.forced_callback_cancellations,
                );
            }
            Ok(CallbackRunOutcome::Panicked) | Err(_) => {
                ObserverDiagnosticCounters::increment(&inner.diagnostics.callback_panics);
            }
        }
        inner
            .active_cancellation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
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
        mut deadline_wait: rust_agent_runtime_api::RuntimeFuture<'static, ()>,
        cancellation: &CancellationToken,
    ) -> CallbackRunOutcome<F::Output> {
        let mut future = std::pin::pin!(future);
        let mut cancelled = std::pin::pin!(cancellation.cancelled());
        let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
        let mut context = Context::from_waker(&waker);
        loop {
            let polled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if cancelled.as_mut().poll(&mut context).is_ready() {
                    return Poll::Ready(CallbackRunOutcome::Cancelled);
                }
                if deadline_wait.as_mut().poll(&mut context).is_ready() {
                    cancellation.cancel();
                    return Poll::Ready(CallbackRunOutcome::TimedOut);
                }
                Pin::as_mut(&mut future)
                    .poll(&mut context)
                    .map(CallbackRunOutcome::Completed)
            }));
            match polled {
                Ok(Poll::Ready(outcome)) => return outcome,
                Ok(Poll::Pending) => thread::park(),
                Err(_) => {
                    cancellation.cancel();
                    return CallbackRunOutcome::Panicked;
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::{
            future,
            num::NonZeroU64,
            sync::atomic::{AtomicUsize, Ordering},
            time::Instant,
        };

        use rust_agent_core::AgentId;
        use rust_agent_runtime_api::{
            AgentLifecycleNonce, LifecycleObserverFuture, PublicationCandidate,
            PublicationTransactionView, PublicationVeto, PublishedSessionMode,
            RuntimeAdapterIdentity, RuntimeClock, RuntimeFuture, RuntimePrimitiveError,
            RuntimeSleeper, RuntimeSpawner, RuntimeTaskOwner, new_publication_directory,
        };

        use super::*;

        enum Behavior {
            Error,
            Panic,
            Never,
            Count(Arc<AtomicUsize>),
        }

        struct TestObserver(Behavior);

        impl LifecycleObserver for TestObserver {
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
                match &self.0 {
                    Behavior::Error => Box::pin(async {
                        Err(rust_agent_runtime_api::LifecycleObserverError {
                            reason: "contained observer error".into(),
                        })
                    }),
                    Behavior::Panic => Box::pin(async { panic!("contained observer panic") }),
                    Behavior::Never => Box::pin(future::pending()),
                    Behavior::Count(count) => {
                        count.fetch_add(1, Ordering::AcqRel);
                        Box::pin(async { Ok(()) })
                    }
                }
            }

            fn disposed<'a>(
                &'a self,
                _context: LifecycleNotificationContext,
                _event: &'a DisposalEvent,
                _snapshot: &'a PublicationSnapshot,
            ) -> LifecycleObserverFuture<'a> {
                match &self.0 {
                    Behavior::Error => Box::pin(async {
                        Err(rust_agent_runtime_api::LifecycleObserverError {
                            reason: "contained observer error".into(),
                        })
                    }),
                    Behavior::Panic => Box::pin(async { panic!("contained observer panic") }),
                    Behavior::Never => Box::pin(future::pending()),
                    Behavior::Count(count) => {
                        count.fetch_add(1, Ordering::AcqRel);
                        Box::pin(async { Ok(()) })
                    }
                }
            }
        }

        fn publication() -> (PublicationEvent, PublicationSnapshot) {
            let (directory, writer) = new_publication_directory();
            let candidate = PublicationCandidate::for_generated_agent(
                AgentId::from_nonzero_u128(1).unwrap(),
                AgentLifecycleNonce::from_nonzero(NonZeroU64::new(1).unwrap()),
                None,
                PublishedSessionMode::Sessionless,
            );
            let (event, snapshot) = writer.publish(candidate).unwrap();
            assert_eq!(directory.snapshot(), snapshot);
            (event, snapshot)
        }

        #[derive(Debug)]
        struct ImmediateDeadlineRuntime;

        impl RuntimeClock for ImmediateDeadlineRuntime {
            fn now(&self) -> rust_agent_runtime_api::RuntimeInstant {
                rust_agent_runtime_api::RuntimeInstant::from_monotonic_duration(Duration::ZERO)
            }
        }

        impl RuntimeSleeper for ImmediateDeadlineRuntime {
            fn sleep_until(
                &self,
                _deadline: rust_agent_runtime_api::RuntimeInstant,
            ) -> RuntimeFuture<'static, ()> {
                Box::pin(async {})
            }
        }

        impl RuntimeSpawner for ImmediateDeadlineRuntime {
            fn spawn(
                &self,
                _owner: RuntimeTaskOwner,
                _task: RuntimeFuture<'static, ()>,
            ) -> Result<(), RuntimePrimitiveError> {
                Err(RuntimePrimitiveError::SpawnFailed)
            }

            fn drain(&self, _owner: RuntimeTaskOwner) -> RuntimeFuture<'static, ()> {
                Box::pin(async {})
            }
        }

        #[test]
        fn callback_timeout_is_driven_by_the_selected_runtime_sleeper() {
            let adapter = Arc::new(ImmediateDeadlineRuntime);
            let runtime = RuntimePrimitives::from_adapter(
                RuntimeAdapterIdentity::checked("runtime-immediate-deadline").unwrap(),
                Arc::clone(&adapter),
                adapter.clone(),
                adapter.clone(),
                adapter,
            );
            let observers: Arc<[Arc<dyn LifecycleObserver>]> =
                Arc::from([Arc::new(TestObserver(Behavior::Never)) as Arc<dyn LifecycleObserver>]);
            let dispatcher = ObserverDispatcher::new(
                observers,
                runtime,
                2,
                Duration::from_secs(30),
                Duration::from_secs(1),
            )
            .unwrap();
            let mut reservation = dispatcher.reserve_pair().unwrap();
            let (event, snapshot) = publication();
            reservation.published(event, snapshot);
            drop(reservation);

            let deadline = Instant::now() + Duration::from_secs(1);
            while dispatcher.diagnostics().callback_timeouts() == 0 && Instant::now() < deadline {
                thread::yield_now();
            }

            assert_eq!(dispatcher.diagnostics().callback_timeouts(), 1);
            dispatcher.shutdown();
        }

        #[test]
        fn bounded_dispatcher_contains_timeout_panic_and_shutdown() {
            let count = Arc::new(AtomicUsize::new(0));
            let observers: Arc<[Arc<dyn LifecycleObserver>]> = Arc::from([
                Arc::new(TestObserver(Behavior::Panic)) as Arc<dyn LifecycleObserver>,
                Arc::new(TestObserver(Behavior::Error)),
                Arc::new(TestObserver(Behavior::Count(Arc::clone(&count)))),
            ]);
            let dispatcher = ObserverDispatcher::new(
                observers,
                rust_agent_runtime_tokio::create_runtime_primitives().unwrap(),
                2,
                Duration::from_millis(250),
                Duration::from_secs(1),
            )
            .unwrap();
            let mut reservation = dispatcher.reserve_pair().unwrap();
            let (event, snapshot) = publication();
            reservation.published(event, snapshot);
            let deadline = Instant::now() + Duration::from_secs(1);
            while count.load(Ordering::Acquire) == 0 && Instant::now() < deadline {
                thread::yield_now();
            }
            assert_eq!(count.load(Ordering::Acquire), 1);
            let diagnostics = dispatcher.diagnostics();
            assert_eq!(diagnostics.callback_panics(), 1);
            assert_eq!(diagnostics.callback_errors(), 1);
            drop(reservation);
            dispatcher.shutdown();

            let observers: Arc<[Arc<dyn LifecycleObserver>]> =
                Arc::from([Arc::new(TestObserver(Behavior::Never)) as Arc<dyn LifecycleObserver>]);
            let dispatcher = ObserverDispatcher::new(
                observers,
                rust_agent_runtime_tokio::create_runtime_primitives().unwrap(),
                2,
                Duration::from_millis(250),
                Duration::from_secs(1),
            )
            .unwrap();
            let mut reservation = dispatcher.reserve_pair().unwrap();
            let (event, snapshot) = publication();
            reservation.published(event, snapshot);
            drop(reservation);
            thread::sleep(Duration::from_millis(10));
            let started = Instant::now();
            dispatcher.shutdown();
            assert!(started.elapsed() < Duration::from_secs(1));
            assert_eq!(dispatcher.diagnostics().callback_timeouts(), 1);
        }

        #[test]
        fn shutdown_drains_reserved_notifications_before_forcing_cancellation() {
            let count = Arc::new(AtomicUsize::new(0));
            let observers: Arc<[Arc<dyn LifecycleObserver>]> =
                Arc::from([Arc::new(TestObserver(Behavior::Count(Arc::clone(&count))))
                    as Arc<dyn LifecycleObserver>]);
            let dispatcher = ObserverDispatcher::new(
                observers,
                rust_agent_runtime_tokio::create_runtime_primitives().unwrap(),
                2,
                Duration::from_millis(250),
                Duration::from_secs(1),
            )
            .unwrap();
            let mut reservation = dispatcher.reserve_pair().unwrap();
            let (directory, writer) = new_publication_directory();
            let agent_id = AgentId::from_nonzero_u128(2).unwrap();
            let lifecycle = AgentLifecycleNonce::from_nonzero(NonZeroU64::new(2).unwrap());
            let candidate = PublicationCandidate::for_generated_agent(
                agent_id,
                lifecycle,
                None,
                PublishedSessionMode::Sessionless,
            );
            let (published, published_snapshot) = writer.publish(candidate).unwrap();
            let (disposed, disposed_snapshot) = writer.remove(agent_id, lifecycle).unwrap();
            assert_eq!(directory.snapshot(), disposed_snapshot);
            reservation.published(published, published_snapshot);
            reservation.disposed(disposed, disposed_snapshot);

            dispatcher.shutdown();

            assert_eq!(count.load(Ordering::Acquire), 2);
            assert!(dispatcher.reserve_pair().is_none());
        }

        #[test]
        fn shutdown_deadline_cancels_remaining_notifications() {
            let observers: Arc<[Arc<dyn LifecycleObserver>]> =
                Arc::from([Arc::new(TestObserver(Behavior::Never)) as Arc<dyn LifecycleObserver>]);
            let dispatcher = ObserverDispatcher::new(
                observers,
                rust_agent_runtime_tokio::create_runtime_primitives().unwrap(),
                2,
                Duration::from_secs(5),
                Duration::from_millis(50),
            )
            .unwrap();
            let mut reservation = dispatcher.reserve_pair().unwrap();
            let (directory, writer) = new_publication_directory();
            let agent_id = AgentId::from_nonzero_u128(3).unwrap();
            let lifecycle = AgentLifecycleNonce::from_nonzero(NonZeroU64::new(3).unwrap());
            let candidate = PublicationCandidate::for_generated_agent(
                agent_id,
                lifecycle,
                None,
                PublishedSessionMode::Sessionless,
            );
            let (published, published_snapshot) = writer.publish(candidate).unwrap();
            let (disposed, disposed_snapshot) = writer.remove(agent_id, lifecycle).unwrap();
            assert_eq!(directory.snapshot(), disposed_snapshot);
            reservation.published(published, published_snapshot);
            reservation.disposed(disposed, disposed_snapshot);
            let started = Instant::now();

            dispatcher.shutdown();

            assert!(started.elapsed() < Duration::from_secs(1));
            let deadline = Instant::now() + Duration::from_secs(1);
            while (dispatcher.diagnostics().forced_callback_cancellations() == 0
                || dispatcher.diagnostics().dropped_notifications() == 0)
                && Instant::now() < deadline
            {
                thread::yield_now();
            }
            let diagnostics = dispatcher.diagnostics();
            assert_eq!(diagnostics.forced_callback_cancellations(), 1);
            assert_eq!(diagnostics.dropped_notifications(), 1);
        }

        #[test]
        fn drop_forces_dispatcher_shutdown_without_waiting_for_unpublished_reservations() {
            let dispatcher = ObserverDispatcher::new(
                Arc::from([]),
                rust_agent_runtime_tokio::create_runtime_primitives().unwrap(),
                2,
                Duration::from_millis(250),
                Duration::from_secs(3),
            )
            .unwrap();
            let reservation = dispatcher.reserve_pair().unwrap();
            let started = Instant::now();

            drop(dispatcher);

            assert!(started.elapsed() < Duration::from_secs(1));
            drop(reservation);
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
        pub(crate) fn new(
            observers: Arc<[Arc<dyn LifecycleObserver>]>,
            _runtime: rust_agent_runtime_api::RuntimePrimitives,
            _capacity: usize,
            _callback_timeout: std::time::Duration,
            _shutdown_timeout: std::time::Duration,
        ) -> Result<Self, super::ObserverDispatcherBuildError> {
            if observers.is_empty() {
                Ok(Self)
            } else {
                Err(super::ObserverDispatcherBuildError)
            }
        }

        pub(crate) fn reserve_pair(&self) -> Option<NotificationReservation> {
            Some(NotificationReservation)
        }

        pub(crate) fn shutdown(&self) {}

        pub(crate) fn diagnostics(&self) -> super::LifecycleObserverDiagnostics {
            super::LifecycleObserverDiagnostics::default()
        }

        pub(crate) fn record_callback_panic(&self) {}
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
