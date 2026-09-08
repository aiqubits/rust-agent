//! Native runtime adapter that owns an independent Tokio driver.

use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Instant,
};

use rust_agent_runtime_api::{
    RuntimeAdapterIdentity, RuntimeClock, RuntimeFuture, RuntimeInstant, RuntimePrimitiveError,
    RuntimePrimitives, RuntimeSleeper, RuntimeSpawner, RuntimeTaskOwner,
};

#[derive(Debug)]
struct TokioDriver {
    handle: tokio::runtime::Handle,
    origin: Instant,
    state: Arc<TokioState>,
}

#[derive(Debug, Default)]
struct OwnerTasks {
    tasks: BTreeMap<u64, tokio::task::AbortHandle>,
    waiters: BTreeMap<u64, Waker>,
}

#[derive(Debug)]
struct TokioState {
    owners: Mutex<BTreeMap<u64, OwnerTasks>>,
    next_task: AtomicU64,
    next_waiter: AtomicU64,
}

impl Default for TokioState {
    fn default() -> Self {
        Self {
            owners: Mutex::new(BTreeMap::new()),
            next_task: AtomicU64::new(1),
            next_waiter: AtomicU64::new(1),
        }
    }
}

#[derive(Debug)]
struct TaskCompletion {
    state: Arc<TokioState>,
    owner_id: u64,
    task_id: u64,
}

impl Drop for TaskCompletion {
    fn drop(&mut self) {
        let waiters = {
            let mut owners = self
                .state
                .owners
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(tasks) = owners.get_mut(&self.owner_id) else {
                return;
            };
            tasks.tasks.remove(&self.task_id);
            if tasks.tasks.is_empty() {
                let waiters = std::mem::take(&mut tasks.waiters);
                owners.remove(&self.owner_id);
                waiters
            } else {
                BTreeMap::new()
            }
        };
        for waker in waiters.into_values() {
            waker.wake();
        }
    }
}

#[derive(Debug)]
struct TokioDrain {
    state: Arc<TokioState>,
    owner_id: u64,
    waiter_id: Option<u64>,
    complete: bool,
}

impl Future for TokioDrain {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.complete {
            return Poll::Ready(());
        }
        {
            let mut owners = self
                .state
                .owners
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match owners.get(&self.owner_id) {
                None => {
                    drop(owners);
                    self.complete = true;
                    return Poll::Ready(());
                }
                Some(tasks) if tasks.tasks.is_empty() => {
                    owners.remove(&self.owner_id);
                    drop(owners);
                    self.complete = true;
                    return Poll::Ready(());
                }
                Some(_) => {}
            }
        }
        let waiter_id = match self.waiter_id {
            Some(waiter_id) => waiter_id,
            None => {
                if let Some(waiter_id) = next_id(&self.state.next_waiter) {
                    self.waiter_id = Some(waiter_id);
                    waiter_id
                } else {
                    self.abort_owner_tasks();
                    context.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
        };
        let mut owners = self
            .state
            .owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(tasks) = owners.get_mut(&self.owner_id) else {
            drop(owners);
            self.complete = true;
            return Poll::Ready(());
        };
        if tasks.tasks.is_empty() {
            owners.remove(&self.owner_id);
            drop(owners);
            self.complete = true;
            return Poll::Ready(());
        }
        tasks.waiters.insert(waiter_id, context.waker().clone());
        Poll::Pending
    }
}

impl TokioDrain {
    fn abort_owner_tasks(&self) {
        let handles = self
            .state
            .owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&self.owner_id)
            .map(|tasks| tasks.tasks.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        for handle in handles {
            handle.abort();
        }
    }
}

impl Drop for TokioDrain {
    fn drop(&mut self) {
        if self.complete {
            return;
        }
        if let Some(waiter_id) = self.waiter_id
            && let Some(tasks) = self
                .state
                .owners
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get_mut(&self.owner_id)
        {
            tasks.waiters.remove(&waiter_id);
        }
        self.abort_owner_tasks();
    }
}

#[derive(Debug)]
struct TokioRuntimeOwner {
    runtime: Option<tokio::runtime::Runtime>,
    driver: Arc<TokioDriver>,
}

impl Drop for TokioRuntimeOwner {
    fn drop(&mut self) {
        let handles = {
            let owners = self
                .driver
                .state
                .owners
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            owners
                .values()
                .flat_map(|tasks| tasks.tasks.values().cloned())
                .collect::<Vec<_>>()
        };
        for handle in handles {
            handle.abort();
        }
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl RuntimeClock for TokioDriver {
    fn now(&self) -> RuntimeInstant {
        RuntimeInstant::from_monotonic_duration(self.origin.elapsed())
    }
}

impl RuntimeSleeper for TokioDriver {
    fn sleep_until(&self, deadline: RuntimeInstant) -> RuntimeFuture<'static, ()> {
        let _entered = self.handle.enter();
        let sleep = tokio::time::sleep(deadline.saturating_duration_since(self.now()));
        Box::pin(sleep)
    }
}

impl RuntimeSpawner for TokioDriver {
    fn spawn(
        &self,
        owner: RuntimeTaskOwner,
        task: RuntimeFuture<'static, ()>,
    ) -> Result<(), RuntimePrimitiveError> {
        let task_id =
            next_id(&self.state.next_task).ok_or(RuntimePrimitiveError::TaskOwnerExhausted)?;
        let mut owners = self
            .state
            .owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if owner.is_draining() {
            return Err(RuntimePrimitiveError::TaskOwnerClosed);
        }
        let owner_id = owner.id();
        let completion = TaskCompletion {
            state: Arc::clone(&self.state),
            owner_id,
            task_id,
        };
        let task = self.handle.spawn(async move {
            let _completion = completion;
            task.await;
        });
        owners
            .entry(owner_id)
            .or_default()
            .tasks
            .insert(task_id, task.abort_handle());
        Ok(())
    }

    fn drain(&self, owner: RuntimeTaskOwner) -> RuntimeFuture<'static, ()> {
        Box::pin(TokioDrain {
            state: Arc::clone(&self.state),
            owner_id: owner.id(),
            waiter_id: None,
            complete: false,
        })
    }
}

fn next_id(counter: &AtomicU64) -> Option<u64> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .ok()
}

pub fn create_runtime_primitives() -> Result<RuntimePrimitives, RuntimePrimitiveError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_time()
        .build()
        .map_err(|_| RuntimePrimitiveError::DriverConstructionFailed)?;
    let driver = Arc::new(TokioDriver {
        handle: runtime.handle().clone(),
        origin: Instant::now(),
        state: Arc::new(TokioState::default()),
    });
    let owner = Arc::new(TokioRuntimeOwner {
        runtime: Some(runtime),
        driver: Arc::clone(&driver),
    });
    let clock: Arc<dyn RuntimeClock> = owner.driver.clone();
    let sleeper: Arc<dyn RuntimeSleeper> = owner.driver.clone();
    let spawner: Arc<dyn RuntimeSpawner> = owner.driver.clone();
    Ok(RuntimePrimitives::from_adapter(
        RuntimeAdapterIdentity::checked("runtime-tokio")?,
        owner,
        clock,
        sleeper,
        spawner,
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        future,
        sync::Arc,
        task::{Context, Poll, Wake, Waker},
        thread,
    };

    use super::*;

    struct ThreadWake(thread::Thread);

    impl Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
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

    #[test]
    fn every_bundle_owns_an_independent_runtime() {
        let first = create_runtime_primitives().unwrap();
        let second = create_runtime_primitives().unwrap();
        assert!(first.has_owned_driver());
        assert!(second.has_owned_driver());
        assert!(!first.same_bundle_identity(&second));
        assert!(first.now().is_ok());
        assert!(first.sleep_until(first.now().unwrap()).is_ok());

        let owner = first.new_task_owner().unwrap();
        first
            .spawn(owner.clone(), Box::pin(future::pending()))
            .unwrap();
        let mut cancelled_drain = first.drain(owner.clone()).unwrap();
        let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
        let mut context = Context::from_waker(&waker);
        assert!(cancelled_drain.as_mut().poll(&mut context).is_pending());
        drop(cancelled_drain);
        run(first.drain(owner.clone()).unwrap());
        assert_eq!(
            first.spawn(owner, Box::pin(async {})),
            Err(RuntimePrimitiveError::TaskOwnerClosed)
        );
    }

    #[test]
    fn owned_runtime_can_be_dropped_inside_an_outer_tokio_task() {
        let outer = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        outer.block_on(async {
            let inner = create_runtime_primitives().unwrap();
            drop(inner);
        });
    }

    #[test]
    fn exhausted_drain_waiter_ids_still_reach_quiescence() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_time()
            .build()
            .unwrap();
        let state = Arc::new(TokioState::default());
        let completion = TaskCompletion {
            state: Arc::clone(&state),
            owner_id: 7,
            task_id: 11,
        };
        let task = runtime.spawn(async move {
            let _completion = completion;
            future::pending::<()>().await;
        });
        state
            .owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(7)
            .or_default()
            .tasks
            .insert(11, task.abort_handle());
        state.next_waiter.store(u64::MAX, Ordering::Release);

        run(TokioDrain {
            state,
            owner_id: 7,
            waiter_id: None,
            complete: false,
        });
        runtime.shutdown_background();
    }
}
