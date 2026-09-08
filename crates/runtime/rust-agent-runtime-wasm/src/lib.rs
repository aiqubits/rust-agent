//! Browser-local runtime adapter backed by the JavaScript event loop.

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod browser {
    use std::{
        collections::BTreeMap,
        future::Future,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, Ordering},
        },
        task::{Context, Poll, Waker},
        time::Duration,
    };

    use futures_util::future::{AbortHandle, Abortable};
    use rust_agent_runtime_api::{
        RuntimeAdapterIdentity, RuntimeClock, RuntimeFuture, RuntimeInstant, RuntimePrimitiveError,
        RuntimePrimitives, RuntimeSleeper, RuntimeSpawner, RuntimeTaskOwner,
    };
    use wasm_bindgen::prelude::wasm_bindgen;
    use wasm_bindgen_futures::{JsFuture, spawn_local};

    const MAX_TIMER_MILLIS: f64 = 2_147_483_647.0;

    #[wasm_bindgen(inline_js = r#"
        let rustAgentRuntimeActiveTimerCount = 0;

        export function rustAgentRuntimeNow() {
            return globalThis.performance.now();
        }

        export function rustAgentRuntimeTimer(milliseconds) {
            const state = { active: true, handle: undefined };
            const promise = new Promise((resolve) => {
                rustAgentRuntimeActiveTimerCount += 1;
                state.handle = globalThis.setTimeout(() => {
                    if (state.active) {
                        state.active = false;
                        rustAgentRuntimeActiveTimerCount -= 1;
                    }
                    resolve();
                }, milliseconds);
            });
            return {
                promise,
                cancel() {
                    if (state.active) {
                        state.active = false;
                        globalThis.clearTimeout(state.handle);
                        rustAgentRuntimeActiveTimerCount -= 1;
                    }
                },
            };
        }

        export function rustAgentRuntimeActiveTimers() {
            return rustAgentRuntimeActiveTimerCount;
        }
    "#)]
    extern "C" {
        #[wasm_bindgen(js_name = rustAgentRuntimeNow)]
        fn runtime_now_milliseconds() -> f64;

        #[wasm_bindgen(js_name = rustAgentRuntimeTimer)]
        fn runtime_timer(milliseconds: f64) -> BrowserTimer;

        type BrowserTimer;

        #[wasm_bindgen(method, getter)]
        fn promise(this: &BrowserTimer) -> js_sys::Promise;

        #[wasm_bindgen(method)]
        fn cancel(this: &BrowserTimer);

        #[cfg(test)]
        #[wasm_bindgen(js_name = rustAgentRuntimeActiveTimers)]
        fn runtime_active_timers() -> u32;
    }

    struct BrowserTimerFuture {
        timer: BrowserTimer,
        future: Pin<Box<JsFuture>>,
        completed: bool,
    }

    impl BrowserTimerFuture {
        fn new(milliseconds: f64) -> Self {
            let timer = runtime_timer(milliseconds);
            let future = Box::pin(JsFuture::from(timer.promise()));
            Self {
                timer,
                future,
                completed: false,
            }
        }
    }

    impl Future for BrowserTimerFuture {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            match self.future.as_mut().poll(context) {
                Poll::Ready(_) => {
                    self.completed = true;
                    Poll::Ready(())
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl Drop for BrowserTimerFuture {
        fn drop(&mut self) {
            if !self.completed {
                self.timer.cancel();
            }
        }
    }

    #[derive(Debug, Default)]
    struct OwnerTasks {
        tasks: BTreeMap<u64, AbortHandle>,
        waiters: BTreeMap<u64, Waker>,
    }

    #[derive(Debug)]
    struct WasmState {
        owners: Mutex<BTreeMap<u64, OwnerTasks>>,
        next_task: AtomicU64,
        next_waiter: AtomicU64,
    }

    impl Default for WasmState {
        fn default() -> Self {
            Self {
                owners: Mutex::new(BTreeMap::new()),
                next_task: AtomicU64::new(1),
                next_waiter: AtomicU64::new(1),
            }
        }
    }

    #[derive(Debug)]
    struct WasmDriver {
        state: Arc<WasmState>,
        origin_milliseconds: f64,
    }

    #[derive(Debug)]
    struct WasmRuntimeOwner {
        driver: Arc<WasmDriver>,
    }

    #[derive(Debug)]
    struct WasmDrain {
        state: Arc<WasmState>,
        owner_id: u64,
        waiter_id: Option<u64>,
        complete: bool,
    }

    impl Future for WasmDrain {
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

    impl WasmDrain {
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

    impl Drop for WasmDrain {
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

    impl Drop for WasmRuntimeOwner {
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
        }
    }

    impl RuntimeClock for WasmDriver {
        fn now(&self) -> RuntimeInstant {
            runtime_instant(self.origin_milliseconds)
        }
    }

    impl RuntimeSleeper for WasmDriver {
        fn sleep_until(&self, deadline: RuntimeInstant) -> RuntimeFuture<'static, ()> {
            let origin_milliseconds = self.origin_milliseconds;
            Box::pin(async move {
                loop {
                    let now = runtime_instant(origin_milliseconds);
                    let remaining = deadline.saturating_duration_since(now);
                    if remaining == Duration::ZERO {
                        return;
                    }
                    let milliseconds = remaining.as_secs_f64().mul_add(1_000.0, 0.0);
                    let milliseconds = milliseconds.clamp(1.0, MAX_TIMER_MILLIS);
                    BrowserTimerFuture::new(milliseconds).await;
                }
            })
        }
    }

    impl RuntimeSpawner for WasmDriver {
        fn spawn(
            &self,
            owner: RuntimeTaskOwner,
            task: RuntimeFuture<'static, ()>,
        ) -> Result<(), RuntimePrimitiveError> {
            let task_id =
                next_id(&self.state.next_task).ok_or(RuntimePrimitiveError::TaskOwnerExhausted)?;
            let (abort_handle, abort_registration) = AbortHandle::new_pair();
            {
                let mut owners = self
                    .state
                    .owners
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if owner.is_draining() {
                    return Err(RuntimePrimitiveError::TaskOwnerClosed);
                }
                owners
                    .entry(owner.id())
                    .or_default()
                    .tasks
                    .insert(task_id, abort_handle);
            }

            let state = Arc::clone(&self.state);
            let owner_id = owner.id();
            spawn_local(async move {
                let _ = Abortable::new(task, abort_registration).await;
                let waiters = {
                    let mut owners = state
                        .owners
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let Some(tasks) = owners.get_mut(&owner_id) else {
                        return;
                    };
                    tasks.tasks.remove(&task_id);
                    if tasks.tasks.is_empty() {
                        let waiters = std::mem::take(&mut tasks.waiters);
                        owners.remove(&owner_id);
                        waiters
                    } else {
                        BTreeMap::new()
                    }
                };
                for waker in waiters.into_values() {
                    waker.wake();
                }
            });
            Ok(())
        }

        fn drain(&self, owner: RuntimeTaskOwner) -> RuntimeFuture<'static, ()> {
            Box::pin(WasmDrain {
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

    fn runtime_instant(origin_milliseconds: f64) -> RuntimeInstant {
        let elapsed_milliseconds = runtime_now_milliseconds() - origin_milliseconds;
        let elapsed = if elapsed_milliseconds.is_finite() && elapsed_milliseconds > 0.0 {
            Duration::from_secs_f64(elapsed_milliseconds / 1_000.0)
        } else {
            Duration::ZERO
        };
        RuntimeInstant::from_monotonic_duration(elapsed)
    }

    pub fn create_runtime_primitives() -> Result<RuntimePrimitives, RuntimePrimitiveError> {
        let driver = Arc::new(WasmDriver {
            state: Arc::new(WasmState::default()),
            origin_milliseconds: runtime_now_milliseconds(),
        });
        let owner = Arc::new(WasmRuntimeOwner {
            driver: Arc::clone(&driver),
        });
        let clock: Arc<dyn RuntimeClock> = owner.driver.clone();
        let sleeper: Arc<dyn RuntimeSleeper> = owner.driver.clone();
        let spawner: Arc<dyn RuntimeSpawner> = owner.driver.clone();
        Ok(RuntimePrimitives::from_adapter(
            RuntimeAdapterIdentity::checked("runtime-wasm")?,
            owner,
            clock,
            sleeper,
            spawner,
        ))
    }

    #[cfg(test)]
    mod tests {
        use futures_util::future::poll_fn;
        use rust_agent_runtime_api::CancellationToken;
        use wasm_bindgen::JsValue;
        use wasm_bindgen_test::wasm_bindgen_test;

        use super::*;

        async fn yield_to_javascript() {
            let _ = JsFuture::from(js_sys::Promise::resolve(&JsValue::UNDEFINED)).await;
        }

        #[wasm_bindgen_test]
        async fn dropping_sleep_and_owner_drain_cancel_underlying_javascript_timers() {
            let runtime = create_runtime_primitives().unwrap();
            let deadline = runtime.now().unwrap() + Duration::from_secs(60);
            let mut sleep = runtime.sleep_until(deadline).unwrap();
            poll_fn(|context| {
                assert!(sleep.as_mut().poll(context).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(runtime_active_timers(), 1);
            drop(sleep);
            assert_eq!(runtime_active_timers(), 0);

            let owner = runtime.new_task_owner().unwrap();
            let cancellation = CancellationToken::new();
            let task_cancellation = cancellation.clone();
            let task_runtime = runtime.clone();
            runtime
                .spawn(
                    owner.clone(),
                    Box::pin(async move {
                        let deadline = task_runtime.now().unwrap() + Duration::from_secs(60);
                        let mut sleep = task_runtime.sleep_until(deadline).unwrap();
                        let mut cancelled = Box::pin(task_cancellation.cancelled());
                        poll_fn(|context| {
                            if cancelled.as_mut().poll(context).is_ready() {
                                return Poll::Ready(());
                            }
                            sleep.as_mut().poll(context)
                        })
                        .await;
                    }),
                )
                .unwrap();
            for _ in 0..10 {
                if runtime_active_timers() == 1 {
                    break;
                }
                yield_to_javascript().await;
            }
            assert_eq!(runtime_active_timers(), 1);
            cancellation.cancel();
            runtime.drain(owner).unwrap().await;
            assert_eq!(runtime_active_timers(), 0);
        }

        #[wasm_bindgen_test]
        async fn exhausted_drain_waiter_ids_still_reach_quiescence() {
            let state = Arc::new(WasmState::default());
            let (abort_handle, abort_registration) = AbortHandle::new_pair();
            state
                .owners
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry(7)
                .or_default()
                .tasks
                .insert(11, abort_handle);
            let completion_state = Arc::clone(&state);
            spawn_local(async move {
                let _ = Abortable::new(std::future::pending::<()>(), abort_registration).await;
                completion_state
                    .owners
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&7);
            });
            state.next_waiter.store(u64::MAX, Ordering::Release);

            WasmDrain {
                state: Arc::clone(&state),
                owner_id: 7,
                waiter_id: None,
                complete: false,
            }
            .await;
            assert!(
                !state
                    .owners
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains_key(&7)
            );
        }
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub use browser::create_runtime_primitives;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub fn create_runtime_primitives()
-> Result<rust_agent_runtime_api::RuntimePrimitives, rust_agent_runtime_api::RuntimePrimitiveError>
{
    Err(rust_agent_runtime_api::RuntimePrimitiveError::DriverConstructionFailed)
}
