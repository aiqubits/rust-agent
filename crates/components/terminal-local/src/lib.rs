//! Provider-neutral local terminal adapter over sandboxed interactive subprocesses.

use std::{
    collections::BTreeMap,
    num::NonZeroU64,
    sync::{Arc, Mutex},
};

use rust_agent_core::{CanonicalId, SecurityEffects};
use rust_agent_process::{
    ProcessError, ProcessExecutable, ProcessFuture, ProcessHandle, ProcessSpec, SandboxBinding,
    SubprocessBinding, TerminalBytes, TerminalError, TerminalId, TerminalManager,
    TerminalReadRequest, TerminalSize, TerminalSpec,
};
use rust_agent_runtime_api::{
    CancellationToken, ComponentBuildError, ComponentOutput, Initializable, InitializeError,
    RuntimeFuture, RuntimePrimitiveBindings, Shutdown, ShutdownError,
};
use serde::Deserialize;

const PROVIDER_KEY: &str = "local";
const MAX_OPEN_TERMINALS: usize = 128;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    executable: String,
}

impl Config {
    pub fn checked(executable: impl Into<String>) -> Result<Self, ComponentBuildError> {
        let config = Self {
            executable: executable.into(),
        };
        validate_config(&config)?;
        Ok(config)
    }

    pub fn executable(&self) -> &str {
        &self.executable
    }
}

#[derive(Debug)]
pub struct Dependencies {
    pub subprocess: SubprocessBinding,
    pub sandbox: SandboxBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lifecycle {
    Uninitialized,
    Ready,
    Closed,
}

#[derive(Debug)]
struct State {
    lifecycle: Lifecycle,
    next_identity: u64,
    opening: usize,
    terminals: BTreeMap<NonZeroU64, Arc<ProcessHandle>>,
}

#[derive(Debug)]
pub struct LocalTerminal {
    executable: ProcessExecutable,
    subprocess: SubprocessBinding,
    sandbox: SandboxBinding,
    state: Mutex<State>,
}

impl LocalTerminal {
    fn reserve_open(&self) -> Result<OpenReservation<'_>, TerminalError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match state.lifecycle {
            Lifecycle::Uninitialized => return Err(TerminalError::OpenFailed),
            Lifecycle::Closed => return Err(TerminalError::Cancelled),
            Lifecycle::Ready => {}
        }
        if state.terminals.len().saturating_add(state.opening) >= MAX_OPEN_TERMINALS {
            return Err(TerminalError::OpenFailed);
        }
        let identity = NonZeroU64::new(state.next_identity).ok_or(TerminalError::OpenFailed)?;
        state.next_identity = state
            .next_identity
            .checked_add(1)
            .ok_or(TerminalError::OpenFailed)?;
        state.opening += 1;
        Ok(OpenReservation {
            terminal: self,
            identity,
            active: true,
        })
    }

    fn handle(&self, identity: NonZeroU64) -> Result<Arc<ProcessHandle>, TerminalError> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.lifecycle == Lifecycle::Closed {
            return Err(TerminalError::Cancelled);
        }
        state
            .terminals
            .get(&identity)
            .cloned()
            .ok_or(TerminalError::ForeignTerminal)
    }
}

struct OpenReservation<'a> {
    terminal: &'a LocalTerminal,
    identity: NonZeroU64,
    active: bool,
}

impl OpenReservation<'_> {
    fn retain(mut self, handle: Arc<ProcessHandle>) -> Result<NonZeroU64, Arc<ProcessHandle>> {
        let mut state = self
            .terminal
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.opening = state
            .opening
            .checked_sub(1)
            .expect("active reservation is counted");
        self.active = false;
        if state.lifecycle != Lifecycle::Ready {
            return Err(handle);
        }
        state.terminals.insert(self.identity, handle);
        Ok(self.identity)
    }
}

impl Drop for OpenReservation<'_> {
    fn drop(&mut self) {
        if self.active {
            let mut state = self
                .terminal
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.opening = state
                .opening
                .checked_sub(1)
                .expect("active reservation is counted");
        }
    }
}

impl TerminalManager for LocalTerminal {
    fn provider_key(&self) -> CanonicalId {
        provider_key()
    }

    fn effects(&self) -> SecurityEffects {
        SecurityEffects::PROCESS_EXEC | SecurityEffects::READ_LOCAL | SecurityEffects::WRITE_LOCAL
    }

    fn open_provider(
        &self,
        spec: TerminalSpec,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<NonZeroU64, TerminalError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(TerminalError::Cancelled);
            }
            let reservation = self.reserve_open()?;
            let Ok(process) = ProcessSpec::checked_terminal(
                self.executable.clone(),
                std::iter::empty(),
                spec.cwd().clone(),
                spec.environment().clone(),
                spec.size(),
            ) else {
                return Err(TerminalError::OpenFailed);
            };
            let Ok(confined) = self.sandbox.confine(process, spec.policy().clone()).await else {
                return Err(if cancellation.is_cancelled() {
                    TerminalError::Cancelled
                } else {
                    TerminalError::OpenFailed
                });
            };
            if cancellation.is_cancelled() {
                return Err(TerminalError::Cancelled);
            }
            let handle = match self.subprocess.spawn(confined, cancellation.clone()).await {
                Ok(handle) => Arc::new(handle),
                Err(error) => return Err(map_open_error(error)),
            };
            if cancellation.is_cancelled() {
                let _ = handle.terminate_tree().await;
                return Err(TerminalError::Cancelled);
            }
            match reservation.retain(handle) {
                Ok(identity) => Ok(identity),
                Err(handle) => {
                    let _ = handle.terminate_tree().await;
                    Err(TerminalError::Cancelled)
                }
            }
        })
    }

    fn write(
        &self,
        id: TerminalId,
        data: TerminalBytes,
    ) -> ProcessFuture<'_, Result<(), TerminalError>> {
        let handle = self.handle(id.identity());
        Box::pin(async move { handle?.write_terminal(data).await.map_err(map_write_error) })
    }

    fn read(
        &self,
        id: TerminalId,
        request: TerminalReadRequest,
    ) -> ProcessFuture<'_, Result<TerminalBytes, TerminalError>> {
        let handle = self.handle(id.identity());
        Box::pin(async move { handle?.read_terminal(request).await.map_err(map_read_error) })
    }

    fn resize(
        &self,
        id: TerminalId,
        size: TerminalSize,
    ) -> ProcessFuture<'_, Result<(), TerminalError>> {
        let handle = self.handle(id.identity());
        Box::pin(async move {
            handle?
                .resize_terminal(size)
                .await
                .map_err(map_resize_error)
        })
    }

    fn close(&self, id: TerminalId) -> ProcessFuture<'_, Result<(), TerminalError>> {
        Box::pin(async move {
            let handle = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.lifecycle == Lifecycle::Closed {
                    return Err(TerminalError::Cancelled);
                }
                state.terminals.remove(&id.identity())
            };
            handle
                .ok_or(TerminalError::ForeignTerminal)?
                .terminate_tree()
                .await
                .map_err(|_| TerminalError::CloseFailed)
        })
    }
}

impl Initializable for LocalTerminal {
    fn initialize(&self) -> RuntimeFuture<'_, Result<(), InitializeError>> {
        let result = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match state.lifecycle {
                Lifecycle::Uninitialized => {
                    state.lifecycle = Lifecycle::Ready;
                    Ok(())
                }
                Lifecycle::Ready => Err(InitializeError::AlreadyInitialized),
                Lifecycle::Closed => Err(InitializeError::ScopeClosed),
            }
        };
        Box::pin(async move { result })
    }
}

impl Shutdown for LocalTerminal {
    fn shutdown(&self) -> RuntimeFuture<'_, Result<(), ShutdownError>> {
        Box::pin(async move {
            let handles = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.lifecycle = Lifecycle::Closed;
                std::mem::take(&mut state.terminals).into_values()
            };
            let mut failed = false;
            for handle in handles {
                if handle.terminate_tree().await.is_err() {
                    failed = true;
                }
            }
            if failed {
                Err(ShutdownError::ResourceTeardownFailed)
            } else {
                Ok(())
            }
        })
    }
}

pub fn build(
    config: &Config,
    dependencies: Dependencies,
    runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<LocalTerminal>, ComponentBuildError> {
    validate_runtime_primitives(runtime.allowed())?;
    drop(runtime);
    validate_config(config)?;
    Ok(ComponentOutput::initializable(LocalTerminal {
        executable: ProcessExecutable::absolute(config.executable.clone()).map_err(|_| {
            ComponentBuildError::InvalidConfig(
                "terminal executable must be canonical and absolute".into(),
            )
        })?,
        subprocess: dependencies.subprocess,
        sandbox: dependencies.sandbox,
        state: Mutex::new(State {
            lifecycle: Lifecycle::Uninitialized,
            next_identity: 1,
            opening: 0,
            terminals: BTreeMap::new(),
        }),
    }))
}

fn validate_runtime_primitives(
    primitives: &[rust_agent_runtime_api::RuntimePrimitiveKind],
) -> Result<(), ComponentBuildError> {
    if primitives.is_empty() {
        Ok(())
    } else {
        Err(ComponentBuildError::InvalidConfig(
            "terminal-local declares no runtime primitives".into(),
        ))
    }
}

fn validate_config(config: &Config) -> Result<(), ComponentBuildError> {
    ProcessExecutable::absolute(config.executable.clone()).map_err(|_| {
        ComponentBuildError::InvalidConfig(
            "terminal executable must be canonical and absolute".into(),
        )
    })?;
    Ok(())
}

fn provider_key() -> CanonicalId {
    CanonicalId::new(PROVIDER_KEY).expect("static provider key is canonical")
}

fn map_open_error(error: ProcessError) -> TerminalError {
    match error {
        ProcessError::Cancelled => TerminalError::Cancelled,
        ProcessError::DeadlineExceeded => TerminalError::DeadlineExceeded,
        ProcessError::OutputBudgetExceeded => TerminalError::IoBudgetExceeded,
        _ => TerminalError::OpenFailed,
    }
}

fn map_write_error(error: ProcessError) -> TerminalError {
    match error {
        ProcessError::Cancelled => TerminalError::Cancelled,
        ProcessError::DeadlineExceeded => TerminalError::DeadlineExceeded,
        ProcessError::OutputBudgetExceeded => TerminalError::IoBudgetExceeded,
        _ => TerminalError::WriteFailed,
    }
}

fn map_read_error(error: ProcessError) -> TerminalError {
    match error {
        ProcessError::Cancelled => TerminalError::Cancelled,
        ProcessError::DeadlineExceeded => TerminalError::DeadlineExceeded,
        ProcessError::OutputBudgetExceeded => TerminalError::IoBudgetExceeded,
        _ => TerminalError::ReadFailed,
    }
}

fn map_resize_error(error: ProcessError) -> TerminalError {
    match error {
        ProcessError::Cancelled => TerminalError::Cancelled,
        ProcessError::DeadlineExceeded => TerminalError::DeadlineExceeded,
        ProcessError::OutputBudgetExceeded => TerminalError::IoBudgetExceeded,
        _ => TerminalError::ResizeFailed,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
