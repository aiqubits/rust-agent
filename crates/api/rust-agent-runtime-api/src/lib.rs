//! Effect-free runtime primitives and shared lifecycle protocol types.

use std::{fmt, sync::Arc};

pub use rust_agent_core::{AgentOperationRecoveryKey, Digest};

/// Opaque identity of the runtime adapter that created a primitive bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAdapterIdentity(Arc<str>);

impl RuntimeAdapterIdentity {
    pub fn checked(value: impl Into<Arc<str>>) -> Result<Self, RuntimePrimitiveError> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 || !value.is_ascii() {
            return Err(RuntimePrimitiveError::InvalidAdapterIdentity);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An owned runtime primitive bundle. Phase 1A fixtures carry identity only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePrimitives {
    adapter: RuntimeAdapterIdentity,
}

impl RuntimePrimitives {
    pub fn new(adapter: RuntimeAdapterIdentity) -> Self {
        Self { adapter }
    }

    pub fn adapter(&self) -> &RuntimeAdapterIdentity {
        &self.adapter
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimePrimitiveError {
    InvalidAdapterIdentity,
    AdapterMismatch { expected: String, actual: String },
}

impl fmt::Display for RuntimePrimitiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAdapterIdentity => formatter.write_str("invalid runtime adapter identity"),
            Self::AdapterMismatch { expected, actual } => {
                write!(
                    formatter,
                    "runtime adapter mismatch: expected {expected}, got {actual}"
                )
            }
        }
    }
}

impl std::error::Error for RuntimePrimitiveError {}

/// Primitive projection passed to a Component factory.
#[derive(Clone, Debug, Default)]
pub struct RuntimePrimitiveBindings {
    runtime: Option<RuntimePrimitives>,
}

impl RuntimePrimitiveBindings {
    pub fn none() -> Self {
        Self { runtime: None }
    }

    pub fn runtime(runtime: RuntimePrimitives) -> Self {
        Self {
            runtime: Some(runtime),
        }
    }

    pub fn get(&self) -> Option<&RuntimePrimitives> {
        self.runtime.as_ref()
    }
}

/// Factory result that keeps a concrete Component owner alive.
#[derive(Debug)]
pub struct ComponentOutput<T> {
    service: Arc<T>,
}

impl<T> ComponentOutput<T> {
    pub fn stateless(service: T) -> Self {
        Self {
            service: Arc::new(service),
        }
    }

    pub fn service(&self) -> &Arc<T> {
        &self.service
    }

    pub fn into_service(self) -> Arc<T> {
        self.service
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComponentBuildError {
    InvalidConfig(String),
    MissingDependency(&'static str),
    Runtime(RuntimePrimitiveError),
}

impl fmt::Display for ComponentBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => {
                write!(formatter, "invalid component config: {message}")
            }
            Self::MissingDependency(field) => {
                write!(formatter, "missing component dependency {field}")
            }
            Self::Runtime(error) => write!(formatter, "runtime primitive error: {error}"),
        }
    }
}

impl std::error::Error for ComponentBuildError {}

/// Canonical lifecycle intent. Allocation tokens remain in later owner APIs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentOperationIntent {
    CreateSessionless,
    CreateEphemeral,
    CreateDurable,
    ResumeDurable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentOperationAllocationError {
    Closed,
    UnsupportedMode,
    ReservationConflict,
    OperationConflict,
    OutcomeUnknown,
}

/// Bounded public event-feed cursor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AgentEventCursor(u64);

impl AgentEventCursor {
    pub const fn initial() -> Self {
        Self(0)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentEventFeedError {
    Lagged { next_available: AgentEventCursor },
    Closed,
    InvalidCursor,
}

/// Session query cursor shared without importing an Agent API crate.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SessionQueryCursor(u64);

impl SessionQueryCursor {
    pub const fn initial() -> Self {
        Self(0)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Error returned by a generated composition build.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildError {
    Component(ComponentBuildError),
    InvalidRuntime(RuntimePrimitiveError),
    InvalidComposition(&'static str),
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Component(error) => write!(formatter, "component build failed: {error}"),
            Self::InvalidRuntime(error) => write!(formatter, "invalid runtime: {error}"),
            Self::InvalidComposition(message) => {
                write!(formatter, "invalid composition: {message}")
            }
        }
    }
}

impl std::error::Error for BuildError {}

impl From<ComponentBuildError> for BuildError {
    fn from(error: ComponentBuildError) -> Self {
        Self::Component(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_identity_is_checked_and_owned() {
        assert!(RuntimeAdapterIdentity::checked("").is_err());
        let identity = RuntimeAdapterIdentity::checked("fixture-runtime").unwrap();
        let runtime = RuntimePrimitives::new(identity);
        assert_eq!(runtime.adapter().as_str(), "fixture-runtime");
    }

    #[test]
    fn public_cursors_start_at_zero() {
        assert_eq!(AgentEventCursor::initial().value(), 0);
        assert_eq!(SessionQueryCursor::initial().value(), 0);
    }
}
