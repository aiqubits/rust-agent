//! Structured, bounded telemetry contracts with no free-form secret-bearing values.

use std::{collections::BTreeSet, fmt, sync::Arc, time::Duration};

use rust_agent_core::{AgentId, CallId, CanonicalId, Digest, MaybeSendSync};

pub const MAX_TELEMETRY_ATTRIBUTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelemetryEventKind {
    OperationStarted,
    OperationCompleted,
    OperationFailed,
    BudgetExceeded,
    PolicyDecision,
    ObserverDropped,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TelemetrySeverity {
    Trace,
    Info,
    Warn,
    Error,
}

/// Closed values intentionally exclude arbitrary strings and byte buffers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TelemetryValue {
    Bool(bool),
    I64(i64),
    U64(u64),
    Duration(Duration),
    Digest(Digest),
    Label(CanonicalId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetryAttribute {
    key: CanonicalId,
    value: TelemetryValue,
}

impl TelemetryAttribute {
    pub fn new(key: impl Into<String>, value: TelemetryValue) -> Result<Self, TelemetryBuildError> {
        let key =
            CanonicalId::new(key.into()).map_err(|_| TelemetryBuildError::InvalidAttributeKey)?;
        Ok(Self { key, value })
    }

    pub fn key(&self) -> &str {
        self.key.as_str()
    }

    pub const fn value(&self) -> &TelemetryValue {
        &self.value
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetryEvent {
    name: CanonicalId,
    kind: TelemetryEventKind,
    severity: TelemetrySeverity,
    agent_id: Option<AgentId>,
    call_id: Option<CallId>,
    attributes: Arc<[TelemetryAttribute]>,
}

impl TelemetryEvent {
    pub fn builder(
        name: impl Into<String>,
        kind: TelemetryEventKind,
        severity: TelemetrySeverity,
    ) -> Result<TelemetryEventBuilder, TelemetryBuildError> {
        let name = CanonicalId::new(name.into()).map_err(|_| TelemetryBuildError::InvalidName)?;
        Ok(TelemetryEventBuilder {
            name,
            kind,
            severity,
            agent_id: None,
            call_id: None,
            attributes: Vec::new(),
            keys: BTreeSet::new(),
        })
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub const fn kind(&self) -> TelemetryEventKind {
        self.kind
    }

    pub const fn severity(&self) -> TelemetrySeverity {
        self.severity
    }

    pub const fn agent_id(&self) -> Option<AgentId> {
        self.agent_id
    }

    pub const fn call_id(&self) -> Option<CallId> {
        self.call_id
    }

    pub fn attributes(&self) -> &[TelemetryAttribute] {
        &self.attributes
    }
}

#[derive(Debug)]
pub struct TelemetryEventBuilder {
    name: CanonicalId,
    kind: TelemetryEventKind,
    severity: TelemetrySeverity,
    agent_id: Option<AgentId>,
    call_id: Option<CallId>,
    attributes: Vec<TelemetryAttribute>,
    keys: BTreeSet<CanonicalId>,
}

impl TelemetryEventBuilder {
    #[must_use]
    pub fn agent_id(mut self, agent_id: AgentId) -> Self {
        self.agent_id = Some(agent_id);
        self
    }

    #[must_use]
    pub fn call_id(mut self, call_id: CallId) -> Self {
        self.call_id = Some(call_id);
        self
    }

    pub fn attribute(mut self, attribute: TelemetryAttribute) -> Result<Self, TelemetryBuildError> {
        if self.attributes.len() >= MAX_TELEMETRY_ATTRIBUTES {
            return Err(TelemetryBuildError::AttributeLimitExceeded);
        }
        if !self.keys.insert(attribute.key.clone()) {
            return Err(TelemetryBuildError::DuplicateAttributeKey);
        }
        self.attributes.push(attribute);
        Ok(self)
    }

    pub fn build(self) -> TelemetryEvent {
        TelemetryEvent {
            name: self.name,
            kind: self.kind,
            severity: self.severity,
            agent_id: self.agent_id,
            call_id: self.call_id,
            attributes: Arc::from(self.attributes),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelemetryBuildError {
    InvalidName,
    InvalidAttributeKey,
    DuplicateAttributeKey,
    AttributeLimitExceeded,
}

impl fmt::Display for TelemetryBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidName => "invalid telemetry event name",
            Self::InvalidAttributeKey => "invalid telemetry attribute key",
            Self::DuplicateAttributeKey => "telemetry attribute key is duplicated",
            Self::AttributeLimitExceeded => "telemetry attribute limit exceeded",
        })
    }
}

impl std::error::Error for TelemetryBuildError {}

pub trait Telemetry: MaybeSendSync {
    fn event(&self, event: TelemetryEvent);
}

/// One generated ordered-multi entry. The provider itself remains inaccessible.
#[derive(Clone)]
pub struct TelemetryBinding {
    provider: Arc<dyn Telemetry>,
}

impl TelemetryBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: Telemetry + 'static,
    {
        Self { provider }
    }

    pub fn event(&self, event: TelemetryEvent) {
        self.provider.event(event);
    }
}

impl fmt::Debug for TelemetryBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelemetryBinding")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, PoisonError};

    use super::*;

    #[derive(Debug, Default)]
    struct Recorder(Mutex<Vec<TelemetryEvent>>);

    impl Telemetry for Recorder {
        fn event(&self, event: TelemetryEvent) {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(event);
        }
    }

    #[test]
    fn event_builder_is_structured_unique_and_bounded() {
        let attribute = TelemetryAttribute::new("attempt", TelemetryValue::U64(1)).unwrap();
        let builder = TelemetryEvent::builder(
            "tool-started",
            TelemetryEventKind::OperationStarted,
            TelemetrySeverity::Info,
        )
        .unwrap()
        .attribute(attribute.clone())
        .unwrap();
        assert_eq!(
            builder.attribute(attribute).unwrap_err(),
            TelemetryBuildError::DuplicateAttributeKey
        );

        let mut builder = TelemetryEvent::builder(
            "bounded-event",
            TelemetryEventKind::OperationCompleted,
            TelemetrySeverity::Info,
        )
        .unwrap();
        for index in 0..MAX_TELEMETRY_ATTRIBUTES {
            builder = builder
                .attribute(
                    TelemetryAttribute::new(
                        format!("key-{index}"),
                        TelemetryValue::U64(index as u64),
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        assert_eq!(
            builder
                .attribute(TelemetryAttribute::new("overflow", TelemetryValue::Bool(true)).unwrap())
                .unwrap_err(),
            TelemetryBuildError::AttributeLimitExceeded
        );
    }

    #[test]
    fn binding_delivers_only_the_closed_event_value() {
        let recorder = Arc::new(Recorder::default());
        let binding = TelemetryBinding::from_provider(recorder.clone());
        binding.event(
            TelemetryEvent::builder(
                "operation-completed",
                TelemetryEventKind::OperationCompleted,
                TelemetrySeverity::Info,
            )
            .unwrap()
            .build(),
        );
        let events = recorder.0.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].name(), "operation-completed");
    }
}
