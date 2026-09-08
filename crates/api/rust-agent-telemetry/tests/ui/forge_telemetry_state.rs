use std::sync::Arc;

use rust_agent_core::CanonicalId;
use rust_agent_telemetry::{TelemetryEvent, TelemetryEventKind, TelemetrySeverity};

fn main() {
    let _event = TelemetryEvent {
        name: CanonicalId::new("event").unwrap(),
        kind: TelemetryEventKind::OperationStarted,
        severity: TelemetrySeverity::Info,
        agent_id: None,
        call_id: None,
        attributes: Arc::from([]),
    };
}
