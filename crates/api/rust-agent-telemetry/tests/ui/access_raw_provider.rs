use std::sync::Arc;

use rust_agent_telemetry::{Telemetry, TelemetryBinding, TelemetryEvent};

struct Sink;

impl Telemetry for Sink {
    fn event(&self, _event: TelemetryEvent) {}
}

fn main() {
    let binding = TelemetryBinding::from_provider(Arc::new(Sink));
    let _provider = binding.provider;
}
