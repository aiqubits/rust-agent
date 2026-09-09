use std::sync::Arc;

use rust_agent_runtime_api::ComponentOutput;

#[derive(Debug)]
struct LifecycleOwner;

fn main() {
    let _forged = ComponentOutput::<LifecycleOwner> {
        service: Arc::new(LifecycleOwner),
        initializer: None,
        activator: None,
        shutdown: None,
    };
}
