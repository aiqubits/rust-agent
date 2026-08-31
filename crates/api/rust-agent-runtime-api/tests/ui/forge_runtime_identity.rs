use rust_agent_runtime_api::RuntimeAdapterIdentity;
use std::sync::Arc;

fn main() {
    let _forged = RuntimeAdapterIdentity(Arc::from("forged"));
}
