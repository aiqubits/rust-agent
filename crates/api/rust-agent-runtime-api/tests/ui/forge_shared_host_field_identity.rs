use std::sync::Arc;

use rust_agent_runtime_api::{SharedHostHandle, seal_shared_host_handle};

fn main() {
    let handle = SharedHostHandle::new(Arc::new(()));
    let sealed = seal_shared_host_handle("fixture-model.shared", &handle).unwrap();
    let _identity = sealed.identity;
}
