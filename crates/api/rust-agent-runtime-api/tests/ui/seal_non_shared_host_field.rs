use std::sync::Arc;

use rust_agent_runtime_api::seal_shared_host_handle;

fn main() {
    let not_a_shared_handle = Arc::new(());
    let _ = seal_shared_host_handle("fixture-model.shared", &not_a_shared_handle);
}
