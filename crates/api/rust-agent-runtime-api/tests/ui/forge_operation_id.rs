use rust_agent_runtime_api::AgentLifecycleOperationId;

fn main() {
    let _forged = AgentLifecycleOperationId([0; AgentLifecycleOperationId::ENCODED_LEN]);
}
