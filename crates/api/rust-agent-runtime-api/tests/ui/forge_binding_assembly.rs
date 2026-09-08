use rust_agent_runtime_api::{
    BindingAssemblyOwner, GeneratedScopeCallAuthority, GeneratedToolConsumerBinding, RuntimeOwner,
};

fn requires_clone<T: Clone>() {}

fn main() {
    let _owner = BindingAssemblyOwner {};
    let _authority = GeneratedScopeCallAuthority {};
    let _tool_binding = GeneratedToolConsumerBinding {};
    requires_clone::<GeneratedToolConsumerBinding>();
    let _runtime_owner = RuntimeOwner {};
}
