fn main() {
    let _ = rust_agent_tools::registry::ToolRegistry::from_bindings(&[]);
    let _ = rust_agent_tools::GuardedToolExecutor::build;
}
