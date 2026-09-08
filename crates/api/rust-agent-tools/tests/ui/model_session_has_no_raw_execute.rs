fn raw_execute(session: &rust_agent_tools::ToolExecutionSession) {
    let request = rust_agent_tools::ToolExecutionRequest::new(
        rust_agent_core::CallId::from_nonzero_u128(1).unwrap(),
        "fixture",
        serde_json::json!({}),
    )
    .unwrap();
    let _ = session.execute(request);
}

fn main() {}
