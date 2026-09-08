use std::sync::Arc;

use rust_agent_tools::ToolMiddlewareContext;

fn mutate(context: &mut ToolMiddlewareContext) {
    context.tool_name = Arc::from("forged");
    context.deadline = None;
    let _ = context.cancellation_guard();
}

fn main() {
    let _ = ToolMiddlewareContext::from_guarded_call;
}
