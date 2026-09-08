use std::sync::Arc;

use rust_agent_core::SecurityEffects;
use rust_agent_tools::{
    ExecutionPermit, Tool, ToolCallPolicy, ToolConcurrencyRule, ToolContext, ToolDefinition,
    ToolError, ToolFuture, ToolRegistration, ToolSafety, ToolValue,
};
use serde_json::{Value, json};

struct Echo;

impl Tool for Echo {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(
            "echo",
            "echo",
            json!({"type": "object"}),
            ToolSafety::ReadOnly,
            SecurityEffects::empty(),
            ToolCallPolicy::builder(ToolConcurrencyRule::Exclusive)
                .build()
                .unwrap(),
        )
        .unwrap()
    }

    fn execute<'a>(
        &'a self,
        _permit: &'a ExecutionPermit,
        context: &'a ToolContext,
        _input: Value,
    ) -> ToolFuture<'a, Result<ToolValue, ToolError>> {
        Box::pin(async move { Ok(context.output_builder().build()) })
    }
}

fn main() {
    let registration = ToolRegistration::new(Arc::new(Echo)).unwrap();
    let _handler = registration.handler;
}
