use rust_agent_tools::{ToolCallPolicy, ToolConcurrencyRule};

fn main() {
    let _forged = ToolCallPolicy {
        rules: [].into(),
        concurrency: ToolConcurrencyRule::Exclusive,
        canonical_bytes: 1,
        evaluator_steps: 1,
    };
}
