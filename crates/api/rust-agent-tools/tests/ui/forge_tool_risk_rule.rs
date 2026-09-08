use rust_agent_core::SecurityEffects;
use rust_agent_tools::{ToolRiskRule, ToolSafety};

fn main() {
    let _forged = ToolRiskRule {
        all: [].into(),
        raise_to: ToolSafety::Unknown,
        add_effects: SecurityEffects::empty(),
        canonical_bytes: 10,
        evaluator_steps: 1,
    };
}
