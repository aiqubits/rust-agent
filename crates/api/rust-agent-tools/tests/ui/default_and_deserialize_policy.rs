use rust_agent_tools::{ToolCallPolicy, ToolRiskRule};

fn main() {
    let _default = ToolCallPolicy::default();
    let _decoded: ToolCallPolicy = serde_json::from_str("{}").unwrap();
    let _default_rule = ToolRiskRule::default();
    let _decoded_rule: ToolRiskRule = serde_json::from_str("{}").unwrap();
}
