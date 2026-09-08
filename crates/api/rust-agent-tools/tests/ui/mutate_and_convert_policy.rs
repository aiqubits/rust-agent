use rust_agent_core::SecurityEffects;
use rust_agent_tools::{
    BoundedJsonPointer, ToolArgumentPredicate, ToolCallPolicy, ToolConcurrencyRule, ToolRiskRule,
    ToolSafety,
};

fn main() {
    let mut rule = ToolRiskRule::builder(ToolSafety::Unknown, SecurityEffects::empty())
        .build()
        .unwrap();
    rule.all = [].into();
    let mut policy = ToolCallPolicy::builder(ToolConcurrencyRule::Exclusive)
        .build()
        .unwrap();
    policy.rules = [].into();

    let predicate = ToolArgumentPredicate::Present {
        pointer: BoundedJsonPointer::new("/a").unwrap(),
    };
    let _rule_from_collection: ToolRiskRule = vec![predicate].into();
    let _policy_from_collection: ToolCallPolicy = vec![rule].into();
}
