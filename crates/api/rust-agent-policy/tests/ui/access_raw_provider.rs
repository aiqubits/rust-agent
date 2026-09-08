use std::sync::Arc;

use rust_agent_policy::{Action, PermissionDecision, PermissionPolicy, PermissionPolicyBinding};

struct Policy;

impl PermissionPolicy for Policy {
    fn evaluate(&self, _action: &Action) -> PermissionDecision {
        PermissionDecision::Deny
    }
}

fn main() {
    let binding = PermissionPolicyBinding::from_provider(Arc::new(Policy));
    let _provider = binding.provider;
}
