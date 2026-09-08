use rust_agent_core::{CanonicalId, Digest, SecurityEffects};
use rust_agent_policy::{Action, ActionKind, ActionRisk, ApprovalRequest};
use rust_agent_runtime_api::CancellationToken;

fn main() {
    let action = Action {
        kind: ActionKind::Tool,
        subject: CanonicalId::new("tool".to_owned()).unwrap(),
        risk: ActionRisk::Unknown,
        effects: SecurityEffects::all(),
        input_digest: Digest::from_bytes([0; 32]),
    };
    let _request = ApprovalRequest {
        action,
        cancellation: CancellationToken::new(),
        deadline: None,
    };
}
