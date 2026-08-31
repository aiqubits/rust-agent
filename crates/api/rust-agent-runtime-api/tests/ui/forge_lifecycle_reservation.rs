use rust_agent_runtime_api::{
    AgentLifecycleOperationIntent, AgentOperationRecoveryKey, CompositionHash, Digest,
    LifecycleOperationReservationDraft,
};

fn main() {
    let mut key = [0_u8; AgentOperationRecoveryKey::ENCODED_LEN];
    key[0] = AgentOperationRecoveryKey::VERSION;
    key[1] = 1;
    let _forged = LifecycleOperationReservationDraft {
        recovery_key: AgentOperationRecoveryKey::from_canonical_v1_bytes(key).unwrap(),
        intent: AgentLifecycleOperationIntent::CreateDurable,
        request_fingerprint: Digest::from_bytes([1; 32]),
        projected_authority_digest: Digest::from_bytes([2; 32]),
        projected_plan_digest: Digest::from_bytes([3; 32]),
        composition: CompositionHash::from_digest(Digest::from_bytes([4; 32])),
        catalog: Digest::from_bytes([5; 32]),
    };
}
