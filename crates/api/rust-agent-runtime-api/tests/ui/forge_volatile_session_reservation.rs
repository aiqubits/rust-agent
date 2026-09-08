use rust_agent_runtime_api::{
    CompositionHash, Digest, SessionId, VolatileLifecycleOperation,
    VolatileLifecycleOperationReservation,
};

fn operation() -> VolatileLifecycleOperation {
    panic!("compile-fail fixture")
}

fn main() {
    let _forged = VolatileLifecycleOperationReservation {
        operation: operation(),
        proposed_session_id: SessionId::from_canonical_v1_bytes([1; 50]).unwrap(),
        request_fingerprint: Digest::from_bytes([1; 32]),
        projected_authority_digest: Digest::from_bytes([2; 32]),
        projected_plan_digest: Digest::from_bytes([3; 32]),
        composition: CompositionHash::from_digest(Digest::from_bytes([4; 32])),
        catalog: Digest::from_bytes([5; 32]),
    };
}
