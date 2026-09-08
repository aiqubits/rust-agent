use rust_agent_core::{AgentId, CanonicalId, Digest};
use rust_agent_runtime_api::RuntimeInstant;
use rust_agent_spill::SpillRef;

fn main() {
    let _reference = SpillRef {
        provider_key: CanonicalId::new("memory").unwrap(),
        owner: AgentId::from_nonzero_u128(1).unwrap(),
        content_digest: Digest::from_bytes([0; 32]),
        byte_len: 1,
        expires_at: RuntimeInstant::from_monotonic_duration(std::time::Duration::from_secs(1)),
    };
}
