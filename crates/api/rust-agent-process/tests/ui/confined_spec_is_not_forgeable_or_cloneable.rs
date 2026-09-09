use rust_agent_core::Digest;
use rust_agent_policy::process::SandboxPolicy;
use rust_agent_process::{
    ConfinedProcessSpec, ConfinementIssuerBinding, ConfinementProjection,
    ConfinementVerifierBinding, VerifiedProcessSpec,
};

fn require_clone<T: Clone>() {}
fn require_default<T: Default>() {}

fn forge_projection(
    effective_policy: SandboxPolicy,
    policy_digest: Digest,
) -> ConfinementProjection {
    ConfinementProjection {
        effective_policy,
        policy_digest,
    }
}

fn main() {
    require_clone::<ConfinedProcessSpec>();
    require_default::<ConfinedProcessSpec>();
    require_clone::<ConfinementProjection>();
    require_clone::<VerifiedProcessSpec>();
    require_clone::<ConfinementIssuerBinding>();
    require_clone::<ConfinementVerifierBinding>();
}
