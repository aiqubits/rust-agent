use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};

use rust_agent_core::Digest;
use rust_agent_policy::process::{
    BackendKind, BackendPlan, EnforcementPrimitives, ProcessResourceLimits,
};

fn forge_limits() -> ProcessResourceLimits {
    ProcessResourceLimits {
        max_processes: NonZeroU32::MIN,
        max_memory_bytes: NonZeroU64::MIN,
        max_output_bytes: NonZeroUsize::MIN,
        max_wall_time_millis: NonZeroU64::MIN,
    }
}

fn forge_plan() -> BackendPlan {
    BackendPlan {
        schema_version: 1,
        kind: BackendKind::Linux,
        policy_digest: Digest::from_bytes([0; 32]),
        required_primitives: EnforcementPrimitives::empty(),
    }
}

fn main() {}
