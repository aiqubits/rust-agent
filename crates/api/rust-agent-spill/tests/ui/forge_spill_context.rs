use std::{num::NonZeroUsize, time::Duration};

use rust_agent_core::AgentId;
use rust_agent_runtime_api::{CancellationToken, RuntimeInstant};
use rust_agent_spill::SpillCallContext;

fn main() {
    let _context = SpillCallContext {
        agent_id: AgentId::from_nonzero_u128(1).unwrap(),
        cancellation: CancellationToken::new(),
        now: RuntimeInstant::from_monotonic_duration(Duration::from_secs(1)),
        deadline: None,
        byte_budget: NonZeroUsize::new(1).unwrap(),
    };
}
