use std::num::NonZeroUsize;

use rust_agent_attachments::StorageCallContext;
use rust_agent_runtime_api::CancellationToken;

fn main() {
    let _context = StorageCallContext {
        cancellation: CancellationToken::new(),
        deadline: None,
        byte_budget: NonZeroUsize::new(1).unwrap(),
    };
}
