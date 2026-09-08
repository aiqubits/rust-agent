use std::{num::{NonZeroU64, NonZeroUsize}, time::Duration};

use rust_agent_core::{Digest, MessageRole};
use rust_agent_prompt::{
    BoundedConversation, CompactionContext, CompactionInput, ConversationContent,
    ConversationEntry,
};
use rust_agent_runtime_api::{CancellationToken, RuntimeInstant};

fn main() {
    let conversation = BoundedConversation::new(vec![
        ConversationEntry::new(
            MessageRole::User,
            vec![ConversationContent::text("question").unwrap()],
        )
        .unwrap(),
    ])
    .unwrap();
    let _input = CompactionInput {
        source_digest: Digest::from_bytes([0; 32]),
        conversation,
        target_bytes: NonZeroUsize::new(1).unwrap(),
        target_tokens: NonZeroU64::new(1).unwrap(),
    };
    let _context = CompactionContext {
        cancellation: CancellationToken::new(),
        deadline: Some(RuntimeInstant::from_monotonic_duration(Duration::from_secs(1))),
    };
}
