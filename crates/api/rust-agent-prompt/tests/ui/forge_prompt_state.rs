use std::sync::Arc;

use rust_agent_core::CanonicalId;
use rust_agent_prompt::{
    AssembledPrompt, PromptContribution, PromptSegment, PromptSegmentKind,
};

fn main() {
    let segment = PromptSegment::new(PromptSegmentKind::Instruction, "text").unwrap();
    let contribution = PromptContribution {
        contributor_id: CanonicalId::new("base").unwrap(),
        segments: Arc::from([segment]),
        estimated_tokens: 1,
        byte_len: 4,
    };
    let _prompt = AssembledPrompt {
        contributions: Arc::from([contribution]),
        segment_count: 1,
        byte_len: 4,
        estimated_tokens: 1,
    };
}
