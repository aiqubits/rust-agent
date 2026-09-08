use std::num::NonZeroUsize;

use rust_agent_attachments::{AttachmentRef, ByteRange};
use rust_agent_core::{CanonicalId, Digest};

fn main() {
    let _reference = AttachmentRef {
        provider_key: CanonicalId::new("memory").unwrap(),
        content_digest: Digest::from_bytes([0; 32]),
        byte_len: 1,
    };
    let _range = ByteRange {
        start: 0,
        length: NonZeroUsize::new(1).unwrap(),
    };
}
