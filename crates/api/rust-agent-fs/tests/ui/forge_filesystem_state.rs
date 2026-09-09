use std::{num::NonZeroUsize, sync::Arc};

use rust_agent_core::CanonicalId;
use rust_agent_fs::{
    AgentPath, ByteRange, DirEntry, DirPage, DirPageCursor, FileKind, FsCallContext,
};
use rust_agent_runtime_api::CancellationToken;

fn main() {
    let path = AgentPath::new("root").unwrap();
    let _context = FsCallContext {
        cancellation: CancellationToken::new(),
        deadline: None,
        byte_budget: NonZeroUsize::MIN,
        entry_budget: NonZeroUsize::MIN,
    };
    let _range = ByteRange {
        start: 0,
        length: NonZeroUsize::MIN,
    };
    let cursor = DirPageCursor {
        provider_key: CanonicalId::new("local").unwrap(),
        path,
        token: Arc::from([1]),
    };
    let _page = DirPage {
        entries: Arc::from([DirEntry::new("entry", FileKind::File, 1).unwrap()]),
        next_cursor: Some(cursor),
        complete: false,
        encoded_bytes: 1,
    };
}
