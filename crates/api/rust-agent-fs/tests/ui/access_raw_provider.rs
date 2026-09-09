use std::sync::Arc;

use rust_agent_core::{CanonicalId, SecurityEffects};
use rust_agent_fs::{
    AgentPath, ByteRange, DirPage, DirPageRequest, FileBytes, FileMetadata, FileRead,
    FileReadBinding, FsCallContext, FsError, FsFuture,
};

struct Reader;

impl FileRead for Reader {
    fn provider_key(&self) -> CanonicalId {
        CanonicalId::new("reader").unwrap()
    }

    fn effects(&self) -> SecurityEffects {
        SecurityEffects::READ_LOCAL
    }

    fn metadata<'a>(
        &'a self,
        _context: FsCallContext,
        _path: &'a AgentPath,
    ) -> FsFuture<'a, Result<FileMetadata, FsError>> {
        todo!()
    }

    fn read<'a>(
        &'a self,
        _context: FsCallContext,
        _path: &'a AgentPath,
        _range: ByteRange,
    ) -> FsFuture<'a, Result<FileBytes, FsError>> {
        todo!()
    }

    fn list_page(
        &self,
        _context: FsCallContext,
        _request: DirPageRequest,
    ) -> FsFuture<'_, Result<DirPage, FsError>> {
        todo!()
    }
}

fn main() {
    let binding = FileReadBinding::from_provider(Arc::new(Reader));
    let _provider = binding.provider;
}
