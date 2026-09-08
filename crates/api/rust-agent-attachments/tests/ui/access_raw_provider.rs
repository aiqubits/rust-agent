use std::sync::Arc;

use rust_agent_attachments::{
    AttachmentData, AttachmentError, AttachmentFuture, AttachmentInput, AttachmentRef,
    AttachmentStore, AttachmentStoreBinding, ByteRange, StorageCallContext,
};
use rust_agent_core::CanonicalId;

struct Store;

impl AttachmentStore for Store {
    fn provider_key(&self) -> CanonicalId {
        CanonicalId::new("memory").unwrap()
    }

    fn put(
        &self,
        _context: StorageCallContext,
        _input: AttachmentInput,
    ) -> AttachmentFuture<'_, Result<AttachmentRef, AttachmentError>> {
        todo!()
    }

    fn get(
        &self,
        _context: StorageCallContext,
        _reference: AttachmentRef,
        _range: ByteRange,
    ) -> AttachmentFuture<'_, Result<AttachmentData, AttachmentError>> {
        todo!()
    }
}

fn main() {
    let binding = AttachmentStoreBinding::from_provider(Arc::new(Store));
    let _provider = binding.provider;
}
