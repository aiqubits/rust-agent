use std::sync::Arc;

use rust_agent_core::CanonicalId;
use rust_agent_spill::{
    SpillByteRange, SpillCallContext, SpillData, SpillError, SpillFuture, SpillInput, SpillRef,
    SpillStore, SpillStoreBinding,
};

struct Store;

impl SpillStore for Store {
    fn provider_key(&self) -> CanonicalId {
        CanonicalId::new("memory").unwrap()
    }

    fn put(
        &self,
        _context: SpillCallContext,
        _input: SpillInput,
    ) -> SpillFuture<'_, Result<SpillRef, SpillError>> {
        todo!()
    }

    fn get(
        &self,
        _context: SpillCallContext,
        _reference: SpillRef,
        _range: SpillByteRange,
    ) -> SpillFuture<'_, Result<SpillData, SpillError>> {
        todo!()
    }

    fn purge_owner(
        &self,
        _context: SpillCallContext,
    ) -> SpillFuture<'_, Result<(), SpillError>> {
        todo!()
    }
}

fn main() {
    let binding = SpillStoreBinding::from_provider(Arc::new(Store));
    let _provider = binding.provider;
}
