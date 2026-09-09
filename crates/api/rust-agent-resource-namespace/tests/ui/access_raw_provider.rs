use std::sync::Arc;

use rust_agent_core::{CanonicalId, SecurityEffects};
use rust_agent_resource_namespace::{
    ResourceNamespaceBootstrap, ResourceNamespaceBootstrapBinding, ResourceNamespaceBootstrapRequest,
    ResourceNamespaceBootstrapResult, ResourceNamespaceFuture, ResourceNamespacePrepareError,
};

struct Bootstrap;

impl ResourceNamespaceBootstrap for Bootstrap {
    fn component_identity(&self) -> CanonicalId {
        CanonicalId::new("bootstrap-component").unwrap()
    }

    fn provider_key(&self) -> CanonicalId {
        CanonicalId::new("bootstrap").unwrap()
    }

    fn effects(&self) -> SecurityEffects {
        SecurityEffects::READ_LOCAL
    }

    fn open_local_directory(
        &self,
        _request: ResourceNamespaceBootstrapRequest,
    ) -> ResourceNamespaceFuture<'_, Result<ResourceNamespaceBootstrapResult, ResourceNamespacePrepareError>> {
        todo!()
    }
}

fn main() {
    let binding = ResourceNamespaceBootstrapBinding::from_provider(Arc::new(Bootstrap));
    let _provider = binding.provider;
}
