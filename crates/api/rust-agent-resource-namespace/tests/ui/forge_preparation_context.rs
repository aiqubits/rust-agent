use rust_agent_core::{CanonicalId, CapabilityId, SecurityEffects};
use rust_agent_resource_namespace::{
    ResourceNamespaceBootstrapBinding, ResourceNamespacePreparationContext, ResourceNamespaceRoute,
};
use rust_agent_runtime_api::CancellationToken;

fn forge<'a>(
    route: &'a ResourceNamespaceRoute,
    binding: &'a ResourceNamespaceBootstrapBinding,
) -> ResourceNamespacePreparationContext<'a> {
    ResourceNamespacePreparationContext {
        route,
        binding,
        cancellation: CancellationToken::new(),
        deadline: None,
    }
}

fn main() {
    let _ = (CanonicalId::new("component"), CapabilityId::new("cap:fs-read"), SecurityEffects::READ_LOCAL);
}
