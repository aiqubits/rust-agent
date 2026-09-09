use std::sync::Arc;

use rust_agent_core::{CanonicalId, CapabilityId, Digest, SecurityEffects};
use rust_agent_resource_namespace::{
    BootstrapAuthorityProjection, LocalDirectoryAnchor, LocalResourceLocator,
    ResourceNamespaceBootstrapRequest, ResourceNamespaceDescriptor, ResourceNamespaceKind,
    ResourceNamespaceRoute,
};
use rust_agent_runtime_api::CancellationToken;

fn main() {
    let route = ResourceNamespaceRoute {
        component: CanonicalId::new("component").unwrap(),
        provide_capability: CapabilityId::new("cap:fs-read").unwrap(),
        provide_key: None,
        bootstrap_component: CanonicalId::new("bootstrap-component").unwrap(),
        bootstrap_key: CanonicalId::new("bootstrap").unwrap(),
        bootstrap_effects: SecurityEffects::READ_LOCAL,
    };
    let _projection = BootstrapAuthorityProjection {
        route: route.clone(),
        retained: true,
    };
    let _request = ResourceNamespaceBootstrapRequest {
        route: route.clone(),
        locator: LocalResourceLocator::root(),
        cancellation: CancellationToken::new(),
        deadline: None,
    };
    let _descriptor = ResourceNamespaceDescriptor {
        route,
        kind: ResourceNamespaceKind::LocalDirectory,
        commitment: Digest::from_bytes([0; 32]),
    };
    let _anchor = LocalDirectoryAnchor {
        descriptor: Arc::new(std::fs::File::open(".").unwrap().into()),
    };
}
