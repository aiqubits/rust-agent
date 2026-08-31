use rust_agent_composition::{CompositionManifest, profile::BuildKind, target::Environment};
use thiserror::Error;

/// Framework-neutral Host boundaries supported by the composition contract.
///
/// The topology is derived exclusively from the process/module ABI, target
/// facts, and build kind. Product or UI framework names never participate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostIntegrationTopology {
    SameProcessNativeRust,
    SameModuleRustWasm,
    JavaScriptWasm,
    NativeBackendIpc,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum HostTopologyError {
    #[error(
        "composition is incompatible with {topology:?}: build-kind={build_kind:?}, target={target}, environment={environment}, host-boundary={host_boundary:?}"
    )]
    Incompatible {
        topology: HostIntegrationTopology,
        build_kind: BuildKind,
        target: String,
        environment: String,
        host_boundary: Option<String>,
    },
}

/// Verify that a composition can cross the requested Host boundary.
///
/// This check is deliberately performed before an Integrator invokes Cargo.
/// Native direct and IPC integrations share the same composition shape; their
/// distinction lives solely in product-owned adapter code outside the emitted
/// composition.
pub fn verify_host_topology(
    manifest: &CompositionManifest,
    topology: HostIntegrationTopology,
) -> Result<(), HostTopologyError> {
    let is_wasm = manifest
        .normalized_target
        .fact_value("target_arch")
        .is_some_and(|arch| arch == "wasm32");
    let is_browser = manifest.normalized_target.environment == Environment::Browser;
    let compatible = match topology {
        HostIntegrationTopology::SameProcessNativeRust
        | HostIntegrationTopology::NativeBackendIpc => {
            manifest.build_kind == BuildKind::Library
                && !is_wasm
                && !is_browser
                && manifest.host_boundary.is_none()
        }
        HostIntegrationTopology::SameModuleRustWasm => {
            manifest.build_kind == BuildKind::Library
                && is_wasm
                && is_browser
                && manifest.host_boundary.is_none()
        }
        HostIntegrationTopology::JavaScriptWasm => {
            manifest.build_kind == BuildKind::Wasm
                && is_wasm
                && is_browser
                && manifest.host_boundary.is_some()
        }
    };
    if compatible {
        return Ok(());
    }
    Err(HostTopologyError::Incompatible {
        topology,
        build_kind: manifest.build_kind,
        target: manifest.target.clone(),
        environment: manifest.normalized_target.environment.as_str().into(),
        host_boundary: manifest.host_boundary.clone(),
    })
}
