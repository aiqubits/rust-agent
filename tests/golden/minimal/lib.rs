#![forbid(unsafe_code)]

mod identity;

pub use identity::COMPOSITION_HASH;
pub use rust_agent_fixture_api::FixtureApp;
pub use rust_agent_runtime_api::{AppHandoffError, AppHandoffMode, BuildError, RuntimePrimitives};
pub use rust_agent_fixture_runtime::create_runtime_primitives as create_runtime_primitives;

pub const CATALOG_DIGEST: &str = "05262656d13865efd85c9b00fd1f8e69bec354e8421f90b7ca971539ce7c8305";

#[derive(Default)]
pub struct RuntimeConfig {
}

#[derive(Default)]
pub struct HostBindings {
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostBindingsError {
    DuplicateField(&'static str),
    MissingField(&'static str),
}

impl std::fmt::Display for HostBindingsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateField(field) => write!(formatter, "duplicate Host binding `{field}`"),
            Self::MissingField(field) => write!(formatter, "missing Host binding `{field}`"),
        }
    }
}

impl std::error::Error for HostBindingsError {}

pub struct HostBindingsBuilder {
}

impl Default for HostBindingsBuilder {
    fn default() -> Self {
        Self {
        }
    }
}

impl HostBindingsBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(self) -> Result<HostBindings, HostBindingsError> {
        Ok(HostBindings {
        })
    }
}

pub fn build(runtime_config: RuntimeConfig, host_bindings: HostBindings, runtime: RuntimePrimitives) -> Result<rust_agent_fixture_api::FixtureApp, BuildError> {
    if runtime.adapter().as_str() != "fixture-runtime" {
        return Err(BuildError::InvalidComposition("runtime adapter identity mismatch"));
    }
    let _ = runtime_config;
    let _ = host_bindings;
    let shared_host_fields = vec![
    ];
    let handoff = rust_agent_runtime_api::AppHandoffSeal::new(
        rust_agent_runtime_api::AppHandoffMode::Concurrent,
        COMPOSITION_HASH,
        CATALOG_DIGEST,
        shared_host_fields,
    )?;
    let fixture_model_config: rust_agent_fixture_model::Config = Default::default();
    let fixture_model_dependencies = rust_agent_fixture_model::Dependencies {};
    let fixture_model_output = rust_agent_fixture_model::build(
        &fixture_model_config,
        fixture_model_dependencies,
        rust_agent_runtime_api::RuntimePrimitiveBindings::none(),
    )?;
    let binding_model_fixture_model: rust_agent_fixture_api::ModelBinding = rust_agent_fixture_api::ModelBinding::from_provider(fixture_model_output.service().clone());
    let fixture_driver_config: rust_agent_fixture_driver::Config = Default::default();
    let fixture_driver_dependencies = rust_agent_fixture_driver::Dependencies {
        model: binding_model_fixture_model.clone(),
    };
    let fixture_driver_output = rust_agent_fixture_driver::build(
        &fixture_driver_config,
        fixture_driver_dependencies,
        rust_agent_runtime_api::RuntimePrimitiveBindings::none(),
    )?;
    let binding_driver_fixture_driver: rust_agent_fixture_api::DriverBinding = rust_agent_fixture_api::DriverBinding::from_provider(fixture_driver_output.service().clone());
    Ok(rust_agent_fixture_api::FixtureApp::new(binding_driver_fixture_driver, None, handoff))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_factory_graph_executes() {
        let runtime = create_runtime_primitives().unwrap();
        let app = build(RuntimeConfig::default(), HostBindings::default(), runtime).unwrap();
        assert_eq!(app.run("hello"), "fixture-response:hello");
    }
}
