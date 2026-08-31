use rust_agent_fixture_api::Model;
use rust_agent_runtime_api::{ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings};

#[derive(Clone, Debug, Default)]
pub struct Config;

#[derive(Clone, Debug, Default)]
pub struct Dependencies;

#[derive(Debug)]
pub struct FallbackModel;

impl Model for FallbackModel {
    fn respond(&self, request: &str) -> String {
        format!("fallback:{request}")
    }
}

pub fn build(
    _config: &Config,
    _dependencies: Dependencies,
    _runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<FallbackModel>, ComponentBuildError> {
    Ok(ComponentOutput::stateless(FallbackModel))
}
