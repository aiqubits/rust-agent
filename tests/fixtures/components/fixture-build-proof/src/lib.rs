use rust_agent_fixture_api::BuildProof;
use rust_agent_runtime_api::{ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings};

#[derive(Clone, Debug, Default)]
pub struct Config;

#[derive(Clone, Debug, Default)]
pub struct Dependencies;

#[derive(Debug)]
pub struct FixtureBuildProof;

impl BuildProof for FixtureBuildProof {
    fn marker(&self) -> &'static str {
        "controlled-build-requirements"
    }
}

pub fn build(
    _config: &Config,
    _dependencies: Dependencies,
    _runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<FixtureBuildProof>, ComponentBuildError> {
    Ok(ComponentOutput::stateless(FixtureBuildProof))
}
