use rust_agent_fixture_api::Model;
use rust_agent_runtime_api::{ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings};

#[derive(Clone, Debug, Default)]
pub struct Config;

#[derive(Clone, Debug, Default)]
pub struct Dependencies;

#[derive(Debug)]
pub struct FixtureModel;

impl Model for FixtureModel {
    fn respond(&self, request: &str) -> String {
        format!("fixture-response:{request}")
    }
}

pub fn build(
    _config: &Config,
    _dependencies: Dependencies,
    _runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<FixtureModel>, ComponentBuildError> {
    Ok(ComponentOutput::stateless(FixtureModel))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_is_deterministic() {
        let output = build(&Config, Dependencies, RuntimePrimitiveBindings::none()).unwrap();
        assert_eq!(output.service().respond("hello"), "fixture-response:hello");
    }
}
