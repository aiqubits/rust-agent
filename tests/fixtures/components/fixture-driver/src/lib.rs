use rust_agent_fixture_api::{Driver, ModelBinding};
use rust_agent_runtime_api::{ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings};

#[derive(Clone, Debug, Default)]
pub struct Config;

#[derive(Clone, Debug)]
pub struct Dependencies {
    pub model: ModelBinding,
}

#[derive(Debug)]
pub struct FixtureDriver {
    model: ModelBinding,
}

impl Driver for FixtureDriver {
    fn run(&self, request: &str) -> String {
        self.model.respond(request)
    }
}

pub fn build(
    _config: &Config,
    dependencies: Dependencies,
    _runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<FixtureDriver>, ComponentBuildError> {
    Ok(ComponentOutput::stateless(FixtureDriver {
        model: dependencies.model,
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rust_agent_fixture_api::{Model, ModelBinding};

    use super::*;

    struct Echo;

    impl Model for Echo {
        fn respond(&self, request: &str) -> String {
            request.to_owned()
        }
    }

    #[test]
    fn driver_uses_only_the_model_binding() {
        let model = ModelBinding::from_provider(Arc::new(Echo));
        let output = build(
            &Config,
            Dependencies { model },
            RuntimePrimitiveBindings::none(),
        )
        .unwrap();
        assert_eq!(output.service().run("hello"), "hello");
    }
}
