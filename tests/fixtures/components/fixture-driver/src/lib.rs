use rust_agent_fixture_api::{Driver, ModelBinding};
use rust_agent_runtime_api::{ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings};

#[cfg(not(target_arch = "wasm32"))]
pub use rust_agent_fixture_target_native::TARGET_DEPENDENCY_MARKER;
#[cfg(target_arch = "wasm32")]
pub use rust_agent_fixture_target_wasm::TARGET_DEPENDENCY_MARKER;

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub route: u8,
}

#[derive(Clone, Debug)]
pub struct Dependencies {
    pub model: ModelBinding,
}

#[derive(Debug)]
pub struct FixtureDriver {
    model: ModelBinding,
    route: u8,
    ownership: std::sync::Arc<()>,
}

impl Driver for FixtureDriver {
    fn run(&self, request: &str) -> String {
        debug_assert_eq!(std::sync::Arc::strong_count(&self.ownership), 1);
        let response = self.model.respond(request);
        if self.route == 0 {
            response
        } else {
            format!("route-{}:{response}", self.route)
        }
    }
}

pub fn build(
    config: &Config,
    dependencies: Dependencies,
    _runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<FixtureDriver>, ComponentBuildError> {
    Ok(ComponentOutput::stateless(FixtureDriver {
        model: dependencies.model,
        route: config.route,
        ownership: std::sync::Arc::new(()),
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
        assert_eq!(TARGET_DEPENDENCY_MARKER, "native");
        let model = ModelBinding::from_provider(Arc::new(Echo));
        let output = build(
            &Config::default(),
            Dependencies { model },
            RuntimePrimitiveBindings::none(),
        )
        .unwrap();
        assert_eq!(output.service().run("hello"), "hello");
    }

    #[test]
    fn two_instances_keep_independent_config_and_dependency_ownership() {
        for (left, right) in [(5, 5), (5, 8), (0, u8::MAX)] {
            let first = build(
                &Config { route: left },
                Dependencies {
                    model: ModelBinding::from_provider(Arc::new(Echo)),
                },
                RuntimePrimitiveBindings::none(),
            )
            .unwrap();
            let second = build(
                &Config { route: right },
                Dependencies {
                    model: ModelBinding::from_provider(Arc::new(Echo)),
                },
                RuntimePrimitiveBindings::none(),
            )
            .unwrap();

            assert_eq!(first.service().route, left);
            assert_eq!(second.service().route, right);
            assert!(!Arc::ptr_eq(
                &first.service().ownership,
                &second.service().ownership
            ));
        }
    }
}
