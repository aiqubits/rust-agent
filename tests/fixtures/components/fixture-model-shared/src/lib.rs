use rust_agent_fixture_api::Model;
use rust_agent_runtime_api::{
    ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings, SharedHostHandle,
};

pub mod host_api {
    use std::sync::Arc;

    pub use rust_agent_runtime_api::SharedHostHandle;

    pub trait SharedModelResource: Send + Sync {
        fn respond(&self, request: &str) -> String;
    }

    #[derive(Clone, Debug)]
    pub struct Config {
        pub shared: SharedHostHandle<dyn SharedModelResource>,
    }

    impl Config {
        pub fn new(resource: Arc<dyn SharedModelResource>) -> Self {
            Self {
                shared: SharedHostHandle::new(resource),
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Dependencies;

#[derive(Debug)]
pub struct FixtureSharedModel {
    shared: SharedHostHandle<dyn host_api::SharedModelResource>,
}

impl Model for FixtureSharedModel {
    fn respond(&self, request: &str) -> String {
        self.shared.service().respond(request)
    }
}

pub fn build(
    config: &host_api::Config,
    _dependencies: Dependencies,
    _runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<FixtureSharedModel>, ComponentBuildError> {
    Ok(ComponentOutput::stateless(FixtureSharedModel {
        shared: config.shared.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    struct Echo;

    impl host_api::SharedModelResource for Echo {
        fn respond(&self, request: &str) -> String {
            format!("shared:{request}")
        }
    }

    #[test]
    fn component_consumes_only_the_injected_shared_handle() {
        let config = host_api::Config::new(Arc::new(Echo));
        let output = build(&config, Dependencies, RuntimePrimitiveBindings::none()).unwrap();
        assert_eq!(output.service().respond("hello"), "shared:hello");
        assert!(config.shared.same_identity(&output.service().shared));
    }
}
