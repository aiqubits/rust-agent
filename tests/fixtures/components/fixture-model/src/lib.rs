use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use rust_agent_fixture_api::Model;
use rust_agent_runtime_api::{ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings};

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub label: u8,
}

#[derive(Clone, Debug, Default)]
pub struct Dependencies;

#[derive(Debug)]
pub struct FixtureModel {
    label: u8,
    resource: Arc<AtomicU64>,
}

impl Model for FixtureModel {
    fn respond(&self, request: &str) -> String {
        self.resource.fetch_add(1, Ordering::Relaxed);
        if self.label == 0 {
            format!("fixture-response:{request}")
        } else {
            format!("fixture-{}-response:{request}", self.label)
        }
    }
}

pub fn build(
    config: &Config,
    _dependencies: Dependencies,
    _runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<FixtureModel>, ComponentBuildError> {
    Ok(ComponentOutput::stateless(FixtureModel {
        label: config.label,
        resource: Arc::new(AtomicU64::new(0)),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_is_deterministic() {
        let output = build(
            &Config::default(),
            Dependencies,
            RuntimePrimitiveBindings::none(),
        )
        .unwrap();
        assert_eq!(output.service().respond("hello"), "fixture-response:hello");
    }

    #[test]
    fn two_instances_are_independent_for_identical_different_and_boundary_configs() {
        for (left, right) in [(7, 7), (7, 9), (0, u8::MAX)] {
            let first = build(
                &Config { label: left },
                Dependencies,
                RuntimePrimitiveBindings::none(),
            )
            .unwrap();
            let second = build(
                &Config { label: right },
                Dependencies,
                RuntimePrimitiveBindings::none(),
            )
            .unwrap();

            assert!(!Arc::ptr_eq(
                &first.service().resource,
                &second.service().resource
            ));
            first.service().respond("first");
            assert_eq!(first.service().resource.load(Ordering::Relaxed), 1);
            assert_eq!(second.service().resource.load(Ordering::Relaxed), 0);
        }
    }
}
