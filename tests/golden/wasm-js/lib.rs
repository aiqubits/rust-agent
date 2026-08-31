#![forbid(unsafe_code)]

mod identity;

pub use identity::COMPOSITION_HASH;
pub use rust_agent_runtime_api::{BuildError, RuntimePrimitives};
mod wasm;
pub use wasm::start;
pub use rust_agent_fixture_runtime::create_runtime_primitives as create_runtime_primitives;

pub fn build(runtime: RuntimePrimitives) -> Result<rust_agent_fixture_api::FixtureApp, BuildError> {
    if runtime.adapter().as_str() != "fixture-runtime" {
        return Err(BuildError::InvalidComposition("runtime adapter identity mismatch"));
    }
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
    Ok(rust_agent_fixture_api::FixtureApp::new(binding_driver_fixture_driver, None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_factory_graph_executes() {
        let runtime = create_runtime_primitives().unwrap();
        let app = build(runtime).unwrap();
        assert_eq!(app.run("hello"), "fixture-response:hello");
    }
}
