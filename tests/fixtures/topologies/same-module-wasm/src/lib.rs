#![forbid(unsafe_code)]

/// A Rust Host compiled into the same WASM module as the emitted composition.
/// The typed handle never crosses a JavaScript ABI boundary.
pub fn invoke(request: &str) -> Result<String, agent::BuildError> {
    let runtime = agent::create_runtime_primitives().map_err(agent::BuildError::InvalidRuntime)?;
    let app = agent::build(
        agent::RuntimeConfig::default(),
        agent::HostBindings::default(),
        runtime,
    )?;
    Ok(app.run(request))
}
