use rust_agent_fixture_host_export::{JsValue, WasmAppHandle, wasm_bindgen};

#[wasm_bindgen]
pub async fn start(
    runtime_config: JsValue,
    host_bindings: JsValue,
) -> Result<WasmAppHandle, JsValue> {
    if !runtime_config.is_object() || runtime_config.is_null() {
        return Err(JsValue::from_str("runtime_config must be an object"));
    }
    if !host_bindings.is_object() || host_bindings.is_null() {
        return Err(JsValue::from_str("host_bindings must be an object"));
    }
    let runtime = rust_agent_fixture_host_export::runtime_primitives(crate::create_runtime_primitives)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    let app = crate::build(
        crate::RuntimeConfig::default(),
        crate::HostBindings::default(),
        runtime,
    )
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    Ok(WasmAppHandle::from_app(app))
}
