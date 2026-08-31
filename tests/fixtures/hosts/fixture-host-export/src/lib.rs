use rust_agent_fixture_api::FixtureApp;
use rust_agent_runtime_api::{RuntimePrimitiveError, RuntimePrimitives};
pub use wasm_bindgen::{JsValue, prelude::wasm_bindgen};
pub use wasm_bindgen_futures as futures;

pub const ABI_VERSION: u32 = 1;

pub fn runtime_primitives(
    create: fn() -> Result<RuntimePrimitives, RuntimePrimitiveError>,
) -> Result<RuntimePrimitives, RuntimePrimitiveError> {
    create()
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct WasmAppHandle {
    app: FixtureApp,
}

impl WasmAppHandle {
    pub fn from_app(app: FixtureApp) -> Self {
        Self { app }
    }
}

#[wasm_bindgen]
impl WasmAppHandle {
    pub fn run(&self, request: &str) -> String {
        self.app.run(request)
    }

    pub fn status(&self) -> String {
        "ready".into()
    }
}
