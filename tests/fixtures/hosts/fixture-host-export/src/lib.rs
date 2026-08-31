use rust_agent_runtime_api::{RuntimePrimitiveError, RuntimePrimitives};

pub const ABI_VERSION: u32 = 1;

pub fn runtime_primitives(
    create: fn() -> Result<RuntimePrimitives, RuntimePrimitiveError>,
) -> Result<RuntimePrimitives, RuntimePrimitiveError> {
    create()
}
