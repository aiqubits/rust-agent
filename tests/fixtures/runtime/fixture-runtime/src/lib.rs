use rust_agent_runtime_api::{RuntimeAdapterIdentity, RuntimePrimitiveError, RuntimePrimitives};

pub fn create_runtime_primitives() -> Result<RuntimePrimitives, RuntimePrimitiveError> {
    Ok(RuntimePrimitives::new(RuntimeAdapterIdentity::checked(
        "fixture-runtime",
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_bundle_has_exact_adapter_identity() {
        assert_eq!(
            create_runtime_primitives().unwrap().adapter().as_str(),
            "fixture-runtime"
        );
    }
}
