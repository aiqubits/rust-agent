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

    #[test]
    fn two_runtime_bundles_are_independently_owned() {
        let first = create_runtime_primitives().unwrap();
        let second = create_runtime_primitives().unwrap();

        assert_eq!(first.adapter(), second.adapter());
        assert!(!first.same_bundle_identity(&second));
        assert!(first.same_bundle_identity(&first.clone()));
    }
}
