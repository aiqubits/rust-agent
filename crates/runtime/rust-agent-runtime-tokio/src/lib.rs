//! Native runtime adapter that owns an independent Tokio driver.

use std::sync::Arc;

use rust_agent_runtime_api::{RuntimeAdapterIdentity, RuntimePrimitiveError, RuntimePrimitives};

pub fn create_runtime_primitives() -> Result<RuntimePrimitives, RuntimePrimitiveError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|_| RuntimePrimitiveError::DriverConstructionFailed)?;
    Ok(RuntimePrimitives::new_owned(
        RuntimeAdapterIdentity::checked("runtime-tokio")?,
        Arc::new(runtime),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bundle_owns_an_independent_runtime() {
        let first = create_runtime_primitives().unwrap();
        let second = create_runtime_primitives().unwrap();
        assert!(first.has_owned_driver());
        assert!(second.has_owned_driver());
        assert!(!first.same_bundle_identity(&second));
    }
}
