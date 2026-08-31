use std::fmt;

use rust_agent_fixture_api::FixtureApp;
use rust_agent_runtime_api::{BuildError, RuntimePrimitiveError, RuntimePrimitives};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostEntryError {
    Runtime(RuntimePrimitiveError),
    Build(BuildError),
}

impl fmt::Display for HostEntryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => write!(formatter, "runtime creation failed: {error}"),
            Self::Build(error) => write!(formatter, "composition build failed: {error}"),
        }
    }
}

impl std::error::Error for HostEntryError {}

pub fn run<R, F>(create_runtime: R, build: F) -> Result<FixtureApp, HostEntryError>
where
    R: FnOnce() -> Result<RuntimePrimitives, RuntimePrimitiveError>,
    F: FnOnce(RuntimePrimitives) -> Result<FixtureApp, BuildError>,
{
    let runtime = create_runtime().map_err(HostEntryError::Runtime)?;
    build(runtime).map_err(HostEntryError::Build)
}

#[cfg(test)]
mod tests {
    use rust_agent_fixture_api::{Driver, DriverBinding};
    use rust_agent_runtime_api::RuntimeAdapterIdentity;
    use std::sync::Arc;

    use super::*;

    struct Echo;
    impl Driver for Echo {
        fn run(&self, request: &str) -> String {
            request.to_owned()
        }
    }

    #[test]
    fn entry_passes_the_exact_runtime_bundle_to_build() {
        let app = run(
            || {
                Ok(RuntimePrimitives::new(RuntimeAdapterIdentity::checked(
                    "fixture-runtime",
                )?))
            },
            |runtime| {
                assert_eq!(runtime.adapter().as_str(), "fixture-runtime");
                Ok(FixtureApp::new(
                    DriverBinding::from_provider(Arc::new(Echo)),
                    None,
                ))
            },
        )
        .unwrap();
        assert_eq!(app.run("hello"), "hello");
    }
}
