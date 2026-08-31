use rust_agent_fixture_api::FileReader;
use rust_agent_runtime_api::{
    BuildError, ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings,
};

#[derive(Clone, Debug, Default)]
pub struct Config;

#[derive(Clone, Debug, Default)]
pub struct Dependencies;

#[derive(Debug)]
pub struct FixtureFileReader;

impl FileReader for FixtureFileReader {
    fn read_fixture(&self, path: &str) -> Result<String, BuildError> {
        if path.contains('/') || path.contains('\\') || path == ".." {
            return Err(BuildError::InvalidComposition(
                "fixture path must be a single safe segment",
            ));
        }
        Ok(format!("fixture-file:{path}"))
    }
}

pub fn build(
    _config: &Config,
    _dependencies: Dependencies,
    _runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<FixtureFileReader>, ComponentBuildError> {
    Ok(ComponentOutput::stateless(FixtureFileReader))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_reader_rejects_path_traversal_shapes() {
        let reader = FixtureFileReader;
        assert_eq!(
            reader.read_fixture("readme").unwrap(),
            "fixture-file:readme"
        );
        assert!(reader.read_fixture("../secret").is_err());
    }
}
