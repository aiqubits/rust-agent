//! Product-neutral typed seams for Phase 1A generated-graph proofs.

use std::sync::Arc;

use rust_agent_runtime_api::BuildError;

pub const FACTORY_ABI: &str = "rust-agent-component-factory-v1";

pub trait BuildProof: Send + Sync {
    fn marker(&self) -> &'static str;
}

#[derive(Clone)]
pub struct BuildProofBinding(Arc<dyn BuildProof>);

impl std::fmt::Debug for BuildProofBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BuildProofBinding(<opaque>)")
    }
}

impl BuildProofBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: BuildProof + 'static,
    {
        Self(provider)
    }

    pub fn marker(&self) -> &'static str {
        self.0.marker()
    }
}

pub trait Model: Send + Sync {
    fn respond(&self, request: &str) -> String;
}

#[derive(Clone)]
pub struct ModelBinding(Arc<dyn Model>);

impl std::fmt::Debug for ModelBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ModelBinding(<opaque>)")
    }
}

impl ModelBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: Model + 'static,
    {
        Self(provider)
    }

    pub fn respond(&self, request: &str) -> String {
        self.0.respond(request)
    }
}

pub trait Driver: Send + Sync {
    fn run(&self, request: &str) -> String;
}

#[derive(Clone)]
pub struct DriverBinding(Arc<dyn Driver>);

impl std::fmt::Debug for DriverBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DriverBinding(<opaque>)")
    }
}

impl DriverBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: Driver + 'static,
    {
        Self(provider)
    }

    pub fn run(&self, request: &str) -> String {
        self.0.run(request)
    }
}

pub trait FileReader: Send + Sync {
    fn read_fixture(&self, path: &str) -> Result<String, BuildError>;
}

#[derive(Clone)]
pub struct FileReaderBinding(Arc<dyn FileReader>);

impl std::fmt::Debug for FileReaderBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FileReaderBinding(<opaque>)")
    }
}

impl FileReaderBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: FileReader + 'static,
    {
        Self(provider)
    }

    pub fn read_fixture(&self, path: &str) -> Result<String, BuildError> {
        self.0.read_fixture(path)
    }
}

#[derive(Clone, Debug)]
pub struct FixtureApp {
    driver: DriverBinding,
    file_reader: Option<FileReaderBinding>,
}

impl FixtureApp {
    pub fn new(driver: DriverBinding, file_reader: Option<FileReaderBinding>) -> Self {
        Self {
            driver,
            file_reader,
        }
    }

    pub fn run(&self, request: &str) -> String {
        self.driver.run(request)
    }

    pub fn read_fixture(&self, path: &str) -> Result<Option<String>, BuildError> {
        self.file_reader
            .as_ref()
            .map(|reader| reader.read_fixture(path))
            .transpose()
    }

    pub fn has_file_reader(&self) -> bool {
        self.file_reader.is_some()
    }
}
