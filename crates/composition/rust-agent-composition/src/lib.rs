//! Pure catalog/resolver logic and deterministic Phase 1A composition generation.

pub mod canonical;
pub mod catalog;
pub mod diagnostics;
pub mod generator;
pub mod manifest;
pub mod metadata;
pub mod profile;
pub mod resolver;
pub mod target;

pub use catalog::{CatalogError, NormalizedCatalog};
pub use generator::{
    ComposeError, ComposeOptions, GeneratedComposition, compose, load_manifest, verify_composition,
};
pub use manifest::CompositionManifest;
pub use metadata::CatalogDocument;
pub use profile::CompositionProfile;
pub use resolver::{Resolution, ResolutionError, resolve};
pub use target::{Environment, Target, TargetError};

pub const WASM_BINDGEN_CLI_LOGICAL_ID: &str = "wasm-bindgen-cli";
pub const WASM_BINDGEN_PROTOCOL_VERSION: &str = "0.2.127";
pub const WASM_BINDGEN_FUTURES_VERSION: &str = "0.4.77";
