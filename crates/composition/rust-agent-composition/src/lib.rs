//! Pure catalog/resolver logic and deterministic Phase 1A composition generation.

pub mod canonical;
pub mod cargo_context;
pub mod catalog;
pub mod custom_target;
pub mod diagnostics;
pub mod generator;
pub mod manifest;
pub mod metadata;
pub mod profile;
pub mod resolver;
pub mod snapshot;
pub mod target;

pub use cargo_context::{CargoConfigIsolationError, verify_cargo_config_isolation};
pub use catalog::{CatalogError, NormalizedCatalog};
pub use custom_target::{
    CustomTargetSnapshotObservation, CustomTargetSpecError, CustomTargetSpecRecord,
    MAX_CUSTOM_TARGET_SPEC_BYTES, verify_custom_target_snapshot,
};
pub use generator::{
    ComposeError, ComposeOptions, GeneratedComposition, compose, load_manifest, verify_composition,
    verify_emitted_composition,
};
pub use manifest::CompositionManifest;
pub use metadata::CatalogDocument;
pub use profile::CompositionProfile;
pub use resolver::{Resolution, ResolutionError, resolve};
pub use target::{Arch, Environment, Os, Target, TargetError};

pub const WASM_BINDGEN_CLI_LOGICAL_ID: &str = "wasm-bindgen-cli";
pub const WASM_BINDGEN_PROTOCOL_VERSION: &str = "0.2.127";
pub const WASM_BINDGEN_FUTURES_VERSION: &str = "0.4.77";
