use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    metadata::BuildRequirements,
    profile::{BuildKind, CompositionProfile},
    resolver::{AppHandoff, Resolution},
    target::Target,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFileRecord {
    pub path: String,
    pub digest: String,
    pub bytes: u64,
    pub executable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePackageRecord {
    pub id: String,
    pub package: String,
    #[serde(rename = "logical-path")]
    pub logical_path: String,
    #[serde(rename = "tree-digest")]
    pub tree_digest: String,
    pub files: Vec<SourceFileRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedFileRecord {
    pub path: String,
    pub digest: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoResolutionRecord {
    pub schema: u32,
    pub target: String,
    #[serde(rename = "target-fact-digest")]
    pub target_fact_digest: String,
    pub resolver: String,
    pub offline: bool,
    #[serde(rename = "isolated-cargo-home")]
    pub isolated_cargo_home: bool,
    #[serde(rename = "ancestor-config")]
    pub ancestor_config: String,
    pub registries: BTreeMap<String, String>,
    #[serde(rename = "git-sources")]
    pub git_sources: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionIdentityPayload<'a> {
    pub schema: u32,
    pub profile: &'a CompositionProfile,
    pub target: &'a Target,
    pub resolution: &'a Resolution,
    pub sources: &'a [SourcePackageRecord],
    #[serde(rename = "generated-files")]
    pub generated_files: &'a [GeneratedFileRecord],
    #[serde(rename = "cargo-lock-digest")]
    pub cargo_lock_digest: &'a str,
    #[serde(rename = "cargo-resolution")]
    pub cargo_resolution: &'a CargoResolutionRecord,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionManifest {
    pub schema: u32,
    pub algorithm: String,
    #[serde(rename = "composition-hash")]
    pub composition_hash: String,
    #[serde(rename = "build-kind")]
    pub build_kind: BuildKind,
    #[serde(rename = "profile-name")]
    pub profile: String,
    #[serde(rename = "normalized-profile")]
    pub normalized_profile: CompositionProfile,
    pub target: String,
    #[serde(rename = "normalized-target")]
    pub normalized_target: Target,
    #[serde(rename = "target-fact-digest")]
    pub target_fact_digest: String,
    #[serde(rename = "selected-components")]
    pub selected_components: Vec<String>,
    #[serde(rename = "runtime-adapter")]
    pub runtime_adapter: String,
    #[serde(rename = "host-boundary")]
    pub host_boundary: Option<String>,
    #[serde(rename = "component-runtime-effects")]
    pub component_runtime_effects: BTreeSet<String>,
    #[serde(rename = "host-runtime-effects")]
    pub host_runtime_effects: BTreeSet<String>,
    #[serde(rename = "compiled-runtime-effects")]
    pub compiled_runtime_effects: BTreeSet<String>,
    #[serde(rename = "build-requirements")]
    pub build_requirements: BuildRequirements,
    #[serde(rename = "app-handoff")]
    pub app_handoff: AppHandoff,
    pub deployable: bool,
    pub resolution: Resolution,
    pub sources: Vec<SourcePackageRecord>,
    #[serde(rename = "generated-files")]
    pub generated_files: Vec<GeneratedFileRecord>,
    #[serde(rename = "cargo-lock-digest")]
    pub cargo_lock_digest: String,
    #[serde(rename = "cargo-resolution-digest")]
    pub cargo_resolution_digest: String,
    #[serde(rename = "cargo-resolution")]
    pub cargo_resolution: CargoResolutionRecord,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityManifest {
    pub schema: u32,
    #[serde(rename = "composition-hash")]
    pub composition_hash: String,
    #[serde(rename = "component-runtime-effects")]
    pub component_runtime_effects: BTreeSet<String>,
    #[serde(rename = "host-runtime-effects")]
    pub host_runtime_effects: BTreeSet<String>,
    #[serde(rename = "compiled-runtime-effects")]
    pub compiled_runtime_effects: BTreeSet<String>,
    #[serde(rename = "build-requirements")]
    pub build_requirements: BuildRequirements,
}
