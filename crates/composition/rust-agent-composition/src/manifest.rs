use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};

use crate::{
    custom_target::CustomTargetSpecRecord,
    generator_input::GeneratorInputCommitment,
    metadata::{BuildRequirements, MAX_CATALOG_OWNERS},
    profile::{BuildKind, CompositionProfile},
    resolver::{AppHandoff, MAX_RESOLUTION_EFFECT_ENTRIES, Resolution},
    serde_bounds::{
        deserialize_bounded_vec, deserialize_unique_bounded_map, deserialize_unique_bounded_set,
    },
    snapshot::{
        CanonicalSnapshotEntry, CanonicalSnapshotEntryKind, MAX_CANONICAL_SNAPSHOT_ENTRIES,
        MAX_CANONICAL_SNAPSHOT_FILE_BYTES, MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES,
    },
    target::{Target, TargetFactsRecord},
    toolchain::ComposeRustcProvenance,
};

pub const MAX_COMPOSITION_SOURCE_PACKAGES: usize = 1_024;
pub const MAX_COMPOSITION_SOURCE_ENTRIES: usize = MAX_CANONICAL_SNAPSHOT_ENTRIES;
pub const MAX_COMPOSITION_SOURCE_FILE_BYTES: u64 = MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES;
pub const MAX_COMPOSITION_GENERATED_FILES: usize = 32;
pub const MAX_COMPOSITION_DIRECT_ROOT_BUILD_REQUIREMENTS: usize = MAX_CATALOG_OWNERS + 5;
pub const MAX_CARGO_SOURCE_IDENTITIES: usize = 1_024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePackageRecord {
    pub id: String,
    pub package: String,
    #[serde(rename = "logical-path")]
    pub logical_path: String,
    #[serde(rename = "tree-digest")]
    pub tree_digest: String,
    #[serde(rename = "tree-entries")]
    pub tree_entries: Vec<CanonicalSnapshotEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedSourcePackageRecord {
    id: String,
    package: String,
    #[serde(rename = "logical-path")]
    logical_path: String,
    #[serde(rename = "tree-digest")]
    tree_digest: String,
    #[serde(
        rename = "tree-entries",
        deserialize_with = "deserialize_source_tree_entries"
    )]
    tree_entries: Vec<CanonicalSnapshotEntry>,
}

impl<'de> Deserialize<'de> for SourcePackageRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedSourcePackageRecord::deserialize(deserializer)?;
        let record = Self {
            id: unchecked.id,
            package: unchecked.package,
            logical_path: unchecked.logical_path,
            tree_digest: unchecked.tree_digest,
            tree_entries: unchecked.tree_entries,
        };
        source_record_usage(&record).map_err(de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedFileRecord {
    pub path: String,
    pub digest: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoResolutionRecord {
    pub schema: u32,
    pub target: String,
    #[serde(rename = "cargo-target-input")]
    pub cargo_target_input: String,
    #[serde(rename = "target-fact-digest")]
    pub target_fact_digest: String,
    #[serde(rename = "custom-target-spec-digest")]
    pub custom_target_spec_digest: Option<String>,
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

impl CargoResolutionRecord {
    /// Reconstructs the exact schema-v1 Cargo configuration committed by this
    /// resolution record.
    pub fn canonical_cargo_config(&self) -> String {
        canonical_cargo_config(
            &self.cargo_target_input,
            self.custom_target_spec_digest.is_some(),
        )
    }
}

pub(crate) fn canonical_cargo_config(cargo_target_input: &str, custom_target: bool) -> String {
    let rustflags = if custom_target {
        "rustflags = [\"-Zunstable-options\"]\n"
    } else {
        ""
    };
    format!("[build]\ntarget = {cargo_target_input:?}\n{rustflags}\n[net]\noffline = true\n")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCargoResolutionRecord {
    schema: u32,
    target: String,
    #[serde(rename = "cargo-target-input")]
    cargo_target_input: String,
    #[serde(rename = "target-fact-digest")]
    target_fact_digest: String,
    #[serde(rename = "custom-target-spec-digest")]
    custom_target_spec_digest: Option<String>,
    resolver: String,
    offline: bool,
    #[serde(rename = "isolated-cargo-home")]
    isolated_cargo_home: bool,
    #[serde(rename = "ancestor-config")]
    ancestor_config: String,
    #[serde(deserialize_with = "deserialize_cargo_registries")]
    registries: BTreeMap<String, String>,
    #[serde(
        rename = "git-sources",
        deserialize_with = "deserialize_cargo_git_sources"
    )]
    git_sources: BTreeSet<String>,
}

impl<'de> Deserialize<'de> for CargoResolutionRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedCargoResolutionRecord::deserialize(deserializer)?;
        let source_count = unchecked
            .registries
            .len()
            .checked_add(unchecked.git_sources.len())
            .ok_or_else(|| de::Error::custom("Cargo source identity count overflowed"))?;
        if source_count > MAX_CARGO_SOURCE_IDENTITIES {
            return Err(de::Error::custom(format!(
                "Cargo resolution has {source_count} source identities; maximum is {MAX_CARGO_SOURCE_IDENTITIES}"
            )));
        }
        Ok(Self {
            schema: unchecked.schema,
            target: unchecked.target,
            cargo_target_input: unchecked.cargo_target_input,
            target_fact_digest: unchecked.target_fact_digest,
            custom_target_spec_digest: unchecked.custom_target_spec_digest,
            resolver: unchecked.resolver,
            offline: unchecked.offline,
            isolated_cargo_home: unchecked.isolated_cargo_home,
            ancestor_config: unchecked.ancestor_config,
            registries: unchecked.registries,
            git_sources: unchecked.git_sources,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionIdentityPayload<'a> {
    pub schema: u32,
    pub profile: &'a CompositionProfile,
    pub target: &'a Target,
    #[serde(rename = "target-facts")]
    pub target_facts: &'a TargetFactsRecord,
    #[serde(rename = "compose-rustc")]
    pub compose_rustc: &'a ComposeRustcProvenance,
    #[serde(rename = "generator-inputs")]
    pub generator_inputs: &'a GeneratorInputCommitment,
    #[serde(rename = "custom-target-spec")]
    pub custom_target_spec: Option<&'a CustomTargetSpecRecord>,
    pub resolution: &'a Resolution,
    #[serde(rename = "component-runtime-effects")]
    pub component_runtime_effects: &'a BTreeSet<String>,
    #[serde(rename = "host-runtime-effects")]
    pub host_runtime_effects: &'a BTreeSet<String>,
    #[serde(rename = "direct-root-build-requirements")]
    pub direct_root_build_requirements: &'a BTreeMap<String, BuildRequirements>,
    pub sources: &'a [SourcePackageRecord],
    #[serde(rename = "generated-files")]
    pub generated_files: &'a [GeneratedFileRecord],
    #[serde(rename = "cargo-lock-digest")]
    pub cargo_lock_digest: &'a str,
    #[serde(rename = "cargo-resolution")]
    pub cargo_resolution: &'a CargoResolutionRecord,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
    #[serde(rename = "target-facts")]
    pub target_facts: TargetFactsRecord,
    #[serde(rename = "compose-rustc")]
    pub compose_rustc: ComposeRustcProvenance,
    #[serde(rename = "generator-inputs")]
    pub generator_inputs: GeneratorInputCommitment,
    #[serde(rename = "custom-target-spec")]
    pub custom_target_spec: Option<CustomTargetSpecRecord>,
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
    #[serde(rename = "direct-root-build-requirements")]
    pub direct_root_build_requirements: BTreeMap<String, BuildRequirements>,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCompositionManifest {
    schema: u32,
    algorithm: String,
    #[serde(rename = "composition-hash")]
    composition_hash: String,
    #[serde(rename = "build-kind")]
    build_kind: BuildKind,
    #[serde(rename = "profile-name")]
    profile: String,
    #[serde(rename = "normalized-profile")]
    normalized_profile: CompositionProfile,
    target: String,
    #[serde(rename = "normalized-target")]
    normalized_target: Target,
    #[serde(rename = "target-fact-digest")]
    target_fact_digest: String,
    #[serde(rename = "target-facts")]
    target_facts: TargetFactsRecord,
    #[serde(rename = "compose-rustc")]
    compose_rustc: ComposeRustcProvenance,
    #[serde(rename = "generator-inputs")]
    generator_inputs: GeneratorInputCommitment,
    #[serde(rename = "custom-target-spec")]
    custom_target_spec: Option<CustomTargetSpecRecord>,
    #[serde(
        rename = "selected-components",
        deserialize_with = "deserialize_manifest_selected_components"
    )]
    selected_components: Vec<String>,
    #[serde(rename = "runtime-adapter")]
    runtime_adapter: String,
    #[serde(rename = "host-boundary")]
    host_boundary: Option<String>,
    #[serde(
        rename = "component-runtime-effects",
        deserialize_with = "deserialize_manifest_runtime_effects"
    )]
    component_runtime_effects: BTreeSet<String>,
    #[serde(
        rename = "host-runtime-effects",
        deserialize_with = "deserialize_manifest_runtime_effects"
    )]
    host_runtime_effects: BTreeSet<String>,
    #[serde(
        rename = "compiled-runtime-effects",
        deserialize_with = "deserialize_manifest_runtime_effects"
    )]
    compiled_runtime_effects: BTreeSet<String>,
    #[serde(rename = "build-requirements")]
    build_requirements: BuildRequirements,
    #[serde(
        rename = "direct-root-build-requirements",
        deserialize_with = "deserialize_direct_root_build_requirements"
    )]
    direct_root_build_requirements: BTreeMap<String, BuildRequirements>,
    #[serde(rename = "app-handoff")]
    app_handoff: AppHandoff,
    deployable: bool,
    resolution: Resolution,
    #[serde(deserialize_with = "deserialize_composition_sources")]
    sources: Vec<SourcePackageRecord>,
    #[serde(
        rename = "generated-files",
        deserialize_with = "deserialize_generated_files"
    )]
    generated_files: Vec<GeneratedFileRecord>,
    #[serde(rename = "cargo-lock-digest")]
    cargo_lock_digest: String,
    #[serde(rename = "cargo-resolution-digest")]
    cargo_resolution_digest: String,
    #[serde(rename = "cargo-resolution")]
    cargo_resolution: CargoResolutionRecord,
}

impl<'de> Deserialize<'de> for CompositionManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedCompositionManifest::deserialize(deserializer)?;
        Ok(Self {
            schema: unchecked.schema,
            algorithm: unchecked.algorithm,
            composition_hash: unchecked.composition_hash,
            build_kind: unchecked.build_kind,
            profile: unchecked.profile,
            normalized_profile: unchecked.normalized_profile,
            target: unchecked.target,
            normalized_target: unchecked.normalized_target,
            target_fact_digest: unchecked.target_fact_digest,
            target_facts: unchecked.target_facts,
            compose_rustc: unchecked.compose_rustc,
            generator_inputs: unchecked.generator_inputs,
            custom_target_spec: unchecked.custom_target_spec,
            selected_components: unchecked.selected_components,
            runtime_adapter: unchecked.runtime_adapter,
            host_boundary: unchecked.host_boundary,
            component_runtime_effects: unchecked.component_runtime_effects,
            host_runtime_effects: unchecked.host_runtime_effects,
            compiled_runtime_effects: unchecked.compiled_runtime_effects,
            build_requirements: unchecked.build_requirements,
            direct_root_build_requirements: unchecked.direct_root_build_requirements,
            app_handoff: unchecked.app_handoff,
            deployable: unchecked.deployable,
            resolution: unchecked.resolution,
            sources: unchecked.sources,
            generated_files: unchecked.generated_files,
            cargo_lock_digest: unchecked.cargo_lock_digest,
            cargo_resolution_digest: unchecked.cargo_resolution_digest,
            cargo_resolution: unchecked.cargo_resolution,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedSecurityManifest {
    schema: u32,
    #[serde(rename = "composition-hash")]
    composition_hash: String,
    #[serde(
        rename = "component-runtime-effects",
        deserialize_with = "deserialize_manifest_runtime_effects"
    )]
    component_runtime_effects: BTreeSet<String>,
    #[serde(
        rename = "host-runtime-effects",
        deserialize_with = "deserialize_manifest_runtime_effects"
    )]
    host_runtime_effects: BTreeSet<String>,
    #[serde(
        rename = "compiled-runtime-effects",
        deserialize_with = "deserialize_manifest_runtime_effects"
    )]
    compiled_runtime_effects: BTreeSet<String>,
    #[serde(rename = "build-requirements")]
    build_requirements: BuildRequirements,
}

impl<'de> Deserialize<'de> for SecurityManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedSecurityManifest::deserialize(deserializer)?;
        Ok(Self {
            schema: unchecked.schema,
            composition_hash: unchecked.composition_hash,
            component_runtime_effects: unchecked.component_runtime_effects,
            host_runtime_effects: unchecked.host_runtime_effects,
            compiled_runtime_effects: unchecked.compiled_runtime_effects,
            build_requirements: unchecked.build_requirements,
        })
    }
}

fn deserialize_source_tree_entries<'de, D>(
    deserializer: D,
) -> Result<Vec<CanonicalSnapshotEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(
        deserializer,
        MAX_CANONICAL_SNAPSHOT_ENTRIES,
        "source package tree-entries",
    )
}

fn deserialize_cargo_registries<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_unique_bounded_map(
        deserializer,
        MAX_CARGO_SOURCE_IDENTITIES,
        "Cargo registry sources",
    )
}

fn deserialize_cargo_git_sources<'de, D>(deserializer: D) -> Result<BTreeSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_unique_bounded_set(
        deserializer,
        MAX_CARGO_SOURCE_IDENTITIES,
        "Cargo git sources",
    )
}

fn deserialize_manifest_selected_components<'de, D>(
    deserializer: D,
) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(
        deserializer,
        MAX_CATALOG_OWNERS,
        "manifest selected-components",
    )
}

fn deserialize_manifest_runtime_effects<'de, D>(
    deserializer: D,
) -> Result<BTreeSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_unique_bounded_set(
        deserializer,
        MAX_RESOLUTION_EFFECT_ENTRIES,
        "manifest runtime effects",
    )
}

fn deserialize_direct_root_build_requirements<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, BuildRequirements>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_unique_bounded_map(
        deserializer,
        MAX_COMPOSITION_DIRECT_ROOT_BUILD_REQUIREMENTS,
        "manifest direct root build requirements",
    )
}

fn deserialize_generated_files<'de, D>(
    deserializer: D,
) -> Result<Vec<GeneratedFileRecord>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(
        deserializer,
        MAX_COMPOSITION_GENERATED_FILES,
        "manifest generated files",
    )
}

fn source_record_usage(record: &SourcePackageRecord) -> Result<(usize, u64), String> {
    let mut file_bytes = 0_u64;
    for entry in &record.tree_entries {
        let CanonicalSnapshotEntryKind::RegularFile { bytes, .. } = &entry.kind else {
            continue;
        };
        if *bytes > MAX_CANONICAL_SNAPSHOT_FILE_BYTES {
            return Err(format!(
                "source package `{}` entry `{}` has {bytes} bytes; maximum is {MAX_CANONICAL_SNAPSHOT_FILE_BYTES}",
                record.logical_path, entry.path
            ));
        }
        file_bytes = file_bytes.checked_add(*bytes).ok_or_else(|| {
            format!(
                "source package `{}` file byte count overflowed",
                record.logical_path
            )
        })?;
        if file_bytes > MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES {
            return Err(format!(
                "source package `{}` has {file_bytes} total file bytes; maximum is {MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES}",
                record.logical_path
            ));
        }
    }
    Ok((record.tree_entries.len(), file_bytes))
}

fn deserialize_composition_sources<'de, D>(
    deserializer: D,
) -> Result<Vec<SourcePackageRecord>, D::Error>
where
    D: Deserializer<'de>,
{
    struct CompositionSourcesVisitor;

    impl<'de> Visitor<'de> for CompositionSourcesVisitor {
        type Value = Vec<SourcePackageRecord>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_COMPOSITION_SOURCE_PACKAGES} source packages within the composition-wide entry and byte bounds"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|hint| hint > MAX_COMPOSITION_SOURCE_PACKAGES)
            {
                return Err(de::Error::custom(format!(
                    "composition has more than {MAX_COMPOSITION_SOURCE_PACKAGES} source packages"
                )));
            }
            let mut records = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or(0)
                    .min(MAX_COMPOSITION_SOURCE_PACKAGES),
            );
            let mut entry_count = 0_usize;
            let mut file_bytes = 0_u64;
            loop {
                if records.len() == MAX_COMPOSITION_SOURCE_PACKAGES {
                    return match sequence.next_element::<de::IgnoredAny>()? {
                        Some(_) => Err(de::Error::custom(format!(
                            "composition has more than {MAX_COMPOSITION_SOURCE_PACKAGES} source packages"
                        ))),
                        None => Ok(records),
                    };
                }
                let Some(record) = sequence.next_element::<SourcePackageRecord>()? else {
                    return Ok(records);
                };
                let (package_entries, package_bytes) =
                    source_record_usage(&record).map_err(de::Error::custom)?;
                entry_count = entry_count.checked_add(package_entries).ok_or_else(|| {
                    de::Error::custom("composition source entry count overflowed")
                })?;
                if entry_count > MAX_COMPOSITION_SOURCE_ENTRIES {
                    return Err(de::Error::custom(format!(
                        "composition source trees have {entry_count} entries; maximum is {MAX_COMPOSITION_SOURCE_ENTRIES}"
                    )));
                }
                file_bytes = file_bytes.checked_add(package_bytes).ok_or_else(|| {
                    de::Error::custom("composition source file byte count overflowed")
                })?;
                if file_bytes > MAX_COMPOSITION_SOURCE_FILE_BYTES {
                    return Err(de::Error::custom(format!(
                        "composition source files have {file_bytes} total bytes; maximum is {MAX_COMPOSITION_SOURCE_FILE_BYTES}"
                    )));
                }
                records.push(record);
            }
        }
    }

    deserializer.deserialize_seq(CompositionSourcesVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_record(id: &str, sizes: &[u64]) -> SourcePackageRecord {
        SourcePackageRecord {
            id: id.into(),
            package: id.into(),
            logical_path: id.into(),
            tree_digest: "0".repeat(64),
            tree_entries: sizes
                .iter()
                .enumerate()
                .map(|(index, bytes)| {
                    CanonicalSnapshotEntry::regular_file(
                        format!("file-{index}"),
                        "0".repeat(64),
                        *bytes,
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn composition_sources_enforce_the_aggregate_during_deserialization() {
        let excessive_packages = serde_json::to_string(
            &(0..=MAX_COMPOSITION_SOURCE_PACKAGES)
                .map(|index| source_record(&format!("source-{index:04}"), &[]))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let mut deserializer = serde_json::Deserializer::from_str(&excessive_packages);
        let error = deserialize_composition_sources(&mut deserializer).unwrap_err();
        assert!(error.to_string().contains("source packages"));

        let records = vec![
            source_record(
                "first",
                &[
                    MAX_CANONICAL_SNAPSHOT_FILE_BYTES,
                    MAX_CANONICAL_SNAPSHOT_FILE_BYTES,
                ],
            ),
            source_record(
                "second",
                &[
                    MAX_CANONICAL_SNAPSHOT_FILE_BYTES,
                    MAX_CANONICAL_SNAPSHOT_FILE_BYTES,
                    1,
                ],
            ),
        ];
        let input = serde_json::to_string(&records).unwrap();
        let mut deserializer = serde_json::Deserializer::from_str(&input);
        let error = deserialize_composition_sources(&mut deserializer).unwrap_err();
        assert!(error.to_string().contains("composition source files have"));
    }

    #[test]
    fn cargo_source_collections_are_unique_and_bounded_during_deserialization() {
        let value = serde_json::json!({
            "schema": 1,
            "target": "x86_64-unknown-linux-gnu",
            "cargo-target-input": "x86_64-unknown-linux-gnu",
            "target-fact-digest": "0".repeat(64),
            "custom-target-spec-digest": null,
            "resolver": "2",
            "offline": true,
            "isolated-cargo-home": true,
            "ancestor-config": "forbidden",
            "registries": {},
            "git-sources": [],
        });
        let mut excessive = value.clone();
        excessive["registries"] = serde_json::Value::Object(
            (0..=MAX_CARGO_SOURCE_IDENTITIES)
                .map(|index| {
                    (
                        format!("registry-{index:04}"),
                        serde_json::Value::String(format!("registry+https://{index}.invalid")),
                    )
                })
                .collect(),
        );
        let error = serde_json::from_value::<CargoResolutionRecord>(excessive).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Cargo registry sources has more than")
        );

        let mut combined = value;
        combined["registries"] = serde_json::Value::Object(
            (0..600)
                .map(|index| {
                    (
                        format!("registry-{index:04}"),
                        serde_json::Value::String(format!("registry+https://{index}.invalid")),
                    )
                })
                .collect(),
        );
        combined["git-sources"] = serde_json::Value::Array(
            (0..425)
                .map(|index| {
                    serde_json::Value::String(format!(
                        "git+https://example.invalid/{index}#{}",
                        "0".repeat(40)
                    ))
                })
                .collect(),
        );
        let error = serde_json::from_value::<CargoResolutionRecord>(combined).unwrap_err();
        assert!(error.to_string().contains("has 1025 source identities"));

        let duplicate = r#"{
            "schema":1,
            "target":"x86_64-unknown-linux-gnu",
            "cargo-target-input":"x86_64-unknown-linux-gnu",
            "target-fact-digest":"0000000000000000000000000000000000000000000000000000000000000000",
            "custom-target-spec-digest":null,
            "resolver":"2",
            "offline":true,
            "isolated-cargo-home":true,
            "ancestor-config":"forbidden",
            "registries":{"crates-io":"first","crates-io":"second"},
            "git-sources":[]
        }"#;
        let error = serde_json::from_str::<CargoResolutionRecord>(duplicate).unwrap_err();
        assert!(error.to_string().contains("duplicate key"));
    }

    #[test]
    fn security_manifest_sets_reject_duplicate_direct_serde_entries() {
        let input = r#"{
            "schema":1,
            "composition-hash":"0000000000000000000000000000000000000000000000000000000000000000",
            "component-runtime-effects":["read-local","read-local"],
            "host-runtime-effects":[],
            "compiled-runtime-effects":[],
            "build-requirements":{"executables":[],"read-inputs":[],"environment":[]}
        }"#;
        let error = serde_json::from_str::<SecurityManifest>(input).unwrap_err();
        assert!(error.to_string().contains("duplicate entry"));
    }

    #[test]
    fn composition_manifest_top_level_collections_are_directly_bounded() {
        let selected = serde_json::to_string(
            &(0..=MAX_CATALOG_OWNERS)
                .map(|index| format!("component-{index}"))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let mut deserializer = serde_json::Deserializer::from_str(&selected);
        let error = deserialize_manifest_selected_components(&mut deserializer).unwrap_err();
        assert!(error.to_string().contains("manifest selected-components"));

        let generated = serde_json::to_string(
            &(0..=MAX_COMPOSITION_GENERATED_FILES)
                .map(|index| GeneratedFileRecord {
                    path: format!("generated-{index}"),
                    digest: "0".repeat(64),
                    bytes: 0,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let mut deserializer = serde_json::Deserializer::from_str(&generated);
        let error = deserialize_generated_files(&mut deserializer).unwrap_err();
        assert!(error.to_string().contains("manifest generated files"));

        let direct_roots = serde_json::Value::Object(
            (0..=MAX_COMPOSITION_DIRECT_ROOT_BUILD_REQUIREMENTS)
                .map(|index| {
                    (
                        format!("root-{index}"),
                        serde_json::json!({
                            "executables": [],
                            "read-inputs": [],
                            "environment": [],
                        }),
                    )
                })
                .collect(),
        );
        let direct_roots = serde_json::to_string(&direct_roots).unwrap();
        let mut deserializer = serde_json::Deserializer::from_str(&direct_roots);
        let error = deserialize_direct_root_build_requirements(&mut deserializer).unwrap_err();
        assert!(error.to_string().contains("direct root build requirements"));
    }
}
