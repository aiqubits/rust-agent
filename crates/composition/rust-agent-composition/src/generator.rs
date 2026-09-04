use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, FileTimes},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use walkdir::WalkDir;

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos"
))]
use rustix::fs::{CWD, RenameFlags, renameat_with};

use crate::{
    canonical::{self, CanonicalError},
    cargo_context::{
        CargoConfigIsolationError, reject_ambient_cargo_config_for_planned_path,
        verify_cargo_config_isolation,
    },
    catalog::{CatalogError, NormalizedCatalog},
    catalog_trust::{
        CatalogEvidenceOwner, CatalogTrustError, CatalogTrustInputCommitment, EvidenceOwnerKind,
        MAX_COEXISTENCE_EVIDENCE_BYTES, MAX_TOTAL_COEXISTENCE_EVIDENCE_BYTES, evidence_requests,
    },
    custom_target::{
        CustomTargetSpecError, CustomTargetSpecRecord, MAX_CUSTOM_TARGET_SPEC_BYTES,
        verify_custom_target_snapshot,
    },
    discovery::{DiscoveredCatalog, DiscoveryError, discover_workspace_catalog},
    generator_input::{GeneratorInputCommitment, GeneratorInputError},
    manifest::{
        CargoResolutionRecord, CompositionIdentityPayload, CompositionManifest,
        GeneratedFileRecord, MAX_CARGO_SOURCE_IDENTITIES, MAX_COMPOSITION_SOURCE_ENTRIES,
        MAX_COMPOSITION_SOURCE_FILE_BYTES, MAX_COMPOSITION_SOURCE_PACKAGES, SecurityManifest,
        SourcePackageRecord,
    },
    metadata::{
        AppCoexistence, BuildRequirements, CatalogTrustPolicy, ConfigSource, HostBoundaryKind,
        MAX_CATALOG_TRUST_POLICY_BYTES,
    },
    profile::{BuildKind, CompositionProfile, MAX_PROFILE_DOCUMENT_BYTES},
    resolver::{ResolutionError, resolve},
    snapshot::{
        CanonicalSnapshotEntry, CanonicalSnapshotEntryKind, CanonicalSnapshotError,
        CanonicalSnapshotTree, MAX_CANONICAL_SNAPSHOT_ENTRIES, MAX_CANONICAL_SNAPSHOT_FILE_BYTES,
        MAX_CANONICAL_SNAPSHOT_JSON_BYTES, MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES,
    },
    target::{MAX_CANONICAL_TARGET_FACTS_RECORD_BYTES, Target, TargetError, TargetFactsRecord},
    toolchain::{ComposeRustcError, ComposeRustcSnapshot},
};

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(1);
const PINNED_RUST_VERSION: &str = env!("CARGO_PKG_RUST_VERSION");
const MAX_SOURCE_MANIFEST_BYTES: u64 = MAX_CANONICAL_SNAPSHOT_JSON_BYTES as u64;
const MAX_COMPOSITION_CONTROL_FILE_BYTES: u64 = MAX_CANONICAL_SNAPSHOT_JSON_BYTES as u64;
const SNAPSHOT_COPY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_MANIFEST_TARGET_SELECTORS: usize = 256;
const MAX_MANIFEST_DEPENDENCIES: usize = 4_096;
const MAX_CARGO_LOCK_PACKAGES: usize = 16 * 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompositionTreeEntryKind {
    Directory,
    RegularFile,
}

#[derive(Clone, Debug)]
pub struct ComposeOptions {
    pub workspace_root: PathBuf,
    pub profile_path: PathBuf,
    pub catalog_trust_policy_path: PathBuf,
    pub output_root: PathBuf,
    pub rustc_path: PathBuf,
    pub cargo_path: PathBuf,
    pub registry_cache_path: Option<PathBuf>,
    pub custom_target_spec_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedComposition {
    pub composition_hash: String,
    pub path: PathBuf,
    pub manifest: CompositionManifest,
}

#[derive(Debug, Error)]
pub enum ComposeError {
    #[error("workspace, input, tool, and output paths must be absolute: {0}")]
    NonAbsolutePath(String),
    #[error("composition input escapes the workspace: {0}")]
    InputOutsideWorkspace(String),
    #[error("composition input `{path}` has {actual} bytes; maximum is {maximum}")]
    InputTooLarge {
        path: String,
        actual: u64,
        maximum: u64,
    },
    #[error("I/O failed while composing: {0}")]
    Io(#[from] io::Error),
    #[error("workspace package metadata discovery failed: {0}")]
    Discovery(#[from] DiscoveryError),
    #[error("profile TOML is invalid: {0}")]
    ProfileToml(#[source] toml::de::Error),
    #[error("catalog trust-policy TOML is invalid: {0}")]
    CatalogTrustToml(#[source] toml::de::Error),
    #[error("catalog is invalid: {0}")]
    Catalog(#[from] CatalogError),
    #[error("catalog trust input is invalid: {0}")]
    CatalogTrust(#[from] CatalogTrustError),
    #[error("target is invalid: {0}")]
    Target(#[from] TargetError),
    #[error("compose rustc provenance is invalid: {0}")]
    ComposeRustc(#[from] ComposeRustcError),
    #[error("generator-input commitment is invalid: {0}")]
    GeneratorInput(#[from] GeneratorInputError),
    #[error("custom target spec is invalid: {0}")]
    CustomTargetSpec(#[from] CustomTargetSpecError),
    #[error("composition cannot be resolved: {0}")]
    Resolution(#[from] ResolutionError),
    #[error("canonical encoding failed: {0}")]
    Canonical(#[from] CanonicalError),
    #[error("canonical source snapshot is invalid: {0}")]
    Snapshot(#[from] CanonicalSnapshotError),
    #[error("source tree contains a symlink or unsupported file: {0}")]
    UnsupportedSourceEntry(String),
    #[error("source package is missing: {0}")]
    MissingSourcePackage(String),
    #[error("source manifest normalization failed for {path}: {message}")]
    ManifestNormalization { path: String, message: String },
    #[error("generated Cargo lock failed: {0}")]
    CargoLock(String),
    #[error("existing composition at {path} does not match expected identity {expected}")]
    ExistingCompositionMismatch { path: String, expected: String },
    #[error("existing composition at {path} failed canonical verification: {message}")]
    ExistingCompositionCorrupt { path: String, message: String },
    #[error("Phase 1A supports product-neutral library fixture generation only: {0}")]
    UnsupportedPhase1A(String),
    #[error("composition verification failed: {0}")]
    Verification(String),
    #[error("explicit Cargo registry cache is invalid: {0}")]
    InvalidRegistryCache(String),
    #[error("Cargo resolution context is not isolated: {0}")]
    CargoConfigIsolation(#[from] CargoConfigIsolationError),
}

pub fn compose(options: &ComposeOptions) -> Result<GeneratedComposition, ComposeError> {
    validate_options(options)?;
    reject_ambient_cargo_config_for_planned_path(&options.workspace_root)?;
    reject_ambient_cargo_config_for_planned_path(&options.output_root)?;
    let profile_bytes = read_workspace_input(
        &options.workspace_root,
        &options.profile_path,
        MAX_PROFILE_DOCUMENT_BYTES,
    )?;
    let profile =
        CompositionProfile::from_toml(std::str::from_utf8(&profile_bytes).map_err(|error| {
            ComposeError::ManifestNormalization {
                path: options.profile_path.display().to_string(),
                message: error.to_string(),
            }
        })?)
        .map_err(ComposeError::ProfileToml)?;
    let catalog_trust_policy_bytes = read_workspace_input(
        &options.workspace_root,
        &options.catalog_trust_policy_path,
        MAX_CATALOG_TRUST_POLICY_BYTES,
    )?;
    let catalog_trust_policy =
        CatalogTrustPolicy::from_toml(std::str::from_utf8(&catalog_trust_policy_bytes).map_err(
            |error| ComposeError::ManifestNormalization {
                path: options.catalog_trust_policy_path.display().to_string(),
                message: error.to_string(),
            },
        )?)
        .map_err(ComposeError::CatalogTrustToml)?;
    if !matches!(profile.build_kind, BuildKind::Library | BuildKind::Wasm) {
        return Err(ComposeError::UnsupportedPhase1A(format!(
            "{:?}",
            profile.build_kind
        )));
    }
    let custom_target_spec = options
        .custom_target_spec_path
        .as_ref()
        .map(|path| prepare_custom_target_spec(&options.workspace_root, path, &profile.target))
        .transpose()?;
    let compose_rustc = ComposeRustcSnapshot::capture(&options.rustc_path)?;
    fs::create_dir_all(&options.output_root)?;
    let staging = unique_staging(&options.output_root);
    fs::create_dir(&staging)?;
    let result = (|| {
        let target = if let Some(spec) = &custom_target_spec {
            materialize_custom_target_spec(staging.as_path(), spec)?;
            let target = Target::query_with_custom_spec(
                &options.rustc_path,
                profile.environment,
                &spec.record,
                &staging.join(&spec.record.snapshot_path),
            );
            compose_rustc.ensure_unchanged("rustc target-fact query")?;
            target?
        } else {
            let target = Target::query(&options.rustc_path, &profile.target, profile.environment);
            compose_rustc.ensure_unchanged("rustc target-fact query")?;
            target?
        };
        fs::create_dir_all(staging.join(".cargo"))?;
        let cargo_config = generate_cargo_config(
            &target,
            custom_target_spec.as_ref().map(|spec| &spec.record),
        );
        write_text(&staging.join(".cargo/config.toml"), &cargo_config)?;
        let cargo_target_input = custom_target_spec.as_ref().map_or_else(
            || PathBuf::from(&target.triple),
            |spec| staging.join(&spec.record.snapshot_path),
        );
        let custom_snapshot_before = custom_target_spec
            .as_ref()
            .map(|spec| {
                verify_custom_target_snapshot(
                    &spec.record,
                    &staging.join(&spec.record.snapshot_path),
                )
            })
            .transpose()?;
        let discovered = discover_workspace_catalog(
            &options.workspace_root,
            &options.cargo_path,
            &options.rustc_path,
            &staging,
            &cargo_target_input,
        );
        let cargo_config_after = (|| {
            verify_cargo_config_isolation(&staging, &staging.join(".cargo/config.toml"))?;
            read_composition_regular_file_bounded(
                &staging.join(".cargo/config.toml"),
                MAX_COMPOSITION_CONTROL_FILE_BYTES,
                None,
            )
        })();
        let custom_snapshot_after = custom_target_spec
            .as_ref()
            .map(|spec| {
                verify_custom_target_snapshot(
                    &spec.record,
                    &staging.join(&spec.record.snapshot_path),
                )
            })
            .transpose()?;
        if let (Some(before), Some(after)) = (&custom_snapshot_before, &custom_snapshot_after) {
            before.ensure_unchanged(after, "Cargo metadata discovery")?;
        }
        if cargo_config_after? != cargo_config.as_bytes() {
            return Err(ComposeError::Verification(
                "Cargo metadata discovery changed the generated Cargo config".into(),
            ));
        }
        compose_rustc.ensure_unchanged("Cargo metadata discovery")?;
        let DiscoveredCatalog {
            document,
            root_build_requirements,
        } = discovered?;
        validate_mandatory_root_build_requirements(&root_build_requirements)?;
        let catalog = NormalizedCatalog::normalize(document)?;
        let evidence_bytes = read_catalog_evidence(&options.workspace_root, &catalog)?;
        let catalog_trust_input =
            CatalogTrustInputCommitment::new(&catalog, &catalog_trust_policy, evidence_bytes)?;
        let generator_inputs =
            GeneratorInputCommitment::new(&catalog, catalog_trust_input, &root_build_requirements)?;
        let resolution = resolve(&catalog, &profile, &target)?;
        let package_inputs =
            selected_packages(&options.workspace_root, &catalog, &resolution, &target)?;
        let requires_registry = profile.build_kind == BuildKind::Wasm
            || package_inputs
                .iter()
                .any(|package| package.manifest.requires_registry);
        if requires_registry && options.registry_cache_path.is_none() {
            return Err(ComposeError::InvalidRegistryCache(
                "composition Cargo graph requires an explicit offline registry cache".into(),
            ));
        }
        let composition_catalog = CompositionCatalog {
            normalized: &catalog,
            generator_inputs: &generator_inputs,
        };
        compose_in_staging(
            &StagingCompositionInputs {
                options,
                composition_catalog: &composition_catalog,
                profile: &profile,
                target: &target,
                resolution: &resolution,
                package_inputs: &package_inputs,
                custom_target_spec: custom_target_spec.as_ref().map(|spec| &spec.record),
                compose_rustc: &compose_rustc,
            },
            &staging,
        )
    })();
    if result.is_err() {
        let _ = remove_staging_tree(&staging);
    }
    result
}

fn compose_in_staging(
    inputs: &StagingCompositionInputs<'_>,
    staging: &Path,
) -> Result<GeneratedComposition, ComposeError> {
    let &StagingCompositionInputs {
        options,
        composition_catalog,
        profile,
        target,
        resolution,
        package_inputs,
        custom_target_spec,
        compose_rustc,
    } = inputs;
    let catalog = composition_catalog.normalized;
    let generator_inputs = composition_catalog.generator_inputs;
    let target_facts = TargetFactsRecord::from_target(target)?;
    write_canonical_target_facts(&staging.join("target-facts.json"), &target_facts)?;
    write_json(
        &staging.join("compose-rustc.json"),
        compose_rustc.provenance(),
    )?;
    write_json(&staging.join("generator-inputs.json"), generator_inputs)?;

    let snapshot_plans =
        plan_composition_source_packages(&options.workspace_root, package_inputs, target)?;
    let source_root = staging.join("sources");
    fs::create_dir_all(&source_root)?;
    let mut sources = Vec::new();
    for (package, plan) in package_inputs.iter().zip(&snapshot_plans) {
        sources.push(snapshot_planned_package(
            &options.workspace_root,
            &source_root,
            package,
            target,
            plan,
        )?);
    }
    sources.sort_by(|left, right| left.id.cmp(&right.id));
    verify_selected_catalog_evidence(
        &source_root,
        resolution,
        &generator_inputs.catalog_trust_input,
    )?;

    fs::create_dir_all(staging.join("src"))?;
    fs::create_dir_all(staging.join(".cargo"))?;
    fs::create_dir_all(staging.join("vendor"))?;
    write_text(
        &staging.join("Cargo.toml"),
        &generate_cargo_toml(catalog, resolution, package_inputs, profile.build_kind),
    )?;
    write_text(
        &staging.join("src/lib.rs"),
        &generate_lib_rs(
            catalog,
            resolution,
            profile.build_kind,
            &generator_inputs.normalized_catalog_digest,
        )?,
    )?;
    if profile.build_kind == BuildKind::Wasm {
        write_text(
            &staging.join("src/wasm.rs"),
            &generate_wasm_rs(catalog, resolution)?,
        )?;
    }
    write_text(
        &staging.join("src/identity.rs"),
        "pub const COMPOSITION_HASH: &str = \"pending\";\n",
    )?;

    let lockfile = generate_lockfile(options, staging, custom_target_spec);
    compose_rustc.ensure_unchanged("Cargo lockfile generation")?;
    lockfile?;
    let (registries, git_sources) = locked_cargo_sources(&staging.join("Cargo.lock"))?;
    let cargo_resolution = CargoResolutionRecord {
        schema: 1,
        target: target.triple.clone(),
        cargo_target_input: custom_target_spec
            .map_or_else(|| target.triple.clone(), |spec| spec.snapshot_path.clone()),
        target_fact_digest: target.target_fact_digest.clone(),
        custom_target_spec_digest: custom_target_spec
            .map(|spec| spec.custom_target_spec_digest.clone()),
        resolver: "2".into(),
        offline: true,
        isolated_cargo_home: true,
        ancestor_config: "forbidden".into(),
        registries,
        git_sources,
    };
    write_json(&staging.join("cargo-resolution.json"), &cargo_resolution)?;
    let cargo_lock_digest = file_digest(&staging.join("Cargo.lock"))?;
    let mut generated_paths = vec![
        "Cargo.toml",
        "cargo-resolution.json",
        "compose-rustc.json",
        "generator-inputs.json",
        "target-facts.json",
        ".cargo/config.toml",
        "src/lib.rs",
    ];
    if profile.build_kind == BuildKind::Wasm {
        generated_paths.push("src/wasm.rs");
    }
    if let Some(spec) = custom_target_spec {
        generated_paths.push(&spec.snapshot_path);
    }
    let generated_files = generated_file_records(staging, &generated_paths)?;
    let direct_root_build_requirements = direct_root_build_requirements(
        catalog,
        resolution,
        &generator_inputs.root_build_requirements,
    )?;
    let build_requirements = build_requirement_union(&direct_root_build_requirements);
    let mut component_runtime_effects = BTreeSet::new();
    for id in &resolution.selected_components {
        component_runtime_effects.extend(catalog.components[id].security.iter().cloned());
    }
    let host_runtime_effects = resolution
        .host_boundary
        .as_ref()
        .map_or_else(BTreeSet::new, |id| {
            catalog.host_boundaries[id].security.clone()
        });
    let payload = CompositionIdentityPayload {
        schema: 1,
        profile,
        target,
        target_facts: &target_facts,
        compose_rustc: compose_rustc.provenance(),
        generator_inputs,
        custom_target_spec,
        resolution,
        component_runtime_effects: &component_runtime_effects,
        host_runtime_effects: &host_runtime_effects,
        direct_root_build_requirements: &direct_root_build_requirements,
        sources: &sources,
        generated_files: &generated_files,
        cargo_lock_digest: &cargo_lock_digest,
        cargo_resolution: &cargo_resolution,
    };
    let composition_hash = hex::encode(canonical::domain_hash(
        b"rust-agent-composition-v1\0",
        &payload,
    )?);
    write_text(
        &staging.join("src/identity.rs"),
        &format!("pub const COMPOSITION_HASH: &str = \"{composition_hash}\";\n"),
    )?;

    let cargo_resolution_digest = file_digest(&staging.join("cargo-resolution.json"))?;
    let manifest = CompositionManifest {
        schema: 1,
        algorithm: "sha256-rust-agent-composition-v1".into(),
        composition_hash: composition_hash.clone(),
        build_kind: profile.build_kind,
        profile: profile.name.clone(),
        normalized_profile: profile.clone(),
        target: target.triple.clone(),
        normalized_target: target.clone(),
        target_fact_digest: target.target_fact_digest.clone(),
        target_facts,
        compose_rustc: compose_rustc.provenance().clone(),
        generator_inputs: generator_inputs.clone(),
        custom_target_spec: custom_target_spec.cloned(),
        selected_components: resolution.selected_components.clone(),
        runtime_adapter: resolution.runtime_adapter.clone(),
        host_boundary: resolution.host_boundary.clone(),
        component_runtime_effects: component_runtime_effects.clone(),
        host_runtime_effects: host_runtime_effects.clone(),
        compiled_runtime_effects: resolution.compiled_runtime_effects.clone(),
        build_requirements: build_requirements.clone(),
        direct_root_build_requirements,
        app_handoff: resolution.app_handoff,
        deployable: false,
        resolution: resolution.clone(),
        sources,
        generated_files,
        cargo_lock_digest,
        cargo_resolution_digest,
        cargo_resolution,
    };
    write_json(&staging.join("rust-agent-composition.json"), &manifest)?;
    write_json(
        &staging.join("rust-agent-security.json"),
        &SecurityManifest {
            schema: 1,
            composition_hash: composition_hash.clone(),
            component_runtime_effects,
            host_runtime_effects,
            compiled_runtime_effects: resolution.compiled_runtime_effects.clone(),
            build_requirements,
        },
    )?;

    let final_path = options.output_root.join(&composition_hash);
    if final_path.exists() {
        return reuse_existing_composition(&final_path, staging, manifest);
    }
    if let Err(error) = publish_composition_noreplace(staging, &final_path) {
        if fs::symlink_metadata(&final_path).is_ok() {
            return reuse_existing_composition(&final_path, staging, manifest);
        }
        return Err(error.into());
    }
    finish_published_composition(&final_path, manifest)
}

fn finish_published_composition(
    final_path: &Path,
    manifest: CompositionManifest,
) -> Result<GeneratedComposition, ComposeError> {
    let published = verify_composition(final_path).map_err(|error| {
        ComposeError::ExistingCompositionCorrupt {
            path: final_path.display().to_string(),
            message: format!("post-publication verification failed: {error}"),
        }
    })?;
    if published != manifest {
        return Err(ComposeError::ExistingCompositionMismatch {
            path: final_path.display().to_string(),
            expected: manifest.composition_hash,
        });
    }
    Ok(GeneratedComposition {
        composition_hash: manifest.composition_hash.clone(),
        path: final_path.to_owned(),
        manifest,
    })
}

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos"
))]
fn publish_composition_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    renameat_with(CWD, source, CWD, destination, RenameFlags::NOREPLACE)
        .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))
}

#[cfg(windows)]
fn publish_composition_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    renamore::rename_exclusive(source, destination)
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    windows
)))]
fn publish_composition_noreplace(_source: &Path, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-clobber composition publication is unsupported on this Host",
    ))
}

fn reuse_existing_composition(
    final_path: &Path,
    staging: &Path,
    manifest: CompositionManifest,
) -> Result<GeneratedComposition, ComposeError> {
    let metadata = fs::symlink_metadata(final_path).map_err(|error| {
        ComposeError::ExistingCompositionCorrupt {
            path: final_path.display().to_string(),
            message: error.to_string(),
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ComposeError::ExistingCompositionCorrupt {
            path: final_path.display().to_string(),
            message: "final identity path is not a concrete directory".into(),
        });
    }
    let existing = verify_composition(final_path).map_err(|error| {
        ComposeError::ExistingCompositionCorrupt {
            path: final_path.display().to_string(),
            message: error.to_string(),
        }
    })?;
    if existing != manifest {
        return Err(ComposeError::ExistingCompositionMismatch {
            path: final_path.display().to_string(),
            expected: manifest.composition_hash,
        });
    }
    remove_staging_tree(staging)?;
    Ok(GeneratedComposition {
        composition_hash: manifest.composition_hash.clone(),
        path: final_path.to_owned(),
        manifest,
    })
}

fn direct_root_build_requirements(
    catalog: &NormalizedCatalog,
    resolution: &crate::resolver::Resolution,
    root_build_requirements: &BTreeMap<String, BuildRequirements>,
) -> Result<BTreeMap<String, crate::metadata::BuildRequirements>, ComposeError> {
    validate_mandatory_root_build_requirements(root_build_requirements)?;
    let mut roots = BTreeMap::new();
    for package in [
        "rust-agent-core",
        "rust-agent-runtime-api",
        "rust-agent-fixture-api",
    ] {
        let requirements = &root_build_requirements[package];
        roots.insert(format!("api:{package}"), requirements.clone());
    }
    for component in &resolution.selected_components {
        roots.insert(
            format!("component:{component}"),
            catalog.components[component].build_requirements.clone(),
        );
    }
    roots.insert(
        format!("runtime-adapter:{}", resolution.runtime_adapter),
        catalog.runtime_adapters[&resolution.runtime_adapter]
            .build_requirements
            .clone(),
    );
    if let Some(boundary) = &resolution.host_boundary {
        roots.insert(
            format!("host-boundary:{boundary}"),
            catalog.host_boundaries[boundary].build_requirements.clone(),
        );
    }
    Ok(roots)
}

fn validate_mandatory_root_build_requirements(
    root_build_requirements: &BTreeMap<String, BuildRequirements>,
) -> Result<(), ComposeError> {
    for package in [
        "rust-agent-core",
        "rust-agent-runtime-api",
        "rust-agent-fixture-api",
    ] {
        if !root_build_requirements.contains_key(package) {
            return Err(ComposeError::UnsupportedPhase1A(format!(
                "mandatory API package `{package}` is missing package-owned build requirements"
            )));
        }
    }
    Ok(())
}

fn build_requirement_union(
    direct_root_build_requirements: &BTreeMap<String, BuildRequirements>,
) -> BuildRequirements {
    let mut union = BuildRequirements::default();
    for requirements in direct_root_build_requirements.values() {
        union.merge_from(requirements);
    }
    union
}

fn read_catalog_evidence(
    workspace_root: &Path,
    catalog: &NormalizedCatalog,
) -> Result<BTreeMap<CatalogEvidenceOwner, Vec<u8>>, ComposeError> {
    let mut result = BTreeMap::new();
    let mut aggregate_bytes = 0_usize;
    for request in evidence_requests(catalog) {
        let path = workspace_root
            .join(&request.package_path)
            .join(&request.evidence.source);
        let bytes = read_workspace_input(workspace_root, &path, MAX_COEXISTENCE_EVIDENCE_BYTES)?;
        aggregate_bytes = aggregate_bytes.checked_add(bytes.len()).ok_or_else(|| {
            CatalogTrustError::InvalidEvidence("aggregate evidence byte count overflowed".into())
        })?;
        if aggregate_bytes > MAX_TOTAL_COEXISTENCE_EVIDENCE_BYTES {
            return Err(CatalogTrustError::InvalidEvidence(format!(
                "aggregate evidence exceeds {MAX_TOTAL_COEXISTENCE_EVIDENCE_BYTES} bytes"
            ))
            .into());
        }
        if result.insert(request.owner.clone(), bytes).is_some() {
            return Err(CatalogTrustError::InvalidEvidence(format!(
                "duplicate evidence owner {}:{}",
                match request.owner.kind {
                    EvidenceOwnerKind::Component => "component",
                    EvidenceOwnerKind::RuntimeAdapter => "runtime-adapter",
                },
                request.owner.id
            ))
            .into());
        }
    }
    Ok(result)
}

fn verify_selected_catalog_evidence(
    source_root: &Path,
    resolution: &crate::resolver::Resolution,
    trust: &CatalogTrustInputCommitment,
) -> Result<(), ComposeError> {
    for record in &trust.evidence {
        let selected = match record.owner_kind {
            EvidenceOwnerKind::Component => resolution
                .selected_components
                .binary_search(&record.owner)
                .is_ok(),
            EvidenceOwnerKind::RuntimeAdapter => record.owner == resolution.runtime_adapter,
        };
        if !selected {
            continue;
        }
        let expected = trust
            .evidence_bytes(record.owner_kind, &record.owner)?
            .ok_or_else(|| {
                CatalogTrustError::MissingEvidence(format!(
                    "selected {}:{}",
                    match record.owner_kind {
                        EvidenceOwnerKind::Component => "component",
                        EvidenceOwnerKind::RuntimeAdapter => "runtime-adapter",
                    },
                    record.owner
                ))
            })?;
        let path = source_root.join(&record.package_path).join(&record.source);
        let actual = read_composition_regular_file_bounded(
            &path,
            MAX_COEXISTENCE_EVIDENCE_BYTES as u64,
            Some(expected.len() as u64),
        )?;
        if actual != expected {
            return Err(ComposeError::Verification(format!(
                "selected coexistence evidence differs from its catalog trust commitment for {}:{}",
                match record.owner_kind {
                    EvidenceOwnerKind::Component => "component",
                    EvidenceOwnerKind::RuntimeAdapter => "runtime-adapter",
                },
                record.owner
            )));
        }
    }
    Ok(())
}

pub fn load_manifest(path: &Path) -> Result<CompositionManifest, ComposeError> {
    let manifest_path = path.join("rust-agent-composition.json");
    let bytes = read_composition_regular_file_bounded(
        &manifest_path,
        MAX_COMPOSITION_CONTROL_FILE_BYTES,
        None,
    )?;
    let manifest: CompositionManifest =
        serde_json::from_slice(&bytes).map_err(|error| ComposeError::ManifestNormalization {
            path: manifest_path.display().to_string(),
            message: error.to_string(),
        })?;
    let canonical = deterministic_json_bytes(&manifest).map_err(|error| {
        ComposeError::ManifestNormalization {
            path: manifest_path.display().to_string(),
            message: error.to_string(),
        }
    })?;
    if bytes != canonical {
        return Err(ComposeError::ManifestNormalization {
            path: manifest_path.display().to_string(),
            message: "manifest bytes are not the exact deterministic generator JSON encoding"
                .into(),
        });
    }
    let catalog = manifest.generator_inputs.catalog().map_err(|error| {
        ComposeError::ManifestNormalization {
            path: manifest_path.display().to_string(),
            message: format!("generator-input commitment is invalid: {error}"),
        }
    })?;
    let expected_resolution = resolve(
        &catalog,
        &manifest.normalized_profile,
        &manifest.normalized_target,
    )
    .map_err(|error| ComposeError::ManifestNormalization {
        path: manifest_path.display().to_string(),
        message: format!("committed resolver inputs cannot be resolved: {error}"),
    })?;
    if expected_resolution != manifest.resolution {
        return Err(ComposeError::ManifestNormalization {
            path: manifest_path.display().to_string(),
            message: "resolution differs from the committed normalized catalog inputs".into(),
        });
    }
    manifest
        .resolution
        .verify_canonical_semantics(&manifest.normalized_profile, &manifest.normalized_target)
        .map_err(|error| ComposeError::ManifestNormalization {
            path: manifest_path.display().to_string(),
            message: format!("resolution semantics are invalid: {error}"),
        })?;
    Ok(manifest)
}

fn deterministic_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(CanonicalError::Serialize)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Verifies a published content-addressed composition, including its hash basename.
pub fn verify_composition(path: &Path) -> Result<CompositionManifest, ComposeError> {
    verify_composition_with_location_policy(path, true)
}

/// Verifies an emitted integration copy whose destination name is integrator-owned.
pub fn verify_emitted_composition(path: &Path) -> Result<CompositionManifest, ComposeError> {
    verify_composition_with_location_policy(path, false)
}

fn verify_composition_with_location_policy(
    path: &Path,
    require_content_addressed_basename: bool,
) -> Result<CompositionManifest, ComposeError> {
    if !path.is_absolute() {
        return Err(ComposeError::Verification(format!(
            "composition path must be an absolute directory: {}",
            path.display()
        )));
    }
    let root_metadata = fs::symlink_metadata(path)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(ComposeError::Verification(format!(
            "composition path must be a concrete directory: {}",
            path.display()
        )));
    }
    let manifest = load_manifest(path)?;
    if require_content_addressed_basename
        && path.file_name().and_then(std::ffi::OsStr::to_str)
            != Some(manifest.composition_hash.as_str())
    {
        return Err(ComposeError::Verification(format!(
            "composition directory basename must equal its composition hash: {}",
            manifest.composition_hash
        )));
    }
    if manifest.schema != 1 || manifest.algorithm != "sha256-rust-agent-composition-v1" {
        return Err(ComposeError::Verification(
            "unknown manifest schema or algorithm".into(),
        ));
    }
    manifest.normalized_target.verify().map_err(|error| {
        ComposeError::Verification(format!("canonical target facts are invalid: {error}"))
    })?;
    let expected_target_facts = TargetFactsRecord::from_target(&manifest.normalized_target)
        .map_err(|error| {
            ComposeError::Verification(format!(
                "manifest target-facts projection is invalid: {error}"
            ))
        })?;
    let manifest_target_fact_digest = manifest.target_facts.semantic_digest().map_err(|error| {
        ComposeError::Verification(format!("manifest target-facts record is invalid: {error}"))
    })?;
    if manifest.normalized_profile.schema != 1
        || manifest.resolution.schema != 1
        || manifest.cargo_resolution.schema != 1
        || manifest.build_kind != manifest.normalized_profile.build_kind
        || manifest.profile != manifest.normalized_profile.name
        || manifest.target != manifest.normalized_target.triple
        || manifest.target_fact_digest != manifest.normalized_target.target_fact_digest
        || manifest.target_facts != expected_target_facts
        || manifest_target_fact_digest != manifest.target_fact_digest
        || manifest.normalized_target.custom_target_spec_digest
            != manifest
                .custom_target_spec
                .as_ref()
                .map(|spec| spec.custom_target_spec_digest.clone())
        || manifest
            .custom_target_spec
            .as_ref()
            .is_some_and(|spec| spec.logical_triple != manifest.target)
        || manifest.normalized_profile.target != manifest.target
        || manifest.normalized_profile.environment != manifest.normalized_target.environment
        || manifest.normalized_profile.runtime_adapter != manifest.runtime_adapter
        || manifest.normalized_profile.host_boundary != manifest.host_boundary
        || manifest.resolution.profile != manifest.profile
        || manifest.resolution.target != manifest.target
        || manifest.resolution.target_fact_digest != manifest.target_fact_digest
        || manifest.selected_components != manifest.resolution.selected_components
        || manifest.runtime_adapter != manifest.resolution.runtime_adapter
        || manifest.host_boundary != manifest.resolution.host_boundary
        || manifest.app_handoff != manifest.resolution.app_handoff
        || manifest.compiled_runtime_effects != manifest.resolution.compiled_runtime_effects
        || manifest.cargo_resolution.target != manifest.target
        || manifest.cargo_resolution.cargo_target_input
            != manifest.custom_target_spec.as_ref().map_or_else(
                || manifest.target.clone(),
                |spec| spec.snapshot_path.clone(),
            )
        || manifest.cargo_resolution.target_fact_digest != manifest.target_fact_digest
        || manifest.cargo_resolution.custom_target_spec_digest
            != manifest
                .custom_target_spec
                .as_ref()
                .map(|spec| spec.custom_target_spec_digest.clone())
        || manifest.cargo_resolution.resolver != "2"
        || !manifest.cargo_resolution.offline
        || !manifest.cargo_resolution.isolated_cargo_home
        || manifest.cargo_resolution.ancestor_config != "forbidden"
        || manifest.deployable
    {
        return Err(ComposeError::Verification(
            "manifest projection differs from normalized profile, target, or resolution".into(),
        ));
    }
    if !manifest
        .sources
        .windows(2)
        .all(|pair| pair[0].id < pair[1].id)
    {
        return Err(ComposeError::Verification(
            "source package records are not in strict canonical id order".into(),
        ));
    }
    preflight_composition_source_snapshots(path, &manifest.sources)?;
    if !manifest
        .generated_files
        .windows(2)
        .all(|pair| pair[0].path < pair[1].path)
    {
        return Err(ComposeError::Verification(
            "generated file records are not in strict canonical path order".into(),
        ));
    }
    let target_facts_bytes = read_composition_regular_file_bounded(
        &path.join("target-facts.json"),
        MAX_CANONICAL_TARGET_FACTS_RECORD_BYTES as u64,
        None,
    )?;
    let stored_target_facts =
        TargetFactsRecord::from_json(&target_facts_bytes).map_err(|error| {
            ComposeError::Verification(format!("target-facts.json is invalid: {error}"))
        })?;
    let canonical_target_facts =
        canonical_target_facts_bytes(&stored_target_facts).map_err(|error| {
            ComposeError::Verification(format!(
                "target-facts.json canonical encoding failed: {error}"
            ))
        })?;
    if target_facts_bytes != canonical_target_facts {
        return Err(ComposeError::Verification(
            "target-facts.json is not the exact RFC 8785 canonical encoding".into(),
        ));
    }
    if stored_target_facts != manifest.target_facts {
        return Err(ComposeError::Verification(
            "target-facts.json differs from the manifest target-facts record".into(),
        ));
    }
    manifest.compose_rustc.validate().map_err(|error| {
        ComposeError::Verification(format!("compose rustc provenance is invalid: {error}"))
    })?;
    let compose_rustc_bytes = read_composition_regular_file_bounded(
        &path.join("compose-rustc.json"),
        MAX_COMPOSITION_CONTROL_FILE_BYTES,
        None,
    )?;
    let stored_compose_rustc =
        serde_json::from_slice::<crate::toolchain::ComposeRustcProvenance>(&compose_rustc_bytes)
            .map_err(|error| {
                ComposeError::Verification(format!("compose-rustc.json is invalid: {error}"))
            })?;
    let expected_compose_rustc_bytes =
        deterministic_json_bytes(&manifest.compose_rustc).map_err(|error| {
            ComposeError::Verification(format!(
                "compose rustc provenance deterministic encoding failed: {error}"
            ))
        })?;
    if stored_compose_rustc != manifest.compose_rustc
        || compose_rustc_bytes != expected_compose_rustc_bytes
    {
        return Err(ComposeError::Verification(
            "compose-rustc.json drifted from its exact deterministic provenance".into(),
        ));
    }
    manifest.generator_inputs.validate().map_err(|error| {
        ComposeError::Verification(format!("generator-input commitment is invalid: {error}"))
    })?;
    let generator_input_bytes = read_composition_regular_file_bounded(
        &path.join("generator-inputs.json"),
        MAX_COMPOSITION_CONTROL_FILE_BYTES,
        None,
    )?;
    let stored_generator_inputs = serde_json::from_slice::<GeneratorInputCommitment>(
        &generator_input_bytes,
    )
    .map_err(|error| {
        ComposeError::Verification(format!("generator-inputs.json is invalid: {error}"))
    })?;
    let expected_generator_input_bytes = deterministic_json_bytes(&manifest.generator_inputs)
        .map_err(|error| {
            ComposeError::Verification(format!(
                "generator-input commitment deterministic encoding failed: {error}"
            ))
        })?;
    if stored_generator_inputs != manifest.generator_inputs
        || generator_input_bytes != expected_generator_input_bytes
    {
        return Err(ComposeError::Verification(
            "generator-inputs.json drifted from its exact deterministic commitment".into(),
        ));
    }
    let committed_catalog = manifest.generator_inputs.catalog().map_err(|error| {
        ComposeError::Verification(format!("generator-input commitment is invalid: {error}"))
    })?;
    let rederived_resolution = resolve(
        &committed_catalog,
        &manifest.normalized_profile,
        &manifest.normalized_target,
    )
    .map_err(|error| {
        ComposeError::Verification(format!(
            "committed resolver inputs cannot be resolved: {error}"
        ))
    })?;
    if rederived_resolution != manifest.resolution {
        return Err(ComposeError::Verification(
            "resolution differs from the committed normalized catalog inputs".into(),
        ));
    }
    let mut component_runtime_effects = BTreeSet::new();
    for component in &rederived_resolution.selected_components {
        component_runtime_effects.extend(
            committed_catalog.components[component]
                .security
                .iter()
                .cloned(),
        );
    }
    let host_runtime_effects = rederived_resolution
        .host_boundary
        .as_ref()
        .map_or_else(BTreeSet::new, |boundary| {
            committed_catalog.host_boundaries[boundary].security.clone()
        });
    if component_runtime_effects != manifest.component_runtime_effects
        || host_runtime_effects != manifest.host_runtime_effects
    {
        return Err(ComposeError::Verification(
            "Component or Host runtime effects attribution differs from the committed catalog"
                .into(),
        ));
    }
    let mut runtime_effect_union = component_runtime_effects;
    runtime_effect_union.extend(host_runtime_effects);
    if runtime_effect_union != rederived_resolution.compiled_runtime_effects
        || runtime_effect_union != manifest.compiled_runtime_effects
    {
        return Err(ComposeError::Verification(
            "Component and Host runtime effects do not equal the compiled runtime-effect union"
                .into(),
        ));
    }
    let expected_direct_root_build_requirements = direct_root_build_requirements(
        &committed_catalog,
        &rederived_resolution,
        &manifest.generator_inputs.root_build_requirements,
    )
    .map_err(|error| {
        ComposeError::Verification(format!(
            "direct root build-requirement attribution cannot be rederived: {error}"
        ))
    })?;
    if expected_direct_root_build_requirements != manifest.direct_root_build_requirements {
        return Err(ComposeError::Verification(
            "direct root build requirements differ from the committed generator inputs".into(),
        ));
    }
    let mut expected_roots = BTreeSet::from([
        "api:rust-agent-core".to_owned(),
        "api:rust-agent-runtime-api".to_owned(),
        "api:rust-agent-fixture-api".to_owned(),
        format!("runtime-adapter:{}", manifest.runtime_adapter),
    ]);
    expected_roots.extend(
        manifest
            .selected_components
            .iter()
            .map(|component| format!("component:{component}")),
    );
    if let Some(boundary) = &manifest.host_boundary {
        expected_roots.insert(format!("host-boundary:{boundary}"));
    }
    if manifest
        .direct_root_build_requirements
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected_roots
    {
        return Err(ComposeError::Verification(
            "direct root build-requirement keys differ from the resolved Cargo roots".into(),
        ));
    }
    let mut resolution_requirement_union = BuildRequirements::default();
    for (root, requirements) in &manifest.direct_root_build_requirements {
        if !root.starts_with("api:") {
            resolution_requirement_union.merge_from(requirements);
        }
    }
    if resolution_requirement_union != manifest.resolution.build_requirements {
        return Err(ComposeError::Verification(
            "resolved Component/runtime/Host build requirements differ from their direct roots"
                .into(),
        ));
    }
    let requirement_union = build_requirement_union(&manifest.direct_root_build_requirements);
    if requirement_union != manifest.build_requirements {
        return Err(ComposeError::Verification(
            "direct root build requirements do not equal the authorized union".into(),
        ));
    }

    let package_inputs = selected_packages(
        &path.join("sources"),
        &committed_catalog,
        &rederived_resolution,
        &manifest.normalized_target,
    )?;
    for package in &package_inputs {
        let snapshot_manifest = path.join("sources").join(&package.path).join("Cargo.toml");
        let bytes = read_composition_regular_file_bounded(
            &snapshot_manifest,
            MAX_SOURCE_MANIFEST_BYTES,
            None,
        )?;
        if bytes != package.manifest.bytes {
            return Err(ComposeError::Verification(format!(
                "source manifest `{}` is not the exact target-fact-derived normalized manifest",
                package.path
            )));
        }
    }
    let mut expected_source_headers = package_inputs
        .iter()
        .map(|package| {
            (
                package.id.clone(),
                package.package.clone(),
                package.path.clone(),
            )
        })
        .collect::<Vec<_>>();
    expected_source_headers.sort();
    let actual_source_headers = manifest
        .sources
        .iter()
        .map(|package| {
            (
                package.id.clone(),
                package.package.clone(),
                package.logical_path.clone(),
            )
        })
        .collect::<Vec<_>>();
    if actual_source_headers != expected_source_headers {
        return Err(ComposeError::Verification(
            "source package closure differs from the committed catalog and resolution".into(),
        ));
    }
    verify_selected_catalog_evidence(
        &path.join("sources"),
        &rederived_resolution,
        &manifest.generator_inputs.catalog_trust_input,
    )?;

    let mut expected_tree = BTreeMap::new();
    for directory in [".cargo", "sources", "src", "vendor"] {
        insert_expected_composition_entry(
            &mut expected_tree,
            directory,
            CompositionTreeEntryKind::Directory,
        )?;
    }
    if manifest.custom_target_spec.is_some() {
        insert_expected_composition_entry(
            &mut expected_tree,
            "targets",
            CompositionTreeEntryKind::Directory,
        )?;
    }
    for file in [
        "Cargo.lock",
        "rust-agent-composition.json",
        "rust-agent-security.json",
        "src/identity.rs",
    ] {
        insert_expected_composition_entry(
            &mut expected_tree,
            file,
            CompositionTreeEntryKind::RegularFile,
        )?;
    }

    let expected_generated_paths =
        expected_generated_file_paths(manifest.build_kind, manifest.custom_target_spec.as_ref());
    let actual_generated_paths = manifest
        .generated_files
        .iter()
        .map(|file| file.path.clone())
        .collect::<BTreeSet<_>>();
    if actual_generated_paths.len() != manifest.generated_files.len()
        || actual_generated_paths != expected_generated_paths
    {
        return Err(ComposeError::Verification(
            "generated file records are duplicate, missing, or unexpected".into(),
        ));
    }
    for file in &manifest.generated_files {
        validate_composition_relative_path(&file.path)?;
        if file.bytes > MAX_COMPOSITION_CONTROL_FILE_BYTES || !is_sha256_hex(&file.digest) {
            return Err(ComposeError::Verification(format!(
                "generated file record `{}` exceeds bounds or has an invalid digest",
                file.path
            )));
        }
        insert_expected_composition_entry(
            &mut expected_tree,
            &file.path,
            CompositionTreeEntryKind::RegularFile,
        )?;
    }

    let mut source_ids = BTreeSet::new();
    let mut source_paths = BTreeSet::new();
    for package in &manifest.sources {
        validate_composition_relative_path(&package.logical_path)?;
        if !source_ids.insert(package.id.clone())
            || !source_paths.insert(package.logical_path.clone())
        {
            return Err(ComposeError::Verification(
                "source package ids and logical paths must be unique".into(),
            ));
        }
        let expected_snapshot = CanonicalSnapshotTree::from_entries(package.tree_entries.clone())?;
        if expected_snapshot.entries() != package.tree_entries.as_slice()
            || expected_snapshot.digest() != package.tree_digest
        {
            return Err(ComposeError::Verification(format!(
                "source snapshot manifest `{}` is not canonical",
                package.logical_path
            )));
        }
        let package_root = format!("sources/{}", package.logical_path);
        insert_expected_composition_entry(
            &mut expected_tree,
            &package_root,
            CompositionTreeEntryKind::Directory,
        )?;
        for entry in &package.tree_entries {
            let path = format!("{package_root}/{}", entry.path);
            let kind = match &entry.kind {
                CanonicalSnapshotEntryKind::Directory => CompositionTreeEntryKind::Directory,
                CanonicalSnapshotEntryKind::RegularFile { .. } => {
                    CompositionTreeEntryKind::RegularFile
                }
            };
            insert_expected_composition_entry(&mut expected_tree, &path, kind)?;
        }
    }
    verify_composition_tree_topology(path, &expected_tree)?;

    let mut rederived_generated_sources = vec![
        (
            "Cargo.toml",
            generate_cargo_toml(
                &committed_catalog,
                &rederived_resolution,
                &package_inputs,
                manifest.build_kind,
            ),
        ),
        (
            "src/lib.rs",
            generate_lib_rs(
                &committed_catalog,
                &rederived_resolution,
                manifest.build_kind,
                &manifest.generator_inputs.normalized_catalog_digest,
            )?,
        ),
    ];
    if manifest.build_kind == BuildKind::Wasm {
        rederived_generated_sources.push((
            "src/wasm.rs",
            generate_wasm_rs(&committed_catalog, &rederived_resolution)?,
        ));
    }
    for (relative_path, expected) in rederived_generated_sources {
        if read_composition_regular_file_bounded(
            &path.join(relative_path),
            MAX_COMPOSITION_CONTROL_FILE_BYTES,
            None,
        )? != expected.as_bytes()
        {
            return Err(ComposeError::Verification(format!(
                "generated `{relative_path}` differs from the committed catalog and resolution"
            )));
        }
    }

    let cargo_resolution_bytes = read_composition_regular_file_bounded(
        &path.join("cargo-resolution.json"),
        MAX_COMPOSITION_CONTROL_FILE_BYTES,
        None,
    )?;
    let cargo_resolution: CargoResolutionRecord =
        match serde_json::from_slice(&cargo_resolution_bytes) {
            Ok(record) => record,
            Err(error) => {
                return Err(ComposeError::Verification(format!(
                    "invalid cargo-resolution.json: {error}"
                )));
            }
        };
    let expected_cargo_resolution_bytes = deterministic_json_bytes(&manifest.cargo_resolution)
        .map_err(|error| {
            ComposeError::Verification(format!(
                "Cargo resolution deterministic encoding failed: {error}"
            ))
        })?;
    if cargo_resolution_bytes != expected_cargo_resolution_bytes {
        return Err(ComposeError::Verification(
            "Cargo resolution record drifted from its exact deterministic encoding".into(),
        ));
    }
    if cargo_resolution != manifest.cargo_resolution
        || sha256_hex(&cargo_resolution_bytes) != manifest.cargo_resolution_digest
    {
        return Err(ComposeError::Verification(
            "Cargo resolution record drifted".into(),
        ));
    }
    let expected_cargo_config = generate_cargo_config(
        &manifest.normalized_target,
        manifest.custom_target_spec.as_ref(),
    );
    if read_composition_regular_file_bounded(
        &path.join(".cargo/config.toml"),
        MAX_COMPOSITION_CONTROL_FILE_BYTES,
        Some(expected_cargo_config.len() as u64),
    )? != expected_cargo_config.as_bytes()
    {
        return Err(ComposeError::Verification(
            "generated Cargo config differs from the canonical target input".into(),
        ));
    }
    if let Some(spec) = &manifest.custom_target_spec {
        let bytes = read_composition_regular_file_bounded(
            &path.join(&spec.snapshot_path),
            MAX_CUSTOM_TARGET_SPEC_BYTES,
            None,
        )?;
        spec.verify(&bytes).map_err(|error| {
            ComposeError::Verification(format!("custom target spec snapshot is invalid: {error}"))
        })?;
    }
    let cargo_lock_path = path.join("Cargo.lock");
    let cargo_lock_bytes = read_composition_regular_file_bounded(
        &cargo_lock_path,
        MAX_COMPOSITION_CONTROL_FILE_BYTES,
        None,
    )?;
    if sha256_hex(&cargo_lock_bytes) != manifest.cargo_lock_digest {
        return Err(ComposeError::Verification("Cargo.lock drifted".into()));
    }
    let (locked_registries, locked_git_sources) =
        locked_cargo_sources_from_bytes(&cargo_lock_path, &cargo_lock_bytes)?;
    if locked_registries != manifest.cargo_resolution.registries
        || locked_git_sources != manifest.cargo_resolution.git_sources
    {
        return Err(ComposeError::Verification(
            "Cargo resolution source projection differs from Cargo.lock".into(),
        ));
    }
    for file in &manifest.generated_files {
        let file_path = path.join(&file.path);
        let (digest, bytes) = hash_composition_regular_file_bounded(
            &file_path,
            MAX_COMPOSITION_CONTROL_FILE_BYTES,
            Some(file.bytes),
        )?;
        if bytes != file.bytes || digest != file.digest {
            return Err(ComposeError::Verification(format!(
                "generated file `{}` drifted",
                file.path
            )));
        }
    }
    for package in &manifest.sources {
        let root = path.join("sources").join(&package.logical_path);
        let actual = source_snapshot_tree(&root)?;
        if actual.entries() != package.tree_entries {
            return Err(ComposeError::Verification(format!(
                "source snapshot `{}` drifted",
                package.logical_path
            )));
        }
        if actual.digest() != package.tree_digest {
            return Err(ComposeError::Verification(format!(
                "source snapshot digest `{}` drifted",
                package.logical_path
            )));
        }
    }
    let payload = CompositionIdentityPayload {
        schema: 1,
        profile: &manifest.normalized_profile,
        target: &manifest.normalized_target,
        target_facts: &manifest.target_facts,
        compose_rustc: &manifest.compose_rustc,
        generator_inputs: &manifest.generator_inputs,
        custom_target_spec: manifest.custom_target_spec.as_ref(),
        resolution: &manifest.resolution,
        component_runtime_effects: &manifest.component_runtime_effects,
        host_runtime_effects: &manifest.host_runtime_effects,
        direct_root_build_requirements: &manifest.direct_root_build_requirements,
        sources: &manifest.sources,
        generated_files: &manifest.generated_files,
        cargo_lock_digest: &manifest.cargo_lock_digest,
        cargo_resolution: &manifest.cargo_resolution,
    };
    let expected = hex::encode(canonical::domain_hash(
        b"rust-agent-composition-v1\0",
        &payload,
    )?);
    if expected != manifest.composition_hash {
        return Err(ComposeError::Verification(format!(
            "composition identity mismatch: expected {expected}"
        )));
    }
    let identity_source = format!(
        "pub const COMPOSITION_HASH: &str = \"{}\";\n",
        manifest.composition_hash
    );
    if read_composition_regular_file_bounded(
        &path.join("src/identity.rs"),
        MAX_COMPOSITION_CONTROL_FILE_BYTES,
        Some(identity_source.len() as u64),
    )? != identity_source.as_bytes()
    {
        return Err(ComposeError::Verification(
            "derived identity source drifted".into(),
        ));
    }
    let security_bytes = read_composition_regular_file_bounded(
        &path.join("rust-agent-security.json"),
        MAX_COMPOSITION_CONTROL_FILE_BYTES,
        None,
    )?;
    let security: SecurityManifest = serde_json::from_slice(&security_bytes).map_err(|error| {
        ComposeError::Verification(format!("invalid security manifest: {error}"))
    })?;
    let expected_security = SecurityManifest {
        schema: 1,
        composition_hash: manifest.composition_hash.clone(),
        component_runtime_effects: manifest.component_runtime_effects.clone(),
        host_runtime_effects: manifest.host_runtime_effects.clone(),
        compiled_runtime_effects: manifest.compiled_runtime_effects.clone(),
        build_requirements: manifest.build_requirements.clone(),
    };
    let expected_security_bytes =
        deterministic_json_bytes(&expected_security).map_err(|error| {
            ComposeError::Verification(format!(
                "security manifest deterministic encoding failed: {error}"
            ))
        })?;
    if security != expected_security || security_bytes != expected_security_bytes {
        return Err(ComposeError::Verification(
            "security manifest drifted from its exact deterministic derived encoding".into(),
        ));
    }
    Ok(manifest)
}

fn expected_generated_file_paths(
    build_kind: BuildKind,
    custom_target_spec: Option<&CustomTargetSpecRecord>,
) -> BTreeSet<String> {
    let mut paths = BTreeSet::from([
        ".cargo/config.toml".into(),
        "Cargo.toml".into(),
        "cargo-resolution.json".into(),
        "compose-rustc.json".into(),
        "generator-inputs.json".into(),
        "target-facts.json".into(),
        "src/lib.rs".into(),
    ]);
    if build_kind == BuildKind::Wasm {
        paths.insert("src/wasm.rs".into());
    }
    if let Some(spec) = custom_target_spec {
        paths.insert(spec.snapshot_path.clone());
    }
    paths
}

fn validate_composition_relative_path(path: &str) -> Result<(), ComposeError> {
    let candidate = Path::new(path);
    if path.is_empty()
        || path.contains('\\')
        || candidate.is_absolute()
        || !candidate
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err(ComposeError::Verification(format!(
            "invalid composition-relative path `{path}`"
        )));
    }
    Ok(())
}

fn insert_expected_composition_entry(
    entries: &mut BTreeMap<String, CompositionTreeEntryKind>,
    path: &str,
    kind: CompositionTreeEntryKind,
) -> Result<(), ComposeError> {
    validate_composition_relative_path(path)?;
    let mut offset = 0;
    while let Some(index) = path[offset..].find('/') {
        let end = offset + index;
        let parent = &path[..end];
        match entries.insert(parent.to_owned(), CompositionTreeEntryKind::Directory) {
            Some(CompositionTreeEntryKind::RegularFile) => {
                return Err(ComposeError::Verification(format!(
                    "composition path `{path}` has regular-file parent `{parent}`"
                )));
            }
            Some(CompositionTreeEntryKind::Directory) | None => {}
        }
        offset = end + 1;
    }
    match entries.insert(path.to_owned(), kind) {
        Some(previous) if previous != kind => Err(ComposeError::Verification(format!(
            "composition path `{path}` has conflicting entry kinds"
        ))),
        Some(_) | None => Ok(()),
    }
}

fn verify_composition_tree_topology(
    root: &Path,
    expected: &BTreeMap<String, CompositionTreeEntryKind>,
) -> Result<(), ComposeError> {
    let mut seen = BTreeSet::new();
    for entry in WalkDir::new(root).sort_by_file_name().into_iter().skip(1) {
        let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err(ComposeError::UnsupportedSourceEntry(
                entry.path().display().to_string(),
            ));
        }
        let kind = if metadata.is_file() {
            CompositionTreeEntryKind::RegularFile
        } else if metadata.is_dir() {
            CompositionTreeEntryKind::Directory
        } else {
            return Err(ComposeError::UnsupportedSourceEntry(
                entry.path().display().to_string(),
            ));
        };
        let relative = entry
            .path()
            .strip_prefix(root)
            .expect("walked path is below composition root")
            .to_str()
            .ok_or_else(|| {
                ComposeError::UnsupportedSourceEntry(entry.path().display().to_string())
            })?
            .replace('\\', "/");
        if expected.get(&relative) != Some(&kind) {
            return Err(ComposeError::Verification(format!(
                "composition tree contains unexpected or mistyped entry `{relative}`"
            )));
        }
        seen.insert(relative);
    }
    if seen.len() != expected.len() {
        let missing = expected
            .keys()
            .filter(|path| !seen.contains(*path))
            .take(16)
            .cloned()
            .collect::<Vec<_>>();
        return Err(ComposeError::Verification(format!(
            "composition tree is missing expected entries {missing:?}"
        )));
    }
    Ok(())
}

#[derive(Debug)]
struct SourceSnapshotVerificationEntry {
    path: PathBuf,
    relative: String,
    bytes: Option<u64>,
}

fn source_snapshot_tree(root: &Path) -> Result<CanonicalSnapshotTree, ComposeError> {
    let (plan, _) = plan_source_snapshot_verification(root)?;
    let mut entries = Vec::with_capacity(plan.len());
    for entry in plan {
        let directory = entry.bytes.is_none();
        verify_source_snapshot_storage_projection(&entry.path, directory)?;
        if let Some(expected_bytes) = entry.bytes {
            let (digest, bytes) = hash_snapshot_file(&entry.path, expected_bytes)?;
            entries.push(CanonicalSnapshotEntry::regular_file(
                entry.relative,
                digest,
                bytes,
            ));
        } else {
            entries.push(CanonicalSnapshotEntry::directory(entry.relative));
        }
    }
    verify_source_snapshot_storage_projection(root, true)?;
    Ok(CanonicalSnapshotTree::from_entries(entries)?)
}

fn plan_source_snapshot_verification(
    root: &Path,
) -> Result<(Vec<SourceSnapshotVerificationEntry>, u64), ComposeError> {
    let root_metadata = fs::symlink_metadata(root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(ComposeError::Verification(format!(
            "missing source root {}",
            root.display()
        )));
    }
    verify_source_snapshot_storage_projection(root, true)?;
    let mut plan = Vec::new();
    let mut total_file_bytes = 0_u64;
    for entry in WalkDir::new(root).sort_by_file_name().into_iter().skip(1) {
        let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
        if plan.len() == MAX_CANONICAL_SNAPSHOT_ENTRIES {
            return Err(CanonicalSnapshotError::TooManyEntries {
                actual: plan.len() + 1,
                maximum: MAX_CANONICAL_SNAPSHOT_ENTRIES,
            }
            .into());
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err(ComposeError::UnsupportedSourceEntry(
                entry.path().display().to_string(),
            ));
        }
        if !metadata.is_file() && !metadata.is_dir() {
            return Err(ComposeError::UnsupportedSourceEntry(
                entry.path().display().to_string(),
            ));
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .expect("walked path is below source root")
            .to_str()
            .ok_or_else(|| {
                ComposeError::UnsupportedSourceEntry(entry.path().display().to_string())
            })?
            .replace('\\', "/");
        verify_source_snapshot_storage_projection(entry.path(), metadata.is_dir())?;
        let bytes = if metadata.is_dir() {
            None
        } else {
            account_snapshot_file_bytes(&relative, metadata.len(), &mut total_file_bytes)?;
            Some(metadata.len())
        };
        plan.push(SourceSnapshotVerificationEntry {
            path: entry.path().to_owned(),
            relative,
            bytes,
        });
    }
    Ok((plan, total_file_bytes))
}

fn preflight_composition_source_snapshots(
    composition: &Path,
    sources: &[SourcePackageRecord],
) -> Result<(), ComposeError> {
    let mut usage = CompositionSourceUsage::default();
    for source in sources {
        validate_composition_relative_path(&source.logical_path)?;
        let root = composition.join("sources").join(&source.logical_path);
        let (plan, package_bytes) = plan_source_snapshot_verification(&root)?;
        usage.account(plan.len(), package_bytes)?;
    }
    Ok(())
}

#[derive(Debug, Default)]
struct CompositionSourceUsage {
    entries: usize,
    file_bytes: u64,
}

impl CompositionSourceUsage {
    fn account(&mut self, entries: usize, file_bytes: u64) -> Result<(), ComposeError> {
        self.entries =
            self.entries
                .checked_add(entries)
                .ok_or(CanonicalSnapshotError::TooManyEntries {
                    actual: usize::MAX,
                    maximum: MAX_COMPOSITION_SOURCE_ENTRIES,
                })?;
        if self.entries > MAX_COMPOSITION_SOURCE_ENTRIES {
            return Err(CanonicalSnapshotError::TooManyEntries {
                actual: self.entries,
                maximum: MAX_COMPOSITION_SOURCE_ENTRIES,
            }
            .into());
        }
        self.file_bytes = self.file_bytes.checked_add(file_bytes).ok_or(
            CanonicalSnapshotError::TotalBytesTooLarge {
                actual: u64::MAX,
                maximum: MAX_COMPOSITION_SOURCE_FILE_BYTES,
            },
        )?;
        if self.file_bytes > MAX_COMPOSITION_SOURCE_FILE_BYTES {
            return Err(CanonicalSnapshotError::TotalBytesTooLarge {
                actual: self.file_bytes,
                maximum: MAX_COMPOSITION_SOURCE_FILE_BYTES,
            }
            .into());
        }
        Ok(())
    }
}

fn hash_snapshot_file(path: &Path, expected_bytes: u64) -> Result<(String, u64), ComposeError> {
    if expected_bytes > MAX_CANONICAL_SNAPSHOT_FILE_BYTES {
        return Err(CanonicalSnapshotError::FileTooLarge {
            path: path.display().to_string(),
            actual: expected_bytes,
            maximum: MAX_CANONICAL_SNAPSHOT_FILE_BYTES,
        }
        .into());
    }
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() != expected_bytes {
        return Err(ComposeError::UnsupportedSourceEntry(
            path.display().to_string(),
        ));
    }
    let file = File::open(path)?;
    let handle_before = file.metadata()?;
    if !handle_before.is_file()
        || handle_before.len() != before.len()
        || handle_before.modified()? != before.modified()?
    {
        return Err(ComposeError::Verification(format!(
            "source snapshot file `{}` changed before hashing",
            path.display()
        )));
    }
    let mut reader = BufReader::new(file).take(MAX_CANONICAL_SNAPSHOT_FILE_BYTES + 1);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut bytes = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes = bytes.checked_add(read as u64).ok_or_else(|| {
            ComposeError::Verification(format!(
                "source snapshot file `{}` exceeds schema bounds",
                path.display()
            ))
        })?;
        hasher.update(&buffer[..read]);
    }
    let file = reader.into_inner().into_inner();
    let handle_after = file.metadata()?;
    let path_after = fs::symlink_metadata(path)?;
    if bytes != expected_bytes
        || handle_after.len() != before.len()
        || handle_after.modified()? != before.modified()?
        || path_after.file_type().is_symlink()
        || !path_after.is_file()
        || path_after.len() != before.len()
        || path_after.modified()? != before.modified()?
    {
        return Err(ComposeError::Verification(format!(
            "source snapshot file `{}` changed while hashing",
            path.display()
        )));
    }
    Ok((hex::encode(hasher.finalize()), bytes))
}

fn seal_source_snapshot_storage_projection(root: &Path) -> Result<(), ComposeError> {
    let mut directories = Vec::new();
    for entry in WalkDir::new(root).sort_by_file_name() {
        let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
            return Err(ComposeError::UnsupportedSourceEntry(
                entry.path().display().to_string(),
            ));
        }
        if metadata.is_dir() {
            directories.push(entry.path().to_owned());
        } else {
            set_snapshot_epoch(entry.path())?;
            set_snapshot_permissions(entry.path(), false)?;
        }
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        set_snapshot_epoch(&directory)?;
        set_snapshot_permissions(&directory, true)?;
    }
    Ok(())
}

fn set_snapshot_epoch(path: &Path) -> io::Result<()> {
    open_metadata_handle(path)?.set_times(
        FileTimes::new()
            .set_accessed(SystemTime::UNIX_EPOCH)
            .set_modified(SystemTime::UNIX_EPOCH),
    )
}

#[cfg(windows)]
fn open_metadata_handle(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

    File::options()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

#[cfg(not(windows))]
fn open_metadata_handle(path: &Path) -> io::Result<File> {
    File::open(path)
}

#[cfg(unix)]
fn set_snapshot_permissions(path: &Path, directory: bool) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = if directory { 0o555 } else { 0o444 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_snapshot_permissions(path: &Path, _directory: bool) -> io::Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)
}

fn verify_source_snapshot_storage_projection(
    path: &Path,
    directory: bool,
) -> Result<(), ComposeError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || metadata.is_dir() != directory
        || metadata.modified()? != SystemTime::UNIX_EPOCH
    {
        return Err(ComposeError::Verification(format!(
            "source snapshot metadata drifted at `{}`",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let expected = if directory { 0o555 } else { 0o444 };
        if metadata.permissions().mode() & 0o7777 != expected {
            return Err(ComposeError::Verification(format!(
                "source snapshot metadata drifted at `{}`",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    if !metadata.permissions().readonly() {
        return Err(ComposeError::Verification(format!(
            "source snapshot metadata drifted at `{}`",
            path.display()
        )));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct PackageInput {
    id: String,
    package: String,
    path: String,
    direct: bool,
    manifest: NormalizedPackageManifest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NormalizedPackageManifest {
    bytes: Vec<u8>,
    package: String,
    path_dependencies: Vec<PathDependency>,
    requires_registry: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PathDependency {
    alias: String,
    package: String,
    logical_path: String,
}

#[derive(Clone, Debug)]
struct PreparedCustomTargetSpec {
    record: CustomTargetSpecRecord,
    bytes: Vec<u8>,
}

struct CompositionCatalog<'a> {
    normalized: &'a NormalizedCatalog,
    generator_inputs: &'a GeneratorInputCommitment,
}

struct StagingCompositionInputs<'a> {
    options: &'a ComposeOptions,
    composition_catalog: &'a CompositionCatalog<'a>,
    profile: &'a CompositionProfile,
    target: &'a Target,
    resolution: &'a crate::resolver::Resolution,
    package_inputs: &'a [PackageInput],
    custom_target_spec: Option<&'a CustomTargetSpecRecord>,
    compose_rustc: &'a ComposeRustcSnapshot,
}

fn prepare_custom_target_spec(
    workspace_root: &Path,
    path: &Path,
    logical_triple: &str,
) -> Result<PreparedCustomTargetSpec, ComposeError> {
    let canonical_workspace = workspace_root.canonicalize()?;
    let relative = path
        .strip_prefix(&canonical_workspace)
        .map_err(|_| ComposeError::InputOutsideWorkspace(path.display().to_string()))?;
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err(ComposeError::InputOutsideWorkspace(
            path.display().to_string(),
        ));
    }
    let mut current = canonical_workspace.clone();
    for component in relative.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            return Err(ComposeError::UnsupportedSourceEntry(
                current.display().to_string(),
            ));
        }
    }
    let canonical_path = path.canonicalize()?;
    if !canonical_path.starts_with(&canonical_workspace) {
        return Err(ComposeError::InputOutsideWorkspace(
            path.display().to_string(),
        ));
    }
    let before = fs::symlink_metadata(&canonical_path)?;
    if !before.is_file() || before.len() > MAX_CUSTOM_TARGET_SPEC_BYTES {
        if before.len() > MAX_CUSTOM_TARGET_SPEC_BYTES {
            return Err(CustomTargetSpecError::TooLarge {
                actual: before.len(),
                maximum: MAX_CUSTOM_TARGET_SPEC_BYTES,
            }
            .into());
        }
        return Err(ComposeError::UnsupportedSourceEntry(
            canonical_path.display().to_string(),
        ));
    }
    let file = File::open(&canonical_path)?;
    let handle_before = file.metadata()?;
    if !handle_before.is_file()
        || handle_before.len() != before.len()
        || handle_before.modified()? != before.modified()?
    {
        return Err(ComposeError::Verification(format!(
            "custom target spec `{}` changed before reading",
            canonical_path.display()
        )));
    }
    let mut reader = BufReader::new(file).take(MAX_CUSTOM_TARGET_SPEC_BYTES + 1);
    let capacity = usize::try_from(before.len()).map_err(|_| CustomTargetSpecError::TooLarge {
        actual: before.len(),
        maximum: MAX_CUSTOM_TARGET_SPEC_BYTES,
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    reader.read_to_end(&mut bytes)?;
    let file = reader.into_inner().into_inner();
    let handle_after = file.metadata()?;
    let path_after = fs::symlink_metadata(&canonical_path)?;
    if bytes.len() as u64 != before.len()
        || handle_after.len() != before.len()
        || handle_after.modified()? != before.modified()?
        || path_after.file_type().is_symlink()
        || !path_after.is_file()
        || path_after.len() != before.len()
        || path_after.modified()? != before.modified()?
    {
        return Err(ComposeError::Verification(format!(
            "custom target spec `{}` changed or exceeded its bound while reading",
            canonical_path.display()
        )));
    }
    let record = CustomTargetSpecRecord::from_raw_bytes(logical_triple, &bytes)?;
    Ok(PreparedCustomTargetSpec { record, bytes })
}

fn materialize_custom_target_spec(
    staging: &Path,
    spec: &PreparedCustomTargetSpec,
) -> Result<(), ComposeError> {
    let destination = staging.join(&spec.record.snapshot_path);
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(ComposeError::Verification(format!(
            "custom target snapshot destination already exists: {}",
            destination.display()
        )));
    }
    fs::create_dir(staging.join("targets"))?;
    fs::write(&destination, &spec.bytes)?;
    verify_custom_target_snapshot(&spec.record, &destination)?;
    Ok(())
}

#[derive(Clone, Debug)]
struct PackageSeed {
    id: String,
    package: String,
    path: String,
    direct: bool,
}

fn selected_package_roots(
    catalog: &NormalizedCatalog,
    resolution: &crate::resolver::Resolution,
) -> Result<Vec<PackageSeed>, ComposeError> {
    let mut packages = BTreeMap::new();
    let mandatory = [
        (
            "rust-agent-core",
            "rust-agent-core",
            "crates/api/rust-agent-core",
        ),
        (
            "rust-agent-runtime-api",
            "rust-agent-runtime-api",
            "crates/api/rust-agent-runtime-api",
        ),
        (
            "fixture-api",
            "rust-agent-fixture-api",
            "tests/fixtures/api/fixture-api",
        ),
    ];
    for (id, package, path) in mandatory {
        packages.insert(
            path.to_owned(),
            PackageSeed {
                id: id.to_owned(),
                package: package.to_owned(),
                path: path.to_owned(),
                direct: true,
            },
        );
    }
    for id in &resolution.selected_components {
        let component = &catalog.components[id];
        packages.insert(
            component.package_path.clone(),
            PackageSeed {
                id: component.id.clone(),
                package: component.package.clone(),
                path: component.package_path.clone(),
                direct: true,
            },
        );
    }
    let adapter = &catalog.runtime_adapters[&resolution.runtime_adapter];
    packages.insert(
        adapter.package_path.clone(),
        PackageSeed {
            id: adapter.id.clone(),
            package: adapter.package.clone(),
            path: adapter.package_path.clone(),
            direct: true,
        },
    );
    if let Some(boundary_id) = &resolution.host_boundary {
        let boundary = &catalog.host_boundaries[boundary_id];
        if !matches!(
            boundary.kind,
            HostBoundaryKind::Entry | HostBoundaryKind::WasmExport
        ) {
            return Err(ComposeError::UnsupportedPhase1A(boundary_id.clone()));
        }
        packages.insert(
            boundary.package_path.clone(),
            PackageSeed {
                id: boundary.id.clone(),
                package: boundary.package.clone(),
                path: boundary.package_path.clone(),
                direct: true,
            },
        );
    }
    Ok(packages.into_values().collect())
}

fn selected_packages(
    workspace_root: &Path,
    catalog: &NormalizedCatalog,
    resolution: &crate::resolver::Resolution,
    target: &Target,
) -> Result<Vec<PackageInput>, ComposeError> {
    package_closure(
        workspace_root,
        selected_package_roots(catalog, resolution)?,
        target,
    )
}

fn package_closure(
    workspace_root: &Path,
    roots: Vec<PackageSeed>,
    target: &Target,
) -> Result<Vec<PackageInput>, ComposeError> {
    let mut seeds = BTreeMap::new();
    for seed in roots {
        if let Some(previous) = seeds.insert(seed.path.clone(), seed.clone())
            && (previous.id != seed.id || previous.package != seed.package)
        {
            return manifest_error(
                workspace_root.join(&seed.path).join("Cargo.toml"),
                format!(
                    "package path `{}` is claimed by both `{}` and `{}`",
                    seed.path, previous.id, seed.id
                ),
            );
        }
    }
    let mut pending = seeds.keys().cloned().collect::<BTreeSet<_>>();
    let mut packages = BTreeMap::new();
    let mut package_paths = BTreeMap::<String, String>::new();

    while let Some(path) = pending.pop_first() {
        let seed = seeds
            .get(&path)
            .expect("pending package always has a seed")
            .clone();
        let manifest = normalize_package_manifest(workspace_root, &path, target)?;
        if manifest.package != seed.package {
            return manifest_error(
                workspace_root.join(&path).join("Cargo.toml"),
                format!(
                    "resolved package is `{}` but the dependency/catalog requires `{}`",
                    manifest.package, seed.package
                ),
            );
        }
        if let Some(previous) = package_paths.insert(manifest.package.clone(), path.clone())
            && previous != path
        {
            return manifest_error(
                workspace_root.join(&path).join("Cargo.toml"),
                format!(
                    "package `{}` is ambiguous between `{previous}` and `{path}`",
                    manifest.package
                ),
            );
        }
        let dependencies = manifest.path_dependencies.clone();
        packages.insert(
            path.clone(),
            PackageInput {
                id: seed.id,
                package: seed.package,
                path: path.clone(),
                direct: seed.direct,
                manifest,
            },
        );
        for dependency in dependencies {
            if packages.len() + pending.len() >= MAX_COMPOSITION_SOURCE_PACKAGES
                && !seeds.contains_key(&dependency.logical_path)
            {
                return manifest_error(
                    workspace_root.join(&path).join("Cargo.toml"),
                    format!(
                        "path dependency closure exceeds {MAX_COMPOSITION_SOURCE_PACKAGES} packages"
                    ),
                );
            }
            if let Some(existing) = seeds.get(&dependency.logical_path) {
                if existing.package != dependency.package {
                    return manifest_error(
                        workspace_root.join(&path).join("Cargo.toml"),
                        format!(
                            "dependency `{}` expects package `{}` at `{}`, already committed as `{}`",
                            dependency.alias,
                            dependency.package,
                            dependency.logical_path,
                            existing.package
                        ),
                    );
                }
                continue;
            }
            let dependency_path = dependency.logical_path.clone();
            seeds.insert(
                dependency_path.clone(),
                PackageSeed {
                    id: format!("path-dependency-{}", dependency.package),
                    package: dependency.package,
                    path: dependency_path.clone(),
                    direct: false,
                },
            );
            pending.insert(dependency_path);
        }
    }

    if packages.len() > MAX_COMPOSITION_SOURCE_PACKAGES {
        return manifest_error(
            workspace_root.join("Cargo.toml"),
            format!("path dependency closure exceeds {MAX_COMPOSITION_SOURCE_PACKAGES} packages"),
        );
    }
    let mut source_ids = BTreeMap::new();
    for package in packages.values() {
        if let Some(previous) = source_ids.insert(package.id.clone(), package.path.clone()) {
            return manifest_error(
                workspace_root.join(&package.path).join("Cargo.toml"),
                format!(
                    "source id `{}` is ambiguous between `{previous}` and `{}`",
                    package.id, package.path
                ),
            );
        }
    }
    Ok(packages.into_values().collect())
}

fn manifest_error<T>(
    path: impl AsRef<Path>,
    message: impl Into<String>,
) -> Result<T, ComposeError> {
    Err(ComposeError::ManifestNormalization {
        path: path.as_ref().display().to_string(),
        message: message.into(),
    })
}

fn normalize_package_manifest(
    workspace_root: &Path,
    logical_path: &str,
    target: &Target,
) -> Result<NormalizedPackageManifest, ComposeError> {
    let package_root = resolve_package_root(workspace_root, logical_path)?;
    let manifest_path = package_root.join("Cargo.toml");
    let input = read_bounded_snapshot_source_file(&manifest_path, MAX_SOURCE_MANIFEST_BYTES)?;
    let input =
        std::str::from_utf8(&input).map_err(|error| ComposeError::ManifestNormalization {
            path: manifest_path.display().to_string(),
            message: error.to_string(),
        })?;
    let mut value: toml::Value =
        toml::from_str(input).map_err(|error| ComposeError::ManifestNormalization {
            path: manifest_path.display().to_string(),
            message: error.to_string(),
        })?;
    let table = value
        .as_table_mut()
        .ok_or_else(|| ComposeError::ManifestNormalization {
            path: manifest_path.display().to_string(),
            message: "manifest root is not a table".into(),
        })?;
    if table.contains_key("workspace") {
        return manifest_error(
            &manifest_path,
            "snapshot packages cannot contain a nested [workspace] table",
        );
    }
    let package = table
        .get_mut("package")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| ComposeError::ManifestNormalization {
            path: manifest_path.display().to_string(),
            message: "manifest has no package table".into(),
        })?;
    let package_name = package
        .get("name")
        .and_then(toml::Value::as_str)
        .filter(|name| valid_cargo_package_name(name))
        .ok_or_else(|| ComposeError::ManifestNormalization {
            path: manifest_path.display().to_string(),
            message: "package.name must be a bounded canonical Cargo package name".into(),
        })?
        .to_owned();
    if package.contains_key("workspace") {
        return manifest_error(
            &manifest_path,
            "package.workspace cannot remain active in a source snapshot",
        );
    }
    package.insert("version".into(), toml::Value::String("0.1.0".into()));
    package.insert("edition".into(), toml::Value::String("2024".into()));
    package.insert(
        "rust-version".into(),
        toml::Value::String(PINNED_RUST_VERSION.into()),
    );
    package.insert("license".into(), toml::Value::String("MIT".into()));
    package.remove("repository");
    reject_remaining_workspace_inheritance(package, &manifest_path)?;

    table.remove("dev-dependencies");
    table.remove("lints");
    expand_target_dependencies(table, target, &manifest_path)?;

    let mut path_dependencies = Vec::new();
    let mut requires_registry = false;
    for section in ["dependencies", "build-dependencies"] {
        normalize_dependency_section(
            table,
            section,
            workspace_root,
            logical_path,
            &manifest_path,
            &mut path_dependencies,
            &mut requires_registry,
        )?;
    }
    path_dependencies.sort_by(|left, right| {
        (&left.logical_path, &left.package, &left.alias).cmp(&(
            &right.logical_path,
            &right.package,
            &right.alias,
        ))
    });
    path_dependencies.dedup();

    let mut output =
        toml::to_string(&value).map_err(|error| ComposeError::ManifestNormalization {
            path: manifest_path.display().to_string(),
            message: error.to_string(),
        })?;
    if !output.ends_with('\n') {
        output.push('\n');
    }
    Ok(NormalizedPackageManifest {
        bytes: output.into_bytes(),
        package: package_name,
        path_dependencies,
        requires_registry,
    })
}

fn valid_cargo_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn reject_remaining_workspace_inheritance(
    package: &toml::Table,
    manifest_path: &Path,
) -> Result<(), ComposeError> {
    if package.values().any(|value| {
        value
            .as_table()
            .and_then(|table| table.get("workspace"))
            .is_some()
    }) {
        return manifest_error(
            manifest_path,
            "package workspace inheritance is not resolved by the Phase 1A snapshot schema",
        );
    }
    Ok(())
}

fn expand_target_dependencies(
    root: &mut toml::Table,
    target: &Target,
    manifest_path: &Path,
) -> Result<(), ComposeError> {
    let Some(target_value) = root.remove("target") else {
        return Ok(());
    };
    let targets = target_value
        .as_table()
        .ok_or_else(|| ComposeError::ManifestNormalization {
            path: manifest_path.display().to_string(),
            message: "target dependency clauses must be a table".into(),
        })?;
    if targets.len() > MAX_MANIFEST_TARGET_SELECTORS {
        return manifest_error(
            manifest_path,
            format!(
                "target dependency selector count {} exceeds {MAX_MANIFEST_TARGET_SELECTORS}",
                targets.len()
            ),
        );
    }

    let mut active_dependencies = Vec::new();
    for (selector, value) in targets {
        let matches = target.matches_cargo_selector(selector).map_err(|error| {
            ComposeError::ManifestNormalization {
                path: manifest_path.display().to_string(),
                message: format!("invalid Cargo target selector `{selector}`: {error}"),
            }
        })?;
        let clause = value
            .as_table()
            .ok_or_else(|| ComposeError::ManifestNormalization {
                path: manifest_path.display().to_string(),
                message: format!("Cargo target selector `{selector}` is not a table"),
            })?;
        for key in clause.keys() {
            if !matches!(
                key.as_str(),
                "dependencies" | "dev-dependencies" | "build-dependencies"
            ) {
                return manifest_error(
                    manifest_path,
                    format!("unsupported key `{key}` in Cargo target selector `{selector}`"),
                );
            }
        }
        for section in ["dependencies", "dev-dependencies"] {
            if let Some(dependencies) = clause.get(section) {
                validate_dependency_table_shape(
                    dependencies,
                    manifest_path,
                    &format!("target `{selector}` {section}"),
                )?;
            }
        }
        if let Some(build_dependencies) = clause.get("build-dependencies") {
            let build_dependencies = dependency_table(
                build_dependencies,
                manifest_path,
                &format!("target `{selector}` build-dependencies"),
            )?;
            if !build_dependencies.is_empty() {
                return manifest_error(
                    manifest_path,
                    format!(
                        "target-specific build-dependencies under `{selector}` require committed BuildHost facts"
                    ),
                );
            }
        }
        if matches && let Some(dependencies) = clause.get("dependencies") {
            let dependencies = dependency_table(
                dependencies,
                manifest_path,
                &format!("target `{selector}` dependencies"),
            )?;
            active_dependencies.extend(
                dependencies
                    .iter()
                    .map(|(alias, specification)| (alias.clone(), specification.clone())),
            );
        }
    }

    if active_dependencies.is_empty() {
        return Ok(());
    }
    if !root.contains_key("dependencies") {
        root.insert(
            "dependencies".into(),
            toml::Value::Table(toml::Table::new()),
        );
    }
    let dependencies = root
        .get_mut("dependencies")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| ComposeError::ManifestNormalization {
            path: manifest_path.display().to_string(),
            message: "dependencies must be a table".into(),
        })?;
    for (alias, specification) in active_dependencies {
        if dependencies.contains_key(&alias) {
            return manifest_error(
                manifest_path,
                format!(
                    "dependency alias `{alias}` is selected by more than one unconditional/target clause"
                ),
            );
        }
        dependencies.insert(alias, specification);
    }
    Ok(())
}

fn validate_dependency_table_shape(
    value: &toml::Value,
    manifest_path: &Path,
    context: &str,
) -> Result<(), ComposeError> {
    let dependencies = dependency_table(value, manifest_path, context)?;
    if dependencies.len() > MAX_MANIFEST_DEPENDENCIES {
        return manifest_error(
            manifest_path,
            format!(
                "{context} contains {} entries; maximum is {MAX_MANIFEST_DEPENDENCIES}",
                dependencies.len()
            ),
        );
    }
    for (alias, specification) in dependencies {
        if !valid_cargo_package_name(alias) {
            return manifest_error(
                manifest_path,
                format!("{context} has invalid dependency alias `{alias}`"),
            );
        }
        match specification {
            toml::Value::String(_) => {}
            toml::Value::Table(specification) => {
                let allowed = BTreeSet::from([
                    "branch",
                    "default-features",
                    "features",
                    "git",
                    "optional",
                    "package",
                    "path",
                    "registry",
                    "rev",
                    "tag",
                    "version",
                    "workspace",
                ]);
                if let Some(unknown) = specification
                    .keys()
                    .find(|key| !allowed.contains(key.as_str()))
                {
                    return manifest_error(
                        manifest_path,
                        format!("{context} dependency `{alias}` has unsupported key `{unknown}`"),
                    );
                }
                if specification.contains_key("workspace") {
                    return manifest_error(
                        manifest_path,
                        format!("{context} dependency `{alias}` uses workspace inheritance"),
                    );
                }
                if specification.contains_key("registry") {
                    return manifest_error(
                        manifest_path,
                        format!("{context} dependency `{alias}` uses a named registry"),
                    );
                }
                if let Some(package) = specification.get("package")
                    && !package.as_str().is_some_and(valid_cargo_package_name)
                {
                    return manifest_error(
                        manifest_path,
                        format!("{context} dependency `{alias}` has an invalid package name"),
                    );
                }
                for key in ["version", "git", "branch", "tag", "rev"] {
                    if let Some(value) = specification.get(key)
                        && value.as_str().is_none()
                    {
                        return manifest_error(
                            manifest_path,
                            format!("{context} dependency `{alias}` key `{key}` must be a string"),
                        );
                    }
                }
                for key in ["optional", "default-features"] {
                    if let Some(value) = specification.get(key)
                        && value.as_bool().is_none()
                    {
                        return manifest_error(
                            manifest_path,
                            format!("{context} dependency `{alias}` key `{key}` must be a boolean"),
                        );
                    }
                }
                if let Some(features) = specification.get("features") {
                    let Some(features) = features.as_array() else {
                        return manifest_error(
                            manifest_path,
                            format!("{context} dependency `{alias}` features must be an array"),
                        );
                    };
                    if features.len() > MAX_MANIFEST_DEPENDENCIES
                        || features.iter().any(|feature| {
                            feature.as_str().is_none_or(|feature| {
                                feature.is_empty()
                                    || feature.len() > 256
                                    || feature.contains(char::is_whitespace)
                            })
                        })
                    {
                        return manifest_error(
                            manifest_path,
                            format!(
                                "{context} dependency `{alias}` features are invalid or exceed bounds"
                            ),
                        );
                    }
                }
                let git_references = ["branch", "tag", "rev"]
                    .into_iter()
                    .filter(|key| specification.contains_key(*key))
                    .count();
                if git_references > 1 || (git_references == 1 && !specification.contains_key("git"))
                {
                    return manifest_error(
                        manifest_path,
                        format!("{context} dependency `{alias}` has an ambiguous git reference"),
                    );
                }
                if let Some(path) = specification.get("path") {
                    let path =
                        path.as_str()
                            .ok_or_else(|| ComposeError::ManifestNormalization {
                                path: manifest_path.display().to_string(),
                                message: format!(
                                    "{context} dependency `{alias}` path must be a string"
                                ),
                            })?;
                    validate_relative_dependency_path(path, manifest_path, context, alias)?;
                    if specification.contains_key("git") {
                        return manifest_error(
                            manifest_path,
                            format!("{context} dependency `{alias}` combines path and git"),
                        );
                    }
                }
            }
            _ => {
                return manifest_error(
                    manifest_path,
                    format!("{context} dependency `{alias}` has an invalid specification"),
                );
            }
        }
    }
    Ok(())
}

fn dependency_table<'a>(
    value: &'a toml::Value,
    manifest_path: &Path,
    context: &str,
) -> Result<&'a toml::Table, ComposeError> {
    value
        .as_table()
        .ok_or_else(|| ComposeError::ManifestNormalization {
            path: manifest_path.display().to_string(),
            message: format!("{context} must be a table"),
        })
}

fn normalize_dependency_section(
    root: &mut toml::Table,
    section: &str,
    workspace_root: &Path,
    package_logical_path: &str,
    manifest_path: &Path,
    path_dependencies: &mut Vec<PathDependency>,
    requires_registry: &mut bool,
) -> Result<(), ComposeError> {
    let Some(value) = root.get_mut(section) else {
        return Ok(());
    };
    validate_dependency_table_shape(value, manifest_path, section)?;
    let dependencies = value
        .as_table_mut()
        .expect("dependency table shape was validated");
    for (alias, specification) in dependencies {
        match specification {
            toml::Value::String(_) => *requires_registry = true,
            toml::Value::Table(specification) => {
                let expected_package = specification
                    .get("package")
                    .and_then(toml::Value::as_str)
                    .unwrap_or(alias)
                    .to_owned();
                if let Some(raw_path) = specification
                    .get("path")
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned)
                {
                    if specification.get("optional").and_then(toml::Value::as_bool) == Some(true) {
                        return manifest_error(
                            manifest_path,
                            format!(
                                "{section} dependency `{alias}` is an optional path dependency; Phase 1A requires exact feature-unit planning before snapshot inclusion"
                            ),
                        );
                    }
                    let dependency_logical_path = resolve_dependency_logical_path(
                        workspace_root,
                        package_logical_path,
                        &raw_path,
                        manifest_path,
                        alias,
                    )?;
                    let rewritten =
                        relative_package_path(package_logical_path, &dependency_logical_path);
                    specification.insert("path".into(), toml::Value::String(rewritten));
                    path_dependencies.push(PathDependency {
                        alias: alias.clone(),
                        package: expected_package,
                        logical_path: dependency_logical_path,
                    });
                } else if !specification.contains_key("git") {
                    *requires_registry = true;
                }
            }
            _ => unreachable!("dependency shape was validated"),
        }
    }
    Ok(())
}

fn validate_relative_dependency_path(
    raw_path: &str,
    manifest_path: &Path,
    context: &str,
    alias: &str,
) -> Result<(), ComposeError> {
    let path = Path::new(raw_path);
    if raw_path.is_empty()
        || raw_path.contains('\\')
        || path.is_absolute()
        || !path.components().all(|component| {
            matches!(
                component,
                std::path::Component::Normal(_)
                    | std::path::Component::ParentDir
                    | std::path::Component::CurDir
            )
        })
    {
        return manifest_error(
            manifest_path,
            format!("{context} dependency `{alias}` has an unsafe path `{raw_path}`"),
        );
    }
    Ok(())
}

fn resolve_package_root(
    workspace_root: &Path,
    logical_path: &str,
) -> Result<PathBuf, ComposeError> {
    let logical = Path::new(logical_path);
    if logical_path.is_empty()
        || logical_path.contains('\\')
        || logical.is_absolute()
        || !logical
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return manifest_error(
            workspace_root.join("Cargo.toml"),
            format!("invalid package logical path `{logical_path}`"),
        );
    }
    let canonical_workspace = workspace_root.canonicalize()?;
    let root_metadata = fs::symlink_metadata(workspace_root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(ComposeError::UnsupportedSourceEntry(
            workspace_root.display().to_string(),
        ));
    }
    let mut current = canonical_workspace.clone();
    for component in logical.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                ComposeError::MissingSourcePackage(current.display().to_string())
            } else {
                error.into()
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ComposeError::UnsupportedSourceEntry(
                current.display().to_string(),
            ));
        }
    }
    let metadata = fs::symlink_metadata(&current)?;
    if !metadata.is_dir() {
        return Err(ComposeError::MissingSourcePackage(
            current.display().to_string(),
        ));
    }
    let canonical = current.canonicalize()?;
    if !canonical.starts_with(&canonical_workspace) {
        return Err(ComposeError::InputOutsideWorkspace(
            canonical.display().to_string(),
        ));
    }
    Ok(canonical)
}

fn resolve_dependency_logical_path(
    workspace_root: &Path,
    package_logical_path: &str,
    raw_path: &str,
    manifest_path: &Path,
    alias: &str,
) -> Result<String, ComposeError> {
    validate_relative_dependency_path(raw_path, manifest_path, "path", alias)?;
    let canonical_workspace = workspace_root.canonicalize()?;
    let mut current = resolve_package_root(workspace_root, package_logical_path)?;
    for component in Path::new(raw_path).components() {
        match component {
            std::path::Component::Normal(value) => {
                current.push(value);
                let metadata = fs::symlink_metadata(&current).map_err(|error| {
                    if error.kind() == io::ErrorKind::NotFound {
                        ComposeError::MissingSourcePackage(current.display().to_string())
                    } else {
                        error.into()
                    }
                })?;
                if metadata.file_type().is_symlink() {
                    return Err(ComposeError::UnsupportedSourceEntry(
                        current.display().to_string(),
                    ));
                }
            }
            std::path::Component::ParentDir => {
                if current == canonical_workspace || !current.pop() {
                    return Err(ComposeError::InputOutsideWorkspace(raw_path.into()));
                }
            }
            std::path::Component::CurDir => {}
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                return Err(ComposeError::InputOutsideWorkspace(raw_path.into()));
            }
        }
        if !current.starts_with(&canonical_workspace) {
            return Err(ComposeError::InputOutsideWorkspace(raw_path.into()));
        }
    }
    let metadata = fs::symlink_metadata(&current).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            ComposeError::MissingSourcePackage(current.display().to_string())
        } else {
            error.into()
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ComposeError::MissingSourcePackage(
            current.display().to_string(),
        ));
    }
    let manifest = current.join("Cargo.toml");
    let manifest_metadata = fs::symlink_metadata(&manifest).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            ComposeError::MissingSourcePackage(manifest.display().to_string())
        } else {
            error.into()
        }
    })?;
    if manifest_metadata.file_type().is_symlink() || !manifest_metadata.is_file() {
        return Err(ComposeError::MissingSourcePackage(
            manifest.display().to_string(),
        ));
    }
    let logical = current
        .strip_prefix(&canonical_workspace)
        .map_err(|_| ComposeError::InputOutsideWorkspace(current.display().to_string()))?;
    logical
        .to_str()
        .map(|path| path.replace('\\', "/"))
        .ok_or_else(|| ComposeError::UnsupportedSourceEntry(current.display().to_string()))
}

fn relative_package_path(from: &str, to: &str) -> String {
    let from = from.split('/').collect::<Vec<_>>();
    let to = to.split('/').collect::<Vec<_>>();
    let common = from
        .iter()
        .zip(&to)
        .take_while(|(left, right)| left == right)
        .count();
    let mut parts = vec![".."; from.len() - common];
    parts.extend(to[common..].iter().copied());
    if parts.is_empty() {
        ".".into()
    } else {
        parts.join("/")
    }
}

#[derive(Debug)]
struct SnapshotPackagePlanEntry {
    source: PathBuf,
    relative: PathBuf,
    logical_path: String,
    content: SnapshotPackagePlanContent,
}

#[derive(Debug)]
struct SnapshotPackagePlan {
    entries: Vec<SnapshotPackagePlanEntry>,
    file_bytes: u64,
}

#[derive(Debug)]
enum SnapshotPackagePlanContent {
    Directory,
    RegularFile { bytes: u64 },
    NormalizedManifest { bytes: Vec<u8> },
}

fn plan_composition_source_packages(
    workspace_root: &Path,
    packages: &[PackageInput],
    target: &Target,
) -> Result<Vec<SnapshotPackagePlan>, ComposeError> {
    let mut plans = Vec::with_capacity(packages.len());
    let mut usage = CompositionSourceUsage::default();
    for package in packages {
        let plan = plan_selected_package_snapshot(workspace_root, package, target)?;
        usage.account(plan.entries.len(), plan.file_bytes)?;
        plans.push(plan);
    }
    Ok(plans)
}

fn plan_selected_package_snapshot(
    workspace_root: &Path,
    package: &PackageInput,
    target: &Target,
) -> Result<SnapshotPackagePlan, ComposeError> {
    let source = workspace_root.join(&package.path);
    validate_snapshot_package_root(&source)?;
    let current_manifest = normalize_package_manifest(workspace_root, &package.path, target)?;
    if current_manifest != package.manifest {
        return Err(ComposeError::Verification(format!(
            "source manifest `{}` changed after dependency closure planning",
            source.join("Cargo.toml").display()
        )));
    }
    plan_snapshot_package(&source, &package.manifest.bytes)
}

fn validate_snapshot_package_root(source: &Path) -> Result<(), ComposeError> {
    let source_metadata = fs::symlink_metadata(source).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            ComposeError::MissingSourcePackage(source.display().to_string())
        } else {
            error.into()
        }
    })?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_dir() {
        return Err(ComposeError::MissingSourcePackage(
            source.display().to_string(),
        ));
    }
    Ok(())
}

fn snapshot_planned_package(
    workspace_root: &Path,
    source_root: &Path,
    package: &PackageInput,
    target: &Target,
    plan: &SnapshotPackagePlan,
) -> Result<SourcePackageRecord, ComposeError> {
    let source = workspace_root.join(&package.path);
    validate_snapshot_package_root(&source)?;
    let current_manifest = normalize_package_manifest(workspace_root, &package.path, target)?;
    if current_manifest != package.manifest {
        return Err(ComposeError::Verification(format!(
            "source manifest `{}` changed after dependency closure planning",
            source.join("Cargo.toml").display()
        )));
    }
    let destination = source_root.join(&package.path);
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(ComposeError::Verification(format!(
            "source snapshot destination already exists: {}",
            destination.display()
        )));
    }
    fs::create_dir_all(&destination)?;
    let result = (|| {
        let current_manifest = normalize_package_manifest(workspace_root, &package.path, target)?;
        if current_manifest != package.manifest {
            return Err(ComposeError::Verification(format!(
                "source manifest `{}` changed while snapshotting",
                source.join("Cargo.toml").display()
            )));
        }
        let copied_tree = materialize_snapshot_package_plan(&source, &destination, &plan.entries)?;
        let current_manifest = normalize_package_manifest(workspace_root, &package.path, target)?;
        if current_manifest != package.manifest {
            return Err(ComposeError::Verification(format!(
                "source manifest `{}` changed while snapshotting",
                source.join("Cargo.toml").display()
            )));
        }
        seal_source_snapshot_storage_projection(&destination)?;
        let tree = source_snapshot_tree(&destination)?;
        if tree != copied_tree {
            return Err(ComposeError::Verification(format!(
                "source snapshot changed while materializing `{}`",
                source.display()
            )));
        }
        Ok(SourcePackageRecord {
            id: package.id.clone(),
            package: package.package.clone(),
            logical_path: package.path.clone(),
            tree_digest: tree.digest().to_owned(),
            tree_entries: tree.entries().to_vec(),
        })
    })();
    if result.is_err() {
        let _ = remove_staging_tree(&destination);
    }
    result
}

#[cfg(test)]
fn snapshot_package(
    workspace_root: &Path,
    source_root: &Path,
    id: &str,
    package: &str,
    logical_path: &str,
) -> Result<SourcePackageRecord, ComposeError> {
    let facts = crate::target::canonical_builtin_facts(
        crate::target::CoreTargetFacts::little_endian("x86_64", "gnu", "linux", "64", "unwind"),
    )?;
    let target = Target::from_facts(
        "x86_64-unknown-linux-gnu",
        crate::target::Environment::Server,
        facts,
    )?;
    let manifest = normalize_package_manifest(workspace_root, logical_path, &target)?;
    let package = PackageInput {
        id: id.into(),
        package: package.into(),
        path: logical_path.into(),
        direct: true,
        manifest,
    };
    let plan = plan_selected_package_snapshot(workspace_root, &package, &target)?;
    snapshot_planned_package(workspace_root, source_root, &package, &target, &plan)
}

fn plan_snapshot_package(
    source: &Path,
    normalized_manifest: &[u8],
) -> Result<SnapshotPackagePlan, ComposeError> {
    let mut plan = Vec::new();
    let mut validation_entries = Vec::new();
    let mut total_file_bytes = 0_u64;
    let walker = WalkDir::new(source)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            entry.path() == source
                || entry
                    .path()
                    .strip_prefix(source)
                    .is_ok_and(|relative| !snapshot_path_is_transient(relative))
        });
    for entry in walker {
        let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
        let relative = entry
            .path()
            .strip_prefix(source)
            .expect("walked path is below source package");
        if relative.as_os_str().is_empty() {
            continue;
        }
        if plan.len() == MAX_CANONICAL_SNAPSHOT_ENTRIES {
            return Err(CanonicalSnapshotError::TooManyEntries {
                actual: plan.len() + 1,
                maximum: MAX_CANONICAL_SNAPSHOT_ENTRIES,
            }
            .into());
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err(ComposeError::UnsupportedSourceEntry(
                entry.path().display().to_string(),
            ));
        }
        if !metadata.is_file() && !metadata.is_dir() {
            return Err(ComposeError::UnsupportedSourceEntry(
                entry.path().display().to_string(),
            ));
        }
        let logical_entry_path = relative
            .to_str()
            .ok_or_else(|| {
                ComposeError::UnsupportedSourceEntry(entry.path().display().to_string())
            })?
            .replace('\\', "/");
        let content = if metadata.is_dir() {
            validation_entries.push(CanonicalSnapshotEntry::directory(
                logical_entry_path.clone(),
            ));
            SnapshotPackagePlanContent::Directory
        } else if relative == Path::new("Cargo.toml") {
            let bytes = normalized_manifest.to_vec();
            account_snapshot_file_bytes(
                &logical_entry_path,
                bytes.len() as u64,
                &mut total_file_bytes,
            )?;
            validation_entries.push(CanonicalSnapshotEntry::regular_file(
                logical_entry_path.clone(),
                sha256_hex(&bytes),
                bytes.len() as u64,
            ));
            SnapshotPackagePlanContent::NormalizedManifest { bytes }
        } else {
            account_snapshot_file_bytes(
                &logical_entry_path,
                metadata.len(),
                &mut total_file_bytes,
            )?;
            validation_entries.push(CanonicalSnapshotEntry::regular_file(
                logical_entry_path.clone(),
                "0".repeat(64),
                metadata.len(),
            ));
            SnapshotPackagePlanContent::RegularFile {
                bytes: metadata.len(),
            }
        };
        plan.push(SnapshotPackagePlanEntry {
            source: entry.path().to_owned(),
            relative: relative.to_owned(),
            logical_path: logical_entry_path,
            content,
        });
    }
    CanonicalSnapshotTree::from_entries(validation_entries)?;
    Ok(SnapshotPackagePlan {
        entries: plan,
        file_bytes: total_file_bytes,
    })
}

fn account_snapshot_file_bytes(
    path: &str,
    bytes: u64,
    total: &mut u64,
) -> Result<(), ComposeError> {
    if bytes > MAX_CANONICAL_SNAPSHOT_FILE_BYTES {
        return Err(CanonicalSnapshotError::FileTooLarge {
            path: path.into(),
            actual: bytes,
            maximum: MAX_CANONICAL_SNAPSHOT_FILE_BYTES,
        }
        .into());
    }
    let next = total
        .checked_add(bytes)
        .ok_or(CanonicalSnapshotError::TotalBytesTooLarge {
            actual: u64::MAX,
            maximum: MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES,
        })?;
    if next > MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES {
        return Err(CanonicalSnapshotError::TotalBytesTooLarge {
            actual: next,
            maximum: MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES,
        }
        .into());
    }
    *total = next;
    Ok(())
}

fn materialize_snapshot_package_plan(
    source_root: &Path,
    destination: &Path,
    plan: &[SnapshotPackagePlanEntry],
) -> Result<CanonicalSnapshotTree, ComposeError> {
    let root_metadata = fs::symlink_metadata(source_root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(ComposeError::UnsupportedSourceEntry(
            source_root.display().to_string(),
        ));
    }
    let mut copied_entries = Vec::with_capacity(plan.len());
    for entry in plan {
        let target = destination.join(&entry.relative);
        match &entry.content {
            SnapshotPackagePlanContent::Directory => {
                let metadata = fs::symlink_metadata(&entry.source)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(ComposeError::UnsupportedSourceEntry(
                        entry.source.display().to_string(),
                    ));
                }
                fs::create_dir_all(&target)?;
                copied_entries.push(CanonicalSnapshotEntry::directory(
                    entry.logical_path.clone(),
                ));
            }
            SnapshotPackagePlanContent::RegularFile { bytes } => {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                let (digest, actual_bytes) =
                    copy_snapshot_source_file(&entry.source, &target, *bytes)?;
                copied_entries.push(CanonicalSnapshotEntry::regular_file(
                    entry.logical_path.clone(),
                    digest,
                    actual_bytes,
                ));
            }
            SnapshotPackagePlanContent::NormalizedManifest { bytes } => {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                let file = File::options().write(true).create_new(true).open(&target)?;
                let mut writer = BufWriter::new(file);
                writer.write_all(bytes)?;
                writer.flush()?;
                copied_entries.push(CanonicalSnapshotEntry::regular_file(
                    entry.logical_path.clone(),
                    sha256_hex(bytes),
                    bytes.len() as u64,
                ));
            }
        }
    }
    Ok(CanonicalSnapshotTree::from_entries(copied_entries)?)
}

fn copy_snapshot_source_file(
    source: &Path,
    destination: &Path,
    expected_bytes: u64,
) -> Result<(String, u64), ComposeError> {
    let before = fs::symlink_metadata(source)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.len() != expected_bytes
        || expected_bytes > MAX_CANONICAL_SNAPSHOT_FILE_BYTES
    {
        return Err(ComposeError::UnsupportedSourceEntry(
            source.display().to_string(),
        ));
    }
    let source_file = File::open(source)?;
    let handle_before = source_file.metadata()?;
    if !handle_before.is_file()
        || handle_before.len() != before.len()
        || handle_before.modified()? != before.modified()?
    {
        return Err(ComposeError::Verification(format!(
            "source snapshot file `{}` changed before copying",
            source.display()
        )));
    }
    let target_file = File::options()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let mut reader = BufReader::new(source_file);
    let mut writer = BufWriter::new(target_file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; SNAPSHOT_COPY_BUFFER_BYTES];
    let mut copied = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let next = copied.checked_add(read as u64).ok_or_else(|| {
            ComposeError::Verification(format!(
                "source snapshot file `{}` exceeds schema bounds",
                source.display()
            ))
        })?;
        if next > expected_bytes || next > MAX_CANONICAL_SNAPSHOT_FILE_BYTES {
            return Err(ComposeError::Verification(format!(
                "source snapshot file `{}` changed size while copying",
                source.display()
            )));
        }
        writer.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        copied = next;
    }
    writer.flush()?;
    let handle_after = reader.get_ref().metadata()?;
    let path_after = fs::symlink_metadata(source)?;
    if copied != expected_bytes
        || handle_after.len() != before.len()
        || handle_after.modified()? != before.modified()?
        || path_after.file_type().is_symlink()
        || !path_after.is_file()
        || path_after.len() != before.len()
        || path_after.modified()? != before.modified()?
    {
        return Err(ComposeError::Verification(format!(
            "source snapshot file `{}` changed while copying",
            source.display()
        )));
    }
    Ok((hex::encode(hasher.finalize()), copied))
}

fn snapshot_path_is_transient(relative: &Path) -> bool {
    let is_trybuild_wip = relative
        .components()
        .next()
        .is_some_and(|part| part.as_os_str() == "wip");
    is_trybuild_wip
        || relative
            .components()
            .any(|part| part.as_os_str() == "target" || part.as_os_str() == ".git")
}

fn read_bounded_snapshot_source_file(path: &Path, maximum: u64) -> Result<Vec<u8>, ComposeError> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(ComposeError::UnsupportedSourceEntry(
            path.display().to_string(),
        ));
    }
    if before.len() > maximum {
        return Err(CanonicalSnapshotError::FileTooLarge {
            path: path.display().to_string(),
            actual: before.len(),
            maximum,
        }
        .into());
    }
    let file = File::open(path)?;
    let handle_before = file.metadata()?;
    if !handle_before.is_file()
        || handle_before.len() != before.len()
        || handle_before.modified()? != before.modified()?
    {
        return Err(ComposeError::Verification(format!(
            "source snapshot file `{}` changed before reading",
            path.display()
        )));
    }
    let mut reader = BufReader::new(file).take(maximum + 1);
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.len())
            .unwrap_or(usize::MAX)
            .min(MAX_CANONICAL_SNAPSHOT_JSON_BYTES),
    );
    reader.read_to_end(&mut bytes)?;
    let file = reader.into_inner().into_inner();
    let handle_after = file.metadata()?;
    let path_after = fs::symlink_metadata(path)?;
    if bytes.len() as u64 > maximum {
        return Err(CanonicalSnapshotError::FileTooLarge {
            path: path.display().to_string(),
            actual: bytes.len() as u64,
            maximum,
        }
        .into());
    }
    if handle_after.len() != before.len()
        || handle_after.modified()? != before.modified()?
        || path_after.file_type().is_symlink()
        || !path_after.is_file()
        || path_after.len() != before.len()
        || path_after.modified()? != before.modified()?
        || bytes.len() as u64 != before.len()
    {
        return Err(ComposeError::Verification(format!(
            "source snapshot file `{}` changed while reading",
            path.display()
        )));
    }
    Ok(bytes)
}

fn composition_regular_file_metadata(
    path: &Path,
    maximum: u64,
    expected_bytes: Option<u64>,
) -> Result<fs::Metadata, ComposeError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ComposeError::Verification(format!(
            "composition input `{}` must be a concrete regular file",
            path.display()
        )));
    }
    if metadata.len() > maximum {
        return Err(ComposeError::Verification(format!(
            "composition input `{}` has {} bytes; maximum is {maximum}",
            path.display(),
            metadata.len()
        )));
    }
    if let Some(expected) = expected_bytes
        && metadata.len() != expected
    {
        return Err(ComposeError::Verification(format!(
            "composition input `{}` has {} bytes; expected {expected}",
            path.display(),
            metadata.len()
        )));
    }
    Ok(metadata)
}

fn read_composition_regular_file_bounded(
    path: &Path,
    maximum: u64,
    expected_bytes: Option<u64>,
) -> Result<Vec<u8>, ComposeError> {
    let before = composition_regular_file_metadata(path, maximum, expected_bytes)?;
    let file = File::open(path)?;
    let handle_before = file.metadata()?;
    if !handle_before.is_file()
        || handle_before.len() != before.len()
        || handle_before.modified()? != before.modified()?
    {
        return Err(ComposeError::Verification(format!(
            "composition input `{}` changed before reading",
            path.display()
        )));
    }
    let mut reader = BufReader::new(file).take(maximum.saturating_add(1));
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.len())
            .unwrap_or(usize::MAX)
            .min(MAX_CANONICAL_SNAPSHOT_JSON_BYTES),
    );
    reader.read_to_end(&mut bytes)?;
    let file = reader.into_inner().into_inner();
    let handle_after = file.metadata()?;
    let path_after = fs::symlink_metadata(path)?;
    if bytes.len() as u64 > maximum
        || bytes.len() as u64 != before.len()
        || handle_after.len() != before.len()
        || handle_after.modified()? != before.modified()?
        || path_after.file_type().is_symlink()
        || !path_after.is_file()
        || path_after.len() != before.len()
        || path_after.modified()? != before.modified()?
    {
        return Err(ComposeError::Verification(format!(
            "composition input `{}` changed or exceeded its bound while reading",
            path.display()
        )));
    }
    Ok(bytes)
}

fn hash_composition_regular_file_bounded(
    path: &Path,
    maximum: u64,
    expected_bytes: Option<u64>,
) -> Result<(String, u64), ComposeError> {
    let before = composition_regular_file_metadata(path, maximum, expected_bytes)?;
    let file = File::open(path)?;
    let handle_before = file.metadata()?;
    if !handle_before.is_file()
        || handle_before.len() != before.len()
        || handle_before.modified()? != before.modified()?
    {
        return Err(ComposeError::Verification(format!(
            "composition input `{}` changed before hashing",
            path.display()
        )));
    }
    let mut reader = BufReader::new(file).take(maximum.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; SNAPSHOT_COPY_BUFFER_BYTES];
    let mut bytes = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes = bytes.checked_add(read as u64).ok_or_else(|| {
            ComposeError::Verification(format!(
                "composition input `{}` exceeds its byte bound",
                path.display()
            ))
        })?;
        if bytes > maximum {
            return Err(ComposeError::Verification(format!(
                "composition input `{}` exceeds its byte bound",
                path.display()
            )));
        }
        hasher.update(&buffer[..read]);
    }
    let file = reader.into_inner().into_inner();
    let handle_after = file.metadata()?;
    let path_after = fs::symlink_metadata(path)?;
    if bytes != before.len()
        || handle_after.len() != before.len()
        || handle_after.modified()? != before.modified()?
        || path_after.file_type().is_symlink()
        || !path_after.is_file()
        || path_after.len() != before.len()
        || path_after.modified()? != before.modified()?
    {
        return Err(ComposeError::Verification(format!(
            "composition input `{}` changed while hashing",
            path.display()
        )));
    }
    Ok((hex::encode(hasher.finalize()), bytes))
}

fn generate_cargo_toml(
    catalog: &NormalizedCatalog,
    resolution: &crate::resolver::Resolution,
    packages: &[PackageInput],
    build_kind: BuildKind,
) -> String {
    let mut output = format!(
        "[package]\nname = \"rust-agent-generated-composition\"\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"{PINNED_RUST_VERSION}\"\nlicense = \"MIT\"\npublish = false\n\n[workspace]\nresolver = \"2\"\nexclude = [\n",
    );
    for package in packages {
        output.push_str(&format!("    {:?},\n", format!("sources/{}", package.path)));
    }
    output.push_str("]\n\n");
    if build_kind == BuildKind::Wasm {
        output.push_str("[lib]\ncrate-type = [\"cdylib\", \"rlib\"]\n\n");
    }
    output.push_str("[features]\ndefault = []\n\n[dependencies]\n");
    let mut dependencies = BTreeMap::new();
    for package in packages.iter().filter(|package| package.direct) {
        dependencies.insert(
            package.package.clone(),
            (package.path.clone(), BTreeSet::new()),
        );
    }
    for component in &resolution.selected_components {
        let spec = &catalog.components[component];
        dependencies
            .entry(spec.package.clone())
            .and_modify(|(_, features)| features.extend(spec.cargo_features.iter().cloned()));
    }
    for (package, (path, features)) in dependencies {
        let source_path = format!("sources/{path}");
        output.push_str(&format!(
            "{package} = {{ version = \"0.1.0\", path = {source_path:?}, default-features = false"
        ));
        if !features.is_empty() {
            let values = features
                .iter()
                .map(|value| format!("{value:?}"))
                .collect::<Vec<_>>()
                .join(", ");
            output.push_str(&format!(", features = [{values}]"));
        }
        output.push_str(" }\n");
    }
    if build_kind == BuildKind::Wasm {
        output.push_str(&format!(
            "wasm-bindgen = {{ version = \"={}\", default-features = false, features = [\"std\"] }}\nwasm-bindgen-futures = {{ version = \"={}\", default-features = false, features = [\"std\"] }}\n",
            crate::WASM_BINDGEN_PROTOCOL_VERSION,
            crate::WASM_BINDGEN_FUTURES_VERSION,
        ));
    }
    output
}

fn generate_cargo_config(
    target: &Target,
    custom_target_spec: Option<&CustomTargetSpecRecord>,
) -> String {
    let cargo_target_input =
        custom_target_spec.map_or(target.triple.as_str(), |spec| spec.snapshot_path.as_str());
    format!("[build]\ntarget = {cargo_target_input:?}\n\n[net]\noffline = true\n")
}

fn generate_lib_rs(
    catalog: &NormalizedCatalog,
    resolution: &crate::resolver::Resolution,
    build_kind: BuildKind,
    catalog_digest: &str,
) -> Result<String, ComposeError> {
    let adapter = &catalog.runtime_adapters[&resolution.runtime_adapter];
    let mut output = String::from(
        "#![forbid(unsafe_code)]\n\nmod identity;\n\npub use identity::COMPOSITION_HASH;\npub use rust_agent_fixture_api::FixtureApp;\npub use rust_agent_runtime_api::{AppHandoffError, AppHandoffMode, BuildError, RuntimePrimitives};\n",
    );
    if build_kind == BuildKind::Wasm {
        output.push_str("mod wasm;\npub use wasm::start;\n");
    }
    output.push_str(&format!(
        "pub use {} as create_runtime_primitives;\n\n",
        adapter.constructor
    ));
    output.push_str(&format!(
        "pub const CATALOG_DIGEST: &str = {catalog_digest:?};\n\n"
    ));

    let file_components = resolution
        .construction_order
        .iter()
        .map(|id| &catalog.components[id])
        .filter(|component| component.config_source == ConfigSource::File)
        .collect::<Vec<_>>();
    let host_components = resolution
        .construction_order
        .iter()
        .map(|id| &catalog.components[id])
        .filter(|component| component.config_source == ConfigSource::Host)
        .collect::<Vec<_>>();

    if !host_components.is_empty() {
        output.push_str("pub mod host_api {\n");
        for component in &host_components {
            let module = rust_ident(&component.id);
            let host_api = component.host_api.as_ref().ok_or_else(|| {
                ComposeError::UnsupportedPhase1A(format!(
                    "host-source component {} has no host-api",
                    component.id
                ))
            })?;
            output.push_str(&format!(
                "    pub mod {module} {{ pub use {host_api}::*; }}\n"
            ));
        }
        output.push_str("}\n\n");
    }

    if file_components.is_empty() {
        output.push_str("#[derive(Default)]\n");
    }
    output.push_str("pub struct RuntimeConfig {\n");
    for component in &file_components {
        let field = rust_ident(component.config_key.as_deref().ok_or_else(|| {
            ComposeError::UnsupportedPhase1A(format!(
                "file-source component {} has no config-key",
                component.id
            ))
        })?);
        output.push_str(&format!("    pub {field}: {},\n", component.config_type));
    }
    output.push_str("}\n\n");

    if host_components.is_empty() {
        output.push_str("#[derive(Default)]\n");
    }
    output.push_str("pub struct HostBindings {\n");
    for component in &host_components {
        let field = rust_ident(component.config_key.as_deref().ok_or_else(|| {
            ComposeError::UnsupportedPhase1A(format!(
                "host-source component {} has no config-key",
                component.id
            ))
        })?);
        let module = rust_ident(&component.id);
        output.push_str(&format!("    {field}: host_api::{module}::Config,\n"));
    }
    output.push_str("}\n\n");

    output.push_str(
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub enum HostBindingsError {\n    DuplicateField(&'static str),\n    MissingField(&'static str),\n}\n\nimpl std::fmt::Display for HostBindingsError {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        match self {\n            Self::DuplicateField(field) => write!(formatter, \"duplicate Host binding `{field}`\"),\n            Self::MissingField(field) => write!(formatter, \"missing Host binding `{field}`\"),\n        }\n    }\n}\n\nimpl std::error::Error for HostBindingsError {}\n\n",
    );
    output.push_str("pub struct HostBindingsBuilder {\n");
    for component in &host_components {
        let field = rust_ident(component.config_key.as_deref().ok_or_else(|| {
            ComposeError::UnsupportedPhase1A(format!(
                "host-source component {} has no config-key",
                component.id
            ))
        })?);
        let module = rust_ident(&component.id);
        output.push_str(&format!(
            "    {field}: Option<host_api::{module}::Config>,\n"
        ));
    }
    output.push_str(
        "}\n\nimpl Default for HostBindingsBuilder {\n    fn default() -> Self {\n        Self {\n",
    );
    for component in &host_components {
        let field = rust_ident(component.config_key.as_deref().ok_or_else(|| {
            ComposeError::UnsupportedPhase1A(format!(
                "host-source component {} has no config-key",
                component.id
            ))
        })?);
        output.push_str(&format!("            {field}: None,\n"));
    }
    output.push_str("        }\n    }\n}\n\nimpl HostBindingsBuilder {\n    pub fn new() -> Self {\n        Self::default()\n    }\n\n");
    for component in &host_components {
        let key = component.config_key.as_deref().ok_or_else(|| {
            ComposeError::UnsupportedPhase1A(format!(
                "host-source component {} has no config-key",
                component.id
            ))
        })?;
        let field = rust_ident(key);
        let module = rust_ident(&component.id);
        output.push_str(&format!(
            "    pub fn set_{field}(&mut self, value: host_api::{module}::Config) -> Result<&mut Self, HostBindingsError> {{\n        if self.{field}.is_some() {{\n            return Err(HostBindingsError::DuplicateField({key:?}));\n        }}\n        self.{field} = Some(value);\n        Ok(self)\n    }}\n\n"
        ));
    }
    output.push_str("    pub fn build(self) -> Result<HostBindings, HostBindingsError> {\n        Ok(HostBindings {\n");
    for component in &host_components {
        let key = component.config_key.as_deref().ok_or_else(|| {
            ComposeError::UnsupportedPhase1A(format!(
                "host-source component {} has no config-key",
                component.id
            ))
        })?;
        let field = rust_ident(key);
        output.push_str(&format!(
            "            {field}: self.{field}.ok_or(HostBindingsError::MissingField({key:?}))?,\n"
        ));
    }
    output.push_str("        })\n    }\n}\n\n");

    output.push_str("pub fn build(runtime_config: RuntimeConfig, host_bindings: HostBindings, runtime: RuntimePrimitives) -> Result<rust_agent_fixture_api::FixtureApp, BuildError> {\n");
    output.push_str(&format!(
        "    if runtime.adapter().as_str() != {:?} {{\n        return Err(BuildError::InvalidComposition(\"runtime adapter identity mismatch\"));\n    }}\n",
        adapter.id
    ));
    if file_components.is_empty() {
        output.push_str("    let _ = runtime_config;\n");
    }
    if host_components.is_empty() {
        output.push_str("    let _ = host_bindings;\n");
    }
    output.push_str("    let shared_host_fields = vec![\n");
    for component_id in &resolution.construction_order {
        let component = &catalog.components[component_id];
        let Some(AppCoexistence::ConcurrentSharedHostHandle {
            host_config_fields, ..
        }) = &component.app_coexistence
        else {
            continue;
        };
        let config_field = rust_ident(component.config_key.as_deref().ok_or_else(|| {
            ComposeError::UnsupportedPhase1A(format!(
                "shared-host component {} has no config-key",
                component.id
            ))
        })?);
        for path in host_config_fields {
            let (_, field) = path.split_once('.').ok_or_else(|| {
                ComposeError::UnsupportedPhase1A(format!(
                    "shared-host field {path} is not component-qualified"
                ))
            })?;
            output.push_str(&format!(
                "        rust_agent_runtime_api::seal_shared_host_handle({path:?}, &host_bindings.{config_field}.{field})?,\n"
            ));
        }
    }
    output.push_str("    ];\n");
    let handoff_mode = match resolution.app_handoff {
        crate::resolver::AppHandoff::Concurrent => {
            "rust_agent_runtime_api::AppHandoffMode::Concurrent"
        }
        crate::resolver::AppHandoff::StopOldApp => {
            "rust_agent_runtime_api::AppHandoffMode::StopOldApp"
        }
    };
    output.push_str(&format!(
        "    let handoff = rust_agent_runtime_api::AppHandoffSeal::new(\n        {handoff_mode},\n        COMPOSITION_HASH,\n        CATALOG_DIGEST,\n        shared_host_fields,\n    )?;\n"
    ));

    let mut binding_variables: BTreeMap<(String, Option<String>, String), String> = BTreeMap::new();
    for component_id in &resolution.construction_order {
        let component = &catalog.components[component_id];
        let component_var = rust_ident(component_id);
        let config_expression = match component.config_source {
            ConfigSource::None => "Default::default()".to_owned(),
            ConfigSource::File => format!(
                "runtime_config.{}",
                rust_ident(component.config_key.as_deref().ok_or_else(|| {
                    ComposeError::UnsupportedPhase1A(format!(
                        "file-source component {} has no config-key",
                        component.id
                    ))
                })?)
            ),
            ConfigSource::Host => format!(
                "host_bindings.{}",
                rust_ident(component.config_key.as_deref().ok_or_else(|| {
                    ComposeError::UnsupportedPhase1A(format!(
                        "host-source component {} has no config-key",
                        component.id
                    ))
                })?)
            ),
        };
        output.push_str(&format!(
            "    let {component_var}_config: {} = {config_expression};\n",
            component.config_type
        ));
        output.push_str(&format!(
            "    let {component_var}_dependencies = {} {{",
            component.dependencies_type
        ));
        if component.requires.is_empty() {
            output.push_str("};\n");
        } else {
            output.push('\n');
            for requirement in &component.requires {
                let binding = resolution
                    .bindings
                    .iter()
                    .find(|binding| {
                        binding.consumer == component.id
                            && binding.field == requirement.field
                            && binding.capability == requirement.capability
                    })
                    .ok_or_else(|| {
                        ComposeError::UnsupportedPhase1A(format!(
                            "generated fixture cannot materialize optional unresolved field {}.{}",
                            component.id, requirement.field
                        ))
                    })?;
                let variable = binding_variables
                    .get(&(
                        binding.capability.clone(),
                        binding.key.clone(),
                        binding.provider.clone(),
                    ))
                    .ok_or_else(|| {
                        ComposeError::UnsupportedPhase1A(format!(
                            "provider binding for {} was not constructed before {}",
                            binding.capability, component.id
                        ))
                    })?;
                output.push_str(&format!(
                    "        {}: {variable}.clone(),\n",
                    requirement.field
                ));
            }
            output.push_str("    };\n");
        }
        output.push_str(&format!(
            "    let {component_var}_output = {}(\n        &{component_var}_config,\n        {component_var}_dependencies,\n        rust_agent_runtime_api::RuntimePrimitiveBindings::none(),\n    )?;\n",
            component.factory
        ));
        for provide in &component.provides {
            let capability = &catalog.capabilities[&provide.capability];
            let variable = format!(
                "binding_{}_{}",
                rust_ident(
                    provide
                        .capability
                        .strip_prefix("cap:")
                        .unwrap_or(&provide.capability)
                ),
                component_var
            );
            output.push_str(&format!(
                "    let {variable}: {} = {}({component_var}_output.service().clone());\n",
                capability.binding_type, capability.binding_adapter
            ));
            binding_variables.insert(
                (
                    provide.capability.clone(),
                    provide.key.clone(),
                    component.id.clone(),
                ),
                variable,
            );
        }
    }
    let driver = binding_variables
        .iter()
        .find(|((capability, _, _), _)| capability == "cap:driver")
        .map(|(_, variable)| variable)
        .ok_or_else(|| {
            ComposeError::UnsupportedPhase1A("fixture composition needs cap:driver".into())
        })?;
    let file_reader = binding_variables
        .iter()
        .find(|((capability, _, _), _)| capability == "cap:fs-read")
        .map_or_else(
            || "None".to_owned(),
            |(_, variable)| format!("Some({variable})"),
        );
    output.push_str(&format!(
        "    Ok(rust_agent_fixture_api::FixtureApp::new({driver}, {file_reader}, handoff))\n}}\n\n"
    ));
    if file_components.is_empty() && host_components.is_empty() {
        output.push_str(
            "#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn generated_factory_graph_executes() {\n        let runtime = create_runtime_primitives().unwrap();\n        let app = build(RuntimeConfig::default(), HostBindings::default(), runtime).unwrap();\n        assert_eq!(app.run(\"hello\"), \"fixture-response:hello\");\n    }\n}\n",
        );
    }
    Ok(output)
}

fn generate_wasm_rs(
    catalog: &NormalizedCatalog,
    resolution: &crate::resolver::Resolution,
) -> Result<String, ComposeError> {
    let boundary_id = resolution.host_boundary.as_ref().ok_or_else(|| {
        ComposeError::UnsupportedPhase1A("wasm composition requires a Host export".into())
    })?;
    let boundary = &catalog.host_boundaries[boundary_id];
    if boundary.kind != HostBoundaryKind::WasmExport {
        return Err(ComposeError::UnsupportedPhase1A(format!(
            "Host boundary `{boundary_id}` is not a WASM export"
        )));
    }
    let export = boundary.export_module.as_ref().ok_or_else(|| {
        ComposeError::UnsupportedPhase1A(format!(
            "Host boundary `{boundary_id}` has no export module"
        ))
    })?;
    Ok(format!(
        "use {export}::{{JsValue, WasmAppHandle, wasm_bindgen}};\n\n#[wasm_bindgen]\npub async fn start(\n    runtime_config: JsValue,\n    host_bindings: JsValue,\n) -> Result<WasmAppHandle, JsValue> {{\n    if !runtime_config.is_object() || runtime_config.is_null() {{\n        return Err(JsValue::from_str(\"runtime_config must be an object\"));\n    }}\n    if !host_bindings.is_object() || host_bindings.is_null() {{\n        return Err(JsValue::from_str(\"host_bindings must be an object\"));\n    }}\n    let runtime = {export}::runtime_primitives(crate::create_runtime_primitives)\n        .map_err(|error| JsValue::from_str(&error.to_string()))?;\n    let app = crate::build(\n        crate::RuntimeConfig::default(),\n        crate::HostBindings::default(),\n        runtime,\n    )\n        .map_err(|error| JsValue::from_str(&error.to_string()))?;\n    Ok(WasmAppHandle::from_app(app))\n}}\n"
    ))
}

fn generate_lockfile(
    options: &ComposeOptions,
    staging: &Path,
    custom_target_spec: Option<&CustomTargetSpecRecord>,
) -> Result<(), ComposeError> {
    verify_cargo_config_isolation(staging, &staging.join(".cargo/config.toml"))?;
    let custom_snapshot_before = custom_target_spec
        .map(|spec| verify_custom_target_snapshot(spec, &staging.join(&spec.snapshot_path)))
        .transpose()?;
    let cargo_home = staging.with_extension(format!(
        "cargo-home-{}-{}",
        std::process::id(),
        STAGING_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&cargo_home)?;
    link_registry_cache(&cargo_home, options.registry_cache_path.as_deref())?;
    let output = Command::new(&options.cargo_path)
        .args(["generate-lockfile", "--offline", "--manifest-path"])
        .arg(staging.join("Cargo.toml"))
        .arg("--config")
        .arg(staging.join(".cargo/config.toml"))
        .current_dir(staging)
        .env_clear()
        .env("CARGO_HOME", &cargo_home)
        .env("RUSTC", &options.rustc_path)
        .env(
            "PATH",
            options
                .cargo_path
                .parent()
                .unwrap_or_else(|| Path::new("/")),
        )
        .output();
    let custom_snapshot_after = custom_target_spec
        .map(|spec| verify_custom_target_snapshot(spec, &staging.join(&spec.snapshot_path)))
        .transpose();
    let cleanup = fs::remove_dir_all(&cargo_home);
    let custom_snapshot_after = custom_snapshot_after?;
    if let (Some(before), Some(after)) = (&custom_snapshot_before, &custom_snapshot_after) {
        before.ensure_unchanged(after, "Cargo lockfile generation")?;
    }
    cleanup?;
    let output = output?;
    if !output.status.success() {
        return Err(ComposeError::CargoLock(format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

fn locked_cargo_sources(
    lockfile: &Path,
) -> Result<(BTreeMap<String, String>, BTreeSet<String>), ComposeError> {
    let input_bytes =
        read_composition_regular_file_bounded(lockfile, MAX_COMPOSITION_CONTROL_FILE_BYTES, None)?;
    locked_cargo_sources_from_bytes(lockfile, &input_bytes)
}

fn locked_cargo_sources_from_bytes(
    lockfile: &Path,
    input_bytes: &[u8],
) -> Result<(BTreeMap<String, String>, BTreeSet<String>), ComposeError> {
    let input =
        std::str::from_utf8(input_bytes).map_err(|error| ComposeError::ManifestNormalization {
            path: lockfile.display().to_string(),
            message: error.to_string(),
        })?;
    let document: CargoLockDocument =
        toml::from_str(input).map_err(|error| ComposeError::ManifestNormalization {
            path: lockfile.display().to_string(),
            message: error.to_string(),
        })?;
    let mut registries = BTreeMap::new();
    let mut git_sources = BTreeSet::new();
    for source in document.source_projection.sources {
        if source.starts_with("registry+") {
            let id = if source == "registry+https://github.com/rust-lang/crates.io-index" {
                "crates-io".to_owned()
            } else {
                format!("registry-{}", &sha256_hex(source.as_bytes())[..16])
            };
            match registries.get(&id) {
                Some(previous) if previous != &source => {
                    return Err(ComposeError::CargoLock(format!(
                        "registry source id `{id}` is ambiguous"
                    )));
                }
                Some(_) => {}
                None => {
                    registries.insert(id, source);
                }
            }
        } else if source.starts_with("git+") {
            git_sources.insert(source);
        } else {
            return Err(ComposeError::CargoLock(format!(
                "unsupported locked package source `{source}`"
            )));
        }
    }
    Ok((registries, git_sources))
}

#[derive(Deserialize)]
struct CargoLockDocument {
    #[serde(
        default,
        rename = "package",
        deserialize_with = "deserialize_cargo_lock_packages"
    )]
    source_projection: CargoLockSourceProjection,
}

#[derive(Default)]
struct CargoLockSourceProjection {
    sources: BTreeSet<String>,
}

#[derive(Deserialize)]
struct CargoLockPackage {
    #[serde(default)]
    source: Option<String>,
}

fn deserialize_cargo_lock_packages<'de, D>(
    deserializer: D,
) -> Result<CargoLockSourceProjection, D::Error>
where
    D: Deserializer<'de>,
{
    struct CargoLockPackagesVisitor;

    impl<'de> Visitor<'de> for CargoLockPackagesVisitor {
        type Value = CargoLockSourceProjection;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_CARGO_LOCK_PACKAGES} Cargo.lock packages and {MAX_CARGO_SOURCE_IDENTITIES} distinct source identities"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|hint| hint > MAX_CARGO_LOCK_PACKAGES)
            {
                return Err(de::Error::custom(format!(
                    "Cargo.lock packages has more than {MAX_CARGO_LOCK_PACKAGES} entries"
                )));
            }
            let mut package_count = 0_usize;
            let mut sources = BTreeSet::new();
            loop {
                if package_count == MAX_CARGO_LOCK_PACKAGES {
                    return match sequence.next_element::<de::IgnoredAny>()? {
                        Some(_) => Err(de::Error::custom(format!(
                            "Cargo.lock packages has more than {MAX_CARGO_LOCK_PACKAGES} entries"
                        ))),
                        None => Ok(CargoLockSourceProjection { sources }),
                    };
                }
                let Some(package) = sequence.next_element::<CargoLockPackage>()? else {
                    return Ok(CargoLockSourceProjection { sources });
                };
                package_count += 1;
                let Some(source) = package.source else {
                    continue;
                };
                if !sources.contains(&source) {
                    if sources.len() == MAX_CARGO_SOURCE_IDENTITIES {
                        return Err(de::Error::custom(format!(
                            "Cargo.lock source identities has more than {MAX_CARGO_SOURCE_IDENTITIES} entries"
                        )));
                    }
                    sources.insert(source);
                }
            }
        }
    }

    deserializer.deserialize_seq(CargoLockPackagesVisitor)
}

fn generated_file_records(
    staging: &Path,
    paths: &[&str],
) -> Result<Vec<GeneratedFileRecord>, ComposeError> {
    let mut records = Vec::new();
    for path in paths {
        let (digest, bytes) = hash_composition_regular_file_bounded(
            &staging.join(path),
            MAX_COMPOSITION_CONTROL_FILE_BYTES,
            None,
        )?;
        records.push(GeneratedFileRecord {
            path: (*path).to_owned(),
            digest,
            bytes,
        });
    }
    records.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(records)
}

fn validate_options(options: &ComposeOptions) -> Result<(), ComposeError> {
    for path in [
        &options.workspace_root,
        &options.profile_path,
        &options.catalog_trust_policy_path,
        &options.output_root,
        &options.rustc_path,
        &options.cargo_path,
    ] {
        if !path.is_absolute() {
            return Err(ComposeError::NonAbsolutePath(path.display().to_string()));
        }
    }
    if let Some(path) = &options.custom_target_spec_path
        && !path.is_absolute()
    {
        return Err(ComposeError::NonAbsolutePath(path.display().to_string()));
    }
    if let Some(cache) = &options.registry_cache_path
        && (!cache.is_absolute() || !cache.is_dir())
    {
        return Err(ComposeError::InvalidRegistryCache(
            cache.display().to_string(),
        ));
    }
    Ok(())
}

#[cfg(any(unix, windows))]
fn link_registry_cache(cargo_home: &Path, cache: Option<&Path>) -> Result<(), ComposeError> {
    let Some(cache) = cache else {
        return Ok(());
    };
    let destination = cargo_home.join("registry");
    #[cfg(unix)]
    std::os::unix::fs::symlink(cache, destination)?;
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(cache, destination)?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn link_registry_cache(_cargo_home: &Path, _cache: Option<&Path>) -> Result<(), ComposeError> {
    Ok(())
}

fn read_workspace_input(
    workspace: &Path,
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, ComposeError> {
    let (canonical_path, before_metadata) = resolve_workspace_input(workspace, path)?;
    let before_identity = workspace_input_identity(&before_metadata);
    let maximum_bytes = u64::try_from(maximum).unwrap_or(u64::MAX);
    if before_metadata.len() > maximum_bytes {
        return Err(ComposeError::InputTooLarge {
            path: path.display().to_string(),
            actual: before_metadata.len(),
            maximum: maximum_bytes,
        });
    }
    let mut file = File::open(&canonical_path)?;
    ensure_workspace_input_identity(path, &before_identity, &file.metadata()?)?;
    let bytes = read_bounded_workspace_input(&mut file, path, maximum, maximum_bytes)?;
    ensure_workspace_input_identity(path, &before_identity, &file.metadata()?)?;

    let (path_after, path_after_metadata) = resolve_workspace_input(workspace, path)?;
    if path_after != canonical_path {
        return Err(ComposeError::Verification(format!(
            "workspace input `{}` changed its resolved path while reading",
            path.display()
        )));
    }
    ensure_workspace_input_identity(path, &before_identity, &path_after_metadata)?;

    let mut reopened = File::open(&path_after)?;
    ensure_workspace_input_identity(path, &before_identity, &reopened.metadata()?)?;
    let reopened_bytes = read_bounded_workspace_input(&mut reopened, path, maximum, maximum_bytes)?;
    ensure_workspace_input_identity(path, &before_identity, &reopened.metadata()?)?;
    if reopened_bytes != bytes {
        return Err(ComposeError::Verification(format!(
            "workspace input `{}` changed while reading",
            path.display()
        )));
    }
    let (final_path, final_metadata) = resolve_workspace_input(workspace, path)?;
    if final_path != canonical_path {
        return Err(ComposeError::Verification(format!(
            "workspace input `{}` changed its resolved path while reading",
            path.display()
        )));
    }
    ensure_workspace_input_identity(path, &before_identity, &final_metadata)?;
    Ok(bytes)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkspaceInputIdentity {
    bytes: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
}

fn resolve_workspace_input(
    workspace: &Path,
    path: &Path,
) -> Result<(PathBuf, fs::Metadata), ComposeError> {
    let canonical_workspace = workspace.canonicalize()?;
    let relative = path
        .strip_prefix(&canonical_workspace)
        .map_err(|_| ComposeError::InputOutsideWorkspace(path.display().to_string()))?;
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err(ComposeError::InputOutsideWorkspace(
            path.display().to_string(),
        ));
    }

    let mut current = canonical_workspace.clone();
    let component_count = relative.components().count();
    let mut final_metadata = None;
    for (index, component) in relative.components().enumerate() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            return Err(ComposeError::UnsupportedSourceEntry(
                current.display().to_string(),
            ));
        }
        let is_final = index + 1 == component_count;
        if (is_final && !metadata.is_file()) || (!is_final && !metadata.is_dir()) {
            return Err(ComposeError::UnsupportedSourceEntry(
                current.display().to_string(),
            ));
        }
        if is_final {
            final_metadata = Some(metadata);
        }
    }
    let canonical_path = current.canonicalize()?;
    if !canonical_path.starts_with(&canonical_workspace) {
        return Err(ComposeError::InputOutsideWorkspace(
            path.display().to_string(),
        ));
    }
    Ok((
        canonical_path,
        final_metadata.expect("a non-empty relative path has a final component"),
    ))
}

fn workspace_input_identity(metadata: &fs::Metadata) -> WorkspaceInputIdentity {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt as _;

    WorkspaceInputIdentity {
        bytes: metadata.len(),
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        changed_seconds: metadata.ctime(),
        #[cfg(unix)]
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

fn ensure_workspace_input_identity(
    path: &Path,
    expected: &WorkspaceInputIdentity,
    metadata: &fs::Metadata,
) -> Result<(), ComposeError> {
    if !metadata.is_file() || workspace_input_identity(metadata) != *expected {
        return Err(ComposeError::Verification(format!(
            "workspace input `{}` changed while reading",
            path.display()
        )));
    }
    Ok(())
}

fn read_bounded_workspace_input(
    file: &mut File,
    path: &Path,
    maximum: usize,
    maximum_bytes: u64,
) -> Result<Vec<u8>, ComposeError> {
    let mut reader = BufReader::new(file).take(maximum_bytes.saturating_add(1));
    let mut bytes = Vec::with_capacity(maximum.min(8 * 1024));
    reader.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(ComposeError::InputTooLarge {
            path: path.display().to_string(),
            actual: bytes.len() as u64,
            maximum: maximum_bytes,
        });
    }
    Ok(bytes)
}

fn unique_staging(output_root: &Path) -> PathBuf {
    output_root.join(format!(
        ".staging-{}-{}",
        std::process::id(),
        STAGING_COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

fn remove_staging_tree(path: &Path) -> io::Result<()> {
    make_staging_tree_owner_writable(path)?;
    fs::remove_dir_all(path)
}

fn make_staging_tree_owner_writable(root: &Path) -> io::Result<()> {
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        let mut permissions = metadata.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let owner_access = if metadata.is_dir() { 0o700 } else { 0o600 };
            permissions.set_mode(permissions.mode() | owner_access);
        }
        #[cfg(not(unix))]
        permissions.set_readonly(false);
        fs::set_permissions(entry.path(), permissions)?;
    }
    Ok(())
}

fn write_text(path: &Path, value: &str) -> Result<(), ComposeError> {
    debug_assert!(value.ends_with('\n'));
    fs::write(path, value.as_bytes())?;
    Ok(())
}

fn canonical_target_facts_bytes(record: &TargetFactsRecord) -> Result<Vec<u8>, ComposeError> {
    record.validate()?;
    let bytes = canonical::jcs_bytes(record)?;
    if bytes.len() > MAX_CANONICAL_TARGET_FACTS_RECORD_BYTES {
        return Err(ComposeError::Target(
            TargetError::TargetFactsRecordTooLarge {
                actual: bytes.len(),
                maximum: MAX_CANONICAL_TARGET_FACTS_RECORD_BYTES,
            },
        ));
    }
    Ok(bytes)
}

fn write_canonical_target_facts(
    path: &Path,
    record: &TargetFactsRecord,
) -> Result<(), ComposeError> {
    fs::write(path, canonical_target_facts_bytes(record)?)?;
    Ok(())
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), ComposeError> {
    let bytes = deterministic_json_bytes(value)?;
    if bytes.len() as u64 > MAX_COMPOSITION_CONTROL_FILE_BYTES {
        return Err(ComposeError::Verification(format!(
            "composition control file `{}` has {} bytes; maximum is {MAX_COMPOSITION_CONTROL_FILE_BYTES}",
            path.display(),
            bytes.len()
        )));
    }
    fs::write(path, bytes)?;
    Ok(())
}

fn file_digest(path: &Path) -> Result<String, ComposeError> {
    Ok(hash_composition_regular_file_bounded(path, MAX_COMPOSITION_CONTROL_FILE_BYTES, None)?.0)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn rust_ident(value: &str) -> String {
    value.replace(['-', ':'], "_")
}

#[cfg(test)]
mod tests {
    use std::{env, ffi::OsString, process::Command};

    use tempfile::TempDir;

    use super::*;

    fn tool(name: &str) -> PathBuf {
        let selected = Command::new("rustup")
            .args(["which", name])
            .output()
            .expect("rustup must resolve the selected test toolchain");
        if selected.status.success() {
            return PathBuf::from(String::from_utf8(selected.stdout).unwrap().trim())
                .canonicalize()
                .unwrap();
        }
        let path = env::var_os("PATH").unwrap_or_else(|| OsString::from(""));
        env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
            .unwrap()
            .canonicalize()
            .unwrap()
    }

    fn options(temp: &TempDir, profile: &str) -> ComposeOptions {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        ComposeOptions {
            profile_path: root.join(profile),
            catalog_trust_policy_path: root.join("tests/fixtures/catalog-trust.toml"),
            output_root: temp.path().join("compositions"),
            rustc_path: tool("rustc"),
            cargo_path: tool("cargo"),
            registry_cache_path: None,
            custom_target_spec_path: None,
            workspace_root: root,
        }
    }

    fn reseal_manifest(path: &Path, manifest: &mut CompositionManifest) -> PathBuf {
        let payload = CompositionIdentityPayload {
            schema: 1,
            profile: &manifest.normalized_profile,
            target: &manifest.normalized_target,
            target_facts: &manifest.target_facts,
            compose_rustc: &manifest.compose_rustc,
            generator_inputs: &manifest.generator_inputs,
            custom_target_spec: manifest.custom_target_spec.as_ref(),
            resolution: &manifest.resolution,
            component_runtime_effects: &manifest.component_runtime_effects,
            host_runtime_effects: &manifest.host_runtime_effects,
            direct_root_build_requirements: &manifest.direct_root_build_requirements,
            sources: &manifest.sources,
            generated_files: &manifest.generated_files,
            cargo_lock_digest: &manifest.cargo_lock_digest,
            cargo_resolution: &manifest.cargo_resolution,
        };
        manifest.composition_hash =
            hex::encode(canonical::domain_hash(b"rust-agent-composition-v1\0", &payload).unwrap());
        write_text(
            &path.join("src/identity.rs"),
            &format!(
                "pub const COMPOSITION_HASH: &str = {:?};\n",
                manifest.composition_hash
            ),
        )
        .unwrap();
        write_json(
            &path.join("rust-agent-security.json"),
            &SecurityManifest {
                schema: 1,
                composition_hash: manifest.composition_hash.clone(),
                component_runtime_effects: manifest.component_runtime_effects.clone(),
                host_runtime_effects: manifest.host_runtime_effects.clone(),
                compiled_runtime_effects: manifest.compiled_runtime_effects.clone(),
                build_requirements: manifest.build_requirements.clone(),
            },
        )
        .unwrap();
        write_json(&path.join("rust-agent-composition.json"), manifest).unwrap();
        let resealed_path = path.parent().unwrap().join(&manifest.composition_hash);
        fs::rename(path, &resealed_path).unwrap();
        resealed_path
    }

    fn reseal_with_cargo_resolution_bytes(
        path: &Path,
        manifest: &mut CompositionManifest,
        cargo_resolution_bytes: &[u8],
    ) -> PathBuf {
        fs::write(path.join("cargo-resolution.json"), cargo_resolution_bytes).unwrap();
        manifest.cargo_resolution_digest = sha256_hex(cargo_resolution_bytes);
        let generated_record = manifest
            .generated_files
            .iter_mut()
            .find(|record| record.path == "cargo-resolution.json")
            .unwrap();
        generated_record.digest = sha256_hex(cargo_resolution_bytes);
        generated_record.bytes = cargo_resolution_bytes.len() as u64;
        reseal_manifest(path, manifest)
    }

    fn registry_cache() -> PathBuf {
        let cargo_home = env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
            .expect("Cargo home must be discoverable");
        cargo_home.join("registry").canonicalize().unwrap()
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, source: &str) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, source).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    fn write_fake_rustc(temp: &Path, body: &str) -> (PathBuf, PathBuf) {
        let sysroot = temp.join("fake-toolchain");
        let rustc = sysroot.join("bin/rustc");
        let real_rustc = tool("rustc");
        fs::create_dir_all(sysroot.join("bin")).unwrap();
        fs::create_dir_all(sysroot.join("lib/rustlib/fixture/lib")).unwrap();
        fs::write(
            sysroot.join("lib/rustlib/fixture/lib/libcore-fixture.rlib"),
            b"fixture-sysroot-v1",
        )
        .unwrap();
        write_executable(
            &rustc,
            &format!(
                concat!(
                    "#!/bin/sh\n",
                    "if [ \"$1\" = -vV ]; then exec {:?} \"$@\"; fi\n",
                    "if [ \"$1 $2\" = \"--print sysroot\" ]; then printf '%s\\n' {:?}; exit 0; fi\n",
                    "{}\n"
                ),
                real_rustc,
                sysroot.display().to_string(),
                body,
            ),
        );
        (rustc, sysroot)
    }

    #[cfg(unix)]
    fn custom_target_tools(temp: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let cargo = temp.join("fake-cargo");
        let rustc_log = temp.join("rustc-args.log");
        let real_cargo = tool("cargo");
        let (rustc, _) = write_fake_rustc(
            temp,
            &format!(
                concat!(
                    "IFS= read -r observed < \"$4\"\n",
                    "[ -n \"$observed\" ] || exit 41\n",
                    "printf 'rustc-args:%s\\nrustc-spec:%s\\n' \"$*\" \"$observed\" >> {:?}\n",
                    "printf '%s\\n' 'panic=\"unwind\"' 'target_abi=\"\"' ",
                    "'target_arch=\"x86_64\"' 'target_endian=\"little\"' ",
                    "'target_env=\"gnu\"' 'target_family=\"unix\"' ",
                    "'target_os=\"linux\"' 'target_pointer_width=\"64\"' ",
                    "'target_vendor=\"unknown\"' 'unix'"
                ),
                rustc_log,
            ),
        );
        write_executable(
            &cargo,
            &format!(
                concat!(
                    "#!/bin/sh\n",
                    "if [ \"$1\" = metadata ]; then exec {:?} \"$@\"; fi\n",
                    "manifest=\nconfig=\nnext=\n",
                    "for arg in \"$@\"; do\n",
                    "  if [ \"$next\" = manifest ]; then manifest=\"$arg\"; next=; continue; fi\n",
                    "  if [ \"$next\" = config ]; then config=\"$arg\"; next=; continue; fi\n",
                    "  if [ \"$arg\" = \"--manifest-path\" ]; then next=manifest; fi\n",
                    "  if [ \"$arg\" = \"--config\" ]; then next=config; fi\n",
                    "done\n",
                    "[ -n \"$manifest\" ] && [ -n \"$config\" ] || exit 31\n",
                    "found=0\n",
                    "while IFS= read -r line; do\n",
                    "  [ \"$line\" = 'target = \"targets/x86_64-unknown-linux-gnu.json\"' ] && found=1\n",
                    "done < \"$config\"\n",
                    "[ \"$found\" = 1 ] || exit 32\n",
                    "snapshot=\"${{manifest%/*}}/targets/x86_64-unknown-linux-gnu.json\"\n",
                    "IFS= read -r observed < \"$snapshot\"\n",
                    "[ -n \"$observed\" ] || exit 34\n",
                    "printf 'cargo-spec:%s\\n' \"$observed\" >> {:?}\n",
                    "printf '# generated by bounded custom-target fixture\\nversion = 4\\n' ",
                    "> \"${{manifest%/*}}/Cargo.lock\"\n"
                ),
                real_cargo, rustc_log,
            ),
        );
        (rustc, cargo, rustc_log)
    }

    #[cfg(unix)]
    fn custom_target_options(
        workspace_root: &Path,
        temp: &Path,
        spec: &Path,
        output: &str,
    ) -> (ComposeOptions, PathBuf) {
        let (rustc, cargo, rustc_log) = custom_target_tools(temp);
        (
            ComposeOptions {
                workspace_root: workspace_root.to_owned(),
                profile_path: workspace_root.join("tests/fixtures/profiles/minimal.toml"),
                catalog_trust_policy_path: workspace_root.join("tests/fixtures/catalog-trust.toml"),
                output_root: temp.join(output),
                rustc_path: rustc,
                cargo_path: cargo,
                registry_cache_path: None,
                custom_target_spec_path: Some(spec.to_owned()),
            },
            rustc_log,
        )
    }

    #[cfg(unix)]
    #[test]
    fn custom_target_spec_snapshot_binds_raw_and_canonical_identity() {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        fs::create_dir_all(workspace.join("target/custom-target-tests")).unwrap();
        let temp = TempDir::new_in(workspace.join("target/custom-target-tests")).unwrap();
        let compact_path = temp.path().join("compact.json");
        let spaced_path = temp.path().join("spaced.json");
        let compact = br#"{"arch":"x86_64","target-pointer-width":"64"}"#;
        let spaced = br#"{ "target-pointer-width": "64", "arch": "x86_64" }"#;
        fs::write(&compact_path, compact).unwrap();
        fs::write(&spaced_path, spaced).unwrap();

        let (compact_options, rustc_log) =
            custom_target_options(&workspace, temp.path(), &compact_path, "compact-output");
        let compact_generated = compose(&compact_options).unwrap();
        let compact_record = compact_generated
            .manifest
            .custom_target_spec
            .as_ref()
            .unwrap();
        assert_eq!(
            fs::read(compact_generated.path.join(&compact_record.snapshot_path)).unwrap(),
            compact
        );
        assert_eq!(
            compact_generated
                .manifest
                .normalized_target
                .custom_target_spec_digest
                .as_deref(),
            Some(compact_record.custom_target_spec_digest.as_str())
        );
        assert_eq!(
            compact_generated
                .manifest
                .cargo_resolution
                .cargo_target_input,
            compact_record.snapshot_path
        );
        assert_eq!(
            fs::read_to_string(compact_generated.path.join(".cargo/config.toml")).unwrap(),
            format!(
                "[build]\ntarget = {:?}\n\n[net]\noffline = true\n",
                compact_record.snapshot_path
            )
        );
        let invocation = fs::read_to_string(&rustc_log).unwrap();
        assert!(invocation.contains("rustc-args:--print cfg --target"));
        assert!(invocation.contains(".staging-"));
        assert!(invocation.contains("/targets/x86_64-unknown-linux-gnu.json"));
        assert!(invocation.contains(&format!("rustc-spec:{}", String::from_utf8_lossy(compact))));
        assert!(invocation.contains(&format!("cargo-spec:{}", String::from_utf8_lossy(compact))));

        fs::remove_file(&compact_path).unwrap();
        verify_composition(&compact_generated.path).unwrap();

        let (spaced_options, _) =
            custom_target_options(&workspace, temp.path(), &spaced_path, "spaced-output");
        let spaced_generated = compose(&spaced_options).unwrap();
        let spaced_record = spaced_generated
            .manifest
            .custom_target_spec
            .as_ref()
            .unwrap();
        assert_ne!(
            compact_record.raw_bytes_sha256,
            spaced_record.raw_bytes_sha256
        );
        assert_eq!(
            compact_record.canonical_json_sha256,
            spaced_record.canonical_json_sha256
        );
        assert_ne!(
            compact_record.custom_target_spec_digest,
            spaced_record.custom_target_spec_digest
        );
        assert_ne!(
            compact_generated.composition_hash,
            spaced_generated.composition_hash
        );
    }

    #[cfg(unix)]
    #[test]
    fn invalid_custom_target_inputs_fail_before_rustc_or_cargo() {
        use std::os::unix::fs::symlink;

        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        fs::create_dir_all(workspace.join("target/custom-target-tests")).unwrap();
        let temp = TempDir::new_in(workspace.join("target/custom-target-tests")).unwrap();
        let invalid = [
            (
                "duplicate.json",
                br#"{"arch":"x86_64","arch":"aarch64"}"#.as_slice(),
            ),
            ("float.json", br#"{"number":1.25}"#.as_slice()),
            ("nonobject.json", br"[]".as_slice()),
        ];
        for (index, (name, bytes)) in invalid.into_iter().enumerate() {
            let path = temp.path().join(name);
            fs::write(&path, bytes).unwrap();
            let (options, rustc_log) =
                custom_target_options(&workspace, temp.path(), &path, &format!("invalid-{index}"));
            assert!(matches!(
                compose(&options),
                Err(ComposeError::CustomTargetSpec(_))
            ));
            assert!(!rustc_log.exists());
            assert!(!options.output_root.exists());
        }

        let oversized = temp.path().join("oversized.json");
        File::create(&oversized)
            .unwrap()
            .set_len(MAX_CUSTOM_TARGET_SPEC_BYTES + 1)
            .unwrap();
        let (options, rustc_log) =
            custom_target_options(&workspace, temp.path(), &oversized, "oversized-output");
        assert!(matches!(
            compose(&options),
            Err(ComposeError::CustomTargetSpec(
                CustomTargetSpecError::TooLarge { .. }
            ))
        ));
        assert!(!rustc_log.exists());

        let outside = TempDir::new().unwrap();
        let outside_spec = outside.path().join("outside.json");
        fs::write(&outside_spec, b"{}").unwrap();
        let (options, rustc_log) =
            custom_target_options(&workspace, temp.path(), &outside_spec, "outside-output");
        assert!(matches!(
            compose(&options),
            Err(ComposeError::InputOutsideWorkspace(_))
        ));
        assert!(!rustc_log.exists());

        let real = temp.path().join("real.json");
        let link = temp.path().join("link.json");
        fs::write(&real, b"{}").unwrap();
        symlink(&real, &link).unwrap();
        let (options, rustc_log) =
            custom_target_options(&workspace, temp.path(), &link, "symlink-output");
        assert!(matches!(
            compose(&options),
            Err(ComposeError::UnsupportedSourceEntry(_))
        ));
        assert!(!rustc_log.exists());
    }

    #[cfg(unix)]
    #[test]
    fn custom_target_lockfile_prioritizes_snapshot_drift_over_cargo_failure() {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        fs::create_dir_all(workspace.join("target/custom-target-tests")).unwrap();
        let temp = TempDir::new_in(workspace.join("target/custom-target-tests")).unwrap();
        let spec_path = temp.path().join("target.json");
        let cargo_marker = temp.path().join("cargo-started");
        fs::write(&spec_path, br#"{"arch":"x86_64"}"#).unwrap();
        let (options, _) =
            custom_target_options(&workspace, temp.path(), &spec_path, "drift-output");
        write_executable(
            &options.cargo_path,
            &format!(
                concat!(
                    "#!/bin/sh\n",
                    ": > {:?}\n",
                    "printf '{{\"arch\":\"aarch64\"}}' > ",
                    "\"$PWD/targets/x86_64-unknown-linux-gnu.json\"\n",
                    "exit 29\n"
                ),
                cargo_marker,
            ),
        );

        let result = compose(&options);
        assert!(cargo_marker.exists());
        assert!(matches!(
            &result,
            Err(ComposeError::CustomTargetSpec(
                CustomTargetSpecError::SnapshotChanged(_)
                    | CustomTargetSpecError::IdentityMismatch(_)
            ))
        ));
        assert!(fs::read_dir(&options.output_root).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn custom_target_snapshot_and_cargo_config_tampering_fail_verification() {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        fs::create_dir_all(workspace.join("target/custom-target-tests")).unwrap();
        let temp = TempDir::new_in(workspace.join("target/custom-target-tests")).unwrap();
        let spec_path = temp.path().join("target.json");
        fs::write(&spec_path, br#"{"arch":"x86_64"}"#).unwrap();
        let (options, _) =
            custom_target_options(&workspace, temp.path(), &spec_path, "tamper-output");
        let generated = compose(&options).unwrap();
        let record = generated.manifest.custom_target_spec.as_ref().unwrap();
        let snapshot = generated.path.join(&record.snapshot_path);
        let original = fs::read(&snapshot).unwrap();

        fs::write(&snapshot, br#"{"arch":"aarch64"}"#).unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("custom target spec snapshot")
        ));
        fs::write(&snapshot, original).unwrap();

        let manifest_path = generated.path.join("rust-agent-composition.json");
        let original_manifest = fs::read(&manifest_path).unwrap();
        let mut mismatched_logical_target = generated.manifest.clone();
        let mismatched_spec = mismatched_logical_target
            .custom_target_spec
            .as_mut()
            .unwrap();
        mismatched_spec.logical_triple = "other-unknown-none".into();
        mismatched_spec.snapshot_path = "targets/other-unknown-none.json".into();
        write_json(&manifest_path, &mismatched_logical_target).unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("manifest projection")
        ));
        fs::write(&manifest_path, original_manifest).unwrap();

        let forged_config = generate_cargo_config(
            &generated.manifest.normalized_target,
            generated.manifest.custom_target_spec.as_ref(),
        )
        .replace("targets/", "sources/");
        fs::write(
            generated.path.join(".cargo/config.toml"),
            forged_config.as_bytes(),
        )
        .unwrap();
        let mut resealed = generated.manifest.clone();
        let config_record = resealed
            .generated_files
            .iter_mut()
            .find(|file| file.path == ".cargo/config.toml")
            .unwrap();
        config_record.digest = sha256_hex(forged_config.as_bytes());
        config_record.bytes = forged_config.len() as u64;
        let payload = CompositionIdentityPayload {
            schema: 1,
            profile: &resealed.normalized_profile,
            target: &resealed.normalized_target,
            target_facts: &resealed.target_facts,
            compose_rustc: &resealed.compose_rustc,
            generator_inputs: &resealed.generator_inputs,
            custom_target_spec: resealed.custom_target_spec.as_ref(),
            resolution: &resealed.resolution,
            component_runtime_effects: &resealed.component_runtime_effects,
            host_runtime_effects: &resealed.host_runtime_effects,
            direct_root_build_requirements: &resealed.direct_root_build_requirements,
            sources: &resealed.sources,
            generated_files: &resealed.generated_files,
            cargo_lock_digest: &resealed.cargo_lock_digest,
            cargo_resolution: &resealed.cargo_resolution,
        };
        resealed.composition_hash =
            hex::encode(canonical::domain_hash(b"rust-agent-composition-v1\0", &payload).unwrap());
        write_text(
            &generated.path.join("src/identity.rs"),
            &format!(
                "pub const COMPOSITION_HASH: &str = {:?};\n",
                resealed.composition_hash
            ),
        )
        .unwrap();
        write_json(
            &generated.path.join("rust-agent-security.json"),
            &SecurityManifest {
                schema: 1,
                composition_hash: resealed.composition_hash.clone(),
                component_runtime_effects: resealed.component_runtime_effects.clone(),
                host_runtime_effects: resealed.host_runtime_effects.clone(),
                compiled_runtime_effects: resealed.compiled_runtime_effects.clone(),
                build_requirements: resealed.build_requirements.clone(),
            },
        )
        .unwrap();
        write_json(
            &generated.path.join("rust-agent-composition.json"),
            &resealed,
        )
        .unwrap();
        let resealed_path = generated
            .path
            .parent()
            .unwrap()
            .join(&resealed.composition_hash);
        fs::rename(&generated.path, &resealed_path).unwrap();
        let result = verify_composition(&resealed_path);
        assert!(
            matches!(
                result,
                Err(ComposeError::Verification(ref message))
                    if message.contains("Cargo config")
            ),
            "unexpected verification result: {result:?}"
        );
        make_staging_tree_owner_writable(&resealed_path).unwrap();
    }

    fn write_snapshot_fixture(root: &Path, name: &str) -> PathBuf {
        let package = root.join(name);
        fs::create_dir_all(package.join("src")).unwrap();
        fs::write(
            package.join("Cargo.toml"),
            format!(
                "[package]\nname = {name:?}\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"{PINNED_RUST_VERSION}\"\nlicense = \"MIT\"\n"
            ),
        )
        .unwrap();
        fs::write(package.join("src/lib.rs"), b"pub fn fixture() {}\n").unwrap();
        package
    }

    fn test_target(
        triple: &str,
        arch: &str,
        target_env: &str,
        os: &str,
        pointer_width: &str,
        panic_strategy: &str,
    ) -> Target {
        let facts =
            crate::target::canonical_builtin_facts(crate::target::CoreTargetFacts::little_endian(
                arch,
                target_env,
                os,
                pointer_width,
                panic_strategy,
            ))
            .unwrap();
        Target::from_facts(triple, crate::target::Environment::Server, facts).unwrap()
    }

    fn native_test_target() -> Target {
        test_target(
            "x86_64-unknown-linux-gnu",
            "x86_64",
            "gnu",
            "linux",
            "64",
            "unwind",
        )
    }

    fn wasm_test_target() -> Target {
        test_target(
            "wasm32-unknown-unknown",
            "wasm32",
            "",
            "unknown",
            "32",
            "abort",
        )
    }

    #[test]
    fn cargo_lock_package_collection_is_bounded_during_deserialization() {
        let mut lock = String::from("version = 4\n");
        for _ in 0..=MAX_CARGO_LOCK_PACKAGES {
            lock.push_str("[[package]]\n");
        }

        assert!(matches!(
            locked_cargo_sources_from_bytes(Path::new("Cargo.lock"), lock.as_bytes()),
            Err(ComposeError::ManifestNormalization { message, .. })
                if message.contains("Cargo.lock packages has more than")
        ));
    }

    #[test]
    fn cargo_lock_source_identity_collection_is_bounded() {
        let mut lock = String::from("version = 4\n");
        for index in 0..=MAX_CARGO_SOURCE_IDENTITIES {
            lock.push_str(&format!(
                "[[package]]\nsource = \"git+https://example.invalid/repository-{index}#{}\"\n",
                "0".repeat(40)
            ));
        }

        assert!(matches!(
            locked_cargo_sources_from_bytes(Path::new("Cargo.lock"), lock.as_bytes()),
            Err(ComposeError::ManifestNormalization { message, .. })
                if message.contains("Cargo.lock source identities has more than")
        ));
    }

    fn write_test_package(root: &Path, logical_path: &str, name: &str, manifest_tail: &str) {
        let package = root.join(logical_path);
        fs::create_dir_all(package.join("src")).unwrap();
        fs::write(
            package.join("Cargo.toml"),
            format!(
                "[package]\nname = {name:?}\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"{PINNED_RUST_VERSION}\"\nlicense = \"MIT\"\n\n[features]\ndefault = []\n\n{manifest_tail}"
            ),
        )
        .unwrap();
        fs::write(
            package.join("src/lib.rs"),
            "pub const MARKER: &str = \"test\";\n",
        )
        .unwrap();
    }

    #[test]
    fn target_dependency_manifest_rewrite_is_fact_bound_and_deterministic() {
        let temp = TempDir::new().unwrap();
        write_test_package(temp.path(), "packages/native", "target-native", "");
        write_test_package(temp.path(), "packages/wasm", "target-wasm", "");
        write_test_package(temp.path(), "packages/exact", "target-exact", "");
        let first_tail = r#"
[target.'cfg(target_arch = "wasm32")'.dependencies]
target-wasm = { version = "0.1.0", path = "../wasm", default-features = false }

[target.'x86_64-unknown-linux-gnu'.dependencies]
target-exact = { version = "0.1.0", path = "../exact", default-features = false }

[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
target-native = { version = "0.1.0", path = "../native", default-features = false }
"#;
        write_test_package(temp.path(), "packages/root", "target-root", first_tail);

        let native =
            normalize_package_manifest(temp.path(), "packages/root", &native_test_target())
                .unwrap();
        let wasm =
            normalize_package_manifest(temp.path(), "packages/root", &wasm_test_target()).unwrap();
        let native_text = String::from_utf8(native.bytes.clone()).unwrap();
        let wasm_text = String::from_utf8(wasm.bytes.clone()).unwrap();
        assert!(!native_text.contains("[target."));
        assert!(native_text.contains("target-native"));
        assert!(native_text.contains("target-exact"));
        assert!(!native_text.contains("target-wasm"));
        assert!(!wasm_text.contains("[target."));
        assert!(wasm_text.contains("target-wasm"));
        assert!(!wasm_text.contains("target-native"));
        assert!(!wasm_text.contains("target-exact"));
        assert_eq!(
            native
                .path_dependencies
                .iter()
                .map(|dependency| dependency.logical_path.as_str())
                .collect::<Vec<_>>(),
            ["packages/exact", "packages/native"]
        );
        assert_eq!(
            wasm.path_dependencies
                .iter()
                .map(|dependency| dependency.logical_path.as_str())
                .collect::<Vec<_>>(),
            ["packages/wasm"]
        );

        let reordered_tail = r#"
[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
target-native = { default-features = false, path = "../native", version = "0.1.0" }

[target.'x86_64-unknown-linux-gnu'.dependencies]
target-exact = { default-features = false, path = "../exact", version = "0.1.0" }

[target.'cfg(target_arch = "wasm32")'.dependencies]
target-wasm = { default-features = false, path = "../wasm", version = "0.1.0" }
"#;
        write_test_package(temp.path(), "packages/root", "target-root", reordered_tail);
        let reordered =
            normalize_package_manifest(temp.path(), "packages/root", &native_test_target())
                .unwrap();
        assert_eq!(native, reordered);
    }

    #[test]
    fn target_dependency_manifest_rejects_non_builtin_or_ambiguous_clauses_before_cargo() {
        let cases = [
            (
                "environment",
                r#"[target.'cfg(environment = "server")'.dependencies]
helper = { path = "../helper" }
"#,
                "composition-only fact",
            ),
            (
                "feature",
                r#"[target.'cfg(feature = "leak")'.dependencies]
helper = { path = "../helper" }
"#,
                "reserved predicate identifier `feature`",
            ),
            (
                "build-host",
                r#"[target.'cfg(true)'.build-dependencies]
helper = { path = "../helper" }
"#,
                "committed BuildHost facts",
            ),
            (
                "duplicate",
                r#"[dependencies]
helper = { path = "../helper" }

[target.'cfg(true)'.dependencies]
helper = { path = "../helper" }
"#,
                "selected by more than one",
            ),
            (
                "unknown-dependency-key",
                r#"[target.'cfg(true)'.dependencies]
helper = { pth = "../helper" }
"#,
                "unsupported key `pth`",
            ),
            (
                "optional-path",
                r#"[target.'cfg(true)'.dependencies]
helper = { path = "../helper", optional = true }
"#,
                "requires exact feature-unit planning",
            ),
        ];
        for (name, tail, expected) in cases {
            let temp = TempDir::new().unwrap();
            write_test_package(temp.path(), "packages/helper", "helper", "");
            write_test_package(temp.path(), "packages/root", "root", tail);
            let result =
                normalize_package_manifest(temp.path(), "packages/root", &native_test_target());
            assert!(
                matches!(
                    result,
                    Err(ComposeError::ManifestNormalization { ref message, .. })
                        if message.contains(expected)
                ),
                "case `{name}` did not fail closed: {result:?}"
            );
        }
    }

    #[test]
    fn inactive_target_path_is_absent_and_escape_is_rejected_before_cargo() {
        let temp = TempDir::new().unwrap();
        write_test_package(
            temp.path(),
            "packages/root",
            "root",
            r#"[target.'cfg(target_arch = "wasm32")'.dependencies]
missing-wasm = { path = "../missing-wasm" }
"#,
        );
        let inactive =
            normalize_package_manifest(temp.path(), "packages/root", &native_test_target())
                .unwrap();
        assert!(inactive.path_dependencies.is_empty());
        assert!(
            !String::from_utf8(inactive.bytes)
                .unwrap()
                .contains("missing-wasm")
        );

        write_test_package(
            temp.path(),
            "packages/root",
            "root",
            r#"[target.'cfg(true)'.dependencies]
escape = { path = "../../../outside-workspace" }
"#,
        );
        assert!(matches!(
            normalize_package_manifest(temp.path(), "packages/root", &native_test_target()),
            Err(ComposeError::InputOutsideWorkspace(_))
        ));
    }

    #[test]
    fn target_dependency_selector_count_is_bounded_before_cargo() {
        let temp = TempDir::new().unwrap();
        let mut tail = String::new();
        for index in 0..MAX_MANIFEST_TARGET_SELECTORS {
            tail.push_str(&format!(
                "[target.'bounded-{index}-unknown-none'.dependencies]\n"
            ));
        }
        write_test_package(temp.path(), "packages/root", "root", &tail);
        normalize_package_manifest(temp.path(), "packages/root", &native_test_target()).unwrap();
        tail.push_str("[target.'one-too-many-unknown-none'.dependencies]\n");
        write_test_package(temp.path(), "packages/root", "root", &tail);
        assert!(matches!(
            normalize_package_manifest(
                temp.path(),
                "packages/root",
                &native_test_target()
            ),
            Err(ComposeError::ManifestNormalization { message, .. })
                if message.contains("selector count")
        ));
    }

    #[test]
    fn target_dependency_entry_count_is_bounded_before_cargo() {
        let temp = TempDir::new().unwrap();
        let mut tail = String::from("[target.'cfg(true)'.dependencies]\n");
        for index in 0..MAX_MANIFEST_DEPENDENCIES {
            tail.push_str(&format!("dependency-{index} = \"1\"\n"));
        }
        write_test_package(temp.path(), "packages/root", "root", &tail);
        let at_limit =
            normalize_package_manifest(temp.path(), "packages/root", &native_test_target())
                .unwrap();
        assert!(at_limit.requires_registry);

        tail.push_str("one-too-many = \"1\"\n");
        write_test_package(temp.path(), "packages/root", "root", &tail);
        assert!(matches!(
            normalize_package_manifest(
                temp.path(),
                "packages/root",
                &native_test_target()
            ),
            Err(ComposeError::ManifestNormalization { message, .. })
                if message.contains("maximum is")
        ));
    }

    #[test]
    fn path_dependency_package_closure_count_is_bounded_before_cargo() {
        let temp = TempDir::new().unwrap();
        for index in 0..MAX_COMPOSITION_SOURCE_PACKAGES {
            let tail = if index + 1 == MAX_COMPOSITION_SOURCE_PACKAGES {
                String::new()
            } else {
                format!(
                    "[target.'cfg(true)'.dependencies]\npackage-{} = {{ path = \"../{}\" }}\n",
                    index + 1,
                    index + 1
                )
            };
            write_test_package(
                temp.path(),
                &format!("packages/{index}"),
                &format!("package-{index}"),
                &tail,
            );
        }
        let root = PackageSeed {
            id: "root".into(),
            package: "package-0".into(),
            path: "packages/0".into(),
            direct: true,
        };
        let at_limit =
            package_closure(temp.path(), vec![root.clone()], &native_test_target()).unwrap();
        assert_eq!(at_limit.len(), MAX_COMPOSITION_SOURCE_PACKAGES);

        write_test_package(
            temp.path(),
            &format!("packages/{MAX_COMPOSITION_SOURCE_PACKAGES}"),
            &format!("package-{MAX_COMPOSITION_SOURCE_PACKAGES}"),
            "",
        );
        write_test_package(
            temp.path(),
            &format!("packages/{}", MAX_COMPOSITION_SOURCE_PACKAGES - 1),
            &format!("package-{}", MAX_COMPOSITION_SOURCE_PACKAGES - 1),
            &format!(
                "[target.'cfg(true)'.dependencies]\npackage-{MAX_COMPOSITION_SOURCE_PACKAGES} = {{ path = \"../{MAX_COMPOSITION_SOURCE_PACKAGES}\" }}\n"
            ),
        );
        assert!(matches!(
            package_closure(temp.path(), vec![root], &native_test_target()),
            Err(ComposeError::ManifestNormalization { message, .. })
                if message.contains("path dependency closure exceeds")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn active_target_dependency_symlink_is_rejected_before_cargo() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        write_test_package(temp.path(), "packages/helper", "helper", "");
        symlink(
            temp.path().join("packages/helper"),
            temp.path().join("packages/link"),
        )
        .unwrap();
        write_test_package(
            temp.path(),
            "packages/root",
            "root",
            r#"[target.'cfg(true)'.dependencies]
helper = { path = "../link" }
"#,
        );
        assert!(matches!(
            normalize_package_manifest(
                temp.path(),
                "packages/root",
                &native_test_target()
            ),
            Err(ComposeError::UnsupportedSourceEntry(path)) if path.ends_with("packages/link")
        ));
    }

    fn assert_no_composition_staging(output_root: &Path) {
        assert!(fs::read_dir(output_root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".staging-")
        }));
    }

    #[test]
    fn regeneration_is_deterministic() {
        let temp = TempDir::new().unwrap();
        let options = options(&temp, "tests/fixtures/profiles/minimal.toml");
        let first = compose(&options).unwrap();
        let second = compose(&options).unwrap();
        assert_eq!(first.composition_hash, second.composition_hash);
        assert_eq!(first.manifest, second.manifest);
        assert_eq!(first.path, second.path);
    }

    #[test]
    fn canonical_target_facts_snapshot_is_schema_owned_bounded_and_deterministic() {
        let temp = TempDir::new().unwrap();
        let mut first_options = options(&temp, "tests/fixtures/profiles/minimal.toml");
        first_options.output_root = temp.path().join("first-compositions");
        let mut second_options = first_options.clone();
        second_options.output_root = temp.path().join("second-compositions");

        let first = compose(&first_options).unwrap();
        let second = compose(&second_options).unwrap();
        let first_bytes = fs::read(first.path.join("target-facts.json")).unwrap();
        let second_bytes = fs::read(second.path.join("target-facts.json")).unwrap();
        let parsed = TargetFactsRecord::from_json(&first_bytes).unwrap();
        let generated_record = first
            .manifest
            .generated_files
            .iter()
            .find(|file| file.path == "target-facts.json")
            .unwrap();

        assert_eq!(first_bytes, canonical::jcs_bytes(&parsed).unwrap());
        assert_eq!(first_bytes, second_bytes);
        assert!(first_bytes.len() <= MAX_CANONICAL_TARGET_FACTS_RECORD_BYTES);
        assert_eq!(parsed, first.manifest.target_facts);
        assert_eq!(
            parsed.semantic_digest().unwrap(),
            first.manifest.target_fact_digest
        );
        assert_eq!(generated_record.digest, sha256_hex(&first_bytes));
        assert_eq!(generated_record.bytes, first_bytes.len() as u64);
        assert_eq!(first.composition_hash, second.composition_hash);
        verify_composition(&first.path).unwrap();
        verify_composition(&second.path).unwrap();

        make_staging_tree_owner_writable(&first.path).unwrap();
        make_staging_tree_owner_writable(&second.path).unwrap();
    }

    #[test]
    fn target_facts_snapshot_rejects_raw_canonical_semantic_and_size_tampering() {
        let temp = TempDir::new().unwrap();
        let generated = compose(&options(&temp, "tests/fixtures/profiles/minimal.toml")).unwrap();
        let snapshot_path = generated.path.join("target-facts.json");
        let manifest_path = generated.path.join("rust-agent-composition.json");
        let original_snapshot = fs::read(&snapshot_path).unwrap();
        let original_manifest = fs::read(&manifest_path).unwrap();

        fs::write(&snapshot_path, b"{").unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("target-facts.json is invalid")
        ));

        let pretty_snapshot = serde_json::to_vec_pretty(&generated.manifest.target_facts).unwrap();
        fs::write(&snapshot_path, &pretty_snapshot).unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("exact RFC 8785 canonical encoding")
        ));

        let mut forged_manifest = generated.manifest.clone();
        forged_manifest
            .target_facts
            .facts
            .entry("target_feature".into())
            .or_default()
            .insert(Some("forged-feature".into()));
        forged_manifest.target_facts.validate().unwrap();
        let forged_snapshot = canonical_target_facts_bytes(&forged_manifest.target_facts).unwrap();
        fs::write(&snapshot_path, &forged_snapshot).unwrap();
        let generated_record = forged_manifest
            .generated_files
            .iter_mut()
            .find(|file| file.path == "target-facts.json")
            .unwrap();
        generated_record.digest = sha256_hex(&forged_snapshot);
        generated_record.bytes = forged_snapshot.len() as u64;
        write_json(&manifest_path, &forged_manifest).unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("manifest projection")
        ));

        fs::write(&snapshot_path, &original_snapshot).unwrap();
        fs::write(&manifest_path, &original_manifest).unwrap();
        File::options()
            .write(true)
            .truncate(true)
            .open(&snapshot_path)
            .unwrap()
            .set_len(MAX_CANONICAL_TARGET_FACTS_RECORD_BYTES as u64 + 1)
            .unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message)) if message.contains("maximum")
        ));

        make_staging_tree_owner_writable(&generated.path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn invalid_target_facts_fail_before_cargo_side_effects() {
        let temp = TempDir::new().unwrap();
        let (rustc, _) = write_fake_rustc(temp.path(), "printf '%s\\n' 'panic=\"unwind\"'");
        let cargo = temp.path().join("side-effect-cargo");
        let cargo_marker = temp.path().join("cargo-ran");
        write_executable(
            &cargo,
            &format!("#!/bin/sh\nprintf cargo-ran > {cargo_marker:?}\n"),
        );
        let mut compose_options = options(&temp, "tests/fixtures/profiles/minimal.toml");
        compose_options.rustc_path = rustc;
        compose_options.cargo_path = cargo;

        assert!(matches!(
            compose(&compose_options),
            Err(ComposeError::Target(TargetError::InvalidFact(message)))
                if message.contains("missing required scalar")
        ));
        assert!(!cargo_marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn compose_rustc_provenance_is_identity_bound_but_separate_from_target_facts() {
        let temp = TempDir::new().unwrap();
        let target_facts = concat!(
            "printf '%s\\n' 'panic=\"unwind\"' 'target_abi=\"\"' ",
            "'target_arch=\"x86_64\"' 'target_endian=\"little\"' ",
            "'target_env=\"gnu\"' 'target_family=\"unix\"' ",
            "'target_os=\"linux\"' 'target_pointer_width=\"64\"' ",
            "'target_vendor=\"unknown\"' 'unix'",
        );
        let (rustc, sysroot) = write_fake_rustc(temp.path(), target_facts);
        let mut first_options = options(&temp, "tests/fixtures/profiles/minimal.toml");
        first_options.rustc_path = rustc.clone();
        first_options.output_root = temp.path().join("first-compositions");
        let first = compose(&first_options).unwrap();

        fs::write(
            sysroot.join("lib/rustlib/fixture/lib/libcore-fixture.rlib"),
            b"fixture-sysroot-v2",
        )
        .unwrap();
        let mut second_options = first_options.clone();
        second_options.output_root = temp.path().join("second-compositions");
        let second = compose(&second_options).unwrap();

        assert_eq!(
            first.manifest.target_fact_digest,
            second.manifest.target_fact_digest
        );
        assert_eq!(
            first.manifest.compose_rustc.rustc.sha256,
            second.manifest.compose_rustc.rustc.sha256
        );
        assert_eq!(
            first.manifest.compose_rustc.rustc.verbose_version,
            second.manifest.compose_rustc.rustc.verbose_version
        );
        assert_ne!(
            first.manifest.compose_rustc.sysroot.tree_digest,
            second.manifest.compose_rustc.sysroot.tree_digest
        );
        assert_ne!(
            first.manifest.compose_rustc.identity_digest,
            second.manifest.compose_rustc.identity_digest
        );
        assert_ne!(first.composition_hash, second.composition_hash);
        verify_composition(&first.path).unwrap();
        verify_composition(&second.path).unwrap();
        make_staging_tree_owner_writable(&first.path).unwrap();
        make_staging_tree_owner_writable(&second.path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn compose_rustc_drift_takes_priority_over_target_query_failure() {
        let temp = TempDir::new().unwrap();
        let sysroot = temp.path().join("fake-toolchain");
        let mutation = sysroot.join("lib/rustlib/fixture/lib/libcore-fixture.rlib");
        let (rustc, _) = write_fake_rustc(
            temp.path(),
            &format!("printf changed-sysroot > {mutation:?}\nexit 79"),
        );
        let cargo = temp.path().join("side-effect-cargo");
        let cargo_marker = temp.path().join("cargo-ran");
        write_executable(
            &cargo,
            &format!("#!/bin/sh\nprintf cargo-ran > {cargo_marker:?}\nexit 80\n"),
        );
        let mut compose_options = options(&temp, "tests/fixtures/profiles/minimal.toml");
        compose_options.rustc_path = rustc;
        compose_options.cargo_path = cargo;

        let result = compose(&compose_options);
        assert!(matches!(
            result,
            Err(ComposeError::ComposeRustc(ComposeRustcError::Drift {
                phase,
                surface: "sysroot tree metadata",
            })) if phase == "rustc target-fact query"
        ));
        assert!(!cargo_marker.exists());
        assert!(
            fs::read_dir(&compose_options.output_root)
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn compose_rustc_record_rejects_encoding_and_manifest_tampering() {
        let temp = TempDir::new().unwrap();
        let generated = compose(&options(&temp, "tests/fixtures/profiles/minimal.toml")).unwrap();
        let record_path = generated.path.join("compose-rustc.json");
        let manifest_path = generated.path.join("rust-agent-composition.json");
        let original_record = fs::read(&record_path).unwrap();
        let original_manifest = fs::read(&manifest_path).unwrap();

        fs::write(
            &record_path,
            serde_json::to_vec(&generated.manifest.compose_rustc).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("exact deterministic provenance")
        ));
        fs::write(&record_path, &original_record).unwrap();

        let mut manifest: serde_json::Value = serde_json::from_slice(&original_manifest).unwrap();
        manifest["compose-rustc"]["identity-digest"] = serde_json::Value::String("0".repeat(64));
        let mut forged = serde_json::to_vec_pretty(&manifest).unwrap();
        forged.push(b'\n');
        fs::write(&manifest_path, forged).unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::ManifestNormalization { message, .. })
                if message.contains("identity digest")
        ));

        fs::write(&manifest_path, original_manifest).unwrap();
        verify_composition(&generated.path).unwrap();
        make_staging_tree_owner_writable(&generated.path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn missing_package_owned_root_requirements_fail_before_lockfile_side_effects() {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        let temp = TempDir::new().unwrap();
        let metadata_path = temp.path().join("cargo-metadata.json");
        let lock_marker = temp.path().join("lockfile-command-ran");
        let fake_cargo = temp.path().join("fake-cargo");
        let output = Command::new(tool("cargo"))
            .args([
                "metadata",
                "--format-version",
                "1",
                "--no-deps",
                "--locked",
                "--offline",
            ])
            .current_dir(&workspace)
            .output()
            .unwrap();
        assert!(output.status.success());
        let mut metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let core = metadata["packages"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|package| package["name"] == "rust-agent-core")
            .unwrap();
        core["metadata"] = serde_json::json!({});
        fs::write(&metadata_path, serde_json::to_vec(&metadata).unwrap()).unwrap();
        write_executable(
            &fake_cargo,
            &format!(
                concat!(
                    "#!/bin/sh\n",
                    "if [ \"$1\" = metadata ]; then exec /bin/cat {:?}; fi\n",
                    ": > {:?}\n",
                    "exit 91\n"
                ),
                metadata_path, lock_marker,
            ),
        );
        let mut compose_options = options(&temp, "tests/fixtures/profiles/minimal.toml");
        compose_options.cargo_path = fake_cargo;

        let result = compose(&compose_options);
        assert!(
            matches!(
                &result,
                Err(ComposeError::UnsupportedPhase1A(message))
                    if message.contains("rust-agent-core")
                        && message.contains("package-owned build requirements")
            ),
            "unexpected result: {result:?}"
        );
        assert!(!lock_marker.exists());
        assert!(
            fs::read_dir(&compose_options.output_root)
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn package_owned_api_requirements_flow_into_the_composition_manifest() {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        let temp = TempDir::new().unwrap();
        let metadata_path = temp.path().join("cargo-metadata.json");
        let fake_cargo = temp.path().join("fake-cargo");
        let real_cargo = tool("cargo");
        let output = Command::new(&real_cargo)
            .args([
                "metadata",
                "--format-version",
                "1",
                "--no-deps",
                "--locked",
                "--offline",
            ])
            .current_dir(&workspace)
            .output()
            .unwrap();
        assert!(output.status.success());
        let mut metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let core = metadata["packages"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|package| package["name"] == "rust-agent-core")
            .unwrap();
        core["metadata"]["rust-agent"]["build-requirements"]["executables"] =
            serde_json::json!(["fixture-codegen"]);
        fs::write(&metadata_path, serde_json::to_vec(&metadata).unwrap()).unwrap();
        write_executable(
            &fake_cargo,
            &format!(
                concat!(
                    "#!/bin/sh\n",
                    "if [ \"$1\" = metadata ]; then exec /bin/cat {:?}; fi\n",
                    "exec {:?} \"$@\"\n"
                ),
                metadata_path, real_cargo,
            ),
        );
        let mut compose_options = options(&temp, "tests/fixtures/profiles/minimal.toml");
        compose_options.cargo_path = fake_cargo;

        let generated = compose(&compose_options).unwrap();
        let requirements =
            &generated.manifest.direct_root_build_requirements["api:rust-agent-core"];
        assert_eq!(
            requirements.executables,
            BTreeSet::from(["fixture-codegen".into()])
        );
        assert!(
            generated
                .manifest
                .build_requirements
                .executables
                .contains("fixture-codegen")
        );
        assert!(generated.manifest.compiled_runtime_effects.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn cargo_metadata_config_drift_takes_priority_over_child_failure() {
        let temp = TempDir::new().unwrap();
        let cargo = temp.path().join("mutating-cargo");
        let marker = temp.path().join("cargo-ran");
        write_executable(
            &cargo,
            &format!(
                concat!(
                    "#!/bin/sh\n",
                    ": > {:?}\n",
                    "printf '[net]\\noffline = false\\n' > \"$PWD/.cargo/config.toml\"\n",
                    "exit 71\n"
                ),
                marker,
            ),
        );
        let mut compose_options = options(&temp, "tests/fixtures/profiles/minimal.toml");
        compose_options.cargo_path = cargo;

        let result = compose(&compose_options);
        assert!(marker.exists());
        assert!(matches!(
            result,
            Err(ComposeError::Verification(message))
                if message.contains("changed the generated Cargo config")
        ));
        assert!(
            fs::read_dir(&compose_options.output_root)
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn oversized_profile_fails_before_tool_or_output_side_effects() {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        let inputs = TempDir::new_in(workspace.join("target")).unwrap();
        let effects = TempDir::new().unwrap();
        let rustc = effects.path().join("side-effect-rustc");
        let cargo = effects.path().join("side-effect-cargo");
        let rustc_marker = effects.path().join("rustc-ran");
        let cargo_marker = effects.path().join("cargo-ran");
        write_executable(
            &rustc,
            &format!("#!/bin/sh\nprintf rustc-ran > {rustc_marker:?}\nexit 97\n"),
        );
        write_executable(
            &cargo,
            &format!("#!/bin/sh\nprintf cargo-ran > {cargo_marker:?}\nexit 97\n"),
        );

        let oversized = inputs.path().join("oversized-profile.toml");
        File::create(&oversized)
            .unwrap()
            .set_len(MAX_PROFILE_DOCUMENT_BYTES as u64 + 1)
            .unwrap();
        let output_root = effects.path().join("profile-compositions");
        let mut compose_options = options(&effects, "tests/fixtures/profiles/minimal.toml");
        compose_options.rustc_path = rustc;
        compose_options.cargo_path = cargo;
        compose_options.output_root = output_root.clone();
        compose_options.profile_path = oversized;

        assert!(matches!(
            compose(&compose_options),
            Err(ComposeError::InputTooLarge {
                maximum: actual_maximum,
                ..
            }) if actual_maximum == MAX_PROFILE_DOCUMENT_BYTES as u64
        ));
        assert!(!rustc_marker.exists());
        assert!(!cargo_marker.exists());
        assert!(!output_root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn workspace_input_rejects_symlink_provenance_and_same_metadata_inode_replacement() {
        use std::os::unix::fs::symlink;

        let workspace = TempDir::new().unwrap();
        let input = workspace.path().join("catalog.toml");
        let alias = workspace.path().join("catalog-alias.toml");
        fs::write(&input, b"schema = 1\n").unwrap();
        symlink(&input, &alias).unwrap();
        assert!(matches!(
            read_workspace_input(workspace.path(), &alias, 1024),
            Err(ComposeError::UnsupportedSourceEntry(_))
        ));

        let before = fs::symlink_metadata(&input).unwrap();
        let before_identity = workspace_input_identity(&before);
        let replacement = workspace.path().join("replacement.toml");
        fs::write(&replacement, b"schema = 1\n").unwrap();
        File::options()
            .write(true)
            .open(&replacement)
            .unwrap()
            .set_times(FileTimes::new().set_modified(before.modified().unwrap()))
            .unwrap();
        fs::rename(&replacement, &input).unwrap();
        let after = fs::symlink_metadata(&input).unwrap();
        assert_eq!(after.len(), before.len());
        assert_eq!(after.modified().unwrap(), before.modified().unwrap());
        assert!(
            ensure_workspace_input_identity(&input, &before_identity, &after).is_err(),
            "Unix device/inode identity must detect same-byte same-mtime replacement"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ambient_output_ancestor_cargo_configs_fail_before_cargo_side_effects() {
        for name in ["config", "config.toml"] {
            let temp = TempDir::new().unwrap();
            let cargo_directory = temp.path().join(".cargo");
            fs::create_dir(&cargo_directory).unwrap();
            fs::write(
                cargo_directory.join(name),
                b"[build]\nrustc-wrapper = \"malicious-wrapper\"\n",
            )
            .unwrap();
            let cargo = temp.path().join("fake-cargo");
            let cargo_marker = temp.path().join("cargo-ran");
            write_executable(
                &cargo,
                &format!("#!/bin/sh\nprintf cargo-ran > {cargo_marker:?}\nexit 97\n"),
            );
            let mut compose_options = options(&temp, "tests/fixtures/profiles/minimal.toml");
            compose_options.output_root = temp.path().join("nested/compositions");
            compose_options.cargo_path = cargo;

            assert!(matches!(
                compose(&compose_options),
                Err(ComposeError::CargoConfigIsolation(
                    CargoConfigIsolationError::AmbientConfig(path)
                )) if path.ends_with(name)
            ));
            assert!(!cargo_marker.exists());
            assert!(!compose_options.output_root.exists());
        }
    }

    #[test]
    fn existing_composition_reuse_rejects_tampered_snapshot_bytes_without_repair() {
        let temp = TempDir::new().unwrap();
        let options = options(&temp, "tests/fixtures/profiles/minimal.toml");
        let generated = compose(&options).unwrap();
        let package = generated
            .manifest
            .sources
            .iter()
            .find(|package| {
                package
                    .tree_entries
                    .iter()
                    .any(|entry| entry.path == "src/lib.rs")
            })
            .unwrap();
        let source_file = generated
            .path
            .join("sources")
            .join(&package.logical_path)
            .join("src/lib.rs");
        let original = fs::read(&source_file).unwrap();
        let mut mutated = original.clone();
        mutated[0] ^= 1;
        let mut permissions = fs::metadata(&source_file).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            permissions.set_mode(permissions.mode() | 0o200);
        }
        #[cfg(not(unix))]
        permissions.set_readonly(false);
        fs::set_permissions(&source_file, permissions).unwrap();
        fs::write(&source_file, &mutated).unwrap();
        set_snapshot_epoch(&source_file).unwrap();
        set_snapshot_permissions(&source_file, false).unwrap();

        assert!(matches!(
            compose(&options),
            Err(ComposeError::ExistingCompositionCorrupt { .. })
        ));
        assert_eq!(fs::read(&source_file).unwrap(), mutated);
        assert_no_composition_staging(&options.output_root);

        make_staging_tree_owner_writable(&generated.path).unwrap();
    }

    #[test]
    fn selected_coexistence_evidence_is_reverified_from_the_source_snapshot() {
        let temp = TempDir::new().unwrap();
        let generated = compose(&options(&temp, "tests/fixtures/profiles/minimal.toml")).unwrap();
        let record = generated
            .manifest
            .generator_inputs
            .catalog_trust_input
            .evidence
            .iter()
            .find(|record| record.owner == "fixture-model")
            .unwrap();
        let evidence_path = generated
            .path
            .join("sources")
            .join(&record.package_path)
            .join(&record.source);
        let mut bytes = fs::read(&evidence_path).unwrap();
        bytes[0] ^= 1;
        let mut permissions = fs::metadata(&evidence_path).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            permissions.set_mode(permissions.mode() | 0o200);
        }
        #[cfg(not(unix))]
        permissions.set_readonly(false);
        fs::set_permissions(&evidence_path, permissions).unwrap();
        fs::write(&evidence_path, bytes).unwrap();
        set_snapshot_epoch(&evidence_path).unwrap();
        set_snapshot_permissions(&evidence_path, false).unwrap();

        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("selected coexistence evidence differs")
        ));
        make_staging_tree_owner_writable(&generated.path).unwrap();
    }

    #[test]
    fn aggregate_handoff_requires_every_selected_app_owner_to_be_concurrent() {
        let concurrent_temp = TempDir::new().unwrap();
        let concurrent = compose(&options(
            &concurrent_temp,
            "tests/fixtures/profiles/minimal.toml",
        ))
        .unwrap();
        assert_eq!(
            concurrent.manifest.app_handoff,
            crate::resolver::AppHandoff::Concurrent
        );
        let committed_owners = concurrent
            .manifest
            .generator_inputs
            .catalog_trust_input
            .evidence
            .iter()
            .map(|record| record.owner.as_str())
            .collect::<BTreeSet<_>>();
        assert!(committed_owners.contains("fixture-model"));
        assert!(committed_owners.contains("fixture-driver"));
        assert!(committed_owners.contains("fixture-runtime"));

        let exclusive_temp = TempDir::new().unwrap();
        let exclusive = compose(&options(
            &exclusive_temp,
            "tests/fixtures/profiles/with-fs.toml",
        ))
        .unwrap();
        assert_eq!(
            exclusive.manifest.app_handoff,
            crate::resolver::AppHandoff::StopOldApp
        );

        make_staging_tree_owner_writable(&concurrent.path).unwrap();
        make_staging_tree_owner_writable(&exclusive.path).unwrap();
    }

    #[test]
    fn composition_verification_rejects_deployable_and_handoff_projection_forgery() {
        let temp = TempDir::new().unwrap();
        let generated = compose(&options(&temp, "tests/fixtures/profiles/minimal.toml")).unwrap();
        let manifest_path = generated.path.join("rust-agent-composition.json");
        let original = generated.manifest.clone();
        let mut manifest = original.clone();

        manifest.deployable = true;
        write_json(&manifest_path, &manifest).unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("manifest projection")
        ));

        manifest = original.clone();
        manifest.app_handoff = crate::resolver::AppHandoff::StopOldApp;
        write_json(&manifest_path, &manifest).unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("manifest projection")
        ));

        write_json(&manifest_path, &original).unwrap();
        verify_composition(&generated.path).unwrap();
        make_staging_tree_owner_writable(&generated.path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn composition_control_file_reads_reject_symlinks_and_oversized_regular_files() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let composition = temp.path().join("composition");
        let outside = temp.path().join("outside.json");
        fs::create_dir(&composition).unwrap();
        fs::write(&outside, b"{}\n").unwrap();
        let manifest = composition.join("rust-agent-composition.json");
        symlink(&outside, &manifest).unwrap();

        assert!(matches!(
            load_manifest(&composition),
            Err(ComposeError::Verification(message))
                if message.contains("concrete regular file")
        ));

        fs::remove_file(&manifest).unwrap();
        File::create(&manifest)
            .unwrap()
            .set_len(MAX_COMPOSITION_CONTROL_FILE_BYTES + 1)
            .unwrap();
        assert!(matches!(
            load_manifest(&composition),
            Err(ComposeError::Verification(message))
                if message.contains("maximum")
        ));
    }

    #[test]
    fn composition_manifest_load_rejects_noncanonical_and_duplicate_json() {
        let temp = TempDir::new().unwrap();
        let generated = compose(&options(&temp, "tests/fixtures/profiles/minimal.toml")).unwrap();
        let manifest_path = generated.path.join("rust-agent-composition.json");
        let canonical = fs::read(&manifest_path).unwrap();
        assert_eq!(load_manifest(&generated.path).unwrap(), generated.manifest);

        fs::write(
            &manifest_path,
            serde_json::to_vec(&generated.manifest).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            load_manifest(&generated.path),
            Err(ComposeError::ManifestNormalization { message, .. })
                if message.contains("exact deterministic generator JSON encoding")
        ));

        let (owner, support) = generated
            .manifest
            .resolution
            .target_support
            .first_key_value()
            .unwrap();
        let owner = serde_json::to_string(owner).unwrap();
        let support = serde_json::to_string(support).unwrap();
        let mut duplicate = String::from_utf8(canonical.clone()).unwrap();
        let marker = "\"target-support\": {";
        let insert_at = duplicate.find(marker).unwrap() + marker.len();
        duplicate.insert_str(insert_at, &format!("\n      {owner}: {support},"));
        fs::write(&manifest_path, duplicate).unwrap();
        assert!(matches!(
            load_manifest(&generated.path),
            Err(ComposeError::ManifestNormalization { message, .. })
                if message.contains("duplicate target-support owner")
        ));

        fs::write(&manifest_path, canonical).unwrap();
        verify_composition(&generated.path).unwrap();
        make_staging_tree_owner_writable(&generated.path).unwrap();
    }

    #[test]
    fn composition_manifest_load_rederives_resolution_from_committed_inputs() {
        let temp = TempDir::new().unwrap();
        let generated = compose(&options(&temp, "tests/fixtures/profiles/minimal.toml")).unwrap();
        let manifest_path = generated.path.join("rust-agent-composition.json");
        let mut forged = generated.manifest.clone();
        forged.resolution.profile = "forged-profile".into();
        write_json(&manifest_path, &forged).unwrap();

        assert!(matches!(
            load_manifest(&generated.path),
            Err(ComposeError::ManifestNormalization { message, .. })
                if message.contains("resolution differs from the committed normalized catalog")
        ));
        make_staging_tree_owner_writable(&generated.path).unwrap();
    }

    #[test]
    fn composition_verification_bounds_lockfile_before_hashing() {
        let temp = TempDir::new().unwrap();
        let generated = compose(&options(&temp, "tests/fixtures/profiles/minimal.toml")).unwrap();
        File::options()
            .write(true)
            .open(generated.path.join("Cargo.lock"))
            .unwrap()
            .set_len(MAX_COMPOSITION_CONTROL_FILE_BYTES + 1)
            .unwrap();

        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("Cargo.lock") && message.contains("maximum")
        ));
        make_staging_tree_owner_writable(&generated.path).unwrap();
    }

    #[test]
    fn composition_verification_binds_complete_directory_topology() {
        let temp = TempDir::new().unwrap();
        let generated = compose(&options(&temp, "tests/fixtures/profiles/minimal.toml")).unwrap();
        let extra = generated.path.join("unexpected-empty-directory");
        fs::create_dir(&extra).unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("unexpected-empty-directory")
        ));

        fs::remove_dir(&extra).unwrap();
        fs::remove_dir(generated.path.join("vendor")).unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("missing expected entries") && message.contains("vendor")
        ));

        fs::create_dir(generated.path.join("vendor")).unwrap();
        verify_composition(&generated.path).unwrap();
        make_staging_tree_owner_writable(&generated.path).unwrap();
    }

    #[test]
    fn composition_directory_basename_is_bound_to_the_composition_hash() {
        let temp = TempDir::new().unwrap();
        let generated = compose(&options(&temp, "tests/fixtures/profiles/minimal.toml")).unwrap();
        let renamed = temp.path().join("forged-composition-name");
        fs::rename(&generated.path, &renamed).unwrap();

        assert_eq!(
            verify_emitted_composition(&renamed).unwrap(),
            generated.manifest
        );

        assert!(matches!(
            verify_composition(&renamed),
            Err(ComposeError::Verification(message))
                if message.contains("directory basename")
                    && message.contains(&generated.composition_hash)
        ));
        make_staging_tree_owner_writable(&renamed).unwrap();
    }

    #[test]
    fn composition_verification_rejects_nested_schema_and_resolution_projection_forgery() {
        let temp = TempDir::new().unwrap();
        let generated = compose(&options(&temp, "tests/fixtures/profiles/minimal.toml")).unwrap();
        let manifest_path = generated.path.join("rust-agent-composition.json");
        let original = generated.manifest.clone();
        let mut forgeries = Vec::new();

        let mut profile_schema = original.clone();
        profile_schema.normalized_profile.schema = 2;
        forgeries.push(profile_schema);
        let mut resolution_schema = original.clone();
        resolution_schema.resolution.schema = 2;
        forgeries.push(resolution_schema);
        let mut cargo_schema = original.clone();
        cargo_schema.cargo_resolution.schema = 2;
        forgeries.push(cargo_schema);
        for field in ["profile", "target", "target-fact-digest"] {
            let mut resolution_projection = original.clone();
            match field {
                "profile" => resolution_projection.resolution.profile = "forged".into(),
                "target" => resolution_projection.resolution.target = "forged".into(),
                "target-fact-digest" => {
                    resolution_projection.resolution.target_fact_digest = "forged".into();
                }
                _ => unreachable!(),
            }
            forgeries.push(resolution_projection);
        }

        for forgery in forgeries {
            write_json(&manifest_path, &forgery).unwrap();
            let result = verify_composition(&generated.path);
            assert!(
                matches!(
                    &result,
                    Err(ComposeError::Verification(message))
                        if message.contains("manifest projection")
                ) || matches!(
                    &result,
                    Err(ComposeError::ManifestNormalization { message, .. })
                        if message.contains("resolution semantics")
                            || message.contains("resolution differs from the committed normalized catalog")
                            || message.contains("unsupported profile schema")
                            || message.contains("unsupported resolution schema")
                ),
                "unexpected nested projection result: {result:?}"
            );
        }

        let mut consistently_forged_target_digest = original.clone();
        let forged_digest = "0".repeat(64);
        consistently_forged_target_digest.target_fact_digest = forged_digest.clone();
        consistently_forged_target_digest
            .normalized_target
            .target_fact_digest = forged_digest.clone();
        consistently_forged_target_digest
            .resolution
            .target_fact_digest = forged_digest.clone();
        consistently_forged_target_digest
            .cargo_resolution
            .target_fact_digest = forged_digest;
        write_json(&manifest_path, &consistently_forged_target_digest).unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::ManifestNormalization { message, .. })
                if message.contains("target fact digest does not match")
        ));

        write_json(&manifest_path, &original).unwrap();
        verify_composition(&generated.path).unwrap();
        make_staging_tree_owner_writable(&generated.path).unwrap();
    }

    #[test]
    fn composition_effect_attribution_is_union_checked_and_identity_bound() {
        let temp = TempDir::new().unwrap();
        let generated = compose(&options(&temp, "tests/fixtures/profiles/with-fs.toml")).unwrap();
        let manifest_path = generated.path.join("rust-agent-composition.json");
        let original = generated.manifest.clone();

        let mut missing_effect = original.clone();
        missing_effect.component_runtime_effects.clear();
        write_json(&manifest_path, &missing_effect).unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("runtime effects")
        ));

        let mut reattributed_effect = original.clone();
        reattributed_effect.component_runtime_effects.clear();
        reattributed_effect.host_runtime_effects = BTreeSet::from(["read-local".into()]);
        write_json(&manifest_path, &reattributed_effect).unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("runtime effects attribution")
        ));

        write_json(&manifest_path, &original).unwrap();
        verify_composition(&generated.path).unwrap();
        make_staging_tree_owner_writable(&generated.path).unwrap();
    }

    #[test]
    fn security_manifest_requires_exact_deterministic_encoding() {
        let temp = TempDir::new().unwrap();
        let generated = compose(&options(&temp, "tests/fixtures/profiles/with-fs.toml")).unwrap();
        let security_path = generated.path.join("rust-agent-security.json");
        let original = fs::read(&security_path).unwrap();
        let security: SecurityManifest = serde_json::from_slice(&original).unwrap();

        fs::write(&security_path, serde_json::to_vec(&security).unwrap()).unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("exact deterministic derived encoding")
        ));

        let duplicate = String::from_utf8(original.clone()).unwrap().replacen(
            "\"read-local\"",
            "\"read-local\", \"read-local\"",
            1,
        );
        assert_ne!(duplicate.as_bytes(), original);
        fs::write(&security_path, duplicate).unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("duplicate entry")
        ));

        fs::write(&security_path, original).unwrap();
        verify_composition(&generated.path).unwrap();
        make_staging_tree_owner_writable(&generated.path).unwrap();
    }

    #[test]
    fn cargo_resolution_requires_exact_deterministic_encoding_after_resealing() {
        let temp = TempDir::new().unwrap();
        let mut compact_options = options(&temp, "tests/fixtures/profiles/minimal.toml");
        compact_options.output_root = temp.path().join("compact-cargo-resolution");
        let compact = compose(&compact_options).unwrap();
        let mut compact_manifest = compact.manifest.clone();
        let compact_bytes = serde_json::to_vec(&compact_manifest.cargo_resolution).unwrap();
        let compact_path = reseal_with_cargo_resolution_bytes(
            &compact.path,
            &mut compact_manifest,
            &compact_bytes,
        );
        assert!(matches!(
            verify_composition(&compact_path),
            Err(ComposeError::Verification(message))
                if message.contains("exact deterministic encoding")
        ));
        make_staging_tree_owner_writable(&compact_path).unwrap();

        let mut duplicate_options = options(&temp, "tests/fixtures/profiles/minimal.toml");
        duplicate_options.output_root = temp.path().join("duplicate-cargo-resolution");
        let duplicate = compose(&duplicate_options).unwrap();
        let mut duplicate_manifest = duplicate.manifest.clone();
        let source = format!("git+https://example.invalid/repository#{}", "0".repeat(40));
        duplicate_manifest
            .cargo_resolution
            .git_sources
            .insert(source.clone());
        let canonical = deterministic_json_bytes(&duplicate_manifest.cargo_resolution).unwrap();
        let quoted = serde_json::to_string(&source).unwrap();
        let duplicate_bytes = String::from_utf8(canonical)
            .unwrap()
            .replacen(&quoted, &format!("{quoted},\n    {quoted}"), 1)
            .into_bytes();
        let duplicate_path = reseal_with_cargo_resolution_bytes(
            &duplicate.path,
            &mut duplicate_manifest,
            &duplicate_bytes,
        );
        assert!(matches!(
            verify_composition(&duplicate_path),
            Err(ComposeError::Verification(message))
                if message.contains("duplicate entry")
        ));
        make_staging_tree_owner_writable(&duplicate_path).unwrap();
    }

    #[test]
    fn cargo_resolution_source_projection_must_match_lock_after_resealing() {
        let temp = TempDir::new().unwrap();
        let mut added_options = options(&temp, "tests/fixtures/profiles/minimal.toml");
        added_options.output_root = temp.path().join("added-cargo-source");
        let added = compose(&added_options).unwrap();
        let mut added_manifest = added.manifest.clone();
        added_manifest.cargo_resolution.git_sources.insert(format!(
            "git+https://example.invalid/repository#{}",
            "0".repeat(40)
        ));
        let added_bytes = deterministic_json_bytes(&added_manifest.cargo_resolution).unwrap();
        let added_path =
            reseal_with_cargo_resolution_bytes(&added.path, &mut added_manifest, &added_bytes);
        assert!(matches!(
            verify_composition(&added_path),
            Err(ComposeError::Verification(message))
                if message.contains("source projection differs from Cargo.lock")
        ));
        make_staging_tree_owner_writable(&added_path).unwrap();

        let mut removed_options = options(&temp, "tests/fixtures/profiles/controlled-build.toml");
        removed_options.output_root = temp.path().join("removed-cargo-source");
        removed_options.registry_cache_path = Some(registry_cache());
        let removed = compose(&removed_options).unwrap();
        let mut removed_manifest = removed.manifest.clone();
        assert!(!removed_manifest.cargo_resolution.registries.is_empty());
        removed_manifest.cargo_resolution.registries.clear();
        let removed_bytes = deterministic_json_bytes(&removed_manifest.cargo_resolution).unwrap();
        let removed_path = reseal_with_cargo_resolution_bytes(
            &removed.path,
            &mut removed_manifest,
            &removed_bytes,
        );
        assert!(matches!(
            verify_composition(&removed_path),
            Err(ComposeError::Verification(message))
                if message.contains("source projection differs from Cargo.lock")
        ));
        make_staging_tree_owner_writable(&removed_path).unwrap();
    }

    #[test]
    fn composition_record_sequences_require_canonical_order_after_resealing() {
        fn reseal(path: &Path, manifest: &mut CompositionManifest) -> PathBuf {
            let payload = CompositionIdentityPayload {
                schema: 1,
                profile: &manifest.normalized_profile,
                target: &manifest.normalized_target,
                target_facts: &manifest.target_facts,
                compose_rustc: &manifest.compose_rustc,
                generator_inputs: &manifest.generator_inputs,
                custom_target_spec: manifest.custom_target_spec.as_ref(),
                resolution: &manifest.resolution,
                component_runtime_effects: &manifest.component_runtime_effects,
                host_runtime_effects: &manifest.host_runtime_effects,
                direct_root_build_requirements: &manifest.direct_root_build_requirements,
                sources: &manifest.sources,
                generated_files: &manifest.generated_files,
                cargo_lock_digest: &manifest.cargo_lock_digest,
                cargo_resolution: &manifest.cargo_resolution,
            };
            manifest.composition_hash = hex::encode(
                canonical::domain_hash(b"rust-agent-composition-v1\0", &payload).unwrap(),
            );
            write_text(
                &path.join("src/identity.rs"),
                &format!(
                    "pub const COMPOSITION_HASH: &str = {:?};\n",
                    manifest.composition_hash
                ),
            )
            .unwrap();
            write_json(
                &path.join("rust-agent-security.json"),
                &SecurityManifest {
                    schema: 1,
                    composition_hash: manifest.composition_hash.clone(),
                    component_runtime_effects: manifest.component_runtime_effects.clone(),
                    host_runtime_effects: manifest.host_runtime_effects.clone(),
                    compiled_runtime_effects: manifest.compiled_runtime_effects.clone(),
                    build_requirements: manifest.build_requirements.clone(),
                },
            )
            .unwrap();
            write_json(&path.join("rust-agent-composition.json"), manifest).unwrap();
            let resealed_path = path.parent().unwrap().join(&manifest.composition_hash);
            fs::rename(path, &resealed_path).unwrap();
            resealed_path
        }

        let temp = TempDir::new().unwrap();
        let mut source_options = options(&temp, "tests/fixtures/profiles/minimal.toml");
        source_options.output_root = temp.path().join("source-record-order");
        let source_generated = compose(&source_options).unwrap();
        assert!(source_generated.manifest.sources.len() > 1);
        let mut source_manifest = source_generated.manifest.clone();
        source_manifest.sources.reverse();
        let source_path = reseal(&source_generated.path, &mut source_manifest);
        assert!(matches!(
            verify_composition(&source_path),
            Err(ComposeError::Verification(message))
                if message.contains("strict canonical id order")
        ));
        make_staging_tree_owner_writable(&source_path).unwrap();

        let mut generated_options = options(&temp, "tests/fixtures/profiles/minimal.toml");
        generated_options.output_root = temp.path().join("generated-record-order");
        let generated = compose(&generated_options).unwrap();
        assert!(generated.manifest.generated_files.len() > 1);
        let mut generated_manifest = generated.manifest.clone();
        generated_manifest.generated_files.reverse();
        let generated_path = reseal(&generated.path, &mut generated_manifest);
        assert!(matches!(
            verify_composition(&generated_path),
            Err(ComposeError::Verification(message))
                if message.contains("strict canonical path order")
        ));
        make_staging_tree_owner_writable(&generated_path).unwrap();
    }

    #[test]
    fn generator_input_commitment_rederives_resolution_and_exact_sidecar() {
        let temp = TempDir::new().unwrap();

        let mut resolution_options = options(&temp, "tests/fixtures/profiles/minimal.toml");
        resolution_options.output_root = temp.path().join("resolution-forgery");
        let generated = compose(&resolution_options).unwrap();
        let mut manifest = generated.manifest.clone();
        manifest.resolution.explored_decisions += 1;
        assert!(
            manifest.resolution.explored_decisions
                <= manifest.normalized_profile.resolver_decision_budget
        );
        let forged_path = reseal_manifest(&generated.path, &mut manifest);
        assert!(matches!(
            verify_composition(&forged_path),
            Err(ComposeError::ManifestNormalization { message, .. })
                if message.contains("resolution differs from the committed normalized catalog")
        ));
        make_staging_tree_owner_writable(&forged_path).unwrap();

        let mut sidecar_options = options(&temp, "tests/fixtures/profiles/minimal.toml");
        sidecar_options.output_root = temp.path().join("sidecar-forgery");
        let generated = compose(&sidecar_options).unwrap();
        let mut manifest = generated.manifest.clone();
        let compact = serde_json::to_vec(&manifest.generator_inputs).unwrap();
        fs::write(generated.path.join("generator-inputs.json"), &compact).unwrap();
        let record = manifest
            .generated_files
            .iter_mut()
            .find(|record| record.path == "generator-inputs.json")
            .unwrap();
        record.digest = sha256_hex(&compact);
        record.bytes = compact.len() as u64;
        let forged_path = reseal_manifest(&generated.path, &mut manifest);
        assert!(matches!(
            verify_composition(&forged_path),
            Err(ComposeError::Verification(message))
                if message.contains("exact deterministic commitment")
        ));
        make_staging_tree_owner_writable(&forged_path).unwrap();
    }

    #[test]
    fn generator_input_commitment_rederives_generated_and_source_closure() {
        let temp = TempDir::new().unwrap();

        let mut cargo_options = options(&temp, "tests/fixtures/profiles/minimal.toml");
        cargo_options.output_root = temp.path().join("cargo-forgery");
        let generated = compose(&cargo_options).unwrap();
        let mut manifest = generated.manifest.clone();
        let mut forged_cargo = fs::read(generated.path.join("Cargo.toml")).unwrap();
        forged_cargo.extend_from_slice(b"# identity-consistent forgery\n");
        fs::write(generated.path.join("Cargo.toml"), &forged_cargo).unwrap();
        let record = manifest
            .generated_files
            .iter_mut()
            .find(|record| record.path == "Cargo.toml")
            .unwrap();
        record.digest = sha256_hex(&forged_cargo);
        record.bytes = forged_cargo.len() as u64;
        let forged_path = reseal_manifest(&generated.path, &mut manifest);
        assert!(matches!(
            verify_composition(&forged_path),
            Err(ComposeError::Verification(message))
                if message.contains("generated `Cargo.toml` differs")
        ));
        make_staging_tree_owner_writable(&forged_path).unwrap();

        let mut source_options = options(&temp, "tests/fixtures/profiles/minimal.toml");
        source_options.output_root = temp.path().join("source-forgery");
        let generated = compose(&source_options).unwrap();
        let mut manifest = generated.manifest.clone();
        manifest.sources[0].package.push_str("-forged");
        let forged_path = reseal_manifest(&generated.path, &mut manifest);
        assert!(matches!(
            verify_composition(&forged_path),
            Err(ComposeError::Verification(message))
                if message.contains("source package closure differs")
        ));
        make_staging_tree_owner_writable(&forged_path).unwrap();
    }

    #[test]
    fn verification_rejects_resealed_unrewritten_target_dependency_manifest() {
        let temp = TempDir::new().unwrap();
        let generated = compose(&options(&temp, "tests/fixtures/profiles/minimal.toml")).unwrap();
        let mut manifest = generated.manifest.clone();
        let source_index = manifest
            .sources
            .iter()
            .position(|source| source.logical_path == "tests/fixtures/components/fixture-driver")
            .unwrap();
        let package_root = generated
            .path
            .join("sources")
            .join(&manifest.sources[source_index].logical_path);
        let cargo_manifest = package_root.join("Cargo.toml");
        let mut bytes = fs::read(&cargo_manifest).unwrap();
        bytes.extend_from_slice(
            br#"
[target.'cfg(target_arch = "wasm32")'.dependencies]
rust-agent-fixture-target-wasm = { version = "0.1.0", path = "../../helpers/fixture-target-wasm", default-features = false }
"#,
        );
        let mut permissions = fs::metadata(&cargo_manifest).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            permissions.set_mode(permissions.mode() | 0o200);
        }
        #[cfg(not(unix))]
        permissions.set_readonly(false);
        fs::set_permissions(&cargo_manifest, permissions).unwrap();
        fs::write(&cargo_manifest, bytes).unwrap();
        set_snapshot_epoch(&cargo_manifest).unwrap();
        set_snapshot_permissions(&cargo_manifest, false).unwrap();
        let tree = source_snapshot_tree(&package_root).unwrap();
        manifest.sources[source_index].tree_digest = tree.digest().into();
        manifest.sources[source_index].tree_entries = tree.entries().to_vec();
        let forged_path = reseal_manifest(&generated.path, &mut manifest);

        let result = verify_composition(&forged_path);
        assert!(
            matches!(
                result,
                Err(ComposeError::Verification(ref message))
                    if message.contains("exact target-fact-derived normalized manifest")
            ),
            "unexpected verification result: {result:?}"
        );
        make_staging_tree_owner_writable(&forged_path).unwrap();
    }

    #[cfg(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        windows
    ))]
    #[test]
    fn composition_publication_never_replaces_an_existing_empty_directory() {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(source.join("source-marker"), b"source").unwrap();

        assert!(publish_composition_noreplace(&source, &destination).is_err());
        assert!(source.join("source-marker").is_file());
        assert!(destination.is_dir());
        assert!(fs::read_dir(destination).unwrap().next().is_none());
    }

    #[test]
    fn fresh_publication_is_post_verified_before_success() {
        let temp = TempDir::new().unwrap();
        let generated = compose(&options(&temp, "tests/fixtures/profiles/minimal.toml")).unwrap();
        fs::write(generated.path.join("target-facts.json"), b"{").unwrap();

        let result = finish_published_composition(&generated.path, generated.manifest.clone());
        assert!(
            matches!(
                &result,
                Err(ComposeError::ExistingCompositionCorrupt { message, .. })
                    if message.contains("post-publication verification failed")
            ),
            "unexpected post-publication result: {result:?}"
        );
        assert!(generated.path.is_dir());
        make_staging_tree_owner_writable(&generated.path).unwrap();
    }

    #[test]
    fn snapshot_preflight_rejects_oversized_file_without_creating_destination() {
        let temp = TempDir::new().unwrap();
        let package = write_snapshot_fixture(temp.path(), "fixture");
        File::create(package.join("oversized.bin"))
            .unwrap()
            .set_len(MAX_CANONICAL_SNAPSHOT_FILE_BYTES + 1)
            .unwrap();
        let snapshot_root = temp.path().join("snapshots");

        assert!(matches!(
            snapshot_package(
                temp.path(),
                &snapshot_root,
                "fixture",
                "fixture",
                "fixture"
            ),
            Err(ComposeError::Snapshot(CanonicalSnapshotError::FileTooLarge {
                actual,
                maximum,
                ..
            })) if actual == MAX_CANONICAL_SNAPSHOT_FILE_BYTES + 1
                && maximum == MAX_CANONICAL_SNAPSHOT_FILE_BYTES
        ));
        assert!(!snapshot_root.join("fixture").exists());
    }

    #[test]
    fn snapshot_preflight_rejects_aggregate_overflow_without_copying() {
        let temp = TempDir::new().unwrap();
        let package = write_snapshot_fixture(temp.path(), "fixture");
        for name in ["a.bin", "b.bin", "c.bin", "d.bin"] {
            File::create(package.join(name))
                .unwrap()
                .set_len(MAX_CANONICAL_SNAPSHOT_FILE_BYTES)
                .unwrap();
        }
        let snapshot_root = temp.path().join("snapshots");

        assert!(matches!(
            snapshot_package(
                temp.path(),
                &snapshot_root,
                "fixture",
                "fixture",
                "fixture"
            ),
            Err(ComposeError::Snapshot(
                CanonicalSnapshotError::TotalBytesTooLarge { maximum, .. }
            )) if maximum == MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES
        ));
        assert!(!snapshot_root.join("fixture").exists());
    }

    #[test]
    fn composition_source_preflight_rejects_cross_package_overflow_before_copying() {
        let temp = TempDir::new().unwrap();
        let target = native_test_target();
        let mut packages = Vec::new();
        for name in ["first", "second"] {
            let package_root = write_snapshot_fixture(temp.path(), name);
            for file in ["a.bin", "b.bin"] {
                File::create(package_root.join(file))
                    .unwrap()
                    .set_len(MAX_CANONICAL_SNAPSHOT_FILE_BYTES)
                    .unwrap();
            }
            packages.push(PackageInput {
                id: name.into(),
                package: name.into(),
                path: name.into(),
                direct: true,
                manifest: normalize_package_manifest(temp.path(), name, &target).unwrap(),
            });
        }
        let snapshot_root = temp.path().join("snapshots");

        assert!(matches!(
            plan_composition_source_packages(temp.path(), &packages, &target),
            Err(ComposeError::Snapshot(
                CanonicalSnapshotError::TotalBytesTooLarge { maximum, .. }
            )) if maximum == MAX_COMPOSITION_SOURCE_FILE_BYTES
        ));
        assert!(!snapshot_root.exists());
    }

    #[test]
    fn composition_source_usage_closes_cross_package_entry_and_byte_boundaries() {
        let mut entries = CompositionSourceUsage::default();
        entries
            .account(MAX_COMPOSITION_SOURCE_ENTRIES - 1, 0)
            .unwrap();
        assert!(matches!(
            entries.account(2, 0),
            Err(ComposeError::Snapshot(
                CanonicalSnapshotError::TooManyEntries { maximum, .. }
            )) if maximum == MAX_COMPOSITION_SOURCE_ENTRIES
        ));

        let mut bytes = CompositionSourceUsage::default();
        bytes
            .account(0, MAX_COMPOSITION_SOURCE_FILE_BYTES - 1)
            .unwrap();
        assert!(matches!(
            bytes.account(0, 2),
            Err(ComposeError::Snapshot(
                CanonicalSnapshotError::TotalBytesTooLarge { maximum, .. }
            )) if maximum == MAX_COMPOSITION_SOURCE_FILE_BYTES
        ));
    }

    #[test]
    fn snapshot_verification_rejects_aggregate_overflow_before_hashing_sparse_files() {
        let temp = TempDir::new().unwrap();
        let package = write_snapshot_fixture(temp.path(), "fixture");
        for name in ["a.bin", "b.bin", "c.bin", "d.bin"] {
            File::create(package.join(name))
                .unwrap()
                .set_len(MAX_CANONICAL_SNAPSHOT_FILE_BYTES)
                .unwrap();
        }
        seal_source_snapshot_storage_projection(&package).unwrap();

        assert!(matches!(
            source_snapshot_tree(&package),
            Err(ComposeError::Snapshot(
                CanonicalSnapshotError::TotalBytesTooLarge { maximum, .. }
            )) if maximum == MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES
        ));
        make_staging_tree_owner_writable(&package).unwrap();
    }

    #[test]
    fn composition_source_verification_rejects_cross_package_overflow_before_hashing() {
        let temp = TempDir::new().unwrap();
        let composition = temp.path().join("composition");
        let sources_root = composition.join("sources");
        fs::create_dir_all(&sources_root).unwrap();
        let mut sources = Vec::new();
        for name in ["first", "second"] {
            let package_root = write_snapshot_fixture(&sources_root, name);
            for file in ["a.bin", "b.bin"] {
                File::create(package_root.join(file))
                    .unwrap()
                    .set_len(MAX_CANONICAL_SNAPSHOT_FILE_BYTES)
                    .unwrap();
            }
            seal_source_snapshot_storage_projection(&package_root).unwrap();
            sources.push(SourcePackageRecord {
                id: name.into(),
                package: name.into(),
                logical_path: name.into(),
                tree_digest: String::new(),
                tree_entries: Vec::new(),
            });
        }

        assert!(matches!(
            preflight_composition_source_snapshots(&composition, &sources),
            Err(ComposeError::Snapshot(
                CanonicalSnapshotError::TotalBytesTooLarge { maximum, .. }
            )) if maximum == MAX_COMPOSITION_SOURCE_FILE_BYTES
        ));
        make_staging_tree_owner_writable(&sources_root).unwrap();
    }

    #[test]
    fn snapshot_manifest_read_is_bounded_before_parsing_or_copying() {
        let temp = TempDir::new().unwrap();
        let package = temp.path().join("fixture");
        fs::create_dir_all(&package).unwrap();
        File::create(package.join("Cargo.toml"))
            .unwrap()
            .set_len(MAX_SOURCE_MANIFEST_BYTES + 1)
            .unwrap();
        let snapshot_root = temp.path().join("snapshots");

        assert!(matches!(
            snapshot_package(
                temp.path(),
                &snapshot_root,
                "fixture",
                "fixture",
                "fixture"
            ),
            Err(ComposeError::Snapshot(CanonicalSnapshotError::FileTooLarge {
                actual,
                maximum,
                ..
            })) if actual == MAX_SOURCE_MANIFEST_BYTES + 1
                && maximum == MAX_SOURCE_MANIFEST_BYTES
        ));
        assert!(!snapshot_root.join("fixture").exists());
    }

    #[test]
    fn transient_trees_are_pruned_before_snapshot_resource_checks() {
        let temp = TempDir::new().unwrap();
        let package = write_snapshot_fixture(temp.path(), "fixture");
        for relative in ["target/huge.bin", ".git/huge.bin", "wip/huge.bin"] {
            let path = package.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            File::create(path)
                .unwrap()
                .set_len(MAX_CANONICAL_SNAPSHOT_FILE_BYTES + 1)
                .unwrap();
        }
        let snapshot_root = temp.path().join("snapshots");
        let record =
            snapshot_package(temp.path(), &snapshot_root, "fixture", "fixture", "fixture").unwrap();

        assert!(
            record
                .tree_entries
                .iter()
                .all(|entry| !entry.path.starts_with("target/")
                    && !entry.path.starts_with(".git/")
                    && !entry.path.starts_with("wip/"))
        );
        make_staging_tree_owner_writable(&snapshot_root).unwrap();
    }

    #[test]
    fn snapshot_streaming_copy_preserves_multibuffer_bytes_and_digest() {
        let temp = TempDir::new().unwrap();
        let package = write_snapshot_fixture(temp.path(), "fixture");
        let bytes = (0..(SNAPSHOT_COPY_BUFFER_BYTES * 2 + 17))
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        fs::write(package.join("payload.bin"), &bytes).unwrap();
        let snapshot_root = temp.path().join("snapshots");
        let record =
            snapshot_package(temp.path(), &snapshot_root, "fixture", "fixture", "fixture").unwrap();

        let payload = record
            .tree_entries
            .iter()
            .find(|entry| entry.path == "payload.bin")
            .unwrap();
        assert!(matches!(
            &payload.kind,
            CanonicalSnapshotEntryKind::RegularFile { sha256, bytes: actual }
                if sha256 == &sha256_hex(&bytes) && *actual == bytes.len() as u64
        ));
        assert_eq!(
            fs::read(snapshot_root.join("fixture/payload.bin")).unwrap(),
            bytes
        );
        make_staging_tree_owner_writable(&snapshot_root).unwrap();
    }

    #[test]
    fn snapshot_epoch_opens_files_and_directories() {
        let temp = TempDir::new().unwrap();
        let directory = temp.path().join("directory");
        let file = temp.path().join("file");
        fs::create_dir(&directory).unwrap();
        fs::write(&file, b"file").unwrap();

        for path in [&file, &directory] {
            set_snapshot_epoch(path).unwrap();
            assert_eq!(
                fs::symlink_metadata(path).unwrap().modified().unwrap(),
                SystemTime::UNIX_EPOCH
            );
        }
    }

    #[test]
    fn javascript_wasm_requires_an_explicit_registry_cache() {
        let temp = TempDir::new().unwrap();
        assert!(matches!(
            compose(&options(&temp, "tests/fixtures/profiles/wasm-js.toml")),
            Err(ComposeError::InvalidRegistryCache(_))
        ));
    }

    #[test]
    fn trybuild_wip_does_not_enter_the_source_snapshot() {
        let temp = TempDir::new().unwrap();
        let package = temp.path().join("fixture");
        fs::create_dir_all(package.join("src")).unwrap();
        fs::create_dir_all(package.join("wip")).unwrap();
        fs::write(
            package.join("Cargo.toml"),
            format!(
                "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"{PINNED_RUST_VERSION}\"\nlicense = \"MIT\"\n"
            ),
        )
        .unwrap();
        fs::write(package.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
        fs::write(package.join("wip/.gitignore"), "*\n").unwrap();
        fs::write(package.join("wip/transient.stderr"), "not canonical\n").unwrap();

        let snapshot_root = temp.path().join("snapshots");
        let record =
            snapshot_package(temp.path(), &snapshot_root, "fixture", "fixture", "fixture").unwrap();

        assert_eq!(
            record
                .tree_entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            ["Cargo.toml", "src", "src/lib.rs"]
        );
        let tree = CanonicalSnapshotTree::from_entries(record.tree_entries.clone()).unwrap();
        assert_eq!(record.tree_digest, tree.digest());
        assert!(record.tree_entries.iter().all(|entry| match &entry.kind {
            CanonicalSnapshotEntryKind::Directory => entry.metadata.mode == 0o555,
            CanonicalSnapshotEntryKind::RegularFile { .. } => entry.metadata.mode == 0o444,
        }));
        assert!(!snapshot_root.join("fixture/wip").exists());
    }

    #[test]
    fn source_snapshot_uses_shared_contract_and_rejects_storage_metadata_drift() {
        use std::time::Duration;

        fn assert_metadata_drift(root: &Path) {
            assert!(matches!(
                source_snapshot_tree(root),
                Err(ComposeError::Verification(message)) if message.contains("metadata drifted")
            ));
        }

        let temp = TempDir::new().unwrap();
        let package = temp.path().join("fixture");
        fs::create_dir_all(package.join("src")).unwrap();
        fs::write(
            package.join("Cargo.toml"),
            format!(
                "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"{PINNED_RUST_VERSION}\"\nlicense = \"MIT\"\n"
            ),
        )
        .unwrap();
        fs::write(package.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();

        let snapshot_root = temp.path().join("snapshots");
        let record =
            snapshot_package(temp.path(), &snapshot_root, "fixture", "fixture", "fixture").unwrap();
        let root = snapshot_root.join("fixture");
        let actual = source_snapshot_tree(&root).unwrap();
        assert_eq!(actual.entries(), record.tree_entries);
        assert_eq!(actual.digest(), record.tree_digest);

        let file = root.join("src/lib.rs");
        let directory = root.join("src");
        for path in [&file, &directory] {
            open_metadata_handle(path)
                .unwrap()
                .set_times(
                    FileTimes::new()
                        .set_accessed(SystemTime::UNIX_EPOCH)
                        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
                )
                .unwrap();
            assert_metadata_drift(&root);
            set_snapshot_epoch(path).unwrap();
            source_snapshot_tree(&root).unwrap();
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            for (path, drifted_mode, directory) in
                [(&file, 0o644, false), (&directory, 0o755, true)]
            {
                fs::set_permissions(path, fs::Permissions::from_mode(drifted_mode)).unwrap();
                assert_metadata_drift(&root);
                set_snapshot_permissions(path, directory).unwrap();
                source_snapshot_tree(&root).unwrap();
            }
        }

        make_staging_tree_owner_writable(&snapshot_root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn readonly_source_snapshot_staging_cleanup_restores_owner_write() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let staging = temp.path().join("staging");
        let nested = staging.join("sources/package/src");
        fs::create_dir_all(&nested).unwrap();
        let file = nested.join("lib.rs");
        fs::write(&file, b"pub fn fixture() {}\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o444)).unwrap();
        for directory in [
            &nested,
            &staging.join("sources/package"),
            &staging.join("sources"),
            &staging,
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o555)).unwrap();
        }

        make_staging_tree_owner_writable(&staging).unwrap();
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o600,
            0o600
        );
        assert_eq!(
            fs::metadata(&nested).unwrap().permissions().mode() & 0o700,
            0o700
        );
        remove_staging_tree(&staging).unwrap();
        assert!(!staging.exists());
    }

    #[test]
    fn minimal_golden_is_fresh() {
        let temp = TempDir::new().unwrap();
        let generated = compose(&options(&temp, "tests/fixtures/profiles/minimal.toml")).unwrap();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        for (actual, golden) in [
            ("Cargo.toml", "Cargo.toml"),
            ("compose-rustc.json", "compose-rustc.json"),
            ("generator-inputs.json", "generator-inputs.json"),
            ("src/lib.rs", "lib.rs"),
            ("target-facts.json", "target-facts.json"),
            ("rust-agent-composition.json", "rust-agent-composition.json"),
        ] {
            if std::env::var_os("RUST_AGENT_UPDATE_GOLDENS").as_deref()
                == Some(std::ffi::OsStr::new("1"))
            {
                fs::copy(
                    generated.path.join(actual),
                    root.join("tests/golden/minimal").join(golden),
                )
                .unwrap();
            }
            assert_eq!(
                fs::read(generated.path.join(actual)).unwrap(),
                fs::read(root.join("tests/golden/minimal").join(golden)).unwrap(),
                "stale golden {golden}"
            );
        }
    }

    #[test]
    fn javascript_wasm_golden_is_fresh() {
        let temp = TempDir::new().unwrap();
        let mut wasm_options = options(&temp, "tests/fixtures/profiles/wasm-js.toml");
        wasm_options.registry_cache_path = Some(registry_cache());
        let generated = compose(&wasm_options).unwrap();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        for (actual, golden) in [
            ("Cargo.toml", "Cargo.toml"),
            ("compose-rustc.json", "compose-rustc.json"),
            ("generator-inputs.json", "generator-inputs.json"),
            ("src/lib.rs", "lib.rs"),
            ("src/wasm.rs", "wasm.rs"),
            ("target-facts.json", "target-facts.json"),
            ("rust-agent-composition.json", "rust-agent-composition.json"),
        ] {
            if std::env::var_os("RUST_AGENT_UPDATE_GOLDENS").as_deref()
                == Some(std::ffi::OsStr::new("1"))
            {
                fs::copy(
                    generated.path.join(actual),
                    root.join("tests/golden/wasm-js").join(golden),
                )
                .unwrap();
            }
            assert_eq!(
                fs::read(generated.path.join(actual)).unwrap(),
                fs::read(root.join("tests/golden/wasm-js").join(golden)).unwrap(),
                "stale golden {golden}"
            );
        }
    }

    #[test]
    fn wasm_direct_host_tool_requirement_is_identity_bound() {
        let temp = TempDir::new().unwrap();
        let mut wasm_options = options(&temp, "tests/fixtures/profiles/wasm-js.toml");
        wasm_options.registry_cache_path = Some(registry_cache());
        let generated = compose(&wasm_options).unwrap();
        let manifest_path = generated.path.join("rust-agent-composition.json");
        let mut manifest = generated.manifest.clone();
        manifest
            .direct_root_build_requirements
            .get_mut("host-boundary:fixture-host-export")
            .unwrap()
            .executables
            .clear();
        manifest.build_requirements.executables.clear();
        manifest.resolution.build_requirements.executables.clear();
        write_json(&manifest_path, &manifest).unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::ManifestNormalization { message, .. })
                if message.contains("resolution differs from the committed normalized catalog")
        ));
    }

    #[test]
    fn selected_packages_match_cargo_tree() {
        let temp = TempDir::new().unwrap();
        let minimal = compose(&options(&temp, "tests/fixtures/profiles/minimal.toml")).unwrap();
        let with_fs = compose(&options(&temp, "tests/fixtures/profiles/with-fs.toml")).unwrap();
        let mut wasm_options = options(&temp, "tests/fixtures/profiles/wasm-js.toml");
        wasm_options.registry_cache_path = Some(registry_cache());
        let wasm = compose(&wasm_options).unwrap();
        assert!(
            !minimal
                .path
                .join("sources/tests/fixtures/components/fixture-fs-read")
                .exists()
        );
        assert!(
            with_fs
                .path
                .join("sources/tests/fixtures/components/fixture-fs-read")
                .exists()
        );
        assert!(
            !minimal
                .manifest
                .selected_components
                .contains(&"fixture-fs-read".into())
        );
        assert!(
            with_fs
                .manifest
                .selected_components
                .contains(&"fixture-fs-read".into())
        );
        assert!(
            minimal
                .path
                .join("sources/tests/fixtures/helpers/fixture-target-native")
                .exists()
        );
        assert!(
            !minimal
                .path
                .join("sources/tests/fixtures/helpers/fixture-target-wasm")
                .exists()
        );
        assert!(
            wasm.path
                .join("sources/tests/fixtures/helpers/fixture-target-wasm")
                .exists()
        );
        assert!(
            !wasm
                .path
                .join("sources/tests/fixtures/helpers/fixture-target-native")
                .exists()
        );
        let minimal_driver_manifest = fs::read_to_string(
            minimal
                .path
                .join("sources/tests/fixtures/components/fixture-driver/Cargo.toml"),
        )
        .unwrap();
        let wasm_driver_manifest = fs::read_to_string(
            wasm.path
                .join("sources/tests/fixtures/components/fixture-driver/Cargo.toml"),
        )
        .unwrap();
        assert!(!minimal_driver_manifest.contains("[target."));
        assert!(minimal_driver_manifest.contains("rust-agent-fixture-target-native"));
        assert!(!minimal_driver_manifest.contains("rust-agent-fixture-target-wasm"));
        assert!(!wasm_driver_manifest.contains("[target."));
        assert!(wasm_driver_manifest.contains("rust-agent-fixture-target-wasm"));
        assert!(!wasm_driver_manifest.contains("rust-agent-fixture-target-native"));
        let minimal_generated_manifest =
            fs::read_to_string(minimal.path.join("Cargo.toml")).unwrap();
        let wasm_generated_manifest = fs::read_to_string(wasm.path.join("Cargo.toml")).unwrap();
        assert!(!minimal_generated_manifest.contains("rust-agent-fixture-target-native"));
        assert!(!wasm_generated_manifest.contains("rust-agent-fixture-target-wasm"));

        let minimal_tree = cargo_tree(&minimal.path);
        let with_fs_tree = cargo_tree(&with_fs.path);
        let wasm_tree = cargo_tree(&wasm.path);
        let minimal_metadata = cargo_metadata_packages(&minimal.path);
        let wasm_metadata = cargo_metadata_packages(&wasm.path);
        let minimal_lock = fs::read_to_string(minimal.path.join("Cargo.lock")).unwrap();
        let wasm_lock = fs::read_to_string(wasm.path.join("Cargo.lock")).unwrap();
        assert!(!minimal_tree.contains("rust-agent-fixture-fs-read"));
        assert!(with_fs_tree.contains("rust-agent-fixture-fs-read"));
        assert!(!minimal_tree.contains("rust-agent-fixture-model-fallback"));
        assert!(minimal_tree.contains("rust-agent-fixture-target-native"));
        assert!(!minimal_tree.contains("rust-agent-fixture-target-wasm"));
        assert!(wasm_tree.contains("rust-agent-fixture-target-wasm"));
        assert!(!wasm_tree.contains("rust-agent-fixture-target-native"));
        assert!(minimal_metadata.contains("rust-agent-fixture-target-native"));
        assert!(!minimal_metadata.contains("rust-agent-fixture-target-wasm"));
        assert!(wasm_metadata.contains("rust-agent-fixture-target-wasm"));
        assert!(!wasm_metadata.contains("rust-agent-fixture-target-native"));
        assert!(minimal_lock.contains("rust-agent-fixture-target-native"));
        assert!(!minimal_lock.contains("rust-agent-fixture-target-wasm"));
        assert!(wasm_lock.contains("rust-agent-fixture-target-wasm"));
        assert!(!wasm_lock.contains("rust-agent-fixture-target-native"));
    }

    fn cargo_tree(composition: &Path) -> String {
        let sandbox = TempDir::new().unwrap();
        link_registry_cache(sandbox.path(), Some(&registry_cache())).unwrap();
        let manifest = load_manifest(composition).unwrap();
        let output = Command::new(tool("cargo"))
            .args([
                "tree",
                "--locked",
                "--offline",
                "--edges",
                "normal",
                "--target",
                &manifest.cargo_resolution.cargo_target_input,
            ])
            .arg("--manifest-path")
            .arg(composition.join("Cargo.toml"))
            .arg("--config")
            .arg(composition.join(".cargo/config.toml"))
            .current_dir(composition)
            .env_clear()
            .env("CARGO_HOME", sandbox.path())
            .env("RUSTC", tool("rustc"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn cargo_metadata_packages(composition: &Path) -> BTreeSet<String> {
        let sandbox = TempDir::new().unwrap();
        link_registry_cache(sandbox.path(), Some(&registry_cache())).unwrap();
        let manifest = load_manifest(composition).unwrap();
        let output = Command::new(tool("cargo"))
            .args([
                "metadata",
                "--format-version",
                "1",
                "--locked",
                "--offline",
                "--filter-platform",
                &manifest.cargo_resolution.cargo_target_input,
            ])
            .arg("--manifest-path")
            .arg(composition.join("Cargo.toml"))
            .arg("--config")
            .arg(composition.join(".cargo/config.toml"))
            .current_dir(composition)
            .env_clear()
            .env("CARGO_HOME", sandbox.path())
            .env("RUSTC", tool("rustc"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        document["packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|package| package["name"].as_str().unwrap().to_owned())
            .collect()
    }
}
