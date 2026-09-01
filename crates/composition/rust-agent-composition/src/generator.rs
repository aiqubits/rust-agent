use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, FileTimes},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
};

use serde::Serialize;
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
    catalog::{CatalogError, NormalizedCatalog},
    manifest::{
        CargoResolutionRecord, CompositionIdentityPayload, CompositionManifest,
        GeneratedFileRecord, SecurityManifest, SourcePackageRecord,
    },
    metadata::{BuildRequirements, CatalogDocument, HostBoundaryKind},
    profile::{BuildKind, CompositionProfile},
    resolver::{ResolutionError, resolve},
    snapshot::{
        CanonicalSnapshotEntry, CanonicalSnapshotEntryKind, CanonicalSnapshotError,
        CanonicalSnapshotTree, MAX_CANONICAL_SNAPSHOT_ENTRIES, MAX_CANONICAL_SNAPSHOT_FILE_BYTES,
        MAX_CANONICAL_SNAPSHOT_JSON_BYTES, MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES,
    },
    target::{Target, TargetError},
};

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(1);
const PINNED_RUST_VERSION: &str = env!("CARGO_PKG_RUST_VERSION");
const MAX_SOURCE_MANIFEST_BYTES: u64 = MAX_CANONICAL_SNAPSHOT_JSON_BYTES as u64;
const MAX_COMPOSITION_CONTROL_FILE_BYTES: u64 = MAX_CANONICAL_SNAPSHOT_JSON_BYTES as u64;
const SNAPSHOT_COPY_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompositionTreeEntryKind {
    Directory,
    RegularFile,
}

#[derive(Clone, Debug)]
pub struct ComposeOptions {
    pub workspace_root: PathBuf,
    pub catalog_path: PathBuf,
    pub profile_path: PathBuf,
    pub output_root: PathBuf,
    pub rustc_path: PathBuf,
    pub cargo_path: PathBuf,
    pub registry_cache_path: Option<PathBuf>,
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
    #[error("I/O failed while composing: {0}")]
    Io(#[from] io::Error),
    #[error("catalog TOML is invalid: {0}")]
    CatalogToml(#[source] toml::de::Error),
    #[error("profile TOML is invalid: {0}")]
    ProfileToml(#[source] toml::de::Error),
    #[error("catalog is invalid: {0}")]
    Catalog(#[from] CatalogError),
    #[error("target is invalid: {0}")]
    Target(#[from] TargetError),
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
}

pub fn compose(options: &ComposeOptions) -> Result<GeneratedComposition, ComposeError> {
    validate_options(options)?;
    let catalog_bytes = read_workspace_input(&options.workspace_root, &options.catalog_path)?;
    let profile_bytes = read_workspace_input(&options.workspace_root, &options.profile_path)?;
    let document =
        CatalogDocument::from_toml(std::str::from_utf8(&catalog_bytes).map_err(|error| {
            ComposeError::ManifestNormalization {
                path: options.catalog_path.display().to_string(),
                message: error.to_string(),
            }
        })?)
        .map_err(ComposeError::CatalogToml)?;
    let catalog = NormalizedCatalog::normalize(document)?;
    let profile =
        CompositionProfile::from_toml(std::str::from_utf8(&profile_bytes).map_err(|error| {
            ComposeError::ManifestNormalization {
                path: options.profile_path.display().to_string(),
                message: error.to_string(),
            }
        })?)
        .map_err(ComposeError::ProfileToml)?;
    if !matches!(profile.build_kind, BuildKind::Library | BuildKind::Wasm) {
        return Err(ComposeError::UnsupportedPhase1A(format!(
            "{:?}",
            profile.build_kind
        )));
    }
    let target = Target::query(&options.rustc_path, &profile.target, profile.environment)?;
    let resolution = resolve(&catalog, &profile, &target)?;
    let requires_registry = profile.build_kind == BuildKind::Wasm
        || selected_packages_require_registry(&options.workspace_root, &catalog, &resolution)?;
    if requires_registry && options.registry_cache_path.is_none() {
        return Err(ComposeError::InvalidRegistryCache(
            "composition Cargo graph requires an explicit offline registry cache".into(),
        ));
    }

    fs::create_dir_all(&options.output_root)?;
    let staging = unique_staging(&options.output_root);
    fs::create_dir(&staging)?;
    let result = compose_in_staging(options, &catalog, &profile, &target, &resolution, &staging);
    if result.is_err() {
        let _ = remove_staging_tree(&staging);
    }
    result
}

fn compose_in_staging(
    options: &ComposeOptions,
    catalog: &NormalizedCatalog,
    profile: &CompositionProfile,
    target: &Target,
    resolution: &crate::resolver::Resolution,
    staging: &Path,
) -> Result<GeneratedComposition, ComposeError> {
    let source_root = staging.join("sources");
    fs::create_dir_all(&source_root)?;
    let package_inputs = selected_packages(catalog, resolution)?;
    let mut sources = Vec::new();
    for package in &package_inputs {
        sources.push(snapshot_package(
            &options.workspace_root,
            &source_root,
            &package.id,
            &package.package,
            &package.path,
        )?);
    }
    sources.sort_by(|left, right| left.id.cmp(&right.id));

    fs::create_dir_all(staging.join("src"))?;
    fs::create_dir_all(staging.join(".cargo"))?;
    fs::create_dir_all(staging.join("vendor"))?;
    write_text(
        &staging.join("Cargo.toml"),
        &generate_cargo_toml(catalog, resolution, &package_inputs, profile.build_kind),
    )?;
    write_text(
        &staging.join("src/lib.rs"),
        &generate_lib_rs(catalog, resolution, profile.build_kind)?,
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

    write_text(
        &staging.join(".cargo/config.toml"),
        &format!(
            "[build]\ntarget = {:?}\n\n[net]\noffline = true\n",
            target.triple
        ),
    )?;

    generate_lockfile(options, staging)?;
    let (registries, git_sources) = locked_cargo_sources(&staging.join("Cargo.lock"))?;
    let cargo_resolution = CargoResolutionRecord {
        schema: 1,
        target: target.triple.clone(),
        target_fact_digest: target.target_fact_digest.clone(),
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
        ".cargo/config.toml",
        "src/lib.rs",
    ];
    if profile.build_kind == BuildKind::Wasm {
        generated_paths.push("src/wasm.rs");
    }
    let generated_files = generated_file_records(staging, &generated_paths)?;
    let direct_root_build_requirements = direct_root_build_requirements(catalog, resolution);
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
        selected_components: resolution.selected_components.clone(),
        runtime_adapter: resolution.runtime_adapter.clone(),
        host_boundary: resolution.host_boundary.clone(),
        component_runtime_effects: component_runtime_effects.clone(),
        host_runtime_effects: host_runtime_effects.clone(),
        compiled_runtime_effects: resolution.compiled_runtime_effects.clone(),
        build_requirements: resolution.build_requirements.clone(),
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
            build_requirements: resolution.build_requirements.clone(),
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
    Ok(GeneratedComposition {
        composition_hash,
        path: final_path,
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
) -> BTreeMap<String, crate::metadata::BuildRequirements> {
    let mut roots = BTreeMap::from([
        ("api:rust-agent-core".into(), BuildRequirements::default()),
        (
            "api:rust-agent-runtime-api".into(),
            BuildRequirements::default(),
        ),
        (
            "api:rust-agent-fixture-api".into(),
            BuildRequirements::default(),
        ),
    ]);
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
    roots
}

pub fn load_manifest(path: &Path) -> Result<CompositionManifest, ComposeError> {
    let manifest_path = path.join("rust-agent-composition.json");
    let bytes = read_composition_regular_file_bounded(
        &manifest_path,
        MAX_COMPOSITION_CONTROL_FILE_BYTES,
        None,
    )?;
    serde_json::from_slice(&bytes).map_err(|error| ComposeError::ManifestNormalization {
        path: manifest_path.display().to_string(),
        message: error.to_string(),
    })
}

pub fn verify_composition(path: &Path) -> Result<CompositionManifest, ComposeError> {
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
    if manifest.schema != 1 || manifest.algorithm != "sha256-rust-agent-composition-v1" {
        return Err(ComposeError::Verification(
            "unknown manifest schema or algorithm".into(),
        ));
    }
    if manifest.normalized_profile.schema != 1
        || manifest.resolution.schema != 1
        || manifest.cargo_resolution.schema != 1
        || manifest.build_kind != manifest.normalized_profile.build_kind
        || manifest.profile != manifest.normalized_profile.name
        || manifest.target != manifest.normalized_target.triple
        || manifest.target_fact_digest != manifest.normalized_target.target_fact_digest
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
        || manifest.build_requirements != manifest.resolution.build_requirements
        || manifest.cargo_resolution.target != manifest.target
        || manifest.cargo_resolution.target_fact_digest != manifest.target_fact_digest
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
    let mut runtime_effect_union = manifest.component_runtime_effects.clone();
    runtime_effect_union.extend(manifest.host_runtime_effects.iter().cloned());
    if runtime_effect_union != manifest.compiled_runtime_effects {
        return Err(ComposeError::Verification(
            "Component and Host runtime effects do not equal the compiled runtime-effect union"
                .into(),
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
    let mut requirement_union = crate::metadata::BuildRequirements::default();
    for requirements in manifest.direct_root_build_requirements.values() {
        requirement_union
            .executables
            .extend(requirements.executables.iter().cloned());
        requirement_union
            .read_inputs
            .extend(requirements.read_inputs.iter().cloned());
        requirement_union
            .environment
            .extend(requirements.environment.iter().cloned());
    }
    if requirement_union != manifest.build_requirements {
        return Err(ComposeError::Verification(
            "direct root build requirements do not equal the authorized union".into(),
        ));
    }

    let mut expected_tree = BTreeMap::new();
    for directory in [".cargo", "sources", "src", "vendor"] {
        insert_expected_composition_entry(
            &mut expected_tree,
            directory,
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

    let expected_generated_paths = expected_generated_file_paths(manifest.build_kind);
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
    if cargo_resolution != manifest.cargo_resolution
        || sha256_hex(&cargo_resolution_bytes) != manifest.cargo_resolution_digest
    {
        return Err(ComposeError::Verification(
            "Cargo resolution record drifted".into(),
        ));
    }
    if hash_composition_regular_file_bounded(
        &path.join("Cargo.lock"),
        MAX_COMPOSITION_CONTROL_FILE_BYTES,
        None,
    )?
    .0 != manifest.cargo_lock_digest
    {
        return Err(ComposeError::Verification("Cargo.lock drifted".into()));
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
    if security != expected_security {
        return Err(ComposeError::Verification(
            "security manifest drifted".into(),
        ));
    }
    Ok(manifest)
}

fn expected_generated_file_paths(build_kind: BuildKind) -> BTreeSet<String> {
    let mut paths = BTreeSet::from([
        ".cargo/config.toml".into(),
        "Cargo.toml".into(),
        "cargo-resolution.json".into(),
        "src/lib.rs".into(),
    ]);
    if build_kind == BuildKind::Wasm {
        paths.insert("src/wasm.rs".into());
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
}

fn selected_packages(
    catalog: &NormalizedCatalog,
    resolution: &crate::resolver::Resolution,
) -> Result<Vec<PackageInput>, ComposeError> {
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
            PackageInput {
                id: id.to_owned(),
                package: package.to_owned(),
                path: path.to_owned(),
            },
        );
    }
    for id in &resolution.selected_components {
        let component = &catalog.components[id];
        packages.insert(
            component.package_path.clone(),
            PackageInput {
                id: component.id.clone(),
                package: component.package.clone(),
                path: component.package_path.clone(),
            },
        );
    }
    let adapter = &catalog.runtime_adapters[&resolution.runtime_adapter];
    packages.insert(
        adapter.package_path.clone(),
        PackageInput {
            id: adapter.id.clone(),
            package: adapter.package.clone(),
            path: adapter.package_path.clone(),
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
            PackageInput {
                id: boundary.id.clone(),
                package: boundary.package.clone(),
                path: boundary.package_path.clone(),
            },
        );
    }
    Ok(packages.into_values().collect())
}

fn selected_packages_require_registry(
    workspace_root: &Path,
    catalog: &NormalizedCatalog,
    resolution: &crate::resolver::Resolution,
) -> Result<bool, ComposeError> {
    for package in selected_packages(catalog, resolution)? {
        let manifest_path = workspace_root.join(&package.path).join("Cargo.toml");
        let manifest_bytes =
            read_bounded_snapshot_source_file(&manifest_path, MAX_SOURCE_MANIFEST_BYTES)?;
        let input = std::str::from_utf8(&manifest_bytes).map_err(|error| {
            ComposeError::ManifestNormalization {
                path: manifest_path.display().to_string(),
                message: error.to_string(),
            }
        })?;
        let document: toml::Value =
            toml::from_str(input).map_err(|error| ComposeError::ManifestNormalization {
                path: manifest_path.display().to_string(),
                message: error.to_string(),
            })?;
        if manifest_requires_registry(&document) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn manifest_requires_registry(document: &toml::Value) -> bool {
    let Some(root) = document.as_table() else {
        return false;
    };
    if dependency_sections_require_registry(root) {
        return true;
    }
    root.get("target")
        .and_then(toml::Value::as_table)
        .is_some_and(|targets| {
            targets.values().any(|target| {
                target
                    .as_table()
                    .is_some_and(dependency_sections_require_registry)
            })
        })
}

fn dependency_sections_require_registry(table: &toml::Table) -> bool {
    ["dependencies", "build-dependencies"]
        .into_iter()
        .filter_map(|section| table.get(section).and_then(toml::Value::as_table))
        .flatten()
        .any(|(_, dependency)| match dependency {
            toml::Value::Table(specification) => {
                !specification.contains_key("path") && !specification.contains_key("git")
            }
            _ => true,
        })
}

#[derive(Debug)]
struct SnapshotPackagePlanEntry {
    source: PathBuf,
    relative: PathBuf,
    logical_path: String,
    content: SnapshotPackagePlanContent,
}

#[derive(Debug)]
enum SnapshotPackagePlanContent {
    Directory,
    RegularFile { bytes: u64 },
    NormalizedManifest { bytes: Vec<u8> },
}

fn snapshot_package(
    workspace_root: &Path,
    source_root: &Path,
    id: &str,
    package: &str,
    logical_path: &str,
) -> Result<SourcePackageRecord, ComposeError> {
    let source = workspace_root.join(logical_path);
    let source_metadata = fs::symlink_metadata(&source).map_err(|error| {
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
    let plan = plan_snapshot_package(&source)?;
    let destination = source_root.join(logical_path);
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(ComposeError::Verification(format!(
            "source snapshot destination already exists: {}",
            destination.display()
        )));
    }
    fs::create_dir_all(&destination)?;
    let result = (|| {
        let copied_tree = materialize_snapshot_package_plan(&source, &destination, &plan)?;
        seal_source_snapshot_storage_projection(&destination)?;
        let tree = source_snapshot_tree(&destination)?;
        if tree != copied_tree {
            return Err(ComposeError::Verification(format!(
                "source snapshot changed while materializing `{}`",
                source.display()
            )));
        }
        Ok(SourcePackageRecord {
            id: id.to_owned(),
            package: package.to_owned(),
            logical_path: logical_path.to_owned(),
            tree_digest: tree.digest().to_owned(),
            tree_entries: tree.entries().to_vec(),
        })
    })();
    if result.is_err() {
        let _ = remove_staging_tree(&destination);
    }
    result
}

fn plan_snapshot_package(source: &Path) -> Result<Vec<SnapshotPackagePlanEntry>, ComposeError> {
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
            let bytes = normalize_snapshot_manifest(entry.path())?;
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
    Ok(plan)
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
                let current = normalize_snapshot_manifest(&entry.source)?;
                if current != *bytes {
                    return Err(ComposeError::Verification(format!(
                        "source manifest `{}` changed while snapshotting",
                        entry.source.display()
                    )));
                }
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

fn normalize_snapshot_manifest(path: &Path) -> Result<Vec<u8>, ComposeError> {
    let input = read_bounded_snapshot_source_file(path, MAX_SOURCE_MANIFEST_BYTES)?;
    let input =
        std::str::from_utf8(&input).map_err(|error| ComposeError::ManifestNormalization {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    let mut value: toml::Value =
        toml::from_str(input).map_err(|error| ComposeError::ManifestNormalization {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    let table = value
        .as_table_mut()
        .ok_or_else(|| ComposeError::ManifestNormalization {
            path: path.display().to_string(),
            message: "manifest root is not a table".into(),
        })?;
    let package = table
        .get_mut("package")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| ComposeError::ManifestNormalization {
            path: path.display().to_string(),
            message: "manifest has no package table".into(),
        })?;
    package.insert("version".into(), toml::Value::String("0.1.0".into()));
    package.insert("edition".into(), toml::Value::String("2024".into()));
    package.insert(
        "rust-version".into(),
        toml::Value::String(PINNED_RUST_VERSION.into()),
    );
    package.insert("license".into(), toml::Value::String("MIT".into()));
    package.remove("repository");
    table.remove("dev-dependencies");
    table.remove("lints");
    if let Some(targets) = table.get_mut("target").and_then(toml::Value::as_table_mut) {
        for target in targets
            .iter_mut()
            .filter_map(|(_, value)| toml::Value::as_table_mut(value))
        {
            target.remove("dev-dependencies");
        }
    }
    let mut output =
        toml::to_string(&value).map_err(|error| ComposeError::ManifestNormalization {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    if !output.ends_with('\n') {
        output.push('\n');
    }
    Ok(output.into_bytes())
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
    for package in packages {
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

fn generate_lib_rs(
    catalog: &NormalizedCatalog,
    resolution: &crate::resolver::Resolution,
    build_kind: BuildKind,
) -> Result<String, ComposeError> {
    let adapter = &catalog.runtime_adapters[&resolution.runtime_adapter];
    let mut output = String::from(
        "#![forbid(unsafe_code)]\n\nmod identity;\n\npub use identity::COMPOSITION_HASH;\npub use rust_agent_runtime_api::{BuildError, RuntimePrimitives};\n",
    );
    if build_kind == BuildKind::Wasm {
        output.push_str("mod wasm;\npub use wasm::start;\n");
    }
    output.push_str(&format!(
        "pub use {} as create_runtime_primitives;\n\n",
        adapter.constructor
    ));
    output.push_str("pub fn build(runtime: RuntimePrimitives) -> Result<rust_agent_fixture_api::FixtureApp, BuildError> {\n");
    output.push_str(&format!(
        "    if runtime.adapter().as_str() != {:?} {{\n        return Err(BuildError::InvalidComposition(\"runtime adapter identity mismatch\"));\n    }}\n",
        adapter.id
    ));

    let mut binding_variables: BTreeMap<(String, Option<String>, String), String> = BTreeMap::new();
    for component_id in &resolution.construction_order {
        let component = &catalog.components[component_id];
        let component_var = rust_ident(component_id);
        output.push_str(&format!(
            "    let {component_var}_config: {} = Default::default();\n",
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
        "    Ok(rust_agent_fixture_api::FixtureApp::new({driver}, {file_reader}))\n}}\n\n"
    ));
    output.push_str(
        "#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn generated_factory_graph_executes() {\n        let runtime = create_runtime_primitives().unwrap();\n        let app = build(runtime).unwrap();\n        assert_eq!(app.run(\"hello\"), \"fixture-response:hello\");\n    }\n}\n",
    );
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
        "use {export}::{{JsValue, WasmAppHandle, wasm_bindgen}};\n\n#[wasm_bindgen]\npub async fn start(\n    runtime_config: JsValue,\n    host_bindings: JsValue,\n) -> Result<WasmAppHandle, JsValue> {{\n    if !runtime_config.is_object() || runtime_config.is_null() {{\n        return Err(JsValue::from_str(\"runtime_config must be an object\"));\n    }}\n    if !host_bindings.is_object() || host_bindings.is_null() {{\n        return Err(JsValue::from_str(\"host_bindings must be an object\"));\n    }}\n    let runtime = {export}::runtime_primitives(crate::create_runtime_primitives)\n        .map_err(|error| JsValue::from_str(&error.to_string()))?;\n    let app = crate::build(runtime)\n        .map_err(|error| JsValue::from_str(&error.to_string()))?;\n    Ok(WasmAppHandle::from_app(app))\n}}\n"
    ))
}

fn generate_lockfile(options: &ComposeOptions, staging: &Path) -> Result<(), ComposeError> {
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
        .output()?;
    fs::remove_dir_all(&cargo_home)?;
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
    let input =
        std::str::from_utf8(&input_bytes).map_err(|error| ComposeError::ManifestNormalization {
            path: lockfile.display().to_string(),
            message: error.to_string(),
        })?;
    let document: toml::Value =
        toml::from_str(input).map_err(|error| ComposeError::ManifestNormalization {
            path: lockfile.display().to_string(),
            message: error.to_string(),
        })?;
    let mut registries = BTreeMap::new();
    let mut git_sources = BTreeSet::new();
    for package in document
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(source) = package.get("source").and_then(toml::Value::as_str) else {
            continue;
        };
        if source.starts_with("registry+") {
            let id = if source == "registry+https://github.com/rust-lang/crates.io-index" {
                "crates-io".to_owned()
            } else {
                format!("registry-{}", &sha256_hex(source.as_bytes())[..16])
            };
            if let Some(previous) = registries.insert(id.clone(), source.to_owned())
                && previous != source
            {
                return Err(ComposeError::CargoLock(format!(
                    "registry source id `{id}` is ambiguous"
                )));
            }
        } else if source.starts_with("git+") {
            git_sources.insert(source.to_owned());
        } else {
            return Err(ComposeError::CargoLock(format!(
                "unsupported locked package source `{source}`"
            )));
        }
    }
    Ok((registries, git_sources))
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
        &options.catalog_path,
        &options.profile_path,
        &options.output_root,
        &options.rustc_path,
        &options.cargo_path,
    ] {
        if !path.is_absolute() {
            return Err(ComposeError::NonAbsolutePath(path.display().to_string()));
        }
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

fn read_workspace_input(workspace: &Path, path: &Path) -> Result<Vec<u8>, ComposeError> {
    let canonical_workspace = workspace.canonicalize()?;
    let canonical_path = path.canonicalize()?;
    if !canonical_path.starts_with(&canonical_workspace) || !canonical_path.is_file() {
        return Err(ComposeError::InputOutsideWorkspace(
            path.display().to_string(),
        ));
    }
    Ok(fs::read(canonical_path)?)
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

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), ComposeError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(CanonicalError::Serialize)?;
    bytes.push(b'\n');
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
            catalog_path: root.join("tests/fixtures/catalog.toml"),
            profile_path: root.join(profile),
            output_root: temp.path().join("compositions"),
            rustc_path: tool("rustc"),
            cargo_path: tool("cargo"),
            registry_cache_path: None,
            workspace_root: root,
        }
    }

    fn registry_cache() -> PathBuf {
        let cargo_home = env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
            .expect("Cargo home must be discoverable");
        cargo_home.join("registry").canonicalize().unwrap()
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
    fn composition_verification_rejects_deployable_and_handoff_projection_forgery() {
        let temp = TempDir::new().unwrap();
        let generated = compose(&options(&temp, "tests/fixtures/profiles/minimal.toml")).unwrap();
        let manifest_path = generated.path.join("rust-agent-composition.json");
        let original = fs::read(&manifest_path).unwrap();
        let mut manifest: serde_json::Value = serde_json::from_slice(&original).unwrap();

        manifest["deployable"] = serde_json::Value::Bool(true);
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("manifest projection")
        ));

        manifest = serde_json::from_slice(&original).unwrap();
        manifest["app-handoff"] = serde_json::Value::String("concurrent".into());
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("manifest projection")
        ));

        fs::write(&manifest_path, original).unwrap();
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
    fn composition_verification_rejects_nested_schema_and_resolution_projection_forgery() {
        let temp = TempDir::new().unwrap();
        let generated = compose(&options(&temp, "tests/fixtures/profiles/minimal.toml")).unwrap();
        let manifest_path = generated.path.join("rust-agent-composition.json");
        let original: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        let mut forgeries = Vec::new();

        let mut profile_schema = original.clone();
        profile_schema["normalized-profile"]["schema"] = serde_json::json!(2);
        forgeries.push(profile_schema);
        let mut resolution_schema = original.clone();
        resolution_schema["resolution"]["schema"] = serde_json::json!(2);
        forgeries.push(resolution_schema);
        let mut cargo_schema = original.clone();
        cargo_schema["cargo-resolution"]["schema"] = serde_json::json!(2);
        forgeries.push(cargo_schema);
        for field in ["profile", "target", "target-fact-digest"] {
            let mut resolution_projection = original.clone();
            resolution_projection["resolution"][field] = serde_json::json!("forged");
            forgeries.push(resolution_projection);
        }

        for forgery in forgeries {
            write_json(&manifest_path, &forgery).unwrap();
            assert!(matches!(
                verify_composition(&generated.path),
                Err(ComposeError::Verification(message))
                    if message.contains("manifest projection")
            ));
        }

        write_json(&manifest_path, &original).unwrap();
        verify_composition(&generated.path).unwrap();
        make_staging_tree_owner_writable(&generated.path).unwrap();
    }

    #[test]
    fn composition_effect_attribution_is_union_checked_and_identity_bound() {
        let temp = TempDir::new().unwrap();
        let generated = compose(&options(&temp, "tests/fixtures/profiles/with-fs.toml")).unwrap();
        let manifest_path = generated.path.join("rust-agent-composition.json");
        let original: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();

        let mut missing_effect = original.clone();
        missing_effect["component-runtime-effects"] = serde_json::json!([]);
        write_json(&manifest_path, &missing_effect).unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("runtime effects")
        ));

        let mut reattributed_effect = original.clone();
        reattributed_effect["component-runtime-effects"] = serde_json::json!([]);
        reattributed_effect["host-runtime-effects"] = serde_json::json!(["read-local"]);
        write_json(&manifest_path, &reattributed_effect).unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("composition identity mismatch")
        ));

        write_json(&manifest_path, &original).unwrap();
        verify_composition(&generated.path).unwrap();
        make_staging_tree_owner_writable(&generated.path).unwrap();
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
            ("src/lib.rs", "lib.rs"),
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
            ("src/lib.rs", "lib.rs"),
            ("src/wasm.rs", "wasm.rs"),
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
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["direct-root-build-requirements"]["host-boundary:fixture-host-export"]["executables"] =
            serde_json::json!([]);
        manifest["build-requirements"]["executables"] = serde_json::json!([]);
        manifest["resolution"]["build-requirements"]["executables"] = serde_json::json!([]);
        let mut bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        bytes.push(b'\n');
        fs::write(manifest_path, bytes).unwrap();
        assert!(matches!(
            verify_composition(&generated.path),
            Err(ComposeError::Verification(message))
                if message.contains("composition identity mismatch")
        ));
    }

    #[test]
    fn selected_packages_match_cargo_tree() {
        let temp = TempDir::new().unwrap();
        let minimal = compose(&options(&temp, "tests/fixtures/profiles/minimal.toml")).unwrap();
        let with_fs = compose(&options(&temp, "tests/fixtures/profiles/with-fs.toml")).unwrap();
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

        let minimal_tree = cargo_tree(&minimal.path);
        let with_fs_tree = cargo_tree(&with_fs.path);
        assert!(!minimal_tree.contains("rust-agent-fixture-fs-read"));
        assert!(with_fs_tree.contains("rust-agent-fixture-fs-read"));
        assert!(!minimal_tree.contains("rust-agent-fixture-model-fallback"));
    }

    fn cargo_tree(composition: &Path) -> String {
        let sandbox = TempDir::new().unwrap();
        let output = Command::new(tool("cargo"))
            .args(["tree", "--locked", "--offline", "--edges", "normal"])
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
}
