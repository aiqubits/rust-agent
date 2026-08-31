use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use walkdir::WalkDir;

use crate::{
    canonical::{self, CanonicalError},
    catalog::{CatalogError, NormalizedCatalog},
    manifest::{
        CargoResolutionRecord, CompositionIdentityPayload, CompositionManifest,
        GeneratedFileRecord, SecurityManifest, SourceFileRecord, SourcePackageRecord,
    },
    metadata::{CatalogDocument, HostBoundaryKind},
    profile::{BuildKind, CompositionProfile},
    resolver::{ResolutionError, resolve},
    target::{Target, TargetError},
};

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct ComposeOptions {
    pub workspace_root: PathBuf,
    pub catalog_path: PathBuf,
    pub profile_path: PathBuf,
    pub output_root: PathBuf,
    pub rustc_path: PathBuf,
    pub cargo_path: PathBuf,
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
    #[error("Phase 1A supports product-neutral library fixture generation only: {0}")]
    UnsupportedPhase1A(String),
    #[error("composition verification failed: {0}")]
    Verification(String),
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
    if profile.build_kind != BuildKind::Library {
        return Err(ComposeError::UnsupportedPhase1A(format!(
            "{:?}",
            profile.build_kind
        )));
    }
    let target = Target::query(&options.rustc_path, &profile.target, profile.environment)?;
    let resolution = resolve(&catalog, &profile, &target)?;

    fs::create_dir_all(&options.output_root)?;
    let staging = unique_staging(&options.output_root);
    fs::create_dir(&staging)?;
    let result = compose_in_staging(options, &catalog, &profile, &target, &resolution, &staging);
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
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
        &generate_cargo_toml(catalog, resolution, &package_inputs),
    )?;
    write_text(
        &staging.join("src/lib.rs"),
        &generate_lib_rs(catalog, resolution)?,
    )?;
    write_text(
        &staging.join("src/identity.rs"),
        "pub const COMPOSITION_HASH: &str = \"pending\";\n",
    )?;

    let cargo_resolution = CargoResolutionRecord {
        schema: 1,
        target: target.triple.clone(),
        target_fact_digest: target.target_fact_digest.clone(),
        resolver: "2".into(),
        offline: true,
        isolated_cargo_home: true,
        ancestor_config: "forbidden".into(),
        registries: BTreeMap::new(),
        git_sources: BTreeSet::new(),
    };
    write_json(&staging.join("cargo-resolution.json"), &cargo_resolution)?;
    write_text(
        &staging.join(".cargo/config.toml"),
        &format!(
            "[build]\ntarget = {:?}\n\n[net]\noffline = true\n",
            target.triple
        ),
    )?;

    generate_lockfile(options, staging)?;
    let cargo_lock_digest = file_digest(&staging.join("Cargo.lock"))?;
    let generated_files = generated_file_records(
        staging,
        &[
            "Cargo.toml",
            "cargo-resolution.json",
            ".cargo/config.toml",
            "src/lib.rs",
        ],
    )?;
    let payload = CompositionIdentityPayload {
        schema: 1,
        profile,
        target,
        resolution,
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
        let existing = load_manifest(&final_path)?;
        if existing != manifest {
            return Err(ComposeError::ExistingCompositionMismatch {
                path: final_path.display().to_string(),
                expected: composition_hash,
            });
        }
        fs::remove_dir_all(staging)?;
        return Ok(GeneratedComposition {
            composition_hash,
            path: final_path,
            manifest,
        });
    }
    fs::rename(staging, &final_path)?;
    Ok(GeneratedComposition {
        composition_hash,
        path: final_path,
        manifest,
    })
}

pub fn load_manifest(path: &Path) -> Result<CompositionManifest, ComposeError> {
    let bytes = fs::read(path.join("rust-agent-composition.json"))?;
    serde_json::from_slice(&bytes).map_err(|error| ComposeError::ManifestNormalization {
        path: path
            .join("rust-agent-composition.json")
            .display()
            .to_string(),
        message: error.to_string(),
    })
}

pub fn verify_composition(path: &Path) -> Result<CompositionManifest, ComposeError> {
    if !path.is_absolute() || !path.is_dir() {
        return Err(ComposeError::Verification(format!(
            "composition path must be an absolute directory: {}",
            path.display()
        )));
    }
    let manifest = load_manifest(path)?;
    if manifest.schema != 1 || manifest.algorithm != "sha256-rust-agent-composition-v1" {
        return Err(ComposeError::Verification(
            "unknown manifest schema or algorithm".into(),
        ));
    }
    let cargo_resolution_bytes = fs::read(path.join("cargo-resolution.json"))?;
    let cargo_resolution: CargoResolutionRecord = serde_json::from_slice(&cargo_resolution_bytes)
        .map_err(|error| {
        ComposeError::Verification(format!("invalid cargo-resolution.json: {error}"))
    })?;
    if cargo_resolution != manifest.cargo_resolution
        || sha256_hex(&cargo_resolution_bytes) != manifest.cargo_resolution_digest
    {
        return Err(ComposeError::Verification(
            "Cargo resolution record drifted".into(),
        ));
    }
    if file_digest(&path.join("Cargo.lock"))? != manifest.cargo_lock_digest {
        return Err(ComposeError::Verification("Cargo.lock drifted".into()));
    }
    for file in &manifest.generated_files {
        let bytes = fs::read(path.join(&file.path))?;
        if bytes.len() as u64 != file.bytes || sha256_hex(&bytes) != file.digest {
            return Err(ComposeError::Verification(format!(
                "generated file `{}` drifted",
                file.path
            )));
        }
    }
    let mut allowed_files: BTreeSet<String> = manifest
        .generated_files
        .iter()
        .map(|file| file.path.clone())
        .collect();
    allowed_files.extend([
        "Cargo.lock".into(),
        "rust-agent-composition.json".into(),
        "rust-agent-security.json".into(),
        "src/identity.rs".into(),
    ]);
    for package in &manifest.sources {
        let root = path.join("sources").join(&package.logical_path);
        let actual = source_file_records(&root)?;
        if actual != package.files {
            return Err(ComposeError::Verification(format!(
                "source snapshot `{}` drifted",
                package.logical_path
            )));
        }
        let digest = hex::encode(canonical::domain_hash(
            b"rust-agent-snapshot-tree-v1\0",
            &actual,
        )?);
        if digest != package.tree_digest {
            return Err(ComposeError::Verification(format!(
                "source snapshot digest `{}` drifted",
                package.logical_path
            )));
        }
        allowed_files.extend(
            package
                .files
                .iter()
                .map(|file| format!("sources/{}/{}", package.logical_path, file.path)),
        );
    }
    let actual_files = all_tree_files(path)?;
    if actual_files != allowed_files {
        let unexpected: Vec<_> = actual_files.difference(&allowed_files).cloned().collect();
        let missing: Vec<_> = allowed_files.difference(&actual_files).cloned().collect();
        return Err(ComposeError::Verification(format!(
            "composition tree differs from manifest; unexpected={unexpected:?}, missing={missing:?}"
        )));
    }
    let payload = CompositionIdentityPayload {
        schema: 1,
        profile: &manifest.normalized_profile,
        target: &manifest.normalized_target,
        resolution: &manifest.resolution,
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
    if fs::read(path.join("src/identity.rs"))? != identity_source.as_bytes() {
        return Err(ComposeError::Verification(
            "derived identity source drifted".into(),
        ));
    }
    let security: SecurityManifest = serde_json::from_slice(&fs::read(
        path.join("rust-agent-security.json"),
    )?)
    .map_err(|error| ComposeError::Verification(format!("invalid security manifest: {error}")))?;
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

fn all_tree_files(root: &Path) -> Result<BTreeSet<String>, ComposeError> {
    let mut files = BTreeSet::new();
    for entry in WalkDir::new(root).sort_by_file_name() {
        let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err(ComposeError::UnsupportedSourceEntry(
                entry.path().display().to_string(),
            ));
        }
        if metadata.is_file() {
            let relative = entry
                .path()
                .strip_prefix(root)
                .expect("walked path is below root")
                .to_str()
                .ok_or_else(|| {
                    ComposeError::UnsupportedSourceEntry(entry.path().display().to_string())
                })?
                .replace('\\', "/");
            files.insert(relative);
        } else if !metadata.is_dir() {
            return Err(ComposeError::UnsupportedSourceEntry(
                entry.path().display().to_string(),
            ));
        }
    }
    Ok(files)
}

fn source_file_records(root: &Path) -> Result<Vec<SourceFileRecord>, ComposeError> {
    if !root.is_dir() {
        return Err(ComposeError::Verification(format!(
            "missing source root {}",
            root.display()
        )));
    }
    let mut records = Vec::new();
    for entry in WalkDir::new(root).sort_by_file_name() {
        let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err(ComposeError::UnsupportedSourceEntry(
                entry.path().display().to_string(),
            ));
        }
        if metadata.is_dir() {
            continue;
        }
        if !metadata.is_file() {
            return Err(ComposeError::UnsupportedSourceEntry(
                entry.path().display().to_string(),
            ));
        }
        let bytes = fs::read(entry.path())?;
        let relative = entry
            .path()
            .strip_prefix(root)
            .expect("walked path is below source root")
            .to_str()
            .ok_or_else(|| {
                ComposeError::UnsupportedSourceEntry(entry.path().display().to_string())
            })?
            .replace('\\', "/");
        records.push(SourceFileRecord {
            path: relative,
            digest: sha256_hex(&bytes),
            bytes: bytes.len() as u64,
            executable: is_executable(&metadata),
        });
    }
    records.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(records)
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

fn snapshot_package(
    workspace_root: &Path,
    source_root: &Path,
    id: &str,
    package: &str,
    logical_path: &str,
) -> Result<SourcePackageRecord, ComposeError> {
    let source = workspace_root.join(logical_path);
    if !source.is_dir() {
        return Err(ComposeError::MissingSourcePackage(
            source.display().to_string(),
        ));
    }
    let destination = source_root.join(logical_path);
    fs::create_dir_all(&destination)?;
    let mut records = Vec::new();
    for entry in WalkDir::new(&source).sort_by_file_name() {
        let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
        let relative = entry
            .path()
            .strip_prefix(&source)
            .expect("walked path is below source package");
        if relative.as_os_str().is_empty() {
            continue;
        }
        if snapshot_path_is_transient(relative) {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err(ComposeError::UnsupportedSourceEntry(
                entry.path().display().to_string(),
            ));
        }
        let target = destination.join(relative);
        if metadata.is_dir() {
            fs::create_dir_all(&target)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(ComposeError::UnsupportedSourceEntry(
                entry.path().display().to_string(),
            ));
        }
        let bytes = if relative == Path::new("Cargo.toml") {
            normalize_snapshot_manifest(entry.path())?
        } else {
            fs::read(entry.path())?
        };
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, &bytes)?;
        let path = relative
            .to_str()
            .ok_or_else(|| {
                ComposeError::UnsupportedSourceEntry(entry.path().display().to_string())
            })?
            .replace('\\', "/");
        records.push(SourceFileRecord {
            path,
            digest: sha256_hex(&bytes),
            bytes: bytes.len() as u64,
            executable: is_executable(&metadata),
        });
    }
    records.sort_by(|left, right| left.path.cmp(&right.path));
    let tree_digest = hex::encode(canonical::domain_hash(
        b"rust-agent-snapshot-tree-v1\0",
        &records,
    )?);
    Ok(SourcePackageRecord {
        id: id.to_owned(),
        package: package.to_owned(),
        logical_path: logical_path.to_owned(),
        tree_digest,
        files: records,
    })
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
    let input = fs::read_to_string(path)?;
    let mut value: toml::Value =
        toml::from_str(&input).map_err(|error| ComposeError::ManifestNormalization {
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
    package.insert("rust-version".into(), toml::Value::String("1.85".into()));
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

fn generate_cargo_toml(
    catalog: &NormalizedCatalog,
    resolution: &crate::resolver::Resolution,
    packages: &[PackageInput],
) -> String {
    let mut output = String::from(
        "[package]\nname = \"rust-agent-generated-composition\"\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"1.85\"\nlicense = \"MIT\"\npublish = false\n\n[workspace]\nresolver = \"2\"\nexclude = [\n",
    );
    for package in packages {
        output.push_str(&format!("    {:?},\n", format!("sources/{}", package.path)));
    }
    output.push_str("]\n\n[features]\ndefault = []\n\n[dependencies]\n");
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
    output
}

fn generate_lib_rs(
    catalog: &NormalizedCatalog,
    resolution: &crate::resolver::Resolution,
) -> Result<String, ComposeError> {
    let adapter = &catalog.runtime_adapters[&resolution.runtime_adapter];
    let mut output = String::from(
        "#![forbid(unsafe_code)]\n\nmod identity;\n\npub use identity::COMPOSITION_HASH;\npub use rust_agent_runtime_api::{BuildError, RuntimePrimitives};\n",
    );
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

fn generate_lockfile(options: &ComposeOptions, staging: &Path) -> Result<(), ComposeError> {
    let cargo_home = staging.with_extension(format!(
        "cargo-home-{}-{}",
        std::process::id(),
        STAGING_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&cargo_home)?;
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

fn generated_file_records(
    staging: &Path,
    paths: &[&str],
) -> Result<Vec<GeneratedFileRecord>, ComposeError> {
    let mut records = Vec::new();
    for path in paths {
        let bytes = fs::read(staging.join(path))?;
        records.push(GeneratedFileRecord {
            path: (*path).to_owned(),
            digest: sha256_hex(&bytes),
            bytes: bytes.len() as u64,
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

fn write_text(path: &Path, value: &str) -> Result<(), ComposeError> {
    debug_assert!(value.ends_with('\n'));
    fs::write(path, value.as_bytes())?;
    Ok(())
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), ComposeError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(CanonicalError::Serialize)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

fn file_digest(path: &Path) -> Result<String, ComposeError> {
    Ok(sha256_hex(&fs::read(path)?))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn rust_ident(value: &str) -> String {
    value.replace(['-', ':'], "_")
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
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
            workspace_root: root,
        }
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
    fn trybuild_wip_does_not_enter_the_source_snapshot() {
        let temp = TempDir::new().unwrap();
        let package = temp.path().join("fixture");
        fs::create_dir_all(package.join("src")).unwrap();
        fs::create_dir_all(package.join("wip")).unwrap();
        fs::write(
            package.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"1.85\"\nlicense = \"MIT\"\n",
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
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>(),
            ["Cargo.toml", "src/lib.rs"]
        );
        assert!(!snapshot_root.join("fixture/wip").exists());
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
            assert_eq!(
                fs::read(generated.path.join(actual)).unwrap(),
                fs::read(root.join("tests/golden/minimal").join(golden)).unwrap(),
                "stale golden {golden}"
            );
        }
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
