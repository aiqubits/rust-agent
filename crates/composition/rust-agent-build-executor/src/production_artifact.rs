use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};

#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;

#[cfg(target_os = "linux")]
use rustix::fs::{CWD, RenameFlags, renameat_with};

use rust_agent_composition::{
    CompositionManifest, WASM_BINDGEN_CLI_LOGICAL_ID, WASM_BINDGEN_PROTOCOL_VERSION, canonical,
    metadata::BuildRequirements, profile::BuildKind,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use walkdir::WalkDir;

use crate::{
    ArtifactError, BuildArtifactSelector, BuildEnforcementIdentity, BuildPanicStrategy,
    WasmPostprocessorManifest,
    artifact::{
        is_canonical_id, is_digest, sha256_hex, validate_relative_path, verify_sbom_files,
        write_cyclonedx_sbom_files,
    },
    production_policy::cargo_driver_environment,
};

#[cfg(target_os = "linux")]
use crate::{BuildArtifactTarget, CargoCrateKind, CargoUnitSelector, TrustedCargoBuildResult};

pub const PRODUCTION_BUILD_MANIFEST_FILE: &str = "rust-agent-build.json";

const MAX_ARTIFACTS: usize = 4_096;
const MAX_GATES: usize = 256;
const MAX_INVOCATION_ARGUMENTS: usize = 4_096;
const MAX_INVOCATION_ENVIRONMENT: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProductionArtifactKind {
    NativeExecutable,
    RustLibrary,
    StaticLibrary,
    DynamicLibrary,
    RawWasmIntermediate,
    JavaScriptLoader,
    TransformedWasm,
    TypeScriptDeclaration,
    JavaScriptSnippet,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionArtifactRecord {
    pub path: String,
    pub kind: ProductionArtifactKind,
    pub target: String,
    pub bytes: u64,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionBuildOptionsIdentity {
    pub schema: u32,
    #[serde(rename = "host-integration")]
    pub host_integration: bool,
    #[serde(rename = "build-kind")]
    pub build_kind: BuildKind,
    #[serde(rename = "composition-profile-name")]
    pub composition_profile: String,
    #[serde(rename = "cargo-profile")]
    pub cargo_profile: String,
    pub target: String,
    #[serde(rename = "artifact-selector")]
    pub artifact_selector: BuildArtifactSelector,
    #[serde(rename = "panic-strategy")]
    pub panic_strategy: BuildPanicStrategy,
    pub locked: bool,
    pub offline: bool,
    pub jobs: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionCargoInvocationIdentity {
    pub schema: u32,
    pub arguments: Vec<String>,
    pub environment: BTreeMap<String, String>,
    #[serde(rename = "working-directory")]
    pub working_directory: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionEnforcementResultIdentity {
    pub schema: u32,
    #[serde(rename = "build-input-content-digest")]
    pub build_input_content_digest: String,
    #[serde(rename = "planned-unit-graph-digest")]
    pub planned_unit_graph_digest: String,
    #[serde(rename = "observed-unit-graph-digest")]
    pub observed_unit_graph_digest: String,
    #[serde(rename = "cargo-messages-digest")]
    pub cargo_messages_digest: String,
    #[serde(rename = "filesystem-enforcement")]
    pub filesystem_enforcement: String,
    #[serde(rename = "network-enforcement")]
    pub network_enforcement: String,
    #[serde(rename = "descendant-enforcement")]
    pub descendant_enforcement: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionBuildManifest {
    pub schema: u32,
    pub mode: String,
    pub deployable: bool,
    pub composition: CompositionManifest,
    #[serde(rename = "build-requirements")]
    pub build_requirements: BuildRequirements,
    #[serde(rename = "effective-compiled-runtime-effects")]
    pub effective_compiled_runtime_effects: BTreeSet<String>,
    #[serde(rename = "composition-manifest-digest")]
    pub composition_manifest_digest: String,
    #[serde(rename = "build-enforcement-identity")]
    pub build_enforcement_identity: BuildEnforcementIdentity,
    #[serde(rename = "build-enforcement-identity-digest")]
    pub build_enforcement_identity_digest: String,
    #[serde(rename = "enforcement-result")]
    pub enforcement_result: ProductionEnforcementResultIdentity,
    #[serde(rename = "build-options")]
    pub build_options: ProductionBuildOptionsIdentity,
    #[serde(rename = "cargo-invocation")]
    pub cargo_invocation: ProductionCargoInvocationIdentity,
    #[serde(rename = "entry-artifact")]
    pub entry_artifact: String,
    pub artifacts: Vec<ProductionArtifactRecord>,
    pub postprocessor: Option<WasmPostprocessorManifest>,
    #[serde(rename = "sbom-file")]
    pub sbom_file: String,
    #[serde(rename = "sbom-digest")]
    pub sbom_digest: String,
    pub gates: Vec<String>,
    #[serde(rename = "build-manifest-digest")]
    pub build_manifest_digest: String,
    #[serde(rename = "build-output-digest")]
    pub build_output_digest: String,
}

#[derive(Clone, Debug)]
pub struct ProductionBuildManifestInput {
    pub composition: CompositionManifest,
    pub build_requirements: BuildRequirements,
    pub effective_compiled_runtime_effects: BTreeSet<String>,
    pub build_enforcement_identity: BuildEnforcementIdentity,
    pub enforcement_result: ProductionEnforcementResultIdentity,
    pub build_options: ProductionBuildOptionsIdentity,
    pub cargo_invocation: ProductionCargoInvocationIdentity,
    pub entry_artifact: String,
    pub artifacts: Vec<ProductionArtifactRecord>,
    pub postprocessor: Option<WasmPostprocessorManifest>,
    pub gates: Vec<String>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionArtifactPublication {
    pub path: PathBuf,
    pub reused: bool,
    pub manifest: ProductionBuildManifest,
}

/// Opaque proof that a matching append-only production attestation was durably
/// published before the deployable artifact becomes visible.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct ProductionArtifactPublicationPermit {
    build_manifest_digest: String,
    build_output_digest: String,
    attestation_path: PathBuf,
    attestation_file_sha256: String,
}

#[cfg(target_os = "linux")]
impl ProductionArtifactPublicationPermit {
    pub(crate) fn new(
        manifest: &ProductionBuildManifest,
        attestation_path: PathBuf,
        attestation_file_sha256: String,
    ) -> Self {
        Self {
            build_manifest_digest: manifest.build_manifest_digest.clone(),
            build_output_digest: manifest.build_output_digest.clone(),
            attestation_path,
            attestation_file_sha256,
        }
    }

    fn verify(&self, manifest: &ProductionBuildManifest) -> Result<(), ProductionArtifactError> {
        if self.build_manifest_digest != manifest.build_manifest_digest
            || self.build_output_digest != manifest.build_output_digest
            || !self.attestation_path.is_absolute()
        {
            return Err(ProductionArtifactError::InvalidPublication(
                "attestation publication permit differs from the staged artifact".into(),
            ));
        }
        let metadata = fs::symlink_metadata(&self.attestation_path)?;
        if !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o777 != 0o444
            || sha256_hex(&fs::read(&self.attestation_path)?) != self.attestation_file_sha256
        {
            return Err(ProductionArtifactError::InvalidPublication(
                "published attestation changed before artifact publication".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ProductionArtifactError {
    #[error("production artifact I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("production artifact serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("production artifact canonical encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
    #[error("production artifact contract failed: {0}")]
    Artifact(#[from] ArtifactError),
    #[error("production artifact manifest is invalid: {0}")]
    InvalidManifest(String),
    #[cfg(target_os = "linux")]
    #[error("trusted Cargo artifact snapshot failed: {0}")]
    Snapshot(#[from] crate::SnapshotMaterializationError),
    #[cfg(target_os = "linux")]
    #[error("production artifact publication input is invalid: {0}")]
    InvalidPublication(String),
    #[cfg(target_os = "linux")]
    #[error("production artifact destination contains different or invalid content: {0}")]
    DestinationConflict(String),
    #[cfg(target_os = "linux")]
    #[error("production artifact was published but final verification failed: {0}")]
    PublishedVerificationFailed(String),
}

#[cfg(target_os = "linux")]
pub fn create_production_artifact_staging(
    artifact_parent: &Path,
) -> Result<PathBuf, ProductionArtifactError> {
    validate_publication_parent(artifact_parent)?;
    tempfile::Builder::new()
        .prefix(".rust-agent-artifact-staging-")
        .tempdir_in(artifact_parent)
        .map(tempfile::TempDir::keep)
        .map_err(Into::into)
}

#[cfg(target_os = "linux")]
pub fn publish_production_artifact(
    staging: &Path,
    artifact_parent: &Path,
    expected_manifest: &ProductionBuildManifest,
    attestation_permit: &ProductionArtifactPublicationPermit,
) -> Result<ProductionArtifactPublication, ProductionArtifactError> {
    validate_publication_parent(artifact_parent)?;
    if !staging.is_absolute()
        || staging.parent() != Some(artifact_parent)
        || !staging
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.starts_with(".rust-agent-artifact-staging-"))
        || !fs::symlink_metadata(staging)?.file_type().is_dir()
    {
        return Err(ProductionArtifactError::InvalidPublication(
            "staging must be an owned direct child of the artifact parent".into(),
        ));
    }
    let staged = read_staged_production_manifest(staging)?;
    if &staged != expected_manifest {
        return Err(ProductionArtifactError::InvalidPublication(
            "staged manifest differs from the caller-verified manifest".into(),
        ));
    }
    attestation_permit.verify(expected_manifest)?;
    seal_production_artifact_tree(staging, expected_manifest)?;
    expected_manifest.verify(staging, false, None, None)?;

    let destination = artifact_parent.join(&expected_manifest.build_output_digest);
    match renameat_with(CWD, staging, CWD, &destination, RenameFlags::NOREPLACE) {
        Ok(()) => {
            File::open(artifact_parent)?.sync_all()?;
            match inspect_production_build_manifest(&destination, None, None) {
                Ok(manifest) if manifest == *expected_manifest => {
                    Ok(ProductionArtifactPublication {
                        path: destination,
                        reused: false,
                        manifest,
                    })
                }
                Ok(_) => Err(ProductionArtifactError::PublishedVerificationFailed(
                    destination.display().to_string(),
                )),
                Err(error) => Err(ProductionArtifactError::PublishedVerificationFailed(
                    error.to_string(),
                )),
            }
        }
        Err(error) if error == rustix::io::Errno::EXIST => {
            let existing =
                inspect_production_build_manifest(&destination, None, None).map_err(|_| {
                    ProductionArtifactError::DestinationConflict(destination.display().to_string())
                })?;
            if existing != *expected_manifest {
                return Err(ProductionArtifactError::DestinationConflict(
                    destination.display().to_string(),
                ));
            }
            remove_owned_artifact_staging(staging)?;
            Ok(ProductionArtifactPublication {
                path: destination,
                reused: true,
                manifest: existing,
            })
        }
        Err(error) => Err(io::Error::from_raw_os_error(error.raw_os_error()).into()),
    }
}

pub fn production_artifact_record(
    root: &Path,
    relative: &str,
    kind: ProductionArtifactKind,
    target: &str,
) -> Result<ProductionArtifactRecord, ProductionArtifactError> {
    validate_relative_path(relative)?;
    if !valid_text(target) {
        return Err(ProductionArtifactError::InvalidManifest(
            "artifact target is invalid".into(),
        ));
    }
    let bytes = fs::read(root.join(relative))?;
    Ok(ProductionArtifactRecord {
        path: relative.into(),
        kind,
        target: target.into(),
        bytes: bytes.len() as u64,
        digest: sha256_hex(&bytes),
    })
}

#[cfg(target_os = "linux")]
pub fn materialize_trusted_cargo_artifact(
    build: &TrustedCargoBuildResult,
    selector: &BuildArtifactSelector,
    artifact_dir: &Path,
    output_relative_path: &str,
    target: &str,
) -> Result<ProductionArtifactRecord, ProductionArtifactError> {
    validate_relative_path(output_relative_path)?;
    if !artifact_dir.is_absolute() || !artifact_dir.is_dir() || !valid_text(target) {
        return invalid("trusted Cargo artifact roots or target are invalid");
    }
    let candidates = build
        .artifact_files()
        .iter()
        .filter(|artifact| selector_matches(selector, artifact.selector(), target))
        .filter_map(|artifact| {
            classify_cargo_artifact(artifact.logical_path(), selector)
                .map(|kind| (artifact.logical_path(), kind))
        })
        .collect::<Vec<_>>();
    let [(logical_path, kind)] = candidates.as_slice() else {
        return invalid("Cargo output has no unique final artifact for the exact selector");
    };
    let relative = logical_path
        .strip_prefix("/rust-agent/target/")
        .ok_or_else(|| {
            ProductionArtifactError::InvalidManifest(
                "Cargo artifact is outside the logical target root".into(),
            )
        })?;
    validate_relative_path(relative)?;
    let source = build
        .artifact_files()
        .iter()
        .find(|artifact| artifact.logical_path() == *logical_path)
        .expect("classified Cargo artifact came from the trusted result")
        .identity();
    let destination = artifact_dir.join(output_relative_path);
    if destination.exists() {
        return invalid("production artifact destination already exists");
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)?;
    let bytes = source.copy_to(&mut output)?;
    output.sync_all()?;
    if bytes == 0 {
        return invalid("production artifact is empty");
    }
    Ok(ProductionArtifactRecord {
        path: output_relative_path.into(),
        kind: *kind,
        target: target.into(),
        bytes,
        digest: source.sha256().into(),
    })
}

#[cfg(target_os = "linux")]
fn selector_matches(
    requested: &BuildArtifactSelector,
    observed: &CargoUnitSelector,
    target: &str,
) -> bool {
    if observed.package.name != requested.package
        || observed.compilation_target != target
        || observed.compile_mode != crate::CargoCompileMode::Build
    {
        return false;
    }
    match &requested.target {
        BuildArtifactTarget::Library => observed.crate_kind == CargoCrateKind::Library,
        BuildArtifactTarget::Binary { name } => {
            observed.crate_kind == CargoCrateKind::Binary && observed.target_name == *name
        }
        BuildArtifactTarget::Example { name } => {
            observed.crate_kind == CargoCrateKind::Example && observed.target_name == *name
        }
        BuildArtifactTarget::Test { name } => {
            observed.crate_kind == CargoCrateKind::Test && observed.target_name == *name
        }
        BuildArtifactTarget::Bench { name } => {
            observed.crate_kind == CargoCrateKind::Bench && observed.target_name == *name
        }
    }
}

#[cfg(target_os = "linux")]
fn classify_cargo_artifact(
    logical_path: &str,
    selector: &BuildArtifactSelector,
) -> Option<ProductionArtifactKind> {
    if !logical_path.starts_with("/rust-agent/target/") {
        return None;
    }
    let path = Path::new(logical_path);
    let extension = path.extension().and_then(|value| value.to_str());
    match &selector.target {
        BuildArtifactTarget::Library => match extension {
            Some("rlib") => Some(ProductionArtifactKind::RustLibrary),
            Some("a") => Some(ProductionArtifactKind::StaticLibrary),
            Some("so" | "dylib" | "dll") => Some(ProductionArtifactKind::DynamicLibrary),
            Some("wasm") => Some(ProductionArtifactKind::RawWasmIntermediate),
            _ => None,
        },
        BuildArtifactTarget::Binary { .. }
        | BuildArtifactTarget::Example { .. }
        | BuildArtifactTarget::Test { .. }
        | BuildArtifactTarget::Bench { .. } => match extension {
            None | Some("exe") => Some(ProductionArtifactKind::NativeExecutable),
            _ => None,
        },
    }
}

pub fn write_production_build_manifest(
    artifact_dir: &Path,
    cargo_lock: &Path,
    mut input: ProductionBuildManifestInput,
) -> Result<ProductionBuildManifest, ProductionArtifactError> {
    if !artifact_dir.is_absolute() || !artifact_dir.is_dir() {
        return Err(ProductionArtifactError::InvalidManifest(
            "artifact staging directory must be an absolute directory".into(),
        ));
    }
    input.artifacts.sort();
    input.gates.sort();
    let mut preview = manifest_from_input(
        input.clone(),
        "rust-agent-sbom.cdx.json".into(),
        "00".repeat(32),
    )?;
    preview.finalize_digests()?;
    let expected_pre_manifest = input
        .artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect::<BTreeSet<_>>();
    verify_tree_file_set(artifact_dir, &expected_pre_manifest)?;
    let files = input
        .artifacts
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact.digest.as_str()))
        .collect::<Vec<_>>();
    let (sbom_file, sbom_digest) =
        write_cyclonedx_sbom_files(artifact_dir, &input.composition, cargo_lock, &files)?;
    let mut manifest = manifest_from_input(input, sbom_file, sbom_digest)?;
    manifest.finalize_digests()?;
    manifest.verify(artifact_dir, false, None, None)?;
    let mut bytes = serde_json::to_vec_pretty(&manifest)?;
    bytes.push(b'\n');
    fs::write(artifact_dir.join(PRODUCTION_BUILD_MANIFEST_FILE), bytes)?;
    manifest.verify(artifact_dir, false, None, None)?;
    Ok(manifest)
}

fn manifest_from_input(
    input: ProductionBuildManifestInput,
    sbom_file: String,
    sbom_digest: String,
) -> Result<ProductionBuildManifest, ProductionArtifactError> {
    let composition_manifest_digest = composition_manifest_digest(&input.composition)?;
    let build_enforcement_identity_digest = input
        .build_enforcement_identity
        .digest()
        .map_err(|error| ProductionArtifactError::InvalidManifest(error.to_string()))?;
    Ok(ProductionBuildManifest {
        schema: 1,
        mode: "production".into(),
        deployable: true,
        composition: input.composition,
        build_requirements: input.build_requirements,
        effective_compiled_runtime_effects: input.effective_compiled_runtime_effects,
        composition_manifest_digest,
        build_enforcement_identity: input.build_enforcement_identity,
        build_enforcement_identity_digest,
        enforcement_result: input.enforcement_result,
        build_options: input.build_options,
        cargo_invocation: input.cargo_invocation,
        entry_artifact: input.entry_artifact,
        artifacts: input.artifacts,
        postprocessor: input.postprocessor,
        sbom_file,
        sbom_digest,
        gates: input.gates,
        build_manifest_digest: String::new(),
        build_output_digest: String::new(),
    })
}

pub fn inspect_production_build_manifest(
    artifact_dir: &Path,
    expected_composition: Option<&CompositionManifest>,
    expected_enforcement_identity: Option<&BuildEnforcementIdentity>,
) -> Result<ProductionBuildManifest, ProductionArtifactError> {
    let bytes = fs::read(artifact_dir.join(PRODUCTION_BUILD_MANIFEST_FILE))?;
    let manifest: ProductionBuildManifest = serde_json::from_slice(&bytes)?;
    manifest.verify(
        artifact_dir,
        true,
        expected_composition,
        expected_enforcement_identity,
    )?;
    Ok(manifest)
}

impl ProductionBuildManifest {
    pub fn finalize_digests(&mut self) -> Result<(), ProductionArtifactError> {
        self.validate_shape(None, None)?;
        self.build_manifest_digest = manifest_digest(self)?;
        self.build_output_digest = output_digest(self)?;
        Ok(())
    }

    pub fn verify(
        &self,
        artifact_dir: &Path,
        require_content_addressed_name: bool,
        expected_composition: Option<&CompositionManifest>,
        expected_enforcement_identity: Option<&BuildEnforcementIdentity>,
    ) -> Result<(), ProductionArtifactError> {
        self.validate_shape(expected_composition, expected_enforcement_identity)?;
        let mut expected = self
            .artifacts
            .iter()
            .map(|artifact| artifact.path.clone())
            .chain([
                self.sbom_file.clone(),
                PRODUCTION_BUILD_MANIFEST_FILE.into(),
            ])
            .collect::<BTreeSet<_>>();
        if !artifact_dir.join(PRODUCTION_BUILD_MANIFEST_FILE).exists() {
            expected.remove(PRODUCTION_BUILD_MANIFEST_FILE);
        }
        verify_tree_file_set(artifact_dir, &expected)?;
        for artifact in &self.artifacts {
            let bytes = fs::read(artifact_dir.join(&artifact.path))?;
            if bytes.len() as u64 != artifact.bytes || sha256_hex(&bytes) != artifact.digest {
                return Err(ProductionArtifactError::InvalidManifest(format!(
                    "artifact `{}` digest or byte count mismatch",
                    artifact.path
                )));
            }
        }
        let sbom = fs::read(artifact_dir.join(&self.sbom_file))?;
        if sha256_hex(&sbom) != self.sbom_digest {
            return Err(ProductionArtifactError::InvalidManifest(
                "SBOM digest mismatch".into(),
            ));
        }
        let files = self
            .artifacts
            .iter()
            .map(|artifact| (artifact.path.as_str(), artifact.digest.as_str()))
            .collect::<Vec<_>>();
        verify_sbom_files(&sbom, &files, &self.composition.composition_hash)?;
        if manifest_digest(self)? != self.build_manifest_digest
            || output_digest(self)? != self.build_output_digest
        {
            return Err(ProductionArtifactError::InvalidManifest(
                "derived build manifest or output digest mismatch".into(),
            ));
        }
        if require_content_addressed_name
            && artifact_dir.file_name().and_then(|value| value.to_str())
                != Some(self.build_output_digest.as_str())
        {
            return Err(ProductionArtifactError::InvalidManifest(
                "production artifact directory is not named by build-output-digest".into(),
            ));
        }
        Ok(())
    }

    fn validate_shape(
        &self,
        expected_composition: Option<&CompositionManifest>,
        expected_enforcement_identity: Option<&BuildEnforcementIdentity>,
    ) -> Result<(), ProductionArtifactError> {
        if self.schema != 1 || self.mode != "production" || !self.deployable {
            return invalid("schema, mode, or deployability contract mismatch");
        }
        if expected_composition.is_some_and(|expected| expected != &self.composition)
            || expected_enforcement_identity
                .is_some_and(|expected| expected != &self.build_enforcement_identity)
        {
            return invalid("manifest differs from independently verified inputs");
        }
        if self.composition_manifest_digest != composition_manifest_digest(&self.composition)?
            || self.build_enforcement_identity_digest
                != self
                    .build_enforcement_identity
                    .digest()
                    .map_err(|error| ProductionArtifactError::InvalidManifest(error.to_string()))?
        {
            return invalid("composition or enforcement identity digest mismatch");
        }
        self.build_enforcement_identity
            .context
            .validate()
            .map_err(|error| ProductionArtifactError::InvalidManifest(error.to_string()))?;
        if self.composition.profile != self.build_options.composition_profile
            || self.composition.target != self.build_options.target
            || (!self.build_options.host_integration
                && self.composition.build_kind != self.build_options.build_kind)
            || (self.build_options.host_integration
                && (self.composition.build_kind != BuildKind::Library
                    || self.build_options.build_kind == BuildKind::Wasm))
            || self.build_enforcement_identity.context.profile != self.build_options.cargo_profile
            || self.build_enforcement_identity.context.target != self.build_options.target
            || self.build_enforcement_identity.context.target_facts_digest
                != self.composition.target_fact_digest
            || self.build_enforcement_identity.context.artifact_selector
                != self.build_options.artifact_selector
            || self.build_enforcement_identity.context.panic_strategy
                != self.build_options.panic_strategy
        {
            return invalid("composition, enforcement context, and build options disagree");
        }
        if !self
            .composition
            .build_requirements
            .executables
            .is_subset(&self.build_requirements.executables)
            || !self
                .composition
                .build_requirements
                .read_inputs
                .is_subset(&self.build_requirements.read_inputs)
            || !self
                .composition
                .build_requirements
                .environment
                .is_subset(&self.build_requirements.environment)
        {
            return invalid("effective build requirements omit composition requirements");
        }
        if !self
            .composition
            .compiled_runtime_effects
            .is_subset(&self.effective_compiled_runtime_effects)
            || self
                .effective_compiled_runtime_effects
                .iter()
                .any(|effect| !is_canonical_id(effect))
        {
            return invalid("effective runtime effects omit or corrupt composition effects");
        }
        self.build_options.validate()?;
        self.cargo_invocation.validate()?;
        let host_linker_selected = self.build_enforcement_identity.host_linker.is_some();
        let expected_driver_environment = cargo_driver_environment(host_linker_selected, true);
        let mut expected_invocation_environment = expected_driver_environment.clone();
        for selected in &self.build_enforcement_identity.environment {
            if expected_invocation_environment
                .insert(selected.variable.clone(), selected.value.clone())
                .is_some()
            {
                return invalid("selected environment collides with the Cargo driver environment");
            }
        }
        if self.build_enforcement_identity.schema != 2
            || self.build_enforcement_identity.backend_semantic_version != 5
            || self.build_enforcement_identity.cargo_driver_environment
                != expected_driver_environment
            || self.cargo_invocation.environment != expected_invocation_environment
        {
            return invalid("Cargo driver or invocation environment is not exact");
        }
        self.enforcement_result.validate()?;
        if self.sbom_file != "rust-agent-sbom.cdx.json"
            || !is_digest(&self.sbom_digest)
            || self.artifacts.is_empty()
            || self.artifacts.len() > MAX_ARTIFACTS
            || !is_digest_or_empty(&self.build_manifest_digest)
            || !is_digest_or_empty(&self.build_output_digest)
            || self.gates.is_empty()
            || self.gates.len() > MAX_GATES
            || !sorted_unique(&self.gates)
            || self.gates.iter().any(|gate| !is_canonical_id(gate))
        {
            return invalid("closure, SBOM, artifact, gate, or digest shape is invalid");
        }
        let mut paths = BTreeSet::new();
        let mut folded = BTreeSet::new();
        for artifact in &self.artifacts {
            validate_relative_path(&artifact.path)?;
            if artifact.target != self.composition.target
                || artifact.bytes == 0
                || !is_digest(&artifact.digest)
                || !paths.insert(artifact.path.clone())
                || !folded.insert(artifact.path.to_ascii_lowercase())
            {
                return invalid("artifact records are duplicated, case-colliding, or invalid");
            }
        }
        if !self.artifacts.windows(2).all(|pair| pair[0] < pair[1])
            || !paths.contains(&self.entry_artifact)
        {
            return invalid("artifact records are not canonical or entry artifact is absent");
        }
        match self.build_options.build_kind {
            BuildKind::Library => validate_library(self)?,
            BuildKind::Bin => validate_binary(self)?,
            BuildKind::Wasm => validate_wasm(self, &paths)?,
        }
        Ok(())
    }
}

impl ProductionBuildOptionsIdentity {
    fn validate(&self) -> Result<(), ProductionArtifactError> {
        if self.schema != 1
            || !valid_text(&self.composition_profile)
            || !valid_text(&self.cargo_profile)
            || !valid_text(&self.target)
            || !self.locked
            || !self.offline
            || self.jobs != 1
        {
            return invalid("production build options are not exact");
        }
        Ok(())
    }
}

impl ProductionCargoInvocationIdentity {
    fn validate(&self) -> Result<(), ProductionArtifactError> {
        if self.schema != 1
            || self.arguments.is_empty()
            || self.arguments.len() > MAX_INVOCATION_ARGUMENTS
            || self.environment.len() > MAX_INVOCATION_ENVIRONMENT
            || !normalized_logical_absolute(&self.working_directory)
            || self.arguments.iter().any(|value| !valid_text(value))
            || self
                .environment
                .iter()
                .any(|(name, value)| !valid_environment_name(name) || !valid_text(value))
            || !contains_exact_flag(&self.arguments, "--locked")
            || !contains_exact_flag(&self.arguments, "--offline")
        {
            return invalid("Cargo invocation identity is invalid");
        }
        Ok(())
    }
}

impl ProductionEnforcementResultIdentity {
    fn validate(&self) -> Result<(), ProductionArtifactError> {
        let digests = [
            &self.build_input_content_digest,
            &self.planned_unit_graph_digest,
            &self.observed_unit_graph_digest,
            &self.cargo_messages_digest,
        ];
        if self.schema != 1
            || digests.into_iter().any(|digest| !is_digest(digest))
            || self.planned_unit_graph_digest != self.observed_unit_graph_digest
            || self.filesystem_enforcement != "closed-world-read-write-exec"
            || self.network_enforcement != "isolated"
            || self.descendant_enforcement != "inherited"
        {
            return invalid("normalized enforcement result is invalid");
        }
        Ok(())
    }
}

fn validate_library(manifest: &ProductionBuildManifest) -> Result<(), ProductionArtifactError> {
    if manifest.postprocessor.is_some()
        || manifest.artifacts.len() != 1
        || !matches!(
            manifest.artifacts[0].kind,
            ProductionArtifactKind::RustLibrary
                | ProductionArtifactKind::StaticLibrary
                | ProductionArtifactKind::DynamicLibrary
        )
        || manifest.entry_artifact != manifest.artifacts[0].path
    {
        return invalid("production library artifact shape is invalid");
    }
    Ok(())
}

fn validate_binary(manifest: &ProductionBuildManifest) -> Result<(), ProductionArtifactError> {
    if manifest.postprocessor.is_some()
        || manifest.artifacts.len() != 1
        || manifest.artifacts[0].kind != ProductionArtifactKind::NativeExecutable
        || manifest.entry_artifact != manifest.artifacts[0].path
    {
        return invalid("production binary artifact shape is invalid");
    }
    Ok(())
}

fn validate_wasm(
    manifest: &ProductionBuildManifest,
    paths: &BTreeSet<String>,
) -> Result<(), ProductionArtifactError> {
    let post = manifest.postprocessor.as_ref().ok_or_else(|| {
        ProductionArtifactError::InvalidManifest("missing WASM postprocessor".into())
    })?;
    if post.schema != 1
        || post.logical_id != WASM_BINDGEN_CLI_LOGICAL_ID
        || post.protocol_version != WASM_BINDGEN_PROTOCOL_VERSION
        || !is_digest(&post.executable_digest)
        || post.executable_version != format!("wasm-bindgen {WASM_BINDGEN_PROTOCOL_VERSION}")
        || post.invocation != crate::wasm_bundle::normalized_invocation()
        || !is_digest(&post.raw_input_digest)
        || manifest.entry_artifact != "bundle/rust_agent.js"
    {
        return invalid("WASM postprocessor identity is invalid");
    }
    let raw = manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ProductionArtifactKind::RawWasmIntermediate)
        .collect::<Vec<_>>();
    if raw.len() != 1
        || raw[0].path != "intermediate/rust_agent_raw.wasm"
        || raw[0].digest != post.raw_input_digest
    {
        return invalid("raw WASM input is missing or not bound to postprocessing");
    }
    let outputs = manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind != ProductionArtifactKind::RawWasmIntermediate)
        .map(|artifact| artifact.path.clone())
        .collect::<Vec<_>>();
    if outputs != post.outputs
        || !paths.contains("bundle/rust_agent.js")
        || !paths.contains("bundle/rust_agent_bg.wasm")
        || !paths.contains("bundle/rust_agent.d.ts")
        || manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.kind == ProductionArtifactKind::JavaScriptLoader)
            .count()
            != 1
        || manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.kind == ProductionArtifactKind::TransformedWasm)
            .count()
            != 1
        || manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.kind != ProductionArtifactKind::RawWasmIntermediate)
            .any(|artifact| !valid_wasm_output(artifact))
    {
        return invalid("WASM bundle is incomplete or output accounting drifted");
    }
    Ok(())
}

fn valid_wasm_output(artifact: &ProductionArtifactRecord) -> bool {
    let Some(relative) = artifact.path.strip_prefix("bundle/") else {
        return false;
    };
    match Path::new(relative)
        .extension()
        .and_then(|value| value.to_str())
    {
        Some("wasm") => artifact.kind == ProductionArtifactKind::TransformedWasm,
        Some("ts") if relative.ends_with(".d.ts") => {
            artifact.kind == ProductionArtifactKind::TypeScriptDeclaration
        }
        Some("js") if relative == "rust_agent.js" => {
            artifact.kind == ProductionArtifactKind::JavaScriptLoader
        }
        Some("js") => artifact.kind == ProductionArtifactKind::JavaScriptSnippet,
        _ => false,
    }
}

fn composition_manifest_digest(
    composition: &CompositionManifest,
) -> Result<String, ProductionArtifactError> {
    Ok(hex::encode(canonical::domain_hash(
        b"rust-agent-composition-manifest-identity-v1\0",
        composition,
    )?))
}

fn manifest_digest(manifest: &ProductionBuildManifest) -> Result<String, ProductionArtifactError> {
    let mut value = serde_json::to_value(manifest)?;
    let object = value
        .as_object_mut()
        .expect("production build manifest serializes as an object");
    if object.remove("build-manifest-digest").is_none()
        || object.remove("build-output-digest").is_none()
    {
        return invalid("derived digest fields are missing");
    }
    let payload = canonical::jcs_bytes(&value)?;
    Ok(hex::encode(canonical::raw_domain_hash(
        b"rust-agent-build-manifest-v1\0",
        &payload,
    )))
}

fn output_digest(manifest: &ProductionBuildManifest) -> Result<String, ProductionArtifactError> {
    #[derive(Serialize)]
    #[serde(deny_unknown_fields)]
    struct OutputIdentity<'a> {
        schema: u32,
        composition_manifest_digest: &'a str,
        build_enforcement_identity: &'a BuildEnforcementIdentity,
        enforcement_result: &'a ProductionEnforcementResultIdentity,
        build_options: &'a ProductionBuildOptionsIdentity,
        cargo_invocation: &'a ProductionCargoInvocationIdentity,
        entry_artifact: &'a str,
        artifacts: &'a [ProductionArtifactRecord],
        postprocessor: &'a Option<WasmPostprocessorManifest>,
        sbom_digest: &'a str,
        build_manifest_digest: String,
    }
    Ok(hex::encode(canonical::domain_hash(
        b"rust-agent-build-output-v1\0",
        &OutputIdentity {
            schema: 1,
            composition_manifest_digest: &manifest.composition_manifest_digest,
            build_enforcement_identity: &manifest.build_enforcement_identity,
            enforcement_result: &manifest.enforcement_result,
            build_options: &manifest.build_options,
            cargo_invocation: &manifest.cargo_invocation,
            entry_artifact: &manifest.entry_artifact,
            artifacts: &manifest.artifacts,
            postprocessor: &manifest.postprocessor,
            sbom_digest: &manifest.sbom_digest,
            build_manifest_digest: manifest_digest(manifest)?,
        },
    )?))
}

fn verify_tree_file_set(
    artifact_dir: &Path,
    expected: &BTreeSet<String>,
) -> Result<(), ProductionArtifactError> {
    let mut actual = BTreeSet::new();
    for entry in WalkDir::new(artifact_dir).sort_by_file_name() {
        let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
        let relative = entry
            .path()
            .strip_prefix(artifact_dir)
            .expect("walked production artifact is below root");
        if relative.as_os_str().is_empty() || entry.file_type().is_dir() {
            continue;
        }
        if !entry.file_type().is_file() {
            return invalid("artifact tree contains a symlink or special file");
        }
        actual.insert(
            relative
                .to_str()
                .ok_or_else(|| {
                    ProductionArtifactError::InvalidManifest("non-UTF-8 artifact path".into())
                })?
                .replace('\\', "/"),
        );
    }
    if &actual != expected {
        return Err(ProductionArtifactError::InvalidManifest(format!(
            "artifact tree file set mismatch: expected={expected:?} actual={actual:?}"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_publication_parent(parent: &Path) -> Result<(), ProductionArtifactError> {
    if !parent.is_absolute()
        || !fs::symlink_metadata(parent)?.file_type().is_dir()
        || fs::canonicalize(parent)? != parent
    {
        return Err(ProductionArtifactError::InvalidPublication(
            "artifact parent must be an existing canonical absolute directory".into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn read_staged_production_manifest(
    staging: &Path,
) -> Result<ProductionBuildManifest, ProductionArtifactError> {
    let path = staging.join(PRODUCTION_BUILD_MANIFEST_FILE);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_file() || metadata.len() > 32 * 1024 * 1024 {
        return Err(ProductionArtifactError::InvalidPublication(
            "staged build manifest kind or size is invalid".into(),
        ));
    }
    let manifest: ProductionBuildManifest = serde_json::from_slice(&fs::read(path)?)?;
    manifest.verify(staging, false, None, None)?;
    Ok(manifest)
}

#[cfg(target_os = "linux")]
fn seal_production_artifact_tree(
    root: &Path,
    manifest: &ProductionBuildManifest,
) -> Result<(), ProductionArtifactError> {
    let executables = manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == ProductionArtifactKind::NativeExecutable)
        .map(|artifact| artifact.path.as_str())
        .collect::<BTreeSet<_>>();
    let mut directories = Vec::new();
    for entry in WalkDir::new(root).sort_by_file_name() {
        let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err(ProductionArtifactError::InvalidPublication(format!(
                "artifact tree contains a symlink: {}",
                entry.path().display()
            )));
        }
        if metadata.is_dir() {
            directories.push(entry.path().to_owned());
            continue;
        }
        if !metadata.is_file() {
            return Err(ProductionArtifactError::InvalidPublication(format!(
                "artifact tree contains a special file: {}",
                entry.path().display()
            )));
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| {
                ProductionArtifactError::InvalidPublication(
                    "artifact entry escaped staging root".into(),
                )
            })?
            .to_str()
            .ok_or_else(|| {
                ProductionArtifactError::InvalidPublication(
                    "artifact entry path is not UTF-8".into(),
                )
            })?
            .replace('\\', "/");
        let mode = if executables.contains(relative.as_str()) {
            0o555
        } else {
            0o444
        };
        fs::set_permissions(entry.path(), fs::Permissions::from_mode(mode))?;
        File::open(entry.path())?.sync_all()?;
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        File::open(&directory)?.sync_all()?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o555))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_owned_artifact_staging(root: &Path) -> Result<(), ProductionArtifactError> {
    let mut entries = WalkDir::new(root)
        .contents_first(true)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io::Error::other(error.to_string()))?;
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.depth()));
    for entry in entries {
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err(ProductionArtifactError::InvalidPublication(
                "owned staging became a symlink".into(),
            ));
        }
        if metadata.is_dir() {
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o700))?;
        } else if metadata.is_file() {
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600))?;
        } else {
            return Err(ProductionArtifactError::InvalidPublication(
                "owned staging contains a special file".into(),
            ));
        }
    }
    fs::remove_dir_all(root)?;
    Ok(())
}

fn valid_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_uppercase())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 16 * 1024
        && !value.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
}

fn normalized_logical_absolute(value: &str) -> bool {
    let path = PathBuf::from(value);
    path.is_absolute()
        && value.starts_with("/rust-agent/")
        && path
            .components()
            .all(|component| !matches!(component, std::path::Component::ParentDir))
}

fn contains_exact_flag(arguments: &[String], flag: &str) -> bool {
    arguments
        .iter()
        .filter(|argument| argument.as_str() == flag)
        .count()
        == 1
}

fn sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn is_digest_or_empty(value: &str) -> bool {
    value.is_empty() || is_digest(value)
}

fn invalid<T>(message: &str) -> Result<T, ProductionArtifactError> {
    Err(ProductionArtifactError::InvalidManifest(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn cargo_artifact_classifier_excludes_intermediates_and_ambiguous_kinds() {
        let library = BuildArtifactSelector {
            package: "fixture".into(),
            target: BuildArtifactTarget::Library,
        };
        assert_eq!(
            classify_cargo_artifact("/rust-agent/target/release/libfixture.rlib", &library),
            Some(ProductionArtifactKind::RustLibrary)
        );
        assert_eq!(
            classify_cargo_artifact("/rust-agent/target/release/libfixture.rmeta", &library),
            None
        );
        assert_eq!(
            classify_cargo_artifact("/host/target/release/libfixture.rlib", &library),
            None
        );
        let binary = BuildArtifactSelector {
            package: "fixture".into(),
            target: BuildArtifactTarget::Binary {
                name: "fixture".into(),
            },
        };
        assert_eq!(
            classify_cargo_artifact("/rust-agent/target/release/fixture", &binary),
            Some(ProductionArtifactKind::NativeExecutable)
        );
        assert_eq!(
            classify_cargo_artifact("/rust-agent/target/release/fixture.d", &binary),
            None
        );
    }

    #[test]
    fn output_identity_is_path_free_but_security_sensitive() {
        #[derive(Serialize)]
        struct Identity<'a> {
            logical_tool: &'a str,
            enforcement_digest: &'a str,
            artifact_digest: &'a str,
        }
        let digest = |logical_tool: &str, enforcement: &str, artifact: &str| {
            hex::encode(
                canonical::domain_hash(
                    b"rust-agent-production-output-identity-test-v1\0",
                    &Identity {
                        logical_tool,
                        enforcement_digest: enforcement,
                        artifact_digest: artifact,
                    },
                )
                .unwrap(),
            )
        };
        let baseline = digest(
            "/rust-agent/toolchain/bin/cargo",
            &"11".repeat(32),
            &"22".repeat(32),
        );
        assert_eq!(
            baseline,
            digest(
                "/rust-agent/toolchain/bin/cargo",
                &"11".repeat(32),
                &"22".repeat(32)
            )
        );
        assert_ne!(
            baseline,
            digest(
                "/rust-agent/toolchain/bin/cargo",
                &"33".repeat(32),
                &"22".repeat(32)
            )
        );
        assert_ne!(
            baseline,
            digest(
                "/rust-agent/toolchain/bin/cargo",
                &"11".repeat(32),
                &"44".repeat(32)
            )
        );
    }

    #[test]
    fn invocation_and_enforcement_shapes_fail_closed() {
        let invocation = ProductionCargoInvocationIdentity {
            schema: 1,
            arguments: vec!["build".into(), "--locked".into(), "--offline".into()],
            environment: BTreeMap::new(),
            working_directory: "/rust-agent/workspace".into(),
        };
        invocation.validate().unwrap();
        let mut duplicate = invocation.clone();
        duplicate.arguments.push("--offline".into());
        assert!(duplicate.validate().is_err());

        let mut enforcement = ProductionEnforcementResultIdentity {
            schema: 1,
            build_input_content_digest: "00".repeat(32),
            planned_unit_graph_digest: "05".repeat(32),
            observed_unit_graph_digest: "05".repeat(32),
            cargo_messages_digest: "08".repeat(32),
            filesystem_enforcement: "closed-world-read-write-exec".into(),
            network_enforcement: "isolated".into(),
            descendant_enforcement: "inherited".into(),
        };
        enforcement.validate().unwrap();
        enforcement.observed_unit_graph_digest = "09".repeat(32);
        assert!(enforcement.validate().is_err());
    }

    #[test]
    fn production_manifest_schema_rejects_unknown_fields() {
        let json = r#"{"schema":1,"mode":"production","deployable":true,"unknown":true}"#;
        assert!(serde_json::from_str::<ProductionBuildManifest>(json).is_err());
    }
}
