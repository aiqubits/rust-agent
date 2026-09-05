use std::{
    collections::BTreeSet,
    fs, io,
    path::{Component, Path},
};

use rust_agent_composition::{
    CompositionManifest, WASM_BINDGEN_CLI_LOGICAL_ID, WASM_BINDGEN_PROTOCOL_VERSION, canonical,
    profile::BuildKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DevelopmentArtifactKind {
    RustLibrary,
    RawWasmIntermediate,
    JavaScriptLoader,
    TransformedWasm,
    TypeScriptDeclaration,
    JavaScriptSnippet,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentArtifactRecord {
    pub path: String,
    pub kind: DevelopmentArtifactKind,
    pub bytes: u64,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WasmPostprocessorManifest {
    pub schema: u32,
    #[serde(rename = "logical-id")]
    pub logical_id: String,
    #[serde(rename = "protocol-version")]
    pub protocol_version: String,
    #[serde(rename = "executable-digest")]
    pub executable_digest: String,
    #[serde(rename = "executable-version")]
    pub executable_version: String,
    pub invocation: Vec<String>,
    #[serde(rename = "raw-input-digest")]
    pub raw_input_digest: String,
    pub outputs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentBuildManifest {
    pub schema: u32,
    #[serde(rename = "composition-hash")]
    pub composition_hash: String,
    #[serde(rename = "profile-name")]
    pub profile: String,
    pub target: String,
    pub deployable: bool,
    pub mode: String,
    #[serde(rename = "build-kind")]
    pub build_kind: BuildKind,
    #[serde(rename = "policy-digest")]
    pub policy_digest: String,
    #[serde(rename = "entry-artifact")]
    pub entry_artifact: String,
    pub artifacts: Vec<DevelopmentArtifactRecord>,
    pub postprocessor: Option<WasmPostprocessorManifest>,
    #[serde(rename = "sbom-file")]
    pub sbom_file: String,
    #[serde(rename = "sbom-digest")]
    pub sbom_digest: String,
    #[serde(rename = "generated-tests-ran")]
    pub generated_tests_ran: bool,
    pub gates: Vec<String>,
    #[serde(rename = "build-manifest-digest")]
    pub build_manifest_digest: String,
    #[serde(rename = "build-output-digest")]
    pub build_output_digest: String,
}

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("artifact I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("artifact serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("artifact canonical encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
    #[error("artifact manifest is invalid: {0}")]
    InvalidManifest(String),
    #[error("CycloneDX SBOM is invalid: {0}")]
    InvalidSbom(String),
    #[error("Cargo.lock is invalid: {0}")]
    InvalidCargoLock(String),
}

impl DevelopmentBuildManifest {
    pub(crate) fn finalize_digests(&mut self) -> Result<(), ArtifactError> {
        validate_manifest_shape(self)?;
        self.build_manifest_digest = manifest_digest(self)?;
        self.build_output_digest = output_digest(self)?;
        Ok(())
    }

    pub(crate) fn verify(&self, artifact_dir: &Path) -> Result<(), ArtifactError> {
        validate_manifest_shape(self)?;
        verify_artifact_files(self, artifact_dir)?;
        let sbom = fs::read(artifact_dir.join(&self.sbom_file))?;
        if sha256_hex(&sbom) != self.sbom_digest {
            return Err(ArtifactError::InvalidManifest(
                "SBOM digest mismatch".into(),
            ));
        }
        verify_sbom_artifacts(&sbom, &self.artifacts, &self.composition_hash)?;
        if manifest_digest(self)? != self.build_manifest_digest {
            return Err(ArtifactError::InvalidManifest(
                "build-manifest-digest mismatch".into(),
            ));
        }
        if output_digest(self)? != self.build_output_digest {
            return Err(ArtifactError::InvalidManifest(
                "build-output-digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn artifact_record(
    root: &Path,
    relative: &str,
    kind: DevelopmentArtifactKind,
) -> Result<DevelopmentArtifactRecord, ArtifactError> {
    validate_relative_path(relative)?;
    let bytes = fs::read(root.join(relative))?;
    Ok(DevelopmentArtifactRecord {
        path: relative.into(),
        kind,
        bytes: bytes.len() as u64,
        digest: sha256_hex(&bytes),
    })
}

pub(crate) fn write_cyclonedx_sbom(
    artifact_dir: &Path,
    composition: &CompositionManifest,
    cargo_lock: &Path,
    artifacts: &[DevelopmentArtifactRecord],
) -> Result<(String, String), ArtifactError> {
    let files = artifacts
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact.digest.as_str()))
        .collect::<Vec<_>>();
    write_cyclonedx_sbom_files(artifact_dir, composition, cargo_lock, &files)
}

pub(crate) fn write_cyclonedx_sbom_files(
    artifact_dir: &Path,
    composition: &CompositionManifest,
    cargo_lock: &Path,
    artifacts: &[(&str, &str)],
) -> Result<(String, String), ArtifactError> {
    #[derive(Deserialize)]
    struct CargoLock {
        package: Vec<LockPackage>,
    }
    #[derive(Deserialize)]
    struct LockPackage {
        name: String,
        version: String,
        source: Option<String>,
        checksum: Option<String>,
    }
    let lock: CargoLock = toml::from_str(&fs::read_to_string(cargo_lock)?)
        .map_err(|error| ArtifactError::InvalidCargoLock(error.to_string()))?;
    let mut components = Vec::new();
    for package in lock.package {
        let source = package.source.unwrap_or_else(|| "path".into());
        let bom_ref = format!(
            "pkg:cargo/{}@{}?source={source}",
            package.name, package.version
        );
        components.push(CycloneDxComponent {
            component_type: "library".into(),
            bom_ref,
            name: package.name,
            version: Some(package.version),
            hashes: package.checksum.map(|checksum| {
                vec![CycloneDxHash {
                    algorithm: "SHA-256".into(),
                    content: checksum,
                }]
            }),
        });
    }
    for (path, digest) in artifacts {
        components.push(CycloneDxComponent {
            component_type: "file".into(),
            bom_ref: format!("file:{path}"),
            name: (*path).into(),
            version: None,
            hashes: Some(vec![CycloneDxHash {
                algorithm: "SHA-256".into(),
                content: (*digest).into(),
            }]),
        });
    }
    components.sort_by(|left, right| left.bom_ref.cmp(&right.bom_ref));
    let bom = CycloneDxBom {
        bom_format: "CycloneDX".into(),
        spec_version: "1.6".into(),
        version: 1,
        metadata: CycloneDxMetadata {
            component: CycloneDxComponent {
                component_type: "application".into(),
                bom_ref: format!("composition:{}", composition.composition_hash),
                name: "rust-agent-generated-composition".into(),
                version: Some("0.1.0".into()),
                hashes: None,
            },
        },
        components,
    };
    let bytes = canonical::jcs_bytes(&bom)?;
    let relative = "rust-agent-sbom.cdx.json".to_owned();
    fs::write(artifact_dir.join(&relative), &bytes)?;
    Ok((relative, sha256_hex(&bytes)))
}

fn validate_manifest_shape(manifest: &DevelopmentBuildManifest) -> Result<(), ArtifactError> {
    if manifest.schema != 2 || manifest.deployable || manifest.mode != "development" {
        return Err(ArtifactError::InvalidManifest(
            "schema/mode/deployability contract mismatch".into(),
        ));
    }
    if manifest.artifacts.is_empty() || !is_digest(&manifest.composition_hash) {
        return Err(ArtifactError::InvalidManifest(
            "artifact set is empty or composition identity is invalid".into(),
        ));
    }
    if manifest.profile.is_empty()
        || manifest.target.is_empty()
        || manifest.gates.is_empty()
        || manifest
            .gates
            .windows(2)
            .any(|pair| pair[0].as_str() >= pair[1].as_str())
        || manifest.gates.iter().any(|gate| !is_canonical_id(gate))
    {
        return Err(ArtifactError::InvalidManifest(
            "profile, target, or normalized gate set is invalid".into(),
        ));
    }
    let mut previous = None;
    let mut paths = BTreeSet::new();
    let mut folded = BTreeSet::new();
    for artifact in &manifest.artifacts {
        validate_relative_path(&artifact.path)?;
        if previous.is_some_and(|value: &str| value >= artifact.path.as_str())
            || !paths.insert(artifact.path.clone())
            || !folded.insert(artifact.path.to_ascii_lowercase())
            || artifact.bytes == 0
            || !is_digest(&artifact.digest)
        {
            return Err(ArtifactError::InvalidManifest(
                "artifact records are unsorted, duplicate, case-colliding, or invalid".into(),
            ));
        }
        previous = Some(&artifact.path);
    }
    if !paths.contains(&manifest.entry_artifact)
        || manifest.sbom_file != "rust-agent-sbom.cdx.json"
        || !is_digest(&manifest.sbom_digest)
        || !is_digest(&manifest.policy_digest)
    {
        return Err(ArtifactError::InvalidManifest(
            "entry, SBOM, or policy identity is invalid".into(),
        ));
    }
    match manifest.build_kind {
        BuildKind::Library => {
            if manifest.postprocessor.is_some()
                || manifest.artifacts.len() != 1
                || manifest.artifacts[0].kind != DevelopmentArtifactKind::RustLibrary
                || manifest.artifacts[0].path != "librust_agent_generated_composition.rlib"
                || manifest.entry_artifact != manifest.artifacts[0].path
            {
                return Err(ArtifactError::InvalidManifest(
                    "library artifact shape is invalid".into(),
                ));
            }
        }
        BuildKind::Wasm => validate_wasm_shape(manifest, &paths)?,
        BuildKind::Bin => {
            return Err(ArtifactError::InvalidManifest(
                "Phase 1A bin artifact is unsupported".into(),
            ));
        }
    }
    Ok(())
}

fn validate_wasm_shape(
    manifest: &DevelopmentBuildManifest,
    paths: &BTreeSet<String>,
) -> Result<(), ArtifactError> {
    let post = manifest.postprocessor.as_ref().ok_or_else(|| {
        ArtifactError::InvalidManifest("raw WASM has no postprocessor manifest".into())
    })?;
    if post.schema != 1
        || post.logical_id != WASM_BINDGEN_CLI_LOGICAL_ID
        || post.protocol_version != WASM_BINDGEN_PROTOCOL_VERSION
        || !is_digest(&post.executable_digest)
        || post.executable_version != format!("wasm-bindgen {WASM_BINDGEN_PROTOCOL_VERSION}")
        || !is_digest(&post.raw_input_digest)
        || post.invocation != crate::wasm_bundle::normalized_invocation()
        || manifest.entry_artifact != "bundle/rust_agent.js"
    {
        return Err(ArtifactError::InvalidManifest(
            "WASM postprocessor identity is invalid".into(),
        ));
    }
    let raw_inputs: Vec<_> = manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == DevelopmentArtifactKind::RawWasmIntermediate)
        .collect();
    if raw_inputs.len() != 1 || raw_inputs[0].path != "intermediate/rust_agent_raw.wasm" {
        return Err(ArtifactError::InvalidManifest(
            "raw WASM input is missing, duplicated, or misplaced".into(),
        ));
    }
    let raw = raw_inputs[0];
    if raw.digest != post.raw_input_digest {
        return Err(ArtifactError::InvalidManifest(
            "raw WASM digest is not bound to postprocessing".into(),
        ));
    }
    let outputs: Vec<_> = manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind != DevelopmentArtifactKind::RawWasmIntermediate)
        .map(|artifact| artifact.path.clone())
        .collect();
    for artifact in manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind != DevelopmentArtifactKind::RawWasmIntermediate)
    {
        let relative = artifact.path.strip_prefix("bundle/").ok_or_else(|| {
            ArtifactError::InvalidManifest("WASM output is outside the bundle directory".into())
        })?;
        if crate::wasm_bundle::classify_output(relative)? != artifact.kind {
            return Err(ArtifactError::InvalidManifest(format!(
                "WASM output `{}` has the wrong artifact kind",
                artifact.path
            )));
        }
    }
    if outputs != post.outputs
        || !paths.contains("bundle/rust_agent_bg.wasm")
        || !paths.contains("bundle/rust_agent.d.ts")
        || !manifest
            .artifacts
            .iter()
            .any(|artifact| artifact.kind == DevelopmentArtifactKind::TransformedWasm)
        || manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.kind == DevelopmentArtifactKind::JavaScriptLoader)
            .count()
            != 1
        || manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.kind == DevelopmentArtifactKind::TransformedWasm)
            .count()
            != 1
    {
        return Err(ArtifactError::InvalidManifest(
            "WASM bundle is incomplete or output accounting drifted".into(),
        ));
    }
    Ok(())
}

fn verify_artifact_files(
    manifest: &DevelopmentBuildManifest,
    artifact_dir: &Path,
) -> Result<(), ArtifactError> {
    let expected: BTreeSet<_> = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .chain([manifest.sbom_file.clone(), "rust-agent-build.json".into()])
        .collect();
    let mut actual = BTreeSet::new();
    for entry in WalkDir::new(artifact_dir).sort_by_file_name() {
        let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
        let relative = entry
            .path()
            .strip_prefix(artifact_dir)
            .expect("walked artifact is below root");
        if relative.as_os_str().is_empty() || entry.file_type().is_dir() {
            continue;
        }
        if !entry.file_type().is_file() {
            return Err(ArtifactError::InvalidManifest(
                "artifact tree contains a symlink or special file".into(),
            ));
        }
        actual.insert(
            relative
                .to_str()
                .ok_or_else(|| ArtifactError::InvalidManifest("non-UTF-8 artifact path".into()))?
                .replace('\\', "/"),
        );
    }
    if actual != expected {
        return Err(ArtifactError::InvalidManifest(
            "artifact tree has missing or unaccounted files".into(),
        ));
    }
    for artifact in &manifest.artifacts {
        let bytes = fs::read(artifact_dir.join(&artifact.path))?;
        if bytes.len() as u64 != artifact.bytes || sha256_hex(&bytes) != artifact.digest {
            return Err(ArtifactError::InvalidManifest(format!(
                "artifact `{}` digest or byte count mismatch",
                artifact.path
            )));
        }
    }
    Ok(())
}

fn manifest_digest(manifest: &DevelopmentBuildManifest) -> Result<String, ArtifactError> {
    let mut value = serde_json::to_value(manifest)?;
    let object = value
        .as_object_mut()
        .expect("build manifest serializes as an object");
    if object.remove("build-manifest-digest").is_none()
        || object.remove("build-output-digest").is_none()
    {
        return Err(ArtifactError::InvalidManifest(
            "derived digest fields are missing".into(),
        ));
    }
    let payload = canonical::jcs_bytes(&value)?;
    Ok(hex::encode(canonical::raw_domain_hash(
        b"rust-agent-build-manifest-v1\0",
        &payload,
    )))
}

fn output_digest(manifest: &DevelopmentBuildManifest) -> Result<String, ArtifactError> {
    #[derive(Serialize)]
    struct OutputIdentity<'a> {
        schema: u32,
        composition_hash: &'a str,
        target: &'a str,
        build_kind: BuildKind,
        policy_digest: &'a str,
        artifacts: &'a [DevelopmentArtifactRecord],
        postprocessor: &'a Option<WasmPostprocessorManifest>,
        sbom_digest: &'a str,
        build_manifest_digest: String,
    }
    let identity = OutputIdentity {
        schema: 1,
        composition_hash: &manifest.composition_hash,
        target: &manifest.target,
        build_kind: manifest.build_kind,
        policy_digest: &manifest.policy_digest,
        artifacts: &manifest.artifacts,
        postprocessor: &manifest.postprocessor,
        sbom_digest: &manifest.sbom_digest,
        build_manifest_digest: manifest_digest(manifest)?,
    };
    Ok(hex::encode(canonical::domain_hash(
        b"rust-agent-build-output-v1\0",
        &identity,
    )?))
}

fn verify_sbom_artifacts(
    bytes: &[u8],
    artifacts: &[DevelopmentArtifactRecord],
    composition_hash: &str,
) -> Result<(), ArtifactError> {
    let files = artifacts
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact.digest.as_str()))
        .collect::<Vec<_>>();
    verify_sbom_files(bytes, &files, composition_hash)
}

pub(crate) fn verify_sbom_files(
    bytes: &[u8],
    artifacts: &[(&str, &str)],
    composition_hash: &str,
) -> Result<(), ArtifactError> {
    let bom: CycloneDxBom = serde_json::from_slice(bytes)?;
    if bom.bom_format != "CycloneDX" || bom.spec_version != "1.6" || bom.version != 1 {
        return Err(ArtifactError::InvalidSbom(
            "unknown format/spec/version".into(),
        ));
    }
    if bom.metadata.component.component_type != "application"
        || bom.metadata.component.bom_ref != format!("composition:{composition_hash}")
        || bom.metadata.component.name != "rust-agent-generated-composition"
        || bom.metadata.component.version.as_deref() != Some("0.1.0")
        || bom
            .components
            .windows(2)
            .any(|pair| pair[0].bom_ref >= pair[1].bom_ref)
    {
        return Err(ArtifactError::InvalidSbom(
            "metadata identity or component ordering is invalid".into(),
        ));
    }
    let expected_files: BTreeSet<_> = artifacts
        .iter()
        .map(|(path, _)| format!("file:{path}"))
        .collect();
    let actual_files: BTreeSet<_> = bom
        .components
        .iter()
        .filter(|component| component.component_type == "file")
        .map(|component| component.bom_ref.clone())
        .collect();
    if actual_files != expected_files {
        return Err(ArtifactError::InvalidSbom(
            "SBOM file component set differs from the artifact set".into(),
        ));
    }
    for (path, digest) in artifacts {
        let component = bom
            .components
            .iter()
            .find(|component| component.bom_ref == format!("file:{path}"))
            .ok_or_else(|| ArtifactError::InvalidSbom(format!("artifact `{path}` is missing")))?;
        if component.component_type != "file"
            || component.name != *path
            || component.hashes.as_deref()
                != Some(&[CycloneDxHash {
                    algorithm: "SHA-256".into(),
                    content: (*digest).into(),
                }])
        {
            return Err(ArtifactError::InvalidSbom(format!(
                "artifact `{path}` identity mismatch"
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_relative_path(value: &str) -> Result<(), ArtifactError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('\\')
        || path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(ArtifactError::InvalidManifest(format!(
            "invalid artifact path `{value}`"
        )));
    }
    Ok(())
}

pub(crate) fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn is_canonical_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && !bytes.windows(2).any(|pair| pair == b"--")
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CycloneDxBom {
    bom_format: String,
    spec_version: String,
    version: u32,
    metadata: CycloneDxMetadata,
    components: Vec<CycloneDxComponent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CycloneDxMetadata {
    component: CycloneDxComponent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CycloneDxComponent {
    #[serde(rename = "type")]
    component_type: String,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hashes: Option<Vec<CycloneDxHash>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CycloneDxHash {
    #[serde(rename = "alg")]
    algorithm: String,
    content: String,
}
