//! Build policy contracts plus the locked development-only Phase 1A executor.
//!
//! The Phase 1B production policy types in this crate do not themselves make a
//! build deployable. A production backend must still supply verified confinement,
//! unit observation, escape-suite evidence and a trusted completion attestation.

mod artifact;
mod cargo_unit_graph;
mod host_feature;
mod integration;
mod policy;
mod production_policy;
mod topology;
mod wasm_bundle;

use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
};

pub use artifact::{
    ArtifactError, DevelopmentArtifactKind, DevelopmentArtifactRecord, DevelopmentBuildManifest,
    WasmPostprocessorManifest,
};
pub use cargo_unit_graph::{
    CargoCompilationKind, CargoCompileMode, CargoCrateKind, CargoDependencyKind,
    CargoPackageIdentity, CargoPackageSource, CargoTargetEvaluationDomain, CargoUnit,
    CargoUnitEdge, CargoUnitGraphError, CargoUnitGraphPlannerIdentity, CargoUnitSelector,
    HostCargoUnitGraph, NormalizedCargoUnit, NormalizedHostCargoUnitGraph,
};
pub use host_feature::{
    DevelopmentHostFeatureReceipt, DevelopmentHostFeatureVerification, FeatureAccountingMode,
    FeatureDelta, FeatureSemanticsEvidence, HostFeatureDeltaRecord, HostFeaturePolicyEntry,
    HostFeaturePolicyError, HostFeaturePolicyStageDigests, HostFeatureUnionPolicy,
    HostFeatureUnitObservation, NormalizedHostFeaturePolicy, ProductBuildContribution,
    verify_development_host_feature_union,
};
pub use integration::{
    IntegrationError, emit_integration, verify_integration, verify_integration_topology,
};
pub use policy::{
    BuildEnvironment, BuildExecutable, BuildExecutionPolicy, BuildPolicyError, BuildReadInput,
    VerifiedBuildExecutable,
};
pub use production_policy::{
    BuildEnforcementContext, BuildEnforcementEnvironment, BuildEnforcementExecutable,
    BuildEnforcementIdentity, BuildEnforcementReadInput, BuildEnforcementToolchain,
    BuildPanicStrategy, DerivedExecutablePolicy, NormalizedProductionBuildPolicy,
    ProductionAttestationPolicy, ProductionBuildExecutionPolicy, ProductionBuildPolicyError,
    ProductionEnvironment, ProductionExecutable, ProductionFetchPolicy, ProductionFileIdentity,
    ProductionReadInput, ProductionSandboxBackend, ProductionToolIdentity, ProductionToolchain,
    ProductionTreeIdentity, SigningHelper, TrustedReviewerPolicy, TrustedSigner,
};
use rust_agent_composition::{
    CompositionManifest, WASM_BINDGEN_CLI_LOGICAL_ID, WASM_BINDGEN_PROTOCOL_VERSION,
    profile::BuildKind, verify_composition,
};
use tempfile::TempDir;
use thiserror::Error;
pub use topology::{HostIntegrationTopology, HostTopologyError, verify_host_topology};

#[derive(Clone, Debug)]
pub struct DevelopmentBuildOptions {
    pub composition_path: PathBuf,
    pub artifact_dir: PathBuf,
    pub cargo_path: PathBuf,
    pub rustc_path: PathBuf,
    pub linker_path: PathBuf,
    pub registry_cache_path: Option<PathBuf>,
    pub policy: BuildExecutionPolicy,
    pub run_generated_tests: bool,
}

#[derive(Debug, Error)]
pub enum DevelopmentBuildError {
    #[error("build inputs and tools must be absolute paths: {0}")]
    NonAbsolutePath(String),
    #[error("composition verification failed: {0}")]
    Composition(#[from] rust_agent_composition::ComposeError),
    #[error("build policy is invalid: {0}")]
    Policy(#[from] BuildPolicyError),
    #[error("artifact contract failed: {0}")]
    Artifact(#[from] ArtifactError),
    #[error("WASM build contract failed: {0}")]
    WasmContract(String),
    #[error("build requires an explicit offline registry cache: {0}")]
    RegistryCacheRequired(String),
    #[error("development Cargo {step} failed: {output}")]
    Cargo { step: &'static str, output: String },
    #[error("expected generated artifact is missing: {0}")]
    MissingArtifact(String),
    #[error("artifact output directory is not empty: {0}")]
    ArtifactDirectoryNotEmpty(String),
    #[error("I/O failed during development build: {0}")]
    Io(#[from] io::Error),
}

pub fn development_build(
    options: &DevelopmentBuildOptions,
) -> Result<DevelopmentBuildManifest, DevelopmentBuildError> {
    validate_paths(options)?;
    let composition = verify_composition(&options.composition_path)?;
    if !composition.cargo_resolution.registries.is_empty() && options.registry_cache_path.is_none()
    {
        return Err(DevelopmentBuildError::RegistryCacheRequired(
            composition
                .cargo_resolution
                .registries
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(","),
        ));
    }
    let normalized_policy = options.policy.normalize()?;
    normalized_policy.authorize(&composition.build_requirements)?;
    let wasm_executable = if composition.build_kind == BuildKind::Wasm {
        verify_wasm_root_requirement(&composition)?;
        wasm_bundle::verify_protocol_lock(&options.composition_path.join("Cargo.lock"))
            .map_err(DevelopmentBuildError::WasmContract)?;
        Some(normalized_policy.verify_executable(
            WASM_BINDGEN_CLI_LOGICAL_ID,
            &format!("wasm-bindgen {WASM_BINDGEN_PROTOCOL_VERSION}"),
        )?)
    } else {
        None
    };

    if options.artifact_dir.exists()
        && fs::read_dir(&options.artifact_dir)?
            .next()
            .transpose()?
            .is_some()
    {
        return Err(DevelopmentBuildError::ArtifactDirectoryNotEmpty(
            options.artifact_dir.display().to_string(),
        ));
    }
    fs::create_dir_all(&options.artifact_dir)?;
    let sandbox = TempDir::new()?;
    let cargo_home = sandbox.path().join("cargo-home");
    let target_dir = sandbox.path().join("target");
    fs::create_dir(&cargo_home)?;
    link_registry_cache(&cargo_home, options.registry_cache_path.as_deref())?;
    fs::create_dir(&target_dir)?;

    if options.run_generated_tests {
        let args: &[&str] = if composition.build_kind == BuildKind::Wasm {
            &["test", "--no-run", "--locked", "--offline"]
        } else {
            &["test", "--locked", "--offline"]
        };
        run_cargo(options, &cargo_home, &target_dir, "test", args)?;
    }
    run_cargo(
        options,
        &cargo_home,
        &target_dir,
        "build",
        &["build", "--locked", "--offline"],
    )?;

    let artifact_source = generated_artifact_path(&target_dir, &composition);
    if !artifact_source.is_file() {
        return Err(DevelopmentBuildError::MissingArtifact(
            artifact_source.display().to_string(),
        ));
    }
    let (mut artifacts, postprocessor, entry_artifact) = match composition.build_kind {
        BuildKind::Library => {
            let artifact_name = artifact_source
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| {
                    DevelopmentBuildError::MissingArtifact(artifact_source.display().to_string())
                })?
                .to_owned();
            fs::copy(&artifact_source, options.artifact_dir.join(&artifact_name))?;
            let artifact = artifact::artifact_record(
                &options.artifact_dir,
                &artifact_name,
                DevelopmentArtifactKind::RustLibrary,
            )?;
            (vec![artifact], None, artifact_name)
        }
        BuildKind::Wasm => {
            let executable = wasm_executable.as_ref().ok_or_else(|| {
                DevelopmentBuildError::WasmContract(
                    "verified wasm-bindgen executable is missing".into(),
                )
            })?;
            let (artifacts, postprocessor) =
                wasm_bundle::postprocess(&artifact_source, &options.artifact_dir, executable)?;
            (
                artifacts,
                Some(postprocessor),
                "bundle/rust_agent.js".into(),
            )
        }
        BuildKind::Bin => {
            return Err(DevelopmentBuildError::WasmContract(
                "Phase 1A binary builds are unsupported".into(),
            ));
        }
    };
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));
    let (sbom_file, sbom_digest) = artifact::write_cyclonedx_sbom(
        &options.artifact_dir,
        &composition,
        &options.composition_path.join("Cargo.lock"),
        &artifacts,
    )?;
    let policy_digest = normalized_policy.digest()?;
    let generated_tests_ran =
        options.run_generated_tests && composition.build_kind == BuildKind::Library;
    let mut gates = vec![
        "composition-identity-verified".into(),
        "build-requirements-authorized".into(),
        "isolated-cargo-home".into(),
        "locked-offline-cargo".into(),
        "generated-factory-typecheck".into(),
        "artifact-tree-accounted".into(),
        "cyclonedx-sbom-emitted".into(),
    ];
    if composition.build_kind == BuildKind::Wasm {
        gates.extend([
            "direct-host-tool-requirement-verified".into(),
            "wasm-protocol-lock-verified".into(),
            "wasm-bindgen-bytes-and-version-verified".into(),
            "wasm-bundle-closed-world-verified".into(),
        ]);
        if options.run_generated_tests {
            gates.push("generated-wasm-tests-compiled".into());
        }
    }
    gates.sort();
    let mut manifest = DevelopmentBuildManifest {
        schema: 2,
        composition_hash: composition.composition_hash,
        profile: composition.profile,
        target: composition.target,
        deployable: false,
        mode: "development".into(),
        build_kind: composition.build_kind,
        policy_digest,
        entry_artifact,
        artifacts,
        postprocessor,
        sbom_file,
        sbom_digest,
        generated_tests_ran,
        gates,
        build_manifest_digest: String::new(),
        build_output_digest: String::new(),
    };
    manifest.finalize_digests()?;
    let mut bytes = serde_json::to_vec_pretty(&manifest).map_err(ArtifactError::from)?;
    bytes.push(b'\n');
    fs::write(options.artifact_dir.join("rust-agent-build.json"), bytes)?;
    manifest.verify(&options.artifact_dir)?;
    Ok(manifest)
}

pub fn inspect_development_build(
    artifact_dir: &Path,
    allow_development: bool,
) -> Result<DevelopmentBuildManifest, DevelopmentBuildError> {
    let bytes = fs::read(artifact_dir.join("rust-agent-build.json"))?;
    let manifest: DevelopmentBuildManifest =
        serde_json::from_slice(&bytes).map_err(ArtifactError::from)?;
    if !allow_development && !manifest.deployable {
        return Err(DevelopmentBuildError::Cargo {
            step: "inspect",
            output: "development artifact rejected by production inspection".into(),
        });
    }
    manifest.verify(artifact_dir)?;
    Ok(manifest)
}

fn run_cargo(
    options: &DevelopmentBuildOptions,
    cargo_home: &Path,
    target_dir: &Path,
    step: &'static str,
    args: &[&str],
) -> Result<(), DevelopmentBuildError> {
    let output = Command::new(&options.cargo_path)
        .args(args)
        .arg("--manifest-path")
        .arg(options.composition_path.join("Cargo.toml"))
        .arg("--config")
        .arg(options.composition_path.join(".cargo/config.toml"))
        .current_dir(&options.composition_path)
        .env_clear()
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_TARGET_DIR", target_dir)
        .env("RUSTC", &options.rustc_path)
        .env("RUST_AGENT_BASELINE_LINKER", &options.linker_path)
        .env("PATH", baseline_path(options)?)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(DevelopmentBuildError::Cargo {
            step,
            output: format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        })
    }
}

fn generated_artifact_path(target_dir: &Path, composition: &CompositionManifest) -> PathBuf {
    let name = match composition.build_kind {
        BuildKind::Library => "librust_agent_generated_composition.rlib",
        BuildKind::Wasm => "rust_agent_generated_composition.wasm",
        BuildKind::Bin => "rust_agent_generated_composition",
    };
    target_dir
        .join(&composition.target)
        .join("debug")
        .join(name)
}

fn verify_wasm_root_requirement(
    composition: &CompositionManifest,
) -> Result<(), DevelopmentBuildError> {
    let boundary = composition.host_boundary.as_ref().ok_or_else(|| {
        DevelopmentBuildError::WasmContract("WASM composition has no Host boundary".into())
    })?;
    let root = format!("host-boundary:{boundary}");
    let requirements = composition
        .direct_root_build_requirements
        .get(&root)
        .ok_or_else(|| {
            DevelopmentBuildError::WasmContract(format!(
                "WASM Host boundary direct root `{root}` is missing"
            ))
        })?;
    if !requirements
        .executables
        .contains(WASM_BINDGEN_CLI_LOGICAL_ID)
    {
        return Err(DevelopmentBuildError::WasmContract(format!(
            "WASM Host boundary `{boundary}` does not directly require `{WASM_BINDGEN_CLI_LOGICAL_ID}`"
        )));
    }
    Ok(())
}

fn validate_paths(options: &DevelopmentBuildOptions) -> Result<(), DevelopmentBuildError> {
    for path in [
        &options.composition_path,
        &options.artifact_dir,
        &options.cargo_path,
        &options.rustc_path,
        &options.linker_path,
    ] {
        if !path.is_absolute() {
            return Err(DevelopmentBuildError::NonAbsolutePath(
                path.display().to_string(),
            ));
        }
    }
    if let Some(cache) = &options.registry_cache_path
        && (!cache.is_absolute() || !cache.is_dir())
    {
        return Err(DevelopmentBuildError::NonAbsolutePath(
            cache.display().to_string(),
        ));
    }
    Ok(())
}

fn link_registry_cache(cargo_home: &Path, cache: Option<&Path>) -> Result<(), io::Error> {
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

fn baseline_path(
    options: &DevelopmentBuildOptions,
) -> Result<std::ffi::OsString, DevelopmentBuildError> {
    let directories = [
        &options.cargo_path,
        &options.rustc_path,
        &options.linker_path,
    ]
    .into_iter()
    .map(|path| path.parent().unwrap_or_else(|| Path::new("/")));
    env::join_paths(directories).map_err(|error| DevelopmentBuildError::Cargo {
        step: "environment",
        output: format!("cannot construct controlled tool PATH: {error}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_manifest_never_deserializes_unknown_fields() {
        let json = format!(
            r#"{{
                "schema":2,"composition-hash":"a","profile-name":"p","target":"x",
                "deployable":false,"mode":"development","build-kind":"library",
                "policy-digest":"{}","entry-artifact":"a",
                "artifacts":[{{"path":"a","kind":"rust-library","bytes":1,"digest":"{}"}}],
                "postprocessor":null,"sbom-file":"rust-agent-sbom.cdx.json",
                "sbom-digest":"{}","generated-tests-ran":false,"gates":[],
                "build-manifest-digest":"{}","build-output-digest":"{}","production":true
            }}"#,
            "00".repeat(32),
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(32),
        );
        assert!(serde_json::from_str::<DevelopmentBuildManifest>(&json).is_err());
    }
}
