//! Locked development-only build executor for Phase 1A.

mod cargo_unit_graph;
mod host_feature;
mod integration;
mod policy;

use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
};

pub use cargo_unit_graph::{
    CargoCompilationKind, CargoCompileMode, CargoCrateKind, CargoDependencyKind,
    CargoPackageIdentity, CargoPackageSource, CargoTargetEvaluationDomain, CargoUnit,
    CargoUnitEdge, CargoUnitGraphError, CargoUnitGraphPlannerIdentity, CargoUnitSelector,
    HostCargoUnitGraph, NormalizedCargoUnit, NormalizedHostCargoUnitGraph,
};
pub use host_feature::{
    FeatureAccountingMode, FeatureDelta, FeatureSemanticsEvidence, HostFeaturePolicyEntry,
    HostFeaturePolicyError, HostFeatureUnionPolicy, NormalizedHostFeaturePolicy,
};
pub use integration::{IntegrationError, emit_integration, verify_integration};
pub use policy::{
    BuildEnvironment, BuildExecutable, BuildExecutionPolicy, BuildPolicyError, BuildReadInput,
};
use rust_agent_composition::{CompositionManifest, verify_composition};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct DevelopmentBuildOptions {
    pub composition_path: PathBuf,
    pub artifact_dir: PathBuf,
    pub cargo_path: PathBuf,
    pub rustc_path: PathBuf,
    pub linker_path: PathBuf,
    pub policy: BuildExecutionPolicy,
    pub run_generated_tests: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentBuildManifest {
    pub schema: u32,
    #[serde(rename = "composition-hash")]
    pub composition_hash: String,
    pub target: String,
    pub deployable: bool,
    #[serde(rename = "build-kind")]
    pub build_kind: String,
    #[serde(rename = "policy-digest")]
    pub policy_digest: String,
    #[serde(rename = "artifact-file")]
    pub artifact_file: String,
    #[serde(rename = "artifact-digest")]
    pub artifact_digest: String,
    #[serde(rename = "generated-tests-ran")]
    pub generated_tests_ran: bool,
    pub gates: Vec<String>,
}

#[derive(Debug, Error)]
pub enum DevelopmentBuildError {
    #[error("build inputs and tools must be absolute paths: {0}")]
    NonAbsolutePath(String),
    #[error("composition verification failed: {0}")]
    Composition(#[from] rust_agent_composition::ComposeError),
    #[error("build policy is invalid: {0}")]
    Policy(#[from] BuildPolicyError),
    #[error("development Cargo {step} failed: {output}")]
    Cargo { step: &'static str, output: String },
    #[error("expected generated artifact is missing: {0}")]
    MissingArtifact(String),
    #[error("artifact output directory is not empty: {0}")]
    ArtifactDirectoryNotEmpty(String),
    #[error("I/O failed during development build: {0}")]
    Io(#[from] io::Error),
    #[error("build manifest serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

pub fn development_build(
    options: &DevelopmentBuildOptions,
) -> Result<DevelopmentBuildManifest, DevelopmentBuildError> {
    validate_paths(options)?;
    let composition = verify_composition(&options.composition_path)?;
    let normalized_policy = options.policy.normalize()?;
    normalized_policy.authorize(&composition.build_requirements)?;

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
    fs::create_dir(&target_dir)?;

    if options.run_generated_tests {
        run_cargo(
            options,
            &cargo_home,
            &target_dir,
            "test",
            &["test", "--locked", "--offline"],
        )?;
    }
    run_cargo(
        options,
        &cargo_home,
        &target_dir,
        "build",
        &["build", "--locked", "--offline"],
    )?;

    let artifact_source = generated_library_path(&target_dir, &composition);
    if !artifact_source.is_file() {
        return Err(DevelopmentBuildError::MissingArtifact(
            artifact_source.display().to_string(),
        ));
    }
    let artifact_name = artifact_source
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            DevelopmentBuildError::MissingArtifact(artifact_source.display().to_string())
        })?
        .to_owned();
    let artifact_destination = options.artifact_dir.join(&artifact_name);
    fs::copy(&artifact_source, &artifact_destination)?;
    let artifact_digest = sha256_file(&artifact_destination)?;
    let policy_digest = normalized_policy.digest()?;
    let manifest = DevelopmentBuildManifest {
        schema: 1,
        composition_hash: composition.composition_hash,
        target: composition.target,
        deployable: false,
        build_kind: "development".into(),
        policy_digest,
        artifact_file: artifact_name,
        artifact_digest,
        generated_tests_ran: options.run_generated_tests,
        gates: vec![
            "composition-identity-verified".into(),
            "build-requirements-authorized".into(),
            "isolated-cargo-home".into(),
            "locked-offline-cargo".into(),
            "generated-factory-typecheck".into(),
        ],
    };
    let mut bytes = serde_json::to_vec_pretty(&manifest)?;
    bytes.push(b'\n');
    fs::write(options.artifact_dir.join("rust-agent-build.json"), bytes)?;
    Ok(manifest)
}

pub fn inspect_development_build(
    artifact_dir: &Path,
    allow_development: bool,
) -> Result<DevelopmentBuildManifest, DevelopmentBuildError> {
    let bytes = fs::read(artifact_dir.join("rust-agent-build.json"))?;
    let manifest: DevelopmentBuildManifest = serde_json::from_slice(&bytes)?;
    if !allow_development && !manifest.deployable {
        return Err(DevelopmentBuildError::Cargo {
            step: "inspect",
            output: "development artifact rejected by production inspection".into(),
        });
    }
    let artifact = artifact_dir.join(&manifest.artifact_file);
    if sha256_file(&artifact)? != manifest.artifact_digest {
        return Err(DevelopmentBuildError::Cargo {
            step: "inspect",
            output: "artifact digest mismatch".into(),
        });
    }
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

fn generated_library_path(target_dir: &Path, composition: &CompositionManifest) -> PathBuf {
    let name = "librust_agent_generated_composition.rlib";
    target_dir
        .join(&composition.target)
        .join("debug")
        .join(name)
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

fn sha256_file(path: &Path) -> Result<String, io::Error> {
    Ok(hex::encode(Sha256::digest(fs::read(path)?)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_manifest_never_deserializes_unknown_fields() {
        let json = r#"{
            "schema":1,"composition-hash":"a","target":"x","deployable":false,
            "build-kind":"development","policy-digest":"p","artifact-file":"a",
            "artifact-digest":"d","generated-tests-ran":false,"gates":[],"production":true
        }"#;
        assert!(serde_json::from_str::<DevelopmentBuildManifest>(json).is_err());
    }
}
