use std::{collections::BTreeSet, fs, io, path::Path};

use rust_agent_composition::{WASM_BINDGEN_CLI_LOGICAL_ID, WASM_BINDGEN_PROTOCOL_VERSION};
use thiserror::Error;

use crate::{
    BuildArtifactSelector, BuildArtifactTarget, LinuxSandboxAnonymousSocketpair,
    LinuxSandboxCommand, LinuxSandboxError, LinuxSandboxExecutionObservation,
    LinuxSandboxMountKind, LinuxSandboxNetworkPolicy, LinuxSandboxReadOnlyMount,
    LinuxSandboxWritableMount, ProductionArtifactError, ProductionArtifactKind,
    ProductionArtifactRecord, ProductionInputFileRole, TrustedCargoBuildResult,
    VerifiedLinuxSandboxBackend, VerifiedProductionInputs, WasmPostprocessorManifest,
    snapshot_materializer::{AnchoredFileIdentity, AnchoredWritableDirectory},
};

const LOGICAL_WASM_BINDGEN: &str = "/rust-agent/tools/wasm-bindgen-cli";
const LOGICAL_RAW_WASM: &str = "/rust-agent/postprocess/raw.wasm";
const LOGICAL_BUNDLE: &str = "/rust-agent/bundle";
const POSTPROCESS_TIMEOUT_MILLISECONDS: u64 = 2 * 60 * 1000;
const MAX_WASM_OUTPUTS: usize = 4_096;

#[derive(Debug)]
pub struct TrustedWasmPostprocessResult {
    artifacts: Vec<ProductionArtifactRecord>,
    postprocessor: WasmPostprocessorManifest,
    sandbox_observation: LinuxSandboxExecutionObservation,
}

#[derive(Debug, Error)]
pub enum TrustedWasmPostprocessError {
    #[error("trusted WASM postprocessor inputs are invalid: {0}")]
    InvalidInput(&'static str),
    #[error("trusted WASM postprocessor failed with exit code {exit_code}: {diagnostic}")]
    SandboxFailed { exit_code: i32, diagnostic: String },
    #[error("trusted WASM postprocessor sandbox failed: {0}")]
    Sandbox(#[from] LinuxSandboxError),
    #[error("trusted WASM postprocessor artifact verification failed: {0}")]
    Artifact(#[from] ProductionArtifactError),
    #[error("trusted WASM postprocessor input verification failed: {0}")]
    Inputs(#[from] crate::ProductionInputIdentityError),
    #[error("trusted WASM postprocessor snapshot failed: {0}")]
    Snapshot(#[from] crate::SnapshotMaterializationError),
    #[error("trusted WASM postprocessor I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[allow(clippy::too_many_arguments)]
pub fn execute_trusted_wasm_postprocessor(
    backend: &VerifiedLinuxSandboxBackend,
    inputs: &VerifiedProductionInputs,
    build: &TrustedCargoBuildResult,
    selector: &BuildArtifactSelector,
    cargo_lock: &Path,
    bundle_root: &Path,
    artifact_dir: &Path,
    target: &str,
) -> Result<TrustedWasmPostprocessResult, TrustedWasmPostprocessError> {
    if target != "wasm32-unknown-unknown"
        || selector.target != BuildArtifactTarget::Library
        || !empty_absolute_directory(bundle_root)?
        || !empty_absolute_directory(artifact_dir)?
    {
        return Err(TrustedWasmPostprocessError::InvalidInput(
            "target, selector, or output roots",
        ));
    }
    crate::wasm_bundle::verify_protocol_lock(cargo_lock)
        .map_err(|_| TrustedWasmPostprocessError::InvalidInput("WASM Cargo.lock protocol"))?;
    inputs.verify_unchanged()?;
    let tool = inputs
        .request()
        .files
        .iter()
        .find(|file| {
            file.role == ProductionInputFileRole::BuildExecutable
                && file.id == WASM_BINDGEN_CLI_LOGICAL_ID
        })
        .ok_or(TrustedWasmPostprocessError::InvalidInput(
            "missing wasm-bindgen-cli production input",
        ))?;
    let expected_version = format!("wasm-bindgen {WASM_BINDGEN_PROTOCOL_VERSION}");
    if tool
        .version_probe
        .as_ref()
        .map(|probe| probe.expected_first_stdout_line.as_str())
        != Some(expected_version.as_str())
    {
        return Err(TrustedWasmPostprocessError::InvalidInput(
            "wasm-bindgen-cli protocol version",
        ));
    }
    let raw = build
        .artifact_files()
        .iter()
        .filter(|artifact| {
            artifact.selector().package.name == selector.package
                && artifact.selector().crate_kind == crate::CargoCrateKind::Library
                && artifact.selector().compilation_target == target
                && Path::new(artifact.logical_path()).extension()
                    == Some(std::ffi::OsStr::new("wasm"))
        })
        .collect::<Vec<_>>();
    let [raw] = raw.as_slice() else {
        return Err(TrustedWasmPostprocessError::InvalidInput(
            "Cargo output has no unique raw WASM artifact",
        ));
    };
    let raw_relative = raw
        .logical_path()
        .strip_prefix("/rust-agent/target/")
        .ok_or(TrustedWasmPostprocessError::InvalidInput(
            "raw WASM logical path",
        ))?;
    crate::artifact::validate_relative_path(raw_relative)
        .map_err(|_| TrustedWasmPostprocessError::InvalidInput("raw WASM logical path"))?;
    let raw_identity = raw.identity();
    let raw_digest = raw_identity.sha256();
    let raw_mount = LinuxSandboxReadOnlyMount::verified_anchored_file(
        "raw-wasm-input",
        LinuxSandboxMountKind::BuildReadInput,
        raw_identity,
        LOGICAL_RAW_WASM,
        raw_digest,
        false,
    )?;
    let arguments = vec![
        "--target".into(),
        "web".into(),
        "--out-name".into(),
        "rust_agent".into(),
        "--out-dir".into(),
        LOGICAL_BUNDLE.into(),
        LOGICAL_RAW_WASM.into(),
    ];
    let command = LinuxSandboxCommand {
        schema: 3,
        executable: LOGICAL_WASM_BINDGEN.into(),
        arguments: arguments.clone(),
        environment: std::collections::BTreeMap::from([
            ("LANG".into(), "C.UTF-8".into()),
            ("LC_ALL".into(), "C.UTF-8".into()),
            ("SOURCE_DATE_EPOCH".into(), "0".into()),
        ]),
        working_directory: LOGICAL_BUNDLE.into(),
        allowed_executables: vec![LOGICAL_WASM_BINDGEN.into()],
        anonymous_socketpairs: Vec::<LinuxSandboxAnonymousSocketpair>::new(),
        read_only_empty_directories: vec![],
        network: LinuxSandboxNetworkPolicy::Isolated,
        timeout_milliseconds: POSTPROCESS_TIMEOUT_MILLISECONDS,
    };
    let mut mounts = LinuxSandboxReadOnlyMount::production_inputs(inputs)?;
    mounts.push(raw_mount);
    let bundle_mount =
        LinuxSandboxWritableMount::open("wasm-bundle", bundle_root, LOGICAL_BUNDLE, false)?;
    let bundle_output = bundle_mount.retained_directory();
    let execution = backend.run_with_output(&command, mounts, vec![bundle_mount])?;
    if execution.observation().exit_code != 0
        || !execution.stdout().is_empty()
        || !execution.stderr().is_empty()
    {
        return Err(TrustedWasmPostprocessError::SandboxFailed {
            exit_code: execution.observation().exit_code,
            diagnostic: format!(
                "stdout={} stderr={}",
                String::from_utf8_lossy(execution.stdout()),
                String::from_utf8_lossy(execution.stderr())
            ),
        });
    }
    let expected_arguments = std::iter::once(LOGICAL_WASM_BINDGEN.into())
        .chain(arguments)
        .collect::<Vec<_>>();
    let [observed] = execution.observation().executed_commands.as_slice() else {
        return Err(TrustedWasmPostprocessError::InvalidInput(
            "postprocessor execution trace",
        ));
    };
    if observed.executable != LOGICAL_WASM_BINDGEN
        || observed.executable_sha256 != tool.sha256
        || observed.arguments != expected_arguments
        || observed.working_directory != LOGICAL_BUNDLE
    {
        return Err(TrustedWasmPostprocessError::InvalidInput(
            "postprocessor execution identity",
        ));
    }
    inputs.verify_unchanged()?;
    let mut output_sources = preflight_outputs(&bundle_output)?;
    let raw_destination = artifact_dir.join("intermediate/rust_agent_raw.wasm");
    fs::create_dir_all(
        raw_destination
            .parent()
            .expect("raw WASM destination has a parent"),
    )?;
    let mut raw_output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&raw_destination)?;
    let raw_bytes = raw_identity.copy_to(&mut raw_output)?;
    raw_output.sync_all()?;
    let mut artifacts = vec![ProductionArtifactRecord {
        path: "intermediate/rust_agent_raw.wasm".into(),
        kind: ProductionArtifactKind::RawWasmIntermediate,
        target: target.into(),
        bytes: raw_bytes,
        digest: raw_identity.sha256().into(),
    }];
    for (relative, kind, source) in &mut output_sources {
        let destination_relative = format!("bundle/{relative}");
        let destination = artifact_dir.join(&destination_relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        let bytes = source.copy_to(&mut output)?;
        output.sync_all()?;
        artifacts.push(ProductionArtifactRecord {
            path: destination_relative,
            kind: *kind,
            target: target.into(),
            bytes,
            digest: source.sha256().into(),
        });
    }
    artifacts.sort();
    let raw = artifacts
        .iter()
        .find(|artifact| artifact.kind == ProductionArtifactKind::RawWasmIntermediate)
        .ok_or(TrustedWasmPostprocessError::InvalidInput("raw artifact"))?;
    let outputs = artifacts
        .iter()
        .filter(|artifact| artifact.kind != ProductionArtifactKind::RawWasmIntermediate)
        .map(|artifact| artifact.path.clone())
        .collect::<Vec<_>>();
    let required = outputs.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if !required.contains("bundle/rust_agent.js")
        || !required.contains("bundle/rust_agent_bg.wasm")
        || !required.contains("bundle/rust_agent.d.ts")
        || !required.contains("bundle/rust_agent_bg.wasm.d.ts")
    {
        return Err(TrustedWasmPostprocessError::InvalidInput(
            "incomplete wasm-bindgen output",
        ));
    }
    let postprocessor = WasmPostprocessorManifest {
        schema: 1,
        logical_id: WASM_BINDGEN_CLI_LOGICAL_ID.into(),
        protocol_version: WASM_BINDGEN_PROTOCOL_VERSION.into(),
        executable_digest: tool.sha256.clone(),
        executable_version: format!("wasm-bindgen {WASM_BINDGEN_PROTOCOL_VERSION}"),
        invocation: crate::wasm_bundle::normalized_invocation(),
        raw_input_digest: raw.digest.clone(),
        outputs,
    };
    Ok(TrustedWasmPostprocessResult {
        artifacts,
        postprocessor,
        sandbox_observation: execution.observation().clone(),
    })
}

impl TrustedWasmPostprocessResult {
    pub fn artifacts(&self) -> &[ProductionArtifactRecord] {
        &self.artifacts
    }

    pub fn postprocessor(&self) -> &WasmPostprocessorManifest {
        &self.postprocessor
    }

    pub fn sandbox_observation(&self) -> &LinuxSandboxExecutionObservation {
        &self.sandbox_observation
    }
}

fn preflight_outputs(
    root: &AnchoredWritableDirectory,
) -> Result<Vec<(String, ProductionArtifactKind, AnchoredFileIdentity)>, TrustedWasmPostprocessError>
{
    let mut outputs = Vec::new();
    let mut folded = BTreeSet::new();
    let anchored = root.anchor_regular_files()?;
    if anchored.len() > MAX_WASM_OUTPUTS {
        return Err(TrustedWasmPostprocessError::InvalidInput(
            "postprocessor output kind or cardinality",
        ));
    }
    for (relative, source) in anchored {
        crate::artifact::validate_relative_path(&relative)
            .map_err(|_| TrustedWasmPostprocessError::InvalidInput("postprocessor output path"))?;
        if !folded.insert(relative.to_ascii_lowercase()) {
            return Err(TrustedWasmPostprocessError::InvalidInput(
                "postprocessor case-fold collision",
            ));
        }
        let kind = classify_output(&relative)?;
        outputs.push((relative, kind, source));
    }
    if outputs.is_empty() {
        return Err(TrustedWasmPostprocessError::InvalidInput(
            "postprocessor emitted no outputs",
        ));
    }
    Ok(outputs)
}

fn classify_output(relative: &str) -> Result<ProductionArtifactKind, TrustedWasmPostprocessError> {
    match relative {
        "rust_agent.js" => Ok(ProductionArtifactKind::JavaScriptLoader),
        "rust_agent_bg.wasm" => Ok(ProductionArtifactKind::TransformedWasm),
        value if value.ends_with(".d.ts") => Ok(ProductionArtifactKind::TypeScriptDeclaration),
        value
            if value.starts_with("snippets/")
                && Path::new(value).extension() == Some(std::ffi::OsStr::new("js"))
                && Path::new(value).components().count() >= 3 =>
        {
            Ok(ProductionArtifactKind::JavaScriptSnippet)
        }
        _ => Err(TrustedWasmPostprocessError::InvalidInput(
            "unsupported postprocessor output",
        )),
    }
}

fn empty_absolute_directory(path: &Path) -> Result<bool, io::Error> {
    Ok(path.is_absolute()
        && path.is_dir()
        && !fs::symlink_metadata(path)?.file_type().is_symlink()
        && fs::read_dir(path)?.next().is_none())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_wasm_classifier_is_closed() {
        assert_eq!(
            classify_output("rust_agent.js").unwrap(),
            ProductionArtifactKind::JavaScriptLoader
        );
        assert_eq!(
            classify_output("snippets/crate/hash/file.js").unwrap(),
            ProductionArtifactKind::JavaScriptSnippet
        );
        assert!(classify_output("package.json").is_err());
        assert!(classify_output("../escape.js").is_err());
    }
}
