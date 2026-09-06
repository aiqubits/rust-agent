use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    CargoCompilationKind, CargoCompileMode, CargoCrateKind, CargoPlannerError, CargoUnitGraphError,
    HostBuildClosureContent, HostBuildClosureItemRole, LinuxSandboxAnonymousSocketpair,
    LinuxSandboxCommand, LinuxSandboxError, LinuxSandboxExecutionObservation,
    LinuxSandboxNetworkPolicy, LinuxSandboxReadOnlyMount, LinuxSandboxWritableMount,
    NormalizedCargoPlannerRequest, NormalizedHostBuildInputClosure, NormalizedHostCargoUnitGraph,
    NormalizedProductionBuildPolicy, ProductionBuildPolicyError, ProductionCargoInvocationIdentity,
    ProductionInputFileRole, ProductionInputIdentityError, ProductionInputPreflightScope,
    VerifiedCargoFetchCache, VerifiedHostClosureSnapshot, VerifiedLinuxSandboxBackend,
    VerifiedProductionInputs, production_policy::cargo_driver_environment,
    snapshot_materializer::AnchoredFileIdentity,
};

const LOGICAL_CARGO: &str = "/rust-agent/toolchain/bin/cargo";
const LOGICAL_RUSTC: &str = "/rust-agent/toolchain/bin/rustc";
const LOGICAL_TARGET: &str = "/rust-agent/target";
const LOGICAL_TEMP: &str = "/rust-agent/tmp";
const BUILD_SYSROOT_FLAG: &str = "--sysroot=/rust-agent/toolchain";
const HOST_LINKER_FEATURE_FLAG: &str = "-Clinker-features=-lld";
const BUILD_TIMEOUT_MILLISECONDS: u64 = 20 * 60 * 1000;
const MAXIMUM_STDERR_DIAGNOSTIC_BYTES: usize = 32 * 1024;
const MAXIMUM_STDOUT_DIAGNOSTIC_BYTES: usize = 4 * 1024;
const MAXIMUM_VERIFICATION_DIAGNOSTIC_BYTES: usize = 768;
const MAXIMUM_COMMAND_DIAGNOSTIC_COUNT: usize = 32;

#[derive(Debug)]
pub struct TrustedCargoBuildResult {
    sandbox_observation: LinuxSandboxExecutionObservation,
    observed_graph: NormalizedHostCargoUnitGraph,
    cargo_messages_sha256: String,
    artifact_files: Vec<TrustedCargoArtifactFile>,
    cargo_invocation: ProductionCargoInvocationIdentity,
}

#[derive(Clone, Debug)]
pub struct TrustedCargoArtifactFile {
    logical_path: String,
    selector: crate::CargoUnitSelector,
    identity: AnchoredFileIdentity,
}

#[derive(Debug, Error)]
pub enum TrustedCargoBuildError {
    #[error("trusted Cargo build inputs do not match the planned graph")]
    InputMismatch,
    #[error("trusted Cargo build target/temp roots must be distinct, empty absolute directories")]
    InvalidWritableRoot,
    #[error("trusted Cargo build failed with exit code {exit_code}: {diagnostic}")]
    SandboxFailed { exit_code: i32, diagnostic: String },
    #[error("trusted Cargo build command trace does not exactly cover the planned units")]
    UnitObservationMismatch,
    #[error(
        "trusted Cargo build command trace does not exactly cover the planned units: {diagnostic}"
    )]
    UnitObservationOutput { diagnostic: String },
    #[error("trusted Cargo build emitted malformed or incomplete JSON messages")]
    InvalidCargoMessages,
    #[error("trusted Cargo build emitted malformed or incomplete JSON messages: {diagnostic}")]
    InvalidCargoMessageOutput { diagnostic: String },
    #[error("trusted Cargo build sandbox failed: {0}")]
    Sandbox(#[from] LinuxSandboxError),
    #[error("trusted Cargo build production input verification failed: {0}")]
    ProductionInputs(#[from] ProductionInputIdentityError),
    #[error("trusted Cargo build policy verification failed: {0}")]
    Policy(#[from] ProductionBuildPolicyError),
    #[error("trusted Cargo build planner request verification failed: {0}")]
    Planner(#[from] CargoPlannerError),
    #[error("trusted Cargo build planned/observed graph differs: {0}")]
    Graph(#[from] CargoUnitGraphError),
    #[error("trusted Cargo build snapshot verification failed: {0}")]
    Snapshot(#[from] crate::SnapshotMaterializationError),
    #[error("trusted Cargo build cache verification failed: {0}")]
    Cache(#[from] crate::CargoFetchCacheError),
    #[error("trusted Cargo build I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

impl TrustedCargoBuildResult {
    pub fn sandbox_observation(&self) -> &LinuxSandboxExecutionObservation {
        &self.sandbox_observation
    }

    pub fn observed_graph(&self) -> &NormalizedHostCargoUnitGraph {
        &self.observed_graph
    }

    pub fn cargo_messages_sha256(&self) -> &str {
        &self.cargo_messages_sha256
    }

    pub fn artifact_files(&self) -> &[TrustedCargoArtifactFile] {
        &self.artifact_files
    }

    pub fn cargo_invocation(&self) -> &ProductionCargoInvocationIdentity {
        &self.cargo_invocation
    }
}

impl TrustedCargoArtifactFile {
    pub fn logical_path(&self) -> &str {
        &self.logical_path
    }

    pub fn selector(&self) -> &crate::CargoUnitSelector {
        &self.selector
    }

    pub(crate) fn identity(&self) -> &AnchoredFileIdentity {
        &self.identity
    }
}

#[allow(clippy::too_many_arguments)]
pub fn execute_trusted_cargo_build(
    backend: &VerifiedLinuxSandboxBackend,
    policy: &NormalizedProductionBuildPolicy,
    request: &NormalizedCargoPlannerRequest,
    host_closure: &NormalizedHostBuildInputClosure,
    closure_snapshot: &VerifiedHostClosureSnapshot,
    cache: &VerifiedCargoFetchCache,
    production_inputs: &VerifiedProductionInputs,
    planned_graph: &NormalizedHostCargoUnitGraph,
    target_root: &Path,
    temp_root: &Path,
) -> Result<TrustedCargoBuildResult, TrustedCargoBuildError> {
    verify_inputs(
        policy,
        request,
        host_closure,
        closure_snapshot,
        cache,
        production_inputs,
        planned_graph,
    )?;
    verify_empty_root(target_root)?;
    verify_empty_root(temp_root)?;
    if target_root == temp_root {
        return Err(TrustedCargoBuildError::InvalidWritableRoot);
    }

    let mut arguments = request.invocation().arguments.clone();
    if arguments.len() < 3
        || arguments[arguments.len() - 3..] != ["--unit-graph", "-Z", "unstable-options"]
    {
        return Err(TrustedCargoBuildError::InputMismatch);
    }
    arguments.truncate(arguments.len() - 3);
    arguments.extend(["--jobs".into(), "1".into()]);
    arguments.push("--message-format=json-render-diagnostics".into());

    let enforcement = policy.enforcement_identity(
        host_closure.build_requirements(),
        host_closure.build_context(),
    )?;
    let mut environment = production_build_environment(&request.invocation().environment)?;
    for selected in &enforcement.environment {
        if environment
            .insert(selected.variable.clone(), selected.value.clone())
            .is_some()
        {
            return Err(TrustedCargoBuildError::InputMismatch);
        }
    }
    let mut allowed_executables = vec![LOGICAL_CARGO.into(), LOGICAL_RUSTC.into()];
    allowed_executables.extend(
        enforcement
            .executables
            .iter()
            .map(|executable| executable.logical_mount.clone()),
    );
    allowed_executables.extend(
        enforcement
            .target_linker
            .iter()
            .map(|linker| linker.executable.logical_mount.clone()),
    );
    allowed_executables.sort();

    let command = LinuxSandboxCommand {
        schema: 3,
        executable: LOGICAL_CARGO.into(),
        arguments: arguments.clone(),
        environment,
        working_directory: request.invocation().working_directory.clone(),
        allowed_executables,
        anonymous_socketpairs: vec![
            LinuxSandboxAnonymousSocketpair::StreamWakeup,
            LinuxSandboxAnonymousSocketpair::RustSpawnError,
        ],
        read_only_empty_directories: vec![],
        network: LinuxSandboxNetworkPolicy::Isolated,
        timeout_milliseconds: BUILD_TIMEOUT_MILLISECONDS,
    };
    let cargo_invocation = ProductionCargoInvocationIdentity {
        schema: 1,
        arguments: command.arguments.clone(),
        environment: command.environment.clone(),
        working_directory: command.working_directory.clone(),
    };
    let mut mounts = vec![
        LinuxSandboxReadOnlyMount::host_closure(closure_snapshot)?,
        LinuxSandboxReadOnlyMount::cargo_cache(cache)?,
    ];
    mounts.extend(LinuxSandboxReadOnlyMount::production_inputs(
        production_inputs,
    )?);
    let target_mount =
        LinuxSandboxWritableMount::open("cargo-target", target_root, LOGICAL_TARGET, true)?;
    let target_output = target_mount.retained_directory();
    let temp_mount = LinuxSandboxWritableMount::open("cargo-temp", temp_root, LOGICAL_TEMP, false)?;
    let execution = backend.run_with_output(&command, mounts, vec![target_mount, temp_mount])?;
    if execution.observation().exit_code != 0 {
        let executed_commands = &execution.observation().executed_commands;
        let command_tail = &executed_commands[executed_commands
            .len()
            .saturating_sub(MAXIMUM_COMMAND_DIAGNOSTIC_COUNT)..];
        return Err(TrustedCargoBuildError::SandboxFailed {
            exit_code: execution.observation().exit_code,
            diagnostic: format!(
                "stderr={} stdout-tail={} execution-count={} executions-tail={command_tail:?}",
                diagnostic_tail(execution.stderr(), MAXIMUM_STDERR_DIAGNOSTIC_BYTES),
                diagnostic_tail(execution.stdout(), MAXIMUM_STDOUT_DIAGNOSTIC_BYTES),
                executed_commands.len(),
            ),
        });
    }
    let cargo_messages = verify_cargo_messages_in_closure(
        execution.stdout(),
        planned_graph,
        &cache.manifest().packages,
        Some(host_closure),
    )
    .map_err(|error| match error {
        TrustedCargoBuildError::InvalidCargoMessages => {
            TrustedCargoBuildError::InvalidCargoMessageOutput {
                diagnostic: cargo_message_verification_diagnostic(
                    execution.stdout(),
                    planned_graph,
                ),
            }
        }
        other => other,
    })?;
    let unit_observation_policy = BuildUnitObservationPolicy {
        executable_digests: enforcement
            .executables
            .iter()
            .map(|item| (item.logical_mount.as_str(), item.sha256.as_str()))
            .collect(),
        host_linker_selected: enforcement.host_linker.is_some(),
        target_linker: enforcement.target_linker.as_ref().map(|linker| {
            (
                linker.executable.logical_mount.as_str(),
                linker.executable.sha256.as_str(),
            )
        }),
    };
    observe_units(
        request,
        production_inputs,
        planned_graph,
        execution.observation(),
        &arguments,
        &unit_observation_policy,
        &cargo_messages,
    )
    .map_err(|error| match error {
        TrustedCargoBuildError::UnitObservationMismatch => {
            TrustedCargoBuildError::UnitObservationOutput {
                diagnostic: unit_observation_diagnostic(execution.observation(), planned_graph),
            }
        }
        other => other,
    })?;
    verify_inputs(
        policy,
        request,
        host_closure,
        closure_snapshot,
        cache,
        production_inputs,
        planned_graph,
    )?;
    let artifact_files = cargo_messages
        .artifact_files
        .into_iter()
        .map(|(logical_path, selector)| {
            let relative = logical_path
                .strip_prefix("/rust-agent/target/")
                .ok_or(TrustedCargoBuildError::InvalidCargoMessages)?;
            let identity = target_output.anchor_file(relative)?;
            Ok(TrustedCargoArtifactFile {
                logical_path,
                selector,
                identity,
            })
        })
        .collect::<Result<Vec<_>, TrustedCargoBuildError>>()?;
    Ok(TrustedCargoBuildResult {
        sandbox_observation: execution.observation().clone(),
        observed_graph: planned_graph.clone(),
        cargo_messages_sha256: hex::encode(Sha256::digest(execution.stdout())),
        artifact_files,
        cargo_invocation,
    })
}

fn production_build_environment(
    planner_environment: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, TrustedCargoBuildError> {
    let host_linker_selected = planner_environment.contains_key("COMPILER_PATH");
    if planner_environment != &cargo_driver_environment(host_linker_selected, false) {
        return Err(TrustedCargoBuildError::InputMismatch);
    }
    Ok(cargo_driver_environment(host_linker_selected, true))
}

#[allow(clippy::too_many_arguments)]
fn verify_inputs(
    policy: &NormalizedProductionBuildPolicy,
    request: &NormalizedCargoPlannerRequest,
    host_closure: &NormalizedHostBuildInputClosure,
    closure_snapshot: &VerifiedHostClosureSnapshot,
    cache: &VerifiedCargoFetchCache,
    inputs: &VerifiedProductionInputs,
    planned_graph: &NormalizedHostCargoUnitGraph,
) -> Result<(), TrustedCargoBuildError> {
    request.verify()?;
    if request.host_build_input_closure_digest() != host_closure.digest()
        || closure_snapshot.manifest().host_build_input_closure_digest != host_closure.digest()
        || inputs.request().scope != ProductionInputPreflightScope::Build
        || inputs.request().host_build_input_closure_digest.as_deref()
            != Some(host_closure.digest())
        || inputs.request().build_execution_policy_digest != policy.full_digest()
        || request.build_execution_policy_digest() != policy.full_digest()
        || planned_graph.planner() != request.planner()
        || planned_graph.build_triple() != request.build_triple()
        || planned_graph.composition_target() != request.target()
        || planned_graph.profile() != request.profile()
    {
        return Err(TrustedCargoBuildError::InputMismatch);
    }
    policy.enforcement_identity(
        host_closure.build_requirements(),
        host_closure.build_context(),
    )?;
    closure_snapshot.verify_unchanged()?;
    cache.verify_unchanged()?;
    Ok(())
}

fn verify_empty_root(path: &Path) -> Result<(), TrustedCargoBuildError> {
    if !path.is_absolute()
        || !path.is_dir()
        || fs::symlink_metadata(path)?.file_type().is_symlink()
        || fs::read_dir(path)?.next().is_some()
    {
        Err(TrustedCargoBuildError::InvalidWritableRoot)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct CargoMessageObservation {
    artifact_files: BTreeMap<String, crate::CargoUnitSelector>,
    build_script_executables: BTreeMap<crate::CargoUnitSelector, String>,
}

struct BuildUnitObservationPolicy<'a> {
    executable_digests: BTreeMap<&'a str, &'a str>,
    host_linker_selected: bool,
    target_linker: Option<(&'a str, &'a str)>,
}

struct CargoMessageVerificationContext<'a> {
    planned: &'a NormalizedHostCargoUnitGraph,
    cache_packages: &'a [crate::CargoFetchCachePackageLocation],
    host_closure: Option<&'a NormalizedHostBuildInputClosure>,
}

#[cfg(test)]
fn verify_cargo_messages(
    stdout: &[u8],
    planned: &NormalizedHostCargoUnitGraph,
    cache_packages: &[crate::CargoFetchCachePackageLocation],
) -> Result<CargoMessageObservation, TrustedCargoBuildError> {
    verify_cargo_messages_in_closure(stdout, planned, cache_packages, None)
}

fn verify_cargo_messages_in_closure(
    stdout: &[u8],
    planned: &NormalizedHostCargoUnitGraph,
    cache_packages: &[crate::CargoFetchCachePackageLocation],
    host_closure: Option<&NormalizedHostBuildInputClosure>,
) -> Result<CargoMessageObservation, TrustedCargoBuildError> {
    if stdout.is_empty() {
        return Err(TrustedCargoBuildError::InvalidCargoMessages);
    }
    let mut finished = false;
    let mut artifacts = BTreeSet::new();
    let mut build_scripts = BTreeSet::new();
    let mut filenames = BTreeSet::new();
    let mut artifact_files = BTreeMap::new();
    let mut artifact_executables = BTreeMap::new();
    let context = CargoMessageVerificationContext {
        planned,
        cache_packages,
        host_closure,
    };
    for (message_index, line) in stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        let value: serde_json::Value = serde_json::from_slice(line)
            .map_err(|_| TrustedCargoBuildError::InvalidCargoMessages)?;
        let object = value
            .as_object()
            .ok_or(TrustedCargoBuildError::InvalidCargoMessages)?;
        let reason = object
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .ok_or(TrustedCargoBuildError::InvalidCargoMessages)?;
        if finished {
            return Err(TrustedCargoBuildError::InvalidCargoMessages);
        }
        let verification = match reason {
            "compiler-artifact" => verify_compiler_artifact(
                object,
                &context,
                &mut artifacts,
                &mut filenames,
                &mut artifact_files,
                &mut artifact_executables,
            ),
            "compiler-message" => verify_compiler_message(object, &context),
            "build-script-executed" => {
                verify_build_script_message(object, planned, &mut build_scripts)
            }
            "build-finished" => {
                let result = require_exact_keys(object, &["reason", "success"]);
                if result.is_ok()
                    && object.get("success").and_then(serde_json::Value::as_bool) == Some(true)
                {
                    finished = true;
                    Ok(())
                } else {
                    Err(TrustedCargoBuildError::InvalidCargoMessages)
                }
            }
            _ => Err(TrustedCargoBuildError::InvalidCargoMessages),
        };
        if let Err(error) = verification {
            if host_closure.is_some()
                && matches!(error, TrustedCargoBuildError::InvalidCargoMessages)
            {
                return Err(TrustedCargoBuildError::InvalidCargoMessageOutput {
                    diagnostic: format!(
                        "stage=message message-index={message_index} reason={reason} message={}",
                        diagnostic_head_and_tail(line, MAXIMUM_VERIFICATION_DIAGNOSTIC_BYTES),
                    ),
                });
            }
            return Err(error);
        }
    }
    let expected_artifacts = planned
        .nodes()
        .keys()
        .filter(|selector| selector.compile_mode != CargoCompileMode::RunCustomBuild)
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_build_scripts = planned
        .nodes()
        .keys()
        .filter(|selector| selector.compile_mode == CargoCompileMode::RunCustomBuild)
        .cloned()
        .collect::<BTreeSet<_>>();
    if !finished || artifacts != expected_artifacts || build_scripts != expected_build_scripts {
        if host_closure.is_some() {
            let missing_artifacts = expected_artifacts
                .difference(&artifacts)
                .collect::<Vec<_>>();
            let unexpected_artifacts = artifacts
                .difference(&expected_artifacts)
                .collect::<Vec<_>>();
            let missing_scripts = expected_build_scripts
                .difference(&build_scripts)
                .collect::<Vec<_>>();
            let unexpected_scripts = build_scripts
                .difference(&expected_build_scripts)
                .collect::<Vec<_>>();
            return Err(TrustedCargoBuildError::InvalidCargoMessageOutput {
                diagnostic: diagnostic_head_and_tail(
                    format!(
                        "stage=stream-coverage finished={finished} missing-artifacts={missing_artifacts:?} unexpected-artifacts={unexpected_artifacts:?} missing-scripts={missing_scripts:?} unexpected-scripts={unexpected_scripts:?}"
                    )
                    .as_bytes(),
                    MAXIMUM_VERIFICATION_DIAGNOSTIC_BYTES,
                ),
            });
        }
        return Err(TrustedCargoBuildError::InvalidCargoMessages);
    }
    let mut build_script_executables = BTreeMap::new();
    for run_selector in &expected_build_scripts {
        let matches = artifact_executables
            .iter()
            .filter(|(selector, _)| {
                selector.package == run_selector.package
                    && selector.target_name == run_selector.target_name
                    && selector.crate_kind == CargoCrateKind::CustomBuild
                    && selector.compile_mode != CargoCompileMode::RunCustomBuild
            })
            .collect::<Vec<_>>();
        let [(_, executable)] = matches.as_slice() else {
            if host_closure.is_some() {
                return Err(TrustedCargoBuildError::InvalidCargoMessageOutput {
                    diagnostic: format!(
                        "stage=build-script-executable selector={run_selector:?} matches={}",
                        matches.len()
                    ),
                });
            }
            return Err(TrustedCargoBuildError::InvalidCargoMessages);
        };
        build_script_executables.insert(run_selector.clone(), (*executable).clone());
    }
    Ok(CargoMessageObservation {
        artifact_files,
        build_script_executables,
    })
}

fn verify_compiler_artifact(
    object: &serde_json::Map<String, serde_json::Value>,
    context: &CargoMessageVerificationContext<'_>,
    observed: &mut BTreeSet<crate::CargoUnitSelector>,
    observed_filenames: &mut BTreeSet<String>,
    artifact_files: &mut BTreeMap<String, crate::CargoUnitSelector>,
    artifact_executables: &mut BTreeMap<crate::CargoUnitSelector, String>,
) -> Result<(), TrustedCargoBuildError> {
    require_exact_keys(
        object,
        &[
            "reason",
            "package_id",
            "manifest_path",
            "target",
            "profile",
            "features",
            "filenames",
            "executable",
            "fresh",
        ],
    )?;
    if object.get("fresh").and_then(serde_json::Value::as_bool) != Some(false) {
        return Err(TrustedCargoBuildError::InvalidCargoMessages);
    }
    let (selector, source_roots) = match_message_selector(object, context)?;
    if !observed.insert(selector.clone()) {
        return Err(TrustedCargoBuildError::InvalidCargoMessages);
    }
    let values = object
        .get("filenames")
        .and_then(serde_json::Value::as_array)
        .ok_or(TrustedCargoBuildError::InvalidCargoMessages)?;
    if values.is_empty() || values.len() > 64 {
        return Err(TrustedCargoBuildError::InvalidCargoMessages);
    }
    for value in values {
        let path = value
            .as_str()
            .ok_or(TrustedCargoBuildError::InvalidCargoMessages)?;
        if !logical_target_path(path) || !observed_filenames.insert(path.into()) {
            return Err(TrustedCargoBuildError::InvalidCargoMessages);
        }
        artifact_files.insert(path.into(), selector.clone());
    }
    if selector.crate_kind == CargoCrateKind::CustomBuild {
        let matches = values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .filter(|path| {
                Path::new(path)
                    .file_name()
                    .is_some_and(|name| name == "build-script-build")
            })
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let [executable] = matches.as_slice() else {
            return Err(TrustedCargoBuildError::InvalidCargoMessages);
        };
        artifact_executables.insert(selector.clone(), executable.clone());
    }
    match object.get("executable") {
        Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::String(path)) if logical_target_path(path) => {
            if !observed_filenames.contains(path)
                || artifact_executables
                    .insert(selector.clone(), path.clone())
                    .is_some()
            {
                return Err(TrustedCargoBuildError::InvalidCargoMessages);
            }
        }
        _ => return Err(TrustedCargoBuildError::InvalidCargoMessages),
    }
    verify_message_target(object.get("target"), &selector, &source_roots)?;
    verify_message_profile(object.get("profile"))
}

fn verify_compiler_message(
    object: &serde_json::Map<String, serde_json::Value>,
    context: &CargoMessageVerificationContext<'_>,
) -> Result<(), TrustedCargoBuildError> {
    require_exact_keys(
        object,
        &["reason", "package_id", "manifest_path", "target", "message"],
    )?;
    let package_id = message_text(object, "package_id")?;
    let manifest_path = message_text(object, "manifest_path")?;
    let target = object
        .get("target")
        .and_then(serde_json::Value::as_object)
        .ok_or(TrustedCargoBuildError::InvalidCargoMessages)?;
    let target_name = message_text(target, "name")?;
    let matches = context
        .planned
        .nodes()
        .keys()
        .filter(|selector| {
            selector.compile_mode != CargoCompileMode::RunCustomBuild
                && selector.target_name == target_name
                && package_id_matches(package_id, &selector.package)
        })
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Err(TrustedCargoBuildError::InvalidCargoMessages);
    }
    let matches_planned_target = matches.iter().any(|selector| {
        let Ok(package_root) = verified_package_root(
            package_id,
            manifest_path,
            &selector.package,
            context.cache_packages,
        ) else {
            return false;
        };
        let Ok(source_roots) =
            verified_package_source_roots(&package_root, &selector.package, context.host_closure)
        else {
            return false;
        };
        verify_message_target(object.get("target"), selector, &source_roots).is_ok()
    });
    if !matches_planned_target {
        return Err(TrustedCargoBuildError::InvalidCargoMessages);
    }
    object
        .get("message")
        .filter(|message| message.is_object())
        .map(|_| ())
        .ok_or(TrustedCargoBuildError::InvalidCargoMessages)
}

fn verify_build_script_message(
    object: &serde_json::Map<String, serde_json::Value>,
    planned: &NormalizedHostCargoUnitGraph,
    observed: &mut BTreeSet<crate::CargoUnitSelector>,
) -> Result<(), TrustedCargoBuildError> {
    require_exact_keys(
        object,
        &[
            "reason",
            "package_id",
            "linked_libs",
            "linked_paths",
            "cfgs",
            "env",
            "out_dir",
        ],
    )?;
    for name in ["linked_libs", "cfgs"] {
        require_bounded_strings(object.get(name), 4096, |_| true)?;
    }
    require_bounded_strings(object.get("linked_paths"), 4096, |value| {
        value
            .split_once('=')
            .is_some_and(|(_, path)| logical_target_path(path))
    })?;
    let environment = object
        .get("env")
        .and_then(serde_json::Value::as_array)
        .ok_or(TrustedCargoBuildError::InvalidCargoMessages)?;
    if environment.len() > 4096
        || environment.iter().any(|entry| {
            entry
                .as_array()
                .is_none_or(|pair| pair.len() != 2 || pair.iter().any(|value| !value.is_string()))
        })
    {
        return Err(TrustedCargoBuildError::InvalidCargoMessages);
    }
    let out_dir = object
        .get("out_dir")
        .and_then(serde_json::Value::as_str)
        .ok_or(TrustedCargoBuildError::InvalidCargoMessages)?;
    if !logical_target_path(out_dir) {
        return Err(TrustedCargoBuildError::InvalidCargoMessages);
    }
    let package_id = message_text(object, "package_id")?;
    let matches = planned
        .nodes()
        .keys()
        .filter(|selector| {
            selector.compile_mode == CargoCompileMode::RunCustomBuild
                && package_id_matches(package_id, &selector.package)
                && build_script_out_dir_matches_selector(out_dir, selector, planned)
        })
        .cloned()
        .collect::<Vec<_>>();
    let [selector] = matches.as_slice() else {
        return Err(TrustedCargoBuildError::InvalidCargoMessages);
    };
    if !observed.insert(selector.clone()) {
        return Err(TrustedCargoBuildError::InvalidCargoMessages);
    }
    Ok(())
}

fn build_script_out_dir_matches_selector(
    out_dir: &str,
    selector: &crate::CargoUnitSelector,
    planned: &NormalizedHostCargoUnitGraph,
) -> bool {
    let profile = if selector.profile == "dev" {
        "debug"
    } else {
        &selector.profile
    };
    if !canonical_path_component(profile) {
        return false;
    }
    let root = match selector.cargo_target_context {
        crate::CargoUnitTargetContext::BuildHost => format!("{LOGICAL_TARGET}/{profile}"),
        crate::CargoUnitTargetContext::CompositionTarget => {
            let Some(target) = Path::new(planned.composition_target())
                .file_stem()
                .and_then(|target| target.to_str())
                .filter(|target| canonical_path_component(target))
            else {
                return false;
            };
            format!("{LOGICAL_TARGET}/{target}/{profile}")
        }
    };
    logical_descendant(out_dir, &root)
}

fn match_message_selector(
    object: &serde_json::Map<String, serde_json::Value>,
    context: &CargoMessageVerificationContext<'_>,
) -> Result<(crate::CargoUnitSelector, Vec<String>), TrustedCargoBuildError> {
    let package_id = message_text(object, "package_id")?;
    let manifest_path = message_text(object, "manifest_path")?;
    let target = object
        .get("target")
        .and_then(serde_json::Value::as_object)
        .ok_or(TrustedCargoBuildError::InvalidCargoMessages)?;
    let target_name = message_text(target, "name")?;
    let features = object
        .get("features")
        .and_then(serde_json::Value::as_array)
        .ok_or(TrustedCargoBuildError::InvalidCargoMessages)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(TrustedCargoBuildError::InvalidCargoMessages)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let matches = context
        .planned
        .nodes()
        .iter()
        .filter(|(selector, unit)| {
            selector.compile_mode != CargoCompileMode::RunCustomBuild
                && selector.target_name == target_name
                && package_id_matches(package_id, &selector.package)
                && unit.features == features
                && message_artifact_paths_match_selector(object, selector)
        })
        .map(|(selector, _)| selector.clone())
        .collect::<Vec<_>>();
    let [selector] = matches.as_slice() else {
        return Err(TrustedCargoBuildError::InvalidCargoMessages);
    };
    let package_root = verified_package_root(
        package_id,
        manifest_path,
        &selector.package,
        context.cache_packages,
    )?;
    let source_roots =
        verified_package_source_roots(&package_root, &selector.package, context.host_closure)?;
    Ok((selector.clone(), source_roots))
}

fn message_artifact_paths_match_selector(
    object: &serde_json::Map<String, serde_json::Value>,
    selector: &crate::CargoUnitSelector,
) -> bool {
    let Some(filenames) = object
        .get("filenames")
        .and_then(serde_json::Value::as_array)
        .filter(|filenames| !filenames.is_empty() && filenames.len() <= 64)
    else {
        return false;
    };
    let profile = if selector.profile == "dev" {
        "debug"
    } else {
        &selector.profile
    };
    if !canonical_path_component(profile) {
        return false;
    }
    let root = match selector.compilation_kind {
        CargoCompilationKind::BuildHost => format!("{LOGICAL_TARGET}/{profile}"),
        CargoCompilationKind::Target => {
            let Some(target) = Path::new(&selector.compilation_target)
                .file_stem()
                .and_then(|target| target.to_str())
                .filter(|target| canonical_path_component(target))
            else {
                return false;
            };
            format!("{LOGICAL_TARGET}/{target}/{profile}")
        }
    };
    filenames.iter().all(|filename| {
        filename
            .as_str()
            .is_some_and(|filename| logical_descendant(filename, &root))
    })
}

fn verify_message_target(
    value: Option<&serde_json::Value>,
    selector: &crate::CargoUnitSelector,
    source_roots: &[String],
) -> Result<(), TrustedCargoBuildError> {
    let target = value
        .and_then(serde_json::Value::as_object)
        .ok_or(TrustedCargoBuildError::InvalidCargoMessages)?;
    let allowed = [
        "kind",
        "crate_types",
        "name",
        "src_path",
        "edition",
        "doc",
        "doctest",
        "test",
        "required-features",
    ];
    let source_path = message_text(target, "src_path")?;
    if target.keys().any(|key| !allowed.contains(&key.as_str()))
        || target.keys().any(|key| key == "required_features")
        || message_text(target, "name")? != selector.target_name
        || !source_roots
            .iter()
            .any(|root| normalized_logical_descendant(source_path, root))
        || !matches!(
            message_text(target, "edition")?,
            "2015" | "2018" | "2021" | "2024"
        )
        || ["doc", "doctest", "test"].iter().any(|name| {
            target
                .get(*name)
                .and_then(serde_json::Value::as_bool)
                .is_none()
        })
    {
        return Err(TrustedCargoBuildError::InvalidCargoMessages);
    }
    let kinds = bounded_string_set(target.get("kind"), 16)?;
    let crate_types = bounded_string_set(target.get("crate_types"), 16)?;
    let library_type =
        |value: &&str| matches!(*value, "lib" | "rlib" | "dylib" | "cdylib" | "staticlib");
    let valid = match selector.crate_kind {
        CargoCrateKind::Library => kinds == crate_types && kinds.iter().all(library_type),
        CargoCrateKind::ProcMacro => {
            kinds == BTreeSet::from(["proc-macro"]) && crate_types == BTreeSet::from(["proc-macro"])
        }
        CargoCrateKind::Binary => {
            kinds == BTreeSet::from(["bin"]) && crate_types == BTreeSet::from(["bin"])
        }
        CargoCrateKind::Example => {
            kinds == BTreeSet::from(["example"])
                && crate_types.iter().all(|value| {
                    matches!(
                        *value,
                        "bin" | "lib" | "rlib" | "dylib" | "cdylib" | "staticlib"
                    )
                })
        }
        CargoCrateKind::Test => {
            kinds == BTreeSet::from(["test"]) && crate_types == BTreeSet::from(["bin"])
        }
        CargoCrateKind::Bench => {
            kinds == BTreeSet::from(["bench"]) && crate_types == BTreeSet::from(["bin"])
        }
        CargoCrateKind::CustomBuild => {
            kinds == BTreeSet::from(["custom-build"]) && crate_types == BTreeSet::from(["bin"])
        }
    };
    if valid {
        Ok(())
    } else {
        Err(TrustedCargoBuildError::InvalidCargoMessages)
    }
}

fn bounded_string_set(
    value: Option<&serde_json::Value>,
    maximum: usize,
) -> Result<BTreeSet<&str>, TrustedCargoBuildError> {
    let values = value
        .and_then(serde_json::Value::as_array)
        .filter(|values| !values.is_empty() && values.len() <= maximum)
        .ok_or(TrustedCargoBuildError::InvalidCargoMessages)?;
    let result = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or(TrustedCargoBuildError::InvalidCargoMessages)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if result.len() == values.len() {
        Ok(result)
    } else {
        Err(TrustedCargoBuildError::InvalidCargoMessages)
    }
}

fn verify_message_profile(value: Option<&serde_json::Value>) -> Result<(), TrustedCargoBuildError> {
    let profile = value
        .and_then(serde_json::Value::as_object)
        .ok_or(TrustedCargoBuildError::InvalidCargoMessages)?;
    require_exact_keys(
        profile,
        &[
            "opt_level",
            "debuginfo",
            "debug_assertions",
            "overflow_checks",
            "test",
        ],
    )?;
    if !profile
        .get("opt_level")
        .is_some_and(serde_json::Value::is_string)
        || !(profile
            .get("debuginfo")
            .is_some_and(serde_json::Value::is_number)
            || profile
                .get("debuginfo")
                .is_some_and(serde_json::Value::is_null))
        || ["debug_assertions", "overflow_checks", "test"]
            .iter()
            .any(|name| {
                profile
                    .get(*name)
                    .and_then(serde_json::Value::as_bool)
                    .is_none()
            })
    {
        return Err(TrustedCargoBuildError::InvalidCargoMessages);
    }
    Ok(())
}

fn require_exact_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    expected: &[&str],
) -> Result<(), TrustedCargoBuildError> {
    if object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)) {
        Ok(())
    } else {
        Err(TrustedCargoBuildError::InvalidCargoMessages)
    }
}

fn require_bounded_strings(
    value: Option<&serde_json::Value>,
    maximum: usize,
    predicate: impl Fn(&str) -> bool,
) -> Result<(), TrustedCargoBuildError> {
    let values = value
        .and_then(serde_json::Value::as_array)
        .ok_or(TrustedCargoBuildError::InvalidCargoMessages)?;
    if values.len() > maximum
        || values
            .iter()
            .any(|value| value.as_str().is_none_or(|value| !predicate(value)))
    {
        Err(TrustedCargoBuildError::InvalidCargoMessages)
    } else {
        Ok(())
    }
}

fn message_text<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a str, TrustedCargoBuildError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 16 * 1024 && !value.contains('\0'))
        .ok_or(TrustedCargoBuildError::InvalidCargoMessages)
}

fn package_id_matches(package_id: &str, package: &crate::CargoPackageIdentity) -> bool {
    let Some((source, fragment)) = package_id.rsplit_once('#') else {
        return false;
    };
    let (name, version) = if let Some((name, version)) = fragment.rsplit_once('@') {
        (name, version)
    } else {
        let source_without_query = source.split_once('?').map_or(source, |(url, _)| url);
        let Some(name) = source_without_query
            .trim_end_matches('/')
            .rsplit('/')
            .next()
        else {
            return false;
        };
        (name, fragment)
    };
    if name != package.name || version != package.version {
        return false;
    }
    match &package.source {
        crate::CargoPackageSource::Registry { registry, .. } => {
            source == format!("registry+{registry}")
                || (registry.starts_with("sparse+") && source == registry)
        }
        crate::CargoPackageSource::Git { repository, .. } => source == format!("git+{repository}"),
        crate::CargoPackageSource::Path { .. } => canonical_logical_path(
            source.strip_prefix("path+file://").unwrap_or_default(),
            "/rust-agent/closure/",
        ),
    }
}

fn verified_package_root(
    package_id: &str,
    manifest_path: &str,
    package: &crate::CargoPackageIdentity,
    cache_packages: &[crate::CargoFetchCachePackageLocation],
) -> Result<String, TrustedCargoBuildError> {
    if !package_id_matches(package_id, package) || !manifest_path.ends_with("/Cargo.toml") {
        return Err(TrustedCargoBuildError::InvalidCargoMessages);
    }
    let package_root = manifest_path
        .strip_suffix("/Cargo.toml")
        .ok_or(TrustedCargoBuildError::InvalidCargoMessages)?;
    match &package.source {
        crate::CargoPackageSource::Path { .. } => {
            let source = package_id
                .rsplit_once('#')
                .and_then(|(source, _)| source.strip_prefix("path+file://"))
                .ok_or(TrustedCargoBuildError::InvalidCargoMessages)?;
            if package_root != source
                || !canonical_logical_path(package_root, "/rust-agent/closure/")
            {
                return Err(TrustedCargoBuildError::InvalidCargoMessages);
            }
        }
        crate::CargoPackageSource::Registry { .. } | crate::CargoPackageSource::Git { .. } => {
            let locations = cache_packages
                .iter()
                .filter(|location| location.package == *package)
                .collect::<Vec<_>>();
            let [location] = locations.as_slice() else {
                return Err(TrustedCargoBuildError::InvalidCargoMessages);
            };
            let source_path = location
                .source_path
                .as_deref()
                .filter(|path| canonical_relative_path(path))
                .ok_or(TrustedCargoBuildError::InvalidCargoMessages)?;
            let cache_root = format!("/rust-agent/cargo-home/{source_path}");
            let valid = match &package.source {
                crate::CargoPackageSource::Registry { .. } => package_root == cache_root,
                crate::CargoPackageSource::Git { .. } => {
                    package_root == cache_root || logical_descendant(package_root, &cache_root)
                }
                crate::CargoPackageSource::Path { .. } => false,
            };
            if !valid {
                return Err(TrustedCargoBuildError::InvalidCargoMessages);
            }
        }
    }
    Ok(package_root.into())
}

fn verified_package_source_roots(
    package_root: &str,
    package: &crate::CargoPackageIdentity,
    host_closure: Option<&NormalizedHostBuildInputClosure>,
) -> Result<Vec<String>, TrustedCargoBuildError> {
    let mut roots = BTreeSet::from([package_root.to_owned()]);
    let crate::CargoPackageSource::Path { tree_digest } = &package.source else {
        return Ok(roots.into_iter().collect());
    };
    let Some(host_closure) = host_closure else {
        return Ok(roots.into_iter().collect());
    };
    if !extend_verified_closure_tree_roots(&mut roots, tree_digest, host_closure.items())? {
        return Err(TrustedCargoBuildError::InvalidCargoMessages);
    }
    Ok(roots.into_iter().collect())
}

fn extend_verified_closure_tree_roots(
    roots: &mut BTreeSet<String>,
    tree_digest: &str,
    items: &[crate::NormalizedHostBuildClosureItem],
) -> Result<bool, TrustedCargoBuildError> {
    let mut matched_tree = false;
    for item in items {
        if matches!(
            item.role,
            HostBuildClosureItemRole::HostPackageTree
                | HostBuildClosureItemRole::PathPackageTree
                | HostBuildClosureItemRole::EmittedCompositionTree
        ) && matches!(
            &item.content,
            HostBuildClosureContent::SnapshotTree {
                tree_digest: item_digest
            } if item_digest == tree_digest
        ) {
            if !canonical_logical_path(&item.logical_path, "/rust-agent/closure/") {
                return Err(TrustedCargoBuildError::InvalidCargoMessages);
            }
            matched_tree = true;
            roots.insert(item.logical_path.clone());
        }
    }
    Ok(matched_tree)
}

fn canonical_logical_path(path: &str, root: &str) -> bool {
    path.starts_with(root)
        && path.len() <= 4096
        && path.is_ascii()
        && !path.ends_with('/')
        && path.split('/').skip(1).all(|component| {
            !component.is_empty() && component.len() <= 255 && !matches!(component, "." | "..")
        })
}

fn canonical_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && path.is_ascii()
        && !path.starts_with('/')
        && !path.ends_with('/')
        && path.split('/').all(|component| {
            !component.is_empty() && component.len() <= 255 && !matches!(component, "." | "..")
        })
}

fn logical_descendant(path: &str, root: &str) -> bool {
    path.strip_prefix(root).is_some_and(|suffix| {
        suffix.starts_with('/')
            && canonical_logical_path(path, "/rust-agent/")
            && !suffix.contains("//")
    })
}

fn normalized_logical_descendant(path: &str, root: &str) -> bool {
    let Some(path) = normalize_logical_path(path) else {
        return false;
    };
    path.strip_prefix(root)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn normalize_logical_path(path: &str) -> Option<String> {
    if !path.starts_with("/rust-agent/")
        || path.len() > 4096
        || !path.is_ascii()
        || path.ends_with('/')
    {
        return None;
    }
    let mut components = Vec::new();
    for component in path.split('/').skip(1) {
        match component {
            ".." if components.len() > 1 => {
                components.pop();
            }
            "" | "." | ".." => return None,
            component if component.len() <= 255 => components.push(component),
            _ => return None,
        }
    }
    (components.first() == Some(&"rust-agent") && components.len() > 1)
        .then(|| format!("/{}", components.join("/")))
}

fn canonical_path_component(component: &str) -> bool {
    !component.is_empty()
        && component.len() <= 255
        && component.is_ascii()
        && !matches!(component, "." | "..")
        && !component.contains('/')
}

fn diagnostic_tail(bytes: &[u8], maximum: usize) -> String {
    let omitted = bytes.len().saturating_sub(maximum);
    let tail = &bytes[omitted..];
    if omitted == 0 {
        String::from_utf8_lossy(tail).into_owned()
    } else {
        format!(
            "[... {omitted} bytes omitted ...]{}",
            String::from_utf8_lossy(tail)
        )
    }
}

fn diagnostic_head_and_tail(bytes: &[u8], maximum: usize) -> String {
    if bytes.len() <= maximum {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let head_len = maximum / 2;
    let tail_len = maximum - head_len;
    format!(
        "{}[... {} bytes omitted ...]{}",
        String::from_utf8_lossy(&bytes[..head_len]),
        bytes.len() - maximum,
        String::from_utf8_lossy(&bytes[bytes.len() - tail_len..]),
    )
}

fn cargo_message_verification_diagnostic(
    stdout: &[u8],
    _planned: &NormalizedHostCargoUnitGraph,
) -> String {
    format!(
        "stage=stream-envelope message-bytes={} messages-tail={}",
        stdout.len(),
        diagnostic_tail(stdout, MAXIMUM_VERIFICATION_DIAGNOSTIC_BYTES),
    )
}

fn unit_observation_diagnostic(
    observation: &LinuxSandboxExecutionObservation,
    planned: &NormalizedHostCargoUnitGraph,
) -> String {
    let mut executable_counts = BTreeMap::<&str, usize>::new();
    for command in &observation.executed_commands {
        *executable_counts
            .entry(command.executable.as_str())
            .or_default() += 1;
    }
    format!(
        "execution-count={} executable-counts={executable_counts:?} planned-units={} planned-edges={}",
        observation.executed_commands.len(),
        planned.nodes().len(),
        planned.edges().len(),
    )
}

fn unit_observation_stage_error(
    stage: impl std::fmt::Display,
    observation: &LinuxSandboxExecutionObservation,
    planned: &NormalizedHostCargoUnitGraph,
) -> TrustedCargoBuildError {
    TrustedCargoBuildError::UnitObservationOutput {
        diagnostic: format!(
            "stage={stage} {}",
            unit_observation_diagnostic(observation, planned)
        ),
    }
}

fn add_unit_observation_stage(
    error: TrustedCargoBuildError,
    stage: impl std::fmt::Display,
    observation: &LinuxSandboxExecutionObservation,
    planned: &NormalizedHostCargoUnitGraph,
) -> TrustedCargoBuildError {
    match error {
        TrustedCargoBuildError::UnitObservationMismatch => {
            unit_observation_stage_error(stage, observation, planned)
        }
        other => other,
    }
}

fn logical_target_path(path: &str) -> bool {
    path.starts_with(&format!("{LOGICAL_TARGET}/"))
        && !path.contains("/../")
        && !path.ends_with("/..")
        && !path.contains('\0')
}

fn observe_units(
    request: &NormalizedCargoPlannerRequest,
    inputs: &VerifiedProductionInputs,
    planned: &NormalizedHostCargoUnitGraph,
    observation: &LinuxSandboxExecutionObservation,
    root_arguments: &[String],
    build_policy: &BuildUnitObservationPolicy<'_>,
    cargo_messages: &CargoMessageObservation,
) -> Result<(), TrustedCargoBuildError> {
    let cargo_digest = input_digest(inputs, ProductionInputFileRole::Cargo)?;
    let rustc_digest = input_digest(inputs, ProductionInputFileRole::Rustc)?;
    let [root, descendants @ ..] = observation.executed_commands.as_slice() else {
        return Err(unit_observation_stage_error(
            "root-missing",
            observation,
            planned,
        ));
    };
    let expected_root_arguments = std::iter::once(LOGICAL_CARGO.into())
        .chain(root_arguments.iter().cloned())
        .collect::<Vec<_>>();
    if root.executable != LOGICAL_CARGO
        || root.executable_sha256 != cargo_digest
        || root.arguments != expected_root_arguments
        || root.working_directory != request.invocation().working_directory
    {
        return Err(unit_observation_stage_error(
            "root-identity",
            observation,
            planned,
        ));
    }

    let mut observed_compile_units = BTreeSet::new();
    let mut observed_build_script_executions = BTreeMap::new();
    let mut expected_target_linker_executions = 0usize;
    let mut observed_target_linker_executions = 0usize;
    for execution in descendants {
        if execution.executable == LOGICAL_RUSTC && execution.executable_sha256 == rustc_digest {
            let arguments = execution
                .arguments
                .strip_prefix(&[LOGICAL_RUSTC.into()])
                .ok_or_else(|| unit_observation_stage_error("rustc-argv", observation, planned))?;
            if build_rustc_query_allowed(request, arguments, build_policy.host_linker_selected) {
                continue;
            }
            let rustc = RustcInvocation::parse(arguments, build_policy.host_linker_selected)
                .map_err(|error| {
                    add_unit_observation_stage(error, "rustc-parse", observation, planned)
                })?;
            expected_target_linker_executions = expected_target_linker_executions
                .checked_add(usize::from(
                    build_policy.target_linker.is_some() && rustc.requires_target_linker(),
                ))
                .ok_or_else(|| {
                    unit_observation_stage_error(
                        "target-linker-expected-overflow",
                        observation,
                        planned,
                    )
                })?;
            let matches = planned
                .nodes()
                .iter()
                .filter(|(selector, unit)| rustc.matches(selector, unit, planned))
                .map(|(selector, _)| selector.clone())
                .collect::<Vec<_>>();
            let [selector] = matches.as_slice() else {
                return Err(unit_observation_stage_error(
                    format!(
                        "rustc-selector-count-{}-crate-{}-target-{:?}",
                        matches.len(),
                        rustc.crate_name,
                        rustc.target,
                    ),
                    observation,
                    planned,
                ));
            };
            if !observed_compile_units.insert(selector.clone()) {
                return Err(unit_observation_stage_error(
                    format!("duplicate-rustc-selector-{selector:?}"),
                    observation,
                    planned,
                ));
            }
            verify_extern_edges(
                planned,
                selector,
                &rustc.externs,
                &cargo_messages.artifact_files,
            )
            .map_err(|error| {
                add_unit_observation_stage(
                    error,
                    format!("extern-edges-{selector:?}"),
                    observation,
                    planned,
                )
            })?;
        } else if execution
            .executable
            .starts_with(&format!("{LOGICAL_TARGET}/"))
        {
            if !cargo_messages
                .build_script_executables
                .values()
                .any(|executable| executable == &execution.executable)
            {
                return Err(unit_observation_stage_error(
                    format!("unexpected-target-executable-{}", execution.executable),
                    observation,
                    planned,
                ));
            }
            let count = observed_build_script_executions
                .entry(execution.executable.clone())
                .or_insert(0usize);
            *count = count.checked_add(1).ok_or_else(|| {
                unit_observation_stage_error("build-script-count-overflow", observation, planned)
            })?;
        } else if build_policy.target_linker.is_some_and(|(logical, digest)| {
            execution.executable == logical && execution.executable_sha256 == digest
        }) {
            observed_target_linker_executions = observed_target_linker_executions
                .checked_add(1)
                .ok_or_else(|| {
                    unit_observation_stage_error(
                        "target-linker-observed-overflow",
                        observation,
                        planned,
                    )
                })?;
        } else if build_policy
            .executable_digests
            .get(execution.executable.as_str())
            .is_none_or(|digest| **digest != execution.executable_sha256)
        {
            return Err(unit_observation_stage_error(
                format!("unaccounted-executable-{}", execution.executable),
                observation,
                planned,
            ));
        }
    }

    let expected_compile_units = planned
        .nodes()
        .keys()
        .filter(|selector| selector.compile_mode != CargoCompileMode::RunCustomBuild)
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_build_scripts = planned
        .nodes()
        .keys()
        .filter(|selector| selector.compile_mode == CargoCompileMode::RunCustomBuild)
        .cloned()
        .collect::<BTreeSet<_>>();
    validate_target_linker_execution_count(
        expected_target_linker_executions,
        observed_target_linker_executions,
    )
    .map_err(|error| {
        add_unit_observation_stage(
            error,
            format!(
                "target-linker-count-expected-{expected_target_linker_executions}-observed-{observed_target_linker_executions}"
            ),
            observation,
            planned,
        )
    })?;
    validate_build_script_execution_counts(
        &expected_build_scripts,
        &cargo_messages.build_script_executables,
        &observed_build_script_executions,
    )
    .map_err(|error| {
        add_unit_observation_stage(error, "build-script-counts", observation, planned)
    })?;
    if observed_compile_units != expected_compile_units {
        let missing = expected_compile_units
            .difference(&observed_compile_units)
            .collect::<Vec<_>>();
        let unexpected = observed_compile_units
            .difference(&expected_compile_units)
            .collect::<Vec<_>>();
        return Err(unit_observation_stage_error(
            format!("compile-coverage-missing-{missing:?}-unexpected-{unexpected:?}"),
            observation,
            planned,
        ));
    }
    Ok(())
}

fn validate_build_script_execution_counts(
    expected_selectors: &BTreeSet<crate::CargoUnitSelector>,
    selector_executables: &BTreeMap<crate::CargoUnitSelector, String>,
    observed_executions: &BTreeMap<String, usize>,
) -> Result<(), TrustedCargoBuildError> {
    if selector_executables.keys().collect::<BTreeSet<_>>()
        != expected_selectors.iter().collect::<BTreeSet<_>>()
    {
        return Err(TrustedCargoBuildError::UnitObservationMismatch);
    }
    let mut expected_executions = BTreeMap::new();
    for executable in selector_executables.values() {
        let count = expected_executions
            .entry(executable.clone())
            .or_insert(0usize);
        *count = count
            .checked_add(1)
            .ok_or(TrustedCargoBuildError::UnitObservationMismatch)?;
    }
    if &expected_executions == observed_executions {
        Ok(())
    } else {
        Err(TrustedCargoBuildError::UnitObservationMismatch)
    }
}

fn validate_target_linker_execution_count(
    expected: usize,
    observed: usize,
) -> Result<(), TrustedCargoBuildError> {
    if expected == observed {
        Ok(())
    } else {
        Err(TrustedCargoBuildError::UnitObservationMismatch)
    }
}

struct RustcInvocation {
    crate_name: String,
    crate_types: BTreeSet<String>,
    target: Option<String>,
    features: BTreeSet<String>,
    externs: BTreeMap<String, String>,
}

impl RustcInvocation {
    fn parse(
        arguments: &[String],
        host_linker_selected: bool,
    ) -> Result<Self, TrustedCargoBuildError> {
        let crate_name = option_value(arguments, "--crate-name")
            .ok_or(TrustedCargoBuildError::UnitObservationMismatch)?;
        let crate_types = option_values(arguments, "--crate-type");
        if crate_types.is_empty() {
            return Err(TrustedCargoBuildError::UnitObservationMismatch);
        }
        let target = option_value(arguments, "--target");
        if target.is_some() && option_count(arguments, "--target") != 1 {
            return Err(TrustedCargoBuildError::UnitObservationMismatch);
        }
        validate_rustc_build_flags(arguments, target.is_some(), host_linker_selected)?;
        let features = option_values(arguments, "--cfg")
            .into_iter()
            .filter_map(|cfg| {
                cfg.strip_prefix("feature=\"")
                    .and_then(|value| value.strip_suffix('"'))
                    .map(str::to_owned)
            })
            .collect();
        let mut externs = BTreeMap::new();
        for value in option_values(arguments, "--extern") {
            if value == "proc_macro" && crate_types.len() == 1 && crate_types.contains("proc-macro")
            {
                continue;
            }
            let Some((name, path)) = value.split_once('=') else {
                return Err(TrustedCargoBuildError::UnitObservationMismatch);
            };
            if name.is_empty()
                || !logical_target_path(path)
                || externs.insert(name.into(), path.into()).is_some()
            {
                return Err(TrustedCargoBuildError::UnitObservationMismatch);
            }
        }
        Ok(Self {
            crate_name,
            crate_types,
            target,
            features,
            externs,
        })
    }

    fn matches(
        &self,
        selector: &crate::CargoUnitSelector,
        unit: &crate::NormalizedCargoUnit,
        graph: &NormalizedHostCargoUnitGraph,
    ) -> bool {
        let expected_target = (selector.compilation_kind == CargoCompilationKind::Target)
            .then(|| graph.composition_target().to_owned());
        self.crate_name == selector.target_name.replace('-', "_")
            && self.target == expected_target
            && self.features == unit.features
            && crate_type_matches(selector.crate_kind, &self.crate_types)
            && selector.compile_mode != CargoCompileMode::RunCustomBuild
    }

    fn requires_target_linker(&self) -> bool {
        self.target.is_some()
            && self
                .crate_types
                .iter()
                .any(|crate_type| matches!(crate_type.as_str(), "bin" | "cdylib" | "dylib"))
    }
}

fn build_rustc_query_allowed(
    request: &NormalizedCargoPlannerRequest,
    arguments: &[String],
    host_linker_selected: bool,
) -> bool {
    if request.allows_rustc_query(arguments) {
        return true;
    }
    let is_target = option_value(arguments, "--target").is_some();
    if validate_rustc_build_flags(arguments, is_target, host_linker_selected).is_err() {
        return false;
    }
    let expected_flag = if is_target {
        Some(BUILD_SYSROOT_FLAG)
    } else if host_linker_selected {
        Some(HOST_LINKER_FEATURE_FLAG)
    } else {
        None
    };
    let mut without_build_flag = arguments.to_vec();
    if let Some(expected_flag) = expected_flag {
        let Some(index) = without_build_flag
            .iter()
            .position(|argument| argument == expected_flag)
        else {
            return false;
        };
        without_build_flag.remove(index);
    }
    request.allows_rustc_query(&without_build_flag)
}

fn validate_rustc_build_flags(
    arguments: &[String],
    is_target: bool,
    host_linker_selected: bool,
) -> Result<(), TrustedCargoBuildError> {
    let sysroot_count = arguments
        .iter()
        .filter(|argument| argument.as_str() == BUILD_SYSROOT_FLAG)
        .count();
    let host_linker_feature_count = arguments
        .iter()
        .filter(|argument| argument.as_str() == HOST_LINKER_FEATURE_FLAG)
        .count();
    let alternate_sysroot = arguments.iter().any(|argument| {
        argument.starts_with("--sysroot") && argument.as_str() != BUILD_SYSROOT_FLAG
    });
    let alternate_linker_feature = arguments.iter().any(|argument| {
        argument.starts_with("-Clinker-features") && argument.as_str() != HOST_LINKER_FEATURE_FLAG
    }) || arguments
        .windows(2)
        .any(|pair| pair[0] == "-C" && pair[1].starts_with("linker-features"));
    let expected_sysroot_count = usize::from(is_target);
    let expected_linker_feature_count = usize::from(!is_target && host_linker_selected);
    if sysroot_count != expected_sysroot_count
        || host_linker_feature_count != expected_linker_feature_count
        || alternate_sysroot
        || alternate_linker_feature
    {
        Err(TrustedCargoBuildError::UnitObservationMismatch)
    } else {
        Ok(())
    }
}

fn option_count(arguments: &[String], name: &str) -> usize {
    let prefix = format!("{name}=");
    arguments
        .iter()
        .filter(|argument| argument.as_str() == name || argument.starts_with(&prefix))
        .count()
}

fn crate_type_matches(kind: CargoCrateKind, crate_types: &BTreeSet<String>) -> bool {
    match kind {
        CargoCrateKind::Library => crate_types.iter().all(|value| {
            matches!(
                value.as_str(),
                "lib" | "rlib" | "dylib" | "cdylib" | "staticlib"
            )
        }),
        CargoCrateKind::ProcMacro => crate_types.len() == 1 && crate_types.contains("proc-macro"),
        CargoCrateKind::Binary
        | CargoCrateKind::Example
        | CargoCrateKind::Test
        | CargoCrateKind::Bench
        | CargoCrateKind::CustomBuild => crate_types.len() == 1 && crate_types.contains("bin"),
    }
}

fn verify_extern_edges(
    planned: &NormalizedHostCargoUnitGraph,
    dependent: &crate::CargoUnitSelector,
    externs: &BTreeMap<String, String>,
    artifact_files: &BTreeMap<String, crate::CargoUnitSelector>,
) -> Result<(), TrustedCargoBuildError> {
    let expected = planned
        .edges()
        .iter()
        .filter(|edge| &edge.dependent == dependent)
        .filter(|edge| edge.dependency.compile_mode != CargoCompileMode::RunCustomBuild)
        .map(|edge| {
            (
                edge.dependency.target_name.replace('-', "_"),
                edge.dependency.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if expected.len() == externs.len()
        && expected.iter().all(|(name, selector)| {
            externs.get(name).and_then(|path| artifact_files.get(path)) == Some(selector)
        })
    {
        Ok(())
    } else {
        Err(TrustedCargoBuildError::UnitObservationMismatch)
    }
}

fn option_value(arguments: &[String], name: &str) -> Option<String> {
    option_values(arguments, name).into_iter().next()
}

fn option_values(arguments: &[String], name: &str) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    let prefix = format!("{name}=");
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == name {
            if let Some(value) = arguments.get(index + 1) {
                values.insert(value.clone());
            }
            index += 2;
        } else {
            if let Some(value) = arguments[index].strip_prefix(&prefix) {
                values.insert(value.into());
            }
            index += 1;
        }
    }
    values
}

fn input_digest(
    inputs: &VerifiedProductionInputs,
    role: ProductionInputFileRole,
) -> Result<&str, TrustedCargoBuildError> {
    inputs
        .request()
        .files
        .iter()
        .find(|file| file.role == role)
        .map(|file| file.sha256.as_str())
        .ok_or(TrustedCargoBuildError::InputMismatch)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{
        CargoDependencyKind, CargoPackageIdentity, CargoPackageSource, CargoTargetEvaluationDomain,
        CargoUnit, CargoUnitEdge, CargoUnitGraphPlannerIdentity, CargoUnitSelector,
        HostCargoUnitGraph,
    };

    #[test]
    fn cargo_build_retains_the_request_bound_channel_override() {
        const CHANNEL_OVERRIDE: &str = "__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS";
        let planner_environment = cargo_driver_environment(true, false);
        let environment = production_build_environment(&planner_environment).unwrap();

        assert_eq!(
            environment.get(CHANNEL_OVERRIDE).map(String::as_str),
            Some("nightly")
        );
        assert_eq!(
            environment
                .get("CARGO_ENCODED_RUSTFLAGS")
                .map(String::as_str),
            Some(BUILD_SYSROOT_FLAG)
        );
        assert_eq!(
            environment.get("TMPDIR").map(String::as_str),
            Some(LOGICAL_TEMP)
        );
        assert_eq!(environment, cargo_driver_environment(true, true));

        let mut changed = planner_environment.clone();
        changed.insert("CARGO_HOME".into(), "/ambient/cargo-home".into());
        let mut missing = planner_environment.clone();
        missing.remove("CARGO_TARGET_DIR");
        let mut extra = planner_environment.clone();
        extra.insert("HOME".into(), "/ambient/home".into());
        let mut preexisting_build_value = planner_environment.clone();
        preexisting_build_value.insert("CARGO_ENCODED_RUSTFLAGS".into(), "ambient".into());
        for invalid_environment in [
            BTreeMap::new(),
            changed,
            missing,
            extra,
            preexisting_build_value,
        ] {
            assert!(matches!(
                production_build_environment(&invalid_environment),
                Err(TrustedCargoBuildError::InputMismatch)
            ));
        }
    }

    #[test]
    fn host_and_target_rustc_flags_are_scope_exact() {
        let host = rustc_arguments(&[HOST_LINKER_FEATURE_FLAG]);
        let parsed_host = RustcInvocation::parse(&host, true).unwrap();
        assert_eq!(parsed_host.target, None);

        let target = rustc_arguments(&["--target", "wasm32-unknown-unknown", BUILD_SYSROOT_FLAG]);
        let parsed_target = RustcInvocation::parse(&target, true).unwrap();
        assert_eq!(
            parsed_target.target.as_deref(),
            Some("wasm32-unknown-unknown")
        );

        RustcInvocation::parse(&rustc_arguments(&[]), false).unwrap();
    }

    #[test]
    fn rustc_observation_rejects_cross_kind_linker_flags() {
        for arguments in [
            rustc_arguments(&[BUILD_SYSROOT_FLAG, HOST_LINKER_FEATURE_FLAG]),
            rustc_arguments(&[]),
            rustc_arguments(&[
                "--target",
                "wasm32-unknown-unknown",
                BUILD_SYSROOT_FLAG,
                HOST_LINKER_FEATURE_FLAG,
            ]),
            rustc_arguments(&["--target", "wasm32-unknown-unknown"]),
            rustc_arguments(&[HOST_LINKER_FEATURE_FLAG, HOST_LINKER_FEATURE_FLAG]),
            rustc_arguments(&["-Clinker-features=+lld"]),
            rustc_arguments(&[
                "--target",
                "wasm32-unknown-unknown",
                "-C",
                "linker-features=-lld",
            ]),
        ] {
            assert!(matches!(
                RustcInvocation::parse(&arguments, true),
                Err(TrustedCargoBuildError::UnitObservationMismatch)
            ));
        }
    }

    #[test]
    fn target_linker_observation_is_exact() {
        let target_cdylib = RustcInvocation::parse(
            &rustc_arguments(&[
                "--target",
                "wasm32-unknown-unknown",
                "--crate-type",
                "cdylib",
                BUILD_SYSROOT_FLAG,
            ]),
            false,
        )
        .unwrap();
        let target_rlib = RustcInvocation::parse(
            &rustc_arguments(&["--target", "wasm32-unknown-unknown", BUILD_SYSROOT_FLAG]),
            false,
        )
        .unwrap();
        let host_binary = RustcInvocation::parse(&rustc_arguments(&[]), false).unwrap();
        assert!(target_cdylib.requires_target_linker());
        assert!(!target_rlib.requires_target_linker());
        assert!(!host_binary.requires_target_linker());
        assert!(validate_target_linker_execution_count(1, 1).is_ok());
        for (expected, observed) in [(1, 0), (0, 1), (1, 2)] {
            assert!(matches!(
                validate_target_linker_execution_count(expected, observed),
                Err(TrustedCargoBuildError::UnitObservationMismatch)
            ));
        }
    }

    #[test]
    fn build_script_execution_counts_preserve_shared_host_and_target_contexts() {
        let mut host_selector = selector("fixture");
        host_selector.compilation_kind = CargoCompilationKind::BuildHost;
        host_selector.compilation_target = "build-host".into();
        host_selector.cargo_target_context = crate::CargoUnitTargetContext::BuildHost;
        host_selector.compile_mode = CargoCompileMode::RunCustomBuild;
        host_selector.crate_kind = CargoCrateKind::CustomBuild;
        let mut target_selector = host_selector.clone();
        target_selector.cargo_target_context = crate::CargoUnitTargetContext::CompositionTarget;
        let expected_selectors = BTreeSet::from([host_selector.clone(), target_selector.clone()]);
        let shared_executable = "/rust-agent/target/release/build/fixture/build-script-build";
        let selector_executables = BTreeMap::from([
            (host_selector.clone(), shared_executable.into()),
            (target_selector.clone(), shared_executable.into()),
        ]);

        validate_build_script_execution_counts(
            &expected_selectors,
            &selector_executables,
            &BTreeMap::from([(shared_executable.into(), 2)]),
        )
        .unwrap();

        for invalid_observations in [
            BTreeMap::new(),
            BTreeMap::from([(shared_executable.into(), 1)]),
            BTreeMap::from([(shared_executable.into(), 3)]),
            BTreeMap::from([(
                "/rust-agent/target/release/build/other/build-script-build".into(),
                2,
            )]),
        ] {
            assert!(matches!(
                validate_build_script_execution_counts(
                    &expected_selectors,
                    &selector_executables,
                    &invalid_observations,
                ),
                Err(TrustedCargoBuildError::UnitObservationMismatch)
            ));
        }

        for invalid_mapping in [
            BTreeMap::from([(host_selector, shared_executable.into())]),
            BTreeMap::from([
                (target_selector.clone(), shared_executable.into()),
                (selector("unplanned"), shared_executable.into()),
            ]),
        ] {
            assert!(matches!(
                validate_build_script_execution_counts(
                    &expected_selectors,
                    &invalid_mapping,
                    &BTreeMap::from([(shared_executable.into(), 2)]),
                ),
                Err(TrustedCargoBuildError::UnitObservationMismatch)
            ));
        }
    }

    #[test]
    fn proc_macro_sysroot_extern_is_not_a_cargo_dependency_edge() {
        let proc_macro = [
            "--crate-name",
            "fixture_macro",
            "--crate-type",
            "proc-macro",
            "--extern",
            "proc_macro",
            "--extern",
            "dependency=/rust-agent/target/release/libdependency.rlib",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let parsed = RustcInvocation::parse(&proc_macro, false).unwrap();
        assert_eq!(
            parsed.externs,
            BTreeMap::from([(
                "dependency".into(),
                "/rust-agent/target/release/libdependency.rlib".into(),
            )])
        );

        let library = rustc_arguments(&["--extern", "proc_macro"]);
        assert!(matches!(
            RustcInvocation::parse(&library, false),
            Err(TrustedCargoBuildError::UnitObservationMismatch)
        ));
    }

    fn rustc_arguments(extra: &[&str]) -> Vec<String> {
        ["--crate-name", "fixture", "--crate-type", "lib"]
            .into_iter()
            .chain(extra.iter().copied())
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn cargo_message_stream_is_closed_complete_and_non_fresh() {
        let graph = graph(false);
        let artifact = json!({
            "reason": "compiler-artifact",
            "package_id": "path+file:///rust-agent/closure/fixture#1.0.0",
            "manifest_path": "/rust-agent/closure/fixture/Cargo.toml",
            "target": {
                "kind": ["lib"],
                "crate_types": ["lib"],
                "name": "fixture",
                "src_path": "/rust-agent/closure/fixture/src/lib.rs",
                "edition": "2024",
                "doc": true,
                "doctest": true,
                "test": true
            },
            "profile": {
                "opt_level": "0",
                "debuginfo": 2,
                "debug_assertions": true,
                "overflow_checks": true,
                "test": false
            },
            "features": [],
            "filenames": ["/rust-agent/target/test-target/debug/libfixture.rlib"],
            "executable": null,
            "fresh": false
        });
        let valid = messages(&[
            artifact.clone(),
            json!({"reason":"build-finished","success":true}),
        ]);
        verify_cargo_messages(&valid, &graph, &[]).unwrap();
        let mut explicit_name = artifact.clone();
        explicit_name["package_id"] =
            json!("path+file:///rust-agent/closure/fixture#fixture@1.0.0");
        verify_cargo_messages(
            &messages(&[
                explicit_name,
                json!({"reason":"build-finished","success":true}),
            ]),
            &graph,
            &[],
        )
        .unwrap();

        let mut cdylib = artifact.clone();
        cdylib["target"]["kind"] = json!(["cdylib"]);
        cdylib["target"]["crate_types"] = json!(["cdylib"]);
        cdylib["filenames"] = json!(["/rust-agent/target/test-target/debug/fixture.wasm"]);
        verify_cargo_messages(
            &messages(&[cdylib, json!({"reason":"build-finished","success":true})]),
            &graph,
            &[],
        )
        .unwrap();

        for (kind, crate_types) in [
            (json!(["cdylib"]), json!(["rlib"])),
            (json!(["plugin"]), json!(["plugin"])),
            (json!(["lib", "lib"]), json!(["lib", "lib"])),
        ] {
            let mut invalid = artifact.clone();
            invalid["target"]["kind"] = kind;
            invalid["target"]["crate_types"] = crate_types;
            assert!(matches!(
                verify_cargo_messages(
                    &messages(&[invalid, json!({"reason":"build-finished","success":true})]),
                    &graph,
                    &[],
                ),
                Err(TrustedCargoBuildError::InvalidCargoMessages)
            ));
        }

        let mut split_source = artifact.clone();
        split_source["target"]["src_path"] = json!("/rust-agent/closure/trees/fixture/src/lib.rs");
        let split_target = split_source["target"].clone();
        verify_message_target(
            Some(&split_target),
            graph.nodes().keys().next().unwrap(),
            &[
                "/rust-agent/closure/host".into(),
                "/rust-agent/closure/trees/fixture".into(),
            ],
        )
        .unwrap();
        let mut sibling_source = split_target.clone();
        sibling_source["src_path"] = json!("/rust-agent/closure/host/../trees/fixture/src/lib.rs");
        verify_message_target(
            Some(&sibling_source),
            graph.nodes().keys().next().unwrap(),
            &["/rust-agent/closure/trees/fixture".into()],
        )
        .unwrap();
        assert!(matches!(
            verify_message_target(
                Some(&split_target),
                graph.nodes().keys().next().unwrap(),
                &["/rust-agent/closure/host".into()],
            ),
            Err(TrustedCargoBuildError::InvalidCargoMessages)
        ));
        for escaped in [
            "/rust-agent/closure/host/../../outside/src/lib.rs",
            "/rust-agent/closure/host/../trees/other/src/lib.rs",
            "/rust-agent/closure/host/./../trees/fixture/src/lib.rs",
        ] {
            sibling_source["src_path"] = json!(escaped);
            assert!(matches!(
                verify_message_target(
                    Some(&sibling_source),
                    graph.nodes().keys().next().unwrap(),
                    &["/rust-agent/closure/trees/fixture".into()],
                ),
                Err(TrustedCargoBuildError::InvalidCargoMessages)
            ));
        }

        for (field, value) in [
            ("manifest_path", "/rust-agent/workspace/fixture/Cargo.toml"),
            ("manifest_path", "/rust-agent/closure/fixture/../Cargo.toml"),
            ("manifest_path", "/rust-agent/closure/other/Cargo.toml"),
            (
                "package_id",
                "path+file:///rust-agent/closure/other#fixture@1.0.0",
            ),
            (
                "package_id",
                "path+file:///rust-agent/closure/fixture#2.0.0",
            ),
        ] {
            let mut invalid = artifact.clone();
            invalid[field] = json!(value);
            assert!(matches!(
                verify_cargo_messages(
                    &messages(&[invalid, json!({"reason":"build-finished","success":true})]),
                    &graph,
                    &[],
                ),
                Err(TrustedCargoBuildError::InvalidCargoMessages)
            ));
        }
        let mut escaped_source = artifact.clone();
        escaped_source["target"]["src_path"] = json!("/rust-agent/closure/other/src/lib.rs");
        assert!(matches!(
            verify_cargo_messages(
                &messages(&[
                    escaped_source,
                    json!({"reason":"build-finished","success":true})
                ]),
                &graph,
                &[],
            ),
            Err(TrustedCargoBuildError::InvalidCargoMessages)
        ));

        let mut unknown = artifact.clone();
        unknown["ambient"] = json!(true);
        assert!(matches!(
            verify_cargo_messages(
                &messages(&[unknown, json!({"reason":"build-finished","success":true})]),
                &graph,
                &[],
            ),
            Err(TrustedCargoBuildError::InvalidCargoMessages)
        ));

        let mut fresh = artifact.clone();
        fresh["fresh"] = json!(true);
        assert!(matches!(
            verify_cargo_messages(
                &messages(&[fresh, json!({"reason":"build-finished","success":true})]),
                &graph,
                &[],
            ),
            Err(TrustedCargoBuildError::InvalidCargoMessages)
        ));
        assert!(matches!(
            verify_cargo_messages(
                &messages(&[json!({"reason":"build-finished","success":true})]),
                &graph,
                &[],
            ),
            Err(TrustedCargoBuildError::InvalidCargoMessages)
        ));
        assert!(matches!(
            verify_cargo_messages(
                &messages(&[
                    artifact,
                    json!({"reason":"build-finished","success":true}),
                    json!({"reason":"build-finished","success":true})
                ]),
                &graph,
                &[],
            ),
            Err(TrustedCargoBuildError::InvalidCargoMessages)
        ));
    }

    #[test]
    fn cached_cargo_message_sources_match_the_verified_package_location() {
        let registry = CargoPackageIdentity {
            name: "cached".into(),
            version: "1.2.3".into(),
            source: CargoPackageSource::Registry {
                registry: "https://github.com/rust-lang/crates.io-index".into(),
                checksum: "4".repeat(64),
            },
        };
        let registry_location = crate::CargoFetchCachePackageLocation {
            package: registry.clone(),
            archive_path: Some("registry/cache/index/cached-1.2.3.crate".into()),
            source_path: Some("registry/src/index/cached-1.2.3".into()),
        };
        let registry_id = "registry+https://github.com/rust-lang/crates.io-index#cached@1.2.3";
        assert_eq!(
            verified_package_root(
                registry_id,
                "/rust-agent/cargo-home/registry/src/index/cached-1.2.3/Cargo.toml",
                &registry,
                std::slice::from_ref(&registry_location),
            )
            .unwrap(),
            "/rust-agent/cargo-home/registry/src/index/cached-1.2.3"
        );

        let git = CargoPackageIdentity {
            name: "member".into(),
            version: "2.0.0".into(),
            source: CargoPackageSource::Git {
                repository: "https://example.invalid/repository?rev=0123456".into(),
                precise: "0".repeat(40),
            },
        };
        let git_location = crate::CargoFetchCachePackageLocation {
            package: git.clone(),
            archive_path: None,
            source_path: Some("git/checkouts/repository/0123456".into()),
        };
        let git_id = "git+https://example.invalid/repository?rev=0123456#member@2.0.0";
        assert_eq!(
            verified_package_root(
                git_id,
                "/rust-agent/cargo-home/git/checkouts/repository/0123456/member/Cargo.toml",
                &git,
                std::slice::from_ref(&git_location),
            )
            .unwrap(),
            "/rust-agent/cargo-home/git/checkouts/repository/0123456/member"
        );

        for (package_id, manifest, locations) in [
            (
                registry_id,
                "/rust-agent/cargo-home/registry/src/index/other-1.2.3/Cargo.toml",
                std::slice::from_ref(&registry_location),
            ),
            (
                registry_id,
                "/rust-agent/cargo-home/registry/src/index/cached-1.2.3/../Cargo.toml",
                std::slice::from_ref(&registry_location),
            ),
            (
                "registry+https://attacker.invalid/index#cached@1.2.3",
                "/rust-agent/cargo-home/registry/src/index/cached-1.2.3/Cargo.toml",
                std::slice::from_ref(&registry_location),
            ),
        ] {
            assert!(matches!(
                verified_package_root(package_id, manifest, &registry, locations),
                Err(TrustedCargoBuildError::InvalidCargoMessages)
            ));
        }
        assert!(matches!(
            verified_package_root(
                git_id,
                "/rust-agent/cargo-home/git/checkouts/other/0123456/member/Cargo.toml",
                &git,
                &[git_location],
            ),
            Err(TrustedCargoBuildError::InvalidCargoMessages)
        ));
    }

    #[test]
    fn cargo_artifact_paths_distinguish_identical_host_and_target_units() {
        let target_selector = selector("fixture");
        let mut host_selector = target_selector.clone();
        host_selector.compilation_kind = CargoCompilationKind::BuildHost;
        host_selector.compilation_target = "build-host".into();
        host_selector.cargo_target_context = crate::CargoUnitTargetContext::BuildHost;
        let graph = HostCargoUnitGraph {
            schema: 2,
            planner: CargoUnitGraphPlannerIdentity {
                interface: "cargo-unit-graph-v1".into(),
                cargo_version: "1.97.1".into(),
                cargo_digest: "1".repeat(64),
                rustc_version: "1.97.1".into(),
                rustc_digest: "2".repeat(64),
            },
            build_triple: "build-host".into(),
            composition_target: "test-target".into(),
            profile: "debug".into(),
            nodes: [&host_selector, &target_selector]
                .into_iter()
                .map(|selector| CargoUnit {
                    selector: selector.clone(),
                    features: vec![],
                    build_script: false,
                    proc_macro: false,
                })
                .collect(),
            edges: vec![],
        }
        .normalize()
        .unwrap();
        let target = json!({
            "kind": ["lib"],
            "crate_types": ["lib"],
            "name": "fixture",
            "src_path": "/rust-agent/closure/fixture/src/lib.rs",
            "edition": "2024",
            "doc": true,
            "doctest": true,
            "test": true
        });
        let artifact = |filename: &str| {
            json!({
                "reason": "compiler-artifact",
                "package_id": "path+file:///rust-agent/closure/fixture#fixture@1.0.0",
                "manifest_path": "/rust-agent/closure/fixture/Cargo.toml",
                "target": target,
                "profile": {
                    "opt_level": "0",
                    "debuginfo": 2,
                    "debug_assertions": true,
                    "overflow_checks": true,
                    "test": false
                },
                "features": [],
                "filenames": [filename],
                "executable": null,
                "fresh": false
            })
        };
        let compiler_message = json!({
            "reason": "compiler-message",
            "package_id": "path+file:///rust-agent/closure/fixture#fixture@1.0.0",
            "manifest_path": "/rust-agent/closure/fixture/Cargo.toml",
            "target": target,
            "message": {}
        });
        let host_file = "/rust-agent/target/debug/deps/libfixture-host.rlib";
        let target_file = "/rust-agent/target/test-target/debug/deps/libfixture-target.rlib";
        let observation = verify_cargo_messages(
            &messages(&[
                compiler_message,
                artifact(host_file),
                artifact(target_file),
                json!({"reason":"build-finished","success":true}),
            ]),
            &graph,
            &[],
        )
        .unwrap();
        assert_eq!(
            observation.artifact_files[host_file].compilation_kind,
            CargoCompilationKind::BuildHost
        );
        assert_eq!(
            observation.artifact_files[target_file].compilation_kind,
            CargoCompilationKind::Target
        );

        for invalid_target_files in [
            vec!["/rust-agent/target/other-target/debug/deps/libfixture.rlib"],
            vec![host_file, target_file],
        ] {
            let mut invalid_target = artifact(target_file);
            invalid_target["filenames"] = json!(invalid_target_files);
            assert!(matches!(
                verify_cargo_messages(
                    &messages(&[
                        artifact(host_file),
                        invalid_target,
                        json!({"reason":"build-finished","success":true}),
                    ]),
                    &graph,
                    &[],
                ),
                Err(TrustedCargoBuildError::InvalidCargoMessages)
            ));
        }
    }

    #[test]
    fn build_script_out_dirs_distinguish_host_and_target_contexts() {
        let mut host_selector = selector("fixture");
        host_selector.compilation_kind = CargoCompilationKind::BuildHost;
        host_selector.compilation_target = "build-host".into();
        host_selector.cargo_target_context = crate::CargoUnitTargetContext::BuildHost;
        host_selector.compile_mode = CargoCompileMode::RunCustomBuild;
        host_selector.crate_kind = CargoCrateKind::CustomBuild;
        let mut target_selector = host_selector.clone();
        target_selector.cargo_target_context = crate::CargoUnitTargetContext::CompositionTarget;
        let graph = HostCargoUnitGraph {
            schema: 2,
            planner: CargoUnitGraphPlannerIdentity {
                interface: "cargo-unit-graph-v1".into(),
                cargo_version: "1.97.1".into(),
                cargo_digest: "1".repeat(64),
                rustc_version: "1.97.1".into(),
                rustc_digest: "2".repeat(64),
            },
            build_triple: "build-host".into(),
            composition_target: "test-target".into(),
            profile: "debug".into(),
            nodes: [&host_selector, &target_selector]
                .into_iter()
                .map(|selector| CargoUnit {
                    selector: selector.clone(),
                    features: vec![],
                    build_script: true,
                    proc_macro: false,
                })
                .collect(),
            edges: vec![],
        }
        .normalize()
        .unwrap();
        let message = |out_dir: &str| {
            json!({
                "reason": "build-script-executed",
                "package_id": "path+file:///rust-agent/closure/fixture#fixture@1.0.0",
                "linked_libs": [],
                "linked_paths": [],
                "cfgs": [],
                "env": [],
                "out_dir": out_dir
            })
        };
        let host_out = "/rust-agent/target/debug/build/fixture-host/out";
        let target_out = "/rust-agent/target/test-target/debug/build/fixture-target/out";
        let mut observed = BTreeSet::new();
        verify_build_script_message(
            message(host_out).as_object().unwrap(),
            &graph,
            &mut observed,
        )
        .unwrap();
        verify_build_script_message(
            message(target_out).as_object().unwrap(),
            &graph,
            &mut observed,
        )
        .unwrap();
        assert_eq!(observed, BTreeSet::from([host_selector, target_selector]));

        for invalid in [
            "/rust-agent/target/other-target/debug/build/fixture/out",
            "/rust-agent/target/debug/../test-target/debug/build/fixture/out",
        ] {
            assert!(matches!(
                verify_build_script_message(
                    message(invalid).as_object().unwrap(),
                    &graph,
                    &mut BTreeSet::new(),
                ),
                Err(TrustedCargoBuildError::InvalidCargoMessages)
            ));
        }
        assert!(matches!(
            verify_build_script_message(
                message(host_out).as_object().unwrap(),
                &graph,
                &mut observed,
            ),
            Err(TrustedCargoBuildError::InvalidCargoMessages)
        ));
    }

    #[test]
    fn path_package_source_roots_are_bound_to_the_matching_closure_tree_digest() {
        let tree_digest = "7".repeat(64);
        let items = vec![
            crate::NormalizedHostBuildClosureItem {
                role: HostBuildClosureItemRole::HostPackageTree,
                id: "host-tree".into(),
                logical_path: "/rust-agent/closure/trees/host-fixture".into(),
                metadata_contract: crate::CanonicalSnapshotMetadataContract::ReadOnlyEpochV1,
                content: HostBuildClosureContent::SnapshotTree {
                    tree_digest: tree_digest.clone(),
                },
                digest: "8".repeat(64),
            },
            crate::NormalizedHostBuildClosureItem {
                role: HostBuildClosureItemRole::PathPackageTree,
                id: "other-tree".into(),
                logical_path: "/rust-agent/closure/trees/other".into(),
                metadata_contract: crate::CanonicalSnapshotMetadataContract::ReadOnlyEpochV1,
                content: HostBuildClosureContent::SnapshotTree {
                    tree_digest: "9".repeat(64),
                },
                digest: "a".repeat(64),
            },
        ];
        let mut roots = BTreeSet::from(["/rust-agent/closure/host".into()]);
        assert!(extend_verified_closure_tree_roots(&mut roots, &tree_digest, &items).unwrap());
        assert_eq!(
            roots,
            BTreeSet::from([
                "/rust-agent/closure/host".into(),
                "/rust-agent/closure/trees/host-fixture".into(),
            ])
        );

        let mut unmatched = BTreeSet::new();
        assert!(
            !extend_verified_closure_tree_roots(&mut unmatched, &"b".repeat(64), &items).unwrap()
        );
        assert!(unmatched.is_empty());

        let mut escaped = items.clone();
        escaped[0].logical_path = "/rust-agent/closure/trees/../escape".into();
        assert!(matches!(
            extend_verified_closure_tree_roots(&mut BTreeSet::new(), &tree_digest, &escaped),
            Err(TrustedCargoBuildError::InvalidCargoMessages)
        ));
    }

    #[test]
    fn failed_build_diagnostics_retain_bounded_output_tails() {
        assert_eq!(diagnostic_tail(b"short", 5), "short");
        assert_eq!(
            diagnostic_tail(b"0123456789", 4),
            "[... 6 bytes omitted ...]6789"
        );
        assert_eq!(diagnostic_tail(&[0xff, b'e'], 2), "\u{fffd}e");
        assert_eq!(
            diagnostic_head_and_tail(b"0123456789", 6),
            "012[... 4 bytes omitted ...]789"
        );

        let observation = LinuxSandboxExecutionObservation {
            schema: 1,
            request_digest: "1".repeat(64),
            backend_identity_digest: "2".repeat(64),
            landlock_policy_digest: "3".repeat(64),
            read_only_mounts: vec![],
            writable_mounts: vec![],
            canonical_metadata_roots: vec![],
            enforcements: vec![],
            executed_commands: vec![crate::SeccompExecutedCommand {
                executable: LOGICAL_CARGO.into(),
                arguments: vec![LOGICAL_CARGO.into()],
                working_directory: "/rust-agent/closure".into(),
                executable_sha256: "4".repeat(64),
            }],
            exit_code: 0,
            stdout_sha256: "5".repeat(64),
            stderr_sha256: "6".repeat(64),
            digest: "7".repeat(64),
        };
        let TrustedCargoBuildError::UnitObservationOutput { diagnostic } =
            unit_observation_stage_error("exact-stage", &observation, &graph(false))
        else {
            panic!("stage diagnostics must retain the unit-observation error class");
        };
        assert!(diagnostic.starts_with("stage=exact-stage execution-count=1 "));
        assert!(diagnostic.contains(&format!("\"{LOGICAL_CARGO}\": 1")));
    }

    #[test]
    fn extern_edges_require_exact_equality() {
        let graph = graph(true);
        let dependent = graph
            .nodes()
            .keys()
            .find(|selector| selector.package.name == "fixture")
            .unwrap();
        let dependency = graph
            .nodes()
            .keys()
            .find(|selector| selector.package.name == "dependency")
            .unwrap()
            .clone();
        let dependency_path = "/rust-agent/target/test-target/debug/libdependency.rlib";
        let artifact_files = BTreeMap::from([(dependency_path.into(), dependency)]);
        verify_extern_edges(
            &graph,
            dependent,
            &BTreeMap::from([("dependency".into(), dependency_path.into())]),
            &artifact_files,
        )
        .unwrap();
        assert!(matches!(
            verify_extern_edges(
                &graph,
                dependent,
                &BTreeMap::from([
                    ("dependency".into(), dependency_path.into()),
                    ("unplanned".into(), dependency_path.into()),
                ]),
                &artifact_files,
            ),
            Err(TrustedCargoBuildError::UnitObservationMismatch)
        ));
        assert!(matches!(
            verify_extern_edges(&graph, dependent, &BTreeMap::new(), &artifact_files),
            Err(TrustedCargoBuildError::UnitObservationMismatch)
        ));
    }

    fn messages(values: &[serde_json::Value]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in values {
            bytes.extend(serde_json::to_vec(value).unwrap());
            bytes.push(b'\n');
        }
        bytes
    }

    fn graph(with_dependency: bool) -> NormalizedHostCargoUnitGraph {
        let fixture = selector("fixture");
        let dependency = selector("dependency");
        let mut nodes = vec![CargoUnit {
            selector: fixture.clone(),
            features: vec![],
            build_script: false,
            proc_macro: false,
        }];
        let mut edges = vec![];
        if with_dependency {
            nodes.push(CargoUnit {
                selector: dependency.clone(),
                features: vec![],
                build_script: false,
                proc_macro: false,
            });
            edges.push(CargoUnitEdge {
                dependent: fixture,
                dependency,
                dependency_kind: CargoDependencyKind::Normal,
                target_evaluation_domain: CargoTargetEvaluationDomain::Target,
            });
        }
        HostCargoUnitGraph {
            schema: 2,
            planner: CargoUnitGraphPlannerIdentity {
                interface: "cargo-unit-graph-v1".into(),
                cargo_version: "1.97.1".into(),
                cargo_digest: "1".repeat(64),
                rustc_version: "1.97.1".into(),
                rustc_digest: "2".repeat(64),
            },
            build_triple: "build-host".into(),
            composition_target: "test-target".into(),
            profile: "debug".into(),
            nodes,
            edges,
        }
        .normalize()
        .unwrap()
    }

    fn selector(name: &str) -> CargoUnitSelector {
        CargoUnitSelector {
            package: CargoPackageIdentity {
                name: name.into(),
                version: "1.0.0".into(),
                source: CargoPackageSource::Path {
                    tree_digest: "3".repeat(64),
                },
            },
            target_name: name.into(),
            compilation_kind: CargoCompilationKind::Target,
            compilation_target: "test-target".into(),
            cargo_target_context: crate::CargoUnitTargetContext::CompositionTarget,
            compile_mode: CargoCompileMode::Build,
            profile: "debug".into(),
            crate_kind: CargoCrateKind::Library,
        }
    }
}
