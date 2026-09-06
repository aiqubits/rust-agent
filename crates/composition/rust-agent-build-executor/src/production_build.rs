use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    CargoCompilationKind, CargoCompileMode, CargoCrateKind, CargoPlannerError, CargoUnitGraphError,
    LinuxSandboxAnonymousSocketpair, LinuxSandboxCommand, LinuxSandboxError,
    LinuxSandboxExecutionObservation, LinuxSandboxNetworkPolicy, LinuxSandboxReadOnlyMount,
    LinuxSandboxWritableMount, NormalizedCargoPlannerRequest, NormalizedHostBuildInputClosure,
    NormalizedHostCargoUnitGraph, NormalizedProductionBuildPolicy, ProductionBuildPolicyError,
    ProductionCargoInvocationIdentity, ProductionInputFileRole, ProductionInputIdentityError,
    ProductionInputPreflightScope, VerifiedCargoFetchCache, VerifiedHostClosureSnapshot,
    VerifiedLinuxSandboxBackend, VerifiedProductionInputs,
    production_policy::cargo_driver_environment, snapshot_materializer::AnchoredFileIdentity,
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
    #[error("trusted Cargo build emitted malformed or incomplete JSON messages")]
    InvalidCargoMessages,
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
    let cargo_messages = verify_cargo_messages(
        execution.stdout(),
        planned_graph,
        &cache.manifest().packages,
    )?;
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
    )?;
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

fn verify_cargo_messages(
    stdout: &[u8],
    planned: &NormalizedHostCargoUnitGraph,
    cache_packages: &[crate::CargoFetchCachePackageLocation],
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
    for line in stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
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
        match reason {
            "compiler-artifact" => verify_compiler_artifact(
                object,
                planned,
                cache_packages,
                &mut artifacts,
                &mut filenames,
                &mut artifact_files,
                &mut artifact_executables,
            )?,
            "compiler-message" => verify_compiler_message(object, planned, cache_packages)?,
            "build-script-executed" => {
                verify_build_script_message(object, planned, &mut build_scripts)?;
            }
            "build-finished" => {
                require_exact_keys(object, &["reason", "success"])?;
                if object.get("success").and_then(serde_json::Value::as_bool) != Some(true) {
                    return Err(TrustedCargoBuildError::InvalidCargoMessages);
                }
                finished = true;
            }
            _ => return Err(TrustedCargoBuildError::InvalidCargoMessages),
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
    planned: &NormalizedHostCargoUnitGraph,
    cache_packages: &[crate::CargoFetchCachePackageLocation],
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
    let (selector, package_root) = match_message_selector(object, planned, cache_packages)?;
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
    verify_message_target(object.get("target"), &selector, &package_root)?;
    verify_message_profile(object.get("profile"))
}

fn verify_compiler_message(
    object: &serde_json::Map<String, serde_json::Value>,
    planned: &NormalizedHostCargoUnitGraph,
    cache_packages: &[crate::CargoFetchCachePackageLocation],
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
    let matches = planned
        .nodes()
        .keys()
        .filter(|selector| {
            selector.compile_mode != CargoCompileMode::RunCustomBuild
                && selector.target_name == target_name
                && package_id_matches(package_id, &selector.package)
        })
        .cloned()
        .collect::<Vec<_>>();
    let [selector] = matches.as_slice() else {
        return Err(TrustedCargoBuildError::InvalidCargoMessages);
    };
    let package_root =
        verified_package_root(package_id, manifest_path, &selector.package, cache_packages)?;
    verify_message_target(object.get("target"), selector, &package_root)?;
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

fn match_message_selector(
    object: &serde_json::Map<String, serde_json::Value>,
    planned: &NormalizedHostCargoUnitGraph,
    cache_packages: &[crate::CargoFetchCachePackageLocation],
) -> Result<(crate::CargoUnitSelector, String), TrustedCargoBuildError> {
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
    let matches = planned
        .nodes()
        .iter()
        .filter(|(selector, unit)| {
            selector.compile_mode != CargoCompileMode::RunCustomBuild
                && selector.target_name == target_name
                && package_id_matches(package_id, &selector.package)
                && unit.features == features
        })
        .map(|(selector, _)| selector.clone())
        .collect::<Vec<_>>();
    let [selector] = matches.as_slice() else {
        return Err(TrustedCargoBuildError::InvalidCargoMessages);
    };
    let package_root =
        verified_package_root(package_id, manifest_path, &selector.package, cache_packages)?;
    Ok((selector.clone(), package_root))
}

fn verify_message_target(
    value: Option<&serde_json::Value>,
    selector: &crate::CargoUnitSelector,
    package_root: &str,
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
    if target.keys().any(|key| !allowed.contains(&key.as_str()))
        || target.keys().any(|key| key == "required_features")
        || message_text(target, "name")? != selector.target_name
        || !logical_descendant(message_text(target, "src_path")?, package_root)
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
    let expected_kind = match selector.crate_kind {
        CargoCrateKind::Library => "lib",
        CargoCrateKind::ProcMacro => "proc-macro",
        CargoCrateKind::Binary => "bin",
        CargoCrateKind::Example => "example",
        CargoCrateKind::Test => "test",
        CargoCrateKind::Bench => "bench",
        CargoCrateKind::CustomBuild => "custom-build",
    };
    require_bounded_strings(target.get("kind"), 16, |kind| kind == expected_kind)?;
    require_bounded_strings(target.get("crate_types"), 16, |_| true)
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
        return Err(TrustedCargoBuildError::UnitObservationMismatch);
    };
    let expected_root_arguments = std::iter::once(LOGICAL_CARGO.into())
        .chain(root_arguments.iter().cloned())
        .collect::<Vec<_>>();
    if root.executable != LOGICAL_CARGO
        || root.executable_sha256 != cargo_digest
        || root.arguments != expected_root_arguments
        || root.working_directory != request.invocation().working_directory
    {
        return Err(TrustedCargoBuildError::UnitObservationMismatch);
    }

    let mut observed_compile_units = BTreeSet::new();
    let mut observed_build_scripts = BTreeSet::new();
    let mut expected_target_linker_executions = 0usize;
    let mut observed_target_linker_executions = 0usize;
    for execution in descendants {
        if execution.executable == LOGICAL_RUSTC && execution.executable_sha256 == rustc_digest {
            let arguments = execution
                .arguments
                .strip_prefix(&[LOGICAL_RUSTC.into()])
                .ok_or(TrustedCargoBuildError::UnitObservationMismatch)?;
            if build_rustc_query_allowed(request, arguments, build_policy.host_linker_selected) {
                continue;
            }
            let rustc = RustcInvocation::parse(arguments, build_policy.host_linker_selected)?;
            expected_target_linker_executions = expected_target_linker_executions
                .checked_add(usize::from(
                    build_policy.target_linker.is_some() && rustc.requires_target_linker(),
                ))
                .ok_or(TrustedCargoBuildError::UnitObservationMismatch)?;
            let matches = planned
                .nodes()
                .iter()
                .filter(|(selector, unit)| rustc.matches(selector, unit, planned))
                .map(|(selector, _)| selector.clone())
                .collect::<Vec<_>>();
            let [selector] = matches.as_slice() else {
                return Err(TrustedCargoBuildError::UnitObservationMismatch);
            };
            if !observed_compile_units.insert(selector.clone()) {
                return Err(TrustedCargoBuildError::UnitObservationMismatch);
            }
            verify_extern_edges(
                planned,
                selector,
                &rustc.externs,
                &cargo_messages.artifact_files,
            )?;
        } else if execution
            .executable
            .starts_with(&format!("{LOGICAL_TARGET}/"))
        {
            let matches = cargo_messages
                .build_script_executables
                .iter()
                .filter(|(_, executable)| executable.as_str() == execution.executable)
                .map(|(selector, _)| selector.clone())
                .collect::<Vec<_>>();
            let [selector] = matches.as_slice() else {
                return Err(TrustedCargoBuildError::UnitObservationMismatch);
            };
            if !observed_build_scripts.insert(selector.clone()) {
                return Err(TrustedCargoBuildError::UnitObservationMismatch);
            }
        } else if build_policy.target_linker.is_some_and(|(logical, digest)| {
            execution.executable == logical && execution.executable_sha256 == digest
        }) {
            observed_target_linker_executions = observed_target_linker_executions
                .checked_add(1)
                .ok_or(TrustedCargoBuildError::UnitObservationMismatch)?;
        } else if build_policy
            .executable_digests
            .get(execution.executable.as_str())
            .is_none_or(|digest| **digest != execution.executable_sha256)
        {
            return Err(TrustedCargoBuildError::UnitObservationMismatch);
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
    )?;
    if observed_compile_units != expected_compile_units
        || observed_build_scripts != expected_build_scripts
    {
        return Err(TrustedCargoBuildError::UnitObservationMismatch);
    }
    Ok(())
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
    fn failed_build_diagnostics_retain_bounded_output_tails() {
        assert_eq!(diagnostic_tail(b"short", 5), "short");
        assert_eq!(
            diagnostic_tail(b"0123456789", 4),
            "[... 6 bytes omitted ...]6789"
        );
        assert_eq!(diagnostic_tail(&[0xff, b'e'], 2), "\u{fffd}e");
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
