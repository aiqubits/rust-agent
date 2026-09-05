use std::{collections::BTreeMap, path::Path};

use thiserror::Error;

use crate::{
    CargoPlannerEdgeSemantics, CargoPlannerError, CargoPlannerGraphRoot,
    CargoUnitGraphNormalizationError, LinuxSandboxAnonymousSocketpair, LinuxSandboxCommand,
    LinuxSandboxError, LinuxSandboxExecutionObservation, LinuxSandboxNetworkPolicy,
    LinuxSandboxReadOnlyMount, NormalizedCargoPlannerRequest, NormalizedHostBuildInputClosure,
    NormalizedHostCargoUnitGraph, NormalizedLockedSourceClosure, ProductionInputFileRole,
    ProductionInputIdentityError, ProductionInputPreflightScope, SeccompExecutedCommand,
    VerifiedCargoFetchCache, VerifiedCargoUnitGraphEnvelope, VerifiedHostClosureSnapshot,
    VerifiedLinuxSandboxBackend, VerifiedProductionInputs,
    derive_cargo_planner_edge_semantics_from_metadata, normalize_cargo_unit_graph,
};

const LOGICAL_CARGO: &str = "/rust-agent/toolchain/bin/cargo";
const LOGICAL_RUSTC: &str = "/rust-agent/toolchain/bin/rustc";
const LOGICAL_TARGET_DIR: &str = "/rust-agent/target";
const PLANNER_TIMEOUT_MILLISECONDS: u64 = 2 * 60 * 1000;
const CHANNEL_OVERRIDE: &str = "__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS";

#[derive(Debug)]
pub struct TrustedCargoPlannerResult {
    unit_graph_sandbox_observation: LinuxSandboxExecutionObservation,
    metadata_sandbox_observation: LinuxSandboxExecutionObservation,
    envelope: VerifiedCargoUnitGraphEnvelope,
    edge_semantics: CargoPlannerEdgeSemantics,
    graph: NormalizedHostCargoUnitGraph,
}

#[derive(Debug, Error)]
pub enum TrustedCargoPlannerError {
    #[error("trusted Cargo planner inputs do not match the normalized request")]
    InputMismatch,
    #[error("trusted Cargo planner command failed with exit code {exit_code}: {diagnostic}")]
    SandboxFailed { exit_code: i32, diagnostic: String },
    #[error("trusted Cargo planner executed a command outside its exact allowlist")]
    InvalidExecutionTrace,
    #[error("trusted Cargo planner output root was modified")]
    OutputMutation,
    #[error("trusted Cargo planner sandbox failed: {0}")]
    Sandbox(#[from] LinuxSandboxError),
    #[error("trusted Cargo planner input verification failed: {0}")]
    ProductionInputs(#[from] ProductionInputIdentityError),
    #[error("trusted Cargo planner graph verification failed: {0}")]
    Planner(#[from] CargoPlannerError),
    #[error("trusted Cargo planner normalization failed: {0}")]
    Normalization(#[from] CargoUnitGraphNormalizationError),
    #[error("trusted Cargo planner output differs from the committed Host graph: {diagnostic}")]
    PlannedGraphMismatch { diagnostic: String },
    #[error("trusted Cargo planner snapshot verification failed: {0}")]
    Snapshot(#[from] crate::SnapshotMaterializationError),
    #[error("trusted Cargo planner cache verification failed: {0}")]
    Cache(#[from] crate::CargoFetchCacheError),
    #[error("trusted Cargo planner locked-source verification failed: {0}")]
    LockedSources(#[from] crate::LockedSourceError),
}

impl TrustedCargoPlannerResult {
    pub fn unit_graph_sandbox_observation(&self) -> &LinuxSandboxExecutionObservation {
        &self.unit_graph_sandbox_observation
    }

    pub fn metadata_sandbox_observation(&self) -> &LinuxSandboxExecutionObservation {
        &self.metadata_sandbox_observation
    }

    pub fn envelope(&self) -> &VerifiedCargoUnitGraphEnvelope {
        &self.envelope
    }

    pub fn edge_semantics(&self) -> &CargoPlannerEdgeSemantics {
        &self.edge_semantics
    }

    pub fn graph(&self) -> &NormalizedHostCargoUnitGraph {
        &self.graph
    }
}

pub fn execute_trusted_cargo_planner(
    backend: &VerifiedLinuxSandboxBackend,
    request: &NormalizedCargoPlannerRequest,
    host_closure: &NormalizedHostBuildInputClosure,
    closure_snapshot: &VerifiedHostClosureSnapshot,
    locked_sources: &NormalizedLockedSourceClosure,
    cache: &VerifiedCargoFetchCache,
    production_inputs: &VerifiedProductionInputs,
) -> Result<TrustedCargoPlannerResult, TrustedCargoPlannerError> {
    verify_inputs(
        request,
        host_closure,
        closure_snapshot,
        locked_sources,
        cache,
        production_inputs,
    )?;

    let unit_graph_command = sandbox_command(
        request,
        request.invocation().arguments.clone(),
        request.invocation().environment.clone(),
    );
    let unit_graph_execution = backend.run_with_output(
        &unit_graph_command,
        read_only_mounts(closure_snapshot, cache, production_inputs)?,
        Vec::new(),
    )?;
    require_success(&unit_graph_execution)?;
    validate_execution_trace(
        request,
        production_inputs,
        unit_graph_execution.observation(),
        &unit_graph_command.arguments,
    )?;
    let envelope = request.verify_output(
        unit_graph_execution.observation().exit_code,
        unit_graph_execution.stdout(),
        unit_graph_execution.stderr(),
    )?;

    let metadata_arguments = metadata_arguments(request);
    let mut metadata_environment = request.invocation().environment.clone();
    metadata_environment.remove(CHANNEL_OVERRIDE);
    let metadata_command = sandbox_command(request, metadata_arguments, metadata_environment);
    let metadata_execution = backend.run_with_output(
        &metadata_command,
        read_only_mounts(closure_snapshot, cache, production_inputs)?,
        Vec::new(),
    )?;
    require_success(&metadata_execution)?;
    validate_execution_trace(
        request,
        production_inputs,
        metadata_execution.observation(),
        &metadata_command.arguments,
    )?;
    if !metadata_execution.stderr().is_empty() {
        return Err(TrustedCargoPlannerError::SandboxFailed {
            exit_code: metadata_execution.observation().exit_code,
            diagnostic: "Cargo metadata emitted unexpected stderr".into(),
        });
    }
    let edge_semantics = derive_cargo_planner_edge_semantics_from_metadata(
        request,
        &envelope,
        metadata_execution.stdout(),
    )?;
    let graph = normalize_cargo_unit_graph(
        request,
        &envelope,
        host_closure,
        locked_sources,
        &edge_semantics,
    )?;
    let expected_graph = match request.root() {
        CargoPlannerGraphRoot::EmittedStandalone => host_closure.standalone_unit_graph(),
        CargoPlannerGraphRoot::FinalHost => host_closure.final_unit_graph(),
    };
    if expected_graph != &graph {
        return Err(TrustedCargoPlannerError::PlannedGraphMismatch {
            diagnostic: format!(
                "expected-digest={} observed-digest={} expected={expected_graph:?} observed={graph:?}",
                expected_graph.digest(),
                graph.digest(),
            ),
        });
    }

    verify_inputs(
        request,
        host_closure,
        closure_snapshot,
        locked_sources,
        cache,
        production_inputs,
    )?;
    Ok(TrustedCargoPlannerResult {
        unit_graph_sandbox_observation: unit_graph_execution.observation().clone(),
        metadata_sandbox_observation: metadata_execution.observation().clone(),
        envelope,
        edge_semantics,
        graph,
    })
}

fn sandbox_command(
    request: &NormalizedCargoPlannerRequest,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
) -> LinuxSandboxCommand {
    LinuxSandboxCommand {
        schema: 3,
        executable: LOGICAL_CARGO.into(),
        arguments,
        environment,
        working_directory: request.invocation().working_directory.clone(),
        allowed_executables: vec![LOGICAL_CARGO.into(), LOGICAL_RUSTC.into()],
        anonymous_socketpairs: vec![LinuxSandboxAnonymousSocketpair::StreamWakeup],
        read_only_empty_directories: vec![LOGICAL_TARGET_DIR.into()],
        network: LinuxSandboxNetworkPolicy::Isolated,
        timeout_milliseconds: PLANNER_TIMEOUT_MILLISECONDS,
    }
}

fn metadata_arguments(request: &NormalizedCargoPlannerRequest) -> Vec<String> {
    vec![
        "metadata".into(),
        "--format-version".into(),
        "1".into(),
        "--manifest-path".into(),
        request.manifest_logical_path().into(),
        "--config".into(),
        request.cargo_config_logical_path().into(),
        "--locked".into(),
        "--offline".into(),
        "--filter-platform".into(),
        request.target().into(),
    ]
}

fn read_only_mounts(
    closure: &VerifiedHostClosureSnapshot,
    cache: &VerifiedCargoFetchCache,
    inputs: &VerifiedProductionInputs,
) -> Result<Vec<LinuxSandboxReadOnlyMount>, LinuxSandboxError> {
    let mut mounts = vec![
        LinuxSandboxReadOnlyMount::host_closure(closure)?,
        LinuxSandboxReadOnlyMount::cargo_cache(cache)?,
    ];
    mounts.extend(LinuxSandboxReadOnlyMount::production_inputs(inputs)?);
    Ok(mounts)
}

fn verify_inputs(
    request: &NormalizedCargoPlannerRequest,
    host_closure: &NormalizedHostBuildInputClosure,
    closure_snapshot: &VerifiedHostClosureSnapshot,
    locked_sources: &NormalizedLockedSourceClosure,
    cache: &VerifiedCargoFetchCache,
    production_inputs: &VerifiedProductionInputs,
) -> Result<(), TrustedCargoPlannerError> {
    request.verify()?;
    if request.invocation().executable != Path::new(LOGICAL_CARGO)
        || request.host_build_input_closure_digest() != host_closure.digest()
        || request.host_build_input_closure_digest()
            != closure_snapshot.manifest().host_build_input_closure_digest
        || production_inputs.request().scope != ProductionInputPreflightScope::Build
        || production_inputs
            .request()
            .host_build_input_closure_digest
            .as_deref()
            != Some(host_closure.digest())
        || production_inputs.request().build_execution_policy_digest
            != request.build_execution_policy_digest()
    {
        return Err(TrustedCargoPlannerError::InputMismatch);
    }
    locked_sources.verify_host_closure(host_closure)?;
    closure_snapshot.verify_unchanged()?;
    cache.verify_unchanged()?;
    Ok(())
}

fn require_success(
    execution: &crate::LinuxSandboxCapturedExecution,
) -> Result<(), TrustedCargoPlannerError> {
    if execution.observation().exit_code == 0 {
        Ok(())
    } else {
        Err(TrustedCargoPlannerError::SandboxFailed {
            exit_code: execution.observation().exit_code,
            diagnostic: format!(
                "stdout={} stderr={} executions={:?}",
                String::from_utf8_lossy(execution.stdout()),
                String::from_utf8_lossy(execution.stderr()),
                execution.observation().executed_commands,
            ),
        })
    }
}

fn validate_execution_trace(
    request: &NormalizedCargoPlannerRequest,
    inputs: &VerifiedProductionInputs,
    observation: &LinuxSandboxExecutionObservation,
    arguments: &[String],
) -> Result<(), TrustedCargoPlannerError> {
    let cargo_digest = input_digest(inputs, ProductionInputFileRole::Cargo)?;
    let rustc_digest = input_digest(inputs, ProductionInputFileRole::Rustc)?;
    let expected_root_arguments = std::iter::once(LOGICAL_CARGO.into())
        .chain(arguments.iter().cloned())
        .collect::<Vec<_>>();
    let [root, descendants @ ..] = observation.executed_commands.as_slice() else {
        return Err(TrustedCargoPlannerError::InvalidExecutionTrace);
    };
    if root.executable != LOGICAL_CARGO
        || root.executable_sha256 != cargo_digest
        || root.arguments != expected_root_arguments
        || root.working_directory != request.invocation().working_directory
        || descendants
            .iter()
            .any(|execution| !valid_rustc_query(request, execution, rustc_digest))
    {
        return Err(TrustedCargoPlannerError::InvalidExecutionTrace);
    }
    Ok(())
}

fn valid_rustc_query(
    request: &NormalizedCargoPlannerRequest,
    execution: &SeccompExecutedCommand,
    rustc_digest: &str,
) -> bool {
    let Some(arguments) = execution.arguments.strip_prefix(&[LOGICAL_RUSTC.into()]) else {
        return false;
    };
    execution.executable == LOGICAL_RUSTC
        && execution.executable_sha256 == rustc_digest
        && execution.working_directory == request.invocation().working_directory
        && request.allows_rustc_query(arguments)
}

fn input_digest(
    inputs: &VerifiedProductionInputs,
    role: ProductionInputFileRole,
) -> Result<&str, TrustedCargoPlannerError> {
    inputs
        .request()
        .files
        .iter()
        .find(|file| file.role == role)
        .map(|file| file.sha256.as_str())
        .ok_or(TrustedCargoPlannerError::InputMismatch)
}
