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
const BUILD_SYSROOT_FLAG: &str = "--sysroot=/rust-agent/toolchain";
const PLANNER_TIMEOUT_MILLISECONDS: u64 = 2 * 60 * 1000;
const CHANNEL_OVERRIDE: &str = "__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS";
const HOST_LINKER_FEATURE_FLAG: &str = "-Clinker-features=-lld";

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
    let host_linker_selected = request_invokes_host_linker(request);
    execution.executable == LOGICAL_RUSTC
        && execution.executable_sha256 == rustc_digest
        && execution.working_directory == request.invocation().working_directory
        && planner_rustc_query_allowed(request, arguments, host_linker_selected)
}

fn planner_rustc_query_allowed(
    request: &NormalizedCargoPlannerRequest,
    arguments: &[String],
    host_linker_selected: bool,
) -> bool {
    normalize_configured_rustc_query(arguments, host_linker_selected)
        .is_some_and(|arguments| request.allows_rustc_query(&arguments))
}

fn normalize_configured_rustc_query(
    arguments: &[String],
    host_linker_selected: bool,
) -> Option<Vec<String>> {
    if arguments == ["-vV"] {
        return Some(arguments.to_vec());
    }
    if arguments.iter().any(|argument| argument == "-vV") {
        return None;
    }
    let is_target = option_value(arguments, "--target").is_some();
    validate_rustc_query(arguments, is_target, host_linker_selected).ok()?;
    let expected_flag = if is_target {
        Some(BUILD_SYSROOT_FLAG)
    } else if host_linker_selected {
        Some(HOST_LINKER_FEATURE_FLAG)
    } else {
        None
    };
    let mut normalized_arguments = arguments.to_vec();
    if let Some(expected_flag) = expected_flag {
        let index = normalized_arguments
            .iter()
            .position(|argument| argument == expected_flag)
            .expect("validated query contains its required scoped flag");
        normalized_arguments.remove(index);
    }
    Some(normalized_arguments)
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

fn validate_rustc_query(
    arguments: &[String],
    is_target: bool,
    host_linker_selected: bool,
) -> Result<(), TrustedCargoPlannerError> {
    let sysroot_count = arguments
        .iter()
        .filter(|argument| argument.as_str() == BUILD_SYSROOT_FLAG)
        .count();
    let alternate_sysroot = arguments.windows(2).any(|pair| pair[0] == "--sysroot")
        || arguments.iter().any(|argument| {
            argument.starts_with("--sysroot=") && argument.as_str() != BUILD_SYSROOT_FLAG
        });
    let host_linker_feature_count = arguments
        .iter()
        .filter(|argument| argument.as_str() == HOST_LINKER_FEATURE_FLAG)
        .count();
    let alternate_linker_feature = arguments.iter().any(|argument| {
        argument.starts_with("-Clinker-features") && argument.as_str() != HOST_LINKER_FEATURE_FLAG
    }) || arguments
        .windows(2)
        .any(|pair| pair[0] == "-C" && pair[1].starts_with("linker-features"));
    let expected_host_linker_feature_count = usize::from(!is_target && host_linker_selected);
    let expected_sysroot_count = usize::from(is_target);
    if alternate_sysroot
        || alternate_linker_feature
        || sysroot_count != expected_sysroot_count
        || host_linker_feature_count != expected_host_linker_feature_count
    {
        Err(TrustedCargoPlannerError::InvalidExecutionTrace)
    } else {
        Ok(())
    }
}

fn request_invokes_host_linker(request: &NormalizedCargoPlannerRequest) -> bool {
    let expected = format!(
        "host.{}.rustflags=[\"{}\"]",
        request.build_triple(),
        HOST_LINKER_FEATURE_FLAG
    );
    request
        .invocation()
        .arguments
        .windows(2)
        .any(|value| value[0] == "--config" && value[1].as_str() == expected)
}

fn option_value<'a>(arguments: &'a [String], name: &str) -> Option<&'a str> {
    let prefix = format!("{name}=");
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == name {
            if let Some(value) = arguments.get(index + 1) {
                return Some(value);
            }
            index += 2;
        } else if let Some(value) = arguments[index].strip_prefix(&prefix) {
            return Some(value);
        } else {
            index += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::fetch_runner::cargo_target_information_query;

    use super::*;

    const TARGET: &str = "aarch64-unknown-linux-gnu";

    #[test]
    fn configured_rustc_queries_are_normalized_with_scope_exact_flags() {
        assert_eq!(
            normalize_configured_rustc_query(&["-vV".into()], true),
            Some(vec!["-vV".into()])
        );

        let host_query = cargo_target_information_query(None);
        assert_eq!(
            normalize_configured_rustc_query(&host_query, false),
            Some(host_query.clone())
        );
        let mut configured_host_query = host_query.clone();
        let host_flag_index = configured_host_query
            .iter()
            .position(|argument| argument == "--crate-type")
            .unwrap();
        configured_host_query.insert(host_flag_index, HOST_LINKER_FEATURE_FLAG.into());
        assert_eq!(
            normalize_configured_rustc_query(&configured_host_query, true),
            Some(host_query)
        );

        let target_query = cargo_target_information_query(Some(TARGET));
        let mut configured_target_query = target_query.clone();
        let target_flag_index = configured_target_query
            .iter()
            .position(|argument| argument == "--target")
            .unwrap();
        configured_target_query.insert(target_flag_index, BUILD_SYSROOT_FLAG.into());
        assert_eq!(
            normalize_configured_rustc_query(&configured_target_query, true),
            Some(target_query)
        );
    }

    #[test]
    fn configured_rustc_queries_reject_missing_cross_kind_duplicate_and_alternate_flags() {
        let host_query = cargo_target_information_query(None);
        let target_query = cargo_target_information_query(Some(TARGET));
        let invalid_queries = [
            host_query.clone(),
            with_flags(&host_query, &[BUILD_SYSROOT_FLAG]),
            with_flags(
                &host_query,
                &[HOST_LINKER_FEATURE_FLAG, HOST_LINKER_FEATURE_FLAG],
            ),
            with_flags(&host_query, &["-Clinker-features=+lld"]),
            with_flags(&host_query, &["-C", "linker-features=-lld"]),
            target_query.clone(),
            with_flags(
                &target_query,
                &[HOST_LINKER_FEATURE_FLAG, BUILD_SYSROOT_FLAG],
            ),
            with_flags(&target_query, &[BUILD_SYSROOT_FLAG, BUILD_SYSROOT_FLAG]),
            with_flags(&target_query, &["--sysroot=/ambient/toolchain"]),
            with_flags(&target_query, &["--sysroot", "/rust-agent/toolchain"]),
            vec!["-vV".into(), HOST_LINKER_FEATURE_FLAG.into()],
        ];

        for arguments in invalid_queries {
            assert_eq!(normalize_configured_rustc_query(&arguments, true), None);
        }
        assert_eq!(
            normalize_configured_rustc_query(
                &with_flags(&host_query, &[HOST_LINKER_FEATURE_FLAG]),
                false,
            ),
            None
        );
    }

    fn with_flags(arguments: &[String], flags: &[&str]) -> Vec<String> {
        arguments
            .iter()
            .cloned()
            .chain(flags.iter().map(|flag| (*flag).into()))
            .collect()
    }
}
