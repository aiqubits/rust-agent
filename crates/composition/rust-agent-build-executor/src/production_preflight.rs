use std::{collections::BTreeMap, str};

use thiserror::Error;

use crate::{
    LinuxSandboxCommand, LinuxSandboxError, LinuxSandboxExecutionObservation,
    LinuxSandboxNetworkPolicy, LinuxSandboxReadOnlyMount, NormalizedHostBuildInputClosure,
    ProductionInputFile, ProductionInputFileRole, ProductionInputIdentityError,
    ProductionInputIdentityObservation, ProductionInputPreflightScope,
    ProductionTargetFactsProbeObservation, ProductionVersionProbeResult,
    SnapshotMaterializationError, ValidatedProductionInputIdentityObservation,
    ValidatedProductionTargetFactsProbeObservation, VerifiedHostClosureSnapshot,
    VerifiedLinuxSandboxBackend, VerifiedProductionInputs,
    production_inputs::target_facts_from_probe,
};

const PREFLIGHT_TIMEOUT_MILLISECONDS: u64 = 30_000;
const LOGICAL_RUSTC: &str = "/rust-agent/toolchain/bin/rustc";
const LOGICAL_EMPTY_HOME: &str = "/rust-agent/empty-home";

#[derive(Debug)]
pub struct TrustedProductionPreflightEvidence {
    version_sandbox_observations: Vec<LinuxSandboxExecutionObservation>,
    version_observation: ProductionInputIdentityObservation,
    validated_version_observation: ValidatedProductionInputIdentityObservation,
    target_facts_sandbox_observation: LinuxSandboxExecutionObservation,
    target_facts_observation: ProductionTargetFactsProbeObservation,
    validated_target_facts_observation: ValidatedProductionTargetFactsProbeObservation,
}

#[derive(Debug, Error)]
pub enum TrustedProductionPreflightError {
    #[error("trusted production preflight requires exact Build-scope inputs")]
    InputMismatch,
    #[error(
        "trusted production preflight command `{id}` failed with exit code {exit_code}: {diagnostic}"
    )]
    SandboxFailed {
        id: String,
        exit_code: i32,
        diagnostic: String,
    },
    #[error("trusted production preflight output is not UTF-8")]
    InvalidOutputEncoding,
    #[error("trusted production preflight sandbox failed: {0}")]
    Sandbox(#[from] LinuxSandboxError),
    #[error("trusted production preflight input verification failed: {0}")]
    ProductionInputs(#[from] ProductionInputIdentityError),
    #[error("trusted production preflight closure snapshot verification failed: {0}")]
    Snapshot(#[from] SnapshotMaterializationError),
}

pub fn execute_trusted_production_preflight(
    backend: &VerifiedLinuxSandboxBackend,
    inputs: &VerifiedProductionInputs,
    closure: &NormalizedHostBuildInputClosure,
    closure_snapshot: &VerifiedHostClosureSnapshot,
) -> Result<TrustedProductionPreflightEvidence, TrustedProductionPreflightError> {
    inputs.verify_unchanged()?;
    closure_snapshot.verify_unchanged()?;
    if inputs.request().scope != ProductionInputPreflightScope::Build
        || inputs.request().host_build_input_closure_digest.as_deref() != Some(closure.digest())
        || closure_snapshot.manifest().host_build_input_closure_digest != closure.digest()
    {
        return Err(TrustedProductionPreflightError::InputMismatch);
    }

    let mut version_sandbox_observations = Vec::new();
    let mut probe_results = Vec::new();
    for file in inputs.request().expected_probes() {
        let probe = file
            .version_probe
            .as_ref()
            .ok_or(TrustedProductionPreflightError::InputMismatch)?;
        let executable = logical_executable(file)?;
        let cargo_probe = file.role == ProductionInputFileRole::Cargo;
        let execution = backend.run_with_output(
            &LinuxSandboxCommand {
                schema: 3,
                executable: executable.clone(),
                arguments: probe.arguments.clone(),
                environment: if cargo_probe {
                    BTreeMap::from([("HOME".into(), LOGICAL_EMPTY_HOME.into())])
                } else {
                    BTreeMap::new()
                },
                working_directory: "/".into(),
                allowed_executables: vec![executable],
                anonymous_socketpairs: vec![],
                read_only_empty_directories: if cargo_probe {
                    vec![LOGICAL_EMPTY_HOME.into()]
                } else {
                    vec![]
                },
                network: LinuxSandboxNetworkPolicy::Isolated,
                timeout_milliseconds: PREFLIGHT_TIMEOUT_MILLISECONDS,
            },
            LinuxSandboxReadOnlyMount::production_inputs(inputs)?,
            vec![],
        )?;
        require_success(&file.id, &execution)?;
        probe_results.push(ProductionVersionProbeResult {
            role: file.role,
            id: file.id.clone(),
            executable_sha256: file.sha256.clone(),
            arguments: probe.arguments.clone(),
            exit_code: execution.observation().exit_code,
            stdout: utf8(execution.stdout())?.into(),
            stderr: utf8(execution.stderr())?.into(),
        });
        version_sandbox_observations.push(execution.observation().clone());
    }
    let version_observation =
        ProductionInputIdentityObservation::new(inputs.request().digest.clone(), probe_results)?;
    let validated_version_observation = inputs.validate_probe_observation(&version_observation)?;

    let target_request = inputs.target_facts_probe_request(closure)?;
    let target_execution = backend.run_with_output(
        &LinuxSandboxCommand {
            schema: 3,
            executable: LOGICAL_RUSTC.into(),
            arguments: target_request.arguments.clone(),
            environment: BTreeMap::new(),
            working_directory: target_request.working_directory.clone(),
            allowed_executables: vec![LOGICAL_RUSTC.into()],
            anonymous_socketpairs: vec![],
            read_only_empty_directories: vec![],
            network: LinuxSandboxNetworkPolicy::Isolated,
            timeout_milliseconds: PREFLIGHT_TIMEOUT_MILLISECONDS,
        },
        std::iter::once(LinuxSandboxReadOnlyMount::host_closure(closure_snapshot)?)
            .chain(LinuxSandboxReadOnlyMount::production_inputs(inputs)?)
            .collect(),
        vec![],
    )?;
    require_success("rustc-target-facts", &target_execution)?;
    let target_stdout = utf8(target_execution.stdout())?.to_owned();
    let target_stderr = utf8(target_execution.stderr())?.to_owned();
    let target_facts = target_facts_from_probe(&target_request, &target_stdout)?;
    let target_facts_observation = ProductionTargetFactsProbeObservation::new(
        &target_request,
        target_execution.observation().exit_code,
        target_stdout,
        target_stderr,
        target_facts,
    )?;
    let validated_target_facts_observation =
        inputs.validate_target_facts_probe_observation(closure, &target_facts_observation)?;
    inputs.verify_unchanged()?;
    closure_snapshot.verify_unchanged()?;

    Ok(TrustedProductionPreflightEvidence {
        version_sandbox_observations,
        version_observation,
        validated_version_observation,
        target_facts_sandbox_observation: target_execution.observation().clone(),
        target_facts_observation,
        validated_target_facts_observation,
    })
}

impl TrustedProductionPreflightEvidence {
    pub fn version_sandbox_observations(&self) -> &[LinuxSandboxExecutionObservation] {
        &self.version_sandbox_observations
    }

    pub fn version_observation(&self) -> &ProductionInputIdentityObservation {
        &self.version_observation
    }

    pub fn validated_version_observation(&self) -> &ValidatedProductionInputIdentityObservation {
        &self.validated_version_observation
    }

    pub fn target_facts_sandbox_observation(&self) -> &LinuxSandboxExecutionObservation {
        &self.target_facts_sandbox_observation
    }

    pub fn target_facts_observation(&self) -> &ProductionTargetFactsProbeObservation {
        &self.target_facts_observation
    }

    pub fn validated_target_facts_observation(
        &self,
    ) -> &ValidatedProductionTargetFactsProbeObservation {
        &self.validated_target_facts_observation
    }
}

fn logical_executable(
    file: &ProductionInputFile,
) -> Result<String, TrustedProductionPreflightError> {
    match file.role {
        ProductionInputFileRole::Cargo => Ok("/rust-agent/toolchain/bin/cargo".into()),
        ProductionInputFileRole::Rustc => Ok(LOGICAL_RUSTC.into()),
        ProductionInputFileRole::BuildExecutable => Ok(format!("/rust-agent/tools/{}", file.id)),
        ProductionInputFileRole::CredentialHelper | ProductionInputFileRole::FetchTlsCaBundle => {
            Err(TrustedProductionPreflightError::InputMismatch)
        }
    }
}

fn require_success(
    id: &str,
    execution: &crate::LinuxSandboxCapturedExecution,
) -> Result<(), TrustedProductionPreflightError> {
    if execution.observation().exit_code == 0 {
        Ok(())
    } else {
        Err(TrustedProductionPreflightError::SandboxFailed {
            id: id.into(),
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

fn utf8(bytes: &[u8]) -> Result<&str, TrustedProductionPreflightError> {
    str::from_utf8(bytes).map_err(|_| TrustedProductionPreflightError::InvalidOutputEncoding)
}
