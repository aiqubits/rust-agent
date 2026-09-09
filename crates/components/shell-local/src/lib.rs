//! Provider-neutral local shell adapter over the sandbox and subprocess capabilities.

use std::sync::Arc;

use rust_agent_core::{CanonicalId, SecurityEffects};
use rust_agent_process::{
    MAX_PROCESS_ARGUMENT_BYTES, ProcessExecutable, ProcessFuture, ProcessHandle, ProcessOutput,
    ProcessSpec, SandboxBinding, Shell, ShellError, ShellProcess, ShellProcessControl,
    ShellRequest, ShellResult, ShellSpec, SubprocessBinding,
};
use rust_agent_runtime_api::{
    CancellationToken, ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings,
};
use serde::Deserialize;

const PROVIDER_KEY: &str = "local";
const SHELL_COMMAND_ARGUMENT: &str = "-c";
pub const MAX_LOCAL_SHELL_COMMAND_BYTES: usize =
    MAX_PROCESS_ARGUMENT_BYTES - SHELL_COMMAND_ARGUMENT.len() - 2;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    executable: String,
}

impl Config {
    pub fn checked(executable: impl Into<String>) -> Result<Self, ComponentBuildError> {
        let config = Self {
            executable: executable.into(),
        };
        validate_config(&config)?;
        Ok(config)
    }

    pub fn executable(&self) -> &str {
        &self.executable
    }
}

#[derive(Debug)]
pub struct Dependencies {
    pub subprocess: SubprocessBinding,
    pub sandbox: SandboxBinding,
}

#[derive(Debug)]
pub struct LocalShell {
    executable: ProcessExecutable,
    subprocess: SubprocessBinding,
    sandbox: SandboxBinding,
}

impl LocalShell {
    async fn spawn(
        &self,
        spec: &ShellSpec,
        cancellation: CancellationToken,
    ) -> Result<ProcessHandle, ShellError> {
        if cancellation.is_cancelled() {
            return Err(ShellError::Cancelled);
        }
        let request = spec.request();
        let process = ProcessSpec::checked(
            self.executable.clone(),
            [
                SHELL_COMMAND_ARGUMENT.to_owned(),
                request.command().to_owned(),
            ],
            request.cwd().clone(),
            request.environment().clone(),
            request.stdin().to_vec(),
        )
        .map_err(|_| ShellError::ResolveFailed)?;
        let confined = self
            .sandbox
            .confine(process, request.policy().clone())
            .await
            .map_err(|_| ShellError::ResolveFailed)?;
        if cancellation.is_cancelled() {
            return Err(ShellError::Cancelled);
        }
        self.subprocess
            .spawn(confined, cancellation)
            .await
            .map_err(ShellError::Process)
    }
}

impl Shell for LocalShell {
    fn provider_key(&self) -> CanonicalId {
        CanonicalId::new(PROVIDER_KEY).expect("static provider key is canonical")
    }

    fn effects(&self) -> SecurityEffects {
        SecurityEffects::PROCESS_EXEC | SecurityEffects::READ_LOCAL | SecurityEffects::WRITE_LOCAL
    }

    fn normalize(&self, request: ShellRequest) -> Result<ShellRequest, ShellError> {
        if request.command().len() > MAX_LOCAL_SHELL_COMMAND_BYTES {
            Err(ShellError::InvalidCommand)
        } else {
            Ok(request)
        }
    }

    fn run(
        &self,
        spec: ShellSpec,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ShellResult, ShellError>> {
        Box::pin(async move {
            let output_budget = spec.output_budget();
            let handle = self.spawn(&spec, cancellation.clone()).await?;
            let report = handle.enforcement_report().clone();
            let output = handle
                .wait(cancellation)
                .await
                .map_err(ShellError::Process)?;
            shell_result(&output, output_budget, report)
        })
    }

    fn start(
        &self,
        spec: ShellSpec,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ShellProcess, ShellError>> {
        Box::pin(async move {
            let output_budget = spec.output_budget();
            let handle = self.spawn(&spec, cancellation).await?;
            ShellProcess::from_provider(
                provider_key(),
                output_budget,
                Arc::new(LocalShellProcess { handle }),
            )
        })
    }
}

#[derive(Debug)]
struct LocalShellProcess {
    handle: ProcessHandle,
}

impl ShellProcessControl for LocalShellProcess {
    fn wait(
        &self,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ShellResult, ShellError>> {
        let report = self.handle.enforcement_report().clone();
        let output_budget = self.handle.output_budget();
        let future = self.handle.wait(cancellation);
        Box::pin(async move {
            let output = future.await.map_err(ShellError::Process)?;
            shell_result(&output, output_budget, report)
        })
    }

    fn terminate_tree(&self) -> ProcessFuture<'_, Result<(), ShellError>> {
        let future = self.handle.terminate_tree();
        Box::pin(async move { future.await.map_err(ShellError::Process) })
    }
}

fn shell_result(
    output: &ProcessOutput,
    output_budget: usize,
    report: rust_agent_process::EnforcementReport,
) -> Result<ShellResult, ShellError> {
    ShellResult::from_provider(
        provider_key(),
        output.exit(),
        output.stdout().to_vec(),
        output.stderr().to_vec(),
        output_budget,
        Some(report),
    )
}

fn provider_key() -> CanonicalId {
    CanonicalId::new(PROVIDER_KEY).expect("static provider key is canonical")
}

pub fn build(
    config: &Config,
    dependencies: Dependencies,
    runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<LocalShell>, ComponentBuildError> {
    validate_runtime_primitives(runtime.allowed())?;
    validate_config(config)?;
    drop(runtime);
    Ok(ComponentOutput::stateless(LocalShell {
        executable: ProcessExecutable::absolute(config.executable.clone()).map_err(|_| {
            ComponentBuildError::InvalidConfig(
                "shell executable must be canonical and absolute".into(),
            )
        })?,
        subprocess: dependencies.subprocess,
        sandbox: dependencies.sandbox,
    }))
}

fn validate_config(config: &Config) -> Result<(), ComponentBuildError> {
    ProcessExecutable::absolute(config.executable.clone()).map_err(|_| {
        ComponentBuildError::InvalidConfig("shell executable must be canonical and absolute".into())
    })?;
    Ok(())
}

fn validate_runtime_primitives(
    primitives: &[rust_agent_runtime_api::RuntimePrimitiveKind],
) -> Result<(), ComponentBuildError> {
    if primitives.is_empty() {
        Ok(())
    } else {
        Err(ComponentBuildError::InvalidConfig(
            "shell-local declares no runtime primitives".into(),
        ))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
