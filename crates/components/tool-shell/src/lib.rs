//! Provider-neutral shell Tool built only from the typed shell capability.

use std::{
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::Arc,
};

use rust_agent_fs::{AgentPath, MAX_AGENT_PATH_BYTES};
use rust_agent_policy::process::{
    FilesystemAccess, NetworkAccess, ProcessResourceLimits, SandboxPolicy,
};
use rust_agent_process::{
    MAX_SHELL_COMMAND_BYTES, ProcessEnvironment, ProcessError, ProcessExit, ShellBinding,
    ShellError, ShellRequest, ShellResult,
};
use rust_agent_runtime_api::{
    CancellationToken, ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings,
};
use rust_agent_tools::{
    ExecutionPermit, Tool, ToolCallPolicy, ToolConcurrencyRule, ToolContext, ToolContribution,
    ToolDefinition, ToolError, ToolFuture, ToolRegistration, ToolRegistrationSnapshot, ToolSafety,
    ToolValue,
};
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

pub const SHELL_MAX_TIMEOUT_SECONDS: u64 = 600;
pub const SHELL_CAPTURE_MAX_BYTES: usize = 256 * 1024;
pub const SHELL_DISPLAY_MAX_CHARS: usize = 12_000;
const SHELL_MAX_PROCESSES: u32 = 256;
const SHELL_MAX_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const TRUNCATION_MARKER: &str = "\n...[truncated]...";

#[derive(Clone, Debug, Default)]
pub struct Config;

#[derive(Clone, Debug)]
pub struct Dependencies {
    pub shell: ShellBinding,
}

#[derive(Debug)]
pub struct ShellTools {
    shell: ShellBinding,
}

pub fn build(
    _config: &Config,
    dependencies: Dependencies,
    runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<ShellTools>, ComponentBuildError> {
    if !runtime.allowed().is_empty() {
        return Err(ComponentBuildError::InvalidConfig(
            "tool-shell declares no runtime primitives".into(),
        ));
    }
    drop(runtime);
    Ok(ComponentOutput::stateless(ShellTools {
        shell: dependencies.shell,
    }))
}

impl ToolContribution for ShellTools {
    fn snapshot(&self) -> Result<ToolRegistrationSnapshot, rust_agent_tools::ToolProviderError> {
        let registration = ToolRegistration::new(Arc::new(ShellCommandTool {
            shell: self.shell.clone(),
        }))
        .map_err(|_| rust_agent_tools::ToolProviderError::InvalidRegistration)?;
        ToolRegistrationSnapshot::new("tool-shell", NonZeroU64::MIN, vec![registration])
    }
}

#[derive(Debug)]
struct ShellCommandTool {
    shell: ShellBinding,
}

impl Tool for ShellCommandTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(
            "shell-command",
            "Run one bounded command through the selected shell capability.",
            json!({
                "type": "object",
                "properties": {
                    "command": {"type": "string", "maxLength": MAX_SHELL_COMMAND_BYTES},
                    "cwd": {"type": "string", "maxLength": MAX_AGENT_PATH_BYTES},
                    "timeout_seconds": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": SHELL_MAX_TIMEOUT_SECONDS
                    }
                },
                "required": ["command"],
                "additionalProperties": false
            }),
            ToolSafety::Mutating,
            self.shell.effects(),
            ToolCallPolicy::builder(ToolConcurrencyRule::Exclusive)
                .build()
                .expect("static shell policy is bounded"),
        )
        .expect("static shell Tool definition is valid")
    }

    fn execute<'a>(
        &'a self,
        _permit: &'a ExecutionPermit,
        context: &'a ToolContext,
        input: JsonValue,
    ) -> ToolFuture<'a, Result<ToolValue, ToolError>> {
        Box::pin(async move {
            let result = invoke(&self.shell, input, context.cancellation()).await?;
            let rendered = render(&result);
            let mut output = context.output_builder();
            output.append_text(rendered.text)?;
            output.append_structured(rendered.exit)?;
            Ok(output.build())
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShellInput {
    command: String,
    cwd: Option<String>,
    timeout_seconds: Option<u64>,
}

async fn invoke(
    shell: &ShellBinding,
    input: JsonValue,
    cancellation: CancellationToken,
) -> Result<ShellResult, ToolError> {
    if cancellation.is_cancelled() {
        return Err(ToolError::cancelled());
    }
    let input: ShellInput = serde_json::from_value(input)
        .map_err(|_| ToolError::invalid_input("invalid input shape"))?;
    let timeout_seconds = input.timeout_seconds.unwrap_or(SHELL_MAX_TIMEOUT_SECONDS);
    if !(1..=SHELL_MAX_TIMEOUT_SECONDS).contains(&timeout_seconds) {
        return Err(ToolError::invalid_input(
            "timeout_seconds is outside the shell bound",
        ));
    }
    let cwd = input.cwd.map_or_else(
        || Ok(AgentPath::root()),
        |path| AgentPath::new(path).map_err(|error| ToolError::invalid_input(error.to_string())),
    )?;
    let request = ShellRequest::checked(
        input.command,
        cwd,
        ProcessEnvironment::empty(),
        Vec::new(),
        shell_policy(timeout_seconds),
    )
    .map_err(shell_error)?;
    let spec = shell.resolve(request).map_err(shell_error)?;
    shell.run(spec, cancellation).await.map_err(shell_error)
}

fn shell_policy(timeout_seconds: u64) -> SandboxPolicy {
    let wall_millis = timeout_seconds
        .checked_mul(1_000)
        .and_then(NonZeroU64::new)
        .expect("validated shell timeout is bounded and nonzero");
    let limits = ProcessResourceLimits::checked(
        NonZeroU32::new(SHELL_MAX_PROCESSES).expect("constant is nonzero"),
        NonZeroU64::new(SHELL_MAX_MEMORY_BYTES).expect("constant is nonzero"),
        NonZeroUsize::new(SHELL_CAPTURE_MAX_BYTES).expect("constant is nonzero"),
        wall_millis,
    )
    .expect("static shell limits fit the process policy hard maxima");
    SandboxPolicy::new(FilesystemAccess::ReadWrite, NetworkAccess::Deny, limits)
}

#[derive(Debug, Eq, PartialEq)]
struct RenderedOutput {
    text: String,
    exit: JsonValue,
}

fn render(result: &ShellResult) -> RenderedOutput {
    let process = result.output();
    let mut bytes = Vec::with_capacity(process.encoded_bytes());
    bytes.extend_from_slice(process.stdout());
    bytes.extend_from_slice(process.stderr());
    let normalized = String::from_utf8_lossy(&bytes).replace("\r\n", "\n");
    let trimmed = normalized.trim();
    let text = if trimmed.is_empty() {
        "(no output)".to_owned()
    } else if trimmed.chars().count() > SHELL_DISPLAY_MAX_CHARS {
        let boundary = trimmed
            .char_indices()
            .nth(SHELL_DISPLAY_MAX_CHARS)
            .map_or(trimmed.len(), |(index, _)| index);
        let mut bounded = trimmed[..boundary].to_owned();
        bounded.push_str(TRUNCATION_MARKER);
        bounded
    } else {
        trimmed.to_owned()
    };
    let exit = match process.exit() {
        ProcessExit::Code(value) => json!({"exit": {"kind": "code", "value": value}}),
        ProcessExit::Signal(value) => json!({"exit": {"kind": "signal", "value": value}}),
    };
    RenderedOutput { text, exit }
}

fn shell_error(error: ShellError) -> ToolError {
    match error {
        ShellError::InvalidCommand | ShellError::InputTooLarge => {
            ToolError::invalid_input(error.to_string())
        }
        ShellError::Cancelled | ShellError::Process(ProcessError::Cancelled) => {
            ToolError::cancelled()
        }
        ShellError::DeadlineExceeded | ShellError::Process(ProcessError::DeadlineExceeded) => {
            ToolError::deadline_exceeded()
        }
        _ => ToolError::provider("shell", error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Waker},
    };

    use rust_agent_core::{CanonicalId, SecurityEffects};
    use rust_agent_process::{ProcessFuture, Shell, ShellProcess, ShellSpec};
    use rust_agent_tools::{ToolErrorKind, ToolValueItem};

    use super::*;

    type TestResponse = Result<(ProcessExit, Vec<u8>, Vec<u8>), ShellError>;

    #[derive(Debug)]
    struct FakeShell {
        normalize_calls: AtomicUsize,
        run_calls: AtomicUsize,
        seen: Mutex<Vec<ShellRequest>>,
        effects: SecurityEffects,
        response: Mutex<TestResponse>,
    }

    impl FakeShell {
        fn new(effects: SecurityEffects) -> Arc<Self> {
            Arc::new(Self {
                normalize_calls: AtomicUsize::new(0),
                run_calls: AtomicUsize::new(0),
                seen: Mutex::new(Vec::new()),
                effects,
                response: Mutex::new(Ok((ProcessExit::Code(0), b"ok\n".to_vec(), Vec::new()))),
            })
        }

        fn binding(self: &Arc<Self>) -> ShellBinding {
            ShellBinding::from_provider(Arc::clone(self))
        }
    }

    impl Shell for FakeShell {
        fn provider_key(&self) -> CanonicalId {
            CanonicalId::new("fake-shell").unwrap()
        }

        fn effects(&self) -> SecurityEffects {
            self.effects
        }

        fn normalize(&self, request: ShellRequest) -> Result<ShellRequest, ShellError> {
            self.normalize_calls.fetch_add(1, Ordering::SeqCst);
            Ok(request)
        }

        fn run(
            &self,
            spec: ShellSpec,
            _cancellation: CancellationToken,
        ) -> ProcessFuture<'_, Result<ShellResult, ShellError>> {
            self.run_calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().unwrap().push(spec.request().clone());
            let response = self.response.lock().unwrap().clone();
            let provider = self.provider_key();
            let budget = spec.output_budget();
            Box::pin(async move {
                let (exit, stdout, stderr) = response?;
                ShellResult::from_provider(provider, exit, stdout, stderr, budget, None)
            })
        }

        fn start(
            &self,
            _spec: ShellSpec,
            _cancellation: CancellationToken,
        ) -> ProcessFuture<'_, Result<ShellProcess, ShellError>> {
            Box::pin(async { Err(ShellError::ResolveFailed) })
        }
    }

    #[derive(Debug)]
    struct RuntimeBackend;

    impl rust_agent_runtime_api::RuntimeClock for RuntimeBackend {
        fn now(&self) -> rust_agent_runtime_api::RuntimeInstant {
            rust_agent_runtime_api::RuntimeInstant::from_monotonic_duration(
                std::time::Duration::ZERO,
            )
        }
    }

    impl rust_agent_runtime_api::RuntimeSleeper for RuntimeBackend {
        fn sleep_until(
            &self,
            _deadline: rust_agent_runtime_api::RuntimeInstant,
        ) -> rust_agent_runtime_api::RuntimeFuture<'static, ()> {
            Box::pin(async {})
        }
    }

    impl rust_agent_runtime_api::RuntimeSpawner for RuntimeBackend {
        fn spawn(
            &self,
            _owner: rust_agent_runtime_api::RuntimeTaskOwner,
            _task: rust_agent_runtime_api::RuntimeFuture<'static, ()>,
        ) -> Result<(), rust_agent_runtime_api::RuntimePrimitiveError> {
            Ok(())
        }

        fn drain(
            &self,
            _owner: rust_agent_runtime_api::RuntimeTaskOwner,
        ) -> rust_agent_runtime_api::RuntimeFuture<'static, ()> {
            Box::pin(async {})
        }
    }

    fn run<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("tool-shell future unexpectedly pending"),
        }
    }

    #[test]
    fn snapshot_has_one_exclusive_mutating_tool_with_exact_shell_effects() {
        let effects = SecurityEffects::PROCESS_EXEC
            | SecurityEffects::READ_LOCAL
            | SecurityEffects::WRITE_LOCAL;
        let shell = FakeShell::new(effects);
        let service = build(
            &Config,
            Dependencies {
                shell: shell.binding(),
            },
            RuntimePrimitiveBindings::none(),
        )
        .unwrap()
        .into_service();
        let snapshot = service.snapshot().unwrap();
        assert_eq!(snapshot.provider_id(), "tool-shell");
        assert_eq!(snapshot.registrations().len(), 1);
        let definition = snapshot.registrations()[0].definition();
        assert_eq!(definition.name(), "shell-command");
        assert_eq!(definition.static_effects(), effects);
        assert_eq!(definition.static_safety(), ToolSafety::Mutating);
        assert_eq!(
            definition.call_policy().concurrency(),
            &ToolConcurrencyRule::Exclusive
        );
        assert_eq!(definition.input_schema()["additionalProperties"], false);
        assert_eq!(
            definition.input_schema()["properties"]["timeout_seconds"]["maximum"],
            SHELL_MAX_TIMEOUT_SECONDS
        );
    }

    #[test]
    fn invocation_uses_only_the_shell_binding_and_seals_bounded_policy() {
        let shell = FakeShell::new(SecurityEffects::PROCESS_EXEC);
        let result = run(invoke(
            &shell.binding(),
            json!({"command": "printf test", "cwd": "workspace", "timeout_seconds": 17}),
            CancellationToken::new(),
        ))
        .unwrap();
        assert_eq!(result.output().stdout(), b"ok\n");
        assert_eq!(shell.normalize_calls.load(Ordering::SeqCst), 1);
        assert_eq!(shell.run_calls.load(Ordering::SeqCst), 1);
        let seen = shell.seen.lock().unwrap();
        let request = &seen[0];
        assert_eq!(request.command(), "printf test");
        assert_eq!(request.cwd().as_str(), "workspace");
        assert!(request.environment().entries().is_empty());
        assert!(request.stdin().is_empty());
        assert_eq!(request.policy().filesystem(), FilesystemAccess::ReadWrite);
        assert_eq!(request.policy().network(), NetworkAccess::Deny);
        assert_eq!(request.policy().limits().max_processes().get(), 256);
        assert_eq!(
            request.policy().limits().max_memory_bytes().get(),
            SHELL_MAX_MEMORY_BYTES
        );
        assert_eq!(
            request.policy().limits().max_output_bytes().get(),
            SHELL_CAPTURE_MAX_BYTES
        );
        assert_eq!(
            request.policy().limits().max_wall_time_millis().get(),
            17_000
        );
    }

    #[test]
    fn invalid_and_cancelled_calls_fail_before_provider_callbacks() {
        let shell = FakeShell::new(SecurityEffects::PROCESS_EXEC);
        let binding = shell.binding();
        let cases = [
            json!({"command": "ok", "unknown": true}),
            json!({"command": "ok", "cwd": "../escape"}),
            json!({"command": "ok", "timeout_seconds": 0}),
            json!({"command": "ok", "timeout_seconds": SHELL_MAX_TIMEOUT_SECONDS + 1}),
            json!({"command": ""}),
            json!({"command": "bad\0command"}),
            json!({"command": "x".repeat(MAX_SHELL_COMMAND_BYTES + 1)}),
        ];
        for input in cases {
            assert_eq!(
                run(invoke(&binding, input, CancellationToken::new()))
                    .unwrap_err()
                    .kind(),
                ToolErrorKind::InvalidInput
            );
        }
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert_eq!(
            run(invoke(
                &binding,
                json!({"command": "must-not-run"}),
                cancellation
            ))
            .unwrap_err()
            .kind(),
            ToolErrorKind::Cancelled
        );
        assert_eq!(shell.normalize_calls.load(Ordering::SeqCst), 0);
        assert_eq!(shell.run_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn rendering_is_normalized_merged_bounded_and_utf8_safe() {
        let result = ShellResult::from_provider(
            CanonicalId::new("fake-shell").unwrap(),
            ProcessExit::Signal(9),
            b"  stdout\r\n".to_vec(),
            b"stderr  ".to_vec(),
            SHELL_CAPTURE_MAX_BYTES,
            None,
        )
        .unwrap();
        assert_eq!(
            render(&result),
            RenderedOutput {
                text: "stdout\nstderr".to_owned(),
                exit: json!({"exit": {"kind": "signal", "value": 9}}),
            }
        );

        let empty = ShellResult::from_provider(
            CanonicalId::new("fake-shell").unwrap(),
            ProcessExit::Code(0),
            b" \r\n".to_vec(),
            Vec::new(),
            SHELL_CAPTURE_MAX_BYTES,
            None,
        )
        .unwrap();
        assert_eq!(render(&empty).text, "(no output)");

        let long = "界".repeat(SHELL_DISPLAY_MAX_CHARS + 1);
        let long = ShellResult::from_provider(
            CanonicalId::new("fake-shell").unwrap(),
            ProcessExit::Code(2),
            long.into_bytes(),
            Vec::new(),
            SHELL_CAPTURE_MAX_BYTES,
            None,
        )
        .unwrap();
        let rendered = render(&long);
        assert_eq!(
            rendered.text.chars().count(),
            SHELL_DISPLAY_MAX_CHARS + TRUNCATION_MARKER.chars().count()
        );
        assert!(rendered.text.ends_with(TRUNCATION_MARKER));
        assert_eq!(rendered.exit, json!({"exit": {"kind": "code", "value": 2}}));
    }

    #[test]
    fn shell_error_mapping_preserves_typed_failures_and_bounds_provider_messages() {
        assert_eq!(
            shell_error(ShellError::Cancelled).kind(),
            ToolErrorKind::Cancelled
        );
        assert_eq!(
            shell_error(ShellError::Process(ProcessError::DeadlineExceeded)).kind(),
            ToolErrorKind::DeadlineExceeded
        );
        assert_eq!(
            shell_error(ShellError::InvalidCommand).kind(),
            ToolErrorKind::InvalidInput
        );
        let provider = shell_error(ShellError::ProviderContractViolation);
        assert_eq!(provider.kind(), ToolErrorKind::Provider);
        assert_eq!(provider.category(), Some("shell"));
        assert!(provider.message().len() <= rust_agent_tools::MAX_TOOL_ERROR_MESSAGE_BYTES);

        let shell = FakeShell::new(SecurityEffects::PROCESS_EXEC);
        *shell.response.lock().unwrap() = Err(ShellError::Process(ProcessError::DeadlineExceeded));
        let error = run(invoke(
            &shell.binding(),
            json!({"command": "deadline"}),
            CancellationToken::new(),
        ))
        .unwrap_err();
        assert_eq!(error.kind(), ToolErrorKind::DeadlineExceeded);
        assert_eq!(shell.normalize_calls.load(Ordering::SeqCst), 1);
        assert_eq!(shell.run_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn factory_is_stateless_deterministic_and_runtime_exact() {
        let shell = FakeShell::new(SecurityEffects::PROCESS_EXEC);
        for _ in 0..2 {
            let output = build(
                &Config,
                Dependencies {
                    shell: shell.binding(),
                },
                RuntimePrimitiveBindings::none(),
            )
            .unwrap();
            assert!(output.initializer().is_none());
            assert!(output.shutdown_hook().is_none());
        }

        let backend = Arc::new(RuntimeBackend);
        let primitives = rust_agent_runtime_api::RuntimePrimitives::from_adapter(
            rust_agent_runtime_api::RuntimeAdapterIdentity::checked("tool-shell-test").unwrap(),
            Arc::clone(&backend),
            backend.clone(),
            backend.clone(),
            backend,
        );
        let projected = RuntimePrimitiveBindings::projected(
            primitives,
            &[rust_agent_runtime_api::RuntimePrimitiveKind::Clock],
        )
        .unwrap();
        assert!(matches!(
            build(
                &Config,
                Dependencies {
                    shell: shell.binding(),
                },
                projected,
            ),
            Err(ComponentBuildError::InvalidConfig(_))
        ));
    }

    #[test]
    fn tool_output_shape_contains_text_then_structured_exit() {
        let result = ShellResult::from_provider(
            CanonicalId::new("fake-shell").unwrap(),
            ProcessExit::Code(0),
            b"done".to_vec(),
            Vec::new(),
            SHELL_CAPTURE_MAX_BYTES,
            None,
        )
        .unwrap();
        let rendered = render(&result);
        let items = [
            ToolValueItem::Text(rendered.text),
            ToolValueItem::Structured(rendered.exit),
        ];
        assert!(matches!(&items[0], ToolValueItem::Text(text) if text == "done"));
        assert!(matches!(
            &items[1],
            ToolValueItem::Structured(value) if value == &json!({"exit": {"kind": "code", "value": 0}})
        ));
    }
}
