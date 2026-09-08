//! Bounded Agent driver that alternates proof-bound model and Tool execution steps.

use std::{collections::BTreeSet, num::NonZeroUsize};

use rust_agent_agent::{
    AgentContext, AgentDriver, AgentError, AgentFuture, AgentOutput, AgentRequest,
};
use rust_agent_core::{CallId, ContentBlock, Message, MessageRole, Usage};
use rust_agent_model::{
    MAX_MODEL_TOOLS, MAX_MODEL_VISIBLE_BYTES, ModelCallDraft, ModelParams, ModelRegistryBinding,
    ModelRequest, ModelRequestPurpose, ModelResponse, ModelToolCall, ModelToolDefinition,
};
use rust_agent_runtime_api::{
    ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings, ToolCallScopeIdentity,
};
use rust_agent_tools::{
    PreparedToolCall, StepId, ToolBatchConcurrency, ToolCallPlan, ToolDefinition,
    ToolExecutionError, ToolExecutionOutcome, ToolExecutionRequest, ToolExecutorBinding, ToolScope,
    ToolValueItem,
};
use serde_json::{Value as JsonValue, json};
use sha2::{Digest as _, Sha256};

pub const MAX_TOOL_STEPS_PER_TURN: u64 = 16;
pub const DEFAULT_TOOL_BATCH_CONCURRENCY: usize = 4;

const TOOL_CALLS_MEDIA_TYPE: &str = "application/vnd.rust-agent.model-tool-calls+json;v=1";
const TOOL_RESULTS_MEDIA_TYPE: &str = "application/vnd.rust-agent.tool-results+json;v=1";

#[derive(Clone, Debug, Default)]
pub struct Config;

#[derive(Clone, Debug)]
pub struct Dependencies {
    pub model: ModelRegistryBinding,
    pub tools: ToolExecutorBinding,
}

#[derive(Debug)]
pub struct ToolsDriver {
    model: ModelRegistryBinding,
    tools: ToolExecutorBinding,
}

#[derive(Clone, Debug)]
struct NormalizedModelCall {
    call_id: CallId,
    tool_name: String,
    arguments: JsonValue,
    provider_call_id: Option<String>,
}

impl AgentDriver for ToolsDriver {
    fn run<'a>(
        &'a self,
        context: &'a AgentContext,
        request: AgentRequest,
    ) -> AgentFuture<'a, Result<AgentOutput, AgentError>> {
        Box::pin(async move { self.run_turn(context, request).await })
    }
}

impl ToolsDriver {
    async fn run_turn(
        &self,
        context: &AgentContext,
        request: AgentRequest,
    ) -> Result<AgentOutput, AgentError> {
        let journal_scope = context.tool_call_scope_identity()?;
        if journal_scope.agent_id() != request.request_id().agent_id()
            || journal_scope.lifecycle() != request.request_id().lifecycle()
        {
            return Err(AgentError::InvalidRequest(
                "tool journal scope does not match the Agent request",
            ));
        }
        let tool_scope = ToolScope::from_journal_scope(journal_scope);
        let mut messages = vec![Message {
            role: MessageRole::User,
            content: vec![ContentBlock::Text(request.input().as_str().to_owned())],
        }];
        let mut usage = Usage::default();
        let mut linked_from = None;

        for step_ordinal in 1..=MAX_TOOL_STEPS_PER_TURN {
            let model_request_id = context.allocate_model_request()?;
            let step = StepId::new(
                model_request_id,
                std::num::NonZeroU64::new(step_ordinal).expect("Tool step ordinals start at one"),
            );
            let tool_session = self
                .tools
                .prepare_model_step(&tool_scope, step)
                .map_err(|error| map_tool_execution_error(&error))?;
            let definitions = model_definitions(&tool_session.definitions())?;
            let plan = self.model.plan_call(ModelCallDraft {
                request_id: model_request_id,
                purpose: ModelRequestPurpose::AgentTurn,
                route: request.model_route().clone(),
                request: ModelRequest {
                    messages: messages.clone(),
                    system: None,
                    tools: definitions,
                    params: ModelParams::default(),
                },
                linked_from,
            })?;
            let prepared = context.prepare_model_call(plan).await?;
            let response = context.complete_model_call(&self.model, prepared).await?;
            add_usage(&mut usage, response.usage)?;

            if response.tool_calls.is_empty() {
                return final_output(response, usage);
            }
            if step_ordinal == MAX_TOOL_STEPS_PER_TURN {
                return Err(AgentError::InvalidRequest("tool step limit exceeded"));
            }

            let normalized = normalize_model_calls(
                journal_scope,
                request.request_id(),
                step,
                &response.tool_calls,
            )?;
            let call_history = encode_json_array(
                normalized.iter().enumerate().map(|(index, call)| {
                    json!({
                        "arguments": call.arguments,
                        "call_id": encode_call_id(call.call_id),
                        "ordinal": index,
                        "provider_call_id": call.provider_call_id,
                        "tool": call.tool_name,
                    })
                }),
                MAX_MODEL_VISIBLE_BYTES,
            )?;
            let plans = plan_tool_calls(&tool_session, &normalized)?;
            let prepared_calls = seal_tool_calls(context, plans).await?;
            let batch = tool_session
                .execute_prepared_batch(
                    prepared_calls,
                    ToolBatchConcurrency::checked(
                        NonZeroUsize::new(DEFAULT_TOOL_BATCH_CONCURRENCY)
                            .expect("default Tool concurrency is nonzero"),
                    )
                    .expect("default Tool concurrency is below the hard ceiling"),
                )
                .await
                .map_err(|error| map_tool_execution_error(&error))?;
            propagate_terminal_outcome(batch.outcomes())?;
            let result_history = encode_json_array_checked(
                normalized
                    .iter()
                    .zip(batch.outcomes())
                    .map(|(call, outcome)| tool_outcome_json(call, outcome)),
                MAX_MODEL_VISIBLE_BYTES,
            )?;
            append_step_history(
                &mut messages,
                response.message,
                call_history,
                result_history,
            )?;
            linked_from = Some(model_request_id);
        }

        Err(AgentError::InvalidRequest("tool step limit exceeded"))
    }
}

pub fn build(
    _config: &Config,
    dependencies: Dependencies,
    runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<ToolsDriver>, ComponentBuildError> {
    if !runtime.allowed().is_empty() {
        return Err(ComponentBuildError::InvalidConfig(
            "driver-tools declares no runtime primitives".into(),
        ));
    }
    drop(runtime);
    Ok(ComponentOutput::stateless(ToolsDriver {
        model: dependencies.model,
        tools: dependencies.tools,
    }))
}

fn model_definitions(
    definitions: &[ToolDefinition],
) -> Result<Vec<ModelToolDefinition>, AgentError> {
    if definitions.len() > MAX_MODEL_TOOLS {
        return Err(AgentError::InvalidRequest(
            "tool definition count exceeds the model boundary",
        ));
    }
    definitions
        .iter()
        .map(|definition| {
            Ok(ModelToolDefinition {
                name: definition.name().to_owned(),
                description: definition.description().to_owned(),
                input_schema: serde_json::to_string(definition.input_schema()).map_err(|_| {
                    AgentError::InvalidRequest("tool input schema is not model-encodable")
                })?,
            })
        })
        .collect()
}

fn normalize_model_calls(
    scope: &ToolCallScopeIdentity,
    request_id: rust_agent_agent::AgentRequestId,
    step: StepId,
    calls: &[ModelToolCall],
) -> Result<Vec<NormalizedModelCall>, AgentError> {
    let mut provider_ids = BTreeSet::new();
    let mut normalized = Vec::with_capacity(calls.len());
    for (ordinal, call) in calls.iter().enumerate() {
        if let Some(provider_call_id) = call.provider_call_id()
            && !provider_ids.insert(provider_call_id.to_owned())
        {
            return Err(AgentError::InvalidRequest(
                "duplicate provider model tool call id",
            ));
        }
        let arguments: JsonValue = serde_json::from_str(call.arguments_json())
            .map_err(|_| AgentError::InvalidRequest("model tool arguments are invalid JSON"))?;
        if !arguments.is_object() {
            return Err(AgentError::InvalidRequest(
                "model tool arguments must be a JSON object",
            ));
        }
        normalized.push(NormalizedModelCall {
            call_id: normalized_call_id(scope, request_id, step, ordinal)?,
            tool_name: call.name().to_owned(),
            arguments,
            provider_call_id: call.provider_call_id().map(str::to_owned),
        });
    }
    Ok(normalized)
}

fn normalized_call_id(
    scope: &ToolCallScopeIdentity,
    request_id: rust_agent_agent::AgentRequestId,
    step: StepId,
    ordinal: usize,
) -> Result<CallId, AgentError> {
    let ordinal = u64::try_from(ordinal)
        .map_err(|_| AgentError::InvalidRequest("tool call ordinal overflowed"))?;
    let mut hasher = Sha256::new();
    append_hash_field(&mut hasher, b"rust-agent-normalized-tool-call-v1\0");
    append_hash_field(&mut hasher, scope.composition().digest().as_bytes());
    append_hash_field(&mut hasher, &request_id.agent_id().to_canonical_v1_bytes());
    append_hash_field(&mut hasher, &request_id.lifecycle().get().to_be_bytes());
    append_hash_field(&mut hasher, &request_id.sequence().to_be_bytes());
    append_hash_field(&mut hasher, &step.request_id().to_canonical_v1_bytes());
    append_hash_field(&mut hasher, &step.ordinal().to_be_bytes());
    append_hash_field(&mut hasher, &ordinal.to_be_bytes());
    let digest = hasher.finalize();
    let mut value = [0_u8; 16];
    value.copy_from_slice(&digest[..16]);
    CallId::from_nonzero_u128(u128::from_be_bytes(value))
        .map_err(|_| AgentError::InvalidRequest("normalized tool call id is zero"))
}

fn append_hash_field(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("normalized call hash field fits u64");
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

fn plan_tool_calls(
    session: &rust_agent_tools::ToolExecutionSession,
    calls: &[NormalizedModelCall],
) -> Result<Vec<ToolCallPlan>, AgentError> {
    calls
        .iter()
        .map(|call| {
            let mut request = ToolExecutionRequest::new(
                call.call_id,
                call.tool_name.clone(),
                call.arguments.clone(),
            )
            .map_err(|error| map_tool_execution_error(&error))?;
            if let Some(provider_call_id) = &call.provider_call_id {
                request = request
                    .with_provider_call_id(provider_call_id.clone())
                    .map_err(|error| map_tool_execution_error(&error))?;
            }
            session
                .plan_call(request)
                .map_err(|error| map_tool_execution_error(&error))
        })
        .collect()
}

async fn seal_tool_calls(
    context: &AgentContext,
    plans: Vec<ToolCallPlan>,
) -> Result<Vec<PreparedToolCall>, AgentError> {
    let mut prepared = Vec::with_capacity(plans.len());
    for plan in plans {
        let proof = context.prepare_tool_call(plan.journal_projection()).await?;
        prepared.push(
            plan.seal(proof)
                .map_err(|error| map_tool_execution_error(&error))?,
        );
    }
    Ok(prepared)
}

fn propagate_terminal_outcome(outcomes: &[ToolExecutionOutcome]) -> Result<(), AgentError> {
    for outcome in outcomes {
        if let Err(error) = outcome.result() {
            match error {
                ToolExecutionError::Cancelled => return Err(AgentError::Cancelled),
                ToolExecutionError::DeadlineExceeded => return Err(AgentError::DeadlineExceeded),
                ToolExecutionError::Tool(error) => match error.kind() {
                    rust_agent_tools::ToolErrorKind::Cancelled => {
                        return Err(AgentError::Cancelled);
                    }
                    rust_agent_tools::ToolErrorKind::DeadlineExceeded => {
                        return Err(AgentError::DeadlineExceeded);
                    }
                    rust_agent_tools::ToolErrorKind::InvalidInput
                    | rust_agent_tools::ToolErrorKind::Output
                    | rust_agent_tools::ToolErrorKind::Provider => {}
                },
                _ => {}
            }
        }
    }
    Ok(())
}

fn tool_outcome_json(
    call: &NormalizedModelCall,
    outcome: &ToolExecutionOutcome,
) -> Result<JsonValue, AgentError> {
    if outcome.call_id() != call.call_id {
        return Err(AgentError::InvalidRequest(
            "tool executor changed model call order",
        ));
    }
    Ok(match outcome.result() {
        Ok(result) => {
            let output = result
                .value()
                .items()
                .iter()
                .map(|item| match item {
                    ToolValueItem::Text(value) => json!({"text": value, "type": "text"}),
                    ToolValueItem::Structured(value) => {
                        json!({"type": "structured", "value": value})
                    }
                    ToolValueItem::BinaryReference { reference, digest } => json!({
                        "digest": digest.to_lower_hex(),
                        "reference": reference,
                        "type": "binary-reference",
                    }),
                })
                .collect::<Vec<_>>();
            json!({
                "call_id": encode_call_id(call.call_id),
                "output": output,
                "provider_call_id": call.provider_call_id,
                "status": "ok",
                "tool": call.tool_name,
            })
        }
        Err(error) => json!({
            "call_id": encode_call_id(call.call_id),
            "error": error.to_string(),
            "provider_call_id": call.provider_call_id,
            "status": "error",
            "tool": call.tool_name,
        }),
    })
}

fn encode_json_array<I>(items: I, max_bytes: usize) -> Result<String, AgentError>
where
    I: IntoIterator<Item = JsonValue>,
{
    encode_json_array_checked(items.into_iter().map(Ok), max_bytes)
}

fn encode_json_array_checked<I>(items: I, max_bytes: usize) -> Result<String, AgentError>
where
    I: IntoIterator<Item = Result<JsonValue, AgentError>>,
{
    if max_bytes < 2 {
        return Err(AgentError::InvalidRequest(
            "model-visible Tool history exceeds its byte limit",
        ));
    }
    let mut encoded = String::from("[");
    let mut first = true;
    for item in items {
        let item = item?;
        let item = serde_json::to_string(&item)
            .map_err(|_| AgentError::InvalidRequest("Tool history is not JSON-encodable"))?;
        let separator = usize::from(!first);
        let retained = encoded
            .len()
            .checked_add(separator)
            .and_then(|bytes| bytes.checked_add(item.len()))
            .and_then(|bytes| bytes.checked_add(1))
            .ok_or(AgentError::InvalidRequest(
                "model-visible Tool history byte count overflowed",
            ))?;
        if retained > max_bytes {
            return Err(AgentError::InvalidRequest(
                "model-visible Tool history exceeds its byte limit",
            ));
        }
        if !first {
            encoded.push(',');
        }
        encoded.push_str(&item);
        first = false;
    }
    encoded.push(']');
    Ok(encoded)
}

fn append_step_history(
    messages: &mut Vec<Message>,
    mut assistant: Message,
    call_history: String,
    result_history: String,
) -> Result<(), AgentError> {
    if assistant.role != MessageRole::Assistant {
        return Err(AgentError::InvalidRequest(
            "model response role is not assistant",
        ));
    }
    assistant.content.push(ContentBlock::Structured {
        media_type: TOOL_CALLS_MEDIA_TYPE.to_owned(),
        value: call_history,
    });
    let results = Message {
        role: MessageRole::Tool,
        content: vec![ContentBlock::Structured {
            media_type: TOOL_RESULTS_MEDIA_TYPE.to_owned(),
            value: result_history,
        }],
    };
    let visible_bytes = messages
        .iter()
        .chain([&assistant, &results])
        .flat_map(|message| &message.content)
        .map(content_visible_bytes)
        .try_fold(0_usize, usize::checked_add)
        .ok_or(AgentError::InvalidRequest(
            "model-visible Tool history byte count overflowed",
        ))?;
    if visible_bytes > MAX_MODEL_VISIBLE_BYTES {
        return Err(AgentError::InvalidRequest(
            "model-visible Tool history exceeds its byte limit",
        ));
    }
    messages.push(assistant);
    messages.push(results);
    Ok(())
}

fn content_visible_bytes(content: &ContentBlock) -> usize {
    match content {
        ContentBlock::Text(value) => value.len(),
        ContentBlock::ImageReference { uri } => uri.len(),
        ContentBlock::Structured { media_type, value } => media_type.len() + value.len(),
    }
}

fn add_usage(total: &mut Usage, step: Usage) -> Result<(), AgentError> {
    total.input_tokens =
        total
            .input_tokens
            .checked_add(step.input_tokens)
            .ok_or(AgentError::InvalidRequest(
                "model input token usage overflowed",
            ))?;
    total.output_tokens =
        total
            .output_tokens
            .checked_add(step.output_tokens)
            .ok_or(AgentError::InvalidRequest(
                "model output token usage overflowed",
            ))?;
    Ok(())
}

fn final_output(response: ModelResponse, usage: Usage) -> Result<AgentOutput, AgentError> {
    let mut text = String::new();
    for block in response.message.content {
        match block {
            ContentBlock::Text(value) => text.push_str(&value),
            ContentBlock::ImageReference { .. } | ContentBlock::Structured { .. } => {
                return Err(AgentError::InvalidRequest(
                    "driver-tools expected text-only final output",
                ));
            }
        }
    }
    Ok(AgentOutput { text, usage })
}

fn encode_call_id(call_id: CallId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = call_id.to_canonical_v1_bytes();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn map_tool_execution_error(error: &ToolExecutionError) -> AgentError {
    match error {
        ToolExecutionError::Cancelled => AgentError::Cancelled,
        ToolExecutionError::DeadlineExceeded => AgentError::DeadlineExceeded,
        _ => AgentError::InvalidRequest("Tool execution failed closed"),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        future::Future,
        num::NonZeroU64,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
        thread,
        time::Duration,
    };

    use futures_core::Stream;
    use rust_agent_agent::{
        AgentDriverBinding, AgentInput, AgentOperationDraft, AgentScopeFactory, AgentSendRequest,
        AppHandle, Phase2RuntimeConfig,
    };
    use rust_agent_core::{AgentId, CompositionHash, Digest, RequestId, SecurityEffects};
    use rust_agent_model::{
        LanguageModel, ModelCallContext, ModelError, ModelEvent, ModelFuture, ModelId,
        ModelProviderBinding, ModelRegistry, ModelStream, ProviderKey,
    };
    use rust_agent_policy::{
        Action, PermissionDecision, PermissionPolicy, PermissionPolicyBinding,
    };
    use rust_agent_runtime_api::{
        AgentLifecycleNonce, AppHandoffMode, AppHandoffSeal, GeneratedModelBindingPlan,
        GeneratedToolConsumerBinding, RuntimeAdapterIdentity, RuntimeClock, RuntimeFuture,
        RuntimePrimitiveError, RuntimePrimitiveKind, RuntimePrimitives, RuntimeSleeper,
        RuntimeSpawner, RuntimeTaskOwner, begin_composition_assembly,
    };
    use rust_agent_tools::{
        Tool, ToolCallPolicy, ToolContribution, ToolError, ToolFuture, ToolRegistration,
        ToolRegistrationSnapshot, ToolSafety, ToolValue,
    };

    use super::*;

    struct ThreadWake(thread::Thread);

    impl Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }

    fn run<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
        let mut context = Context::from_waker(&waker);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => thread::park(),
            }
        }
    }

    #[derive(Debug)]
    struct TestRuntime;

    impl RuntimeClock for TestRuntime {
        fn now(&self) -> rust_agent_runtime_api::RuntimeInstant {
            rust_agent_runtime_api::RuntimeInstant::from_monotonic_duration(Duration::ZERO)
        }
    }

    impl RuntimeSleeper for TestRuntime {
        fn sleep_until(
            &self,
            _deadline: rust_agent_runtime_api::RuntimeInstant,
        ) -> RuntimeFuture<'static, ()> {
            Box::pin(async {})
        }
    }

    impl RuntimeSpawner for TestRuntime {
        fn spawn(
            &self,
            _owner: RuntimeTaskOwner,
            task: RuntimeFuture<'static, ()>,
        ) -> Result<(), RuntimePrimitiveError> {
            thread::spawn(move || run(task));
            Ok(())
        }

        fn drain(&self, _owner: RuntimeTaskOwner) -> RuntimeFuture<'static, ()> {
            Box::pin(async {})
        }
    }

    fn runtime() -> RuntimePrimitives {
        let runtime = Arc::new(TestRuntime);
        RuntimePrimitives::from_adapter(
            RuntimeAdapterIdentity::checked("driver-tools-test-runtime").unwrap(),
            Arc::clone(&runtime),
            runtime.clone(),
            runtime.clone(),
            runtime,
        )
    }

    struct TestStream(VecDeque<Result<ModelEvent, ModelError>>);

    impl Stream for TestStream {
        type Item = Result<ModelEvent, ModelError>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.0.pop_front())
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Script {
        Positive,
        DuplicateProviderId,
        InvalidJson,
        Endless,
    }

    #[derive(Debug)]
    struct ScriptedModel {
        script: Script,
        calls: AtomicUsize,
        requests: Mutex<Vec<ModelRequest>>,
    }

    impl ScriptedModel {
        fn new(script: Script) -> Self {
            Self {
                script,
                calls: AtomicUsize::new(0),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn tool_call(value: &str, provider_call_id: &str) -> ModelToolCall {
            ModelToolCall::new("echo", format!(r#"{{"value":"{value}"}}"#))
                .unwrap()
                .with_provider_call_id(provider_call_id)
                .unwrap()
        }
    }

    impl LanguageModel for ScriptedModel {
        fn provider_key(&self) -> ProviderKey {
            ProviderKey::new("scripted").unwrap()
        }

        fn model_id(&self) -> ModelId {
            ModelId::new("scripted-v1").unwrap()
        }

        fn stream(
            &self,
            _context: ModelCallContext,
            request: ModelRequest,
        ) -> ModelFuture<'_, Result<ModelStream, ModelError>> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            self.requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(request);
            let events = match (self.script, call) {
                (Script::Positive, 0) => VecDeque::from([
                    Ok(ModelEvent::ToolCall(Self::tool_call("one", "provider-1"))),
                    Ok(ModelEvent::ToolCall(Self::tool_call("two", "provider-2"))),
                    Ok(ModelEvent::Completed(Usage {
                        input_tokens: 1,
                        output_tokens: 2,
                    })),
                ]),
                (Script::Positive, _) => VecDeque::from([
                    Ok(ModelEvent::Delta("done".to_owned())),
                    Ok(ModelEvent::Completed(Usage {
                        input_tokens: 3,
                        output_tokens: 4,
                    })),
                ]),
                (Script::DuplicateProviderId, _) => VecDeque::from([
                    Ok(ModelEvent::ToolCall(Self::tool_call("one", "duplicate"))),
                    Ok(ModelEvent::ToolCall(Self::tool_call("two", "duplicate"))),
                    Ok(ModelEvent::Completed(Usage::default())),
                ]),
                (Script::InvalidJson, _) => VecDeque::from([
                    Ok(ModelEvent::ToolCall(
                        ModelToolCall::new("echo", "not-json").unwrap(),
                    )),
                    Ok(ModelEvent::Completed(Usage::default())),
                ]),
                (Script::Endless, _) => VecDeque::from([
                    Ok(ModelEvent::ToolCall(Self::tool_call("again", "endless"))),
                    Ok(ModelEvent::Completed(Usage::default())),
                ]),
            };
            Box::pin(async move { Ok(Box::pin(TestStream(events)) as ModelStream) })
        }
    }

    #[derive(Debug)]
    struct EchoTool {
        calls: Arc<AtomicUsize>,
        roots: Arc<Mutex<Vec<CallId>>>,
    }

    impl Tool for EchoTool {
        fn definition(&self) -> ToolDefinition {
            ToolDefinition::new(
                "echo",
                "echoes the checked value",
                json!({
                    "additionalProperties": false,
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                    "type": "object"
                }),
                ToolSafety::ReadOnly,
                SecurityEffects::empty(),
                ToolCallPolicy::builder(rust_agent_tools::ToolConcurrencyRule::ParallelSafe)
                    .build()
                    .unwrap(),
            )
            .unwrap()
        }

        fn execute<'a>(
            &'a self,
            _permit: &'a rust_agent_tools::ExecutionPermit,
            context: &'a rust_agent_tools::ToolContext,
            input: JsonValue,
        ) -> ToolFuture<'a, Result<ToolValue, ToolError>> {
            Box::pin(async move {
                let value = input
                    .get("value")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| ToolError::invalid_input("value must be a string"))?;
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.roots
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(context.root_call_id());
                let mut output = context.output_builder();
                output.append_text(value)?;
                Ok(output.build())
            })
        }
    }

    #[derive(Debug)]
    struct FixedContribution {
        registration: ToolRegistration,
    }

    impl ToolContribution for FixedContribution {
        fn snapshot(
            &self,
        ) -> Result<ToolRegistrationSnapshot, rust_agent_tools::ToolProviderError> {
            ToolRegistrationSnapshot::new(
                "echo-provider",
                NonZeroU64::MIN,
                vec![self.registration.clone()],
            )
        }
    }

    #[derive(Debug)]
    struct Allow;

    impl PermissionPolicy for Allow {
        fn evaluate(&self, _action: &Action) -> PermissionDecision {
            PermissionDecision::Allow
        }
    }

    #[derive(Debug)]
    struct TestScopeFactory {
        provider: rust_agent_tools::ToolProviderBinding,
    }

    impl AgentScopeFactory for TestScopeFactory {
        fn driver_component_identity(&self) -> &'static str {
            "driver-tools"
        }

        fn tool_consumer_edge(&self) -> Option<(&'static str, &'static str)> {
            Some(("driver-tools", "tool-executor-guarded"))
        }

        fn build_driver(
            &self,
            _model: ModelRegistryBinding,
            _runtime: RuntimePrimitives,
        ) -> Result<AgentDriverBinding, ComponentBuildError> {
            Err(ComponentBuildError::MissingDependency("tools"))
        }

        fn build_driver_with_tools(
            &self,
            model: ModelRegistryBinding,
            binding: Option<GeneratedToolConsumerBinding>,
            runtime: RuntimePrimitives,
        ) -> Result<AgentDriverBinding, ComponentBuildError> {
            let executor_dependencies =
                rust_agent_tools::guarded_component::Dependencies::from_generated_agent(
                    vec![self.provider.clone()],
                    PermissionPolicyBinding::from_provider(Arc::new(Allow)),
                    None,
                    Vec::new(),
                    "driver-tools",
                    binding.ok_or(ComponentBuildError::MissingDependency("tools"))?,
                )?;
            let executor = rust_agent_tools::guarded_component::build(
                &rust_agent_tools::guarded_component::Config,
                executor_dependencies,
                RuntimePrimitiveBindings::projected(
                    runtime,
                    &[RuntimePrimitiveKind::Clock, RuntimePrimitiveKind::Sleep],
                )
                .map_err(ComponentBuildError::Runtime)?,
            )?
            .into_service();
            let driver = build(
                &Config,
                Dependencies {
                    model,
                    tools: ToolExecutorBinding::from_provider(executor),
                },
                RuntimePrimitiveBindings::none(),
            )?
            .into_service();
            AgentDriverBinding::from_generated_component("driver-tools", driver)
        }
    }

    fn test_app(
        model: Arc<ScriptedModel>,
        tool_calls: Arc<AtomicUsize>,
        roots: Arc<Mutex<Vec<CallId>>>,
    ) -> AppHandle {
        let provider =
            rust_agent_tools::ToolProviderBinding::from_provider(Arc::new(FixedContribution {
                registration: ToolRegistration::new(Arc::new(EchoTool {
                    calls: tool_calls,
                    roots,
                }))
                .unwrap(),
            }));
        let model = ModelRegistry::from_compiled(
            vec![ModelProviderBinding::from_generated_component("scripted-model", model).unwrap()],
            None,
        )
        .unwrap();
        let scope_factory: Arc<dyn AgentScopeFactory> = Arc::new(TestScopeFactory { provider });
        let composition = CompositionHash::from_digest(Digest::from_bytes([17; 32]));
        let catalog = Digest::from_bytes([18; 32]);
        let plan = GeneratedModelBindingPlan::checked(
            scope_factory.driver_component_identity(),
            model.generated_provider_identities(),
            Vec::new(),
            vec![RuntimePrimitiveKind::Clock, RuntimePrimitiveKind::Sleep],
        )
        .unwrap()
        .with_tool_consumer_edge("driver-tools", "tool-executor-guarded")
        .unwrap();
        let runtime = runtime();
        let owner = runtime
            .claim_generated_composition_owner(composition, catalog, plan)
            .unwrap();
        let binding_assembly = begin_composition_assembly(owner, composition, catalog)
            .unwrap()
            .finish();
        let handoff = AppHandoffSeal::new(
            AppHandoffMode::Concurrent,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "1111111111111111111111111111111111111111111111111111111111111111",
            Vec::new(),
        )
        .unwrap();
        AppHandle::from_generated(
            composition,
            catalog,
            handoff,
            Phase2RuntimeConfig::default(),
            runtime,
            model,
            binding_assembly,
            scope_factory,
            Vec::new(),
        )
        .unwrap()
    }

    fn send_once(app: &AppHandle) -> Result<AgentOutput, AgentError> {
        let sealed = run(app.seal_agent_operation(AgentOperationDraft::sessionless())).unwrap();
        let allocated = run(app.allocate_agent_operation(sealed)).unwrap();
        let agent = run(app.create_agent(allocated.into_create_request())).unwrap();
        let request_id = agent.allocate_turn_request().unwrap();
        let result = run(agent.send(AgentSendRequest::new(
            request_id,
            AgentInput::text("use tools").unwrap(),
            Digest::from_bytes([19; 32]),
            None,
        )));
        run(agent.shutdown()).unwrap();
        result
    }

    fn structured_value(message: &Message, media_type: &str) -> JsonValue {
        let value = message
            .content
            .iter()
            .find_map(|content| match content {
                ContentBlock::Structured {
                    media_type: actual,
                    value,
                } if actual == media_type => Some(value),
                _ => None,
            })
            .expect("structured history block is present");
        serde_json::from_str(value).unwrap()
    }

    #[test]
    fn sessionless_loop_preserves_model_order_and_aggregates_usage() {
        let model = Arc::new(ScriptedModel::new(Script::Positive));
        let tool_calls = Arc::new(AtomicUsize::new(0));
        let roots = Arc::new(Mutex::new(Vec::new()));
        let app = test_app(
            Arc::clone(&model),
            Arc::clone(&tool_calls),
            Arc::clone(&roots),
        );

        let output = send_once(&app).unwrap();
        assert_eq!(output.text, "done");
        assert_eq!(
            output.usage,
            Usage {
                input_tokens: 4,
                output_tokens: 6,
            }
        );
        assert_eq!(tool_calls.load(Ordering::SeqCst), 2);
        let roots = roots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(roots.len(), 2);
        assert_ne!(roots[0], roots[1]);

        let requests = model
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].tools.len(), 1);
        assert_eq!(requests[0].tools[0].name, "echo");
        assert_eq!(requests[1].messages.len(), 3);
        assert_eq!(requests[1].messages[1].role, MessageRole::Assistant);
        assert_eq!(requests[1].messages[2].role, MessageRole::Tool);
        let calls = structured_value(&requests[1].messages[1], TOOL_CALLS_MEDIA_TYPE);
        let results = structured_value(&requests[1].messages[2], TOOL_RESULTS_MEDIA_TYPE);
        assert_eq!(calls[0]["provider_call_id"], "provider-1");
        assert_eq!(calls[1]["provider_call_id"], "provider-2");
        assert_eq!(results[0]["output"][0]["text"], "one");
        assert_eq!(results[1]["output"][0]["text"], "two");
        assert_eq!(calls[0]["call_id"], results[0]["call_id"]);
        assert_eq!(calls[1]["call_id"], results[1]["call_id"]);
        drop(requests);
        drop(roots);
        run(app.shutdown()).unwrap();
    }

    #[test]
    fn malformed_or_duplicate_model_calls_fail_before_tool_effects() {
        for (script, expected) in [
            (
                Script::DuplicateProviderId,
                "duplicate provider model tool call id",
            ),
            (Script::InvalidJson, "model tool arguments are invalid JSON"),
        ] {
            let model = Arc::new(ScriptedModel::new(script));
            let tool_calls = Arc::new(AtomicUsize::new(0));
            let app = test_app(
                Arc::clone(&model),
                Arc::clone(&tool_calls),
                Arc::new(Mutex::new(Vec::new())),
            );
            assert_eq!(send_once(&app), Err(AgentError::InvalidRequest(expected)));
            assert_eq!(model.calls.load(Ordering::SeqCst), 1);
            assert_eq!(tool_calls.load(Ordering::SeqCst), 0);
            run(app.shutdown()).unwrap();
        }
    }

    #[test]
    fn step_limit_rejects_the_last_batch_before_an_extra_side_effect() {
        let model = Arc::new(ScriptedModel::new(Script::Endless));
        let tool_calls = Arc::new(AtomicUsize::new(0));
        let app = test_app(
            Arc::clone(&model),
            Arc::clone(&tool_calls),
            Arc::new(Mutex::new(Vec::new())),
        );

        assert_eq!(
            send_once(&app),
            Err(AgentError::InvalidRequest("tool step limit exceeded"))
        );
        assert_eq!(model.calls.load(Ordering::SeqCst), 16);
        assert_eq!(tool_calls.load(Ordering::SeqCst), 15);
        run(app.shutdown()).unwrap();
    }

    #[test]
    fn json_and_usage_boundaries_fail_closed() {
        let item = json!({"value": "bounded"});
        let encoded = encode_json_array([item.clone()], MAX_MODEL_VISIBLE_BYTES).unwrap();
        assert_eq!(
            encode_json_array([item], encoded.len() - 1),
            Err(AgentError::InvalidRequest(
                "model-visible Tool history exceeds its byte limit"
            ))
        );
        let mut usage = Usage {
            input_tokens: u64::MAX,
            output_tokens: 0,
        };
        assert_eq!(
            add_usage(
                &mut usage,
                Usage {
                    input_tokens: 1,
                    output_tokens: 0,
                }
            ),
            Err(AgentError::InvalidRequest(
                "model input token usage overflowed"
            ))
        );
    }

    #[test]
    fn normalized_call_ids_are_deterministic_and_lineage_sensitive() {
        let agent_id = AgentId::from_nonzero_u128(7).unwrap();
        let lifecycle = AgentLifecycleNonce::from_nonzero(NonZeroU64::new(8).unwrap());
        let scope = ToolCallScopeIdentity::for_generated_agent(
            agent_id,
            lifecycle,
            None,
            CompositionHash::from_digest(Digest::from_bytes([9; 32])),
            Digest::from_bytes([10; 32]),
        );
        let request_id = rust_agent_agent::AgentRequestId::from_agent(
            agent_id,
            lifecycle,
            NonZeroU64::new(11).unwrap(),
        );
        let step = StepId::new(
            RequestId::from_nonzero_u128(12).unwrap(),
            NonZeroU64::new(13).unwrap(),
        );

        let first = normalized_call_id(&scope, request_id, step, 0).unwrap();
        assert_eq!(
            first,
            normalized_call_id(&scope, request_id, step, 0).unwrap()
        );
        assert_ne!(
            first,
            normalized_call_id(&scope, request_id, step, 1).unwrap()
        );

        let other_scope = ToolCallScopeIdentity::for_generated_agent(
            agent_id,
            lifecycle,
            None,
            CompositionHash::from_digest(Digest::from_bytes([14; 32])),
            Digest::from_bytes([10; 32]),
        );
        assert_ne!(
            first,
            normalized_call_id(&other_scope, request_id, step, 0).unwrap()
        );
    }
}
