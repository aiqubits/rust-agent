//! Streaming-first model capability with a proof-gated consumer binding.

use std::{
    collections::BTreeMap,
    fmt,
    future::{Future, poll_fn},
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::Poll,
};

use futures_core::Stream;
use futures_util::StreamExt as _;
use rust_agent_core::{
    CanonicalId, ContentBlock, Digest, MaybeSendSync, Message, MessageRole, RequestId, Usage,
};
use rust_agent_runtime_api::{
    CancellationToken, ModelCallJournalProjection, ModelRequestJournalVerifier,
    RequestJournalProof, RuntimeInstant,
};
use sha2::{Digest as _, Sha256};

pub const MAX_MODEL_MESSAGES: usize = 128;
pub const MAX_MODEL_CONTENT_BLOCKS: usize = 1_024;
pub const MAX_MODEL_TOOLS: usize = 64;
pub const MAX_MODEL_VISIBLE_BYTES: usize = 256 * 1024;
pub const MAX_MODEL_OUTPUT_BYTES: usize = 256 * 1024;

#[cfg(not(target_arch = "wasm32"))]
pub type ModelFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type ModelFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

#[cfg(not(target_arch = "wasm32"))]
pub type ModelStream = Pin<Box<dyn Stream<Item = Result<ModelEvent, ModelError>> + Send + 'static>>;

#[cfg(target_arch = "wasm32")]
pub type ModelStream = Pin<Box<dyn Stream<Item = Result<ModelEvent, ModelError>> + 'static>>;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderKey(CanonicalId);

impl ProviderKey {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        CanonicalId::new(value)
            .map(Self)
            .map_err(|_| ModelError::InvalidProviderKey)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for ProviderKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ProviderKey")
            .field(&self.as_str())
            .finish()
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModelId(CanonicalId);

impl ModelId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        CanonicalId::new(value)
            .map(Self)
            .map_err(|_| ModelError::InvalidModelId)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for ModelId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ModelId")
            .field(&self.as_str())
            .finish()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModelParams {
    pub temperature_millis: Option<u16>,
    pub max_output_bytes: Option<NonZeroUsize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModelRequest {
    pub messages: Vec<Message>,
    pub system: Option<String>,
    pub tools: Vec<ModelToolDefinition>,
    pub params: ModelParams,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelResponse {
    pub message: Message,
    pub usage: Usage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelEvent {
    Delta(String),
    Completed(Usage),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelRequestPurpose {
    AgentTurn,
    SessionTitle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelRouteSelection {
    ConfiguredDefault,
    Explicit(ProviderKey),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelRoutingMode {
    Default { provider: ProviderKey },
    ExplicitPerRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelCallDraft {
    pub request_id: RequestId,
    pub purpose: ModelRequestPurpose,
    pub route: ModelRouteSelection,
    pub request: ModelRequest,
    pub linked_from: Option<RequestId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelError {
    InvalidComponentIdentity,
    InvalidProviderKey,
    InvalidModelId,
    InvalidRequest(&'static str),
    DuplicateProvider(ProviderKey),
    CompiledProviderSetMismatch,
    EmptyRegistry,
    AmbiguousModelRouting,
    ModelRouteRequired,
    UnknownProvider(ProviderKey),
    JournalProofMismatch,
    Cancelled,
    DeadlineExceeded,
    OutputBudgetExceeded,
    ProtocolViolation(&'static str),
    RuntimeUnavailable,
    Provider {
        category: &'static str,
        message: String,
    },
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidComponentIdentity => {
                formatter.write_str("invalid model provider component identity")
            }
            Self::InvalidProviderKey => formatter.write_str("invalid model provider key"),
            Self::InvalidModelId => formatter.write_str("invalid model id"),
            Self::InvalidRequest(reason) => write!(formatter, "invalid model request: {reason}"),
            Self::DuplicateProvider(key) => write!(formatter, "duplicate model provider {key:?}"),
            Self::CompiledProviderSetMismatch => {
                formatter.write_str("constructed model providers differ from the validated set")
            }
            Self::EmptyRegistry => formatter.write_str("model registry is empty"),
            Self::AmbiguousModelRouting => formatter.write_str("model routing is ambiguous"),
            Self::ModelRouteRequired => formatter.write_str("an explicit model route is required"),
            Self::UnknownProvider(key) => write!(formatter, "unknown model provider {key:?}"),
            Self::JournalProofMismatch => {
                formatter.write_str("model request journal proof mismatch")
            }
            Self::Cancelled => formatter.write_str("model request was cancelled"),
            Self::DeadlineExceeded => formatter.write_str("model request deadline exceeded"),
            Self::OutputBudgetExceeded => formatter.write_str("model output budget exceeded"),
            Self::ProtocolViolation(reason) => {
                write!(formatter, "model protocol violation: {reason}")
            }
            Self::RuntimeUnavailable => {
                formatter.write_str("required model runtime primitive is unavailable")
            }
            Self::Provider { category, message } => {
                write!(formatter, "model provider {category}: {message}")
            }
        }
    }
}

impl std::error::Error for ModelError {}

#[allow(missing_debug_implementations)]
pub struct ModelCallContext {
    proof: RequestJournalProof,
}

impl ModelCallContext {
    pub const fn request_id(&self) -> RequestId {
        self.proof.request_id()
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.proof.cancellation()
    }

    pub const fn output_budget(&self) -> NonZeroUsize {
        self.proof.output_budget()
    }

    pub const fn deadline(&self) -> Option<RuntimeInstant> {
        self.proof.deadline()
    }
}

pub trait LanguageModel: MaybeSendSync {
    fn provider_key(&self) -> ProviderKey;
    fn model_id(&self) -> ModelId;

    fn stream(
        &self,
        context: ModelCallContext,
        request: ModelRequest,
    ) -> ModelFuture<'_, Result<ModelStream, ModelError>>;

    fn complete(
        &self,
        context: ModelCallContext,
        request: ModelRequest,
    ) -> ModelFuture<'_, Result<ModelResponse, ModelError>> {
        Box::pin(async move {
            let budget = context.output_budget().get();
            let stream = self.stream(context, request).await?;
            collect_stream(stream, budget).await
        })
    }
}

#[derive(Clone)]
pub struct ModelProviderBinding {
    component: Arc<str>,
    key: ProviderKey,
    model_id: ModelId,
    provider: Arc<dyn LanguageModel>,
}

impl fmt::Debug for ModelProviderBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelProviderBinding")
            .field("component", &self.component)
            .field("key", &self.key)
            .field("model_id", &self.model_id)
            .finish_non_exhaustive()
    }
}

impl ModelProviderBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: LanguageModel + 'static,
    {
        let key = provider.provider_key();
        Self {
            component: Arc::from(key.as_str()),
            key,
            model_id: provider.model_id(),
            provider,
        }
    }

    #[doc(hidden)]
    pub fn from_generated_component<T>(
        component: impl Into<String>,
        provider: Arc<T>,
    ) -> Result<Self, ModelError>
    where
        T: LanguageModel + 'static,
    {
        let component = component.into();
        CanonicalId::new(component.clone()).map_err(|_| ModelError::InvalidComponentIdentity)?;
        Ok(Self {
            component: Arc::from(component),
            key: provider.provider_key(),
            model_id: provider.model_id(),
            provider,
        })
    }

    pub fn key(&self) -> &ProviderKey {
        &self.key
    }
}

#[derive(Clone, Debug)]
pub struct ModelRegistry {
    providers: Arc<BTreeMap<ProviderKey, ModelProviderBinding>>,
    routing: ModelRoutingMode,
}

/// Opaque result of validating generated routing before Component construction.
#[allow(missing_debug_implementations)]
pub struct ValidatedModelRouting {
    provider_keys: Arc<[ProviderKey]>,
    routing: ModelRoutingMode,
}

impl ModelRegistry {
    #[doc(hidden)]
    pub fn validate_generated_routing(
        mut provider_keys: Vec<ProviderKey>,
        routing: Option<ModelRoutingMode>,
    ) -> Result<ValidatedModelRouting, ModelError> {
        if provider_keys.is_empty() {
            return Err(ModelError::EmptyRegistry);
        }
        provider_keys.sort();
        if let Some(duplicate) = provider_keys
            .windows(2)
            .find_map(|pair| (pair[0] == pair[1]).then(|| pair[0].clone()))
        {
            return Err(ModelError::DuplicateProvider(duplicate));
        }
        let routing = match routing {
            Some(mode) => mode,
            None if provider_keys.len() == 1 => ModelRoutingMode::Default {
                provider: provider_keys[0].clone(),
            },
            None => return Err(ModelError::AmbiguousModelRouting),
        };
        if let ModelRoutingMode::Default { provider } = &routing
            && provider_keys.binary_search(provider).is_err()
        {
            return Err(ModelError::UnknownProvider(provider.clone()));
        }
        Ok(ValidatedModelRouting {
            provider_keys: provider_keys.into(),
            routing,
        })
    }

    pub fn from_compiled(
        providers: Vec<ModelProviderBinding>,
        routing: Option<ModelRoutingMode>,
    ) -> Result<Self, ModelError> {
        let mut compiled = BTreeMap::new();
        for provider in providers {
            let key = provider.key.clone();
            if compiled.insert(key.clone(), provider).is_some() {
                return Err(ModelError::DuplicateProvider(key));
            }
        }
        let validated =
            Self::validate_generated_routing(compiled.keys().cloned().collect(), routing)?;
        Ok(Self {
            providers: Arc::new(compiled),
            routing: validated.routing,
        })
    }

    #[doc(hidden)]
    pub fn from_compiled_validated(
        providers: Vec<ModelProviderBinding>,
        validated: ValidatedModelRouting,
    ) -> Result<Self, ModelError> {
        let mut compiled = BTreeMap::new();
        for provider in providers {
            let key = provider.key.clone();
            if compiled.insert(key.clone(), provider).is_some() {
                return Err(ModelError::DuplicateProvider(key));
            }
        }
        if !compiled.keys().eq(validated.provider_keys.iter()) {
            return Err(ModelError::CompiledProviderSetMismatch);
        }
        Ok(Self {
            providers: Arc::new(compiled),
            routing: validated.routing,
        })
    }

    #[doc(hidden)]
    pub fn bind_generated_scope(
        &self,
        verifier: ModelRequestJournalVerifier,
    ) -> ModelRegistryBinding {
        ModelRegistryBinding {
            providers: Arc::clone(&self.providers),
            routing: self.routing.clone(),
            verifier,
        }
    }

    pub fn provider_keys(&self) -> impl ExactSizeIterator<Item = &ProviderKey> {
        self.providers.keys()
    }

    #[doc(hidden)]
    pub fn generated_provider_keys(&self) -> Vec<Arc<str>> {
        self.providers
            .keys()
            .map(|key| Arc::<str>::from(key.as_str()))
            .collect()
    }

    #[doc(hidden)]
    pub fn generated_provider_identities(&self) -> Vec<(Arc<str>, Arc<str>)> {
        self.providers
            .values()
            .map(|provider| {
                (
                    Arc::clone(&provider.component),
                    Arc::<str>::from(provider.key.as_str()),
                )
            })
            .collect()
    }
}

#[derive(Clone)]
pub struct ModelRegistryBinding {
    providers: Arc<BTreeMap<ProviderKey, ModelProviderBinding>>,
    routing: ModelRoutingMode,
    verifier: ModelRequestJournalVerifier,
}

impl fmt::Debug for ModelRegistryBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelRegistryBinding")
            .field("provider_count", &self.providers.len())
            .field("routing", &self.routing)
            .finish_non_exhaustive()
    }
}

#[allow(missing_debug_implementations)]
pub struct ModelCallPlan {
    verifier: ModelRequestJournalVerifier,
    request_id: RequestId,
    purpose: ModelRequestPurpose,
    provider_key: ProviderKey,
    model_id: ModelId,
    materialized_request: ModelRequest,
    plan_digest: Digest,
    request_digest: Digest,
    route_digest: Digest,
    linked_from: Option<RequestId>,
}

impl ModelCallPlan {
    pub fn journal_projection(&self) -> ModelCallJournalProjection {
        ModelCallJournalProjection::from_model_plan(
            self.request_id,
            self.plan_digest,
            self.request_digest,
            self.route_digest,
        )
    }

    pub const fn record_digest(&self) -> Digest {
        self.plan_digest
    }

    pub fn output_budget(&self) -> NonZeroUsize {
        self.materialized_request
            .params
            .max_output_bytes
            .expect("planned model calls always materialize an output budget")
    }

    pub fn seal(self, proof: RequestJournalProof) -> Result<PreparedModelCall, ModelError> {
        let projection = ModelCallJournalProjection::from_model_plan(
            self.request_id,
            self.plan_digest,
            self.request_digest,
            self.route_digest,
        );
        if !self
            .verifier
            .verifies(&proof, &projection, self.plan_digest)
            || proof.output_budget() != self.output_budget()
        {
            return Err(ModelError::JournalProofMismatch);
        }
        Ok(PreparedModelCall {
            context: ModelCallContext { proof },
            request: self.materialized_request,
            provider_key: self.provider_key,
            model_id: self.model_id,
            purpose: self.purpose,
            plan_digest: self.plan_digest,
            request_digest: self.request_digest,
            route_digest: self.route_digest,
            linked_from: self.linked_from,
        })
    }
}

#[allow(missing_debug_implementations)]
pub struct PreparedModelCall {
    context: ModelCallContext,
    request: ModelRequest,
    provider_key: ProviderKey,
    model_id: ModelId,
    purpose: ModelRequestPurpose,
    plan_digest: Digest,
    request_digest: Digest,
    route_digest: Digest,
    linked_from: Option<RequestId>,
}

impl PreparedModelCall {
    pub fn output_budget(&self) -> NonZeroUsize {
        self.context.output_budget()
    }
}

impl ModelRegistryBinding {
    pub fn plan_call(&self, mut draft: ModelCallDraft) -> Result<ModelCallPlan, ModelError> {
        validate_request(&draft.request)?;
        let provider_key = match (&self.routing, draft.route) {
            (ModelRoutingMode::Default { provider }, ModelRouteSelection::ConfiguredDefault) => {
                provider.clone()
            }
            (_, ModelRouteSelection::Explicit(provider)) => provider,
            (ModelRoutingMode::ExplicitPerRequest, ModelRouteSelection::ConfiguredDefault) => {
                return Err(ModelError::ModelRouteRequired);
            }
        };
        let provider = self
            .providers
            .get(&provider_key)
            .ok_or_else(|| ModelError::UnknownProvider(provider_key.clone()))?;
        if draft.request.params.max_output_bytes.is_none() {
            draft.request.params.max_output_bytes = NonZeroUsize::new(64 * 1024);
        }
        let request_digest = hash_request(&draft.request);
        let route_digest = hash_parts(&[
            b"rust-agent-model-route-v1\0",
            provider_key.as_str().as_bytes(),
            provider.model_id.as_str().as_bytes(),
        ]);
        let purpose = match draft.purpose {
            ModelRequestPurpose::AgentTurn => b"agent-turn".as_slice(),
            ModelRequestPurpose::SessionTitle => b"session-title".as_slice(),
        };
        let mut linked = Vec::new();
        if let Some(linked_from) = draft.linked_from {
            linked.extend_from_slice(&linked_from.to_canonical_v1_bytes());
        }
        let plan_digest = hash_parts(&[
            b"rust-agent-model-plan-v1\0",
            &draft.request_id.to_canonical_v1_bytes(),
            purpose,
            request_digest.as_bytes(),
            route_digest.as_bytes(),
            &linked,
        ]);
        Ok(ModelCallPlan {
            verifier: self.verifier.clone(),
            request_id: draft.request_id,
            purpose: draft.purpose,
            provider_key,
            model_id: provider.model_id.clone(),
            materialized_request: draft.request,
            plan_digest,
            request_digest,
            route_digest,
            linked_from: draft.linked_from,
        })
    }

    pub fn stream_prepared(
        &self,
        call: PreparedModelCall,
    ) -> ModelFuture<'_, Result<ModelStream, ModelError>> {
        Box::pin(async move {
            let projection = ModelCallJournalProjection::from_model_plan(
                call.context.request_id(),
                call.plan_digest,
                call.request_digest,
                call.route_digest,
            );
            if !self
                .verifier
                .verifies(&call.context.proof, &projection, call.plan_digest)
            {
                return Err(ModelError::JournalProofMismatch);
            }
            let cancellation = call.context.cancellation();
            let deadline = call.context.deadline();
            let runtime = call.context.proof.runtime().clone();
            check_guard(&cancellation, deadline, &runtime)?;
            let provider = self
                .providers
                .get(&call.provider_key)
                .ok_or_else(|| ModelError::UnknownProvider(call.provider_key.clone()))?;
            if provider.model_id != call.model_id {
                return Err(ModelError::JournalProofMismatch);
            }
            let _ = (call.purpose, call.linked_from);
            let budget = call
                .request
                .params
                .max_output_bytes
                .expect("planned model calls always materialize an output budget")
                .get();
            if call.context.output_budget().get() != budget {
                return Err(ModelError::JournalProofMismatch);
            }
            let provider_future = provider.provider.stream(call.context, call.request);
            let stream =
                await_guarded(provider_future, cancellation.clone(), deadline, &runtime).await??;
            guarded_stream(stream, budget, cancellation, deadline, &runtime)
        })
    }

    pub fn complete_prepared(
        &self,
        call: PreparedModelCall,
    ) -> ModelFuture<'_, Result<ModelResponse, ModelError>> {
        Box::pin(async move {
            let budget = call.context.output_budget().get();
            let stream = self.stream_prepared(call).await?;
            collect_stream(stream, budget).await
        })
    }
}

fn check_guard(
    cancellation: &CancellationToken,
    deadline: Option<RuntimeInstant>,
    runtime: &rust_agent_runtime_api::RuntimePrimitives,
) -> Result<(), ModelError> {
    if cancellation.is_cancelled() {
        return Err(ModelError::Cancelled);
    }
    if let Some(deadline) = deadline
        && runtime.now().map_err(|_| ModelError::RuntimeUnavailable)? >= deadline
    {
        return Err(ModelError::DeadlineExceeded);
    }
    Ok(())
}

async fn await_guarded<F, T>(
    future: F,
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
    runtime: &rust_agent_runtime_api::RuntimePrimitives,
) -> Result<T, ModelError>
where
    F: Future<Output = T>,
{
    let mut future = std::pin::pin!(future);
    let mut cancelled = Box::pin(cancellation.cancelled());
    let mut deadline_wait = deadline
        .map(|value| runtime.sleep_until(value))
        .transpose()
        .map_err(|_| ModelError::RuntimeUnavailable)?;
    poll_fn(move |context| {
        if cancelled.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(ModelError::Cancelled));
        }
        if deadline_wait
            .as_mut()
            .is_some_and(|wait| wait.as_mut().poll(context).is_ready())
        {
            return Poll::Ready(Err(ModelError::DeadlineExceeded));
        }
        future.as_mut().poll(context).map(Ok)
    })
    .await
}

fn guarded_stream(
    source: ModelStream,
    budget: usize,
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
    runtime: &rust_agent_runtime_api::RuntimePrimitives,
) -> Result<ModelStream, ModelError> {
    let deadline_wait = deadline
        .map(|value| runtime.sleep_until(value))
        .transpose()
        .map_err(|_| ModelError::RuntimeUnavailable)?;
    let cancelled = Box::pin(cancellation.cancelled());
    Ok(Box::pin(GuardedModelStream {
        source,
        budget,
        used: 0,
        terminal: false,
        completed: false,
        cancellation,
        cancelled,
        deadline_wait,
    }))
}

struct GuardedModelStream {
    source: ModelStream,
    budget: usize,
    used: usize,
    terminal: bool,
    completed: bool,
    cancellation: CancellationToken,
    cancelled: Pin<Box<rust_agent_runtime_api::CancellationFuture>>,
    deadline_wait: Option<rust_agent_runtime_api::RuntimeFuture<'static, ()>>,
}

impl Stream for GuardedModelStream {
    type Item = Result<ModelEvent, ModelError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        if self.terminal {
            return Poll::Ready(None);
        }
        if self.cancelled.as_mut().poll(context).is_ready() || self.cancellation.is_cancelled() {
            self.terminal = true;
            return Poll::Ready(Some(Err(ModelError::Cancelled)));
        }
        if self
            .deadline_wait
            .as_mut()
            .is_some_and(|wait| wait.as_mut().poll(context).is_ready())
        {
            self.terminal = true;
            return Poll::Ready(Some(Err(ModelError::DeadlineExceeded)));
        }
        match self.source.as_mut().poll_next(context) {
            Poll::Ready(Some(Ok(ModelEvent::Delta(delta)))) => {
                if self.completed {
                    self.terminal = true;
                    return Poll::Ready(Some(Err(ModelError::ProtocolViolation(
                        "delta after completion event",
                    ))));
                }
                self.used = match self.used.checked_add(delta.len()) {
                    Some(total) if total <= self.budget => total,
                    _ => {
                        self.terminal = true;
                        return Poll::Ready(Some(Err(ModelError::OutputBudgetExceeded)));
                    }
                };
                Poll::Ready(Some(Ok(ModelEvent::Delta(delta))))
            }
            Poll::Ready(Some(Ok(ModelEvent::Completed(usage)))) => {
                if self.completed {
                    self.terminal = true;
                    Poll::Ready(Some(Err(ModelError::ProtocolViolation(
                        "multiple completion events",
                    ))))
                } else {
                    self.completed = true;
                    Poll::Ready(Some(Ok(ModelEvent::Completed(usage))))
                }
            }
            Poll::Ready(Some(Err(error))) => {
                self.terminal = true;
                if self.completed {
                    Poll::Ready(Some(Err(ModelError::ProtocolViolation(
                        "error after completion event",
                    ))))
                } else {
                    Poll::Ready(Some(Err(error)))
                }
            }
            Poll::Ready(None) if !self.completed => {
                self.terminal = true;
                Poll::Ready(Some(Err(ModelError::ProtocolViolation(
                    "stream ended before completion event",
                ))))
            }
            Poll::Ready(None) => {
                self.terminal = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub async fn collect_stream(
    stream: ModelStream,
    budget: usize,
) -> Result<ModelResponse, ModelError> {
    collect_stream_with(stream, budget, |_| {}).await
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamCollectionError<E> {
    Model(ModelError),
    Consumer(E),
}

pub async fn try_collect_stream_with<F, E>(
    mut stream: ModelStream,
    budget: usize,
    mut on_delta: F,
) -> Result<ModelResponse, StreamCollectionError<E>>
where
    F: FnMut(&str) -> Result<(), E>,
{
    if budget == 0 || budget > MAX_MODEL_OUTPUT_BYTES {
        return Err(StreamCollectionError::Model(ModelError::InvalidRequest(
            "invalid model output budget",
        )));
    }
    let mut text = String::new();
    let mut usage = None;
    while let Some(event) = stream.next().await {
        let event = match event {
            Ok(event) => event,
            Err(error @ ModelError::ProtocolViolation(_)) => {
                return Err(StreamCollectionError::Model(error));
            }
            Err(_) if usage.is_some() => {
                return Err(StreamCollectionError::Model(ModelError::ProtocolViolation(
                    "error after completion event",
                )));
            }
            Err(error) => return Err(StreamCollectionError::Model(error)),
        };
        match event {
            ModelEvent::Delta(delta) => {
                if usage.is_some() {
                    return Err(StreamCollectionError::Model(ModelError::ProtocolViolation(
                        "delta after completion event",
                    )));
                }
                if text.len().saturating_add(delta.len()) > budget {
                    return Err(StreamCollectionError::Model(
                        ModelError::OutputBudgetExceeded,
                    ));
                }
                text.push_str(&delta);
                on_delta(&delta).map_err(StreamCollectionError::Consumer)?;
            }
            ModelEvent::Completed(value) => {
                if usage.replace(value).is_some() {
                    return Err(StreamCollectionError::Model(ModelError::ProtocolViolation(
                        "multiple completion events",
                    )));
                }
            }
        }
    }
    let usage = usage.ok_or(StreamCollectionError::Model(ModelError::ProtocolViolation(
        "missing completion event",
    )))?;
    Ok(ModelResponse {
        message: Message {
            role: MessageRole::Assistant,
            content: vec![ContentBlock::Text(text)],
        },
        usage,
    })
}

pub async fn collect_stream_with<F>(
    stream: ModelStream,
    budget: usize,
    mut on_delta: F,
) -> Result<ModelResponse, ModelError>
where
    F: FnMut(&str),
{
    match try_collect_stream_with(stream, budget, |delta| {
        on_delta(delta);
        Ok::<(), std::convert::Infallible>(())
    })
    .await
    {
        Ok(response) => Ok(response),
        Err(StreamCollectionError::Model(error)) => Err(error),
        Err(StreamCollectionError::Consumer(never)) => match never {},
    }
}

fn validate_request(request: &ModelRequest) -> Result<(), ModelError> {
    if request.messages.len() > MAX_MODEL_MESSAGES {
        return Err(ModelError::InvalidRequest("too many messages"));
    }
    if request.tools.len() > MAX_MODEL_TOOLS {
        return Err(ModelError::InvalidRequest("too many tool definitions"));
    }
    let content_blocks = request
        .messages
        .iter()
        .map(|message| message.content.len())
        .try_fold(0_usize, usize::checked_add)
        .ok_or(ModelError::InvalidRequest("content block count overflowed"))?;
    if content_blocks > MAX_MODEL_CONTENT_BLOCKS {
        return Err(ModelError::InvalidRequest("too many content blocks"));
    }
    if request
        .params
        .max_output_bytes
        .is_some_and(|budget| budget.get() > MAX_MODEL_OUTPUT_BYTES)
    {
        return Err(ModelError::InvalidRequest(
            "model output budget is too large",
        ));
    }
    let bytes = request
        .messages
        .iter()
        .flat_map(|message| &message.content)
        .map(|content| match content {
            ContentBlock::Text(value) => value.len(),
            ContentBlock::ImageReference { uri } => uri.len(),
            ContentBlock::Structured { media_type, value } => media_type.len() + value.len(),
        })
        .chain(request.system.iter().map(String::len))
        .chain(
            request
                .tools
                .iter()
                .map(|tool| tool.name.len() + tool.description.len() + tool.input_schema.len()),
        )
        .try_fold(0_usize, usize::checked_add)
        .ok_or(ModelError::InvalidRequest("visible byte count overflowed"))?;
    if bytes > MAX_MODEL_VISIBLE_BYTES {
        return Err(ModelError::InvalidRequest(
            "model-visible input is too large",
        ));
    }
    Ok(())
}

fn hash_request(request: &ModelRequest) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"rust-agent-model-request-v1\0");
    hash_optional_string(&mut hasher, request.system.as_deref());
    hash_len(&mut hasher, request.messages.len());
    for message in &request.messages {
        hasher.update([match message.role {
            MessageRole::System => 0,
            MessageRole::User => 1,
            MessageRole::Assistant => 2,
            MessageRole::Tool => 3,
        }]);
        hash_len(&mut hasher, message.content.len());
        for content in &message.content {
            match content {
                ContentBlock::Text(value) => {
                    hasher.update([0]);
                    hash_string(&mut hasher, value);
                }
                ContentBlock::ImageReference { uri } => {
                    hasher.update([1]);
                    hash_string(&mut hasher, uri);
                }
                ContentBlock::Structured { media_type, value } => {
                    hasher.update([2]);
                    hash_string(&mut hasher, media_type);
                    hash_string(&mut hasher, value);
                }
            }
        }
    }
    hash_len(&mut hasher, request.tools.len());
    for tool in &request.tools {
        hash_string(&mut hasher, &tool.name);
        hash_string(&mut hasher, &tool.description);
        hash_string(&mut hasher, &tool.input_schema);
    }
    match request.params.temperature_millis {
        None => hasher.update([0]),
        Some(temperature_millis) => {
            hasher.update([1]);
            hasher.update(temperature_millis.to_be_bytes());
        }
    }
    hasher.update(
        request
            .params
            .max_output_bytes
            .map_or(0_u64, |value| value.get() as u64)
            .to_be_bytes(),
    );
    Digest::from_bytes(hasher.finalize().into())
}

fn hash_parts(parts: &[&[u8]]) -> Digest {
    let mut hasher = Sha256::new();
    for part in parts {
        hash_len(&mut hasher, part.len());
        hasher.update(part);
    }
    Digest::from_bytes(hasher.finalize().into())
}

fn hash_optional_string(hasher: &mut Sha256, value: Option<&str>) {
    if let Some(value) = value {
        hasher.update([1]);
        hash_string(hasher, value);
    } else {
        hasher.update([0]);
    }
}

fn hash_string(hasher: &mut Sha256, value: &str) {
    hash_len(hasher, value.len());
    hasher.update(value.as_bytes());
}

fn hash_len(hasher: &mut Sha256, value: usize) {
    hasher.update((value as u64).to_be_bytes());
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        num::{NonZeroU64, NonZeroUsize},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Waker},
    };

    use futures_util::stream;
    use rust_agent_core::{AgentId, CompositionHash};
    use rust_agent_runtime_api::{
        AgentLifecycleNonce, GeneratedModelBindingPlan, ModelCallScopeIdentity,
        RuntimeAdapterIdentity, RuntimeClock, RuntimeFuture, RuntimePrimitiveError,
        RuntimePrimitives, RuntimeSleeper, RuntimeSpawner, RuntimeTaskOwner,
        begin_composition_assembly,
    };

    use super::*;

    fn run<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    struct CountingModel(AtomicUsize);

    impl LanguageModel for CountingModel {
        fn provider_key(&self) -> ProviderKey {
            ProviderKey::new("counting").unwrap()
        }

        fn model_id(&self) -> ModelId {
            ModelId::new("counting-v1").unwrap()
        }

        fn stream(
            &self,
            _context: ModelCallContext,
            _request: ModelRequest,
        ) -> ModelFuture<'_, Result<ModelStream, ModelError>> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Box::pin(async {
                Ok(Box::pin(stream::iter([
                    Ok(ModelEvent::Delta("ok".into())),
                    Ok(ModelEvent::Completed(Usage::default())),
                ])) as ModelStream)
            })
        }
    }

    fn scope() -> ModelCallScopeIdentity {
        ModelCallScopeIdentity::for_generated_agent(
            AgentId::from_nonzero_u128(1).unwrap(),
            AgentLifecycleNonce::from_nonzero(NonZeroU64::new(1).unwrap()),
            None,
            CompositionHash::from_digest(Digest::from_bytes([2; 32])),
            Digest::from_bytes([3; 32]),
        )
    }

    fn draft(request_id: u128) -> ModelCallDraft {
        ModelCallDraft {
            request_id: RequestId::from_nonzero_u128(request_id).unwrap(),
            purpose: ModelRequestPurpose::AgentTurn,
            route: ModelRouteSelection::ConfiguredDefault,
            request: ModelRequest {
                messages: vec![Message {
                    role: MessageRole::User,
                    content: vec![ContentBlock::Text("hello".into())],
                }],
                ..ModelRequest::default()
            },
            linked_from: None,
        }
    }

    fn journal_authority_for(
        scope: ModelCallScopeIdentity,
        provider: &'static str,
    ) -> (
        rust_agent_runtime_api::ModelRequestJournalIssuer,
        rust_agent_runtime_api::ModelRequestJournalVerifier,
    ) {
        let plan = GeneratedModelBindingPlan::checked(
            "test-driver",
            vec![(Arc::<str>::from(provider), Arc::<str>::from(provider))],
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let owner = binding_owner(&scope, plan);
        let mut assembly = owner.begin_binding_assembly(scope).unwrap();
        assembly
            .bind_model_consumer("test-driver", &[Arc::<str>::from(provider)])
            .unwrap();
        assembly
            .finish()
            .unwrap()
            .into_journal_parts(&owner)
            .unwrap()
    }

    fn journal_authority(
        scope: ModelCallScopeIdentity,
    ) -> (
        rust_agent_runtime_api::ModelRequestJournalIssuer,
        rust_agent_runtime_api::ModelRequestJournalVerifier,
    ) {
        journal_authority_for(scope, "counting")
    }

    #[test]
    fn request_digest_distinguishes_absent_temperature_from_maximum_value() {
        let absent = draft(1).request;
        let mut maximum = absent.clone();
        maximum.params.temperature_millis = Some(u16::MAX);

        assert_ne!(hash_request(&absent), hash_request(&maximum));
    }

    fn binding_owner(
        scope: &ModelCallScopeIdentity,
        plan: GeneratedModelBindingPlan,
    ) -> rust_agent_runtime_api::BindingAssemblyOwner {
        let runtime = explicit_runtime();
        let runtime_owner = runtime
            .claim_generated_composition_owner(scope.composition(), scope.catalog(), plan)
            .unwrap();
        begin_composition_assembly(runtime_owner, scope.composition(), scope.catalog())
            .unwrap()
            .finish()
    }

    fn runtime() -> RuntimePrimitives {
        RuntimePrimitives::new(RuntimeAdapterIdentity::checked("test-runtime").unwrap())
    }

    #[derive(Debug)]
    struct ImmediateRuntime;

    impl RuntimeClock for ImmediateRuntime {
        fn now(&self) -> RuntimeInstant {
            RuntimeInstant::from_monotonic_duration(std::time::Duration::ZERO)
        }
    }

    impl RuntimeSleeper for ImmediateRuntime {
        fn sleep_until(&self, _deadline: RuntimeInstant) -> RuntimeFuture<'static, ()> {
            Box::pin(async {})
        }
    }

    impl RuntimeSpawner for ImmediateRuntime {
        fn spawn(
            &self,
            _owner: RuntimeTaskOwner,
            _task: RuntimeFuture<'static, ()>,
        ) -> Result<(), RuntimePrimitiveError> {
            Ok(())
        }

        fn drain(&self, _owner: RuntimeTaskOwner) -> RuntimeFuture<'static, ()> {
            Box::pin(async {})
        }
    }

    fn explicit_runtime() -> RuntimePrimitives {
        let driver = Arc::new(ImmediateRuntime);
        let clock: Arc<dyn RuntimeClock> = driver.clone();
        let sleeper: Arc<dyn RuntimeSleeper> = driver.clone();
        let spawner: Arc<dyn RuntimeSpawner> = driver.clone();
        RuntimePrimitives::from_adapter(
            RuntimeAdapterIdentity::checked("test-explicit-runtime").unwrap(),
            driver,
            clock,
            sleeper,
            spawner,
        )
    }

    #[test]
    fn journal_proof_is_verified_before_provider_side_effect() {
        let provider = Arc::new(CountingModel(AtomicUsize::new(0)));
        let registry = ModelRegistry::from_compiled(
            vec![ModelProviderBinding::from_provider(Arc::clone(&provider))],
            None,
        )
        .unwrap();
        let (issuer, verifier) = journal_authority(scope());
        let binding = registry.bind_generated_scope(verifier);

        let plan = binding.plan_call(draft(1)).unwrap();
        let projection = plan.journal_projection();
        let (foreign_issuer, foreign_verifier) = journal_authority(scope());
        let foreign_binding = registry.bind_generated_scope(foreign_verifier);
        let proof = issuer
            .seal_committed_record(
                projection,
                plan.record_digest(),
                CancellationToken::new(),
                None,
                plan.output_budget(),
                runtime(),
            )
            .unwrap();
        let prepared = plan.seal(proof).unwrap();
        assert_eq!(
            run(foreign_binding.complete_prepared(prepared)),
            Err(ModelError::JournalProofMismatch)
        );
        assert_eq!(provider.0.load(Ordering::Relaxed), 0);

        let plan = binding.plan_call(draft(3)).unwrap();
        let proof = foreign_issuer
            .seal_committed_record(
                plan.journal_projection(),
                plan.record_digest(),
                CancellationToken::new(),
                None,
                plan.output_budget(),
                runtime(),
            )
            .unwrap();
        assert_eq!(
            plan.seal(proof).err(),
            Some(ModelError::JournalProofMismatch)
        );

        let plan = binding.plan_call(draft(4)).unwrap();
        let proof = issuer
            .seal_committed_record(
                plan.journal_projection(),
                Digest::from_bytes([99; 32]),
                CancellationToken::new(),
                None,
                plan.output_budget(),
                runtime(),
            )
            .unwrap();
        assert_eq!(
            plan.seal(proof).err(),
            Some(ModelError::JournalProofMismatch)
        );
        assert_eq!(provider.0.load(Ordering::Relaxed), 0);

        let plan = binding.plan_call(draft(2)).unwrap();
        let proof = issuer
            .seal_committed_record(
                plan.journal_projection(),
                plan.record_digest(),
                CancellationToken::new(),
                None,
                plan.output_budget(),
                runtime(),
            )
            .unwrap();
        let response = run(binding.complete_prepared(plan.seal(proof).unwrap())).unwrap();
        assert_eq!(
            response.message.content,
            vec![ContentBlock::Text("ok".into())]
        );
        assert_eq!(provider.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn explicit_routing_rejects_missing_route_before_provider() {
        let provider = Arc::new(CountingModel(AtomicUsize::new(0)));
        let registry = ModelRegistry::from_compiled(
            vec![ModelProviderBinding::from_provider(Arc::clone(&provider))],
            Some(ModelRoutingMode::ExplicitPerRequest),
        )
        .unwrap();
        let (_, verifier) = journal_authority(scope());
        assert_eq!(
            registry
                .bind_generated_scope(verifier)
                .plan_call(draft(1))
                .err(),
            Some(ModelError::ModelRouteRequired)
        );
        assert_eq!(provider.0.load(Ordering::Relaxed), 0);
    }

    struct NamedCountingModel {
        key: &'static str,
        calls: Arc<AtomicUsize>,
    }

    impl LanguageModel for NamedCountingModel {
        fn provider_key(&self) -> ProviderKey {
            ProviderKey::new(self.key).unwrap()
        }

        fn model_id(&self) -> ModelId {
            ModelId::new(format!("{}-v1", self.key)).unwrap()
        }

        fn stream(
            &self,
            _context: ModelCallContext,
            _request: ModelRequest,
        ) -> ModelFuture<'_, Result<ModelStream, ModelError>> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            Box::pin(async {
                Ok(
                    Box::pin(stream::iter([Ok(ModelEvent::Completed(Usage::default()))]))
                        as ModelStream,
                )
            })
        }
    }

    #[test]
    fn multiple_provider_modes_fail_closed_before_journal_or_provider() {
        let calls = Arc::new(AtomicUsize::new(0));
        let providers = || {
            vec![
                ModelProviderBinding::from_provider(Arc::new(NamedCountingModel {
                    key: "alpha",
                    calls: Arc::clone(&calls),
                })),
                ModelProviderBinding::from_provider(Arc::new(NamedCountingModel {
                    key: "beta",
                    calls: Arc::clone(&calls),
                })),
            ]
        };
        assert_eq!(
            ModelRegistry::validate_generated_routing(
                vec![
                    ProviderKey::new("alpha").unwrap(),
                    ProviderKey::new("beta").unwrap(),
                ],
                None,
            )
            .err(),
            Some(ModelError::AmbiguousModelRouting)
        );
        let validated = ModelRegistry::validate_generated_routing(
            vec![
                ProviderKey::new("alpha").unwrap(),
                ProviderKey::new("beta").unwrap(),
            ],
            Some(ModelRoutingMode::ExplicitPerRequest),
        )
        .unwrap();
        assert_eq!(
            ModelRegistry::from_compiled_validated(
                vec![ModelProviderBinding::from_provider(Arc::new(
                    NamedCountingModel {
                        key: "alpha",
                        calls: Arc::clone(&calls),
                    }
                ))],
                validated,
            )
            .unwrap_err(),
            ModelError::CompiledProviderSetMismatch
        );
        assert_eq!(
            ModelRegistry::from_compiled(providers(), None).unwrap_err(),
            ModelError::AmbiguousModelRouting
        );
        let registry =
            ModelRegistry::from_compiled(providers(), Some(ModelRoutingMode::ExplicitPerRequest))
                .unwrap();
        let plan = GeneratedModelBindingPlan::checked(
            "test-driver",
            registry.generated_provider_identities(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let call_scope = scope();
        let owner = binding_owner(&call_scope, plan);
        let mut assembly = owner.begin_binding_assembly(call_scope).unwrap();
        assembly
            .bind_model_consumer("test-driver", &registry.generated_provider_keys())
            .unwrap();
        let (issuer, verifier) = assembly
            .finish()
            .unwrap()
            .into_journal_parts(&owner)
            .unwrap();
        let binding = registry.bind_generated_scope(verifier);
        assert_eq!(
            binding.plan_call(draft(1)).err(),
            Some(ModelError::ModelRouteRequired)
        );
        let mut unknown = draft(2);
        unknown.route = ModelRouteSelection::Explicit(ProviderKey::new("missing").unwrap());
        assert!(matches!(
            binding.plan_call(unknown),
            Err(ModelError::UnknownProvider(key)) if key.as_str() == "missing"
        ));
        let mut explicit = draft(3);
        explicit.route = ModelRouteSelection::Explicit(ProviderKey::new("beta").unwrap());
        let plan = binding.plan_call(explicit).unwrap();
        let proof = issuer
            .seal_committed_record(
                plan.journal_projection(),
                plan.record_digest(),
                CancellationToken::new(),
                None,
                plan.output_budget(),
                runtime(),
            )
            .unwrap();
        run(binding.complete_prepared(plan.seal(proof).unwrap())).unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 1);

        let registry = ModelRegistry::from_compiled(
            providers(),
            Some(ModelRoutingMode::Default {
                provider: ProviderKey::new("alpha").unwrap(),
            }),
        )
        .unwrap();
        let plan = GeneratedModelBindingPlan::checked(
            "test-driver",
            registry.generated_provider_identities(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let scope = scope();
        let owner = binding_owner(&scope, plan);
        let mut assembly = owner.begin_binding_assembly(scope).unwrap();
        assembly
            .bind_model_consumer("test-driver", &registry.generated_provider_keys())
            .unwrap();
        let (issuer, verifier) = assembly
            .finish()
            .unwrap()
            .into_journal_parts(&owner)
            .unwrap();
        let binding = registry.bind_generated_scope(verifier);
        assert_eq!(
            binding.plan_call(draft(4)).unwrap().provider_key.as_str(),
            "alpha"
        );
        let mut explicit = draft(5);
        explicit.route = ModelRouteSelection::Explicit(ProviderKey::new("beta").unwrap());
        let plan = binding.plan_call(explicit).unwrap();
        assert_eq!(plan.provider_key.as_str(), "beta");
        let proof = issuer
            .seal_committed_record(
                plan.journal_projection(),
                plan.record_digest(),
                CancellationToken::new(),
                None,
                plan.output_budget(),
                runtime(),
            )
            .unwrap();
        run(binding.complete_prepared(plan.seal(proof).unwrap())).unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 2);
    }

    #[test]
    fn request_shape_output_budget_and_proof_budget_are_closed() {
        let provider = Arc::new(CountingModel(AtomicUsize::new(0)));
        let registry = ModelRegistry::from_compiled(
            vec![ModelProviderBinding::from_provider(Arc::clone(&provider))],
            None,
        )
        .unwrap();
        let (issuer, verifier) = journal_authority(scope());
        let binding = registry.bind_generated_scope(verifier);

        let mut oversized_output = draft(1);
        oversized_output.request.params.max_output_bytes =
            NonZeroUsize::new(MAX_MODEL_OUTPUT_BYTES + 1);
        assert_eq!(
            binding.plan_call(oversized_output).err(),
            Some(ModelError::InvalidRequest(
                "model output budget is too large"
            ))
        );

        let mut too_many_blocks = draft(2);
        too_many_blocks.request.messages[0].content =
            vec![ContentBlock::Text(String::new()); MAX_MODEL_CONTENT_BLOCKS + 1];
        assert_eq!(
            binding.plan_call(too_many_blocks).err(),
            Some(ModelError::InvalidRequest("too many content blocks"))
        );
        assert_eq!(provider.0.load(Ordering::Acquire), 0);

        let mut exact = draft(3);
        exact.request.params.max_output_bytes = NonZeroUsize::new(2);
        let plan = binding.plan_call(exact).unwrap();
        let proof = issuer
            .seal_committed_record(
                plan.journal_projection(),
                plan.record_digest(),
                CancellationToken::new(),
                None,
                plan.output_budget(),
                runtime(),
            )
            .unwrap();
        assert_eq!(
            run(binding.complete_prepared(plan.seal(proof).unwrap()))
                .unwrap()
                .message
                .content,
            vec![ContentBlock::Text("ok".into())]
        );

        let mut overflow = draft(4);
        overflow.request.params.max_output_bytes = NonZeroUsize::new(1);
        let plan = binding.plan_call(overflow).unwrap();
        let proof = issuer
            .seal_committed_record(
                plan.journal_projection(),
                plan.record_digest(),
                CancellationToken::new(),
                None,
                plan.output_budget(),
                runtime(),
            )
            .unwrap();
        assert_eq!(
            run(binding.complete_prepared(plan.seal(proof).unwrap())),
            Err(ModelError::OutputBudgetExceeded)
        );

        let mut mismatched = draft(5);
        mismatched.request.params.max_output_bytes = NonZeroUsize::new(2);
        let plan = binding.plan_call(mismatched).unwrap();
        let proof = issuer
            .seal_committed_record(
                plan.journal_projection(),
                plan.record_digest(),
                CancellationToken::new(),
                None,
                NonZeroUsize::new(3).unwrap(),
                runtime(),
            )
            .unwrap();
        assert_eq!(
            plan.seal(proof).err(),
            Some(ModelError::JournalProofMismatch)
        );
        assert_eq!(provider.0.load(Ordering::Acquire), 2);
        assert_eq!(
            run(collect_stream(
                Box::pin(stream::empty()),
                MAX_MODEL_OUTPUT_BYTES + 1
            )),
            Err(ModelError::InvalidRequest("invalid model output budget"))
        );
    }

    struct InvalidProtocolModel;

    #[test]
    fn default_collector_rejects_delta_after_completion() {
        let stream = Box::pin(stream::iter([
            Ok(ModelEvent::Completed(Usage::default())),
            Ok(ModelEvent::Delta("late".into())),
        ]));

        assert_eq!(
            run(collect_stream(stream, MAX_MODEL_OUTPUT_BYTES)),
            Err(ModelError::ProtocolViolation(
                "delta after completion event"
            ))
        );

        let stream = Box::pin(stream::iter([
            Ok(ModelEvent::Completed(Usage::default())),
            Err(ModelError::Provider {
                category: "late",
                message: "late transport failure".into(),
            }),
        ]));
        assert_eq!(
            run(collect_stream(stream, MAX_MODEL_OUTPUT_BYTES)),
            Err(ModelError::ProtocolViolation(
                "error after completion event"
            ))
        );
    }

    impl LanguageModel for InvalidProtocolModel {
        fn provider_key(&self) -> ProviderKey {
            ProviderKey::new("invalid-protocol").unwrap()
        }

        fn model_id(&self) -> ModelId {
            ModelId::new("invalid-protocol-v1").unwrap()
        }

        fn stream(
            &self,
            _context: ModelCallContext,
            _request: ModelRequest,
        ) -> ModelFuture<'_, Result<ModelStream, ModelError>> {
            Box::pin(async {
                Ok(Box::pin(stream::iter([
                    Ok(ModelEvent::Completed(Usage::default())),
                    Ok(ModelEvent::Delta("late".into())),
                ])) as ModelStream)
            })
        }
    }

    struct MissingCompletionModel;

    impl LanguageModel for MissingCompletionModel {
        fn provider_key(&self) -> ProviderKey {
            ProviderKey::new("missing-completion").unwrap()
        }

        fn model_id(&self) -> ModelId {
            ModelId::new("missing-completion-v1").unwrap()
        }

        fn stream(
            &self,
            _context: ModelCallContext,
            _request: ModelRequest,
        ) -> ModelFuture<'_, Result<ModelStream, ModelError>> {
            Box::pin(async {
                Ok(
                    Box::pin(stream::iter([Ok(ModelEvent::Delta("partial".into()))]))
                        as ModelStream,
                )
            })
        }
    }

    struct ErrorAfterCompletionModel;

    impl LanguageModel for ErrorAfterCompletionModel {
        fn provider_key(&self) -> ProviderKey {
            ProviderKey::new("error-after-completion").unwrap()
        }

        fn model_id(&self) -> ModelId {
            ModelId::new("error-after-completion-v1").unwrap()
        }

        fn stream(
            &self,
            _context: ModelCallContext,
            _request: ModelRequest,
        ) -> ModelFuture<'_, Result<ModelStream, ModelError>> {
            Box::pin(async {
                Ok(Box::pin(stream::iter([
                    Ok(ModelEvent::Completed(Usage::default())),
                    Err(ModelError::Provider {
                        category: "late",
                        message: "late transport failure".into(),
                    }),
                ])) as ModelStream)
            })
        }
    }

    #[test]
    fn completion_is_unique_and_terminal_in_the_guarded_protocol() {
        let registry = ModelRegistry::from_compiled(
            vec![ModelProviderBinding::from_provider(Arc::new(
                InvalidProtocolModel,
            ))],
            None,
        )
        .unwrap();
        let (issuer, verifier) = journal_authority_for(scope(), "invalid-protocol");
        let binding = registry.bind_generated_scope(verifier);
        let plan = binding.plan_call(draft(1)).unwrap();
        let proof = issuer
            .seal_committed_record(
                plan.journal_projection(),
                plan.record_digest(),
                CancellationToken::new(),
                None,
                plan.output_budget(),
                runtime(),
            )
            .unwrap();
        assert_eq!(
            run(binding.complete_prepared(plan.seal(proof).unwrap())),
            Err(ModelError::ProtocolViolation(
                "delta after completion event"
            ))
        );

        let registry = ModelRegistry::from_compiled(
            vec![ModelProviderBinding::from_provider(Arc::new(
                MissingCompletionModel,
            ))],
            None,
        )
        .unwrap();
        let (issuer, verifier) = journal_authority_for(scope(), "missing-completion");
        let binding = registry.bind_generated_scope(verifier);
        let plan = binding.plan_call(draft(2)).unwrap();
        let proof = issuer
            .seal_committed_record(
                plan.journal_projection(),
                plan.record_digest(),
                CancellationToken::new(),
                None,
                plan.output_budget(),
                runtime(),
            )
            .unwrap();
        assert_eq!(
            run(binding.complete_prepared(plan.seal(proof).unwrap())),
            Err(ModelError::ProtocolViolation(
                "stream ended before completion event"
            ))
        );

        let registry = ModelRegistry::from_compiled(
            vec![ModelProviderBinding::from_provider(Arc::new(
                ErrorAfterCompletionModel,
            ))],
            None,
        )
        .unwrap();
        let (issuer, verifier) = journal_authority_for(scope(), "error-after-completion");
        let binding = registry.bind_generated_scope(verifier);
        let plan = binding.plan_call(draft(3)).unwrap();
        let proof = issuer
            .seal_committed_record(
                plan.journal_projection(),
                plan.record_digest(),
                CancellationToken::new(),
                None,
                plan.output_budget(),
                runtime(),
            )
            .unwrap();
        assert_eq!(
            run(binding.complete_prepared(plan.seal(proof).unwrap())),
            Err(ModelError::ProtocolViolation(
                "error after completion event"
            ))
        );
    }

    struct PendingModel(Arc<AtomicUsize>);

    impl LanguageModel for PendingModel {
        fn provider_key(&self) -> ProviderKey {
            ProviderKey::new("pending").unwrap()
        }

        fn model_id(&self) -> ModelId {
            ModelId::new("pending-v1").unwrap()
        }

        fn stream(
            &self,
            _context: ModelCallContext,
            _request: ModelRequest,
        ) -> ModelFuture<'_, Result<ModelStream, ModelError>> {
            self.0.fetch_add(1, Ordering::AcqRel);
            Box::pin(async { Ok(Box::pin(stream::pending()) as ModelStream) })
        }
    }

    #[test]
    fn deadline_and_cancellation_stop_active_stream() {
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = ModelRegistry::from_compiled(
            vec![ModelProviderBinding::from_provider(Arc::new(PendingModel(
                Arc::clone(&calls),
            )))],
            None,
        )
        .unwrap();
        let (issuer, verifier) = journal_authority_for(scope(), "pending");
        let binding = registry.bind_generated_scope(verifier);

        let plan = binding.plan_call(draft(1)).unwrap();
        let proof = issuer
            .seal_committed_record(
                plan.journal_projection(),
                plan.record_digest(),
                CancellationToken::new(),
                Some(RuntimeInstant::from_monotonic_duration(
                    std::time::Duration::ZERO,
                )),
                plan.output_budget(),
                explicit_runtime(),
            )
            .unwrap();
        assert_eq!(
            run(binding.stream_prepared(plan.seal(proof).unwrap())).err(),
            Some(ModelError::DeadlineExceeded)
        );
        assert_eq!(calls.load(Ordering::Acquire), 0);

        let cancellation = CancellationToken::new();
        let plan = binding.plan_call(draft(2)).unwrap();
        let proof = issuer
            .seal_committed_record(
                plan.journal_projection(),
                plan.record_digest(),
                cancellation.clone(),
                None,
                plan.output_budget(),
                runtime(),
            )
            .unwrap();
        let mut stream = run(binding.stream_prepared(plan.seal(proof).unwrap())).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        assert!(stream.as_mut().poll_next(&mut context).is_pending());
        cancellation.cancel();
        assert_eq!(
            stream.as_mut().poll_next(&mut context),
            Poll::Ready(Some(Err(ModelError::Cancelled)))
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
    }
}
