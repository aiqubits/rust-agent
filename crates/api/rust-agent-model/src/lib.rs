//! Streaming-first model capability with a proof-gated consumer binding.

use std::{collections::BTreeMap, fmt, future::Future, num::NonZeroUsize, pin::Pin, sync::Arc};

use futures_core::Stream;
use futures_util::{StreamExt as _, stream};
use rust_agent_core::{
    CanonicalId, ContentBlock, Digest, MaybeSendSync, Message, MessageRole, RequestId, Usage,
};
use rust_agent_runtime_api::{
    CancellationToken, ModelCallJournalProjection, ModelRequestJournalVerifier, RequestJournalProof,
};
use sha2::{Digest as _, Sha256};

pub const MAX_MODEL_MESSAGES: usize = 128;
pub const MAX_MODEL_TOOLS: usize = 64;
pub const MAX_MODEL_VISIBLE_BYTES: usize = 256 * 1024;

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
    InvalidProviderKey,
    InvalidModelId,
    InvalidRequest(&'static str),
    DuplicateProvider(ProviderKey),
    EmptyRegistry,
    AmbiguousModelRouting,
    ModelRouteRequired,
    UnknownProvider(ProviderKey),
    JournalProofMismatch,
    Cancelled,
    DeadlineExceeded,
    OutputBudgetExceeded,
    ProtocolViolation(&'static str),
    Provider {
        category: &'static str,
        message: String,
    },
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProviderKey => formatter.write_str("invalid model provider key"),
            Self::InvalidModelId => formatter.write_str("invalid model id"),
            Self::InvalidRequest(reason) => write!(formatter, "invalid model request: {reason}"),
            Self::DuplicateProvider(key) => write!(formatter, "duplicate model provider {key:?}"),
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
    key: ProviderKey,
    model_id: ModelId,
    provider: Arc<dyn LanguageModel>,
}

impl fmt::Debug for ModelProviderBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelProviderBinding")
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
        Self {
            key: provider.provider_key(),
            model_id: provider.model_id(),
            provider,
        }
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

impl ModelRegistry {
    pub fn from_compiled(
        providers: Vec<ModelProviderBinding>,
        routing: Option<ModelRoutingMode>,
    ) -> Result<Self, ModelError> {
        if providers.is_empty() {
            return Err(ModelError::EmptyRegistry);
        }
        let mut compiled = BTreeMap::new();
        for provider in providers {
            let key = provider.key.clone();
            if compiled.insert(key.clone(), provider).is_some() {
                return Err(ModelError::DuplicateProvider(key));
            }
        }
        let routing = match routing {
            Some(mode) => mode,
            None if compiled.len() == 1 => ModelRoutingMode::Default {
                provider: compiled
                    .first_key_value()
                    .expect("nonempty registry has a first provider")
                    .0
                    .clone(),
            },
            None => return Err(ModelError::AmbiguousModelRouting),
        };
        if let ModelRoutingMode::Default { provider } = &routing
            && !compiled.contains_key(provider)
        {
            return Err(ModelError::UnknownProvider(provider.clone()));
        }
        Ok(Self {
            providers: Arc::new(compiled),
            routing,
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

    pub fn seal(self, proof: RequestJournalProof) -> Result<PreparedModelCall, ModelError> {
        if proof.request_id() != self.request_id {
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
            if call.context.cancellation().is_cancelled() {
                return Err(ModelError::Cancelled);
            }
            if call
                .context
                .proof
                .deadline()
                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
            {
                return Err(ModelError::DeadlineExceeded);
            }
            let provider = self
                .providers
                .get(&call.provider_key)
                .ok_or_else(|| ModelError::UnknownProvider(call.provider_key.clone()))?;
            if provider.model_id != call.model_id {
                return Err(ModelError::JournalProofMismatch);
            }
            let _ = (call.purpose, call.linked_from);
            let budget = call.context.output_budget().get();
            let cancellation = call.context.cancellation();
            let stream = provider.provider.stream(call.context, call.request).await?;
            Ok(budget_stream(stream, budget, cancellation))
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

fn budget_stream(
    source: ModelStream,
    budget: usize,
    cancellation: CancellationToken,
) -> ModelStream {
    Box::pin(stream::unfold(
        (source, 0_usize, false, cancellation),
        move |(mut source, used, terminal, cancellation)| async move {
            if terminal {
                return None;
            }
            if cancellation.is_cancelled() {
                return Some((
                    Err(ModelError::Cancelled),
                    (source, used, true, cancellation),
                ));
            }
            let event = source.next().await?;
            let mut next_used = used;
            let mut next_terminal = false;
            if let Ok(ModelEvent::Delta(delta)) = &event {
                next_used = match next_used.checked_add(delta.len()) {
                    Some(total) if total <= budget => total,
                    _ => {
                        return Some((
                            Err(ModelError::OutputBudgetExceeded),
                            (source, used, true, cancellation),
                        ));
                    }
                };
            }
            if event.is_err() {
                next_terminal = true;
            }
            Some((event, (source, next_used, next_terminal, cancellation)))
        },
    ))
}

pub async fn collect_stream(
    mut stream: ModelStream,
    budget: usize,
) -> Result<ModelResponse, ModelError> {
    let mut text = String::new();
    let mut usage = None;
    while let Some(event) = stream.next().await {
        match event? {
            ModelEvent::Delta(delta) => {
                if text.len().saturating_add(delta.len()) > budget {
                    return Err(ModelError::OutputBudgetExceeded);
                }
                text.push_str(&delta);
            }
            ModelEvent::Completed(value) => {
                if usage.replace(value).is_some() {
                    return Err(ModelError::ProtocolViolation("multiple completion events"));
                }
            }
        }
    }
    let usage = usage.ok_or(ModelError::ProtocolViolation("missing completion event"))?;
    Ok(ModelResponse {
        message: Message {
            role: MessageRole::Assistant,
            content: vec![ContentBlock::Text(text)],
        },
        usage,
    })
}

fn validate_request(request: &ModelRequest) -> Result<(), ModelError> {
    if request.messages.len() > MAX_MODEL_MESSAGES {
        return Err(ModelError::InvalidRequest("too many messages"));
    }
    if request.tools.len() > MAX_MODEL_TOOLS {
        return Err(ModelError::InvalidRequest("too many tool definitions"));
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
    hasher.update(
        request
            .params
            .temperature_millis
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
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
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll, Waker},
    };

    use rust_agent_core::{AgentId, CompositionHash};
    use rust_agent_runtime_api::{
        AgentLifecycleNonce, ModelCallScopeIdentity, ModelRequestJournalAuthority,
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

    #[test]
    fn journal_proof_is_verified_before_provider_side_effect() {
        let provider = Arc::new(CountingModel(AtomicUsize::new(0)));
        let registry = ModelRegistry::from_compiled(
            vec![ModelProviderBinding::from_provider(Arc::clone(&provider))],
            None,
        )
        .unwrap();
        let (issuer, verifier) =
            ModelRequestJournalAuthority::issue_for_generated_scope(scope()).unwrap();
        let binding = registry.bind_generated_scope(verifier);

        let plan = binding.plan_call(draft(1)).unwrap();
        let projection = plan.journal_projection();
        let (_, foreign_verifier) =
            ModelRequestJournalAuthority::issue_for_generated_scope(scope()).unwrap();
        let foreign_binding = registry.bind_generated_scope(foreign_verifier);
        let proof = issuer
            .seal_committed_record(
                projection,
                plan.record_digest(),
                CancellationToken::new(),
                None,
                NonZeroUsize::new(1024).unwrap(),
            )
            .unwrap();
        let prepared = plan.seal(proof).unwrap();
        assert_eq!(
            run(foreign_binding.complete_prepared(prepared)),
            Err(ModelError::JournalProofMismatch)
        );
        assert_eq!(provider.0.load(Ordering::Relaxed), 0);

        let plan = binding.plan_call(draft(2)).unwrap();
        let proof = issuer
            .seal_committed_record(
                plan.journal_projection(),
                plan.record_digest(),
                CancellationToken::new(),
                None,
                NonZeroUsize::new(1024).unwrap(),
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
        let (_, verifier) =
            ModelRequestJournalAuthority::issue_for_generated_scope(scope()).unwrap();
        assert_eq!(
            registry
                .bind_generated_scope(verifier)
                .plan_call(draft(1))
                .err(),
            Some(ModelError::ModelRouteRequired)
        );
        assert_eq!(provider.0.load(Ordering::Relaxed), 0);
    }
}
