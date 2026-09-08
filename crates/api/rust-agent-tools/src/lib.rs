//! Bounded Tool contracts. Raw handlers and execution permits remain inside this crate's
//! guarded reference-monitor boundary.

mod execution;
pub mod guarded_component;
mod middleware;
mod output;
mod policy;
mod registry;

use std::{fmt, future::Future, num::NonZeroU64, pin::Pin, sync::Arc};

pub use execution::{
    BorrowedToolExecutionSession, GuardedToolExecutor, MAX_ACTIVE_TOOL_SESSIONS,
    MAX_NESTED_TOOL_CALLS, MAX_NESTED_TOOL_DEPTH, MAX_TOOL_ARGUMENT_BYTES, MAX_TOOL_ARGUMENT_DEPTH,
    MAX_TOOL_CALLS_PER_STEP, PreparedToolCall, StepId, ToolCallPlan, ToolExecutionError,
    ToolExecutionRequest, ToolExecutionResult, ToolExecutionSession, ToolExecutor,
    ToolExecutorBinding, ToolScope,
};
pub use middleware::{
    MAX_TOOL_EXECUTION_MIDDLEWARE, MAX_TOOL_MIDDLEWARE_ERROR_BYTES, ToolAroundExecutionPhase,
    ToolExecutionMiddleware, ToolExecutionMiddlewareBinding, ToolExecutionOrigin,
    ToolMiddlewareBuildError, ToolMiddlewareContext, ToolMiddlewareError, ToolMiddlewareErrorKind,
    ToolMiddlewareOutcome, ToolMiddlewareStage, ToolPostPolicyDecision, ToolPrePolicyDecision,
};
pub use output::{
    MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_OUTPUT_ITEMS, MAX_TOOL_OUTPUT_JSON_DEPTH,
    MAX_TOOL_OUTPUT_REFERENCE_BYTES, ToolOutputBuilder, ToolOutputError, ToolValue, ToolValueItem,
};
pub use policy::{
    BoundedJsonPointer, BoundedJsonScalar, BoundedKey, JsonKind, MAX_TOOL_EXCLUSIVE_KEY_BYTES,
    MAX_TOOL_JSON_POINTER_BYTES, MAX_TOOL_JSON_POINTER_DEPTH, MAX_TOOL_POLICY_BYTES,
    MAX_TOOL_POLICY_EVALUATOR_STEPS, MAX_TOOL_POLICY_RULES, MAX_TOOL_RULE_PREDICATES,
    MAX_TOOL_SCALAR_BYTES, ToolArgumentPredicate, ToolCallPolicy, ToolCallPolicyBuilder,
    ToolConcurrencyRule, ToolPolicyBuildError, ToolRiskRule, ToolRiskRuleBuilder, ToolSafety,
};
pub use registry::{
    CapabilityProviderAdapter, MAX_TOOL_PROVIDERS, MAX_TOOL_SCHEMA_BYTES_PER_AGENT,
    MAX_TOOLS_PER_AGENT, ToolProvider, ToolProviderBinding, ToolSetSnapshot,
};
use rust_agent_core::{CanonicalId, Digest, MaybeSendSync, SecurityEffects};
use rust_agent_runtime_api::{CancellationToken, RuntimeInstant};
use serde_json::Value as JsonValue;
use sha2::{Digest as _, Sha256};

pub const MAX_TOOL_DESCRIPTION_BYTES: usize = 4 * 1024;
pub const MAX_TOOL_SCHEMA_BYTES: usize = 64 * 1024;
pub const MAX_TOOL_SCHEMA_DEPTH: usize = 16;
pub const MAX_TOOL_REGISTRATIONS_PER_PROVIDER: usize = 64;
pub const MAX_TOOL_ERROR_MESSAGE_BYTES: usize = 4 * 1024;

#[cfg(not(target_arch = "wasm32"))]
pub type ToolFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type ToolFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolDefinition {
    name: CanonicalId,
    description: Arc<str>,
    input_schema: JsonValue,
    static_safety: ToolSafety,
    static_effects: SecurityEffects,
    call_policy: ToolCallPolicy,
    canonical_schema_bytes: usize,
}

impl ToolDefinition {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        input_schema: JsonValue,
        static_safety: ToolSafety,
        static_effects: SecurityEffects,
        call_policy: ToolCallPolicy,
    ) -> Result<Self, ToolRegistrationError> {
        let name = CanonicalId::new(name.into())
            .map_err(|_| ToolRegistrationError::InvalidDefinition("invalid tool name"))?;
        let description = description.into();
        if description.is_empty() || description.len() > MAX_TOOL_DESCRIPTION_BYTES {
            return Err(ToolRegistrationError::InvalidDefinition(
                "invalid tool description",
            ));
        }
        if !input_schema.is_object() {
            return Err(ToolRegistrationError::InvalidDefinition(
                "tool input schema must be a JSON object",
            ));
        }
        if json_depth(&input_schema) > MAX_TOOL_SCHEMA_DEPTH {
            return Err(ToolRegistrationError::InvalidDefinition(
                "tool input schema is too deep",
            ));
        }
        let canonical_schema_bytes = serde_json::to_vec(&input_schema)
            .map_err(|_| ToolRegistrationError::InvalidDefinition("invalid tool input schema"))?
            .len();
        if canonical_schema_bytes > MAX_TOOL_SCHEMA_BYTES {
            return Err(ToolRegistrationError::InvalidDefinition(
                "tool input schema is too large",
            ));
        }
        if policy::effects_require_mutating(static_effects) && static_safety < ToolSafety::Mutating
        {
            return Err(ToolRegistrationError::InvalidPolicy(
                ToolPolicyBuildError::SafetyNotMonotonic,
            ));
        }
        call_policy
            .validate_bounded(static_safety)
            .map_err(ToolRegistrationError::InvalidPolicy)?;
        Ok(Self {
            name,
            description: Arc::from(description),
            input_schema,
            static_safety,
            static_effects,
            call_policy,
            canonical_schema_bytes,
        })
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub const fn input_schema(&self) -> &JsonValue {
        &self.input_schema
    }

    pub const fn static_safety(&self) -> ToolSafety {
        self.static_safety
    }

    pub const fn static_effects(&self) -> SecurityEffects {
        self.static_effects
    }

    pub const fn call_policy(&self) -> &ToolCallPolicy {
        &self.call_policy
    }

    pub const fn canonical_schema_bytes(&self) -> usize {
        self.canonical_schema_bytes
    }

    fn validate_again(&self) -> Result<(), ToolRegistrationError> {
        if policy::effects_require_mutating(self.static_effects)
            && self.static_safety < ToolSafety::Mutating
        {
            return Err(ToolRegistrationError::InvalidPolicy(
                ToolPolicyBuildError::SafetyNotMonotonic,
            ));
        }
        self.call_policy
            .validate_bounded(self.static_safety)
            .map_err(ToolRegistrationError::InvalidPolicy)?;
        if self.description.is_empty()
            || self.description.len() > MAX_TOOL_DESCRIPTION_BYTES
            || !self.input_schema.is_object()
            || json_depth(&self.input_schema) > MAX_TOOL_SCHEMA_DEPTH
        {
            return Err(ToolRegistrationError::InvalidDefinition(
                "tool definition failed defensive validation",
            ));
        }
        let bytes = serde_json::to_vec(&self.input_schema)
            .map_err(|_| ToolRegistrationError::InvalidDefinition("invalid tool input schema"))?
            .len();
        if bytes != self.canonical_schema_bytes || bytes > MAX_TOOL_SCHEMA_BYTES {
            return Err(ToolRegistrationError::InvalidDefinition(
                "tool schema charge mismatch",
            ));
        }
        Ok(())
    }

    fn maximum_effects(&self) -> SecurityEffects {
        self.call_policy
            .rules()
            .iter()
            .fold(self.static_effects, |effects, rule| {
                effects | rule.add_effects()
            })
    }
}

fn hash_parts(parts: &[&[u8]]) -> Digest {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((*part).len().to_be_bytes());
        hasher.update(part);
    }
    Digest::from_bytes(hasher.finalize().into())
}

fn json_depth(value: &JsonValue) -> usize {
    match value {
        JsonValue::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or_default(),
        JsonValue::Object(values) => 1 + values.values().map(json_depth).max().unwrap_or_default(),
        _ => 1,
    }
}

/// Only the guarded pipeline can construct this value.
#[allow(missing_debug_implementations)]
pub struct ExecutionPermit {
    authority: Arc<execution::NestedToolAuthority>,
}

#[derive(Debug)]
pub struct ToolContext {
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
    output_limits: output::ToolOutputLimits,
    authority: Arc<execution::NestedToolAuthority>,
}

impl ToolContext {
    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub const fn deadline(&self) -> Option<RuntimeInstant> {
        self.deadline
    }

    pub const fn output_builder(&self) -> ToolOutputBuilder {
        ToolOutputBuilder::with_limits(self.output_limits)
    }

    pub fn root_call_id(&self) -> rust_agent_core::CallId {
        self.authority.root_call_id()
    }

    pub fn prepare_nested<'a>(
        &'a self,
        parent: &'a ExecutionPermit,
    ) -> Result<BorrowedToolExecutionSession<'a>, ToolExecutionError> {
        execution::prepare_nested(self, parent)
    }
}

pub trait Tool: MaybeSendSync {
    fn definition(&self) -> ToolDefinition;

    fn execute<'a>(
        &'a self,
        permit: &'a ExecutionPermit,
        context: &'a ToolContext,
        input: JsonValue,
    ) -> ToolFuture<'a, Result<ToolValue, ToolError>>;
}

#[derive(Clone)]
pub struct ToolRegistration {
    definition: ToolDefinition,
    #[allow(dead_code)] // Raw payload is intentionally reserved for this crate's guarded pipeline.
    handler: Arc<dyn Tool>,
}

impl ToolRegistration {
    pub fn new(tool: Arc<dyn Tool>) -> Result<Self, ToolRegistrationError> {
        let definition = tool.definition();
        definition.validate_again()?;
        Ok(Self {
            definition,
            handler: tool,
        })
    }
}

impl fmt::Debug for ToolRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolRegistration")
            .field("name", &self.definition.name())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct ToolRegistrationSnapshot {
    provider_id: CanonicalId,
    schema_version: NonZeroU64,
    registrations: Arc<[ToolRegistration]>,
}

impl ToolRegistrationSnapshot {
    pub fn new(
        provider_id: impl Into<String>,
        schema_version: NonZeroU64,
        registrations: Vec<ToolRegistration>,
    ) -> Result<Self, ToolProviderError> {
        let provider_id = CanonicalId::new(provider_id.into())
            .map_err(|_| ToolProviderError::InvalidProviderIdentity)?;
        if registrations.len() > MAX_TOOL_REGISTRATIONS_PER_PROVIDER {
            return Err(ToolProviderError::RegistrationLimitExceeded);
        }
        let mut names = registrations
            .iter()
            .map(|registration| registration.definition.name())
            .collect::<Vec<_>>();
        names.sort_unstable();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ToolProviderError::DuplicateToolName);
        }
        Ok(Self {
            provider_id,
            schema_version,
            registrations: registrations.into(),
        })
    }

    pub fn provider_id(&self) -> &str {
        self.provider_id.as_str()
    }

    pub const fn schema_version(&self) -> NonZeroU64 {
        self.schema_version
    }

    pub fn registrations(&self) -> &[ToolRegistration] {
        &self.registrations
    }
}

pub trait ToolContribution: MaybeSendSync {
    fn snapshot(&self) -> Result<ToolRegistrationSnapshot, ToolProviderError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolRegistrationError {
    InvalidDefinition(&'static str),
    InvalidPolicy(ToolPolicyBuildError),
}

impl fmt::Display for ToolRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDefinition(reason) => {
                write!(formatter, "invalid tool definition: {reason}")
            }
            Self::InvalidPolicy(error) => write!(formatter, "invalid tool call policy: {error}"),
        }
    }
}

impl std::error::Error for ToolRegistrationError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolProviderError {
    InvalidProviderIdentity,
    InvalidComponentIdentity,
    InvalidRegistration,
    RegistrationLimitExceeded,
    ProviderLimitExceeded,
    ToolLimitExceeded,
    SchemaByteLimitExceeded,
    DuplicateToolName,
    DuplicateProviderIdentity,
    EffectCeilingExceeded,
    SchemaVersionRegressed,
    SchemaVersionConflict,
    SnapshotUnavailable,
}

impl fmt::Display for ToolProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProviderIdentity => formatter.write_str("invalid tool provider identity"),
            Self::InvalidComponentIdentity => {
                formatter.write_str("invalid tool provider Component identity")
            }
            Self::InvalidRegistration => formatter.write_str("invalid tool registration"),
            Self::RegistrationLimitExceeded => {
                formatter.write_str("tool provider registration limit exceeded")
            }
            Self::ProviderLimitExceeded => {
                formatter.write_str("tool provider count limit exceeded")
            }
            Self::ToolLimitExceeded => formatter.write_str("Agent tool count limit exceeded"),
            Self::SchemaByteLimitExceeded => {
                formatter.write_str("Agent tool schema byte limit exceeded")
            }
            Self::DuplicateToolName => formatter.write_str("duplicate tool name in snapshot"),
            Self::DuplicateProviderIdentity => {
                formatter.write_str("duplicate tool provider identity")
            }
            Self::EffectCeilingExceeded => {
                formatter.write_str("tool effects exceed the sealed provider ceiling")
            }
            Self::SchemaVersionRegressed => {
                formatter.write_str("tool provider schema version regressed")
            }
            Self::SchemaVersionConflict => {
                formatter.write_str("tool provider reused a schema version with different content")
            }
            Self::SnapshotUnavailable => formatter.write_str("tool provider snapshot unavailable"),
        }
    }
}

impl std::error::Error for ToolProviderError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolErrorKind {
    InvalidInput,
    Cancelled,
    DeadlineExceeded,
    Output,
    Provider,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolError {
    kind: ToolErrorKind,
    category: Option<&'static str>,
    message: Arc<str>,
}

impl ToolError {
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::bounded(ToolErrorKind::InvalidInput, None, message.into())
    }

    pub fn cancelled() -> Self {
        Self::bounded(ToolErrorKind::Cancelled, None, "tool call cancelled".into())
    }

    pub fn deadline_exceeded() -> Self {
        Self::bounded(
            ToolErrorKind::DeadlineExceeded,
            None,
            "tool call deadline exceeded".into(),
        )
    }

    pub fn provider(category: &'static str, message: impl Into<String>) -> Self {
        Self::bounded(ToolErrorKind::Provider, Some(category), message.into())
    }

    pub const fn kind(&self) -> ToolErrorKind {
        self.kind
    }

    pub const fn category(&self) -> Option<&'static str> {
        self.category
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    fn bounded(kind: ToolErrorKind, category: Option<&'static str>, mut message: String) -> Self {
        if message.len() > MAX_TOOL_ERROR_MESSAGE_BYTES {
            message.truncate(floor_char_boundary(&message, MAX_TOOL_ERROR_MESSAGE_BYTES));
        }
        Self {
            kind,
            category,
            message: Arc::from(message),
        }
    }
}

fn floor_char_boundary(value: &str, mut index: usize) -> usize {
    index = index.min(value.len());
    while !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

impl fmt::Display for ToolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ToolErrorKind::InvalidInput => {
                write!(formatter, "invalid tool input: {}", self.message)
            }
            ToolErrorKind::Cancelled | ToolErrorKind::DeadlineExceeded => {
                formatter.write_str(&self.message)
            }
            ToolErrorKind::Output => write!(formatter, "invalid tool output: {}", self.message),
            ToolErrorKind::Provider => write!(
                formatter,
                "tool provider {}: {}",
                self.category.unwrap_or("unknown"),
                self.message
            ),
        }
    }
}

impl std::error::Error for ToolError {}

impl From<ToolOutputError> for ToolError {
    fn from(value: ToolOutputError) -> Self {
        Self::bounded(ToolErrorKind::Output, None, value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        num::{NonZeroU64, NonZeroUsize},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use serde_json::json;

    use super::*;

    struct DefinitionCounter {
        count: Arc<AtomicUsize>,
        name: String,
    }

    impl Tool for DefinitionCounter {
        fn definition(&self) -> ToolDefinition {
            self.count.fetch_add(1, Ordering::SeqCst);
            definition(&self.name)
        }

        fn execute<'a>(
            &'a self,
            _permit: &'a ExecutionPermit,
            context: &'a ToolContext,
            _input: JsonValue,
        ) -> ToolFuture<'a, Result<ToolValue, ToolError>> {
            Box::pin(async move {
                let mut output = context.output_builder();
                output.append_text("ok")?;
                Ok(output.build())
            })
        }
    }

    fn definition(name: &str) -> ToolDefinition {
        ToolDefinition::new(
            name,
            "test tool",
            json!({"type": "object"}),
            ToolSafety::ReadOnly,
            SecurityEffects::empty(),
            ToolCallPolicy::builder(ToolConcurrencyRule::Exclusive)
                .build()
                .unwrap(),
        )
        .unwrap()
    }

    fn registration(name: &str) -> ToolRegistration {
        ToolRegistration::new(Arc::new(DefinitionCounter {
            count: Arc::new(AtomicUsize::new(0)),
            name: name.to_owned(),
        }))
        .unwrap()
    }

    #[test]
    fn registration_captures_one_validated_definition_without_handler_access() {
        let count = Arc::new(AtomicUsize::new(0));
        let registration = ToolRegistration::new(Arc::new(DefinitionCounter {
            count: Arc::clone(&count),
            name: "echo".to_owned(),
        }))
        .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(format!("{registration:?}").contains("echo"));
    }

    #[test]
    fn definition_and_provider_snapshot_bounds_fail_closed() {
        assert!(matches!(
            ToolDefinition::new(
                "NotCanonical",
                "bad",
                json!({}),
                ToolSafety::ReadOnly,
                SecurityEffects::empty(),
                ToolCallPolicy::builder(ToolConcurrencyRule::Exclusive)
                    .build()
                    .unwrap(),
            ),
            Err(ToolRegistrationError::InvalidDefinition(_))
        ));
        assert!(matches!(
            ToolDefinition::new(
                "network-reader",
                "misclassified network tool",
                json!({}),
                ToolSafety::ReadOnly,
                SecurityEffects::NETWORK,
                ToolCallPolicy::builder(ToolConcurrencyRule::Exclusive)
                    .build()
                    .unwrap(),
            ),
            Err(ToolRegistrationError::InvalidPolicy(
                ToolPolicyBuildError::SafetyNotMonotonic
            ))
        ));
        assert!(matches!(
            ToolRegistrationSnapshot::new(
                "provider",
                NonZeroU64::new(1).unwrap(),
                vec![registration("same"), registration("same")],
            ),
            Err(ToolProviderError::DuplicateToolName)
        ));
        let too_many = (0..=MAX_TOOL_REGISTRATIONS_PER_PROVIDER)
            .map(|index| registration(&format!("tool-{index}")))
            .collect();
        assert!(matches!(
            ToolRegistrationSnapshot::new("provider", NonZeroU64::new(1).unwrap(), too_many,),
            Err(ToolProviderError::RegistrationLimitExceeded)
        ));
    }

    #[test]
    fn context_output_builder_inherits_a_checked_budget() {
        let context = ToolContext {
            cancellation: CancellationToken::new(),
            deadline: None,
            output_limits: output::ToolOutputLimits::checked(1, NonZeroUsize::new(2).unwrap(), 1)
                .unwrap(),
            authority: execution::test_nested_authority(),
        };
        let mut output = context.output_builder();
        output.append_text("ok").unwrap();
        assert_eq!(
            output.append_text("x"),
            Err(ToolOutputError::ItemLimitExceeded)
        );
    }

    #[test]
    fn provider_error_messages_are_utf8_safely_bounded() {
        let error = ToolError::provider("test", "界".repeat(MAX_TOOL_ERROR_MESSAGE_BYTES));
        assert_eq!(error.kind(), ToolErrorKind::Provider);
        assert!(error.message().len() <= MAX_TOOL_ERROR_MESSAGE_BYTES);
        assert!(error.message().is_char_boundary(error.message().len()));
    }
}
