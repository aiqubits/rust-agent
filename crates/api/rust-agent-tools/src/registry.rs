use std::{
    fmt,
    num::NonZeroU64,
    sync::{Arc, Mutex},
};

use rust_agent_core::{CanonicalId, Digest, SecurityEffects};

use crate::{
    JsonKind, MAX_TOOL_SCHEMA_BYTES, ToolArgumentPredicate, ToolCallPolicy, ToolConcurrencyRule,
    ToolContribution, ToolDefinition, ToolProviderError, ToolSafety, hash_parts,
};

pub const MAX_TOOL_PROVIDERS: usize = 64;
pub const MAX_TOOLS_PER_AGENT: usize = 256;
pub const MAX_TOOL_SCHEMA_BYTES_PER_AGENT: usize = 1024 * 1024;

#[derive(Clone)]
pub(crate) struct RegisteredTool {
    provider_id: CanonicalId,
    component_id: CanonicalId,
    schema_version: NonZeroU64,
    definition: ToolDefinition,
    effective_ceiling: SecurityEffects,
    identity_digest: Digest,
    handler: Arc<dyn crate::Tool>,
}

impl RegisteredTool {
    pub(crate) fn definition(&self) -> &ToolDefinition {
        &self.definition
    }

    pub(crate) const fn effective_ceiling(&self) -> SecurityEffects {
        self.effective_ceiling
    }

    pub(crate) const fn identity_digest(&self) -> Digest {
        self.identity_digest
    }

    pub(crate) fn handler(&self) -> &Arc<dyn crate::Tool> {
        &self.handler
    }
}

impl fmt::Debug for RegisteredTool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegisteredTool")
            .field("provider_id", &self.provider_id)
            .field("component_id", &self.component_id)
            .field("schema_version", &self.schema_version)
            .field("name", &self.definition.name())
            .field("effective_ceiling", &self.effective_ceiling)
            .finish_non_exhaustive()
    }
}

/// Sealed provider snapshot. Public consumers can inspect definitions but never handlers.
#[derive(Clone, Debug)]
pub struct ToolSetSnapshot {
    provider_id: CanonicalId,
    schema_version: NonZeroU64,
    definitions: Arc<[ToolDefinition]>,
    snapshot_digest: Digest,
    tools: Arc<[RegisteredTool]>,
}

impl ToolSetSnapshot {
    pub fn provider_id(&self) -> &str {
        self.provider_id.as_str()
    }

    pub const fn schema_version(&self) -> NonZeroU64 {
        self.schema_version
    }

    pub fn definitions(&self) -> Arc<[ToolDefinition]> {
        Arc::clone(&self.definitions)
    }

    pub const fn snapshot_digest(&self) -> Digest {
        self.snapshot_digest
    }
}

mod private {
    pub trait Sealed {}
}

/// API-owned adapter surface used by the guarded registry.
#[allow(private_bounds)]
pub trait ToolProvider: rust_agent_core::MaybeSendSync + private::Sealed {
    fn snapshot(&self) -> Result<ToolSetSnapshot, ToolProviderError>;
}

struct AdapterState {
    published: Option<ToolSetSnapshot>,
}

/// Blanket adapter which is the only route from a contribution to a sealed provider snapshot.
#[allow(missing_debug_implementations)]
pub struct CapabilityProviderAdapter<T> {
    contribution: Arc<T>,
    component_id: Option<CanonicalId>,
    effective_ceiling: Option<SecurityEffects>,
    state: Mutex<AdapterState>,
}

impl<T> private::Sealed for CapabilityProviderAdapter<T> {}

impl<T> CapabilityProviderAdapter<T>
where
    T: ToolContribution + 'static,
{
    fn direct(contribution: Arc<T>) -> Self {
        Self {
            contribution,
            component_id: None,
            effective_ceiling: None,
            state: Mutex::new(AdapterState { published: None }),
        }
    }

    fn generated(
        component_id: CanonicalId,
        effective_ceiling: SecurityEffects,
        contribution: Arc<T>,
    ) -> Self {
        Self {
            contribution,
            component_id: Some(component_id),
            effective_ceiling: Some(effective_ceiling),
            state: Mutex::new(AdapterState { published: None }),
        }
    }

    fn seal_snapshot(
        &self,
        snapshot: &crate::ToolRegistrationSnapshot,
    ) -> Result<ToolSetSnapshot, ToolProviderError> {
        let provider_id = CanonicalId::new(snapshot.provider_id().to_owned())
            .map_err(|_| ToolProviderError::InvalidProviderIdentity)?;
        let component_id = self
            .component_id
            .clone()
            .unwrap_or_else(|| provider_id.clone());
        let mut registrations = snapshot.registrations().to_vec();
        registrations.sort_by(|left, right| left.definition.name().cmp(right.definition.name()));

        let mut tools = Vec::with_capacity(registrations.len());
        let mut definitions = Vec::with_capacity(registrations.len());
        let schema_version_bytes = snapshot.schema_version().get().to_be_bytes();
        let mut snapshot_parts = vec![
            b"rust-agent-tool-provider-snapshot-v1\0".as_slice(),
            provider_id.as_str().as_bytes(),
            schema_version_bytes.as_slice(),
        ];
        let mut owned_parts = Vec::<Vec<u8>>::with_capacity(registrations.len());
        for registration in registrations {
            registration
                .definition
                .validate_again()
                .map_err(|_| ToolProviderError::InvalidRegistration)?;
            let declared_maximum = registration.definition.maximum_effects();
            let effective_ceiling = self.effective_ceiling.unwrap_or(declared_maximum);
            if !declared_maximum.is_subset_of(effective_ceiling) {
                return Err(ToolProviderError::EffectCeilingExceeded);
            }
            let schema = serde_json::to_vec(registration.definition.input_schema())
                .map_err(|_| ToolProviderError::InvalidRegistration)?;
            let policy = canonical_policy_bytes(registration.definition.call_policy())?;
            let schema_version_bytes = snapshot.schema_version().get().to_be_bytes();
            let static_effect_bytes = registration
                .definition
                .static_effects()
                .bits()
                .to_be_bytes();
            let ceiling_effect_bytes = effective_ceiling.bits().to_be_bytes();
            let call_cost_bytes = registration
                .definition
                .call_cost()
                .units()
                .get()
                .to_be_bytes();
            let identity_digest = hash_parts(&[
                b"rust-agent-registered-tool-v2\0",
                component_id.as_str().as_bytes(),
                provider_id.as_str().as_bytes(),
                &schema_version_bytes,
                registration.definition.name().as_bytes(),
                registration.definition.description().as_bytes(),
                &schema,
                &[safety_tag(registration.definition.static_safety())],
                &static_effect_bytes,
                &call_cost_bytes,
                &policy,
                &ceiling_effect_bytes,
            ]);
            owned_parts.push(identity_digest.as_bytes().to_vec());
            definitions.push(registration.definition.clone());
            tools.push(RegisteredTool {
                provider_id: provider_id.clone(),
                component_id: component_id.clone(),
                schema_version: snapshot.schema_version(),
                definition: registration.definition,
                effective_ceiling,
                identity_digest,
                handler: registration.handler,
            });
        }
        snapshot_parts.extend(owned_parts.iter().map(Vec::as_slice));
        let snapshot_digest = hash_parts(&snapshot_parts);
        let sealed = ToolSetSnapshot {
            provider_id,
            schema_version: snapshot.schema_version(),
            definitions: definitions.into(),
            snapshot_digest,
            tools: tools.into(),
        };

        let mut state = self
            .state
            .lock()
            .map_err(|_| ToolProviderError::SnapshotUnavailable)?;
        if let Some(published) = &state.published {
            if sealed.schema_version < published.schema_version {
                return Err(ToolProviderError::SchemaVersionRegressed);
            }
            if sealed.schema_version == published.schema_version {
                if sealed.snapshot_digest != published.snapshot_digest {
                    return Err(ToolProviderError::SchemaVersionConflict);
                }
                return Ok(published.clone());
            }
        }
        state.published = Some(sealed.clone());
        Ok(sealed)
    }
}

fn canonical_policy_bytes(policy: &ToolCallPolicy) -> Result<Vec<u8>, ToolProviderError> {
    let mut bytes = Vec::new();
    match policy.concurrency() {
        ToolConcurrencyRule::Exclusive => bytes.push(0),
        ToolConcurrencyRule::ParallelSafe => bytes.push(1),
        ToolConcurrencyRule::ExclusiveByScalar { prefix, pointer } => {
            bytes.push(2);
            append_field(&mut bytes, prefix.as_str().as_bytes())?;
            append_field(&mut bytes, pointer.as_str().as_bytes())?;
        }
    }
    append_usize(&mut bytes, policy.rules().len())?;
    for rule in policy.rules() {
        bytes.push(safety_tag(rule.raise_to()));
        bytes.extend_from_slice(&rule.add_effects().bits().to_be_bytes());
        append_usize(&mut bytes, rule.predicates().len())?;
        for predicate in rule.predicates() {
            match predicate {
                ToolArgumentPredicate::Present { pointer } => {
                    bytes.push(0);
                    append_field(&mut bytes, pointer.as_str().as_bytes())?;
                }
                ToolArgumentPredicate::TypeIs { pointer, kind } => {
                    bytes.push(1);
                    append_field(&mut bytes, pointer.as_str().as_bytes())?;
                    bytes.push(json_kind_tag(*kind));
                }
                ToolArgumentPredicate::ScalarEquals { pointer, value } => {
                    bytes.push(2);
                    append_field(&mut bytes, pointer.as_str().as_bytes())?;
                    let value = serde_json::to_vec(value.as_json())
                        .map_err(|_| ToolProviderError::InvalidRegistration)?;
                    append_field(&mut bytes, &value)?;
                }
            }
        }
    }
    Ok(bytes)
}

fn append_usize(bytes: &mut Vec<u8>, value: usize) -> Result<(), ToolProviderError> {
    let value = u64::try_from(value).map_err(|_| ToolProviderError::InvalidRegistration)?;
    bytes.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn append_field(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), ToolProviderError> {
    append_usize(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
}

const fn safety_tag(safety: ToolSafety) -> u8 {
    match safety {
        ToolSafety::ReadOnly => 0,
        ToolSafety::Mutating => 1,
        ToolSafety::Sensitive => 2,
        ToolSafety::Unknown => 3,
    }
}

const fn json_kind_tag(kind: JsonKind) -> u8 {
    match kind {
        JsonKind::Null => 0,
        JsonKind::Boolean => 1,
        JsonKind::Number => 2,
        JsonKind::String => 3,
        JsonKind::Array => 4,
        JsonKind::Object => 5,
    }
}

impl<T> ToolProvider for CapabilityProviderAdapter<T>
where
    T: ToolContribution + 'static,
{
    fn snapshot(&self) -> Result<ToolSetSnapshot, ToolProviderError> {
        self.seal_snapshot(&self.contribution.snapshot()?)
    }
}

/// Consumer-facing provider binding; it exposes no registration or handler access.
#[derive(Clone)]
pub struct ToolProviderBinding {
    provider: Arc<dyn ToolProvider>,
}

impl ToolProviderBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: ToolContribution + 'static,
    {
        Self {
            provider: Arc::new(CapabilityProviderAdapter::direct(provider)),
        }
    }

    #[doc(hidden)]
    pub fn from_generated_component<T>(
        component_id: impl Into<String>,
        effective_ceiling: SecurityEffects,
        provider: Arc<T>,
    ) -> Result<Self, ToolProviderError>
    where
        T: ToolContribution + 'static,
    {
        let component_id = CanonicalId::new(component_id.into())
            .map_err(|_| ToolProviderError::InvalidComponentIdentity)?;
        Ok(Self {
            provider: Arc::new(CapabilityProviderAdapter::generated(
                component_id,
                effective_ceiling,
                provider,
            )),
        })
    }

    pub(crate) fn snapshot(&self) -> Result<ToolSetSnapshot, ToolProviderError> {
        self.provider.snapshot()
    }
}

impl fmt::Debug for ToolProviderBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolProviderBinding")
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) struct ToolRegistry {
    definitions: Arc<[ToolDefinition]>,
    tools: Arc<[RegisteredTool]>,
    snapshot_digest: Digest,
}

impl ToolRegistry {
    pub(crate) fn from_bindings(
        providers: &[ToolProviderBinding],
    ) -> Result<Self, ToolProviderError> {
        if providers.len() > MAX_TOOL_PROVIDERS {
            return Err(ToolProviderError::ProviderLimitExceeded);
        }
        let mut snapshots = providers
            .iter()
            .map(ToolProviderBinding::snapshot)
            .collect::<Result<Vec<_>, _>>()?;
        snapshots.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
        if snapshots
            .windows(2)
            .any(|pair| pair[0].provider_id == pair[1].provider_id)
        {
            return Err(ToolProviderError::DuplicateProviderIdentity);
        }

        let tool_count = snapshots.iter().try_fold(0_usize, |total, snapshot| {
            total
                .checked_add(snapshot.tools.len())
                .ok_or(ToolProviderError::ToolLimitExceeded)
        })?;
        if tool_count > MAX_TOOLS_PER_AGENT {
            return Err(ToolProviderError::ToolLimitExceeded);
        }
        let schema_bytes = snapshots.iter().try_fold(0_usize, |total, snapshot| {
            let provider_bytes =
                snapshot
                    .definitions
                    .iter()
                    .try_fold(0_usize, |subtotal, definition| {
                        subtotal
                            .checked_add(definition.canonical_schema_bytes())
                            .ok_or(ToolProviderError::SchemaByteLimitExceeded)
                    })?;
            total
                .checked_add(provider_bytes)
                .ok_or(ToolProviderError::SchemaByteLimitExceeded)
        })?;
        if schema_bytes > MAX_TOOL_SCHEMA_BYTES_PER_AGENT
            || snapshots.iter().any(|snapshot| {
                snapshot
                    .definitions
                    .iter()
                    .any(|definition| definition.canonical_schema_bytes() > MAX_TOOL_SCHEMA_BYTES)
            })
        {
            return Err(ToolProviderError::SchemaByteLimitExceeded);
        }

        let mut tools = snapshots
            .iter()
            .flat_map(|snapshot| snapshot.tools.iter().cloned())
            .collect::<Vec<_>>();
        tools.sort_by(|left, right| left.definition.name().cmp(right.definition.name()));
        if tools
            .windows(2)
            .any(|pair| pair[0].definition.name() == pair[1].definition.name())
        {
            return Err(ToolProviderError::DuplicateToolName);
        }
        let definitions = tools
            .iter()
            .map(|tool| tool.definition.clone())
            .collect::<Vec<_>>();
        let digest_parts = snapshots
            .iter()
            .map(|snapshot| snapshot.snapshot_digest.as_bytes().as_slice())
            .collect::<Vec<_>>();
        Ok(Self {
            definitions: definitions.into(),
            tools: tools.into(),
            snapshot_digest: hash_parts(&digest_parts),
        })
    }

    pub(crate) fn definitions(&self) -> Arc<[ToolDefinition]> {
        Arc::clone(&self.definitions)
    }

    pub(crate) fn lookup(&self, name: &str) -> Option<&RegisteredTool> {
        self.tools
            .binary_search_by(|tool| tool.definition.name().cmp(name))
            .ok()
            .map(|index| &self.tools[index])
    }

    pub(crate) const fn snapshot_digest(&self) -> Digest {
        self.snapshot_digest
    }
}

#[cfg(test)]
mod tests {
    use std::{
        num::NonZeroUsize,
        sync::atomic::{AtomicU64, Ordering},
    };

    use serde_json::{Value as JsonValue, json};

    use super::*;
    use crate::{
        ExecutionPermit, Tool, ToolCallPolicy, ToolContext, ToolError, ToolFuture,
        ToolRegistrationSnapshot, ToolSafety, ToolValue,
    };

    #[derive(Debug)]
    struct NoopTool {
        name: String,
        parallel: bool,
        call_cost: crate::ToolCallCost,
    }

    impl Tool for NoopTool {
        fn definition(&self) -> ToolDefinition {
            ToolDefinition::new(
                self.name.clone(),
                "registry fixture",
                json!({"type": "object"}),
                ToolSafety::ReadOnly,
                SecurityEffects::empty(),
                ToolCallPolicy::builder(if self.parallel {
                    crate::ToolConcurrencyRule::ParallelSafe
                } else {
                    crate::ToolConcurrencyRule::Exclusive
                })
                .build()
                .unwrap(),
            )
            .map(|definition| definition.with_call_cost(self.call_cost))
            .unwrap()
        }

        fn execute<'a>(
            &'a self,
            _permit: &'a ExecutionPermit,
            context: &'a ToolContext,
            _input: JsonValue,
        ) -> ToolFuture<'a, Result<ToolValue, ToolError>> {
            Box::pin(async move { Ok(context.output_builder().build()) })
        }
    }

    #[derive(Debug)]
    struct MutableContribution {
        version: AtomicU64,
        variant: AtomicU64,
        policy_variant: AtomicU64,
        cost_variant: AtomicU64,
    }

    impl ToolContribution for MutableContribution {
        fn snapshot(&self) -> Result<ToolRegistrationSnapshot, ToolProviderError> {
            let version = NonZeroU64::new(self.version.load(Ordering::SeqCst)).unwrap();
            let name = if self.variant.load(Ordering::SeqCst) == 0 {
                "alpha"
            } else {
                "beta"
            };
            ToolRegistrationSnapshot::new(
                "mutable-provider",
                version,
                vec![
                    crate::ToolRegistration::new(Arc::new(NoopTool {
                        name: name.to_owned(),
                        parallel: self.policy_variant.load(Ordering::SeqCst) != 0,
                        call_cost: crate::ToolCallCost::checked(
                            NonZeroUsize::new(
                                usize::try_from(self.cost_variant.load(Ordering::SeqCst)).unwrap()
                                    + 1,
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    }))
                    .unwrap(),
                ],
            )
        }
    }

    #[test]
    fn provider_adapter_rejects_regression_and_same_version_content_change() {
        let contribution = Arc::new(MutableContribution {
            version: AtomicU64::new(2),
            variant: AtomicU64::new(0),
            policy_variant: AtomicU64::new(0),
            cost_variant: AtomicU64::new(0),
        });
        let binding = ToolProviderBinding::from_provider(Arc::clone(&contribution));
        let initial = binding.snapshot().unwrap();
        assert_eq!(initial.schema_version().get(), 2);
        assert_eq!(initial.definitions()[0].name(), "alpha");

        contribution.policy_variant.store(1, Ordering::SeqCst);
        assert!(matches!(
            binding.snapshot(),
            Err(ToolProviderError::SchemaVersionConflict)
        ));
        contribution.policy_variant.store(0, Ordering::SeqCst);
        contribution.cost_variant.store(1, Ordering::SeqCst);
        assert!(matches!(
            binding.snapshot(),
            Err(ToolProviderError::SchemaVersionConflict)
        ));
        contribution.cost_variant.store(0, Ordering::SeqCst);
        contribution.version.store(1, Ordering::SeqCst);
        assert!(matches!(
            binding.snapshot(),
            Err(ToolProviderError::SchemaVersionRegressed)
        ));
        contribution.version.store(3, Ordering::SeqCst);
        contribution.variant.store(1, Ordering::SeqCst);
        let replacement = binding.snapshot().unwrap();
        assert_eq!(replacement.schema_version().get(), 3);
        assert_eq!(replacement.definitions()[0].name(), "beta");
    }

    #[test]
    fn registry_rejects_provider_count_and_duplicate_provider_identity() {
        let provider = ToolProviderBinding::from_provider(Arc::new(MutableContribution {
            version: AtomicU64::new(1),
            variant: AtomicU64::new(0),
            policy_variant: AtomicU64::new(0),
            cost_variant: AtomicU64::new(0),
        }));
        assert!(matches!(
            ToolRegistry::from_bindings(&vec![provider.clone(); MAX_TOOL_PROVIDERS + 1]),
            Err(ToolProviderError::ProviderLimitExceeded)
        ));
        assert!(matches!(
            ToolRegistry::from_bindings(&[provider.clone(), provider]),
            Err(ToolProviderError::DuplicateProviderIdentity)
        ));
    }
}
