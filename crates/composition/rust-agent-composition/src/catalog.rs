use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component as PathComponent, Path},
};

use thiserror::Error;

use crate::{
    metadata::{
        AppCoexistence, BindingKind, BuildRequirements, CapabilitySpec, CatalogDocument,
        CatalogResourceBoundsError, ComponentSpec, ConfigSource, HostBoundarySpec, ProvideLayer,
        ResourceNamespaceMode, RuntimeAdapterSpec, ScopeKind, SupportTier, TargetSupport,
    },
    target::{
        CoreTargetFacts, PredicateAnalysisBudget, TargetError, canonical_builtin_facts,
        validate_predicate_partition_with_budget,
    },
};

const SCHEMA_VERSION: u32 = 1;
const RUNTIME_EFFECTS: &[&str] = &[
    "code-execution",
    "host-bridge",
    "network-outbound",
    "persistent-storage",
    "process-exec",
    "read-local",
    "remote-execution",
    "secret-access",
    "write-local",
];
const RUNTIME_PRIMITIVES: &[&str] = &["clock", "sleep", "spawn", "blocking-spawn", "entropy"];

#[derive(Clone, Debug)]
pub struct NormalizedCatalog {
    pub capabilities: BTreeMap<String, CapabilitySpec>,
    pub components: BTreeMap<String, ComponentSpec>,
    pub runtime_adapters: BTreeMap<String, RuntimeAdapterSpec>,
    pub host_boundaries: BTreeMap<String, HostBoundarySpec>,
    pub resource_namespace_requirements: BTreeMap<String, Vec<ResourceNamespaceRequirement>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceNamespaceRequirement {
    pub provide_capability: String,
    pub provide_key: Option<String>,
    pub bootstrap_key: String,
}

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("unsupported catalog schema {0}; expected 1")]
    UnsupportedSchema(u32),
    #[error("duplicate {kind} id `{id}`")]
    DuplicateId { kind: &'static str, id: String },
    #[error("invalid {kind} id `{id}`")]
    InvalidId { kind: &'static str, id: String },
    #[error("invalid Rust path `{path}` in {owner}")]
    InvalidRustPath { owner: String, path: String },
    #[error("invalid package path `{path}` in {owner}")]
    InvalidPackagePath { owner: String, path: String },
    #[error("unknown runtime effect `{effect}` in {owner}")]
    UnknownRuntimeEffect { owner: String, effect: String },
    #[error("runtime effect `{effect}` in {owner} is outside the declared security ceiling")]
    EffectOutsideCeiling { owner: String, effect: String },
    #[error("build requirement `{id}` in {owner} is not canonical kebab-case")]
    InvalidBuildRequirement { owner: String, id: String },
    #[error("unknown runtime primitive `{primitive}` in {owner}")]
    UnknownRuntimePrimitive { owner: String, primitive: String },
    #[error("component `{0}` references unknown capability `{1}`")]
    UnknownCapability(String, String),
    #[error(
        "component `{component}` scope {consumer:?} cannot depend on {provider:?} capability `{capability}`"
    )]
    IllegalScopeDependency {
        component: String,
        consumer: ScopeKind,
        provider: ScopeKind,
        capability: String,
    },
    #[error("component `{0}` has invalid app-coexistence metadata: {1}")]
    InvalidAppCoexistence(String, String),
    #[error("component `{0}` has invalid config metadata: {1}")]
    InvalidConfig(String, String),
    #[error("component `{0}` has invalid binding metadata: {1}")]
    InvalidBinding(String, String),
    #[error("component `{0}` has duplicate requirement field `{1}`")]
    DuplicateRequirementField(String, String),
    #[error("component `{0}` conflicts with unknown component `{1}`")]
    UnknownConflict(String, String),
    #[error("selectable components `{0}` and `{1}` share Cargo package `{2}`")]
    SharedComponentPackage(String, String, String),
    #[error("runtime adapter `{0}` must have an empty runtime security ceiling")]
    EffectfulRuntimeAdapter(String),
    #[error("host boundary `{0}` has an empty runtime-adapter allowlist")]
    EmptyHostAdapterAllowlist(String),
    #[error("component `{0}` has invalid resource-namespace metadata: {1}")]
    InvalidResourceNamespace(String, String),
    #[error("target predicate in {owner} is invalid: {source}")]
    InvalidTargetPredicate { owner: String, source: TargetError },
    #[error("target support in {owner} is invalid: {message}")]
    InvalidTargetSupport { owner: String, message: String },
    #[error("target support predicate in {owner} is invalid: {source}")]
    InvalidTargetSupportPredicate { owner: String, source: TargetError },
    #[error("catalog owner count overflowed")]
    CatalogOwnerCountOverflow,
    #[error("catalog has {actual} owners; maximum is {maximum}")]
    CatalogOwnerLimitExceeded { actual: usize, maximum: usize },
}

impl NormalizedCatalog {
    pub fn normalize(document: CatalogDocument) -> Result<Self, CatalogError> {
        let mut predicate_analysis_budget = PredicateAnalysisBudget::new();
        Self::normalize_with_predicate_budget(document, &mut predicate_analysis_budget)
    }

    fn normalize_with_predicate_budget(
        document: CatalogDocument,
        predicate_analysis_budget: &mut PredicateAnalysisBudget,
    ) -> Result<Self, CatalogError> {
        document
            .validate_resource_bounds()
            .map_err(|error| match error {
                CatalogResourceBoundsError::OwnerCountOverflow => {
                    CatalogError::CatalogOwnerCountOverflow
                }
                CatalogResourceBoundsError::TooManyOwners { actual, maximum } => {
                    CatalogError::CatalogOwnerLimitExceeded { actual, maximum }
                }
            })?;
        if document.schema != SCHEMA_VERSION {
            return Err(CatalogError::UnsupportedSchema(document.schema));
        }

        let capabilities = collect_unique("capability", document.capabilities, |value| &value.id)?;
        let mut components = collect_unique("component", document.components, |value| &value.id)?;
        let mut runtime_adapters =
            collect_unique("runtime adapter", document.runtime_adapters, |value| {
                &value.id
            })?;
        let mut host_boundaries =
            collect_unique("host boundary", document.host_boundaries, |value| &value.id)?;

        for capability in capabilities.values() {
            validate_capability(capability)?;
        }

        let mut package_owners = BTreeMap::new();
        for component in components.values_mut() {
            normalize_target_support(
                &component.id,
                &component.targets,
                &mut component.support,
                &mut component.target_support,
                predicate_analysis_budget,
            )?;
            validate_component(component, &capabilities)?;
            if let Some(previous) =
                package_owners.insert(component.package.clone(), component.id.clone())
            {
                return Err(CatalogError::SharedComponentPackage(
                    previous,
                    component.id.clone(),
                    component.package.clone(),
                ));
            }
        }
        for component in components.values() {
            for conflict in &component.conflicts {
                if !components.contains_key(conflict) {
                    return Err(CatalogError::UnknownConflict(
                        component.id.clone(),
                        conflict.clone(),
                    ));
                }
            }
        }
        let resource_namespace_requirements =
            normalize_resource_namespace_requirements(&components, &capabilities)?;
        for adapter in runtime_adapters.values_mut() {
            normalize_target_support(
                &adapter.id,
                &adapter.targets,
                &mut adapter.support,
                &mut adapter.target_support,
                predicate_analysis_budget,
            )?;
            validate_adapter(adapter)?;
        }
        for boundary in host_boundaries.values_mut() {
            normalize_target_support(
                &boundary.id,
                &boundary.targets,
                &mut boundary.support,
                &mut boundary.target_support,
                predicate_analysis_budget,
            )?;
            validate_boundary(boundary)?;
        }

        Ok(Self {
            capabilities,
            components,
            runtime_adapters,
            host_boundaries,
            resource_namespace_requirements,
        })
    }

    pub(crate) fn to_document(&self) -> CatalogDocument {
        CatalogDocument {
            schema: SCHEMA_VERSION,
            capabilities: self.capabilities.values().cloned().collect(),
            components: self.components.values().cloned().collect(),
            runtime_adapters: self.runtime_adapters.values().cloned().collect(),
            host_boundaries: self.host_boundaries.values().cloned().collect(),
        }
    }
}

fn collect_unique<T, F>(
    kind: &'static str,
    values: Vec<T>,
    id: F,
) -> Result<BTreeMap<String, T>, CatalogError>
where
    F: Fn(&T) -> &String,
{
    let mut result = BTreeMap::new();
    for value in values {
        let key = id(&value).clone();
        if result.insert(key.clone(), value).is_some() {
            return Err(CatalogError::DuplicateId { kind, id: key });
        }
    }
    Ok(result)
}

fn validate_capability(spec: &CapabilitySpec) -> Result<(), CatalogError> {
    validate_capability_id(&spec.id, "capability")?;
    validate_id(&spec.api_package, "Cargo package")?;
    validate_rust_path(&spec.id, &spec.rust_api)?;
    validate_rust_path(&spec.id, &spec.binding_type)?;
    validate_rust_path(&spec.id, &spec.binding_adapter)?;
    Ok(())
}

fn validate_component(
    spec: &ComponentSpec,
    capabilities: &BTreeMap<String, CapabilitySpec>,
) -> Result<(), CatalogError> {
    validate_id(&spec.id, "component")?;
    validate_id(&spec.package, "Cargo package")?;
    validate_package_path(&spec.id, &spec.package_path)?;
    validate_rust_path(&spec.id, &spec.factory)?;
    validate_rust_path(&spec.id, &spec.dependencies_type)?;
    validate_rust_path(&spec.id, &spec.config_type)?;
    if let Some(preparer) = &spec.resource_namespace_preparer {
        validate_rust_path(&spec.id, preparer)?;
    }
    if let Some(prepared) = &spec.prepared_config_type {
        validate_rust_path(&spec.id, prepared)?;
    }
    validate_target_syntax(&spec.id, &spec.targets)?;

    match spec.config_source {
        ConfigSource::None if spec.config_key.is_some() => {
            return Err(CatalogError::InvalidConfig(
                spec.id.clone(),
                "none source forbids config-key".into(),
            ));
        }
        ConfigSource::File | ConfigSource::Host
            if spec.config_key.as_deref() != Some(spec.id.as_str()) =>
        {
            return Err(CatalogError::InvalidConfig(
                spec.id.clone(),
                "file/host config-key must exactly equal component id".into(),
            ));
        }
        _ => {}
    }

    match (&spec.scope, &spec.app_coexistence) {
        (ScopeKind::App, None) => {
            return Err(CatalogError::InvalidAppCoexistence(
                spec.id.clone(),
                "App-scoped component must declare app-coexistence".into(),
            ));
        }
        (ScopeKind::Session | ScopeKind::Agent, Some(_)) => {
            return Err(CatalogError::InvalidAppCoexistence(
                spec.id.clone(),
                "Session/Agent component must not declare app-coexistence".into(),
            ));
        }
        _ => {}
    }
    if let Some(coexistence) = &spec.app_coexistence {
        validate_coexistence(&spec.id, coexistence, spec.config_source)?;
    }

    validate_effects(&spec.id, &spec.security)?;
    for effect in &spec.lifecycle_effects {
        if !spec.security.contains(effect) {
            return Err(CatalogError::EffectOutsideCeiling {
                owner: format!("{} lifecycle", spec.id),
                effect: effect.clone(),
            });
        }
    }
    validate_effects(&format!("{} lifecycle", spec.id), &spec.lifecycle_effects)?;
    validate_build_requirements(&spec.id, &spec.build_requirements)?;
    for primitive in &spec.runtime_primitives {
        if !RUNTIME_PRIMITIVES.contains(&primitive.as_str()) {
            return Err(CatalogError::UnknownRuntimePrimitive {
                owner: spec.id.clone(),
                primitive: primitive.clone(),
            });
        }
    }

    let mut fields = BTreeSet::new();
    for requirement in &spec.requires {
        validate_capability_id(&requirement.capability, "requirement capability")?;
        validate_rust_field(&spec.id, &requirement.field)?;
        if !fields.insert(requirement.field.clone()) {
            return Err(CatalogError::DuplicateRequirementField(
                spec.id.clone(),
                requirement.field.clone(),
            ));
        }
        let capability = capabilities.get(&requirement.capability).ok_or_else(|| {
            CatalogError::UnknownCapability(spec.id.clone(), requirement.capability.clone())
        })?;
        if !spec.scope.may_depend_on(capability.scope) {
            return Err(CatalogError::IllegalScopeDependency {
                component: spec.id.clone(),
                consumer: spec.scope,
                provider: capability.scope,
                capability: requirement.capability.clone(),
            });
        }
        match capability.binding {
            BindingKind::Registry if requirement.key.is_none() => {
                return Err(CatalogError::InvalidBinding(
                    spec.id.clone(),
                    format!(
                        "registry requirement `{}` needs a key",
                        requirement.capability
                    ),
                ));
            }
            BindingKind::Registry => {
                validate_id(requirement.key.as_deref().unwrap(), "provider key")?;
            }
            _ if requirement.key.is_some() => {
                return Err(CatalogError::InvalidBinding(
                    spec.id.clone(),
                    format!(
                        "non-registry requirement `{}` forbids a key",
                        requirement.capability
                    ),
                ));
            }
            _ => {}
        }
    }

    if spec.provides.is_empty() {
        return Err(CatalogError::InvalidBinding(
            spec.id.clone(),
            "component provides nothing".into(),
        ));
    }
    for provide in &spec.provides {
        let capability = capabilities.get(&provide.capability).ok_or_else(|| {
            CatalogError::UnknownCapability(spec.id.clone(), provide.capability.clone())
        })?;
        if capability.scope != spec.scope {
            return Err(CatalogError::InvalidBinding(
                spec.id.clone(),
                format!(
                    "provide `{}` scope does not match component",
                    provide.capability
                ),
            ));
        }
        validate_effects(
            &format!("{} provide {}", spec.id, provide.capability),
            &provide.effects,
        )?;
        for effect in &provide.effects {
            if !spec.security.contains(effect) {
                return Err(CatalogError::EffectOutsideCeiling {
                    owner: format!("{} provide {}", spec.id, provide.capability),
                    effect: effect.clone(),
                });
            }
        }
        match capability.binding {
            BindingKind::Registry if provide.key.is_none() => {
                return Err(CatalogError::InvalidBinding(
                    spec.id.clone(),
                    format!("registry provide `{}` needs a key", provide.capability),
                ));
            }
            BindingKind::Registry => validate_id(provide.key.as_deref().unwrap(), "provider key")?,
            _ if provide.key.is_some() => {
                return Err(CatalogError::InvalidBinding(
                    spec.id.clone(),
                    format!(
                        "non-registry provide `{}` forbids a key",
                        provide.capability
                    ),
                ));
            }
            _ => {}
        }
        match capability.binding {
            BindingKind::DecoratorChain => {}
            _ if provide.layer == ProvideLayer::Decorator || provide.order != 0 => {
                return Err(CatalogError::InvalidBinding(
                    spec.id.clone(),
                    format!("provide `{}` has decorator-only fields", provide.capability),
                ));
            }
            _ => {}
        }
    }

    for conflict in &spec.conflicts {
        validate_id(conflict, "component conflict")?;
    }
    for feature in &spec.cargo_features {
        validate_id(feature, "Cargo feature")?;
        if feature.starts_with("no-") || feature.starts_with("disable-") {
            return Err(CatalogError::InvalidBinding(
                spec.id.clone(),
                format!("negative Cargo feature `{feature}` is forbidden"),
            ));
        }
    }
    Ok(())
}

fn normalize_resource_namespace_requirements(
    components: &BTreeMap<String, ComponentSpec>,
    capabilities: &BTreeMap<String, CapabilitySpec>,
) -> Result<BTreeMap<String, Vec<ResourceNamespaceRequirement>>, CatalogError> {
    let mut requirements = BTreeMap::new();
    for component in components.values() {
        let mut component_requirements = Vec::new();
        for provide in &component.provides {
            let ResourceNamespaceMode::Required { bootstrap } = &provide.resource_namespace else {
                continue;
            };
            validate_id(bootstrap, "resource namespace bootstrap key")?;
            component_requirements.push(ResourceNamespaceRequirement {
                provide_capability: provide.capability.clone(),
                provide_key: provide.key.clone(),
                bootstrap_key: bootstrap.clone(),
            });
        }

        match (
            component_requirements.is_empty(),
            component.resource_namespace_preparer.as_ref(),
            component.prepared_config_type.as_ref(),
        ) {
            (true, None, None) | (false, Some(_), Some(_)) => {}
            (true, _, _) => {
                return Err(CatalogError::InvalidResourceNamespace(
                    component.id.clone(),
                    "preparer/prepared-config-type are forbidden without a required provide".into(),
                ));
            }
            (false, _, _) => {
                return Err(CatalogError::InvalidResourceNamespace(
                    component.id.clone(),
                    "every required provide needs both resource-namespace-preparer and prepared-config-type"
                        .into(),
                ));
            }
        }

        for requirement in &component_requirements {
            validate_bootstrap_requirement(component, requirement, components, capabilities)?;
        }
        if !component_requirements.is_empty() {
            component_requirements.sort_by(|left, right| {
                (
                    &left.provide_capability,
                    &left.provide_key,
                    &left.bootstrap_key,
                )
                    .cmp(&(
                        &right.provide_capability,
                        &right.provide_key,
                        &right.bootstrap_key,
                    ))
            });
            requirements.insert(component.id.clone(), component_requirements);
        }
    }
    Ok(requirements)
}

fn validate_bootstrap_requirement(
    consumer: &ComponentSpec,
    requirement: &ResourceNamespaceRequirement,
    components: &BTreeMap<String, ComponentSpec>,
    capabilities: &BTreeMap<String, CapabilitySpec>,
) -> Result<(), CatalogError> {
    let capability = capabilities
        .get("cap:resource-namespace-bootstrap")
        .ok_or_else(|| {
            CatalogError::InvalidResourceNamespace(
                consumer.id.clone(),
                "required namespace needs cap:resource-namespace-bootstrap".into(),
            )
        })?;
    if capability.binding != BindingKind::Registry || capability.scope != ScopeKind::App {
        return Err(CatalogError::InvalidResourceNamespace(
            consumer.id.clone(),
            "cap:resource-namespace-bootstrap must be an App Registry".into(),
        ));
    }

    let providers: Vec<_> = components
        .values()
        .filter(|candidate| {
            candidate.provides.iter().any(|provide| {
                provide.capability == capability.id
                    && provide.key.as_deref() == Some(requirement.bootstrap_key.as_str())
            })
        })
        .collect();
    let [provider] = providers.as_slice() else {
        return Err(CatalogError::InvalidResourceNamespace(
            consumer.id.clone(),
            format!(
                "bootstrap key `{}` must resolve to exactly one provider",
                requirement.bootstrap_key
            ),
        ));
    };
    let bootstrap_provide = provider
        .provides
        .iter()
        .find(|provide| {
            provide.capability == capability.id
                && provide.key.as_deref() == Some(requirement.bootstrap_key.as_str())
        })
        .expect("provider was selected by this exact provide");
    if provider.scope != ScopeKind::App
        || !provider.lifecycle_effects.is_empty()
        || !provider.requires.is_empty()
        || provider.config_source != ConfigSource::None
        || bootstrap_provide.effects.is_empty()
        || provider
            .provides
            .iter()
            .any(|provide| !matches!(provide.resource_namespace, ResourceNamespaceMode::None))
    {
        return Err(CatalogError::InvalidResourceNamespace(
            consumer.id.clone(),
            format!(
                "bootstrap provider `{}` must be App-scoped, stateless-configured, effect-accounted, dependency-free, and namespace-free",
                provider.id
            ),
        ));
    }
    Ok(())
}

fn validate_adapter(spec: &RuntimeAdapterSpec) -> Result<(), CatalogError> {
    validate_id(&spec.id, "runtime adapter")?;
    validate_id(&spec.package, "Cargo package")?;
    validate_package_path(&spec.id, &spec.package_path)?;
    validate_rust_path(&spec.id, &spec.constructor)?;
    validate_target_syntax(&spec.id, &spec.targets)?;
    validate_effects(&spec.id, &spec.security)?;
    if !spec.security.is_empty() {
        return Err(CatalogError::EffectfulRuntimeAdapter(spec.id.clone()));
    }
    validate_coexistence(&spec.id, &spec.app_coexistence, ConfigSource::None)?;
    validate_build_requirements(&spec.id, &spec.build_requirements)?;
    for primitive in &spec.primitives {
        if !RUNTIME_PRIMITIVES.contains(&primitive.as_str()) {
            return Err(CatalogError::UnknownRuntimePrimitive {
                owner: spec.id.clone(),
                primitive: primitive.clone(),
            });
        }
    }
    Ok(())
}

fn validate_boundary(spec: &HostBoundarySpec) -> Result<(), CatalogError> {
    validate_id(&spec.id, "host boundary")?;
    validate_id(&spec.package, "Cargo package")?;
    validate_package_path(&spec.id, &spec.package_path)?;
    validate_target_syntax(&spec.id, &spec.targets)?;
    validate_effects(&spec.id, &spec.security)?;
    validate_build_requirements(&spec.id, &spec.build_requirements)?;
    match spec.kind {
        crate::metadata::HostBoundaryKind::Entry
            if spec.entry.is_some() && spec.export_module.is_none() =>
        {
            validate_rust_path(&spec.id, spec.entry.as_deref().unwrap())?;
        }
        crate::metadata::HostBoundaryKind::WasmExport
            if spec.entry.is_none() && spec.export_module.is_some() =>
        {
            validate_rust_path(&spec.id, spec.export_module.as_deref().unwrap())?;
            if !spec
                .build_requirements
                .executables
                .contains(crate::WASM_BINDGEN_CLI_LOGICAL_ID)
            {
                return Err(CatalogError::InvalidBinding(
                    spec.id.clone(),
                    "WASM Host export requires executable `wasm-bindgen-cli`".into(),
                ));
            }
        }
        _ => {
            return Err(CatalogError::InvalidBinding(
                spec.id.clone(),
                "Host boundary kind requires exactly its matching entry/export-module path".into(),
            ));
        }
    }
    if spec.runtime_adapters.is_empty() {
        return Err(CatalogError::EmptyHostAdapterAllowlist(spec.id.clone()));
    }
    for adapter in &spec.runtime_adapters {
        validate_id(adapter, "runtime adapter")?;
    }
    Ok(())
}

fn validate_effects(owner: &str, effects: &BTreeSet<String>) -> Result<(), CatalogError> {
    for effect in effects {
        if !RUNTIME_EFFECTS.contains(&effect.as_str()) {
            return Err(CatalogError::UnknownRuntimeEffect {
                owner: owner.to_owned(),
                effect: effect.clone(),
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_build_requirements(
    owner: &str,
    value: &BuildRequirements,
) -> Result<(), CatalogError> {
    for id in value
        .executables
        .iter()
        .chain(&value.read_inputs)
        .chain(&value.environment)
    {
        if !is_id(id) {
            return Err(CatalogError::InvalidBuildRequirement {
                owner: owner.to_owned(),
                id: id.clone(),
            });
        }
    }
    Ok(())
}

fn validate_coexistence(
    owner: &str,
    value: &AppCoexistence,
    config_source: ConfigSource,
) -> Result<(), CatalogError> {
    match value {
        AppCoexistence::RequiresStop => Ok(()),
        AppCoexistence::ConcurrentIndependent { evidence } => validate_evidence(owner, evidence),
        AppCoexistence::ConcurrentSharedHostHandle {
            evidence,
            host_config_fields,
        } => {
            if config_source != ConfigSource::Host {
                return Err(CatalogError::InvalidAppCoexistence(
                    owner.to_owned(),
                    "shared-host-handle requires config-source=host".into(),
                ));
            }
            if host_config_fields.is_empty() {
                return Err(CatalogError::InvalidAppCoexistence(
                    owner.to_owned(),
                    "shared-host-handle needs at least one field".into(),
                ));
            }
            validate_evidence(owner, evidence)
        }
    }
}

fn validate_evidence(
    owner: &str,
    evidence: &crate::metadata::EvidenceRef,
) -> Result<(), CatalogError> {
    if evidence.algorithm != "sha256"
        || evidence.digest.len() != 64
        || evidence
            .digest
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        || !is_safe_relative_path(&evidence.source)
        || !is_id(&evidence.reviewer_policy)
    {
        return Err(CatalogError::InvalidAppCoexistence(
            owner.to_owned(),
            "invalid evidence source, algorithm, digest, or reviewer policy".into(),
        ));
    }
    Ok(())
}

fn validate_target_syntax(owner: &str, predicate: &str) -> Result<(), CatalogError> {
    // Parsing against inert facts validates the closed grammar; the truth value is irrelevant.
    let target = crate::target::Target::from_facts(
        "validation-unknown-none",
        crate::target::Environment::Server,
        minimal_validation_target_facts(),
    )
    .expect("the static validation target facts are canonical");
    target
        .matches(predicate)
        .map(|_| ())
        .map_err(|source| CatalogError::InvalidTargetPredicate {
            owner: owner.to_owned(),
            source,
        })
}

fn normalize_target_support(
    owner: &str,
    targets: &str,
    support: &mut Option<SupportTier>,
    target_support: &mut Option<Vec<TargetSupport>>,
    predicate_analysis_budget: &mut PredicateAnalysisBudget,
) -> Result<(), CatalogError> {
    validate_target_support(
        owner,
        targets,
        *support,
        target_support.as_deref(),
        predicate_analysis_budget,
    )?;
    if let Some(tier) = support.take() {
        *target_support = Some(vec![TargetSupport {
            predicate: targets.into(),
            tier,
        }]);
    }
    target_support
        .as_mut()
        .expect("validated target support is always present")
        .sort();
    Ok(())
}

fn validate_target_support(
    owner: &str,
    targets: &str,
    support: Option<SupportTier>,
    target_support: Option<&[TargetSupport]>,
    predicate_analysis_budget: &mut PredicateAnalysisBudget,
) -> Result<(), CatalogError> {
    match (support, target_support) {
        (Some(_), None) => Ok(()),
        (Some(_), Some(_)) => Err(CatalogError::InvalidTargetSupport {
            owner: owner.into(),
            message: "blanket `support` and `target-support` are mutually exclusive".into(),
        }),
        (None, None) => Err(CatalogError::InvalidTargetSupport {
            owner: owner.into(),
            message: "exactly one of blanket `support` or `target-support` is required".into(),
        }),
        (None, Some([])) => Err(CatalogError::InvalidTargetSupport {
            owner: owner.into(),
            message: "`target-support` must not be empty".into(),
        }),
        (None, Some(entries)) => {
            let predicates = entries
                .iter()
                .map(|entry| entry.predicate.as_str())
                .collect::<Vec<_>>();
            validate_predicate_partition_with_budget(
                targets,
                &predicates,
                predicate_analysis_budget,
            )
            .map_err(|source| CatalogError::InvalidTargetSupportPredicate {
                owner: owner.into(),
                source,
            })
        }
    }
}

fn minimal_validation_target_facts() -> BTreeMap<String, BTreeSet<Option<String>>> {
    canonical_builtin_facts(CoreTargetFacts::little_endian(
        "x86_64", "gnu", "linux", "64", "unwind",
    ))
    .expect("the static core target facts are canonical")
}

fn validate_id(value: &str, kind: &'static str) -> Result<(), CatalogError> {
    if is_id(value) {
        Ok(())
    } else {
        Err(CatalogError::InvalidId {
            kind,
            id: value.to_owned(),
        })
    }
}

fn validate_capability_id(value: &str, kind: &'static str) -> Result<(), CatalogError> {
    if value.strip_prefix("cap:").is_some_and(is_id) {
        Ok(())
    } else {
        Err(CatalogError::InvalidId {
            kind,
            id: value.to_owned(),
        })
    }
}

fn is_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && !bytes.windows(2).any(|pair| pair == b"--")
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn validate_rust_field(owner: &str, value: &str) -> Result<(), CatalogError> {
    let valid = !value.is_empty()
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && !matches!(
            value,
            "self" | "super" | "crate" | "type" | "match" | "fn" | "mod"
        );
    if valid {
        Ok(())
    } else {
        Err(CatalogError::InvalidRustPath {
            owner: owner.to_owned(),
            path: value.to_owned(),
        })
    }
}

fn validate_rust_path(owner: &str, value: &str) -> Result<(), CatalogError> {
    let valid = !value.is_empty()
        && value.split("::").all(|segment| {
            !segment.is_empty()
                && (segment.as_bytes()[0].is_ascii_lowercase()
                    || segment.as_bytes()[0].is_ascii_uppercase())
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        });
    if valid {
        Ok(())
    } else {
        Err(CatalogError::InvalidRustPath {
            owner: owner.to_owned(),
            path: value.to_owned(),
        })
    }
}

fn validate_package_path(owner: &str, value: &str) -> Result<(), CatalogError> {
    if is_safe_relative_path(value) {
        Ok(())
    } else {
        Err(CatalogError::InvalidPackagePath {
            owner: owner.to_owned(),
            path: value.to_owned(),
        })
    }
}

fn is_safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !value.contains('\\')
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, PathComponent::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
schema = 1

[[capabilities]]
id = "cap:model"
api-package = "rust-agent-fixture-api"
rust-api = "rust_agent_fixture_api::Model"
binding-type = "rust_agent_fixture_api::ModelBinding"
binding-adapter = "rust_agent_fixture_api::ModelBinding::from_provider"
binding = "singleton"
scope = "app"

[[components]]
id = "model"
package = "fixture-model"
package-path = "fixtures/model"
scope = "app"
factory = "fixture_model::build"
dependencies-type = "fixture_model::Dependencies"
config-type = "fixture_model::Config"
config-source = "none"
targets = "cfg(true)"
support = "production"
lifecycle-effects = []
security = []
runtime-primitives = []
app-coexistence = { mode = "requires-stop" }
cargo-features = []
build-requirements = { executables = [], read-inputs = [], environment = [] }
provides = [{ capability = "cap:model", priority = 1, effects = [] }]
"#;

    #[test]
    fn valid_minimal_catalog_normalizes() {
        let document = CatalogDocument::from_toml(BASE).unwrap();
        let catalog = NormalizedCatalog::normalize(document).unwrap();
        assert!(catalog.components.contains_key("model"));
    }

    fn catalog_with_component_target_support(targets: &str, support: &str) -> String {
        BASE.replace(
            "targets = \"cfg(true)\"\nsupport = \"production\"",
            &format!("targets = '{targets}'\n{support}"),
        )
    }

    #[test]
    fn blanket_support_normalizes_to_an_exact_round_trippable_entry() {
        let catalog =
            NormalizedCatalog::normalize(CatalogDocument::from_toml(BASE).unwrap()).unwrap();
        let component = &catalog.components["model"];
        assert_eq!(component.support, None);
        assert_eq!(
            component.target_support.as_deref(),
            Some(
                [TargetSupport {
                    predicate: "cfg(true)".into(),
                    tier: SupportTier::Production,
                }]
                .as_slice()
            )
        );

        let encoded = serde_json::to_vec(component).unwrap();
        let decoded: ComponentSpec = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.support, None);
        assert_eq!(decoded.target_support, component.target_support);
    }

    #[test]
    fn explicit_support_partition_is_canonical_and_order_deterministic() {
        let targets = "cfg(any(target_os = \"linux\", target_os = \"windows\"))";
        let linux = "{ predicate = 'cfg(target_os = \"linux\")', tier = \"production\" }";
        let windows = "{ predicate = 'cfg(target_os = \"windows\")', tier = \"experimental\" }";
        let first = catalog_with_component_target_support(
            targets,
            &format!("target-support = [{windows}, {linux}]"),
        );
        let second = catalog_with_component_target_support(
            targets,
            &format!("target-support = [{linux}, {windows}]"),
        );
        let first =
            NormalizedCatalog::normalize(CatalogDocument::from_toml(&first).unwrap()).unwrap();
        let second =
            NormalizedCatalog::normalize(CatalogDocument::from_toml(&second).unwrap()).unwrap();
        let first = &first.components["model"];
        let second = &second.components["model"];
        assert_eq!(first.target_support, second.target_support);
        assert_eq!(
            serde_json::to_vec(first).unwrap(),
            serde_json::to_vec(second).unwrap()
        );
    }

    #[test]
    fn target_support_shape_and_unknown_fields_fail_closed() {
        let both = BASE.replace(
            "support = \"production\"",
            "support = \"production\"\ntarget-support = [{ predicate = 'cfg(true)', tier = \"production\" }]",
        );
        assert!(matches!(
            NormalizedCatalog::normalize(CatalogDocument::from_toml(&both).unwrap()),
            Err(CatalogError::InvalidTargetSupport { owner, .. }) if owner == "model"
        ));

        for support in ["", "target-support = []"] {
            let input = BASE.replace("support = \"production\"", support);
            assert!(matches!(
                NormalizedCatalog::normalize(CatalogDocument::from_toml(&input).unwrap()),
                Err(CatalogError::InvalidTargetSupport { owner, .. }) if owner == "model"
            ));
        }

        let unknown = BASE.replace(
            "support = \"production\"",
            "target-support = [{ predicate = 'cfg(true)', tier = \"production\", rank = 1 }]",
        );
        assert!(CatalogDocument::from_toml(&unknown).is_err());
    }

    #[test]
    fn target_support_partition_rejects_dead_outside_overlap_and_gap_entries() {
        let dead = catalog_with_component_target_support(
            "cfg(true)",
            "target-support = [{ predicate = 'cfg(false)', tier = \"production\" }, { predicate = 'cfg(true)', tier = \"experimental\" }]",
        );
        assert!(matches!(
            NormalizedCatalog::normalize(CatalogDocument::from_toml(&dead).unwrap()),
            Err(CatalogError::InvalidTargetSupportPredicate {
                owner,
                source: TargetError::PredicatePartitionUnsatisfiable { index: 0 }
            }) if owner == "model"
        ));

        let outside = catalog_with_component_target_support(
            "cfg(target_os = \"linux\")",
            "target-support = [{ predicate = 'cfg(target_os = \"windows\")', tier = \"production\" }]",
        );
        assert!(matches!(
            NormalizedCatalog::normalize(CatalogDocument::from_toml(&outside).unwrap()),
            Err(CatalogError::InvalidTargetSupportPredicate {
                owner,
                source: TargetError::PredicatePartitionOutsideParent { index: 0 }
            }) if owner == "model"
        ));

        let overlap = catalog_with_component_target_support(
            "cfg(any(target_feature = \"sse\", target_feature = \"avx\"))",
            "target-support = [{ predicate = 'cfg(target_feature = \"sse\")', tier = \"production\" }, { predicate = 'cfg(target_feature = \"avx\")', tier = \"experimental\" }]",
        );
        assert!(matches!(
            NormalizedCatalog::normalize(CatalogDocument::from_toml(&overlap).unwrap()),
            Err(CatalogError::InvalidTargetSupportPredicate {
                owner,
                source: TargetError::PredicatePartitionOverlap { first: 0, second: 1 }
            }) if owner == "model"
        ));

        let gap = catalog_with_component_target_support(
            "cfg(true)",
            "target-support = [{ predicate = 'cfg(target_os = \"linux\")', tier = \"production\" }, { predicate = 'cfg(target_os = \"windows\")', tier = \"experimental\" }]",
        );
        assert!(matches!(
            NormalizedCatalog::normalize(CatalogDocument::from_toml(&gap).unwrap()),
            Err(CatalogError::InvalidTargetSupportPredicate {
                owner,
                source: TargetError::PredicatePartitionGap
            }) if owner == "model"
        ));
    }

    #[test]
    fn target_support_entry_count_boundary_is_bounded() {
        let maximum = crate::target::MAX_TARGET_PREDICATE_PARTITIONS;
        let predicates = (0..maximum)
            .map(|index| format!("target_os = \"custom-{index}\""))
            .collect::<Vec<_>>();
        let targets = format!("cfg(any({}))", predicates.join(", "));
        let entries = (0..maximum)
            .map(|index| {
                format!(
                    "{{ predicate = 'cfg(target_os = \"custom-{index}\")', tier = \"production\" }}"
                )
            })
            .collect::<Vec<_>>();
        let exact = catalog_with_component_target_support(
            &targets,
            &format!("target-support = [{}]", entries.join(", ")),
        );
        NormalizedCatalog::normalize(CatalogDocument::from_toml(&exact).unwrap()).unwrap();

        let mut excess_entries = entries;
        excess_entries
            .push("{ predicate = 'cfg(target_os = \"overflow\")', tier = \"production\" }".into());
        let excess = catalog_with_component_target_support(
            "cfg(true)",
            &format!("target-support = [{}]", excess_entries.join(", ")),
        );
        assert!(CatalogDocument::from_toml(&excess).is_err());
    }

    #[test]
    fn catalog_target_support_analysis_budget_is_shared_across_owners() {
        let explicit = catalog_with_component_target_support(
            "cfg(true)",
            "target-support = [{ predicate = 'cfg(true)', tier = \"production\" }]",
        );
        let one_owner = CatalogDocument::from_toml(&explicit).unwrap();
        NormalizedCatalog::normalize(one_owner.clone()).unwrap();

        let succeeds_with = |document: CatalogDocument, work| {
            let mut budget = PredicateAnalysisBudget::with_work_limit_for_test(work);
            NormalizedCatalog::normalize_with_predicate_budget(document, &mut budget).is_ok()
        };
        let mut upper = 1_usize;
        while !succeeds_with(one_owner.clone(), upper) {
            upper = upper.checked_mul(2).expect("test budget search is bounded");
        }
        let mut lower = 0_usize;
        while lower + 1 < upper {
            let middle = lower + (upper - lower) / 2;
            if succeeds_with(one_owner.clone(), middle) {
                upper = middle;
            } else {
                lower = middle;
            }
        }
        let exact_single_owner_work = upper;
        assert!(succeeds_with(one_owner.clone(), exact_single_owner_work));

        let mut two_owners = one_owner;
        let mut second = two_owners.components[0].clone();
        second.id = "model-second".into();
        second.package = "fixture-model-second".into();
        second.package_path = "fixtures/model-second".into();
        two_owners.components.push(second);
        let mut budget = PredicateAnalysisBudget::with_work_limit_for_test(exact_single_owner_work);
        assert!(matches!(
            NormalizedCatalog::normalize_with_predicate_budget(two_owners, &mut budget),
            Err(CatalogError::InvalidTargetSupportPredicate {
                owner,
                source: TargetError::PredicateAnalysisLimitExceeded {
                    resource: "analysis work",
                    maximum,
                },
            }) if owner == "model-second" && maximum == exact_single_owner_work
        ));
    }

    #[test]
    fn normalization_rechecks_catalog_owner_bound_after_mutation() {
        let mut document = CatalogDocument::from_toml(BASE).unwrap();
        let component = document.components[0].clone();
        document
            .components
            .resize(crate::metadata::MAX_CATALOG_OWNERS + 1, component);

        assert!(matches!(
            NormalizedCatalog::normalize(document),
            Err(CatalogError::CatalogOwnerLimitExceeded { actual, maximum })
                if actual > crate::metadata::MAX_CATALOG_OWNERS
                    && maximum == crate::metadata::MAX_CATALOG_OWNERS
        ));
    }

    #[test]
    fn unknown_fields_fail_closed() {
        let input = BASE.replace("schema = 1", "schema = 1\nframework = \"tauri\"");
        assert!(CatalogDocument::from_toml(&input).is_err());
    }

    #[test]
    fn wasm_host_requires_its_own_postprocessor_executable() {
        let catalog = include_str!("../../../../tests/fixtures/catalog.toml");
        let required = "build-requirements = { executables = [\"wasm-bindgen-cli\"], read-inputs = [], environment = [] }";
        assert_eq!(catalog.matches(required).count(), 1);
        let invalid = catalog.replace(
            required,
            "build-requirements = { executables = [], read-inputs = [], environment = [] }",
        );
        assert!(matches!(
            NormalizedCatalog::normalize(CatalogDocument::from_toml(&invalid).unwrap()),
            Err(CatalogError::InvalidBinding(_, _))
        ));
    }

    #[test]
    fn effects_must_be_accounted() {
        let input = BASE.replace("effects = [] }]", "effects = [\"read-local\"] }]");
        let error =
            NormalizedCatalog::normalize(CatalogDocument::from_toml(&input).unwrap()).unwrap_err();
        assert!(matches!(error, CatalogError::EffectOutsideCeiling { .. }));
    }

    #[test]
    fn lifecycle_and_provide_effect_fields_are_required() {
        let missing_lifecycle = BASE.replace("lifecycle-effects = []\n", "");
        assert!(CatalogDocument::from_toml(&missing_lifecycle).is_err());

        let missing_provide = BASE.replace(", effects = [] }]", " }]");
        assert!(CatalogDocument::from_toml(&missing_provide).is_err());
    }

    #[test]
    fn app_coexistence_is_scope_bound() {
        let missing = BASE.replace("app-coexistence = { mode = \"requires-stop\" }\n", "");
        assert!(matches!(
            NormalizedCatalog::normalize(CatalogDocument::from_toml(&missing).unwrap()),
            Err(CatalogError::InvalidAppCoexistence(_, _))
        ));

        let shorter = BASE.replace("scope = \"app\"", "scope = \"agent\"");
        assert!(
            NormalizedCatalog::normalize(CatalogDocument::from_toml(&shorter).unwrap()).is_err()
        );
    }

    fn namespace_catalog() -> String {
        let consumer = BASE
            .replace(
                "config-source = \"none\"\n",
                "config-source = \"none\"\nresource-namespace-preparer = \"fixture_model::prepare_resource_namespaces\"\nprepared-config-type = \"fixture_model::PreparedConfig\"\n",
            )
            .replace(
                "provides = [{ capability = \"cap:model\", priority = 1, effects = [] }]",
                "provides = [{ capability = \"cap:model\", priority = 1, resource-namespace = { mode = \"required\", bootstrap = \"local-bootstrap\" }, effects = [] }]",
            );
        format!(
            r#"{consumer}

[[capabilities]]
id = "cap:resource-namespace-bootstrap"
api-package = "rust-agent-fixture-api"
rust-api = "rust_agent_fixture_api::ResourceNamespaceBootstrap"
binding-type = "rust_agent_fixture_api::ResourceNamespaceBootstrapBinding"
binding-adapter = "rust_agent_fixture_api::ResourceNamespaceBootstrapBinding::from_provider"
binding = "registry"
scope = "app"

[[components]]
id = "local-bootstrap"
package = "fixture-local-bootstrap"
package-path = "fixtures/local-bootstrap"
scope = "app"
factory = "fixture_local_bootstrap::build"
dependencies-type = "fixture_local_bootstrap::Dependencies"
config-type = "fixture_local_bootstrap::Config"
config-source = "none"
targets = "cfg(true)"
support = "production"
lifecycle-effects = []
security = ["read-local"]
runtime-primitives = []
app-coexistence = {{ mode = "requires-stop" }}
cargo-features = []
build-requirements = {{ executables = [], read-inputs = [], environment = [] }}
provides = [{{ capability = "cap:resource-namespace-bootstrap", key = "local-bootstrap", priority = 1, effects = ["read-local"] }}]
requires = []

[[runtime-adapters]]
id = "fixture-runtime"
package = "fixture-runtime"
package-path = "fixtures/runtime"
constructor = "fixture_runtime::create_runtime_primitives"
targets = "cfg(true)"
support = "production"
primitives = []
security = []
app-coexistence = {{ mode = "requires-stop" }}
build-requirements = {{ executables = [], read-inputs = [], environment = [] }}
"#
        )
    }

    #[test]
    fn required_resource_namespace_derives_an_exact_bootstrap_requirement() {
        let catalog =
            NormalizedCatalog::normalize(CatalogDocument::from_toml(&namespace_catalog()).unwrap())
                .unwrap();
        assert_eq!(
            catalog.resource_namespace_requirements["model"],
            vec![ResourceNamespaceRequirement {
                provide_capability: "cap:model".into(),
                provide_key: None,
                bootstrap_key: "local-bootstrap".into(),
            }]
        );
    }

    #[test]
    fn resolver_selects_the_exact_namespace_bootstrap_before_the_consumer() {
        let catalog =
            NormalizedCatalog::normalize(CatalogDocument::from_toml(&namespace_catalog()).unwrap())
                .unwrap();
        let profile = crate::profile::CompositionProfile::from_toml(
            r#"
schema = 1
name = "namespace"
build-kind = "library"
target = "x86_64-unknown-linux-gnu"
environment = "desktop"
support-tier = "production"
runtime-adapter = "fixture-runtime"
resolver-decision-budget = 10
denied-effects = []

[components]
model = "enabled"
local-bootstrap = "auto"
"#,
        )
        .unwrap();
        let target = crate::target::Target::from_facts(
            "x86_64-unknown-linux-gnu",
            crate::target::Environment::Desktop,
            minimal_validation_target_facts(),
        )
        .unwrap();
        let resolution = crate::resolver::resolve(&catalog, &profile, &target).unwrap();
        assert_eq!(resolution.selected_components, ["local-bootstrap", "model"]);
        assert_eq!(resolution.construction_order, ["local-bootstrap", "model"]);
        assert_eq!(resolution.resource_namespace_bindings.len(), 1);
        let binding = &resolution.resource_namespace_bindings[0];
        assert_eq!(binding.bootstrap_provider, "local-bootstrap");
        assert_eq!(binding.bootstrap_key, "local-bootstrap");
        assert_eq!(binding.effects, ["read-local".into()].into_iter().collect());

        let unavailable = namespace_catalog().replace(
            "config-type = \"fixture_local_bootstrap::Config\"\nconfig-source = \"none\"\ntargets = \"cfg(true)\"",
            "config-type = \"fixture_local_bootstrap::Config\"\nconfig-source = \"none\"\ntargets = \"cfg(target_os = \\\"windows\\\")\"",
        );
        let unavailable =
            NormalizedCatalog::normalize(CatalogDocument::from_toml(&unavailable).unwrap())
                .unwrap();
        assert!(matches!(
            crate::resolver::resolve(&unavailable, &profile, &target),
            Err(crate::resolver::ResolutionError::Unsatisfiable { .. })
        ));
    }

    #[test]
    fn incomplete_or_unsafe_namespace_metadata_fails_closed() {
        let missing_preparer = namespace_catalog().replace(
            "resource-namespace-preparer = \"fixture_model::prepare_resource_namespaces\"\n",
            "",
        );
        assert!(matches!(
            NormalizedCatalog::normalize(CatalogDocument::from_toml(&missing_preparer).unwrap()),
            Err(CatalogError::InvalidResourceNamespace(_, _))
        ));

        let missing_provider = namespace_catalog().replacen(
            "bootstrap = \"local-bootstrap\"",
            "bootstrap = \"missing-bootstrap\"",
            1,
        );
        assert!(matches!(
            NormalizedCatalog::normalize(CatalogDocument::from_toml(&missing_provider).unwrap()),
            Err(CatalogError::InvalidResourceNamespace(_, _))
        ));

        let effectful_lifecycle = namespace_catalog().replace(
            "lifecycle-effects = []\nsecurity = [\"read-local\"]",
            "lifecycle-effects = [\"read-local\"]\nsecurity = [\"read-local\"]",
        );
        assert!(matches!(
            NormalizedCatalog::normalize(CatalogDocument::from_toml(&effectful_lifecycle).unwrap()),
            Err(CatalogError::InvalidResourceNamespace(_, _))
        ));
    }
}
