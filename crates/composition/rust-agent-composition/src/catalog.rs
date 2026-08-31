use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component as PathComponent, Path},
};

use thiserror::Error;

use crate::{
    metadata::{
        AppCoexistence, BindingKind, BuildRequirements, CapabilitySpec, CatalogDocument,
        ComponentSpec, ConfigSource, HostBoundarySpec, ProvideLayer, RuntimeAdapterSpec, ScopeKind,
    },
    target::TargetError,
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
    #[error("target predicate in {owner} is invalid: {source}")]
    InvalidTargetPredicate { owner: String, source: TargetError },
}

impl NormalizedCatalog {
    pub fn normalize(document: CatalogDocument) -> Result<Self, CatalogError> {
        if document.schema != SCHEMA_VERSION {
            return Err(CatalogError::UnsupportedSchema(document.schema));
        }

        let capabilities = collect_unique("capability", document.capabilities, |value| &value.id)?;
        let components = collect_unique("component", document.components, |value| &value.id)?;
        let runtime_adapters =
            collect_unique("runtime adapter", document.runtime_adapters, |value| {
                &value.id
            })?;
        let host_boundaries =
            collect_unique("host boundary", document.host_boundaries, |value| &value.id)?;

        for capability in capabilities.values() {
            validate_capability(capability)?;
        }

        let mut package_owners = BTreeMap::new();
        for component in components.values() {
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
        for adapter in runtime_adapters.values() {
            validate_adapter(adapter)?;
        }
        for boundary in host_boundaries.values() {
            validate_boundary(boundary)?;
        }

        Ok(Self {
            capabilities,
            components,
            runtime_adapters,
            host_boundaries,
        })
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

fn validate_build_requirements(owner: &str, value: &BuildRequirements) -> Result<(), CatalogError> {
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
        BTreeMap::new(),
    )
    .expect("empty target facts have a canonical encoding");
    target
        .matches(predicate)
        .map(|_| ())
        .map_err(|source| CatalogError::InvalidTargetPredicate {
            owner: owner.to_owned(),
            source,
        })
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

    #[test]
    fn unknown_fields_fail_closed() {
        let input = BASE.replace("schema = 1", "schema = 1\nframework = \"tauri\"");
        assert!(CatalogDocument::from_toml(&input).is_err());
    }

    #[test]
    fn effects_must_be_accounted() {
        let input = BASE.replace("effects = [] }]", "effects = [\"read-local\"] }]");
        let error =
            NormalizedCatalog::normalize(CatalogDocument::from_toml(&input).unwrap()).unwrap_err();
        assert!(matches!(error, CatalogError::EffectOutsideCeiling { .. }));
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
}
