use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    catalog::NormalizedCatalog,
    diagnostics::Diagnostic,
    metadata::{
        AppCoexistence, BindingKind, BuildRequirements, ComponentSpec, HostBoundaryKind,
        RequirementMode, ScopeKind, SupportTier,
    },
    profile::{BuildKind, ComponentChoice, CompositionProfile},
    target::{Target, TargetError},
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resolution {
    pub schema: u32,
    pub profile: String,
    pub target: String,
    #[serde(rename = "target-fact-digest")]
    pub target_fact_digest: String,
    #[serde(rename = "selected-components")]
    pub selected_components: Vec<String>,
    pub bindings: Vec<ResolvedBinding>,
    #[serde(rename = "resource-namespace-bindings")]
    pub resource_namespace_bindings: Vec<ResolvedResourceNamespaceBinding>,
    #[serde(rename = "construction-order")]
    pub construction_order: Vec<String>,
    #[serde(rename = "runtime-adapter")]
    pub runtime_adapter: String,
    #[serde(rename = "host-boundary")]
    pub host_boundary: Option<String>,
    #[serde(rename = "compiled-runtime-effects")]
    pub compiled_runtime_effects: BTreeSet<String>,
    #[serde(rename = "build-requirements")]
    pub build_requirements: BuildRequirements,
    #[serde(rename = "app-handoff")]
    pub app_handoff: AppHandoff,
    #[serde(rename = "explored-decisions")]
    pub explored_decisions: u32,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedBinding {
    pub capability: String,
    pub key: Option<String>,
    pub provider: String,
    pub consumer: String,
    pub field: String,
    pub effects: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedResourceNamespaceBinding {
    pub consumer: String,
    #[serde(rename = "provide-capability")]
    pub provide_capability: String,
    #[serde(rename = "provide-key")]
    pub provide_key: Option<String>,
    #[serde(rename = "bootstrap-provider")]
    pub bootstrap_provider: String,
    #[serde(rename = "bootstrap-key")]
    pub bootstrap_key: String,
    pub effects: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppHandoff {
    Concurrent,
    StopOldApp,
}

#[derive(Debug, Error)]
pub enum ResolutionError {
    #[error("unsupported profile schema {0}; expected 1")]
    UnsupportedProfileSchema(u32),
    #[error("profile `{0}` has an invalid resolver decision budget")]
    InvalidDecisionBudget(String),
    #[error("profile references unknown component `{0}`")]
    UnknownComponent(String),
    #[error("profile references unknown capability `{0}`")]
    UnknownCapability(String),
    #[error("profile references unknown runtime adapter `{0}`")]
    UnknownRuntimeAdapter(String),
    #[error("profile references unknown host boundary `{0}`")]
    UnknownHostBoundary(String),
    #[error("runtime adapter `{id}` is not available for target `{target}`")]
    InvalidRuntimeAdapter { id: String, target: String },
    #[error("invalid Host boundary for build kind {build_kind:?}: {message}")]
    InvalidHostBoundary {
        build_kind: BuildKind,
        message: String,
    },
    #[error("profile binding keys must omit the `cap:` prefix: `{0}`")]
    PrefixedBindingKey(String),
    #[error("profile provider `{provider}` does not provide `{capability}`")]
    InvalidBindingOverride {
        capability: String,
        provider: String,
    },
    #[error("explicitly enabled component `{component}` cannot be satisfied: {reason}")]
    Unsatisfiable { component: String, reason: String },
    #[error(
        "resolver decision budget {budget} exhausted after {explored} decisions; frontier {frontier}"
    )]
    ResolutionLimitExceeded {
        budget: u32,
        explored: u32,
        frontier: String,
    },
    #[error("target predicate evaluation failed for `{owner}`: {source}")]
    Target { owner: String, source: TargetError },
}

#[derive(Clone, Debug, Default)]
struct State {
    selected: BTreeSet<String>,
    visiting: BTreeSet<String>,
    bindings: Vec<ResolvedBinding>,
    resource_namespace_bindings: Vec<ResolvedResourceNamespaceBinding>,
    order: Vec<String>,
    reasons: BTreeMap<String, Vec<String>>,
}

struct Resolver<'a> {
    catalog: &'a NormalizedCatalog,
    profile: &'a CompositionProfile,
    target: &'a Target,
    explored: u32,
}

pub fn resolve(
    catalog: &NormalizedCatalog,
    profile: &CompositionProfile,
    target: &Target,
) -> Result<Resolution, ResolutionError> {
    validate_profile(catalog, profile)?;
    if profile.target != target.triple || profile.environment != target.environment {
        return Err(ResolutionError::InvalidRuntimeAdapter {
            id: profile.runtime_adapter.clone(),
            target: format!("{} / {:?}", target.triple, target.environment),
        });
    }
    let adapter = catalog
        .runtime_adapters
        .get(&profile.runtime_adapter)
        .ok_or_else(|| ResolutionError::UnknownRuntimeAdapter(profile.runtime_adapter.clone()))?;
    if !is_available(
        adapter.support,
        &adapter.targets,
        profile,
        target,
        &adapter.id,
    )? {
        return Err(ResolutionError::InvalidRuntimeAdapter {
            id: adapter.id.clone(),
            target: target.triple.clone(),
        });
    }
    if !adapter.security.is_empty() {
        return Err(ResolutionError::InvalidRuntimeAdapter {
            id: adapter.id.clone(),
            target: target.triple.clone(),
        });
    }
    let boundary = validate_host_boundary(catalog, profile, target, adapter)?;

    let mut resolver = Resolver {
        catalog,
        profile,
        target,
        explored: 0,
    };
    let mut state = State::default();
    for (component, choice) in &profile.components {
        if *choice == ComponentChoice::Enabled {
            state
                .reasons
                .entry(component.clone())
                .or_default()
                .push(format!("RequiredBy(profile:{})", profile.name));
            state = resolver
                .include_component(state, component)
                .map_err(|reason| {
                    if let BranchFailure::Limit(error) = reason {
                        error
                    } else {
                        ResolutionError::Unsatisfiable {
                            component: component.clone(),
                            reason: reason.to_string(),
                        }
                    }
                })?;
        }
    }

    let mut selected_components: Vec<_> = state.selected.iter().cloned().collect();
    selected_components.sort();
    state.bindings.sort_by(|left, right| {
        (
            &left.consumer,
            &left.field,
            &left.capability,
            &left.provider,
        )
            .cmp(&(
                &right.consumer,
                &right.field,
                &right.capability,
                &right.provider,
            ))
    });
    state.resource_namespace_bindings.sort_by(|left, right| {
        (
            &left.consumer,
            &left.provide_capability,
            &left.provide_key,
            &left.bootstrap_key,
        )
            .cmp(&(
                &right.consumer,
                &right.provide_capability,
                &right.provide_key,
                &right.bootstrap_key,
            ))
    });

    let mut compiled_runtime_effects = BTreeSet::new();
    let mut build_requirements = BuildRequirements::default();
    let mut app_handoff = match &adapter.app_coexistence {
        AppCoexistence::RequiresStop => AppHandoff::StopOldApp,
        _ => AppHandoff::Concurrent,
    };
    build_requirements.merge_from(&adapter.build_requirements);
    for component in &selected_components {
        let spec = &catalog.components[component];
        compiled_runtime_effects.extend(spec.security.iter().cloned());
        build_requirements.merge_from(&spec.build_requirements);
        if spec.scope == ScopeKind::App
            && matches!(spec.app_coexistence, Some(AppCoexistence::RequiresStop))
        {
            app_handoff = AppHandoff::StopOldApp;
        }
    }
    if let Some(boundary) = boundary {
        compiled_runtime_effects.extend(boundary.security.iter().cloned());
        build_requirements.merge_from(&boundary.build_requirements);
    }

    let mut diagnostics = Vec::new();
    for component in catalog.components.keys() {
        if state.selected.contains(component) {
            diagnostics.push(Diagnostic::selected(
                component,
                state
                    .reasons
                    .get(component)
                    .cloned()
                    .unwrap_or_else(|| vec!["SelectedProvider".into()]),
            ));
        } else {
            let reason = match profile.components.get(component) {
                Some(ComponentChoice::Disabled) => "ExplicitDisabled",
                _ => "NotRequired",
            };
            diagnostics.push(Diagnostic::excluded(component, vec![reason.into()]));
        }
    }

    Ok(Resolution {
        schema: 1,
        profile: profile.name.clone(),
        target: target.triple.clone(),
        target_fact_digest: target.target_fact_digest.clone(),
        selected_components,
        bindings: state.bindings,
        resource_namespace_bindings: state.resource_namespace_bindings,
        construction_order: state.order,
        runtime_adapter: adapter.id.clone(),
        host_boundary: boundary.map(|value| value.id.clone()),
        compiled_runtime_effects,
        build_requirements,
        app_handoff,
        explored_decisions: resolver.explored,
        diagnostics,
    })
}

impl Resolver<'_> {
    fn include_component(&mut self, mut state: State, id: &str) -> Result<State, BranchFailure> {
        if state.visiting.contains(id) {
            return Err(BranchFailure::Constraint(format!(
                "construction cycle reaches `{id}`"
            )));
        }
        if state.selected.contains(id) {
            return Ok(state);
        }
        let component = self
            .catalog
            .components
            .get(id)
            .ok_or_else(|| BranchFailure::Constraint(format!("unknown component `{id}`")))?;
        self.ensure_component_available(component, &state)?;
        state.selected.insert(id.to_owned());
        state.visiting.insert(id.to_owned());

        for requirement in &component.requires {
            if requirement.mode == RequirementMode::UsesIfPresent {
                if let Some(provider) = self.find_selected_provider(
                    &state,
                    &requirement.capability,
                    requirement.key.as_deref(),
                ) {
                    state
                        .bindings
                        .push(self.binding(component, requirement, provider));
                }
                continue;
            }

            let candidates =
                self.candidates(&requirement.capability, requirement.key.as_deref())?;
            if candidates.is_empty() {
                return Err(BranchFailure::Constraint(format!(
                    "required capability `{}` has no provider",
                    requirement.capability
                )));
            }

            let mut last_failure = None;
            let mut resolved = None;
            for provider in candidates {
                self.explored = self.explored.saturating_add(1);
                if self.explored > self.profile.resolver_decision_budget {
                    return Err(BranchFailure::Limit(
                        ResolutionError::ResolutionLimitExceeded {
                            budget: self.profile.resolver_decision_budget,
                            explored: self.explored,
                            frontier: format!(
                                "{}:{}:{}",
                                component.id, requirement.capability, provider
                            ),
                        },
                    ));
                }
                let mut branch = state.clone();
                branch
                    .reasons
                    .entry(provider.clone())
                    .or_default()
                    .push(format!(
                        "CandidateFor({}) required by {}",
                        requirement.capability, component.id
                    ));
                match self.include_component(branch, &provider) {
                    Ok(mut branch) => {
                        branch
                            .bindings
                            .push(self.binding(component, requirement, &provider));
                        resolved = Some(branch);
                        break;
                    }
                    Err(BranchFailure::Limit(error)) => return Err(BranchFailure::Limit(error)),
                    Err(error) => last_failure = Some(error),
                }
            }
            state = resolved.ok_or_else(|| {
                last_failure.unwrap_or_else(|| {
                    BranchFailure::Constraint(format!(
                        "all providers for `{}` were rejected",
                        requirement.capability
                    ))
                })
            })?;
        }

        if let Some(requirements) = self
            .catalog
            .resource_namespace_requirements
            .get(&component.id)
        {
            for requirement in requirements {
                let candidates = self.candidates(
                    "cap:resource-namespace-bootstrap",
                    Some(&requirement.bootstrap_key),
                )?;
                let provider = candidates.into_iter().next().ok_or_else(|| {
                    BranchFailure::Constraint(format!(
                        "resource namespace bootstrap `{}` has no provider",
                        requirement.bootstrap_key
                    ))
                })?;
                let mut branch = state.clone();
                branch
                    .reasons
                    .entry(provider.clone())
                    .or_default()
                    .push(format!(
                        "ResourceNamespaceFor({}:{})",
                        component.id, requirement.provide_capability
                    ));
                let mut branch = self.include_component(branch, &provider)?;
                let bootstrap_provide = self.catalog.components[&provider]
                    .provides
                    .iter()
                    .find(|provide| {
                        provide.capability == "cap:resource-namespace-bootstrap"
                            && provide.key.as_deref() == Some(requirement.bootstrap_key.as_str())
                    })
                    .expect("catalog normalization fixed the exact bootstrap provide");
                let mut effects = self.catalog.components[&provider].lifecycle_effects.clone();
                effects.extend(bootstrap_provide.effects.iter().cloned());
                branch
                    .resource_namespace_bindings
                    .push(ResolvedResourceNamespaceBinding {
                        consumer: component.id.clone(),
                        provide_capability: requirement.provide_capability.clone(),
                        provide_key: requirement.provide_key.clone(),
                        bootstrap_provider: provider,
                        bootstrap_key: requirement.bootstrap_key.clone(),
                        effects,
                    });
                state = branch;
            }
        }

        state.visiting.remove(id);
        state.order.push(id.to_owned());
        Ok(state)
    }

    fn ensure_component_available(
        &self,
        component: &ComponentSpec,
        state: &State,
    ) -> Result<(), BranchFailure> {
        if self.profile.components.get(&component.id) == Some(&ComponentChoice::Disabled) {
            return Err(BranchFailure::Constraint(format!(
                "component `{}` is explicitly disabled",
                component.id
            )));
        }
        if !is_available(
            component.support,
            &component.targets,
            self.profile,
            self.target,
            &component.id,
        )
        .map_err(BranchFailure::Resolution)?
        {
            return Err(BranchFailure::Constraint(format!(
                "component `{}` is unsupported for {}",
                component.id, self.target.triple
            )));
        }
        if component
            .security
            .iter()
            .any(|effect| self.profile.denied_effects.contains(effect))
        {
            return Err(BranchFailure::Constraint(format!(
                "component `{}` security ceiling is denied",
                component.id
            )));
        }
        for selected in &state.selected {
            let other = &self.catalog.components[selected];
            if component.conflicts.contains(selected) || other.conflicts.contains(&component.id) {
                return Err(BranchFailure::Constraint(format!(
                    "component `{}` conflicts with `{selected}`",
                    component.id
                )));
            }
        }
        Ok(())
    }

    fn candidates(
        &self,
        capability: &str,
        key: Option<&str>,
    ) -> Result<Vec<String>, BranchFailure> {
        let spec = self.catalog.capabilities.get(capability).ok_or_else(|| {
            BranchFailure::Constraint(format!("unknown capability `{capability}`"))
        })?;
        let suffix = capability.strip_prefix("cap:").unwrap_or(capability);
        let explicit = self.profile.bindings.get(suffix);
        let preferred = self.profile.preferred_providers.get(suffix);
        let mut candidates = Vec::new();
        for component in self.catalog.components.values() {
            let priority = component
                .provides
                .iter()
                .filter(|provide| provide.capability == capability && provide.key.as_deref() == key)
                .map(|provide| provide.priority)
                .max();
            if let Some(priority) = priority {
                if explicit.is_none_or(|value| value == &component.id) {
                    candidates.push((
                        explicit == Some(&component.id),
                        preferred == Some(&component.id),
                        priority,
                        component.id.clone(),
                    ));
                }
            }
        }
        if spec.binding == BindingKind::Registry && key.is_none() {
            return Err(BranchFailure::Constraint(format!(
                "registry capability `{capability}` requires a key"
            )));
        }
        candidates.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then_with(|| right.1.cmp(&left.1))
                .then_with(|| right.2.cmp(&left.2))
                .then_with(|| left.3.cmp(&right.3))
        });
        Ok(candidates.into_iter().map(|value| value.3).collect())
    }

    fn find_selected_provider<'a>(
        &self,
        state: &'a State,
        capability: &str,
        key: Option<&str>,
    ) -> Option<&'a str> {
        state.selected.iter().find_map(|id| {
            self.catalog.components[id]
                .provides
                .iter()
                .any(|provide| provide.capability == capability && provide.key.as_deref() == key)
                .then_some(id.as_str())
        })
    }

    fn binding(
        &self,
        consumer: &ComponentSpec,
        requirement: &crate::metadata::CapabilityRequirement,
        provider: &str,
    ) -> ResolvedBinding {
        let provide = self.catalog.components[provider]
            .provides
            .iter()
            .find(|provide| {
                provide.capability == requirement.capability
                    && provide.key.as_deref() == requirement.key.as_deref()
            })
            .expect("candidate provider has the requested provide");
        let mut effects = self.catalog.components[provider].lifecycle_effects.clone();
        effects.extend(provide.effects.iter().cloned());
        ResolvedBinding {
            capability: requirement.capability.clone(),
            key: requirement.key.clone(),
            provider: provider.to_owned(),
            consumer: consumer.id.clone(),
            field: requirement.field.clone(),
            effects,
        }
    }
}

#[derive(Debug)]
enum BranchFailure {
    Constraint(String),
    Resolution(ResolutionError),
    Limit(ResolutionError),
}

impl std::fmt::Display for BranchFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Constraint(message) => formatter.write_str(message),
            Self::Resolution(error) | Self::Limit(error) => error.fmt(formatter),
        }
    }
}

fn validate_profile(
    catalog: &NormalizedCatalog,
    profile: &CompositionProfile,
) -> Result<(), ResolutionError> {
    if profile.schema != 1 {
        return Err(ResolutionError::UnsupportedProfileSchema(profile.schema));
    }
    if profile.resolver_decision_budget == 0 {
        return Err(ResolutionError::InvalidDecisionBudget(profile.name.clone()));
    }
    for component in profile.components.keys() {
        if !catalog.components.contains_key(component) {
            return Err(ResolutionError::UnknownComponent(component.clone()));
        }
    }
    for (capability, provider) in profile.bindings.iter().chain(&profile.preferred_providers) {
        if capability.starts_with("cap:") {
            return Err(ResolutionError::PrefixedBindingKey(capability.clone()));
        }
        let full = format!("cap:{capability}");
        if !catalog.capabilities.contains_key(&full) {
            return Err(ResolutionError::UnknownCapability(full));
        }
        let component = catalog
            .components
            .get(provider)
            .ok_or_else(|| ResolutionError::UnknownComponent(provider.clone()))?;
        if !component
            .provides
            .iter()
            .any(|provide| provide.capability == full)
        {
            return Err(ResolutionError::InvalidBindingOverride {
                capability: full,
                provider: provider.clone(),
            });
        }
    }
    Ok(())
}

fn validate_host_boundary<'a>(
    catalog: &'a NormalizedCatalog,
    profile: &CompositionProfile,
    target: &Target,
    adapter: &crate::metadata::RuntimeAdapterSpec,
) -> Result<Option<&'a crate::metadata::HostBoundarySpec>, ResolutionError> {
    let boundary = profile
        .host_boundary
        .as_ref()
        .map(|id| {
            catalog
                .host_boundaries
                .get(id)
                .ok_or_else(|| ResolutionError::UnknownHostBoundary(id.clone()))
        })
        .transpose()?;
    match (profile.build_kind, boundary) {
        (BuildKind::Library, None) => return Ok(None),
        (BuildKind::Library, Some(_)) => {
            return Err(ResolutionError::InvalidHostBoundary {
                build_kind: profile.build_kind,
                message: "library composition forbids Host entry/export packages".into(),
            });
        }
        (BuildKind::Bin, Some(value)) if matches!(value.kind, HostBoundaryKind::Entry) => {}
        (BuildKind::Wasm, Some(value)) if matches!(value.kind, HostBoundaryKind::WasmExport) => {}
        (_, None) => {
            return Err(ResolutionError::InvalidHostBoundary {
                build_kind: profile.build_kind,
                message: "exactly one compatible Host boundary is required".into(),
            });
        }
        (_, Some(_)) => {
            return Err(ResolutionError::InvalidHostBoundary {
                build_kind: profile.build_kind,
                message: "Host entry/export kind does not match build kind".into(),
            });
        }
    }
    let boundary = boundary.expect("checked above");
    if !boundary.runtime_adapters.contains(&adapter.id)
        || !is_available(
            boundary.support,
            &boundary.targets,
            profile,
            target,
            &boundary.id,
        )?
    {
        return Err(ResolutionError::InvalidHostBoundary {
            build_kind: profile.build_kind,
            message: format!(
                "boundary `{}` is incompatible with target or adapter",
                boundary.id
            ),
        });
    }
    if boundary
        .security
        .iter()
        .any(|effect| profile.denied_effects.contains(effect))
    {
        return Err(ResolutionError::InvalidHostBoundary {
            build_kind: profile.build_kind,
            message: format!(
                "boundary `{}` runtime security ceiling is denied",
                boundary.id
            ),
        });
    }
    if profile.build_kind == BuildKind::Wasm && target.fact_value("target_arch") != Some("wasm32") {
        return Err(ResolutionError::InvalidHostBoundary {
            build_kind: profile.build_kind,
            message: "wasm build requires target_arch=wasm32".into(),
        });
    }
    Ok(Some(boundary))
}

fn is_available(
    support: SupportTier,
    predicate: &str,
    profile: &CompositionProfile,
    target: &Target,
    owner: &str,
) -> Result<bool, ResolutionError> {
    let matches = target
        .matches(predicate)
        .map_err(|source| ResolutionError::Target {
            owner: owner.to_owned(),
            source,
        })?;
    Ok(matches
        && (profile.support_tier == SupportTier::Experimental
            || support == SupportTier::Production))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{metadata::CatalogDocument, target::parse_facts};
    use proptest::prelude::*;

    use super::*;

    fn fixture_catalog() -> NormalizedCatalog {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/fixtures/catalog.toml");
        let input = std::fs::read_to_string(path).unwrap();
        NormalizedCatalog::normalize(CatalogDocument::from_toml(&input).unwrap()).unwrap()
    }

    fn target() -> Target {
        Target::from_facts(
            "x86_64-unknown-linux-gnu",
            crate::target::Environment::Desktop,
            parse_facts(
                "target_arch=\"x86_64\"\ntarget_os=\"linux\"\ntarget_family=\"unix\"\nunix\n",
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn profile() -> CompositionProfile {
        CompositionProfile::from_toml(include_str!(
            "../../../../tests/fixtures/profiles/minimal.toml"
        ))
        .unwrap()
    }

    #[test]
    fn required_closure_selects_model_before_driver() {
        let resolution = resolve(&fixture_catalog(), &profile(), &target()).unwrap();
        assert_eq!(
            resolution.selected_components,
            ["fixture-driver", "fixture-model"]
        );
        assert_eq!(
            resolution.construction_order,
            ["fixture-model", "fixture-driver"]
        );
        assert_eq!(resolution.bindings[0].provider, "fixture-model");
    }

    #[test]
    fn explicitly_disabled_provider_is_unsatisfiable() {
        let mut profile = profile();
        profile
            .components
            .insert("fixture-model".into(), ComponentChoice::Disabled);
        assert!(matches!(
            resolve(&fixture_catalog(), &profile, &target()),
            Err(ResolutionError::Unsatisfiable { .. })
        ));
    }

    #[test]
    fn denied_effect_prevents_optional_component_from_entering_graph() {
        let mut profile = profile();
        profile
            .components
            .insert("fixture-fs-read".into(), ComponentChoice::Enabled);
        profile.denied_effects.insert("read-local".into());
        assert!(matches!(
            resolve(&fixture_catalog(), &profile, &target()),
            Err(ResolutionError::Unsatisfiable { component, .. }) if component == "fixture-fs-read"
        ));
    }

    #[test]
    fn decision_budget_exhaustion_is_not_reported_as_unsat() {
        let mut profile = profile();
        profile.resolver_decision_budget = 1;
        assert!(matches!(
            resolve(&fixture_catalog(), &profile, &target()),
            Err(ResolutionError::ResolutionLimitExceeded { .. })
        ));
    }

    #[test]
    fn identical_input_is_deterministic() {
        let catalog = fixture_catalog();
        let profile = profile();
        assert_eq!(
            resolve(&catalog, &profile, &target()).unwrap(),
            resolve(&catalog, &profile, &target()).unwrap()
        );
    }

    #[test]
    fn host_boundary_cardinality_kind_target_and_effect_union_are_closed() {
        let catalog = fixture_catalog();
        let mut profile = profile();
        profile.build_kind = BuildKind::Bin;
        assert!(matches!(
            resolve(&catalog, &profile, &target()),
            Err(ResolutionError::InvalidHostBoundary { .. })
        ));

        profile.host_boundary = Some("fixture-host-export".into());
        assert!(matches!(
            resolve(&catalog, &profile, &target()),
            Err(ResolutionError::InvalidHostBoundary { .. })
        ));

        profile.host_boundary = Some("fixture-host-entry".into());
        assert!(matches!(
            resolve(&catalog, &profile, &target()),
            Err(ResolutionError::InvalidHostBoundary { .. })
        ));
        profile.denied_effects.remove("host-bridge");
        let resolved = resolve(&catalog, &profile, &target()).unwrap();
        assert!(resolved.compiled_runtime_effects.contains("host-bridge"));

        profile.build_kind = BuildKind::Library;
        assert!(matches!(
            resolve(&catalog, &profile, &target()),
            Err(ResolutionError::InvalidHostBoundary { .. })
        ));

        profile.build_kind = BuildKind::Wasm;
        profile.host_boundary = None;
        assert!(matches!(
            resolve(&catalog, &profile, &target()),
            Err(ResolutionError::InvalidHostBoundary { .. })
        ));
        profile.host_boundary = Some("fixture-host-entry".into());
        assert!(matches!(
            resolve(&catalog, &profile, &target()),
            Err(ResolutionError::InvalidHostBoundary { .. })
        ));
        profile.host_boundary = Some("fixture-host-export".into());
        assert!(matches!(
            resolve(&catalog, &profile, &target()),
            Err(ResolutionError::InvalidHostBoundary { .. })
        ));

        profile.target = "wasm32-unknown-unknown".into();
        profile.environment = crate::target::Environment::Browser;
        let wasm = Target::from_facts(
            "wasm32-unknown-unknown",
            crate::target::Environment::Browser,
            parse_facts("target_arch=\"wasm32\"\ntarget_os=\"unknown\"\n").unwrap(),
        )
        .unwrap();
        let resolved = resolve(&catalog, &profile, &wasm).unwrap();
        assert!(resolved.compiled_runtime_effects.contains("host-bridge"));

        let mut unsupported_catalog = catalog;
        unsupported_catalog
            .host_boundaries
            .get_mut("fixture-host-export")
            .unwrap()
            .support = crate::metadata::SupportTier::Experimental;
        assert!(matches!(
            resolve(&unsupported_catalog, &profile, &wasm),
            Err(ResolutionError::InvalidHostBoundary { .. })
        ));
    }

    #[test]
    fn native_host_entry_accepts_only_declared_desktop_operating_systems() {
        let catalog = fixture_catalog();
        let mut profile = profile();
        profile.build_kind = BuildKind::Bin;
        profile.host_boundary = Some("fixture-host-entry".into());
        profile.denied_effects.remove("host-bridge");
        for (triple, environment, os, accepted) in [
            (
                "x86_64-unknown-linux-gnu",
                crate::target::Environment::Desktop,
                "linux",
                true,
            ),
            (
                "x86_64-apple-darwin",
                crate::target::Environment::Desktop,
                "macos",
                true,
            ),
            (
                "x86_64-pc-windows-msvc",
                crate::target::Environment::Desktop,
                "windows",
                true,
            ),
            (
                "aarch64-linux-android",
                crate::target::Environment::Mobile,
                "android",
                false,
            ),
            (
                "aarch64-apple-ios",
                crate::target::Environment::Mobile,
                "ios",
                false,
            ),
            (
                "x86_64-unknown-freebsd",
                crate::target::Environment::Desktop,
                "freebsd",
                false,
            ),
        ] {
            profile.target = triple.into();
            profile.environment = environment;
            let target = Target::from_facts(
                triple,
                environment,
                parse_facts(&format!("target_os=\"{os}\"\n")).unwrap(),
            )
            .unwrap();
            assert_eq!(
                resolve(&catalog, &profile, &target).is_ok(),
                accepted,
                "{triple}"
            );
        }
    }

    proptest! {
        #[test]
        fn small_graph_matches_bruteforce_oracle(
            disable_primary in any::<bool>(),
            disable_fallback in any::<bool>(),
            fallback_conflicts in any::<bool>(),
            primary_priority in -10_i32..10,
            fallback_priority in -10_i32..10,
        ) {
            let mut catalog = fixture_catalog();
            catalog.components.get_mut("fixture-model").unwrap().provides[0].priority = primary_priority;
            catalog.components.get_mut("fixture-model-fallback").unwrap().provides[0].priority = fallback_priority;
            if !fallback_conflicts {
                catalog.components.get_mut("fixture-model-fallback").unwrap().conflicts.clear();
            }
            let mut profile = profile();
            if disable_primary {
                profile.components.insert("fixture-model".into(), ComponentChoice::Disabled);
            }
            if disable_fallback {
                profile.components.insert("fixture-model-fallback".into(), ComponentChoice::Disabled);
            }
            let primary_feasible = !disable_primary;
            let fallback_feasible = !disable_fallback && !fallback_conflicts;
            let oracle_sat = primary_feasible || fallback_feasible;
            let actual = resolve(&catalog, &profile, &target());
            prop_assert_eq!(actual.is_ok(), oracle_sat);
            if let Ok(actual) = actual {
                let selected_primary = actual.selected_components.contains(&"fixture-model".to_owned());
                if primary_feasible && fallback_feasible {
                    let primary_wins = primary_priority > fallback_priority
                        || (primary_priority == fallback_priority && "fixture-model" < "fixture-model-fallback");
                    prop_assert_eq!(selected_primary, primary_wins);
                } else {
                    prop_assert_eq!(selected_primary, primary_feasible);
                }
            }
        }
    }
}
