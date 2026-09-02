use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt,
    marker::PhantomData,
};

use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

use crate::{
    catalog::NormalizedCatalog,
    diagnostics::Diagnostic,
    metadata::{
        AppCoexistence, BindingKind, BuildRequirements, ComponentSpec, HostBoundaryKind,
        MAX_CATALOG_DOCUMENT_BYTES, MAX_CATALOG_OWNERS, RequirementMode, ScopeKind, SupportTier,
        TargetSupport,
    },
    profile::{BuildKind, ComponentChoice, CompositionProfile, ProfileResourceBoundsError},
    target::{
        MAX_TARGET_PREDICATE_PARTITIONS, MAX_TARGET_TRIPLE_BYTES, PredicateAnalysisBudget, Target,
        TargetError, validate_predicate_partition_with_budget,
    },
};

pub const MAX_RESOLUTION_SELECTED_COMPONENTS: usize = MAX_CATALOG_OWNERS;
pub const MAX_RESOLUTION_BINDINGS: usize = 16 * 1_024;
pub const MAX_RESOLUTION_RESOURCE_NAMESPACE_BINDINGS: usize = 16 * 1_024;
pub const MAX_RESOLUTION_DIAGNOSTICS: usize = MAX_CATALOG_OWNERS;
pub const MAX_RESOLUTION_DIAGNOSTIC_REASONS_PER_COMPONENT: usize = MAX_CATALOG_OWNERS;
pub const MAX_RESOLUTION_TARGET_SUPPORT_OWNERS: usize = MAX_CATALOG_OWNERS + 2;
pub const MAX_RESOLUTION_TARGET_SUPPORT_ENTRIES: usize =
    MAX_RESOLUTION_TARGET_SUPPORT_OWNERS * MAX_TARGET_PREDICATE_PARTITIONS;
pub const MAX_RESOLUTION_EFFECT_ENTRIES: usize = 64 * 1_024;
pub const MAX_RESOLUTION_BUILD_REQUIREMENT_ENTRIES: usize = 16 * 1_024;
pub const MAX_RESOLUTION_INDIVIDUAL_STRING_BYTES: usize = MAX_CATALOG_DOCUMENT_BYTES;
pub const MAX_RESOLUTION_TOTAL_STRING_BYTES: usize = 16 * 1_024 * 1_024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
    #[serde(rename = "target-support")]
    pub target_support: BTreeMap<String, ResolvedTargetSupport>,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedResolution {
    schema: u32,
    profile: String,
    target: String,
    #[serde(rename = "target-fact-digest")]
    target_fact_digest: String,
    #[serde(
        rename = "selected-components",
        deserialize_with = "deserialize_selected_components"
    )]
    selected_components: Vec<String>,
    #[serde(deserialize_with = "deserialize_resolution_bindings")]
    bindings: Vec<ResolvedBinding>,
    #[serde(
        rename = "resource-namespace-bindings",
        deserialize_with = "deserialize_resource_namespace_bindings"
    )]
    resource_namespace_bindings: Vec<ResolvedResourceNamespaceBinding>,
    #[serde(
        rename = "construction-order",
        deserialize_with = "deserialize_construction_order"
    )]
    construction_order: Vec<String>,
    #[serde(rename = "runtime-adapter")]
    runtime_adapter: String,
    #[serde(rename = "host-boundary")]
    host_boundary: Option<String>,
    #[serde(
        rename = "target-support",
        deserialize_with = "deserialize_unique_target_support"
    )]
    target_support: BTreeMap<String, ResolvedTargetSupport>,
    #[serde(
        rename = "compiled-runtime-effects",
        deserialize_with = "deserialize_runtime_effects"
    )]
    compiled_runtime_effects: BTreeSet<String>,
    #[serde(
        rename = "build-requirements",
        deserialize_with = "deserialize_resolution_build_requirements"
    )]
    build_requirements: BuildRequirements,
    #[serde(rename = "app-handoff")]
    app_handoff: AppHandoff,
    #[serde(rename = "explored-decisions")]
    explored_decisions: u32,
    #[serde(deserialize_with = "deserialize_resolution_diagnostics")]
    diagnostics: Vec<Diagnostic>,
}

impl<'de> Deserialize<'de> for Resolution {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedResolution::deserialize(deserializer)?;
        let resolution = Self {
            schema: unchecked.schema,
            profile: unchecked.profile,
            target: unchecked.target,
            target_fact_digest: unchecked.target_fact_digest,
            selected_components: unchecked.selected_components,
            bindings: unchecked.bindings,
            resource_namespace_bindings: unchecked.resource_namespace_bindings,
            construction_order: unchecked.construction_order,
            runtime_adapter: unchecked.runtime_adapter,
            host_boundary: unchecked.host_boundary,
            target_support: unchecked.target_support,
            compiled_runtime_effects: unchecked.compiled_runtime_effects,
            build_requirements: unchecked.build_requirements,
            app_handoff: unchecked.app_handoff,
            explored_decisions: unchecked.explored_decisions,
            diagnostics: unchecked.diagnostics,
        };
        resolution
            .verify_canonical_structure()
            .map_err(de::Error::custom)?;
        Ok(resolution)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedTargetSupport {
    pub targets: String,
    #[serde(rename = "entries")]
    pub entries: Vec<TargetSupport>,
    #[serde(rename = "matched-predicate")]
    pub matched_predicate: String,
    #[serde(rename = "selected-tier")]
    pub selected_tier: SupportTier,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedResolvedTargetSupport {
    targets: String,
    #[serde(
        rename = "entries",
        deserialize_with = "deserialize_target_support_entries"
    )]
    entries: Vec<TargetSupport>,
    #[serde(rename = "matched-predicate")]
    matched_predicate: String,
    #[serde(rename = "selected-tier")]
    selected_tier: SupportTier,
}

impl<'de> Deserialize<'de> for ResolvedTargetSupport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedResolvedTargetSupport::deserialize(deserializer)?;
        let support = Self {
            targets: unchecked.targets,
            entries: unchecked.entries,
            matched_predicate: unchecked.matched_predicate,
            selected_tier: unchecked.selected_tier,
        };
        support
            .verify_canonical_structure("target-support")
            .map_err(de::Error::custom)?;
        Ok(support)
    }
}

fn deserialize_selected_components<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(
        deserializer,
        MAX_RESOLUTION_SELECTED_COMPONENTS,
        "selected-components",
    )
}

fn deserialize_resolution_bindings<'de, D>(
    deserializer: D,
) -> Result<Vec<ResolvedBinding>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_RESOLUTION_BINDINGS, "bindings")
}

fn deserialize_resource_namespace_bindings<'de, D>(
    deserializer: D,
) -> Result<Vec<ResolvedResourceNamespaceBinding>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(
        deserializer,
        MAX_RESOLUTION_RESOURCE_NAMESPACE_BINDINGS,
        "resource-namespace-bindings",
    )
}

fn deserialize_construction_order<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(
        deserializer,
        MAX_RESOLUTION_SELECTED_COMPONENTS,
        "construction-order",
    )
}

fn deserialize_resolution_diagnostics<'de, D>(deserializer: D) -> Result<Vec<Diagnostic>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_RESOLUTION_DIAGNOSTICS, "diagnostics")
}

fn deserialize_target_support_entries<'de, D>(
    deserializer: D,
) -> Result<Vec<TargetSupport>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(
        deserializer,
        MAX_TARGET_PREDICATE_PARTITIONS,
        "target-support entries",
    )
}

fn deserialize_runtime_effects<'de, D>(deserializer: D) -> Result<BTreeSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_unique_bounded_set(
        deserializer,
        MAX_RESOLUTION_EFFECT_ENTRIES,
        "runtime effects",
    )
}

fn deserialize_build_requirement_set<'de, D>(deserializer: D) -> Result<BTreeSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_unique_bounded_set(
        deserializer,
        MAX_RESOLUTION_BUILD_REQUIREMENT_ENTRIES,
        "build requirements",
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedResolutionBuildRequirements {
    #[serde(deserialize_with = "deserialize_build_requirement_set")]
    executables: BTreeSet<String>,
    #[serde(
        rename = "read-inputs",
        deserialize_with = "deserialize_build_requirement_set"
    )]
    read_inputs: BTreeSet<String>,
    #[serde(deserialize_with = "deserialize_build_requirement_set")]
    environment: BTreeSet<String>,
}

fn deserialize_resolution_build_requirements<'de, D>(
    deserializer: D,
) -> Result<BuildRequirements, D::Error>
where
    D: Deserializer<'de>,
{
    let unchecked = UncheckedResolutionBuildRequirements::deserialize(deserializer)?;
    Ok(BuildRequirements {
        executables: unchecked.executables,
        read_inputs: unchecked.read_inputs,
        environment: unchecked.environment,
    })
}

fn deserialize_bounded_vec<'de, D, T>(
    deserializer: D,
    maximum: usize,
    field: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T> {
        maximum: usize,
        field: &'static str,
        marker: PhantomData<T>,
    }

    impl<'de, T> de::Visitor<'de> for BoundedVecVisitor<T>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {} entries in {}",
                self.maximum, self.field
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            if sequence.size_hint().is_some_and(|hint| hint > self.maximum) {
                return Err(de::Error::custom(format!(
                    "{} has more than {} entries",
                    self.field, self.maximum
                )));
            }
            let mut values =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.maximum));
            while let Some(value) = sequence.next_element()? {
                if values.len() == self.maximum {
                    return Err(de::Error::custom(format!(
                        "{} has more than {} entries",
                        self.field, self.maximum
                    )));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor {
        maximum,
        field,
        marker: PhantomData,
    })
}

fn deserialize_unique_bounded_set<'de, D, T>(
    deserializer: D,
    maximum: usize,
    field: &'static str,
) -> Result<BTreeSet<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Ord,
{
    struct UniqueBoundedSetVisitor<T> {
        maximum: usize,
        field: &'static str,
        marker: PhantomData<T>,
    }

    impl<'de, T> de::Visitor<'de> for UniqueBoundedSetVisitor<T>
    where
        T: Deserialize<'de> + Ord,
    {
        type Value = BTreeSet<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {} unique entries in {}",
                self.maximum, self.field
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            if sequence.size_hint().is_some_and(|hint| hint > self.maximum) {
                return Err(de::Error::custom(format!(
                    "{} has more than {} entries",
                    self.field, self.maximum
                )));
            }
            let mut values = BTreeSet::new();
            let mut entry_count = 0_usize;
            while let Some(value) = sequence.next_element()? {
                if entry_count == self.maximum {
                    return Err(de::Error::custom(format!(
                        "{} has more than {} entries",
                        self.field, self.maximum
                    )));
                }
                entry_count += 1;
                if !values.insert(value) {
                    return Err(de::Error::custom(format!(
                        "{} contains a duplicate entry",
                        self.field
                    )));
                }
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(UniqueBoundedSetVisitor {
        maximum,
        field,
        marker: PhantomData,
    })
}

fn deserialize_unique_target_support<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, ResolvedTargetSupport>, D::Error>
where
    D: Deserializer<'de>,
{
    struct UniqueTargetSupport;

    impl<'de> de::Visitor<'de> for UniqueTargetSupport {
        type Value = BTreeMap<String, ResolvedTargetSupport>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "a target-support object with at most {MAX_RESOLUTION_TARGET_SUPPORT_OWNERS} unique owner keys"
            )
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: de::MapAccess<'de>,
        {
            if map
                .size_hint()
                .is_some_and(|hint| hint > MAX_RESOLUTION_TARGET_SUPPORT_OWNERS)
            {
                return Err(de::Error::custom(format!(
                    "target-support has more than {MAX_RESOLUTION_TARGET_SUPPORT_OWNERS} owners"
                )));
            }
            let mut target_support = BTreeMap::new();
            while let Some((owner, support)) = map.next_entry()? {
                if target_support.len() == MAX_RESOLUTION_TARGET_SUPPORT_OWNERS {
                    return Err(de::Error::custom(format!(
                        "target-support has more than {MAX_RESOLUTION_TARGET_SUPPORT_OWNERS} owners"
                    )));
                }
                match target_support.entry(owner) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(support);
                    }
                    std::collections::btree_map::Entry::Occupied(entry) => {
                        return Err(de::Error::custom(format!(
                            "duplicate target-support owner `{}`",
                            entry.key()
                        )));
                    }
                }
            }
            Ok(target_support)
        }
    }

    deserializer.deserialize_map(UniqueTargetSupport)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedBinding {
    pub capability: String,
    pub key: Option<String>,
    pub provider: String,
    pub consumer: String,
    pub field: String,
    pub effects: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedResolvedBinding {
    capability: String,
    key: Option<String>,
    provider: String,
    consumer: String,
    field: String,
    #[serde(deserialize_with = "deserialize_runtime_effects")]
    effects: BTreeSet<String>,
}

impl<'de> Deserialize<'de> for ResolvedBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedResolvedBinding::deserialize(deserializer)?;
        Ok(Self {
            capability: unchecked.capability,
            key: unchecked.key,
            provider: unchecked.provider,
            consumer: unchecked.consumer,
            field: unchecked.field,
            effects: unchecked.effects,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedResolvedResourceNamespaceBinding {
    consumer: String,
    #[serde(rename = "provide-capability")]
    provide_capability: String,
    #[serde(rename = "provide-key")]
    provide_key: Option<String>,
    #[serde(rename = "bootstrap-provider")]
    bootstrap_provider: String,
    #[serde(rename = "bootstrap-key")]
    bootstrap_key: String,
    #[serde(deserialize_with = "deserialize_runtime_effects")]
    effects: BTreeSet<String>,
}

impl<'de> Deserialize<'de> for ResolvedResourceNamespaceBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedResolvedResourceNamespaceBinding::deserialize(deserializer)?;
        Ok(Self {
            consumer: unchecked.consumer,
            provide_capability: unchecked.provide_capability,
            provide_key: unchecked.provide_key,
            bootstrap_provider: unchecked.bootstrap_provider,
            bootstrap_key: unchecked.bootstrap_key,
            effects: unchecked.effects,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppHandoff {
    Concurrent,
    StopOldApp,
}

#[derive(Debug, Error)]
pub enum ResolutionError {
    #[error("unsupported resolution schema {0}; expected 1")]
    UnsupportedResolutionSchema(u32),
    #[error("resolution `{field}` has {actual} entries; maximum is {maximum}")]
    ResolutionCollectionLimitExceeded {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("resolution `{field}` is not in strict canonical order or contains duplicates")]
    NonCanonicalResolutionCollection { field: &'static str },
    #[error("resolution `{left}` does not contain the same unique identities as `{right}`")]
    ResolutionCollectionSetMismatch {
        left: &'static str,
        right: &'static str,
    },
    #[error("resolution projection `{field}` does not match its normalized input")]
    InvalidResolutionProjection { field: &'static str },
    #[error("resolution {kind} route from `{provider}` to `{consumer}` is invalid: {message}")]
    InvalidResolutionRoute {
        kind: &'static str,
        provider: String,
        consumer: String,
        message: &'static str,
    },
    #[error("resolution selection for `{component}` conflicts with profile choice {choice:?}")]
    InvalidProfileComponentSelection {
        component: String,
        choice: ComponentChoice,
    },
    #[error("resolution includes profile-denied runtime effect `{0}`")]
    DeniedRuntimeEffect(String),
    #[error("resolution diagnostic for `{component}` is invalid: {message}")]
    InvalidResolutionDiagnostic { component: String, message: String },
    #[error("resolution string `{field}` has {actual} bytes; maximum is {maximum}")]
    ResolutionStringLimitExceeded {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("resolution strings have {actual} total bytes; maximum is {maximum}")]
    ResolutionTotalStringLimitExceeded { actual: usize, maximum: usize },
    #[error("profile selection count overflowed")]
    ProfileSelectionCountOverflow,
    #[error("profile has {actual} selections; maximum is {maximum}")]
    ProfileSelectionLimitExceeded { actual: usize, maximum: usize },
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
    #[error("target support for `{owner}` is invalid: {message}")]
    InvalidTargetSupport { owner: String, message: String },
    #[error("target support predicate for `{owner}` is invalid: {source}")]
    InvalidTargetSupportPredicate { owner: String, source: TargetError },
    #[error("target support for `{owner}` matched {actual} entries; expected exactly one")]
    TargetSupportMatchCount { owner: String, actual: usize },
    #[error("target support for `{owner}` has unsupported tier {support:?} for target `{target}`")]
    UnsupportedTargetSupportTier {
        owner: String,
        target: String,
        support: SupportTier,
    },
    #[error("Host boundary `{id}` does not support target `{target}`")]
    UnsupportedHostBoundaryTarget { id: String, target: String },
    #[error("Host boundary `{id}` has unsupported tier {support:?} for target `{target}`")]
    UnsupportedHostBoundarySupportTier {
        id: String,
        target: String,
        support: SupportTier,
    },
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
    target.verify().map_err(|source| ResolutionError::Target {
        owner: "resolver-input".into(),
        source,
    })?;
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
        adapter.target_support.as_deref(),
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
    state.bindings.sort_by(compare_resolved_bindings);
    state
        .resource_namespace_bindings
        .sort_by(compare_resource_namespace_bindings);

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
            let mut reasons = state
                .reasons
                .get(component)
                .cloned()
                .unwrap_or_else(|| vec!["SelectedProvider".into()]);
            reasons.sort();
            reasons.dedup();
            diagnostics.push(Diagnostic::selected(component, reasons));
        } else {
            let reason = match profile.components.get(component) {
                Some(ComponentChoice::Disabled) => "ExplicitDisabled",
                _ => "NotRequired",
            };
            diagnostics.push(Diagnostic::excluded(component, vec![reason.into()]));
        }
    }

    let mut target_support = BTreeMap::new();
    target_support.insert(
        format!("runtime-adapter:{}", adapter.id),
        resolved_target_support(
            adapter.support,
            adapter.target_support.as_deref(),
            &adapter.targets,
            target,
            &adapter.id,
        )?,
    );
    for component in &selected_components {
        let spec = &catalog.components[component];
        target_support.insert(
            format!("component:{}", spec.id),
            resolved_target_support(
                spec.support,
                spec.target_support.as_deref(),
                &spec.targets,
                target,
                &spec.id,
            )?,
        );
    }
    if let Some(boundary) = boundary {
        target_support.insert(
            format!("host-boundary:{}", boundary.id),
            resolved_target_support(
                boundary.support,
                boundary.target_support.as_deref(),
                &boundary.targets,
                target,
                &boundary.id,
            )?,
        );
    }

    let resolution = Resolution {
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
        target_support,
        compiled_runtime_effects,
        build_requirements,
        app_handoff,
        explored_decisions: resolver.explored,
        diagnostics,
    };
    resolution.verify_canonical_semantics(profile, target)?;
    Ok(resolution)
}

impl Resolution {
    fn verify_canonical_structure(&self) -> Result<(), ResolutionError> {
        if self.schema != 1 {
            return Err(ResolutionError::UnsupportedResolutionSchema(self.schema));
        }
        verify_collection_limit(
            "selected-components",
            self.selected_components.len(),
            MAX_RESOLUTION_SELECTED_COMPONENTS,
        )?;
        if !is_strictly_increasing(&self.selected_components) {
            return Err(ResolutionError::NonCanonicalResolutionCollection {
                field: "selected-components",
            });
        }
        verify_collection_limit(
            "construction-order",
            self.construction_order.len(),
            MAX_RESOLUTION_SELECTED_COMPONENTS,
        )?;
        let construction_set = self
            .construction_order
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if construction_set.len() != self.construction_order.len() {
            return Err(ResolutionError::NonCanonicalResolutionCollection {
                field: "construction-order",
            });
        }
        let selected_set = self
            .selected_components
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if construction_set != selected_set {
            return Err(ResolutionError::ResolutionCollectionSetMismatch {
                left: "construction-order",
                right: "selected-components",
            });
        }

        verify_collection_limit("bindings", self.bindings.len(), MAX_RESOLUTION_BINDINGS)?;
        if !self
            .bindings
            .windows(2)
            .all(|pair| compare_resolved_bindings(&pair[0], &pair[1]) == Ordering::Less)
        {
            return Err(ResolutionError::NonCanonicalResolutionCollection { field: "bindings" });
        }
        verify_collection_limit(
            "resource-namespace-bindings",
            self.resource_namespace_bindings.len(),
            MAX_RESOLUTION_RESOURCE_NAMESPACE_BINDINGS,
        )?;
        if !self
            .resource_namespace_bindings
            .windows(2)
            .all(|pair| compare_resource_namespace_bindings(&pair[0], &pair[1]) == Ordering::Less)
        {
            return Err(ResolutionError::NonCanonicalResolutionCollection {
                field: "resource-namespace-bindings",
            });
        }
        if self
            .bindings
            .windows(2)
            .any(|pair| compare_resolved_binding_routes(&pair[0], &pair[1]) == Ordering::Equal)
        {
            return Err(ResolutionError::NonCanonicalResolutionCollection {
                field: "binding routes",
            });
        }
        if self.resource_namespace_bindings.windows(2).any(|pair| {
            compare_resource_namespace_binding_routes(&pair[0], &pair[1]) == Ordering::Equal
        }) {
            return Err(ResolutionError::NonCanonicalResolutionCollection {
                field: "resource-namespace-binding routes",
            });
        }

        let construction_positions = self
            .construction_order
            .iter()
            .enumerate()
            .map(|(index, component)| (component.as_str(), index))
            .collect::<BTreeMap<_, _>>();
        for binding in &self.bindings {
            verify_resolution_route(
                "binding",
                &binding.provider,
                &binding.consumer,
                &binding.effects,
                &construction_positions,
                &self.compiled_runtime_effects,
            )?;
        }
        for binding in &self.resource_namespace_bindings {
            verify_resolution_route(
                "resource-namespace binding",
                &binding.bootstrap_provider,
                &binding.consumer,
                &binding.effects,
                &construction_positions,
                &self.compiled_runtime_effects,
            )?;
        }

        verify_collection_limit(
            "diagnostics",
            self.diagnostics.len(),
            MAX_RESOLUTION_DIAGNOSTICS,
        )?;
        if !self
            .diagnostics
            .windows(2)
            .all(|pair| pair[0].component < pair[1].component)
        {
            return Err(ResolutionError::NonCanonicalResolutionCollection {
                field: "diagnostics",
            });
        }
        let mut diagnostic_reason_count = 0_usize;
        for diagnostic in &self.diagnostics {
            verify_collection_limit(
                "diagnostic reasons",
                diagnostic.reasons.len(),
                MAX_RESOLUTION_DIAGNOSTIC_REASONS_PER_COMPONENT,
            )?;
            if diagnostic.reasons.is_empty() || !is_strictly_increasing(&diagnostic.reasons) {
                return Err(ResolutionError::InvalidResolutionDiagnostic {
                    component: diagnostic.component.clone(),
                    message: "reasons must be non-empty, unique, and strictly sorted".into(),
                });
            }
            diagnostic_reason_count =
                diagnostic_reason_count.saturating_add(diagnostic.reasons.len());
            let selected = self
                .selected_components
                .binary_search(&diagnostic.component)
                .is_ok();
            let expected_conclusion = if selected { "selected" } else { "excluded" };
            if diagnostic.conclusion != expected_conclusion {
                return Err(ResolutionError::InvalidResolutionDiagnostic {
                    component: diagnostic.component.clone(),
                    message: format!(
                        "conclusion must be `{expected_conclusion}` for this selection state"
                    ),
                });
            }
        }
        verify_collection_limit(
            "diagnostic reasons",
            diagnostic_reason_count,
            MAX_RESOLUTION_DIAGNOSTICS * MAX_RESOLUTION_DIAGNOSTIC_REASONS_PER_COMPONENT,
        )?;
        for component in &self.selected_components {
            if self
                .diagnostics
                .binary_search_by(|diagnostic| diagnostic.component.cmp(component))
                .is_err()
            {
                return Err(ResolutionError::InvalidResolutionDiagnostic {
                    component: component.clone(),
                    message: "selected component is missing its diagnostic".into(),
                });
            }
        }

        verify_collection_limit(
            "target-support owners",
            self.target_support.len(),
            MAX_RESOLUTION_TARGET_SUPPORT_OWNERS,
        )?;
        let expected_owner_maximum = self
            .selected_components
            .len()
            .saturating_add(1)
            .saturating_add(usize::from(self.host_boundary.is_some()));
        verify_collection_limit(
            "target-support owners",
            self.target_support.len(),
            expected_owner_maximum,
        )?;
        let mut target_support_entry_count = 0_usize;
        for (owner, support) in &self.target_support {
            support.verify_canonical_structure(owner)?;
            target_support_entry_count =
                target_support_entry_count.saturating_add(support.entries.len());
        }
        verify_collection_limit(
            "target-support entries",
            target_support_entry_count,
            MAX_RESOLUTION_TARGET_SUPPORT_ENTRIES,
        )?;

        let effect_entry_count = self
            .bindings
            .iter()
            .map(|binding| binding.effects.len())
            .chain(
                self.resource_namespace_bindings
                    .iter()
                    .map(|binding| binding.effects.len()),
            )
            .fold(self.compiled_runtime_effects.len(), usize::saturating_add);
        verify_collection_limit(
            "runtime-effect entries",
            effect_entry_count,
            MAX_RESOLUTION_EFFECT_ENTRIES,
        )?;
        let build_requirement_count = self
            .build_requirements
            .executables
            .len()
            .saturating_add(self.build_requirements.read_inputs.len())
            .saturating_add(self.build_requirements.environment.len());
        verify_collection_limit(
            "build-requirement entries",
            build_requirement_count,
            MAX_RESOLUTION_BUILD_REQUIREMENT_ENTRIES,
        )?;

        self.verify_string_bounds()
    }

    fn verify_string_bounds(&self) -> Result<(), ResolutionError> {
        let mut budget = ResolutionStringBudget::default();
        budget.take("profile", &self.profile)?;
        budget.take_with_max("target", &self.target, MAX_TARGET_TRIPLE_BYTES)?;
        budget.take("target-fact-digest", &self.target_fact_digest)?;
        budget.take("runtime-adapter", &self.runtime_adapter)?;
        if let Some(boundary) = &self.host_boundary {
            budget.take("host-boundary", boundary)?;
        }
        for component in self
            .selected_components
            .iter()
            .chain(&self.construction_order)
        {
            budget.take("component", component)?;
        }
        for binding in &self.bindings {
            budget.take("binding capability", &binding.capability)?;
            if let Some(key) = &binding.key {
                budget.take("binding key", key)?;
            }
            budget.take("binding provider", &binding.provider)?;
            budget.take("binding consumer", &binding.consumer)?;
            budget.take("binding field", &binding.field)?;
            for effect in &binding.effects {
                budget.take("binding effect", effect)?;
            }
        }
        for binding in &self.resource_namespace_bindings {
            budget.take("resource binding consumer", &binding.consumer)?;
            budget.take(
                "resource binding provide capability",
                &binding.provide_capability,
            )?;
            if let Some(key) = &binding.provide_key {
                budget.take("resource binding provide key", key)?;
            }
            budget.take(
                "resource binding bootstrap provider",
                &binding.bootstrap_provider,
            )?;
            budget.take("resource binding bootstrap key", &binding.bootstrap_key)?;
            for effect in &binding.effects {
                budget.take("resource binding effect", effect)?;
            }
        }
        for (owner, support) in &self.target_support {
            budget.take("target-support owner", owner)?;
            budget.take("target-support targets", &support.targets)?;
            budget.take(
                "target-support matched predicate",
                &support.matched_predicate,
            )?;
            for entry in &support.entries {
                budget.take("target-support predicate", &entry.predicate)?;
            }
        }
        for effect in &self.compiled_runtime_effects {
            budget.take("compiled runtime effect", effect)?;
        }
        for executable in &self.build_requirements.executables {
            budget.take("build executable", executable)?;
        }
        for input in &self.build_requirements.read_inputs {
            budget.take("build read input", input)?;
        }
        for environment in &self.build_requirements.environment {
            budget.take("build environment", environment)?;
        }
        for diagnostic in &self.diagnostics {
            budget.take("diagnostic component", &diagnostic.component)?;
            budget.take("diagnostic conclusion", &diagnostic.conclusion)?;
            for reason in &diagnostic.reasons {
                budget.take("diagnostic reason", reason)?;
            }
        }
        Ok(())
    }

    /// Verifies every canonical invariant derivable from the committed Resolution plus the
    /// normalized profile and target. Composition loading and verification additionally rerun the
    /// resolver from the identity-bound generator-input commitment to prove catalog-derived
    /// binding, diagnostic, effect, build-requirement, and handoff truth. This standalone check
    /// deliberately does not present structural self-consistency as that stronger proof.
    pub(crate) fn verify_canonical_semantics(
        &self,
        profile: &CompositionProfile,
        target: &Target,
    ) -> Result<(), ResolutionError> {
        self.verify_canonical_structure()?;
        profile
            .validate_resource_bounds()
            .map_err(|error| match error {
                ProfileResourceBoundsError::SelectionCountOverflow => {
                    ResolutionError::ProfileSelectionCountOverflow
                }
                ProfileResourceBoundsError::TooManySelections { actual, maximum } => {
                    ResolutionError::ProfileSelectionLimitExceeded { actual, maximum }
                }
            })?;
        if profile.schema != 1 {
            return Err(ResolutionError::UnsupportedProfileSchema(profile.schema));
        }
        if profile.resolver_decision_budget == 0 {
            return Err(ResolutionError::InvalidDecisionBudget(profile.name.clone()));
        }
        for capability in profile
            .bindings
            .keys()
            .chain(profile.preferred_providers.keys())
        {
            if capability.starts_with("cap:") {
                return Err(ResolutionError::PrefixedBindingKey(capability.clone()));
            }
        }
        for binding in &self.bindings {
            let Some(capability) = binding.capability.strip_prefix("cap:") else {
                return Err(ResolutionError::InvalidResolutionRoute {
                    kind: "binding",
                    provider: binding.provider.clone(),
                    consumer: binding.consumer.clone(),
                    message: "capability must use the `cap:` namespace",
                });
            };
            if profile
                .bindings
                .get(capability)
                .is_some_and(|provider| provider != &binding.provider)
            {
                return Err(ResolutionError::InvalidResolutionRoute {
                    kind: "binding",
                    provider: binding.provider.clone(),
                    consumer: binding.consumer.clone(),
                    message: "provider differs from the explicit profile binding",
                });
            }
        }
        for binding in &self.resource_namespace_bindings {
            if !binding.provide_capability.starts_with("cap:") {
                return Err(ResolutionError::InvalidResolutionRoute {
                    kind: "resource-namespace binding",
                    provider: binding.bootstrap_provider.clone(),
                    consumer: binding.consumer.clone(),
                    message: "provide capability must use the `cap:` namespace",
                });
            }
            if profile
                .bindings
                .get("resource-namespace-bootstrap")
                .is_some_and(|provider| provider != &binding.bootstrap_provider)
            {
                return Err(ResolutionError::InvalidResolutionRoute {
                    kind: "resource-namespace binding",
                    provider: binding.bootstrap_provider.clone(),
                    consumer: binding.consumer.clone(),
                    message: "provider differs from the explicit profile binding",
                });
            }
        }
        for (component, choice) in &profile.components {
            let selected = self.selected_components.binary_search(component).is_ok();
            if (*choice == ComponentChoice::Enabled && !selected)
                || (*choice == ComponentChoice::Disabled && selected)
            {
                return Err(ResolutionError::InvalidProfileComponentSelection {
                    component: component.clone(),
                    choice: *choice,
                });
            }
        }
        if let Some(effect) = self
            .compiled_runtime_effects
            .intersection(&profile.denied_effects)
            .next()
        {
            return Err(ResolutionError::DeniedRuntimeEffect(effect.clone()));
        }
        match (profile.build_kind, self.host_boundary.is_some()) {
            (BuildKind::Library, true) => {
                return Err(ResolutionError::InvalidHostBoundary {
                    build_kind: profile.build_kind,
                    message: "library composition forbids a Host boundary".into(),
                });
            }
            (BuildKind::Bin | BuildKind::Wasm, false) => {
                return Err(ResolutionError::InvalidHostBoundary {
                    build_kind: profile.build_kind,
                    message: "exactly one Host boundary is required".into(),
                });
            }
            (BuildKind::Library, false) | (BuildKind::Bin | BuildKind::Wasm, true) => {}
        }
        if profile.build_kind == BuildKind::Wasm && target.arch().as_str() != "wasm32" {
            return Err(ResolutionError::InvalidHostBoundary {
                build_kind: profile.build_kind,
                message: "wasm build requires target_arch=wasm32".into(),
            });
        }
        target.verify().map_err(|source| ResolutionError::Target {
            owner: "resolution-verifier".into(),
            source,
        })?;
        for (field, matches) in [
            ("profile", self.profile == profile.name),
            (
                "target",
                self.target == profile.target && self.target == target.triple,
            ),
            (
                "target-fact-digest",
                self.target_fact_digest == target.target_fact_digest,
            ),
            (
                "runtime-adapter",
                self.runtime_adapter == profile.runtime_adapter,
            ),
            ("host-boundary", self.host_boundary == profile.host_boundary),
            ("environment", profile.environment == target.environment),
            (
                "explored-decisions",
                self.explored_decisions <= profile.resolver_decision_budget,
            ),
        ] {
            if !matches {
                return Err(ResolutionError::InvalidResolutionProjection { field });
            }
        }
        let mut predicate_analysis_budget = PredicateAnalysisBudget::new();
        self.verify_target_support_projection_with_budget(
            profile,
            target,
            &mut predicate_analysis_budget,
        )
    }

    #[cfg(test)]
    fn verify_target_support_projection(
        &self,
        profile: &CompositionProfile,
        target: &Target,
    ) -> Result<(), ResolutionError> {
        self.verify_canonical_structure()?;
        let mut predicate_analysis_budget = PredicateAnalysisBudget::new();
        self.verify_target_support_projection_with_budget(
            profile,
            target,
            &mut predicate_analysis_budget,
        )
    }

    fn verify_target_support_projection_with_budget(
        &self,
        profile: &CompositionProfile,
        target: &Target,
        predicate_analysis_budget: &mut PredicateAnalysisBudget,
    ) -> Result<(), ResolutionError> {
        let mut expected_owners =
            BTreeSet::from([format!("runtime-adapter:{}", self.runtime_adapter)]);
        expected_owners.extend(
            self.selected_components
                .iter()
                .map(|id| format!("component:{id}")),
        );
        if let Some(id) = &self.host_boundary {
            expected_owners.insert(format!("host-boundary:{id}"));
        }
        let actual_owners = self.target_support.keys().cloned().collect::<BTreeSet<_>>();
        if actual_owners != expected_owners {
            return Err(ResolutionError::InvalidTargetSupport {
                owner: "resolution".into(),
                message: "owner keys differ from the resolved package roots".into(),
            });
        }

        for (owner, support) in &self.target_support {
            let predicates = support
                .entries
                .iter()
                .map(|entry| entry.predicate.as_str())
                .collect::<Vec<_>>();
            validate_predicate_partition_with_budget(
                &support.targets,
                &predicates,
                predicate_analysis_budget,
            )
            .map_err(|source| ResolutionError::InvalidTargetSupportPredicate {
                owner: owner.clone(),
                source,
            })?;
            let selected = matching_target_support_entry(
                None,
                Some(&support.entries),
                &support.targets,
                target,
                owner,
            )?
            .ok_or_else(|| ResolutionError::InvalidTargetSupport {
                owner: owner.clone(),
                message: "selected owner is outside its target predicate".into(),
            })?;
            if selected.predicate != support.matched_predicate
                || selected.tier != support.selected_tier
            {
                return Err(ResolutionError::InvalidTargetSupport {
                    owner: owner.clone(),
                    message: "matched predicate or selected tier differs from the unique entry"
                        .into(),
                });
            }
            if profile.support_tier == SupportTier::Production
                && selected.tier == SupportTier::Experimental
            {
                if let Some(id) = owner.strip_prefix("host-boundary:") {
                    return Err(ResolutionError::UnsupportedHostBoundarySupportTier {
                        id: id.into(),
                        target: target.triple.clone(),
                        support: selected.tier,
                    });
                }
                return Err(ResolutionError::UnsupportedTargetSupportTier {
                    owner: owner.clone(),
                    target: target.triple.clone(),
                    support: selected.tier,
                });
            }
        }
        Ok(())
    }
}

impl ResolvedTargetSupport {
    fn verify_canonical_structure(&self, owner: &str) -> Result<(), ResolutionError> {
        if self.entries.is_empty() {
            return Err(ResolutionError::InvalidTargetSupport {
                owner: owner.into(),
                message: "entries must not be empty".into(),
            });
        }
        verify_collection_limit(
            "target-support entries",
            self.entries.len(),
            MAX_TARGET_PREDICATE_PARTITIONS,
        )?;
        if !is_strictly_increasing(&self.entries) {
            return Err(ResolutionError::InvalidTargetSupport {
                owner: owner.into(),
                message: "entries must be unique and in strict canonical order".into(),
            });
        }
        Ok(())
    }
}

#[derive(Default)]
struct ResolutionStringBudget {
    total: usize,
}

impl ResolutionStringBudget {
    fn take(&mut self, field: &'static str, value: &str) -> Result<(), ResolutionError> {
        self.take_with_max(field, value, MAX_RESOLUTION_INDIVIDUAL_STRING_BYTES)
    }

    fn take_with_max(
        &mut self,
        field: &'static str,
        value: &str,
        maximum: usize,
    ) -> Result<(), ResolutionError> {
        if value.len() > maximum {
            return Err(ResolutionError::ResolutionStringLimitExceeded {
                field,
                actual: value.len(),
                maximum,
            });
        }
        self.total = self.total.saturating_add(value.len());
        if self.total > MAX_RESOLUTION_TOTAL_STRING_BYTES {
            return Err(ResolutionError::ResolutionTotalStringLimitExceeded {
                actual: self.total,
                maximum: MAX_RESOLUTION_TOTAL_STRING_BYTES,
            });
        }
        Ok(())
    }
}

fn verify_collection_limit(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), ResolutionError> {
    if actual > maximum {
        Err(ResolutionError::ResolutionCollectionLimitExceeded {
            field,
            actual,
            maximum,
        })
    } else {
        Ok(())
    }
}

fn is_strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn compare_resolved_bindings(left: &ResolvedBinding, right: &ResolvedBinding) -> Ordering {
    (
        &left.consumer,
        &left.field,
        &left.capability,
        &left.provider,
        &left.key,
        &left.effects,
    )
        .cmp(&(
            &right.consumer,
            &right.field,
            &right.capability,
            &right.provider,
            &right.key,
            &right.effects,
        ))
}

fn compare_resolved_binding_routes(left: &ResolvedBinding, right: &ResolvedBinding) -> Ordering {
    (
        &left.consumer,
        &left.field,
        &left.capability,
        &left.provider,
        &left.key,
    )
        .cmp(&(
            &right.consumer,
            &right.field,
            &right.capability,
            &right.provider,
            &right.key,
        ))
}

fn compare_resource_namespace_bindings(
    left: &ResolvedResourceNamespaceBinding,
    right: &ResolvedResourceNamespaceBinding,
) -> Ordering {
    (
        &left.consumer,
        &left.provide_capability,
        &left.provide_key,
        &left.bootstrap_key,
        &left.bootstrap_provider,
        &left.effects,
    )
        .cmp(&(
            &right.consumer,
            &right.provide_capability,
            &right.provide_key,
            &right.bootstrap_key,
            &right.bootstrap_provider,
            &right.effects,
        ))
}

fn compare_resource_namespace_binding_routes(
    left: &ResolvedResourceNamespaceBinding,
    right: &ResolvedResourceNamespaceBinding,
) -> Ordering {
    (
        &left.consumer,
        &left.provide_capability,
        &left.provide_key,
        &left.bootstrap_key,
        &left.bootstrap_provider,
    )
        .cmp(&(
            &right.consumer,
            &right.provide_capability,
            &right.provide_key,
            &right.bootstrap_key,
            &right.bootstrap_provider,
        ))
}

fn verify_resolution_route(
    kind: &'static str,
    provider: &str,
    consumer: &str,
    effects: &BTreeSet<String>,
    construction_positions: &BTreeMap<&str, usize>,
    compiled_runtime_effects: &BTreeSet<String>,
) -> Result<(), ResolutionError> {
    let Some(provider_position) = construction_positions.get(provider) else {
        return Err(ResolutionError::InvalidResolutionRoute {
            kind,
            provider: provider.into(),
            consumer: consumer.into(),
            message: "provider is not selected",
        });
    };
    let Some(consumer_position) = construction_positions.get(consumer) else {
        return Err(ResolutionError::InvalidResolutionRoute {
            kind,
            provider: provider.into(),
            consumer: consumer.into(),
            message: "consumer is not selected",
        });
    };
    if provider_position >= consumer_position {
        return Err(ResolutionError::InvalidResolutionRoute {
            kind,
            provider: provider.into(),
            consumer: consumer.into(),
            message: "provider must precede consumer in construction-order",
        });
    }
    if !effects.is_subset(compiled_runtime_effects) {
        return Err(ResolutionError::InvalidResolutionRoute {
            kind,
            provider: provider.into(),
            consumer: consumer.into(),
            message: "effects exceed compiled-runtime-effects",
        });
    }
    Ok(())
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
            component.target_support.as_deref(),
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
            if let Some(priority) = priority
                && explicit.is_none_or(|value| value == &component.id)
            {
                candidates.push((
                    explicit == Some(&component.id),
                    preferred == Some(&component.id),
                    priority,
                    component.id.clone(),
                ));
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
    profile
        .validate_resource_bounds()
        .map_err(|error| match error {
            ProfileResourceBoundsError::SelectionCountOverflow => {
                ResolutionError::ProfileSelectionCountOverflow
            }
            ProfileResourceBoundsError::TooManySelections { actual, maximum } => {
                ResolutionError::ProfileSelectionLimitExceeded { actual, maximum }
            }
        })?;
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
    let target_supported =
        target
            .matches(&boundary.targets)
            .map_err(|source| ResolutionError::Target {
                owner: boundary.id.clone(),
                source,
            })?;
    if !target_supported {
        return Err(ResolutionError::UnsupportedHostBoundaryTarget {
            id: boundary.id.clone(),
            target: target.triple.clone(),
        });
    }
    if !boundary.runtime_adapters.contains(&adapter.id) {
        return Err(ResolutionError::InvalidHostBoundary {
            build_kind: profile.build_kind,
            message: format!(
                "boundary `{}` does not allow runtime adapter `{}`",
                boundary.id, adapter.id
            ),
        });
    }
    let selected_support = matching_target_support_entry(
        boundary.support,
        boundary.target_support.as_deref(),
        &boundary.targets,
        target,
        &boundary.id,
    )?
    .expect("the Host boundary target predicate was checked above");
    if profile.support_tier == SupportTier::Production
        && selected_support.tier == SupportTier::Experimental
    {
        return Err(ResolutionError::UnsupportedHostBoundarySupportTier {
            id: boundary.id.clone(),
            target: target.triple.clone(),
            support: selected_support.tier,
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
    if profile.build_kind == BuildKind::Wasm && target.arch().as_str() != "wasm32" {
        return Err(ResolutionError::InvalidHostBoundary {
            build_kind: profile.build_kind,
            message: "wasm build requires target_arch=wasm32".into(),
        });
    }
    Ok(Some(boundary))
}

fn is_available(
    support: Option<SupportTier>,
    target_support: Option<&[TargetSupport]>,
    predicate: &str,
    profile: &CompositionProfile,
    target: &Target,
    owner: &str,
) -> Result<bool, ResolutionError> {
    let Some(selected) =
        matching_target_support_entry(support, target_support, predicate, target, owner)?
    else {
        return Ok(false);
    };
    Ok(profile.support_tier == SupportTier::Experimental
        || selected.tier == SupportTier::Production)
}

fn matching_target_support_entry(
    support: Option<SupportTier>,
    target_support: Option<&[TargetSupport]>,
    predicate: &str,
    target: &Target,
    owner: &str,
) -> Result<Option<TargetSupport>, ResolutionError> {
    let in_target_set = target
        .matches(predicate)
        .map_err(|source| ResolutionError::Target {
            owner: owner.to_owned(),
            source,
        })?;
    if !in_target_set {
        return Ok(None);
    }
    match (support, target_support) {
        (Some(tier), None) => Ok(Some(TargetSupport {
            predicate: predicate.into(),
            tier,
        })),
        (None, Some(entries)) => {
            let mut matched = None;
            let mut count = 0_usize;
            for entry in entries {
                if target
                    .matches(&entry.predicate)
                    .map_err(|source| ResolutionError::Target {
                        owner: owner.to_owned(),
                        source,
                    })?
                {
                    count += 1;
                    matched.get_or_insert_with(|| entry.clone());
                }
            }
            if count == 1 {
                Ok(matched)
            } else {
                Err(ResolutionError::TargetSupportMatchCount {
                    owner: owner.into(),
                    actual: count,
                })
            }
        }
        (Some(_), Some(_)) => Err(ResolutionError::InvalidTargetSupport {
            owner: owner.into(),
            message: "blanket and per-target support are both present".into(),
        }),
        (None, None) => Err(ResolutionError::InvalidTargetSupport {
            owner: owner.into(),
            message: "support metadata is missing".into(),
        }),
    }
}

fn resolved_target_support(
    support: Option<SupportTier>,
    target_support: Option<&[TargetSupport]>,
    targets: &str,
    target: &Target,
    owner: &str,
) -> Result<ResolvedTargetSupport, ResolutionError> {
    let selected = matching_target_support_entry(support, target_support, targets, target, owner)?
        .ok_or_else(|| ResolutionError::InvalidTargetSupport {
            owner: owner.into(),
            message: "selected owner is outside its target predicate".into(),
        })?;
    let mut entries = match (support, target_support) {
        (Some(tier), None) => vec![TargetSupport {
            predicate: targets.into(),
            tier,
        }],
        (None, Some(entries)) => entries.to_vec(),
        _ => {
            return Err(ResolutionError::InvalidTargetSupport {
                owner: owner.into(),
                message: "support metadata is not normalized".into(),
            });
        }
    };
    entries.sort();
    Ok(ResolvedTargetSupport {
        targets: targets.into(),
        entries,
        matched_predicate: selected.predicate,
        selected_tier: selected.tier,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{
        metadata::CatalogDocument,
        target::{CoreTargetFacts, canonical_builtin_facts},
    };
    use proptest::prelude::*;

    use super::*;

    fn fixture_catalog() -> NormalizedCatalog {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/fixtures/catalog.toml");
        let input = std::fs::read_to_string(path).unwrap();
        NormalizedCatalog::normalize(CatalogDocument::from_toml(&input).unwrap()).unwrap()
    }

    fn target() -> Target {
        let mut facts = canonical_builtin_facts(CoreTargetFacts::little_endian(
            "x86_64", "gnu", "linux", "64", "unwind",
        ))
        .unwrap();
        facts.insert(
            "target_family".into(),
            BTreeSet::from([Some("unix".into())]),
        );
        facts.insert("unix".into(), BTreeSet::from([None]));
        Target::from_facts(
            "x86_64-unknown-linux-gnu",
            crate::target::Environment::Desktop,
            facts,
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
        profile
            .components
            .insert("fixture-model-shared".into(), ComponentChoice::Disabled);
        assert!(matches!(
            resolve(&fixture_catalog(), &profile, &target()),
            Err(ResolutionError::Unsatisfiable { .. })
        ));
    }

    #[test]
    fn resolver_rechecks_profile_selection_bound_after_mutation() {
        let mut profile = profile();
        while profile.components.len() <= crate::profile::MAX_PROFILE_SELECTION_ENTRIES {
            let index = profile.components.len();
            profile
                .components
                .insert(format!("unknown-{index}"), ComponentChoice::Disabled);
        }

        assert!(matches!(
            resolve(&fixture_catalog(), &profile, &target()),
            Err(ResolutionError::ProfileSelectionLimitExceeded { actual, maximum })
                if actual > crate::profile::MAX_PROFILE_SELECTION_ENTRIES
                    && maximum == crate::profile::MAX_PROFILE_SELECTION_ENTRIES
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
    fn resolver_requires_exactly_one_current_target_support_match() {
        let mut overlapping = fixture_catalog();
        let adapter = overlapping
            .runtime_adapters
            .get_mut("fixture-runtime")
            .unwrap();
        let duplicate = adapter.target_support.as_ref().unwrap()[0].clone();
        adapter.target_support.as_mut().unwrap().push(duplicate);
        assert!(matches!(
            resolve(&overlapping, &profile(), &target()),
            Err(ResolutionError::TargetSupportMatchCount { owner, actual: 2 })
                if owner == "fixture-runtime"
        ));

        let mut gap = fixture_catalog();
        gap.runtime_adapters
            .get_mut("fixture-runtime")
            .unwrap()
            .target_support
            .as_mut()
            .unwrap()[0]
            .predicate = "cfg(false)".into();
        assert!(matches!(
            resolve(&gap, &profile(), &target()),
            Err(ResolutionError::TargetSupportMatchCount { owner, actual: 0 })
                if owner == "fixture-runtime"
        ));
    }

    #[test]
    fn resolved_target_support_projection_is_complete_and_semantically_verified() {
        let profile = profile();
        let target = target();
        let resolution = resolve(&fixture_catalog(), &profile, &target).unwrap();
        resolution
            .verify_target_support_projection(&profile, &target)
            .unwrap();
        assert_eq!(
            resolution
                .target_support
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            [
                "component:fixture-driver",
                "component:fixture-model",
                "runtime-adapter:fixture-runtime",
            ]
        );
        for support in resolution.target_support.values() {
            assert_eq!(support.entries.len(), 1);
            assert_eq!(support.matched_predicate, support.entries[0].predicate);
            assert_eq!(support.selected_tier, SupportTier::Production);
        }

        let mut missing_owner = resolution.clone();
        missing_owner
            .target_support
            .remove("component:fixture-driver");
        assert!(matches!(
            missing_owner.verify_target_support_projection(&profile, &target),
            Err(ResolutionError::InvalidTargetSupport { owner, .. }) if owner == "resolution"
        ));

        let mut forged_tier = resolution;
        let support = forged_tier
            .target_support
            .get_mut("component:fixture-driver")
            .unwrap();
        support.entries[0].tier = SupportTier::Experimental;
        support.selected_tier = SupportTier::Experimental;
        assert!(matches!(
            forged_tier.verify_target_support_projection(&profile, &target),
            Err(ResolutionError::UnsupportedTargetSupportTier { owner, .. })
                if owner == "component:fixture-driver"
        ));
    }

    #[test]
    fn resolution_checked_deserialization_rejects_bounds_duplicates_and_noncanonical_sets() {
        let resolution = resolve(&fixture_catalog(), &profile(), &target()).unwrap();

        let mut excessive_components = serde_json::to_value(&resolution).unwrap();
        excessive_components["selected-components"] = serde_json::Value::Array(
            (0..=MAX_RESOLUTION_SELECTED_COMPONENTS)
                .map(|index| serde_json::json!(format!("component-{index:04}")))
                .collect(),
        );
        assert!(serde_json::from_value::<Resolution>(excessive_components).is_err());

        let mut duplicate_binding = resolution.clone();
        duplicate_binding
            .bindings
            .push(duplicate_binding.bindings[0].clone());
        assert!(
            serde_json::from_value::<Resolution>(serde_json::to_value(duplicate_binding).unwrap())
                .is_err()
        );

        let mut duplicate_effect = serde_json::to_value(&resolution).unwrap();
        duplicate_effect["bindings"][0]["effects"] =
            serde_json::json!(["forged-effect", "forged-effect"]);
        let error = serde_json::from_value::<Resolution>(duplicate_effect).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("runtime effects contains a duplicate")
        );

        let mut duplicate_compiled_effect = serde_json::to_value(&resolution).unwrap();
        duplicate_compiled_effect["compiled-runtime-effects"] =
            serde_json::json!(["forged-effect", "forged-effect"]);
        let error = serde_json::from_value::<Resolution>(duplicate_compiled_effect).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("runtime effects contains a duplicate")
        );

        let resource_binding = ResolvedResourceNamespaceBinding {
            consumer: "fixture-driver".into(),
            provide_capability: "cap:model".into(),
            provide_key: None,
            bootstrap_provider: "fixture-model".into(),
            bootstrap_key: "fixture".into(),
            effects: BTreeSet::new(),
        };
        let mut duplicate_resource_effect = serde_json::to_value(resource_binding).unwrap();
        duplicate_resource_effect["effects"] =
            serde_json::json!(["forged-effect", "forged-effect"]);
        let error =
            serde_json::from_value::<ResolvedResourceNamespaceBinding>(duplicate_resource_effect)
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("runtime effects contains a duplicate")
        );

        let mut duplicate_build_requirement = serde_json::to_value(&resolution).unwrap();
        duplicate_build_requirement["build-requirements"]["executables"] =
            serde_json::json!(["tool", "tool"]);
        let error = serde_json::from_value::<Resolution>(duplicate_build_requirement).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("build requirements contains a duplicate")
        );

        let support = resolution.target_support.first_key_value().unwrap().1;
        let mut duplicate_entry = serde_json::to_value(support).unwrap();
        duplicate_entry["entries"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::to_value(&support.entries[0]).unwrap());
        assert!(serde_json::from_value::<ResolvedTargetSupport>(duplicate_entry).is_err());

        let mut excessive_entries = serde_json::to_value(support).unwrap();
        excessive_entries["entries"] = serde_json::Value::Array(
            (0..=MAX_TARGET_PREDICATE_PARTITIONS)
                .map(|index| {
                    serde_json::json!({
                        "predicate": format!("cfg(target_os = \"custom-{index:03}\")"),
                        "tier": "production",
                    })
                })
                .collect(),
        );
        assert!(serde_json::from_value::<ResolvedTargetSupport>(excessive_entries).is_err());

        let mut excessive_owners = serde_json::to_value(&resolution).unwrap();
        let support = serde_json::to_value(support).unwrap();
        excessive_owners["target-support"] = serde_json::Value::Object(
            (0..=MAX_RESOLUTION_TARGET_SUPPORT_OWNERS)
                .map(|index| (format!("component:owner-{index:03}"), support.clone()))
                .collect(),
        );
        assert!(serde_json::from_value::<Resolution>(excessive_owners).is_err());
    }

    #[test]
    fn resolution_semantics_reject_post_deserialization_order_and_duplicate_mutations() {
        let profile = profile();
        let target = target();
        let resolution = resolve(&fixture_catalog(), &profile, &target).unwrap();
        resolution
            .verify_canonical_semantics(&profile, &target)
            .unwrap();

        let mut unsorted_components = resolution.clone();
        unsorted_components.selected_components.swap(0, 1);
        assert!(matches!(
            unsorted_components.verify_canonical_semantics(&profile, &target),
            Err(ResolutionError::NonCanonicalResolutionCollection {
                field: "selected-components"
            })
        ));

        let mut duplicate_construction = resolution.clone();
        duplicate_construction
            .construction_order
            .push(duplicate_construction.construction_order[0].clone());
        assert!(matches!(
            duplicate_construction.verify_canonical_semantics(&profile, &target),
            Err(ResolutionError::NonCanonicalResolutionCollection {
                field: "construction-order"
            })
        ));

        let mut duplicate_binding = resolution.clone();
        duplicate_binding
            .bindings
            .push(duplicate_binding.bindings[0].clone());
        duplicate_binding
            .bindings
            .sort_by(compare_resolved_bindings);
        assert!(matches!(
            duplicate_binding.verify_canonical_semantics(&profile, &target),
            Err(ResolutionError::NonCanonicalResolutionCollection { field: "bindings" })
        ));

        let mut duplicate_resource_binding = resolution.clone();
        let resource_binding = ResolvedResourceNamespaceBinding {
            consumer: "fixture-driver".into(),
            provide_capability: "cap:model".into(),
            provide_key: None,
            bootstrap_provider: "fixture-model".into(),
            bootstrap_key: "fixture".into(),
            effects: BTreeSet::new(),
        };
        duplicate_resource_binding.resource_namespace_bindings =
            vec![resource_binding.clone(), resource_binding];
        assert!(matches!(
            duplicate_resource_binding.verify_canonical_semantics(&profile, &target),
            Err(ResolutionError::NonCanonicalResolutionCollection {
                field: "resource-namespace-bindings"
            })
        ));

        let mut duplicate_diagnostic = resolution.clone();
        duplicate_diagnostic
            .diagnostics
            .push(duplicate_diagnostic.diagnostics[0].clone());
        duplicate_diagnostic
            .diagnostics
            .sort_by(|left, right| left.component.cmp(&right.component));
        assert!(matches!(
            duplicate_diagnostic.verify_canonical_semantics(&profile, &target),
            Err(ResolutionError::NonCanonicalResolutionCollection {
                field: "diagnostics"
            })
        ));

        let mut duplicate_reason = resolution.clone();
        let reason = duplicate_reason.diagnostics[0].reasons[0].clone();
        duplicate_reason.diagnostics[0].reasons.push(reason);
        duplicate_reason.diagnostics[0].reasons.sort();
        assert!(matches!(
            duplicate_reason.verify_canonical_semantics(&profile, &target),
            Err(ResolutionError::InvalidResolutionDiagnostic { .. })
        ));

        let mut duplicate_target_support_entry = resolution;
        let support = duplicate_target_support_entry
            .target_support
            .first_entry()
            .unwrap()
            .into_mut();
        support.entries.push(support.entries[0].clone());
        support.entries.sort();
        assert!(matches!(
            duplicate_target_support_entry.verify_canonical_semantics(&profile, &target),
            Err(ResolutionError::InvalidTargetSupport { .. })
        ));
    }

    #[test]
    fn resolution_semantics_recheck_profile_constraints_without_catalog() {
        let target = target();
        let original_profile = profile();
        let resolution = resolve(&fixture_catalog(), &original_profile, &target).unwrap();

        let mut disabled_selected = original_profile.clone();
        disabled_selected
            .components
            .insert("fixture-model".into(), ComponentChoice::Disabled);
        assert!(matches!(
            resolution.verify_canonical_semantics(&disabled_selected, &target),
            Err(ResolutionError::InvalidProfileComponentSelection {
                component,
                choice: ComponentChoice::Disabled,
            }) if component == "fixture-model"
        ));

        let mut missing_enabled = original_profile.clone();
        missing_enabled
            .components
            .insert("fixture-fs-read".into(), ComponentChoice::Enabled);
        assert!(matches!(
            resolution.verify_canonical_semantics(&missing_enabled, &target),
            Err(ResolutionError::InvalidProfileComponentSelection {
                component,
                choice: ComponentChoice::Enabled,
            }) if component == "fixture-fs-read"
        ));

        let mut prefixed_override = original_profile.clone();
        prefixed_override
            .bindings
            .insert("cap:model".into(), "fixture-model".into());
        assert!(matches!(
            resolution.verify_canonical_semantics(&prefixed_override, &target),
            Err(ResolutionError::PrefixedBindingKey(capability)) if capability == "cap:model"
        ));

        let mut denied_effect = resolution.clone();
        denied_effect
            .compiled_runtime_effects
            .insert("read-local".into());
        assert!(matches!(
            denied_effect.verify_canonical_semantics(&original_profile, &target),
            Err(ResolutionError::DeniedRuntimeEffect(effect)) if effect == "read-local"
        ));

        let mut missing_bin_boundary = original_profile.clone();
        missing_bin_boundary.build_kind = BuildKind::Bin;
        assert!(matches!(
            resolution.verify_canonical_semantics(&missing_bin_boundary, &target),
            Err(ResolutionError::InvalidHostBoundary {
                build_kind: BuildKind::Bin,
                ..
            })
        ));

        let mut non_wasm_target_profile = original_profile;
        non_wasm_target_profile.build_kind = BuildKind::Wasm;
        non_wasm_target_profile.host_boundary = Some("synthetic-host".into());
        let mut non_wasm_target_resolution = resolution;
        non_wasm_target_resolution.host_boundary = Some("synthetic-host".into());
        let support = non_wasm_target_resolution
            .target_support
            .values()
            .next()
            .unwrap()
            .clone();
        non_wasm_target_resolution
            .target_support
            .insert("host-boundary:synthetic-host".into(), support);
        assert!(matches!(
            non_wasm_target_resolution
                .verify_canonical_semantics(&non_wasm_target_profile, &target),
            Err(ResolutionError::InvalidHostBoundary {
                build_kind: BuildKind::Wasm,
                message,
            }) if message.contains("target_arch=wasm32")
        ));
    }

    #[test]
    fn resolution_routes_require_selected_ordered_endpoints_and_bounded_unique_effects() {
        let profile = profile();
        let target = target();
        let resolution = resolve(&fixture_catalog(), &profile, &target).unwrap();

        let mut unnamespaced_capability = resolution.clone();
        unnamespaced_capability.bindings[0].capability = "model".into();
        assert!(matches!(
            unnamespaced_capability.verify_canonical_semantics(&profile, &target),
            Err(ResolutionError::InvalidResolutionRoute {
                kind: "binding",
                message: "capability must use the `cap:` namespace",
                ..
            })
        ));

        let mut conflicting_profile_binding = profile.clone();
        conflicting_profile_binding
            .bindings
            .insert("model".into(), "fixture-driver".into());
        assert!(matches!(
            resolution.verify_canonical_semantics(&conflicting_profile_binding, &target),
            Err(ResolutionError::InvalidResolutionRoute {
                kind: "binding",
                message: "provider differs from the explicit profile binding",
                ..
            })
        ));

        let mut unselected_provider = resolution.clone();
        unselected_provider.bindings[0].provider = "unselected-provider".into();
        assert!(matches!(
            unselected_provider.verify_canonical_semantics(&profile, &target),
            Err(ResolutionError::InvalidResolutionRoute {
                kind: "binding",
                message: "provider is not selected",
                ..
            })
        ));

        let mut unselected_consumer = resolution.clone();
        unselected_consumer.bindings[0].consumer = "unselected-consumer".into();
        assert!(matches!(
            unselected_consumer.verify_canonical_semantics(&profile, &target),
            Err(ResolutionError::InvalidResolutionRoute {
                kind: "binding",
                message: "consumer is not selected",
                ..
            })
        ));

        let mut reversed_construction = resolution.clone();
        reversed_construction.construction_order.reverse();
        assert!(matches!(
            reversed_construction.verify_canonical_semantics(&profile, &target),
            Err(ResolutionError::InvalidResolutionRoute {
                kind: "binding",
                message: "provider must precede consumer in construction-order",
                ..
            })
        ));

        let mut excessive_binding_effect = resolution.clone();
        excessive_binding_effect.bindings[0]
            .effects
            .insert("read-local".into());
        assert!(matches!(
            excessive_binding_effect.verify_canonical_semantics(&profile, &target),
            Err(ResolutionError::InvalidResolutionRoute {
                kind: "binding",
                message: "effects exceed compiled-runtime-effects",
                ..
            })
        ));

        let mut duplicate_binding_route = resolution.clone();
        let mut duplicate = duplicate_binding_route.bindings[0].clone();
        duplicate.effects.insert("read-local".into());
        duplicate_binding_route.bindings.push(duplicate);
        duplicate_binding_route
            .bindings
            .sort_by(compare_resolved_bindings);
        duplicate_binding_route
            .compiled_runtime_effects
            .insert("read-local".into());
        assert!(matches!(
            duplicate_binding_route.verify_canonical_semantics(&profile, &target),
            Err(ResolutionError::NonCanonicalResolutionCollection {
                field: "binding routes"
            })
        ));

        let resource_binding = ResolvedResourceNamespaceBinding {
            consumer: "fixture-driver".into(),
            provide_capability: "cap:model".into(),
            provide_key: None,
            bootstrap_provider: "fixture-model".into(),
            bootstrap_key: "fixture".into(),
            effects: BTreeSet::new(),
        };
        let mut resource_resolution = resolution.clone();
        resource_resolution.bindings.clear();
        resource_resolution.resource_namespace_bindings = vec![resource_binding.clone()];
        resource_resolution
            .verify_canonical_semantics(&profile, &target)
            .unwrap();

        let mut unnamespaced_resource_capability = resource_resolution.clone();
        unnamespaced_resource_capability.resource_namespace_bindings[0].provide_capability =
            "model".into();
        assert!(matches!(
            unnamespaced_resource_capability.verify_canonical_semantics(&profile, &target),
            Err(ResolutionError::InvalidResolutionRoute {
                kind: "resource-namespace binding",
                message: "provide capability must use the `cap:` namespace",
                ..
            })
        ));

        let mut conflicting_resource_profile_binding = profile.clone();
        conflicting_resource_profile_binding.bindings.insert(
            "resource-namespace-bootstrap".into(),
            "fixture-driver".into(),
        );
        assert!(matches!(
            resource_resolution
                .verify_canonical_semantics(&conflicting_resource_profile_binding, &target,),
            Err(ResolutionError::InvalidResolutionRoute {
                kind: "resource-namespace binding",
                message: "provider differs from the explicit profile binding",
                ..
            })
        ));

        let mut unselected_resource_provider = resource_resolution.clone();
        unselected_resource_provider.resource_namespace_bindings[0].bootstrap_provider =
            "unselected-provider".into();
        assert!(matches!(
            unselected_resource_provider.verify_canonical_semantics(&profile, &target),
            Err(ResolutionError::InvalidResolutionRoute {
                kind: "resource-namespace binding",
                message: "provider is not selected",
                ..
            })
        ));

        let mut excessive_resource_effect = resource_resolution.clone();
        excessive_resource_effect.resource_namespace_bindings[0]
            .effects
            .insert("read-local".into());
        assert!(matches!(
            excessive_resource_effect.verify_canonical_semantics(&profile, &target),
            Err(ResolutionError::InvalidResolutionRoute {
                kind: "resource-namespace binding",
                message: "effects exceed compiled-runtime-effects",
                ..
            })
        ));

        let mut duplicate_resource_route = resource_resolution;
        let mut duplicate = resource_binding;
        duplicate.effects.insert("read-local".into());
        duplicate_resource_route
            .resource_namespace_bindings
            .push(duplicate);
        duplicate_resource_route
            .resource_namespace_bindings
            .sort_by(compare_resource_namespace_bindings);
        duplicate_resource_route
            .compiled_runtime_effects
            .insert("read-local".into());
        assert!(matches!(
            duplicate_resource_route.verify_canonical_semantics(&profile, &target),
            Err(ResolutionError::NonCanonicalResolutionCollection {
                field: "resource-namespace-binding routes"
            })
        ));
    }

    #[test]
    fn resolution_target_support_analysis_budget_is_shared_across_owners() {
        let profile = profile();
        let target = target();
        let mut one_owner = resolve(&fixture_catalog(), &profile, &target).unwrap();
        let runtime_owner = format!("runtime-adapter:{}", one_owner.runtime_adapter);
        let support = one_owner.target_support[&runtime_owner].clone();
        one_owner.selected_components.clear();
        one_owner.construction_order.clear();
        one_owner.target_support = BTreeMap::from([(runtime_owner.clone(), support.clone())]);

        let succeeds_with = |resolution: &Resolution, work| {
            let mut budget = PredicateAnalysisBudget::with_work_limit_for_test(work);
            resolution
                .verify_target_support_projection_with_budget(&profile, &target, &mut budget)
                .is_ok()
        };
        let mut upper = 1_usize;
        while !succeeds_with(&one_owner, upper) {
            upper = upper.checked_mul(2).expect("test budget search is bounded");
        }
        let mut lower = 0_usize;
        while lower + 1 < upper {
            let middle = lower + (upper - lower) / 2;
            if succeeds_with(&one_owner, middle) {
                upper = middle;
            } else {
                lower = middle;
            }
        }
        let exact_one_owner_work = upper;
        assert!(succeeds_with(&one_owner, exact_one_owner_work));

        let mut two_owners = one_owner;
        two_owners.selected_components = vec!["synthetic".into()];
        two_owners
            .target_support
            .insert("component:synthetic".into(), support);
        let mut budget = PredicateAnalysisBudget::with_work_limit_for_test(exact_one_owner_work);
        assert!(matches!(
            two_owners.verify_target_support_projection_with_budget(
                &profile,
                &target,
                &mut budget,
            ),
            Err(ResolutionError::InvalidTargetSupportPredicate {
                owner,
                source: TargetError::PredicateAnalysisLimitExceeded {
                    resource: "analysis work",
                    maximum,
                },
            }) if owner == runtime_owner && maximum == exact_one_owner_work
        ));
    }

    #[test]
    fn resolution_deserialization_rejects_duplicate_target_support_owner_keys() {
        let resolution = resolve(&fixture_catalog(), &profile(), &target()).unwrap();
        let json = serde_json::to_string(&resolution).unwrap();
        assert_eq!(
            serde_json::from_str::<Resolution>(&json).unwrap(),
            resolution
        );

        let (owner, valid) = resolution.target_support.first_key_value().unwrap();
        let mut forged = valid.clone();
        forged.targets = "cfg(false)".into();
        let owner = serde_json::to_string(owner).unwrap();
        let valid = serde_json::to_string(valid).unwrap();
        let forged = serde_json::to_string(&forged).unwrap();
        let canonical_map = serde_json::to_string(&resolution.target_support).unwrap();
        let canonical_field = format!("\"target-support\":{canonical_map}");

        for (case, first, last) in [
            ("same-value", valid.as_str(), valid.as_str()),
            ("forged-first", forged.as_str(), valid.as_str()),
            ("forged-last", valid.as_str(), forged.as_str()),
        ] {
            let duplicate_field = format!("\"target-support\":{{{owner}:{first},{owner}:{last}}}");
            let duplicate = json.replacen(&canonical_field, &duplicate_field, 1);
            assert_ne!(duplicate, json, "{case} fixture did not inject a duplicate");
            let error = serde_json::from_str::<Resolution>(&duplicate).unwrap_err();
            assert!(
                error.to_string().contains("duplicate target-support owner"),
                "{case} was rejected for the wrong reason: {error}"
            );
        }
    }

    #[test]
    fn resolver_rejects_a_forged_target_before_selection() {
        let mut forged = target();
        forged.target_fact_digest = "0".repeat(64);
        assert!(matches!(
            resolve(&fixture_catalog(), &profile(), &forged),
            Err(ResolutionError::Target { owner, source: TargetError::TargetFactDigestMismatch })
                if owner == "resolver-input"
        ));
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
            Err(ResolutionError::UnsupportedHostBoundaryTarget { .. })
        ));

        profile.target = "wasm32-unknown-unknown".into();
        profile.environment = crate::target::Environment::Browser;
        let mut wasm_facts = canonical_builtin_facts(CoreTargetFacts::little_endian(
            "wasm32", "", "unknown", "32", "abort",
        ))
        .unwrap();
        wasm_facts.insert(
            "target_family".into(),
            BTreeSet::from([Some("wasm".into())]),
        );
        let wasm = Target::from_facts(
            "wasm32-unknown-unknown",
            crate::target::Environment::Browser,
            wasm_facts,
        )
        .unwrap();
        let resolved = resolve(&catalog, &profile, &wasm).unwrap();
        assert!(resolved.compiled_runtime_effects.contains("host-bridge"));

        let mut unsupported_catalog = catalog;
        unsupported_catalog
            .host_boundaries
            .get_mut("fixture-host-export")
            .unwrap()
            .target_support
            .as_mut()
            .expect("normalized Host boundary target support")
            .iter_mut()
            .for_each(|entry| entry.tier = crate::metadata::SupportTier::Experimental);
        assert!(matches!(
            resolve(&unsupported_catalog, &profile, &wasm),
            Err(ResolutionError::UnsupportedHostBoundarySupportTier {
                support: SupportTier::Experimental,
                ..
            })
        ));
    }

    #[test]
    fn native_host_entry_enforces_closed_targets_and_per_target_support_tiers() {
        let catalog = fixture_catalog();
        let mut profile = profile();
        profile.build_kind = BuildKind::Bin;
        profile.host_boundary = Some("fixture-host-entry".into());
        profile.denied_effects.remove("host-bridge");
        for (triple, environment, arch, target_env, os, production, experimental) in [
            (
                "x86_64-unknown-linux-gnu",
                crate::target::Environment::Desktop,
                "x86_64",
                "gnu",
                "linux",
                true,
                true,
            ),
            (
                "x86_64-apple-darwin",
                crate::target::Environment::Desktop,
                "x86_64",
                "",
                "macos",
                false,
                true,
            ),
            (
                "x86_64-pc-windows-msvc",
                crate::target::Environment::Desktop,
                "x86_64",
                "msvc",
                "windows",
                false,
                true,
            ),
            (
                "aarch64-linux-android",
                crate::target::Environment::Mobile,
                "aarch64",
                "",
                "android",
                false,
                false,
            ),
            (
                "aarch64-apple-ios",
                crate::target::Environment::Mobile,
                "aarch64",
                "",
                "ios",
                false,
                false,
            ),
            (
                "x86_64-unknown-freebsd",
                crate::target::Environment::Desktop,
                "x86_64",
                "",
                "freebsd",
                false,
                false,
            ),
        ] {
            profile.target = triple.into();
            profile.environment = environment;
            let target = Target::from_facts(
                triple,
                environment,
                canonical_builtin_facts(CoreTargetFacts::little_endian(
                    arch, target_env, os, "64", "unwind",
                ))
                .unwrap(),
            )
            .unwrap();
            profile.support_tier = SupportTier::Production;
            let production_result = resolve(&catalog, &profile, &target);
            assert_eq!(production_result.is_ok(), production, "production {triple}");
            if matches!(os, "android" | "ios" | "freebsd") {
                assert!(matches!(
                    production_result,
                    Err(ResolutionError::UnsupportedHostBoundaryTarget { .. })
                ));
            } else if matches!(os, "macos" | "windows") {
                assert!(matches!(
                    production_result,
                    Err(ResolutionError::UnsupportedHostBoundarySupportTier {
                        support: SupportTier::Experimental,
                        ..
                    })
                ));
            }

            profile.support_tier = SupportTier::Experimental;
            assert_eq!(
                resolve(&catalog, &profile, &target).is_ok(),
                experimental,
                "experimental {triple}"
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
            profile.components.insert(
                "fixture-model-shared".into(),
                ComponentChoice::Disabled,
            );
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
