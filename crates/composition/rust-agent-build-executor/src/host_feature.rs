use std::collections::{BTreeMap, BTreeSet};

use rust_agent_composition::{canonical, metadata::BuildRequirements};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cargo_unit_graph::{
    CargoCompilationKind, CargoCrateKind, CargoDependencyKind, CargoTargetEvaluationDomain,
    CargoUnit, CargoUnitEdge, CargoUnitGraphError, CargoUnitSelector, NormalizedCargoUnit,
    NormalizedHostCargoUnitGraph, validate_selector_identity,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FeatureAccountingMode {
    CompositionConservative,
    HostOnlyAdditiveApi,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureSemanticsEvidence {
    pub schema: u32,
    pub feature: String,
    #[serde(rename = "source-digest")]
    pub source_digest: String,
    #[serde(rename = "reviewer-policy")]
    pub reviewer_policy: String,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostFeaturePolicyEntry {
    pub unit: CargoUnitSelector,
    #[serde(rename = "baseline-features")]
    pub baseline_features: BTreeSet<String>,
    #[serde(rename = "additive-features")]
    pub additive_features: BTreeSet<String>,
    #[serde(rename = "allowed-added-units")]
    pub allowed_added_units: Vec<CargoUnit>,
    #[serde(rename = "allowed-added-edges")]
    pub allowed_added_edges: Vec<CargoUnitEdge>,
    pub accounting: FeatureAccountingMode,
    #[serde(rename = "composition-effects")]
    pub composition_effects: BTreeSet<String>,
    #[serde(rename = "product-host-effects")]
    pub product_host_effects: BTreeSet<String>,
    #[serde(rename = "build-requirements")]
    pub build_requirements: BuildRequirements,
    #[serde(rename = "audit-ref")]
    pub audit_ref: String,
    #[serde(default)]
    pub evidence: Vec<FeatureSemanticsEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostFeatureUnionPolicy {
    pub schema: u32,
    pub entries: Vec<HostFeaturePolicyEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedHostFeaturePolicy {
    entries: BTreeMap<CargoUnitSelector, HostFeaturePolicyEntry>,
    digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostFeatureUnitObservation {
    #[serde(rename = "feature-requesters")]
    pub feature_requesters: BTreeSet<CargoUnitSelector>,
    #[serde(rename = "added-units")]
    pub added_units: Vec<CargoUnit>,
    #[serde(rename = "added-edges")]
    pub added_edges: Vec<CargoUnitEdge>,
    #[serde(rename = "runtime-effects")]
    pub runtime_effects: BTreeSet<String>,
    #[serde(rename = "build-requirements")]
    pub build_requirements: BuildRequirements,
    #[serde(rename = "has-generated-output")]
    pub has_generated_output: bool,
    #[serde(rename = "has-native-link-output")]
    pub has_native_link_output: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductBuildContribution {
    pub unit: CargoUnitSelector,
    #[serde(rename = "build-requirements")]
    pub build_requirements: BuildRequirements,
    #[serde(rename = "downstream-runtime-effects")]
    pub downstream_runtime_effects: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostFeaturePolicyStageDigests {
    pub pre: Option<String>,
    #[serde(rename = "build-host")]
    pub build_host: Option<String>,
    pub post: Option<String>,
}

impl HostFeaturePolicyStageDigests {
    pub fn for_policy(policy: Option<&NormalizedHostFeaturePolicy>) -> Self {
        let digest = policy.map(|value| value.digest().to_owned());
        Self {
            pre: digest.clone(),
            build_host: digest.clone(),
            post: digest,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DevelopmentHostFeatureVerification<'a> {
    pub standalone_graph: &'a NormalizedHostCargoUnitGraph,
    pub final_graph: &'a NormalizedHostCargoUnitGraph,
    pub observed_graph: &'a NormalizedHostCargoUnitGraph,
    pub first_party_units: &'a BTreeSet<CargoUnitSelector>,
    pub policy: Option<&'a NormalizedHostFeaturePolicy>,
    pub stage_policy_digests: &'a HostFeaturePolicyStageDigests,
    pub observations: &'a BTreeMap<CargoUnitSelector, HostFeatureUnitObservation>,
    pub composition_compiled_runtime_effects: &'a BTreeSet<String>,
    pub host_root_runtime_effects: &'a BTreeSet<String>,
    pub product_build_contributions: &'a [ProductBuildContribution],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureDelta {
    #[serde(rename = "added-features")]
    pub added_features: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostFeatureDeltaRecord {
    pub unit: CargoUnitSelector,
    #[serde(rename = "baseline-features")]
    pub baseline_features: BTreeSet<String>,
    #[serde(rename = "actual-features")]
    pub actual_features: BTreeSet<String>,
    #[serde(rename = "added-features")]
    pub added_features: BTreeSet<String>,
    #[serde(rename = "added-units")]
    pub added_units: Vec<CargoUnit>,
    #[serde(rename = "added-edges")]
    pub added_edges: Vec<CargoUnitEdge>,
    #[serde(rename = "feature-requesters")]
    pub feature_requesters: BTreeSet<CargoUnitSelector>,
    pub accounting: FeatureAccountingMode,
    #[serde(rename = "composition-effects")]
    pub composition_effects: BTreeSet<String>,
    #[serde(rename = "product-host-effects")]
    pub product_host_effects: BTreeSet<String>,
    #[serde(rename = "build-requirements")]
    pub build_requirements: BuildRequirements,
    #[serde(rename = "audit-ref")]
    pub audit_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentHostFeatureReceipt {
    pub schema: u32,
    pub deployable: bool,
    #[serde(rename = "standalone-unit-graph-digest")]
    pub standalone_unit_graph_digest: String,
    #[serde(rename = "final-unit-graph-digest")]
    pub final_unit_graph_digest: String,
    #[serde(rename = "observed-unit-graph-digest")]
    pub observed_unit_graph_digest: String,
    #[serde(rename = "policy-digest")]
    pub policy_digest: Option<String>,
    #[serde(rename = "stage-policy-digests")]
    pub stage_policy_digests: HostFeaturePolicyStageDigests,
    pub deltas: Vec<HostFeatureDeltaRecord>,
    #[serde(rename = "composition-compiled-runtime-effects")]
    pub composition_compiled_runtime_effects: BTreeSet<String>,
    #[serde(rename = "host-root-runtime-effects")]
    pub host_root_runtime_effects: BTreeSet<String>,
    #[serde(rename = "product-build-contributions")]
    pub product_build_contributions: Vec<ProductBuildContribution>,
    #[serde(rename = "product-compiled-runtime-effects")]
    pub product_compiled_runtime_effects: BTreeSet<String>,
    pub digest: String,
}

#[derive(Debug, Error)]
pub enum HostFeaturePolicyError {
    #[error("unsupported HostFeatureUnionPolicy schema {0}; expected 1")]
    UnsupportedSchema(u32),
    #[error("HostFeatureUnionPolicy must not be empty; use explicit none when there is no delta")]
    EmptyPolicy,
    #[error("duplicate Host feature unit selector: {0:?}")]
    DuplicateUnit(Box<CargoUnitSelector>),
    #[error("Host unit feature deltas are unsupported: {0:?}")]
    HostBuildUnitDeltaUnsupported(Box<CargoUnitSelector>),
    #[error("feature delta is allowed only for external target library units: {0:?}")]
    UnitKindUnsupported(Box<CargoUnitSelector>),
    #[error("first-party generated composition units require exact features: {0:?}")]
    FirstPartyFeatureDelta(Box<CargoUnitSelector>),
    #[error("feature policy entry has an empty or overlapping additive set: {0:?}")]
    InvalidAdditiveSet(Box<CargoUnitSelector>),
    #[error("invalid feature/evidence identifier `{0}`")]
    InvalidIdentifier(String),
    #[error("invalid or empty audit reference `{0}`")]
    InvalidAuditReference(String),
    #[error("feature policy contains an invalid exact Cargo unit selector: {0:?}")]
    InvalidUnitSelector(Box<CargoUnitSelector>),
    #[error("invalid canonical digest in feature evidence for `{0}`")]
    InvalidDigest(String),
    #[error("host-only-additive-api requires exact evidence for every feature: {0:?}")]
    MissingEvidence(Box<CargoUnitSelector>),
    #[error("host-only-additive-api feature provenance includes the composition projection: {0:?}")]
    CompositionFeatureRequester(Box<CargoUnitSelector>),
    #[error("feature delta can affect generated or native link output: {0:?}")]
    GeneratedOutputDelta(Box<CargoUnitSelector>),
    #[error("no policy entry for Cargo unit: {0:?}")]
    MissingUnit(Box<CargoUnitSelector>),
    #[error("actual unit removed baseline features: {0:?}")]
    RemovedFeature(Box<CargoUnitSelector>),
    #[error("actual unit added unapproved features {features:?}: {unit:?}")]
    UnapprovedFeature {
        unit: Box<CargoUnitSelector>,
        features: BTreeSet<String>,
    },
    #[error("actual feature set does not equal the policy's exact additive set: {0:?}")]
    FeatureClosureMismatch(Box<CargoUnitSelector>),
    #[error("declared feature effect/build-requirement closure does not match observation: {0:?}")]
    ClosureMismatch(Box<CargoUnitSelector>),
    #[error("declared added unit closure does not match the observed final graph")]
    AddedUnitClosureMismatch,
    #[error("declared added edge closure does not match the observed final graph")]
    AddedEdgeClosureMismatch,
    #[error("multiple policy entries claim the same added unit or edge")]
    OverlappingClosure,
    #[error("policy entry has no corresponding non-empty feature delta: {0:?}")]
    UnusedPolicyEntry(Box<CargoUnitSelector>),
    #[error("a feature delta exists but HostFeatureUnionPolicy is none")]
    MissingPolicy,
    #[error("HostFeatureUnionPolicy was provided but no feature delta exists")]
    UnexpectedPolicy,
    #[error("pre/build-host/post HostFeatureUnionPolicy digests differ")]
    PolicyStageDigestMismatch,
    #[error("standalone and final graphs use different planner/target/profile contexts")]
    GraphContextMismatch,
    #[error("final graph removed a baseline unit: {0:?}")]
    MissingBaselineUnit(Box<CargoUnitSelector>),
    #[error("final graph removed a baseline dependency edge")]
    RemovedBaselineEdge,
    #[error("feature observation is missing for unit: {0:?}")]
    MissingObservation(Box<CargoUnitSelector>),
    #[error("feature observation exists for a unit without a delta: {0:?}")]
    UnexpectedObservation(Box<CargoUnitSelector>),
    #[error("composition feature effects are not contained by compiled composition effects: {0:?}")]
    CompositionEffectCeiling(Box<CargoUnitSelector>),
    #[error("product feature/build contribution is not contained by the Host-root ceiling: {0:?}")]
    HostRootEffectCeiling(Box<CargoUnitSelector>),
    #[error(
        "product build contribution does not identify a build-host custom-build/proc-macro unit: {0:?}"
    )]
    InvalidProductBuildContribution(Box<CargoUnitSelector>),
    #[error("planned and observed Host Cargo unit graphs differ: {0}")]
    UnitGraph(#[from] CargoUnitGraphError),
    #[error("canonical Host feature encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
}

impl HostFeatureUnionPolicy {
    pub fn normalize(&self) -> Result<NormalizedHostFeaturePolicy, HostFeaturePolicyError> {
        if self.schema != 1 {
            return Err(HostFeaturePolicyError::UnsupportedSchema(self.schema));
        }
        if self.entries.is_empty() {
            return Err(HostFeaturePolicyError::EmptyPolicy);
        }
        let mut entries = BTreeMap::new();
        for raw_entry in &self.entries {
            let entry = normalize_entry(raw_entry)?;
            if entries.insert(entry.unit.clone(), entry.clone()).is_some() {
                return Err(HostFeaturePolicyError::DuplicateUnit(Box::new(entry.unit)));
            }
        }
        let canonical_entries: Vec<_> = entries.values().cloned().collect();
        let digest = hex::encode(canonical::domain_hash(
            b"rust-agent-host-feature-policy-v1\0",
            &(1_u32, &canonical_entries),
        )?);
        Ok(NormalizedHostFeaturePolicy { entries, digest })
    }
}

impl NormalizedHostFeaturePolicy {
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn entries(&self) -> &BTreeMap<CargoUnitSelector, HostFeaturePolicyEntry> {
        &self.entries
    }

    pub fn authorize_delta(
        &self,
        unit: &CargoUnitSelector,
        actual_features: &BTreeSet<String>,
        observation: &HostFeatureUnitObservation,
    ) -> Result<FeatureDelta, HostFeaturePolicyError> {
        let entry = self
            .entries
            .get(unit)
            .ok_or_else(|| HostFeaturePolicyError::MissingUnit(Box::new(unit.clone())))?;
        authorize_entry(entry, actual_features, observation)
    }
}

pub fn verify_development_host_feature_union(
    verification: &DevelopmentHostFeatureVerification<'_>,
) -> Result<DevelopmentHostFeatureReceipt, HostFeaturePolicyError> {
    verification
        .final_graph
        .verify_observation(verification.observed_graph)?;
    verify_graph_context(verification.standalone_graph, verification.final_graph)?;
    let expected_policy_digest = verification.policy.map(NormalizedHostFeaturePolicy::digest);
    verify_stage_policy_digests(verification.stage_policy_digests, expected_policy_digest)?;

    let baseline_nodes = verification.standalone_graph.nodes();
    let final_nodes = verification.final_graph.nodes();
    let projection_units: BTreeSet<_> = baseline_nodes.keys().cloned().collect();
    let mut changed_units = BTreeSet::new();
    for (selector, baseline) in baseline_nodes {
        let actual = final_nodes.get(selector).ok_or_else(|| {
            HostFeaturePolicyError::MissingBaselineUnit(Box::new(selector.clone()))
        })?;
        if baseline.build_script != actual.build_script || baseline.proc_macro != actual.proc_macro
        {
            return Err(HostFeaturePolicyError::GeneratedOutputDelta(Box::new(
                selector.clone(),
            )));
        }
        if !baseline.features.is_subset(&actual.features) {
            return Err(HostFeaturePolicyError::RemovedFeature(Box::new(
                selector.clone(),
            )));
        }
        if baseline.features != actual.features {
            if verification.first_party_units.contains(selector) {
                return Err(HostFeaturePolicyError::FirstPartyFeatureDelta(Box::new(
                    selector.clone(),
                )));
            }
            validate_delta_unit(selector)?;
            changed_units.insert(selector.clone());
        }
    }
    if !verification
        .standalone_graph
        .edges()
        .is_subset(verification.final_graph.edges())
    {
        return Err(HostFeaturePolicyError::RemovedBaselineEdge);
    }

    if changed_units.is_empty() {
        if verification.policy.is_some() {
            return Err(HostFeaturePolicyError::UnexpectedPolicy);
        }
        if let Some(unit) = verification.observations.keys().next() {
            return Err(HostFeaturePolicyError::UnexpectedObservation(Box::new(
                unit.clone(),
            )));
        }
    } else if verification.policy.is_none() {
        return Err(HostFeaturePolicyError::MissingPolicy);
    }

    let policy_entries = verification
        .policy
        .map(NormalizedHostFeaturePolicy::entries)
        .cloned()
        .unwrap_or_default();
    for selector in policy_entries.keys() {
        if !changed_units.contains(selector) {
            return Err(HostFeaturePolicyError::UnusedPolicyEntry(Box::new(
                selector.clone(),
            )));
        }
    }
    for selector in verification.observations.keys() {
        if !changed_units.contains(selector) {
            return Err(HostFeaturePolicyError::UnexpectedObservation(Box::new(
                selector.clone(),
            )));
        }
    }

    let actual_added_units: BTreeMap<_, _> = final_nodes
        .iter()
        .filter(|(selector, _)| !baseline_nodes.contains_key(*selector))
        .map(|(selector, unit)| (selector.clone(), denormalize_unit(unit)))
        .collect();
    if let Some(unit) = actual_added_units
        .keys()
        .find(|unit| verification.first_party_units.contains(*unit))
    {
        return Err(HostFeaturePolicyError::FirstPartyFeatureDelta(Box::new(
            unit.clone(),
        )));
    }
    for unit in actual_added_units.values() {
        validate_added_unit(unit)?;
    }
    let actual_added_edges: BTreeSet<_> = verification
        .final_graph
        .edges()
        .difference(verification.standalone_graph.edges())
        .cloned()
        .collect();

    let mut observed_added_units = BTreeMap::new();
    let mut observed_added_edges = BTreeSet::new();
    let mut policy_added_units = BTreeMap::new();
    let mut policy_added_edges = BTreeSet::new();
    let mut delta_records = Vec::new();
    for selector in &changed_units {
        let observation = verification.observations.get(selector).ok_or_else(|| {
            HostFeaturePolicyError::MissingObservation(Box::new(selector.clone()))
        })?;
        let entry = policy_entries
            .get(selector)
            .ok_or_else(|| HostFeaturePolicyError::MissingUnit(Box::new(selector.clone())))?;
        for requester in &observation.feature_requesters {
            validate_selector_identity(requester).map_err(|_| {
                HostFeaturePolicyError::InvalidUnitSelector(Box::new(requester.clone()))
            })?;
        }
        let actual = &final_nodes
            .get(selector)
            .expect("changed unit came from final graph")
            .features;
        let delta = authorize_entry(entry, actual, observation)?;
        if entry.accounting == FeatureAccountingMode::HostOnlyAdditiveApi
            && (observation.feature_requesters.is_empty()
                || !observation
                    .feature_requesters
                    .is_disjoint(&projection_units))
        {
            return Err(HostFeaturePolicyError::CompositionFeatureRequester(
                Box::new(selector.clone()),
            ));
        }
        if !entry
            .composition_effects
            .is_subset(verification.composition_compiled_runtime_effects)
        {
            return Err(HostFeaturePolicyError::CompositionEffectCeiling(Box::new(
                selector.clone(),
            )));
        }
        if !entry
            .product_host_effects
            .is_subset(verification.host_root_runtime_effects)
        {
            return Err(HostFeaturePolicyError::HostRootEffectCeiling(Box::new(
                selector.clone(),
            )));
        }
        insert_unit_closure(&mut observed_added_units, &observation.added_units)?;
        insert_edge_closure(&mut observed_added_edges, &observation.added_edges)?;
        insert_unit_closure(&mut policy_added_units, &entry.allowed_added_units)?;
        insert_edge_closure(&mut policy_added_edges, &entry.allowed_added_edges)?;
        delta_records.push(HostFeatureDeltaRecord {
            unit: selector.clone(),
            baseline_features: entry.baseline_features.clone(),
            actual_features: actual.clone(),
            added_features: delta.added_features,
            added_units: observation.added_units.clone(),
            added_edges: observation.added_edges.clone(),
            feature_requesters: observation.feature_requesters.clone(),
            accounting: entry.accounting,
            composition_effects: entry.composition_effects.clone(),
            product_host_effects: entry.product_host_effects.clone(),
            build_requirements: entry.build_requirements.clone(),
            audit_ref: entry.audit_ref.clone(),
        });
    }
    if actual_added_units != observed_added_units || actual_added_units != policy_added_units {
        return Err(HostFeaturePolicyError::AddedUnitClosureMismatch);
    }
    if actual_added_edges != observed_added_edges || actual_added_edges != policy_added_edges {
        return Err(HostFeaturePolicyError::AddedEdgeClosureMismatch);
    }

    let mut product_build_contributions = verification.product_build_contributions.to_vec();
    product_build_contributions.sort_by(|left, right| left.unit.cmp(&right.unit));
    if product_build_contributions
        .windows(2)
        .any(|pair| pair[0].unit == pair[1].unit)
    {
        return Err(HostFeaturePolicyError::OverlappingClosure);
    }
    for contribution in &product_build_contributions {
        validate_selector_identity(&contribution.unit).map_err(|_| {
            HostFeaturePolicyError::InvalidUnitSelector(Box::new(contribution.unit.clone()))
        })?;
        if contribution.unit.compilation_kind != CargoCompilationKind::BuildHost
            || !matches!(
                contribution.unit.crate_kind,
                CargoCrateKind::CustomBuild | CargoCrateKind::ProcMacro
            )
        {
            return Err(HostFeaturePolicyError::InvalidProductBuildContribution(
                Box::new(contribution.unit.clone()),
            ));
        }
        for requirement in contribution
            .build_requirements
            .executables
            .iter()
            .chain(&contribution.build_requirements.read_inputs)
            .chain(&contribution.build_requirements.environment)
        {
            validate_identifier(requirement)?;
        }
        for effect in &contribution.downstream_runtime_effects {
            validate_identifier(effect)?;
        }
        if !contribution
            .downstream_runtime_effects
            .is_subset(verification.host_root_runtime_effects)
        {
            return Err(HostFeaturePolicyError::HostRootEffectCeiling(Box::new(
                contribution.unit.clone(),
            )));
        }
    }

    let mut product_compiled_runtime_effects =
        verification.composition_compiled_runtime_effects.clone();
    product_compiled_runtime_effects.extend(verification.host_root_runtime_effects.iter().cloned());
    for entry in policy_entries.values() {
        product_compiled_runtime_effects.extend(entry.product_host_effects.iter().cloned());
    }
    for contribution in &product_build_contributions {
        product_compiled_runtime_effects
            .extend(contribution.downstream_runtime_effects.iter().cloned());
    }

    let policy_digest = verification.policy.map(|policy| policy.digest().to_owned());
    let stage_policy_digests = verification.stage_policy_digests.clone();
    let standalone_unit_graph_digest = verification.standalone_graph.digest().to_owned();
    let final_unit_graph_digest = verification.final_graph.digest().to_owned();
    let observed_unit_graph_digest = verification.observed_graph.digest().to_owned();
    let composition_compiled_runtime_effects =
        verification.composition_compiled_runtime_effects.clone();
    let host_root_runtime_effects = verification.host_root_runtime_effects.clone();
    let digest = hex::encode(canonical::domain_hash(
        b"rust-agent-development-host-feature-receipt-v1\0",
        &(
            1_u32,
            false,
            &standalone_unit_graph_digest,
            &final_unit_graph_digest,
            &observed_unit_graph_digest,
            &policy_digest,
            &stage_policy_digests,
            &delta_records,
            &composition_compiled_runtime_effects,
            &host_root_runtime_effects,
            &product_build_contributions,
            &product_compiled_runtime_effects,
        ),
    )?);
    Ok(DevelopmentHostFeatureReceipt {
        schema: 1,
        deployable: false,
        standalone_unit_graph_digest,
        final_unit_graph_digest,
        observed_unit_graph_digest,
        policy_digest,
        stage_policy_digests,
        deltas: delta_records,
        composition_compiled_runtime_effects,
        host_root_runtime_effects,
        product_build_contributions,
        product_compiled_runtime_effects,
        digest,
    })
}

fn normalize_entry(
    raw_entry: &HostFeaturePolicyEntry,
) -> Result<HostFeaturePolicyEntry, HostFeaturePolicyError> {
    let mut entry = raw_entry.clone();
    validate_selector_identity(&entry.unit)
        .map_err(|_| HostFeaturePolicyError::InvalidUnitSelector(Box::new(entry.unit.clone())))?;
    validate_delta_unit(&entry.unit)?;
    if entry.additive_features.is_empty()
        || !entry
            .baseline_features
            .is_disjoint(&entry.additive_features)
    {
        return Err(HostFeaturePolicyError::InvalidAdditiveSet(Box::new(
            entry.unit.clone(),
        )));
    }
    for value in entry
        .baseline_features
        .iter()
        .chain(&entry.additive_features)
    {
        validate_feature(value)?;
    }
    for effect in entry
        .composition_effects
        .iter()
        .chain(&entry.product_host_effects)
    {
        validate_identifier(effect)?;
    }
    for requirement in entry
        .build_requirements
        .executables
        .iter()
        .chain(&entry.build_requirements.read_inputs)
        .chain(&entry.build_requirements.environment)
    {
        validate_identifier(requirement)?;
    }
    validate_audit_reference(&entry.audit_ref)?;

    entry
        .allowed_added_units
        .sort_by(|left, right| left.selector.cmp(&right.selector));
    if entry
        .allowed_added_units
        .windows(2)
        .any(|pair| pair[0].selector == pair[1].selector)
    {
        return Err(HostFeaturePolicyError::OverlappingClosure);
    }
    for unit in &entry.allowed_added_units {
        validate_added_unit(unit)?;
    }
    entry.allowed_added_edges.sort();
    if entry
        .allowed_added_edges
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(HostFeaturePolicyError::OverlappingClosure);
    }
    for edge in &entry.allowed_added_edges {
        validate_policy_edge(edge)?;
    }

    entry
        .evidence
        .sort_by(|left, right| (&left.feature, &left.digest).cmp(&(&right.feature, &right.digest)));
    if entry
        .evidence
        .windows(2)
        .any(|pair| pair[0].feature == pair[1].feature)
    {
        return Err(HostFeaturePolicyError::MissingEvidence(Box::new(
            entry.unit.clone(),
        )));
    }
    let evidence_features: BTreeSet<_> = entry
        .evidence
        .iter()
        .map(|item| item.feature.clone())
        .collect();
    if entry.accounting == FeatureAccountingMode::HostOnlyAdditiveApi
        && (evidence_features != entry.additive_features || !entry.composition_effects.is_empty())
    {
        return Err(HostFeaturePolicyError::MissingEvidence(Box::new(
            entry.unit.clone(),
        )));
    }
    for evidence in &entry.evidence {
        if evidence.schema != 1 || !entry.additive_features.contains(&evidence.feature) {
            return Err(HostFeaturePolicyError::MissingEvidence(Box::new(
                entry.unit.clone(),
            )));
        }
        validate_feature(&evidence.feature)?;
        validate_identifier(&evidence.reviewer_policy)?;
        validate_digest(&evidence.feature, &evidence.source_digest)?;
        validate_digest(&evidence.feature, &evidence.digest)?;
    }
    Ok(entry)
}

fn authorize_entry(
    entry: &HostFeaturePolicyEntry,
    actual_features: &BTreeSet<String>,
    observation: &HostFeatureUnitObservation,
) -> Result<FeatureDelta, HostFeaturePolicyError> {
    if !entry.baseline_features.is_subset(actual_features) {
        return Err(HostFeaturePolicyError::RemovedFeature(Box::new(
            entry.unit.clone(),
        )));
    }
    let added_features: BTreeSet<_> = actual_features
        .difference(&entry.baseline_features)
        .cloned()
        .collect();
    let unapproved: BTreeSet<_> = added_features
        .difference(&entry.additive_features)
        .cloned()
        .collect();
    if !unapproved.is_empty() {
        return Err(HostFeaturePolicyError::UnapprovedFeature {
            unit: Box::new(entry.unit.clone()),
            features: unapproved,
        });
    }
    if added_features != entry.additive_features {
        return Err(HostFeaturePolicyError::FeatureClosureMismatch(Box::new(
            entry.unit.clone(),
        )));
    }
    if observation.has_generated_output || observation.has_native_link_output {
        return Err(HostFeaturePolicyError::GeneratedOutputDelta(Box::new(
            entry.unit.clone(),
        )));
    }
    let mut expected_runtime_effects = entry.composition_effects.clone();
    expected_runtime_effects.extend(entry.product_host_effects.iter().cloned());
    if observation.runtime_effects != expected_runtime_effects
        || observation.build_requirements != entry.build_requirements
        || observation.added_units != entry.allowed_added_units
        || observation.added_edges != entry.allowed_added_edges
    {
        return Err(HostFeaturePolicyError::ClosureMismatch(Box::new(
            entry.unit.clone(),
        )));
    }
    Ok(FeatureDelta { added_features })
}

fn verify_graph_context(
    standalone: &NormalizedHostCargoUnitGraph,
    final_graph: &NormalizedHostCargoUnitGraph,
) -> Result<(), HostFeaturePolicyError> {
    if standalone.planner() == final_graph.planner()
        && standalone.build_triple() == final_graph.build_triple()
        && standalone.composition_target() == final_graph.composition_target()
        && standalone.profile() == final_graph.profile()
    {
        Ok(())
    } else {
        Err(HostFeaturePolicyError::GraphContextMismatch)
    }
}

fn verify_stage_policy_digests(
    stages: &HostFeaturePolicyStageDigests,
    expected: Option<&str>,
) -> Result<(), HostFeaturePolicyError> {
    let expected = expected.map(str::to_owned);
    if stages.pre == expected && stages.build_host == expected && stages.post == expected {
        Ok(())
    } else {
        Err(HostFeaturePolicyError::PolicyStageDigestMismatch)
    }
}

fn validate_delta_unit(unit: &CargoUnitSelector) -> Result<(), HostFeaturePolicyError> {
    if unit.compilation_kind == CargoCompilationKind::BuildHost {
        return Err(HostFeaturePolicyError::HostBuildUnitDeltaUnsupported(
            Box::new(unit.clone()),
        ));
    }
    if unit.crate_kind != CargoCrateKind::Library {
        return Err(HostFeaturePolicyError::UnitKindUnsupported(Box::new(
            unit.clone(),
        )));
    }
    Ok(())
}

fn validate_added_unit(unit: &CargoUnit) -> Result<(), HostFeaturePolicyError> {
    validate_selector_identity(&unit.selector).map_err(|_| {
        HostFeaturePolicyError::InvalidUnitSelector(Box::new(unit.selector.clone()))
    })?;
    validate_delta_unit(&unit.selector)?;
    if unit.build_script
        || unit.proc_macro
        || unit.features.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(HostFeaturePolicyError::GeneratedOutputDelta(Box::new(
            unit.selector.clone(),
        )));
    }
    for feature in &unit.features {
        validate_feature(feature)?;
    }
    Ok(())
}

fn validate_policy_edge(edge: &CargoUnitEdge) -> Result<(), HostFeaturePolicyError> {
    validate_selector_identity(&edge.dependent).map_err(|_| {
        HostFeaturePolicyError::InvalidUnitSelector(Box::new(edge.dependent.clone()))
    })?;
    validate_selector_identity(&edge.dependency).map_err(|_| {
        HostFeaturePolicyError::InvalidUnitSelector(Box::new(edge.dependency.clone()))
    })?;
    if edge.dependency.compilation_kind == CargoCompilationKind::BuildHost
        || edge.dependency_kind == CargoDependencyKind::Build
        || edge.target_evaluation_domain != CargoTargetEvaluationDomain::Target
    {
        return Err(HostFeaturePolicyError::HostBuildUnitDeltaUnsupported(
            Box::new(edge.dependency.clone()),
        ));
    }
    Ok(())
}

fn denormalize_unit(unit: &NormalizedCargoUnit) -> CargoUnit {
    CargoUnit {
        selector: unit.selector.clone(),
        features: unit.features.iter().cloned().collect(),
        build_script: unit.build_script,
        proc_macro: unit.proc_macro,
    }
}

fn insert_unit_closure(
    closure: &mut BTreeMap<CargoUnitSelector, CargoUnit>,
    units: &[CargoUnit],
) -> Result<(), HostFeaturePolicyError> {
    for unit in units {
        if closure
            .insert(unit.selector.clone(), unit.clone())
            .is_some()
        {
            return Err(HostFeaturePolicyError::OverlappingClosure);
        }
    }
    Ok(())
}

fn insert_edge_closure(
    closure: &mut BTreeSet<CargoUnitEdge>,
    edges: &[CargoUnitEdge],
) -> Result<(), HostFeaturePolicyError> {
    for edge in edges {
        if !closure.insert(edge.clone()) {
            return Err(HostFeaturePolicyError::OverlappingClosure);
        }
    }
    Ok(())
}

fn validate_feature(value: &str) -> Result<(), HostFeaturePolicyError> {
    if !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Ok(())
    } else {
        Err(HostFeaturePolicyError::InvalidIdentifier(value.to_owned()))
    }
}

fn validate_identifier(value: &str) -> Result<(), HostFeaturePolicyError> {
    if !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(HostFeaturePolicyError::InvalidIdentifier(value.to_owned()))
    }
}

fn validate_audit_reference(value: &str) -> Result<(), HostFeaturePolicyError> {
    if !value.is_empty()
        && value.len() <= 512
        && !value.contains('*')
        && !value.chars().any(char::is_whitespace)
    {
        Ok(())
    } else {
        Err(HostFeaturePolicyError::InvalidAuditReference(
            value.to_owned(),
        ))
    }
}

fn validate_digest(owner: &str, value: &str) -> Result<(), HostFeaturePolicyError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(HostFeaturePolicyError::InvalidDigest(owner.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cargo_unit_graph::{
        CargoCompileMode, CargoPackageIdentity, CargoPackageSource, CargoUnitGraphPlannerIdentity,
        HostCargoUnitGraph,
    };

    fn selector() -> CargoUnitSelector {
        CargoUnitSelector {
            package: CargoPackageIdentity {
                name: "external-helper".into(),
                version: "1.0.0".into(),
                source: CargoPackageSource::Registry {
                    registry: "https://github.com/rust-lang/crates.io-index".into(),
                    checksum: "aa".repeat(32),
                },
            },
            target_name: "external_helper".into(),
            compilation_kind: CargoCompilationKind::Target,
            compilation_target: "x86_64-unknown-linux-gnu".into(),
            compile_mode: CargoCompileMode::Build,
            profile: "dev".into(),
            crate_kind: CargoCrateKind::Library,
        }
    }

    fn product_selector() -> CargoUnitSelector {
        let mut value = selector();
        value.package.name = "product-host".into();
        value.package.source = CargoPackageSource::Path {
            tree_digest: "bb".repeat(32),
        };
        value.target_name = "product_host".into();
        value
    }

    fn build_selector() -> CargoUnitSelector {
        let mut value = product_selector();
        value.compilation_kind = CargoCompilationKind::BuildHost;
        value.crate_kind = CargoCrateKind::CustomBuild;
        value.compile_mode = crate::CargoCompileMode::RunCustomBuild;
        value
    }

    fn entry() -> HostFeaturePolicyEntry {
        HostFeaturePolicyEntry {
            unit: selector(),
            baseline_features: ["std".into()].into_iter().collect(),
            additive_features: ["api-extra".into()].into_iter().collect(),
            allowed_added_units: vec![],
            allowed_added_edges: vec![],
            accounting: FeatureAccountingMode::HostOnlyAdditiveApi,
            composition_effects: BTreeSet::new(),
            product_host_effects: ["host-bridge".into()].into_iter().collect(),
            build_requirements: BuildRequirements::default(),
            audit_ref: "fixture-review".into(),
            evidence: vec![FeatureSemanticsEvidence {
                schema: 1,
                feature: "api-extra".into(),
                source_digest: "00".repeat(32),
                reviewer_policy: "trusted-review".into(),
                digest: "11".repeat(32),
            }],
        }
    }

    fn observation() -> HostFeatureUnitObservation {
        HostFeatureUnitObservation {
            feature_requesters: [product_selector()].into_iter().collect(),
            added_units: vec![],
            added_edges: vec![],
            runtime_effects: ["host-bridge".into()].into_iter().collect(),
            build_requirements: BuildRequirements::default(),
            has_generated_output: false,
            has_native_link_output: false,
        }
    }

    fn graph(features: &[&str]) -> NormalizedHostCargoUnitGraph {
        HostCargoUnitGraph {
            schema: 1,
            planner: CargoUnitGraphPlannerIdentity {
                interface: "cargo-unit-graph-v1".into(),
                cargo_version: "1.97.1".into(),
                cargo_digest: "22".repeat(32),
                rustc_version: "1.97.1".into(),
                rustc_digest: "33".repeat(32),
            },
            build_triple: "x86_64-unknown-linux-gnu".into(),
            composition_target: "x86_64-unknown-linux-gnu".into(),
            profile: "dev".into(),
            nodes: vec![CargoUnit {
                selector: selector(),
                features: features.iter().map(|value| (*value).to_owned()).collect(),
                build_script: false,
                proc_macro: false,
            }],
            edges: vec![],
        }
        .normalize()
        .unwrap()
    }

    fn graph_with_unapproved_added_unit(features: &[&str]) -> NormalizedHostCargoUnitGraph {
        let mut added_selector = selector();
        added_selector.package.name = "feature-activated-helper".into();
        added_selector.target_name = "feature_activated_helper".into();
        HostCargoUnitGraph {
            schema: 1,
            planner: CargoUnitGraphPlannerIdentity {
                interface: "cargo-unit-graph-v1".into(),
                cargo_version: "1.97.1".into(),
                cargo_digest: "22".repeat(32),
                rustc_version: "1.97.1".into(),
                rustc_digest: "33".repeat(32),
            },
            build_triple: "x86_64-unknown-linux-gnu".into(),
            composition_target: "x86_64-unknown-linux-gnu".into(),
            profile: "dev".into(),
            nodes: vec![
                CargoUnit {
                    selector: selector(),
                    features: features.iter().map(|value| (*value).to_owned()).collect(),
                    build_script: false,
                    proc_macro: false,
                },
                CargoUnit {
                    selector: added_selector,
                    features: vec![],
                    build_script: false,
                    proc_macro: false,
                },
            ],
            edges: vec![],
        }
        .normalize()
        .unwrap()
    }

    #[test]
    fn exact_external_target_library_delta_is_authorized_and_accounted() {
        let policy = HostFeatureUnionPolicy {
            schema: 1,
            entries: vec![entry()],
        }
        .normalize()
        .unwrap();
        let baseline = graph(&["std"]);
        let final_graph = graph(&["api-extra", "std"]);
        let observations = [(selector(), observation())].into_iter().collect();
        let stages = HostFeaturePolicyStageDigests::for_policy(Some(&policy));
        let host_effects = ["host-bridge".into(), "product-generated".into()]
            .into_iter()
            .collect();
        let contribution = ProductBuildContribution {
            unit: build_selector(),
            build_requirements: BuildRequirements::default(),
            downstream_runtime_effects: ["product-generated".into()].into_iter().collect(),
        };
        let receipt = verify_development_host_feature_union(&DevelopmentHostFeatureVerification {
            standalone_graph: &baseline,
            final_graph: &final_graph,
            observed_graph: &final_graph,
            first_party_units: &BTreeSet::new(),
            policy: Some(&policy),
            stage_policy_digests: &stages,
            observations: &observations,
            composition_compiled_runtime_effects: &BTreeSet::new(),
            host_root_runtime_effects: &host_effects,
            product_build_contributions: &[contribution],
        })
        .unwrap();
        assert!(!receipt.deployable);
        assert_eq!(receipt.policy_digest.as_deref(), Some(policy.digest()));
        assert_eq!(
            receipt.final_unit_graph_digest,
            receipt.observed_unit_graph_digest
        );
        assert_eq!(
            receipt.deltas[0].added_features,
            ["api-extra".into()].into_iter().collect()
        );
        assert_eq!(receipt.product_compiled_runtime_effects, host_effects);
    }

    #[test]
    fn exact_policy_rejects_host_first_party_unknown_and_underfilled_deltas() {
        let mut invalid = entry();
        invalid.unit.compilation_kind = CargoCompilationKind::BuildHost;
        assert!(matches!(
            (HostFeatureUnionPolicy {
                schema: 1,
                entries: vec![invalid]
            })
            .normalize(),
            Err(HostFeaturePolicyError::HostBuildUnitDeltaUnsupported(_))
        ));
        let policy = HostFeatureUnionPolicy {
            schema: 1,
            entries: vec![entry()],
        }
        .normalize()
        .unwrap();
        let unknown = ["api-extra".into(), "std".into(), "unknown".into()]
            .into_iter()
            .collect();
        assert!(matches!(
            policy.authorize_delta(&selector(), &unknown, &observation()),
            Err(HostFeaturePolicyError::UnapprovedFeature { .. })
        ));
        let underfilled = ["std".into()].into_iter().collect();
        assert!(matches!(
            policy.authorize_delta(&selector(), &underfilled, &observation()),
            Err(HostFeaturePolicyError::FeatureClosureMismatch(_))
        ));

        let baseline = graph(&["std"]);
        let final_graph = graph(&["api-extra", "std"]);
        let observations = [(selector(), observation())].into_iter().collect();
        let stages = HostFeaturePolicyStageDigests::for_policy(Some(&policy));
        let first_party = [selector()].into_iter().collect();
        let host_effects = ["host-bridge".into()].into_iter().collect();
        let result = verify_development_host_feature_union(&DevelopmentHostFeatureVerification {
            standalone_graph: &baseline,
            final_graph: &final_graph,
            observed_graph: &final_graph,
            first_party_units: &first_party,
            policy: Some(&policy),
            stage_policy_digests: &stages,
            observations: &observations,
            composition_compiled_runtime_effects: &BTreeSet::new(),
            host_root_runtime_effects: &host_effects,
            product_build_contributions: &[],
        });
        assert!(matches!(
            result,
            Err(HostFeaturePolicyError::FirstPartyFeatureDelta(_))
        ));

        let mut composition_requested = observation();
        composition_requested.feature_requesters = [selector()].into_iter().collect();
        let composition_observations = [(selector(), composition_requested)].into_iter().collect();
        let result = verify_development_host_feature_union(&DevelopmentHostFeatureVerification {
            standalone_graph: &baseline,
            final_graph: &final_graph,
            observed_graph: &final_graph,
            first_party_units: &BTreeSet::new(),
            policy: Some(&policy),
            stage_policy_digests: &stages,
            observations: &composition_observations,
            composition_compiled_runtime_effects: &BTreeSet::new(),
            host_root_runtime_effects: &host_effects,
            product_build_contributions: &[],
        });
        assert!(matches!(
            result,
            Err(HostFeaturePolicyError::CompositionFeatureRequester(_))
        ));
    }

    #[test]
    fn observation_stage_digest_and_effect_ceiling_fail_closed() {
        let policy = HostFeatureUnionPolicy {
            schema: 1,
            entries: vec![entry()],
        }
        .normalize()
        .unwrap();
        let baseline = graph(&["std"]);
        let final_graph = graph(&["api-extra", "std"]);
        let stages = HostFeaturePolicyStageDigests::for_policy(Some(&policy));
        let mut wrong_stage = stages.clone();
        wrong_stage.post = Some("ff".repeat(32));
        let observations = [(selector(), observation())].into_iter().collect();
        let host_effects = ["host-bridge".into()].into_iter().collect();
        let verify = |stage_digests: &HostFeaturePolicyStageDigests,
                      observed: &NormalizedHostCargoUnitGraph,
                      host_effects: &BTreeSet<String>| {
            verify_development_host_feature_union(&DevelopmentHostFeatureVerification {
                standalone_graph: &baseline,
                final_graph: &final_graph,
                observed_graph: observed,
                first_party_units: &BTreeSet::new(),
                policy: Some(&policy),
                stage_policy_digests: stage_digests,
                observations: &observations,
                composition_compiled_runtime_effects: &BTreeSet::new(),
                host_root_runtime_effects: host_effects,
                product_build_contributions: &[],
            })
        };
        assert!(matches!(
            verify(&wrong_stage, &final_graph, &host_effects),
            Err(HostFeaturePolicyError::PolicyStageDigestMismatch)
        ));
        assert!(matches!(
            verify(&stages, &baseline, &host_effects),
            Err(HostFeaturePolicyError::UnitGraph(_))
        ));
        assert!(matches!(
            verify(&stages, &final_graph, &BTreeSet::new()),
            Err(HostFeaturePolicyError::HostRootEffectCeiling(_))
        ));

        let mut generated = observation();
        generated.has_generated_output = true;
        assert!(matches!(
            policy.authorize_delta(
                &selector(),
                &["api-extra".into(), "std".into()].into_iter().collect(),
                &generated
            ),
            Err(HostFeaturePolicyError::GeneratedOutputDelta(_))
        ));

        let final_with_added_unit = graph_with_unapproved_added_unit(&["api-extra", "std"]);
        assert!(matches!(
            verify(&stages, &final_with_added_unit, &host_effects),
            Err(HostFeaturePolicyError::UnitGraph(_))
        ));
        let added_unit_observed = final_with_added_unit.clone();
        let result = verify_development_host_feature_union(&DevelopmentHostFeatureVerification {
            standalone_graph: &baseline,
            final_graph: &final_with_added_unit,
            observed_graph: &added_unit_observed,
            first_party_units: &BTreeSet::new(),
            policy: Some(&policy),
            stage_policy_digests: &stages,
            observations: &observations,
            composition_compiled_runtime_effects: &BTreeSet::new(),
            host_root_runtime_effects: &host_effects,
            product_build_contributions: &[],
        });
        assert!(matches!(
            result,
            Err(HostFeaturePolicyError::AddedUnitClosureMismatch)
        ));
    }

    #[test]
    fn explicit_none_is_valid_only_without_a_delta() {
        let baseline = graph(&["std"]);
        let stages = HostFeaturePolicyStageDigests::for_policy(None);
        let receipt = verify_development_host_feature_union(&DevelopmentHostFeatureVerification {
            standalone_graph: &baseline,
            final_graph: &baseline,
            observed_graph: &baseline,
            first_party_units: &BTreeSet::new(),
            policy: None,
            stage_policy_digests: &stages,
            observations: &BTreeMap::new(),
            composition_compiled_runtime_effects: &BTreeSet::new(),
            host_root_runtime_effects: &BTreeSet::new(),
            product_build_contributions: &[],
        })
        .unwrap();
        assert!(receipt.policy_digest.is_none());
        assert!(receipt.deltas.is_empty());

        let final_graph = graph(&["api-extra", "std"]);
        assert!(matches!(
            verify_development_host_feature_union(&DevelopmentHostFeatureVerification {
                standalone_graph: &baseline,
                final_graph: &final_graph,
                observed_graph: &final_graph,
                first_party_units: &BTreeSet::new(),
                policy: None,
                stage_policy_digests: &stages,
                observations: &BTreeMap::new(),
                composition_compiled_runtime_effects: &BTreeSet::new(),
                host_root_runtime_effects: &BTreeSet::new(),
                product_build_contributions: &[],
            }),
            Err(HostFeaturePolicyError::MissingPolicy)
        ));
    }

    #[test]
    fn normalization_is_deterministic_and_empty_policy_is_forbidden() {
        let mut second = entry();
        second.unit.package.name = "another".into();
        let first = HostFeatureUnionPolicy {
            schema: 1,
            entries: vec![entry(), second.clone()],
        }
        .normalize()
        .unwrap();
        let reversed = HostFeatureUnionPolicy {
            schema: 1,
            entries: vec![second, entry()],
        }
        .normalize()
        .unwrap();
        assert_eq!(first.digest(), reversed.digest());
        assert!(matches!(
            (HostFeatureUnionPolicy {
                schema: 1,
                entries: vec![]
            })
            .normalize(),
            Err(HostFeaturePolicyError::EmptyPolicy)
        ));
    }
}
