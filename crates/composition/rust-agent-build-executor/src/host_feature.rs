use std::collections::{BTreeMap, BTreeSet};

use rust_agent_composition::{canonical, metadata::BuildRequirements};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cargo_unit_graph::{
    CargoCompilationKind, CargoCrateKind, CargoUnitSelector, validate_selector_identity,
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
    #[serde(rename = "first-party")]
    pub first_party: bool,
    #[serde(rename = "baseline-features")]
    pub baseline_features: BTreeSet<String>,
    #[serde(rename = "additive-features")]
    pub additive_features: BTreeSet<String>,
    pub accounting: FeatureAccountingMode,
    #[serde(rename = "runtime-effects")]
    pub runtime_effects: BTreeSet<String>,
    #[serde(rename = "build-requirements")]
    pub build_requirements: BuildRequirements,
    #[serde(default)]
    pub evidence: Vec<FeatureSemanticsEvidence>,
    #[serde(rename = "has-generated-output")]
    pub has_generated_output: bool,
    #[serde(rename = "has-native-link-output")]
    pub has_native_link_output: bool,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureDelta {
    pub added_features: BTreeSet<String>,
}

#[derive(Debug, Error)]
pub enum HostFeaturePolicyError {
    #[error("unsupported HostFeatureUnionPolicy schema {0}; expected 1")]
    UnsupportedSchema(u32),
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
    #[error("feature policy contains an invalid exact Cargo unit selector: {0:?}")]
    InvalidUnitSelector(Box<CargoUnitSelector>),
    #[error("invalid canonical digest in feature evidence for `{0}`")]
    InvalidDigest(String),
    #[error("host-only-additive-api requires exact evidence for every feature: {0:?}")]
    MissingEvidence(Box<CargoUnitSelector>),
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
    #[error("actual unit added dependency edges; schema v1 only permits feature additions: {0:?}")]
    AddedDependencyEdge(Box<CargoUnitSelector>),
    #[error("declared feature effect/build-requirement closure does not match observation: {0:?}")]
    ClosureMismatch(Box<CargoUnitSelector>),
    #[error("canonical Host feature policy encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
}

impl HostFeatureUnionPolicy {
    pub fn normalize(&self) -> Result<NormalizedHostFeaturePolicy, HostFeaturePolicyError> {
        if self.schema != 1 {
            return Err(HostFeaturePolicyError::UnsupportedSchema(self.schema));
        }
        let mut entries = BTreeMap::new();
        for entry in &self.entries {
            validate_entry(entry)?;
            if entries.insert(entry.unit.clone(), entry.clone()).is_some() {
                return Err(HostFeaturePolicyError::DuplicateUnit(Box::new(
                    entry.unit.clone(),
                )));
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

    #[allow(clippy::too_many_arguments)]
    pub fn authorize_delta(
        &self,
        unit: &CargoUnitSelector,
        actual_features: &BTreeSet<String>,
        added_dependency_edges: usize,
        observed_runtime_effects: &BTreeSet<String>,
        observed_build_requirements: &BuildRequirements,
    ) -> Result<FeatureDelta, HostFeaturePolicyError> {
        let entry = self
            .entries
            .get(unit)
            .ok_or_else(|| HostFeaturePolicyError::MissingUnit(Box::new(unit.clone())))?;
        if !entry.baseline_features.is_subset(actual_features) {
            return Err(HostFeaturePolicyError::RemovedFeature(Box::new(
                unit.clone(),
            )));
        }
        if added_dependency_edges != 0 {
            return Err(HostFeaturePolicyError::AddedDependencyEdge(Box::new(
                unit.clone(),
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
                unit: Box::new(unit.clone()),
                features: unapproved,
            });
        }
        if observed_runtime_effects != &entry.runtime_effects
            || observed_build_requirements != &entry.build_requirements
        {
            return Err(HostFeaturePolicyError::ClosureMismatch(Box::new(
                unit.clone(),
            )));
        }
        Ok(FeatureDelta { added_features })
    }
}

fn validate_entry(entry: &HostFeaturePolicyEntry) -> Result<(), HostFeaturePolicyError> {
    validate_selector_identity(&entry.unit)
        .map_err(|_| HostFeaturePolicyError::InvalidUnitSelector(Box::new(entry.unit.clone())))?;
    if entry.unit.compilation_kind == CargoCompilationKind::BuildHost {
        return Err(HostFeaturePolicyError::HostBuildUnitDeltaUnsupported(
            Box::new(entry.unit.clone()),
        ));
    }
    if entry.unit.crate_kind != CargoCrateKind::Library {
        return Err(HostFeaturePolicyError::UnitKindUnsupported(Box::new(
            entry.unit.clone(),
        )));
    }
    if entry.first_party {
        return Err(HostFeaturePolicyError::FirstPartyFeatureDelta(Box::new(
            entry.unit.clone(),
        )));
    }
    if entry.has_generated_output || entry.has_native_link_output {
        return Err(HostFeaturePolicyError::GeneratedOutputDelta(Box::new(
            entry.unit.clone(),
        )));
    }
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
        validate_identifier(value)?;
    }
    if entry.accounting == FeatureAccountingMode::HostOnlyAdditiveApi {
        let evidence_features: BTreeSet<_> = entry
            .evidence
            .iter()
            .map(|item| item.feature.clone())
            .collect();
        if evidence_features != entry.additive_features || !entry.runtime_effects.is_empty() {
            return Err(HostFeaturePolicyError::MissingEvidence(Box::new(
                entry.unit.clone(),
            )));
        }
    }
    for evidence in &entry.evidence {
        if evidence.schema != 1 {
            return Err(HostFeaturePolicyError::MissingEvidence(Box::new(
                entry.unit.clone(),
            )));
        }
        validate_identifier(&evidence.feature)?;
        validate_identifier(&evidence.reviewer_policy)?;
        validate_digest(&evidence.feature, &evidence.source_digest)?;
        validate_digest(&evidence.feature, &evidence.digest)?;
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), HostFeaturePolicyError> {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(HostFeaturePolicyError::InvalidIdentifier(value.to_owned()))
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
    use crate::cargo_unit_graph::{CargoCompileMode, CargoPackageIdentity, CargoPackageSource};

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
            profile: "release".into(),
            crate_kind: CargoCrateKind::Library,
        }
    }

    fn entry() -> HostFeaturePolicyEntry {
        HostFeaturePolicyEntry {
            unit: selector(),
            first_party: false,
            baseline_features: ["std".into()].into_iter().collect(),
            additive_features: ["api-extra".into()].into_iter().collect(),
            accounting: FeatureAccountingMode::HostOnlyAdditiveApi,
            runtime_effects: BTreeSet::new(),
            build_requirements: BuildRequirements::default(),
            evidence: vec![FeatureSemanticsEvidence {
                schema: 1,
                feature: "api-extra".into(),
                source_digest: "00".repeat(32),
                reviewer_policy: "trusted-review".into(),
                digest: "11".repeat(32),
            }],
            has_generated_output: false,
            has_native_link_output: false,
        }
    }

    #[test]
    fn exact_external_target_library_delta_is_authorized() {
        let normalized = HostFeatureUnionPolicy {
            schema: 1,
            entries: vec![entry()],
        }
        .normalize()
        .unwrap();
        let actual = ["std".into(), "api-extra".into()].into_iter().collect();
        let delta = normalized
            .authorize_delta(
                &selector(),
                &actual,
                0,
                &BTreeSet::new(),
                &BuildRequirements::default(),
            )
            .unwrap();
        assert_eq!(
            delta.added_features,
            ["api-extra".into()].into_iter().collect()
        );
    }

    #[test]
    fn host_first_party_generated_and_unknown_deltas_fail_closed() {
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
        let mut invalid = entry();
        invalid.first_party = true;
        assert!(matches!(
            (HostFeatureUnionPolicy {
                schema: 1,
                entries: vec![invalid]
            })
            .normalize(),
            Err(HostFeaturePolicyError::FirstPartyFeatureDelta(_))
        ));
        let normalized = HostFeatureUnionPolicy {
            schema: 1,
            entries: vec![entry()],
        }
        .normalize()
        .unwrap();
        let actual = ["std".into(), "unknown".into()].into_iter().collect();
        assert!(matches!(
            normalized.authorize_delta(
                &selector(),
                &actual,
                0,
                &BTreeSet::new(),
                &BuildRequirements::default()
            ),
            Err(HostFeaturePolicyError::UnapprovedFeature { .. })
        ));
    }

    #[test]
    fn normalization_is_deterministic() {
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
    }
}
