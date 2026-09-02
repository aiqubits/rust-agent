use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    canonical::{self, CanonicalError},
    catalog::NormalizedCatalog,
    metadata::{
        AppCoexistence, CatalogReviewerPolicy, CatalogTrustPolicy, EvidenceRef, MAX_CATALOG_OWNERS,
        ScopeKind,
    },
};

pub const CATALOG_TRUST_INPUT_SCHEMA: u32 = 1;
pub const MAX_COEXISTENCE_EVIDENCE_BYTES: usize = 64 * 1024;
pub const MAX_TOTAL_COEXISTENCE_EVIDENCE_BYTES: usize = 1024 * 1024;

const MAX_RULE_SETS_PER_POLICY: usize = 16;
const MAX_EVIDENCE_TEST_REFERENCES: usize = 64;
const MAX_EVIDENCE_TEST_REFERENCE_BYTES: usize = 256;
const POLICY_IDENTITY_DOMAIN: &[u8] = b"rust-agent-catalog-trust-policy-v1\0";
const TRUST_INPUT_IDENTITY_DOMAIN: &[u8] = b"rust-agent-catalog-trust-input-v1\0";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceOwnerKind {
    Component,
    RuntimeAdapter,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct CatalogEvidenceOwner {
    pub(crate) kind: EvidenceOwnerKind,
    pub(crate) id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoexistenceEvidenceMode {
    ConcurrentIndependent,
    ConcurrentSharedHostHandle,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoexistenceEvidenceDocument {
    pub schema: u32,
    pub owner: String,
    pub mode: CoexistenceEvidenceMode,
    #[serde(rename = "rule-set")]
    pub rule_set: String,
    pub claims: BTreeSet<String>,
    pub tests: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct CatalogEvidenceRequest {
    pub(crate) owner: CatalogEvidenceOwner,
    pub(crate) package: String,
    pub(crate) package_path: String,
    pub(crate) mode: CoexistenceEvidenceMode,
    pub(crate) evidence: EvidenceRef,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogEvidenceRecord {
    #[serde(rename = "owner-kind")]
    pub owner_kind: EvidenceOwnerKind,
    pub owner: String,
    pub package: String,
    #[serde(rename = "package-path")]
    pub package_path: String,
    pub source: String,
    pub algorithm: String,
    pub digest: String,
    #[serde(rename = "reviewer-policy")]
    pub reviewer_policy: String,
    pub document: CoexistenceEvidenceDocument,
    #[serde(rename = "bytes-hex")]
    pub bytes_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogTrustInputCommitment {
    pub schema: u32,
    #[serde(rename = "normalized-policy")]
    pub normalized_policy: CatalogTrustPolicy,
    #[serde(rename = "normalized-policy-digest")]
    pub normalized_policy_digest: String,
    pub evidence: Vec<CatalogEvidenceRecord>,
    #[serde(rename = "identity-digest")]
    pub identity_digest: String,
}

#[derive(Serialize)]
struct CatalogTrustIdentityPayload<'a> {
    schema: u32,
    #[serde(rename = "normalized-policy")]
    normalized_policy: &'a CatalogTrustPolicy,
    #[serde(rename = "normalized-policy-digest")]
    normalized_policy_digest: &'a str,
    evidence: &'a [CatalogEvidenceRecord],
}

#[derive(Debug, Error)]
pub enum CatalogTrustError {
    #[error("catalog trust policy is invalid: {0}")]
    InvalidPolicy(String),
    #[error("catalog coexistence evidence is invalid: {0}")]
    InvalidEvidence(String),
    #[error("catalog coexistence evidence is missing for {0}")]
    MissingEvidence(String),
    #[error("catalog coexistence evidence is unexpected for {0}")]
    UnexpectedEvidence(String),
    #[error("catalog trust canonical encoding failed: {0}")]
    Canonical(#[from] CanonicalError),
}

impl CatalogTrustInputCommitment {
    pub(crate) fn new(
        catalog: &NormalizedCatalog,
        policy: &CatalogTrustPolicy,
        mut evidence_bytes: BTreeMap<CatalogEvidenceOwner, Vec<u8>>,
    ) -> Result<Self, CatalogTrustError> {
        validate_policy(policy)?;
        let requests = evidence_requests(catalog);
        let referenced_policies = requests
            .iter()
            .map(|request| request.evidence.reviewer_policy.clone())
            .collect::<BTreeSet<_>>();
        let normalized_policy = normalize_policy(policy, &referenced_policies)?;
        let normalized_policy_digest = policy_digest(&normalized_policy)?;
        let mut evidence = Vec::with_capacity(requests.len());
        for request in requests {
            let bytes = evidence_bytes
                .remove(&request.owner)
                .ok_or_else(|| CatalogTrustError::MissingEvidence(owner_label(&request.owner)))?;
            evidence.push(record_from_bytes(&request, &normalized_policy, bytes)?);
        }
        if let Some((owner, _)) = evidence_bytes.into_iter().next() {
            return Err(CatalogTrustError::UnexpectedEvidence(owner_label(&owner)));
        }
        evidence.sort_by(|left, right| {
            (&left.owner_kind, &left.owner).cmp(&(&right.owner_kind, &right.owner))
        });
        let mut commitment = Self {
            schema: CATALOG_TRUST_INPUT_SCHEMA,
            normalized_policy,
            normalized_policy_digest,
            evidence,
            identity_digest: String::new(),
        };
        commitment.identity_digest = commitment.recompute_identity_digest()?;
        commitment.validate(catalog)?;
        Ok(commitment)
    }

    pub fn validate(&self, catalog: &NormalizedCatalog) -> Result<(), CatalogTrustError> {
        if self.schema != CATALOG_TRUST_INPUT_SCHEMA {
            return Err(CatalogTrustError::InvalidPolicy(format!(
                "unsupported catalog trust-input schema {}; expected {CATALOG_TRUST_INPUT_SCHEMA}",
                self.schema
            )));
        }
        validate_policy(&self.normalized_policy)?;
        let requests = evidence_requests(catalog);
        let referenced_policies = requests
            .iter()
            .map(|request| request.evidence.reviewer_policy.clone())
            .collect::<BTreeSet<_>>();
        let normalized_again = normalize_policy(&self.normalized_policy, &referenced_policies)?;
        if normalized_again != self.normalized_policy {
            return Err(CatalogTrustError::InvalidPolicy(
                "normalized policy contains entries not referenced by the catalog".into(),
            ));
        }
        let expected_policy_digest = policy_digest(&self.normalized_policy)?;
        if self.normalized_policy_digest != expected_policy_digest {
            return Err(CatalogTrustError::InvalidPolicy(
                "normalized policy digest does not match its canonical content".into(),
            ));
        }
        if self.evidence.len() != requests.len()
            || !self.evidence.windows(2).all(|pair| {
                (&pair[0].owner_kind, &pair[0].owner) < (&pair[1].owner_kind, &pair[1].owner)
            })
        {
            return Err(CatalogTrustError::InvalidEvidence(
                "evidence records are missing, duplicated, or not in canonical owner order".into(),
            ));
        }
        let mut aggregate_bytes = 0_usize;
        for (record, request) in self.evidence.iter().zip(&requests) {
            validate_record(record, request, &self.normalized_policy)?;
            let bytes = record_bytes(record)?;
            aggregate_bytes = aggregate_bytes.checked_add(bytes.len()).ok_or_else(|| {
                CatalogTrustError::InvalidEvidence(
                    "aggregate evidence byte count overflowed".into(),
                )
            })?;
            if aggregate_bytes > MAX_TOTAL_COEXISTENCE_EVIDENCE_BYTES {
                return Err(CatalogTrustError::InvalidEvidence(format!(
                    "aggregate evidence exceeds {MAX_TOTAL_COEXISTENCE_EVIDENCE_BYTES} bytes"
                )));
            }
        }
        let expected_identity = self.recompute_identity_digest()?;
        if self.identity_digest != expected_identity {
            return Err(CatalogTrustError::InvalidPolicy(
                "catalog trust-input digest does not match its canonical content".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn evidence_bytes(
        &self,
        kind: EvidenceOwnerKind,
        owner: &str,
    ) -> Result<Option<Vec<u8>>, CatalogTrustError> {
        self.evidence
            .iter()
            .find(|record| record.owner_kind == kind && record.owner == owner)
            .map(record_bytes)
            .transpose()
    }

    fn recompute_identity_digest(&self) -> Result<String, CatalogTrustError> {
        Ok(hex::encode(canonical::domain_hash(
            TRUST_INPUT_IDENTITY_DOMAIN,
            &CatalogTrustIdentityPayload {
                schema: self.schema,
                normalized_policy: &self.normalized_policy,
                normalized_policy_digest: &self.normalized_policy_digest,
                evidence: &self.evidence,
            },
        )?))
    }
}

pub(crate) fn evidence_requests(catalog: &NormalizedCatalog) -> Vec<CatalogEvidenceRequest> {
    let mut requests = Vec::new();
    for component in catalog.components.values() {
        if component.scope != ScopeKind::App {
            continue;
        }
        if let Some(coexistence) = &component.app_coexistence
            && let Some((mode, evidence)) = coexistence_evidence(coexistence)
        {
            requests.push(CatalogEvidenceRequest {
                owner: CatalogEvidenceOwner {
                    kind: EvidenceOwnerKind::Component,
                    id: component.id.clone(),
                },
                package: component.package.clone(),
                package_path: component.package_path.clone(),
                mode,
                evidence: evidence.clone(),
            });
        }
    }
    for adapter in catalog.runtime_adapters.values() {
        if let Some((mode, evidence)) = coexistence_evidence(&adapter.app_coexistence) {
            requests.push(CatalogEvidenceRequest {
                owner: CatalogEvidenceOwner {
                    kind: EvidenceOwnerKind::RuntimeAdapter,
                    id: adapter.id.clone(),
                },
                package: adapter.package.clone(),
                package_path: adapter.package_path.clone(),
                mode,
                evidence: evidence.clone(),
            });
        }
    }
    requests.sort_by(|left, right| left.owner.cmp(&right.owner));
    requests
}

fn coexistence_evidence(value: &AppCoexistence) -> Option<(CoexistenceEvidenceMode, &EvidenceRef)> {
    match value {
        AppCoexistence::ConcurrentIndependent { evidence } => {
            Some((CoexistenceEvidenceMode::ConcurrentIndependent, evidence))
        }
        AppCoexistence::ConcurrentSharedHostHandle { evidence, .. } => Some((
            CoexistenceEvidenceMode::ConcurrentSharedHostHandle,
            evidence,
        )),
        AppCoexistence::RequiresStop => None,
    }
}

fn validate_policy(policy: &CatalogTrustPolicy) -> Result<(), CatalogTrustError> {
    if policy.schema != CATALOG_TRUST_INPUT_SCHEMA {
        return Err(CatalogTrustError::InvalidPolicy(format!(
            "unsupported policy schema {}; expected {CATALOG_TRUST_INPUT_SCHEMA}",
            policy.schema
        )));
    }
    if policy.reviewer_policies.len() > MAX_CATALOG_OWNERS {
        return Err(CatalogTrustError::InvalidPolicy(format!(
            "reviewer policy count exceeds {MAX_CATALOG_OWNERS}"
        )));
    }
    for (id, reviewer) in &policy.reviewer_policies {
        if !is_id(id) {
            return Err(CatalogTrustError::InvalidPolicy(format!(
                "reviewer policy id `{id}` is not canonical kebab-case"
            )));
        }
        validate_reviewer_policy(id, reviewer)?;
    }
    Ok(())
}

fn validate_reviewer_policy(
    id: &str,
    reviewer: &CatalogReviewerPolicy,
) -> Result<(), CatalogTrustError> {
    if reviewer.evidence_schema != 1 {
        return Err(CatalogTrustError::InvalidPolicy(format!(
            "reviewer policy `{id}` requires unsupported evidence schema {}",
            reviewer.evidence_schema
        )));
    }
    if reviewer.rule_sets.is_empty() || reviewer.rule_sets.len() > MAX_RULE_SETS_PER_POLICY {
        return Err(CatalogTrustError::InvalidPolicy(format!(
            "reviewer policy `{id}` must allow 1..={MAX_RULE_SETS_PER_POLICY} rule sets"
        )));
    }
    if let Some(rule_set) = reviewer.rule_sets.iter().find(|rule_set| !is_id(rule_set)) {
        return Err(CatalogTrustError::InvalidPolicy(format!(
            "reviewer policy `{id}` has non-canonical rule set `{rule_set}`"
        )));
    }
    Ok(())
}

fn normalize_policy(
    policy: &CatalogTrustPolicy,
    referenced: &BTreeSet<String>,
) -> Result<CatalogTrustPolicy, CatalogTrustError> {
    let mut reviewer_policies = BTreeMap::new();
    for id in referenced {
        let reviewer = policy.reviewer_policies.get(id).ok_or_else(|| {
            CatalogTrustError::InvalidPolicy(format!(
                "catalog references unknown reviewer policy `{id}`"
            ))
        })?;
        reviewer_policies.insert(id.clone(), reviewer.clone());
    }
    Ok(CatalogTrustPolicy {
        schema: CATALOG_TRUST_INPUT_SCHEMA,
        reviewer_policies,
    })
}

fn policy_digest(policy: &CatalogTrustPolicy) -> Result<String, CatalogTrustError> {
    Ok(hex::encode(canonical::domain_hash(
        POLICY_IDENTITY_DOMAIN,
        policy,
    )?))
}

fn record_from_bytes(
    request: &CatalogEvidenceRequest,
    policy: &CatalogTrustPolicy,
    bytes: Vec<u8>,
) -> Result<CatalogEvidenceRecord, CatalogTrustError> {
    let document = parse_document(request, policy, &bytes)?;
    let record = CatalogEvidenceRecord {
        owner_kind: request.owner.kind,
        owner: request.owner.id.clone(),
        package: request.package.clone(),
        package_path: request.package_path.clone(),
        source: request.evidence.source.clone(),
        algorithm: request.evidence.algorithm.clone(),
        digest: request.evidence.digest.clone(),
        reviewer_policy: request.evidence.reviewer_policy.clone(),
        document,
        bytes_hex: hex::encode(bytes),
    };
    validate_record(&record, request, policy)?;
    Ok(record)
}

fn validate_record(
    record: &CatalogEvidenceRecord,
    request: &CatalogEvidenceRequest,
    policy: &CatalogTrustPolicy,
) -> Result<(), CatalogTrustError> {
    if record.owner_kind != request.owner.kind
        || record.owner != request.owner.id
        || record.package != request.package
        || record.package_path != request.package_path
        || record.source != request.evidence.source
        || record.algorithm != request.evidence.algorithm
        || record.digest != request.evidence.digest
        || record.reviewer_policy != request.evidence.reviewer_policy
    {
        return Err(CatalogTrustError::InvalidEvidence(format!(
            "record attribution differs from catalog metadata for {}",
            owner_label(&request.owner)
        )));
    }
    let bytes = record_bytes(record)?;
    let parsed = parse_document(request, policy, &bytes)?;
    if parsed != record.document {
        return Err(CatalogTrustError::InvalidEvidence(format!(
            "normalized document differs from committed bytes for {}",
            owner_label(&request.owner)
        )));
    }
    Ok(())
}

fn parse_document(
    request: &CatalogEvidenceRequest,
    policy: &CatalogTrustPolicy,
    bytes: &[u8],
) -> Result<CoexistenceEvidenceDocument, CatalogTrustError> {
    if bytes.len() > MAX_COEXISTENCE_EVIDENCE_BYTES {
        return Err(CatalogTrustError::InvalidEvidence(format!(
            "{} has {} bytes; maximum is {MAX_COEXISTENCE_EVIDENCE_BYTES}",
            owner_label(&request.owner),
            bytes.len()
        )));
    }
    let digest = hex::encode(Sha256::digest(bytes));
    if request.evidence.algorithm != "sha256" || request.evidence.digest != digest {
        return Err(CatalogTrustError::InvalidEvidence(format!(
            "digest mismatch for {}",
            owner_label(&request.owner)
        )));
    }
    let input = std::str::from_utf8(bytes).map_err(|error| {
        CatalogTrustError::InvalidEvidence(format!(
            "{} is not UTF-8: {error}",
            owner_label(&request.owner)
        ))
    })?;
    let mut document: CoexistenceEvidenceDocument = toml::from_str(input).map_err(|error| {
        CatalogTrustError::InvalidEvidence(format!(
            "{} document is invalid: {error}",
            owner_label(&request.owner)
        ))
    })?;
    let reviewer = policy
        .reviewer_policies
        .get(&request.evidence.reviewer_policy)
        .ok_or_else(|| {
            CatalogTrustError::InvalidPolicy(format!(
                "catalog references unknown reviewer policy `{}`",
                request.evidence.reviewer_policy
            ))
        })?;
    if document.schema != reviewer.evidence_schema
        || !reviewer.rule_sets.contains(&document.rule_set)
    {
        return Err(CatalogTrustError::InvalidEvidence(format!(
            "schema or rule-set mismatch for {}",
            owner_label(&request.owner)
        )));
    }
    if document.owner != request.owner.id || document.mode != request.mode {
        return Err(CatalogTrustError::InvalidEvidence(format!(
            "owner or coexistence mode mismatch for {}",
            owner_label(&request.owner)
        )));
    }
    let expected_claims = required_claims(request.mode);
    if document.claims != expected_claims {
        return Err(CatalogTrustError::InvalidEvidence(format!(
            "claims do not exactly cover the selected rule set for {}",
            owner_label(&request.owner)
        )));
    }
    if document.tests.is_empty() || document.tests.len() > MAX_EVIDENCE_TEST_REFERENCES {
        return Err(CatalogTrustError::InvalidEvidence(format!(
            "{} must cite 1..={MAX_EVIDENCE_TEST_REFERENCES} tests",
            owner_label(&request.owner)
        )));
    }
    let unique = document.tests.iter().cloned().collect::<BTreeSet<_>>();
    if unique.len() != document.tests.len()
        || unique.iter().any(|test| {
            test.is_empty()
                || test.len() > MAX_EVIDENCE_TEST_REFERENCE_BYTES
                || !test.bytes().all(|byte| byte.is_ascii_graphic())
        })
    {
        return Err(CatalogTrustError::InvalidEvidence(format!(
            "{} has duplicate or invalid test references",
            owner_label(&request.owner)
        )));
    }
    document.tests.sort();
    Ok(document)
}

fn record_bytes(record: &CatalogEvidenceRecord) -> Result<Vec<u8>, CatalogTrustError> {
    if record.bytes_hex.len() > MAX_COEXISTENCE_EVIDENCE_BYTES.saturating_mul(2) {
        return Err(CatalogTrustError::InvalidEvidence(format!(
            "committed evidence bytes exceed the bound for {}:{}",
            owner_kind_label(record.owner_kind),
            record.owner
        )));
    }
    let bytes = hex::decode(&record.bytes_hex).map_err(|_| {
        CatalogTrustError::InvalidEvidence(format!(
            "committed evidence bytes are not lowercase hexadecimal for {}:{}",
            owner_kind_label(record.owner_kind),
            record.owner
        ))
    })?;
    if hex::encode(&bytes) != record.bytes_hex {
        return Err(CatalogTrustError::InvalidEvidence(format!(
            "committed evidence bytes are not lowercase hexadecimal for {}:{}",
            owner_kind_label(record.owner_kind),
            record.owner
        )));
    }
    Ok(bytes)
}

fn required_claims(mode: CoexistenceEvidenceMode) -> BTreeSet<String> {
    let claims: &[&str] = match mode {
        CoexistenceEvidenceMode::ConcurrentIndependent => &[
            "boundary-config",
            "different-config",
            "identical-config",
            "independent-real-resources",
            "two-app-in-process",
        ],
        CoexistenceEvidenceMode::ConcurrentSharedHostHandle => &[
            "no-reopen",
            "same-host-handle-identity",
            "two-app-in-process",
        ],
    };
    claims.iter().map(|claim| (*claim).to_owned()).collect()
}

fn owner_label(owner: &CatalogEvidenceOwner) -> String {
    format!("{}:{}", owner_kind_label(owner.kind), owner.id)
}

const fn owner_kind_label(kind: EvidenceOwnerKind) -> &'static str {
    match kind {
        EvidenceOwnerKind::Component => "component",
        EvidenceOwnerKind::RuntimeAdapter => "runtime-adapter",
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

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;
    use crate::metadata::CatalogDocument;

    fn fixture_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap()
    }

    fn fixture_catalog() -> NormalizedCatalog {
        NormalizedCatalog::normalize(
            CatalogDocument::from_toml(include_str!("../../../../tests/fixtures/catalog.toml"))
                .unwrap(),
        )
        .unwrap()
    }

    fn fixture_policy() -> CatalogTrustPolicy {
        CatalogTrustPolicy::from_toml(include_str!(
            "../../../../tests/fixtures/catalog-trust.toml"
        ))
        .unwrap()
    }

    fn fixture_evidence(catalog: &NormalizedCatalog) -> BTreeMap<CatalogEvidenceOwner, Vec<u8>> {
        let root = fixture_root();
        evidence_requests(catalog)
            .into_iter()
            .map(|request| {
                let bytes = fs::read(
                    root.join(&request.package_path)
                        .join(&request.evidence.source),
                )
                .unwrap();
                (request.owner, bytes)
            })
            .collect()
    }

    #[test]
    fn trust_input_commits_exact_policy_and_evidence_bytes() {
        let catalog = fixture_catalog();
        let mut policy = fixture_policy();
        policy.reviewer_policies.insert(
            "unused-policy".into(),
            CatalogReviewerPolicy {
                evidence_schema: 1,
                rule_sets: BTreeSet::from(["unused-rule-v1".into()]),
            },
        );
        let commitment =
            CatalogTrustInputCommitment::new(&catalog, &policy, fixture_evidence(&catalog))
                .unwrap();

        commitment.validate(&catalog).unwrap();
        assert_eq!(commitment.normalized_policy.reviewer_policies.len(), 1);
        assert!(
            commitment
                .normalized_policy
                .reviewer_policies
                .contains_key("phase-1a-fixture-review-v1")
        );
        for record in &commitment.evidence {
            let path = fixture_root()
                .join(&record.package_path)
                .join(&record.source);
            assert_eq!(record_bytes(record).unwrap(), fs::read(path).unwrap());
        }
    }

    #[test]
    fn unknown_policy_digest_drift_and_forged_committed_bytes_fail_closed() {
        let catalog = fixture_catalog();
        let evidence = fixture_evidence(&catalog);
        let mut missing_policy = fixture_policy();
        missing_policy.reviewer_policies.clear();
        assert!(matches!(
            CatalogTrustInputCommitment::new(&catalog, &missing_policy, evidence.clone()),
            Err(CatalogTrustError::InvalidPolicy(message))
                if message.contains("unknown reviewer policy")
        ));

        let mut changed_evidence = evidence;
        changed_evidence.values_mut().next().unwrap()[0] ^= 1;
        assert!(matches!(
            CatalogTrustInputCommitment::new(&catalog, &fixture_policy(), changed_evidence),
            Err(CatalogTrustError::InvalidEvidence(message))
                if message.contains("digest mismatch")
        ));

        let mut commitment = CatalogTrustInputCommitment::new(
            &catalog,
            &fixture_policy(),
            fixture_evidence(&catalog),
        )
        .unwrap();
        commitment.evidence[0].bytes_hex.make_ascii_uppercase();
        commitment.identity_digest = commitment.recompute_identity_digest().unwrap();
        assert!(matches!(
            commitment.validate(&catalog),
            Err(CatalogTrustError::InvalidEvidence(message))
                if message.contains("lowercase hexadecimal")
        ));
    }

    #[test]
    fn evidence_schema_rule_set_owner_mode_claims_and_size_are_closed() {
        let catalog = fixture_catalog();
        let policy = fixture_policy();
        let request = evidence_requests(&catalog)
            .into_iter()
            .find(|request| request.owner.id == "fixture-model")
            .unwrap();
        let original = fs::read(
            fixture_root()
                .join(&request.package_path)
                .join(&request.evidence.source),
        )
        .unwrap();

        for (needle, replacement, expected) in [
            ("schema = 1", "schema = 2", "schema or rule-set mismatch"),
            (
                "phase-1a-independent-v1",
                "phase-1a-unreviewed-v1",
                "schema or rule-set mismatch",
            ),
            (
                "fixture-model",
                "fixture-other",
                "owner or coexistence mode mismatch",
            ),
            (
                "concurrent-independent",
                "concurrent-shared-host-handle",
                "owner or coexistence mode mismatch",
            ),
            (
                ", \"two-app-in-process\"",
                "",
                "claims do not exactly cover",
            ),
        ] {
            let bytes = String::from_utf8(original.clone())
                .unwrap()
                .replacen(needle, replacement, 1)
                .into_bytes();
            let mut request = request.clone();
            request.evidence.digest = hex::encode(Sha256::digest(&bytes));
            assert!(matches!(
                parse_document(&request, &policy, &bytes),
                Err(CatalogTrustError::InvalidEvidence(message)) if message.contains(expected)
            ));
        }

        let bytes = vec![b'x'; MAX_COEXISTENCE_EVIDENCE_BYTES + 1];
        let mut request = request;
        request.evidence.digest = hex::encode(Sha256::digest(&bytes));
        assert!(matches!(
            parse_document(&request, &policy, &bytes),
            Err(CatalogTrustError::InvalidEvidence(message)) if message.contains("maximum")
        ));
    }

    #[test]
    fn shared_host_handle_evidence_uses_the_shared_rule_set_and_identity_claims() {
        let catalog = fixture_catalog();
        let commitment = CatalogTrustInputCommitment::new(
            &catalog,
            &fixture_policy(),
            fixture_evidence(&catalog),
        )
        .unwrap();

        commitment.validate(&catalog).unwrap();
        let model = commitment
            .evidence
            .iter()
            .find(|record| record.owner == "fixture-model-shared")
            .unwrap();
        assert_eq!(
            model.document.mode,
            CoexistenceEvidenceMode::ConcurrentSharedHostHandle
        );
        assert_eq!(model.document.rule_set, "phase-1a-shared-handle-v1");
    }
}
