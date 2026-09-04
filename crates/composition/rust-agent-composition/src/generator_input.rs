use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

use crate::{
    canonical::{self, CanonicalError},
    catalog::{CatalogError, NormalizedCatalog, validate_build_requirements},
    catalog_trust::{CatalogTrustError, CatalogTrustInputCommitment},
    metadata::{
        BuildRequirements, CatalogDocument, CatalogResourceBoundsError, MAX_CATALOG_OWNERS,
    },
    serde_bounds::deserialize_unique_bounded_map,
};

pub const GENERATOR_INPUT_SCHEMA: u32 = 2;

const NORMALIZED_CATALOG_IDENTITY_DOMAIN: &[u8] = b"rust-agent-normalized-catalog-v1\0";
const GENERATOR_INPUT_IDENTITY_DOMAIN: &[u8] = b"rust-agent-generator-input-v2\0";
const PHASE_1A_MANDATORY_ROOT_PACKAGES: [&str; 2] = ["rust-agent-core", "rust-agent-runtime-api"];
const MAX_GENERATOR_ROOT_BUILD_REQUIREMENTS: usize = MAX_CATALOG_OWNERS + 2;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GeneratorInputCommitment {
    pub schema: u32,
    #[serde(rename = "normalized-catalog")]
    pub normalized_catalog: CatalogDocument,
    #[serde(rename = "normalized-catalog-digest")]
    pub normalized_catalog_digest: String,
    #[serde(rename = "catalog-trust-input")]
    pub catalog_trust_input: CatalogTrustInputCommitment,
    #[serde(rename = "root-build-requirements")]
    pub root_build_requirements: BTreeMap<String, BuildRequirements>,
    #[serde(rename = "identity-digest")]
    pub identity_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedGeneratorInputCommitment {
    schema: u32,
    #[serde(rename = "normalized-catalog")]
    normalized_catalog: CatalogDocument,
    #[serde(rename = "normalized-catalog-digest")]
    normalized_catalog_digest: String,
    #[serde(rename = "catalog-trust-input")]
    catalog_trust_input: CatalogTrustInputCommitment,
    #[serde(rename = "root-build-requirements")]
    #[serde(deserialize_with = "deserialize_root_build_requirements")]
    root_build_requirements: BTreeMap<String, BuildRequirements>,
    #[serde(rename = "identity-digest")]
    identity_digest: String,
}

fn deserialize_root_build_requirements<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, BuildRequirements>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_unique_bounded_map(
        deserializer,
        MAX_GENERATOR_ROOT_BUILD_REQUIREMENTS,
        "generator root build requirements",
    )
}

#[derive(Serialize)]
struct GeneratorInputIdentityPayload<'a> {
    schema: u32,
    #[serde(rename = "normalized-catalog")]
    normalized_catalog: &'a CatalogDocument,
    #[serde(rename = "normalized-catalog-digest")]
    normalized_catalog_digest: &'a str,
    #[serde(rename = "catalog-trust-input")]
    catalog_trust_input: &'a CatalogTrustInputCommitment,
    #[serde(rename = "root-build-requirements")]
    root_build_requirements: &'a BTreeMap<String, BuildRequirements>,
}

#[derive(Debug, Error)]
pub enum GeneratorInputError {
    #[error("unsupported generator-input schema {0}; expected 2")]
    UnsupportedSchema(u32),
    #[error("generator-input record is invalid: {0}")]
    InvalidRecord(String),
    #[error("normalized catalog is invalid: {0}")]
    Catalog(#[from] CatalogError),
    #[error("catalog trust input is invalid: {0}")]
    CatalogTrust(#[from] CatalogTrustError),
    #[error("generator-input canonical encoding failed: {0}")]
    Canonical(#[from] CanonicalError),
}

impl<'de> Deserialize<'de> for GeneratorInputCommitment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedGeneratorInputCommitment::deserialize(deserializer)?;
        let record = Self {
            schema: unchecked.schema,
            normalized_catalog: unchecked.normalized_catalog,
            normalized_catalog_digest: unchecked.normalized_catalog_digest,
            catalog_trust_input: unchecked.catalog_trust_input,
            root_build_requirements: unchecked.root_build_requirements,
            identity_digest: unchecked.identity_digest,
        };
        record.validate().map_err(de::Error::custom)?;
        Ok(record)
    }
}

impl GeneratorInputCommitment {
    pub(crate) fn new(
        catalog: &NormalizedCatalog,
        catalog_trust_input: CatalogTrustInputCommitment,
        root_build_requirements: &BTreeMap<String, BuildRequirements>,
    ) -> Result<Self, GeneratorInputError> {
        let normalized_catalog = catalog.to_document();
        let normalized_catalog_digest = normalized_catalog_digest(&normalized_catalog)?;
        let mut record = Self {
            schema: GENERATOR_INPUT_SCHEMA,
            normalized_catalog,
            normalized_catalog_digest,
            catalog_trust_input,
            root_build_requirements: root_build_requirements.clone(),
            identity_digest: String::new(),
        };
        record.identity_digest = record.recompute_identity_digest()?;
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), GeneratorInputError> {
        if self.schema != GENERATOR_INPUT_SCHEMA {
            return Err(GeneratorInputError::UnsupportedSchema(self.schema));
        }
        self.normalized_catalog
            .validate_resource_bounds()
            .map_err(|error| match error {
                CatalogResourceBoundsError::OwnerCountOverflow => {
                    GeneratorInputError::InvalidRecord("catalog owner count overflowed".into())
                }
                CatalogResourceBoundsError::TooManyOwners { actual, maximum } => {
                    GeneratorInputError::InvalidRecord(format!(
                        "catalog has {actual} owners; maximum is {maximum}"
                    ))
                }
            })?;
        validate_canonical_owner_order(&self.normalized_catalog)?;
        validate_root_build_requirements(&self.root_build_requirements)?;

        let normalized = NormalizedCatalog::normalize(self.normalized_catalog.clone())?;
        if normalized.to_document() != self.normalized_catalog {
            return Err(GeneratorInputError::InvalidRecord(
                "catalog is valid but is not the exact normalized catalog encoding".into(),
            ));
        }
        validate_exact_root_build_requirement_owners(&normalized, &self.root_build_requirements)?;
        self.catalog_trust_input.validate(&normalized)?;
        let expected_catalog_digest = normalized_catalog_digest(&self.normalized_catalog)?;
        if !is_sha256(&self.normalized_catalog_digest)
            || self.normalized_catalog_digest != expected_catalog_digest
        {
            return Err(GeneratorInputError::InvalidRecord(
                "normalized catalog digest does not match its canonical content".into(),
            ));
        }
        let expected_identity = self.recompute_identity_digest()?;
        if !is_sha256(&self.identity_digest) || self.identity_digest != expected_identity {
            return Err(GeneratorInputError::InvalidRecord(
                "generator-input identity digest does not match its canonical content".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn catalog(&self) -> Result<NormalizedCatalog, GeneratorInputError> {
        self.validate()?;
        Ok(NormalizedCatalog::normalize(
            self.normalized_catalog.clone(),
        )?)
    }

    fn recompute_identity_digest(&self) -> Result<String, GeneratorInputError> {
        Ok(hex::encode(canonical::domain_hash(
            GENERATOR_INPUT_IDENTITY_DOMAIN,
            &GeneratorInputIdentityPayload {
                schema: self.schema,
                normalized_catalog: &self.normalized_catalog,
                normalized_catalog_digest: &self.normalized_catalog_digest,
                catalog_trust_input: &self.catalog_trust_input,
                root_build_requirements: &self.root_build_requirements,
            },
        )?))
    }
}

fn normalized_catalog_digest(catalog: &CatalogDocument) -> Result<String, GeneratorInputError> {
    Ok(hex::encode(canonical::domain_hash(
        NORMALIZED_CATALOG_IDENTITY_DOMAIN,
        catalog,
    )?))
}

fn validate_canonical_owner_order(catalog: &CatalogDocument) -> Result<(), GeneratorInputError> {
    for (kind, canonical) in [
        (
            "capabilities",
            catalog
                .capabilities
                .windows(2)
                .all(|pair| pair[0].id < pair[1].id),
        ),
        (
            "components",
            catalog
                .components
                .windows(2)
                .all(|pair| pair[0].id < pair[1].id),
        ),
        (
            "runtime-adapters",
            catalog
                .runtime_adapters
                .windows(2)
                .all(|pair| pair[0].id < pair[1].id),
        ),
        (
            "host-boundaries",
            catalog
                .host_boundaries
                .windows(2)
                .all(|pair| pair[0].id < pair[1].id),
        ),
    ] {
        if !canonical {
            return Err(GeneratorInputError::InvalidRecord(format!(
                "normalized catalog {kind} are not in strict id order"
            )));
        }
    }
    Ok(())
}

fn validate_root_build_requirements(
    requirements: &BTreeMap<String, BuildRequirements>,
) -> Result<(), GeneratorInputError> {
    if requirements.len() > MAX_GENERATOR_ROOT_BUILD_REQUIREMENTS {
        return Err(GeneratorInputError::InvalidRecord(format!(
            "root build-requirement owner count exceeds {MAX_GENERATOR_ROOT_BUILD_REQUIREMENTS}"
        )));
    }
    for (package, requirements) in requirements {
        if !is_canonical_id(package) {
            return Err(GeneratorInputError::InvalidRecord(format!(
                "root build-requirement package `{package}` is not canonical kebab-case"
            )));
        }
        validate_build_requirements(package, requirements)?;
    }
    Ok(())
}

fn validate_exact_root_build_requirement_owners(
    catalog: &NormalizedCatalog,
    requirements: &BTreeMap<String, BuildRequirements>,
) -> Result<(), GeneratorInputError> {
    let expected = PHASE_1A_MANDATORY_ROOT_PACKAGES
        .into_iter()
        .map(str::to_owned)
        .chain(
            catalog
                .capabilities
                .values()
                .map(|capability| capability.api_package.clone()),
        )
        .collect::<BTreeSet<_>>();
    let actual = requirements.keys().cloned().collect::<BTreeSet<_>>();
    if actual != expected {
        let missing = expected.difference(&actual).cloned().collect::<Vec<_>>();
        let unexpected = actual.difference(&expected).cloned().collect::<Vec<_>>();
        return Err(GeneratorInputError::InvalidRecord(format!(
            "root build-requirement owners differ from the normalized catalog and mandatory roots; missing={missing:?}; unexpected={unexpected:?}"
        )));
    }
    Ok(())
}

fn is_canonical_id(value: &str) -> bool {
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

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog_trust::evidence_requests;
    use crate::metadata::{CatalogDocument, CatalogTrustPolicy};

    fn fixture_record() -> GeneratorInputCommitment {
        let document =
            CatalogDocument::from_toml(include_str!("../../../../tests/fixtures/catalog.toml"))
                .unwrap();
        let catalog = NormalizedCatalog::normalize(document).unwrap();
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        let evidence = evidence_requests(&catalog)
            .into_iter()
            .map(|request| {
                let bytes = std::fs::read(
                    root.join(&request.package_path)
                        .join(&request.evidence.source),
                )
                .unwrap();
                (request.owner, bytes)
            })
            .collect();
        let roots = BTreeMap::from([
            ("rust-agent-core".into(), BuildRequirements::default()),
            (
                "rust-agent-fixture-api".into(),
                BuildRequirements::default(),
            ),
            (
                "rust-agent-runtime-api".into(),
                BuildRequirements::default(),
            ),
        ]);
        let trust = CatalogTrustInputCommitment::new(
            &catalog,
            &CatalogTrustPolicy::from_toml(include_str!(
                "../../../../tests/fixtures/catalog-trust.toml"
            ))
            .unwrap(),
            evidence,
        )
        .unwrap();
        GeneratorInputCommitment::new(&catalog, trust, &roots).unwrap()
    }

    #[test]
    fn commitment_round_trips_the_exact_normalized_catalog_and_roots() {
        let record = fixture_record();
        record.validate().unwrap();
        let decoded: GeneratorInputCommitment =
            serde_json::from_value(serde_json::to_value(&record).unwrap()).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(
            decoded.catalog().unwrap().to_document(),
            record.normalized_catalog
        );
    }

    #[test]
    fn commitment_rejects_reordering_unknown_fields_and_digest_forgery() {
        let record = fixture_record();
        let mut reordered = serde_json::to_value(&record).unwrap();
        reordered["normalized-catalog"]["components"]
            .as_array_mut()
            .unwrap()
            .reverse();
        assert!(serde_json::from_value::<GeneratorInputCommitment>(reordered).is_err());

        let mut unknown = serde_json::to_value(&record).unwrap();
        unknown["ambient-input"] = serde_json::Value::String("PATH".into());
        assert!(serde_json::from_value::<GeneratorInputCommitment>(unknown).is_err());

        for field in ["normalized-catalog-digest", "identity-digest"] {
            let mut forged = serde_json::to_value(&record).unwrap();
            forged[field] = serde_json::Value::String("0".repeat(64));
            assert!(serde_json::from_value::<GeneratorInputCommitment>(forged).is_err());
        }
    }

    #[test]
    fn commitment_rejects_noncanonical_catalog_and_root_requirements() {
        let record = fixture_record();
        let mut noncanonical = serde_json::to_value(&record).unwrap();
        noncanonical["normalized-catalog"]["components"][0]["support"] =
            serde_json::Value::String("production".into());
        assert!(serde_json::from_value::<GeneratorInputCommitment>(noncanonical).is_err());

        let mut invalid_root = serde_json::to_value(&record).unwrap();
        let roots = invalid_root["root-build-requirements"]
            .as_object_mut()
            .unwrap();
        roots.insert(
            "Not_Canonical".into(),
            serde_json::to_value(BuildRequirements::default()).unwrap(),
        );
        assert!(serde_json::from_value::<GeneratorInputCommitment>(invalid_root).is_err());
    }

    #[test]
    fn commitment_requires_exact_root_owners_and_closes_the_count_boundary() {
        let record = fixture_record();

        let mut missing = record.clone();
        missing.root_build_requirements.remove("rust-agent-core");
        missing.identity_digest = missing.recompute_identity_digest().unwrap();
        assert!(matches!(
            missing.validate(),
            Err(GeneratorInputError::InvalidRecord(message))
                if message.contains("missing=[\"rust-agent-core\"]")
        ));

        let mut unexpected = record;
        unexpected
            .root_build_requirements
            .insert("unselected-package".into(), BuildRequirements::default());
        unexpected.identity_digest = unexpected.recompute_identity_digest().unwrap();
        assert!(matches!(
            unexpected.validate(),
            Err(GeneratorInputError::InvalidRecord(message))
                if message.contains("unexpected=[\"unselected-package\"]")
        ));

        let at_limit = (0..MAX_GENERATOR_ROOT_BUILD_REQUIREMENTS)
            .map(|index| (format!("package-{index:03}"), BuildRequirements::default()))
            .collect::<BTreeMap<_, _>>();
        validate_root_build_requirements(&at_limit).unwrap();
        let mut over_limit = at_limit;
        over_limit.insert("package-over-limit".into(), BuildRequirements::default());
        assert!(matches!(
            validate_root_build_requirements(&over_limit),
            Err(GeneratorInputError::InvalidRecord(message))
                if message.contains("owner count exceeds")
        ));
    }
}
