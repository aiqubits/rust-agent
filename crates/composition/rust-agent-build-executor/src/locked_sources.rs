use std::collections::{BTreeMap, BTreeSet};

use rust_agent_composition::canonical;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    CargoPackageIdentity, CargoPackageSource, HostBuildClosureContent, HostBuildClosureItemRole,
    NormalizedHostBuildInputClosure,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedSourceClosure {
    pub schema: u32,
    #[serde(rename = "cargo-lock-digest")]
    pub cargo_lock_digest: String,
    pub packages: Vec<CargoPackageIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedLockedSourceClosure {
    cargo_lock_digest: String,
    packages: BTreeSet<CargoPackageIdentity>,
    digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FetchedSourceEvidence {
    pub schema: u32,
    #[serde(rename = "locked-source-closure-digest")]
    pub locked_source_closure_digest: String,
    pub packages: Vec<FetchedSourcePackage>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FetchedSourcePackage {
    pub package: CargoPackageIdentity,
    pub observation: FetchedSourceObservation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum FetchedSourceObservation {
    RegistryArchive {
        #[serde(rename = "archive-sha256")]
        archive_sha256: String,
        #[serde(rename = "snapshot-tree-digest")]
        snapshot_tree_digest: String,
    },
    GitCheckout {
        precise: String,
        #[serde(rename = "snapshot-tree-digest")]
        snapshot_tree_digest: String,
    },
    PathSnapshot {
        #[serde(rename = "snapshot-tree-digest")]
        snapshot_tree_digest: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedFetchedSourceEvidence {
    packages: Vec<FetchedSourcePackage>,
    digest: String,
}

#[derive(Debug, Error)]
pub enum LockedSourceError {
    #[error("Cargo.lock TOML is invalid: {0}")]
    CargoLockToml(#[from] toml::de::Error),
    #[error("locked source closure JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported Cargo.lock format {0}; expected 4")]
    UnsupportedCargoLock(u32),
    #[error("unsupported locked source closure schema {0}; expected 1")]
    UnsupportedClosureSchema(u32),
    #[error("unsupported fetched source evidence schema {0}; expected 1")]
    UnsupportedEvidenceSchema(u32),
    #[error("invalid locked package field `{field}` for {package}")]
    InvalidLockedPackage {
        package: String,
        field: &'static str,
    },
    #[error("duplicate locked package identity: {0}")]
    DuplicateLockedPackage(String),
    #[error("path package mapping is missing or ambiguous for {0}")]
    PathPackageMapping(String),
    #[error("locked source closure digest is invalid")]
    InvalidClosureDigest,
    #[error("Host Cargo.lock item does not match locked source closure")]
    HostCargoLockMismatch,
    #[error("final Host unit package is absent or differs from Cargo.lock source closure: {0:?}")]
    UnitPackageMismatch(Box<CargoPackageIdentity>),
    #[error("fetched source evidence package set differs from locked source closure")]
    EvidencePackageSetMismatch,
    #[error("fetched source observation does not match locked identity: {0:?}")]
    EvidenceObservationMismatch(Box<CargoPackageIdentity>),
    #[error("canonical locked source encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCargoLock {
    version: u32,
    #[serde(default)]
    package: Vec<RawLockedPackage>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLockedPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    checksum: Option<String>,
    #[serde(default)]
    dependencies: Vec<String>,
}

impl LockedSourceClosure {
    pub fn from_json(input: &str) -> Result<Self, LockedSourceError> {
        Ok(serde_json::from_str(input)?)
    }

    pub fn from_cargo_lock(
        cargo_lock: &[u8],
        path_packages: &[CargoPackageIdentity],
    ) -> Result<Self, LockedSourceError> {
        let text = std::str::from_utf8(cargo_lock).map_err(|_| {
            LockedSourceError::InvalidLockedPackage {
                package: "Cargo.lock".into(),
                field: "utf-8",
            }
        })?;
        let lock: RawCargoLock = toml::from_str(text)?;
        if lock.version != 4 {
            return Err(LockedSourceError::UnsupportedCargoLock(lock.version));
        }
        let mut path_map = BTreeMap::new();
        for package in path_packages {
            let CargoPackageSource::Path { tree_digest } = &package.source else {
                return Err(LockedSourceError::PathPackageMapping(format!(
                    "{} {}",
                    package.name, package.version
                )));
            };
            validate_package_identity(package)?;
            let key = (package.name.clone(), package.version.clone());
            if path_map.insert(key, tree_digest.clone()).is_some() {
                return Err(LockedSourceError::PathPackageMapping(format!(
                    "{} {}",
                    package.name, package.version
                )));
            }
        }

        let mut packages = Vec::with_capacity(lock.package.len());
        let mut used_path_packages = BTreeSet::new();
        for raw in lock.package {
            validate_lock_text(&raw.name, 128).map_err(|field| {
                LockedSourceError::InvalidLockedPackage {
                    package: raw.name.clone(),
                    field,
                }
            })?;
            validate_lock_text(&raw.version, 128).map_err(|field| {
                LockedSourceError::InvalidLockedPackage {
                    package: raw.name.clone(),
                    field,
                }
            })?;
            if raw
                .dependencies
                .iter()
                .any(|dependency| validate_lock_text(dependency, 1024).is_err())
            {
                return Err(LockedSourceError::InvalidLockedPackage {
                    package: raw.name,
                    field: "dependencies",
                });
            }
            let source = match raw.source {
                Some(source) if source.starts_with("registry+") => {
                    let registry = source
                        .strip_prefix("registry+")
                        .expect("prefix was matched");
                    if !valid_registry_source(registry) {
                        return Err(LockedSourceError::InvalidLockedPackage {
                            package: raw.name,
                            field: "registry",
                        });
                    }
                    let checksum =
                        raw.checksum
                            .ok_or_else(|| LockedSourceError::InvalidLockedPackage {
                                package: raw.name.clone(),
                                field: "checksum",
                            })?;
                    if !is_digest(&checksum) {
                        return Err(LockedSourceError::InvalidLockedPackage {
                            package: raw.name,
                            field: "checksum",
                        });
                    }
                    CargoPackageSource::Registry {
                        registry: registry.into(),
                        checksum,
                    }
                }
                Some(source) if source.starts_with("git+") => {
                    if raw.checksum.is_some() {
                        return Err(LockedSourceError::InvalidLockedPackage {
                            package: raw.name,
                            field: "git-checksum",
                        });
                    }
                    let source = source.strip_prefix("git+").expect("prefix was matched");
                    let Some((repository, precise)) = source.rsplit_once('#') else {
                        return Err(LockedSourceError::InvalidLockedPackage {
                            package: raw.name,
                            field: "git-precise",
                        });
                    };
                    if !valid_git_source(repository) || !is_git_precise(precise) {
                        return Err(LockedSourceError::InvalidLockedPackage {
                            package: raw.name,
                            field: "git-source",
                        });
                    }
                    CargoPackageSource::Git {
                        repository: repository.into(),
                        precise: precise.into(),
                    }
                }
                Some(_) => {
                    return Err(LockedSourceError::InvalidLockedPackage {
                        package: raw.name,
                        field: "source-kind",
                    });
                }
                None => {
                    if raw.checksum.is_some() {
                        return Err(LockedSourceError::InvalidLockedPackage {
                            package: raw.name,
                            field: "path-checksum",
                        });
                    }
                    let key = (raw.name.clone(), raw.version.clone());
                    let tree_digest = path_map.get(&key).cloned().ok_or_else(|| {
                        LockedSourceError::PathPackageMapping(format!(
                            "{} {}",
                            raw.name, raw.version
                        ))
                    })?;
                    used_path_packages.insert(key);
                    CargoPackageSource::Path { tree_digest }
                }
            };
            packages.push(CargoPackageIdentity {
                name: raw.name,
                version: raw.version,
                source,
            });
        }
        if used_path_packages.len() != path_map.len() {
            return Err(LockedSourceError::PathPackageMapping(
                "unused path package mapping".into(),
            ));
        }
        packages.sort();
        if let Some(duplicate) = packages.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(LockedSourceError::DuplicateLockedPackage(format!(
                "{} {}",
                duplicate[0].name, duplicate[0].version
            )));
        }
        Ok(Self {
            schema: 1,
            cargo_lock_digest: sha256_hex(cargo_lock),
            packages,
        })
    }

    pub fn normalize(&self) -> Result<NormalizedLockedSourceClosure, LockedSourceError> {
        if self.schema != 1 {
            return Err(LockedSourceError::UnsupportedClosureSchema(self.schema));
        }
        if !is_digest(&self.cargo_lock_digest) || self.packages.is_empty() {
            return Err(LockedSourceError::InvalidClosureDigest);
        }
        let mut packages = BTreeSet::new();
        for package in &self.packages {
            validate_package_identity(package)?;
            if !packages.insert(package.clone()) {
                return Err(LockedSourceError::DuplicateLockedPackage(format!(
                    "{} {}",
                    package.name, package.version
                )));
            }
        }
        let canonical_packages: Vec<_> = packages.iter().cloned().collect();
        let digest = hex::encode(canonical::domain_hash(
            b"rust-agent-locked-source-closure-v1\0",
            &(1_u32, &self.cargo_lock_digest, &canonical_packages),
        )?);
        Ok(NormalizedLockedSourceClosure {
            cargo_lock_digest: self.cargo_lock_digest.clone(),
            packages,
            digest,
        })
    }
}

impl NormalizedLockedSourceClosure {
    pub fn cargo_lock_digest(&self) -> &str {
        &self.cargo_lock_digest
    }

    pub fn packages(&self) -> &BTreeSet<CargoPackageIdentity> {
        &self.packages
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn verify_host_closure(
        &self,
        host_closure: &NormalizedHostBuildInputClosure,
    ) -> Result<(), LockedSourceError> {
        let lock_matches = host_closure.items().iter().any(|item| {
            item.role == HostBuildClosureItemRole::HostCargoLock
                && matches!(
                    &item.content,
                    HostBuildClosureContent::File { sha256 }
                        if sha256 == &self.cargo_lock_digest
                )
        });
        if !lock_matches {
            return Err(LockedSourceError::HostCargoLockMismatch);
        }
        for package in host_closure.final_unit_packages() {
            if !self.packages.contains(package) {
                return Err(LockedSourceError::UnitPackageMismatch(Box::new(
                    package.clone(),
                )));
            }
        }
        Ok(())
    }
}

impl FetchedSourceEvidence {
    pub fn from_json(input: &str) -> Result<Self, LockedSourceError> {
        Ok(serde_json::from_str(input)?)
    }

    pub fn normalize(
        &self,
        closure: &NormalizedLockedSourceClosure,
    ) -> Result<NormalizedFetchedSourceEvidence, LockedSourceError> {
        if self.schema != 1 {
            return Err(LockedSourceError::UnsupportedEvidenceSchema(self.schema));
        }
        if self.locked_source_closure_digest != closure.digest {
            return Err(LockedSourceError::InvalidClosureDigest);
        }
        let mut packages = self.packages.clone();
        packages.sort_by(|left, right| left.package.cmp(&right.package));
        if packages
            .windows(2)
            .any(|pair| pair[0].package == pair[1].package)
        {
            return Err(LockedSourceError::EvidencePackageSetMismatch);
        }
        let actual: BTreeSet<_> = packages
            .iter()
            .map(|package| package.package.clone())
            .collect();
        if actual != closure.packages {
            return Err(LockedSourceError::EvidencePackageSetMismatch);
        }
        for package in &packages {
            if !observation_matches(&package.package, &package.observation) {
                return Err(LockedSourceError::EvidenceObservationMismatch(Box::new(
                    package.package.clone(),
                )));
            }
        }
        let digest = hex::encode(canonical::domain_hash(
            b"rust-agent-fetched-source-evidence-v1\0",
            &(1_u32, &self.locked_source_closure_digest, &packages),
        )?);
        Ok(NormalizedFetchedSourceEvidence { packages, digest })
    }
}

impl NormalizedFetchedSourceEvidence {
    pub fn packages(&self) -> &[FetchedSourcePackage] {
        &self.packages
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

fn observation_matches(
    package: &CargoPackageIdentity,
    observation: &FetchedSourceObservation,
) -> bool {
    match (&package.source, observation) {
        (
            CargoPackageSource::Registry { checksum, .. },
            FetchedSourceObservation::RegistryArchive {
                archive_sha256,
                snapshot_tree_digest,
            },
        ) => archive_sha256 == checksum && is_digest(snapshot_tree_digest),
        (
            CargoPackageSource::Git { precise, .. },
            FetchedSourceObservation::GitCheckout {
                precise: observed,
                snapshot_tree_digest,
            },
        ) => observed == precise && is_digest(snapshot_tree_digest),
        (
            CargoPackageSource::Path { tree_digest },
            FetchedSourceObservation::PathSnapshot {
                snapshot_tree_digest,
            },
        ) => snapshot_tree_digest == tree_digest,
        _ => false,
    }
}

fn validate_package_identity(package: &CargoPackageIdentity) -> Result<(), LockedSourceError> {
    for (field, value) in [
        ("name", package.name.as_str()),
        ("version", package.version.as_str()),
    ] {
        if validate_lock_text(value, 128).is_err() {
            return Err(LockedSourceError::InvalidLockedPackage {
                package: package.name.clone(),
                field,
            });
        }
    }
    let valid = match &package.source {
        CargoPackageSource::Registry { registry, checksum } => {
            valid_registry_source(registry) && is_digest(checksum)
        }
        CargoPackageSource::Git {
            repository,
            precise,
        } => valid_git_source(repository) && is_git_precise(precise),
        CargoPackageSource::Path { tree_digest } => is_digest(tree_digest),
    };
    if valid {
        Ok(())
    } else {
        Err(LockedSourceError::InvalidLockedPackage {
            package: package.name.clone(),
            field: "source",
        })
    }
}

fn validate_lock_text(value: &str, maximum: usize) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > maximum
        || value.contains(['\0', '\n', '\r'])
        || value.trim() != value
    {
        Err("text")
    } else {
        Ok(())
    }
}

fn valid_registry_source(value: &str) -> bool {
    validate_lock_text(value, 2048).is_ok()
        && !value.contains('*')
        && (value.starts_with("https://") || value.starts_with("sparse+https://"))
}

fn valid_git_source(value: &str) -> bool {
    validate_lock_text(value, 2048).is_ok() && !value.contains('*') && value.starts_with("https://")
}

fn is_git_precise(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
