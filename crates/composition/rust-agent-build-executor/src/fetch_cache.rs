use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    io,
    os::fd::AsRawFd as _,
    path::{Path, PathBuf},
};

use flate2::read::GzDecoder;
use git2::{ObjectType, Oid, Repository, Tree};
use rust_agent_composition::{
    canonical,
    snapshot::{
        CanonicalSnapshotEntry, CanonicalSnapshotEntryKind, CanonicalSnapshotError,
        CanonicalSnapshotTree, MAX_CANONICAL_SNAPSHOT_ENTRIES, MAX_CANONICAL_SNAPSHOT_JSON_BYTES,
        MAX_CANONICAL_SNAPSHOT_PATH_BYTES,
    },
};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use thiserror::Error;

use crate::{
    CargoPackageIdentity, CargoPackageSource, FetchedSourceEvidence, FetchedSourceObservation,
    FetchedSourcePackage, NormalizedCargoFetchRequest, NormalizedLockedSourceClosure,
    SnapshotMaterializationError, ValidatedCargoFetchObservation,
    snapshot_materializer::{
        AnchoredTreeIdentity, anchor_tree_identity, prepare_anchored_tree_publication,
    },
};

const REGISTRY_ARCHIVE_PREFIX: &str = "registry/cache/";
const REGISTRY_SOURCE_PREFIX: &str = "registry/src/";
const GIT_SOURCE_PREFIX: &str = "git/checkouts/";
const CACHE_MANIFEST_FILE: &str = "rust-agent-cargo-fetch-cache.json";
const MAX_GIT_BLOB_BYTES: u64 = 64 * 1024 * 1024;
const MAX_GIT_TREE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoFetchCacheLayout {
    pub schema: u32,
    pub packages: Vec<CargoFetchCachePackageLocation>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoFetchCachePackageLocation {
    pub package: CargoPackageIdentity,
    #[serde(
        rename = "archive-path",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub archive_path: Option<String>,
    #[serde(
        rename = "source-path",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoFetchCacheManifest {
    pub schema: u32,
    #[serde(rename = "request-digest")]
    pub request_digest: String,
    #[serde(rename = "fetch-observation-digest")]
    pub fetch_observation_digest: String,
    #[serde(rename = "cache-tree-digest")]
    pub cache_tree_digest: String,
    #[serde(rename = "cache-tree-entries")]
    pub cache_tree_entries: Vec<CanonicalSnapshotEntry>,
    pub packages: Vec<CargoFetchCachePackageLocation>,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedCargoFetchCache {
    path: PathBuf,
    manifest: CargoFetchCacheManifest,
    reused: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedCargoFetchCache {
    tree: CanonicalSnapshotTree,
    evidence: FetchedSourceEvidence,
}

/// A verified Cargo cache whose directory descriptor is retained across its
/// later unchanged checks.
///
/// This handle closes pathname replacement between verification steps. It is
/// not an immutable read-only mount or production sandbox attestation.
#[derive(Clone, Debug)]
pub struct VerifiedCargoFetchCache {
    path: PathBuf,
    manifest: CargoFetchCacheManifest,
    identity: AnchoredTreeIdentity,
}

#[derive(Debug, Error)]
pub enum CargoFetchCacheError {
    #[error("unsupported Cargo fetch cache layout schema {0}; expected 1")]
    UnsupportedLayoutSchema(u32),
    #[error("unsupported Cargo fetch cache manifest schema {0}; expected 1")]
    UnsupportedManifestSchema(u32),
    #[error("Cargo fetch cache package layout differs from fetched-source evidence")]
    PackageSetMismatch,
    #[error("Cargo fetch cache package location is invalid for {0:?}")]
    InvalidPackageLocation(Box<CargoPackageIdentity>),
    #[error("Cargo fetch cache locations overlap or are duplicated")]
    OverlappingPackageLocation,
    #[error("Cargo fetch cache tree differs from the validated fetch observation")]
    CacheTreeMismatch,
    #[error("registry archive does not match the locked checksum for {0:?}")]
    RegistryArchiveMismatch(Box<CargoPackageIdentity>),
    #[error("cached source tree does not match fetched-source evidence for {0:?}")]
    SourceTreeMismatch(Box<CargoPackageIdentity>),
    #[error("Cargo fetch cache manifest digest or projection differs from verified inputs")]
    ManifestMismatch,
    #[error("Cargo fetch cache manifest JSON exceeds its byte limit")]
    JsonTooLarge,
    #[error("Cargo fetch cache manifest JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Cargo fetch cache filesystem materialization failed: {0}")]
    Materialization(#[from] SnapshotMaterializationError),
    #[error("Cargo fetch cache I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("canonical Cargo fetch cache encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
    #[error("canonical Cargo fetch cache tree is invalid: {0}")]
    Snapshot(#[from] CanonicalSnapshotError),
    #[error("locked Cargo source verification failed: {0}")]
    LockedSources(#[from] crate::LockedSourceError),
    #[error("Cargo fetch cache archive is invalid for {0:?}")]
    InvalidRegistryArchive(Box<CargoPackageIdentity>),
    #[error("Cargo fetch cache observation does not match the locked package set")]
    LockedPackageSetMismatch,
    #[error("Cargo fetch cache git checkout is invalid for {package:?}: {reason}")]
    InvalidGitCheckout {
        package: Box<CargoPackageIdentity>,
        reason: String,
    },
}

#[derive(Serialize)]
struct CacheManifestProjection<'a> {
    schema: u32,
    request_digest: &'a str,
    fetch_observation_digest: &'a str,
    cache_tree_digest: &'a str,
    cache_tree_entries: &'a [CanonicalSnapshotEntry],
    packages: &'a [CargoFetchCachePackageLocation],
}

impl CargoFetchCacheLayout {
    pub fn verify(
        &self,
        request: &NormalizedCargoFetchRequest,
        observation: &ValidatedCargoFetchObservation,
        cache_tree: &CanonicalSnapshotTree,
    ) -> Result<CargoFetchCacheManifest, CargoFetchCacheError> {
        if self.schema != 1 {
            return Err(CargoFetchCacheError::UnsupportedLayoutSchema(self.schema));
        }
        if observation.request_digest() != request.digest()
            || observation.cache_tree_digest() != cache_tree.digest()
        {
            return Err(CargoFetchCacheError::CacheTreeMismatch);
        }

        let evidence = observation.fetched_sources().packages();
        let expected_packages = evidence
            .iter()
            .map(|item| item.package.clone())
            .collect::<BTreeSet<_>>();
        let mut packages = self.packages.clone();
        packages.sort();
        if packages
            .windows(2)
            .any(|pair| pair[0].package == pair[1].package)
            || packages
                .iter()
                .map(|item| item.package.clone())
                .collect::<BTreeSet<_>>()
                != expected_packages
        {
            return Err(CargoFetchCacheError::PackageSetMismatch);
        }
        validate_location_separation(&packages)?;

        let entries = cache_tree
            .entries()
            .iter()
            .map(|entry| (entry.path.as_str(), entry))
            .collect::<BTreeMap<_, _>>();
        let evidence = evidence
            .iter()
            .map(|item| (&item.package, &item.observation))
            .collect::<BTreeMap<_, _>>();
        for location in &packages {
            let observation = evidence
                .get(&location.package)
                .expect("the exact package set was checked");
            verify_package_location(location, observation, &entries, cache_tree)?;
        }

        let projection = CacheManifestProjection {
            schema: 1,
            request_digest: request.digest(),
            fetch_observation_digest: observation.digest(),
            cache_tree_digest: cache_tree.digest(),
            cache_tree_entries: cache_tree.entries(),
            packages: &packages,
        };
        let digest = hex::encode(canonical::domain_hash(
            b"rust-agent-cargo-fetch-cache-manifest-v1\0",
            &projection,
        )?);
        Ok(CargoFetchCacheManifest {
            schema: 1,
            request_digest: request.digest().into(),
            fetch_observation_digest: observation.digest().into(),
            cache_tree_digest: cache_tree.digest().into(),
            cache_tree_entries: cache_tree.entries().to_vec(),
            packages,
            digest,
        })
    }
}

impl CargoFetchCacheManifest {
    pub fn from_json(input: &str) -> Result<Self, CargoFetchCacheError> {
        if input.len() > MAX_CANONICAL_SNAPSHOT_JSON_BYTES {
            return Err(CargoFetchCacheError::JsonTooLarge);
        }
        Ok(serde_json::from_str(input)?)
    }

    pub fn verify(
        &self,
        request: &NormalizedCargoFetchRequest,
        observation: &ValidatedCargoFetchObservation,
        cache_tree: &CanonicalSnapshotTree,
    ) -> Result<(), CargoFetchCacheError> {
        if self.schema != 1 {
            return Err(CargoFetchCacheError::UnsupportedManifestSchema(self.schema));
        }
        let manifest_tree = CanonicalSnapshotTree::from_entries(self.cache_tree_entries.clone())?;
        if manifest_tree.entries() != self.cache_tree_entries
            || manifest_tree.digest() != self.cache_tree_digest
            || &manifest_tree != cache_tree
        {
            return Err(CargoFetchCacheError::ManifestMismatch);
        }
        let expected = CargoFetchCacheLayout {
            schema: self.schema,
            packages: self.packages.clone(),
        }
        .verify(request, observation, cache_tree)?;
        if &expected == self {
            Ok(())
        } else {
            Err(CargoFetchCacheError::ManifestMismatch)
        }
    }
}

impl MaterializedCargoFetchCache {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn manifest(&self) -> &CargoFetchCacheManifest {
        &self.manifest
    }

    pub fn reused(&self) -> bool {
        self.reused
    }
}

impl ObservedCargoFetchCache {
    pub fn tree(&self) -> &CanonicalSnapshotTree {
        &self.tree
    }

    pub fn evidence(&self) -> &FetchedSourceEvidence {
        &self.evidence
    }
}

pub fn observe_cargo_fetch_cache(
    cache: &Path,
    locked_sources: &NormalizedLockedSourceClosure,
    layout: &CargoFetchCacheLayout,
) -> Result<ObservedCargoFetchCache, CargoFetchCacheError> {
    if layout.schema != 1 {
        return Err(CargoFetchCacheError::UnsupportedLayoutSchema(layout.schema));
    }
    let mut locations = layout.packages.clone();
    locations.sort();
    if locations
        .windows(2)
        .any(|pair| pair[0].package == pair[1].package)
        || locations
            .iter()
            .map(|location| location.package.clone())
            .collect::<BTreeSet<_>>()
            != *locked_sources.packages()
    {
        return Err(CargoFetchCacheError::LockedPackageSetMismatch);
    }
    validate_location_separation(&locations)?;

    let identity = anchor_tree_identity(cache)?;
    let tree = identity.tree().clone();
    let entries = tree
        .entries()
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut packages = Vec::with_capacity(locations.len());
    for location in &locations {
        let observation = match &location.package.source {
            CargoPackageSource::Registry { checksum, .. } => {
                let (Some(archive), Some(source)) = (&location.archive_path, &location.source_path)
                else {
                    return Err(invalid_location(&location.package));
                };
                let archive_digest = entries
                    .get(archive.as_str())
                    .and_then(|entry| match &entry.kind {
                        CanonicalSnapshotEntryKind::RegularFile { sha256, .. } => Some(sha256),
                        CanonicalSnapshotEntryKind::Directory => None,
                    })
                    .ok_or_else(|| {
                        CargoFetchCacheError::InvalidRegistryArchive(Box::new(
                            location.package.clone(),
                        ))
                    })?;
                if archive_digest != checksum {
                    return Err(CargoFetchCacheError::RegistryArchiveMismatch(Box::new(
                        location.package.clone(),
                    )));
                }
                let source_tree = source_subtree(&tree, source, &location.package)?;
                let archive_tree = registry_archive_tree(&identity, archive, &location.package)?;
                if registry_source_archive_projection(&source_tree)? != archive_tree {
                    return Err(CargoFetchCacheError::SourceTreeMismatch(Box::new(
                        location.package.clone(),
                    )));
                }
                FetchedSourceObservation::RegistryArchive {
                    archive_sha256: archive_digest.clone(),
                    snapshot_tree_digest: source_tree.digest().into(),
                }
            }
            CargoPackageSource::Git {
                repository,
                precise,
            } => {
                let (None, Some(source)) = (&location.archive_path, &location.source_path) else {
                    return Err(invalid_location(&location.package));
                };
                let source_tree = source_subtree(&tree, source, &location.package)?;
                verify_git_checkout(
                    &identity,
                    source,
                    repository,
                    precise,
                    &source_tree,
                    &location.package,
                )?;
                FetchedSourceObservation::GitCheckout {
                    precise: precise.clone(),
                    snapshot_tree_digest: source_tree.digest().into(),
                }
            }
            CargoPackageSource::Path { tree_digest } => {
                if location.archive_path.is_some() || location.source_path.is_some() {
                    return Err(invalid_location(&location.package));
                }
                FetchedSourceObservation::PathSnapshot {
                    snapshot_tree_digest: tree_digest.clone(),
                }
            }
        };
        packages.push(FetchedSourcePackage {
            package: location.package.clone(),
            observation,
        });
    }
    identity.reverify()?;
    let evidence = FetchedSourceEvidence {
        schema: 1,
        locked_source_closure_digest: locked_sources.digest().into(),
        packages,
    };
    evidence.normalize(locked_sources)?;
    Ok(ObservedCargoFetchCache { tree, evidence })
}

fn registry_source_archive_projection(
    source: &CanonicalSnapshotTree,
) -> Result<CanonicalSnapshotTree, CargoFetchCacheError> {
    CanonicalSnapshotTree::from_entries(
        source
            .entries()
            .iter()
            .filter(|entry| entry.path != ".cargo-ok")
            .cloned()
            .collect(),
    )
    .map_err(Into::into)
}

impl VerifiedCargoFetchCache {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn manifest(&self) -> &CargoFetchCacheManifest {
        &self.manifest
    }

    pub fn verify_unchanged(&self) -> Result<(), CargoFetchCacheError> {
        let cache_tree =
            CanonicalSnapshotTree::from_entries(self.manifest.cache_tree_entries.clone())?;
        let manifest_bytes = canonical::jcs_bytes(&self.manifest)?;
        self.identity
            .verify_publication(&cache_tree, CACHE_MANIFEST_FILE, &manifest_bytes)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn duplicate_mount_descriptor(
        &self,
    ) -> Result<std::os::fd::OwnedFd, CargoFetchCacheError> {
        self.verify_unchanged()?;
        self.identity
            .duplicate_mount_descriptor()
            .map_err(Into::into)
    }
}

pub fn materialize_cargo_fetch_cache(
    source_cache: &Path,
    output: &Path,
    request: &NormalizedCargoFetchRequest,
    observation: &ValidatedCargoFetchObservation,
    layout: &CargoFetchCacheLayout,
) -> Result<MaterializedCargoFetchCache, CargoFetchCacheError> {
    let publication = prepare_anchored_tree_publication(source_cache, output)?;
    let manifest = layout.verify(request, observation, publication.source_tree())?;
    let manifest_bytes = canonical::jcs_bytes(&manifest)?;
    if manifest_bytes.len() > MAX_CANONICAL_SNAPSHOT_JSON_BYTES {
        return Err(CargoFetchCacheError::JsonTooLarge);
    }
    let reused = publication.publish(CACHE_MANIFEST_FILE, &manifest_bytes)?;
    Ok(MaterializedCargoFetchCache {
        path: output.to_owned(),
        manifest,
        reused,
    })
}

pub fn verify_materialized_cargo_fetch_cache(
    output: &Path,
    request: &NormalizedCargoFetchRequest,
    observation: &ValidatedCargoFetchObservation,
) -> Result<CargoFetchCacheManifest, CargoFetchCacheError> {
    Ok(
        open_verified_cargo_fetch_cache(output, request, observation)?
            .manifest
            .clone(),
    )
}

pub fn open_verified_cargo_fetch_cache(
    output: &Path,
    request: &NormalizedCargoFetchRequest,
    observation: &ValidatedCargoFetchObservation,
) -> Result<VerifiedCargoFetchCache, CargoFetchCacheError> {
    let identity = anchor_tree_identity(output)?;
    let bytes = identity
        .read_file(CACHE_MANIFEST_FILE, MAX_CANONICAL_SNAPSHOT_JSON_BYTES)
        .map_err(|error| match error {
            SnapshotMaterializationError::JsonTooLarge => CargoFetchCacheError::JsonTooLarge,
            other => CargoFetchCacheError::Materialization(other),
        })?;
    if bytes.is_empty() {
        return Err(CargoFetchCacheError::JsonTooLarge);
    }
    let manifest: CargoFetchCacheManifest = serde_json::from_slice(&bytes)?;
    let cache_tree = CanonicalSnapshotTree::from_entries(manifest.cache_tree_entries.clone())?;
    manifest.verify(request, observation, &cache_tree)?;
    if canonical::jcs_bytes(&manifest)? != bytes {
        return Err(CargoFetchCacheError::ManifestMismatch);
    }
    identity.verify_publication(&cache_tree, CACHE_MANIFEST_FILE, &bytes)?;
    Ok(VerifiedCargoFetchCache {
        path: output.to_owned(),
        manifest,
        identity,
    })
}

fn validate_location_separation(
    packages: &[CargoFetchCachePackageLocation],
) -> Result<(), CargoFetchCacheError> {
    let mut paths = Vec::new();
    for package in packages {
        if let Some(path) = &package.archive_path {
            paths.push(path.as_str());
        }
        if let Some(path) = &package.source_path {
            paths.push(path.as_str());
        }
    }
    paths.sort_unstable();
    for pair in paths.windows(2) {
        if pair[0] == pair[1]
            || pair[1]
                .strip_prefix(pair[0])
                .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return Err(CargoFetchCacheError::OverlappingPackageLocation);
        }
    }
    Ok(())
}

fn verify_package_location(
    location: &CargoFetchCachePackageLocation,
    observation: &FetchedSourceObservation,
    entries: &BTreeMap<&str, &CanonicalSnapshotEntry>,
    cache_tree: &CanonicalSnapshotTree,
) -> Result<(), CargoFetchCacheError> {
    match (&location.package.source, observation) {
        (
            CargoPackageSource::Registry { checksum, .. },
            FetchedSourceObservation::RegistryArchive {
                archive_sha256,
                snapshot_tree_digest,
            },
        ) => {
            let (Some(archive), Some(source)) = (
                location.archive_path.as_deref(),
                location.source_path.as_deref(),
            ) else {
                return Err(invalid_location(&location.package));
            };
            let expected_archive = format!(
                "{}-{}.crate",
                location.package.name, location.package.version
            );
            let expected_source = format!("{}-{}", location.package.name, location.package.version);
            if !valid_cache_path(archive, REGISTRY_ARCHIVE_PREFIX)
                || archive
                    .rsplit_once('.')
                    .is_none_or(|(_, extension)| extension != "crate")
                || !valid_cache_path(source, REGISTRY_SOURCE_PREFIX)
                || archive.rsplit('/').next() != Some(expected_archive.as_str())
                || source.rsplit('/').next() != Some(expected_source.as_str())
            {
                return Err(invalid_location(&location.package));
            }
            let Some(entry) = entries.get(archive) else {
                return Err(CargoFetchCacheError::RegistryArchiveMismatch(Box::new(
                    location.package.clone(),
                )));
            };
            if !matches!(
                &entry.kind,
                CanonicalSnapshotEntryKind::RegularFile { sha256, .. }
                    if sha256 == checksum && sha256 == archive_sha256
            ) {
                return Err(CargoFetchCacheError::RegistryArchiveMismatch(Box::new(
                    location.package.clone(),
                )));
            }
            verify_source_tree(
                &location.package,
                source,
                snapshot_tree_digest,
                entries,
                cache_tree,
            )
        }
        (
            CargoPackageSource::Git { .. },
            FetchedSourceObservation::GitCheckout {
                snapshot_tree_digest,
                ..
            },
        ) => {
            let (None, Some(source)) = (
                location.archive_path.as_deref(),
                location.source_path.as_deref(),
            ) else {
                return Err(invalid_location(&location.package));
            };
            if !valid_cache_path(source, GIT_SOURCE_PREFIX) {
                return Err(invalid_location(&location.package));
            }
            verify_source_tree(
                &location.package,
                source,
                snapshot_tree_digest,
                entries,
                cache_tree,
            )
        }
        (
            CargoPackageSource::Path { tree_digest },
            FetchedSourceObservation::PathSnapshot {
                snapshot_tree_digest,
            },
        ) if location.archive_path.is_none()
            && location.source_path.is_none()
            && tree_digest == snapshot_tree_digest =>
        {
            Ok(())
        }
        _ => Err(invalid_location(&location.package)),
    }
}

fn verify_source_tree(
    package: &CargoPackageIdentity,
    source: &str,
    expected_digest: &str,
    entries: &BTreeMap<&str, &CanonicalSnapshotEntry>,
    cache_tree: &CanonicalSnapshotTree,
) -> Result<(), CargoFetchCacheError> {
    if !matches!(
        entries.get(source).map(|entry| &entry.kind),
        Some(CanonicalSnapshotEntryKind::Directory)
    ) {
        return Err(CargoFetchCacheError::SourceTreeMismatch(Box::new(
            package.clone(),
        )));
    }
    let prefix = format!("{source}/");
    let mut source_entries = Vec::new();
    for entry in cache_tree.entries() {
        let Some(relative) = entry.path.strip_prefix(&prefix) else {
            continue;
        };
        let mut relative_entry = entry.clone();
        relative_entry.path = relative.into();
        source_entries.push(relative_entry);
    }
    let source_tree = CanonicalSnapshotTree::from_entries(source_entries)?;
    if source_tree.digest() == expected_digest {
        Ok(())
    } else {
        Err(CargoFetchCacheError::SourceTreeMismatch(Box::new(
            package.clone(),
        )))
    }
}

fn source_subtree(
    cache_tree: &CanonicalSnapshotTree,
    source: &str,
    package: &CargoPackageIdentity,
) -> Result<CanonicalSnapshotTree, CargoFetchCacheError> {
    if !valid_cache_path(source, "")
        || !matches!(
            cache_tree
                .entries()
                .iter()
                .find(|entry| entry.path == source)
                .map(|entry| &entry.kind),
            Some(CanonicalSnapshotEntryKind::Directory)
        )
    {
        return Err(invalid_location(package));
    }
    let prefix = format!("{source}/");
    let entries = cache_tree
        .entries()
        .iter()
        .filter_map(|entry| {
            entry.path.strip_prefix(&prefix).map(|relative| {
                let mut entry = entry.clone();
                entry.path = relative.into();
                entry
            })
        })
        .collect();
    CanonicalSnapshotTree::from_entries(entries).map_err(Into::into)
}

fn registry_archive_tree(
    cache: &AnchoredTreeIdentity,
    archive: &str,
    package: &CargoPackageIdentity,
) -> Result<CanonicalSnapshotTree, CargoFetchCacheError> {
    let file = cache.open_file(archive)?;
    let mut archive = tar::Archive::new(GzDecoder::new(file));
    let expected_root = format!("{}-{}", package.name, package.version);
    let mut entries = BTreeMap::<String, CanonicalSnapshotEntry>::new();
    for entry in archive
        .entries()
        .map_err(|_| CargoFetchCacheError::InvalidRegistryArchive(Box::new(package.clone())))?
    {
        let mut entry = entry
            .map_err(|_| CargoFetchCacheError::InvalidRegistryArchive(Box::new(package.clone())))?;
        let path = entry
            .path()
            .map_err(|_| CargoFetchCacheError::InvalidRegistryArchive(Box::new(package.clone())))?;
        let mut components = path.components();
        if components
            .next()
            .and_then(|component| component.as_os_str().to_str())
            != Some(expected_root.as_str())
        {
            return Err(CargoFetchCacheError::InvalidRegistryArchive(Box::new(
                package.clone(),
            )));
        }
        let relative = components
            .map(|component| component.as_os_str().to_str())
            .collect::<Option<Vec<_>>>()
            .filter(|components| {
                !components.is_empty()
                    && components
                        .iter()
                        .all(|component| !component.is_empty() && !matches!(*component, "." | ".."))
            })
            .map(|components| components.join("/"))
            .ok_or_else(|| {
                CargoFetchCacheError::InvalidRegistryArchive(Box::new(package.clone()))
            })?;
        insert_parent_directories(&relative, &mut entries);
        let snapshot_entry = if entry.header().entry_type().is_dir() {
            CanonicalSnapshotEntry::directory(relative.clone())
        } else if entry.header().entry_type().is_file() {
            let mut hasher = sha2::Sha256::new();
            let bytes = io::copy(&mut entry, &mut hasher)?;
            CanonicalSnapshotEntry::regular_file(
                relative.clone(),
                hex::encode(hasher.finalize()),
                bytes,
            )
        } else {
            return Err(CargoFetchCacheError::InvalidRegistryArchive(Box::new(
                package.clone(),
            )));
        };
        match entries.entry(relative) {
            Entry::Vacant(entry) => {
                entry.insert(snapshot_entry);
            }
            Entry::Occupied(entry)
                if matches!(entry.get().kind, CanonicalSnapshotEntryKind::Directory)
                    && matches!(snapshot_entry.kind, CanonicalSnapshotEntryKind::Directory) => {}
            Entry::Occupied(_) => {
                return Err(CargoFetchCacheError::InvalidRegistryArchive(Box::new(
                    package.clone(),
                )));
            }
        }
    }
    CanonicalSnapshotTree::from_entries(entries.into_values().collect()).map_err(Into::into)
}

fn insert_parent_directories(
    relative: &str,
    entries: &mut BTreeMap<String, CanonicalSnapshotEntry>,
) {
    let components = relative.split('/').collect::<Vec<_>>();
    for index in 1..components.len() {
        let parent = components[..index].join("/");
        entries
            .entry(parent.clone())
            .or_insert_with(|| CanonicalSnapshotEntry::directory(parent));
    }
}

fn verify_git_checkout(
    cache: &AnchoredTreeIdentity,
    source: &str,
    repository: &str,
    precise: &str,
    source_tree: &CanonicalSnapshotTree,
    package: &CargoPackageIdentity,
) -> Result<(), CargoFetchCacheError> {
    let (checkout_root, git_dir) = resolve_git_checkout(cache, source, package)?;
    let descriptor = cache.duplicate_mount_descriptor()?;
    let descriptor_root = PathBuf::from(format!("/proc/self/fd/{}", descriptor.as_raw_fd()));
    let repository_path = descriptor_root.join(&git_dir);
    let repository_handle = Repository::open_bare(&repository_path)
        .map_err(|error| invalid_git(package, error.to_string()))?;
    let expected_remote = repository
        .strip_prefix("git+")
        .unwrap_or(repository)
        .split(['?', '#'])
        .next()
        .ok_or_else(|| invalid_git(package, "locked repository URL is empty"))?;
    let origin = repository_handle
        .find_remote("origin")
        .map_err(|error| invalid_git(package, format!("origin is absent: {error}")))?;
    let actual_remote = origin
        .url()
        .map(str::to_owned)
        .map_err(|error| invalid_git(package, format!("origin URL is non-UTF-8: {error}")))?;
    drop(origin);
    if actual_remote != expected_remote {
        return Err(invalid_git(package, "origin URL differs from Cargo.lock"));
    }
    let precise_oid = Oid::from_str(precise)
        .map_err(|error| invalid_git(package, format!("precise revision is invalid: {error}")))?;
    let head_oid = repository_handle
        .head()
        .and_then(|head| head.peel_to_commit())
        .map(|commit| commit.id())
        .map_err(|error| invalid_git(package, format!("HEAD is invalid: {error}")))?;
    if head_oid != precise_oid {
        return Err(CargoFetchCacheError::SourceTreeMismatch(Box::new(
            package.clone(),
        )));
    }
    let commit = repository_handle
        .find_commit(precise_oid)
        .map_err(|error| invalid_git(package, format!("commit object is absent: {error}")))?;
    let mut commit_tree = commit
        .tree()
        .map_err(|error| invalid_git(package, format!("commit tree is absent: {error}")))?;
    let package_subdirectory = source
        .strip_prefix(&checkout_root)
        .and_then(|suffix| suffix.strip_prefix('/'));
    if let Some(subdirectory) = package_subdirectory {
        for component in subdirectory.split('/') {
            let entry_id = commit_tree
                .get_name(component)
                .map(|entry| entry.id())
                .ok_or_else(|| {
                    invalid_git(package, "package subdirectory is absent from commit")
                })?;
            commit_tree = repository_handle
                .find_tree(entry_id)
                .map_err(|error| invalid_git(package, format!("subtree is invalid: {error}")))?;
        }
    } else if source != checkout_root {
        return Err(invalid_git(
            package,
            "package path is outside the checkout root",
        ));
    }
    let expected_tree = canonical_git_tree(&repository_handle, &commit_tree, package)?;
    let actual_tree = git_worktree_projection(source_tree, package)?;
    if expected_tree != actual_tree {
        return Err(CargoFetchCacheError::SourceTreeMismatch(Box::new(
            package.clone(),
        )));
    }
    cache.reverify()?;
    Ok(())
}

fn resolve_git_checkout(
    cache: &AnchoredTreeIdentity,
    source: &str,
    package: &CargoPackageIdentity,
) -> Result<(String, String), CargoFetchCacheError> {
    let mut candidate = Some(source);
    while let Some(path) = candidate {
        let git = format!("{path}/.git");
        if let Some(entry) = cache
            .tree()
            .entries()
            .iter()
            .find(|entry| entry.path == git)
        {
            let git_dir = match &entry.kind {
                CanonicalSnapshotEntryKind::Directory => git,
                CanonicalSnapshotEntryKind::RegularFile { .. } => {
                    let bytes = cache.read_file(&git, 4096)?;
                    let value = std::str::from_utf8(&bytes)
                        .ok()
                        .and_then(|value| value.trim().strip_prefix("gitdir: "))
                        .ok_or_else(|| invalid_location(package))?;
                    normalize_git_dir(path, value).ok_or_else(|| invalid_location(package))?
                }
            };
            return Ok((path.into(), git_dir));
        }
        candidate = path.rsplit_once('/').map(|(parent, _)| parent);
    }
    Err(invalid_location(package))
}

fn canonical_git_tree(
    repository: &Repository,
    root: &Tree<'_>,
    package: &CargoPackageIdentity,
) -> Result<CanonicalSnapshotTree, CargoFetchCacheError> {
    let mut entries = Vec::new();
    let mut total_bytes = 0_u64;
    append_git_tree(
        repository,
        root,
        "",
        &mut entries,
        &mut total_bytes,
        package,
    )?;
    CanonicalSnapshotTree::from_entries(entries).map_err(Into::into)
}

fn append_git_tree(
    repository: &Repository,
    tree: &Tree<'_>,
    prefix: &str,
    entries: &mut Vec<CanonicalSnapshotEntry>,
    total_bytes: &mut u64,
    package: &CargoPackageIdentity,
) -> Result<(), CargoFetchCacheError> {
    for entry in tree {
        let name = entry
            .name()
            .map_err(|_| invalid_git(package, "commit contains a non-UTF-8 path"))?;
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        if entries.len() >= MAX_CANONICAL_SNAPSHOT_ENTRIES
            || path.len() > MAX_CANONICAL_SNAPSHOT_PATH_BYTES
        {
            return Err(invalid_git(package, "commit tree exceeds snapshot bounds"));
        }
        match (entry.kind(), entry.filemode()) {
            (Some(ObjectType::Tree), 0o040_000) => {
                entries.push(CanonicalSnapshotEntry::directory(path.clone()));
                let subtree = repository.find_tree(entry.id()).map_err(|error| {
                    invalid_git(package, format!("tree object is invalid: {error}"))
                })?;
                append_git_tree(repository, &subtree, &path, entries, total_bytes, package)?;
            }
            (Some(ObjectType::Blob), 0o100_644 | 0o100_755) => {
                let (declared_bytes, object_kind) = repository
                    .odb()
                    .and_then(|database| database.read_header(entry.id()))
                    .map_err(|error| {
                        invalid_git(package, format!("blob header is invalid: {error}"))
                    })?;
                let declared_bytes = u64::try_from(declared_bytes)
                    .map_err(|_| invalid_git(package, "blob size overflows u64"))?;
                *total_bytes = total_bytes
                    .checked_add(declared_bytes)
                    .ok_or_else(|| invalid_git(package, "commit tree size overflows u64"))?;
                if object_kind != ObjectType::Blob
                    || declared_bytes > MAX_GIT_BLOB_BYTES
                    || *total_bytes > MAX_GIT_TREE_BYTES
                {
                    return Err(invalid_git(package, "commit blob exceeds fetch bounds"));
                }
                let blob = repository.find_blob(entry.id()).map_err(|error| {
                    invalid_git(package, format!("blob object is invalid: {error}"))
                })?;
                let bytes = u64::try_from(blob.content().len())
                    .map_err(|_| invalid_git(package, "blob size overflows u64"))?;
                if bytes != declared_bytes {
                    return Err(invalid_git(package, "blob body differs from its header"));
                }
                entries.push(CanonicalSnapshotEntry::regular_file(
                    path,
                    hex::encode(sha2::Sha256::digest(blob.content())),
                    bytes,
                ));
            }
            _ => {
                return Err(invalid_git(
                    package,
                    "commit contains a symlink, submodule, or unsupported object mode",
                ));
            }
        }
    }
    Ok(())
}

fn git_worktree_projection(
    source: &CanonicalSnapshotTree,
    package: &CargoPackageIdentity,
) -> Result<CanonicalSnapshotTree, CargoFetchCacheError> {
    let entries = source
        .entries()
        .iter()
        .filter(|entry| {
            entry.path != ".cargo-ok" && entry.path != ".git" && !entry.path.starts_with(".git/")
        })
        .cloned()
        .collect();
    CanonicalSnapshotTree::from_entries(entries)
        .map_err(|error| invalid_git(package, format!("worktree projection is invalid: {error}")))
}

fn normalize_git_dir(checkout: &str, value: &str) -> Option<String> {
    if let Some(relative) = value.strip_prefix("/rust-agent/fetch-cache-staging/cargo-home/") {
        return valid_cache_path(relative, "").then(|| relative.into());
    }
    if value.starts_with('/') || value.contains('\\') {
        return None;
    }
    let mut components = checkout.split('/').collect::<Vec<_>>();
    components.pop();
    for component in value.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop()?;
            }
            component => components.push(component),
        }
    }
    let path = components.join("/");
    valid_cache_path(&path, "").then_some(path)
}

fn valid_cache_path(path: &str, prefix: &str) -> bool {
    path.starts_with(prefix)
        && path.len() <= 4_096
        && path.is_ascii()
        && !path.contains('\\')
        && path
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

fn invalid_location(package: &CargoPackageIdentity) -> CargoFetchCacheError {
    CargoFetchCacheError::InvalidPackageLocation(Box::new(package.clone()))
}

fn invalid_git(package: &CargoPackageIdentity, reason: impl Into<String>) -> CargoFetchCacheError {
    CargoFetchCacheError::InvalidGitCheckout {
        package: Box::new(package.clone()),
        reason: reason.into(),
    }
}
