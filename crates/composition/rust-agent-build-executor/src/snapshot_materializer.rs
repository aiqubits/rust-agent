use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, FileTimes, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Component, Path, PathBuf},
    time::SystemTime,
};

use rust_agent_composition::{
    canonical,
    snapshot::{
        CanonicalSnapshotEntry, CanonicalSnapshotEntryKind, CanonicalSnapshotError,
        CanonicalSnapshotTree, MAX_CANONICAL_SNAPSHOT_ENTRIES, MAX_CANONICAL_SNAPSHOT_FILE_BYTES,
        MAX_CANONICAL_SNAPSHOT_JSON_BYTES, MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES,
    },
};
#[cfg(target_os = "linux")]
use rustix::fs::{CWD, RenameFlags, renameat_with};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use walkdir::WalkDir;

use crate::{
    CanonicalSnapshotMetadataContract, HostBuildClosureContent, HostBuildClosureItemRole,
    NormalizedHostBuildClosureItem, NormalizedHostBuildInputClosure,
};

const LOGICAL_CLOSURE_ROOT: &str = "/rust-agent/closure";
const LOGICAL_CLOSURE_PREFIX: &str = "/rust-agent/closure/";
const SNAPSHOT_DATA_DIRECTORY: &str = "data";
const SNAPSHOT_MANIFEST_FILE: &str = "rust-agent-host-closure-snapshot.json";
const MAX_SNAPSHOT_ITEMS: usize = 16_384;
const MAX_SNAPSHOT_TOTAL_PATH_BYTES: usize = 16 * 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const PREFLIGHT_FILE_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostClosureSnapshotSource {
    pub item_id: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializedHostClosureItem {
    pub role: HostBuildClosureItemRole,
    pub id: String,
    #[serde(rename = "logical-path")]
    pub logical_path: String,
    #[serde(rename = "closure-item-digest")]
    pub closure_item_digest: String,
    #[serde(rename = "metadata-contract")]
    pub metadata_contract: CanonicalSnapshotMetadataContract,
    pub content: HostBuildClosureContent,
    #[serde(
        rename = "tree-entries",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub tree_entries: Vec<CanonicalSnapshotEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostClosureSnapshotManifest {
    pub schema: u32,
    pub deployable: bool,
    #[serde(rename = "host-build-input-closure-digest")]
    pub host_build_input_closure_digest: String,
    #[serde(rename = "metadata-contract")]
    pub metadata_contract: CanonicalSnapshotMetadataContract,
    pub items: Vec<MaterializedHostClosureItem>,
    #[serde(rename = "data-tree-digest")]
    pub data_tree_digest: String,
    #[serde(rename = "data-tree-entries")]
    pub data_tree_entries: Vec<CanonicalSnapshotEntry>,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostClosureMountObservation {
    pub schema: u32,
    #[serde(rename = "snapshot-manifest-digest")]
    pub snapshot_manifest_digest: String,
    #[serde(rename = "logical-root")]
    pub logical_root: String,
    #[serde(rename = "read-only")]
    pub read_only: bool,
    pub entries: Vec<CanonicalSnapshotEntry>,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedHostClosureSnapshot {
    path: PathBuf,
    manifest: HostClosureSnapshotManifest,
    reused: bool,
}

#[derive(Clone, Debug)]
struct PreparedHostClosureItem {
    item: NormalizedHostBuildClosureItem,
    source: PathBuf,
    content: PreparedHostClosureContent,
}

#[derive(Clone, Debug)]
enum PreparedHostClosureContent {
    File { sha256: String, bytes: u64 },
    SnapshotTree(CanonicalSnapshotTree),
}

#[derive(Clone, Debug)]
struct PreparedHostClosureSnapshot {
    items: Vec<PreparedHostClosureItem>,
    data_tree: CanonicalSnapshotTree,
}

#[derive(Clone, Debug)]
struct PreflightHostClosureItem {
    item: NormalizedHostBuildClosureItem,
    source: PathBuf,
    content: PreflightHostClosureContent,
}

#[derive(Clone, Debug)]
enum PreflightHostClosureContent {
    File(PreflightSourceFile),
    SnapshotTree(PreflightSourceTree),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreflightSourceFile {
    metadata: StableMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreflightSourceTree {
    root_metadata: StableMetadata,
    entries: Vec<PreflightSourceTreeEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreflightSourceTreeEntry {
    path: String,
    directory: bool,
    metadata: StableMetadata,
}

#[derive(Clone, Copy, Debug, Default)]
struct PlannedSnapshotBudget {
    file_bytes: u64,
    path_bytes: usize,
}

#[derive(Debug, Error)]
pub enum SnapshotMaterializationError {
    #[error("snapshot materialization is supported only on the Linux reference Host")]
    UnsupportedHost,
    #[error("snapshot source mappings differ from the exact HostBuildInputClosure item set")]
    SourceSetMismatch,
    #[error("duplicate snapshot source mapping for item `{0}`")]
    DuplicateSource(String),
    #[error("snapshot concrete path must be absolute, normalized and canonical: {0}")]
    InvalidConcretePath(String),
    #[error("snapshot destination parent must already exist as a canonical directory: {0}")]
    InvalidDestinationParent(String),
    #[error("snapshot source kind differs from closure item `{0}`")]
    SourceKindMismatch(String),
    #[error("snapshot source contains a symlink, special file or path escape: {0}")]
    UnsupportedSourceEntry(String),
    #[error("snapshot source changed while it was being materialized: {0}")]
    SourceChanged(String),
    #[error("snapshot source exceeds schema-v1 bounds: {0}")]
    SourceBounds(String),
    #[error("snapshot source digest differs from closure item `{0}`")]
    SourceDigestMismatch(String),
    #[error("snapshot items produce conflicting output at `{0}`")]
    ConflictingOverlay(String),
    #[error("snapshot output already exists with different or invalid content: {0}")]
    DestinationConflict(String),
    #[error("snapshot manifest JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("snapshot manifest or observation JSON exceeds the schema-v1 byte limit")]
    JsonTooLarge,
    #[error("unsupported snapshot manifest schema {0}; expected 1")]
    UnsupportedManifestSchema(u32),
    #[error("snapshot manifest cannot claim deployability")]
    DeployableManifest,
    #[error("snapshot manifest or mount observation digest differs from canonical content")]
    ManifestDigestMismatch,
    #[error("snapshot manifest does not match HostBuildInputClosure")]
    ClosureMismatch,
    #[error("snapshot filesystem contains missing, extra or mutated content")]
    SnapshotContentMismatch,
    #[error("snapshot filesystem does not preserve the local mode/mtime storage projection")]
    StorageMetadataMismatch,
    #[error("mounted snapshot observation differs from the exact canonical view")]
    MountObservationMismatch,
    #[error("canonical snapshot tree is invalid: {0}")]
    SnapshotTree(#[from] CanonicalSnapshotError),
    #[error("canonical snapshot encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
    #[error(
        "snapshot was published at `{path}` but parent-directory durability is unknown: {source}"
    )]
    PublishedDurabilityUnknown {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("snapshot was published at `{0}` but post-publication verification failed")]
    PublishedVerificationFailed(String),
    #[error("snapshot filesystem I/O failed: {0}")]
    Io(#[from] io::Error),
}

impl HostClosureSnapshotManifest {
    pub fn from_json(input: &str) -> Result<Self, SnapshotMaterializationError> {
        if input.len() > MAX_CANONICAL_SNAPSHOT_JSON_BYTES {
            return Err(SnapshotMaterializationError::JsonTooLarge);
        }
        let manifest: Self = serde_json::from_str(input)?;
        manifest.verify_self()?;
        Ok(manifest)
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn expected_mount_observation(
        &self,
    ) -> Result<HostClosureMountObservation, SnapshotMaterializationError> {
        self.verify_self()?;
        let mut observation = HostClosureMountObservation {
            schema: 1,
            snapshot_manifest_digest: self.digest.clone(),
            logical_root: LOGICAL_CLOSURE_ROOT.into(),
            read_only: true,
            entries: self.data_tree_entries.clone(),
            digest: String::new(),
        };
        observation.digest = observation.recompute_digest()?;
        Ok(observation)
    }

    pub fn verify_mount_observation(
        &self,
        observation: &HostClosureMountObservation,
    ) -> Result<(), SnapshotMaterializationError> {
        let expected = self.expected_mount_observation()?;
        observation.verify()?;
        if observation == &expected {
            Ok(())
        } else {
            Err(SnapshotMaterializationError::MountObservationMismatch)
        }
    }

    fn recompute_digest(&self) -> Result<String, SnapshotMaterializationError> {
        Ok(hex::encode(canonical::domain_hash(
            b"rust-agent-host-closure-snapshot-manifest-v1\0",
            &(
                self.schema,
                self.deployable,
                &self.host_build_input_closure_digest,
                self.metadata_contract,
                &self.items,
                &self.data_tree_digest,
                &self.data_tree_entries,
            ),
        )?))
    }

    fn verify_self(&self) -> Result<(), SnapshotMaterializationError> {
        if self.schema != 1 {
            return Err(SnapshotMaterializationError::UnsupportedManifestSchema(
                self.schema,
            ));
        }
        if self.deployable {
            return Err(SnapshotMaterializationError::DeployableManifest);
        }
        if !is_digest(&self.host_build_input_closure_digest)
            || !is_digest(&self.data_tree_digest)
            || self.items.is_empty()
            || self.items.len() > MAX_SNAPSHOT_ITEMS
            || self.metadata_contract != CanonicalSnapshotMetadataContract::ReadOnlyEpochV1
        {
            return Err(SnapshotMaterializationError::ManifestDigestMismatch);
        }
        let data_tree = CanonicalSnapshotTree::from_entries(self.data_tree_entries.clone())?;
        if data_tree.digest() != self.data_tree_digest
            || data_tree.entries() != self.data_tree_entries
        {
            return Err(SnapshotMaterializationError::ManifestDigestMismatch);
        }
        verify_materialized_items(&self.items)?;
        verify_items_against_data_tree(&self.items, &self.data_tree_entries)?;
        if self.digest != self.recompute_digest()? {
            return Err(SnapshotMaterializationError::ManifestDigestMismatch);
        }
        Ok(())
    }

    fn verify_closure(
        &self,
        closure: &NormalizedHostBuildInputClosure,
    ) -> Result<(), SnapshotMaterializationError> {
        self.verify_self()?;
        if self.host_build_input_closure_digest != closure.digest()
            || self.items.len() != closure.items().len()
        {
            return Err(SnapshotMaterializationError::ClosureMismatch);
        }
        for (actual, expected) in self.items.iter().zip(closure.items()) {
            if actual.role != expected.role
                || actual.id != expected.id
                || actual.logical_path != expected.logical_path
                || actual.closure_item_digest != expected.digest
                || actual.metadata_contract != expected.metadata_contract
                || actual.content != expected.content
            {
                return Err(SnapshotMaterializationError::ClosureMismatch);
            }
        }
        verify_items_against_data_tree(&self.items, &self.data_tree_entries)
    }
}

impl HostClosureMountObservation {
    pub fn from_json(input: &str) -> Result<Self, SnapshotMaterializationError> {
        if input.len() > MAX_CANONICAL_SNAPSHOT_JSON_BYTES {
            return Err(SnapshotMaterializationError::JsonTooLarge);
        }
        let observation: Self = serde_json::from_str(input)?;
        observation.verify()?;
        Ok(observation)
    }

    fn recompute_digest(&self) -> Result<String, SnapshotMaterializationError> {
        Ok(hex::encode(canonical::domain_hash(
            b"rust-agent-host-closure-mount-observation-v1\0",
            &(
                self.schema,
                &self.snapshot_manifest_digest,
                &self.logical_root,
                self.read_only,
                &self.entries,
            ),
        )?))
    }

    pub fn verify(&self) -> Result<(), SnapshotMaterializationError> {
        if self.schema != 1
            || !is_digest(&self.snapshot_manifest_digest)
            || self.logical_root != LOGICAL_CLOSURE_ROOT
            || !self.read_only
        {
            return Err(SnapshotMaterializationError::MountObservationMismatch);
        }
        let tree = CanonicalSnapshotTree::from_entries(self.entries.clone())
            .map_err(|_| SnapshotMaterializationError::MountObservationMismatch)?;
        if tree.entries() != self.entries || self.digest != self.recompute_digest()? {
            return Err(SnapshotMaterializationError::MountObservationMismatch);
        }
        Ok(())
    }
}

impl MaterializedHostClosureSnapshot {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn manifest(&self) -> &HostClosureSnapshotManifest {
        &self.manifest
    }

    pub fn reused(&self) -> bool {
        self.reused
    }
}

pub fn materialize_host_closure_snapshot(
    closure: &NormalizedHostBuildInputClosure,
    sources: &[HostClosureSnapshotSource],
    output: &Path,
) -> Result<MaterializedHostClosureSnapshot, SnapshotMaterializationError> {
    require_linux_host()?;
    validate_destination(output)?;
    let prepared = prepare_host_closure_snapshot(closure, sources)?;
    match fs::symlink_metadata(output) {
        Ok(_) => {
            let manifest = verify_host_closure_snapshot(closure, output)?;
            return Ok(MaterializedHostClosureSnapshot {
                path: output.to_owned(),
                manifest,
                reused: true,
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let parent = output.parent().ok_or_else(|| {
        SnapshotMaterializationError::InvalidDestinationParent(output.display().to_string())
    })?;
    let mut staging_guard = tempfile::Builder::new()
        .prefix("rust-agent-snapshot-stage-")
        .tempdir_in(parent)?;
    let staging = staging_guard.path().to_owned();
    let data_root = staging.join(SNAPSHOT_DATA_DIRECTORY);
    fs::create_dir(&data_root)?;

    let mut materialized_items = Vec::with_capacity(prepared.items.len());
    for item in &prepared.items {
        materialized_items.push(materialize_item(item, &data_root)?);
    }
    let data_tree = scan_tree(&data_root)?;
    if data_tree != prepared.data_tree {
        return Err(SnapshotMaterializationError::SnapshotContentMismatch);
    }
    verify_items_against_data_tree(&materialized_items, data_tree.entries())?;

    let mut manifest = HostClosureSnapshotManifest {
        schema: 1,
        deployable: false,
        host_build_input_closure_digest: closure.digest().into(),
        metadata_contract: CanonicalSnapshotMetadataContract::ReadOnlyEpochV1,
        items: materialized_items,
        data_tree_digest: data_tree.digest().into(),
        data_tree_entries: data_tree.entries().to_vec(),
        digest: String::new(),
    };
    manifest.digest = manifest.recompute_digest()?;
    manifest.verify_closure(closure)?;
    write_manifest(&staging, &manifest)?;
    if let Err(error) = seal_local_storage_projection(&staging)
        .and_then(|()| verify_snapshot_filesystem(&manifest, &staging))
        .and_then(|()| sync_snapshot_tree(&staging))
    {
        make_storage_writable(&staging);
        return Err(error);
    }

    match publish_noreplace(&staging, output) {
        Ok(()) => {
            staging_guard.disable_cleanup(true);
            let durability = sync_directory(parent);
            let verification = verify_host_closure_snapshot(closure, output);
            let published = classify_published_result(output, verification, durability)?;
            Ok(MaterializedHostClosureSnapshot {
                path: output.to_owned(),
                manifest: published,
                reused: false,
            })
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            make_storage_writable(&staging);
            let existing = verify_host_closure_snapshot(closure, output).map_err(|_| {
                SnapshotMaterializationError::DestinationConflict(output.display().to_string())
            })?;
            Ok(MaterializedHostClosureSnapshot {
                path: output.to_owned(),
                manifest: existing,
                reused: true,
            })
        }
        Err(error) => {
            make_storage_writable(&staging);
            Err(SnapshotMaterializationError::Io(error))
        }
    }
}

fn classify_published_result<T>(
    output: &Path,
    verification: Result<T, SnapshotMaterializationError>,
    durability: io::Result<()>,
) -> Result<T, SnapshotMaterializationError> {
    let published = verification.map_err(|_| {
        SnapshotMaterializationError::PublishedVerificationFailed(output.display().to_string())
    })?;
    if let Err(source) = durability {
        return Err(SnapshotMaterializationError::PublishedDurabilityUnknown {
            path: output.display().to_string(),
            source,
        });
    }
    Ok(published)
}

pub fn verify_host_closure_snapshot(
    closure: &NormalizedHostBuildInputClosure,
    output: &Path,
) -> Result<HostClosureSnapshotManifest, SnapshotMaterializationError> {
    require_linux_host()?;
    validate_existing_snapshot_path(output)?;
    let manifest_path = output.join(SNAPSHOT_MANIFEST_FILE);
    let bytes = read_bounded_regular_file(&manifest_path, MAX_CANONICAL_SNAPSHOT_JSON_BYTES)?;
    if bytes.is_empty() {
        return Err(SnapshotMaterializationError::SnapshotContentMismatch);
    }
    let manifest: HostClosureSnapshotManifest = serde_json::from_slice(&bytes)?;
    manifest.verify_closure(closure)?;
    verify_snapshot_filesystem(&manifest, output)?;
    Ok(manifest)
}

fn prepare_host_closure_snapshot(
    closure: &NormalizedHostBuildInputClosure,
    sources: &[HostClosureSnapshotSource],
) -> Result<PreparedHostClosureSnapshot, SnapshotMaterializationError> {
    let source_map = normalize_sources(closure, sources)?;
    let mut preflight_entries = BTreeMap::<String, CanonicalSnapshotEntry>::new();
    let mut preflight_budget = PlannedSnapshotBudget::default();
    let mut preflight_items = Vec::with_capacity(closure.items().len());
    let mut total_item_tree_entries = 0_usize;
    let mut total_item_tree_path_bytes = 0_usize;
    let mut total_item_path_bytes = 0_usize;
    let mut total_source_file_bytes = 0_u64;

    // Complete the metadata-only plan for the entire closure before hashing any
    // source. This makes entry, path, per-file and aggregate byte rejection an
    // actual preflight boundary rather than a limit discovered after reading a
    // preceding item.
    for item in closure.items() {
        let source = source_map
            .get(&item.id)
            .expect("the exact source set was checked");
        let relative = logical_relative(&item.logical_path)?;
        total_item_path_bytes = total_item_path_bytes
            .checked_add(item.logical_path.len())
            .ok_or_else(|| SnapshotMaterializationError::SourceBounds(item.id.clone()))?;
        if total_item_path_bytes > MAX_SNAPSHOT_TOTAL_PATH_BYTES {
            return Err(SnapshotMaterializationError::SourceBounds(item.id.clone()));
        }
        insert_planned_ancestors(relative, &mut preflight_entries, &mut preflight_budget)?;
        let preflight_content = match &item.content {
            HostBuildClosureContent::SnapshotTree { tree_digest } => {
                require_source_kind(source, true, &item.id)?;
                let tree = preflight_source_tree(source)?;
                total_item_tree_entries = total_item_tree_entries
                    .checked_add(tree.entries.len())
                    .ok_or_else(|| {
                    SnapshotMaterializationError::SourceBounds(item.id.clone())
                })?;
                if total_item_tree_entries > MAX_CANONICAL_SNAPSHOT_ENTRIES {
                    return Err(SnapshotMaterializationError::SourceBounds(item.id.clone()));
                }
                let tree_path_bytes = tree
                    .entries
                    .iter()
                    .try_fold(0_usize, |total, entry| total.checked_add(entry.path.len()))
                    .ok_or_else(|| SnapshotMaterializationError::SourceBounds(item.id.clone()))?;
                total_item_tree_path_bytes = total_item_tree_path_bytes
                    .checked_add(tree_path_bytes)
                    .ok_or_else(|| SnapshotMaterializationError::SourceBounds(item.id.clone()))?;
                if total_item_tree_path_bytes > MAX_SNAPSHOT_TOTAL_PATH_BYTES {
                    return Err(SnapshotMaterializationError::SourceBounds(item.id.clone()));
                }
                let tree_file_bytes = tree
                    .entries
                    .iter()
                    .filter(|entry| !entry.directory)
                    .try_fold(0_u64, |total, entry| total.checked_add(entry.metadata.len))
                    .ok_or_else(|| SnapshotMaterializationError::SourceBounds(item.id.clone()))?;
                total_source_file_bytes = total_source_file_bytes
                    .checked_add(tree_file_bytes)
                    .ok_or_else(|| SnapshotMaterializationError::SourceBounds(item.id.clone()))?;
                if total_source_file_bytes > MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES {
                    return Err(SnapshotMaterializationError::SourceBounds(item.id.clone()));
                }
                insert_planned_entry(
                    CanonicalSnapshotEntry::directory(relative),
                    &mut preflight_entries,
                    &mut preflight_budget,
                )?;
                for entry in &tree.entries {
                    let path = format!("{relative}/{}", entry.path);
                    let planned = if entry.directory {
                        CanonicalSnapshotEntry::directory(path)
                    } else {
                        CanonicalSnapshotEntry::regular_file(
                            path,
                            PREFLIGHT_FILE_SHA256,
                            entry.metadata.len,
                        )
                    };
                    insert_planned_entry(planned, &mut preflight_entries, &mut preflight_budget)?;
                }
                let _ = tree_digest;
                PreflightHostClosureContent::SnapshotTree(tree)
            }
            content => {
                require_source_kind(source, false, &item.id)?;
                expected_file_digest(content).ok_or_else(|| {
                    SnapshotMaterializationError::SourceKindMismatch(item.id.clone())
                })?;
                let file = preflight_source_file(source)?;
                total_source_file_bytes = total_source_file_bytes
                    .checked_add(file.metadata.len)
                    .ok_or_else(|| SnapshotMaterializationError::SourceBounds(item.id.clone()))?;
                if total_source_file_bytes > MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES {
                    return Err(SnapshotMaterializationError::SourceBounds(item.id.clone()));
                }
                insert_planned_entry(
                    CanonicalSnapshotEntry::regular_file(
                        relative,
                        PREFLIGHT_FILE_SHA256,
                        file.metadata.len,
                    ),
                    &mut preflight_entries,
                    &mut preflight_budget,
                )?;
                PreflightHostClosureContent::File(file)
            }
        };
        preflight_items.push(PreflightHostClosureItem {
            item: item.clone(),
            source: (*source).to_owned(),
            content: preflight_content,
        });
    }

    CanonicalSnapshotTree::from_entries(preflight_entries.into_values().collect())?;

    let mut planned_entries = BTreeMap::<String, CanonicalSnapshotEntry>::new();
    let mut planned_budget = PlannedSnapshotBudget::default();
    let mut prepared_items = Vec::with_capacity(preflight_items.len());
    for preflight in preflight_items {
        let relative = logical_relative(&preflight.item.logical_path)?;
        insert_planned_ancestors(relative, &mut planned_entries, &mut planned_budget)?;
        let prepared_content = match preflight.content {
            PreflightHostClosureContent::SnapshotTree(tree_plan) => {
                let tree = hash_preflighted_tree(&preflight.source, &tree_plan)?;
                let HostBuildClosureContent::SnapshotTree { tree_digest } = &preflight.item.content
                else {
                    return Err(SnapshotMaterializationError::SourceKindMismatch(
                        preflight.item.id,
                    ));
                };
                if tree.digest() != tree_digest {
                    return Err(SnapshotMaterializationError::SourceDigestMismatch(
                        preflight.item.id.clone(),
                    ));
                }
                insert_planned_entry(
                    CanonicalSnapshotEntry::directory(relative),
                    &mut planned_entries,
                    &mut planned_budget,
                )?;
                for entry in tree.entries() {
                    let mut planned = entry.clone();
                    planned.path = format!("{relative}/{}", entry.path);
                    insert_planned_entry(planned, &mut planned_entries, &mut planned_budget)?;
                }
                PreparedHostClosureContent::SnapshotTree(tree)
            }
            PreflightHostClosureContent::File(file_plan) => {
                let expected = expected_file_digest(&preflight.item.content).ok_or_else(|| {
                    SnapshotMaterializationError::SourceKindMismatch(preflight.item.id.clone())
                })?;
                let (actual, bytes) = hash_preflighted_file(&preflight.source, &file_plan)?;
                if actual != expected {
                    return Err(SnapshotMaterializationError::SourceDigestMismatch(
                        preflight.item.id.clone(),
                    ));
                }
                insert_planned_entry(
                    CanonicalSnapshotEntry::regular_file(relative, expected, bytes),
                    &mut planned_entries,
                    &mut planned_budget,
                )?;
                PreparedHostClosureContent::File {
                    sha256: expected.into(),
                    bytes,
                }
            }
        };
        prepared_items.push(PreparedHostClosureItem {
            item: preflight.item,
            source: preflight.source,
            content: prepared_content,
        });
    }

    let data_tree = CanonicalSnapshotTree::from_entries(planned_entries.into_values().collect())?;
    Ok(PreparedHostClosureSnapshot {
        items: prepared_items,
        data_tree,
    })
}

fn insert_planned_ancestors(
    relative: &str,
    planned: &mut BTreeMap<String, CanonicalSnapshotEntry>,
    budget: &mut PlannedSnapshotBudget,
) -> Result<(), SnapshotMaterializationError> {
    let components = relative.split('/').collect::<Vec<_>>();
    for end in 1..components.len() {
        insert_planned_entry(
            CanonicalSnapshotEntry::directory(components[..end].join("/")),
            planned,
            budget,
        )?;
    }
    Ok(())
}

fn insert_planned_entry(
    entry: CanonicalSnapshotEntry,
    planned: &mut BTreeMap<String, CanonicalSnapshotEntry>,
    budget: &mut PlannedSnapshotBudget,
) -> Result<(), SnapshotMaterializationError> {
    if let Some(existing) = planned.get(&entry.path) {
        if existing == &entry {
            return Ok(());
        }
        return Err(SnapshotMaterializationError::ConflictingOverlay(entry.path));
    }
    let file_bytes = match &entry.kind {
        CanonicalSnapshotEntryKind::Directory => 0,
        CanonicalSnapshotEntryKind::RegularFile { bytes, .. } => *bytes,
    };
    let next_file_bytes = budget
        .file_bytes
        .checked_add(file_bytes)
        .ok_or_else(|| SnapshotMaterializationError::SourceBounds(entry.path.clone()))?;
    let next_path_bytes = budget
        .path_bytes
        .checked_add(entry.path.len())
        .ok_or_else(|| SnapshotMaterializationError::SourceBounds(entry.path.clone()))?;
    if planned.len() == MAX_CANONICAL_SNAPSHOT_ENTRIES
        || next_file_bytes > MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES
        || next_path_bytes > MAX_SNAPSHOT_TOTAL_PATH_BYTES
    {
        return Err(SnapshotMaterializationError::SourceBounds(entry.path));
    }
    budget.file_bytes = next_file_bytes;
    budget.path_bytes = next_path_bytes;
    planned.insert(entry.path.clone(), entry);
    Ok(())
}

fn materialize_item(
    prepared: &PreparedHostClosureItem,
    data_root: &Path,
) -> Result<MaterializedHostClosureItem, SnapshotMaterializationError> {
    let item = &prepared.item;
    let relative = logical_relative(&item.logical_path)?;
    let destination = data_root.join(relative);
    let tree_entries = match &prepared.content {
        PreparedHostClosureContent::SnapshotTree(tree) => {
            ensure_parent_directories(data_root, &destination)?;
            ensure_directory_overlay(&destination)?;
            copy_tree(&prepared.source, &destination, tree)?;
            tree.entries().to_vec()
        }
        PreparedHostClosureContent::File { sha256, bytes } => {
            ensure_parent_directories(data_root, &destination)?;
            copy_file_overlay(&prepared.source, &destination, sha256, *bytes)?;
            Vec::new()
        }
    };
    Ok(MaterializedHostClosureItem {
        role: item.role,
        id: item.id.clone(),
        logical_path: item.logical_path.clone(),
        closure_item_digest: item.digest.clone(),
        metadata_contract: item.metadata_contract,
        content: item.content.clone(),
        tree_entries,
    })
}

fn normalize_sources<'a>(
    closure: &NormalizedHostBuildInputClosure,
    sources: &'a [HostClosureSnapshotSource],
) -> Result<BTreeMap<String, &'a Path>, SnapshotMaterializationError> {
    if sources.len() != closure.items().len() || sources.len() > MAX_SNAPSHOT_ITEMS {
        return Err(SnapshotMaterializationError::SourceSetMismatch);
    }
    let expected: BTreeSet<_> = closure
        .items()
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    let mut normalized = BTreeMap::new();
    for source in sources {
        if normalized
            .insert(source.item_id.clone(), source.path.as_path())
            .is_some()
        {
            return Err(SnapshotMaterializationError::DuplicateSource(
                source.item_id.clone(),
            ));
        }
        validate_source_path(&source.path)?;
    }
    let actual: BTreeSet<_> = normalized.keys().map(String::as_str).collect();
    if actual != expected {
        return Err(SnapshotMaterializationError::SourceSetMismatch);
    }
    Ok(normalized)
}

fn require_source_kind(
    source: &Path,
    directory: bool,
    item_id: &str,
) -> Result<(), SnapshotMaterializationError> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        Err(SnapshotMaterializationError::SourceKindMismatch(
            item_id.into(),
        ))
    } else {
        Ok(())
    }
}

fn require_linux_host() -> Result<(), SnapshotMaterializationError> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err(SnapshotMaterializationError::UnsupportedHost)
    }
}

fn validate_destination(output: &Path) -> Result<(), SnapshotMaterializationError> {
    if !is_normalized_absolute_path(output) || output.file_name().is_none() {
        return Err(SnapshotMaterializationError::InvalidDestinationParent(
            output.display().to_string(),
        ));
    }
    let parent = output.parent().ok_or_else(|| {
        SnapshotMaterializationError::InvalidDestinationParent(output.display().to_string())
    })?;
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || fs::canonicalize(parent)? != parent
    {
        return Err(SnapshotMaterializationError::InvalidDestinationParent(
            parent.display().to_string(),
        ));
    }
    Ok(())
}

fn validate_existing_snapshot_path(output: &Path) -> Result<(), SnapshotMaterializationError> {
    validate_destination(output)?;
    let metadata = fs::symlink_metadata(output)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || fs::canonicalize(output)? != output
    {
        return Err(SnapshotMaterializationError::DestinationConflict(
            output.display().to_string(),
        ));
    }
    Ok(())
}

fn validate_source_path(source: &Path) -> Result<(), SnapshotMaterializationError> {
    if !is_normalized_absolute_path(source) {
        return Err(SnapshotMaterializationError::InvalidConcretePath(
            source.display().to_string(),
        ));
    }
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() || fs::canonicalize(source)? != source {
        return Err(SnapshotMaterializationError::InvalidConcretePath(
            source.display().to_string(),
        ));
    }
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(SnapshotMaterializationError::UnsupportedSourceEntry(
            source.display().to_string(),
        ));
    }
    Ok(())
}

fn is_normalized_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().enumerate().all(|(index, component)| {
            (index == 0 && matches!(component, Component::RootDir))
                || (index > 0 && matches!(component, Component::Normal(_)))
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StableMetadata {
    len: u64,
    modified: SystemTime,
    readonly: bool,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    links: u64,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
    #[cfg(unix)]
    mtime: i64,
    #[cfg(unix)]
    mtime_nanos: i64,
    #[cfg(unix)]
    ctime: i64,
    #[cfg(unix)]
    ctime_nanos: i64,
}

fn stable_metadata(metadata: &fs::Metadata) -> io::Result<StableMetadata> {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    Ok(StableMetadata {
        len: metadata.len(),
        modified: metadata.modified()?,
        readonly: metadata.permissions().readonly(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        mode: metadata.mode(),
        #[cfg(unix)]
        links: metadata.nlink(),
        #[cfg(unix)]
        uid: metadata.uid(),
        #[cfg(unix)]
        gid: metadata.gid(),
        #[cfg(unix)]
        mtime: metadata.mtime(),
        #[cfg(unix)]
        mtime_nanos: metadata.mtime_nsec(),
        #[cfg(unix)]
        ctime: metadata.ctime(),
        #[cfg(unix)]
        ctime_nanos: metadata.ctime_nsec(),
    })
}

fn preflight_source_file(
    source: &Path,
) -> Result<PreflightSourceFile, SnapshotMaterializationError> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SnapshotMaterializationError::UnsupportedSourceEntry(
            source.display().to_string(),
        ));
    }
    if metadata.len() > MAX_CANONICAL_SNAPSHOT_FILE_BYTES {
        return Err(SnapshotMaterializationError::SourceBounds(
            source.display().to_string(),
        ));
    }
    Ok(PreflightSourceFile {
        metadata: stable_metadata(&metadata)?,
    })
}

fn hash_preflighted_file(
    source: &Path,
    plan: &PreflightSourceFile,
) -> Result<(String, u64), SnapshotMaterializationError> {
    if preflight_source_file(source)? != *plan {
        return Err(SnapshotMaterializationError::SourceChanged(
            source.display().to_string(),
        ));
    }
    let result = hash_source_file(source, Some(plan.metadata.len))?;
    if preflight_source_file(source)? != *plan {
        return Err(SnapshotMaterializationError::SourceChanged(
            source.display().to_string(),
        ));
    }
    Ok(result)
}

fn preflight_source_tree(root: &Path) -> Result<PreflightSourceTree, SnapshotMaterializationError> {
    let root_metadata = fs::symlink_metadata(root)?;
    if root_metadata.file_type().is_symlink()
        || !root_metadata.is_dir()
        || fs::canonicalize(root)? != root
    {
        return Err(SnapshotMaterializationError::UnsupportedSourceEntry(
            root.display().to_string(),
        ));
    }
    let root_before = stable_metadata(&root_metadata)?;
    let mut canonical_entries = Vec::new();
    let mut entries_by_path = BTreeMap::new();
    let mut total_file_bytes = 0_u64;
    let mut total_path_bytes = 0_usize;
    for entry in WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .skip(1)
    {
        let entry = entry.map_err(io::Error::other)?;
        if canonical_entries.len() == MAX_CANONICAL_SNAPSHOT_ENTRIES {
            return Err(SnapshotMaterializationError::SourceBounds(
                root.display().to_string(),
            ));
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink()
            || (!metadata.is_dir() && !metadata.is_file())
            || fs::canonicalize(path)?.strip_prefix(root).is_err()
        {
            return Err(SnapshotMaterializationError::UnsupportedSourceEntry(
                path.display().to_string(),
            ));
        }
        let relative = path.strip_prefix(root).map_err(|_| {
            SnapshotMaterializationError::UnsupportedSourceEntry(path.display().to_string())
        })?;
        let relative = relative.to_str().ok_or_else(|| {
            SnapshotMaterializationError::UnsupportedSourceEntry(path.display().to_string())
        })?;
        let relative = relative.replace(std::path::MAIN_SEPARATOR, "/");
        total_path_bytes = total_path_bytes
            .checked_add(relative.len())
            .ok_or_else(|| SnapshotMaterializationError::SourceBounds(relative.clone()))?;
        if total_path_bytes > MAX_SNAPSHOT_TOTAL_PATH_BYTES {
            return Err(SnapshotMaterializationError::SourceBounds(relative));
        }
        let stable = stable_metadata(&metadata)?;
        let directory = metadata.is_dir();
        if directory {
            canonical_entries.push(CanonicalSnapshotEntry::directory(relative.clone()));
        } else {
            if metadata.len() > MAX_CANONICAL_SNAPSHOT_FILE_BYTES {
                return Err(SnapshotMaterializationError::SourceBounds(
                    path.display().to_string(),
                ));
            }
            total_file_bytes = total_file_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| {
                    SnapshotMaterializationError::SourceBounds(path.display().to_string())
                })?;
            if total_file_bytes > MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES {
                return Err(SnapshotMaterializationError::SourceBounds(
                    path.display().to_string(),
                ));
            }
            canonical_entries.push(CanonicalSnapshotEntry::regular_file(
                relative.clone(),
                PREFLIGHT_FILE_SHA256,
                metadata.len(),
            ));
        }
        entries_by_path.insert(
            relative.clone(),
            PreflightSourceTreeEntry {
                path: relative,
                directory,
                metadata: stable,
            },
        );
    }
    if stable_metadata(&fs::symlink_metadata(root)?)? != root_before {
        return Err(SnapshotMaterializationError::SourceChanged(
            root.display().to_string(),
        ));
    }
    let canonical = CanonicalSnapshotTree::from_entries(canonical_entries)?;
    let entries = canonical
        .entries()
        .iter()
        .map(|entry| {
            entries_by_path.remove(&entry.path).ok_or_else(|| {
                SnapshotMaterializationError::SourceChanged(root.display().to_string())
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !entries_by_path.is_empty() {
        return Err(SnapshotMaterializationError::SourceChanged(
            root.display().to_string(),
        ));
    }
    Ok(PreflightSourceTree {
        root_metadata: root_before,
        entries,
    })
}

fn hash_preflighted_tree(
    root: &Path,
    plan: &PreflightSourceTree,
) -> Result<CanonicalSnapshotTree, SnapshotMaterializationError> {
    if preflight_source_tree(root)? != *plan {
        return Err(SnapshotMaterializationError::SourceChanged(
            root.display().to_string(),
        ));
    }
    let mut entries = Vec::with_capacity(plan.entries.len());
    for entry in &plan.entries {
        let path = root.join(&entry.path);
        if entry.directory {
            entries.push(CanonicalSnapshotEntry::directory(entry.path.clone()));
        } else {
            let (sha256, bytes) = hash_source_file(&path, Some(entry.metadata.len))?;
            entries.push(CanonicalSnapshotEntry::regular_file(
                entry.path.clone(),
                sha256,
                bytes,
            ));
        }
    }
    if preflight_source_tree(root)? != *plan {
        return Err(SnapshotMaterializationError::SourceChanged(
            root.display().to_string(),
        ));
    }
    Ok(CanonicalSnapshotTree::from_entries(entries)?)
}

fn scan_tree(root: &Path) -> Result<CanonicalSnapshotTree, SnapshotMaterializationError> {
    let plan = preflight_source_tree(root)?;
    hash_preflighted_tree(root, &plan)
}

fn hash_source_file(
    source: &Path,
    expected_bytes: Option<u64>,
) -> Result<(String, u64), SnapshotMaterializationError> {
    let path_metadata = fs::symlink_metadata(source)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(SnapshotMaterializationError::UnsupportedSourceEntry(
            source.display().to_string(),
        ));
    }
    if path_metadata.len() > MAX_CANONICAL_SNAPSHOT_FILE_BYTES
        || expected_bytes.is_some_and(|expected| expected != path_metadata.len())
    {
        return Err(SnapshotMaterializationError::SourceBounds(
            source.display().to_string(),
        ));
    }
    let before = stable_metadata(&path_metadata)?;
    let file = File::open(source)?;
    if stable_metadata(&file.metadata()?)? != before {
        return Err(SnapshotMaterializationError::SourceChanged(
            source.display().to_string(),
        ));
    }
    let mut reader = BufReader::new(file);
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut bytes = 0_u64;
    let mut hasher = Sha256::new();
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes = bytes.checked_add(read as u64).ok_or_else(|| {
            SnapshotMaterializationError::SourceBounds(source.display().to_string())
        })?;
        if bytes > MAX_CANONICAL_SNAPSHOT_FILE_BYTES {
            return Err(SnapshotMaterializationError::SourceBounds(
                source.display().to_string(),
            ));
        }
        hasher.update(&buffer[..read]);
    }
    let handle_after = stable_metadata(&reader.get_ref().metadata()?)?;
    let path_after = stable_metadata(&fs::symlink_metadata(source)?)?;
    if before != handle_after
        || before != path_after
        || bytes != before.len
        || expected_bytes.is_some_and(|expected| expected != bytes)
    {
        return Err(SnapshotMaterializationError::SourceChanged(
            source.display().to_string(),
        ));
    }
    Ok((hex::encode(hasher.finalize()), bytes))
}

fn read_bounded_regular_file(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, SnapshotMaterializationError> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(SnapshotMaterializationError::SnapshotContentMismatch);
    }
    if path_metadata.len() > maximum as u64 {
        return Err(SnapshotMaterializationError::JsonTooLarge);
    }
    let before = stable_metadata(&path_metadata)?;
    let file = File::open(path)?;
    if stable_metadata(&file.metadata()?)? != before {
        return Err(SnapshotMaterializationError::SnapshotContentMismatch);
    }
    let mut reader = BufReader::new(file).take(maximum as u64 + 1);
    let capacity = usize::try_from(path_metadata.len())
        .map_err(|_| SnapshotMaterializationError::JsonTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);
    reader.read_to_end(&mut bytes)?;
    let reader = reader.into_inner();
    let handle_after = stable_metadata(&reader.get_ref().metadata()?)?;
    let path_after = stable_metadata(&fs::symlink_metadata(path)?)?;
    if bytes.len() > maximum
        || before != handle_after
        || before != path_after
        || bytes.len() as u64 != before.len
    {
        return Err(SnapshotMaterializationError::SnapshotContentMismatch);
    }
    Ok(bytes)
}

fn ensure_parent_directories(
    root: &Path,
    destination: &Path,
) -> Result<(), SnapshotMaterializationError> {
    let parent = destination.parent().ok_or_else(|| {
        SnapshotMaterializationError::ConflictingOverlay(destination.display().to_string())
    })?;
    let relative = parent.strip_prefix(root).map_err(|_| {
        SnapshotMaterializationError::ConflictingOverlay(destination.display().to_string())
    })?;
    let mut current = root.to_owned();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(SnapshotMaterializationError::ConflictingOverlay(
                destination.display().to_string(),
            ));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_dir() => {}
            Ok(_) => {
                return Err(SnapshotMaterializationError::ConflictingOverlay(
                    current.display().to_string(),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir(&current)?,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn ensure_directory_overlay(path: &Path) -> Result<(), SnapshotMaterializationError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_dir() => Ok(()),
        Ok(_) => Err(SnapshotMaterializationError::ConflictingOverlay(
            path.display().to_string(),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn copy_tree(
    source: &Path,
    destination: &Path,
    expected: &CanonicalSnapshotTree,
) -> Result<(), SnapshotMaterializationError> {
    for entry in expected.entries() {
        let source_path = source.join(&entry.path);
        let destination_path = destination.join(&entry.path);
        ensure_parent_directories(destination, &destination_path)?;
        match &entry.kind {
            CanonicalSnapshotEntryKind::Directory => {
                ensure_directory_overlay(&destination_path)?;
            }
            CanonicalSnapshotEntryKind::RegularFile { sha256, bytes } => {
                copy_file_overlay(&source_path, &destination_path, sha256, *bytes)?;
            }
        }
    }
    if scan_tree(source)? != *expected {
        return Err(SnapshotMaterializationError::SourceChanged(
            source.display().to_string(),
        ));
    }
    verify_declared_tree_entries(destination, expected)?;
    Ok(())
}

fn verify_declared_tree_entries(
    root: &Path,
    expected: &CanonicalSnapshotTree,
) -> Result<(), SnapshotMaterializationError> {
    let root_metadata = fs::symlink_metadata(root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(SnapshotMaterializationError::SnapshotContentMismatch);
    }
    for entry in expected.entries() {
        let path = root.join(&entry.path);
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(SnapshotMaterializationError::SnapshotContentMismatch);
        }
        match &entry.kind {
            CanonicalSnapshotEntryKind::Directory if metadata.is_dir() => {}
            CanonicalSnapshotEntryKind::RegularFile { sha256, bytes }
                if metadata.is_file() && metadata.len() == *bytes =>
            {
                let (actual_sha256, actual_bytes) = hash_source_file(&path, Some(*bytes))?;
                if actual_sha256 != *sha256 || actual_bytes != *bytes {
                    return Err(SnapshotMaterializationError::SnapshotContentMismatch);
                }
            }
            _ => return Err(SnapshotMaterializationError::SnapshotContentMismatch),
        }
    }
    Ok(())
}

fn copy_file_overlay(
    source: &Path,
    destination: &Path,
    expected_digest: &str,
    expected_bytes: u64,
) -> Result<(), SnapshotMaterializationError> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_file() => {
            if metadata.len() != expected_bytes {
                return Err(SnapshotMaterializationError::ConflictingOverlay(
                    destination.display().to_string(),
                ));
            }
            let (digest, bytes) =
                hash_source_file(destination, Some(expected_bytes)).map_err(|_| {
                    SnapshotMaterializationError::ConflictingOverlay(
                        destination.display().to_string(),
                    )
                })?;
            if digest == expected_digest && bytes == expected_bytes {
                return Ok(());
            }
            return Err(SnapshotMaterializationError::ConflictingOverlay(
                destination.display().to_string(),
            ));
        }
        Ok(_) => {
            return Err(SnapshotMaterializationError::ConflictingOverlay(
                destination.display().to_string(),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let source_metadata = fs::symlink_metadata(source)?;
    if source_metadata.file_type().is_symlink()
        || !source_metadata.is_file()
        || source_metadata.len() != expected_bytes
        || expected_bytes > MAX_CANONICAL_SNAPSHOT_FILE_BYTES
    {
        return Err(SnapshotMaterializationError::UnsupportedSourceEntry(
            source.display().to_string(),
        ));
    }
    let before = stable_metadata(&source_metadata)?;
    let source_file = File::open(source)?;
    if stable_metadata(&source_file.metadata()?)? != before {
        return Err(SnapshotMaterializationError::SourceChanged(
            source.display().to_string(),
        ));
    }
    let mut reader = BufReader::new(source_file);
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut bytes = 0_u64;
    let mut hasher = Sha256::new();
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes = bytes.checked_add(read as u64).ok_or_else(|| {
            SnapshotMaterializationError::SourceBounds(source.display().to_string())
        })?;
        if bytes > MAX_CANONICAL_SNAPSHOT_FILE_BYTES {
            return Err(SnapshotMaterializationError::SourceBounds(
                source.display().to_string(),
            ));
        }
        hasher.update(&buffer[..read]);
        destination_file.write_all(&buffer[..read])?;
    }
    destination_file.flush()?;
    let digest = hex::encode(hasher.finalize());
    let handle_after = stable_metadata(&reader.get_ref().metadata()?)?;
    let path_after = stable_metadata(&fs::symlink_metadata(source)?)?;
    if before != handle_after
        || before != path_after
        || bytes != expected_bytes
        || digest != expected_digest
    {
        return Err(SnapshotMaterializationError::SourceChanged(
            source.display().to_string(),
        ));
    }
    Ok(())
}

fn expected_file_digest(content: &HostBuildClosureContent) -> Option<&str> {
    match content {
        HostBuildClosureContent::File { sha256 } => Some(sha256),
        HostBuildClosureContent::CanonicalRecord { bytes_sha256, .. } => Some(bytes_sha256),
        HostBuildClosureContent::SignedEvidence { bytes_digest, .. } => Some(bytes_digest),
        HostBuildClosureContent::SnapshotTree { .. } => None,
    }
}

fn verify_materialized_items(
    items: &[MaterializedHostClosureItem],
) -> Result<(), SnapshotMaterializationError> {
    if items.is_empty() || items.len() > MAX_SNAPSHOT_ITEMS {
        return Err(SnapshotMaterializationError::ManifestDigestMismatch);
    }
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut folded_paths = BTreeSet::new();
    let mut previous: Option<(HostBuildClosureItemRole, &str, &str)> = None;
    let mut total_tree_entries = 0_usize;
    let mut total_tree_path_bytes = 0_usize;
    let mut total_item_path_bytes = 0_usize;
    for item in items {
        let key = (item.role, item.id.as_str(), item.logical_path.as_str());
        if previous.is_some_and(|previous| previous >= key)
            || !ids.insert(item.id.as_str())
            || !paths.insert(item.logical_path.as_str())
            || !folded_paths.insert(item.logical_path.to_ascii_lowercase())
            || item.metadata_contract != CanonicalSnapshotMetadataContract::ReadOnlyEpochV1
            || logical_relative(&item.logical_path).is_err()
            || !is_digest(&item.closure_item_digest)
            || !content_has_valid_digests(&item.content)
        {
            return Err(SnapshotMaterializationError::ManifestDigestMismatch);
        }
        previous = Some(key);
        total_item_path_bytes = total_item_path_bytes
            .checked_add(item.logical_path.len())
            .ok_or(SnapshotMaterializationError::ManifestDigestMismatch)?;
        total_tree_entries = total_tree_entries
            .checked_add(item.tree_entries.len())
            .ok_or(SnapshotMaterializationError::ManifestDigestMismatch)?;
        let item_tree_path_bytes = item
            .tree_entries
            .iter()
            .try_fold(0_usize, |total, entry| total.checked_add(entry.path.len()))
            .ok_or(SnapshotMaterializationError::ManifestDigestMismatch)?;
        total_tree_path_bytes = total_tree_path_bytes
            .checked_add(item_tree_path_bytes)
            .ok_or(SnapshotMaterializationError::ManifestDigestMismatch)?;
        if total_tree_entries > MAX_CANONICAL_SNAPSHOT_ENTRIES
            || total_tree_path_bytes > MAX_SNAPSHOT_TOTAL_PATH_BYTES
            || total_item_path_bytes > MAX_SNAPSHOT_TOTAL_PATH_BYTES
        {
            return Err(SnapshotMaterializationError::ManifestDigestMismatch);
        }

        match &item.content {
            HostBuildClosureContent::SnapshotTree { tree_digest } => {
                let tree = CanonicalSnapshotTree::from_entries(item.tree_entries.clone())?;
                if tree.digest() != tree_digest || tree.entries() != item.tree_entries {
                    return Err(SnapshotMaterializationError::ManifestDigestMismatch);
                }
            }
            _ if !item.tree_entries.is_empty() => {
                return Err(SnapshotMaterializationError::ManifestDigestMismatch);
            }
            _ => {}
        }
        let expected_item_digest = hex::encode(canonical::domain_hash(
            b"rust-agent-host-build-closure-item-v1\0",
            &(
                item.role,
                &item.id,
                &item.logical_path,
                item.metadata_contract,
                &item.content,
            ),
        )?);
        if item.closure_item_digest != expected_item_digest {
            return Err(SnapshotMaterializationError::ManifestDigestMismatch);
        }
    }
    Ok(())
}

fn verify_items_against_data_tree(
    items: &[MaterializedHostClosureItem],
    data_entries: &[CanonicalSnapshotEntry],
) -> Result<(), SnapshotMaterializationError> {
    let data_by_path: BTreeMap<_, _> = data_entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let mut claimed = BTreeSet::new();
    for item in items {
        let relative = logical_relative(&item.logical_path)?;
        match &item.content {
            HostBuildClosureContent::SnapshotTree { tree_digest } => {
                let Some(base) = data_by_path.get(relative).copied() else {
                    return Err(SnapshotMaterializationError::SnapshotContentMismatch);
                };
                if !matches!(base.kind, CanonicalSnapshotEntryKind::Directory) {
                    return Err(SnapshotMaterializationError::SnapshotContentMismatch);
                }
                claim_path_and_ancestors(&base.path, &mut claimed);
                let tree = CanonicalSnapshotTree::from_entries(item.tree_entries.clone())?;
                if tree.digest() != tree_digest || tree.entries() != item.tree_entries {
                    return Err(SnapshotMaterializationError::SnapshotContentMismatch);
                }
                for declared in tree.entries() {
                    let global_path = format!("{relative}/{}", declared.path);
                    let Some(actual) = data_by_path.get(global_path.as_str()).copied() else {
                        return Err(SnapshotMaterializationError::SnapshotContentMismatch);
                    };
                    let mut expected = declared.clone();
                    expected.path = global_path;
                    if actual != &expected {
                        return Err(SnapshotMaterializationError::SnapshotContentMismatch);
                    }
                    claim_path_and_ancestors(&actual.path, &mut claimed);
                }
            }
            content => {
                let expected_digest = expected_file_digest(content)
                    .ok_or(SnapshotMaterializationError::SnapshotContentMismatch)?;
                let Some(entry) = data_by_path.get(relative).copied() else {
                    return Err(SnapshotMaterializationError::SnapshotContentMismatch);
                };
                if !matches!(
                    &entry.kind,
                    CanonicalSnapshotEntryKind::RegularFile { sha256, .. }
                        if sha256 == expected_digest
                ) {
                    return Err(SnapshotMaterializationError::SnapshotContentMismatch);
                }
                claim_path_and_ancestors(&entry.path, &mut claimed);
            }
        }
    }
    if data_by_path.keys().copied().collect::<BTreeSet<_>>() != claimed {
        return Err(SnapshotMaterializationError::SnapshotContentMismatch);
    }
    Ok(())
}

fn claim_path_and_ancestors<'a>(path: &'a str, claimed: &mut BTreeSet<&'a str>) {
    claimed.insert(path);
    let mut cursor = path;
    while let Some((parent, _)) = cursor.rsplit_once('/') {
        claimed.insert(parent);
        cursor = parent;
    }
}

fn logical_relative(logical_path: &str) -> Result<&str, SnapshotMaterializationError> {
    let relative = logical_path
        .strip_prefix(LOGICAL_CLOSURE_PREFIX)
        .ok_or_else(|| SnapshotMaterializationError::UnsupportedSourceEntry(logical_path.into()))?;
    if logical_path.len() > 4_096
        || relative.is_empty()
        || !relative.is_ascii()
        || relative
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || byte == b'\\')
        || relative.split('/').any(|component| {
            component.is_empty() || component.len() > 255 || matches!(component, "." | "..")
        })
    {
        return Err(SnapshotMaterializationError::UnsupportedSourceEntry(
            logical_path.into(),
        ));
    }
    Ok(relative)
}

fn content_has_valid_digests(content: &HostBuildClosureContent) -> bool {
    match content {
        HostBuildClosureContent::File { sha256 } => is_digest(sha256),
        HostBuildClosureContent::SnapshotTree { tree_digest } => is_digest(tree_digest),
        HostBuildClosureContent::CanonicalRecord {
            digest,
            bytes_sha256,
        } => is_digest(digest) && is_digest(bytes_sha256),
        HostBuildClosureContent::SignedEvidence {
            bytes_digest,
            reviewer_policy,
            reviewer_policy_digest,
            signature_set_digest,
        } => {
            is_digest(bytes_digest)
                && !reviewer_policy.is_empty()
                && reviewer_policy.is_ascii()
                && is_digest(reviewer_policy_digest)
                && is_digest(signature_set_digest)
        }
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn write_manifest(
    staging: &Path,
    manifest: &HostClosureSnapshotManifest,
) -> Result<(), SnapshotMaterializationError> {
    let bytes = canonical::jcs_bytes(manifest)?;
    if bytes.len() > MAX_CANONICAL_SNAPSHOT_JSON_BYTES {
        return Err(SnapshotMaterializationError::JsonTooLarge);
    }
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(staging.join(SNAPSHOT_MANIFEST_FILE))?;
    let mut writer = BufWriter::new(file);
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

fn seal_local_storage_projection(root: &Path) -> Result<(), SnapshotMaterializationError> {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let mut directories = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(io::Error::other)?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
            return Err(SnapshotMaterializationError::UnsupportedSourceEntry(
                entry.path().display().to_string(),
            ));
        }
        if metadata.is_dir() {
            directories.push(entry.path().to_owned());
        } else {
            set_epoch_times(entry.path())?;
            #[cfg(unix)]
            fs::set_permissions(
                entry.path(),
                fs::Permissions::from_mode(
                    rust_agent_composition::snapshot::READ_ONLY_EPOCH_V1_FILE_MODE,
                ),
            )?;
        }
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        set_epoch_times(&directory)?;
        #[cfg(unix)]
        fs::set_permissions(
            &directory,
            fs::Permissions::from_mode(
                rust_agent_composition::snapshot::READ_ONLY_EPOCH_V1_DIRECTORY_MODE,
            ),
        )?;
    }
    Ok(())
}

fn set_epoch_times(path: &Path) -> io::Result<()> {
    let file = File::open(path)?;
    file.set_times(
        FileTimes::new()
            .set_accessed(SystemTime::UNIX_EPOCH)
            .set_modified(SystemTime::UNIX_EPOCH),
    )
}

fn verify_snapshot_filesystem(
    manifest: &HostClosureSnapshotManifest,
    root: &Path,
) -> Result<(), SnapshotMaterializationError> {
    validate_existing_snapshot_path(root)?;
    verify_local_storage_projection(root, true)?;
    let manifest_path = root.join(SNAPSHOT_MANIFEST_FILE);
    let data_root = root.join(SNAPSHOT_DATA_DIRECTORY);
    let expected_manifest_bytes = canonical::jcs_bytes(manifest)?;
    if read_bounded_regular_file(&manifest_path, MAX_CANONICAL_SNAPSHOT_JSON_BYTES)?
        != expected_manifest_bytes
    {
        return Err(SnapshotMaterializationError::SnapshotContentMismatch);
    }

    let mut expected_paths = BTreeMap::new();
    expected_paths.insert(SNAPSHOT_DATA_DIRECTORY.to_owned(), true);
    expected_paths.insert(SNAPSHOT_MANIFEST_FILE.to_owned(), false);
    for entry in &manifest.data_tree_entries {
        expected_paths.insert(
            format!("{SNAPSHOT_DATA_DIRECTORY}/{}", entry.path),
            matches!(entry.kind, CanonicalSnapshotEntryKind::Directory),
        );
    }
    let mut actual_paths = BTreeMap::new();
    for entry in WalkDir::new(root).follow_links(false).into_iter().skip(1) {
        if actual_paths.len() == expected_paths.len() {
            return Err(SnapshotMaterializationError::SnapshotContentMismatch);
        }
        let entry = entry.map_err(io::Error::other)?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink()
            || (!metadata.is_dir() && !metadata.is_file())
            || fs::canonicalize(entry.path())?.strip_prefix(root).is_err()
        {
            return Err(SnapshotMaterializationError::SnapshotContentMismatch);
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| SnapshotMaterializationError::SnapshotContentMismatch)?;
        let relative = relative
            .to_str()
            .ok_or(SnapshotMaterializationError::SnapshotContentMismatch)?
            .replace(std::path::MAIN_SEPARATOR, "/");
        verify_local_storage_projection(entry.path(), metadata.is_dir())?;
        if actual_paths.insert(relative, metadata.is_dir()).is_some() {
            return Err(SnapshotMaterializationError::SnapshotContentMismatch);
        }
    }
    if actual_paths != expected_paths {
        return Err(SnapshotMaterializationError::SnapshotContentMismatch);
    }
    let actual_tree = scan_tree(&data_root)?;
    if actual_tree.digest() != manifest.data_tree_digest
        || actual_tree.entries() != manifest.data_tree_entries
    {
        return Err(SnapshotMaterializationError::SnapshotContentMismatch);
    }
    Ok(())
}

fn verify_local_storage_projection(
    path: &Path,
    directory: bool,
) -> Result<(), SnapshotMaterializationError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata = fs::symlink_metadata(path)?;
        let expected_mode = if directory {
            rust_agent_composition::snapshot::READ_ONLY_EPOCH_V1_DIRECTORY_MODE
        } else {
            rust_agent_composition::snapshot::READ_ONLY_EPOCH_V1_FILE_MODE
        };
        if metadata.file_type().is_symlink()
            || metadata.is_dir() != directory
            || metadata.mode() & 0o7777 != expected_mode
            || metadata.mtime() != 0
            || metadata.mtime_nsec() != 0
        {
            return Err(SnapshotMaterializationError::StorageMetadataMismatch);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, directory);
        Err(SnapshotMaterializationError::UnsupportedHost)
    }
}

fn sync_snapshot_tree(root: &Path) -> Result<(), SnapshotMaterializationError> {
    let mut directories = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(io::Error::other)?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() {
            directories.push(entry.path().to_owned());
        } else if metadata.is_file() {
            File::open(entry.path())?.sync_all()?;
        } else {
            return Err(SnapshotMaterializationError::SnapshotContentMismatch);
        }
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        sync_directory(&directory)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(target_os = "linux")]
fn publish_noreplace(source: &Path, destination: &Path) -> io::Result<()> {
    renameat_with(CWD, source, CWD, destination, RenameFlags::NOREPLACE)
        .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))
}

#[cfg(not(target_os = "linux"))]
fn publish_noreplace(_source: &Path, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "snapshot publication requires Linux renameat2",
    ))
}

fn make_storage_writable(root: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut entries = WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.depth()));
        for entry in entries {
            let Ok(metadata) = fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            let mode = if metadata.is_dir() { 0o700 } else { 0o600 };
            let _ = fs::set_permissions(entry.path(), fs::Permissions::from_mode(mode));
        }
    }
    #[cfg(not(unix))]
    let _ = root;
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn rename_noreplace_preserves_an_existing_destination() {
        let temp = tempfile::TempDir::new().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(source.join("source-marker"), b"source").unwrap();

        let error = publish_noreplace(&source, &destination).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(fs::read_dir(&destination).unwrap().next().is_none());
        assert_eq!(fs::read(source.join("source-marker")).unwrap(), b"source");
    }

    #[test]
    fn published_result_reports_verification_and_durability_state_exactly() {
        let output = Path::new("/state/snapshot");
        let verification = classify_published_result::<()>(
            output,
            Err(SnapshotMaterializationError::SnapshotContentMismatch),
            Err(io::Error::other("durability failed")),
        )
        .unwrap_err();
        assert!(matches!(
            verification,
            SnapshotMaterializationError::PublishedVerificationFailed(path)
                if path == "/state/snapshot"
        ));

        let durability =
            classify_published_result(output, Ok(7_u8), Err(io::Error::other("durability failed")))
                .unwrap_err();
        assert!(matches!(
            durability,
            SnapshotMaterializationError::PublishedDurabilityUnknown { path, source }
                if path == "/state/snapshot" && source.to_string() == "durability failed"
        ));

        assert_eq!(
            classify_published_result(output, Ok(7_u8), Ok(())).unwrap(),
            7
        );
    }
}
