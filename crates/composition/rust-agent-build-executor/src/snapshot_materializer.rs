use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Component, Path, PathBuf},
    time::SystemTime,
};
#[cfg(target_os = "linux")]
use std::{
    fs::FileTimes,
    io::{Seek, SeekFrom},
    os::fd::AsRawFd,
    sync::Arc,
};

use crate::{
    CanonicalSnapshotMetadataContract, HostBuildClosureContent, HostBuildClosureItemRole,
    HostBuildInputClosureError, NormalizedHostBuildClosureItem, NormalizedHostBuildInputClosure,
    host_input_closure::{
        verify_canonical_cargo_config, verify_canonical_record, verify_custom_target_spec,
    },
};
use rust_agent_composition::{
    MAX_CUSTOM_TARGET_SPEC_BYTES, canonical,
    snapshot::{
        CanonicalSnapshotEntry, CanonicalSnapshotEntryKind, CanonicalSnapshotError,
        CanonicalSnapshotTree, MAX_CANONICAL_SNAPSHOT_ENTRIES, MAX_CANONICAL_SNAPSHOT_FILE_BYTES,
        MAX_CANONICAL_SNAPSHOT_JSON_BYTES, MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES,
    },
};
#[cfg(target_os = "linux")]
use rustix::{
    fs::{
        AtFlags, Dir, Mode, OFlags, RenameFlags, ResolveFlags, fchmod, mkdirat, openat2,
        renameat_with, unlinkat,
    },
    rand::{GetRandomFlags, getrandom},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const LOGICAL_CLOSURE_ROOT: &str = "/rust-agent/closure";
const LOGICAL_CLOSURE_PREFIX: &str = "/rust-agent/closure/";
const SNAPSHOT_DATA_DIRECTORY: &str = "data";
const SNAPSHOT_MANIFEST_FILE: &str = "rust-agent-host-closure-snapshot.json";
const MAX_SNAPSHOT_ITEMS: usize = 16_384;
const MAX_SNAPSHOT_TOTAL_PATH_BYTES: usize = 16 * 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const STAGING_RANDOM_BYTES: usize = 16;
#[cfg(target_os = "linux")]
const MAX_STAGING_NAME_ATTEMPTS: usize = 128;
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

/// A verified Host closure snapshot whose directory descriptor remains open.
///
/// Retaining the descriptor lets the production mounted-view layer bind the
/// exact directory that was verified, even if an attacker replaces the
/// original pathname before the sandbox is created.
#[derive(Clone, Debug)]
pub struct VerifiedHostClosureSnapshot {
    path: PathBuf,
    closure: NormalizedHostBuildInputClosure,
    manifest: HostClosureSnapshotManifest,
    directory: AnchoredDirectory,
}

#[derive(Clone, Debug)]
struct PreparedHostClosureItem {
    item: NormalizedHostBuildClosureItem,
    source: AnchoredSource,
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
    source: AnchoredSource,
    content: PreflightHostClosureContent,
}

#[derive(Clone, Debug)]
struct AnchoredSource {
    path: PathBuf,
    #[cfg(target_os = "linux")]
    handle: Arc<File>,
}

#[derive(Clone, Debug)]
struct AnchoredDirectory {
    path: PathBuf,
    #[cfg(target_os = "linux")]
    handle: Arc<File>,
    #[cfg(target_os = "linux")]
    identity: FileIdentity,
}

#[derive(Debug)]
struct AnchoredDestination {
    output: PathBuf,
    output_name: String,
    parent: AnchoredDirectory,
}

#[derive(Debug)]
struct StagingDirectory {
    #[cfg(target_os = "linux")]
    parent: AnchoredDirectory,
    #[cfg(target_os = "linux")]
    name: String,
    directory: AnchoredDirectory,
    #[cfg(target_os = "linux")]
    published: bool,
}

#[derive(Debug)]
pub(crate) struct AnchoredTreePublication {
    destination: AnchoredDestination,
    source: AnchoredSource,
    source_tree: CanonicalSnapshotTree,
}

#[derive(Clone, Debug)]
pub(crate) struct AnchoredFileIdentity {
    source: AnchoredSource,
    plan: PreflightSourceFile,
    sha256: String,
    bytes: u64,
    executable: bool,
    linux_elf: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct AnchoredTreeIdentity {
    source: AnchoredSource,
    tree: CanonicalSnapshotTree,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
pub(crate) struct AnchoredWritableDirectory {
    source: AnchoredSource,
    identity: FileIdentity,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
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
    #[error("snapshot destination parent, staging directory or published entry changed: {0}")]
    DestinationPathChanged(String),
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
    #[error("snapshot canonical-record verification failed: {0}")]
    CanonicalRecord(#[from] HostBuildInputClosureError),
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

impl VerifiedHostClosureSnapshot {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn manifest(&self) -> &HostClosureSnapshotManifest {
        &self.manifest
    }

    pub fn verify_unchanged(&self) -> Result<(), SnapshotMaterializationError> {
        let manifest = verify_host_closure_snapshot_anchored(&self.closure, &self.directory)?;
        if manifest != self.manifest {
            return Err(SnapshotMaterializationError::SnapshotContentMismatch);
        }
        anchor_destination(&self.path)?.ensure_output_matches(&self.directory)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn duplicate_mount_descriptor(
        &self,
    ) -> Result<std::os::fd::OwnedFd, SnapshotMaterializationError> {
        self.verify_unchanged()?;
        self.directory
            .open_directory(SNAPSHOT_DATA_DIRECTORY)?
            .duplicate_for_child()
            .map_err(Into::into)
    }
}

pub fn materialize_host_closure_snapshot(
    closure: &NormalizedHostBuildInputClosure,
    sources: &[HostClosureSnapshotSource],
    output: &Path,
) -> Result<MaterializedHostClosureSnapshot, SnapshotMaterializationError> {
    require_linux_host()?;
    let destination = anchor_destination(output)?;
    let prepared = prepare_host_closure_snapshot(closure, sources)?;
    if let Some(existing) = destination.open_output()? {
        let manifest = verify_host_closure_snapshot_anchored(closure, &existing)?;
        destination.ensure_output_matches(&existing)?;
        return Ok(MaterializedHostClosureSnapshot {
            path: output.to_owned(),
            manifest,
            reused: true,
        });
    }

    let mut staging_guard = destination.create_staging()?;
    let staging = staging_guard.directory.operation_path();
    let data_root = staging.join(SNAPSHOT_DATA_DIRECTORY);
    fs::create_dir(&data_root)?;

    let mut materialized_items = Vec::with_capacity(prepared.items.len());
    for item in &prepared.items {
        materialized_items.push(materialize_item(item, &data_root)?);
    }
    let data_directory = staging_guard
        .directory
        .open_directory(SNAPSHOT_DATA_DIRECTORY)?;
    let data_tree = scan_anchored_tree(&data_directory.as_source())?;
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
    seal_local_storage_projection(&staging_guard.directory)?;
    verify_snapshot_filesystem(&manifest, &staging_guard.directory)?;
    verify_snapshot_canonical_records(closure, &staging_guard.directory)?;
    sync_snapshot_tree(&staging_guard.directory)?;

    match publish_noreplace(&destination, &mut staging_guard) {
        Ok(()) => {
            let durability = destination.sync_parent();
            let verification =
                verify_host_closure_snapshot_anchored(closure, &staging_guard.directory).and_then(
                    |manifest| {
                        destination.ensure_output_matches(&staging_guard.directory)?;
                        Ok(manifest)
                    },
                );
            let published = classify_published_result(output, verification, durability)?;
            Ok(MaterializedHostClosureSnapshot {
                path: output.to_owned(),
                manifest: published,
                reused: false,
            })
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let existing_directory = destination.open_output()?.ok_or_else(|| {
                SnapshotMaterializationError::DestinationPathChanged(output.display().to_string())
            })?;
            let existing = verify_host_closure_snapshot_anchored(closure, &existing_directory)
                .map_err(|_| {
                    SnapshotMaterializationError::DestinationConflict(output.display().to_string())
                })?;
            destination.ensure_output_matches(&existing_directory)?;
            Ok(MaterializedHostClosureSnapshot {
                path: output.to_owned(),
                manifest: existing,
                reused: true,
            })
        }
        Err(error) => Err(SnapshotMaterializationError::Io(error)),
    }
}

pub(crate) fn prepare_anchored_tree_publication(
    source: &Path,
    output: &Path,
) -> Result<AnchoredTreePublication, SnapshotMaterializationError> {
    require_linux_host()?;
    let destination = anchor_destination(output)?;
    let source = anchor_source_path(source)?;
    require_source_kind(&source, true, &source.path().display().to_string())?;
    let source_tree = scan_anchored_tree(&source)?;
    Ok(AnchoredTreePublication {
        destination,
        source,
        source_tree,
    })
}

impl AnchoredTreePublication {
    pub(crate) fn source_tree(&self) -> &CanonicalSnapshotTree {
        &self.source_tree
    }

    pub(crate) fn publish(
        self,
        manifest_name: &str,
        manifest_bytes: &[u8],
    ) -> Result<bool, SnapshotMaterializationError> {
        let expected_tree = publication_tree(&self.source_tree, manifest_name, manifest_bytes)?;
        if let Some(existing) = self.destination.open_output()? {
            verify_anchored_storage_tree(&existing, &expected_tree)?;
            self.destination.ensure_output_matches(&existing)?;
            return Ok(true);
        }

        let mut staging_guard = self.destination.create_staging()?;
        let staging = staging_guard.directory.operation_path();
        copy_tree(&self.source, &staging, &self.source_tree)?;
        write_publication_manifest(&staging, manifest_name, manifest_bytes)?;
        seal_local_storage_projection(&staging_guard.directory)?;
        verify_anchored_storage_tree(&staging_guard.directory, &expected_tree)?;
        sync_snapshot_tree(&staging_guard.directory)?;

        match publish_noreplace(&self.destination, &mut staging_guard) {
            Ok(()) => {
                let durability = self.destination.sync_parent();
                let verification =
                    verify_anchored_storage_tree(&staging_guard.directory, &expected_tree)
                        .and_then(|()| {
                            self.destination
                                .ensure_output_matches(&staging_guard.directory)
                        });
                classify_published_result(&self.destination.output, verification, durability)?;
                Ok(false)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let existing = self.destination.open_output()?.ok_or_else(|| {
                    SnapshotMaterializationError::DestinationPathChanged(
                        self.destination.output.display().to_string(),
                    )
                })?;
                verify_anchored_storage_tree(&existing, &expected_tree).map_err(|_| {
                    SnapshotMaterializationError::DestinationConflict(
                        self.destination.output.display().to_string(),
                    )
                })?;
                self.destination.ensure_output_matches(&existing)?;
                Ok(true)
            }
            Err(error) => Err(SnapshotMaterializationError::Io(error)),
        }
    }
}

pub(crate) fn anchor_file_identity(
    source: &Path,
) -> Result<AnchoredFileIdentity, SnapshotMaterializationError> {
    require_linux_host()?;
    let source = anchor_source_path(source)?;
    anchor_opened_file(source)
}

fn anchor_opened_file(
    source: AnchoredSource,
) -> Result<AnchoredFileIdentity, SnapshotMaterializationError> {
    require_source_kind(&source, false, &source.path().display().to_string())?;
    let plan = preflight_source_file(&source)?;
    let (sha256, bytes) = hash_preflighted_file(&source, &plan)?;
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt;

        source.metadata()?.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = false;
    #[cfg(target_os = "linux")]
    let linux_elf = {
        use std::os::unix::fs::FileExt;

        let mut magic = [0_u8; 4];
        source.handle.read_at(&mut magic, 0)? == magic.len() && magic == *b"\x7fELF"
    };
    #[cfg(not(target_os = "linux"))]
    let linux_elf = false;
    Ok(AnchoredFileIdentity {
        source,
        plan,
        sha256,
        bytes,
        executable,
        linux_elf,
    })
}

impl AnchoredFileIdentity {
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(crate) fn is_executable(&self) -> bool {
        self.executable
    }

    pub(crate) fn is_linux_elf(&self) -> bool {
        self.linux_elf
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn read_bytes(
        &self,
        maximum: usize,
    ) -> Result<Vec<u8>, SnapshotMaterializationError> {
        use std::os::unix::fs::FileExt;

        self.reverify()?;
        let length = usize::try_from(self.bytes)
            .ok()
            .filter(|length| *length <= maximum)
            .ok_or_else(|| {
                SnapshotMaterializationError::SourceChanged(
                    self.source.path().display().to_string(),
                )
            })?;
        let mut bytes = vec![0; length];
        let mut offset = 0;
        while offset < length {
            let read = self
                .source
                .handle
                .read_at(&mut bytes[offset..], offset as u64)?;
            if read == 0 {
                return Err(SnapshotMaterializationError::SourceChanged(
                    self.source.path().display().to_string(),
                ));
            }
            offset += read;
        }
        self.reverify()?;
        Ok(bytes)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn copy_to(
        &self,
        output: &mut impl std::io::Write,
    ) -> Result<u64, SnapshotMaterializationError> {
        use std::os::unix::fs::FileExt;

        self.reverify()?;
        let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
        let mut offset = 0_u64;
        while offset < self.bytes {
            let remaining = usize::try_from((self.bytes - offset).min(COPY_BUFFER_BYTES as u64))
                .expect("bounded copy chunk fits usize");
            let read = self
                .source
                .handle
                .read_at(&mut buffer[..remaining], offset)?;
            if read == 0 {
                return Err(SnapshotMaterializationError::SourceChanged(
                    self.source.path().display().to_string(),
                ));
            }
            output.write_all(&buffer[..read])?;
            offset += read as u64;
        }
        self.reverify()?;
        Ok(offset)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn descriptor_execution_path(&self) -> PathBuf {
        use std::os::fd::AsRawFd;

        PathBuf::from(format!("/proc/self/fd/{}", self.source.handle.as_raw_fd()))
    }

    pub(crate) fn reverify(&self) -> Result<(), SnapshotMaterializationError> {
        ensure_original_path_matches(&self.source)?;
        let (sha256, bytes) = hash_preflighted_file(&self.source, &self.plan)?;
        if sha256 != self.sha256 || bytes != self.bytes {
            return Err(SnapshotMaterializationError::SourceChanged(
                self.source.path().display().to_string(),
            ));
        }
        ensure_original_path_matches(&self.source)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn duplicate_mount_descriptor(
        &self,
    ) -> Result<std::os::fd::OwnedFd, SnapshotMaterializationError> {
        self.reverify()?;
        rustix::io::dup(&*self.source.handle)
            .map_err(rustix_io_error)
            .map_err(Into::into)
    }
}

pub(crate) fn anchor_tree_identity(
    source: &Path,
) -> Result<AnchoredTreeIdentity, SnapshotMaterializationError> {
    require_linux_host()?;
    let source = anchor_source_path(source)?;
    require_source_kind(&source, true, &source.path().display().to_string())?;
    let tree = scan_anchored_tree(&source)?;
    Ok(AnchoredTreeIdentity { source, tree })
}

impl AnchoredTreeIdentity {
    pub(crate) fn digest(&self) -> &str {
        self.tree.digest()
    }

    pub(crate) fn tree(&self) -> &CanonicalSnapshotTree {
        &self.tree
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn open_file(&self, relative: &str) -> Result<File, SnapshotMaterializationError> {
        let handle = self.source.open(Some(relative))?;
        let source = AnchoredSource {
            path: self.source.path().join(relative),
            handle: Arc::new(handle),
        };
        require_source_kind(&source, false, &source.path().display().to_string())?;
        source.handle.try_clone().map_err(Into::into)
    }

    pub(crate) fn read_file(
        &self,
        relative: &str,
        maximum: usize,
    ) -> Result<Vec<u8>, SnapshotMaterializationError> {
        #[cfg(target_os = "linux")]
        {
            let handle = self.source.open(Some(relative))?;
            let source = AnchoredSource {
                path: self.source.path().join(relative),
                handle: Arc::new(handle),
            };
            require_source_kind(&source, false, &source.path().display().to_string())?;
            let plan = preflight_source_file(&source)?;
            read_preflighted_file(&source, &plan, maximum)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (relative, maximum);
            Err(SnapshotMaterializationError::UnsupportedHost)
        }
    }

    pub(crate) fn verify_publication(
        &self,
        source_tree: &CanonicalSnapshotTree,
        manifest_name: &str,
        manifest_bytes: &[u8],
    ) -> Result<(), SnapshotMaterializationError> {
        let expected = publication_tree(source_tree, manifest_name, manifest_bytes)?;
        if self.tree != expected {
            return Err(SnapshotMaterializationError::SnapshotContentMismatch);
        }
        self.reverify()
    }

    pub(crate) fn reverify(&self) -> Result<(), SnapshotMaterializationError> {
        ensure_original_path_matches(&self.source)?;
        let tree = scan_anchored_tree(&self.source)?;
        if tree != self.tree {
            return Err(SnapshotMaterializationError::SourceChanged(
                self.source.path().display().to_string(),
            ));
        }
        ensure_original_path_matches(&self.source)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn duplicate_mount_descriptor(
        &self,
    ) -> Result<std::os::fd::OwnedFd, SnapshotMaterializationError> {
        self.reverify()?;
        rustix::io::dup(&*self.source.handle)
            .map_err(rustix_io_error)
            .map_err(Into::into)
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn anchor_writable_directory(
    path: &Path,
) -> Result<AnchoredWritableDirectory, SnapshotMaterializationError> {
    require_linux_host()?;
    let source = anchor_source_path(path)?;
    require_source_kind(&source, true, &path.display().to_string())?;
    let identity = file_identity(&source.metadata()?);
    Ok(AnchoredWritableDirectory { source, identity })
}

#[cfg(target_os = "linux")]
impl AnchoredWritableDirectory {
    pub(crate) fn duplicate_mount_descriptor(
        &self,
    ) -> Result<std::os::fd::OwnedFd, SnapshotMaterializationError> {
        self.verify_path_identity()?;
        rustix::io::dup(&*self.source.handle)
            .map_err(rustix_io_error)
            .map_err(Into::into)
    }

    pub(crate) fn verify_path_identity(&self) -> Result<(), SnapshotMaterializationError> {
        let current = anchor_source_path(self.source.path()).map_err(|_| {
            SnapshotMaterializationError::SourceChanged(self.source.path().display().to_string())
        })?;
        if file_identity(&current.metadata()?) != self.identity {
            return Err(SnapshotMaterializationError::SourceChanged(
                self.source.path().display().to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn anchor_file(
        &self,
        relative: &str,
    ) -> Result<AnchoredFileIdentity, SnapshotMaterializationError> {
        self.verify_path_identity()?;
        let handle = self.source.open(Some(relative))?;
        let source = AnchoredSource {
            path: self.source.path().join(relative),
            handle: Arc::new(handle),
        };
        let identity = anchor_opened_file(source)?;
        self.verify_path_identity()?;
        Ok(identity)
    }

    pub(crate) fn anchor_regular_files(
        &self,
    ) -> Result<Vec<(String, AnchoredFileIdentity)>, SnapshotMaterializationError> {
        self.verify_path_identity()?;
        let tree = scan_anchored_tree(&self.source)?;
        let mut files = Vec::new();
        for entry in tree.entries() {
            if matches!(
                entry.kind,
                rust_agent_composition::snapshot::CanonicalSnapshotEntryKind::RegularFile { .. }
            ) {
                files.push((entry.path.clone(), self.anchor_file(&entry.path)?));
            }
        }
        self.verify_path_identity()?;
        Ok(files)
    }

    pub(crate) fn create_or_open_child_directory(
        &self,
        name: &str,
    ) -> Result<Self, SnapshotMaterializationError> {
        if !is_single_normal_component(name) {
            return Err(SnapshotMaterializationError::InvalidConcretePath(
                self.source.path().join(name).display().to_string(),
            ));
        }
        self.verify_path_identity()?;
        match mkdirat(&*self.source.handle, name, Mode::RWXU) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(rustix_io_error(error).into()),
        }
        let handle = self.source.open(Some(name))?;
        let source = AnchoredSource {
            path: self.source.path().join(name),
            handle: Arc::new(handle),
        };
        require_source_kind(&source, true, name)?;
        let child = Self {
            identity: file_identity(&source.metadata()?),
            source,
        };
        self.verify_path_identity()?;
        child.verify_path_identity()?;
        self.source.handle.sync_all()?;
        Ok(child)
    }

    pub(crate) fn create_new_file(&self, name: &str) -> Result<File, SnapshotMaterializationError> {
        if !is_single_normal_component(name) {
            return Err(SnapshotMaterializationError::InvalidConcretePath(
                self.source.path().join(name).display().to_string(),
            ));
        }
        self.verify_path_identity()?;
        let file = File::from(
            openat2(
                &*self.source.handle,
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .map_err(rustix_io_error)?,
        );
        self.verify_path_identity()?;
        Ok(file)
    }

    pub(crate) fn sync(&self) -> Result<(), SnapshotMaterializationError> {
        self.verify_path_identity()?;
        self.source.handle.sync_all()?;
        self.verify_path_identity()
    }

    pub(crate) fn write_new_file_atomic(
        &self,
        name: &str,
        bytes: &[u8],
        mode: u32,
    ) -> Result<bool, SnapshotMaterializationError> {
        use std::os::unix::fs::PermissionsExt as _;

        if !is_single_normal_component(name) {
            return Err(SnapshotMaterializationError::InvalidConcretePath(
                self.source.path().join(name).display().to_string(),
            ));
        }
        self.verify_path_identity()?;
        for _ in 0..MAX_STAGING_NAME_ATTEMPTS {
            let mut random = [0_u8; STAGING_RANDOM_BYTES];
            let written =
                getrandom(&mut random, GetRandomFlags::empty()).map_err(rustix_io_error)?;
            if written != random.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "getrandom returned a short atomic-write nonce",
                )
                .into());
            }
            let staging = format!(".rust-agent-write-{}", hex::encode(random));
            let mut file = match self.create_new_file(&staging) {
                Ok(file) => file,
                Err(SnapshotMaterializationError::Io(error))
                    if error.kind() == io::ErrorKind::AlreadyExists =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            let result = (|| -> Result<bool, SnapshotMaterializationError> {
                file.write_all(bytes)?;
                file.sync_all()?;
                file.set_permissions(fs::Permissions::from_mode(mode))?;
                file.sync_all()?;
                self.verify_path_identity()?;
                match renameat_with(
                    &*self.source.handle,
                    staging.as_str(),
                    &*self.source.handle,
                    name,
                    RenameFlags::NOREPLACE,
                ) {
                    Ok(()) => {
                        self.sync()?;
                        Ok(true)
                    }
                    Err(rustix::io::Errno::EXIST) => Ok(false),
                    Err(error) => Err(rustix_io_error(error).into()),
                }
            })();
            if !matches!(result, Ok(true)) {
                let _ = unlinkat(&*self.source.handle, staging.as_str(), AtFlags::empty());
            }
            return result;
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique atomic-write staging file",
        )
        .into())
    }
}

#[cfg(target_os = "linux")]
fn is_single_normal_component(value: &str) -> bool {
    let mut components = Path::new(value).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn ensure_original_path_matches(
    source: &AnchoredSource,
) -> Result<(), SnapshotMaterializationError> {
    let current = anchor_source_path(source.path()).map_err(|_| {
        SnapshotMaterializationError::SourceChanged(source.path().display().to_string())
    })?;
    if stable_metadata(&current.metadata()?)? != stable_metadata(&source.metadata()?)? {
        return Err(SnapshotMaterializationError::SourceChanged(
            source.path().display().to_string(),
        ));
    }
    Ok(())
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
    Ok(open_verified_host_closure_snapshot(closure, output)?.manifest)
}

pub fn open_verified_host_closure_snapshot(
    closure: &NormalizedHostBuildInputClosure,
    output: &Path,
) -> Result<VerifiedHostClosureSnapshot, SnapshotMaterializationError> {
    require_linux_host()?;
    let destination = anchor_destination(output)?;
    let snapshot = destination.open_output()?.ok_or_else(|| {
        SnapshotMaterializationError::DestinationConflict(output.display().to_string())
    })?;
    let manifest = verify_host_closure_snapshot_anchored(closure, &snapshot)?;
    destination.ensure_output_matches(&snapshot)?;
    Ok(VerifiedHostClosureSnapshot {
        path: output.to_owned(),
        closure: closure.clone(),
        manifest,
        directory: snapshot,
    })
}

fn verify_host_closure_snapshot_anchored(
    closure: &NormalizedHostBuildInputClosure,
    snapshot: &AnchoredDirectory,
) -> Result<HostClosureSnapshotManifest, SnapshotMaterializationError> {
    let manifest_source = snapshot.open_entry(SNAPSHOT_MANIFEST_FILE)?;
    let plan = preflight_source_file(&manifest_source)?;
    let bytes = read_preflighted_file(&manifest_source, &plan, MAX_CANONICAL_SNAPSHOT_JSON_BYTES)?;
    if bytes.is_empty() {
        return Err(SnapshotMaterializationError::SnapshotContentMismatch);
    }
    let manifest: HostClosureSnapshotManifest = serde_json::from_slice(&bytes)?;
    manifest.verify_closure(closure)?;
    verify_snapshot_filesystem(&manifest, snapshot)?;
    verify_snapshot_canonical_records(closure, snapshot)?;
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
    let mut semantic_file_bytes = BTreeMap::<HostBuildClosureItemRole, Vec<u8>>::new();

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
            source: source.clone(),
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
                let retain_semantic_bytes = retains_semantic_bytes(&preflight.item);
                let (actual, bytes) = if retain_semantic_bytes {
                    let semantic_limit = semantic_file_limit(&preflight.item);
                    if preflight.item.role == HostBuildClosureItemRole::CustomTargetSpec
                        && file_plan.metadata.len > semantic_limit as u64
                    {
                        return Err(SnapshotMaterializationError::SourceBounds(
                            preflight.item.id.clone(),
                        ));
                    }
                    let record_bytes =
                        read_preflighted_file(&preflight.source, &file_plan, semantic_limit)?;
                    let actual = sha256_bytes(&record_bytes);
                    if actual != expected {
                        return Err(SnapshotMaterializationError::SourceDigestMismatch(
                            preflight.item.id.clone(),
                        ));
                    }
                    if matches!(
                        preflight.item.content,
                        HostBuildClosureContent::CanonicalRecord { .. }
                    ) {
                        verify_canonical_record(
                            &preflight.item,
                            &record_bytes,
                            closure.build_context(),
                        )?;
                    }
                    if matches!(
                        preflight.item.content,
                        HostBuildClosureContent::CustomTargetSpec { .. }
                    ) {
                        verify_custom_target_spec(closure, &record_bytes)?;
                    }
                    semantic_file_bytes.insert(preflight.item.role, record_bytes.clone());
                    (actual, record_bytes.len() as u64)
                } else {
                    hash_preflighted_file(&preflight.source, &file_plan)?
                };
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

    verify_canonical_cargo_config(
        closure,
        semantic_file_bytes
            .get(&HostBuildClosureItemRole::CargoConfig)
            .expect("normalized closure retains its Cargo config"),
        semantic_file_bytes
            .get(&HostBuildClosureItemRole::CargoResolutionRecord)
            .expect("normalized closure retains its Cargo resolution record"),
    )?;

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
            copy_file_overlay(&prepared.source, None, &destination, sha256, *bytes)?;
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

fn normalize_sources(
    closure: &NormalizedHostBuildInputClosure,
    sources: &[HostClosureSnapshotSource],
) -> Result<BTreeMap<String, AnchoredSource>, SnapshotMaterializationError> {
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
            .insert(source.item_id.clone(), anchor_source_path(&source.path)?)
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
    source: &AnchoredSource,
    directory: bool,
    item_id: &str,
) -> Result<(), SnapshotMaterializationError> {
    let metadata = source.metadata()?;
    if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
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

fn anchor_destination(output: &Path) -> Result<AnchoredDestination, SnapshotMaterializationError> {
    if !is_normalized_absolute_path(output) || output.file_name().is_none() {
        return Err(SnapshotMaterializationError::InvalidDestinationParent(
            output.display().to_string(),
        ));
    }
    let parent = output.parent().ok_or_else(|| {
        SnapshotMaterializationError::InvalidDestinationParent(output.display().to_string())
    })?;
    let output_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            SnapshotMaterializationError::InvalidDestinationParent(output.display().to_string())
        })?;
    #[cfg(target_os = "linux")]
    {
        let filesystem_root = File::open(Path::new("/"))?;
        let relative = parent.strip_prefix(Path::new("/")).map_err(|_| {
            SnapshotMaterializationError::InvalidDestinationParent(parent.display().to_string())
        })?;
        let relative = if relative.as_os_str().is_empty() {
            Path::new(".")
        } else {
            relative
        };
        let handle = File::from(
            openat2(
                &filesystem_root,
                relative,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .map_err(|_| {
                SnapshotMaterializationError::InvalidDestinationParent(parent.display().to_string())
            })?,
        );
        let metadata = handle.metadata()?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(SnapshotMaterializationError::InvalidDestinationParent(
                parent.display().to_string(),
            ));
        }
        Ok(AnchoredDestination {
            output: output.to_owned(),
            output_name: output_name.to_owned(),
            parent: AnchoredDirectory {
                path: parent.to_owned(),
                identity: file_identity(&metadata),
                handle: Arc::new(handle),
            },
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (parent, output_name);
        Err(SnapshotMaterializationError::UnsupportedHost)
    }
}

impl AnchoredDestination {
    fn open_output(&self) -> Result<Option<AnchoredDirectory>, SnapshotMaterializationError> {
        match self
            .parent
            .open_directory_io(&self.output_name, self.output.clone())
        {
            Ok(directory) => Ok(Some(directory)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(SnapshotMaterializationError::DestinationConflict(
                self.output.display().to_string(),
            )),
        }
    }

    fn ensure_output_matches(
        &self,
        expected: &AnchoredDirectory,
    ) -> Result<(), SnapshotMaterializationError> {
        let actual = self.open_output()?.ok_or_else(|| {
            SnapshotMaterializationError::DestinationPathChanged(self.output.display().to_string())
        })?;
        if actual.identity_matches(expected) {
            Ok(())
        } else {
            Err(SnapshotMaterializationError::DestinationPathChanged(
                self.output.display().to_string(),
            ))
        }
    }

    fn create_staging(&self) -> Result<StagingDirectory, SnapshotMaterializationError> {
        #[cfg(target_os = "linux")]
        {
            for _ in 0..MAX_STAGING_NAME_ATTEMPTS {
                let mut random = [0_u8; STAGING_RANDOM_BYTES];
                let written =
                    getrandom(&mut random[..], GetRandomFlags::empty()).map_err(rustix_io_error)?;
                if written != random.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "getrandom returned a short staging nonce",
                    )
                    .into());
                }
                let name = format!("rust-agent-snapshot-stage-{}", hex::encode(random));
                match mkdirat(&*self.parent.handle, name.as_str(), Mode::RWXU) {
                    Ok(()) => {
                        let directory = self
                            .parent
                            .open_directory_io(&name, self.parent.path.join(&name))
                            .map_err(|_| {
                                SnapshotMaterializationError::DestinationPathChanged(
                                    self.parent.path.join(&name).display().to_string(),
                                )
                            })?;
                        return Ok(StagingDirectory {
                            parent: self.parent.clone(),
                            name,
                            directory,
                            published: false,
                        });
                    }
                    Err(error) if error == rustix::io::Errno::EXIST => {}
                    Err(error) => return Err(rustix_io_error(error).into()),
                }
            }
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a unique snapshot staging directory",
            )
            .into())
        }
        #[cfg(not(target_os = "linux"))]
        Err(SnapshotMaterializationError::UnsupportedHost)
    }

    fn sync_parent(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.parent.handle.sync_all()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "snapshot publication requires Linux directory descriptors",
            ))
        }
    }
}

impl AnchoredDirectory {
    #[cfg(target_os = "linux")]
    fn duplicate_for_child(&self) -> io::Result<std::os::fd::OwnedFd> {
        rustix::io::dup(&*self.handle).map_err(rustix_io_error)
    }

    fn handle_metadata(&self) -> io::Result<fs::Metadata> {
        #[cfg(target_os = "linux")]
        {
            self.handle.metadata()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "snapshot verification requires Linux directory descriptors",
            ))
        }
    }

    #[cfg(target_os = "linux")]
    fn open_directory_io(&self, relative: &str, path: PathBuf) -> io::Result<Self> {
        let handle = File::from(
            openat2(
                &*self.handle,
                relative,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .map_err(rustix_io_error)?,
        );
        let metadata = handle.metadata()?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "descriptor-relative entry is not a directory",
            ));
        }
        Ok(Self {
            path,
            identity: file_identity(&metadata),
            handle: Arc::new(handle),
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn open_directory_io(&self, _relative: &str, _path: PathBuf) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "snapshot verification requires Linux directory descriptors",
        ))
    }

    fn open_directory(&self, relative: &str) -> Result<Self, SnapshotMaterializationError> {
        self.open_directory_io(relative, self.path.join(relative))
            .map_err(SnapshotMaterializationError::Io)
    }

    fn open_entry(&self, relative: &str) -> Result<AnchoredSource, SnapshotMaterializationError> {
        #[cfg(target_os = "linux")]
        {
            let handle = File::from(
                openat2(
                    &*self.handle,
                    relative,
                    OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )
                .map_err(|_| SnapshotMaterializationError::SnapshotContentMismatch)?,
            );
            let metadata = handle
                .metadata()
                .map_err(|_| SnapshotMaterializationError::SnapshotContentMismatch)?;
            if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
                return Err(SnapshotMaterializationError::SnapshotContentMismatch);
            }
            Ok(AnchoredSource {
                path: self.path.join(relative),
                handle: Arc::new(handle),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = relative;
            Err(SnapshotMaterializationError::UnsupportedHost)
        }
    }

    fn as_source(&self) -> AnchoredSource {
        #[cfg(target_os = "linux")]
        {
            AnchoredSource {
                path: self.path.clone(),
                handle: Arc::clone(&self.handle),
            }
        }
        #[cfg(not(target_os = "linux"))]
        AnchoredSource {
            path: self.path.clone(),
        }
    }

    fn operation_path(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            PathBuf::from(format!("/proc/self/fd/{}/.", self.handle.as_raw_fd()))
        }
        #[cfg(not(target_os = "linux"))]
        self.path.clone()
    }

    fn identity_matches(&self, other: &Self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.identity == other.identity
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = other;
            false
        }
    }
}

impl StagingDirectory {
    #[cfg(target_os = "linux")]
    fn ensure_linked(&self) -> io::Result<()> {
        let current = self
            .parent
            .open_directory_io(&self.name, self.parent.path.join(&self.name))?;
        if current.identity_matches(&self.directory) {
            Ok(())
        } else {
            Err(io::Error::other(
                "snapshot staging directory entry was replaced",
            ))
        }
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if !self.published {
            let _ = remove_directory_contents(&self.directory.handle);
            if self.ensure_linked().is_ok() {
                let _ = unlinkat(&*self.parent.handle, self.name.as_str(), AtFlags::REMOVEDIR);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;

    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(target_os = "linux")]
fn rustix_io_error(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(target_os = "linux")]
fn remove_directory_contents(directory: &File) -> io::Result<()> {
    fchmod(directory, Mode::RWXU).map_err(rustix_io_error)?;
    let mut names = Vec::new();
    for entry in Dir::read_from(directory).map_err(rustix_io_error)? {
        let entry = entry.map_err(rustix_io_error)?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        names.push(
            std::str::from_utf8(name)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 staging entry"))?
                .to_owned(),
        );
    }
    for name in names {
        let entry = File::from(
            openat2(
                directory,
                name.as_str(),
                OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS,
            )
            .map_err(rustix_io_error)?,
        );
        if entry.metadata()?.is_dir() {
            let child = File::from(
                openat2(
                    directory,
                    name.as_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )
                .map_err(rustix_io_error)?,
            );
            remove_directory_contents(&child)?;
            unlinkat(directory, name.as_str(), AtFlags::REMOVEDIR).map_err(rustix_io_error)?;
        } else {
            unlinkat(directory, name.as_str(), AtFlags::empty()).map_err(rustix_io_error)?;
        }
    }
    Ok(())
}

fn validate_source_path(source: &Path) -> Result<(), SnapshotMaterializationError> {
    if !is_normalized_absolute_path(source) {
        return Err(SnapshotMaterializationError::InvalidConcretePath(
            source.display().to_string(),
        ));
    }
    Ok(())
}

fn anchor_source_path(source: &Path) -> Result<AnchoredSource, SnapshotMaterializationError> {
    validate_source_path(source)?;
    #[cfg(target_os = "linux")]
    {
        let filesystem_root = File::open(Path::new("/"))?;
        let relative = source.strip_prefix(Path::new("/")).map_err(|_| {
            SnapshotMaterializationError::InvalidConcretePath(source.display().to_string())
        })?;
        let relative = if relative.as_os_str().is_empty() {
            Path::new(".")
        } else {
            relative
        };
        let path_handle = openat2(
            &filesystem_root,
            relative,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| {
            SnapshotMaterializationError::InvalidConcretePath(source.display().to_string())
        })?;
        let path_handle = File::from(path_handle);
        let metadata = path_handle.metadata()?;
        if metadata.file_type().is_symlink() {
            return Err(SnapshotMaterializationError::InvalidConcretePath(
                source.display().to_string(),
            ));
        }
        if !metadata.is_file() && !metadata.is_dir() {
            return Err(SnapshotMaterializationError::UnsupportedSourceEntry(
                source.display().to_string(),
            ));
        }
        let identity = stable_metadata(&metadata)?;
        let handle = File::from(
            openat2(
                &filesystem_root,
                relative,
                OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .map_err(|_| {
                SnapshotMaterializationError::InvalidConcretePath(source.display().to_string())
            })?,
        );
        if stable_metadata(&handle.metadata()?)? != identity {
            return Err(SnapshotMaterializationError::SourceChanged(
                source.display().to_string(),
            ));
        }
        Ok(AnchoredSource {
            path: source.to_owned(),
            handle: Arc::new(handle),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = source;
        Err(SnapshotMaterializationError::UnsupportedHost)
    }
}

impl AnchoredSource {
    fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(target_os = "linux")]
    fn metadata(&self) -> io::Result<fs::Metadata> {
        self.handle.metadata()
    }

    #[cfg(not(target_os = "linux"))]
    fn metadata(&self) -> io::Result<fs::Metadata> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "descriptor-relative sources require Linux openat2",
        ))
    }

    #[cfg(target_os = "linux")]
    fn open(&self, relative: Option<&str>) -> io::Result<File> {
        let mut file = match relative {
            Some(relative) => {
                let path_handle = File::from(
                    openat2(
                        &*self.handle,
                        relative,
                        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                        ResolveFlags::BENEATH
                            | ResolveFlags::NO_SYMLINKS
                            | ResolveFlags::NO_MAGICLINKS,
                    )
                    .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?,
                );
                let path_metadata = path_handle.metadata()?;
                if path_metadata.file_type().is_symlink()
                    || (!path_metadata.is_file() && !path_metadata.is_dir())
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "descriptor-relative source is not a regular file or directory",
                    ));
                }
                let identity = stable_metadata(&path_metadata)?;
                let file = File::from(
                    openat2(
                        &*self.handle,
                        relative,
                        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                        ResolveFlags::BENEATH
                            | ResolveFlags::NO_SYMLINKS
                            | ResolveFlags::NO_MAGICLINKS,
                    )
                    .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?,
                );
                if stable_metadata(&file.metadata()?)? != identity {
                    return Err(io::Error::other(
                        "descriptor-relative source changed while it was opened",
                    ));
                }
                file
            }
            None => self.handle.try_clone()?,
        };
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }

    #[cfg(not(target_os = "linux"))]
    fn open(&self, _relative: Option<&str>) -> io::Result<File> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "descriptor-relative sources require Linux openat2",
        ))
    }
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
    source: &AnchoredSource,
) -> Result<PreflightSourceFile, SnapshotMaterializationError> {
    let metadata = source.metadata()?;
    if !metadata.is_file() {
        return Err(SnapshotMaterializationError::UnsupportedSourceEntry(
            source.path().display().to_string(),
        ));
    }
    if metadata.len() > MAX_CANONICAL_SNAPSHOT_FILE_BYTES {
        return Err(SnapshotMaterializationError::SourceBounds(
            source.path().display().to_string(),
        ));
    }
    Ok(PreflightSourceFile {
        metadata: stable_metadata(&metadata)?,
    })
}

fn hash_preflighted_file(
    source: &AnchoredSource,
    plan: &PreflightSourceFile,
) -> Result<(String, u64), SnapshotMaterializationError> {
    if preflight_source_file(source)? != *plan {
        return Err(SnapshotMaterializationError::SourceChanged(
            source.path().display().to_string(),
        ));
    }
    let result = hash_anchored_file(source, None, &plan.metadata)?;
    if preflight_source_file(source)? != *plan {
        return Err(SnapshotMaterializationError::SourceChanged(
            source.path().display().to_string(),
        ));
    }
    Ok(result)
}

fn read_preflighted_file(
    source: &AnchoredSource,
    plan: &PreflightSourceFile,
    maximum: usize,
) -> Result<Vec<u8>, SnapshotMaterializationError> {
    if preflight_source_file(source)? != *plan {
        return Err(SnapshotMaterializationError::SourceChanged(
            source.path().display().to_string(),
        ));
    }
    let bytes = read_bounded_anchored_file(source, None, &plan.metadata, maximum)?;
    if preflight_source_file(source)? != *plan || bytes.len() as u64 != plan.metadata.len {
        return Err(SnapshotMaterializationError::SourceChanged(
            source.path().display().to_string(),
        ));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn preflight_source_tree(
    root: &AnchoredSource,
) -> Result<PreflightSourceTree, SnapshotMaterializationError> {
    let root_metadata = root.metadata()?;
    if !root_metadata.is_dir() {
        return Err(SnapshotMaterializationError::UnsupportedSourceEntry(
            root.path().display().to_string(),
        ));
    }
    let root_before = stable_metadata(&root_metadata)?;
    let mut canonical_entries = Vec::new();
    let mut entries_by_path = BTreeMap::new();
    let mut total_file_bytes = 0_u64;
    let mut total_path_bytes = 0_usize;
    let mut pending_directories = vec![String::new()];
    while let Some(directory) = pending_directories.pop() {
        let directory_file = root
            .open((!directory.is_empty()).then_some(directory.as_str()))
            .map_err(|_| {
                SnapshotMaterializationError::SourceChanged(root.path().display().to_string())
            })?;
        if !directory_file.metadata()?.is_dir() {
            return Err(SnapshotMaterializationError::UnsupportedSourceEntry(
                root.path().join(&directory).display().to_string(),
            ));
        }
        let mut names = Vec::new();
        for entry in Dir::read_from(&directory_file)
            .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?
        {
            let entry =
                entry.map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            let name = std::str::from_utf8(name).map_err(|_| {
                SnapshotMaterializationError::UnsupportedSourceEntry(
                    root.path().display().to_string(),
                )
            })?;
            if name.is_empty() || name.contains('/') {
                return Err(SnapshotMaterializationError::UnsupportedSourceEntry(
                    root.path().display().to_string(),
                ));
            }
            names.push(name.to_owned());
        }
        names.sort();
        for name in names.into_iter().rev() {
            if canonical_entries.len() == MAX_CANONICAL_SNAPSHOT_ENTRIES {
                return Err(SnapshotMaterializationError::SourceBounds(
                    root.path().display().to_string(),
                ));
            }
            let relative = if directory.is_empty() {
                name
            } else {
                format!("{directory}/{name}")
            };
            total_path_bytes = total_path_bytes
                .checked_add(relative.len())
                .ok_or_else(|| SnapshotMaterializationError::SourceBounds(relative.clone()))?;
            if total_path_bytes > MAX_SNAPSHOT_TOTAL_PATH_BYTES {
                return Err(SnapshotMaterializationError::SourceBounds(relative));
            }
            let entry_file = root.open(Some(&relative)).map_err(|_| {
                SnapshotMaterializationError::UnsupportedSourceEntry(
                    root.path().join(&relative).display().to_string(),
                )
            })?;
            let metadata = entry_file.metadata()?;
            let stable = stable_metadata(&metadata)?;
            let directory_entry = metadata.is_dir();
            if directory_entry {
                canonical_entries.push(CanonicalSnapshotEntry::directory(relative.clone()));
                pending_directories.push(relative.clone());
            } else if metadata.is_file() {
                if metadata.len() > MAX_CANONICAL_SNAPSHOT_FILE_BYTES {
                    return Err(SnapshotMaterializationError::SourceBounds(
                        root.path().join(&relative).display().to_string(),
                    ));
                }
                total_file_bytes = total_file_bytes
                    .checked_add(metadata.len())
                    .ok_or_else(|| SnapshotMaterializationError::SourceBounds(relative.clone()))?;
                if total_file_bytes > MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES {
                    return Err(SnapshotMaterializationError::SourceBounds(
                        root.path().join(&relative).display().to_string(),
                    ));
                }
                canonical_entries.push(CanonicalSnapshotEntry::regular_file(
                    relative.clone(),
                    PREFLIGHT_FILE_SHA256,
                    metadata.len(),
                ));
            } else {
                return Err(SnapshotMaterializationError::UnsupportedSourceEntry(
                    root.path().join(&relative).display().to_string(),
                ));
            }
            entries_by_path.insert(
                relative.clone(),
                PreflightSourceTreeEntry {
                    path: relative,
                    directory: directory_entry,
                    metadata: stable,
                },
            );
        }
    }
    if stable_metadata(&root.metadata()?)? != root_before {
        return Err(SnapshotMaterializationError::SourceChanged(
            root.path().display().to_string(),
        ));
    }
    let canonical = CanonicalSnapshotTree::from_entries(canonical_entries)?;
    let entries = canonical
        .entries()
        .iter()
        .map(|entry| {
            entries_by_path.remove(&entry.path).ok_or_else(|| {
                SnapshotMaterializationError::SourceChanged(root.path().display().to_string())
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !entries_by_path.is_empty() {
        return Err(SnapshotMaterializationError::SourceChanged(
            root.path().display().to_string(),
        ));
    }
    Ok(PreflightSourceTree {
        root_metadata: root_before,
        entries,
    })
}

#[cfg(not(target_os = "linux"))]
fn preflight_source_tree(
    _root: &AnchoredSource,
) -> Result<PreflightSourceTree, SnapshotMaterializationError> {
    Err(SnapshotMaterializationError::UnsupportedHost)
}

fn hash_preflighted_tree(
    root: &AnchoredSource,
    plan: &PreflightSourceTree,
) -> Result<CanonicalSnapshotTree, SnapshotMaterializationError> {
    if preflight_source_tree(root)? != *plan {
        return Err(SnapshotMaterializationError::SourceChanged(
            root.path().display().to_string(),
        ));
    }
    let mut entries = Vec::with_capacity(plan.entries.len());
    for entry in &plan.entries {
        if entry.directory {
            entries.push(CanonicalSnapshotEntry::directory(entry.path.clone()));
        } else {
            let (sha256, bytes) = hash_anchored_file(root, Some(&entry.path), &entry.metadata)?;
            entries.push(CanonicalSnapshotEntry::regular_file(
                entry.path.clone(),
                sha256,
                bytes,
            ));
        }
    }
    if preflight_source_tree(root)? != *plan {
        return Err(SnapshotMaterializationError::SourceChanged(
            root.path().display().to_string(),
        ));
    }
    Ok(CanonicalSnapshotTree::from_entries(entries)?)
}

fn scan_anchored_tree(
    root: &AnchoredSource,
) -> Result<CanonicalSnapshotTree, SnapshotMaterializationError> {
    let plan = preflight_source_tree(root)?;
    hash_preflighted_tree(root, &plan)
}

fn hash_anchored_file(
    source: &AnchoredSource,
    relative: Option<&str>,
    expected: &StableMetadata,
) -> Result<(String, u64), SnapshotMaterializationError> {
    let label = anchored_source_label(source, relative);
    let file = source
        .open(relative)
        .map_err(|_| SnapshotMaterializationError::SourceChanged(label.display().to_string()))?;
    let before = stable_metadata(&file.metadata()?)?;
    if &before != expected || before.len > MAX_CANONICAL_SNAPSHOT_FILE_BYTES {
        return Err(SnapshotMaterializationError::SourceChanged(
            label.display().to_string(),
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
            SnapshotMaterializationError::SourceBounds(label.display().to_string())
        })?;
        if bytes > MAX_CANONICAL_SNAPSHOT_FILE_BYTES {
            return Err(SnapshotMaterializationError::SourceBounds(
                label.display().to_string(),
            ));
        }
        hasher.update(&buffer[..read]);
    }
    let handle_after = stable_metadata(&reader.get_ref().metadata()?)?;
    let path_after = anchored_metadata(source, relative)
        .map_err(|_| SnapshotMaterializationError::SourceChanged(label.display().to_string()))?;
    if before != handle_after || before != path_after || bytes != before.len || &before != expected
    {
        return Err(SnapshotMaterializationError::SourceChanged(
            label.display().to_string(),
        ));
    }
    Ok((hex::encode(hasher.finalize()), bytes))
}

fn read_bounded_anchored_file(
    source: &AnchoredSource,
    relative: Option<&str>,
    expected: &StableMetadata,
    maximum: usize,
) -> Result<Vec<u8>, SnapshotMaterializationError> {
    let label = anchored_source_label(source, relative);
    let file = source
        .open(relative)
        .map_err(|_| SnapshotMaterializationError::SourceChanged(label.display().to_string()))?;
    let before = stable_metadata(&file.metadata()?)?;
    if &before != expected || !file.metadata()?.is_file() {
        return Err(SnapshotMaterializationError::SourceChanged(
            label.display().to_string(),
        ));
    }
    if before.len > maximum as u64 {
        return Err(SnapshotMaterializationError::JsonTooLarge);
    }
    let mut reader = BufReader::new(file).take(maximum as u64 + 1);
    let capacity =
        usize::try_from(before.len).map_err(|_| SnapshotMaterializationError::JsonTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);
    reader.read_to_end(&mut bytes)?;
    let reader = reader.into_inner();
    let handle_after = stable_metadata(&reader.get_ref().metadata()?)?;
    let path_after = anchored_metadata(source, relative)
        .map_err(|_| SnapshotMaterializationError::SourceChanged(label.display().to_string()))?;
    if bytes.len() > maximum
        || before != handle_after
        || before != path_after
        || bytes.len() as u64 != before.len
        || &before != expected
    {
        return Err(SnapshotMaterializationError::SourceChanged(
            label.display().to_string(),
        ));
    }
    Ok(bytes)
}

fn anchored_metadata(
    source: &AnchoredSource,
    relative: Option<&str>,
) -> io::Result<StableMetadata> {
    match relative {
        Some(relative) => stable_metadata(&source.open(Some(relative))?.metadata()?),
        None => stable_metadata(&source.metadata()?),
    }
}

fn anchored_source_label(source: &AnchoredSource, relative: Option<&str>) -> PathBuf {
    match relative {
        Some(relative) => source.path().join(relative),
        None => source.path().to_owned(),
    }
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
    source: &AnchoredSource,
    destination: &Path,
    expected: &CanonicalSnapshotTree,
) -> Result<(), SnapshotMaterializationError> {
    for entry in expected.entries() {
        let destination_path = destination.join(&entry.path);
        ensure_parent_directories(destination, &destination_path)?;
        match &entry.kind {
            CanonicalSnapshotEntryKind::Directory => {
                ensure_directory_overlay(&destination_path)?;
            }
            CanonicalSnapshotEntryKind::RegularFile { sha256, bytes } => {
                copy_file_overlay(source, Some(&entry.path), &destination_path, sha256, *bytes)?;
            }
        }
    }
    if scan_anchored_tree(source)? != *expected {
        return Err(SnapshotMaterializationError::SourceChanged(
            source.path().display().to_string(),
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
    source: &AnchoredSource,
    source_relative: Option<&str>,
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

    let source_label = anchored_source_label(source, source_relative);
    let source_file = source.open(source_relative).map_err(|_| {
        SnapshotMaterializationError::SourceChanged(source_label.display().to_string())
    })?;
    let source_metadata = source_file.metadata()?;
    if !source_metadata.is_file()
        || source_metadata.len() != expected_bytes
        || expected_bytes > MAX_CANONICAL_SNAPSHOT_FILE_BYTES
    {
        return Err(SnapshotMaterializationError::UnsupportedSourceEntry(
            source_label.display().to_string(),
        ));
    }
    let before = stable_metadata(&source_metadata)?;
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
            SnapshotMaterializationError::SourceBounds(source_label.display().to_string())
        })?;
        if bytes > MAX_CANONICAL_SNAPSHOT_FILE_BYTES {
            return Err(SnapshotMaterializationError::SourceBounds(
                source_label.display().to_string(),
            ));
        }
        hasher.update(&buffer[..read]);
        destination_file.write_all(&buffer[..read])?;
    }
    destination_file.flush()?;
    let digest = hex::encode(hasher.finalize());
    let handle_after = stable_metadata(&reader.get_ref().metadata()?)?;
    let path_after = anchored_metadata(source, source_relative).map_err(|_| {
        SnapshotMaterializationError::SourceChanged(source_label.display().to_string())
    })?;
    if before != handle_after
        || before != path_after
        || bytes != expected_bytes
        || digest != expected_digest
    {
        return Err(SnapshotMaterializationError::SourceChanged(
            source_label.display().to_string(),
        ));
    }
    Ok(())
}

fn expected_file_digest(content: &HostBuildClosureContent) -> Option<&str> {
    match content {
        HostBuildClosureContent::File { sha256 } => Some(sha256),
        HostBuildClosureContent::CanonicalRecord { bytes_sha256, .. }
        | HostBuildClosureContent::CustomTargetSpec { bytes_sha256, .. } => Some(bytes_sha256),
        HostBuildClosureContent::SignedEvidence { bytes_digest, .. } => Some(bytes_digest),
        HostBuildClosureContent::SnapshotTree { .. } => None,
    }
}

fn retains_semantic_bytes(item: &NormalizedHostBuildClosureItem) -> bool {
    matches!(
        item.content,
        HostBuildClosureContent::CanonicalRecord { .. }
            | HostBuildClosureContent::CustomTargetSpec { .. }
    ) || item.role == HostBuildClosureItemRole::CargoConfig
}

fn semantic_file_limit(item: &NormalizedHostBuildClosureItem) -> usize {
    if item.role == HostBuildClosureItemRole::CustomTargetSpec {
        usize::try_from(MAX_CUSTOM_TARGET_SPEC_BYTES)
            .expect("custom-target byte limit fits the host address space")
    } else {
        MAX_CANONICAL_SNAPSHOT_JSON_BYTES
    }
}

fn verify_snapshot_canonical_records(
    closure: &NormalizedHostBuildInputClosure,
    snapshot_root: &AnchoredDirectory,
) -> Result<(), SnapshotMaterializationError> {
    let mut semantic_file_bytes = BTreeMap::<HostBuildClosureItemRole, Vec<u8>>::new();
    for item in closure.items() {
        if !retains_semantic_bytes(item) {
            continue;
        }
        let relative = logical_relative(&item.logical_path)?;
        let source = snapshot_root.open_entry(&format!("{SNAPSHOT_DATA_DIRECTORY}/{relative}"))?;
        let plan = preflight_source_file(&source)?;
        let bytes = read_preflighted_file(&source, &plan, semantic_file_limit(item))?;
        if matches!(
            item.content,
            HostBuildClosureContent::CanonicalRecord { .. }
        ) {
            verify_canonical_record(item, &bytes, closure.build_context())?;
        }
        if matches!(
            item.content,
            HostBuildClosureContent::CustomTargetSpec { .. }
        ) {
            verify_custom_target_spec(closure, &bytes)?;
        }
        semantic_file_bytes.insert(item.role, bytes);
    }
    verify_canonical_cargo_config(
        closure,
        semantic_file_bytes
            .get(&HostBuildClosureItemRole::CargoConfig)
            .expect("normalized closure retains its Cargo config"),
        semantic_file_bytes
            .get(&HostBuildClosureItemRole::CargoResolutionRecord)
            .expect("normalized closure retains its Cargo resolution record"),
    )?;
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
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
        }
        | HostBuildClosureContent::CustomTargetSpec {
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

fn publication_tree(
    source_tree: &CanonicalSnapshotTree,
    manifest_name: &str,
    manifest_bytes: &[u8],
) -> Result<CanonicalSnapshotTree, SnapshotMaterializationError> {
    if manifest_bytes.is_empty()
        || manifest_bytes.len() > MAX_CANONICAL_SNAPSHOT_JSON_BYTES
        || manifest_name.is_empty()
        || manifest_name.len() > 255
        || !manifest_name.is_ascii()
        || manifest_name.contains(['/', '\\'])
        || matches!(manifest_name, "." | "..")
    {
        return Err(SnapshotMaterializationError::SnapshotContentMismatch);
    }
    let mut entries = source_tree.entries().to_vec();
    entries.push(CanonicalSnapshotEntry::regular_file(
        manifest_name,
        sha256_bytes(manifest_bytes),
        manifest_bytes.len() as u64,
    ));
    Ok(CanonicalSnapshotTree::from_entries(entries)?)
}

fn write_publication_manifest(
    staging: &Path,
    manifest_name: &str,
    manifest_bytes: &[u8],
) -> Result<(), SnapshotMaterializationError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(staging.join(manifest_name))?;
    let mut writer = BufWriter::new(file);
    writer.write_all(manifest_bytes)?;
    writer.flush()?;
    Ok(())
}

fn seal_local_storage_projection(
    root: &AnchoredDirectory,
) -> Result<(), SnapshotMaterializationError> {
    #[cfg(target_os = "linux")]
    {
        let source = root.as_source();
        let plan = preflight_source_tree(&source)?;
        let mut directories = Vec::new();
        for entry in &plan.entries {
            let anchored = root.open_entry(&entry.path)?;
            if entry.directory {
                directories.push((entry.path.matches('/').count(), anchored));
            } else {
                set_epoch_times(&anchored.handle)?;
                fchmod(
                    &*anchored.handle,
                    Mode::from(rust_agent_composition::snapshot::READ_ONLY_EPOCH_V1_FILE_MODE),
                )
                .map_err(rustix_io_error)?;
            }
        }
        directories.sort_by_key(|(depth, _)| std::cmp::Reverse(*depth));
        for (_, directory) in directories {
            set_epoch_times(&directory.handle)?;
            fchmod(
                &*directory.handle,
                Mode::from(rust_agent_composition::snapshot::READ_ONLY_EPOCH_V1_DIRECTORY_MODE),
            )
            .map_err(rustix_io_error)?;
        }
        set_epoch_times(&root.handle)?;
        fchmod(
            &*root.handle,
            Mode::from(rust_agent_composition::snapshot::READ_ONLY_EPOCH_V1_DIRECTORY_MODE),
        )
        .map_err(rustix_io_error)?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = root;
        Err(SnapshotMaterializationError::UnsupportedHost)
    }
}

#[cfg(target_os = "linux")]
fn set_epoch_times(file: &File) -> io::Result<()> {
    file.set_times(
        FileTimes::new()
            .set_accessed(SystemTime::UNIX_EPOCH)
            .set_modified(SystemTime::UNIX_EPOCH),
    )
}

fn verify_snapshot_filesystem(
    manifest: &HostClosureSnapshotManifest,
    root: &AnchoredDirectory,
) -> Result<(), SnapshotMaterializationError> {
    let expected_manifest_bytes = canonical::jcs_bytes(manifest)?;
    let mut expected_entries = vec![
        CanonicalSnapshotEntry::directory(SNAPSHOT_DATA_DIRECTORY),
        CanonicalSnapshotEntry::regular_file(
            SNAPSHOT_MANIFEST_FILE,
            sha256_bytes(&expected_manifest_bytes),
            expected_manifest_bytes.len() as u64,
        ),
    ];
    for entry in &manifest.data_tree_entries {
        let mut expected = entry.clone();
        expected.path = format!("{SNAPSHOT_DATA_DIRECTORY}/{}", entry.path);
        expected_entries.push(expected);
    }
    let expected_tree = CanonicalSnapshotTree::from_entries(expected_entries)?;
    verify_anchored_storage_tree(root, &expected_tree)
}

fn verify_anchored_storage_tree(
    root: &AnchoredDirectory,
    expected_tree: &CanonicalSnapshotTree,
) -> Result<(), SnapshotMaterializationError> {
    verify_local_storage_projection(&stable_metadata(&root.handle_metadata()?)?, true)?;
    let source = root.as_source();
    let plan = preflight_source_tree(&source)
        .map_err(|_| SnapshotMaterializationError::SnapshotContentMismatch)?;
    for entry in &plan.entries {
        verify_local_storage_projection(&entry.metadata, entry.directory)?;
    }
    let actual_tree = hash_preflighted_tree(&source, &plan)
        .map_err(|_| SnapshotMaterializationError::SnapshotContentMismatch)?;
    if &actual_tree != expected_tree {
        return Err(SnapshotMaterializationError::SnapshotContentMismatch);
    }
    Ok(())
}

fn verify_local_storage_projection(
    metadata: &StableMetadata,
    directory: bool,
) -> Result<(), SnapshotMaterializationError> {
    #[cfg(unix)]
    {
        let expected_mode = if directory {
            rust_agent_composition::snapshot::READ_ONLY_EPOCH_V1_DIRECTORY_MODE
        } else {
            rust_agent_composition::snapshot::READ_ONLY_EPOCH_V1_FILE_MODE
        };
        if metadata.mode & 0o7777 != expected_mode
            || metadata.mtime != 0
            || metadata.mtime_nanos != 0
        {
            return Err(SnapshotMaterializationError::StorageMetadataMismatch);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (metadata, directory);
        Err(SnapshotMaterializationError::UnsupportedHost)
    }
}

fn sync_snapshot_tree(root: &AnchoredDirectory) -> Result<(), SnapshotMaterializationError> {
    #[cfg(target_os = "linux")]
    {
        let source = root.as_source();
        let plan = preflight_source_tree(&source)?;
        let mut directories = Vec::new();
        for entry in &plan.entries {
            let anchored = root.open_entry(&entry.path)?;
            if entry.directory {
                directories.push((entry.path.matches('/').count(), anchored));
            } else {
                anchored.handle.sync_all()?;
            }
        }
        directories.sort_by_key(|(depth, _)| std::cmp::Reverse(*depth));
        for (_, directory) in directories {
            directory.handle.sync_all()?;
        }
        root.handle.sync_all()?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = root;
        Err(SnapshotMaterializationError::UnsupportedHost)
    }
}

#[cfg(target_os = "linux")]
fn publish_noreplace(
    destination: &AnchoredDestination,
    staging: &mut StagingDirectory,
) -> io::Result<()> {
    staging.ensure_linked()?;
    renameat_with(
        &*destination.parent.handle,
        staging.name.as_str(),
        &*destination.parent.handle,
        destination.output_name.as_str(),
        RenameFlags::NOREPLACE,
    )
    .map_err(rustix_io_error)?;
    staging.published = true;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn publish_noreplace(
    _destination: &AnchoredDestination,
    _staging: &mut StagingDirectory,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "snapshot publication requires Linux renameat2",
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::FileExt as _;

    use super::*;

    #[test]
    fn source_file_descriptor_is_not_redirected_by_path_replacement() {
        let temp = tempfile::TempDir::new().unwrap();
        let source_path = temp.path().join("source");
        let displaced_path = temp.path().join("source-displaced");
        fs::write(&source_path, b"trusted").unwrap();
        let source_path = fs::canonicalize(source_path).unwrap();
        let anchored = anchor_source_path(&source_path).unwrap();
        let plan = preflight_source_file(&anchored).unwrap();

        fs::rename(&source_path, &displaced_path).unwrap();
        fs::write(&source_path, b"attacker").unwrap();

        match read_preflighted_file(&anchored, &plan, 32) {
            Ok(bytes) => assert_eq!(bytes, b"trusted"),
            Err(SnapshotMaterializationError::SourceChanged(path)) => {
                assert_eq!(path, source_path.display().to_string());
            }
            Err(error) => panic!("unexpected anchored read result: {error}"),
        }
        let mut anchored_bytes = [0_u8; 7];
        assert_eq!(anchored.handle.read_at(&mut anchored_bytes, 0).unwrap(), 7);
        assert_eq!(&anchored_bytes, b"trusted");
    }

    #[test]
    fn source_tree_descriptor_is_not_redirected_by_root_replacement() {
        let temp = tempfile::TempDir::new().unwrap();
        let source_path = temp.path().join("source-tree");
        let displaced_path = temp.path().join("source-tree-displaced");
        fs::create_dir(&source_path).unwrap();
        fs::write(source_path.join("input"), b"trusted").unwrap();
        let source_path = fs::canonicalize(source_path).unwrap();
        let anchored = anchor_source_path(&source_path).unwrap();
        let expected = scan_anchored_tree(&anchored).unwrap();

        fs::rename(&source_path, &displaced_path).unwrap();
        fs::create_dir(&source_path).unwrap();
        fs::write(source_path.join("input"), b"attacker").unwrap();

        assert_eq!(scan_anchored_tree(&anchored).unwrap(), expected);
    }

    #[test]
    fn source_tree_descriptor_rejects_a_relative_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::TempDir::new().unwrap();
        let source_path = temp.path().join("source-tree");
        let external_path = temp.path().join("external");
        fs::create_dir(&source_path).unwrap();
        fs::write(&external_path, b"external").unwrap();
        let source_path = fs::canonicalize(source_path).unwrap();
        let anchored = anchor_source_path(&source_path).unwrap();
        symlink(&external_path, source_path.join("redirect")).unwrap();

        assert!(matches!(
            preflight_source_tree(&anchored),
            Err(SnapshotMaterializationError::UnsupportedSourceEntry(_))
        ));
    }

    #[test]
    fn writable_output_collection_rejects_root_and_file_replacement() {
        let temp = tempfile::TempDir::new().unwrap();
        let output = temp.path().join("output");
        let displaced = temp.path().join("output-displaced");
        fs::create_dir(&output).unwrap();
        fs::write(output.join("artifact"), b"trusted").unwrap();
        let output = fs::canonicalize(output).unwrap();
        let anchored = anchor_writable_directory(&output).unwrap();
        let files = anchored.anchor_regular_files().unwrap();
        let [(relative, artifact)] = files.as_slice() else {
            panic!("expected one anchored output");
        };
        assert_eq!(relative, "artifact");

        fs::rename(&output, &displaced).unwrap();
        fs::create_dir(&output).unwrap();
        fs::write(output.join("artifact"), b"attacker").unwrap();

        assert!(matches!(
            anchored.anchor_regular_files(),
            Err(SnapshotMaterializationError::SourceChanged(path)) if path == output.display().to_string()
        ));
        assert!(matches!(
            artifact.reverify(),
            Err(SnapshotMaterializationError::SourceChanged(path))
                if path == displaced.join("artifact").display().to_string()
                    || path == output.join("artifact").display().to_string()
        ));
    }

    #[test]
    fn descriptor_relative_atomic_write_is_no_clobber_and_root_bound() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::TempDir::new().unwrap();
        let output = temp.path().join("output");
        let displaced = temp.path().join("output-displaced");
        fs::create_dir(&output).unwrap();
        let output = fs::canonicalize(output).unwrap();
        let anchored = anchor_writable_directory(&output).unwrap();

        assert!(
            anchored
                .write_new_file_atomic("receipt.json", b"trusted\n", 0o444)
                .unwrap()
        );
        assert!(
            !anchored
                .write_new_file_atomic("receipt.json", b"attacker\n", 0o444)
                .unwrap()
        );
        assert_eq!(fs::read(output.join("receipt.json")).unwrap(), b"trusted\n");
        assert_eq!(
            fs::metadata(output.join("receipt.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o444
        );

        fs::rename(&output, &displaced).unwrap();
        fs::create_dir(&output).unwrap();
        assert!(matches!(
            anchored.write_new_file_atomic("redirected", b"denied", 0o444),
            Err(SnapshotMaterializationError::SourceChanged(path)) if path == output.display().to_string()
        ));
        assert!(!output.join("redirected").exists());
    }

    #[test]
    fn destination_parent_descriptor_is_not_redirected_by_path_replacement() {
        let temp = tempfile::TempDir::new().unwrap();
        let parent = temp.path().join("snapshot-parent");
        let displaced_parent = temp.path().join("snapshot-parent-displaced");
        fs::create_dir(&parent).unwrap();
        let output = parent.join("snapshot");
        let destination = anchor_destination(&output).unwrap();

        fs::rename(&parent, &displaced_parent).unwrap();
        fs::create_dir(&parent).unwrap();
        let staging = destination.create_staging().unwrap();
        let staging_name = staging.name.clone();
        fs::write(
            staging.directory.operation_path().join("trusted"),
            b"trusted",
        )
        .unwrap();

        assert!(
            displaced_parent
                .join(&staging_name)
                .join("trusted")
                .is_file()
        );
        assert!(!parent.join(&staging_name).exists());
        drop(staging);
        assert!(!displaced_parent.join(staging_name).exists());
    }

    #[test]
    fn staging_directory_replacement_is_rejected_before_publication() {
        let temp = tempfile::TempDir::new().unwrap();
        let output = temp.path().join("snapshot");
        let destination = anchor_destination(&output).unwrap();
        let mut staging = destination.create_staging().unwrap();
        let staging_path = temp.path().join(&staging.name);
        let displaced = temp.path().join("displaced-staging");

        fs::rename(&staging_path, &displaced).unwrap();
        fs::create_dir(&staging_path).unwrap();
        fs::write(staging_path.join("attacker"), b"attacker").unwrap();

        let error = publish_noreplace(&destination, &mut staging).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(!output.exists());
        assert_eq!(
            fs::read(staging_path.join("attacker")).unwrap(),
            b"attacker"
        );

        drop(staging);
        fs::remove_dir_all(&staging_path).unwrap();
        fs::remove_dir(&displaced).unwrap();
    }

    #[test]
    fn published_directory_handle_detects_output_path_replacement() {
        let temp = tempfile::TempDir::new().unwrap();
        let output = temp.path().join("snapshot");
        let displaced = temp.path().join("snapshot-displaced");
        let destination = anchor_destination(&output).unwrap();
        let mut staging = destination.create_staging().unwrap();
        fs::write(
            staging.directory.operation_path().join("trusted"),
            b"trusted",
        )
        .unwrap();
        publish_noreplace(&destination, &mut staging).unwrap();

        fs::rename(&output, &displaced).unwrap();
        fs::create_dir(&output).unwrap();
        fs::write(output.join("attacker"), b"attacker").unwrap();

        assert_eq!(
            fs::read(staging.directory.operation_path().join("trusted")).unwrap(),
            b"trusted"
        );
        assert!(matches!(
            destination.ensure_output_matches(&staging.directory),
            Err(SnapshotMaterializationError::DestinationPathChanged(_))
        ));

        drop(staging);
        fs::remove_dir_all(output).unwrap();
        fs::remove_dir_all(displaced).unwrap();
    }

    #[test]
    fn rename_noreplace_preserves_an_existing_destination() {
        let temp = tempfile::TempDir::new().unwrap();
        let destination = temp.path().join("destination");
        fs::create_dir(&destination).unwrap();
        let destination_anchor = anchor_destination(&destination).unwrap();
        let mut staging = destination_anchor.create_staging().unwrap();
        fs::write(
            staging.directory.operation_path().join("source-marker"),
            b"source",
        )
        .unwrap();

        let error = publish_noreplace(&destination_anchor, &mut staging).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(fs::read_dir(&destination).unwrap().next().is_none());
        assert_eq!(
            fs::read(staging.directory.operation_path().join("source-marker")).unwrap(),
            b"source"
        );
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
