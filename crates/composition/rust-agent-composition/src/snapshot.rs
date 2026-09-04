use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{canonical, serde_bounds::deserialize_bounded_vec};

const SNAPSHOT_TREE_DOMAIN: &[u8] = b"rust-agent-snapshot-tree-v1\0";

pub const CANONICAL_SNAPSHOT_SCHEMA: u32 = 1;
pub const MAX_CANONICAL_SNAPSHOT_ENTRIES: usize = 100_000;
pub const MAX_CANONICAL_SNAPSHOT_PATH_BYTES: usize = 4_096;
pub const MAX_CANONICAL_SNAPSHOT_PATH_COMPONENT_BYTES: usize = 255;
pub const MAX_CANONICAL_SNAPSHOT_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES: u64 = 4 * MAX_CANONICAL_SNAPSHOT_FILE_BYTES;
pub const MAX_CANONICAL_SNAPSHOT_JSON_BYTES: usize = 64 * 1024 * 1024;

pub const READ_ONLY_EPOCH_V1_FILE_MODE: u32 = 0o444;
pub const READ_ONLY_EPOCH_V1_DIRECTORY_MODE: u32 = 0o555;
pub const READ_ONLY_EPOCH_V1_LOGICAL_UID: u32 = 0;
pub const READ_ONLY_EPOCH_V1_LOGICAL_GID: u32 = 0;
pub const READ_ONLY_EPOCH_V1_TIME_NANOS: u64 = 0;
pub const READ_ONLY_EPOCH_V1_LINK_COUNT: u64 = 1;
pub const READ_ONLY_EPOCH_V1_DEVICE: u64 = 0;
pub const READ_ONLY_EPOCH_V1_INODE: u64 = 0;
pub const READ_ONLY_EPOCH_V1_GENERATION: u64 = 0;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CanonicalSnapshotMetadataContract {
    ReadOnlyEpochV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CanonicalSnapshotMetadata {
    pub contract: CanonicalSnapshotMetadataContract,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub atime_nanos: u64,
    pub mtime_nanos: u64,
    pub ctime_nanos: u64,
    pub birthtime_nanos: u64,
    pub link_count: u64,
    pub device: u64,
    pub inode: u64,
    pub generation: u64,
}

impl CanonicalSnapshotMetadata {
    pub const fn read_only_epoch_v1_file() -> Self {
        Self::read_only_epoch_v1(READ_ONLY_EPOCH_V1_FILE_MODE)
    }

    pub const fn read_only_epoch_v1_directory() -> Self {
        Self::read_only_epoch_v1(READ_ONLY_EPOCH_V1_DIRECTORY_MODE)
    }

    const fn read_only_epoch_v1(mode: u32) -> Self {
        Self {
            contract: CanonicalSnapshotMetadataContract::ReadOnlyEpochV1,
            mode,
            uid: READ_ONLY_EPOCH_V1_LOGICAL_UID,
            gid: READ_ONLY_EPOCH_V1_LOGICAL_GID,
            atime_nanos: READ_ONLY_EPOCH_V1_TIME_NANOS,
            mtime_nanos: READ_ONLY_EPOCH_V1_TIME_NANOS,
            ctime_nanos: READ_ONLY_EPOCH_V1_TIME_NANOS,
            birthtime_nanos: READ_ONLY_EPOCH_V1_TIME_NANOS,
            link_count: READ_ONLY_EPOCH_V1_LINK_COUNT,
            device: READ_ONLY_EPOCH_V1_DEVICE,
            inode: READ_ONLY_EPOCH_V1_INODE,
            generation: READ_ONLY_EPOCH_V1_GENERATION,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CanonicalSnapshotEntryKind {
    Directory,
    RegularFile { sha256: String, bytes: u64 },
}

impl CanonicalSnapshotEntryKind {
    fn expected_metadata(&self) -> CanonicalSnapshotMetadata {
        match self {
            Self::Directory => CanonicalSnapshotMetadata::read_only_epoch_v1_directory(),
            Self::RegularFile { .. } => CanonicalSnapshotMetadata::read_only_epoch_v1_file(),
        }
    }

    fn is_directory(&self) -> bool {
        matches!(self, Self::Directory)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalSnapshotEntry {
    pub path: String,
    pub kind: CanonicalSnapshotEntryKind,
    pub metadata: CanonicalSnapshotMetadata,
}

impl CanonicalSnapshotEntry {
    pub fn directory(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            kind: CanonicalSnapshotEntryKind::Directory,
            metadata: CanonicalSnapshotMetadata::read_only_epoch_v1_directory(),
        }
    }

    pub fn regular_file(path: impl Into<String>, sha256: impl Into<String>, bytes: u64) -> Self {
        Self {
            path: path.into(),
            kind: CanonicalSnapshotEntryKind::RegularFile {
                sha256: sha256.into(),
                bytes,
            },
            metadata: CanonicalSnapshotMetadata::read_only_epoch_v1_file(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CanonicalSnapshotTree {
    schema: u32,
    entries: Vec<CanonicalSnapshotEntry>,
    #[serde(rename = "snapshot-tree-digest")]
    digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct CanonicalSnapshotTreeDocument {
    schema: u32,
    #[serde(deserialize_with = "deserialize_snapshot_entries")]
    entries: Vec<CanonicalSnapshotEntry>,
    #[serde(rename = "snapshot-tree-digest")]
    digest: String,
}

fn deserialize_snapshot_entries<'de, D>(
    deserializer: D,
) -> Result<Vec<CanonicalSnapshotEntry>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_vec(
        deserializer,
        MAX_CANONICAL_SNAPSHOT_ENTRIES,
        "canonical snapshot entries",
    )
}

#[derive(Debug, Error)]
pub enum CanonicalSnapshotError {
    #[error("canonical snapshot JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("canonical snapshot JSON has {actual} bytes; maximum is {maximum}")]
    JsonTooLarge { actual: usize, maximum: usize },
    #[error("unsupported canonical snapshot schema {0}; expected 1")]
    UnsupportedSchema(u32),
    #[error("canonical snapshot tree must contain at least one entry")]
    EmptyTree,
    #[error("canonical snapshot has {actual} entries; maximum is {maximum}")]
    TooManyEntries { actual: usize, maximum: usize },
    #[error("invalid canonical snapshot path `{path}`: {reason}")]
    InvalidPath { path: String, reason: &'static str },
    #[error("duplicate canonical snapshot path `{0}`")]
    DuplicatePath(String),
    #[error("canonical snapshot paths have a case-fold collision: `{first}` and `{second}`")]
    CaseFoldCollision { first: String, second: String },
    #[error("canonical snapshot entry `{path}` is missing directory parent `{parent}`")]
    MissingParentDirectory { path: String, parent: String },
    #[error("canonical snapshot entry `{path}` has non-directory parent `{parent}`")]
    ParentNotDirectory { path: String, parent: String },
    #[error("canonical snapshot regular file `{path}` has invalid SHA-256 digest `{digest}`")]
    InvalidFileDigest { path: String, digest: String },
    #[error("canonical snapshot regular file `{path}` has {actual} bytes; maximum is {maximum}")]
    FileTooLarge {
        path: String,
        actual: u64,
        maximum: u64,
    },
    #[error("canonical snapshot files have {actual} total bytes; maximum is {maximum}")]
    TotalBytesTooLarge { actual: u64, maximum: u64 },
    #[error("canonical snapshot entry `{path}` metadata does not match its kind")]
    MetadataMismatch { path: String },
    #[error("canonical snapshot tree digest is invalid: {0}")]
    InvalidTreeDigest(String),
    #[error("canonical snapshot tree digest mismatch: expected {expected}, actual {actual}")]
    TreeDigestMismatch { expected: String, actual: String },
    #[error("canonical snapshot encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
}

impl CanonicalSnapshotTree {
    pub fn from_entries(
        mut entries: Vec<CanonicalSnapshotEntry>,
    ) -> Result<Self, CanonicalSnapshotError> {
        if entries.is_empty() {
            return Err(CanonicalSnapshotError::EmptyTree);
        }
        if entries.len() > MAX_CANONICAL_SNAPSHOT_ENTRIES {
            return Err(CanonicalSnapshotError::TooManyEntries {
                actual: entries.len(),
                maximum: MAX_CANONICAL_SNAPSHOT_ENTRIES,
            });
        }

        entries.sort_by(|left, right| left.path.cmp(&right.path));
        validate_entries(&entries)?;
        let digest = hex::encode(canonical::domain_hash(SNAPSHOT_TREE_DOMAIN, &entries)?);
        Ok(Self {
            schema: CANONICAL_SNAPSHOT_SCHEMA,
            entries,
            digest,
        })
    }

    pub fn from_json(input: &str) -> Result<Self, CanonicalSnapshotError> {
        if input.len() > MAX_CANONICAL_SNAPSHOT_JSON_BYTES {
            return Err(CanonicalSnapshotError::JsonTooLarge {
                actual: input.len(),
                maximum: MAX_CANONICAL_SNAPSHOT_JSON_BYTES,
            });
        }
        let document: CanonicalSnapshotTreeDocument = serde_json::from_str(input)?;
        if document.schema != CANONICAL_SNAPSHOT_SCHEMA {
            return Err(CanonicalSnapshotError::UnsupportedSchema(document.schema));
        }
        if !is_sha256(&document.digest) {
            return Err(CanonicalSnapshotError::InvalidTreeDigest(document.digest));
        }
        let tree = Self::from_entries(document.entries)?;
        if document.digest != tree.digest {
            return Err(CanonicalSnapshotError::TreeDigestMismatch {
                expected: document.digest,
                actual: tree.digest,
            });
        }
        Ok(tree)
    }

    pub const fn schema(&self) -> u32 {
        self.schema
    }

    pub fn entries(&self) -> &[CanonicalSnapshotEntry] {
        &self.entries
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

fn validate_entries(entries: &[CanonicalSnapshotEntry]) -> Result<(), CanonicalSnapshotError> {
    let mut folded_paths = BTreeMap::<String, String>::new();
    let mut path_kinds = BTreeMap::<&str, bool>::new();
    let mut total_file_bytes = 0_u64;
    let mut previous_path: Option<&str> = None;

    for entry in entries {
        validate_path(&entry.path)?;
        if previous_path == Some(entry.path.as_str()) {
            return Err(CanonicalSnapshotError::DuplicatePath(entry.path.clone()));
        }
        previous_path = Some(&entry.path);

        // Schema v1 admits printable ASCII paths only. ASCII lowercase is therefore
        // its complete, locale-independent case-fold operation.
        let folded = entry.path.to_ascii_lowercase();
        if let Some(first) = folded_paths.insert(folded, entry.path.clone()) {
            return Err(CanonicalSnapshotError::CaseFoldCollision {
                first,
                second: entry.path.clone(),
            });
        }

        if entry.metadata != entry.kind.expected_metadata() {
            return Err(CanonicalSnapshotError::MetadataMismatch {
                path: entry.path.clone(),
            });
        }
        if let CanonicalSnapshotEntryKind::RegularFile { sha256, bytes } = &entry.kind {
            if !is_sha256(sha256) {
                return Err(CanonicalSnapshotError::InvalidFileDigest {
                    path: entry.path.clone(),
                    digest: sha256.clone(),
                });
            }
            if *bytes > MAX_CANONICAL_SNAPSHOT_FILE_BYTES {
                return Err(CanonicalSnapshotError::FileTooLarge {
                    path: entry.path.clone(),
                    actual: *bytes,
                    maximum: MAX_CANONICAL_SNAPSHOT_FILE_BYTES,
                });
            }
            total_file_bytes = total_file_bytes.checked_add(*bytes).ok_or(
                CanonicalSnapshotError::TotalBytesTooLarge {
                    actual: u64::MAX,
                    maximum: MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES,
                },
            )?;
            if total_file_bytes > MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES {
                return Err(CanonicalSnapshotError::TotalBytesTooLarge {
                    actual: total_file_bytes,
                    maximum: MAX_CANONICAL_SNAPSHOT_TOTAL_FILE_BYTES,
                });
            }
        }
        path_kinds.insert(entry.path.as_str(), entry.kind.is_directory());
    }

    for entry in entries {
        if let Some((parent, _)) = entry.path.rsplit_once('/') {
            match path_kinds.get(parent) {
                Some(true) => {}
                Some(false) => {
                    return Err(CanonicalSnapshotError::ParentNotDirectory {
                        path: entry.path.clone(),
                        parent: parent.into(),
                    });
                }
                None => {
                    return Err(CanonicalSnapshotError::MissingParentDirectory {
                        path: entry.path.clone(),
                        parent: parent.into(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), CanonicalSnapshotError> {
    let invalid = |reason: &'static str| CanonicalSnapshotError::InvalidPath {
        path: path.into(),
        reason,
    };
    if path.is_empty() {
        return Err(invalid("path is empty"));
    }
    if path.len() > MAX_CANONICAL_SNAPSHOT_PATH_BYTES {
        return Err(invalid("path exceeds the schema byte limit"));
    }
    if path.starts_with('/') {
        return Err(invalid("absolute paths are forbidden"));
    }
    if path.contains('\\') {
        return Err(invalid("backslashes are forbidden"));
    }
    if !path.bytes().all(|byte| (b' '..=b'~').contains(&byte)) {
        return Err(invalid("path must contain printable ASCII only"));
    }
    for component in path.split('/') {
        if component.is_empty() {
            return Err(invalid("empty path components are forbidden"));
        }
        if matches!(component, "." | "..") {
            return Err(invalid("dot path components are forbidden"));
        }
        if component.len() > MAX_CANONICAL_SNAPSHOT_PATH_COMPONENT_BYTES {
            return Err(invalid("path component exceeds the schema byte limit"));
        }
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    type MetadataDrift = (&'static str, fn(&mut CanonicalSnapshotMetadata));

    fn hash(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn fixture_entries() -> Vec<CanonicalSnapshotEntry> {
        vec![
            CanonicalSnapshotEntry::regular_file("src/lib.rs", hash('a'), 7),
            CanonicalSnapshotEntry::regular_file("Cargo.toml", hash('b'), 11),
            CanonicalSnapshotEntry::directory("src"),
        ]
    }

    #[test]
    fn entry_order_and_digest_are_deterministic() {
        let first = CanonicalSnapshotTree::from_entries(fixture_entries()).unwrap();
        let mut reversed = fixture_entries();
        reversed.reverse();
        let second = CanonicalSnapshotTree::from_entries(reversed).unwrap();

        assert_eq!(first, second);
        assert_eq!(
            first
                .entries()
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            vec!["Cargo.toml", "src", "src/lib.rs"]
        );
        assert_eq!(
            first.digest(),
            hex::encode(
                canonical::domain_hash(b"rust-agent-snapshot-tree-v1\0", &first.entries()).unwrap()
            )
        );
        assert_eq!(
            first.digest(),
            "e8a44c5c6de714341faf9e4d1328ac903df54c5782e1c5d61c4cb41a4922d4f9"
        );
    }

    #[test]
    fn path_and_case_failures_are_deterministic_and_closed() {
        for path in [
            "",
            "/absolute",
            ".",
            "a/./b",
            "a/../b",
            "a//b",
            "a/",
            "a\\b",
            "line\nbreak",
            "café",
        ] {
            assert!(matches!(
                CanonicalSnapshotTree::from_entries(vec![CanonicalSnapshotEntry::directory(path)]),
                Err(CanonicalSnapshotError::InvalidPath { .. })
            ));
        }

        let collision = vec![
            CanonicalSnapshotEntry::directory("readme"),
            CanonicalSnapshotEntry::directory("README"),
        ];
        let mut reversed = collision.clone();
        reversed.reverse();
        let error = CanonicalSnapshotTree::from_entries(collision).unwrap_err();
        let reversed_error = CanonicalSnapshotTree::from_entries(reversed).unwrap_err();
        let fields = |error| match error {
            CanonicalSnapshotError::CaseFoldCollision { first, second } => (first, second),
            other => panic!("expected case-fold collision, got {other:?}"),
        };
        assert_eq!(fields(error), fields(reversed_error));
        assert!(matches!(
            CanonicalSnapshotTree::from_entries(vec![
                CanonicalSnapshotEntry::directory("same"),
                CanonicalSnapshotEntry::directory("same"),
            ]),
            Err(CanonicalSnapshotError::DuplicatePath(path)) if path == "same"
        ));
    }

    #[test]
    fn path_entry_and_byte_limits_are_enforced_at_the_boundary() {
        let maximum_component = "a".repeat(MAX_CANONICAL_SNAPSHOT_PATH_COMPONENT_BYTES);
        validate_path(&maximum_component).unwrap();
        assert!(matches!(
            validate_path(&(maximum_component + "a")),
            Err(CanonicalSnapshotError::InvalidPath { .. })
        ));

        let maximum_path = format!("aa/{}a", "a/".repeat(2_046));
        assert_eq!(maximum_path.len(), MAX_CANONICAL_SNAPSHOT_PATH_BYTES);
        validate_path(&maximum_path).unwrap();
        assert!(matches!(
            validate_path(&(maximum_path + "a")),
            Err(CanonicalSnapshotError::InvalidPath { .. })
        ));

        let too_many =
            vec![CanonicalSnapshotEntry::directory("entry"); MAX_CANONICAL_SNAPSHOT_ENTRIES + 1];
        assert!(matches!(
            CanonicalSnapshotTree::from_entries(too_many),
            Err(CanonicalSnapshotError::TooManyEntries { .. })
        ));

        CanonicalSnapshotTree::from_entries(vec![CanonicalSnapshotEntry::regular_file(
            "large",
            hash('a'),
            MAX_CANONICAL_SNAPSHOT_FILE_BYTES,
        )])
        .unwrap();
        assert!(matches!(
            CanonicalSnapshotTree::from_entries(vec![CanonicalSnapshotEntry::regular_file(
                "too-large",
                hash('a'),
                MAX_CANONICAL_SNAPSHOT_FILE_BYTES + 1,
            )]),
            Err(CanonicalSnapshotError::FileTooLarge { .. })
        ));

        let mut exact_total = Vec::new();
        for index in 0..4 {
            exact_total.push(CanonicalSnapshotEntry::regular_file(
                format!("file-{index}"),
                hash('a'),
                MAX_CANONICAL_SNAPSHOT_FILE_BYTES,
            ));
        }
        CanonicalSnapshotTree::from_entries(exact_total.clone()).unwrap();
        exact_total.push(CanonicalSnapshotEntry::regular_file(
            "overflow",
            hash('b'),
            1,
        ));
        assert!(matches!(
            CanonicalSnapshotTree::from_entries(exact_total),
            Err(CanonicalSnapshotError::TotalBytesTooLarge { .. })
        ));
    }

    #[test]
    fn snapshot_entry_collection_is_bounded_during_direct_deserialization() {
        let deserializer = serde::de::value::SeqDeserializer::<_, serde::de::value::Error>::new(
            std::iter::repeat_n(0_u8, MAX_CANONICAL_SNAPSHOT_ENTRIES + 1),
        );
        let error = deserialize_snapshot_entries(deserializer).unwrap_err();
        assert!(error.to_string().contains("canonical snapshot entries"));
    }

    #[test]
    fn tree_topology_requires_explicit_directory_parents() {
        assert!(matches!(
            CanonicalSnapshotTree::from_entries(Vec::new()),
            Err(CanonicalSnapshotError::EmptyTree)
        ));
        assert!(matches!(
            CanonicalSnapshotTree::from_entries(vec![CanonicalSnapshotEntry::regular_file(
                "src/lib.rs",
                hash('a'),
                1,
            )]),
            Err(CanonicalSnapshotError::MissingParentDirectory { .. })
        ));
        assert!(matches!(
            CanonicalSnapshotTree::from_entries(vec![
                CanonicalSnapshotEntry::regular_file("src", hash('a'), 1),
                CanonicalSnapshotEntry::regular_file("src/lib.rs", hash('b'), 1),
            ]),
            Err(CanonicalSnapshotError::ParentNotDirectory { .. })
        ));
    }

    #[test]
    fn metadata_and_file_digest_drift_fail_closed() {
        let mut wrong_file_metadata = CanonicalSnapshotEntry::regular_file("file", hash('a'), 1);
        wrong_file_metadata.metadata = CanonicalSnapshotMetadata::read_only_epoch_v1_directory();
        assert!(matches!(
            CanonicalSnapshotTree::from_entries(vec![wrong_file_metadata]),
            Err(CanonicalSnapshotError::MetadataMismatch { .. })
        ));

        let mut wrong_directory_metadata = CanonicalSnapshotEntry::directory("dir");
        wrong_directory_metadata.metadata.mode = READ_ONLY_EPOCH_V1_FILE_MODE;
        assert!(matches!(
            CanonicalSnapshotTree::from_entries(vec![wrong_directory_metadata]),
            Err(CanonicalSnapshotError::MetadataMismatch { .. })
        ));

        let metadata_drifts: [MetadataDrift; 10] = [
            ("uid", |metadata| metadata.uid = 1),
            ("gid", |metadata| metadata.gid = 1),
            ("atime-nanos", |metadata| metadata.atime_nanos = 1),
            ("mtime-nanos", |metadata| metadata.mtime_nanos = 1),
            ("ctime-nanos", |metadata| metadata.ctime_nanos = 1),
            ("birthtime-nanos", |metadata| metadata.birthtime_nanos = 1),
            ("link-count", |metadata| metadata.link_count = 2),
            ("device", |metadata| metadata.device = 1),
            ("inode", |metadata| metadata.inode = 1),
            ("generation", |metadata| metadata.generation = 1),
        ];
        for (field, drift) in metadata_drifts {
            let mut entry = CanonicalSnapshotEntry::regular_file("file", hash('a'), 1);
            drift(&mut entry.metadata);
            assert!(
                matches!(
                    CanonicalSnapshotTree::from_entries(vec![entry]),
                    Err(CanonicalSnapshotError::MetadataMismatch { .. })
                ),
                "metadata drift in {field} must fail closed"
            );
        }

        assert!(matches!(
            CanonicalSnapshotTree::from_entries(vec![CanonicalSnapshotEntry::regular_file(
                "file",
                "A".repeat(64),
                1,
            )]),
            Err(CanonicalSnapshotError::InvalidFileDigest { .. })
        ));

        let first =
            CanonicalSnapshotTree::from_entries(vec![CanonicalSnapshotEntry::regular_file(
                "file",
                hash('a'),
                1,
            )])
            .unwrap();
        let second =
            CanonicalSnapshotTree::from_entries(vec![CanonicalSnapshotEntry::regular_file(
                "file",
                hash('b'),
                1,
            )])
            .unwrap();
        assert_ne!(first.digest(), second.digest());
    }

    #[test]
    fn tree_json_is_closed_and_recomputes_identity() {
        let tree = CanonicalSnapshotTree::from_entries(fixture_entries()).unwrap();
        let json = serde_json::to_string(&tree).unwrap();
        assert_eq!(CanonicalSnapshotTree::from_json(&json).unwrap(), tree);

        let mut unsupported_schema: Value = serde_json::from_str(&json).unwrap();
        unsupported_schema["schema"] = Value::from(CANONICAL_SNAPSHOT_SCHEMA + 1);
        assert!(matches!(
            CanonicalSnapshotTree::from_json(&serde_json::to_string(&unsupported_schema).unwrap()),
            Err(CanonicalSnapshotError::UnsupportedSchema(schema))
                if schema == CANONICAL_SNAPSHOT_SCHEMA + 1
        ));

        let mut invalid_digest: Value = serde_json::from_str(&json).unwrap();
        invalid_digest["snapshot-tree-digest"] = Value::String("A".repeat(64));
        assert!(matches!(
            CanonicalSnapshotTree::from_json(&serde_json::to_string(&invalid_digest).unwrap()),
            Err(CanonicalSnapshotError::InvalidTreeDigest(_))
        ));

        let mut unknown: Value = serde_json::from_str(&json).unwrap();
        unknown["ambient-path"] = Value::String("/tmp/source".into());
        assert!(matches!(
            CanonicalSnapshotTree::from_json(&serde_json::to_string(&unknown).unwrap()),
            Err(CanonicalSnapshotError::Json(_))
        ));

        let mut drifted: Value = serde_json::from_str(&json).unwrap();
        drifted["snapshot-tree-digest"] = Value::String(hash('0'));
        assert!(matches!(
            CanonicalSnapshotTree::from_json(&serde_json::to_string(&drifted).unwrap()),
            Err(CanonicalSnapshotError::TreeDigestMismatch { .. })
        ));

        let mut unknown_kind_field: Value = serde_json::from_str(&json).unwrap();
        unknown_kind_field["entries"][0]["kind"]["executable"] = Value::Bool(true);
        assert!(matches!(
            CanonicalSnapshotTree::from_json(&serde_json::to_string(&unknown_kind_field).unwrap()),
            Err(CanonicalSnapshotError::Json(_))
        ));

        let boundary_json = vec![b' '; MAX_CANONICAL_SNAPSHOT_JSON_BYTES + 1];
        let exact_boundary =
            std::str::from_utf8(&boundary_json[..MAX_CANONICAL_SNAPSHOT_JSON_BYTES]).unwrap();
        assert!(matches!(
            CanonicalSnapshotTree::from_json(exact_boundary),
            Err(CanonicalSnapshotError::Json(_))
        ));
        let over_boundary = std::str::from_utf8(&boundary_json).unwrap();
        assert!(matches!(
            CanonicalSnapshotTree::from_json(over_boundary),
            Err(CanonicalSnapshotError::JsonTooLarge { actual, maximum })
                if actual == MAX_CANONICAL_SNAPSHOT_JSON_BYTES + 1
                    && maximum == MAX_CANONICAL_SNAPSHOT_JSON_BYTES
        ));
    }
}
