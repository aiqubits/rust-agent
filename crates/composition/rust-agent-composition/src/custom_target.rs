use std::{
    cell::Cell,
    collections::BTreeSet,
    fmt,
    fs::{self, File, Metadata},
    io::{self, BufReader, Read},
    path::Path,
    time::SystemTime,
};

use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    canonical::{self, CanonicalError},
    target::validate_target_triple,
};

pub const MAX_CUSTOM_TARGET_SPEC_BYTES: u64 = 256 * 1024;
const MAX_CUSTOM_TARGET_JSON_DEPTH: usize = 16;
const MAX_CUSTOM_TARGET_JSON_ITEMS: usize = 16 * 1024;
const MAX_CUSTOM_TARGET_JSON_STRING_BYTES: usize = 64 * 1024;
const MAX_CUSTOM_TARGET_JSON_KEY_BYTES: usize = 256;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedCustomTargetSpecRecord")]
pub struct CustomTargetSpecRecord {
    pub schema: u32,
    #[serde(rename = "logical-triple")]
    pub logical_triple: String,
    #[serde(rename = "snapshot-path")]
    pub snapshot_path: String,
    #[serde(rename = "raw-bytes-sha256")]
    pub raw_bytes_sha256: String,
    #[serde(rename = "canonical-json-sha256")]
    pub canonical_json_sha256: String,
    #[serde(rename = "custom-target-spec-digest")]
    pub custom_target_spec_digest: String,
}

/// A point-in-time observation of a verified custom-target snapshot.
///
/// Equality includes the underlying file identity where the host exposes one.
/// It is intentionally only a drift detector for the development path: it does
/// not make a path immutable against a same-UID replace-and-restore attack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomTargetSnapshotObservation {
    custom_target_spec_digest: String,
    raw_bytes_sha256: String,
    file_identity: SnapshotFileIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SnapshotFileIdentity {
    bytes: u64,
    modified: Option<SystemTime>,
    created: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedCustomTargetSpecRecord {
    schema: u32,
    #[serde(rename = "logical-triple")]
    logical_triple: String,
    #[serde(rename = "snapshot-path")]
    snapshot_path: String,
    #[serde(rename = "raw-bytes-sha256")]
    raw_bytes_sha256: String,
    #[serde(rename = "canonical-json-sha256")]
    canonical_json_sha256: String,
    #[serde(rename = "custom-target-spec-digest")]
    custom_target_spec_digest: String,
}

#[derive(Serialize)]
struct CustomTargetSpecIdentity<'a> {
    schema: u32,
    #[serde(rename = "raw-bytes-sha256")]
    raw_bytes_sha256: &'a str,
    #[serde(rename = "canonical-json-sha256")]
    canonical_json_sha256: &'a str,
}

#[derive(Debug, Error)]
pub enum CustomTargetSpecError {
    #[error("custom target spec has {actual} bytes; maximum is {maximum}")]
    TooLarge { actual: u64, maximum: u64 },
    #[error("custom target spec JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("custom target spec must be a JSON object")]
    NonObject,
    #[error("custom target spec floating-point numbers are forbidden")]
    FloatingPoint,
    #[error("custom target spec record has an unknown schema")]
    UnknownSchema,
    #[error("custom target logical triple is invalid: {0}")]
    InvalidLogicalTriple(String),
    #[error("custom target snapshot path is invalid: {0}")]
    InvalidSnapshotPath(String),
    #[error("custom target snapshot path must be explicit and absolute: {0}")]
    SnapshotPathNotAbsolute(String),
    #[error("custom target snapshot must be a concrete regular file: {0}")]
    InvalidSnapshotFile(String),
    #[error("custom target snapshot changed while it was being verified: {0}")]
    SnapshotChanged(String),
    #[error("custom target snapshot identity changed across {operation}")]
    SnapshotIdentityChanged { operation: &'static str },
    #[error("custom target snapshot I/O failed: {0}")]
    SnapshotIo(#[from] io::Error),
    #[error("custom target spec record digest is invalid: {0}")]
    InvalidDigest(&'static str),
    #[error("custom target spec bytes do not match their declared identity: {0}")]
    IdentityMismatch(&'static str),
    #[error("custom target canonical encoding failed: {0}")]
    Canonical(#[from] CanonicalError),
}

impl CustomTargetSpecRecord {
    pub fn from_raw_bytes(
        logical_triple: &str,
        bytes: &[u8],
    ) -> Result<Self, CustomTargetSpecError> {
        validate_logical_triple(logical_triple)?;
        let (raw_bytes_sha256, canonical_json_sha256) = spec_digests(bytes)?;
        let custom_target_spec_digest =
            composite_digest(&raw_bytes_sha256, &canonical_json_sha256)?;
        Ok(Self {
            schema: 1,
            logical_triple: logical_triple.to_owned(),
            snapshot_path: format!("targets/{logical_triple}.json"),
            raw_bytes_sha256,
            canonical_json_sha256,
            custom_target_spec_digest,
        })
    }

    pub fn validate(&self) -> Result<(), CustomTargetSpecError> {
        if self.schema != 1 {
            return Err(CustomTargetSpecError::UnknownSchema);
        }
        validate_logical_triple(&self.logical_triple)?;
        let expected_path = format!("targets/{}.json", self.logical_triple);
        if self.snapshot_path != expected_path {
            return Err(CustomTargetSpecError::InvalidSnapshotPath(
                self.snapshot_path.clone(),
            ));
        }
        for (field, digest) in [
            ("raw-bytes-sha256", self.raw_bytes_sha256.as_str()),
            ("canonical-json-sha256", self.canonical_json_sha256.as_str()),
            (
                "custom-target-spec-digest",
                self.custom_target_spec_digest.as_str(),
            ),
        ] {
            if !is_digest(digest) {
                return Err(CustomTargetSpecError::InvalidDigest(field));
            }
        }
        let composite = composite_digest(&self.raw_bytes_sha256, &self.canonical_json_sha256)?;
        if composite != self.custom_target_spec_digest {
            return Err(CustomTargetSpecError::IdentityMismatch(
                "custom-target-spec-digest",
            ));
        }
        Ok(())
    }

    pub fn verify(&self, bytes: &[u8]) -> Result<(), CustomTargetSpecError> {
        self.validate()?;
        let (raw, canonical) = spec_digests(bytes)?;
        if raw != self.raw_bytes_sha256 {
            return Err(CustomTargetSpecError::IdentityMismatch("raw-bytes-sha256"));
        }
        if canonical != self.canonical_json_sha256 {
            return Err(CustomTargetSpecError::IdentityMismatch(
                "canonical-json-sha256",
            ));
        }
        let composite = composite_digest(&raw, &canonical)?;
        if composite != self.custom_target_spec_digest {
            return Err(CustomTargetSpecError::IdentityMismatch(
                "custom-target-spec-digest",
            ));
        }
        Ok(())
    }
}

impl CustomTargetSnapshotObservation {
    pub fn ensure_unchanged(
        &self,
        current: &Self,
        operation: &'static str,
    ) -> Result<(), CustomTargetSpecError> {
        if self != current {
            return Err(CustomTargetSpecError::SnapshotIdentityChanged { operation });
        }
        Ok(())
    }
}

/// Verify a concrete custom-target snapshot using the record's raw and
/// canonical JSON identities and return a storage observation suitable for a
/// before/after development-path drift check.
pub fn verify_custom_target_snapshot(
    record: &CustomTargetSpecRecord,
    snapshot_path: &Path,
) -> Result<CustomTargetSnapshotObservation, CustomTargetSpecError> {
    record.validate()?;
    if !snapshot_path.is_absolute() {
        return Err(CustomTargetSpecError::SnapshotPathNotAbsolute(
            snapshot_path.display().to_string(),
        ));
    }

    let before = snapshot_metadata(snapshot_path)?;
    let before_identity = snapshot_file_identity(&before);
    let mut file = File::open(snapshot_path)?;
    let handle_before = file.metadata()?;
    ensure_same_snapshot_identity(snapshot_path, &before_identity, &handle_before)?;

    let bytes = read_snapshot_bytes(&mut file)?;
    let handle_after = file.metadata()?;
    ensure_same_snapshot_identity(snapshot_path, &before_identity, &handle_after)?;
    record.verify(&bytes)?;

    let path_after = snapshot_metadata(snapshot_path)?;
    ensure_same_snapshot_identity(snapshot_path, &before_identity, &path_after)?;

    // Re-open and re-verify the current path. On platforms without a stable
    // file id this is the conservative fallback that still checks the exact
    // bounded bytes, rather than trusting only length and timestamps.
    let mut reopened = File::open(snapshot_path)?;
    let reopened_metadata = reopened.metadata()?;
    ensure_same_snapshot_identity(snapshot_path, &before_identity, &reopened_metadata)?;
    let reopened_bytes = read_snapshot_bytes(&mut reopened)?;
    if bytes != reopened_bytes {
        return Err(CustomTargetSpecError::SnapshotChanged(
            snapshot_path.display().to_string(),
        ));
    }
    record.verify(&reopened_bytes)?;
    let final_metadata = snapshot_metadata(snapshot_path)?;
    ensure_same_snapshot_identity(snapshot_path, &before_identity, &final_metadata)?;

    Ok(CustomTargetSnapshotObservation {
        custom_target_spec_digest: record.custom_target_spec_digest.clone(),
        raw_bytes_sha256: sha256_hex(&bytes),
        file_identity: before_identity,
    })
}

fn snapshot_metadata(path: &Path) -> Result<Metadata, CustomTargetSpecError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CustomTargetSpecError::InvalidSnapshotFile(
            path.display().to_string(),
        ));
    }
    if metadata.len() > MAX_CUSTOM_TARGET_SPEC_BYTES {
        return Err(CustomTargetSpecError::TooLarge {
            actual: metadata.len(),
            maximum: MAX_CUSTOM_TARGET_SPEC_BYTES,
        });
    }
    Ok(metadata)
}

fn read_snapshot_bytes(file: &mut File) -> Result<Vec<u8>, CustomTargetSpecError> {
    let mut reader = BufReader::new(file).take(MAX_CUSTOM_TARGET_SPEC_BYTES + 1);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CUSTOM_TARGET_SPEC_BYTES {
        return Err(CustomTargetSpecError::TooLarge {
            actual: bytes.len() as u64,
            maximum: MAX_CUSTOM_TARGET_SPEC_BYTES,
        });
    }
    Ok(bytes)
}

fn ensure_same_snapshot_identity(
    path: &Path,
    expected: &SnapshotFileIdentity,
    metadata: &Metadata,
) -> Result<(), CustomTargetSpecError> {
    if !metadata.is_file() || snapshot_file_identity(metadata) != *expected {
        return Err(CustomTargetSpecError::SnapshotChanged(
            path.display().to_string(),
        ));
    }
    Ok(())
}

fn snapshot_file_identity(metadata: &Metadata) -> SnapshotFileIdentity {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt as _;

    SnapshotFileIdentity {
        bytes: metadata.len(),
        modified: metadata.modified().ok(),
        created: metadata.created().ok(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        changed_seconds: metadata.ctime(),
        #[cfg(unix)]
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

impl TryFrom<UncheckedCustomTargetSpecRecord> for CustomTargetSpecRecord {
    type Error = CustomTargetSpecError;

    fn try_from(value: UncheckedCustomTargetSpecRecord) -> Result<Self, Self::Error> {
        let record = Self {
            schema: value.schema,
            logical_triple: value.logical_triple,
            snapshot_path: value.snapshot_path,
            raw_bytes_sha256: value.raw_bytes_sha256,
            canonical_json_sha256: value.canonical_json_sha256,
            custom_target_spec_digest: value.custom_target_spec_digest,
        };
        record.validate()?;
        Ok(record)
    }
}

fn spec_digests(bytes: &[u8]) -> Result<(String, String), CustomTargetSpecError> {
    if bytes.len() as u64 > MAX_CUSTOM_TARGET_SPEC_BYTES {
        return Err(CustomTargetSpecError::TooLarge {
            actual: bytes.len() as u64,
            maximum: MAX_CUSTOM_TARGET_SPEC_BYTES,
        });
    }
    validate_closed_json(bytes)?;
    let value: Value = serde_json::from_slice(bytes)?;
    if !value.is_object() {
        return Err(CustomTargetSpecError::NonObject);
    }
    reject_floating_point(&value)?;
    let canonical = canonical::jcs_bytes(&value)?;
    Ok((sha256_hex(bytes), sha256_hex(&canonical)))
}

fn composite_digest(
    raw_bytes_sha256: &str,
    canonical_json_sha256: &str,
) -> Result<String, CustomTargetSpecError> {
    Ok(hex::encode(canonical::domain_hash(
        b"rust-agent-custom-target-spec-v1\0",
        &CustomTargetSpecIdentity {
            schema: 1,
            raw_bytes_sha256,
            canonical_json_sha256,
        },
    )?))
}

fn reject_floating_point(value: &Value) -> Result<(), CustomTargetSpecError> {
    match value {
        Value::Number(number) if number.as_i64().is_none() && number.as_u64().is_none() => {
            Err(CustomTargetSpecError::FloatingPoint)
        }
        Value::Array(values) => values.iter().try_for_each(reject_floating_point),
        Value::Object(values) => values.values().try_for_each(reject_floating_point),
        _ => Ok(()),
    }
}

fn validate_logical_triple(value: &str) -> Result<(), CustomTargetSpecError> {
    validate_target_triple(value)
        .map_err(|_| CustomTargetSpecError::InvalidLogicalTriple(value.to_owned()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_closed_json(bytes: &[u8]) -> Result<(), CustomTargetSpecError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let remaining_items = Cell::new(MAX_CUSTOM_TARGET_JSON_ITEMS);
    ClosedJsonSeed {
        depth: 0,
        remaining_items: &remaining_items,
    }
    .deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(())
}

#[derive(Clone, Copy)]
struct ClosedJsonSeed<'budget> {
    depth: usize,
    remaining_items: &'budget Cell<usize>,
}

impl<'de> DeserializeSeed<'de> for ClosedJsonSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > MAX_CUSTOM_TARGET_JSON_DEPTH {
            return Err(de::Error::custom("JSON nesting exceeds the schema bound"));
        }
        let remaining = self.remaining_items.get();
        if remaining == 0 {
            return Err(de::Error::custom(
                "JSON item count exceeds the schema bound",
            ));
        }
        self.remaining_items.set(remaining - 1);
        deserializer.deserialize_any(ClosedJsonVisitor {
            depth: self.depth,
            remaining_items: self.remaining_items,
        })
    }
}

struct ClosedJsonVisitor<'budget> {
    depth: usize,
    remaining_items: &'budget Cell<usize>,
}

impl<'de> Visitor<'de> for ClosedJsonVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON without duplicate object keys or floating point")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<(), E>
    where
        E: de::Error,
    {
        Err(E::custom("floating-point JSON numbers are forbidden"))
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        ClosedJsonSeed {
            depth: self.depth + 1,
            remaining_items: self.remaining_items,
        }
        .deserialize(deserializer)
    }

    fn visit_str<E>(self, value: &str) -> Result<(), E>
    where
        E: de::Error,
    {
        if value.len() > MAX_CUSTOM_TARGET_JSON_STRING_BYTES {
            return Err(E::custom("JSON string exceeds the schema bound"));
        }
        Ok(())
    }

    fn visit_string<E>(self, value: String) -> Result<(), E>
    where
        E: de::Error,
    {
        self.visit_str(&value)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(ClosedJsonSeed {
                depth: self.depth + 1,
                remaining_items: self.remaining_items,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > MAX_CUSTOM_TARGET_JSON_KEY_BYTES {
                return Err(de::Error::custom(
                    "JSON object key exceeds the schema bound",
                ));
            }
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            map.next_value_seed(ClosedJsonSeed {
                depth: self.depth + 1,
                remaining_items: self.remaining_items,
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::FileTimes, path::PathBuf};

    use super::*;

    #[test]
    fn identity_binds_raw_and_canonical_json() {
        let compact = br#"{"arch":"x86_64","target-pointer-width":"64"}"#;
        let spaced = br#"{ "target-pointer-width": "64", "arch": "x86_64" }"#;
        let first = CustomTargetSpecRecord::from_raw_bytes("fixture-none-none", compact).unwrap();
        assert_eq!(
            first.custom_target_spec_digest,
            "55dcf07fd9a7e9dd01b9e35017c859c0749ff5e41e2b5eb587dda64311a13fbc"
        );
        let second = CustomTargetSpecRecord::from_raw_bytes("fixture-none-none", spaced).unwrap();
        assert_ne!(first.raw_bytes_sha256, second.raw_bytes_sha256);
        assert_eq!(first.canonical_json_sha256, second.canonical_json_sha256);
        assert_ne!(
            first.custom_target_spec_digest,
            second.custom_target_spec_digest
        );
        let different_logical =
            CustomTargetSpecRecord::from_raw_bytes("other-none-none", compact).unwrap();
        assert_eq!(
            first.custom_target_spec_digest,
            different_logical.custom_target_spec_digest
        );
        assert_ne!(first.snapshot_path, different_logical.snapshot_path);
        first.verify(compact).unwrap();
        second.verify(spaced).unwrap();
    }

    #[test]
    fn rejects_duplicate_float_nonobject_depth_and_size() {
        for invalid in [
            br#"{"arch":"x86_64","arch":"aarch64"}"#.as_slice(),
            br#"{"number":1.5}"#.as_slice(),
            br"[]".as_slice(),
        ] {
            assert!(CustomTargetSpecRecord::from_raw_bytes("fixture-none-none", invalid).is_err());
        }
        let mut nested = String::new();
        for _ in 0..=MAX_CUSTOM_TARGET_JSON_DEPTH {
            nested.push_str("{\"x\":");
        }
        nested.push_str("null");
        for _ in 0..=MAX_CUSTOM_TARGET_JSON_DEPTH {
            nested.push('}');
        }
        assert!(
            CustomTargetSpecRecord::from_raw_bytes("fixture-none-none", nested.as_bytes()).is_err()
        );
        let oversized = vec![b' '; usize::try_from(MAX_CUSTOM_TARGET_SPEC_BYTES).unwrap() + 1];
        assert!(matches!(
            CustomTargetSpecRecord::from_raw_bytes("fixture-none-none", &oversized),
            Err(CustomTargetSpecError::TooLarge { .. })
        ));
    }

    #[test]
    fn rejects_invalid_deserialized_records_and_enforces_a_global_item_budget() {
        let bytes = br#"{"arch":"x86_64"}"#;
        let record = CustomTargetSpecRecord::from_raw_bytes("fixture-none-none", bytes).unwrap();
        let mut value = serde_json::to_value(&record).unwrap();
        value["snapshot-path"] = serde_json::json!("targets/other-none-none.json");
        assert!(serde_json::from_value::<CustomTargetSpecRecord>(value).is_err());

        let allowed_scalars = MAX_CUSTOM_TARGET_JSON_ITEMS - 2;
        let allowed = format!("{{\"items\":[{}]}}", vec!["0"; allowed_scalars].join(","));
        assert!(validate_closed_json(allowed.as_bytes()).is_ok());
        let rejected = format!(
            "{{\"items\":[{}]}}",
            vec!["0"; allowed_scalars + 1].join(",")
        );
        assert!(validate_closed_json(rejected.as_bytes()).is_err());
    }

    #[test]
    fn snapshot_verification_rejects_missing_wrong_and_non_regular_inputs() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot = temp.path().join("target.json");
        let bytes = br#"{"arch":"x86_64"}"#;
        let record = CustomTargetSpecRecord::from_raw_bytes("fixture-none-none", bytes).unwrap();

        assert!(matches!(
            verify_custom_target_snapshot(&record, &snapshot),
            Err(CustomTargetSpecError::SnapshotIo(error))
                if error.kind() == io::ErrorKind::NotFound
        ));

        fs::write(&snapshot, br#"{"arch":"aarch64"}"#).unwrap();
        assert!(matches!(
            verify_custom_target_snapshot(&record, &snapshot),
            Err(CustomTargetSpecError::IdentityMismatch("raw-bytes-sha256"))
        ));

        fs::remove_file(&snapshot).unwrap();
        fs::create_dir(&snapshot).unwrap();
        assert!(matches!(
            verify_custom_target_snapshot(&record, &snapshot),
            Err(CustomTargetSpecError::InvalidSnapshotFile(_))
        ));

        let relative = PathBuf::from("target.json");
        assert!(matches!(
            verify_custom_target_snapshot(&record, &relative),
            Err(CustomTargetSpecError::SnapshotPathNotAbsolute(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn observations_detect_same_bytes_same_mtime_inode_replacement_and_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let snapshot = temp.path().join("target.json");
        let replacement = temp.path().join("replacement.json");
        let bytes = br#"{"arch":"x86_64"}"#;
        fs::write(&snapshot, bytes).unwrap();
        let record = CustomTargetSpecRecord::from_raw_bytes("fixture-none-none", bytes).unwrap();
        let before = verify_custom_target_snapshot(&record, &snapshot).unwrap();
        let original_modified = fs::metadata(&snapshot).unwrap().modified().unwrap();

        fs::write(&replacement, bytes).unwrap();
        File::open(&replacement)
            .unwrap()
            .set_times(FileTimes::new().set_modified(original_modified))
            .unwrap();
        fs::rename(&replacement, &snapshot).unwrap();
        let after = verify_custom_target_snapshot(&record, &snapshot).unwrap();
        assert!(matches!(
            before.ensure_unchanged(&after, "test replacement"),
            Err(CustomTargetSpecError::SnapshotIdentityChanged {
                operation: "test replacement"
            })
        ));

        let link = temp.path().join("target-link.json");
        symlink(&snapshot, &link).unwrap();
        assert!(matches!(
            verify_custom_target_snapshot(&record, &link),
            Err(CustomTargetSpecError::InvalidSnapshotFile(_))
        ));
    }
}
