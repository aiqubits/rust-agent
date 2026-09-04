use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, BufReader, Read},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Mutex, OnceLock},
    thread,
    time::{Duration, Instant, SystemTime},
};

use serde::{Deserialize, Deserializer, Serialize, de};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use walkdir::WalkDir;

use crate::canonical;

pub const COMPOSE_RUSTC_PROVENANCE_SCHEMA: u32 = 1;
pub const MAX_RUSTC_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_RUSTC_VERBOSE_VERSION_BYTES: usize = 16 * 1024;
pub const MAX_RUSTC_SYSROOT_OUTPUT_BYTES: usize = 16 * 1024;
pub const MAX_COMPOSE_SYSROOT_ENTRIES: usize = 16 * 1024;
pub const MAX_COMPOSE_SYSROOT_FILE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_COMPOSE_SYSROOT_TOTAL_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_COMPOSE_SYSROOT_RELATIVE_PATH_BYTES: usize = 4 * 1024;

const PINNED_RUST_RELEASE: &str = env!("CARGO_PKG_RUST_VERSION");
const RUSTC_QUERY_TIMEOUT: Duration = Duration::from_secs(30);
const RUSTC_QUERY_POLL_INTERVAL: Duration = Duration::from_millis(10);
const RUSTC_QUERY_TERMINATION_GRACE: Duration = Duration::from_secs(1);
const COMPOSE_RUSTC_IDENTITY_DOMAIN: &[u8] = b"rust-agent-compose-rustc-v1\0";
const COMPOSE_SYSROOT_TREE_DOMAIN: &[u8] = b"rust-agent-compose-sysroot-tree-v1\0";
const SNAPSHOT_BUFFER_BYTES: usize = 64 * 1024;
const MAX_SYSROOT_IDENTITY_CACHE_ENTRIES: usize = 8;

static SYSROOT_IDENTITY_CACHE: OnceLock<Mutex<Vec<SysrootIdentityCacheEntry>>> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedComposeRustcProvenance")]
pub struct ComposeRustcProvenance {
    pub schema: u32,
    pub source: String,
    pub rustc: RustcExecutableProvenance,
    pub sysroot: RustcSysrootProvenance,
    #[serde(rename = "identity-digest")]
    pub identity_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RustcExecutableProvenance {
    pub bytes: u64,
    pub sha256: String,
    #[serde(rename = "verbose-version")]
    pub verbose_version: String,
    #[serde(rename = "verbose-version-sha256")]
    pub verbose_version_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RustcSysrootProvenance {
    #[serde(rename = "tree-digest")]
    pub tree_digest: String,
    pub entries: u64,
    pub files: u64,
    pub directories: u64,
    #[serde(rename = "file-bytes")]
    pub file_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedComposeRustcProvenance {
    schema: u32,
    source: String,
    rustc: RustcExecutableProvenance,
    sysroot: RustcSysrootProvenance,
    #[serde(rename = "identity-digest")]
    identity_digest: String,
}

#[derive(Serialize)]
struct ComposeRustcIdentityPayload<'a> {
    schema: u32,
    source: &'a str,
    rustc: &'a RustcExecutableProvenance,
    sysroot: &'a RustcSysrootProvenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SysrootEntryKind {
    Directory,
    RegularFile,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct SysrootDigestEntry {
    path: String,
    kind: SysrootEntryKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MetadataIdentity {
    kind: SysrootEntryKind,
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
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PlannedSysrootEntry {
    logical_path: String,
    path: PathBuf,
    metadata: MetadataIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SysrootPlan {
    root: PathBuf,
    root_metadata: MetadataIdentity,
    entries: Vec<PlannedSysrootEntry>,
    file_bytes: u64,
}

#[derive(Debug)]
struct SysrootIdentityCacheEntry {
    plan: SysrootPlan,
    rustc_path: PathBuf,
    sysroot: RustcSysrootProvenance,
    rustc_identity: (String, u64),
}

#[derive(Debug)]
pub(crate) struct ComposeRustcSnapshot {
    rustc_path: PathBuf,
    sysroot_path: PathBuf,
    provenance: ComposeRustcProvenance,
    observation: SysrootPlan,
}

#[derive(Debug, Error)]
pub enum ComposeRustcError {
    #[error("compose rustc path must be explicit, absolute, canonical and concrete: {0}")]
    InvalidRustcPath(String),
    #[error("compose rustc executable has {actual} bytes; expected 1..={maximum}")]
    RustcExecutableTooLarge { actual: u64, maximum: u64 },
    #[error("compose rustc query `{query}` failed to start or observe: {error}")]
    QueryIo {
        query: &'static str,
        #[source]
        error: io::Error,
    },
    #[error("compose rustc query `{query}` exceeded its {milliseconds}-millisecond deadline")]
    QueryTimedOut {
        query: &'static str,
        milliseconds: u128,
    },
    #[error("compose rustc query `{query}` {stream} exceeded the {maximum}-byte limit")]
    QueryOutputTooLarge {
        query: &'static str,
        stream: &'static str,
        maximum: usize,
    },
    #[error("compose rustc query `{query}` {stream} is not valid UTF-8")]
    InvalidQueryEncoding {
        query: &'static str,
        stream: &'static str,
    },
    #[error("compose rustc query `{query}` output reader thread panicked")]
    QueryReaderPanicked { query: &'static str },
    #[error("compose rustc query `{query}` failed: {diagnostic}")]
    QueryFailed {
        query: &'static str,
        diagnostic: String,
    },
    #[error("compose rustc verbose version is invalid: {0}")]
    InvalidVerboseVersion(String),
    #[error("compose rustc reported an invalid sysroot: {0}")]
    InvalidSysroot(String),
    #[error("compose rustc must be the concrete `bin/rustc` executable below its reported sysroot")]
    RustcOutsideSysroot,
    #[error("compose rustc sysroot contains a symlink or unsupported entry: {0}")]
    UnsupportedSysrootEntry(String),
    #[error("compose rustc sysroot relative path is invalid: {0}")]
    InvalidSysrootPath(String),
    #[error("compose rustc sysroot has {actual} entries; maximum is {maximum}")]
    TooManySysrootEntries { actual: usize, maximum: usize },
    #[error("compose rustc sysroot file `{path}` has {actual} bytes; maximum is {maximum}")]
    SysrootFileTooLarge {
        path: String,
        actual: u64,
        maximum: u64,
    },
    #[error("compose rustc sysroot files have {actual} aggregate bytes; maximum is {maximum}")]
    SysrootTooLarge { actual: u64, maximum: u64 },
    #[error("compose rustc sysroot contains a case-fold-colliding path: {0}")]
    SysrootPathCollision(String),
    #[error("compose rustc provenance changed during {phase}: {surface}")]
    Drift {
        phase: String,
        surface: &'static str,
    },
    #[error("compose rustc provenance is invalid: {0}")]
    InvalidRecord(String),
    #[error("canonical compose rustc provenance encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
}

impl<'de> Deserialize<'de> for ComposeRustcProvenance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedComposeRustcProvenance::deserialize(deserializer)?;
        Self::try_from(unchecked).map_err(de::Error::custom)
    }
}

impl TryFrom<UncheckedComposeRustcProvenance> for ComposeRustcProvenance {
    type Error = ComposeRustcError;

    fn try_from(value: UncheckedComposeRustcProvenance) -> Result<Self, Self::Error> {
        let record = Self {
            schema: value.schema,
            source: value.source,
            rustc: value.rustc,
            sysroot: value.sysroot,
            identity_digest: value.identity_digest,
        };
        record.validate()?;
        Ok(record)
    }
}

impl ComposeRustcProvenance {
    pub fn validate(&self) -> Result<(), ComposeRustcError> {
        if self.schema != COMPOSE_RUSTC_PROVENANCE_SCHEMA {
            return invalid_record(format!(
                "unsupported schema {}; expected {COMPOSE_RUSTC_PROVENANCE_SCHEMA}",
                self.schema
            ));
        }
        if self.source != "explicit-compose-rustc" {
            return invalid_record("unknown rustc provenance source");
        }
        if self.rustc.bytes == 0 || self.rustc.bytes > MAX_RUSTC_EXECUTABLE_BYTES {
            return invalid_record("rustc executable byte count is outside schema bounds");
        }
        if !is_sha256(&self.rustc.sha256)
            || !is_sha256(&self.rustc.verbose_version_sha256)
            || self.rustc.verbose_version_sha256
                != sha256_hex(self.rustc.verbose_version.as_bytes())
        {
            return invalid_record("rustc executable or version digest is invalid");
        }
        validate_verbose_version(&self.rustc.verbose_version)?;
        let expected_entries = self
            .sysroot
            .files
            .checked_add(self.sysroot.directories)
            .ok_or_else(|| ComposeRustcError::InvalidRecord("sysroot count overflow".into()))?;
        if self.sysroot.entries == 0
            || self.sysroot.entries != expected_entries
            || usize::try_from(self.sysroot.entries)
                .map_or(true, |entries| entries > MAX_COMPOSE_SYSROOT_ENTRIES)
            || self.sysroot.files == 0
            || self.sysroot.file_bytes == 0
            || self.sysroot.file_bytes > MAX_COMPOSE_SYSROOT_TOTAL_FILE_BYTES
            || !is_sha256(&self.sysroot.tree_digest)
        {
            return invalid_record("sysroot identity is outside schema bounds");
        }
        let expected_identity = self.recompute_identity_digest()?;
        if !is_sha256(&self.identity_digest) || self.identity_digest != expected_identity {
            return invalid_record("identity digest does not match the canonical provenance");
        }
        Ok(())
    }

    fn recompute_identity_digest(&self) -> Result<String, ComposeRustcError> {
        Ok(hex::encode(canonical::domain_hash(
            COMPOSE_RUSTC_IDENTITY_DOMAIN,
            &ComposeRustcIdentityPayload {
                schema: self.schema,
                source: &self.source,
                rustc: &self.rustc,
                sysroot: &self.sysroot,
            },
        )?))
    }
}

impl ComposeRustcSnapshot {
    pub(crate) fn capture(rustc_path: &Path) -> Result<Self, ComposeRustcError> {
        let rustc_path = validate_concrete_canonical_rustc_path(rustc_path)?;
        let rustc_before = hash_rustc_executable(&rustc_path)?;
        let version_before = query_verbose_version(&rustc_path)?;
        let sysroot_path = query_sysroot(&rustc_path)?;
        validate_rustc_sysroot_relationship(&rustc_path, &sysroot_path)?;
        let plan = plan_sysroot(&sysroot_path)?;
        let (sysroot, rustc_from_tree) = cached_sysroot_identity(&plan, &rustc_path)?;

        let version_after = query_verbose_version(&rustc_path);
        let sysroot_after = query_sysroot(&rustc_path);
        let rustc_after = hash_rustc_executable(&rustc_path);
        let observation_after = plan_sysroot(&sysroot_path);
        if rustc_after
            .as_ref()
            .is_ok_and(|value| value != &rustc_before)
        {
            return drift("provenance capture", "rustc executable bytes or metadata");
        }
        if observation_after.as_ref().is_ok_and(|value| value != &plan) {
            return drift("provenance capture", "sysroot tree metadata");
        }
        let rustc_after = rustc_after?;
        let observation_after = observation_after?;
        let version_after = version_after?;
        let sysroot_after = sysroot_after?;
        if rustc_after != rustc_before || rustc_from_tree != rustc_before {
            return drift("provenance capture", "rustc executable bytes or metadata");
        }
        if observation_after != plan || sysroot_after != sysroot_path {
            return drift("provenance capture", "sysroot tree metadata");
        }
        if version_after != version_before {
            return drift("provenance capture", "rustc verbose version");
        }

        let rustc = RustcExecutableProvenance {
            bytes: rustc_before.1,
            sha256: rustc_before.0,
            verbose_version_sha256: sha256_hex(version_before.as_bytes()),
            verbose_version: version_before,
        };
        let mut provenance = ComposeRustcProvenance {
            schema: COMPOSE_RUSTC_PROVENANCE_SCHEMA,
            source: "explicit-compose-rustc".into(),
            rustc,
            sysroot,
            identity_digest: String::new(),
        };
        provenance.identity_digest = provenance.recompute_identity_digest()?;
        provenance.validate()?;
        Ok(Self {
            rustc_path,
            sysroot_path,
            provenance,
            observation: plan,
        })
    }

    pub(crate) fn provenance(&self) -> &ComposeRustcProvenance {
        &self.provenance
    }

    pub(crate) fn ensure_unchanged(&self, phase: &str) -> Result<(), ComposeRustcError> {
        let rustc = hash_rustc_executable(&self.rustc_path);
        let version = query_verbose_version(&self.rustc_path);
        let sysroot = query_sysroot(&self.rustc_path);
        let observation = plan_sysroot(&self.sysroot_path);

        if rustc.as_ref().is_ok_and(|value| {
            value.0 != self.provenance.rustc.sha256 || value.1 != self.provenance.rustc.bytes
        }) {
            return drift(phase, "rustc executable bytes or metadata");
        }
        if observation
            .as_ref()
            .is_ok_and(|value| value != &self.observation)
        {
            return drift(phase, "sysroot tree metadata");
        }
        let rustc = rustc?;
        let observation = observation?;
        let version = version?;
        let sysroot = sysroot?;
        if rustc.0 != self.provenance.rustc.sha256 || rustc.1 != self.provenance.rustc.bytes {
            return drift(phase, "rustc executable bytes or metadata");
        }
        if observation != self.observation || sysroot != self.sysroot_path {
            return drift(phase, "sysroot tree metadata");
        }
        if version != self.provenance.rustc.verbose_version {
            return drift(phase, "rustc verbose version");
        }
        Ok(())
    }
}

fn validate_concrete_canonical_rustc_path(path: &Path) -> Result<PathBuf, ComposeRustcError> {
    if !path.is_absolute() {
        return Err(ComposeRustcError::InvalidRustcPath(
            path.display().to_string(),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| ComposeRustcError::QueryIo {
        query: "rustc executable identity",
        error,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ComposeRustcError::InvalidRustcPath(
            path.display().to_string(),
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_RUSTC_EXECUTABLE_BYTES {
        return Err(ComposeRustcError::RustcExecutableTooLarge {
            actual: metadata.len(),
            maximum: MAX_RUSTC_EXECUTABLE_BYTES,
        });
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| ComposeRustcError::QueryIo {
            query: "rustc executable identity",
            error,
        })?;
    #[cfg(not(windows))]
    if canonical != path {
        return Err(ComposeRustcError::InvalidRustcPath(
            path.display().to_string(),
        ));
    }
    Ok(canonical)
}

fn validate_rustc_sysroot_relationship(
    rustc_path: &Path,
    sysroot: &Path,
) -> Result<(), ComposeRustcError> {
    let expected_name = if cfg!(windows) { "rustc.exe" } else { "rustc" };
    if rustc_path.file_name().and_then(|name| name.to_str()) != Some(expected_name)
        || rustc_path.parent().and_then(Path::parent) != Some(sysroot)
        || rustc_path
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            != Some("bin")
    {
        return Err(ComposeRustcError::RustcOutsideSysroot);
    }
    Ok(())
}

fn hash_rustc_executable(path: &Path) -> Result<(String, u64), ComposeRustcError> {
    hash_regular_file(path, "rustc", MAX_RUSTC_EXECUTABLE_BYTES, None)
}

fn query_verbose_version(rustc: &Path) -> Result<String, ComposeRustcError> {
    let bytes = run_rustc_query(
        rustc,
        "verbose-version",
        &["-vV"],
        MAX_RUSTC_VERBOSE_VERSION_BYTES,
        RUSTC_QUERY_TIMEOUT,
    )?;
    let version =
        String::from_utf8(bytes).map_err(|_| ComposeRustcError::InvalidQueryEncoding {
            query: "verbose-version",
            stream: "stdout",
        })?;
    validate_verbose_version(&version)?;
    Ok(version)
}

fn validate_verbose_version(version: &str) -> Result<(), ComposeRustcError> {
    if version.is_empty()
        || version.len() > MAX_RUSTC_VERBOSE_VERSION_BYTES
        || !version.ends_with('\n')
        || version.contains('\r')
        || version.contains('\0')
    {
        return Err(ComposeRustcError::InvalidVerboseVersion(
            "output must be bounded UTF-8 with one LF line ending convention".into(),
        ));
    }
    let lines = version.strip_suffix('\n').unwrap_or(version).split('\n');
    let mut lines = lines.collect::<Vec<_>>();
    if lines.iter().any(|line| line.is_empty()) || lines.len() != 7 {
        return Err(ComposeRustcError::InvalidVerboseVersion(
            "expected the pinned seven-line rustc verbose version schema".into(),
        ));
    }
    let banner = lines.remove(0);
    let mut fields = BTreeMap::new();
    for line in lines {
        let (key, value) = line.split_once(": ").ok_or_else(|| {
            ComposeRustcError::InvalidVerboseVersion(format!("invalid line `{line}`"))
        })?;
        if fields.insert(key, value).is_some() {
            return Err(ComposeRustcError::InvalidVerboseVersion(format!(
                "duplicate field `{key}`"
            )));
        }
    }
    let expected_keys = BTreeSet::from([
        "LLVM version",
        "binary",
        "commit-date",
        "commit-hash",
        "host",
        "release",
    ]);
    if fields.keys().copied().collect::<BTreeSet<_>>() != expected_keys
        || fields.get("binary") != Some(&"rustc")
        || fields.get("release") != Some(&PINNED_RUST_RELEASE)
    {
        return Err(ComposeRustcError::InvalidVerboseVersion(format!(
            "rustc must be the exact pinned {PINNED_RUST_RELEASE} release"
        )));
    }
    let commit = fields["commit-hash"];
    let date = fields["commit-date"];
    let host = fields["host"];
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || date.len() != 10
        || !date.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7) && byte == b'-'
                || !matches!(index, 4 | 7) && byte.is_ascii_digit()
        })
        || host.is_empty()
        || host.len() > 128
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || fields["LLVM version"].is_empty()
    {
        return Err(ComposeRustcError::InvalidVerboseVersion(
            "commit, date, host or LLVM identity is malformed".into(),
        ));
    }
    let expected_banner_prefix = format!("rustc {PINNED_RUST_RELEASE} (");
    let expected_banner_suffix = format!("{} {date})", &commit[..9]);
    if !banner.starts_with(&expected_banner_prefix) || !banner.ends_with(&expected_banner_suffix) {
        return Err(ComposeRustcError::InvalidVerboseVersion(
            "banner does not match the verbose commit/date identity".into(),
        ));
    }
    Ok(())
}

fn query_sysroot(rustc: &Path) -> Result<PathBuf, ComposeRustcError> {
    let bytes = run_rustc_query(
        rustc,
        "sysroot",
        &["--print", "sysroot"],
        MAX_RUSTC_SYSROOT_OUTPUT_BYTES,
        RUSTC_QUERY_TIMEOUT,
    )?;
    let output = String::from_utf8(bytes).map_err(|_| ComposeRustcError::InvalidQueryEncoding {
        query: "sysroot",
        stream: "stdout",
    })?;
    if output.contains('\r') || output.contains('\0') || output.lines().count() != 1 {
        return Err(ComposeRustcError::InvalidSysroot(
            "output must contain exactly one LF-terminated path".into(),
        ));
    }
    let raw = output
        .strip_suffix('\n')
        .ok_or_else(|| ComposeRustcError::InvalidSysroot("output must end with LF".into()))?;
    let path = PathBuf::from(raw);
    if raw.is_empty() || !path.is_absolute() {
        return Err(ComposeRustcError::InvalidSysroot(raw.into()));
    }
    let metadata = fs::symlink_metadata(&path).map_err(|error| ComposeRustcError::QueryIo {
        query: "sysroot identity",
        error,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ComposeRustcError::InvalidSysroot(raw.into()));
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| ComposeRustcError::QueryIo {
            query: "sysroot identity",
            error,
        })?;
    #[cfg(not(windows))]
    if canonical != path {
        return Err(ComposeRustcError::InvalidSysroot(raw.into()));
    }
    Ok(canonical)
}

fn plan_sysroot(root: &Path) -> Result<SysrootPlan, ComposeRustcError> {
    let root_metadata = metadata_identity(root)?;
    if root_metadata.kind != SysrootEntryKind::Directory {
        return Err(ComposeRustcError::InvalidSysroot(
            root.display().to_string(),
        ));
    }
    let mut entries = Vec::new();
    let mut case_folded = BTreeSet::new();
    let mut file_bytes = 0_u64;
    for walked in WalkDir::new(root).sort_by_file_name().into_iter().skip(1) {
        let walked = walked
            .map_err(|error| ComposeRustcError::UnsupportedSysrootEntry(error.to_string()))?;
        if entries.len() == MAX_COMPOSE_SYSROOT_ENTRIES {
            return Err(ComposeRustcError::TooManySysrootEntries {
                actual: entries.len() + 1,
                maximum: MAX_COMPOSE_SYSROOT_ENTRIES,
            });
        }
        let path = walked.path();
        let metadata = metadata_identity(path)?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| ComposeRustcError::InvalidSysrootPath(path.display().to_string()))?;
        let logical_path = canonical_sysroot_relative_path(relative)?;
        if !case_folded.insert(logical_path.to_ascii_lowercase()) {
            return Err(ComposeRustcError::SysrootPathCollision(logical_path));
        }
        if metadata.kind == SysrootEntryKind::RegularFile {
            if metadata.len > MAX_COMPOSE_SYSROOT_FILE_BYTES {
                return Err(ComposeRustcError::SysrootFileTooLarge {
                    path: logical_path,
                    actual: metadata.len,
                    maximum: MAX_COMPOSE_SYSROOT_FILE_BYTES,
                });
            }
            file_bytes =
                file_bytes
                    .checked_add(metadata.len)
                    .ok_or(ComposeRustcError::SysrootTooLarge {
                        actual: u64::MAX,
                        maximum: MAX_COMPOSE_SYSROOT_TOTAL_FILE_BYTES,
                    })?;
            if file_bytes > MAX_COMPOSE_SYSROOT_TOTAL_FILE_BYTES {
                return Err(ComposeRustcError::SysrootTooLarge {
                    actual: file_bytes,
                    maximum: MAX_COMPOSE_SYSROOT_TOTAL_FILE_BYTES,
                });
            }
        }
        entries.push(PlannedSysrootEntry {
            logical_path,
            path: path.to_owned(),
            metadata,
        });
    }
    if entries.is_empty() || file_bytes == 0 {
        return Err(ComposeRustcError::InvalidSysroot(
            "sysroot must contain at least one regular file".into(),
        ));
    }
    entries.sort_by(|left, right| left.logical_path.cmp(&right.logical_path));
    Ok(SysrootPlan {
        root: root.to_owned(),
        root_metadata,
        entries,
        file_bytes,
    })
}

fn hash_sysroot(
    plan: &SysrootPlan,
    rustc_path: &Path,
) -> Result<(RustcSysrootProvenance, (String, u64)), ComposeRustcError> {
    let mut digest_entries = Vec::with_capacity(plan.entries.len());
    let mut rustc_identity = None;
    let mut files = 0_u64;
    let mut directories = 0_u64;
    for entry in &plan.entries {
        match entry.metadata.kind {
            SysrootEntryKind::Directory => {
                directories += 1;
                digest_entries.push(SysrootDigestEntry {
                    path: entry.logical_path.clone(),
                    kind: SysrootEntryKind::Directory,
                    bytes: None,
                    sha256: None,
                });
            }
            SysrootEntryKind::RegularFile => {
                files += 1;
                let identity = hash_regular_file(
                    &entry.path,
                    &entry.logical_path,
                    MAX_COMPOSE_SYSROOT_FILE_BYTES,
                    Some(&entry.metadata),
                )?;
                if entry.path == rustc_path {
                    rustc_identity = Some(identity.clone());
                }
                digest_entries.push(SysrootDigestEntry {
                    path: entry.logical_path.clone(),
                    kind: SysrootEntryKind::RegularFile,
                    bytes: Some(identity.1),
                    sha256: Some(identity.0),
                });
            }
        }
    }
    let rustc_identity = rustc_identity.ok_or(ComposeRustcError::RustcOutsideSysroot)?;
    let tree_digest = hex::encode(canonical::domain_hash(
        COMPOSE_SYSROOT_TREE_DOMAIN,
        &digest_entries,
    )?);
    Ok((
        RustcSysrootProvenance {
            tree_digest,
            entries: digest_entries.len() as u64,
            files,
            directories,
            file_bytes: plan.file_bytes,
        },
        rustc_identity,
    ))
}

fn cached_sysroot_identity(
    plan: &SysrootPlan,
    rustc_path: &Path,
) -> Result<(RustcSysrootProvenance, (String, u64)), ComposeRustcError> {
    let cache = SYSROOT_IDENTITY_CACHE.get_or_init(|| Mutex::new(Vec::new()));
    let mut cache = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(entry) = cache
        .iter()
        .find(|entry| entry.rustc_path == rustc_path && entry.plan == *plan)
    {
        return Ok((entry.sysroot.clone(), entry.rustc_identity.clone()));
    }
    // Keep the lock during the expensive first hash. This intentionally serializes
    // concurrent compose calls in one process so they cannot all hash the same pinned
    // sysroot before the first verified identity is available.
    let (sysroot, rustc_identity) = hash_sysroot(plan, rustc_path)?;
    if cache.len() == MAX_SYSROOT_IDENTITY_CACHE_ENTRIES {
        cache.remove(0);
    }
    cache.push(SysrootIdentityCacheEntry {
        plan: plan.clone(),
        rustc_path: rustc_path.to_owned(),
        sysroot: sysroot.clone(),
        rustc_identity: rustc_identity.clone(),
    });
    Ok((sysroot, rustc_identity))
}

fn metadata_identity(path: &Path) -> Result<MetadataIdentity, ComposeRustcError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| ComposeRustcError::QueryIo {
        query: "sysroot metadata",
        error,
    })?;
    if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
        return Err(ComposeRustcError::UnsupportedSysrootEntry(
            path.display().to_string(),
        ));
    }
    let kind = if metadata.is_dir() {
        SysrootEntryKind::Directory
    } else {
        SysrootEntryKind::RegularFile
    };
    let modified = metadata
        .modified()
        .map_err(|error| ComposeRustcError::QueryIo {
            query: "sysroot metadata",
            error,
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        Ok(MetadataIdentity {
            kind,
            len: metadata.len(),
            modified,
            readonly: metadata.permissions().readonly(),
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(MetadataIdentity {
            kind,
            len: metadata.len(),
            modified,
            readonly: metadata.permissions().readonly(),
        })
    }
}

fn canonical_sysroot_relative_path(path: &Path) -> Result<String, ComposeRustcError> {
    if path.as_os_str().is_empty()
        || !path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err(ComposeRustcError::InvalidSysrootPath(
            path.display().to_string(),
        ));
    }
    let value = path
        .to_str()
        .ok_or_else(|| ComposeRustcError::InvalidSysrootPath(path.display().to_string()))?
        .replace('\\', "/");
    if value.len() > MAX_COMPOSE_SYSROOT_RELATIVE_PATH_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'/' | b'.' | b'_' | b'+' | b'@' | b'=' | b'-')
        })
    {
        return Err(ComposeRustcError::InvalidSysrootPath(value));
    }
    Ok(value)
}

fn hash_regular_file(
    path: &Path,
    logical_path: &str,
    maximum: u64,
    expected: Option<&MetadataIdentity>,
) -> Result<(String, u64), ComposeRustcError> {
    let before = metadata_identity(path)?;
    if before.kind != SysrootEntryKind::RegularFile
        || before.len > maximum
        || expected.is_some_and(|expected| expected != &before)
    {
        return Err(ComposeRustcError::UnsupportedSysrootEntry(
            logical_path.into(),
        ));
    }
    let file = File::open(path).map_err(|error| ComposeRustcError::QueryIo {
        query: "toolchain file hashing",
        error,
    })?;
    let handle_before = metadata_identity_from_open_file(&file, path)?;
    if handle_before != before {
        return drift("toolchain file hashing", "file identity");
    }
    let mut reader = BufReader::new(file).take(maximum.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; SNAPSHOT_BUFFER_BYTES];
    let mut bytes = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| ComposeRustcError::QueryIo {
                query: "toolchain file hashing",
                error,
            })?;
        if read == 0 {
            break;
        }
        bytes = bytes.checked_add(read as u64).ok_or_else(|| {
            ComposeRustcError::SysrootFileTooLarge {
                path: logical_path.into(),
                actual: u64::MAX,
                maximum,
            }
        })?;
        if bytes > maximum {
            return Err(ComposeRustcError::SysrootFileTooLarge {
                path: logical_path.into(),
                actual: bytes,
                maximum,
            });
        }
        hasher.update(&buffer[..read]);
    }
    let file = reader.into_inner().into_inner();
    let handle_after = metadata_identity_from_open_file(&file, path)?;
    let path_after = metadata_identity(path)?;
    if bytes != before.len || handle_after != before || path_after != before {
        return drift("toolchain file hashing", "file bytes or metadata");
    }
    Ok((hex::encode(hasher.finalize()), bytes))
}

fn metadata_identity_from_open_file(
    file: &File,
    path: &Path,
) -> Result<MetadataIdentity, ComposeRustcError> {
    let metadata = file
        .metadata()
        .map_err(|error| ComposeRustcError::QueryIo {
            query: "toolchain file hashing",
            error,
        })?;
    if !metadata.is_file() {
        return Err(ComposeRustcError::UnsupportedSysrootEntry(
            path.display().to_string(),
        ));
    }
    let kind = SysrootEntryKind::RegularFile;
    let modified = metadata
        .modified()
        .map_err(|error| ComposeRustcError::QueryIo {
            query: "toolchain file hashing",
            error,
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        Ok(MetadataIdentity {
            kind,
            len: metadata.len(),
            modified,
            readonly: metadata.permissions().readonly(),
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(MetadataIdentity {
            kind,
            len: metadata.len(),
            modified,
            readonly: metadata.permissions().readonly(),
        })
    }
}

fn run_rustc_query(
    rustc: &Path,
    query: &'static str,
    args: &[&str],
    stdout_maximum: usize,
    timeout: Duration,
) -> Result<Vec<u8>, ComposeRustcError> {
    let mut command = Command::new(rustc);
    command
        .args(args)
        .env_clear()
        .env("PATH", rustc.parent().unwrap_or_else(|| Path::new("/")))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;

        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|error| ComposeRustcError::QueryIo { query, error })?;
    #[cfg(unix)]
    let process_group = rustix::process::Pid::from_child(&child);
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ComposeRustcError::QueryIo {
            query,
            error: io::Error::other("rustc stdout pipe was unavailable after successful spawn"),
        })?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ComposeRustcError::QueryIo {
            query,
            error: io::Error::other("rustc stderr pipe was unavailable after successful spawn"),
        })?;
    let mut stdout_reader = Some(thread::spawn(move || {
        read_bounded_query_stream(stdout, query, "stdout", stdout_maximum)
    }));
    let mut stderr_reader = Some(thread::spawn(move || {
        read_bounded_query_stream(stderr, query, "stderr", MAX_RUSTC_VERBOSE_VERSION_BYTES)
    }));
    let started = Instant::now();
    let deadline = started.checked_add(timeout).unwrap_or(started);
    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;
    loop {
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|error| ComposeRustcError::QueryIo { query, error })?;
        }
        collect_finished_query_reader(query, &mut stdout_reader, &mut stdout);
        collect_finished_query_reader(query, &mut stderr_reader, &mut stderr);
        if status.is_some() && stdout.is_some() && stderr.is_some() {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            #[cfg(unix)]
            let _ =
                rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL);
            terminate_and_collect_query(
                query,
                &mut child,
                &mut status,
                &mut stdout_reader,
                &mut stdout,
                &mut stderr_reader,
                &mut stderr,
                now.checked_add(RUSTC_QUERY_TERMINATION_GRACE)
                    .unwrap_or(now),
            );
            return Err(ComposeRustcError::QueryTimedOut {
                query,
                milliseconds: timeout.as_millis(),
            });
        }
        thread::sleep(
            deadline
                .saturating_duration_since(now)
                .min(RUSTC_QUERY_POLL_INTERVAL),
        );
    }
    let status = status.expect("rustc status is present after the query loop");
    let stdout = stdout.expect("rustc stdout is present after the query loop")?;
    let stderr = stderr.expect("rustc stderr is present after the query loop")?;
    if !status.success() {
        let diagnostic =
            String::from_utf8(stderr).map_err(|_| ComposeRustcError::InvalidQueryEncoding {
                query,
                stream: "stderr",
            })?;
        return Err(ComposeRustcError::QueryFailed { query, diagnostic });
    }
    if !stderr.is_empty() {
        return Err(ComposeRustcError::QueryFailed {
            query,
            diagnostic: String::from_utf8(stderr).map_err(|_| {
                ComposeRustcError::InvalidQueryEncoding {
                    query,
                    stream: "stderr",
                }
            })?,
        });
    }
    Ok(stdout)
}

type QueryReader = thread::JoinHandle<Result<Vec<u8>, ComposeRustcError>>;

fn collect_finished_query_reader(
    query: &'static str,
    reader: &mut Option<QueryReader>,
    output: &mut Option<Result<Vec<u8>, ComposeRustcError>>,
) {
    if reader.as_ref().is_some_and(QueryReader::is_finished) {
        let finished = reader
            .take()
            .expect("a finished query reader must still be present");
        *output = Some(
            finished
                .join()
                .map_err(|_| ComposeRustcError::QueryReaderPanicked { query })
                .and_then(|value| value),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn terminate_and_collect_query(
    query: &'static str,
    child: &mut Child,
    status: &mut Option<ExitStatus>,
    stdout_reader: &mut Option<QueryReader>,
    stdout: &mut Option<Result<Vec<u8>, ComposeRustcError>>,
    stderr_reader: &mut Option<QueryReader>,
    stderr: &mut Option<Result<Vec<u8>, ComposeRustcError>>,
    cleanup_deadline: Instant,
) {
    let _ = child.kill();
    loop {
        if status.is_none()
            && let Ok(observed) = child.try_wait()
        {
            *status = observed;
        }
        collect_finished_query_reader(query, stdout_reader, stdout);
        collect_finished_query_reader(query, stderr_reader, stderr);
        if status.is_some() && stdout_reader.is_none() && stderr_reader.is_none() {
            return;
        }
        let now = Instant::now();
        if now >= cleanup_deadline {
            return;
        }
        thread::sleep(
            cleanup_deadline
                .saturating_duration_since(now)
                .min(RUSTC_QUERY_POLL_INTERVAL),
        );
    }
}

fn read_bounded_query_stream(
    mut stream: impl Read,
    query: &'static str,
    stream_name: &'static str,
    maximum: usize,
) -> Result<Vec<u8>, ComposeRustcError> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|error| ComposeRustcError::QueryIo { query, error })?;
        if read == 0 {
            return Ok(output);
        }
        let remaining = maximum.saturating_sub(output.len());
        if read > remaining {
            return Err(ComposeRustcError::QueryOutputTooLarge {
                query,
                stream: stream_name,
                maximum,
            });
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn drift<T>(phase: impl Into<String>, surface: &'static str) -> Result<T, ComposeRustcError> {
    Err(ComposeRustcError::Drift {
        phase: phase.into(),
        surface,
    })
}

fn invalid_record<T>(message: impl Into<String>) -> Result<T, ComposeRustcError> {
    Err(ComposeRustcError::InvalidRecord(message.into()))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    const PINNED_VERBOSE_VERSION: &str = concat!(
        "rustc 1.97.1 (8bab26f4f 2026-07-14)\n",
        "binary: rustc\n",
        "commit-hash: 8bab26f4f68e0e26f0bb7960be334d5b520ea452\n",
        "commit-date: 2026-07-14\n",
        "host: x86_64-unknown-linux-gnu\n",
        "release: 1.97.1\n",
        "LLVM version: 22.1.6\n",
    );

    #[cfg(unix)]
    fn write_executable(path: &Path, source: &str) {
        use std::os::unix::fs::PermissionsExt as _;

        fs::write(path, source).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    fn fake_toolchain() -> (TempDir, PathBuf, PathBuf) {
        let temp = TempDir::new().unwrap();
        let sysroot = temp.path().join("toolchain");
        let rustc = sysroot.join("bin/rustc");
        fs::create_dir_all(sysroot.join("bin")).unwrap();
        fs::create_dir_all(sysroot.join("lib/rustlib/fixture/lib")).unwrap();
        fs::write(
            sysroot.join("lib/rustlib/fixture/lib/libcore-fixture.rlib"),
            b"fixture-core-v1",
        )
        .unwrap();
        write_executable(
            &rustc,
            &format!(
                concat!(
                    "#!/bin/sh\n",
                    "rustc_dir=${{0%/*}}\n",
                    "sysroot=${{rustc_dir%/*}}\n",
                    "if [ \"$1\" = \"-vV\" ]; then printf '%b' {:?}; exit 0; fi\n",
                    "if [ \"$1 $2\" = \"--print sysroot\" ]; then printf '%s\\n' \"$sysroot\"; exit 0; fi\n",
                    "exit 93\n"
                ),
                PINNED_VERBOSE_VERSION,
            ),
        );
        (temp, sysroot, rustc)
    }

    #[test]
    fn pinned_verbose_version_schema_is_closed() {
        validate_verbose_version(PINNED_VERBOSE_VERSION).unwrap();
        for invalid in [
            PINNED_VERBOSE_VERSION.replace("release: 1.97.1", "release: 1.98.0"),
            PINNED_VERBOSE_VERSION.replace("binary: rustc\n", ""),
            PINNED_VERBOSE_VERSION.replace("LLVM version", "unknown-field"),
            PINNED_VERBOSE_VERSION.trim_end().to_owned(),
            PINNED_VERBOSE_VERSION.replace('\n', "\r\n"),
        ] {
            assert!(matches!(
                validate_verbose_version(&invalid),
                Err(ComposeRustcError::InvalidVerboseVersion(_))
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn provenance_binds_rustc_version_and_path_free_sysroot_bytes() {
        let (_temp, sysroot, rustc) = fake_toolchain();
        let first = ComposeRustcSnapshot::capture(&rustc).unwrap();
        let second = ComposeRustcSnapshot::capture(&rustc).unwrap();
        let provenance = first.provenance();

        provenance.validate().unwrap();
        assert_eq!(provenance, second.provenance());
        assert_eq!(provenance.rustc.verbose_version, PINNED_VERBOSE_VERSION);
        assert!(provenance.sysroot.entries >= 5);
        assert!(provenance.sysroot.files >= 2);
        assert!(provenance.sysroot.directories >= 3);
        assert_eq!(
            provenance.rustc.sha256,
            "6e90462605efd5d03afa2fb0b462d09b4302a69d315de68d81e0073440691a5e"
        );
        assert_eq!(
            provenance.sysroot.tree_digest,
            "2079a74249db578a6249082476371f2e86d632ea0c179f420e639e2c73124273"
        );
        assert_eq!(
            provenance.identity_digest,
            "f002815399248cf3d16f235d85a1a8ab64e2e8bbed6b7ef19798b85b552aeb50"
        );
        let encoded = serde_json::to_string(provenance).unwrap();
        assert!(!encoded.contains(sysroot.to_str().unwrap()));
        assert!(!encoded.contains(rustc.to_str().unwrap()));

        let mut forged = serde_json::to_value(provenance).unwrap();
        forged["identity-digest"] = serde_json::Value::String("0".repeat(64));
        assert!(serde_json::from_value::<ComposeRustcProvenance>(forged).is_err());
        let mut unknown = serde_json::to_value(provenance).unwrap();
        unknown["ambient-path"] = serde_json::Value::String("/tmp/rustc".into());
        assert!(serde_json::from_value::<ComposeRustcProvenance>(unknown).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rustc_and_sysroot_drift_are_detected_and_change_identity() {
        let (_temp, sysroot, rustc) = fake_toolchain();
        let first = ComposeRustcSnapshot::capture(&rustc).unwrap();
        let library = sysroot.join("lib/rustlib/fixture/lib/libcore-fixture.rlib");
        fs::write(&library, b"fixture-core-v2").unwrap();

        assert!(matches!(
            first.ensure_unchanged("fixture child"),
            Err(ComposeRustcError::Drift { phase, surface })
                if phase == "fixture child" && surface == "sysroot tree metadata"
        ));
        let second = ComposeRustcSnapshot::capture(&rustc).unwrap();
        assert_eq!(
            first.provenance.rustc.verbose_version,
            second.provenance.rustc.verbose_version
        );
        assert_eq!(
            first.provenance.rustc.sha256,
            second.provenance.rustc.sha256
        );
        assert_ne!(
            first.provenance.sysroot.tree_digest,
            second.provenance.sysroot.tree_digest
        );
        assert_ne!(
            first.provenance.identity_digest,
            second.provenance.identity_digest
        );
    }

    #[cfg(unix)]
    #[test]
    fn sysroot_symlinks_and_file_size_overflow_fail_closed() {
        use std::os::unix::fs::symlink;

        let (_temp, sysroot, rustc) = fake_toolchain();
        symlink(
            sysroot.join("lib/rustlib/fixture/lib/libcore-fixture.rlib"),
            sysroot.join("lib/rustlib/fixture/lib/libalias.rlib"),
        )
        .unwrap();
        assert!(matches!(
            ComposeRustcSnapshot::capture(&rustc),
            Err(ComposeRustcError::UnsupportedSysrootEntry(_))
        ));

        fs::remove_file(sysroot.join("lib/rustlib/fixture/lib/libalias.rlib")).unwrap();
        File::create(sysroot.join("lib/oversized"))
            .unwrap()
            .set_len(MAX_COMPOSE_SYSROOT_FILE_BYTES + 1)
            .unwrap();
        assert!(matches!(
            ComposeRustcSnapshot::capture(&rustc),
            Err(ComposeRustcError::SysrootFileTooLarge {
                actual,
                maximum,
                ..
            }) if actual == MAX_COMPOSE_SYSROOT_FILE_BYTES + 1
                && maximum == MAX_COMPOSE_SYSROOT_FILE_BYTES
        ));
    }

    #[cfg(unix)]
    #[test]
    fn query_output_and_deadline_are_bounded() {
        let temp = TempDir::new().unwrap();
        let oversized = temp.path().join("oversized");
        write_executable(
            &oversized,
            "#!/bin/sh\nwhile :; do printf 0123456789; done\n",
        );
        assert!(matches!(
            run_rustc_query(&oversized, "fixture", &[], 64, Duration::from_secs(1),),
            Err(ComposeRustcError::QueryOutputTooLarge {
                query: "fixture",
                stream: "stdout",
                maximum: 64,
            })
        ));

        let hanging = temp.path().join("hanging");
        write_executable(&hanging, "#!/bin/sh\nwhile :; do :; done\n");
        assert!(matches!(
            run_rustc_query(&hanging, "fixture", &[], 64, Duration::from_millis(25),),
            Err(ComposeRustcError::QueryTimedOut {
                query: "fixture",
                ..
            })
        ));
    }
}
