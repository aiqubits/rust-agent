use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{self, Read},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use thiserror::Error;

use crate::{
    canonical,
    custom_target::{CustomTargetSpecError, CustomTargetSpecRecord, verify_custom_target_snapshot},
};

pub const TARGET_FACTS_SCHEMA: u32 = 1;
pub const MAX_CANONICAL_TARGET_FACTS_RECORD_BYTES: usize = 256 * 1024;
pub const MAX_RUSTC_CFG_OUTPUT_BYTES: usize = 256 * 1024;
pub const MAX_RUSTC_DIAGNOSTIC_BYTES: usize = 256 * 1024;
pub const MAX_TARGET_TRIPLE_BYTES: usize = 128;
pub const MAX_TARGET_FACT_KEYS: usize = 1_024;
pub const MAX_TARGET_FACT_VALUES_PER_KEY: usize = 1_024;
pub const MAX_TARGET_FACT_TOTAL_VALUES: usize = 16 * 1_024;
pub const MAX_TARGET_FACT_KEY_BYTES: usize = 128;
pub const MAX_TARGET_FACT_VALUE_BYTES: usize = 4 * 1_024;
pub const MAX_TARGET_ARCH_BYTES: usize = MAX_TARGET_FACT_VALUE_BYTES;
pub const MAX_TARGET_OS_BYTES: usize = MAX_TARGET_FACT_VALUE_BYTES;
pub const MAX_TARGET_PREDICATE_BYTES: usize = 4 * 1_024;
pub const MAX_TARGET_PREDICATE_NODES: usize = 256;
pub const MAX_TARGET_PREDICATE_DEPTH: usize = 32;
pub const MAX_TARGET_PREDICATE_PARTITIONS: usize = 64;

const RUSTC_QUERY_TIMEOUT: Duration = Duration::from_secs(30);
const RUSTC_QUERY_POLL_INTERVAL: Duration = Duration::from_millis(10);
const RUSTC_QUERY_TERMINATION_GRACE: Duration = Duration::from_secs(1);
const MAX_TARGET_PREDICATE_ANALYSIS_ATOMS: usize = 16 * 1_024;
const MAX_TARGET_PREDICATE_ANALYSIS_VARIABLES: usize = 4 * 1_024 * 1_024;
const MAX_TARGET_PREDICATE_ANALYSIS_CLAUSES: usize = 8 * 1_024 * 1_024;
const MAX_TARGET_PREDICATE_ANALYSIS_LITERALS: usize = 32 * 1_024 * 1_024;
const MAX_TARGET_PREDICATE_ANALYSIS_DECISIONS: usize = 100_000;
const MAX_TARGET_PREDICATE_ANALYSIS_WORK: usize = 64 * 1_024 * 1_024;
const MAX_TARGET_PREDICATE_ANALYSIS_DEPTH: usize = 1_024;
const REQUIRED_SCALAR_FACTS: &[&str] = &[
    "panic",
    "target_abi",
    "target_arch",
    "target_endian",
    "target_env",
    "target_os",
    "target_pointer_width",
    "target_vendor",
];

const TARGET_FACTS_DOMAIN: &[u8] = b"rust-agent-target-facts-v1\0";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Environment {
    Browser,
    Server,
    Desktop,
    Mobile,
}

impl Environment {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Server => "server",
            Self::Desktop => "desktop",
            Self::Mobile => "mobile",
        }
    }
}

macro_rules! target_projection {
    ($name:ident, $maximum:ident, $error:ident) => {
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, TargetError> {
                let value = value.into();
                if !valid_target_projection_value(&value, $maximum) {
                    return Err(TargetError::$error(value));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl TryFrom<String> for $name {
            type Error = TargetError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

target_projection!(Arch, MAX_TARGET_ARCH_BYTES, InvalidArch);
target_projection!(Os, MAX_TARGET_OS_BYTES, InvalidOs);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoreTargetFacts<'a> {
    pub(crate) panic_strategy: &'a str,
    pub(crate) target_abi: &'a str,
    pub(crate) target_arch: &'a str,
    pub(crate) target_endian: &'a str,
    pub(crate) target_env: &'a str,
    pub(crate) target_os: &'a str,
    pub(crate) target_pointer_width: &'a str,
    pub(crate) target_vendor: &'a str,
}

impl<'a> CoreTargetFacts<'a> {
    pub(crate) const fn little_endian(
        target_arch: &'a str,
        target_env: &'a str,
        target_os: &'a str,
        target_pointer_width: &'a str,
        panic_strategy: &'a str,
    ) -> Self {
        Self {
            panic_strategy,
            target_abi: "",
            target_arch,
            target_endian: "little",
            target_env,
            target_os,
            target_pointer_width,
            target_vendor: "unknown",
        }
    }
}

pub(crate) fn canonical_builtin_facts(
    core: CoreTargetFacts<'_>,
) -> Result<BTreeMap<String, BTreeSet<Option<String>>>, TargetError> {
    let facts: BTreeMap<String, BTreeSet<Option<String>>> = BTreeMap::from([
        (
            "panic".into(),
            BTreeSet::from([Some(core.panic_strategy.into())]),
        ),
        (
            "target_abi".into(),
            BTreeSet::from([Some(core.target_abi.into())]),
        ),
        (
            "target_arch".into(),
            BTreeSet::from([Some(core.target_arch.into())]),
        ),
        (
            "target_endian".into(),
            BTreeSet::from([Some(core.target_endian.into())]),
        ),
        (
            "target_env".into(),
            BTreeSet::from([Some(core.target_env.into())]),
        ),
        (
            "target_os".into(),
            BTreeSet::from([Some(core.target_os.into())]),
        ),
        (
            "target_pointer_width".into(),
            BTreeSet::from([Some(core.target_pointer_width.into())]),
        ),
        (
            "target_vendor".into(),
            BTreeSet::from([Some(core.target_vendor.into())]),
        ),
    ]);
    for (key, values) in &facts {
        for value in values {
            validate_fact(key, value.as_deref())?;
        }
        validate_fact_values(key, values)?;
    }
    validate_complete_rustc_facts(&facts)?;
    Ok(facts)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedTarget")]
pub struct Target {
    pub triple: String,
    pub arch: Arch,
    pub os: Os,
    pub environment: Environment,
    pub facts: BTreeMap<String, BTreeSet<Option<String>>>,
    #[serde(rename = "target-fact-digest")]
    pub target_fact_digest: String,
    #[serde(default, rename = "custom-target-spec-digest")]
    pub custom_target_spec_digest: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedTarget {
    triple: String,
    arch: Arch,
    os: Os,
    environment: Environment,
    #[serde(deserialize_with = "deserialize_target_facts")]
    facts: BTreeMap<String, BTreeSet<Option<String>>>,
    #[serde(rename = "target-fact-digest")]
    target_fact_digest: String,
    #[serde(default, rename = "custom-target-spec-digest")]
    custom_target_spec_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "UncheckedTargetFactsRecord")]
pub struct TargetFactsRecord {
    pub schema: u32,
    pub triple: String,
    pub facts: BTreeMap<String, BTreeSet<Option<String>>>,
    #[serde(default, rename = "custom-target-spec-digest")]
    pub custom_target_spec_digest: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedTargetFactsRecord {
    schema: u32,
    triple: String,
    #[serde(deserialize_with = "deserialize_target_facts")]
    facts: BTreeMap<String, BTreeSet<Option<String>>>,
    #[serde(default, rename = "custom-target-spec-digest")]
    custom_target_spec_digest: Option<String>,
}

#[derive(Debug, Error)]
pub enum TargetError {
    #[error("rustc path must be explicit and absolute: {0}")]
    RustcPathNotAbsolute(String),
    #[error("failed to execute rustc target-fact query: {0}")]
    RustcIo(#[from] std::io::Error),
    #[error("rustc {stream} exceeded the {maximum}-byte limit")]
    RustcOutputTooLarge {
        stream: &'static str,
        maximum: usize,
    },
    #[error("rustc {stream} is not valid UTF-8")]
    InvalidRustcOutputEncoding { stream: &'static str },
    #[error("rustc output reader thread panicked")]
    RustcOutputReaderPanicked,
    #[error("rustc target-fact query exceeded its {milliseconds}-millisecond deadline")]
    RustcTimedOut { milliseconds: u128 },
    #[error("rustc target-fact query failed: {0}")]
    RustcFailed(String),
    #[error("invalid rustc cfg line: {0}")]
    InvalidFact(String),
    #[error("invalid canonical target triple: {0}")]
    InvalidTriple(String),
    #[error("invalid target architecture: {0}")]
    InvalidArch(String),
    #[error("invalid target operating system: {0}")]
    InvalidOs(String),
    #[error("target {projection} projection does not match the canonical `{fact}` fact")]
    TargetProjectionMismatch {
        projection: &'static str,
        fact: &'static str,
    },
    #[error("invalid custom target specification digest: {0}")]
    InvalidCustomTargetSpecDigest(String),
    #[error("custom target snapshot path must be explicit and absolute: {0}")]
    CustomTargetPathNotAbsolute(String),
    #[error("custom target snapshot is invalid: {0}")]
    CustomTargetSpec(#[from] CustomTargetSpecError),
    #[error("target fact digest does not match the canonical target facts")]
    TargetFactDigestMismatch,
    #[error("unsupported target-facts record schema {actual}; expected {expected}")]
    UnsupportedTargetFactsSchema { actual: u32, expected: u32 },
    #[error("canonical target-facts record has {actual} bytes; maximum is {maximum}")]
    TargetFactsRecordTooLarge { actual: usize, maximum: usize },
    #[error("target JSON has {actual} bytes; maximum is {maximum}")]
    TargetJsonTooLarge { actual: usize, maximum: usize },
    #[error("target JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid target predicate: {0}")]
    InvalidPredicate(String),
    #[error("target predicate partition has {actual} entries; expected 1..={maximum}")]
    InvalidPredicatePartitionCount { actual: usize, maximum: usize },
    #[error("target predicate partition entry {index} matches outside the parent predicate")]
    PredicatePartitionOutsideParent { index: usize },
    #[error("target predicate partition entry {index} cannot match within the parent predicate")]
    PredicatePartitionUnsatisfiable { index: usize },
    #[error("target predicate partition entries {first} and {second} overlap")]
    PredicatePartitionOverlap { first: usize, second: usize },
    #[error("target predicate partition does not completely cover the parent predicate")]
    PredicatePartitionGap,
    #[error("target predicate analysis exceeded its deterministic {resource} limit of {maximum}")]
    PredicateAnalysisLimitExceeded {
        resource: &'static str,
        maximum: usize,
    },
    #[error("canonical target-fact encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
}

impl Target {
    pub fn from_json(bytes: &[u8]) -> Result<Self, TargetError> {
        validate_target_json_size(bytes)?;
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn query(
        rustc: &Path,
        triple: impl Into<String>,
        environment: Environment,
    ) -> Result<Self, TargetError> {
        if !rustc.is_absolute() {
            return Err(TargetError::RustcPathNotAbsolute(
                rustc.display().to_string(),
            ));
        }
        let triple = triple.into();
        validate_target_triple(&triple)?;
        let facts = query_rustc_facts(rustc, Path::new(&triple))?;
        Self::from_facts(triple, environment, facts)
    }

    pub fn query_with_custom_spec(
        rustc: &Path,
        environment: Environment,
        record: &CustomTargetSpecRecord,
        snapshot_path: &Path,
    ) -> Result<Self, TargetError> {
        if !rustc.is_absolute() {
            return Err(TargetError::RustcPathNotAbsolute(
                rustc.display().to_string(),
            ));
        }
        let before = verify_custom_target_snapshot(record, snapshot_path)?;
        let facts = query_rustc_facts(rustc, snapshot_path);
        let after = verify_custom_target_snapshot(record, snapshot_path)?;
        before.ensure_unchanged(&after, "rustc target-fact query")?;
        let facts = facts?;
        Self::from_facts_with_custom_spec_digest(
            record.logical_triple.clone(),
            environment,
            facts,
            Some(record.custom_target_spec_digest.clone()),
        )
    }

    pub fn from_facts(
        triple: impl Into<String>,
        environment: Environment,
        facts: BTreeMap<String, BTreeSet<Option<String>>>,
    ) -> Result<Self, TargetError> {
        Self::from_facts_with_custom_spec_digest(triple, environment, facts, None)
    }

    fn from_facts_with_custom_spec_digest(
        triple: impl Into<String>,
        environment: Environment,
        facts: BTreeMap<String, BTreeSet<Option<String>>>,
        custom_target_spec_digest: Option<String>,
    ) -> Result<Self, TargetError> {
        let triple = triple.into();
        validate_target_fact_fields(&triple, &facts, custom_target_spec_digest.as_deref())?;
        let arch = Arch::new(required_scalar_fact(&facts, "target_arch")?.to_owned())?;
        let os = Os::new(required_scalar_fact(&facts, "target_os")?.to_owned())?;
        let digest =
            recompute_target_fact_digest(&triple, &facts, custom_target_spec_digest.as_deref())?;
        Ok(Self {
            triple,
            arch,
            os,
            environment,
            facts,
            target_fact_digest: digest,
            custom_target_spec_digest,
        })
    }

    pub fn verify(&self) -> Result<(), TargetError> {
        validate_target_fact_fields(
            &self.triple,
            &self.facts,
            self.custom_target_spec_digest.as_deref(),
        )?;
        let expected_arch =
            Arch::new(required_scalar_fact(&self.facts, "target_arch")?.to_owned())?;
        if self.arch != expected_arch {
            return Err(TargetError::TargetProjectionMismatch {
                projection: "arch",
                fact: "target_arch",
            });
        }
        let expected_os = Os::new(required_scalar_fact(&self.facts, "target_os")?.to_owned())?;
        if self.os != expected_os {
            return Err(TargetError::TargetProjectionMismatch {
                projection: "os",
                fact: "target_os",
            });
        }
        if !is_digest(&self.target_fact_digest)
            || self.target_fact_digest
                != recompute_target_fact_digest(
                    &self.triple,
                    &self.facts,
                    self.custom_target_spec_digest.as_deref(),
                )?
        {
            return Err(TargetError::TargetFactDigestMismatch);
        }
        Ok(())
    }

    pub fn matches(&self, predicate: &str) -> Result<bool, TargetError> {
        let predicate = parse_validated_predicate(predicate)?;
        predicate.evaluate(self)
    }

    /// Evaluates a Cargo target-table selector using only committed rustc built-in facts.
    ///
    /// Composition-only facts such as `environment` are deliberately rejected so a
    /// generated manifest can never rely on a cfg that rustc/Cargo cannot reproduce.
    pub(crate) fn matches_cargo_selector(&self, selector: &str) -> Result<bool, TargetError> {
        if selector.starts_with("cfg(") {
            let predicate = parse_validated_predicate(selector)?;
            if predicate.uses_environment() {
                return Err(TargetError::InvalidPredicate(
                    "`environment` is a composition-only fact and cannot select Cargo dependencies"
                        .into(),
                ));
            }
            predicate.evaluate(self)
        } else {
            validate_target_triple(selector)?;
            Ok(selector == self.triple)
        }
    }

    pub fn fact_value(&self, key: &str) -> Option<&str> {
        self.facts
            .get(key)?
            .iter()
            .find_map(|value| value.as_deref())
    }

    pub fn arch(&self) -> &Arch {
        &self.arch
    }

    pub fn os(&self) -> &Os {
        &self.os
    }
}

fn query_rustc_facts(
    rustc: &Path,
    target_argument: &Path,
) -> Result<BTreeMap<String, BTreeSet<Option<String>>>, TargetError> {
    query_rustc_facts_with_timeout(rustc, target_argument, RUSTC_QUERY_TIMEOUT)
}

fn query_rustc_facts_with_timeout(
    rustc: &Path,
    target_argument: &Path,
    timeout: Duration,
) -> Result<BTreeMap<String, BTreeSet<Option<String>>>, TargetError> {
    let mut command = Command::new(rustc);
    command
        .args(["--print", "cfg", "--target"])
        .arg(target_argument)
        .env_clear()
        .env("PATH", rustc.parent().unwrap_or_else(|| Path::new("/")))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;

        command.process_group(0);
    }
    let mut child = command.spawn()?;
    #[cfg(unix)]
    let process_group = rustix::process::Pid::from_child(&child);
    let stdout = child.stdout.take().ok_or_else(|| {
        io::Error::other("rustc stdout pipe was unavailable after successful spawn")
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        io::Error::other("rustc stderr pipe was unavailable after successful spawn")
    })?;
    let mut stdout_reader = Some(thread::spawn(move || {
        read_bounded_stream(stdout, "stdout", MAX_RUSTC_CFG_OUTPUT_BYTES)
    }));
    let mut stderr_reader = Some(thread::spawn(move || {
        read_bounded_stream(stderr, "stderr", MAX_RUSTC_DIAGNOSTIC_BYTES)
    }));
    let started = Instant::now();
    let deadline = started.checked_add(timeout).unwrap_or(started);
    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;
    loop {
        if status.is_none() {
            status = child.try_wait()?;
        }
        collect_finished_output_reader(&mut stdout_reader, &mut stdout);
        collect_finished_output_reader(&mut stderr_reader, &mut stderr);
        if status.is_some() && stdout.is_some() && stderr.is_some() {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            #[cfg(unix)]
            let _ =
                rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL);
            terminate_and_collect_rustc_query(
                &mut child,
                &mut status,
                &mut stdout_reader,
                &mut stdout,
                &mut stderr_reader,
                &mut stderr,
                now.checked_add(RUSTC_QUERY_TERMINATION_GRACE)
                    .unwrap_or(now),
            );
            return Err(TargetError::RustcTimedOut {
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
    let stdout = String::from_utf8(stdout)
        .map_err(|_| TargetError::InvalidRustcOutputEncoding { stream: "stdout" })?;
    let stderr = String::from_utf8(stderr)
        .map_err(|_| TargetError::InvalidRustcOutputEncoding { stream: "stderr" })?;
    if !status.success() {
        return Err(TargetError::RustcFailed(stderr));
    }
    let facts = parse_facts(&stdout)?;
    validate_complete_rustc_facts(&facts)?;
    Ok(facts)
}

type OutputReader = thread::JoinHandle<Result<Vec<u8>, TargetError>>;

fn collect_finished_output_reader(
    reader: &mut Option<OutputReader>,
    output: &mut Option<Result<Vec<u8>, TargetError>>,
) {
    if reader.as_ref().is_some_and(OutputReader::is_finished) {
        let finished = reader
            .take()
            .expect("a finished output reader must still be present");
        *output = Some(join_output_reader(finished));
    }
}

fn terminate_and_collect_rustc_query(
    child: &mut Child,
    status: &mut Option<ExitStatus>,
    stdout_reader: &mut Option<OutputReader>,
    stdout: &mut Option<Result<Vec<u8>, TargetError>>,
    stderr_reader: &mut Option<OutputReader>,
    stderr: &mut Option<Result<Vec<u8>, TargetError>>,
    cleanup_deadline: Instant,
) {
    let _ = child.kill();
    loop {
        if status.is_none()
            && let Ok(observed) = child.try_wait()
        {
            *status = observed;
        }
        collect_finished_output_reader(stdout_reader, stdout);
        collect_finished_output_reader(stderr_reader, stderr);
        if status.is_some() && stdout_reader.is_none() && stderr_reader.is_none() {
            return;
        }
        let now = Instant::now();
        if now >= cleanup_deadline {
            // Dropping an unfinished JoinHandle detaches it. In particular, this keeps
            // platforms without process-group termination from ever blocking forever
            // on a descendant which inherited one of the output pipes.
            return;
        }
        thread::sleep(
            cleanup_deadline
                .saturating_duration_since(now)
                .min(RUSTC_QUERY_POLL_INTERVAL),
        );
    }
}

impl TryFrom<UncheckedTarget> for Target {
    type Error = TargetError;

    fn try_from(value: UncheckedTarget) -> Result<Self, Self::Error> {
        let target = Self {
            triple: value.triple,
            arch: value.arch,
            os: value.os,
            environment: value.environment,
            facts: value.facts,
            target_fact_digest: value.target_fact_digest,
            custom_target_spec_digest: value.custom_target_spec_digest,
        };
        target.verify()?;
        Ok(target)
    }
}

impl TargetFactsRecord {
    pub fn from_json(bytes: &[u8]) -> Result<Self, TargetError> {
        validate_target_json_size(bytes)?;
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn new(
        triple: impl Into<String>,
        facts: BTreeMap<String, BTreeSet<Option<String>>>,
        custom_target_spec_digest: Option<String>,
    ) -> Result<Self, TargetError> {
        let record = Self {
            schema: TARGET_FACTS_SCHEMA,
            triple: triple.into(),
            facts,
            custom_target_spec_digest,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn from_target(target: &Target) -> Result<Self, TargetError> {
        target.verify()?;
        let record = Self::new(
            target.triple.clone(),
            target.facts.clone(),
            target.custom_target_spec_digest.clone(),
        )?;
        if record.semantic_digest()? != target.target_fact_digest {
            return Err(TargetError::TargetFactDigestMismatch);
        }
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), TargetError> {
        if self.schema != TARGET_FACTS_SCHEMA {
            return Err(TargetError::UnsupportedTargetFactsSchema {
                actual: self.schema,
                expected: TARGET_FACTS_SCHEMA,
            });
        }
        validate_target_fact_fields(
            &self.triple,
            &self.facts,
            self.custom_target_spec_digest.as_deref(),
        )?;
        Ok(())
    }

    pub fn semantic_digest(&self) -> Result<String, TargetError> {
        self.validate()?;
        recompute_target_fact_digest(
            &self.triple,
            &self.facts,
            self.custom_target_spec_digest.as_deref(),
        )
    }
}

fn validate_target_json_size(bytes: &[u8]) -> Result<(), TargetError> {
    if bytes.len() > MAX_CANONICAL_TARGET_FACTS_RECORD_BYTES {
        Err(TargetError::TargetJsonTooLarge {
            actual: bytes.len(),
            maximum: MAX_CANONICAL_TARGET_FACTS_RECORD_BYTES,
        })
    } else {
        Ok(())
    }
}

impl TryFrom<UncheckedTargetFactsRecord> for TargetFactsRecord {
    type Error = TargetError;

    fn try_from(value: UncheckedTargetFactsRecord) -> Result<Self, Self::Error> {
        let record = Self {
            schema: value.schema,
            triple: value.triple,
            facts: value.facts,
            custom_target_spec_digest: value.custom_target_spec_digest,
        };
        record.validate()?;
        Ok(record)
    }
}

fn join_output_reader<T: Send + 'static>(
    reader: thread::JoinHandle<Result<T, TargetError>>,
) -> Result<T, TargetError> {
    reader
        .join()
        .map_err(|_| TargetError::RustcOutputReaderPanicked)?
}

fn read_bounded_stream(
    mut stream: impl Read,
    name: &'static str,
    maximum: usize,
) -> Result<Vec<u8>, TargetError> {
    let mut output = Vec::with_capacity(maximum.min(8 * 1_024));
    let mut chunk = [0_u8; 8 * 1_024];
    let mut too_large = false;
    loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        if !too_large {
            let remaining = maximum.saturating_sub(output.len());
            if count <= remaining {
                output.extend_from_slice(&chunk[..count]);
            } else {
                too_large = true;
            }
        }
    }
    if too_large {
        Err(TargetError::RustcOutputTooLarge {
            stream: name,
            maximum,
        })
    } else {
        Ok(output)
    }
}

fn recompute_target_fact_digest(
    triple: &str,
    facts: &BTreeMap<String, BTreeSet<Option<String>>>,
    custom_target_spec_digest: Option<&str>,
) -> Result<String, TargetError> {
    Ok(hex::encode(canonical::domain_hash(
        TARGET_FACTS_DOMAIN,
        &(triple, facts, custom_target_spec_digest),
    )?))
}

fn validate_target_fact_fields(
    triple: &str,
    facts: &BTreeMap<String, BTreeSet<Option<String>>>,
    custom_target_spec_digest: Option<&str>,
) -> Result<(), TargetError> {
    validate_target_triple(triple)?;
    if facts.len() > MAX_TARGET_FACT_KEYS {
        return Err(TargetError::InvalidFact(format!(
            "target fact key count exceeds {MAX_TARGET_FACT_KEYS}"
        )));
    }
    let mut total_values = 0_usize;
    for (key, values) in facts {
        if key.len() > MAX_TARGET_FACT_KEY_BYTES {
            return Err(TargetError::InvalidFact(format!(
                "target fact key exceeds {MAX_TARGET_FACT_KEY_BYTES} bytes"
            )));
        }
        if values.is_empty() || values.len() > MAX_TARGET_FACT_VALUES_PER_KEY {
            return Err(TargetError::InvalidFact(format!(
                "target fact `{key}` has an invalid value count"
            )));
        }
        total_values = total_values
            .checked_add(values.len())
            .ok_or_else(|| TargetError::InvalidFact("target fact value count overflowed".into()))?;
        if total_values > MAX_TARGET_FACT_TOTAL_VALUES {
            return Err(TargetError::InvalidFact(format!(
                "target fact value count exceeds {MAX_TARGET_FACT_TOTAL_VALUES}"
            )));
        }
        for value in values {
            validate_fact(key, value.as_deref())?;
        }
        validate_fact_values(key, values)?;
    }
    if custom_target_spec_digest.is_some_and(|digest| !is_digest(digest)) {
        return Err(TargetError::InvalidCustomTargetSpecDigest(
            custom_target_spec_digest.unwrap_or_default().into(),
        ));
    }
    validate_complete_rustc_facts(facts)?;
    let encoded = canonical::jcs_bytes(&TargetFactsRecordRef {
        schema: TARGET_FACTS_SCHEMA,
        triple,
        facts,
        custom_target_spec_digest,
    })?;
    if encoded.len() > MAX_CANONICAL_TARGET_FACTS_RECORD_BYTES {
        return Err(TargetError::TargetFactsRecordTooLarge {
            actual: encoded.len(),
            maximum: MAX_CANONICAL_TARGET_FACTS_RECORD_BYTES,
        });
    }
    Ok(())
}

#[derive(Serialize)]
struct TargetFactsRecordRef<'a> {
    schema: u32,
    triple: &'a str,
    facts: &'a BTreeMap<String, BTreeSet<Option<String>>>,
    #[serde(rename = "custom-target-spec-digest")]
    custom_target_spec_digest: Option<&'a str>,
}

pub(crate) fn validate_target_triple(triple: &str) -> Result<(), TargetError> {
    if triple.is_empty()
        || triple.len() > MAX_TARGET_TRIPLE_BYTES
        || !triple.is_ascii()
        || !triple.as_bytes()[0].is_ascii_lowercase()
        || triple.starts_with('-')
        || triple.ends_with('-')
        || triple.split('-').any(str::is_empty)
        || !triple.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        Err(TargetError::InvalidTriple(triple.into()))
    } else {
        Ok(())
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_target_projection_value(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.is_ascii()
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'"' | b'\\'))
}

fn required_scalar_fact<'a>(
    facts: &'a BTreeMap<String, BTreeSet<Option<String>>>,
    key: &str,
) -> Result<&'a str, TargetError> {
    let values = facts.get(key).ok_or_else(|| {
        TargetError::InvalidFact(format!(
            "rustc cfg output is missing required scalar `{key}`"
        ))
    })?;
    if values.len() != 1 {
        return Err(TargetError::InvalidFact(format!(
            "required scalar `{key}` does not have exactly one value"
        )));
    }
    values
        .iter()
        .next()
        .and_then(|value| value.as_deref())
        .ok_or_else(|| {
            TargetError::InvalidFact(format!(
                "required scalar `{key}` does not have a string value"
            ))
        })
}

pub fn parse_facts(input: &str) -> Result<BTreeMap<String, BTreeSet<Option<String>>>, TargetError> {
    if input.len() > MAX_RUSTC_CFG_OUTPUT_BYTES {
        return Err(TargetError::RustcOutputTooLarge {
            stream: "stdout",
            maximum: MAX_RUSTC_CFG_OUTPUT_BYTES,
        });
    }
    let mut facts: BTreeMap<String, BTreeSet<Option<String>>> = BTreeMap::new();
    let mut total_values = 0_usize;
    for line in input.lines() {
        if line.is_empty() {
            return Err(TargetError::InvalidFact("empty rustc cfg line".into()));
        }
        let (key, value) = if let Some((key, raw)) = line.split_once('=') {
            if !(raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2) {
                return Err(TargetError::InvalidFact(line.to_owned()));
            }
            (key, Some(raw[1..raw.len() - 1].to_owned()))
        } else {
            (line, None)
        };
        validate_fact(key, value.as_deref())?;
        if !facts.contains_key(key) && facts.len() == MAX_TARGET_FACT_KEYS {
            return Err(TargetError::InvalidFact(format!(
                "target fact key count exceeds {MAX_TARGET_FACT_KEYS}"
            )));
        }
        total_values = total_values
            .checked_add(1)
            .ok_or_else(|| TargetError::InvalidFact("target fact value count overflowed".into()))?;
        if total_values > MAX_TARGET_FACT_TOTAL_VALUES {
            return Err(TargetError::InvalidFact(format!(
                "target fact value count exceeds {MAX_TARGET_FACT_TOTAL_VALUES}"
            )));
        }
        let values = facts.entry(key.to_owned()).or_default();
        if values.len() == MAX_TARGET_FACT_VALUES_PER_KEY {
            return Err(TargetError::InvalidFact(format!(
                "target fact `{key}` value count exceeds {MAX_TARGET_FACT_VALUES_PER_KEY}"
            )));
        }
        if !values.insert(value) {
            return Err(TargetError::InvalidFact(format!(
                "duplicate rustc cfg fact `{line}`"
            )));
        }
    }
    for (key, values) in &facts {
        validate_fact_values(key, values)?;
    }
    Ok(facts)
}

#[derive(Clone, Copy)]
enum FactSchema {
    Flag,
    SingleClosed(&'static [&'static str]),
    MultiClosed(&'static [&'static str]),
    SingleOpen,
    MultiOpen,
}

fn fact_schema(key: &str) -> Option<FactSchema> {
    match key {
        "debug_assertions" | "unix" | "windows" => Some(FactSchema::Flag),
        "panic" => Some(FactSchema::SingleClosed(&["abort", "unwind"])),
        "target_abi" | "target_arch" | "target_env" | "target_os" | "target_vendor" => {
            Some(FactSchema::SingleOpen)
        }
        "target_endian" => Some(FactSchema::SingleClosed(&["big", "little"])),
        "target_family" | "target_feature" => Some(FactSchema::MultiOpen),
        "target_has_atomic" | "target_has_atomic_primitive_alignment" => {
            Some(FactSchema::MultiClosed(&[
                "8", "16", "32", "64", "128", "ptr",
            ]))
        }
        "target_pointer_width" => Some(FactSchema::SingleClosed(&["16", "32", "64"])),
        _ => None,
    }
}

fn validate_fact(key: &str, value: Option<&str>) -> Result<(), TargetError> {
    if key.is_empty()
        || key.len() > MAX_TARGET_FACT_KEY_BYTES
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(TargetError::InvalidFact(format!(
            "invalid target fact key `{key}`"
        )));
    }
    let Some(schema) = fact_schema(key) else {
        return Err(TargetError::InvalidFact(format!(
            "unknown or reserved target fact key `{key}`"
        )));
    };
    if let Some(value) = value
        && (value.len() > MAX_TARGET_FACT_VALUE_BYTES
            || !value.is_ascii()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || matches!(byte, b'"' | b'\\')))
    {
        return Err(TargetError::InvalidFact(format!(
            "invalid target fact value for `{key}`"
        )));
    }
    let valid = match (schema, value) {
        (FactSchema::Flag, None) | (FactSchema::SingleOpen | FactSchema::MultiOpen, Some(_)) => {
            true
        }
        (FactSchema::SingleClosed(allowed) | FactSchema::MultiClosed(allowed), Some(value)) => {
            allowed.contains(&value)
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(TargetError::InvalidFact(format!(
            "invalid schema-v1 form or value for target fact `{key}`"
        )))
    }
}

fn validate_fact_values(key: &str, values: &BTreeSet<Option<String>>) -> Result<(), TargetError> {
    if matches!(
        fact_schema(key),
        Some(FactSchema::SingleClosed(_) | FactSchema::SingleOpen)
    ) && values.len() != 1
    {
        return Err(TargetError::InvalidFact(format!(
            "single-valued target fact `{key}` has {} values",
            values.len()
        )));
    }
    Ok(())
}

fn validate_complete_rustc_facts(
    facts: &BTreeMap<String, BTreeSet<Option<String>>>,
) -> Result<(), TargetError> {
    for key in REQUIRED_SCALAR_FACTS {
        if facts.get(*key).is_none_or(|values| values.len() != 1) {
            return Err(TargetError::InvalidFact(format!(
                "rustc cfg output is missing required scalar `{key}`"
            )));
        }
    }
    Ok(())
}

fn deserialize_target_facts<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, BTreeSet<Option<String>>>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(TargetFactsVisitor)
}

struct TargetFactsVisitor;

impl<'de> Visitor<'de> for TargetFactsVisitor {
    type Value = BTreeMap<String, BTreeSet<Option<String>>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded map of unique rustc cfg keys and value sets")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut facts = BTreeMap::new();
        let mut total_values = 0_usize;
        while let Some(key) = map.next_key::<String>()? {
            if facts.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate target fact key `{key}`"
                )));
            }
            if facts.len() == MAX_TARGET_FACT_KEYS {
                return Err(de::Error::custom(format!(
                    "target fact key count exceeds {MAX_TARGET_FACT_KEYS}"
                )));
            }
            if key.len() > MAX_TARGET_FACT_KEY_BYTES {
                return Err(de::Error::custom(format!(
                    "target fact key exceeds {MAX_TARGET_FACT_KEY_BYTES} bytes"
                )));
            }
            let values = map.next_value_seed(TargetFactValuesSeed)?;
            total_values = total_values
                .checked_add(values.len())
                .ok_or_else(|| de::Error::custom("target fact value count overflowed"))?;
            if total_values > MAX_TARGET_FACT_TOTAL_VALUES {
                return Err(de::Error::custom(format!(
                    "target fact value count exceeds {MAX_TARGET_FACT_TOTAL_VALUES}"
                )));
            }
            facts.insert(key, values);
        }
        Ok(facts)
    }
}

struct TargetFactValuesSeed;

impl<'de> de::DeserializeSeed<'de> for TargetFactValuesSeed {
    type Value = BTreeSet<Option<String>>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(TargetFactValuesVisitor)
    }
}

struct TargetFactValuesVisitor;

impl<'de> Visitor<'de> for TargetFactValuesVisitor {
    type Value = BTreeSet<Option<String>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded sequence of unique optional rustc cfg values")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = BTreeSet::new();
        while let Some(value) = sequence.next_element::<Option<String>>()? {
            if values.len() == MAX_TARGET_FACT_VALUES_PER_KEY {
                return Err(de::Error::custom(format!(
                    "target fact value count exceeds {MAX_TARGET_FACT_VALUES_PER_KEY}"
                )));
            }
            if value
                .as_deref()
                .is_some_and(|value| value.len() > MAX_TARGET_FACT_VALUE_BYTES)
            {
                return Err(de::Error::custom(format!(
                    "target fact value exceeds {MAX_TARGET_FACT_VALUE_BYTES} bytes"
                )));
            }
            if !values.insert(value) {
                return Err(de::Error::custom("duplicate target fact value"));
            }
        }
        if values.is_empty() {
            return Err(de::Error::custom("target fact value set is empty"));
        }
        Ok(values)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Predicate {
    All(Vec<Self>),
    Any(Vec<Self>),
    Not(Box<Self>),
    Equals(String, String),
    Present(String),
}

impl Predicate {
    fn uses_environment(&self) -> bool {
        match self {
            Self::All(items) | Self::Any(items) => items.iter().any(Self::uses_environment),
            Self::Not(item) => item.uses_environment(),
            Self::Equals(key, _) | Self::Present(key) => key == "environment",
        }
    }

    fn validate(&self) -> Result<(), TargetError> {
        match self {
            Self::All(items) | Self::Any(items) => {
                for item in items {
                    item.validate()?;
                }
                Ok(())
            }
            Self::Not(item) => item.validate(),
            Self::Equals(key, value) if key == "environment" => {
                if matches!(value.as_str(), "browser" | "server" | "desktop" | "mobile") {
                    Ok(())
                } else {
                    Err(TargetError::InvalidPredicate(format!(
                        "invalid environment value `{value}`"
                    )))
                }
            }
            Self::Equals(key, value) => validate_predicate_fact(key, Some(value)),
            Self::Present(key) if matches!(key.as_str(), "true" | "false") => Ok(()),
            Self::Present(key) => validate_predicate_fact(key, None),
        }
    }

    fn evaluate(&self, target: &Target) -> Result<bool, TargetError> {
        match self {
            Self::All(items) => {
                for item in items {
                    if !item.evaluate(target)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Self::Any(items) => {
                for item in items {
                    if item.evaluate(target)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Self::Not(item) => Ok(!item.evaluate(target)?),
            Self::Equals(key, value) if key == "environment" => match value.as_str() {
                "browser" | "server" | "desktop" | "mobile" => {
                    Ok(value == target.environment.as_str())
                }
                _ => Err(TargetError::InvalidPredicate(format!(
                    "invalid environment value `{value}`"
                ))),
            },
            Self::Equals(key, value) => {
                validate_predicate_fact(key, Some(value))?;
                Ok(target
                    .facts
                    .get(key)
                    .is_some_and(|values| values.contains(&Some(value.clone()))))
            }
            Self::Present(key) if key == "true" => Ok(true),
            Self::Present(key) if key == "false" => Ok(false),
            Self::Present(key) => {
                validate_predicate_fact(key, None)?;
                Ok(target.facts.contains_key(key))
            }
        }
    }
}

fn parse_validated_predicate(input: &str) -> Result<Predicate, TargetError> {
    let predicate = PredicateParser::new(input).parse()?;
    predicate.validate()?;
    Ok(predicate)
}

/// Proves that `partitions` form an exact, non-overlapping partition of `parent`
/// for every schema-valid target fact assignment, including open custom fact values.
pub fn validate_predicate_partition(parent: &str, partitions: &[&str]) -> Result<(), TargetError> {
    let mut budget = PredicateAnalysisBudget::new();
    validate_predicate_partition_with_budget(parent, partitions, &mut budget)
}

/// The catalog owns one of these budgets so independently valid owner records
/// cannot multiply the bounded SAT work by the catalog owner limit.
pub(crate) struct PredicateAnalysisBudget {
    limits: PredicateAnalysisLimits,
    variables_remaining: usize,
    clauses_remaining: usize,
    literals_remaining: usize,
    decisions_remaining: usize,
    work_remaining: usize,
}

#[derive(Clone, Copy)]
struct PredicateAnalysisLimits {
    variables: usize,
    clauses: usize,
    literals: usize,
    decisions: usize,
    work: usize,
}

impl PredicateAnalysisBudget {
    pub(crate) const fn new() -> Self {
        Self::with_limits(PredicateAnalysisLimits {
            variables: MAX_TARGET_PREDICATE_ANALYSIS_VARIABLES,
            clauses: MAX_TARGET_PREDICATE_ANALYSIS_CLAUSES,
            literals: MAX_TARGET_PREDICATE_ANALYSIS_LITERALS,
            decisions: MAX_TARGET_PREDICATE_ANALYSIS_DECISIONS,
            work: MAX_TARGET_PREDICATE_ANALYSIS_WORK,
        })
    }

    const fn with_limits(limits: PredicateAnalysisLimits) -> Self {
        Self {
            limits,
            variables_remaining: limits.variables,
            clauses_remaining: limits.clauses,
            literals_remaining: limits.literals,
            decisions_remaining: limits.decisions,
            work_remaining: limits.work,
        }
    }

    #[cfg(test)]
    pub(crate) const fn with_work_limit_for_test(work: usize) -> Self {
        Self::with_limits(PredicateAnalysisLimits {
            variables: MAX_TARGET_PREDICATE_ANALYSIS_VARIABLES,
            clauses: MAX_TARGET_PREDICATE_ANALYSIS_CLAUSES,
            literals: MAX_TARGET_PREDICATE_ANALYSIS_LITERALS,
            decisions: MAX_TARGET_PREDICATE_ANALYSIS_DECISIONS,
            work,
        })
    }

    fn take_variables(&mut self, count: usize) -> Result<(), TargetError> {
        take_analysis_resource(
            &mut self.variables_remaining,
            count,
            "CNF variables",
            self.limits.variables,
        )
    }

    fn take_clause(&mut self, literals: usize) -> Result<(), TargetError> {
        take_analysis_resource(
            &mut self.clauses_remaining,
            1,
            "CNF clauses",
            self.limits.clauses,
        )?;
        take_analysis_resource(
            &mut self.literals_remaining,
            literals,
            "CNF literals",
            self.limits.literals,
        )
    }

    fn take_decision(&mut self) -> Result<(), TargetError> {
        take_analysis_resource(
            &mut self.decisions_remaining,
            1,
            "DPLL decisions",
            self.limits.decisions,
        )?;
        self.take_work(1)
    }

    fn take_work(&mut self, count: usize) -> Result<(), TargetError> {
        take_analysis_resource(
            &mut self.work_remaining,
            count,
            "analysis work",
            self.limits.work,
        )
    }
}

fn take_analysis_resource(
    remaining: &mut usize,
    count: usize,
    resource: &'static str,
    maximum: usize,
) -> Result<(), TargetError> {
    let Some(next) = remaining.checked_sub(count) else {
        return Err(TargetError::PredicateAnalysisLimitExceeded { resource, maximum });
    };
    *remaining = next;
    Ok(())
}

pub(crate) fn validate_predicate_partition_with_budget(
    parent: &str,
    partitions: &[&str],
    budget: &mut PredicateAnalysisBudget,
) -> Result<(), TargetError> {
    if partitions.is_empty() || partitions.len() > MAX_TARGET_PREDICATE_PARTITIONS {
        return Err(TargetError::InvalidPredicatePartitionCount {
            actual: partitions.len(),
            maximum: MAX_TARGET_PREDICATE_PARTITIONS,
        });
    }
    let input_bytes = partitions
        .iter()
        .try_fold(parent.len(), |total, predicate| {
            total
                .checked_add(predicate.len())
                .ok_or(TargetError::PredicateAnalysisLimitExceeded {
                    resource: "analysis work",
                    maximum: budget.limits.work,
                })
        })?;
    budget.take_work(input_bytes)?;
    let parent = parse_validated_predicate(parent)?;
    let partitions = partitions
        .iter()
        .map(|predicate| parse_validated_predicate(predicate))
        .collect::<Result<Vec<_>, _>>()?;
    validate_predicate_model_universe(&parent, &partitions, budget)?;

    for (index, partition) in partitions.iter().enumerate() {
        let outside_parent = Predicate::All(vec![
            partition.clone(),
            Predicate::Not(Box::new(parent.clone())),
        ]);
        if predicate_is_satisfiable(&outside_parent, budget)? {
            return Err(TargetError::PredicatePartitionOutsideParent { index });
        }
        let inside_parent = Predicate::All(vec![parent.clone(), partition.clone()]);
        if !predicate_is_satisfiable(&inside_parent, budget)? {
            return Err(TargetError::PredicatePartitionUnsatisfiable { index });
        }
    }

    for first in 0..partitions.len() {
        for second in first + 1..partitions.len() {
            let overlap = Predicate::All(vec![
                parent.clone(),
                partitions[first].clone(),
                partitions[second].clone(),
            ]);
            if predicate_is_satisfiable(&overlap, budget)? {
                return Err(TargetError::PredicatePartitionOverlap { first, second });
            }
        }
    }

    let gap = Predicate::All(vec![
        parent,
        Predicate::Not(Box::new(Predicate::Any(partitions))),
    ]);
    if predicate_is_satisfiable(&gap, budget)? {
        return Err(TargetError::PredicatePartitionGap);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum PredicateAtom {
    Environment(String),
    FactEquals(String, String),
    FactPresent(String),
}

fn validate_predicate_model_universe(
    parent: &Predicate,
    partitions: &[Predicate],
    budget: &mut PredicateAnalysisBudget,
) -> Result<(), TargetError> {
    let mut atoms = BTreeSet::new();
    collect_predicate_atoms(parent, &mut atoms, budget)?;
    for partition in partitions {
        collect_predicate_atoms(partition, &mut atoms, budget)?;
    }

    let mut present_keys = BTreeSet::new();
    let mut equality_values: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for atom in atoms {
        match atom {
            PredicateAtom::Environment(_) => {}
            PredicateAtom::FactEquals(key, value) => {
                present_keys.insert(key.clone());
                equality_values.entry(key).or_default().insert(value);
            }
            PredicateAtom::FactPresent(key) => {
                present_keys.insert(key);
            }
        }
    }

    present_keys.extend(REQUIRED_SCALAR_FACTS.iter().map(|key| (*key).to_owned()));
    // These variables are introduced by the schema encoding even when no
    // predicate mentions them, so the maximal concrete witness includes them.
    present_keys.insert("target_has_atomic".into());
    present_keys.insert("target_has_atomic_primitive_alignment".into());

    let mut facts = BTreeMap::new();
    let mut maximum_model_values = 0_usize;
    for key in present_keys {
        budget.take_work(1)?;
        let mentioned = equality_values.remove(&key).unwrap_or_default();
        let schema = fact_schema(&key).expect("validated predicate keys have a schema");
        let values = match schema {
            FactSchema::Flag => BTreeSet::from([None]),
            FactSchema::SingleClosed(allowed) => {
                let value = allowed
                    .iter()
                    .max_by_key(|value| value.len())
                    .expect("closed scalar domains are non-empty");
                BTreeSet::from([Some((*value).to_owned())])
            }
            FactSchema::MultiClosed(allowed) => allowed
                .iter()
                .map(|value| Some((*value).to_owned()))
                .collect(),
            FactSchema::SingleOpen => {
                let other = fresh_open_fact_value(&mentioned);
                let value = mentioned
                    .iter()
                    .chain(std::iter::once(&other))
                    .max_by_key(|value| value.len())
                    .expect("the fresh open value makes the domain non-empty")
                    .clone();
                BTreeSet::from([Some(value)])
            }
            FactSchema::MultiOpen => {
                if mentioned.len() > MAX_TARGET_FACT_VALUES_PER_KEY {
                    return Err(TargetError::PredicateAnalysisLimitExceeded {
                        resource: "values per multi-valued fact",
                        maximum: MAX_TARGET_FACT_VALUES_PER_KEY,
                    });
                }
                let mentioned_values = mentioned.iter().cloned().map(Some).collect::<BTreeSet<_>>();
                let other_values = BTreeSet::from([Some(fresh_open_fact_value(&mentioned))]);
                if canonical::jcs_bytes(&mentioned_values)?.len()
                    >= canonical::jcs_bytes(&other_values)?.len()
                    && !mentioned_values.is_empty()
                {
                    mentioned_values
                } else {
                    other_values
                }
            }
        };
        let maximum_for_key = match schema {
            FactSchema::Flag | FactSchema::SingleClosed(_) | FactSchema::SingleOpen => 1,
            FactSchema::MultiClosed(allowed) => allowed.len(),
            FactSchema::MultiOpen => mentioned.len().max(1),
        };
        maximum_model_values = maximum_model_values.checked_add(maximum_for_key).ok_or(
            TargetError::PredicateAnalysisLimitExceeded {
                resource: "concrete target values",
                maximum: MAX_TARGET_FACT_TOTAL_VALUES,
            },
        )?;
        facts.insert(key, values);
    }

    if maximum_model_values > MAX_TARGET_FACT_TOTAL_VALUES {
        return Err(TargetError::PredicateAnalysisLimitExceeded {
            resource: "concrete target values",
            maximum: MAX_TARGET_FACT_TOTAL_VALUES,
        });
    }

    // For each key this record selects the largest canonical value sequence any
    // SAT assignment can require. JSON record overhead is fixed and additive;
    // removing keys or values only shortens it. Therefore a successful check
    // proves every symbolic model has a schema-valid <=256-KiB concrete witness.
    if let Err(error) = validate_target_fact_fields("a", &facts, None) {
        return match error {
            TargetError::TargetFactsRecordTooLarge { .. } => {
                Err(TargetError::PredicateAnalysisLimitExceeded {
                    resource: "canonical target-facts bytes",
                    maximum: MAX_CANONICAL_TARGET_FACTS_RECORD_BYTES,
                })
            }
            other => Err(other),
        };
    }
    Ok(())
}

fn collect_predicate_atoms(
    predicate: &Predicate,
    atoms: &mut BTreeSet<PredicateAtom>,
    budget: &mut PredicateAnalysisBudget,
) -> Result<(), TargetError> {
    budget.take_work(1)?;
    match predicate {
        Predicate::All(items) | Predicate::Any(items) => {
            for item in items {
                collect_predicate_atoms(item, atoms, budget)?;
            }
            return Ok(());
        }
        Predicate::Not(item) => return collect_predicate_atoms(item, atoms, budget),
        Predicate::Equals(key, value) if key == "environment" => {
            insert_predicate_atom(atoms, PredicateAtom::Environment(value.clone()))?;
        }
        Predicate::Equals(key, value) => {
            insert_predicate_atom(atoms, PredicateAtom::FactEquals(key.clone(), value.clone()))?;
        }
        Predicate::Present(key) if key == "true" || key == "false" => {}
        Predicate::Present(key) => {
            insert_predicate_atom(atoms, PredicateAtom::FactPresent(key.clone()))?;
        }
    }
    Ok(())
}

fn insert_predicate_atom(
    atoms: &mut BTreeSet<PredicateAtom>,
    atom: PredicateAtom,
) -> Result<(), TargetError> {
    if !atoms.contains(&atom) && atoms.len() == MAX_TARGET_PREDICATE_ANALYSIS_ATOMS {
        return Err(TargetError::PredicateAnalysisLimitExceeded {
            resource: "predicate atoms",
            maximum: MAX_TARGET_PREDICATE_ANALYSIS_ATOMS,
        });
    }
    atoms.insert(atom);
    Ok(())
}

fn fresh_open_fact_value(mentioned: &BTreeSet<String>) -> String {
    for index in 0..=mentioned.len() {
        let candidate = format!("rust_agent_other_{index}");
        if !mentioned.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!("a finite set cannot contain more distinct candidates than its length")
}

struct PredicateSatBuilder<'a> {
    atom_variables: BTreeMap<PredicateAtom, i32>,
    clauses: Vec<Vec<i32>>,
    variables: i32,
    budget: &'a mut PredicateAnalysisBudget,
}

impl PredicateSatBuilder<'_> {
    fn new(budget: &mut PredicateAnalysisBudget) -> PredicateSatBuilder<'_> {
        PredicateSatBuilder {
            atom_variables: BTreeMap::new(),
            clauses: Vec::new(),
            variables: 0,
            budget,
        }
    }

    fn new_variable(&mut self) -> Result<i32, TargetError> {
        self.budget.take_variables(1)?;
        self.variables += 1;
        Ok(self.variables)
    }

    fn atom_variable(&mut self, atom: PredicateAtom) -> Result<i32, TargetError> {
        if let Some(variable) = self.atom_variables.get(&atom) {
            return Ok(*variable);
        }
        let variable = self.new_variable()?;
        self.atom_variables.insert(atom, variable);
        Ok(variable)
    }

    fn add_clause(&mut self, clause: Vec<i32>) -> Result<(), TargetError> {
        self.budget.take_clause(clause.len())?;
        self.budget.take_work(clause.len().saturating_add(1))?;
        self.clauses.push(clause);
        Ok(())
    }

    fn encode(&mut self, predicate: &Predicate) -> Result<i32, TargetError> {
        self.budget.take_work(1)?;
        match predicate {
            Predicate::All(items) => {
                let children = items
                    .iter()
                    .map(|item| self.encode(item))
                    .collect::<Result<Vec<_>, _>>()?;
                let variable = self.new_variable()?;
                for child in &children {
                    self.add_clause(vec![-variable, *child])?;
                }
                let mut reverse = Vec::with_capacity(children.len() + 1);
                reverse.push(variable);
                reverse.extend(children.iter().map(|child| -*child));
                self.add_clause(reverse)?;
                Ok(variable)
            }
            Predicate::Any(items) => {
                let children = items
                    .iter()
                    .map(|item| self.encode(item))
                    .collect::<Result<Vec<_>, _>>()?;
                let variable = self.new_variable()?;
                for child in &children {
                    self.add_clause(vec![variable, -*child])?;
                }
                let mut reverse = Vec::with_capacity(children.len() + 1);
                reverse.push(-variable);
                reverse.extend(children);
                self.add_clause(reverse)?;
                Ok(variable)
            }
            Predicate::Not(item) => {
                let child = self.encode(item)?;
                let variable = self.new_variable()?;
                self.add_clause(vec![-variable, -child])?;
                self.add_clause(vec![variable, child])?;
                Ok(variable)
            }
            Predicate::Equals(key, value) if key == "environment" => {
                self.atom_variable(PredicateAtom::Environment(value.clone()))
            }
            Predicate::Equals(key, value) => {
                self.atom_variable(PredicateAtom::FactEquals(key.clone(), value.clone()))
            }
            Predicate::Present(key) if key == "true" || key == "false" => {
                let variable = self.new_variable()?;
                self.add_clause(vec![if key == "true" { variable } else { -variable }])?;
                Ok(variable)
            }
            Predicate::Present(key) => self.atom_variable(PredicateAtom::FactPresent(key.clone())),
        }
    }

    fn add_target_schema_constraints(&mut self) -> Result<(), TargetError> {
        let mut environment = Vec::with_capacity(4);
        for value in ["browser", "desktop", "mobile", "server"] {
            environment.push(self.atom_variable(PredicateAtom::Environment(value.into()))?);
        }
        self.add_exactly_one(&environment)?;

        for (key, allowed) in [
            ("panic", &["abort", "unwind"][..]),
            ("target_endian", &["big", "little"][..]),
            ("target_pointer_width", &["16", "32", "64"][..]),
        ] {
            let mut values = Vec::with_capacity(allowed.len());
            for value in allowed {
                values.push(
                    self.atom_variable(PredicateAtom::FactEquals(key.into(), (*value).into()))?,
                );
            }
            self.add_exactly_one(&values)?;
        }

        let equality_atoms = self
            .atom_variables
            .iter()
            .filter_map(|(atom, variable)| match atom {
                PredicateAtom::FactEquals(key, _) => Some((key.clone(), *variable)),
                _ => None,
            })
            .collect::<Vec<_>>();
        for (key, equality) in equality_atoms {
            let present = self.atom_variable(PredicateAtom::FactPresent(key))?;
            self.add_clause(vec![-equality, present])?;
        }

        for key in REQUIRED_SCALAR_FACTS {
            let present = self.atom_variable(PredicateAtom::FactPresent((*key).into()))?;
            self.add_clause(vec![present])?;
        }

        for (key, allowed) in [
            (
                "target_has_atomic",
                &["8", "16", "32", "64", "128", "ptr"][..],
            ),
            (
                "target_has_atomic_primitive_alignment",
                &["8", "16", "32", "64", "128", "ptr"][..],
            ),
        ] {
            let present = self.atom_variable(PredicateAtom::FactPresent(key.into()))?;
            let mut values = Vec::with_capacity(allowed.len());
            for value in allowed {
                values.push(
                    self.atom_variable(PredicateAtom::FactEquals(key.into(), (*value).into()))?,
                );
            }
            for value in &values {
                self.add_clause(vec![-*value, present])?;
            }
            let mut present_implies_value = Vec::with_capacity(values.len() + 1);
            present_implies_value.push(-present);
            present_implies_value.extend(values);
            self.add_clause(present_implies_value)?;
        }

        let mut open_single_values: BTreeMap<String, Vec<i32>> = BTreeMap::new();
        for (atom, variable) in &self.atom_variables {
            let PredicateAtom::FactEquals(key, _) = atom else {
                continue;
            };
            if matches!(fact_schema(key), Some(FactSchema::SingleOpen)) {
                open_single_values
                    .entry(key.clone())
                    .or_default()
                    .push(*variable);
            }
        }
        for values in open_single_values.values() {
            self.add_at_most_one(values)?;
        }
        Ok(())
    }

    fn add_exactly_one(&mut self, variables: &[i32]) -> Result<(), TargetError> {
        self.add_clause(variables.to_vec())?;
        self.add_at_most_one(variables)
    }

    // Sinz's sequential-counter encoding is linear in the number of values.
    // In particular, an open scalar cannot turn an input-bounded predicate into
    // the previous O(n^2) pairwise clause set.
    fn add_at_most_one(&mut self, variables: &[i32]) -> Result<(), TargetError> {
        if variables.len() < 2 {
            return Ok(());
        }
        let mut counters = Vec::with_capacity(variables.len() - 1);
        for _ in 1..variables.len() {
            counters.push(self.new_variable()?);
        }
        self.add_clause(vec![-variables[0], counters[0]])?;
        for index in 1..variables.len() - 1 {
            self.add_clause(vec![-variables[index], counters[index]])?;
            self.add_clause(vec![-counters[index - 1], counters[index]])?;
            self.add_clause(vec![-variables[index], -counters[index - 1]])?;
        }
        self.add_clause(vec![
            -variables[variables.len() - 1],
            -counters[counters.len() - 1],
        ])?;
        Ok(())
    }
}

fn predicate_is_satisfiable(
    predicate: &Predicate,
    budget: &mut PredicateAnalysisBudget,
) -> Result<bool, TargetError> {
    let (clauses, variables) = {
        let mut builder = PredicateSatBuilder::new(budget);
        let root = builder.encode(predicate)?;
        builder.add_clause(vec![root])?;
        builder.add_target_schema_constraints()?;
        (builder.clauses, builder.variables)
    };
    let assignment_count = usize::try_from(variables)
        .expect("predicate SAT variable count is non-negative")
        .checked_add(1)
        .ok_or(TargetError::PredicateAnalysisLimitExceeded {
            resource: "CNF variables",
            maximum: MAX_TARGET_PREDICATE_ANALYSIS_VARIABLES,
        })?;
    budget.take_work(assignment_count)?;
    PredicateSatSolver {
        clauses: &clauses,
        budget,
    }
    .solve(vec![0; assignment_count], 0)
}

struct PredicateSatSolver<'a> {
    clauses: &'a [Vec<i32>],
    budget: &'a mut PredicateAnalysisBudget,
}

impl PredicateSatSolver<'_> {
    fn solve(&mut self, mut assignments: Vec<i8>, depth: usize) -> Result<bool, TargetError> {
        self.budget.take_work(1)?;
        if !self.propagate(&mut assignments)? {
            return Ok(false);
        }
        let Some(variable) = self.next_variable(&assignments)? else {
            return Ok(true);
        };
        if depth == MAX_TARGET_PREDICATE_ANALYSIS_DEPTH {
            return Err(TargetError::PredicateAnalysisLimitExceeded {
                resource: "DPLL depth",
                maximum: MAX_TARGET_PREDICATE_ANALYSIS_DEPTH,
            });
        }
        self.budget.take_decision()?;
        self.budget.take_work(assignments.len())?;
        let mut enabled = assignments.clone();
        enabled[variable] = 1;
        if self.solve(enabled, depth + 1)? {
            return Ok(true);
        }
        assignments[variable] = -1;
        self.solve(assignments, depth + 1)
    }

    fn propagate(&mut self, assignments: &mut [i8]) -> Result<bool, TargetError> {
        loop {
            let mut changed = false;
            for clause in self.clauses {
                self.budget.take_work(1)?;
                let mut satisfied = false;
                let mut unassigned = None;
                let mut unassigned_count = 0_usize;
                for literal in clause {
                    self.budget.take_work(1)?;
                    let value = assignments[literal.unsigned_abs() as usize];
                    if value == 0 {
                        unassigned = Some(*literal);
                        unassigned_count += 1;
                    } else if (value > 0) == (*literal > 0) {
                        satisfied = true;
                        break;
                    }
                }
                if satisfied {
                    continue;
                }
                if unassigned_count == 0 {
                    return Ok(false);
                }
                if unassigned_count == 1 {
                    let literal = unassigned.expect("one unassigned literal was counted");
                    let index = literal.unsigned_abs() as usize;
                    let value = if literal > 0 { 1 } else { -1 };
                    if assignments[index] != 0 && assignments[index] != value {
                        return Ok(false);
                    }
                    if assignments[index] == 0 {
                        self.budget.take_work(1)?;
                        assignments[index] = value;
                        changed = true;
                    }
                }
            }
            if !changed {
                return Ok(true);
            }
        }
    }

    fn next_variable(&mut self, assignments: &[i8]) -> Result<Option<usize>, TargetError> {
        let mut best = None;
        let mut best_count = usize::MAX;
        for clause in self.clauses {
            self.budget.take_work(1)?;
            let mut satisfied = false;
            let mut first = None;
            let mut count = 0_usize;
            for literal in clause {
                self.budget.take_work(1)?;
                let index = literal.unsigned_abs() as usize;
                let value = assignments[index];
                if value != 0 && (value > 0) == (*literal > 0) {
                    satisfied = true;
                    break;
                }
                if value == 0 {
                    first.get_or_insert(index);
                    count += 1;
                }
            }
            if !satisfied && count != 0 && count < best_count {
                best = first;
                best_count = count;
            }
        }
        Ok(best)
    }
}

fn validate_predicate_fact(key: &str, value: Option<&str>) -> Result<(), TargetError> {
    if matches!(
        key,
        "all" | "any" | "not" | "cfg" | "environment" | "feature"
    ) {
        return Err(TargetError::InvalidPredicate(format!(
            "reserved predicate identifier `{key}` is invalid in this position"
        )));
    }
    if value.is_none() {
        if fact_schema(key).is_none() {
            return Err(TargetError::InvalidPredicate(format!(
                "unknown target fact key `{key}`"
            )));
        }
        return Ok(());
    }
    validate_fact(key, value).map_err(|error| TargetError::InvalidPredicate(error.to_string()))?;
    if matches!(key, "target_arch" | "target_os")
        && value
            .is_none_or(|value| !valid_target_projection_value(value, MAX_TARGET_FACT_VALUE_BYTES))
    {
        return Err(TargetError::InvalidPredicate(format!(
            "invalid target projection value for `{key}`"
        )));
    }
    Ok(())
}

struct PredicateParser<'a> {
    input: &'a [u8],
    cursor: usize,
    nodes: usize,
}

impl<'a> PredicateParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            cursor: 0,
            nodes: 0,
        }
    }

    fn parse(mut self) -> Result<Predicate, TargetError> {
        if self.input.len() > MAX_TARGET_PREDICATE_BYTES {
            return Err(self.error("predicate exceeds its byte limit"));
        }
        self.skip_space();
        let name = self.ident()?;
        if name != "cfg" {
            return Err(self.error("predicate must start with cfg"));
        }
        self.expect(b'(')?;
        let value = self.expression(0)?;
        self.expect(b')')?;
        self.skip_space();
        if self.cursor != self.input.len() {
            return Err(self.error("trailing predicate input"));
        }
        Ok(value)
    }

    fn expression(&mut self, depth: usize) -> Result<Predicate, TargetError> {
        if depth > MAX_TARGET_PREDICATE_DEPTH {
            return Err(self.error("predicate exceeds its nesting-depth limit"));
        }
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or_else(|| self.error("predicate node count overflowed"))?;
        if self.nodes > MAX_TARGET_PREDICATE_NODES {
            return Err(self.error("predicate exceeds its AST-node limit"));
        }
        self.skip_space();
        let name = self.ident()?;
        self.skip_space();
        if self.consume(b'=') {
            let value = self.quoted()?;
            return Ok(Predicate::Equals(name, value));
        }
        if !self.consume(b'(') {
            return Ok(Predicate::Present(name));
        }
        let mut values = Vec::new();
        loop {
            values.push(self.expression(depth + 1)?);
            self.skip_space();
            if self.consume(b')') {
                break;
            }
            self.expect(b',')?;
        }
        match name.as_str() {
            "all" if !values.is_empty() => Ok(Predicate::All(values)),
            "any" if !values.is_empty() => Ok(Predicate::Any(values)),
            "not" if values.len() == 1 => Ok(Predicate::Not(Box::new(values.pop().unwrap()))),
            _ => Err(self.error("unknown predicate function or invalid arity")),
        }
    }

    fn ident(&mut self) -> Result<String, TargetError> {
        self.skip_space();
        let start = self.cursor;
        while self
            .input
            .get(self.cursor)
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
        {
            self.cursor += 1;
        }
        if start == self.cursor {
            return Err(self.error("expected identifier"));
        }
        if self.cursor - start > MAX_TARGET_FACT_KEY_BYTES {
            return Err(self.error("predicate identifier exceeds its byte limit"));
        }
        Ok(String::from_utf8_lossy(&self.input[start..self.cursor]).into_owned())
    }

    fn quoted(&mut self) -> Result<String, TargetError> {
        self.skip_space();
        self.expect(b'"')?;
        let start = self.cursor;
        while let Some(byte) = self.input.get(self.cursor) {
            if *byte == b'"' {
                if self.cursor - start > MAX_TARGET_FACT_VALUE_BYTES {
                    return Err(self.error("predicate string exceeds its byte limit"));
                }
                let result = String::from_utf8_lossy(&self.input[start..self.cursor]).into_owned();
                self.cursor += 1;
                return Ok(result);
            }
            if *byte == b'\\' || !byte.is_ascii() || byte.is_ascii_control() {
                return Err(self.error("predicate strings must be unescaped printable ASCII"));
            }
            if self.cursor - start == MAX_TARGET_FACT_VALUE_BYTES {
                return Err(self.error("predicate string exceeds its byte limit"));
            }
            self.cursor += 1;
        }
        Err(self.error("unterminated predicate string"))
    }

    fn expect(&mut self, expected: u8) -> Result<(), TargetError> {
        self.skip_space();
        if self.consume(expected) {
            Ok(())
        } else {
            Err(self.error(&format!("expected `{}`", char::from(expected))))
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        self.skip_space();
        if self.input.get(self.cursor) == Some(&expected) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn skip_space(&mut self) {
        while self
            .input
            .get(self.cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.cursor += 1;
        }
    }

    fn error(&self, message: &str) -> TargetError {
        TargetError::InvalidPredicate(format!("{message} at byte {}", self.cursor))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use proptest::prelude::*;

    use super::*;

    fn linux_facts() -> BTreeMap<String, BTreeSet<Option<String>>> {
        let mut facts = canonical_builtin_facts(CoreTargetFacts::little_endian(
            "x86_64", "gnu", "linux", "64", "unwind",
        ))
        .unwrap();
        facts.insert(
            "target_family".into(),
            BTreeSet::from([Some("unix".into())]),
        );
        facts.insert("unix".into(), BTreeSet::from([None]));
        facts
    }

    fn linux() -> Target {
        Target::from_facts(
            "x86_64-unknown-linux-gnu",
            Environment::Desktop,
            linux_facts(),
        )
        .unwrap()
    }

    fn environment_predicate(mask: u8) -> String {
        let values = [(1, "browser"), (2, "desktop"), (4, "mobile"), (8, "server")]
            .into_iter()
            .filter_map(|(bit, value)| (mask & bit != 0).then_some(value))
            .collect::<Vec<_>>();
        match values.as_slice() {
            [] => "cfg(false)".into(),
            [value] => format!("cfg(environment = \"{value}\")"),
            _ if values.len() == 4 => "cfg(true)".into(),
            _ => format!(
                "cfg(any({}))",
                values
                    .iter()
                    .map(|value| format!("environment = \"{value}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    #[test]
    fn facts_are_sorted_and_digest_is_stable() {
        let first = linux();
        let second = linux();
        assert_eq!(first.target_fact_digest, second.target_fact_digest);
        assert_eq!(first.arch().as_str(), "x86_64");
        assert_eq!(first.os().as_str(), "linux");
        assert_eq!(first.fact_value("target_os"), Some("linux"));
        first.verify().unwrap();
    }

    #[test]
    fn typed_arch_and_os_are_bounded_open_projections() {
        let maximum_arch = "a".repeat(MAX_TARGET_ARCH_BYTES);
        let maximum_os = "o".repeat(MAX_TARGET_OS_BYTES);
        let mut facts = linux_facts();
        facts.insert(
            "target_arch".into(),
            BTreeSet::from([Some(maximum_arch.clone())]),
        );
        facts.insert(
            "target_os".into(),
            BTreeSet::from([Some(maximum_os.clone())]),
        );
        let target = Target::from_facts("custom-unknown-none", Environment::Server, facts).unwrap();
        assert_eq!(target.arch().as_str(), maximum_arch);
        assert_eq!(target.os().as_str(), maximum_os);

        assert!(Arch::new("custom-arch").is_ok());
        assert!(Os::new("custom-os").is_ok());
        for invalid in ["", "línux", "lin\"ux", "lin\\ux", "lin\nux"] {
            assert!(Arch::new(invalid).is_err());
            assert!(Os::new(invalid).is_err());
        }
        assert!(Arch::new("a".repeat(MAX_TARGET_ARCH_BYTES + 1)).is_err());
        assert!(Os::new("o".repeat(MAX_TARGET_OS_BYTES + 1)).is_err());
    }

    #[test]
    fn target_fact_digest_has_a_fixed_schema_v1_vector() {
        let target = linux();
        assert_eq!(
            target.target_fact_digest,
            "4b3acb0763188cd2ccf26c30349a851086a226c475a55fb8999aa7f23b7ba1ea"
        );
        assert_eq!(
            TargetFactsRecord::from_target(&target)
                .unwrap()
                .semantic_digest()
                .unwrap(),
            target.target_fact_digest
        );

        let mut invalid_projection = target.clone();
        invalid_projection.arch = Arch::new("aarch64").unwrap();
        assert_eq!(
            invalid_projection.target_fact_digest,
            target.target_fact_digest
        );
        assert!(matches!(
            invalid_projection.verify(),
            Err(TargetError::TargetProjectionMismatch {
                projection: "arch",
                fact: "target_arch"
            })
        ));
    }

    #[test]
    fn target_fact_identity_excludes_environment_and_binds_custom_spec() {
        let mut facts = canonical_builtin_facts(CoreTargetFacts::little_endian(
            "wasm32", "", "unknown", "32", "abort",
        ))
        .unwrap();
        facts.insert(
            "target_family".into(),
            BTreeSet::from([Some("wasm".into())]),
        );
        let browser = Target::from_facts(
            "wasm32-unknown-unknown",
            Environment::Browser,
            facts.clone(),
        )
        .unwrap();
        let server =
            Target::from_facts("wasm32-unknown-unknown", Environment::Server, facts.clone())
                .unwrap();
        assert_eq!(browser.target_fact_digest, server.target_fact_digest);

        let custom = Target::from_facts_with_custom_spec_digest(
            "wasm32-unknown-unknown",
            Environment::Browser,
            facts,
            Some("1".repeat(64)),
        )
        .unwrap();
        assert_ne!(browser.target_fact_digest, custom.target_fact_digest);
        custom.verify().unwrap();
    }

    #[test]
    fn deserialized_target_facts_must_be_reverified() {
        let mut target = linux();
        target.target_fact_digest = "0".repeat(64);
        assert!(matches!(
            target.verify(),
            Err(TargetError::TargetFactDigestMismatch)
        ));

        let facts = parse_facts("target_arch=\"x86_64\"\n").unwrap();
        assert!(matches!(
            Target::from_facts("../host", Environment::Server, facts.clone()),
            Err(TargetError::InvalidTriple(_))
        ));
        assert!(matches!(
            Target::from_facts_with_custom_spec_digest(
                "x86_64-unknown-linux-gnu",
                Environment::Server,
                facts,
                Some("not-a-digest".into()),
            ),
            Err(TargetError::InvalidCustomTargetSpecDigest(_))
        ));
    }

    #[test]
    fn target_and_target_record_deserialization_are_checked() {
        let target = linux();
        let json = serde_json::to_string(&target).unwrap();
        assert_eq!(Target::from_json(json.as_bytes()).unwrap(), target);
        let encoded = serde_json::to_value(&target).unwrap();
        assert_eq!(encoded["arch"], "x86_64");
        assert_eq!(encoded["os"], "linux");
        let stale = json.replace(&target.target_fact_digest, &"0".repeat(64));
        assert!(serde_json::from_str::<Target>(&stale).is_err());

        let mutated = json.replace("linux", "windows");
        assert!(serde_json::from_str::<Target>(&mutated).is_err());

        for (projection, mismatch) in [("arch", "aarch64"), ("os", "windows")] {
            let mut mismatched = encoded.clone();
            mismatched[projection] = serde_json::json!(mismatch);
            let error = serde_json::from_value::<Target>(mismatched)
                .unwrap_err()
                .to_string();
            assert!(error.contains("projection does not match"), "{error}");
        }

        let mut invalid_arch = encoded.clone();
        invalid_arch["arch"] = serde_json::json!("a".repeat(MAX_TARGET_ARCH_BYTES + 1));
        assert!(serde_json::from_value::<Target>(invalid_arch).is_err());
        let mut missing_os = encoded.clone();
        missing_os.as_object_mut().unwrap().remove("os");
        assert!(serde_json::from_value::<Target>(missing_os).is_err());

        let duplicate_key = format!(
            concat!(
                "{{\"triple\":\"x86_64-unknown-linux-gnu\",",
                "\"arch\":\"x86_64\",\"os\":\"linux\",",
                "\"environment\":\"desktop\",",
                "\"facts\":{{\"target_arch\":[\"x86_64\"],",
                "\"target_arch\":[\"x86_64\"]}},",
                "\"target-fact-digest\":\"{}\",",
                "\"custom-target-spec-digest\":null}}"
            ),
            target.target_fact_digest
        );
        let duplicate_key_error = serde_json::from_str::<Target>(&duplicate_key)
            .unwrap_err()
            .to_string();
        assert!(
            duplicate_key_error.contains("duplicate target fact key"),
            "{duplicate_key_error}"
        );

        let duplicate_value = format!(
            concat!(
                "{{\"triple\":\"x86_64-unknown-linux-gnu\",",
                "\"arch\":\"x86_64\",\"os\":\"linux\",",
                "\"environment\":\"desktop\",",
                "\"facts\":{{\"target_arch\":[\"x86_64\",\"x86_64\"]}},",
                "\"target-fact-digest\":\"{}\",",
                "\"custom-target-spec-digest\":null}}"
            ),
            target.target_fact_digest
        );
        let duplicate_value_error = serde_json::from_str::<Target>(&duplicate_value)
            .unwrap_err()
            .to_string();
        assert!(
            duplicate_value_error.contains("duplicate target fact value"),
            "{duplicate_value_error}"
        );

        let record = TargetFactsRecord::from_target(&target).unwrap();
        let record_json = serde_json::to_vec(&record).unwrap();
        assert_eq!(TargetFactsRecord::from_json(&record_json).unwrap(), record);
        let mut unsupported = serde_json::to_value(record).unwrap();
        unsupported["schema"] = serde_json::json!(2);
        assert!(serde_json::from_value::<TargetFactsRecord>(unsupported).is_err());

        let exact_limit = vec![b' '; MAX_CANONICAL_TARGET_FACTS_RECORD_BYTES];
        assert!(matches!(
            Target::from_json(&exact_limit),
            Err(TargetError::Json(_))
        ));
        let oversized = vec![b' '; MAX_CANONICAL_TARGET_FACTS_RECORD_BYTES + 1];
        assert!(matches!(
            Target::from_json(&oversized),
            Err(TargetError::TargetJsonTooLarge { .. })
        ));
    }

    #[test]
    fn core_scalars_are_complete_singletons_and_custom_values_are_open() {
        let mut missing = linux_facts();
        missing.remove("panic");
        assert!(matches!(
            Target::from_facts("x86_64-unknown-linux-gnu", Environment::Desktop, missing),
            Err(TargetError::InvalidFact(_))
        ));

        let mut multiple = linux_facts();
        multiple
            .get_mut("target_arch")
            .unwrap()
            .insert(Some("custom-arch".into()));
        assert!(matches!(
            Target::from_facts("x86_64-unknown-linux-gnu", Environment::Desktop, multiple),
            Err(TargetError::InvalidFact(_))
        ));

        let mut custom = linux_facts();
        for (key, value) in [
            ("target_abi", "custom-abi"),
            ("target_arch", "custom-arch"),
            ("target_env", "custom-env"),
            ("target_os", "custom-os"),
            ("target_vendor", "custom-vendor"),
        ] {
            custom.insert(key.into(), BTreeSet::from([Some(value.into())]));
        }
        custom.insert(
            "target_family".into(),
            BTreeSet::from([Some("custom-a".into()), Some("custom-b".into())]),
        );
        Target::from_facts("custom-vendor-os", Environment::Server, custom).unwrap();

        let mut invalid_closed = linux_facts();
        invalid_closed.insert("panic".into(), BTreeSet::from([Some("raise".into())]));
        assert!(matches!(
            Target::from_facts(
                "x86_64-unknown-linux-gnu",
                Environment::Desktop,
                invalid_closed
            ),
            Err(TargetError::InvalidFact(_))
        ));
    }

    #[test]
    fn closed_predicate_language_separates_environment() {
        let target = linux();
        assert!(
            target
                .matches("cfg(all(target_os = \"linux\", environment = \"desktop\"))")
                .unwrap()
        );
        assert!(
            !target
                .matches("cfg(any(target_os = \"windows\", environment = \"browser\"))")
                .unwrap()
        );
        assert!(
            target
                .matches("cfg(not(target_arch = \"wasm32\"))")
                .unwrap()
        );
        assert!(target.matches("cfg(unix)").unwrap());
        assert!(target.matches("target_os = \"linux\"").is_err());
        assert!(target.matches("cfg(unknown())").is_err());
        assert!(target.matches("cfg(unknown)").is_err());
        assert!(target.matches("cfg(feature = \"std\")").is_err());
        assert!(target.matches("cfg(environment)").is_err());
        assert!(target.matches("cfg(environment = \"cloud\")").is_err());
        assert!(!target.matches("cfg(target_os = \"plan9\")").unwrap());
        assert!(target.matches("cfg(target_endian = \"middle\")").is_err());
        assert!(target.matches("cfg(any(true, unknown))").is_err());
        assert!(target.matches("cfg(all(false, unknown))").is_err());
    }

    #[test]
    fn predicate_partition_proves_open_custom_fact_coverage_symbolically() {
        validate_predicate_partition(
            "cfg(true)",
            &[
                "cfg(target_os = \"linux\")",
                "cfg(not(target_os = \"linux\"))",
            ],
        )
        .unwrap();
        validate_predicate_partition(
            "cfg(any(target_arch = \"x86_64\", target_arch = \"aarch64\"))",
            &[
                "cfg(target_arch = \"x86_64\")",
                "cfg(target_arch = \"aarch64\")",
            ],
        )
        .unwrap();

        assert!(matches!(
            validate_predicate_partition(
                "cfg(true)",
                &["cfg(target_os = \"linux\")", "cfg(target_os = \"windows\")"]
            ),
            Err(TargetError::PredicatePartitionGap)
        ));
    }

    #[test]
    fn predicate_partition_models_required_and_multi_value_fact_presence() {
        validate_predicate_partition("cfg(true)", &["cfg(target_arch)"]).unwrap();
        validate_predicate_partition(
            "cfg(target_family)",
            &[
                "cfg(target_family = \"unix\")",
                "cfg(all(target_family, not(target_family = \"unix\")))",
            ],
        )
        .unwrap();

        let values = ["8", "16", "32", "64", "128", "ptr"];
        let entries = values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let mut terms = values[..index]
                    .iter()
                    .map(|previous| format!("not(target_has_atomic = \"{previous}\")"))
                    .collect::<Vec<_>>();
                terms.push(format!("target_has_atomic = \"{value}\""));
                format!("cfg(all({}))", terms.join(", "))
            })
            .collect::<Vec<_>>();
        let entries = entries.iter().map(String::as_str).collect::<Vec<_>>();
        validate_predicate_partition("cfg(target_has_atomic)", &entries).unwrap();

        let target = linux();
        assert!(target.matches("cfg(target_arch)").unwrap());
        assert!(target.matches("cfg(target_arch = \"\")").is_err());
        assert!(target.matches("cfg(target_os = \"\")").is_err());
    }

    #[test]
    fn predicate_partition_rejects_outside_overlap_empty_and_excess_entries() {
        assert!(matches!(
            validate_predicate_partition(
                "cfg(target_arch = \"wasm32\")",
                &["cfg(target_os = \"linux\")"]
            ),
            Err(TargetError::PredicatePartitionOutsideParent { index: 0 })
        ));
        assert!(matches!(
            validate_predicate_partition(
                "cfg(true)",
                &[
                    "cfg(target_arch = \"x86_64\")",
                    "cfg(any(target_arch = \"x86_64\", target_arch = \"aarch64\"))"
                ]
            ),
            Err(TargetError::PredicatePartitionOverlap {
                first: 0,
                second: 1
            })
        ));
        assert!(matches!(
            validate_predicate_partition("cfg(true)", &[]),
            Err(TargetError::InvalidPredicatePartitionCount { actual: 0, .. })
        ));
        assert!(matches!(
            validate_predicate_partition("cfg(true)", &["cfg(false)", "cfg(true)"]),
            Err(TargetError::PredicatePartitionUnsatisfiable { index: 0 })
        ));
        let predicates = vec!["cfg(false)"; MAX_TARGET_PREDICATE_PARTITIONS + 1];
        assert!(matches!(
            validate_predicate_partition("cfg(false)", &predicates),
            Err(TargetError::InvalidPredicatePartitionCount { actual, .. })
                if actual == MAX_TARGET_PREDICATE_PARTITIONS + 1
        ));
    }

    #[test]
    fn predicate_partition_analysis_is_deterministic() {
        let predicates = [
            "cfg(environment = \"browser\")",
            "cfg(environment = \"desktop\")",
            "cfg(environment = \"mobile\")",
            "cfg(environment = \"server\")",
        ];
        for _ in 0..8 {
            validate_predicate_partition("cfg(true)", &predicates).unwrap();
        }
    }

    #[test]
    fn open_single_cardinality_encoding_is_linear() {
        let mut budget = PredicateAnalysisBudget::new();
        let value_count = MAX_TARGET_FACT_VALUES_PER_KEY;
        let (auxiliary_variables, clauses, literals) = {
            let mut builder = PredicateSatBuilder::new(&mut budget);
            let variables = (0..value_count)
                .map(|_| builder.new_variable().unwrap())
                .collect::<Vec<_>>();
            let variables_before = builder.variables;
            builder.add_at_most_one(&variables).unwrap();
            (
                builder.variables - variables_before,
                builder.clauses.len(),
                builder.clauses.iter().map(Vec::len).sum::<usize>(),
            )
        };
        assert_eq!(auxiliary_variables, i32::try_from(value_count - 1).unwrap());
        assert_eq!(clauses, 3 * value_count - 4);
        assert_eq!(literals, 2 * clauses);
    }

    #[test]
    fn predicate_analysis_resource_limits_fail_closed_deterministically() {
        let predicate = parse_validated_predicate(
            "cfg(any(target_feature = \"a\", not(target_feature = \"a\")))",
        )
        .unwrap();
        let generous = PredicateAnalysisLimits {
            variables: 10_000,
            clauses: 10_000,
            literals: 50_000,
            decisions: 10_000,
            work: 1_000_000,
        };
        for (limits, resource) in [
            (
                PredicateAnalysisLimits {
                    variables: 0,
                    ..generous
                },
                "CNF variables",
            ),
            (
                PredicateAnalysisLimits {
                    clauses: 0,
                    ..generous
                },
                "CNF clauses",
            ),
            (
                PredicateAnalysisLimits {
                    literals: 0,
                    ..generous
                },
                "CNF literals",
            ),
            (
                PredicateAnalysisLimits {
                    work: 0,
                    ..generous
                },
                "analysis work",
            ),
            (
                PredicateAnalysisLimits {
                    decisions: 0,
                    ..generous
                },
                "DPLL decisions",
            ),
        ] {
            let mut budget = PredicateAnalysisBudget::with_limits(limits);
            assert!(matches!(
                predicate_is_satisfiable(&predicate, &mut budget),
                Err(TargetError::PredicateAnalysisLimitExceeded {
                    resource: actual,
                    maximum: 0,
                }) if actual == resource
            ));
        }
    }

    #[test]
    fn sixty_four_way_selector_analysis_completes_and_adversarial_gap_is_budgeted() {
        let selector = |index| format!("target_arch = \"selector_{index}\"");
        let parent = format!(
            "cfg(any({}))",
            (0..MAX_TARGET_PREDICATE_PARTITIONS)
                .map(&selector)
                .collect::<Vec<_>>()
                .join(", ")
        );
        let predicates = (0..MAX_TARGET_PREDICATE_PARTITIONS)
            .map(|index| format!("cfg({})", selector(index)))
            .collect::<Vec<_>>();
        let predicate_refs = predicates.iter().map(String::as_str).collect::<Vec<_>>();
        validate_predicate_partition(&parent, &predicate_refs).unwrap();

        let compact_value = |mut value: usize| {
            const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
            let mut encoded = [b'0'; 3];
            for byte in encoded.iter_mut().rev() {
                *byte = DIGITS[value % DIGITS.len()];
                value /= DIGITS.len();
            }
            String::from_utf8(encoded.to_vec()).unwrap()
        };
        let adversarial = (0..MAX_TARGET_PREDICATE_PARTITIONS)
            .map(|index| {
                let dead_branches = (0..240)
                    .map(|branch| {
                        let value = compact_value(index * 240 + branch);
                        format!("target_os=\"{value}\"")
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                format!("cfg(all({},any(true,{dead_branches})))", selector(index))
            })
            .collect::<Vec<_>>();
        assert!(
            adversarial
                .iter()
                .all(|predicate| predicate.len() <= MAX_TARGET_PREDICATE_BYTES)
        );
        let parsed_parent = parse_validated_predicate(&parent).unwrap();
        let parsed_partitions = adversarial
            .iter()
            .map(|predicate| parse_validated_predicate(predicate))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let gap = Predicate::All(vec![
            parsed_parent,
            Predicate::Not(Box::new(Predicate::Any(parsed_partitions))),
        ]);
        let encoded_gap_variables = {
            let mut budget = PredicateAnalysisBudget::new();
            let mut builder = PredicateSatBuilder::new(&mut budget);
            builder.encode(&gap).unwrap();
            builder.variables
        };
        assert!(encoded_gap_variables > 1_024, "{encoded_gap_variables}");
        let mut variable_budget = PredicateAnalysisBudget::with_limits(PredicateAnalysisLimits {
            variables: 1_024,
            clauses: MAX_TARGET_PREDICATE_ANALYSIS_CLAUSES,
            literals: MAX_TARGET_PREDICATE_ANALYSIS_LITERALS,
            decisions: MAX_TARGET_PREDICATE_ANALYSIS_DECISIONS,
            work: MAX_TARGET_PREDICATE_ANALYSIS_WORK,
        });
        let gap_result = predicate_is_satisfiable(&gap, &mut variable_budget);
        assert!(
            matches!(
                gap_result,
                Err(TargetError::PredicateAnalysisLimitExceeded {
                    resource: "CNF variables",
                    maximum: 1_024,
                })
            ),
            "unexpected adversarial gap result: {gap_result:?}"
        );

        let adversarial_refs = adversarial.iter().map(String::as_str).collect::<Vec<_>>();
        let input_bytes = parent.len() + adversarial.iter().map(String::len).sum::<usize>();
        let work_limit = input_bytes + 20_000;
        for _ in 0..2 {
            let mut budget = PredicateAnalysisBudget::with_work_limit_for_test(work_limit);
            assert!(matches!(
                validate_predicate_partition_with_budget(
                    &parent,
                    &adversarial_refs,
                    &mut budget
                ),
                Err(TargetError::PredicateAnalysisLimitExceeded {
                    resource: "analysis work",
                    maximum,
                }) if maximum == work_limit
            ));
        }
    }

    #[test]
    fn multi_value_atom_universe_rejects_more_than_a_concrete_target_can_hold() {
        let values = (0..=MAX_TARGET_FACT_VALUES_PER_KEY)
            .map(|index| format!("value_{index}"))
            .collect::<Vec<_>>();
        let predicates_for = |values: &[String]| {
            values
                .chunks(17)
                .map(|chunk| {
                    format!(
                        "cfg(any({}))",
                        chunk
                            .iter()
                            .map(|value| format!("target_feature = \"{value}\""))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })
                .collect::<Vec<_>>()
        };
        let exact = predicates_for(&values[..MAX_TARGET_FACT_VALUES_PER_KEY]);
        let exact = exact
            .iter()
            .map(|predicate| parse_validated_predicate(predicate))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut budget = PredicateAnalysisBudget::new();
        validate_predicate_model_universe(
            &parse_validated_predicate("cfg(true)").unwrap(),
            &exact,
            &mut budget,
        )
        .unwrap();

        let predicates = predicates_for(&values);
        let predicates = predicates.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(predicates.len() <= MAX_TARGET_PREDICATE_PARTITIONS);
        assert!(matches!(
            validate_predicate_partition("cfg(true)", &predicates),
            Err(TargetError::PredicateAnalysisLimitExceeded {
                resource: "values per multi-valued fact",
                maximum: MAX_TARGET_FACT_VALUES_PER_KEY,
            })
        ));
    }

    #[test]
    fn predicate_atom_universe_rejects_unrealizable_canonical_record_size() {
        let values = (0..=MAX_TARGET_PREDICATE_PARTITIONS)
            .map(|index| format!("{index:04}{}", "x".repeat(4_056)))
            .collect::<Vec<_>>();
        let predicates = values[1..]
            .iter()
            .map(|value| format!("cfg(target_feature = \"{value}\")"))
            .collect::<Vec<_>>();
        let parent = format!("cfg(target_feature = \"{}\")", values[0]);
        assert!(parent.len() <= MAX_TARGET_PREDICATE_BYTES);
        assert!(
            predicates
                .iter()
                .all(|predicate| predicate.len() <= MAX_TARGET_PREDICATE_BYTES)
        );
        let predicates = predicates.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(matches!(
            validate_predicate_partition(&parent, &predicates),
            Err(TargetError::PredicateAnalysisLimitExceeded {
                resource: "canonical target-facts bytes",
                maximum: MAX_CANONICAL_TARGET_FACTS_RECORD_BYTES,
            })
        ));
    }

    proptest! {
        #[test]
        fn predicate_partition_matches_small_environment_bruteforce_oracle(
            parent_mask in 0_u8..16,
            partition_masks in prop::collection::vec(0_u8..16, 1..=4),
        ) {
            let parent = environment_predicate(parent_mask);
            let partitions = partition_masks
                .iter()
                .map(|mask| environment_predicate(*mask))
                .collect::<Vec<_>>();
            let environments = [
                Environment::Browser,
                Environment::Desktop,
                Environment::Mobile,
                Environment::Server,
            ];
            let targets = environments
                .into_iter()
                .map(|environment| {
                    Target::from_facts(
                        "x86_64-unknown-linux-gnu",
                        environment,
                        linux_facts(),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            let every_entry_is_live = partitions.iter().all(|partition| {
                targets.iter().any(|target| {
                    target.matches(&parent).unwrap() && target.matches(partition).unwrap()
                })
            });
            let exact_on_every_target = targets.iter().all(|target| {
                let parent_matches = target.matches(&parent).unwrap();
                let matches = partitions
                    .iter()
                    .filter(|partition| target.matches(partition).unwrap())
                    .count();
                matches == usize::from(parent_matches)
            });
            let predicates = partitions.iter().map(String::as_str).collect::<Vec<_>>();
            prop_assert_eq!(
                validate_predicate_partition(&parent, &predicates).is_ok(),
                every_entry_is_live && exact_on_every_target,
            );
        }
    }

    #[test]
    fn predicate_byte_node_and_depth_boundaries_are_closed() {
        let target = linux();
        let mut exact_bytes = String::from("cfg(true)");
        exact_bytes.push_str(&" ".repeat(MAX_TARGET_PREDICATE_BYTES - exact_bytes.len()));
        assert!(target.matches(&exact_bytes).unwrap());
        exact_bytes.push(' ');
        assert!(target.matches(&exact_bytes).is_err());

        let exact_nodes = format!(
            "cfg(any({}))",
            std::iter::repeat_n("true", MAX_TARGET_PREDICATE_NODES - 1)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(target.matches(&exact_nodes).unwrap());
        let too_many_nodes = format!(
            "cfg(any({}))",
            std::iter::repeat_n("true", MAX_TARGET_PREDICATE_NODES)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(target.matches(&too_many_nodes).is_err());

        let exact_depth = format!(
            "cfg({}true{})",
            "not(".repeat(MAX_TARGET_PREDICATE_DEPTH),
            ")".repeat(MAX_TARGET_PREDICATE_DEPTH)
        );
        assert!(target.matches(&exact_depth).is_ok());
        let too_deep = format!(
            "cfg({}true{})",
            "not(".repeat(MAX_TARGET_PREDICATE_DEPTH + 1),
            ")".repeat(MAX_TARGET_PREDICATE_DEPTH + 1)
        );
        assert!(target.matches(&too_deep).is_err());
    }

    #[test]
    fn malformed_facts_fail_closed() {
        assert!(parse_facts("Target=\"linux\"").is_err());
        assert!(parse_facts("target_os=linux").is_err());
        assert!(parse_facts("environment=\"server\"").is_err());
        assert!(parse_facts("feature=\"std\"").is_err());
        assert!(parse_facts("target_os=\"linux\\gnu\"").is_err());
        assert!(parse_facts("target_os=\"lin\"ux\"").is_err());
        assert!(parse_facts("target_os=\"línux\"").is_err());
        assert!(parse_facts("target_os=\"linux\"\ntarget_os=\"linux\"").is_err());
        assert!(parse_facts("target_os=\"linux\"\n\ntarget_arch=\"x86_64\"").is_err());
    }

    #[test]
    fn target_fact_value_and_count_boundaries_are_closed() {
        let maximum_value = "x".repeat(MAX_TARGET_FACT_VALUE_BYTES);
        let mut facts = linux_facts();
        facts.insert(
            "target_feature".into(),
            BTreeSet::from([Some(maximum_value)]),
        );
        TargetFactsRecord::new("x86_64-unknown-linux-gnu", facts, None).unwrap();

        let oversized_value = "x".repeat(MAX_TARGET_FACT_VALUE_BYTES + 1);
        let mut facts = linux_facts();
        facts.insert(
            "target_feature".into(),
            BTreeSet::from([Some(oversized_value)]),
        );
        assert!(matches!(
            TargetFactsRecord::new("x86_64-unknown-linux-gnu", facts, None,),
            Err(TargetError::InvalidFact(_))
        ));

        let maximum_values = (0..MAX_TARGET_FACT_VALUES_PER_KEY)
            .map(|index| Some(format!("feature-{index}")))
            .collect::<BTreeSet<_>>();
        let mut facts = linux_facts();
        facts.insert("target_feature".into(), maximum_values);
        TargetFactsRecord::new("x86_64-unknown-linux-gnu", facts, None).unwrap();

        let oversized_values = (0..=MAX_TARGET_FACT_VALUES_PER_KEY)
            .map(|index| Some(format!("feature-{index}")))
            .collect::<BTreeSet<_>>();
        let mut facts = linux_facts();
        facts.insert("target_feature".into(), oversized_values);
        assert!(matches!(
            TargetFactsRecord::new("x86_64-unknown-linux-gnu", facts, None,),
            Err(TargetError::InvalidFact(_))
        ));

        let record_too_large = (0..MAX_TARGET_FACT_VALUES_PER_KEY)
            .map(|index| Some(format!("feature-{index}-{}", "x".repeat(256))))
            .collect::<BTreeSet<_>>();
        let mut facts = linux_facts();
        facts.insert("target_feature".into(), record_too_large);
        assert!(matches!(
            TargetFactsRecord::new("x86_64-unknown-linux-gnu", facts, None,),
            Err(TargetError::TargetFactsRecordTooLarge { .. })
        ));
    }

    #[test]
    fn bounded_stream_keeps_only_the_configured_prefix() {
        assert_eq!(
            read_bounded_stream(Cursor::new(b"1234"), "stdout", 4).unwrap(),
            b"1234"
        );
        assert!(matches!(
            read_bounded_stream(Cursor::new(b"12345"), "stdout", 4),
            Err(TargetError::RustcOutputTooLarge {
                stream: "stdout",
                maximum: 4
            })
        ));
    }

    #[cfg(unix)]
    mod unix_query {
        use std::{
            fs,
            os::unix::fs::PermissionsExt as _,
            path::{Path, PathBuf},
        };

        use tempfile::TempDir;

        use super::*;

        fn quote_shell(value: &Path) -> String {
            let value = value.display().to_string();
            assert!(!value.contains('\''));
            format!("'{value}'")
        }

        fn fake_rustc(script_body: &str) -> (TempDir, PathBuf) {
            let directory = tempfile::tempdir().unwrap();
            let rustc = directory.path().join("rustc");
            fs::write(&rustc, format!("#!/bin/sh\n{script_body}\n")).unwrap();
            fs::set_permissions(&rustc, fs::Permissions::from_mode(0o755)).unwrap();
            (directory, rustc)
        }

        fn pipe_holding_descendant_script(pid_file: &Path, parent_body: &str) -> String {
            format!(
                concat!(
                    "(while :; do :; done) &\n",
                    "printf '%s\\n' \"$!\" > {}\n",
                    "{}"
                ),
                quote_shell(pid_file),
                parent_body,
            )
        }

        #[cfg(target_os = "linux")]
        fn assert_descendant_was_stopped(pid_file: &Path) {
            let pid = fs::read_to_string(pid_file).unwrap();
            let pid = pid.trim();
            assert!(pid.bytes().all(|byte| byte.is_ascii_digit()));
            let stat = Path::new("/proc").join(pid).join("stat");
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                match fs::read_to_string(&stat) {
                    Ok(contents) => {
                        let state = contents
                            .rsplit_once(") ")
                            .and_then(|(_, suffix)| suffix.chars().next())
                            .expect("Linux process stat must contain a state");
                        if matches!(state, 'X' | 'Z') {
                            return;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return,
                    Err(error) => panic!("failed to inspect descendant state: {error}"),
                }
                assert!(
                    Instant::now() < deadline,
                    "pipe-holding descendant {pid} remained runnable after query timeout"
                );
                thread::sleep(RUSTC_QUERY_POLL_INTERVAL);
            }
        }

        #[cfg(not(target_os = "linux"))]
        fn assert_descendant_was_stopped(_pid_file: &Path) {}

        #[test]
        fn invalid_target_inputs_fail_before_spawning_rustc() {
            let directory = tempfile::tempdir().unwrap();
            let marker = directory.path().join("spawned");
            let (_rustc_dir, rustc) = fake_rustc(&format!(": > {}", quote_shell(&marker)));
            let bytes = br#"{"arch":"x86_64"}"#;
            let record =
                CustomTargetSpecRecord::from_raw_bytes("custom-unknown-none", bytes).unwrap();

            assert!(matches!(
                Target::query(&rustc, "../host", Environment::Server),
                Err(TargetError::InvalidTriple(_))
            ));
            assert!(!marker.exists());
            assert!(matches!(
                Target::query_with_custom_spec(
                    &rustc,
                    Environment::Server,
                    &record,
                    Path::new("relative-target.json"),
                ),
                Err(TargetError::CustomTargetSpec(
                    CustomTargetSpecError::SnapshotPathNotAbsolute(_)
                ))
            ));
            assert!(!marker.exists());

            let missing = directory.path().join("missing-target.json");
            assert!(matches!(
                Target::query_with_custom_spec(
                    &rustc,
                    Environment::Server,
                    &record,
                    &missing,
                ),
                Err(TargetError::CustomTargetSpec(CustomTargetSpecError::SnapshotIo(error)))
                    if error.kind() == io::ErrorKind::NotFound
            ));
            assert!(!marker.exists());

            let snapshot = directory.path().join("target.json");
            fs::write(&snapshot, bytes).unwrap();
            let wrong_record = CustomTargetSpecRecord::from_raw_bytes(
                "custom-unknown-none",
                br#"{"arch":"aarch64"}"#,
            )
            .unwrap();
            assert!(matches!(
                Target::query_with_custom_spec(
                    &rustc,
                    Environment::Server,
                    &wrong_record,
                    &snapshot,
                ),
                Err(TargetError::CustomTargetSpec(
                    CustomTargetSpecError::IdentityMismatch(_)
                ))
            ));
            assert!(!marker.exists());
        }

        #[test]
        fn query_uses_strict_utf8_and_custom_snapshot_argument() {
            let directory = tempfile::tempdir().unwrap();
            let marker = directory.path().join("argument");
            let (_rustc_dir, rustc) = fake_rustc(&format!(
                concat!(
                    "IFS= read -r observed < \"$4\"\n",
                    "[ \"$observed\" = '{{\"arch\":\"x86_64\"}}' ] || exit 41\n",
                    "printf '%s' \"$4\" > {}\n",
                    "printf 'debug_assertions\\npanic=\"unwind\"\\n",
                    "target_abi=\"\"\\ntarget_arch=\"x86_64\"\\n",
                    "target_endian=\"little\"\\ntarget_env=\"gnu\"\\n",
                    "target_os=\"linux\"\\ntarget_pointer_width=\"64\"\\n",
                    "target_vendor=\"unknown\"\\n'"
                ),
                quote_shell(&marker)
            ));
            let snapshot = directory.path().join("target.json");
            let bytes = br#"{"arch":"x86_64"}"#;
            fs::write(&snapshot, bytes).unwrap();
            let record =
                CustomTargetSpecRecord::from_raw_bytes("custom-unknown-none", bytes).unwrap();
            let target =
                Target::query_with_custom_spec(&rustc, Environment::Server, &record, &snapshot)
                    .unwrap();
            assert_eq!(target.triple, "custom-unknown-none");
            assert_eq!(
                target.custom_target_spec_digest,
                Some(record.custom_target_spec_digest)
            );
            assert_eq!(
                fs::read_to_string(marker).unwrap(),
                snapshot.display().to_string()
            );

            let (_rustc_dir, rustc) = fake_rustc("printf '\\377'");
            assert!(matches!(
                Target::query(&rustc, "x86_64-unknown-linux-gnu", Environment::Server),
                Err(TargetError::InvalidRustcOutputEncoding { stream: "stdout" })
            ));
        }

        #[test]
        fn custom_snapshot_drift_is_prioritized_over_rustc_failure() {
            let directory = tempfile::tempdir().unwrap();
            let marker = directory.path().join("spawned");
            let (_rustc_dir, rustc) = fake_rustc(&format!(
                concat!(
                    ": > {}\n",
                    "printf '{{\"arch\":\"aarch64\"}}' > \"$4\"\n",
                    "printf 'synthetic rustc failure' >&2\n",
                    "exit 17"
                ),
                quote_shell(&marker),
            ));
            let snapshot = directory.path().join("target.json");
            let bytes = br#"{"arch":"x86_64"}"#;
            fs::write(&snapshot, bytes).unwrap();
            let record =
                CustomTargetSpecRecord::from_raw_bytes("custom-unknown-none", bytes).unwrap();

            let result =
                Target::query_with_custom_spec(&rustc, Environment::Server, &record, &snapshot);
            assert!(marker.exists());
            assert!(matches!(
                result,
                Err(TargetError::CustomTargetSpec(
                    CustomTargetSpecError::SnapshotChanged(_)
                        | CustomTargetSpecError::IdentityMismatch(_)
                ))
            ));
        }

        #[test]
        fn query_deadline_kills_and_joins_the_child() {
            let (_rustc_dir, rustc) = fake_rustc("while :; do :; done");
            let timeout = Duration::from_millis(100);
            let result = query_rustc_facts_with_timeout(
                &rustc,
                Path::new("x86_64-unknown-linux-gnu"),
                timeout,
            );
            assert!(
                matches!(
                    &result,
                    Err(TargetError::RustcTimedOut { milliseconds: 100 })
                ),
                "unexpected query result: {result:?}"
            );
        }

        #[test]
        fn query_deadline_kills_descendants_that_inherit_output_pipes() {
            let (_rustc_dir, rustc) = fake_rustc("(while :; do :; done) &\nwhile :; do :; done");
            let timeout = Duration::from_millis(100);
            let started = Instant::now();
            let result = query_rustc_facts_with_timeout(
                &rustc,
                Path::new("x86_64-unknown-linux-gnu"),
                timeout,
            );
            assert!(
                matches!(
                    &result,
                    Err(TargetError::RustcTimedOut { milliseconds: 100 })
                ),
                "unexpected query result: {result:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "query timeout waited on inherited output pipes"
            );
        }

        #[test]
        fn query_deadline_bounds_failed_parent_with_pipe_holding_descendant() {
            let directory = tempfile::tempdir().unwrap();
            let descendant_pid = directory.path().join("descendant.pid");
            let script = pipe_holding_descendant_script(
                &descendant_pid,
                "printf 'synthetic rustc failure' >&2\nexit 17",
            );
            let (_rustc_dir, rustc) = fake_rustc(&script);
            let timeout = Duration::from_millis(100);
            let started = Instant::now();
            let result = query_rustc_facts_with_timeout(
                &rustc,
                Path::new("x86_64-unknown-linux-gnu"),
                timeout,
            );

            assert!(
                matches!(
                    &result,
                    Err(TargetError::RustcTimedOut { milliseconds: 100 })
                ),
                "unexpected query result: {result:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "failed rustc parent left output readers blocked"
            );
            assert_descendant_was_stopped(&descendant_pid);
        }

        #[test]
        fn query_deadline_bounds_successful_parent_with_pipe_holding_descendant() {
            let directory = tempfile::tempdir().unwrap();
            let descendant_pid = directory.path().join("descendant.pid");
            let script = pipe_holding_descendant_script(
                &descendant_pid,
                concat!(
                    "printf 'debug_assertions\\npanic=\"unwind\"\\n",
                    "target_abi=\"\"\\ntarget_arch=\"x86_64\"\\n",
                    "target_endian=\"little\"\\ntarget_env=\"gnu\"\\n",
                    "target_os=\"linux\"\\ntarget_pointer_width=\"64\"\\n",
                    "target_vendor=\"unknown\"\\n'\n",
                    "exit 0"
                ),
            );
            let (_rustc_dir, rustc) = fake_rustc(&script);
            let timeout = Duration::from_millis(100);
            let started = Instant::now();
            let result = query_rustc_facts_with_timeout(
                &rustc,
                Path::new("x86_64-unknown-linux-gnu"),
                timeout,
            );

            assert!(
                matches!(
                    &result,
                    Err(TargetError::RustcTimedOut { milliseconds: 100 })
                ),
                "unexpected query result: {result:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "successful rustc parent left output readers blocked"
            );
            assert_descendant_was_stopped(&descendant_pid);
        }
    }
}
