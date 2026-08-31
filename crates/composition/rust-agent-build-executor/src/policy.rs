use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use rust_agent_composition::{canonical, metadata::BuildRequirements};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildExecutionPolicy {
    pub schema: u32,
    pub executables: Vec<BuildExecutable>,
    #[serde(rename = "read-inputs")]
    pub read_inputs: Vec<BuildReadInput>,
    pub environment: Vec<BuildEnvironment>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildExecutable {
    pub id: String,
    pub path: PathBuf,
    pub digest: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildReadInput {
    pub id: String,
    pub path: PathBuf,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildEnvironment {
    pub id: String,
    pub variable: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedBuildPolicy {
    policy: BuildExecutionPolicy,
    executable_ids: BTreeSet<String>,
    read_input_ids: BTreeSet<String>,
    environment_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBuildExecutable {
    path: PathBuf,
    digest: String,
    version: String,
}

impl VerifiedBuildExecutable {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn version(&self) -> &str {
        &self.version
    }
}

#[derive(Debug, Error)]
pub enum BuildPolicyError {
    #[error("unsupported build policy schema {0}; expected 1")]
    UnsupportedSchema(u32),
    #[error("invalid {kind} logical id `{id}`")]
    InvalidId { kind: &'static str, id: String },
    #[error("duplicate build requirement `{id}` in kind {kind}")]
    Duplicate { kind: &'static str, id: String },
    #[error("logical id `{0}` is declared in more than one build-requirement kind")]
    CrossKindDuplicate(String),
    #[error("build policy path must be absolute: {0}")]
    NonAbsolutePath(String),
    #[error("invalid canonical SHA-256 digest for `{0}`")]
    InvalidDigest(String),
    #[error("environment mapping `{id}` uses forbidden variable `{variable}`")]
    ForbiddenEnvironment { id: String, variable: String },
    #[error("missing {kind} build requirement mapping `{id}`")]
    MissingMapping { kind: &'static str, id: String },
    #[error("build requirement `{id}` is mapped as {actual}, not {expected}")]
    KindMismatch {
        id: String,
        expected: &'static str,
        actual: &'static str,
    },
    #[error("build policy canonical encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
    #[error("executable `{id}` cannot be resolved to a canonical regular file: {path}")]
    InvalidExecutablePath { id: String, path: String },
    #[error("executable `{id}` bytes do not match policy digest")]
    ExecutableDigestMismatch { id: String },
    #[error("executable `{id}` version probe failed: {message}")]
    ExecutableVersionProbe { id: String, message: String },
    #[error("executable `{id}` protocol version mismatch: expected `{expected}`, got `{actual}`")]
    ExecutableVersionMismatch {
        id: String,
        expected: String,
        actual: String,
    },
}

impl BuildExecutionPolicy {
    pub fn empty_development() -> Self {
        Self {
            schema: 1,
            executables: Vec::new(),
            read_inputs: Vec::new(),
            environment: Vec::new(),
        }
    }

    pub fn from_toml(input: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(input)
    }

    pub fn normalize(&self) -> Result<NormalizedBuildPolicy, BuildPolicyError> {
        if self.schema != 1 {
            return Err(BuildPolicyError::UnsupportedSchema(self.schema));
        }
        let mut executable_ids = BTreeSet::new();
        let mut read_input_ids = BTreeSet::new();
        let mut environment_ids = BTreeSet::new();
        for executable in &self.executables {
            validate_id("executable", &executable.id)?;
            validate_path(&executable.path)?;
            validate_digest(&executable.id, &executable.digest)?;
            if executable.version.is_empty() || executable.version.len() > 128 {
                return Err(BuildPolicyError::InvalidId {
                    kind: "executable version",
                    id: executable.version.clone(),
                });
            }
            if !executable_ids.insert(executable.id.clone()) {
                return Err(BuildPolicyError::Duplicate {
                    kind: "executable",
                    id: executable.id.clone(),
                });
            }
        }
        for input in &self.read_inputs {
            validate_id("read-input", &input.id)?;
            validate_path(&input.path)?;
            validate_digest(&input.id, &input.digest)?;
            if !read_input_ids.insert(input.id.clone()) {
                return Err(BuildPolicyError::Duplicate {
                    kind: "read-input",
                    id: input.id.clone(),
                });
            }
        }
        for environment in &self.environment {
            validate_id("environment", &environment.id)?;
            if !valid_environment_name(&environment.variable)
                || forbidden_environment(&environment.variable)
            {
                return Err(BuildPolicyError::ForbiddenEnvironment {
                    id: environment.id.clone(),
                    variable: environment.variable.clone(),
                });
            }
            if !environment_ids.insert(environment.id.clone()) {
                return Err(BuildPolicyError::Duplicate {
                    kind: "environment",
                    id: environment.id.clone(),
                });
            }
        }
        let mut kinds = BTreeMap::new();
        for (kind, values) in [
            ("executable", &executable_ids),
            ("read-input", &read_input_ids),
            ("environment", &environment_ids),
        ] {
            for id in values {
                if kinds.insert(id, kind).is_some() {
                    return Err(BuildPolicyError::CrossKindDuplicate(id.clone()));
                }
            }
        }
        let mut policy = self.clone();
        policy
            .executables
            .sort_by(|left, right| left.id.cmp(&right.id));
        policy
            .read_inputs
            .sort_by(|left, right| left.id.cmp(&right.id));
        policy
            .environment
            .sort_by(|left, right| left.id.cmp(&right.id));
        Ok(NormalizedBuildPolicy {
            policy,
            executable_ids,
            read_input_ids,
            environment_ids,
        })
    }
}

impl NormalizedBuildPolicy {
    pub fn authorize(&self, requirements: &BuildRequirements) -> Result<(), BuildPolicyError> {
        for id in &requirements.executables {
            self.require_kind(id, "executable", &self.executable_ids)?;
        }
        for id in &requirements.read_inputs {
            self.require_kind(id, "read-input", &self.read_input_ids)?;
        }
        for id in &requirements.environment {
            self.require_kind(id, "environment", &self.environment_ids)?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, BuildPolicyError> {
        #[derive(Serialize)]
        struct SemanticProjection<'a> {
            schema: u32,
            executables: Vec<(&'a str, &'a str, &'a str)>,
            read_inputs: Vec<(&'a str, &'a str)>,
            environment: Vec<(&'a str, &'a str, &'a str)>,
        }
        let projection = SemanticProjection {
            schema: self.policy.schema,
            executables: self
                .policy
                .executables
                .iter()
                .map(|item| {
                    (
                        item.id.as_str(),
                        item.digest.as_str(),
                        item.version.as_str(),
                    )
                })
                .collect(),
            read_inputs: self
                .policy
                .read_inputs
                .iter()
                .map(|item| (item.id.as_str(), item.digest.as_str()))
                .collect(),
            environment: self
                .policy
                .environment
                .iter()
                .map(|item| {
                    (
                        item.id.as_str(),
                        item.variable.as_str(),
                        item.value.as_str(),
                    )
                })
                .collect(),
        };
        Ok(hex::encode(canonical::domain_hash(
            b"rust-agent-build-policy-v1\0",
            &projection,
        )?))
    }

    pub fn verify_executable(
        &self,
        id: &str,
        expected_version: &str,
    ) -> Result<VerifiedBuildExecutable, BuildPolicyError> {
        self.require_kind(id, "executable", &self.executable_ids)?;
        let executable = self
            .policy
            .executables
            .iter()
            .find(|item| item.id == id)
            .expect("authorized executable id has a policy entry");
        let canonical = executable.path.canonicalize().map_err(|_| {
            BuildPolicyError::InvalidExecutablePath {
                id: id.to_owned(),
                path: executable.path.display().to_string(),
            }
        })?;
        if canonical != executable.path
            || !fs::metadata(&canonical).is_ok_and(|metadata| metadata.is_file())
        {
            return Err(BuildPolicyError::InvalidExecutablePath {
                id: id.to_owned(),
                path: executable.path.display().to_string(),
            });
        }
        let bytes = fs::read(&canonical).map_err(|_| BuildPolicyError::InvalidExecutablePath {
            id: id.to_owned(),
            path: executable.path.display().to_string(),
        })?;
        if hex::encode(Sha256::digest(bytes)) != executable.digest {
            return Err(BuildPolicyError::ExecutableDigestMismatch { id: id.to_owned() });
        }
        if executable.version != expected_version {
            return Err(BuildPolicyError::ExecutableVersionMismatch {
                id: id.to_owned(),
                expected: expected_version.to_owned(),
                actual: executable.version.clone(),
            });
        }
        let output = Command::new(&canonical)
            .arg("--version")
            .env_clear()
            .env("PATH", canonical.parent().unwrap_or_else(|| Path::new("/")))
            .output()
            .map_err(|error| BuildPolicyError::ExecutableVersionProbe {
                id: id.to_owned(),
                message: error.to_string(),
            })?;
        if !output.status.success() {
            return Err(BuildPolicyError::ExecutableVersionProbe {
                id: id.to_owned(),
                message: format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ),
            });
        }
        let actual = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if actual != expected_version {
            return Err(BuildPolicyError::ExecutableVersionMismatch {
                id: id.to_owned(),
                expected: expected_version.to_owned(),
                actual,
            });
        }
        Ok(VerifiedBuildExecutable {
            path: canonical,
            digest: executable.digest.clone(),
            version: executable.version.clone(),
        })
    }

    fn require_kind(
        &self,
        id: &str,
        expected: &'static str,
        values: &BTreeSet<String>,
    ) -> Result<(), BuildPolicyError> {
        if values.contains(id) {
            return Ok(());
        }
        let actual = if self.executable_ids.contains(id) {
            Some("executable")
        } else if self.read_input_ids.contains(id) {
            Some("read-input")
        } else if self.environment_ids.contains(id) {
            Some("environment")
        } else {
            None
        };
        if let Some(actual) = actual {
            Err(BuildPolicyError::KindMismatch {
                id: id.to_owned(),
                expected,
                actual,
            })
        } else {
            Err(BuildPolicyError::MissingMapping {
                kind: expected,
                id: id.to_owned(),
            })
        }
    }
}

fn validate_id(kind: &'static str, value: &str) -> Result<(), BuildPolicyError> {
    let bytes = value.as_bytes();
    let valid = !bytes.is_empty()
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && !bytes.windows(2).any(|pair| pair == b"--")
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(BuildPolicyError::InvalidId {
            kind,
            id: value.to_owned(),
        })
    }
}

fn validate_path(value: &Path) -> Result<(), BuildPolicyError> {
    if value.is_absolute() {
        Ok(())
    } else {
        Err(BuildPolicyError::NonAbsolutePath(
            value.display().to_string(),
        ))
    }
}

fn validate_digest(id: &str, value: &str) -> Result<(), BuildPolicyError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(BuildPolicyError::InvalidDigest(id.to_owned()))
    }
}

fn valid_environment_name(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes()[0].is_ascii_uppercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn forbidden_environment(value: &str) -> bool {
    matches!(
        value,
        "PATH"
            | "HOME"
            | "CARGO_HOME"
            | "RUSTFLAGS"
            | "RUSTC_WRAPPER"
            | "LANG"
            | "LC_ALL"
            | "SOURCE_DATE_EPOCH"
    ) || value.contains("TOKEN")
        || value.contains("SECRET")
        || value.contains("PASSWORD")
        || value.contains("PROXY")
        || value.contains("CREDENTIAL")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_is_order_independent() {
        let first = BuildExecutionPolicy {
            schema: 1,
            executables: vec![
                BuildExecutable {
                    id: "z-tool".into(),
                    path: "/bin/z".into(),
                    digest: "00".repeat(32),
                    version: "1".into(),
                },
                BuildExecutable {
                    id: "a-tool".into(),
                    path: "/bin/a".into(),
                    digest: "11".repeat(32),
                    version: "1".into(),
                },
            ],
            read_inputs: vec![],
            environment: vec![],
        };
        let mut second = first.clone();
        second.executables.reverse();
        assert_eq!(
            first.normalize().unwrap().digest().unwrap(),
            second.normalize().unwrap().digest().unwrap()
        );
    }

    #[test]
    fn semantic_digest_is_path_independent_but_content_sensitive() {
        let mut first = BuildExecutionPolicy {
            schema: 1,
            executables: vec![BuildExecutable {
                id: "compiler".into(),
                path: "/host-a/bin/compiler".into(),
                digest: "00".repeat(32),
                version: "1".into(),
            }],
            read_inputs: vec![],
            environment: vec![],
        };
        let first_digest = first.normalize().unwrap().digest().unwrap();
        first.executables[0].path = "/host-b/toolchain/compiler".into();
        assert_eq!(first.normalize().unwrap().digest().unwrap(), first_digest);
        first.executables[0].digest = "11".repeat(32);
        assert_ne!(first.normalize().unwrap().digest().unwrap(), first_digest);
    }

    #[test]
    fn kind_mismatch_fails_closed() {
        let policy = BuildExecutionPolicy {
            schema: 1,
            executables: vec![],
            read_inputs: vec![BuildReadInput {
                id: "codegen".into(),
                path: "/sdk".into(),
                digest: "00".repeat(32),
            }],
            environment: vec![],
        }
        .normalize()
        .unwrap();
        let requirements = BuildRequirements {
            executables: ["codegen".into()].into_iter().collect(),
            ..BuildRequirements::default()
        };
        assert!(matches!(
            policy.authorize(&requirements),
            Err(BuildPolicyError::KindMismatch { .. })
        ));
    }

    #[test]
    fn secret_and_proxy_environment_are_rejected() {
        for variable in ["API_TOKEN", "HTTPS_PROXY", "HOME"] {
            let policy = BuildExecutionPolicy {
                schema: 1,
                executables: vec![],
                read_inputs: vec![],
                environment: vec![BuildEnvironment {
                    id: "input".into(),
                    variable: variable.into(),
                    value: "x".into(),
                }],
            };
            assert!(matches!(
                policy.normalize(),
                Err(BuildPolicyError::ForbiddenEnvironment { .. })
            ));
        }
    }
}
