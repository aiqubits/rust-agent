use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use rust_agent_composition::canonical;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CargoPackageSource, FetchedSourceEvidence, HostBuildClosureItemRole, LockedSourceError,
    NormalizedFetchedSourceEvidence, NormalizedHostBuildInputClosure,
    NormalizedLockedSourceClosure, NormalizedProductionBuildPolicy, ProductionFetchRedirectPolicy,
    ProductionFileIdentity, ProductionSandboxBackend,
};

const LOGICAL_CLOSURE_ROOT: &str = "/rust-agent/closure";
const LOGICAL_CARGO: &str = "/rust-agent/toolchain/bin/cargo";
const LOGICAL_RUSTC: &str = "/rust-agent/toolchain/bin/rustc";
const LOGICAL_SYSROOT: &str = "/rust-agent/toolchain";
const LOGICAL_EMPTY_HOME: &str = "/rust-agent/empty-home";
const LOGICAL_FETCH_ROOT: &str = "/rust-agent/fetch-cache-staging";
const LOGICAL_CARGO_HOME: &str = "/rust-agent/fetch-cache-staging/cargo-home";
const LOGICAL_TEMP: &str = "/rust-agent/fetch-cache-staging/tmp";
const LOGICAL_CREDENTIAL_HELPER: &str = "/rust-agent/fetch-tools/credential-helper";
const MAX_FETCH_OBSERVATION_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_DESCENDANT_EXECUTIONS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CargoFetchMode {
    Networked,
    Preprovisioned,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoFetchRequest {
    pub schema: u32,
    pub mode: CargoFetchMode,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoFetchInvocation {
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub environment: BTreeMap<String, String>,
    #[serde(rename = "working-directory")]
    pub working_directory: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoFetchSandboxContract {
    pub backend: ProductionSandboxBackend,
    #[serde(rename = "environment-cleared")]
    pub environment_cleared: bool,
    #[serde(rename = "descendants-inherit-sandbox")]
    pub descendants_inherit_sandbox: bool,
    #[serde(rename = "read-only-mounts")]
    pub read_only_mounts: Vec<String>,
    #[serde(rename = "writable-mounts")]
    pub writable_mounts: Vec<String>,
    #[serde(rename = "network-endpoints")]
    pub network_endpoints: Vec<String>,
    #[serde(rename = "tls-ca-bundle", skip_serializing_if = "Option::is_none")]
    pub tls_ca_bundle: Option<CargoFetchTlsCaBundle>,
    #[serde(rename = "redirect-policy")]
    pub redirect_policy: ProductionFetchRedirectPolicy,
    #[serde(rename = "credential-helper")]
    pub credential_helper: Option<CargoFetchCredentialHelper>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoFetchCredentialHelper {
    pub executable: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoFetchTlsCaBundle {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedCargoFetchRequest {
    mode: CargoFetchMode,
    build_execution_policy_digest: String,
    host_build_input_closure_digest: String,
    locked_source_closure_digest: String,
    build_triple: String,
    cargo_target_input: String,
    manifest_logical_path: String,
    cargo_lock_logical_path: String,
    cargo_config_logical_path: String,
    invocation: CargoFetchInvocation,
    sandbox: CargoFetchSandboxContract,
    digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CargoFetchObservation {
    pub schema: u32,
    #[serde(rename = "request-digest")]
    pub request_digest: String,
    pub sandbox: CargoFetchSandboxContract,
    #[serde(rename = "cargo-exit-code")]
    pub cargo_exit_code: i32,
    #[serde(rename = "descendant-executions")]
    pub descendant_executions: Vec<CargoFetchDescendantExecution>,
    #[serde(rename = "fetched-sources")]
    pub fetched_sources: FetchedSourceEvidence,
    #[serde(rename = "cache-tree-digest")]
    pub cache_tree_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CargoFetchDescendantExecution {
    RustcIdentityQuery {
        executable: String,
        arguments: Vec<String>,
        #[serde(rename = "exit-code")]
        exit_code: i32,
    },
    CredentialHelper {
        executable: String,
        arguments: Vec<String>,
        endpoint: String,
        #[serde(rename = "exit-code")]
        exit_code: i32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedCargoFetchObservation {
    request_digest: String,
    fetched_sources: NormalizedFetchedSourceEvidence,
    cache_tree_digest: String,
    digest: String,
}

#[derive(Debug, Error)]
pub enum CargoFetchError {
    #[error("unsupported Cargo fetch request schema {0}; expected 3")]
    UnsupportedRequestSchema(u32),
    #[error("unsupported Cargo fetch observation schema {0}; expected 3")]
    UnsupportedObservationSchema(u32),
    #[error("Cargo fetch policy does not match HostBuildInputClosure")]
    PolicyMismatch,
    #[error("HostBuildInputClosure is missing Cargo fetch input role {0:?}")]
    MissingClosureItem(HostBuildClosureItemRole),
    #[error("Cargo fetch logical input topology is invalid")]
    InvalidLogicalInputTopology,
    #[error("networked Cargo fetch has no endpoint for locked source `{0}`")]
    MissingSourceEndpoint(String),
    #[error("Cargo fetch observation JSON exceeds its byte limit")]
    ObservationTooLarge,
    #[error("Cargo fetch observation JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Cargo fetch observation is bound to a different request")]
    ObservationRequestMismatch,
    #[error("Cargo fetch sandbox observation differs from the exact request")]
    SandboxMismatch,
    #[error("Cargo fetch failed with exit code {0}")]
    FetchFailed(i32),
    #[error("Cargo fetch descendant execution is outside the schema-3 allowlist")]
    InvalidDescendantExecution,
    #[error("Cargo fetch cache tree digest is invalid")]
    InvalidCacheTreeDigest,
    #[error("locked source verification failed: {0}")]
    LockedSources(#[from] LockedSourceError),
    #[error("canonical Cargo fetch encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
}

#[derive(Serialize)]
struct FetchRequestProjection<'a> {
    schema: u32,
    mode: CargoFetchMode,
    build_execution_policy_digest: &'a str,
    host_build_input_closure_digest: &'a str,
    locked_source_closure_digest: &'a str,
    build_triple: &'a str,
    cargo_target_input: &'a str,
    manifest_logical_path: &'a str,
    cargo_lock_logical_path: &'a str,
    cargo_config_logical_path: &'a str,
    invocation: &'a CargoFetchInvocation,
    sandbox: &'a CargoFetchSandboxContract,
}

impl CargoFetchRequest {
    pub fn normalize(
        &self,
        policy: &NormalizedProductionBuildPolicy,
        host_closure: &NormalizedHostBuildInputClosure,
        locked_sources: &NormalizedLockedSourceClosure,
    ) -> Result<NormalizedCargoFetchRequest, CargoFetchError> {
        if self.schema != 3 {
            return Err(CargoFetchError::UnsupportedRequestSchema(self.schema));
        }
        if host_closure.build_execution_policy_digest() != policy.full_digest() {
            return Err(CargoFetchError::PolicyMismatch);
        }
        locked_sources.verify_host_closure(host_closure)?;

        let manifest_logical_path =
            closure_item_path(host_closure, HostBuildClosureItemRole::HostRootManifest)?;
        let cargo_lock_logical_path =
            closure_item_path(host_closure, HostBuildClosureItemRole::HostCargoLock)?;
        let cargo_config_logical_path =
            closure_item_path(host_closure, HostBuildClosureItemRole::CargoConfig)?;
        validate_logical_topology(
            &manifest_logical_path,
            &cargo_lock_logical_path,
            &cargo_config_logical_path,
        )?;
        let build_triple = host_closure.build_context().build_triple.clone();
        let cargo_target_input = if host_closure
            .build_context()
            .custom_target_spec_digest
            .is_some()
        {
            format!("targets/{}.json", host_closure.build_context().target)
        } else {
            host_closure.build_context().target.clone()
        };

        let fetch = &policy.policy().fetch;
        if self.mode == CargoFetchMode::Networked {
            verify_remote_source_endpoints(locked_sources, &fetch.network_endpoints)?;
        }
        let network_endpoints = if self.mode == CargoFetchMode::Networked {
            fetch.network_endpoints.clone()
        } else {
            Vec::new()
        };
        let credential_helper = (self.mode == CargoFetchMode::Networked)
            .then(|| {
                fetch
                    .credential_helper
                    .as_ref()
                    .map(credential_helper_contract)
            })
            .flatten();
        let tls_ca_bundle = if self.mode == CargoFetchMode::Networked {
            Some(tls_ca_bundle_contract(
                fetch
                    .tls_ca_bundle
                    .as_ref()
                    .ok_or(CargoFetchError::InvalidLogicalInputTopology)?,
            ))
        } else {
            None
        };
        let mut read_only_mounts = vec![
            LOGICAL_CLOSURE_ROOT.into(),
            LOGICAL_CARGO.into(),
            LOGICAL_RUSTC.into(),
            LOGICAL_SYSROOT.into(),
            LOGICAL_EMPTY_HOME.into(),
        ];
        if credential_helper.is_some() {
            read_only_mounts.push(LOGICAL_CREDENTIAL_HELPER.into());
        }
        if tls_ca_bundle.is_some() {
            read_only_mounts.push("/rust-agent/fetch-inputs/ca-bundle.pem".into());
        }
        read_only_mounts.sort();
        let sandbox = CargoFetchSandboxContract {
            backend: policy.policy().backend,
            environment_cleared: true,
            descendants_inherit_sandbox: true,
            read_only_mounts,
            writable_mounts: vec![LOGICAL_FETCH_ROOT.into()],
            network_endpoints,
            tls_ca_bundle,
            redirect_policy: fetch.redirect_policy,
            credential_helper,
        };

        let mut arguments = vec![
            "fetch".into(),
            "--manifest-path".into(),
            manifest_logical_path.clone(),
            "--config".into(),
            cargo_config_logical_path.clone(),
            "--locked".into(),
        ];
        if self.mode == CargoFetchMode::Networked {
            arguments.extend([
                "--config".into(),
                "http.cainfo=\"/rust-agent/fetch-inputs/ca-bundle.pem\"".into(),
                "--config".into(),
                "net.offline=false".into(),
            ]);
            if sandbox.credential_helper.is_some() {
                arguments.extend([
                    "--config".into(),
                    "credential-alias.rust-agent=[\"/rust-agent/fetch-tools/credential-helper\"]"
                        .into(),
                    "--config".into(),
                    "registry.global-credential-providers=[\"rust-agent\"]".into(),
                ]);
            } else {
                arguments.extend([
                    "--config".into(),
                    "registry.global-credential-providers=[]".into(),
                ]);
            }
        }
        if self.mode == CargoFetchMode::Preprovisioned {
            arguments.push("--offline".into());
        }
        let mut environment = BTreeMap::from([
            ("CARGO_HOME".into(), LOGICAL_CARGO_HOME.into()),
            ("CARGO_NET_GIT_FETCH_WITH_CLI".into(), "false".into()),
            ("HOME".into(), LOGICAL_EMPTY_HOME.into()),
            ("LANG".into(), "C.UTF-8".into()),
            ("LC_ALL".into(), "C.UTF-8".into()),
            ("PATH".into(), "/rust-agent/toolchain/bin".into()),
            ("RUSTC".into(), LOGICAL_RUSTC.into()),
            ("SOURCE_DATE_EPOCH".into(), "0".into()),
            ("TMPDIR".into(), LOGICAL_TEMP.into()),
        ]);
        if self.mode == CargoFetchMode::Preprovisioned {
            environment.insert("CARGO_NET_OFFLINE".into(), "true".into());
        }
        let working_directory = Path::new(&manifest_logical_path)
            .parent()
            .and_then(Path::to_str)
            .ok_or(CargoFetchError::InvalidLogicalInputTopology)?
            .into();
        let invocation = CargoFetchInvocation {
            executable: PathBuf::from(LOGICAL_CARGO),
            arguments,
            environment,
            working_directory,
        };
        let projection = FetchRequestProjection {
            schema: 3,
            mode: self.mode,
            build_execution_policy_digest: policy.full_digest(),
            host_build_input_closure_digest: host_closure.digest(),
            locked_source_closure_digest: locked_sources.digest(),
            build_triple: &build_triple,
            cargo_target_input: &cargo_target_input,
            manifest_logical_path: &manifest_logical_path,
            cargo_lock_logical_path: &cargo_lock_logical_path,
            cargo_config_logical_path: &cargo_config_logical_path,
            invocation: &invocation,
            sandbox: &sandbox,
        };
        let digest = hex::encode(canonical::domain_hash(
            b"rust-agent-cargo-fetch-request-v3\0",
            &projection,
        )?);
        Ok(NormalizedCargoFetchRequest {
            mode: self.mode,
            build_execution_policy_digest: policy.full_digest().into(),
            host_build_input_closure_digest: host_closure.digest().into(),
            locked_source_closure_digest: locked_sources.digest().into(),
            build_triple,
            cargo_target_input,
            manifest_logical_path,
            cargo_lock_logical_path,
            cargo_config_logical_path,
            invocation,
            sandbox,
            digest,
        })
    }
}

impl NormalizedCargoFetchRequest {
    pub fn mode(&self) -> CargoFetchMode {
        self.mode
    }

    pub fn build_execution_policy_digest(&self) -> &str {
        &self.build_execution_policy_digest
    }

    pub fn host_build_input_closure_digest(&self) -> &str {
        &self.host_build_input_closure_digest
    }

    pub fn locked_source_closure_digest(&self) -> &str {
        &self.locked_source_closure_digest
    }

    pub fn build_triple(&self) -> &str {
        &self.build_triple
    }

    pub fn cargo_target_input(&self) -> &str {
        &self.cargo_target_input
    }

    pub fn manifest_logical_path(&self) -> &str {
        &self.manifest_logical_path
    }

    pub fn cargo_lock_logical_path(&self) -> &str {
        &self.cargo_lock_logical_path
    }

    pub fn cargo_config_logical_path(&self) -> &str {
        &self.cargo_config_logical_path
    }

    pub fn invocation(&self) -> &CargoFetchInvocation {
        &self.invocation
    }

    pub fn sandbox(&self) -> &CargoFetchSandboxContract {
        &self.sandbox
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub(crate) fn allows_rustc_query(&self, arguments: &[String]) -> bool {
        arguments == ["-vV"]
            || arguments == cargo_target_information_query(None)
            || arguments == cargo_target_information_query(Some(&self.cargo_target_input))
    }

    pub fn validate_observation(
        &self,
        observation: &CargoFetchObservation,
        locked_sources: &NormalizedLockedSourceClosure,
    ) -> Result<ValidatedCargoFetchObservation, CargoFetchError> {
        if observation.schema != 3 {
            return Err(CargoFetchError::UnsupportedObservationSchema(
                observation.schema,
            ));
        }
        if observation.request_digest != self.digest
            || observation.fetched_sources.locked_source_closure_digest
                != self.locked_source_closure_digest
        {
            return Err(CargoFetchError::ObservationRequestMismatch);
        }
        if observation.sandbox != self.sandbox {
            return Err(CargoFetchError::SandboxMismatch);
        }
        if observation.cargo_exit_code != 0 {
            return Err(CargoFetchError::FetchFailed(observation.cargo_exit_code));
        }
        validate_descendant_executions(
            &observation.descendant_executions,
            &self.sandbox,
            &self.cargo_target_input,
        )?;
        if !is_digest(&observation.cache_tree_digest) {
            return Err(CargoFetchError::InvalidCacheTreeDigest);
        }
        let fetched_sources = observation.fetched_sources.normalize(locked_sources)?;
        let digest = hex::encode(canonical::domain_hash(
            b"rust-agent-validated-cargo-fetch-observation-v3\0",
            &(
                1_u32,
                &self.digest,
                &observation.descendant_executions,
                fetched_sources.digest(),
                &observation.cache_tree_digest,
            ),
        )?);
        Ok(ValidatedCargoFetchObservation {
            request_digest: self.digest.clone(),
            fetched_sources,
            cache_tree_digest: observation.cache_tree_digest.clone(),
            digest,
        })
    }
}

impl CargoFetchObservation {
    pub fn from_json(input: &str) -> Result<Self, CargoFetchError> {
        if input.len() > MAX_FETCH_OBSERVATION_JSON_BYTES {
            return Err(CargoFetchError::ObservationTooLarge);
        }
        Ok(serde_json::from_str(input)?)
    }
}

impl ValidatedCargoFetchObservation {
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn fetched_sources(&self) -> &NormalizedFetchedSourceEvidence {
        &self.fetched_sources
    }

    pub fn cache_tree_digest(&self) -> &str {
        &self.cache_tree_digest
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

fn closure_item_path(
    closure: &NormalizedHostBuildInputClosure,
    role: HostBuildClosureItemRole,
) -> Result<String, CargoFetchError> {
    closure
        .items()
        .iter()
        .find(|item| item.role == role)
        .map(|item| item.logical_path.clone())
        .ok_or(CargoFetchError::MissingClosureItem(role))
}

fn validate_logical_topology(
    manifest: &str,
    lock: &str,
    config: &str,
) -> Result<(), CargoFetchError> {
    let manifest = Path::new(manifest);
    let lock = Path::new(lock);
    let config = Path::new(config);
    let root = manifest
        .parent()
        .ok_or(CargoFetchError::InvalidLogicalInputTopology)?;
    let valid = manifest
        .file_name()
        .is_some_and(|name| name == "Cargo.toml")
        && lock.file_name().is_some_and(|name| name == "Cargo.lock")
        && lock.parent() == Some(root)
        && config == root.join(".cargo/config.toml")
        && root.starts_with(LOGICAL_CLOSURE_ROOT);
    if valid {
        Ok(())
    } else {
        Err(CargoFetchError::InvalidLogicalInputTopology)
    }
}

fn credential_helper_contract(helper: &ProductionFileIdentity) -> CargoFetchCredentialHelper {
    CargoFetchCredentialHelper {
        executable: LOGICAL_CREDENTIAL_HELPER.into(),
        sha256: helper.sha256.clone(),
    }
}

fn tls_ca_bundle_contract(bundle: &ProductionFileIdentity) -> CargoFetchTlsCaBundle {
    CargoFetchTlsCaBundle {
        path: "/rust-agent/fetch-inputs/ca-bundle.pem".into(),
        sha256: bundle.sha256.clone(),
    }
}

fn verify_remote_source_endpoints(
    locked_sources: &NormalizedLockedSourceClosure,
    allowed: &[String],
) -> Result<(), CargoFetchError> {
    let allowed = allowed.iter().map(String::as_str).collect::<BTreeSet<_>>();
    for package in locked_sources.packages() {
        let remote = match &package.source {
            CargoPackageSource::Registry { registry, .. } => Some(registry.as_str()),
            CargoPackageSource::Git { repository, .. } => Some(repository.as_str()),
            CargoPackageSource::Path { .. } => None,
        };
        if let Some(remote) = remote {
            let origin = canonical_https_origin(remote).ok_or_else(|| {
                CargoFetchError::MissingSourceEndpoint(format!(
                    "{} {}",
                    package.name, package.version
                ))
            })?;
            if !allowed.contains(origin.as_str()) {
                return Err(CargoFetchError::MissingSourceEndpoint(format!(
                    "{} {}",
                    package.name, package.version
                )));
            }
        }
    }
    Ok(())
}

fn canonical_https_origin(value: &str) -> Option<String> {
    let value = value.strip_prefix("sparse+").unwrap_or(value);
    let remainder = value.strip_prefix("https://")?;
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let authority = if authority.starts_with('[') {
        if authority.contains("]:") {
            authority.to_owned()
        } else if authority.ends_with(']') {
            format!("{authority}:443")
        } else {
            return None;
        }
    } else if authority
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
    {
        authority.to_owned()
    } else if authority.contains(':') {
        return None;
    } else {
        format!("{authority}:443")
    };
    Some(format!("https://{authority}"))
}

fn validate_descendant_executions(
    executions: &[CargoFetchDescendantExecution],
    sandbox: &CargoFetchSandboxContract,
    cargo_target_input: &str,
) -> Result<(), CargoFetchError> {
    if executions.is_empty() || executions.len() > MAX_DESCENDANT_EXECUTIONS {
        return Err(CargoFetchError::InvalidDescendantExecution);
    }
    let host_query = cargo_target_information_query(None);
    let target_query = cargo_target_information_query(Some(cargo_target_input));
    let mut version_queries = 0_usize;
    let mut host_queries = 0_usize;
    let mut target_queries = 0_usize;
    for execution in executions {
        match execution {
            CargoFetchDescendantExecution::RustcIdentityQuery {
                executable,
                arguments,
                exit_code,
            } if executable == LOGICAL_RUSTC && *exit_code == 0 => match arguments.as_slice() {
                [argument] if argument == "-vV" => version_queries += 1,
                arguments if arguments == host_query => host_queries += 1,
                arguments if arguments == target_query => {
                    target_queries += 1;
                }
                _ => return Err(CargoFetchError::InvalidDescendantExecution),
            },
            CargoFetchDescendantExecution::CredentialHelper {
                executable,
                arguments,
                endpoint,
                exit_code,
            } if sandbox.credential_helper.is_some()
                && executable == LOGICAL_CREDENTIAL_HELPER
                && arguments.len() == 1
                && arguments[0] == "--cargo-plugin"
                && sandbox.network_endpoints.contains(endpoint)
                && *exit_code == 0 => {}
            _ => return Err(CargoFetchError::InvalidDescendantExecution),
        }
    }
    if version_queries == 0 || host_queries == 0 || target_queries == 0 {
        return Err(CargoFetchError::InvalidDescendantExecution);
    }
    Ok(())
}

pub(crate) fn cargo_target_information_query(target: Option<&str>) -> Vec<String> {
    let mut arguments = vec![
        "-".into(),
        "--crate-name".into(),
        "___".into(),
        "--print=file-names".into(),
    ];
    if let Some(target) = target {
        arguments.extend(["--target".into(), target.into()]);
    }
    arguments.extend(
        [
            "--crate-type",
            "bin",
            "--crate-type",
            "rlib",
            "--crate-type",
            "dylib",
            "--crate-type",
            "cdylib",
            "--crate-type",
            "staticlib",
            "--crate-type",
            "proc-macro",
            "--print=sysroot",
            "--print=split-debuginfo",
            "--print=crate-name",
            "--print=cfg",
            "-Wwarnings",
        ]
        .map(str::to_owned),
    );
    arguments
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
