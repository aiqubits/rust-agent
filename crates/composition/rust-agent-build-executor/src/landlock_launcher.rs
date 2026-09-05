use std::{collections::BTreeSet, fs, io, net::IpAddr, path::Path};

use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, LandlockStatus, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus,
};
use rust_agent_composition::canonical;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const POLICY_DOMAIN: &[u8] = b"rust-agent-landlock-execution-policy-v3\0";
const MAX_POLICY_JSON_BYTES: usize = 1024 * 1024;
const MAX_NETWORK_ENDPOINTS: usize = 64;
const MAX_ADDRESSES_PER_ENDPOINT: usize = 64;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxSandboxResolvedEndpoint {
    pub origin: String,
    pub host: String,
    pub port: u16,
    pub addresses: Vec<IpAddr>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LinuxSandboxNetworkPolicy {
    Isolated,
    EndpointAllowlist {
        endpoints: Vec<LinuxSandboxResolvedEndpoint>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinuxSandboxAnonymousSocketpair {
    StreamWakeup,
    RustSpawnError,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LandlockExecutionPolicy {
    pub schema: u32,
    #[serde(rename = "read-only-paths")]
    pub read_only_paths: Vec<String>,
    #[serde(rename = "writable-paths")]
    pub writable_paths: Vec<String>,
    #[serde(rename = "executable-paths")]
    pub executable_paths: Vec<String>,
    #[serde(rename = "runtime-interpreter-paths")]
    pub runtime_interpreter_paths: Vec<String>,
    #[serde(rename = "canonical-metadata-roots")]
    pub canonical_metadata_roots: Vec<String>,
    #[serde(rename = "metadata-visible-directories")]
    pub metadata_visible_directories: Vec<String>,
    #[serde(rename = "derived-executable-roots")]
    pub derived_executable_roots: Vec<String>,
    #[serde(rename = "network-endpoints")]
    pub network_endpoints: Vec<LinuxSandboxResolvedEndpoint>,
    #[serde(rename = "anonymous-socketpairs")]
    pub anonymous_socketpairs: Vec<LinuxSandboxAnonymousSocketpair>,
    pub digest: String,
}

#[derive(Debug, Error)]
pub enum LandlockLauncherError {
    #[error("Landlock launcher policy JSON exceeds its byte limit")]
    JsonTooLarge,
    #[error("Landlock launcher policy JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported Landlock launcher policy schema {0}; expected 3")]
    UnsupportedSchema(u32),
    #[error("Landlock launcher policy has an invalid path set")]
    InvalidPathSet,
    #[error("Landlock launcher policy digest differs from its canonical projection")]
    DigestMismatch,
    #[error("Landlock rule setup failed: {0}")]
    Landlock(#[from] landlock::RulesetError),
    #[error("Landlock path rule setup failed: {0}")]
    Path(#[from] landlock::PathFdError),
    #[error("the kernel did not fully enforce the requested Landlock rules")]
    NotFullyEnforced,
    #[error("the kernel did not enable no-new-privileges")]
    NoNewPrivilegesUnavailable,
    #[error("launcher command `{0}` is not an allowed executable or derived executable")]
    CommandNotAllowed(String),
    #[error("Landlock launcher I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("canonical Landlock policy encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
}

#[derive(Serialize)]
struct PolicyProjection<'a> {
    schema: u32,
    read_only_paths: &'a [String],
    writable_paths: &'a [String],
    executable_paths: &'a [String],
    runtime_interpreter_paths: &'a [String],
    canonical_metadata_roots: &'a [String],
    metadata_visible_directories: &'a [String],
    derived_executable_roots: &'a [String],
    network_endpoints: &'a [LinuxSandboxResolvedEndpoint],
    anonymous_socketpairs: &'a [LinuxSandboxAnonymousSocketpair],
}

impl LandlockExecutionPolicy {
    #[expect(
        clippy::too_many_arguments,
        reason = "each independent sandbox authority set remains explicit at the trust boundary"
    )]
    pub fn new(
        mut read_only_paths: Vec<String>,
        mut writable_paths: Vec<String>,
        mut executable_paths: Vec<String>,
        mut runtime_interpreter_paths: Vec<String>,
        mut canonical_metadata_roots: Vec<String>,
        mut derived_executable_roots: Vec<String>,
        mut network_endpoints: Vec<LinuxSandboxResolvedEndpoint>,
        mut anonymous_socketpairs: Vec<LinuxSandboxAnonymousSocketpair>,
    ) -> Result<Self, LandlockLauncherError> {
        read_only_paths.sort();
        writable_paths.sort();
        executable_paths.sort();
        runtime_interpreter_paths.sort();
        canonical_metadata_roots.sort();
        derived_executable_roots.sort();
        network_endpoints.sort();
        anonymous_socketpairs.sort();
        let metadata_visible_directories = derive_metadata_visible_directories(
            &read_only_paths,
            &writable_paths,
            &executable_paths,
            &runtime_interpreter_paths,
            &derived_executable_roots,
        );
        let mut policy = Self {
            schema: 3,
            read_only_paths,
            writable_paths,
            executable_paths,
            runtime_interpreter_paths,
            canonical_metadata_roots,
            metadata_visible_directories,
            derived_executable_roots,
            network_endpoints,
            anonymous_socketpairs,
            digest: String::new(),
        };
        policy.validate_path_sets()?;
        policy.digest = policy.recompute_digest()?;
        Ok(policy)
    }

    pub fn from_json(input: &str) -> Result<Self, LandlockLauncherError> {
        if input.len() > MAX_POLICY_JSON_BYTES {
            return Err(LandlockLauncherError::JsonTooLarge);
        }
        let policy: Self = serde_json::from_str(input)?;
        policy.verify()?;
        Ok(policy)
    }

    pub fn verify(&self) -> Result<(), LandlockLauncherError> {
        if self.schema != 3 {
            return Err(LandlockLauncherError::UnsupportedSchema(self.schema));
        }
        self.validate_path_sets()?;
        if self.digest != self.recompute_digest()? {
            return Err(LandlockLauncherError::DigestMismatch);
        }
        Ok(())
    }

    pub fn command_allowed(&self, command: &Path) -> bool {
        command.to_str().is_some_and(|command| {
            self.executable_paths
                .binary_search_by(|candidate| candidate.as_str().cmp(command))
                .is_ok()
                || self
                    .derived_executable_roots
                    .iter()
                    .any(|root| path_is_beneath(command, root))
        })
    }

    pub fn path_visible(&self, path: &Path) -> bool {
        path.to_str().is_some_and(|path| {
            self.read_only_paths
                .iter()
                .chain(&self.writable_paths)
                .chain(&self.derived_executable_roots)
                .any(|root| path == root || path_is_beneath(path, root))
                || self
                    .executable_paths
                    .iter()
                    .chain(&self.runtime_interpreter_paths)
                    .any(|visible| path == visible)
                || self
                    .metadata_visible_directories
                    .binary_search_by(|visible| visible.as_str().cmp(path))
                    .is_ok()
        })
    }

    pub fn canonical_metadata_visible(&self, path: &Path) -> bool {
        path.to_str().is_some_and(|path| {
            self.canonical_metadata_roots
                .iter()
                .any(|root| path == root || path_is_beneath(path, root))
                || self
                    .metadata_visible_directories
                    .binary_search_by(|visible| visible.as_str().cmp(path))
                    .is_ok()
        })
    }

    pub fn network_endpoint_allowed(&self, address: IpAddr, port: u16) -> bool {
        self.network_endpoints.iter().any(|endpoint| {
            endpoint.port == port && endpoint.addresses.binary_search(&address).is_ok()
        })
    }

    fn recompute_digest(&self) -> Result<String, LandlockLauncherError> {
        Ok(hex::encode(canonical::domain_hash(
            POLICY_DOMAIN,
            &PolicyProjection {
                schema: self.schema,
                read_only_paths: &self.read_only_paths,
                writable_paths: &self.writable_paths,
                executable_paths: &self.executable_paths,
                runtime_interpreter_paths: &self.runtime_interpreter_paths,
                canonical_metadata_roots: &self.canonical_metadata_roots,
                metadata_visible_directories: &self.metadata_visible_directories,
                derived_executable_roots: &self.derived_executable_roots,
                network_endpoints: &self.network_endpoints,
                anonymous_socketpairs: &self.anonymous_socketpairs,
            },
        )?))
    }

    fn validate_path_sets(&self) -> Result<(), LandlockLauncherError> {
        let valid = !self.read_only_paths.is_empty()
            && !self.executable_paths.is_empty()
            && sorted_unique_paths(&self.read_only_paths)
            && sorted_unique_paths(&self.writable_paths)
            && sorted_unique_paths(&self.executable_paths)
            && sorted_unique_paths(&self.runtime_interpreter_paths)
            && sorted_unique_paths(&self.canonical_metadata_roots)
            && sorted_unique_paths(&self.metadata_visible_directories)
            && sorted_unique_paths(&self.derived_executable_roots)
            && disjoint(&self.read_only_paths, &self.writable_paths)
            && self.canonical_metadata_roots.iter().all(|root| {
                self.read_only_paths
                    .iter()
                    .any(|read_only| root == read_only || path_is_beneath(root, read_only))
            })
            && self.metadata_visible_directories
                == derive_metadata_visible_directories(
                    &self.read_only_paths,
                    &self.writable_paths,
                    &self.executable_paths,
                    &self.runtime_interpreter_paths,
                    &self.derived_executable_roots,
                )
            && self.derived_executable_roots.iter().all(|derived| {
                self.writable_paths
                    .iter()
                    .any(|writable| derived == writable || path_is_beneath(derived, writable))
            })
            && valid_network_endpoints(&self.network_endpoints);
        let valid = valid
            && self
                .anonymous_socketpairs
                .windows(2)
                .all(|pair| pair[0] < pair[1]);
        if valid {
            Ok(())
        } else {
            Err(LandlockLauncherError::InvalidPathSet)
        }
    }
}

impl LinuxSandboxNetworkPolicy {
    pub(crate) fn validate(&self) -> bool {
        match self {
            Self::Isolated => true,
            Self::EndpointAllowlist { endpoints } => {
                !endpoints.is_empty() && valid_network_endpoints(endpoints)
            }
        }
    }

    pub(crate) fn endpoints(&self) -> &[LinuxSandboxResolvedEndpoint] {
        match self {
            Self::Isolated => &[],
            Self::EndpointAllowlist { endpoints } => endpoints,
        }
    }

    pub(crate) fn shares_host_network(&self) -> bool {
        matches!(self, Self::EndpointAllowlist { .. })
    }
}

fn valid_network_endpoints(endpoints: &[LinuxSandboxResolvedEndpoint]) -> bool {
    endpoints.len() <= MAX_NETWORK_ENDPOINTS
        && endpoints.windows(2).all(|pair| pair[0] < pair[1])
        && endpoints.iter().all(|endpoint| {
            endpoint.port != 0
                && valid_network_host(&endpoint.host)
                && endpoint.origin == canonical_origin(&endpoint.host, endpoint.port)
                && !endpoint.addresses.is_empty()
                && endpoint.addresses.len() <= MAX_ADDRESSES_PER_ENDPOINT
                && endpoint.addresses.windows(2).all(|pair| pair[0] < pair[1])
        })
}

fn valid_network_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host == host.to_ascii_lowercase()
        && !host.contains(['\0', '/', '@', '[', ']'])
        && (host.parse::<IpAddr>().is_ok()
            || host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            }))
}

fn canonical_origin(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("https://[{host}]:{port}")
    } else {
        format!("https://{host}:{port}")
    }
}

fn derive_metadata_visible_directories(
    read_only_paths: &[String],
    writable_paths: &[String],
    executable_paths: &[String],
    runtime_interpreter_paths: &[String],
    derived_executable_roots: &[String],
) -> Vec<String> {
    let mut directories = BTreeSet::new();
    for path in read_only_paths
        .iter()
        .chain(writable_paths)
        .chain(executable_paths)
        .chain(runtime_interpreter_paths)
        .chain(derived_executable_roots)
    {
        let mut parent = Path::new(path).parent();
        while let Some(path) = parent {
            directories.insert(path.to_string_lossy().into_owned());
            parent = path.parent();
        }
    }
    directories.into_iter().collect()
}

pub fn apply_landlock_execution_policy(
    policy: &LandlockExecutionPolicy,
    command: &Path,
) -> Result<(), LandlockLauncherError> {
    policy.verify()?;
    if !policy.command_allowed(command) {
        return Err(LandlockLauncherError::CommandNotAllowed(
            command.display().to_string(),
        ));
    }

    let abi = if policy.derived_executable_roots.is_empty() {
        ABI::V1
    } else {
        ABI::V2
    };
    let read = AccessFs::from_read(abi) & !AccessFs::Execute;
    let writable = AccessFs::from_all(abi) & !AccessFs::Execute;
    let executable = (AccessFs::from_file(abi) & read) | AccessFs::Execute;
    let all = AccessFs::from_all(abi);
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(all)?
        .create()?;

    for path in &policy.read_only_paths {
        let metadata = fs::metadata(path)?;
        let access = if metadata.is_dir() {
            read
        } else if metadata.is_file() {
            AccessFs::from_file(abi) & read
        } else {
            return Err(LandlockLauncherError::InvalidPathSet);
        };
        ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new(path)?, access))?;
    }
    for path in &policy.writable_paths {
        if !fs::metadata(path)?.is_dir() {
            return Err(LandlockLauncherError::InvalidPathSet);
        }
        ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new(path)?, writable))?;
    }
    for path in &policy.executable_paths {
        if !fs::metadata(path)?.is_file() {
            return Err(LandlockLauncherError::InvalidPathSet);
        }
        ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new(path)?, executable))?;
    }
    for path in &policy.runtime_interpreter_paths {
        if !fs::metadata(path)?.is_file() {
            return Err(LandlockLauncherError::InvalidPathSet);
        }
        ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new(path)?, executable))?;
    }
    for path in &policy.derived_executable_roots {
        if !fs::metadata(path)?.is_dir() {
            return Err(LandlockLauncherError::InvalidPathSet);
        }
        ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new(path)?, all))?;
    }

    let status = ruleset
        .set_compatibility(CompatLevel::HardRequirement)
        .restrict_self()?;
    if status.ruleset != RulesetStatus::FullyEnforced
        || !matches!(status.landlock, LandlockStatus::Available { .. })
    {
        return Err(LandlockLauncherError::NotFullyEnforced);
    }
    if !status.no_new_privs {
        return Err(LandlockLauncherError::NoNewPrivilegesUnavailable);
    }
    Ok(())
}

fn sorted_unique_paths(paths: &[String]) -> bool {
    paths.iter().all(|path| is_normalized_absolute_path(path))
        && paths.windows(2).all(|pair| pair[0] < pair[1])
}

fn disjoint(left: &[String], right: &[String]) -> bool {
    let left = left.iter().map(String::as_str).collect::<BTreeSet<_>>();
    right.iter().all(|item| !left.contains(item.as_str()))
}

fn is_normalized_absolute_path(path: &str) -> bool {
    let path = Path::new(path);
    path.is_absolute()
        && path.components().enumerate().all(|(index, component)| {
            (index == 0 && matches!(component, std::path::Component::RootDir))
                || (index > 0 && matches!(component, std::path::Component::Normal(_)))
        })
}

fn path_is_beneath(path: &str, root: &str) -> bool {
    path.strip_prefix(root)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> LandlockExecutionPolicy {
        LandlockExecutionPolicy::new(
            vec!["/rust-agent/closure".into()],
            vec!["/rust-agent/target".into(), "/rust-agent/tmp".into()],
            vec!["/rust-agent/tools/rustc".into()],
            vec!["/lib64/ld-linux.so.2".into()],
            vec!["/rust-agent/closure".into()],
            vec!["/rust-agent/target".into()],
            vec![],
            vec![LinuxSandboxAnonymousSocketpair::StreamWakeup],
        )
        .unwrap()
    }

    #[test]
    fn policy_is_closed_canonical_and_command_scoped() {
        let policy = policy();
        let json = serde_json::to_string(&policy).unwrap();
        assert_eq!(LandlockExecutionPolicy::from_json(&json).unwrap(), policy);
        assert!(policy.command_allowed(Path::new("/rust-agent/tools/rustc")));
        assert!(policy.command_allowed(Path::new("/rust-agent/target/build/helper")));
        assert!(!policy.command_allowed(Path::new("/rust-agent/tools/other")));

        let mut unknown: serde_json::Value = serde_json::from_str(&json).unwrap();
        unknown["ambient-root"] = serde_json::Value::String("/".into());
        assert!(matches!(
            LandlockExecutionPolicy::from_json(&serde_json::to_string(&unknown).unwrap()),
            Err(LandlockLauncherError::Json(_))
        ));
    }

    #[test]
    fn invalid_path_sets_and_resealed_drift_fail_closed() {
        assert!(matches!(
            LandlockExecutionPolicy::new(
                vec!["/rust-agent/../etc".into()],
                vec![],
                vec!["/rust-agent/tools/rustc".into()],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![LinuxSandboxAnonymousSocketpair::StreamWakeup],
            ),
            Err(LandlockLauncherError::InvalidPathSet)
        ));
        let mut policy = policy();
        policy
            .executable_paths
            .push("/rust-agent/tools/other".into());
        assert!(matches!(
            policy.verify(),
            Err(LandlockLauncherError::InvalidPathSet | LandlockLauncherError::DigestMismatch)
        ));
    }

    #[test]
    fn resolved_network_endpoints_are_closed_sorted_and_digest_bound() {
        let endpoint = LinuxSandboxResolvedEndpoint {
            origin: "https://registry.example:443".into(),
            host: "registry.example".into(),
            port: 443,
            addresses: vec![
                "192.0.2.10".parse().unwrap(),
                "2001:db8::10".parse().unwrap(),
            ],
        };
        let mut policy = policy();
        policy.network_endpoints = vec![endpoint.clone()];
        policy.digest = policy.recompute_digest().unwrap();
        policy.verify().unwrap();
        assert!(policy.network_endpoint_allowed("192.0.2.10".parse().unwrap(), 443));
        assert!(!policy.network_endpoint_allowed("192.0.2.11".parse().unwrap(), 443));
        assert!(!policy.network_endpoint_allowed("192.0.2.10".parse().unwrap(), 80));

        let mut invalid = endpoint.clone();
        invalid.origin = "https://registry.example:444".into();
        let mut drift = policy.clone();
        drift.network_endpoints = vec![invalid];
        drift.digest = drift.recompute_digest().unwrap();
        assert!(matches!(
            drift.verify(),
            Err(LandlockLauncherError::InvalidPathSet)
        ));
        let mut duplicate = policy;
        duplicate.network_endpoints[0].addresses =
            vec!["192.0.2.10".parse().unwrap(), "192.0.2.10".parse().unwrap()];
        duplicate.digest = duplicate.recompute_digest().unwrap();
        assert!(matches!(
            duplicate.verify(),
            Err(LandlockLauncherError::InvalidPathSet)
        ));
    }
}
