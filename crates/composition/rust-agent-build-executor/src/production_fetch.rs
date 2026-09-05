use std::{
    fs,
    net::{IpAddr, ToSocketAddrs as _},
    path::Path,
};

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    CargoFetchCacheError, CargoFetchCacheLayout, CargoFetchDescendantExecution, CargoFetchError,
    CargoFetchMode, CargoFetchObservation, LinuxSandboxAnonymousSocketpair, LinuxSandboxCommand,
    LinuxSandboxError, LinuxSandboxExecutionObservation, LinuxSandboxMountKind,
    LinuxSandboxNetworkPolicy, LinuxSandboxReadOnlyMount, LinuxSandboxResolvedEndpoint,
    LinuxSandboxWritableMount, NormalizedCargoFetchRequest, NormalizedLockedSourceClosure,
    ProductionInputFileRole, ProductionInputIdentityError, ProductionInputPreflightScope,
    SnapshotMaterializationError, ValidatedCargoFetchObservation, VerifiedCargoFetchCache,
    VerifiedHostClosureSnapshot, VerifiedLinuxSandboxBackend, VerifiedProductionInputs,
    materialize_cargo_fetch_cache, observe_cargo_fetch_cache, open_verified_cargo_fetch_cache,
};

const LOGICAL_CARGO: &str = "/rust-agent/toolchain/bin/cargo";
const LOGICAL_RUSTC: &str = "/rust-agent/toolchain/bin/rustc";
const LOGICAL_EMPTY_HOME: &str = "/rust-agent/empty-home";
const LOGICAL_FETCH_ROOT: &str = "/rust-agent/fetch-cache-staging";
const FETCH_TIMEOUT_MILLISECONDS: u64 = 10 * 60 * 1000;
const SYNTHETIC_HOST_CONF: &[u8] = b"multi on\n";
const SYNTHETIC_NSSWITCH: &[u8] = b"hosts: files\n";
const SYNTHETIC_RESOLV_CONF: &[u8] = b"";

#[derive(Debug)]
pub struct TrustedCargoFetchResult {
    sandbox_observation: LinuxSandboxExecutionObservation,
    fetch_observation: CargoFetchObservation,
    validated_observation: ValidatedCargoFetchObservation,
    cache: VerifiedCargoFetchCache,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedCargoFetchEndpointResolution {
    endpoints: Vec<LinuxSandboxResolvedEndpoint>,
}

#[derive(Debug, Error)]
pub enum TrustedCargoFetchError {
    #[error("trusted Cargo fetch inputs do not match the normalized request")]
    InputMismatch,
    #[error("Cargo fetch endpoint resolution failed for `{0}`")]
    EndpointResolution(String),
    #[error("Cargo fetch sandbox exited with code {exit_code}: {diagnostic}")]
    SandboxFailed { exit_code: i32, diagnostic: String },
    #[error("Cargo fetch executed a command outside its exact schema-1 allowlist")]
    InvalidExecutionTrace,
    #[error("Cargo fetch staging filesystem is invalid")]
    InvalidStaging,
    #[error("Cargo fetch staging I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Cargo fetch production input verification failed: {0}")]
    ProductionInputs(#[from] ProductionInputIdentityError),
    #[error("Cargo fetch sandbox failed: {0}")]
    Sandbox(#[from] LinuxSandboxError),
    #[error("Cargo fetch observation failed: {0}")]
    Fetch(#[from] CargoFetchError),
    #[error("Cargo fetch cache verification failed: {0}")]
    Cache(#[from] CargoFetchCacheError),
    #[error("Cargo fetch snapshot verification failed: {0}")]
    Snapshot(#[from] SnapshotMaterializationError),
}

impl TrustedCargoFetchResult {
    pub fn sandbox_observation(&self) -> &LinuxSandboxExecutionObservation {
        &self.sandbox_observation
    }

    pub fn fetch_observation(&self) -> &CargoFetchObservation {
        &self.fetch_observation
    }

    pub fn validated_observation(&self) -> &ValidatedCargoFetchObservation {
        &self.validated_observation
    }

    pub fn cache(&self) -> &VerifiedCargoFetchCache {
        &self.cache
    }
}

impl TrustedCargoFetchEndpointResolution {
    pub fn resolve(request: &NormalizedCargoFetchRequest) -> Result<Self, TrustedCargoFetchError> {
        let endpoints = request
            .sandbox()
            .network_endpoints
            .iter()
            .map(|origin| resolve_endpoint(origin))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_outer_resolution(request, endpoints)
    }

    pub fn from_outer_resolution(
        request: &NormalizedCargoFetchRequest,
        mut endpoints: Vec<LinuxSandboxResolvedEndpoint>,
    ) -> Result<Self, TrustedCargoFetchError> {
        for endpoint in &mut endpoints {
            endpoint.addresses.sort();
            endpoint.addresses.dedup();
        }
        endpoints.sort();
        let expected_origins = request
            .sandbox()
            .network_endpoints
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let actual_origins = endpoints
            .iter()
            .map(|endpoint| endpoint.origin.as_str())
            .collect::<Vec<_>>();
        let policy = if request.mode() == CargoFetchMode::Preprovisioned {
            LinuxSandboxNetworkPolicy::Isolated
        } else {
            LinuxSandboxNetworkPolicy::EndpointAllowlist {
                endpoints: endpoints.clone(),
            }
        };
        if actual_origins != expected_origins
            || (request.mode() == CargoFetchMode::Preprovisioned && !endpoints.is_empty())
            || !policy.validate()
        {
            return Err(TrustedCargoFetchError::EndpointResolution(
                "outer resolution does not exactly cover the fetch request".into(),
            ));
        }
        Ok(Self { endpoints })
    }

    pub fn endpoints(&self) -> &[LinuxSandboxResolvedEndpoint] {
        &self.endpoints
    }

    fn verify_request(
        &self,
        request: &NormalizedCargoFetchRequest,
    ) -> Result<(), TrustedCargoFetchError> {
        Self::from_outer_resolution(request, self.endpoints.clone()).map(|_| ())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn execute_trusted_cargo_fetch(
    backend: &VerifiedLinuxSandboxBackend,
    request: &NormalizedCargoFetchRequest,
    locked_sources: &NormalizedLockedSourceClosure,
    closure: &VerifiedHostClosureSnapshot,
    production_inputs: &VerifiedProductionInputs,
    staging: &Path,
    output: &Path,
    layout: &CargoFetchCacheLayout,
) -> Result<TrustedCargoFetchResult, TrustedCargoFetchError> {
    verify_inputs(request, locked_sources, closure, production_inputs)?;
    let resolution = TrustedCargoFetchEndpointResolution::resolve(request)?;
    execute_preverified_trusted_cargo_fetch(
        backend,
        request,
        locked_sources,
        closure,
        production_inputs,
        &resolution,
        staging,
        output,
        layout,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execute_trusted_cargo_fetch_with_endpoint_resolution(
    backend: &VerifiedLinuxSandboxBackend,
    request: &NormalizedCargoFetchRequest,
    locked_sources: &NormalizedLockedSourceClosure,
    closure: &VerifiedHostClosureSnapshot,
    production_inputs: &VerifiedProductionInputs,
    resolution: &TrustedCargoFetchEndpointResolution,
    staging: &Path,
    output: &Path,
    layout: &CargoFetchCacheLayout,
) -> Result<TrustedCargoFetchResult, TrustedCargoFetchError> {
    verify_inputs(request, locked_sources, closure, production_inputs)?;
    resolution.verify_request(request)?;
    execute_preverified_trusted_cargo_fetch(
        backend,
        request,
        locked_sources,
        closure,
        production_inputs,
        resolution,
        staging,
        output,
        layout,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_preverified_trusted_cargo_fetch(
    backend: &VerifiedLinuxSandboxBackend,
    request: &NormalizedCargoFetchRequest,
    locked_sources: &NormalizedLockedSourceClosure,
    closure: &VerifiedHostClosureSnapshot,
    production_inputs: &VerifiedProductionInputs,
    resolution: &TrustedCargoFetchEndpointResolution,
    staging: &Path,
    output: &Path,
    layout: &CargoFetchCacheLayout,
) -> Result<TrustedCargoFetchResult, TrustedCargoFetchError> {
    prepare_staging(staging)?;
    let mut read_only_mounts = vec![LinuxSandboxReadOnlyMount::host_closure(closure)?];
    read_only_mounts.extend(LinuxSandboxReadOnlyMount::production_inputs(
        production_inputs,
    )?);
    let network_evidence = prepare_network_evidence(request, resolution)?;
    read_only_mounts.extend(network_evidence.read_only_mounts);
    let writable_mount =
        LinuxSandboxWritableMount::open("fetch-cache-staging", staging, LOGICAL_FETCH_ROOT, false)?;
    let mut allowed_executables = vec![LOGICAL_CARGO.into(), LOGICAL_RUSTC.into()];
    if request.sandbox().credential_helper.is_some() {
        allowed_executables.push("/rust-agent/fetch-tools/credential-helper".into());
    }
    allowed_executables.sort();
    let command = LinuxSandboxCommand {
        schema: 3,
        executable: request
            .invocation()
            .executable
            .to_str()
            .ok_or(TrustedCargoFetchError::InputMismatch)?
            .into(),
        arguments: request.invocation().arguments.clone(),
        environment: request.invocation().environment.clone(),
        working_directory: request.invocation().working_directory.clone(),
        allowed_executables,
        anonymous_socketpairs: vec![LinuxSandboxAnonymousSocketpair::StreamWakeup],
        read_only_empty_directories: vec![LOGICAL_EMPTY_HOME.into()],
        network: network_evidence.policy,
        timeout_milliseconds: FETCH_TIMEOUT_MILLISECONDS,
    };
    let execution = backend.run_with_output(&command, read_only_mounts, vec![writable_mount])?;
    let sandbox_observation = execution.observation;
    if sandbox_observation.exit_code != 0 {
        let diagnostic = format!(
            "stdout={} stderr={} executions={:?}",
            String::from_utf8_lossy(&execution.stdout),
            String::from_utf8_lossy(&execution.stderr),
            sandbox_observation.executed_commands,
        );
        return Err(TrustedCargoFetchError::SandboxFailed {
            exit_code: sandbox_observation.exit_code,
            diagnostic,
        });
    }
    let descendant_executions =
        validate_execution_trace(request, production_inputs, &sandbox_observation)?;
    let observed_cache =
        observe_cargo_fetch_cache(&staging.join("cargo-home"), locked_sources, layout)?;
    let fetch_observation = CargoFetchObservation {
        schema: 3,
        request_digest: request.digest().into(),
        sandbox: request.sandbox().clone(),
        cargo_exit_code: sandbox_observation.exit_code,
        descendant_executions,
        fetched_sources: observed_cache.evidence().clone(),
        cache_tree_digest: observed_cache.tree().digest().into(),
    };
    let validated_observation = request.validate_observation(&fetch_observation, locked_sources)?;
    materialize_cargo_fetch_cache(
        &staging.join("cargo-home"),
        output,
        request,
        &validated_observation,
        layout,
    )?;
    let cache = open_verified_cargo_fetch_cache(output, request, &validated_observation)?;
    closure.verify_unchanged()?;
    cache.verify_unchanged()?;
    Ok(TrustedCargoFetchResult {
        sandbox_observation,
        fetch_observation,
        validated_observation,
        cache,
    })
}

struct ResolvedNetworkEvidence {
    _directory: Option<tempfile::TempDir>,
    read_only_mounts: Vec<LinuxSandboxReadOnlyMount>,
    policy: LinuxSandboxNetworkPolicy,
}

fn prepare_network_evidence(
    request: &NormalizedCargoFetchRequest,
    resolution: &TrustedCargoFetchEndpointResolution,
) -> Result<ResolvedNetworkEvidence, TrustedCargoFetchError> {
    if request.mode() == CargoFetchMode::Preprovisioned {
        return Ok(ResolvedNetworkEvidence {
            _directory: None,
            read_only_mounts: Vec::new(),
            policy: LinuxSandboxNetworkPolicy::Isolated,
        });
    }
    resolution.verify_request(request)?;
    let endpoints = resolution.endpoints.clone();
    let directory = tempfile::tempdir()?;
    let hosts = endpoints
        .iter()
        .flat_map(|endpoint| {
            endpoint
                .addresses
                .iter()
                .map(|address| format!("{address}\t{}\n", endpoint.host))
        })
        .collect::<String>();
    let hosts_path = directory.path().join("hosts");
    let host_conf_path = directory.path().join("host.conf");
    let nsswitch_path = directory.path().join("nsswitch.conf");
    let resolv_path = directory.path().join("resolv.conf");
    fs::write(&hosts_path, hosts.as_bytes())?;
    fs::write(&host_conf_path, SYNTHETIC_HOST_CONF)?;
    fs::write(&nsswitch_path, SYNTHETIC_NSSWITCH)?;
    fs::write(&resolv_path, SYNTHETIC_RESOLV_CONF)?;
    let mounts = vec![
        LinuxSandboxReadOnlyMount::verified_file(
            "network-hosts",
            LinuxSandboxMountKind::NetworkConfiguration,
            &hosts_path,
            "/etc/hosts",
            &sha256(hosts.as_bytes()),
            false,
        )?,
        LinuxSandboxReadOnlyMount::verified_file(
            "network-host-conf",
            LinuxSandboxMountKind::NetworkConfiguration,
            &host_conf_path,
            "/etc/host.conf",
            &sha256(SYNTHETIC_HOST_CONF),
            false,
        )?,
        LinuxSandboxReadOnlyMount::verified_file(
            "network-nsswitch",
            LinuxSandboxMountKind::NetworkConfiguration,
            &nsswitch_path,
            "/etc/nsswitch.conf",
            &sha256(SYNTHETIC_NSSWITCH),
            false,
        )?,
        LinuxSandboxReadOnlyMount::verified_file(
            "network-resolv",
            LinuxSandboxMountKind::NetworkConfiguration,
            &resolv_path,
            "/etc/resolv.conf",
            &sha256(SYNTHETIC_RESOLV_CONF),
            false,
        )?,
    ];
    Ok(ResolvedNetworkEvidence {
        _directory: Some(directory),
        read_only_mounts: mounts,
        policy: LinuxSandboxNetworkPolicy::EndpointAllowlist { endpoints },
    })
}

fn resolve_endpoint(origin: &str) -> Result<LinuxSandboxResolvedEndpoint, TrustedCargoFetchError> {
    let authority = origin
        .strip_prefix("https://")
        .ok_or_else(|| TrustedCargoFetchError::EndpointResolution(origin.into()))?;
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| TrustedCargoFetchError::EndpointResolution(origin.into()))?;
        (host, port)
    } else {
        authority
            .rsplit_once(':')
            .ok_or_else(|| TrustedCargoFetchError::EndpointResolution(origin.into()))?
    };
    let port = port
        .parse::<u16>()
        .map_err(|_| TrustedCargoFetchError::EndpointResolution(origin.into()))?;
    let mut addresses = if let Ok(address) = host.parse::<IpAddr>() {
        vec![address]
    } else {
        (host, port)
            .to_socket_addrs()
            .map_err(|_| TrustedCargoFetchError::EndpointResolution(origin.into()))?
            .map(|address| address.ip())
            .collect::<Vec<_>>()
    };
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(TrustedCargoFetchError::EndpointResolution(origin.into()));
    }
    Ok(LinuxSandboxResolvedEndpoint {
        origin: origin.into(),
        host: host.into(),
        port,
        addresses,
    })
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn verify_inputs(
    request: &NormalizedCargoFetchRequest,
    locked_sources: &NormalizedLockedSourceClosure,
    closure: &VerifiedHostClosureSnapshot,
    production_inputs: &VerifiedProductionInputs,
) -> Result<(), TrustedCargoFetchError> {
    let expected_scope = match request.mode() {
        CargoFetchMode::Networked => ProductionInputPreflightScope::NetworkedFetch,
        CargoFetchMode::Preprovisioned => ProductionInputPreflightScope::PreprovisionedFetch,
    };
    if request.locked_source_closure_digest() != locked_sources.digest()
        || request.host_build_input_closure_digest()
            != closure.manifest().host_build_input_closure_digest
        || request.build_execution_policy_digest()
            != production_inputs.request().build_execution_policy_digest
        || production_inputs.request().scope != expected_scope
        || production_inputs
            .request()
            .host_build_input_closure_digest
            .is_some()
        || request.invocation().executable != Path::new(LOGICAL_CARGO)
    {
        return Err(TrustedCargoFetchError::InputMismatch);
    }
    closure.verify_unchanged()?;
    Ok(())
}

fn prepare_staging(staging: &Path) -> Result<(), TrustedCargoFetchError> {
    if !staging.is_absolute() || !staging.is_dir() {
        return Err(TrustedCargoFetchError::InvalidStaging);
    }
    for name in ["cargo-home", "tmp"] {
        let path = staging.join(name);
        if path.exists() {
            if !path.is_dir() || fs::symlink_metadata(&path)?.file_type().is_symlink() {
                return Err(TrustedCargoFetchError::InvalidStaging);
            }
        } else {
            fs::create_dir(&path)?;
        }
    }
    Ok(())
}

fn validate_execution_trace(
    request: &NormalizedCargoFetchRequest,
    inputs: &VerifiedProductionInputs,
    observation: &LinuxSandboxExecutionObservation,
) -> Result<Vec<CargoFetchDescendantExecution>, TrustedCargoFetchError> {
    let cargo_digest = input_digest(inputs, ProductionInputFileRole::Cargo)?;
    let rustc_digest = input_digest(inputs, ProductionInputFileRole::Rustc)?;
    let credential_digest = request
        .sandbox()
        .credential_helper
        .as_ref()
        .map(|_| input_digest(inputs, ProductionInputFileRole::CredentialHelper))
        .transpose()?;
    let Some(root) = observation.executed_commands.first() else {
        return Err(TrustedCargoFetchError::InvalidExecutionTrace);
    };
    let expected_root_arguments = std::iter::once(LOGICAL_CARGO.into())
        .chain(request.invocation().arguments.iter().cloned())
        .collect::<Vec<_>>();
    if root.executable != LOGICAL_CARGO
        || root.executable_sha256 != cargo_digest
        || root.arguments != expected_root_arguments
        || root.working_directory != request.invocation().working_directory
    {
        return Err(TrustedCargoFetchError::InvalidExecutionTrace);
    }
    let mut descendants = Vec::new();
    for execution in &observation.executed_commands[1..] {
        let rustc_arguments = execution.arguments.strip_prefix(&[LOGICAL_RUSTC.into()]);
        if execution.executable == LOGICAL_RUSTC
            && execution.executable_sha256 == rustc_digest
            && rustc_arguments.is_some_and(|arguments| request.allows_rustc_query(arguments))
            && execution.working_directory == request.invocation().working_directory
        {
            descendants.push(CargoFetchDescendantExecution::RustcIdentityQuery {
                executable: LOGICAL_RUSTC.into(),
                arguments: rustc_arguments
                    .expect("validated exact rustc prefix")
                    .to_vec(),
                exit_code: 0,
            });
        } else if credential_digest.is_some_and(|digest| {
            execution.executable == "/rust-agent/fetch-tools/credential-helper"
                && execution.executable_sha256 == digest
                && execution.arguments
                    == [
                        "/rust-agent/fetch-tools/credential-helper",
                        "--cargo-plugin",
                    ]
                && execution.working_directory == request.invocation().working_directory
        }) {
            let endpoint = request
                .sandbox()
                .network_endpoints
                .first()
                .ok_or(TrustedCargoFetchError::InvalidExecutionTrace)?
                .clone();
            descendants.push(CargoFetchDescendantExecution::CredentialHelper {
                executable: "/rust-agent/fetch-tools/credential-helper".into(),
                arguments: vec!["--cargo-plugin".into()],
                endpoint,
                exit_code: 0,
            });
        } else {
            return Err(TrustedCargoFetchError::InvalidExecutionTrace);
        }
    }
    if descendants.is_empty() {
        return Err(TrustedCargoFetchError::InvalidExecutionTrace);
    }
    Ok(descendants)
}

fn input_digest(
    inputs: &VerifiedProductionInputs,
    role: ProductionInputFileRole,
) -> Result<&str, TrustedCargoFetchError> {
    inputs
        .request()
        .files
        .iter()
        .find(|file| file.role == role)
        .map(|file| file.sha256.as_str())
        .ok_or(TrustedCargoFetchError::InputMismatch)
}
