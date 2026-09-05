use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd as _, OwnedFd},
        unix::process::CommandExt as _,
    },
    path::{Component, Path},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use rust_agent_composition::canonical;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    LandlockExecutionPolicy, LinuxSandboxAnonymousSocketpair, LinuxSandboxNetworkPolicy,
    ProductionInputFileRole, ProductionInputIdentityError, ProductionInputTreeRole,
    ProductionToolIdentity, SeccompExecutedCommand, SeccompExecutionReport,
    SnapshotMaterializationError, VerifiedCargoFetchCache, VerifiedHostClosureSnapshot,
    VerifiedProductionInputs,
    fetch_cache::CargoFetchCacheError,
    snapshot_materializer::{
        AnchoredFileIdentity, AnchoredTreeIdentity, AnchoredWritableDirectory,
        anchor_file_identity, anchor_tree_identity, anchor_writable_directory,
    },
};

const BACKEND_VERSION_ARGUMENT: &str = "--version";
const LAUNCHER_LOGICAL_PATH: &str = "/rust-agent/backend/launcher";
const LANDLOCK_POLICY_LOGICAL_PATH: &str = "/rust-agent/backend/landlock-policy.json";
const AUDIT_LOGICAL_ROOT: &str = "/rust-agent/backend-audit";
const AUDIT_LOGICAL_PATH: &str = "/rust-agent/backend-audit/execution-report.json";
const AUDIT_FILE_NAME: &str = "execution-report.json";
const MAX_BACKEND_VERSION_BYTES: usize = 4096;
const MAX_SANDBOX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const TERMINATION_GRACE: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxSandboxBackendIdentity {
    pub schema: u32,
    pub executable: ProductionToolIdentity,
    #[serde(rename = "launcher-executable")]
    pub launcher_executable: ProductionToolIdentity,
    pub runtime: LinuxSandboxRuntimeIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxSandboxRuntimeIdentity {
    pub tree: crate::ProductionTreeIdentity,
    #[serde(rename = "logical-path")]
    pub logical_path: String,
    #[serde(rename = "interpreter-paths")]
    pub interpreter_paths: Vec<String>,
    #[serde(rename = "library-paths")]
    pub library_paths: Vec<String>,
    #[serde(rename = "null-input-path")]
    pub null_input_path: String,
    pub symlinks: Vec<LinuxSandboxRuntimeSymlink>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinuxSandboxMountKind {
    HostClosure,
    CargoCache,
    ToolchainExecutable,
    ToolchainSysroot,
    BuildExecutable,
    FetchTlsCaBundle,
    BuildReadInput,
    NetworkConfiguration,
    RuntimeInput,
    BackendPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxSandboxMountIdentity {
    pub id: String,
    pub kind: LinuxSandboxMountKind,
    #[serde(rename = "logical-path")]
    pub logical_path: String,
    pub digest: String,
    pub executable: bool,
}

#[derive(Debug)]
pub struct LinuxSandboxReadOnlyMount {
    identity: LinuxSandboxMountIdentity,
    descriptor: OwnedFd,
    verifier: ReadOnlyMountVerifier,
}

#[derive(Debug)]
enum ReadOnlyMountVerifier {
    HostClosure(Box<VerifiedHostClosureSnapshot>),
    CargoCache(Box<VerifiedCargoFetchCache>),
    File(Box<AnchoredFileIdentity>),
    Tree(Box<AnchoredTreeIdentity>),
}

#[derive(Debug)]
pub struct LinuxSandboxWritableMount {
    id: String,
    logical_path: String,
    derived_executable_root: bool,
    directory: AnchoredWritableDirectory,
}

impl LinuxSandboxWritableMount {
    pub(crate) fn retained_directory(&self) -> AnchoredWritableDirectory {
        self.directory.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxSandboxRuntimeSymlink {
    pub target: String,
    pub link: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxSandboxCommand {
    pub schema: u32,
    pub executable: String,
    pub arguments: Vec<String>,
    pub environment: BTreeMap<String, String>,
    #[serde(rename = "working-directory")]
    pub working_directory: String,
    #[serde(rename = "allowed-executables")]
    pub allowed_executables: Vec<String>,
    #[serde(rename = "anonymous-socketpairs")]
    pub anonymous_socketpairs: Vec<LinuxSandboxAnonymousSocketpair>,
    #[serde(rename = "read-only-empty-directories")]
    pub read_only_empty_directories: Vec<String>,
    pub network: LinuxSandboxNetworkPolicy,
    #[serde(rename = "timeout-milliseconds")]
    pub timeout_milliseconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxSandboxExecutionObservation {
    pub schema: u32,
    #[serde(rename = "request-digest")]
    pub request_digest: String,
    #[serde(rename = "backend-identity-digest")]
    pub backend_identity_digest: String,
    #[serde(rename = "landlock-policy-digest")]
    pub landlock_policy_digest: String,
    #[serde(rename = "read-only-mounts")]
    pub read_only_mounts: Vec<LinuxSandboxMountIdentity>,
    #[serde(rename = "writable-mounts")]
    pub writable_mounts: Vec<String>,
    #[serde(rename = "canonical-metadata-roots")]
    pub canonical_metadata_roots: Vec<String>,
    pub enforcements: Vec<LinuxSandboxEnforcement>,
    #[serde(rename = "executed-commands")]
    pub executed_commands: Vec<SeccompExecutedCommand>,
    #[serde(rename = "exit-code")]
    pub exit_code: i32,
    #[serde(rename = "stdout-sha256")]
    pub stdout_sha256: String,
    #[serde(rename = "stderr-sha256")]
    pub stderr_sha256: String,
    pub digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinuxSandboxEnforcement {
    AllNamespacesUnshared,
    CanonicalMetadataProjected,
    CapabilitiesDropped,
    DescendantsInheritSandbox,
    EnvironmentCleared,
    ExecveSupervised,
    FilesystemPolicyFullyEnforced,
    NetworkUnshared,
    NetworkEndpointAllowlistEnforced,
    StandardInputDisconnected,
    SyscallFilterEnforced,
}

#[derive(Debug)]
pub struct VerifiedLinuxSandboxBackend {
    identity: LinuxSandboxBackendIdentity,
    backend: AnchoredFileIdentity,
    launcher: AnchoredFileIdentity,
    runtime: AnchoredTreeIdentity,
    digest: String,
}

#[derive(Debug, Error)]
pub enum LinuxSandboxError {
    #[error("unsupported Linux sandbox backend schema {0}; expected 1")]
    UnsupportedSchema(u32),
    #[error("Linux sandbox backend identity is invalid: {0}")]
    InvalidBackendIdentity(&'static str),
    #[error("Linux sandbox backend or launcher digest differs from policy")]
    BackendDigestMismatch,
    #[error("Linux sandbox backend or launcher version differs from policy")]
    BackendVersionMismatch,
    #[error("Linux sandbox request is malformed: {0}")]
    InvalidRequest(&'static str),
    #[error("Linux sandbox mount identities overlap or are duplicated")]
    MountConflict,
    #[error("Linux sandbox process timed out after {0} milliseconds")]
    TimedOut(u64),
    #[error("Linux sandbox output stream `{stream}` exceeds {maximum} bytes")]
    OutputTooLarge {
        stream: &'static str,
        maximum: usize,
    },
    #[error("Linux sandbox child cleanup failed")]
    CleanupFailed,
    #[error("Linux sandbox execution report is invalid: {0}")]
    InvalidExecutionReport(String),
    #[error(
        "Linux sandbox launcher exited without an execution report (code {exit_code}): {diagnostic}"
    )]
    LauncherFailed { exit_code: i32, diagnostic: String },
    #[error("Linux sandbox I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("Linux sandbox snapshot verification failed: {0}")]
    Snapshot(#[from] SnapshotMaterializationError),
    #[error("Linux sandbox production input verification failed: {0}")]
    ProductionInput(#[from] ProductionInputIdentityError),
    #[error("Linux sandbox Cargo cache verification failed: {0}")]
    CargoCache(#[from] CargoFetchCacheError),
    #[error("Linux sandbox Landlock policy failed: {0}")]
    Landlock(#[from] crate::LandlockLauncherError),
    #[error("canonical Linux sandbox encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
}

#[derive(Serialize)]
struct ExecutionRequestProjection<'a> {
    schema: u32,
    backend_identity_digest: &'a str,
    command: &'a LinuxSandboxCommand,
    read_only_mounts: &'a [LinuxSandboxMountIdentity],
    writable_mounts: &'a [WritableMountProjection<'a>],
    landlock_policy_digest: &'a str,
}

#[derive(Serialize)]
struct WritableMountProjection<'a> {
    id: &'a str,
    logical_path: &'a str,
    derived_executable_root: bool,
}

#[derive(Serialize)]
struct ObservationProjection<'a> {
    schema: u32,
    request_digest: &'a str,
    backend_identity_digest: &'a str,
    landlock_policy_digest: &'a str,
    read_only_mounts: &'a [LinuxSandboxMountIdentity],
    writable_mounts: &'a [String],
    canonical_metadata_roots: &'a [String],
    enforcements: &'a [LinuxSandboxEnforcement],
    executed_commands: &'a [SeccompExecutedCommand],
    exit_code: i32,
    stdout_sha256: &'a str,
    stderr_sha256: &'a str,
}

struct ChildOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
pub struct LinuxSandboxCapturedExecution {
    pub(crate) observation: LinuxSandboxExecutionObservation,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

impl LinuxSandboxCapturedExecution {
    pub fn observation(&self) -> &LinuxSandboxExecutionObservation {
        &self.observation
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}

impl VerifiedLinuxSandboxBackend {
    pub fn open(identity: LinuxSandboxBackendIdentity) -> Result<Self, LinuxSandboxError> {
        if identity.schema != 1 {
            return Err(LinuxSandboxError::UnsupportedSchema(identity.schema));
        }
        validate_tool_identity(&identity.executable, "backend")?;
        validate_tool_identity(&identity.launcher_executable, "launcher")?;
        validate_runtime_identity(&identity.runtime)?;
        let backend = anchor_file_identity(&identity.executable.path)?;
        let launcher = anchor_file_identity(&identity.launcher_executable.path)?;
        let runtime = anchor_tree_identity(&identity.runtime.tree.path)?;
        if backend.sha256() != identity.executable.sha256
            || launcher.sha256() != identity.launcher_executable.sha256
            || !backend.is_executable()
            || !backend.is_linux_elf()
            || !launcher.is_executable()
            || !launcher.is_linux_elf()
        {
            return Err(LinuxSandboxError::BackendDigestMismatch);
        }
        if runtime.digest() != identity.runtime.tree.tree_digest {
            return Err(LinuxSandboxError::BackendDigestMismatch);
        }
        let null_input = Path::new(&identity.runtime.null_input_path)
            .strip_prefix(&identity.runtime.logical_path)
            .ok()
            .and_then(Path::to_str)
            .ok_or(LinuxSandboxError::InvalidBackendIdentity(
                "runtime null input",
            ))?;
        if !runtime.read_file(null_input, 1)?.is_empty() {
            return Err(LinuxSandboxError::InvalidBackendIdentity(
                "runtime null input",
            ));
        }
        verify_version(&backend, &identity.executable.version)?;
        verify_version(&launcher, &identity.launcher_executable.version)?;
        let digest = hex::encode(canonical::domain_hash(
            b"rust-agent-linux-sandbox-backend-identity-v1\0",
            &identity,
        )?);
        Ok(Self {
            identity,
            backend,
            launcher,
            runtime,
            digest,
        })
    }

    pub fn identity_digest(&self) -> &str {
        &self.digest
    }

    pub fn identity(&self) -> &LinuxSandboxBackendIdentity {
        &self.identity
    }

    pub fn verify_unchanged(&self) -> Result<(), LinuxSandboxError> {
        self.backend.reverify()?;
        self.launcher.reverify()?;
        self.runtime.reverify()?;
        Ok(())
    }

    pub fn run(
        &self,
        command: &LinuxSandboxCommand,
        read_only_mounts: Vec<LinuxSandboxReadOnlyMount>,
        writable_mounts: Vec<LinuxSandboxWritableMount>,
    ) -> Result<LinuxSandboxExecutionObservation, LinuxSandboxError> {
        Ok(self
            .run_with_output(command, read_only_mounts, writable_mounts)?
            .observation)
    }

    pub fn run_with_output(
        &self,
        command: &LinuxSandboxCommand,
        mut read_only_mounts: Vec<LinuxSandboxReadOnlyMount>,
        mut writable_mounts: Vec<LinuxSandboxWritableMount>,
    ) -> Result<LinuxSandboxCapturedExecution, LinuxSandboxError> {
        self.verify_unchanged()?;
        command.validate()?;
        read_only_mounts.push(self.runtime_mount()?);
        read_only_mounts.sort_by(|left, right| left.identity.cmp(&right.identity));
        writable_mounts.sort_by(|left, right| {
            (left.logical_path.as_str(), left.id.as_str())
                .cmp(&(right.logical_path.as_str(), right.id.as_str()))
        });
        validate_mounts(
            &read_only_mounts,
            &writable_mounts,
            &command.read_only_empty_directories,
        )?;
        validate_allowed_executables(command, &read_only_mounts, &writable_mounts)?;
        for mount in &read_only_mounts {
            mount.verify_source()?;
        }

        let read_only_identities = read_only_mounts
            .iter()
            .map(|mount| mount.identity.clone())
            .collect::<Vec<_>>();
        let writable_projection = writable_mounts
            .iter()
            .map(|mount| WritableMountProjection {
                id: &mount.id,
                logical_path: &mount.logical_path,
                derived_executable_root: mount.derived_executable_root,
            })
            .collect::<Vec<_>>();
        let writable_paths = writable_mounts
            .iter()
            .map(|mount| mount.logical_path.clone())
            .collect::<Vec<_>>();
        let canonical_metadata_roots = read_only_identities
            .iter()
            .filter(|mount| {
                matches!(
                    mount.kind,
                    LinuxSandboxMountKind::HostClosure
                        | LinuxSandboxMountKind::CargoCache
                        | LinuxSandboxMountKind::ToolchainSysroot
                        | LinuxSandboxMountKind::BuildReadInput
                )
            })
            .map(|mount| mount.logical_path.clone())
            .chain(command.read_only_empty_directories.iter().cloned())
            .collect();
        let landlock_policy = LandlockExecutionPolicy::new(
            read_only_identities
                .iter()
                .map(|mount| mount.logical_path.clone())
                .chain(
                    self.identity
                        .runtime
                        .symlinks
                        .iter()
                        .map(|symlink| symlink.link.clone()),
                )
                .chain(command.read_only_empty_directories.iter().cloned())
                .chain([LANDLOCK_POLICY_LOGICAL_PATH.into()])
                .collect(),
            writable_paths.clone(),
            command.allowed_executables.clone(),
            self.identity.runtime.interpreter_paths.clone(),
            canonical_metadata_roots,
            writable_mounts
                .iter()
                .filter(|mount| mount.derived_executable_root)
                .map(|mount| mount.logical_path.clone())
                .collect(),
            command.network.endpoints().to_vec(),
            command.anonymous_socketpairs.clone(),
        )?;
        if !landlock_policy.command_allowed(Path::new(&command.executable)) {
            return Err(LinuxSandboxError::InvalidRequest(
                "command executable is not allowed",
            ));
        }
        let request_digest = hex::encode(canonical::domain_hash(
            b"rust-agent-linux-sandbox-execution-request-v3\0",
            &ExecutionRequestProjection {
                schema: 3,
                backend_identity_digest: &self.digest,
                command,
                read_only_mounts: &read_only_identities,
                writable_mounts: &writable_projection,
                landlock_policy_digest: &landlock_policy.digest,
            },
        )?);

        let mut policy_file = tempfile::tempfile()?;
        policy_file.write_all(&canonical::jcs_bytes(&landlock_policy)?)?;
        policy_file.flush()?;
        policy_file.seek(SeekFrom::Start(0))?;
        let policy_descriptor = rustix::io::dup(&policy_file).map_err(rustix_error)?;
        let launcher_descriptor = self.launcher.duplicate_mount_descriptor()?;
        let audit_directory = tempfile::tempdir()?;
        let audit_mount = anchor_writable_directory(audit_directory.path())?;
        let audit_descriptor = audit_mount.duplicate_mount_descriptor()?;

        let mut sandbox = Command::new(self.backend.descriptor_execution_path());
        sandbox.args([
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--hostname",
            "rust-agent-build",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--proc",
            "/proc",
        ]);
        if command.network.shares_host_network() {
            sandbox.arg("--share-net");
        }
        for directory in mount_parent_directories(
            read_only_mounts
                .iter()
                .map(|mount| mount.identity.logical_path.as_str())
                .chain(
                    writable_mounts
                        .iter()
                        .map(|mount| mount.logical_path.as_str()),
                )
                .chain([
                    LAUNCHER_LOGICAL_PATH,
                    LANDLOCK_POLICY_LOGICAL_PATH,
                    AUDIT_LOGICAL_PATH,
                    command.working_directory.as_str(),
                ])
                .chain(
                    command
                        .read_only_empty_directories
                        .iter()
                        .map(String::as_str),
                )
                .chain(
                    self.identity
                        .runtime
                        .symlinks
                        .iter()
                        .map(|symlink| symlink.link.as_str()),
                ),
        ) {
            sandbox.args(["--dir", &directory]);
        }
        for directory in &command.read_only_empty_directories {
            sandbox.args(["--tmpfs", directory]);
        }
        sandbox.args([
            "--ro-bind-data",
            &policy_descriptor.as_raw_fd().to_string(),
            LANDLOCK_POLICY_LOGICAL_PATH,
            "--ro-bind-fd",
            &launcher_descriptor.as_raw_fd().to_string(),
            LAUNCHER_LOGICAL_PATH,
        ]);
        sandbox.args([
            "--bind-fd",
            &audit_descriptor.as_raw_fd().to_string(),
            AUDIT_LOGICAL_ROOT,
        ]);
        let mut mount_order = read_only_mounts.iter().collect::<Vec<_>>();
        mount_order.sort_by(|left, right| {
            logical_mount_order(&left.identity.logical_path, &right.identity.logical_path)
                .then_with(|| left.identity.cmp(&right.identity))
        });
        for mount in mount_order {
            sandbox.args([
                "--ro-bind-fd",
                &mount.descriptor.as_raw_fd().to_string(),
                &mount.identity.logical_path,
            ]);
        }
        let mut writable_descriptors = Vec::with_capacity(writable_mounts.len());
        for mount in &writable_mounts {
            let descriptor = mount.directory.duplicate_mount_descriptor()?;
            sandbox.args([
                "--bind-fd",
                &descriptor.as_raw_fd().to_string(),
                &mount.logical_path,
            ]);
            writable_descriptors.push(descriptor);
        }
        for symlink in &self.identity.runtime.symlinks {
            sandbox.args(["--symlink", &symlink.target, &symlink.link]);
        }
        if !self.identity.runtime.library_paths.is_empty() {
            sandbox.args([
                "--setenv",
                "LD_LIBRARY_PATH",
                &self.identity.runtime.library_paths.join(":"),
            ]);
        }
        for (variable, value) in &command.environment {
            sandbox.args(["--setenv", variable, value]);
        }
        sandbox.args(["--chdir", &command.working_directory, "--"]);
        sandbox.args([
            LAUNCHER_LOGICAL_PATH,
            "--audit",
            AUDIT_LOGICAL_PATH,
            "--policy",
            LANDLOCK_POLICY_LOGICAL_PATH,
            "--",
            &command.executable,
        ]);
        sandbox.args(&command.arguments);
        sandbox
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let output =
            run_child_bounded(sandbox, Duration::from_millis(command.timeout_milliseconds))?;

        audit_mount.verify_path_identity()?;
        if !audit_directory.path().join(AUDIT_FILE_NAME).is_file() {
            return Err(LinuxSandboxError::LauncherFailed {
                exit_code: output.status.code().unwrap_or(-1),
                diagnostic: format!(
                    "stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                ),
            });
        }
        let audit_tree = anchor_tree_identity(audit_directory.path())?;
        let audit_bytes = audit_tree.read_file(AUDIT_FILE_NAME, MAX_SANDBOX_OUTPUT_BYTES)?;
        let audit = SeccompExecutionReport::from_json(&audit_bytes)
            .map_err(|error| LinuxSandboxError::InvalidExecutionReport(error.to_string()))?;

        for mount in &writable_mounts {
            mount.directory.verify_path_identity()?;
        }
        for mount in &read_only_mounts {
            mount.verify_source()?;
        }
        self.verify_unchanged()?;
        let stdout_sha256 = sha256_bytes(&output.stdout);
        let stderr_sha256 = sha256_bytes(&output.stderr);
        let exit_code = output.status.code().unwrap_or(-1);
        audit
            .verify(&landlock_policy, exit_code)
            .map_err(|error| LinuxSandboxError::InvalidExecutionReport(error.to_string()))?;
        let expected_arguments = std::iter::once(command.executable.clone())
            .chain(command.arguments.iter().cloned())
            .collect::<Vec<_>>();
        if audit.executions.first().is_none_or(|execution| {
            execution.executable != command.executable
                || execution.arguments != expected_arguments
                || execution.working_directory != command.working_directory
        }) {
            return Err(LinuxSandboxError::InvalidExecutionReport(
                "initial command does not match the request".into(),
            ));
        }
        let mut observation = LinuxSandboxExecutionObservation {
            schema: 3,
            request_digest,
            backend_identity_digest: self.digest.clone(),
            landlock_policy_digest: landlock_policy.digest.clone(),
            read_only_mounts: read_only_identities,
            writable_mounts: writable_paths,
            canonical_metadata_roots: landlock_policy.canonical_metadata_roots,
            enforcements: vec![
                LinuxSandboxEnforcement::AllNamespacesUnshared,
                LinuxSandboxEnforcement::CanonicalMetadataProjected,
                LinuxSandboxEnforcement::CapabilitiesDropped,
                LinuxSandboxEnforcement::DescendantsInheritSandbox,
                LinuxSandboxEnforcement::EnvironmentCleared,
                LinuxSandboxEnforcement::ExecveSupervised,
                LinuxSandboxEnforcement::FilesystemPolicyFullyEnforced,
                if command.network.shares_host_network() {
                    LinuxSandboxEnforcement::NetworkEndpointAllowlistEnforced
                } else {
                    LinuxSandboxEnforcement::NetworkUnshared
                },
                LinuxSandboxEnforcement::StandardInputDisconnected,
                LinuxSandboxEnforcement::SyscallFilterEnforced,
            ],
            executed_commands: audit.executions,
            exit_code,
            stdout_sha256,
            stderr_sha256,
            digest: String::new(),
        };
        observation.digest = observation.recompute_digest()?;
        Ok(LinuxSandboxCapturedExecution {
            observation,
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    fn runtime_mount(&self) -> Result<LinuxSandboxReadOnlyMount, LinuxSandboxError> {
        Ok(LinuxSandboxReadOnlyMount {
            identity: LinuxSandboxMountIdentity {
                id: "system-runtime".into(),
                kind: LinuxSandboxMountKind::RuntimeInput,
                logical_path: self.identity.runtime.logical_path.clone(),
                digest: self.identity.runtime.tree.tree_digest.clone(),
                executable: false,
            },
            descriptor: self.runtime.duplicate_mount_descriptor()?,
            verifier: ReadOnlyMountVerifier::Tree(Box::new(self.runtime.clone())),
        })
    }
}

impl LinuxSandboxReadOnlyMount {
    pub fn host_closure(snapshot: &VerifiedHostClosureSnapshot) -> Result<Self, LinuxSandboxError> {
        Ok(Self {
            identity: LinuxSandboxMountIdentity {
                id: "host-closure".into(),
                kind: LinuxSandboxMountKind::HostClosure,
                logical_path: "/rust-agent/closure".into(),
                digest: snapshot.manifest().digest().into(),
                executable: false,
            },
            descriptor: snapshot.duplicate_mount_descriptor()?,
            verifier: ReadOnlyMountVerifier::HostClosure(Box::new(snapshot.clone())),
        })
    }

    pub fn cargo_cache(cache: &VerifiedCargoFetchCache) -> Result<Self, LinuxSandboxError> {
        Ok(Self {
            identity: LinuxSandboxMountIdentity {
                id: "cargo-cache".into(),
                kind: LinuxSandboxMountKind::CargoCache,
                logical_path: "/rust-agent/cargo-home".into(),
                digest: cache.manifest().digest.clone(),
                executable: false,
            },
            descriptor: cache.duplicate_mount_descriptor()?,
            verifier: ReadOnlyMountVerifier::CargoCache(Box::new(cache.clone())),
        })
    }

    pub fn production_inputs(
        inputs: &VerifiedProductionInputs,
    ) -> Result<Vec<Self>, LinuxSandboxError> {
        let mut mounts = Vec::new();
        for file in &inputs.request().files {
            let (kind, logical_path) = match file.role {
                ProductionInputFileRole::Cargo | ProductionInputFileRole::Rustc => (
                    LinuxSandboxMountKind::ToolchainExecutable,
                    format!("/rust-agent/toolchain/bin/{}", file.id),
                ),
                ProductionInputFileRole::CredentialHelper => (
                    LinuxSandboxMountKind::BuildExecutable,
                    "/rust-agent/fetch-tools/credential-helper".into(),
                ),
                ProductionInputFileRole::FetchTlsCaBundle => (
                    LinuxSandboxMountKind::FetchTlsCaBundle,
                    "/rust-agent/fetch-inputs/ca-bundle.pem".into(),
                ),
                ProductionInputFileRole::BuildExecutable
                | ProductionInputFileRole::HostLinker
                | ProductionInputFileRole::HostLinkerHelper => (
                    LinuxSandboxMountKind::BuildExecutable,
                    format!("/rust-agent/tools/{}", file.id),
                ),
            };
            let source = inputs.retained_file_identity(file.role, &file.id)?;
            mounts.push(Self {
                identity: LinuxSandboxMountIdentity {
                    id: file.id.clone(),
                    kind,
                    logical_path,
                    digest: file.sha256.clone(),
                    executable: file.role != ProductionInputFileRole::FetchTlsCaBundle,
                },
                descriptor: source.duplicate_mount_descriptor()?,
                verifier: ReadOnlyMountVerifier::File(Box::new(source)),
            });
        }
        for tree in &inputs.request().trees {
            let (kind, logical_path) = match tree.role {
                ProductionInputTreeRole::RustSysroot => (
                    LinuxSandboxMountKind::ToolchainSysroot,
                    "/rust-agent/toolchain".into(),
                ),
                ProductionInputTreeRole::BuildReadInput => (
                    LinuxSandboxMountKind::BuildReadInput,
                    format!("/rust-agent/inputs/{}", tree.id),
                ),
            };
            let source = inputs.retained_tree_identity(tree.role, &tree.id)?;
            mounts.push(Self {
                identity: LinuxSandboxMountIdentity {
                    id: tree.id.clone(),
                    kind,
                    logical_path,
                    digest: tree.tree_digest.clone(),
                    executable: false,
                },
                descriptor: source.duplicate_mount_descriptor()?,
                verifier: ReadOnlyMountVerifier::Tree(Box::new(source)),
            });
        }
        Ok(mounts)
    }

    pub fn identity(&self) -> &LinuxSandboxMountIdentity {
        &self.identity
    }

    pub fn verified_file(
        id: impl Into<String>,
        kind: LinuxSandboxMountKind,
        path: &Path,
        logical_path: impl Into<String>,
        expected_sha256: &str,
        executable: bool,
    ) -> Result<Self, LinuxSandboxError> {
        let source = anchor_file_identity(path)?;
        if source.sha256() != expected_sha256
            || executable && (!source.is_executable() || !source.is_linux_elf())
        {
            return Err(LinuxSandboxError::BackendDigestMismatch);
        }
        Ok(Self {
            identity: LinuxSandboxMountIdentity {
                id: id.into(),
                kind,
                logical_path: logical_path.into(),
                digest: expected_sha256.into(),
                executable,
            },
            descriptor: source.duplicate_mount_descriptor()?,
            verifier: ReadOnlyMountVerifier::File(Box::new(source)),
        })
    }

    pub(crate) fn verified_anchored_file(
        id: impl Into<String>,
        kind: LinuxSandboxMountKind,
        source: &AnchoredFileIdentity,
        logical_path: impl Into<String>,
        expected_sha256: &str,
        executable: bool,
    ) -> Result<Self, LinuxSandboxError> {
        source.reverify()?;
        if source.sha256() != expected_sha256
            || executable && (!source.is_executable() || !source.is_linux_elf())
        {
            return Err(LinuxSandboxError::BackendDigestMismatch);
        }
        let source = source.clone();
        Ok(Self {
            identity: LinuxSandboxMountIdentity {
                id: id.into(),
                kind,
                logical_path: logical_path.into(),
                digest: expected_sha256.into(),
                executable,
            },
            descriptor: source.duplicate_mount_descriptor()?,
            verifier: ReadOnlyMountVerifier::File(Box::new(source)),
        })
    }

    pub fn verified_tree(
        id: impl Into<String>,
        kind: LinuxSandboxMountKind,
        path: &Path,
        logical_path: impl Into<String>,
        expected_tree_digest: &str,
    ) -> Result<Self, LinuxSandboxError> {
        let source = anchor_tree_identity(path)?;
        if source.digest() != expected_tree_digest {
            return Err(LinuxSandboxError::BackendDigestMismatch);
        }
        Ok(Self {
            identity: LinuxSandboxMountIdentity {
                id: id.into(),
                kind,
                logical_path: logical_path.into(),
                digest: expected_tree_digest.into(),
                executable: false,
            },
            descriptor: source.duplicate_mount_descriptor()?,
            verifier: ReadOnlyMountVerifier::Tree(Box::new(source)),
        })
    }

    fn verify_source(&self) -> Result<(), LinuxSandboxError> {
        match &self.verifier {
            ReadOnlyMountVerifier::HostClosure(snapshot) => snapshot.verify_unchanged()?,
            ReadOnlyMountVerifier::CargoCache(cache) => cache.verify_unchanged()?,
            ReadOnlyMountVerifier::File(file) => file.reverify()?,
            ReadOnlyMountVerifier::Tree(tree) => tree.reverify()?,
        }
        Ok(())
    }
}

impl LinuxSandboxWritableMount {
    pub fn open(
        id: impl Into<String>,
        path: &Path,
        logical_path: impl Into<String>,
        derived_executable_root: bool,
    ) -> Result<Self, LinuxSandboxError> {
        let id = id.into();
        let logical_path = logical_path.into();
        if id.is_empty() || !is_normalized_absolute_path(&logical_path) || logical_path == "/" {
            return Err(LinuxSandboxError::InvalidRequest("writable mount"));
        }
        Ok(Self {
            id,
            logical_path,
            derived_executable_root,
            directory: anchor_writable_directory(path)?,
        })
    }
}

impl LinuxSandboxCommand {
    fn validate(&self) -> Result<(), LinuxSandboxError> {
        let valid_environment = self.environment.iter().all(|(key, value)| {
            !key.is_empty()
                && key.bytes().enumerate().all(|(index, byte)| {
                    byte == b'_'
                        || byte.is_ascii_uppercase()
                        || (index > 0 && byte.is_ascii_digit())
                })
                && !value.contains('\0')
        });
        let valid = self.schema == 3
            && is_normalized_absolute_path(&self.executable)
            && is_normalized_absolute_path(&self.working_directory)
            && self.timeout_milliseconds > 0
            && valid_environment
            && !self.environment.contains_key("LD_LIBRARY_PATH")
            && sorted_unique(&self.allowed_executables)
            && self
                .anonymous_socketpairs
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && sorted_unique_or_empty(&self.read_only_empty_directories)
            && self.network.validate()
            && self
                .allowed_executables
                .iter()
                .all(|path| is_normalized_absolute_path(path));
        if valid {
            Ok(())
        } else if self.schema != 3 {
            Err(LinuxSandboxError::UnsupportedSchema(self.schema))
        } else {
            Err(LinuxSandboxError::InvalidRequest("command"))
        }
    }
}

impl LinuxSandboxExecutionObservation {
    fn recompute_digest(&self) -> Result<String, LinuxSandboxError> {
        Ok(hex::encode(canonical::domain_hash(
            b"rust-agent-linux-sandbox-execution-observation-v3\0",
            &ObservationProjection {
                schema: self.schema,
                request_digest: &self.request_digest,
                backend_identity_digest: &self.backend_identity_digest,
                landlock_policy_digest: &self.landlock_policy_digest,
                read_only_mounts: &self.read_only_mounts,
                writable_mounts: &self.writable_mounts,
                canonical_metadata_roots: &self.canonical_metadata_roots,
                enforcements: &self.enforcements,
                executed_commands: &self.executed_commands,
                exit_code: self.exit_code,
                stdout_sha256: &self.stdout_sha256,
                stderr_sha256: &self.stderr_sha256,
            },
        )?))
    }
}

impl LinuxSandboxBackendIdentity {
    pub(crate) fn validate_declaration(&self) -> Result<(), LinuxSandboxError> {
        if self.schema != 1 {
            return Err(LinuxSandboxError::UnsupportedSchema(self.schema));
        }
        validate_tool_identity(&self.executable, "backend executable")?;
        validate_tool_identity(&self.launcher_executable, "launcher executable")?;
        validate_runtime_identity(&self.runtime)
    }
}

fn validate_tool_identity(
    identity: &ProductionToolIdentity,
    kind: &'static str,
) -> Result<(), LinuxSandboxError> {
    if !identity.path.is_absolute()
        || identity.sha256.len() != 64
        || !identity
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || identity.version.is_empty()
        || identity.version.contains(['\0', '\n', '\r'])
    {
        Err(LinuxSandboxError::InvalidBackendIdentity(kind))
    } else {
        Ok(())
    }
}

fn validate_runtime_identity(
    runtime: &LinuxSandboxRuntimeIdentity,
) -> Result<(), LinuxSandboxError> {
    let digest = &runtime.tree.tree_digest;
    let paths_valid = runtime.tree.path.is_absolute()
        && runtime.logical_path == "/rust-agent/runtime"
        && is_normalized_absolute_path(&runtime.null_input_path)
        && runtime
            .null_input_path
            .strip_prefix(&runtime.logical_path)
            .is_some_and(|suffix| suffix.starts_with('/') && suffix.len() > 1)
        && is_digest(digest)
        && sorted_unique(&runtime.interpreter_paths)
        && sorted_unique_or_empty(&runtime.library_paths)
        && sorted_unique_runtime_symlinks(&runtime.symlinks)
        && runtime.symlinks.iter().all(|symlink| {
            is_normalized_absolute_path(&symlink.target)
                && is_normalized_absolute_path(&symlink.link)
                && symlink.link != "/"
                && (symlink.target == runtime.logical_path
                    || symlink
                        .target
                        .strip_prefix(&runtime.logical_path)
                        .is_some_and(|suffix| suffix.starts_with('/'))
                    || symlink.target == "/rust-agent/toolchain"
                    || symlink
                        .target
                        .strip_prefix("/rust-agent/toolchain")
                        .is_some_and(|suffix| suffix.starts_with('/')))
        })
        && runtime
            .symlinks
            .iter()
            .filter(|symlink| symlink.link == "/dev/null")
            .count()
            == 1
        && runtime.symlinks.iter().any(|symlink| {
            symlink.link == "/dev/null" && symlink.target == runtime.null_input_path
        })
        && runtime.symlinks.iter().all(|symlink| {
            symlink.link == "/dev/null"
                || (symlink.link != "/dev" && !symlink.link.starts_with("/dev/"))
        })
        && runtime.interpreter_paths.iter().all(|interpreter| {
            is_normalized_absolute_path(interpreter)
                && runtime.symlinks.iter().any(|symlink| {
                    interpreter == &symlink.link
                        || interpreter
                            .strip_prefix(&symlink.link)
                            .is_some_and(|suffix| suffix.starts_with('/'))
                })
        })
        && runtime.library_paths.iter().all(|path| {
            is_normalized_absolute_path(path)
                && (path == &runtime.logical_path
                    || path
                        .strip_prefix(&runtime.logical_path)
                        .is_some_and(|suffix| suffix.starts_with('/')))
        });
    if paths_valid {
        Ok(())
    } else {
        Err(LinuxSandboxError::InvalidBackendIdentity("runtime"))
    }
}

fn verify_version(
    executable: &AnchoredFileIdentity,
    expected: &str,
) -> Result<(), LinuxSandboxError> {
    let output = Command::new(executable.descriptor_execution_path())
        .arg(BACKEND_VERSION_ARGUMENT)
        .env_clear()
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success()
        || output.stdout.len() > MAX_BACKEND_VERSION_BYTES
        || output.stderr.len() > MAX_BACKEND_VERSION_BYTES
        || String::from_utf8_lossy(&output.stdout).lines().next() != Some(expected)
    {
        Err(LinuxSandboxError::BackendVersionMismatch)
    } else {
        Ok(())
    }
}

fn validate_mounts(
    read_only: &[LinuxSandboxReadOnlyMount],
    writable: &[LinuxSandboxWritableMount],
    read_only_empty_directories: &[String],
) -> Result<(), LinuxSandboxError> {
    let mut paths = BTreeSet::new();
    let valid_read = read_only.iter().all(|mount| {
        is_normalized_absolute_path(&mount.identity.logical_path)
            && mount.identity.logical_path != "/"
            && paths.insert(mount.identity.logical_path.as_str())
    });
    let valid_write = writable.iter().all(|mount| {
        is_normalized_absolute_path(&mount.logical_path)
            && mount.logical_path != "/"
            && paths.insert(mount.logical_path.as_str())
    });
    let valid_empty = read_only_empty_directories.iter().all(|path| {
        is_normalized_absolute_path(path) && path != "/" && paths.insert(path.as_str())
    });
    if valid_read && valid_write && valid_empty {
        Ok(())
    } else {
        Err(LinuxSandboxError::MountConflict)
    }
}

fn validate_allowed_executables(
    command: &LinuxSandboxCommand,
    read_only: &[LinuxSandboxReadOnlyMount],
    writable: &[LinuxSandboxWritableMount],
) -> Result<(), LinuxSandboxError> {
    let mounted = read_only
        .iter()
        .filter(|mount| mount.identity.executable)
        .map(|mount| mount.identity.logical_path.as_str())
        .collect::<BTreeSet<_>>();
    let derived = writable
        .iter()
        .filter(|mount| mount.derived_executable_root)
        .map(|mount| mount.logical_path.as_str())
        .collect::<Vec<_>>();
    let static_set_matches = command
        .allowed_executables
        .iter()
        .all(|executable| mounted.contains(executable.as_str()));
    let command_mounted_or_derived = mounted.contains(command.executable.as_str())
        || derived.iter().any(|root| {
            command.executable == *root
                || command
                    .executable
                    .strip_prefix(root)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        });
    if static_set_matches && command_mounted_or_derived {
        Ok(())
    } else {
        Err(LinuxSandboxError::InvalidRequest(
            "allowed executable is not descriptor-mounted",
        ))
    }
}

fn mount_parent_directories<'a>(paths: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut directories = BTreeSet::new();
    for path in paths {
        let mut parent = Path::new(path).parent();
        while let Some(path) = parent {
            if path != Path::new("/") {
                directories.insert(path.to_string_lossy().into_owned());
            }
            parent = path.parent();
        }
    }
    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by(|left, right| {
        left.matches('/')
            .count()
            .cmp(&right.matches('/').count())
            .then_with(|| left.cmp(right))
    });
    directories
}

fn logical_mount_order(left: &str, right: &str) -> std::cmp::Ordering {
    left.matches('/')
        .count()
        .cmp(&right.matches('/').count())
        .then_with(|| left.cmp(right))
}

fn is_normalized_absolute_path(path: &str) -> bool {
    let path = Path::new(path);
    path.is_absolute()
        && path.components().enumerate().all(|(index, component)| {
            (index == 0 && matches!(component, Component::RootDir))
                || (index > 0 && matches!(component, Component::Normal(_)))
        })
}

fn sorted_unique(values: &[String]) -> bool {
    !values.is_empty() && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn sorted_unique_or_empty(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn sorted_unique_runtime_symlinks(values: &[LinuxSandboxRuntimeSymlink]) -> bool {
    !values.is_empty() && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn run_child_bounded(
    mut command: Command,
    timeout: Duration,
) -> Result<ChildOutput, LinuxSandboxError> {
    let mut child = command.spawn()?;
    let process_group = rustix::process::Pid::from_child(&child);
    let stdout = child.stdout.take().ok_or_else(|| {
        LinuxSandboxError::Io(io::Error::other("sandbox stdout pipe was unavailable"))
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        LinuxSandboxError::Io(io::Error::other("sandbox stderr pipe was unavailable"))
    })?;
    let mut stdout_reader = Some(spawn_reader(stdout, "stdout"));
    let mut stderr_reader = Some(spawn_reader(stderr, "stderr"));
    let started = Instant::now();
    let deadline = started.checked_add(timeout).unwrap_or(started);
    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;
    loop {
        if status.is_none() {
            status = child.try_wait()?;
        }
        collect_reader(&mut stdout_reader, &mut stdout);
        collect_reader(&mut stderr_reader, &mut stderr);
        if status.is_some() && stdout.is_some() && stderr.is_some() {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            let _ =
                rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL);
            if !terminate_and_collect(
                &mut child,
                &mut status,
                &mut stdout_reader,
                &mut stdout,
                &mut stderr_reader,
                &mut stderr,
                now.checked_add(TERMINATION_GRACE).unwrap_or(now),
            ) {
                return Err(LinuxSandboxError::CleanupFailed);
            }
            return Err(LinuxSandboxError::TimedOut(
                u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
            ));
        }
        thread::sleep(deadline.saturating_duration_since(now).min(POLL_INTERVAL));
    }
    Ok(ChildOutput {
        status: status.expect("status checked above"),
        stdout: stdout.expect("stdout checked above")?,
        stderr: stderr.expect("stderr checked above")?,
    })
}

type Reader = thread::JoinHandle<Result<Vec<u8>, LinuxSandboxError>>;

fn spawn_reader(mut stream: impl Read + Send + 'static, name: &'static str) -> Reader {
    thread::spawn(move || {
        let mut output = Vec::new();
        let mut buffer = [0_u8; 8192];
        let mut too_large = false;
        loop {
            let count = stream.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            if !too_large && output.len().saturating_add(count) <= MAX_SANDBOX_OUTPUT_BYTES {
                output.extend_from_slice(&buffer[..count]);
            } else {
                too_large = true;
            }
        }
        if too_large {
            Err(LinuxSandboxError::OutputTooLarge {
                stream: name,
                maximum: MAX_SANDBOX_OUTPUT_BYTES,
            })
        } else {
            Ok(output)
        }
    })
}

fn collect_reader(
    reader: &mut Option<Reader>,
    output: &mut Option<Result<Vec<u8>, LinuxSandboxError>>,
) {
    if reader.as_ref().is_some_and(Reader::is_finished) {
        *output = Some(
            reader
                .take()
                .expect("finished reader is present")
                .join()
                .unwrap_or_else(|_| {
                    Err(LinuxSandboxError::Io(io::Error::other(
                        "sandbox output reader panicked",
                    )))
                }),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn terminate_and_collect(
    child: &mut Child,
    status: &mut Option<ExitStatus>,
    stdout_reader: &mut Option<Reader>,
    stdout: &mut Option<Result<Vec<u8>, LinuxSandboxError>>,
    stderr_reader: &mut Option<Reader>,
    stderr: &mut Option<Result<Vec<u8>, LinuxSandboxError>>,
    deadline: Instant,
) -> bool {
    let _ = child.kill();
    loop {
        if status.is_none()
            && let Ok(observed) = child.try_wait()
        {
            *status = observed;
        }
        collect_reader(stdout_reader, stdout);
        collect_reader(stderr_reader, stderr);
        if status.is_some() && stdout_reader.is_none() && stderr_reader.is_none() {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        thread::sleep(deadline.saturating_duration_since(now).min(POLL_INTERVAL));
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    hex::encode(Sha256::digest(bytes))
}

fn rustix_error(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_and_mount_paths_fail_closed() {
        let command = LinuxSandboxCommand {
            schema: 3,
            executable: "/rust-agent/tools/probe".into(),
            arguments: vec![],
            environment: BTreeMap::from([("LANG".into(), "C.UTF-8".into())]),
            working_directory: "/rust-agent/closure".into(),
            allowed_executables: vec!["/rust-agent/tools/probe".into()],
            anonymous_socketpairs: vec![LinuxSandboxAnonymousSocketpair::StreamWakeup],
            read_only_empty_directories: vec![],
            network: LinuxSandboxNetworkPolicy::Isolated,
            timeout_milliseconds: 1000,
        };
        command.validate().unwrap();
        let mut ambient = command.clone();
        ambient.working_directory = "/rust-agent/../tmp".into();
        assert!(matches!(
            ambient.validate(),
            Err(LinuxSandboxError::InvalidRequest("command"))
        ));
        let mut duplicate = command;
        duplicate
            .allowed_executables
            .push("/rust-agent/tools/probe".into());
        assert!(matches!(
            duplicate.validate(),
            Err(LinuxSandboxError::InvalidRequest("command"))
        ));
    }

    #[test]
    fn mount_parent_creation_is_ordered_and_path_scoped() {
        assert_eq!(
            mount_parent_directories(
                [
                    "/rust-agent/toolchain/bin/cargo",
                    "/rust-agent/closure/Cargo.toml"
                ]
                .into_iter()
            ),
            vec![
                "/rust-agent".to_owned(),
                "/rust-agent/closure".to_owned(),
                "/rust-agent/toolchain".to_owned(),
                "/rust-agent/toolchain/bin".to_owned(),
            ]
        );
    }

    #[test]
    fn toolchain_sysroot_mount_precedes_pinned_executables() {
        let mut paths = vec![
            "/rust-agent/toolchain/bin/rustc",
            "/rust-agent/toolchain/bin/cargo",
            "/rust-agent/toolchain",
        ];
        paths.sort_by(|left, right| logical_mount_order(left, right));
        assert_eq!(
            paths,
            vec![
                "/rust-agent/toolchain",
                "/rust-agent/toolchain/bin/cargo",
                "/rust-agent/toolchain/bin/rustc",
            ]
        );
    }
}
