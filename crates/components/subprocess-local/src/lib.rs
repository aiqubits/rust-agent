//! Descriptor-anchored, fail-closed Linux subprocess provider.

mod protocol;

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::fd::{AsRawFd as _, OwnedFd},
    os::unix::process::{CommandExt as _, ExitStatusExt as _},
    path::{Component, Path},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use rust_agent_core::{CanonicalId, Digest, SecurityEffects};
use rust_agent_policy::process::{BackendKind, FilesystemAccess, NetworkAccess};
use rust_agent_process::{
    ConfinedProcessSpec, ConfinementVerifierBinding, EnforcementReport, ProcessControl,
    ProcessError, ProcessExit, ProcessFuture, ProcessHandle, ProcessOutput, Subprocess,
    VerifiedProcessSpec,
};
use rust_agent_runtime_api::{
    CancellationToken, ComponentBuildError, ComponentOutput, Initializable, InitializeError,
    RuntimeFuture, RuntimeInstant, RuntimePrimitiveBindings, RuntimePrimitiveKind, Shutdown,
    ShutdownError,
};
use rustix::{
    fs::{CWD, FileType, Mode, OFlags, ResolveFlags, fstat, openat2},
    io::{Errno, FdFlags, dup, fcntl_setfd},
    process::{Pid, Signal, kill_process_group},
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use protocol::SetupAcknowledgement;

const PROVIDER_KEY: &str = "local";
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const MAX_CONFIG_PATHS: usize = 128;
const MAX_CONFIG_BYTES: usize = 128 * 1024;
const MAX_TRACKED_PROCESSES: usize = 1024;
const SANDBOX_WORKSPACE: &str = "/workspace";
const SANDBOX_LAUNCHER: &str = "/rust-agent/launcher";
const SANDBOX_TARGET: &str = "/rust-agent/target";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSymlink {
    link: String,
    target: String,
}

impl RuntimeSymlink {
    pub fn checked(
        link: impl Into<String>,
        target: impl Into<String>,
    ) -> Result<Self, ComponentBuildError> {
        let value = Self {
            link: link.into(),
            target: target.into(),
        };
        validate_symlink(&value)?;
        Ok(value)
    }

    pub fn link(&self) -> &str {
        &self.link
    }

    pub fn target(&self) -> &str {
        &self.target
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    workspace_root: String,
    bubblewrap_path: String,
    bubblewrap_sha256: String,
    launcher_path: String,
    launcher_sha256: String,
    #[serde(default)]
    runtime_read_paths: Vec<String>,
    #[serde(default)]
    allowed_executables: Vec<String>,
    #[serde(default)]
    runtime_symlinks: Vec<RuntimeSymlink>,
}

impl Config {
    #[allow(clippy::too_many_arguments)]
    pub fn checked(
        workspace_root: impl Into<String>,
        bubblewrap_path: impl Into<String>,
        bubblewrap_sha256: impl Into<String>,
        launcher_path: impl Into<String>,
        launcher_sha256: impl Into<String>,
        runtime_read_paths: Vec<String>,
        allowed_executables: Vec<String>,
        runtime_symlinks: Vec<RuntimeSymlink>,
    ) -> Result<Self, ComponentBuildError> {
        let config = Self {
            workspace_root: workspace_root.into(),
            bubblewrap_path: bubblewrap_path.into(),
            bubblewrap_sha256: bubblewrap_sha256.into(),
            launcher_path: launcher_path.into(),
            launcher_sha256: launcher_sha256.into(),
            runtime_read_paths,
            allowed_executables,
            runtime_symlinks,
        };
        validate_config(&config)?;
        Ok(config)
    }
}

#[derive(Debug)]
pub struct Dependencies {
    pub confinement_verifier: ConfinementVerifierBinding,
}

#[derive(Debug)]
struct AnchoredPath {
    destination: String,
    descriptor: OwnedFd,
}

#[derive(Debug)]
struct PreparedConfig {
    workspace: OwnedFd,
    bubblewrap: OwnedFd,
    launcher: OwnedFd,
    runtime_read_paths: Vec<AnchoredPath>,
    allowed_executables: Vec<AnchoredPath>,
    runtime_symlinks: Vec<RuntimeSymlink>,
}

#[derive(Debug)]
enum PreparationState {
    Uninitialized,
    Initializing,
    Ready(PreparedConfig),
    Closed,
}

#[derive(Debug)]
struct LifecycleState {
    preparation: PreparationState,
    live: Vec<Weak<LocalControl>>,
}

#[derive(Debug)]
pub struct LocalSubprocess {
    confinement_verifier: ConfinementVerifierBinding,
    config: Config,
    lifecycle: Mutex<LifecycleState>,
    runtime: RuntimePrimitiveBindings,
}

impl Subprocess for LocalSubprocess {
    fn provider_key(&self) -> CanonicalId {
        CanonicalId::new(PROVIDER_KEY).expect("static provider key is canonical")
    }

    fn effects(&self) -> SecurityEffects {
        SecurityEffects::READ_LOCAL | SecurityEffects::WRITE_LOCAL | SecurityEffects::PROCESS_EXEC
    }

    fn spawn(
        &self,
        spec: ConfinedProcessSpec,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ProcessHandle, ProcessError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(ProcessError::Cancelled);
            }
            let verified = self.confinement_verifier.verify(spec)?;
            if cancellation.is_cancelled() {
                return Err(ProcessError::Cancelled);
            }
            self.spawn_verified(verified, cancellation).await
        })
    }
}

impl LocalSubprocess {
    async fn spawn_verified(
        &self,
        verified: VerifiedProcessSpec,
        cancellation: CancellationToken,
    ) -> Result<ProcessHandle, ProcessError> {
        if verified.backend_plan().kind() != BackendKind::Linux {
            return Err(ProcessError::UnsupportedPolicy);
        }
        let started = self.runtime.now().map_err(|_| ProcessError::SpawnFailed)?;
        let timeout = Duration::from_millis(
            verified
                .effective_policy()
                .limits()
                .max_wall_time_millis()
                .get(),
        );
        let deadline = started
            .checked_add(timeout)
            .ok_or(ProcessError::UnsupportedPolicy)?;
        let (control, setup_receiver, inherited, argument_file, process_id, output_budget) = {
            let mut lifecycle = self
                .lifecycle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            lifecycle.live.retain(|control| {
                control
                    .upgrade()
                    .is_some_and(|control| control.cached_result().is_none())
            });
            if lifecycle.live.len() >= MAX_TRACKED_PROCESSES {
                return Err(ProcessError::SpawnFailed);
            }
            let config = match &lifecycle.preparation {
                PreparationState::Ready(config) => config,
                PreparationState::Closed => return Err(ProcessError::Cancelled),
                PreparationState::Uninitialized | PreparationState::Initializing => {
                    return Err(ProcessError::SetupFailed);
                }
            };
            validate_cwd(&config.workspace, &verified)?;
            let executable = open_absolute(
                verified.process().executable().as_str(),
                OFlags::RDONLY | OFlags::CLOEXEC,
            )
            .map_err(|_| ProcessError::SpawnFailed)?;
            ensure_executable(&executable).map_err(|_| ProcessError::SpawnFailed)?;

            let mut inherited = Vec::new();
            let bubblewrap =
                inheritable_duplicate(&config.bubblewrap).map_err(|_| ProcessError::SpawnFailed)?;
            let bubblewrap_fd = bubblewrap.as_raw_fd();
            inherited.push(bubblewrap);
            let launcher =
                inheritable_duplicate(&config.launcher).map_err(|_| ProcessError::SpawnFailed)?;
            let launcher_fd = launcher.as_raw_fd();
            inherited.push(launcher);
            let target =
                inheritable_duplicate(&executable).map_err(|_| ProcessError::SpawnFailed)?;
            let target_fd = target.as_raw_fd();
            inherited.push(target);
            let workspace =
                inheritable_duplicate(&config.workspace).map_err(|_| ProcessError::SpawnFailed)?;
            let workspace_fd = workspace.as_raw_fd();
            inherited.push(workspace);

            let mut runtime_descriptors = Vec::with_capacity(config.runtime_read_paths.len());
            for path in &config.runtime_read_paths {
                let descriptor = inheritable_duplicate(&path.descriptor)
                    .map_err(|_| ProcessError::SpawnFailed)?;
                runtime_descriptors.push((descriptor.as_raw_fd(), path.destination.clone()));
                inherited.push(descriptor);
            }

            let mut allowed_executable_descriptors =
                Vec::with_capacity(config.allowed_executables.len());
            for path in &config.allowed_executables {
                let descriptor = inheritable_duplicate(&path.descriptor)
                    .map_err(|_| ProcessError::SpawnFailed)?;
                allowed_executable_descriptors
                    .push((descriptor.as_raw_fd(), path.destination.clone()));
                inherited.push(descriptor);
            }

            let arguments = sandbox_arguments(
                &verified,
                launcher_fd,
                target_fd,
                workspace_fd,
                &runtime_descriptors,
                &allowed_executable_descriptors,
                &config.runtime_symlinks,
            );
            let mut argument_file = tempfile::tempfile().map_err(|_| ProcessError::SpawnFailed)?;
            write_nul_arguments(&mut argument_file, &arguments)
                .map_err(|_| ProcessError::SpawnFailed)?;
            argument_file
                .seek(SeekFrom::Start(0))
                .map_err(|_| ProcessError::SpawnFailed)?;
            let argument_descriptor =
                inheritable_duplicate(&argument_file).map_err(|_| ProcessError::SpawnFailed)?;
            let argument_fd = argument_descriptor.as_raw_fd();
            inherited.push(argument_descriptor);

            let mut command = Command::new(format!("/proc/self/fd/{bubblewrap_fd}"));
            command
                .args(["--args", &argument_fd.to_string()])
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0);
            let mut child = command.spawn().map_err(|_| ProcessError::SpawnFailed)?;
            let process_id = child.id();
            let process_group = Pid::from_child(&child);
            let stdin = child.stdin.take().ok_or(ProcessError::SpawnFailed)?;
            let stdout = child.stdout.take().ok_or(ProcessError::SpawnFailed)?;
            let stderr = child.stderr.take().ok_or(ProcessError::SpawnFailed)?;
            let output_budget = verified
                .effective_policy()
                .limits()
                .max_output_bytes()
                .get();
            let output = Arc::new(OutputState::new(output_budget));
            let (setup_sender, setup_receiver) = mpsc::sync_channel(1);
            let stdout_reader = spawn_stdout_reader(stdout, Arc::clone(&output), setup_sender);
            let stderr_reader = spawn_output_reader(stderr, Arc::clone(&output), Stream::Stderr);
            let stdin_writer = spawn_stdin_writer(stdin, verified.process().stdin().to_vec());
            let control = Arc::new(LocalControl {
                child: Mutex::new(Some(child)),
                process_group,
                output,
                stdout_reader: Mutex::new(Some(stdout_reader)),
                stderr_reader: Mutex::new(Some(stderr_reader)),
                stdin_writer: Mutex::new(Some(stdin_writer)),
                runtime: self.runtime.clone(),
                deadline,
                wait_started: AtomicBool::new(false),
                cleanup: Mutex::new(()),
                completed: Mutex::new(None),
            });
            lifecycle.live.push(Arc::downgrade(&control));
            (
                control,
                setup_receiver,
                inherited,
                argument_file,
                process_id,
                output_budget,
            )
        };

        let setup = wait_for_setup(&control, setup_receiver, &cancellation).await;
        drop(inherited);
        drop(argument_file);
        match setup {
            Ok(acknowledgement)
                if acknowledgement.policy_digest == verified.policy_digest()
                    && acknowledgement
                        .applied_primitives
                        .contains(verified.backend_plan().required_primitives()) =>
            {
                let report = EnforcementReport::after_child_setup(
                    acknowledgement.policy_digest,
                    BackendKind::Linux,
                    acknowledgement.applied_primitives,
                    process_id,
                )?;
                ProcessHandle::from_enforced(report, output_budget, control)
            }
            Ok(_) => {
                control.terminate_blocking();
                Err(ProcessError::InvalidEnforcementReport)
            }
            Err(error) => {
                control.terminate_blocking();
                Err(error)
            }
        }
    }
}

impl Initializable for LocalSubprocess {
    fn initialize(&self) -> RuntimeFuture<'_, Result<(), InitializeError>> {
        Box::pin(async move {
            {
                let mut lifecycle = self
                    .lifecycle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match lifecycle.preparation {
                    PreparationState::Uninitialized => {
                        lifecycle.preparation = PreparationState::Initializing;
                    }
                    PreparationState::Initializing | PreparationState::Ready(_) => {
                        return Err(InitializeError::AlreadyInitialized);
                    }
                    PreparationState::Closed => return Err(InitializeError::ScopeClosed),
                }
            }

            let prepared = prepare_config(&self.config);
            let mut lifecycle = self
                .lifecycle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if matches!(lifecycle.preparation, PreparationState::Closed) {
                return Err(InitializeError::ScopeClosed);
            }
            if let Ok(prepared) = prepared {
                lifecycle.preparation = PreparationState::Ready(prepared);
                Ok(())
            } else {
                lifecycle.preparation = PreparationState::Uninitialized;
                Err(InitializeError::ResourcePreparationFailed)
            }
        })
    }
}

impl Shutdown for LocalSubprocess {
    fn shutdown(&self) -> RuntimeFuture<'_, Result<(), ShutdownError>> {
        Box::pin(async move {
            let controls = {
                let mut lifecycle = self
                    .lifecycle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                lifecycle.preparation = PreparationState::Closed;
                lifecycle
                    .live
                    .drain(..)
                    .filter_map(|control| control.upgrade())
                    .collect::<Vec<_>>()
            };
            let mut failed = false;
            for control in controls {
                if control.terminate_and_reap().is_err() {
                    failed = true;
                }
            }
            if failed {
                Err(ShutdownError::ResourceTeardownFailed)
            } else {
                Ok(())
            }
        })
    }
}

pub fn build(
    config: &Config,
    dependencies: Dependencies,
    runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<LocalSubprocess>, ComponentBuildError> {
    if runtime.allowed() != [RuntimePrimitiveKind::Clock, RuntimePrimitiveKind::Sleep] {
        return Err(ComponentBuildError::InvalidConfig(
            "subprocess-local requires exactly clock and sleeper runtime primitives".into(),
        ));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config, dependencies, runtime);
        return Err(ComponentBuildError::InvalidConfig(
            "subprocess-local is available only on Linux".into(),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        validate_config(config)?;
        Ok(ComponentOutput::initializable(LocalSubprocess {
            confinement_verifier: dependencies.confinement_verifier,
            config: config.clone(),
            lifecycle: Mutex::new(LifecycleState {
                preparation: PreparationState::Uninitialized,
                live: Vec::new(),
            }),
            runtime,
        }))
    }
}

fn prepare_config(config: &Config) -> Result<PreparedConfig, ComponentBuildError> {
    let workspace = open_directory(&config.workspace_root)?;
    let bubblewrap = open_verified_executable(
        &config.bubblewrap_path,
        &config.bubblewrap_sha256,
        "bubblewrap",
    )?;
    let launcher =
        open_verified_executable(&config.launcher_path, &config.launcher_sha256, "launcher")?;
    let runtime_read_paths = config
        .runtime_read_paths
        .iter()
        .map(|path| {
            Ok(AnchoredPath {
                destination: path.clone(),
                descriptor: open_absolute(path, OFlags::PATH | OFlags::CLOEXEC)
                    .map_err(|_| invalid_config("runtime read path could not be anchored"))?,
            })
        })
        .collect::<Result<Vec<_>, ComponentBuildError>>()?;
    Ok(PreparedConfig {
        workspace,
        bubblewrap,
        launcher,
        runtime_read_paths,
        allowed_executables: config
            .allowed_executables
            .iter()
            .map(|path| {
                let descriptor = open_absolute(path, OFlags::RDONLY | OFlags::CLOEXEC)
                    .map_err(|_| invalid_config("allowed executable could not be anchored"))?;
                ensure_executable(&descriptor)
                    .map_err(|_| invalid_config("allowed executable is not a regular file"))?;
                Ok(AnchoredPath {
                    destination: path.clone(),
                    descriptor,
                })
            })
            .collect::<Result<Vec<_>, ComponentBuildError>>()?,
        runtime_symlinks: config.runtime_symlinks.clone(),
    })
}

async fn wait_for_setup(
    control: &LocalControl,
    receiver: mpsc::Receiver<Result<SetupAcknowledgement, ()>>,
    cancellation: &CancellationToken,
) -> Result<SetupAcknowledgement, ProcessError> {
    loop {
        if cancellation.is_cancelled() {
            control.output.record_cause(FirstCause::Cancelled);
        }
        let now = control
            .runtime
            .now()
            .map_err(|_| ProcessError::WaitFailed)?;
        if now >= control.deadline {
            control.output.record_cause(FirstCause::Deadline);
        }
        if let Some(error) = control.output.first_error() {
            return Err(error);
        }
        match receiver.try_recv() {
            Ok(Ok(acknowledgement)) => return Ok(acknowledgement),
            Ok(Err(())) | Err(mpsc::TryRecvError::Disconnected) => {
                return Err(ProcessError::SetupFailed);
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if control.child_exited()? {
            return Err(ProcessError::SetupFailed);
        }
        let next = (now + POLL_INTERVAL).min(control.deadline);
        control
            .runtime
            .sleep_until(next)
            .map_err(|_| ProcessError::WaitFailed)?
            .await;
    }
}

#[derive(Clone, Copy)]
enum Stream {
    Stdout,
    Stderr,
}

#[derive(Debug)]
struct CapturedOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    remaining: usize,
    exceeded: bool,
}

#[derive(Debug)]
struct OutputState {
    captured: Mutex<CapturedOutput>,
    first_cause: AtomicU8,
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum FirstCause {
    Cancelled = 1,
    Deadline = 2,
    Output = 3,
}

impl OutputState {
    fn new(budget: usize) -> Self {
        Self {
            captured: Mutex::new(CapturedOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
                remaining: budget,
                exceeded: false,
            }),
            first_cause: AtomicU8::new(0),
        }
    }

    fn push(&self, stream: Stream, bytes: &[u8]) {
        let mut state = self
            .captured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.exceeded {
            return;
        }
        if bytes.len() > state.remaining {
            state.exceeded = true;
            drop(state);
            self.record_cause(FirstCause::Output);
            return;
        }
        state.remaining -= bytes.len();
        match stream {
            Stream::Stdout => state.stdout.extend_from_slice(bytes),
            Stream::Stderr => state.stderr.extend_from_slice(bytes),
        }
    }

    #[cfg(test)]
    fn exceeded(&self) -> bool {
        self.captured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .exceeded
    }

    fn snapshot(&self) -> (Vec<u8>, Vec<u8>, bool) {
        let state = self
            .captured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (state.stdout.clone(), state.stderr.clone(), state.exceeded)
    }

    fn record_cause(&self, cause: FirstCause) {
        let _ =
            self.first_cause
                .compare_exchange(0, cause as u8, Ordering::AcqRel, Ordering::Acquire);
    }

    fn first_error(&self) -> Option<ProcessError> {
        match self.first_cause.load(Ordering::Acquire) {
            value if value == FirstCause::Cancelled as u8 => Some(ProcessError::Cancelled),
            value if value == FirstCause::Deadline as u8 => Some(ProcessError::DeadlineExceeded),
            value if value == FirstCause::Output as u8 => Some(ProcessError::OutputBudgetExceeded),
            _ => None,
        }
    }
}

type ReaderThread = thread::JoinHandle<Result<(), io::Error>>;
type WriterThread = thread::JoinHandle<Result<(), io::Error>>;

fn spawn_stdout_reader(
    mut stdout: impl Read + Send + 'static,
    output: Arc<OutputState>,
    sender: mpsc::SyncSender<Result<SetupAcknowledgement, ()>>,
) -> ReaderThread {
    thread::spawn(move || {
        let mut header = [0_u8; protocol::SETUP_HEADER_BYTES];
        if stdout.read_exact(&mut header).is_err() {
            let _ = sender.send(Err(()));
            return Ok(());
        }
        let acknowledgement = protocol::decode_setup_header(&header).ok_or_else(|| {
            let _ = sender.send(Err(()));
            io::Error::new(io::ErrorKind::InvalidData, "invalid setup acknowledgement")
        })?;
        sender
            .send(Ok(acknowledgement))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "setup receiver dropped"))?;
        copy_bounded(stdout, &output, Stream::Stdout)
    })
}

fn spawn_output_reader(
    reader: impl Read + Send + 'static,
    output: Arc<OutputState>,
    stream: Stream,
) -> ReaderThread {
    thread::spawn(move || copy_bounded(reader, &output, stream))
}

fn copy_bounded(
    mut reader: impl Read,
    output: &OutputState,
    stream: Stream,
) -> Result<(), io::Error> {
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(());
        }
        output.push(stream, &buffer[..count]);
    }
}

fn spawn_stdin_writer(mut stdin: impl Write + Send + 'static, input: Vec<u8>) -> WriterThread {
    thread::spawn(move || match stdin.write_all(&input) {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        result => result,
    })
}

#[derive(Debug)]
struct LocalControl {
    child: Mutex<Option<Child>>,
    process_group: Pid,
    output: Arc<OutputState>,
    stdout_reader: Mutex<Option<ReaderThread>>,
    stderr_reader: Mutex<Option<ReaderThread>>,
    stdin_writer: Mutex<Option<WriterThread>>,
    runtime: RuntimePrimitiveBindings,
    deadline: RuntimeInstant,
    wait_started: AtomicBool,
    cleanup: Mutex<()>,
    completed: Mutex<Option<Result<ProcessOutput, ProcessError>>>,
}

impl LocalControl {
    fn child_exited(&self) -> Result<bool, ProcessError> {
        let mut child = self
            .child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        child
            .as_mut()
            .ok_or(ProcessError::WaitFailed)?
            .try_wait()
            .map(|status| status.is_some())
            .map_err(|_| ProcessError::WaitFailed)
    }

    fn kill_group(&self) -> Result<(), ProcessError> {
        match kill_process_group(self.process_group, Signal::KILL) {
            Ok(()) | Err(Errno::SRCH) => Ok(()),
            Err(_) => Err(ProcessError::TerminationFailed),
        }
    }

    fn reap_and_join(&self) -> Result<ExitStatus, ProcessError> {
        let status = {
            let mut child = self
                .child
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut child = child.take().ok_or(ProcessError::WaitFailed)?;
            child.wait().map_err(|_| ProcessError::WaitFailed)?
        };
        join_thread(&self.stdin_writer)?;
        join_thread(&self.stdout_reader)?;
        join_thread(&self.stderr_reader)?;
        Ok(status)
    }

    fn cached_result(&self) -> Option<Result<ProcessOutput, ProcessError>> {
        self.completed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn store_result(
        &self,
        result: Result<ProcessOutput, ProcessError>,
    ) -> Result<ProcessOutput, ProcessError> {
        *self
            .completed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result.clone());
        result
    }

    fn finish_with_error(&self, cause: ProcessError) -> Result<ProcessOutput, ProcessError> {
        let _cleanup = self
            .cleanup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(result) = self.cached_result() {
            return result;
        }
        let kill = self.kill_group();
        let reap = self.reap_and_join();
        let result = match (kill, reap) {
            (Ok(()), Ok(_)) => Err(cause),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        self.store_result(result)
    }

    fn finish_with_status(&self) -> Result<ProcessOutput, ProcessError> {
        let _cleanup = self
            .cleanup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(result) = self.cached_result() {
            return result;
        }
        let kill = self.kill_group();
        let reap = self.reap_and_join();
        let result = match (kill, reap) {
            (Ok(()), Ok(status)) => {
                let (stdout, stderr, exceeded) = self.output.snapshot();
                if exceeded {
                    Err(ProcessError::OutputBudgetExceeded)
                } else {
                    ProcessOutput::checked(
                        process_exit(status),
                        stdout,
                        stderr,
                        self.output_budget(),
                    )
                }
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        self.store_result(result)
    }

    fn terminate_and_reap(&self) -> Result<(), ProcessError> {
        let _cleanup = self
            .cleanup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.cached_result().is_some() {
            return Ok(());
        }
        let kill = self.kill_group();
        let reap = self.reap_and_join();
        let result = match (kill, reap) {
            (Ok(()), Ok(_)) => Ok(()),
            (Err(error), _) | (_, Err(error)) => Err(error),
        };
        let cached = match result {
            Ok(()) => Err(ProcessError::Cancelled),
            Err(error) => Err(error),
        };
        let _ = self.store_result(cached);
        result
    }

    fn terminate_blocking(&self) {
        let _ = self.terminate_and_reap();
    }

    async fn wait_once(
        &self,
        cancellation: CancellationToken,
    ) -> Result<ProcessOutput, ProcessError> {
        loop {
            if let Some(result) = self.cached_result() {
                return result;
            }
            if cancellation.is_cancelled() {
                self.output.record_cause(FirstCause::Cancelled);
            }
            let now = self.runtime.now().map_err(|_| ProcessError::WaitFailed)?;
            if now >= self.deadline {
                self.output.record_cause(FirstCause::Deadline);
            }
            if let Some(error) = self.output.first_error() {
                return self.finish_with_error(error);
            }
            let status = {
                let _cleanup = self
                    .cleanup
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(result) = self.cached_result() {
                    return result;
                }
                let mut child = self
                    .child
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                child
                    .as_mut()
                    .ok_or(ProcessError::WaitFailed)?
                    .try_wait()
                    .map_err(|_| ProcessError::WaitFailed)?
            };
            if status.is_some() {
                return self.finish_with_status();
            }
            let next = (now + POLL_INTERVAL).min(self.deadline);
            self.runtime
                .sleep_until(next)
                .map_err(|_| ProcessError::WaitFailed)?
                .await;
        }
    }

    fn output_budget(&self) -> usize {
        let state = self
            .output
            .captured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.remaining + state.stdout.len() + state.stderr.len()
    }
}

impl ProcessControl for LocalControl {
    fn wait(
        &self,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<ProcessOutput, ProcessError>> {
        Box::pin(async move {
            if let Some(result) = self.cached_result() {
                return result;
            }
            if self.wait_started.swap(true, Ordering::AcqRel) {
                return Err(ProcessError::WaitFailed);
            }
            self.wait_once(cancellation).await
        })
    }

    fn terminate_tree(&self) -> ProcessFuture<'_, Result<(), ProcessError>> {
        Box::pin(async move { self.terminate_and_reap() })
    }
}

impl Drop for LocalControl {
    fn drop(&mut self) {
        if self.child.get_mut().is_ok_and(|child| child.is_some()) {
            self.terminate_blocking();
        }
    }
}

fn join_thread<T>(
    slot: &Mutex<Option<thread::JoinHandle<Result<T, io::Error>>>>,
) -> Result<T, ProcessError> {
    let handle = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
        .ok_or(ProcessError::WaitFailed)?;
    handle
        .join()
        .map_err(|_| ProcessError::WaitFailed)?
        .map_err(|_| ProcessError::WaitFailed)
}

fn process_exit(status: ExitStatus) -> ProcessExit {
    status.code().map_or_else(
        || ProcessExit::Signal(status.signal().unwrap_or(0)),
        ProcessExit::Code,
    )
}

fn validate_cwd(workspace: &OwnedFd, spec: &VerifiedProcessSpec) -> Result<(), ProcessError> {
    if spec.effective_policy().filesystem() == FilesystemAccess::None {
        return Ok(());
    }
    let relative = if spec.process().cwd().is_root() {
        "."
    } else {
        spec.process().cwd().as_str()
    };
    let descriptor = openat2(
        workspace,
        relative,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| ProcessError::SpawnFailed)?;
    let stat = fstat(&descriptor).map_err(|_| ProcessError::SpawnFailed)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(ProcessError::SpawnFailed);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sandbox_arguments(
    spec: &VerifiedProcessSpec,
    launcher_fd: i32,
    target_fd: i32,
    workspace_fd: i32,
    runtime_descriptors: &[(i32, String)],
    allowed_executables: &[(i32, String)],
    runtime_symlinks: &[RuntimeSymlink],
) -> Vec<String> {
    let policy = spec.effective_policy();
    let mut destinations = runtime_descriptors
        .iter()
        .map(|(_, path)| path.as_str())
        .chain(allowed_executables.iter().map(|(_, path)| path.as_str()))
        .chain(runtime_symlinks.iter().map(|symlink| symlink.link.as_str()))
        .chain([SANDBOX_LAUNCHER, SANDBOX_TARGET, SANDBOX_WORKSPACE]);
    let parent_directories = mount_parent_directories(&mut destinations);
    let mut arguments = vec![
        "--unshare-all".into(),
        "--die-with-parent".into(),
        "--new-session".into(),
        "--hostname".into(),
        "rust-agent".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--clearenv".into(),
    ];
    if policy.network() == NetworkAccess::Outbound {
        arguments.push("--share-net".into());
    }
    for directory in parent_directories {
        arguments.extend(["--dir".into(), directory]);
    }
    arguments.extend([
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--tmpfs".into(),
        "/tmp".into(),
        "--ro-bind-fd".into(),
        launcher_fd.to_string(),
        SANDBOX_LAUNCHER.into(),
        "--ro-bind-fd".into(),
        target_fd.to_string(),
        SANDBOX_TARGET.into(),
    ]);
    for (descriptor, destination) in runtime_descriptors {
        arguments.extend([
            "--ro-bind-fd".into(),
            descriptor.to_string(),
            destination.clone(),
        ]);
    }
    for (descriptor, destination) in allowed_executables {
        arguments.extend([
            "--ro-bind-fd".into(),
            descriptor.to_string(),
            destination.clone(),
        ]);
    }
    for symlink in runtime_symlinks {
        arguments.extend([
            "--symlink".into(),
            symlink.target.clone(),
            symlink.link.clone(),
        ]);
    }
    match policy.filesystem() {
        FilesystemAccess::None => {
            let mut current = String::from(SANDBOX_WORKSPACE);
            arguments.extend(["--dir".into(), current.clone()]);
            for segment in spec
                .process()
                .cwd()
                .as_str()
                .split('/')
                .filter(|item| !item.is_empty())
            {
                current.push('/');
                current.push_str(segment);
                arguments.extend(["--dir".into(), current.clone()]);
            }
        }
        FilesystemAccess::ReadOnly => arguments.extend([
            "--ro-bind-fd".into(),
            workspace_fd.to_string(),
            SANDBOX_WORKSPACE.into(),
        ]),
        FilesystemAccess::ReadWrite => arguments.extend([
            "--bind-fd".into(),
            workspace_fd.to_string(),
            SANDBOX_WORKSPACE.into(),
        ]),
    }
    for (name, value) in spec.process().environment().entries() {
        arguments.extend(["--setenv".into(), name.to_string(), value.to_string()]);
    }
    let cwd = if spec.process().cwd().is_root() {
        SANDBOX_WORKSPACE.to_owned()
    } else {
        format!("{SANDBOX_WORKSPACE}/{}", spec.process().cwd().as_str())
    };
    arguments.extend([
        "--chdir".into(),
        cwd,
        "--".into(),
        SANDBOX_LAUNCHER.into(),
        "--policy-digest".into(),
        spec.policy_digest().to_lower_hex(),
        "--required-primitives".into(),
        spec.backend_plan().required_primitives().bits().to_string(),
        "--filesystem".into(),
        filesystem_name(policy.filesystem()).into(),
        "--network".into(),
        network_name(policy.network()).into(),
        "--max-processes".into(),
        policy.limits().max_processes().get().to_string(),
        "--max-memory-bytes".into(),
        policy.limits().max_memory_bytes().get().to_string(),
    ]);
    for (_, path) in runtime_descriptors {
        arguments.extend(["--runtime-read".into(), path.clone()]);
    }
    for (_, path) in allowed_executables {
        arguments.extend(["--allow-exec".into(), path.clone()]);
    }
    arguments.extend(["--".into(), SANDBOX_TARGET.into()]);
    arguments.extend(spec.process().arguments().iter().map(ToString::to_string));
    arguments
}

fn filesystem_name(access: FilesystemAccess) -> &'static str {
    match access {
        FilesystemAccess::None => "none",
        FilesystemAccess::ReadOnly => "read-only",
        FilesystemAccess::ReadWrite => "read-write",
    }
}

fn network_name(access: NetworkAccess) -> &'static str {
    match access {
        NetworkAccess::Deny => "deny",
        NetworkAccess::Outbound => "outbound",
    }
}

fn mount_parent_directories<'a>(paths: &mut impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut directories = std::collections::BTreeSet::new();
    for path in paths {
        let mut parent = Path::new(path).parent();
        while let Some(path) = parent {
            if path != Path::new("/") {
                directories.insert(path.to_string_lossy().into_owned());
            }
            parent = path.parent();
        }
    }
    directories.into_iter().collect()
}

fn write_nul_arguments(file: &mut File, arguments: &[String]) -> io::Result<()> {
    for argument in arguments {
        file.write_all(argument.as_bytes())?;
        file.write_all(&[0])?;
    }
    file.flush()
}

fn validate_config(config: &Config) -> Result<(), ComponentBuildError> {
    for path in [
        &config.workspace_root,
        &config.bubblewrap_path,
        &config.launcher_path,
    ] {
        validate_absolute(path)?;
    }
    Digest::from_lower_hex(&config.bubblewrap_sha256)
        .map_err(|_| invalid_config("bubblewrap SHA-256 is not canonical"))?;
    Digest::from_lower_hex(&config.launcher_sha256)
        .map_err(|_| invalid_config("launcher SHA-256 is not canonical"))?;
    validate_sorted_paths(&config.runtime_read_paths)?;
    validate_sorted_paths(&config.allowed_executables)?;
    if config
        .allowed_executables
        .iter()
        .any(|path| !runtime_path_is_covered(path, &config.runtime_read_paths))
    {
        return Err(invalid_config(
            "allowed executable is not covered by a runtime read mount",
        ));
    }
    if config.runtime_symlinks.len() > MAX_CONFIG_PATHS
        || !config
            .runtime_symlinks
            .windows(2)
            .all(|pair| pair[0].link < pair[1].link)
    {
        return Err(invalid_config("runtime symlinks are not sorted and unique"));
    }
    for symlink in &config.runtime_symlinks {
        validate_symlink(symlink)?;
    }
    let bytes = config.workspace_root.len()
        + config.bubblewrap_path.len()
        + config.bubblewrap_sha256.len()
        + config.launcher_path.len()
        + config.launcher_sha256.len()
        + config
            .runtime_read_paths
            .iter()
            .map(String::len)
            .sum::<usize>()
        + config
            .allowed_executables
            .iter()
            .map(String::len)
            .sum::<usize>()
        + config
            .runtime_symlinks
            .iter()
            .map(|symlink| symlink.link.len() + symlink.target.len())
            .sum::<usize>();
    if bytes > MAX_CONFIG_BYTES {
        return Err(invalid_config("subprocess configuration is too large"));
    }
    Ok(())
}

fn validate_sorted_paths(paths: &[String]) -> Result<(), ComponentBuildError> {
    if paths.len() > MAX_CONFIG_PATHS || !paths.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(invalid_config("runtime paths are not sorted and unique"));
    }
    for path in paths {
        validate_absolute(path)?;
        if path == "/" || path.starts_with("/workspace") || path.starts_with("/rust-agent") {
            return Err(invalid_config(
                "runtime path overlaps a reserved sandbox path",
            ));
        }
    }
    Ok(())
}

fn runtime_path_is_covered(path: &str, mounts: &[String]) -> bool {
    mounts.iter().any(|mount| {
        path == mount
            || path
                .strip_prefix(mount)
                .is_some_and(|suffix| suffix.starts_with('/'))
    })
}

fn validate_symlink(symlink: &RuntimeSymlink) -> Result<(), ComponentBuildError> {
    validate_absolute(&symlink.link)?;
    if symlink.link == "/"
        || symlink.link.starts_with("/workspace")
        || symlink.link.starts_with("/rust-agent")
    {
        return Err(invalid_config(
            "runtime symlink overlaps a reserved sandbox path",
        ));
    }
    if symlink.target.is_empty()
        || symlink.target.starts_with('/')
        || symlink.target.contains('\0')
        || Path::new(&symlink.target).components().any(|component| {
            matches!(
                component,
                Component::ParentDir
                    | Component::CurDir
                    | Component::RootDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(invalid_config(
            "runtime symlink target is not canonical relative",
        ));
    }
    Ok(())
}

fn validate_absolute(path: &str) -> Result<(), ComponentBuildError> {
    let path = Path::new(path);
    if path.as_os_str().is_empty()
        || path.as_os_str().as_encoded_bytes().len() > 4096
        || !path.is_absolute()
        || !path.components().enumerate().all(|(index, component)| {
            (index == 0 && matches!(component, Component::RootDir))
                || (index > 0 && matches!(component, Component::Normal(_)))
        })
    {
        return Err(invalid_config("path is not canonical absolute"));
    }
    Ok(())
}

fn open_directory(path: &str) -> Result<OwnedFd, ComponentBuildError> {
    let descriptor = open_absolute(path, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC)
        .map_err(|_| invalid_config("workspace root could not be anchored"))?;
    let stat = fstat(&descriptor).map_err(|_| invalid_config("workspace root stat failed"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(invalid_config("workspace root is not a directory"));
    }
    Ok(descriptor)
}

fn open_verified_executable(
    path: &str,
    expected_hex: &str,
    name: &str,
) -> Result<OwnedFd, ComponentBuildError> {
    let descriptor = open_absolute(path, OFlags::RDONLY | OFlags::CLOEXEC)
        .map_err(|_| invalid_config("configured executable could not be anchored"))?;
    ensure_executable(&descriptor)
        .map_err(|_| invalid_config("configured executable is not executable"))?;
    let actual = digest_descriptor(&descriptor)
        .map_err(|_| invalid_config("configured executable could not be hashed"))?;
    let expected = Digest::from_lower_hex(expected_hex)
        .map_err(|_| invalid_config("configured executable digest is invalid"))?;
    if actual != expected {
        return Err(ComponentBuildError::InvalidConfig(format!(
            "{name} executable digest does not match"
        )));
    }
    Ok(descriptor)
}

fn open_absolute(path: &str, flags: OFlags) -> Result<OwnedFd, Errno> {
    openat2(
        CWD,
        path,
        flags | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
}

fn ensure_executable(descriptor: &OwnedFd) -> Result<(), Errno> {
    let stat = fstat(descriptor)?;
    if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile && stat.st_mode & 0o111 != 0 {
        Ok(())
    } else {
        Err(Errno::ACCESS)
    }
}

fn digest_descriptor(descriptor: &OwnedFd) -> io::Result<Digest> {
    let duplicate = dup(descriptor).map_err(io::Error::from)?;
    let mut file = File::from(duplicate);
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(Digest::from_bytes(hasher.finalize().into()))
}

fn inheritable_duplicate(descriptor: &impl std::os::fd::AsFd) -> Result<OwnedFd, Errno> {
    let duplicate = dup(descriptor)?;
    fcntl_setfd(&duplicate, FdFlags::empty())?;
    Ok(duplicate)
}

fn invalid_config(message: &str) -> ComponentBuildError {
    ComponentBuildError::InvalidConfig(message.into())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{
        fs,
        future::Future,
        num::{NonZeroU32, NonZeroU64, NonZeroUsize},
        os::unix::fs::PermissionsExt as _,
        sync::Arc,
        task::{Context, Poll, Waker},
    };

    use rust_agent_fs::AgentPath;
    use rust_agent_policy::process::{ProcessResourceLimits, SandboxPolicy, SandboxPolicyCeiling};
    use rust_agent_process::{
        ConfinementAuthority, ProcessEnvironment, ProcessExecutable, ProcessSpec,
    };
    use rust_agent_runtime_api::{
        RuntimeAdapterIdentity, RuntimeClock, RuntimeFuture, RuntimePrimitiveError,
        RuntimePrimitives, RuntimeSleeper, RuntimeSpawner, RuntimeTaskOwner,
    };
    use sha2::Sha256;
    use tempfile::TempDir;

    use super::*;

    #[derive(Debug)]
    struct TestRuntime;

    impl RuntimeClock for TestRuntime {
        fn now(&self) -> RuntimeInstant {
            RuntimeInstant::from_monotonic_duration(Duration::from_secs(1))
        }
    }

    impl RuntimeSleeper for TestRuntime {
        fn sleep_until(&self, _deadline: RuntimeInstant) -> RuntimeFuture<'static, ()> {
            Box::pin(async {})
        }
    }

    impl RuntimeSpawner for TestRuntime {
        fn spawn(
            &self,
            _owner: RuntimeTaskOwner,
            _task: RuntimeFuture<'static, ()>,
        ) -> Result<(), RuntimePrimitiveError> {
            Ok(())
        }

        fn drain(&self, _owner: RuntimeTaskOwner) -> RuntimeFuture<'static, ()> {
            Box::pin(async {})
        }
    }

    fn runtime() -> RuntimePrimitiveBindings {
        let driver = Arc::new(TestRuntime);
        let primitives = RuntimePrimitives::from_adapter(
            RuntimeAdapterIdentity::checked("subprocess-local-test").unwrap(),
            Arc::clone(&driver),
            driver.clone(),
            driver.clone(),
            driver,
        );
        RuntimePrimitiveBindings::projected(
            primitives,
            &[RuntimePrimitiveKind::Clock, RuntimePrimitiveKind::Sleep],
        )
        .unwrap()
    }

    fn ready<T>(mut future: ProcessFuture<'_, T>) -> T {
        let mut context = Context::from_waker(Waker::noop());
        match Future::poll(future.as_mut(), &mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("future unexpectedly pending"),
        }
    }

    fn policy(filesystem: FilesystemAccess, output: usize) -> SandboxPolicy {
        SandboxPolicy::new(
            filesystem,
            NetworkAccess::Deny,
            ProcessResourceLimits::checked(
                NonZeroU32::new(32).unwrap(),
                NonZeroU64::new(512 * 1024 * 1024).unwrap(),
                NonZeroUsize::new(output).unwrap(),
                NonZeroU64::new(30_000).unwrap(),
            )
            .unwrap(),
        )
    }

    fn write_executable(path: &Path, body: &[u8]) {
        fs::write(path, body).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    fn sha256(path: &Path) -> String {
        let bytes = fs::read(path).unwrap();
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        Digest::from_bytes(digest).to_lower_hex()
    }

    fn fixture_config(owner: &TempDir) -> Config {
        let workspace = owner.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        let bubblewrap = owner.path().join("bubblewrap");
        let launcher = owner.path().join("launcher");
        write_executable(&bubblewrap, b"#!/bin/sh\nexit 99\n");
        write_executable(&launcher, b"#!/bin/sh\nexit 98\n");
        Config::checked(
            workspace.to_str().unwrap(),
            bubblewrap.to_str().unwrap(),
            sha256(&bubblewrap),
            launcher.to_str().unwrap(),
            sha256(&launcher),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn config_is_bounded_canonical_and_digest_anchored() {
        let owner = tempfile::tempdir_in(".").unwrap();
        let mut config = fixture_config(&owner);
        config.launcher_sha256 = "0".repeat(64);
        let (_issuer, verifier) = ConfinementAuthority::new(SandboxPolicyCeiling::new(policy(
            FilesystemAccess::ReadOnly,
            1024,
        )))
        .unwrap();
        let output = build(
            &config,
            Dependencies {
                confinement_verifier: ConfinementVerifierBinding::from_generated_authority(
                    verifier,
                ),
            },
            runtime(),
        )
        .unwrap();
        assert!(output.initializer().is_some());
        assert!(output.shutdown_hook().is_some());
        assert_eq!(
            ready(output.initializer().unwrap().initialize()),
            Err(InitializeError::ResourcePreparationFailed)
        );
        assert!(
            Config::checked(
                "/workspace/overlap",
                "/bin/bwrap",
                "0".repeat(64),
                "/bin/launcher",
                "0".repeat(64),
                vec!["/usr/lib".into()],
                vec!["/opt/not-mounted/tool".into()],
                Vec::new(),
            )
            .is_err()
        );

        let initialized_owner = tempfile::tempdir_in(".").unwrap();
        let config = fixture_config(&initialized_owner);
        let (_issuer, verifier) = ConfinementAuthority::new(SandboxPolicyCeiling::new(policy(
            FilesystemAccess::ReadOnly,
            1024,
        )))
        .unwrap();
        let output = build(
            &config,
            Dependencies {
                confinement_verifier: ConfinementVerifierBinding::from_generated_authority(
                    verifier,
                ),
            },
            runtime(),
        )
        .unwrap();
        assert_eq!(ready(output.initializer().unwrap().initialize()), Ok(()));
        assert_eq!(
            ready(output.initializer().unwrap().initialize()),
            Err(InitializeError::AlreadyInitialized)
        );
        assert_eq!(ready(output.shutdown_hook().unwrap().shutdown()), Ok(()));
        assert_eq!(
            ready(output.initializer().unwrap().initialize()),
            Err(InitializeError::ScopeClosed)
        );
        assert!(
            Config::checked(
                "/workspace/overlap",
                "/bin/bwrap",
                "0".repeat(64),
                "/bin/launcher",
                "0".repeat(64),
                vec!["/usr/lib/z".into(), "/usr/lib/a".into()],
                Vec::new(),
                Vec::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn verifier_and_cancellation_reject_before_any_spawn() {
        let owner = tempfile::tempdir_in(".").unwrap();
        let config = fixture_config(&owner);
        let ceiling = policy(FilesystemAccess::ReadOnly, 1024);
        let (_issuer, verifier) =
            ConfinementAuthority::new(SandboxPolicyCeiling::new(ceiling.clone())).unwrap();
        let (foreign_issuer, _foreign_verifier) =
            ConfinementAuthority::new(SandboxPolicyCeiling::new(ceiling.clone())).unwrap();
        let provider = build(
            &config,
            Dependencies {
                confinement_verifier: ConfinementVerifierBinding::from_generated_authority(
                    verifier,
                ),
            },
            runtime(),
        )
        .unwrap()
        .into_service();
        let process = ProcessSpec::checked(
            ProcessExecutable::absolute("/usr/bin/printf").unwrap(),
            ["ok".into()],
            AgentPath::new("child").unwrap(),
            ProcessEnvironment::empty(),
            Vec::new(),
        )
        .unwrap();
        let projection = foreign_issuer.project(&ceiling);
        let plan = rust_agent_policy::process::BackendPlan::linux(
            &ceiling,
            rust_agent_policy::process::EnforcementPrimitives::all(),
        )
        .unwrap();
        let foreign = foreign_issuer
            .seal(process.clone(), projection, plan)
            .unwrap();
        assert!(matches!(
            ready(provider.spawn(foreign, CancellationToken::new())),
            Err(ProcessError::AuthorityMismatch)
        ));

        let (issuer, verifier) =
            ConfinementAuthority::new(SandboxPolicyCeiling::new(ceiling.clone())).unwrap();
        let provider = build(
            &config,
            Dependencies {
                confinement_verifier: ConfinementVerifierBinding::from_generated_authority(
                    verifier,
                ),
            },
            runtime(),
        )
        .unwrap()
        .into_service();
        let projection = issuer.project(&ceiling);
        let plan = rust_agent_policy::process::BackendPlan::linux(
            &ceiling,
            rust_agent_policy::process::EnforcementPrimitives::all(),
        )
        .unwrap();
        let confined = issuer.seal(process.clone(), projection, plan).unwrap();
        assert!(matches!(
            ready(provider.spawn(confined, CancellationToken::new())),
            Err(ProcessError::SetupFailed)
        ));

        let projection = issuer.project(&ceiling);
        let plan = rust_agent_policy::process::BackendPlan::linux(
            &ceiling,
            rust_agent_policy::process::EnforcementPrimitives::all(),
        )
        .unwrap();
        let confined = issuer.seal(process, projection, plan).unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            ready(provider.spawn(confined, cancellation)),
            Err(ProcessError::Cancelled)
        ));
    }

    #[test]
    fn output_budget_is_shared_and_runtime_projection_is_exact() {
        let output = OutputState::new(5);
        output.push(Stream::Stdout, b"abc");
        output.push(Stream::Stderr, b"de");
        assert!(!output.exceeded());
        output.push(Stream::Stdout, b"f");
        assert!(output.exceeded());
        output.record_cause(FirstCause::Cancelled);
        assert_eq!(
            output.first_error(),
            Some(ProcessError::OutputBudgetExceeded)
        );
        let (stdout, stderr, exceeded) = output.snapshot();
        assert_eq!(stdout, b"abc");
        assert_eq!(stderr, b"de");
        assert!(exceeded);

        let owner = tempfile::tempdir_in(".").unwrap();
        let config = fixture_config(&owner);
        let (_issuer, verifier) = ConfinementAuthority::new(SandboxPolicyCeiling::new(policy(
            FilesystemAccess::None,
            64,
        )))
        .unwrap();
        assert!(matches!(
            build(
                &config,
                Dependencies {
                    confinement_verifier: ConfinementVerifierBinding::from_generated_authority(
                        verifier
                    ),
                },
                RuntimePrimitiveBindings::none(),
            ),
            Err(ComponentBuildError::InvalidConfig(_))
        ));
    }
}
