//! Descriptor-relative read-write Linux filesystem provider.

use rust_agent_core::{CanonicalId, SecurityEffects};
use rust_agent_fs::{
    AgentPath, ByteRange, DirPage, DirPageCursor, DirPageRequest, FileBytes, FileKind,
    FileMetadata, FileRead, FileWrite, FsCallContext, FsError, FsFuture, WriteMode, WriteOptions,
};
use rust_agent_resource_namespace::{
    LocalDirectoryAnchor, LocalResourceLocator, PreparedComponentConfig,
    ResourceNamespacePreparationContext, ResourceNamespacePrepareError,
};
use rust_agent_runtime_api::{
    ComponentBuildError, ComponentOutput, RuntimePrimitiveBindings, RuntimePrimitiveKind,
};
use serde::Deserialize;

#[cfg(target_os = "linux")]
use rustix::{
    fs::{
        Dir, FileType, Mode, OFlags, ResolveFlags, Stat, fstat, fsync, ftruncate, mkdirat, openat2,
    },
    io::Errno,
};

const PROVIDER_KEY: &str = "local";
const CURSOR_VERSION: u8 = 1;
const CURSOR_FIELDS: usize = 8;
const CURSOR_BYTES: usize = 1 + CURSOR_FIELDS * std::mem::size_of::<u64>();

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    root: String,
}

impl Config {
    pub fn checked(root: impl Into<String>) -> Result<Self, ResourceNamespacePrepareError> {
        let root = root.into();
        locator(&root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &str {
        &self.root
    }
}

#[derive(Clone, Debug, Default)]
pub struct Dependencies;

#[derive(Debug)]
pub struct PreparedConfig {
    anchor: LocalDirectoryAnchor,
}

#[derive(Debug)]
pub struct LocalFileSystem {
    anchor: LocalDirectoryAnchor,
    runtime: RuntimePrimitiveBindings,
}

pub async fn prepare_resource_namespaces(
    config: &Config,
    context: ResourceNamespacePreparationContext<'_>,
) -> Result<PreparedComponentConfig<PreparedConfig>, ResourceNamespacePrepareError> {
    let prepared = context
        .prepare_local_directory(locator(config.root())?)
        .await?;
    let expected_route = prepared.descriptor().route().clone();
    let (descriptor, anchor) = prepared.into_local_parts();
    PreparedComponentConfig::checked(
        PreparedConfig { anchor },
        vec![descriptor],
        &[expected_route],
    )
}

pub fn build(
    config: &PreparedConfig,
    _dependencies: Dependencies,
    runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<LocalFileSystem>, ComponentBuildError> {
    if runtime.allowed() != [RuntimePrimitiveKind::Clock] {
        return Err(ComponentBuildError::InvalidConfig(
            "fs-local requires exactly the clock runtime primitive".into(),
        ));
    }
    Ok(ComponentOutput::stateless(LocalFileSystem {
        anchor: config.anchor.clone(),
        runtime,
    }))
}

impl FileRead for LocalFileSystem {
    fn provider_key(&self) -> CanonicalId {
        CanonicalId::new(PROVIDER_KEY).expect("static provider key is canonical")
    }

    fn effects(&self) -> SecurityEffects {
        SecurityEffects::READ_LOCAL
    }

    fn metadata<'a>(
        &'a self,
        context: FsCallContext,
        path: &'a AgentPath,
    ) -> FsFuture<'a, Result<FileMetadata, FsError>> {
        #[cfg(target_os = "linux")]
        {
            Box::pin(async move {
                self.preflight(&context)?;
                let descriptor = self.open(path, OFlags::PATH | OFlags::CLOEXEC)?;
                let stat = fstat(&descriptor).map_err(map_errno)?;
                let metadata = checked_metadata(&stat)?;
                self.preflight(&context)?;
                Ok(metadata)
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (context, path);
            Box::pin(async { Err(FsError::Provider) })
        }
    }

    fn read<'a>(
        &'a self,
        context: FsCallContext,
        path: &'a AgentPath,
        range: ByteRange,
    ) -> FsFuture<'a, Result<FileBytes, FsError>> {
        #[cfg(target_os = "linux")]
        {
            Box::pin(async move {
                self.preflight(&context)?;
                let descriptor = self.open(path, OFlags::RDONLY | OFlags::CLOEXEC)?;
                let stat = fstat(&descriptor).map_err(map_errno)?;
                ensure_regular_single_link(&stat)?;
                let mut bytes = vec![0_u8; range.length().get()];
                let read =
                    rustix::io::pread(&descriptor, &mut bytes, range.start()).map_err(map_errno)?;
                bytes.truncate(read);
                self.preflight(&context)?;
                FileBytes::new(bytes)
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (context, path, range);
            Box::pin(async { Err(FsError::Provider) })
        }
    }

    fn list_page(
        &self,
        context: FsCallContext,
        request: DirPageRequest,
    ) -> FsFuture<'_, Result<DirPage, FsError>> {
        #[cfg(target_os = "linux")]
        {
            Box::pin(async move { self.list_page_linux(&context, &request) })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (context, request);
            Box::pin(async { Err(FsError::Provider) })
        }
    }
}

impl FileWrite for LocalFileSystem {
    fn provider_key(&self) -> CanonicalId {
        CanonicalId::new(PROVIDER_KEY).expect("static provider key is canonical")
    }

    fn effects(&self) -> SecurityEffects {
        SecurityEffects::READ_LOCAL | SecurityEffects::WRITE_LOCAL
    }

    fn write<'a>(
        &'a self,
        context: FsCallContext,
        path: &'a AgentPath,
        data: &'a [u8],
        options: WriteOptions,
    ) -> FsFuture<'a, Result<(), FsError>> {
        #[cfg(target_os = "linux")]
        {
            Box::pin(async move {
                self.preflight(&context)?;
                if path.is_root() {
                    return Err(FsError::NotFile);
                }
                let (parent, name) = self.open_parent(path, options.create_parents())?;
                let flags = match options.mode() {
                    WriteMode::CreateNew => {
                        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC
                    }
                    WriteMode::Truncate => OFlags::WRONLY | OFlags::CREATE | OFlags::CLOEXEC,
                    WriteMode::Append => {
                        OFlags::WRONLY | OFlags::CREATE | OFlags::APPEND | OFlags::CLOEXEC
                    }
                };
                let descriptor = openat2(
                    &parent,
                    name,
                    flags | OFlags::NOFOLLOW,
                    Mode::RUSR | Mode::WUSR,
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )
                .map_err(map_errno)?;
                let stat = fstat(&descriptor).map_err(map_errno)?;
                ensure_regular_single_link(&stat)?;
                if options.mode() == WriteMode::Truncate {
                    ftruncate(&descriptor, 0).map_err(map_errno)?;
                }
                let mut remaining = data;
                while !remaining.is_empty() {
                    let written = rustix::io::write(&descriptor, remaining).map_err(map_errno)?;
                    if written == 0 {
                        return Err(FsError::Provider);
                    }
                    remaining = &remaining[written..];
                }
                fsync(&descriptor).map_err(map_errno)?;
                Ok(())
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (context, path, data, options);
            Box::pin(async { Err(FsError::Provider) })
        }
    }
}

impl LocalFileSystem {
    fn preflight(&self, context: &FsCallContext) -> Result<(), FsError> {
        if context.cancellation().is_cancelled() {
            return Err(FsError::Cancelled);
        }
        if let Some(deadline) = context.deadline()
            && self.runtime.now().map_err(|_| FsError::Provider)? >= deadline
        {
            return Err(FsError::DeadlineExceeded);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn open(&self, path: &AgentPath, flags: OFlags) -> Result<std::os::fd::OwnedFd, FsError> {
        openat2(
            self.anchor.as_fd(),
            provider_path(path),
            flags | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(map_errno)
    }

    #[cfg(target_os = "linux")]
    fn open_parent<'a>(
        &self,
        path: &'a AgentPath,
        create_parents: bool,
    ) -> Result<(std::os::fd::OwnedFd, &'a str), FsError> {
        let (parents, name) = path
            .as_str()
            .rsplit_once('/')
            .unwrap_or(("", path.as_str()));
        let mut parent = openat2(
            self.anchor.as_fd(),
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(map_errno)?;
        for segment in parents.split('/').filter(|segment| !segment.is_empty()) {
            let open = || {
                openat2(
                    &parent,
                    segment,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )
            };
            parent = match open() {
                Ok(next) => next,
                Err(Errno::NOENT) if create_parents => {
                    match mkdirat(&parent, segment, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                        Ok(()) | Err(Errno::EXIST) => {}
                        Err(error) => return Err(map_errno(error)),
                    }
                    open().map_err(map_errno)?
                }
                Err(error) => return Err(map_errno(error)),
            };
        }
        Ok((parent, name))
    }

    #[cfg(target_os = "linux")]
    fn list_page_linux(
        &self,
        context: &FsCallContext,
        request: &DirPageRequest,
    ) -> Result<DirPage, FsError> {
        self.preflight(context)?;
        let descriptor = self.open(
            request.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        )?;
        let initial = fstat(&descriptor).map_err(map_errno)?;
        if !FileType::from_raw_mode(initial.st_mode).is_dir() {
            return Err(FsError::NotDirectory);
        }
        let snapshot = DirectorySnapshot::from_stat(&initial);
        let offset = match request.cursor() {
            Some(cursor) => decode_cursor(cursor.token(), snapshot)?,
            None => 0,
        };
        let mut directory = Dir::new(descriptor).map_err(map_errno)?;
        if offset != 0 {
            directory.seek(offset).map_err(map_errno)?;
        }
        let cursor_charge = PROVIDER_KEY
            .len()
            .checked_add(request.path().as_str().len())
            .and_then(|bytes| bytes.checked_add(CURSOR_BYTES))
            .ok_or(FsError::OutputTooLarge)?;
        let mut entries = Vec::new();
        let mut charged = 0_usize;
        let mut next_offset = offset;
        let mut complete = true;
        while let Some(entry) = directory.read() {
            self.preflight(context)?;
            let entry = entry.map_err(map_errno)?;
            let name = entry.file_name().to_str().map_err(|_| FsError::Provider)?;
            if matches!(name, "." | "..") {
                continue;
            }
            let stat = match openat2(
                directory.fd().map_err(map_errno)?,
                entry.file_name(),
                OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            ) {
                Ok(descriptor) => fstat(descriptor).map_err(map_errno)?,
                Err(Errno::LOOP | Errno::XDEV) => continue,
                Err(error) => return Err(map_errno(error)),
            };
            let kind = match FileType::from_raw_mode(stat.st_mode) {
                kind if kind.is_file() && stat.st_nlink == 1 => FileKind::File,
                kind if kind.is_dir() => FileKind::Directory,
                _ => continue,
            };
            let entry_charge = name
                .len()
                .checked_add(std::mem::size_of::<u64>() + 1)
                .ok_or(FsError::OutputTooLarge)?;
            let projected = charged
                .checked_add(entry_charge)
                .and_then(|bytes| bytes.checked_add(cursor_charge))
                .ok_or(FsError::OutputTooLarge)?;
            if projected > request.byte_budget().get() {
                if entries.is_empty() {
                    return Err(FsError::BudgetExceeded);
                }
                complete = false;
                break;
            }
            entries.push(rust_agent_fs::DirEntry::new(
                name,
                kind,
                u64::try_from(stat.st_size).map_err(|_| FsError::Provider)?,
            )?);
            charged = charged
                .checked_add(entry_charge)
                .ok_or(FsError::OutputTooLarge)?;
            next_offset = entry.offset();
            if entries.len() == request.max_entries().get() {
                complete = false;
                break;
            }
        }
        let final_stat = fstat(directory.fd().map_err(map_errno)?).map_err(map_errno)?;
        if DirectorySnapshot::from_stat(&final_stat) != snapshot {
            return Err(FsError::NamespaceChanged);
        }
        entries.sort_by(|left, right| left.name().cmp(right.name()));
        let cursor = if complete {
            None
        } else {
            Some(DirPageCursor::new(
                PROVIDER_KEY,
                request.path().clone(),
                encode_cursor(snapshot, next_offset),
            )?)
        };
        self.preflight(context)?;
        DirPage::new(entries, cursor, complete)
    }
}

fn locator(root: &str) -> Result<LocalResourceLocator, ResourceNamespacePrepareError> {
    if root.is_empty() {
        Ok(LocalResourceLocator::root())
    } else {
        LocalResourceLocator::new(root.to_owned())
    }
}

fn provider_path(path: &AgentPath) -> &str {
    if path.is_root() { "." } else { path.as_str() }
}

#[cfg(target_os = "linux")]
fn checked_metadata(stat: &Stat) -> Result<FileMetadata, FsError> {
    let kind = FileType::from_raw_mode(stat.st_mode);
    let kind = if kind.is_file() {
        ensure_regular_single_link(stat)?;
        FileKind::File
    } else if kind.is_dir() {
        FileKind::Directory
    } else {
        return Err(FsError::PermissionDenied);
    };
    Ok(FileMetadata::new(
        kind,
        u64::try_from(stat.st_size).map_err(|_| FsError::Provider)?,
        stat.st_mode & 0o222 == 0,
    ))
}

#[cfg(target_os = "linux")]
fn ensure_regular_single_link(stat: &Stat) -> Result<(), FsError> {
    if !FileType::from_raw_mode(stat.st_mode).is_file() {
        return Err(FsError::NotFile);
    }
    if stat.st_nlink != 1 {
        return Err(FsError::PermissionDenied);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectorySnapshot([u64; CURSOR_FIELDS - 1]);

#[cfg(target_os = "linux")]
impl DirectorySnapshot {
    fn from_stat(stat: &Stat) -> Self {
        Self([
            stat.st_dev,
            stat.st_ino,
            stat.st_size.cast_unsigned(),
            stat.st_mtime.cast_unsigned(),
            stat.st_mtime_nsec,
            stat.st_ctime.cast_unsigned(),
            stat.st_ctime_nsec,
        ])
    }
}

#[cfg(target_os = "linux")]
fn encode_cursor(snapshot: DirectorySnapshot, offset: i64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CURSOR_BYTES);
    bytes.push(CURSOR_VERSION);
    for field in snapshot.0 {
        bytes.extend_from_slice(&field.to_be_bytes());
    }
    bytes.extend_from_slice(&offset.to_be_bytes());
    bytes
}

#[cfg(target_os = "linux")]
fn decode_cursor(token: &[u8], expected: DirectorySnapshot) -> Result<i64, FsError> {
    if token.len() != CURSOR_BYTES || token[0] != CURSOR_VERSION {
        return Err(FsError::InvalidCursor);
    }
    let mut fields = [0_u64; CURSOR_FIELDS];
    for (index, chunk) in token[1..].chunks_exact(8).enumerate() {
        fields[index] = u64::from_be_bytes(chunk.try_into().map_err(|_| FsError::InvalidCursor)?);
    }
    if fields[..CURSOR_FIELDS - 1] != expected.0 {
        return Err(FsError::NamespaceChanged);
    }
    Ok(i64::from_be_bytes(fields[CURSOR_FIELDS - 1].to_be_bytes()))
}

#[cfg(target_os = "linux")]
fn map_errno(error: Errno) -> FsError {
    match error {
        Errno::NOENT => FsError::NotFound,
        Errno::EXIST => FsError::AlreadyExists,
        Errno::NOTDIR => FsError::NotDirectory,
        Errno::ISDIR => FsError::NotFile,
        Errno::ACCESS | Errno::PERM | Errno::LOOP | Errno::XDEV => FsError::PermissionDenied,
        _ => FsError::Provider,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{
        fs,
        future::Future,
        num::NonZeroUsize,
        sync::Arc,
        task::{Context, Poll, Waker},
        time::Duration,
    };

    use rust_agent_fs::{FileReadBinding, FileWriteBinding};
    use rust_agent_resource_namespace::{
        BootstrapAuthorityProjection, ResourceNamespaceBootstrapBinding, ResourceNamespaceRoute,
    };
    use rust_agent_resource_namespace_bootstrap_local::{
        Config as BootstrapConfig, Dependencies as BootstrapDependencies,
    };
    use rust_agent_runtime_api::{
        CancellationToken, RuntimeAdapterIdentity, RuntimeClock, RuntimeFuture, RuntimeInstant,
        RuntimePrimitiveError, RuntimePrimitives, RuntimeSleeper, RuntimeSpawner, RuntimeTaskOwner,
    };
    use tempfile::{Builder, TempDir};

    use super::*;

    #[derive(Debug)]
    struct TestRuntime {
        now: RuntimeInstant,
    }

    impl RuntimeClock for TestRuntime {
        fn now(&self) -> RuntimeInstant {
            self.now
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

    fn run<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("filesystem future unexpectedly pending"),
        }
    }

    fn runtime(now: Duration) -> RuntimePrimitiveBindings {
        let driver = Arc::new(TestRuntime {
            now: RuntimeInstant::from_monotonic_duration(now),
        });
        let primitives = RuntimePrimitives::from_adapter(
            RuntimeAdapterIdentity::checked("fs-local-test").unwrap(),
            Arc::clone(&driver),
            driver.clone(),
            driver.clone(),
            driver,
        );
        RuntimePrimitiveBindings::projected(primitives, &[RuntimePrimitiveKind::Clock]).unwrap()
    }

    fn context(cancellation: CancellationToken, deadline: Option<RuntimeInstant>) -> FsCallContext {
        FsCallContext::new(
            cancellation,
            deadline,
            NonZeroUsize::new(1024 * 1024).unwrap(),
            NonZeroUsize::new(1024).unwrap(),
        )
        .unwrap()
    }

    fn fixture() -> (TempDir, PreparedComponentConfig<PreparedConfig>) {
        let owner = Builder::new()
            .prefix("rust-agent-fs-local-")
            .tempdir_in(".")
            .unwrap();
        let root = owner.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("existing.txt"), b"old").unwrap();
        let relative = root
            .strip_prefix(std::env::current_dir().unwrap())
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let bootstrap = rust_agent_resource_namespace_bootstrap_local::build(
            &BootstrapConfig,
            BootstrapDependencies,
            RuntimePrimitiveBindings::none(),
        )
        .unwrap()
        .into_service();
        let binding = ResourceNamespaceBootstrapBinding::from_provider(bootstrap);
        let route = ResourceNamespaceRoute::checked(
            "fs-local",
            "cap:fs-read",
            None,
            "resource-namespace-bootstrap-local",
            "resource-namespace-bootstrap-local",
            SecurityEffects::READ_LOCAL,
        )
        .unwrap();
        let projection =
            BootstrapAuthorityProjection::checked(route, SecurityEffects::READ_LOCAL, true)
                .unwrap();
        let config = Config::checked(relative).unwrap();
        let preparation = projection
            .context(&binding, CancellationToken::new(), None)
            .unwrap();
        let prepared = run(prepare_resource_namespaces(&config, preparation)).unwrap();
        (owner, prepared)
    }

    fn service(prepared: &PreparedComponentConfig<PreparedConfig>) -> Arc<LocalFileSystem> {
        build(prepared.value(), Dependencies, runtime(Duration::ZERO))
            .unwrap()
            .into_service()
    }

    #[test]
    fn write_modes_parent_creation_and_read_facade_are_exact() {
        let (owner, prepared) = fixture();
        let service = service(&prepared);
        let reads = FileReadBinding::from_provider(Arc::clone(&service));
        let writes = FileWriteBinding::from_provider(service);
        assert_eq!(reads.effects(), SecurityEffects::READ_LOCAL);
        assert_eq!(
            writes.effects(),
            SecurityEffects::READ_LOCAL | SecurityEffects::WRITE_LOCAL
        );
        let existing = AgentPath::new("existing.txt").unwrap();
        assert_eq!(
            run(writes.write(
                context(CancellationToken::new(), None),
                &existing,
                b"forbidden",
                WriteOptions::new(WriteMode::CreateNew, false),
            )),
            Err(FsError::AlreadyExists)
        );
        run(writes.write(
            context(CancellationToken::new(), None),
            &existing,
            b"new",
            WriteOptions::new(WriteMode::Truncate, false),
        ))
        .unwrap();
        run(writes.write(
            context(CancellationToken::new(), None),
            &existing,
            b"-tail",
            WriteOptions::new(WriteMode::Append, false),
        ))
        .unwrap();
        let content = run(reads.read(
            context(CancellationToken::new(), None),
            &existing,
            ByteRange::new(0, NonZeroUsize::new(32).unwrap()).unwrap(),
        ))
        .unwrap();
        assert_eq!(content.as_slice(), b"new-tail");

        let nested = AgentPath::new("created/inside.txt").unwrap();
        run(writes.write(
            context(CancellationToken::new(), None),
            &nested,
            b"inside",
            WriteOptions::new(WriteMode::CreateNew, true),
        ))
        .unwrap();
        assert_eq!(
            fs::read(owner.path().join("root/created/inside.txt")).unwrap(),
            b"inside"
        );
    }

    #[test]
    fn symlink_and_hardlink_write_redirects_are_rejected_before_mutation() {
        let (owner, prepared) = fixture();
        let root = owner.path().join("root");
        let outside = owner.path().join("outside.txt");
        fs::write(&outside, b"outside-secret").unwrap();
        std::os::unix::fs::symlink("../outside.txt", root.join("escape.txt")).unwrap();
        std::os::unix::fs::symlink("..", root.join("escape-dir")).unwrap();
        fs::hard_link(&outside, root.join("alias.txt")).unwrap();
        let writes = FileWriteBinding::from_provider(service(&prepared));
        for path in ["escape.txt", "escape-dir/new.txt", "alias.txt"] {
            assert!(matches!(
                run(writes.write(
                    context(CancellationToken::new(), None),
                    &AgentPath::new(path).unwrap(),
                    b"overwrite",
                    WriteOptions::new(WriteMode::Truncate, true),
                )),
                Err(FsError::PermissionDenied | FsError::NotDirectory)
            ));
        }
        assert_eq!(fs::read(outside).unwrap(), b"outside-secret");
    }

    #[test]
    fn cancellation_and_deadline_reject_before_creating_a_file() {
        let (owner, prepared) = fixture();
        let writes = FileWriteBinding::from_provider(service(&prepared));
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert_eq!(
            run(writes.write(
                context(cancellation, None),
                &AgentPath::new("cancelled.txt").unwrap(),
                b"data",
                WriteOptions::new(WriteMode::CreateNew, false),
            )),
            Err(FsError::Cancelled)
        );
        assert_eq!(
            run(writes.write(
                context(
                    CancellationToken::new(),
                    Some(RuntimeInstant::from_monotonic_duration(Duration::ZERO)),
                ),
                &AgentPath::new("expired.txt").unwrap(),
                b"data",
                WriteOptions::new(WriteMode::CreateNew, false),
            )),
            Err(FsError::DeadlineExceeded)
        );
        assert!(!owner.path().join("root/cancelled.txt").exists());
        assert!(!owner.path().join("root/expired.txt").exists());
    }

    #[test]
    fn retained_anchor_writes_only_to_the_original_directory_after_replacement() {
        let (owner, prepared) = fixture();
        let root = owner.path().join("root");
        let moved = owner.path().join("moved");
        fs::rename(&root, &moved).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(root.join("existing.txt"), b"replacement").unwrap();
        let writes = FileWriteBinding::from_provider(service(&prepared));
        run(writes.write(
            context(CancellationToken::new(), None),
            &AgentPath::new("existing.txt").unwrap(),
            b"anchored",
            WriteOptions::new(WriteMode::Truncate, false),
        ))
        .unwrap();
        assert_eq!(fs::read(moved.join("existing.txt")).unwrap(), b"anchored");
        assert_eq!(fs::read(root.join("existing.txt")).unwrap(), b"replacement");
    }

    #[test]
    fn config_and_runtime_projection_are_closed() {
        assert!(Config::checked("../escape").is_err());
        let (_owner, prepared) = fixture();
        assert!(
            build(
                prepared.value(),
                Dependencies,
                RuntimePrimitiveBindings::none()
            )
            .is_err()
        );
    }
}
