//! Bounded, provider-neutral filesystem contracts.
//!
//! Logical paths never expose a Host root. Concrete providers are responsible for anchoring an
//! [`AgentPath`] inside their selected resource namespace and for preserving the bounds carried by
//! [`FsCallContext`] and [`DirPageRequest`]. Consumer bindings revalidate every provider result.

use std::{fmt, future::Future, num::NonZeroUsize, pin::Pin, sync::Arc};

use rust_agent_core::{CanonicalId, MaybeSendSync};
use rust_agent_runtime_api::{CancellationToken, RuntimeInstant};

pub const MAX_AGENT_PATH_BYTES: usize = 4 * 1024;
pub const MAX_AGENT_PATH_DEPTH: usize = 128;
pub const MAX_FS_CALL_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_FS_RANGE_BYTES: usize = 1024 * 1024;
pub const MAX_DIR_PAGE_ENTRIES: usize = 1024;
pub const MAX_DIR_PAGE_BYTES: usize = 1024 * 1024;
pub const MAX_DIR_CURSOR_BYTES: usize = 512;

#[cfg(not(target_arch = "wasm32"))]
pub type FsFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type FsFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// A normalized relative path in a provider-owned namespace.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AgentPath(Arc<str>);

impl AgentPath {
    pub fn root() -> Self {
        Self(Arc::from(""))
    }

    pub fn new(value: impl Into<String>) -> Result<Self, FsError> {
        let value = value.into();
        validate_path(&value, false)?;
        Ok(Self(Arc::from(value)))
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn depth(&self) -> usize {
        if self.is_root() {
            0
        } else {
            self.0.split('/').count()
        }
    }

    pub fn join(&self, segment: &str) -> Result<Self, FsError> {
        validate_segment(segment)?;
        let value = if self.is_root() {
            segment.to_owned()
        } else {
            format!("{}/{segment}", self.0)
        };
        Self::new(value)
    }

    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            return None;
        }
        match self.0.rsplit_once('/') {
            Some((parent, _)) if !parent.is_empty() => Some(Self(Arc::from(parent))),
            _ => Some(Self::root()),
        }
    }
}

impl fmt::Debug for AgentPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AgentPath").field(&self.0).finish()
    }
}

impl fmt::Display for AgentPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            formatter.write_str(".")
        } else {
            formatter.write_str(&self.0)
        }
    }
}

fn validate_path(value: &str, allow_root: bool) -> Result<(), FsError> {
    if value.is_empty() {
        return if allow_root {
            Ok(())
        } else {
            Err(FsError::InvalidPath)
        };
    }
    if value.len() > MAX_AGENT_PATH_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
    {
        return Err(FsError::InvalidPath);
    }
    let mut depth = 0_usize;
    for segment in value.split('/') {
        validate_segment(segment)?;
        depth = depth.checked_add(1).ok_or(FsError::InvalidPath)?;
        if depth > MAX_AGENT_PATH_DEPTH {
            return Err(FsError::PathTooDeep);
        }
    }
    Ok(())
}

fn validate_segment(value: &str) -> Result<(), FsError> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || value.len() > MAX_AGENT_PATH_BYTES
        || value
            .chars()
            .any(|character| character == '\0' || character.is_control() || character == '/')
        || value.contains('\\')
    {
        return Err(FsError::InvalidPath);
    }
    Ok(())
}

/// Per-call cancellation, deadline and aggregate output ceilings.
#[derive(Clone, Debug)]
pub struct FsCallContext {
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
    byte_budget: NonZeroUsize,
    entry_budget: NonZeroUsize,
}

impl FsCallContext {
    pub fn new(
        cancellation: CancellationToken,
        deadline: Option<RuntimeInstant>,
        byte_budget: NonZeroUsize,
        entry_budget: NonZeroUsize,
    ) -> Result<Self, FsError> {
        if byte_budget.get() > MAX_FS_CALL_BYTES || entry_budget.get() > MAX_DIR_PAGE_ENTRIES {
            return Err(FsError::BudgetExceedsHardLimit);
        }
        Ok(Self {
            cancellation,
            deadline,
            byte_budget,
            entry_budget,
        })
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub const fn deadline(&self) -> Option<RuntimeInstant> {
        self.deadline
    }

    pub const fn byte_budget(&self) -> NonZeroUsize {
        self.byte_budget
    }

    pub const fn entry_budget(&self) -> NonZeroUsize {
        self.entry_budget
    }

    fn preflight(&self) -> Result<(), FsError> {
        if self.cancellation.is_cancelled() {
            Err(FsError::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRange {
    start: u64,
    length: NonZeroUsize,
}

impl ByteRange {
    pub fn new(start: u64, length: NonZeroUsize) -> Result<Self, FsError> {
        if length.get() > MAX_FS_RANGE_BYTES || start.checked_add(length.get() as u64).is_none() {
            return Err(FsError::InvalidRange);
        }
        Ok(Self { start, length })
    }

    pub const fn start(self) -> u64 {
        self.start
    }

    pub const fn length(self) -> NonZeroUsize {
        self.length
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileKind {
    File,
    Directory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileMetadata {
    kind: FileKind,
    byte_len: u64,
    readonly: bool,
}

impl FileMetadata {
    pub const fn new(kind: FileKind, byte_len: u64, readonly: bool) -> Self {
        Self {
            kind,
            byte_len,
            readonly,
        }
    }

    pub const fn kind(&self) -> FileKind {
        self.kind
    }

    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub const fn readonly(&self) -> bool {
        self.readonly
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct FileBytes(Arc<[u8]>);

impl FileBytes {
    pub fn new(bytes: Vec<u8>) -> Result<Self, FsError> {
        if bytes.len() > MAX_FS_RANGE_BYTES {
            return Err(FsError::OutputTooLarge);
        }
        Ok(Self(Arc::from(bytes)))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for FileBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileBytes")
            .field("len", &self.len())
            .finish()
    }
}

/// Provider-bound opaque continuation data for one directory and snapshot.
#[derive(Clone, Eq, PartialEq)]
pub struct DirPageCursor {
    provider_key: CanonicalId,
    path: AgentPath,
    token: Arc<[u8]>,
}

impl DirPageCursor {
    pub fn new(
        provider_key: impl Into<String>,
        path: AgentPath,
        token: Vec<u8>,
    ) -> Result<Self, FsError> {
        let provider_key =
            CanonicalId::new(provider_key.into()).map_err(|_| FsError::InvalidProviderKey)?;
        if token.is_empty() || token.len() > MAX_DIR_CURSOR_BYTES {
            return Err(FsError::InvalidCursor);
        }
        Ok(Self {
            provider_key,
            path,
            token: Arc::from(token),
        })
    }

    pub fn provider_key(&self) -> &str {
        self.provider_key.as_str()
    }

    pub const fn path(&self) -> &AgentPath {
        &self.path
    }

    pub fn token(&self) -> &[u8] {
        &self.token
    }

    fn encoded_bytes(&self) -> Result<usize, FsError> {
        self.provider_key
            .as_str()
            .len()
            .checked_add(self.path.as_str().len())
            .and_then(|value| value.checked_add(self.token.len()))
            .ok_or(FsError::OutputTooLarge)
    }
}

impl fmt::Debug for DirPageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirPageCursor")
            .field("provider_key", &self.provider_key)
            .field("path", &self.path)
            .field("token_len", &self.token.len())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirPageRequest {
    path: AgentPath,
    cursor: Option<DirPageCursor>,
    max_entries: NonZeroUsize,
    byte_budget: NonZeroUsize,
}

impl DirPageRequest {
    pub fn new(
        path: AgentPath,
        cursor: Option<DirPageCursor>,
        max_entries: NonZeroUsize,
        byte_budget: NonZeroUsize,
    ) -> Result<Self, FsError> {
        if max_entries.get() > MAX_DIR_PAGE_ENTRIES || byte_budget.get() > MAX_DIR_PAGE_BYTES {
            return Err(FsError::BudgetExceedsHardLimit);
        }
        if cursor.as_ref().is_some_and(|cursor| cursor.path() != &path) {
            return Err(FsError::InvalidCursor);
        }
        Ok(Self {
            path,
            cursor,
            max_entries,
            byte_budget,
        })
    }

    pub const fn path(&self) -> &AgentPath {
        &self.path
    }

    pub const fn cursor(&self) -> Option<&DirPageCursor> {
        self.cursor.as_ref()
    }

    pub const fn max_entries(&self) -> NonZeroUsize {
        self.max_entries
    }

    pub const fn byte_budget(&self) -> NonZeroUsize {
        self.byte_budget
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirEntry {
    name: Arc<str>,
    kind: FileKind,
    byte_len: u64,
}

impl DirEntry {
    pub fn new(name: impl Into<String>, kind: FileKind, byte_len: u64) -> Result<Self, FsError> {
        let name = name.into();
        validate_segment(&name)?;
        Ok(Self {
            name: Arc::from(name),
            kind,
            byte_len,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn kind(&self) -> FileKind {
        self.kind
    }

    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirPage {
    entries: Arc<[DirEntry]>,
    next_cursor: Option<DirPageCursor>,
    complete: bool,
    encoded_bytes: usize,
}

impl DirPage {
    pub fn new(
        entries: Vec<DirEntry>,
        next_cursor: Option<DirPageCursor>,
        complete: bool,
    ) -> Result<Self, FsError> {
        if entries.len() > MAX_DIR_PAGE_ENTRIES || complete == next_cursor.is_some() {
            return Err(FsError::InvalidPage);
        }
        let mut encoded_bytes = 0_usize;
        let mut previous: Option<&str> = None;
        for entry in &entries {
            if previous.is_some_and(|previous| previous >= entry.name()) {
                return Err(FsError::InvalidPage);
            }
            previous = Some(entry.name());
            encoded_bytes = encoded_bytes
                .checked_add(entry.name().len())
                .and_then(|value| value.checked_add(std::mem::size_of::<u64>() + 1))
                .ok_or(FsError::OutputTooLarge)?;
        }
        if let Some(cursor) = &next_cursor {
            encoded_bytes = encoded_bytes
                .checked_add(cursor.encoded_bytes()?)
                .ok_or(FsError::OutputTooLarge)?;
        }
        if encoded_bytes > MAX_DIR_PAGE_BYTES {
            return Err(FsError::OutputTooLarge);
        }
        Ok(Self {
            entries: Arc::from(entries),
            next_cursor,
            complete,
            encoded_bytes,
        })
    }

    pub fn entries(&self) -> &[DirEntry] {
        &self.entries
    }

    pub const fn next_cursor(&self) -> Option<&DirPageCursor> {
        self.next_cursor.as_ref()
    }

    pub const fn complete(&self) -> bool {
        self.complete
    }

    pub const fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteMode {
    CreateNew,
    Truncate,
    Append,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteOptions {
    mode: WriteMode,
    create_parents: bool,
}

impl WriteOptions {
    pub const fn new(mode: WriteMode, create_parents: bool) -> Self {
        Self {
            mode,
            create_parents,
        }
    }

    pub const fn mode(self) -> WriteMode {
        self.mode
    }

    pub const fn create_parents(self) -> bool {
        self.create_parents
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsError {
    InvalidProviderKey,
    InvalidPath,
    PathTooDeep,
    InvalidRange,
    InvalidCursor,
    ForeignCursor,
    InvalidPage,
    BudgetExceedsHardLimit,
    BudgetExceeded,
    OutputTooLarge,
    Cancelled,
    DeadlineExceeded,
    NotFound,
    AlreadyExists,
    NotFile,
    NotDirectory,
    PermissionDenied,
    NamespaceChanged,
    ProviderContractViolation,
    Provider,
}

impl fmt::Display for FsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProviderKey => "invalid filesystem provider key",
            Self::InvalidPath => "invalid logical filesystem path",
            Self::PathTooDeep => "logical filesystem path exceeds its depth limit",
            Self::InvalidRange => "invalid filesystem byte range",
            Self::InvalidCursor => "invalid directory continuation cursor",
            Self::ForeignCursor => "directory cursor belongs to another provider",
            Self::InvalidPage => "invalid directory page",
            Self::BudgetExceedsHardLimit => "filesystem budget exceeds its hard limit",
            Self::BudgetExceeded => "filesystem operation exceeded its call budget",
            Self::OutputTooLarge => "filesystem provider output exceeds its bound",
            Self::Cancelled => "filesystem operation was cancelled",
            Self::DeadlineExceeded => "filesystem operation deadline exceeded",
            Self::NotFound => "filesystem entry was not found",
            Self::AlreadyExists => "filesystem entry already exists",
            Self::NotFile => "filesystem entry is not a file",
            Self::NotDirectory => "filesystem entry is not a directory",
            Self::PermissionDenied => "filesystem operation was denied",
            Self::NamespaceChanged => "filesystem resource namespace changed",
            Self::ProviderContractViolation => "filesystem provider violated its contract",
            Self::Provider => "filesystem provider failed",
        })
    }
}

impl std::error::Error for FsError {}

pub trait FileRead: MaybeSendSync {
    fn provider_key(&self) -> CanonicalId;

    fn metadata<'a>(
        &'a self,
        context: FsCallContext,
        path: &'a AgentPath,
    ) -> FsFuture<'a, Result<FileMetadata, FsError>>;

    fn read<'a>(
        &'a self,
        context: FsCallContext,
        path: &'a AgentPath,
        range: ByteRange,
    ) -> FsFuture<'a, Result<FileBytes, FsError>>;

    fn list_page(
        &self,
        context: FsCallContext,
        request: DirPageRequest,
    ) -> FsFuture<'_, Result<DirPage, FsError>>;
}

/// Consumer-facing read binding that keeps the raw provider private and rechecks output bounds.
#[derive(Clone)]
pub struct FileReadBinding {
    provider_key: CanonicalId,
    provider: Arc<dyn FileRead>,
}

impl FileReadBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: FileRead + 'static,
    {
        let provider_key = provider.provider_key();
        Self {
            provider_key,
            provider,
        }
    }

    pub fn provider_key(&self) -> &str {
        self.provider_key.as_str()
    }

    pub fn metadata<'a>(
        &'a self,
        context: FsCallContext,
        path: &'a AgentPath,
    ) -> FsFuture<'a, Result<FileMetadata, FsError>> {
        if let Err(error) = context.preflight() {
            return Box::pin(async move { Err(error) });
        }
        self.provider.metadata(context, path)
    }

    pub fn read<'a>(
        &'a self,
        context: FsCallContext,
        path: &'a AgentPath,
        range: ByteRange,
    ) -> FsFuture<'a, Result<FileBytes, FsError>> {
        if let Err(error) = context.preflight() {
            return Box::pin(async move { Err(error) });
        }
        if range.length().get() > context.byte_budget().get() {
            return Box::pin(async { Err(FsError::BudgetExceeded) });
        }
        Box::pin(async move {
            let output = self.provider.read(context, path, range).await?;
            if output.len() > range.length().get() {
                return Err(FsError::ProviderContractViolation);
            }
            Ok(output)
        })
    }

    pub fn list_page(
        &self,
        context: FsCallContext,
        request: DirPageRequest,
    ) -> FsFuture<'_, Result<DirPage, FsError>> {
        if let Err(error) = context.preflight() {
            return Box::pin(async move { Err(error) });
        }
        if request.max_entries().get() > context.entry_budget().get()
            || request.byte_budget().get() > context.byte_budget().get()
        {
            return Box::pin(async { Err(FsError::BudgetExceeded) });
        }
        if request
            .cursor()
            .is_some_and(|cursor| cursor.provider_key() != self.provider_key())
        {
            return Box::pin(async { Err(FsError::ForeignCursor) });
        }
        let provider_key = self.provider_key.clone();
        let path = request.path().clone();
        let previous_cursor = request.cursor().cloned();
        let max_entries = request.max_entries().get();
        let byte_budget = request.byte_budget().get();
        Box::pin(async move {
            let page = self.provider.list_page(context, request).await?;
            if page.entries().len() > max_entries || page.encoded_bytes() > byte_budget {
                return Err(FsError::ProviderContractViolation);
            }
            if page.next_cursor().is_some_and(|cursor| {
                cursor.provider_key() != provider_key.as_str() || cursor.path() != &path
            }) {
                return Err(FsError::ProviderContractViolation);
            }
            if previous_cursor
                .as_ref()
                .zip(page.next_cursor())
                .is_some_and(|(previous, next)| previous == next)
            {
                return Err(FsError::ProviderContractViolation);
            }
            Ok(page)
        })
    }
}

impl fmt::Debug for FileReadBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileReadBinding")
            .field("provider_key", &self.provider_key)
            .finish_non_exhaustive()
    }
}

pub trait FileWrite: MaybeSendSync {
    fn provider_key(&self) -> CanonicalId;

    fn write<'a>(
        &'a self,
        context: FsCallContext,
        path: &'a AgentPath,
        data: &'a [u8],
        options: WriteOptions,
    ) -> FsFuture<'a, Result<(), FsError>>;
}

/// Consumer-facing write binding that validates cancellation and byte bounds before dispatch.
#[derive(Clone)]
pub struct FileWriteBinding {
    provider_key: CanonicalId,
    provider: Arc<dyn FileWrite>,
}

impl FileWriteBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: FileWrite + 'static,
    {
        let provider_key = provider.provider_key();
        Self {
            provider_key,
            provider,
        }
    }

    pub fn provider_key(&self) -> &str {
        self.provider_key.as_str()
    }

    pub fn write<'a>(
        &'a self,
        context: FsCallContext,
        path: &'a AgentPath,
        data: &'a [u8],
        options: WriteOptions,
    ) -> FsFuture<'a, Result<(), FsError>> {
        if let Err(error) = context.preflight() {
            return Box::pin(async move { Err(error) });
        }
        if data.len() > MAX_FS_CALL_BYTES || data.len() > context.byte_budget().get() {
            return Box::pin(async { Err(FsError::BudgetExceeded) });
        }
        self.provider.write(context, path, data, options)
    }
}

impl fmt::Debug for FileWriteBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileWriteBinding")
            .field("provider_key", &self.provider_key)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll, Waker},
    };

    use super::*;

    fn context(bytes: usize, entries: usize) -> FsCallContext {
        FsCallContext::new(
            CancellationToken::new(),
            None,
            NonZeroUsize::new(bytes).unwrap(),
            NonZeroUsize::new(entries).unwrap(),
        )
        .unwrap()
    }

    fn ready<T>(mut future: FsFuture<'_, T>) -> T {
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("test future unexpectedly pending"),
        }
    }

    #[test]
    fn logical_paths_are_canonical_bounded_and_deterministic() {
        let path = AgentPath::new("src/lib.rs").unwrap();
        assert_eq!(path.as_str(), "src/lib.rs");
        assert_eq!(path.depth(), 2);
        assert_eq!(path.parent().unwrap().as_str(), "src");
        assert_eq!(path.parent().unwrap().parent().unwrap(), AgentPath::root());
        assert_eq!(AgentPath::root().join("src").unwrap().as_str(), "src");
        assert_eq!(path, AgentPath::new(path.as_str()).unwrap());

        for invalid in [
            "",
            "/tmp",
            "src/",
            "src//lib.rs",
            ".",
            "..",
            "a/../b",
            "a\\b",
            "a/line\nbreak",
        ] {
            assert_eq!(AgentPath::new(invalid), Err(FsError::InvalidPath));
        }
        let too_deep = std::iter::repeat_n("x", MAX_AGENT_PATH_DEPTH + 1)
            .collect::<Vec<_>>()
            .join("/");
        assert_eq!(AgentPath::new(too_deep), Err(FsError::PathTooDeep));
        assert_eq!(
            AgentPath::new("x".repeat(MAX_AGENT_PATH_BYTES + 1)),
            Err(FsError::InvalidPath)
        );
    }

    #[test]
    fn contexts_ranges_cursors_and_pages_enforce_every_boundary() {
        assert!(
            context(MAX_FS_CALL_BYTES, MAX_DIR_PAGE_ENTRIES)
                .byte_budget()
                .get()
                > 0
        );
        assert!(matches!(
            FsCallContext::new(
                CancellationToken::new(),
                None,
                NonZeroUsize::new(MAX_FS_CALL_BYTES + 1).unwrap(),
                NonZeroUsize::MIN,
            ),
            Err(FsError::BudgetExceedsHardLimit)
        ));
        assert!(ByteRange::new(0, NonZeroUsize::new(MAX_FS_RANGE_BYTES).unwrap()).is_ok());
        assert_eq!(
            ByteRange::new(0, NonZeroUsize::new(MAX_FS_RANGE_BYTES + 1).unwrap()),
            Err(FsError::InvalidRange)
        );
        assert_eq!(
            ByteRange::new(u64::MAX, NonZeroUsize::MIN),
            Err(FsError::InvalidRange)
        );

        let root = AgentPath::root();
        assert!(DirPageCursor::new("local", root.clone(), vec![1; MAX_DIR_CURSOR_BYTES]).is_ok());
        assert_eq!(
            DirPageCursor::new("local", root.clone(), Vec::new()),
            Err(FsError::InvalidCursor)
        );
        assert_eq!(
            DirPageCursor::new("local", root.clone(), vec![1; MAX_DIR_CURSOR_BYTES + 1]),
            Err(FsError::InvalidCursor)
        );
        let cursor = DirPageCursor::new("local", root.clone(), vec![1]).unwrap();
        assert_eq!(
            DirPageRequest::new(
                AgentPath::new("other").unwrap(),
                Some(cursor.clone()),
                NonZeroUsize::MIN,
                NonZeroUsize::MIN,
            ),
            Err(FsError::InvalidCursor)
        );
        assert!(matches!(
            DirPageRequest::new(
                root.clone(),
                None,
                NonZeroUsize::new(MAX_DIR_PAGE_ENTRIES + 1).unwrap(),
                NonZeroUsize::MIN,
            ),
            Err(FsError::BudgetExceedsHardLimit)
        ));
        let a = DirEntry::new("a", FileKind::File, 1).unwrap();
        let b = DirEntry::new("b", FileKind::Directory, 0).unwrap();
        let page = DirPage::new(vec![a.clone(), b], Some(cursor), false).unwrap();
        assert_eq!(
            page.encoded_bytes(),
            2 * (1 + std::mem::size_of::<u64>() + 1) + "local".len() + 1
        );
        assert_eq!(
            DirPage::new(vec![a.clone(), a], None, true),
            Err(FsError::InvalidPage)
        );
        assert_eq!(
            DirPage::new(
                Vec::new(),
                Some(DirPageCursor::new("local", root, vec![1]).unwrap()),
                true
            ),
            Err(FsError::InvalidPage)
        );
    }

    #[derive(Debug)]
    struct RecordingProvider {
        metadata: AtomicUsize,
        reads: AtomicUsize,
        lists: AtomicUsize,
        writes: AtomicUsize,
        oversized_read: bool,
        oversized_page: bool,
        wrong_cursor: bool,
    }

    impl RecordingProvider {
        fn valid() -> Self {
            Self {
                metadata: AtomicUsize::new(0),
                reads: AtomicUsize::new(0),
                lists: AtomicUsize::new(0),
                writes: AtomicUsize::new(0),
                oversized_read: false,
                oversized_page: false,
                wrong_cursor: false,
            }
        }
    }

    impl FileRead for RecordingProvider {
        fn provider_key(&self) -> CanonicalId {
            CanonicalId::new("local").unwrap()
        }

        fn metadata<'a>(
            &'a self,
            _context: FsCallContext,
            _path: &'a AgentPath,
        ) -> FsFuture<'a, Result<FileMetadata, FsError>> {
            self.metadata.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(FileMetadata::new(FileKind::File, 2, false)) })
        }

        fn read<'a>(
            &'a self,
            _context: FsCallContext,
            _path: &'a AgentPath,
            range: ByteRange,
        ) -> FsFuture<'a, Result<FileBytes, FsError>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let size = if self.oversized_read {
                range.length().get() + 1
            } else {
                range.length().get()
            };
            Box::pin(async move { FileBytes::new(vec![b'x'; size]) })
        }

        fn list_page(
            &self,
            _context: FsCallContext,
            request: DirPageRequest,
        ) -> FsFuture<'_, Result<DirPage, FsError>> {
            self.lists.fetch_add(1, Ordering::SeqCst);
            let count = if self.oversized_page { 2 } else { 1 };
            let entries = (0..count)
                .map(|index| DirEntry::new(format!("entry-{index}"), FileKind::File, 1).unwrap())
                .collect();
            let cursor_path = if self.wrong_cursor {
                AgentPath::new("wrong").unwrap()
            } else {
                request.path().clone()
            };
            Box::pin(async move {
                DirPage::new(
                    entries,
                    Some(DirPageCursor::new("local", cursor_path, vec![1]).unwrap()),
                    false,
                )
            })
        }
    }

    impl FileWrite for RecordingProvider {
        fn provider_key(&self) -> CanonicalId {
            CanonicalId::new("local").unwrap()
        }

        fn write<'a>(
            &'a self,
            _context: FsCallContext,
            _path: &'a AgentPath,
            _data: &'a [u8],
            _options: WriteOptions,
        ) -> FsFuture<'a, Result<(), FsError>> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn read_and_write_rejections_precede_provider_callbacks() {
        let provider = Arc::new(RecordingProvider::valid());
        let reads = FileReadBinding::from_provider(Arc::clone(&provider));
        let writes = FileWriteBinding::from_provider(Arc::clone(&provider));
        let path = AgentPath::new("file").unwrap();

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let cancelled_context = FsCallContext::new(
            cancelled,
            None,
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::MIN,
        )
        .unwrap();
        assert_eq!(
            ready(reads.read(
                cancelled_context,
                &path,
                ByteRange::new(0, NonZeroUsize::MIN).unwrap(),
            )),
            Err(FsError::Cancelled)
        );
        assert_eq!(provider.reads.load(Ordering::SeqCst), 0);

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let cancelled_context = FsCallContext::new(
            cancelled,
            None,
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::MIN,
        )
        .unwrap();
        assert_eq!(
            ready(reads.metadata(cancelled_context, &path)),
            Err(FsError::Cancelled)
        );
        assert_eq!(provider.metadata.load(Ordering::SeqCst), 0);

        assert_eq!(
            ready(reads.read(
                context(1, 1),
                &path,
                ByteRange::new(0, NonZeroUsize::new(2).unwrap()).unwrap(),
            )),
            Err(FsError::BudgetExceeded)
        );
        assert_eq!(provider.reads.load(Ordering::SeqCst), 0);

        let request = DirPageRequest::new(
            AgentPath::root(),
            None,
            NonZeroUsize::new(2).unwrap(),
            NonZeroUsize::new(8).unwrap(),
        )
        .unwrap();
        assert_eq!(
            ready(reads.list_page(context(8, 1), request)),
            Err(FsError::BudgetExceeded)
        );
        assert_eq!(provider.lists.load(Ordering::SeqCst), 0);

        assert_eq!(
            ready(writes.write(
                context(1, 1),
                &path,
                b"two",
                WriteOptions::new(WriteMode::CreateNew, false),
            )),
            Err(FsError::BudgetExceeded)
        );
        assert_eq!(provider.writes.load(Ordering::SeqCst), 0);

        ready(writes.write(
            context(3, 1),
            &path,
            b"two",
            WriteOptions::new(WriteMode::Truncate, true),
        ))
        .unwrap();
        assert_eq!(provider.writes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn provider_outputs_and_cursor_identity_are_revalidated() {
        let oversized = Arc::new(RecordingProvider {
            oversized_read: true,
            ..RecordingProvider::valid()
        });
        let reads = FileReadBinding::from_provider(oversized);
        let path = AgentPath::new("file").unwrap();
        assert_eq!(
            ready(reads.read(
                context(2, 1),
                &path,
                ByteRange::new(0, NonZeroUsize::new(2).unwrap()).unwrap(),
            )),
            Err(FsError::ProviderContractViolation)
        );

        let provider = Arc::new(RecordingProvider {
            oversized_page: true,
            ..RecordingProvider::valid()
        });
        let reads = FileReadBinding::from_provider(Arc::clone(&provider));
        let request = DirPageRequest::new(
            AgentPath::root(),
            None,
            NonZeroUsize::MIN,
            NonZeroUsize::new(128).unwrap(),
        )
        .unwrap();
        assert_eq!(
            ready(reads.list_page(context(128, 1), request)),
            Err(FsError::ProviderContractViolation)
        );

        let request = DirPageRequest::new(
            AgentPath::root(),
            Some(DirPageCursor::new("other", AgentPath::root(), vec![1]).unwrap()),
            NonZeroUsize::MIN,
            NonZeroUsize::new(128).unwrap(),
        )
        .unwrap();
        assert_eq!(
            ready(reads.list_page(context(128, 1), request)),
            Err(FsError::ForeignCursor)
        );
        assert_eq!(provider.lists.load(Ordering::SeqCst), 1);

        let wrong_cursor = FileReadBinding::from_provider(Arc::new(RecordingProvider {
            wrong_cursor: true,
            ..RecordingProvider::valid()
        }));
        let request = DirPageRequest::new(
            AgentPath::root(),
            None,
            NonZeroUsize::MIN,
            NonZeroUsize::new(128).unwrap(),
        )
        .unwrap();
        assert_eq!(
            ready(wrong_cursor.list_page(context(128, 1), request)),
            Err(FsError::ProviderContractViolation)
        );

        let reads = FileReadBinding::from_provider(Arc::new(RecordingProvider::valid()));
        let cursor = DirPageCursor::new("local", AgentPath::root(), vec![1]).unwrap();
        let request = DirPageRequest::new(
            AgentPath::root(),
            Some(cursor),
            NonZeroUsize::MIN,
            NonZeroUsize::new(128).unwrap(),
        )
        .unwrap();
        assert_eq!(
            ready(reads.list_page(context(128, 1), request)),
            Err(FsError::ProviderContractViolation)
        );
    }
}
