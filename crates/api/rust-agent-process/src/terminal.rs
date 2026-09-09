use std::{
    fmt,
    hash::{Hash, Hasher},
    num::NonZeroU64,
    num::NonZeroUsize,
    sync::Arc,
};

use rust_agent_core::{CanonicalId, MaybeSendSync, SecurityEffects};
use rust_agent_fs::AgentPath;
use rust_agent_policy::process::SandboxPolicy;
use rust_agent_runtime_api::CancellationToken;

use crate::{ProcessEnvironment, ProcessFuture};

pub const MAX_TERMINAL_IO_BYTES: usize = 1024 * 1024;
pub const MAX_TERMINAL_COLUMNS: u16 = 1_000;
pub const MAX_TERMINAL_ROWS: u16 = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalSize {
    columns: u16,
    rows: u16,
}

impl TerminalSize {
    pub fn checked(columns: u16, rows: u16) -> Result<Self, TerminalError> {
        if columns == 0 || rows == 0 || columns > MAX_TERMINAL_COLUMNS || rows > MAX_TERMINAL_ROWS {
            return Err(TerminalError::InvalidSize);
        }
        Ok(Self { columns, rows })
    }

    pub const fn columns(self) -> u16 {
        self.columns
    }

    pub const fn rows(self) -> u16 {
        self.rows
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalSpec {
    cwd: AgentPath,
    environment: ProcessEnvironment,
    policy: SandboxPolicy,
    size: TerminalSize,
}

impl TerminalSpec {
    pub const fn new(
        cwd: AgentPath,
        environment: ProcessEnvironment,
        policy: SandboxPolicy,
        size: TerminalSize,
    ) -> Self {
        Self {
            cwd,
            environment,
            policy,
            size,
        }
    }

    pub const fn cwd(&self) -> &AgentPath {
        &self.cwd
    }

    pub const fn environment(&self) -> &ProcessEnvironment {
        &self.environment
    }

    pub const fn policy(&self) -> &SandboxPolicy {
        &self.policy
    }

    pub const fn size(&self) -> TerminalSize {
        self.size
    }
}

#[derive(Clone)]
pub struct TerminalId {
    provider_key: CanonicalId,
    binding_authority: Option<Arc<()>>,
    identity: NonZeroU64,
}

impl TerminalId {
    pub fn provider_key(&self) -> &str {
        self.provider_key.as_str()
    }

    pub const fn identity(&self) -> NonZeroU64 {
        self.identity
    }
}

impl fmt::Debug for TerminalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalId")
            .field("provider_key", &self.provider_key)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl PartialEq for TerminalId {
    fn eq(&self, other: &Self) -> bool {
        self.provider_key == other.provider_key
            && match (&self.binding_authority, &other.binding_authority) {
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                (None, None) => true,
                _ => false,
            }
            && self.identity == other.identity
    }
}

impl Eq for TerminalId {}

impl Hash for TerminalId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.provider_key.hash(state);
        self.binding_authority.as_ref().map(Arc::as_ptr).hash(state);
        self.identity.hash(state);
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TerminalBytes(Arc<[u8]>);

impl TerminalBytes {
    pub fn checked(bytes: Vec<u8>) -> Result<Self, TerminalError> {
        if bytes.len() > MAX_TERMINAL_IO_BYTES {
            return Err(TerminalError::IoBudgetExceeded);
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

impl fmt::Debug for TerminalBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalBytes")
            .field("len", &self.0.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalReadRequest {
    max_bytes: NonZeroUsize,
}

impl TerminalReadRequest {
    pub fn checked(max_bytes: NonZeroUsize) -> Result<Self, TerminalError> {
        if max_bytes.get() > MAX_TERMINAL_IO_BYTES {
            return Err(TerminalError::IoBudgetExceeded);
        }
        Ok(Self { max_bytes })
    }

    pub const fn max_bytes(self) -> NonZeroUsize {
        self.max_bytes
    }
}

pub trait TerminalManager: MaybeSendSync {
    fn provider_key(&self) -> CanonicalId;

    fn effects(&self) -> SecurityEffects;

    /// Allocates the provider-owned identity before the binding seals it for consumers.
    fn open_provider(
        &self,
        spec: TerminalSpec,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<NonZeroU64, TerminalError>>;

    fn open(
        &self,
        spec: TerminalSpec,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<TerminalId, TerminalError>> {
        let provider_key = self.provider_key();
        let future = self.open_provider(spec, cancellation);
        Box::pin(async move {
            let identity = future.await?;
            Ok(TerminalId {
                provider_key,
                binding_authority: None,
                identity,
            })
        })
    }

    fn write(
        &self,
        id: TerminalId,
        data: TerminalBytes,
    ) -> ProcessFuture<'_, Result<(), TerminalError>>;

    fn read(
        &self,
        id: TerminalId,
        request: TerminalReadRequest,
    ) -> ProcessFuture<'_, Result<TerminalBytes, TerminalError>>;

    fn resize(
        &self,
        id: TerminalId,
        size: TerminalSize,
    ) -> ProcessFuture<'_, Result<(), TerminalError>>;

    fn close(&self, id: TerminalId) -> ProcessFuture<'_, Result<(), TerminalError>>;
}

#[derive(Clone)]
pub struct TerminalBinding {
    component_identity: Option<CanonicalId>,
    provider_key: CanonicalId,
    effects: SecurityEffects,
    binding_authority: Arc<()>,
    provider: Arc<dyn TerminalManager>,
}

impl TerminalBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: TerminalManager + 'static,
    {
        Self {
            component_identity: None,
            provider_key: provider.provider_key(),
            effects: provider.effects(),
            binding_authority: Arc::new(()),
            provider,
        }
    }

    #[doc(hidden)]
    pub fn from_generated_component<T>(
        component_identity: impl Into<String>,
        effective_effects: SecurityEffects,
        provider: Arc<T>,
    ) -> Result<Self, TerminalError>
    where
        T: TerminalManager + 'static,
    {
        let component_identity = CanonicalId::new(component_identity.into())
            .map_err(|_| TerminalError::InvalidProviderIdentity)?;
        if !provider.effects().is_subset_of(effective_effects) {
            return Err(TerminalError::ProviderContractViolation);
        }
        Ok(Self {
            component_identity: Some(component_identity),
            provider_key: provider.provider_key(),
            effects: effective_effects,
            binding_authority: Arc::new(()),
            provider,
        })
    }

    pub fn provider_key(&self) -> &str {
        self.provider_key.as_str()
    }

    pub const fn effects(&self) -> SecurityEffects {
        self.effects
    }

    pub fn open(
        &self,
        spec: TerminalSpec,
        cancellation: CancellationToken,
    ) -> ProcessFuture<'_, Result<TerminalId, TerminalError>> {
        if cancellation.is_cancelled() {
            return Box::pin(async { Err(TerminalError::Cancelled) });
        }
        let future = self.provider.open(spec, cancellation);
        Box::pin(async move {
            let mut id = future.await?;
            if id.provider_key != self.provider_key || id.binding_authority.is_some() {
                return Err(TerminalError::ProviderContractViolation);
            }
            id.binding_authority = Some(Arc::clone(&self.binding_authority));
            Ok(id)
        })
    }

    pub fn write(
        &self,
        id: TerminalId,
        data: TerminalBytes,
    ) -> ProcessFuture<'_, Result<(), TerminalError>> {
        if id.provider_key != self.provider_key
            || !id
                .binding_authority
                .as_ref()
                .is_some_and(|authority| Arc::ptr_eq(authority, &self.binding_authority))
        {
            return Box::pin(async { Err(TerminalError::ForeignTerminal) });
        }
        self.provider.write(id, data)
    }

    pub fn read(
        &self,
        id: TerminalId,
        request: TerminalReadRequest,
    ) -> ProcessFuture<'_, Result<TerminalBytes, TerminalError>> {
        if id.provider_key != self.provider_key
            || !id
                .binding_authority
                .as_ref()
                .is_some_and(|authority| Arc::ptr_eq(authority, &self.binding_authority))
        {
            return Box::pin(async { Err(TerminalError::ForeignTerminal) });
        }
        let max_bytes = request.max_bytes.get();
        let future = self.provider.read(id, request);
        Box::pin(async move {
            let output = future.await?;
            if output.len() > max_bytes {
                return Err(TerminalError::ProviderContractViolation);
            }
            Ok(output)
        })
    }

    pub fn resize(
        &self,
        id: TerminalId,
        size: TerminalSize,
    ) -> ProcessFuture<'_, Result<(), TerminalError>> {
        if id.provider_key != self.provider_key
            || !id
                .binding_authority
                .as_ref()
                .is_some_and(|authority| Arc::ptr_eq(authority, &self.binding_authority))
        {
            return Box::pin(async { Err(TerminalError::ForeignTerminal) });
        }
        self.provider.resize(id, size)
    }

    pub fn close(&self, id: TerminalId) -> ProcessFuture<'_, Result<(), TerminalError>> {
        if id.provider_key != self.provider_key
            || !id
                .binding_authority
                .as_ref()
                .is_some_and(|authority| Arc::ptr_eq(authority, &self.binding_authority))
        {
            return Box::pin(async { Err(TerminalError::ForeignTerminal) });
        }
        self.provider.close(id)
    }
}

impl fmt::Debug for TerminalBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalBinding")
            .field("component_identity", &self.component_identity)
            .field("provider_key", &self.provider_key)
            .field("effects", &self.effects)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalError {
    Cancelled,
    DeadlineExceeded,
    InvalidSize,
    IoBudgetExceeded,
    ForeignTerminal,
    OpenFailed,
    WriteFailed,
    ReadFailed,
    ResizeFailed,
    CloseFailed,
    InvalidProviderIdentity,
    ProviderContractViolation,
}

impl fmt::Display for TerminalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Cancelled => "terminal operation was cancelled",
            Self::DeadlineExceeded => "terminal operation deadline was exceeded",
            Self::InvalidSize => "terminal dimensions are invalid",
            Self::IoBudgetExceeded => "terminal I/O exceeds the hard byte maximum",
            Self::ForeignTerminal => "terminal id belongs to a different provider",
            Self::OpenFailed => "terminal open failed",
            Self::WriteFailed => "terminal write failed",
            Self::ReadFailed => "terminal read failed",
            Self::ResizeFailed => "terminal resize failed",
            Self::CloseFailed => "terminal close failed",
            Self::InvalidProviderIdentity => "terminal provider identity is invalid",
            Self::ProviderContractViolation => "terminal provider violated its binding contract",
        })
    }
}

impl std::error::Error for TerminalError {}
