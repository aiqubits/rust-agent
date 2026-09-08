//! Bounded, Agent-owned temporary spill storage contracts.

use std::{fmt, future::Future, num::NonZeroUsize, pin::Pin, sync::Arc};

use rust_agent_core::{AgentId, CanonicalId, Digest, MaybeSendSync};
use rust_agent_runtime_api::{CancellationToken, RuntimeInstant};
use sha2::{Digest as _, Sha256};

pub const MAX_SPILL_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SPILL_RANGE_BYTES: usize = 1024 * 1024;

#[cfg(not(target_arch = "wasm32"))]
pub type SpillFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type SpillFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

#[derive(Clone, Debug)]
pub struct SpillCallContext {
    agent_id: AgentId,
    cancellation: CancellationToken,
    now: RuntimeInstant,
    deadline: Option<RuntimeInstant>,
    byte_budget: NonZeroUsize,
}

impl SpillCallContext {
    pub fn new(
        agent_id: AgentId,
        cancellation: CancellationToken,
        now: RuntimeInstant,
        deadline: Option<RuntimeInstant>,
        byte_budget: NonZeroUsize,
    ) -> Result<Self, SpillError> {
        if byte_budget.get() > MAX_SPILL_BYTES {
            return Err(SpillError::BudgetExceedsHardLimit);
        }
        Ok(Self {
            agent_id,
            cancellation,
            now,
            deadline,
            byte_budget,
        })
    }

    pub const fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub const fn now(&self) -> RuntimeInstant {
        self.now
    }

    pub const fn deadline(&self) -> Option<RuntimeInstant> {
        self.deadline
    }

    pub const fn byte_budget(&self) -> NonZeroUsize {
        self.byte_budget
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpillInput {
    data: Arc<[u8]>,
    content_digest: Digest,
}

impl SpillInput {
    pub fn new(data: Vec<u8>) -> Result<Self, SpillError> {
        if data.is_empty() || data.len() > MAX_SPILL_BYTES {
            return Err(SpillError::InputTooLarge);
        }
        let content_digest = digest(&data);
        Ok(Self {
            data: Arc::from(data),
            content_digest,
        })
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub const fn content_digest(&self) -> Digest {
        self.content_digest
    }

    pub fn byte_len(&self) -> usize {
        self.data.len()
    }
}

fn digest(bytes: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Digest::from_bytes(hasher.finalize().into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpillRef {
    provider_key: CanonicalId,
    owner: AgentId,
    content_digest: Digest,
    byte_len: u64,
    expires_at: RuntimeInstant,
}

impl SpillRef {
    pub fn new(
        provider_key: impl Into<String>,
        owner: AgentId,
        content_digest: Digest,
        byte_len: u64,
        expires_at: RuntimeInstant,
    ) -> Result<Self, SpillError> {
        let provider_key =
            CanonicalId::new(provider_key.into()).map_err(|_| SpillError::InvalidProviderKey)?;
        if byte_len == 0 || byte_len > MAX_SPILL_BYTES as u64 {
            return Err(SpillError::InputTooLarge);
        }
        Ok(Self {
            provider_key,
            owner,
            content_digest,
            byte_len,
            expires_at,
        })
    }

    pub fn provider_key(&self) -> &str {
        self.provider_key.as_str()
    }

    pub const fn owner(&self) -> AgentId {
        self.owner
    }

    pub const fn content_digest(&self) -> Digest {
        self.content_digest
    }

    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub const fn expires_at(&self) -> RuntimeInstant {
        self.expires_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpillByteRange {
    start: u64,
    length: NonZeroUsize,
}

impl SpillByteRange {
    pub fn new(start: u64, length: NonZeroUsize) -> Result<Self, SpillError> {
        if length.get() > MAX_SPILL_RANGE_BYTES || start.checked_add(length.get() as u64).is_none()
        {
            return Err(SpillError::InvalidRange);
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpillData(Arc<[u8]>);

impl SpillData {
    pub fn new(data: Vec<u8>) -> Result<Self, SpillError> {
        if data.len() > MAX_SPILL_RANGE_BYTES {
            return Err(SpillError::OutputTooLarge);
        }
        Ok(Self(Arc::from(data)))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpillError {
    InvalidProviderKey,
    InvalidRange,
    RangeOutOfBounds,
    ForeignReference,
    ForeignOwner,
    InputTooLarge,
    OutputTooLarge,
    BudgetExceedsHardLimit,
    BudgetExceeded,
    ReferenceMismatch,
    Expired,
    Cancelled,
    DeadlineExceeded,
    NotFound,
    Provider,
}

impl fmt::Display for SpillError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProviderKey => "invalid spill provider key",
            Self::InvalidRange => "invalid spill byte range",
            Self::RangeOutOfBounds => "spill byte range exceeds the referenced object",
            Self::ForeignReference => "spill reference belongs to another provider",
            Self::ForeignOwner => "spill reference belongs to another Agent",
            Self::InputTooLarge => "spill input exceeds the hard limit",
            Self::OutputTooLarge => "spill output exceeds the requested bound",
            Self::BudgetExceedsHardLimit => "spill budget exceeds the hard limit",
            Self::BudgetExceeded => "spill byte budget exceeded",
            Self::ReferenceMismatch => "spill provider returned a mismatched reference",
            Self::Expired => "spill reference is expired",
            Self::Cancelled => "spill operation was cancelled",
            Self::DeadlineExceeded => "spill operation deadline exceeded",
            Self::NotFound => "spill object was not found",
            Self::Provider => "spill provider failed",
        })
    }
}

impl std::error::Error for SpillError {}

pub trait SpillStore: MaybeSendSync {
    fn provider_key(&self) -> CanonicalId;

    fn put(
        &self,
        context: SpillCallContext,
        input: SpillInput,
    ) -> SpillFuture<'_, Result<SpillRef, SpillError>>;

    fn get(
        &self,
        context: SpillCallContext,
        reference: SpillRef,
        range: SpillByteRange,
    ) -> SpillFuture<'_, Result<SpillData, SpillError>>;

    fn purge_owner(&self, context: SpillCallContext) -> SpillFuture<'_, Result<(), SpillError>>;
}

/// Consumer-facing singleton binding that enforces provider and Agent ownership before callbacks.
#[derive(Clone)]
pub struct SpillStoreBinding {
    provider_key: CanonicalId,
    provider: Arc<dyn SpillStore>,
}

impl SpillStoreBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: SpillStore + 'static,
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

    pub fn put(
        &self,
        context: SpillCallContext,
        input: SpillInput,
    ) -> SpillFuture<'_, Result<SpillRef, SpillError>> {
        if context.cancellation.is_cancelled() {
            return Box::pin(async { Err(SpillError::Cancelled) });
        }
        if input.byte_len() > context.byte_budget.get() {
            return Box::pin(async { Err(SpillError::BudgetExceeded) });
        }
        let expected_key = self.provider_key.clone();
        let expected_owner = context.agent_id();
        let expected_digest = input.content_digest();
        let expected_len = input.byte_len() as u64;
        let now = context.now();
        let future = self.provider.put(context, input);
        Box::pin(async move {
            let reference = future.await?;
            if reference.provider_key != expected_key
                || reference.owner() != expected_owner
                || reference.content_digest() != expected_digest
                || reference.byte_len() != expected_len
                || reference.expires_at() <= now
            {
                return Err(SpillError::ReferenceMismatch);
            }
            Ok(reference)
        })
    }

    pub fn get(
        &self,
        context: SpillCallContext,
        reference: SpillRef,
        range: SpillByteRange,
    ) -> SpillFuture<'_, Result<SpillData, SpillError>> {
        if let Some(error) = self.preflight_reference(&context, &reference) {
            return Box::pin(async move { Err(error) });
        }
        if range.start + range.length.get() as u64 > reference.byte_len() {
            return Box::pin(async { Err(SpillError::RangeOutOfBounds) });
        }
        if range.length.get() > context.byte_budget.get() {
            return Box::pin(async { Err(SpillError::BudgetExceeded) });
        }
        let output_limit = range.length.get();
        let future = self.provider.get(context, reference, range);
        Box::pin(async move {
            let data = future.await?;
            if data.byte_len() > output_limit {
                return Err(SpillError::OutputTooLarge);
            }
            Ok(data)
        })
    }

    pub fn purge_owner(
        &self,
        context: SpillCallContext,
    ) -> SpillFuture<'_, Result<(), SpillError>> {
        if context.cancellation.is_cancelled() {
            return Box::pin(async { Err(SpillError::Cancelled) });
        }
        self.provider.purge_owner(context)
    }

    fn preflight_reference(
        &self,
        context: &SpillCallContext,
        reference: &SpillRef,
    ) -> Option<SpillError> {
        if context.cancellation.is_cancelled() {
            Some(SpillError::Cancelled)
        } else if reference.provider_key != self.provider_key {
            Some(SpillError::ForeignReference)
        } else if reference.owner() != context.agent_id() {
            Some(SpillError::ForeignOwner)
        } else if reference.expires_at() <= context.now() {
            Some(SpillError::Expired)
        } else {
            None
        }
    }
}

impl fmt::Debug for SpillStoreBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpillStoreBinding")
            .field("provider_key", &self.provider_key)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll, Waker},
        time::Duration,
    };

    use super::*;

    #[derive(Debug)]
    struct CountingStore {
        calls: AtomicUsize,
        mismatch: bool,
    }

    impl SpillStore for CountingStore {
        fn provider_key(&self) -> CanonicalId {
            CanonicalId::new("memory").unwrap()
        }

        fn put(
            &self,
            context: SpillCallContext,
            input: SpillInput,
        ) -> SpillFuture<'_, Result<SpillRef, SpillError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let owner = if self.mismatch {
                AgentId::from_nonzero_u128(999).unwrap()
            } else {
                context.agent_id()
            };
            let reference = SpillRef::new(
                "memory",
                owner,
                input.content_digest(),
                input.byte_len() as u64,
                context.now() + Duration::from_secs(1),
            )
            .unwrap();
            Box::pin(async move { Ok(reference) })
        }

        fn get(
            &self,
            _context: SpillCallContext,
            _reference: SpillRef,
            range: SpillByteRange,
        ) -> SpillFuture<'_, Result<SpillData, SpillError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let data = vec![0; range.length().get()];
            Box::pin(async move { SpillData::new(data) })
        }

        fn purge_owner(
            &self,
            _context: SpillCallContext,
        ) -> SpillFuture<'_, Result<(), SpillError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }
    }

    fn ready<T>(future: &mut SpillFuture<'_, T>) -> T {
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test future unexpectedly pending"),
        }
    }

    fn context(agent: u128, budget: usize) -> SpillCallContext {
        SpillCallContext::new(
            AgentId::from_nonzero_u128(agent).unwrap(),
            CancellationToken::new(),
            RuntimeInstant::from_monotonic_duration(Duration::from_secs(1)),
            None,
            NonZeroUsize::new(budget).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn spill_input_identity_is_content_derived_and_bounded() {
        let input = SpillInput::new(b"hello".to_vec()).unwrap();
        assert_eq!(input.content_digest(), digest(b"hello"));
        assert_eq!(SpillInput::new(Vec::new()), Err(SpillError::InputTooLarge));
    }

    #[test]
    fn owner_budget_and_expiry_rejection_precede_provider_side_effects() {
        let provider = Arc::new(CountingStore {
            calls: AtomicUsize::new(0),
            mismatch: false,
        });
        let binding = SpillStoreBinding::from_provider(provider.clone());
        let mut future = binding.put(context(1, 1), SpillInput::new(b"large".to_vec()).unwrap());
        assert_eq!(ready(&mut future), Err(SpillError::BudgetExceeded));

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let cancelled_context = SpillCallContext::new(
            AgentId::from_nonzero_u128(1).unwrap(),
            cancelled,
            RuntimeInstant::from_monotonic_duration(Duration::from_secs(1)),
            None,
            NonZeroUsize::new(1).unwrap(),
        )
        .unwrap();
        let mut future = binding.put(cancelled_context, SpillInput::new(b"x".to_vec()).unwrap());
        assert_eq!(ready(&mut future), Err(SpillError::Cancelled));

        let foreign = SpillRef::new(
            "memory",
            AgentId::from_nonzero_u128(2).unwrap(),
            Digest::from_bytes([0; 32]),
            1,
            RuntimeInstant::from_monotonic_duration(Duration::from_secs(2)),
        )
        .unwrap();
        let mut future = binding.get(
            context(1, 1),
            foreign,
            SpillByteRange::new(0, NonZeroUsize::new(1).unwrap()).unwrap(),
        );
        assert_eq!(ready(&mut future), Err(SpillError::ForeignOwner));

        let expired = SpillRef::new(
            "memory",
            AgentId::from_nonzero_u128(1).unwrap(),
            Digest::from_bytes([0; 32]),
            1,
            RuntimeInstant::from_monotonic_duration(Duration::from_secs(1)),
        )
        .unwrap();
        let mut future = binding.get(
            context(1, 1),
            expired,
            SpillByteRange::new(0, NonZeroUsize::new(1).unwrap()).unwrap(),
        );
        assert_eq!(ready(&mut future), Err(SpillError::Expired));

        let short = SpillRef::new(
            "memory",
            AgentId::from_nonzero_u128(1).unwrap(),
            Digest::from_bytes([0; 32]),
            1,
            RuntimeInstant::from_monotonic_duration(Duration::from_secs(2)),
        )
        .unwrap();
        let mut future = binding.get(
            context(1, 2),
            short,
            SpillByteRange::new(0, NonZeroUsize::new(2).unwrap()).unwrap(),
        );
        assert_eq!(ready(&mut future), Err(SpillError::RangeOutOfBounds));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn valid_put_get_and_owner_purge_reach_the_provider() {
        let provider = Arc::new(CountingStore {
            calls: AtomicUsize::new(0),
            mismatch: false,
        });
        let binding = SpillStoreBinding::from_provider(provider.clone());
        let mut future = binding.put(context(1, 4), SpillInput::new(b"data".to_vec()).unwrap());
        let reference = ready(&mut future).unwrap();
        let mut future = binding.get(
            context(1, 2),
            reference,
            SpillByteRange::new(0, NonZeroUsize::new(2).unwrap()).unwrap(),
        );
        assert_eq!(ready(&mut future).unwrap().byte_len(), 2);
        let mut future = binding.purge_owner(context(1, 1));
        ready(&mut future).unwrap();
        assert_eq!(provider.calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn mismatched_provider_reference_is_rejected() {
        let provider = Arc::new(CountingStore {
            calls: AtomicUsize::new(0),
            mismatch: true,
        });
        let binding = SpillStoreBinding::from_provider(provider.clone());
        let mut future = binding.put(context(1, 1), SpillInput::new(b"x".to_vec()).unwrap());
        assert_eq!(ready(&mut future), Err(SpillError::ReferenceMismatch));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }
}
