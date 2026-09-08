//! Bounded attachment storage contracts. Attachment identity and spill identity are distinct.

use std::{fmt, future::Future, num::NonZeroUsize, pin::Pin, sync::Arc};

use rust_agent_core::{CanonicalId, Digest, MaybeSendSync};
use rust_agent_runtime_api::{CancellationToken, RuntimeInstant};
use sha2::{Digest as _, Sha256};

pub const MAX_ATTACHMENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ATTACHMENT_RANGE_BYTES: usize = 1024 * 1024;
pub const MAX_MEDIA_TYPE_BYTES: usize = 255;

#[cfg(not(target_arch = "wasm32"))]
pub type AttachmentFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type AttachmentFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

#[derive(Clone, Debug)]
pub struct StorageCallContext {
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
    byte_budget: NonZeroUsize,
}

impl StorageCallContext {
    pub fn new(
        cancellation: CancellationToken,
        deadline: Option<RuntimeInstant>,
        byte_budget: NonZeroUsize,
    ) -> Result<Self, AttachmentError> {
        if byte_budget.get() > MAX_ATTACHMENT_BYTES {
            return Err(AttachmentError::BudgetExceedsHardLimit);
        }
        Ok(Self {
            cancellation,
            deadline,
            byte_budget,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentInput {
    media_type: Arc<str>,
    data: Arc<[u8]>,
    content_digest: Digest,
}

impl AttachmentInput {
    pub fn new(media_type: impl Into<String>, data: Vec<u8>) -> Result<Self, AttachmentError> {
        let media_type = media_type.into();
        if !valid_media_type(&media_type) {
            return Err(AttachmentError::InvalidMediaType);
        }
        if data.len() > MAX_ATTACHMENT_BYTES {
            return Err(AttachmentError::InputTooLarge);
        }
        let content_digest = digest(&data);
        Ok(Self {
            media_type: Arc::from(media_type),
            data: Arc::from(data),
            content_digest,
        })
    }

    pub fn media_type(&self) -> &str {
        &self.media_type
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

fn valid_media_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_MEDIA_TYPE_BYTES
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'+' | b'-' | b'.'))
        && value.split_once('/').is_some_and(|(kind, subtype)| {
            !kind.is_empty() && !subtype.is_empty() && !subtype.contains('/')
        })
}

fn digest(bytes: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Digest::from_bytes(hasher.finalize().into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentRef {
    provider_key: CanonicalId,
    content_digest: Digest,
    byte_len: u64,
}

impl AttachmentRef {
    pub fn new(
        provider_key: impl Into<String>,
        content_digest: Digest,
        byte_len: u64,
    ) -> Result<Self, AttachmentError> {
        let provider_key = CanonicalId::new(provider_key.into())
            .map_err(|_| AttachmentError::InvalidProviderKey)?;
        if byte_len > MAX_ATTACHMENT_BYTES as u64 {
            return Err(AttachmentError::InputTooLarge);
        }
        Ok(Self {
            provider_key,
            content_digest,
            byte_len,
        })
    }

    pub fn provider_key(&self) -> &str {
        self.provider_key.as_str()
    }

    pub const fn content_digest(&self) -> Digest {
        self.content_digest
    }

    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRange {
    start: u64,
    length: NonZeroUsize,
}

impl ByteRange {
    pub fn new(start: u64, length: NonZeroUsize) -> Result<Self, AttachmentError> {
        if length.get() > MAX_ATTACHMENT_RANGE_BYTES
            || start.checked_add(length.get() as u64).is_none()
        {
            return Err(AttachmentError::InvalidRange);
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
pub struct AttachmentData(Arc<[u8]>);

impl AttachmentData {
    pub fn new(data: Vec<u8>) -> Result<Self, AttachmentError> {
        if data.len() > MAX_ATTACHMENT_RANGE_BYTES {
            return Err(AttachmentError::OutputTooLarge);
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
pub enum AttachmentError {
    InvalidProviderKey,
    InvalidMediaType,
    InvalidRange,
    RangeOutOfBounds,
    ForeignReference,
    InputTooLarge,
    OutputTooLarge,
    BudgetExceedsHardLimit,
    BudgetExceeded,
    ReferenceMismatch,
    Cancelled,
    DeadlineExceeded,
    NotFound,
    Provider,
}

impl fmt::Display for AttachmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProviderKey => "invalid attachment provider key",
            Self::InvalidMediaType => "invalid attachment media type",
            Self::InvalidRange => "invalid attachment byte range",
            Self::RangeOutOfBounds => "attachment byte range exceeds the referenced object",
            Self::ForeignReference => "attachment reference belongs to another provider",
            Self::InputTooLarge => "attachment input exceeds the hard limit",
            Self::OutputTooLarge => "attachment output exceeds the requested bound",
            Self::BudgetExceedsHardLimit => "attachment budget exceeds the hard limit",
            Self::BudgetExceeded => "attachment byte budget exceeded",
            Self::ReferenceMismatch => "attachment provider returned a mismatched reference",
            Self::Cancelled => "attachment operation was cancelled",
            Self::DeadlineExceeded => "attachment operation deadline exceeded",
            Self::NotFound => "attachment was not found",
            Self::Provider => "attachment provider failed",
        })
    }
}

impl std::error::Error for AttachmentError {}

pub trait AttachmentStore: MaybeSendSync {
    fn provider_key(&self) -> CanonicalId;

    fn put(
        &self,
        context: StorageCallContext,
        input: AttachmentInput,
    ) -> AttachmentFuture<'_, Result<AttachmentRef, AttachmentError>>;

    fn get(
        &self,
        context: StorageCallContext,
        reference: AttachmentRef,
        range: ByteRange,
    ) -> AttachmentFuture<'_, Result<AttachmentData, AttachmentError>>;
}

/// Consumer-facing registry entry that keeps the raw store private and validates every call.
#[derive(Clone)]
pub struct AttachmentStoreBinding {
    provider_key: CanonicalId,
    provider: Arc<dyn AttachmentStore>,
}

impl AttachmentStoreBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: AttachmentStore + 'static,
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
        context: StorageCallContext,
        input: AttachmentInput,
    ) -> AttachmentFuture<'_, Result<AttachmentRef, AttachmentError>> {
        if context.cancellation.is_cancelled() {
            return Box::pin(async { Err(AttachmentError::Cancelled) });
        }
        if input.byte_len() > context.byte_budget.get() {
            return Box::pin(async { Err(AttachmentError::BudgetExceeded) });
        }
        let expected_key = self.provider_key.clone();
        let expected_digest = input.content_digest();
        let expected_len = input.byte_len() as u64;
        let future = self.provider.put(context, input);
        Box::pin(async move {
            let reference = future.await?;
            if reference.provider_key != expected_key
                || reference.content_digest() != expected_digest
                || reference.byte_len() != expected_len
            {
                return Err(AttachmentError::ReferenceMismatch);
            }
            Ok(reference)
        })
    }

    pub fn get(
        &self,
        context: StorageCallContext,
        reference: AttachmentRef,
        range: ByteRange,
    ) -> AttachmentFuture<'_, Result<AttachmentData, AttachmentError>> {
        if context.cancellation.is_cancelled() {
            return Box::pin(async { Err(AttachmentError::Cancelled) });
        }
        if reference.provider_key != self.provider_key {
            return Box::pin(async { Err(AttachmentError::ForeignReference) });
        }
        if range.start + range.length.get() as u64 > reference.byte_len() {
            return Box::pin(async { Err(AttachmentError::RangeOutOfBounds) });
        }
        if range.length.get() > context.byte_budget.get() {
            return Box::pin(async { Err(AttachmentError::BudgetExceeded) });
        }
        let output_limit = range.length.get();
        let future = self.provider.get(context, reference, range);
        Box::pin(async move {
            let data = future.await?;
            if data.byte_len() > output_limit {
                return Err(AttachmentError::OutputTooLarge);
            }
            Ok(data)
        })
    }
}

impl fmt::Debug for AttachmentStoreBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttachmentStoreBinding")
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

    #[derive(Debug)]
    struct CountingStore {
        calls: AtomicUsize,
        mismatch: bool,
    }

    impl AttachmentStore for CountingStore {
        fn provider_key(&self) -> CanonicalId {
            CanonicalId::new("memory").unwrap()
        }

        fn put(
            &self,
            _context: StorageCallContext,
            input: AttachmentInput,
        ) -> AttachmentFuture<'_, Result<AttachmentRef, AttachmentError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let content_digest = if self.mismatch {
                Digest::from_bytes([9; 32])
            } else {
                input.content_digest()
            };
            let reference =
                AttachmentRef::new("memory", content_digest, input.byte_len() as u64).unwrap();
            Box::pin(async move { Ok(reference) })
        }

        fn get(
            &self,
            _context: StorageCallContext,
            _reference: AttachmentRef,
            range: ByteRange,
        ) -> AttachmentFuture<'_, Result<AttachmentData, AttachmentError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let data = vec![0; range.length().get()];
            Box::pin(async move { AttachmentData::new(data) })
        }
    }

    fn ready<T>(future: &mut AttachmentFuture<'_, T>) -> T {
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test future unexpectedly pending"),
        }
    }

    fn context(budget: usize) -> StorageCallContext {
        StorageCallContext::new(
            CancellationToken::new(),
            None,
            NonZeroUsize::new(budget).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn input_identity_is_content_derived_and_media_type_is_closed() {
        let input = AttachmentInput::new("text/plain", b"hello".to_vec()).unwrap();
        assert_eq!(input.content_digest(), digest(b"hello"));
        assert_eq!(
            AttachmentInput::new("text/plain; secret=x", Vec::new()),
            Err(AttachmentError::InvalidMediaType)
        );
    }

    #[test]
    fn preflight_rejection_has_no_provider_side_effect() {
        let provider = Arc::new(CountingStore {
            calls: AtomicUsize::new(0),
            mismatch: false,
        });
        let binding = AttachmentStoreBinding::from_provider(provider.clone());
        let mut future = binding.put(
            context(1),
            AttachmentInput::new("text/plain", b"too big".to_vec()).unwrap(),
        );
        assert_eq!(ready(&mut future), Err(AttachmentError::BudgetExceeded));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let cancelled_context =
            StorageCallContext::new(cancelled, None, NonZeroUsize::new(1).unwrap()).unwrap();
        let mut future = binding.put(
            cancelled_context,
            AttachmentInput::new("text/plain", b"x".to_vec()).unwrap(),
        );
        assert_eq!(ready(&mut future), Err(AttachmentError::Cancelled));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);

        let foreign = AttachmentRef::new("other", Digest::from_bytes([0; 32]), 0).unwrap();
        let mut future = binding.get(
            context(1),
            foreign,
            ByteRange::new(0, NonZeroUsize::new(1).unwrap()).unwrap(),
        );
        assert_eq!(ready(&mut future), Err(AttachmentError::ForeignReference));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);

        let short = AttachmentRef::new("memory", Digest::from_bytes([0; 32]), 1).unwrap();
        let mut future = binding.get(
            context(2),
            short,
            ByteRange::new(0, NonZeroUsize::new(2).unwrap()).unwrap(),
        );
        assert_eq!(ready(&mut future), Err(AttachmentError::RangeOutOfBounds));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn valid_put_and_bounded_get_reach_the_provider() {
        let provider = Arc::new(CountingStore {
            calls: AtomicUsize::new(0),
            mismatch: false,
        });
        let binding = AttachmentStoreBinding::from_provider(provider.clone());
        let input = AttachmentInput::new("text/plain", b"data".to_vec()).unwrap();
        let mut future = binding.put(context(4), input);
        let reference = ready(&mut future).unwrap();
        let mut future = binding.get(
            context(2),
            reference,
            ByteRange::new(0, NonZeroUsize::new(2).unwrap()).unwrap(),
        );
        assert_eq!(ready(&mut future).unwrap().byte_len(), 2);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn mismatched_provider_reference_is_rejected() {
        let provider = Arc::new(CountingStore {
            calls: AtomicUsize::new(0),
            mismatch: true,
        });
        let binding = AttachmentStoreBinding::from_provider(provider.clone());
        let mut future = binding.put(
            context(1),
            AttachmentInput::new("text/plain", b"x".to_vec()).unwrap(),
        );
        assert_eq!(ready(&mut future), Err(AttachmentError::ReferenceMismatch));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }
}
