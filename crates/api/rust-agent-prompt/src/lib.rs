//! Bounded prompt assembly, compaction, pruning, and token-meter capability contracts.

use std::{
    collections::BTreeSet,
    fmt,
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    pin::Pin,
    sync::Arc,
};

use rust_agent_core::{CallId, CanonicalId, Digest, MaybeSendSync, MessageRole};
use rust_agent_runtime_api::{CancellationToken, RuntimeInstant};

pub const MAX_PROMPT_CONTRIBUTIONS: usize = 64;
pub const MAX_PROMPT_SEGMENTS: usize = 1_024;
pub const MAX_PROMPT_SEGMENT_BYTES: usize = 64 * 1024;
pub const MAX_PROMPT_BYTES: usize = 256 * 1024;
pub const MAX_CONVERSATION_ENTRIES: usize = 256;
pub const MAX_CONVERSATION_BLOCKS: usize = 1_024;
pub const MAX_CONVERSATION_ENTRY_BYTES: usize = 64 * 1024;
pub const MAX_CONVERSATION_BYTES: usize = 512 * 1024;
pub const MAX_TOOL_RESULTS: usize = 64;
pub const MAX_TOOL_RESULT_BYTES: usize = 256 * 1024;
pub const MAX_TOKEN_ESTIMATE: u64 = 16_777_216;

#[cfg(not(target_arch = "wasm32"))]
pub type PromptFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type PromptFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

macro_rules! binding {
    ($name:ident, $contract:ident) => {
        #[derive(Clone)]
        pub struct $name {
            provider: Arc<dyn $contract>,
        }

        impl $name {
            pub fn from_provider<T>(provider: Arc<T>) -> Self
            where
                T: $contract + 'static,
            {
                Self { provider }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .finish_non_exhaustive()
            }
        }
    };
}

/// Closed audit category for material entering a prompt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptSegmentKind {
    Identity,
    Instruction,
    ToolSchema,
    Skill,
    Memory,
    Retrieval,
    Plan,
    Environment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromptSegment {
    kind: PromptSegmentKind,
    content: Arc<str>,
}

impl PromptSegment {
    pub fn new(kind: PromptSegmentKind, content: impl Into<String>) -> Result<Self, PromptError> {
        let content = content.into();
        if content.is_empty() || content.len() > MAX_PROMPT_SEGMENT_BYTES {
            return Err(PromptError::InvalidSegment);
        }
        Ok(Self {
            kind,
            content: Arc::from(content),
        })
    }

    pub const fn kind(&self) -> PromptSegmentKind {
        self.kind
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    pub fn byte_len(&self) -> usize {
        self.content.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromptContribution {
    contributor_id: CanonicalId,
    segments: Arc<[PromptSegment]>,
    estimated_tokens: u64,
    byte_len: usize,
}

impl PromptContribution {
    pub fn contributor_id(&self) -> &str {
        self.contributor_id.as_str()
    }

    pub fn segments(&self) -> &[PromptSegment] {
        &self.segments
    }

    pub const fn estimated_tokens(&self) -> u64 {
        self.estimated_tokens
    }

    pub const fn byte_len(&self) -> usize {
        self.byte_len
    }
}

/// Bounded accumulator used by the deterministic generated contributor pipeline.
#[derive(Debug)]
pub struct PromptBuilder {
    contributions: Vec<PromptContribution>,
    contributor_ids: BTreeSet<CanonicalId>,
    contribution_limit: usize,
    byte_limit: usize,
    segment_count: usize,
    byte_len: usize,
    estimated_tokens: u64,
}

impl PromptBuilder {
    pub fn new(
        contribution_limit: NonZeroUsize,
        byte_limit: NonZeroUsize,
    ) -> Result<Self, PromptError> {
        if contribution_limit.get() > MAX_PROMPT_CONTRIBUTIONS
            || byte_limit.get() > MAX_PROMPT_BYTES
        {
            return Err(PromptError::BudgetExceedsHardLimit);
        }
        Ok(Self {
            contributions: Vec::new(),
            contributor_ids: BTreeSet::new(),
            contribution_limit: contribution_limit.get(),
            byte_limit: byte_limit.get(),
            segment_count: 0,
            byte_len: 0,
            estimated_tokens: 0,
        })
    }

    pub fn add_contribution(
        &mut self,
        contributor_id: impl Into<String>,
        segments: Vec<PromptSegment>,
        estimated_tokens: u64,
    ) -> Result<(), PromptError> {
        let contributor_id = CanonicalId::new(contributor_id.into())
            .map_err(|_| PromptError::InvalidContributorId)?;
        if segments.is_empty() {
            return Err(PromptError::EmptyContribution);
        }
        if self.contributions.len() >= self.contribution_limit {
            return Err(PromptError::ContributionLimitExceeded);
        }
        if self.contributor_ids.contains(&contributor_id) {
            return Err(PromptError::DuplicateContributor);
        }
        let segment_count = self
            .segment_count
            .checked_add(segments.len())
            .ok_or(PromptError::SegmentLimitExceeded)?;
        if segment_count > MAX_PROMPT_SEGMENTS {
            return Err(PromptError::SegmentLimitExceeded);
        }
        let added_bytes = segments.iter().try_fold(0_usize, |total, segment| {
            total
                .checked_add(segment.byte_len())
                .ok_or(PromptError::ByteLimitExceeded)
        })?;
        let byte_len = self
            .byte_len
            .checked_add(added_bytes)
            .ok_or(PromptError::ByteLimitExceeded)?;
        if byte_len > self.byte_limit {
            return Err(PromptError::ByteLimitExceeded);
        }
        let total_tokens = self
            .estimated_tokens
            .checked_add(estimated_tokens)
            .ok_or(PromptError::TokenEstimateExceeded)?;
        if estimated_tokens > MAX_TOKEN_ESTIMATE || total_tokens > MAX_TOKEN_ESTIMATE {
            return Err(PromptError::TokenEstimateExceeded);
        }

        self.contributor_ids.insert(contributor_id.clone());
        self.contributions.push(PromptContribution {
            contributor_id,
            segments: Arc::from(segments),
            estimated_tokens,
            byte_len: added_bytes,
        });
        self.segment_count = segment_count;
        self.byte_len = byte_len;
        self.estimated_tokens = total_tokens;
        Ok(())
    }

    pub fn finish(self) -> AssembledPrompt {
        AssembledPrompt {
            contributions: Arc::from(self.contributions),
            segment_count: self.segment_count,
            byte_len: self.byte_len,
            estimated_tokens: self.estimated_tokens,
        }
    }

    fn checkpoint(&self) -> usize {
        self.contributions.len()
    }

    fn contribution_since(&self, checkpoint: usize) -> Option<&PromptContribution> {
        (self.contributions.len() == checkpoint + 1).then(|| &self.contributions[checkpoint])
    }

    fn rollback_to(&mut self, checkpoint: usize) {
        self.contributions.truncate(checkpoint);
        self.contributor_ids = self
            .contributions
            .iter()
            .map(|contribution| contribution.contributor_id.clone())
            .collect();
        self.segment_count = self
            .contributions
            .iter()
            .map(|contribution| contribution.segments.len())
            .sum();
        self.byte_len = self
            .contributions
            .iter()
            .map(PromptContribution::byte_len)
            .sum();
        self.estimated_tokens = self
            .contributions
            .iter()
            .map(PromptContribution::estimated_tokens)
            .sum();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssembledPrompt {
    contributions: Arc<[PromptContribution]>,
    segment_count: usize,
    byte_len: usize,
    estimated_tokens: u64,
}

impl AssembledPrompt {
    pub fn contributions(&self) -> &[PromptContribution] {
        &self.contributions
    }

    pub const fn segment_count(&self) -> usize {
        self.segment_count
    }

    pub const fn byte_len(&self) -> usize {
        self.byte_len
    }

    pub const fn estimated_tokens(&self) -> u64 {
        self.estimated_tokens
    }
}

#[derive(Clone, Debug)]
pub struct PromptContext {
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
}

impl PromptContext {
    pub fn new(cancellation: CancellationToken, deadline: Option<RuntimeInstant>) -> Self {
        Self {
            cancellation,
            deadline,
        }
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub const fn deadline(&self) -> Option<RuntimeInstant> {
        self.deadline
    }
}

#[derive(Clone, Debug)]
pub struct PromptAssemblyRequest {
    contribution_limit: NonZeroUsize,
    byte_limit: NonZeroUsize,
}

impl PromptAssemblyRequest {
    pub fn new(
        contribution_limit: NonZeroUsize,
        byte_limit: NonZeroUsize,
    ) -> Result<Self, PromptError> {
        PromptBuilder::new(contribution_limit, byte_limit)?;
        Ok(Self {
            contribution_limit,
            byte_limit,
        })
    }

    pub const fn contribution_limit(&self) -> NonZeroUsize {
        self.contribution_limit
    }

    pub const fn byte_limit(&self) -> NonZeroUsize {
        self.byte_limit
    }

    pub fn builder(&self) -> PromptBuilder {
        PromptBuilder::new(self.contribution_limit, self.byte_limit)
            .expect("validated prompt assembly request must remain valid")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptError {
    InvalidContributorId,
    InvalidSegment,
    EmptyContribution,
    DuplicateContributor,
    ContributorProtocolViolation,
    ContributionLimitExceeded,
    SegmentLimitExceeded,
    ByteLimitExceeded,
    TokenEstimateExceeded,
    BudgetExceedsHardLimit,
    Cancelled,
    DeadlineExceeded,
    Provider,
}

impl fmt::Display for PromptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidContributorId => "invalid prompt contributor identity",
            Self::InvalidSegment => "invalid prompt segment",
            Self::EmptyContribution => "prompt contribution is empty",
            Self::DuplicateContributor => "prompt contributor identity is duplicated",
            Self::ContributorProtocolViolation => {
                "prompt contributor did not append exactly its declared contribution"
            }
            Self::ContributionLimitExceeded => "prompt contribution limit exceeded",
            Self::SegmentLimitExceeded => "prompt segment limit exceeded",
            Self::ByteLimitExceeded => "prompt byte limit exceeded",
            Self::TokenEstimateExceeded => "prompt token estimate limit exceeded",
            Self::BudgetExceedsHardLimit => "prompt budget exceeds the hard limit",
            Self::Cancelled => "prompt operation was cancelled",
            Self::DeadlineExceeded => "prompt operation deadline exceeded",
            Self::Provider => "prompt provider failed",
        })
    }
}

impl std::error::Error for PromptError {}

pub trait PromptContributor: MaybeSendSync {
    fn contributor_id(&self) -> CanonicalId;

    fn contribute<'a>(
        &'a self,
        context: &'a PromptContext,
        out: &'a mut PromptBuilder,
    ) -> PromptFuture<'a, Result<(), PromptError>>;
}

pub trait PromptAssembly: MaybeSendSync {
    fn assemble(
        &self,
        context: PromptContext,
        request: PromptAssemblyRequest,
    ) -> PromptFuture<'_, Result<AssembledPrompt, PromptError>>;
}

binding!(PromptAssemblyBinding, PromptAssembly);

#[derive(Clone)]
pub struct PromptContributorBinding {
    contributor_id: CanonicalId,
    provider: Arc<dyn PromptContributor>,
}

impl PromptContributorBinding {
    pub fn from_provider<T>(provider: Arc<T>) -> Self
    where
        T: PromptContributor + 'static,
    {
        let contributor_id = provider.contributor_id();
        Self {
            contributor_id,
            provider,
        }
    }
}

impl fmt::Debug for PromptContributorBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptContributorBinding")
            .field("contributor_id", &self.contributor_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationContentKind {
    Text,
    ToolCall,
    ToolResult,
    Attachment,
    Structured,
}

/// One bounded typed block. Private fields prevent callers from bypassing constructors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationContent {
    kind: ConversationContentKind,
    call_id: Option<CallId>,
    label: Option<Arc<str>>,
    content: Option<Arc<str>>,
    content_digest: Option<Digest>,
    byte_len: usize,
}

impl ConversationContent {
    pub fn text(content: impl Into<String>) -> Result<Self, CompactionError> {
        Self::with_content(ConversationContentKind::Text, None, None, content.into())
    }

    pub fn tool_call(
        call_id: CallId,
        tool_name: impl Into<String>,
        arguments: impl Into<String>,
    ) -> Result<Self, CompactionError> {
        let tool_name =
            CanonicalId::new(tool_name.into()).map_err(|_| CompactionError::InvalidContent)?;
        Self::with_content(
            ConversationContentKind::ToolCall,
            Some(call_id),
            Some(Arc::from(tool_name.into_string())),
            arguments.into(),
        )
    }

    pub fn tool_result(
        call_id: CallId,
        content: impl Into<String>,
    ) -> Result<Self, CompactionError> {
        Self::with_content(
            ConversationContentKind::ToolResult,
            Some(call_id),
            None,
            content.into(),
        )
    }

    pub const fn attachment(content_digest: Digest) -> Self {
        Self {
            kind: ConversationContentKind::Attachment,
            call_id: None,
            label: None,
            content: None,
            content_digest: Some(content_digest),
            byte_len: Digest::LEN,
        }
    }

    pub fn structured(
        media_type: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, CompactionError> {
        let media_type = media_type.into();
        if !valid_media_type(&media_type) {
            return Err(CompactionError::InvalidContent);
        }
        Self::with_content(
            ConversationContentKind::Structured,
            None,
            Some(Arc::from(media_type)),
            value.into(),
        )
    }

    fn with_content(
        kind: ConversationContentKind,
        call_id: Option<CallId>,
        label: Option<Arc<str>>,
        content: String,
    ) -> Result<Self, CompactionError> {
        let byte_len = label
            .as_ref()
            .map_or(0, |label| label.len())
            .checked_add(content.len())
            .ok_or(CompactionError::ByteLimitExceeded)?;
        if content.is_empty() || byte_len > MAX_CONVERSATION_ENTRY_BYTES {
            return Err(CompactionError::InvalidContent);
        }
        Ok(Self {
            kind,
            call_id,
            label,
            content: Some(Arc::from(content)),
            content_digest: None,
            byte_len,
        })
    }

    pub const fn kind(&self) -> ConversationContentKind {
        self.kind
    }

    pub const fn call_id(&self) -> Option<CallId> {
        self.call_id
    }

    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    pub fn content(&self) -> Option<&str> {
        self.content.as_deref()
    }

    pub const fn content_digest(&self) -> Option<Digest> {
        self.content_digest
    }

    pub const fn byte_len(&self) -> usize {
        self.byte_len
    }
}

fn valid_media_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'+' | b'-' | b'.'))
        && value.split_once('/').is_some_and(|(kind, subtype)| {
            !kind.is_empty() && !subtype.is_empty() && !subtype.contains('/')
        })
}

/// One immutable model-visible conversation entry admitted before compaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationEntry {
    role: MessageRole,
    content: Arc<[ConversationContent]>,
    byte_len: usize,
}

impl ConversationEntry {
    pub fn new(
        role: MessageRole,
        content: Vec<ConversationContent>,
    ) -> Result<Self, CompactionError> {
        if content.is_empty() {
            return Err(CompactionError::InvalidEntry);
        }
        if content.len() > MAX_CONVERSATION_BLOCKS {
            return Err(CompactionError::ContentLimitExceeded);
        }
        let byte_len = content.iter().try_fold(0_usize, |total, block| {
            total
                .checked_add(block.byte_len())
                .ok_or(CompactionError::ByteLimitExceeded)
        })?;
        if byte_len > MAX_CONVERSATION_ENTRY_BYTES {
            return Err(CompactionError::ByteLimitExceeded);
        }
        Ok(Self {
            role,
            content: Arc::from(content),
            byte_len,
        })
    }

    pub const fn role(&self) -> MessageRole {
        self.role
    }

    pub fn content(&self) -> &[ConversationContent] {
        &self.content
    }

    pub const fn byte_len(&self) -> usize {
        self.byte_len
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedConversation {
    entries: Arc<[ConversationEntry]>,
    block_count: usize,
    byte_len: usize,
}

impl BoundedConversation {
    pub fn new(entries: Vec<ConversationEntry>) -> Result<Self, CompactionError> {
        if entries.is_empty() || entries.len() > MAX_CONVERSATION_ENTRIES {
            return Err(CompactionError::EntryLimitExceeded);
        }
        let block_count = entries.iter().try_fold(0_usize, |total, entry| {
            total
                .checked_add(entry.content().len())
                .ok_or(CompactionError::ContentLimitExceeded)
        })?;
        if block_count > MAX_CONVERSATION_BLOCKS {
            return Err(CompactionError::ContentLimitExceeded);
        }
        let byte_len = entries.iter().try_fold(0_usize, |total, entry| {
            total
                .checked_add(entry.byte_len())
                .ok_or(CompactionError::ByteLimitExceeded)
        })?;
        if byte_len > MAX_CONVERSATION_BYTES {
            return Err(CompactionError::ByteLimitExceeded);
        }
        Ok(Self {
            entries: Arc::from(entries),
            block_count,
            byte_len,
        })
    }

    pub fn entries(&self) -> &[ConversationEntry] {
        &self.entries
    }

    pub const fn byte_len(&self) -> usize {
        self.byte_len
    }

    pub const fn block_count(&self) -> usize {
        self.block_count
    }
}

#[derive(Clone, Debug)]
pub struct CompactionContext {
    cancellation: CancellationToken,
    deadline: Option<RuntimeInstant>,
}

impl CompactionContext {
    pub fn new(cancellation: CancellationToken, deadline: Option<RuntimeInstant>) -> Self {
        Self {
            cancellation,
            deadline,
        }
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub const fn deadline(&self) -> Option<RuntimeInstant> {
        self.deadline
    }
}

#[derive(Clone, Debug)]
pub struct CompactionInput {
    source_digest: Digest,
    conversation: BoundedConversation,
    target_bytes: NonZeroUsize,
    target_tokens: NonZeroU64,
}

impl CompactionInput {
    pub fn new(
        source_digest: Digest,
        conversation: BoundedConversation,
        target_bytes: NonZeroUsize,
        target_tokens: NonZeroU64,
    ) -> Result<Self, CompactionError> {
        if target_bytes.get() > MAX_CONVERSATION_BYTES || target_tokens.get() > MAX_TOKEN_ESTIMATE {
            return Err(CompactionError::TargetExceedsHardLimit);
        }
        Ok(Self {
            source_digest,
            conversation,
            target_bytes,
            target_tokens,
        })
    }

    pub const fn source_digest(&self) -> Digest {
        self.source_digest
    }

    pub const fn conversation(&self) -> &BoundedConversation {
        &self.conversation
    }

    pub const fn target_bytes(&self) -> NonZeroUsize {
        self.target_bytes
    }

    pub const fn target_tokens(&self) -> NonZeroU64 {
        self.target_tokens
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactionResult {
    source_digest: Digest,
    conversation: BoundedConversation,
    estimated_tokens: u64,
}

impl CompactionResult {
    pub fn new(
        source_digest: Digest,
        conversation: BoundedConversation,
        estimated_tokens: u64,
    ) -> Result<Self, CompactionError> {
        if estimated_tokens > MAX_TOKEN_ESTIMATE {
            return Err(CompactionError::TokenEstimateExceeded);
        }
        Ok(Self {
            source_digest,
            conversation,
            estimated_tokens,
        })
    }

    pub const fn source_digest(&self) -> Digest {
        self.source_digest
    }

    pub const fn conversation(&self) -> &BoundedConversation {
        &self.conversation
    }

    pub const fn estimated_tokens(&self) -> u64 {
        self.estimated_tokens
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactionError {
    InvalidEntry,
    InvalidContent,
    EntryLimitExceeded,
    ContentLimitExceeded,
    ByteLimitExceeded,
    TargetExceedsHardLimit,
    TokenEstimateExceeded,
    SourceDigestMismatch,
    ResultExceedsTarget,
    Cancelled,
    DeadlineExceeded,
    Provider,
}

impl fmt::Display for CompactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEntry => "invalid conversation entry",
            Self::InvalidContent => "invalid conversation content",
            Self::EntryLimitExceeded => "conversation entry limit exceeded",
            Self::ContentLimitExceeded => "conversation content block limit exceeded",
            Self::ByteLimitExceeded => "conversation byte limit exceeded",
            Self::TargetExceedsHardLimit => "compaction target exceeds the hard limit",
            Self::TokenEstimateExceeded => "compaction token estimate exceeded",
            Self::SourceDigestMismatch => "compaction result source digest mismatch",
            Self::ResultExceedsTarget => "compaction result exceeds the requested target",
            Self::Cancelled => "compaction was cancelled",
            Self::DeadlineExceeded => "compaction deadline exceeded",
            Self::Provider => "compaction provider failed",
        })
    }
}

impl std::error::Error for CompactionError {}

pub trait Compactor: MaybeSendSync {
    fn compact(
        &self,
        context: CompactionContext,
        input: CompactionInput,
    ) -> PromptFuture<'_, Result<CompactionResult, CompactionError>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolResultEntry {
    call_id: CallId,
    content: Arc<str>,
}

impl ToolResultEntry {
    pub fn new(call_id: CallId, content: impl Into<String>) -> Result<Self, PruningError> {
        let content = content.into();
        if content.is_empty() || content.len() > MAX_TOOL_RESULT_BYTES {
            return Err(PruningError::InvalidResult);
        }
        Ok(Self {
            call_id,
            content: Arc::from(content),
        })
    }

    pub const fn call_id(&self) -> CallId {
        self.call_id
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    pub fn byte_len(&self) -> usize {
        self.content.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolResultBatch {
    results: Arc<[ToolResultEntry]>,
    byte_len: usize,
}

impl ToolResultBatch {
    pub fn new(results: Vec<ToolResultEntry>) -> Result<Self, PruningError> {
        if results.len() > MAX_TOOL_RESULTS {
            return Err(PruningError::ResultLimitExceeded);
        }
        let mut ids = BTreeSet::new();
        let byte_len = results.iter().try_fold(0_usize, |total, result| {
            if !ids.insert(result.call_id()) {
                return Err(PruningError::DuplicateCallId);
            }
            total
                .checked_add(result.byte_len())
                .ok_or(PruningError::ByteLimitExceeded)
        })?;
        if byte_len > MAX_TOOL_RESULT_BYTES {
            return Err(PruningError::ByteLimitExceeded);
        }
        Ok(Self {
            results: Arc::from(results),
            byte_len,
        })
    }

    pub fn results(&self) -> &[ToolResultEntry] {
        &self.results
    }

    pub const fn byte_len(&self) -> usize {
        self.byte_len
    }
}

#[derive(Clone, Debug)]
pub struct ToolResultPruningInput {
    results: ToolResultBatch,
    target_bytes: NonZeroUsize,
}

impl ToolResultPruningInput {
    pub fn new(results: ToolResultBatch, target_bytes: NonZeroUsize) -> Result<Self, PruningError> {
        if target_bytes.get() > MAX_TOOL_RESULT_BYTES {
            return Err(PruningError::TargetExceedsHardLimit);
        }
        Ok(Self {
            results,
            target_bytes,
        })
    }

    pub const fn results(&self) -> &ToolResultBatch {
        &self.results
    }

    pub const fn target_bytes(&self) -> NonZeroUsize {
        self.target_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolResultPruningResult {
    results: ToolResultBatch,
}

impl ToolResultPruningResult {
    pub fn new(results: ToolResultBatch) -> Self {
        Self { results }
    }

    pub const fn results(&self) -> &ToolResultBatch {
        &self.results
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PruningError {
    InvalidResult,
    DuplicateCallId,
    ResultLimitExceeded,
    ByteLimitExceeded,
    TargetExceedsHardLimit,
    ResultExceedsTarget,
    Cancelled,
    DeadlineExceeded,
    Provider,
}

impl fmt::Display for PruningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidResult => "invalid tool result",
            Self::DuplicateCallId => "tool result call identity is duplicated",
            Self::ResultLimitExceeded => "tool result count limit exceeded",
            Self::ByteLimitExceeded => "tool result byte limit exceeded",
            Self::TargetExceedsHardLimit => "tool result pruning target exceeds the hard limit",
            Self::ResultExceedsTarget => "pruned tool results exceed the requested target",
            Self::Cancelled => "tool result pruning was cancelled",
            Self::DeadlineExceeded => "tool result pruning deadline exceeded",
            Self::Provider => "tool result pruning provider failed",
        })
    }
}

impl std::error::Error for PruningError {}

pub trait ToolResultPruner: MaybeSendSync {
    fn prune(
        &self,
        context: CompactionContext,
        input: ToolResultPruningInput,
    ) -> PromptFuture<'_, Result<ToolResultPruningResult, PruningError>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenMeterInput {
    Prompt(AssembledPrompt),
    Conversation(BoundedConversation),
    ToolResults(ToolResultBatch),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenEstimate(u64);

impl TokenEstimate {
    pub const fn new(value: u64) -> Result<Self, TokenMeterError> {
        if value > MAX_TOKEN_ESTIMATE {
            Err(TokenMeterError::EstimateExceeded)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenMeterError {
    EstimateExceeded,
    Cancelled,
    DeadlineExceeded,
    Provider,
}

impl fmt::Display for TokenMeterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EstimateExceeded => "token estimate exceeds the hard limit",
            Self::Cancelled => "token metering was cancelled",
            Self::DeadlineExceeded => "token metering deadline exceeded",
            Self::Provider => "token meter provider failed",
        })
    }
}

impl std::error::Error for TokenMeterError {}

pub trait TokenMeter: MaybeSendSync {
    fn estimate(
        &self,
        context: CompactionContext,
        input: TokenMeterInput,
    ) -> PromptFuture<'_, Result<TokenEstimate, TokenMeterError>>;
}

binding!(CompactorBinding, Compactor);
binding!(ToolResultPrunerBinding, ToolResultPruner);
binding!(TokenMeterBinding, TokenMeter);

impl PromptContributorBinding {
    pub fn contributor_id(&self) -> CanonicalId {
        self.contributor_id.clone()
    }

    pub fn contribute<'a>(
        &'a self,
        context: &'a PromptContext,
        out: &'a mut PromptBuilder,
    ) -> PromptFuture<'a, Result<(), PromptError>> {
        if context.cancellation.is_cancelled() {
            return Box::pin(async { Err(PromptError::Cancelled) });
        }
        let checkpoint = out.checkpoint();
        let expected_id = self.contributor_id.clone();
        Box::pin(async move {
            if let Err(error) = self.provider.contribute(context, out).await {
                out.rollback_to(checkpoint);
                return Err(error);
            }
            if out
                .contribution_since(checkpoint)
                .is_none_or(|contribution| contribution.contributor_id != expected_id)
            {
                out.rollback_to(checkpoint);
                return Err(PromptError::ContributorProtocolViolation);
            }
            Ok(())
        })
    }
}

impl PromptAssemblyBinding {
    pub fn assemble(
        &self,
        context: PromptContext,
        request: PromptAssemblyRequest,
    ) -> PromptFuture<'_, Result<AssembledPrompt, PromptError>> {
        if context.cancellation.is_cancelled() {
            return Box::pin(async { Err(PromptError::Cancelled) });
        }
        self.provider.assemble(context, request)
    }
}

impl CompactorBinding {
    pub fn compact(
        &self,
        context: CompactionContext,
        input: CompactionInput,
    ) -> PromptFuture<'_, Result<CompactionResult, CompactionError>> {
        if context.cancellation.is_cancelled() {
            return Box::pin(async { Err(CompactionError::Cancelled) });
        }
        let source_digest = input.source_digest();
        let target_bytes = input.target_bytes().get();
        let target_tokens = input.target_tokens().get();
        let future = self.provider.compact(context, input);
        Box::pin(async move {
            let result = future.await?;
            if result.source_digest() != source_digest {
                return Err(CompactionError::SourceDigestMismatch);
            }
            if result.conversation().byte_len() > target_bytes
                || result.estimated_tokens() > target_tokens
            {
                return Err(CompactionError::ResultExceedsTarget);
            }
            Ok(result)
        })
    }
}

impl ToolResultPrunerBinding {
    pub fn prune(
        &self,
        context: CompactionContext,
        input: ToolResultPruningInput,
    ) -> PromptFuture<'_, Result<ToolResultPruningResult, PruningError>> {
        if context.cancellation.is_cancelled() {
            return Box::pin(async { Err(PruningError::Cancelled) });
        }
        let target_bytes = input.target_bytes().get();
        let future = self.provider.prune(context, input);
        Box::pin(async move {
            let result = future.await?;
            if result.results().byte_len() > target_bytes {
                return Err(PruningError::ResultExceedsTarget);
            }
            Ok(result)
        })
    }
}

impl TokenMeterBinding {
    pub fn estimate(
        &self,
        context: CompactionContext,
        input: TokenMeterInput,
    ) -> PromptFuture<'_, Result<TokenEstimate, TokenMeterError>> {
        if context.cancellation.is_cancelled() {
            return Box::pin(async { Err(TokenMeterError::Cancelled) });
        }
        self.provider.estimate(context, input)
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
    struct MismatchedContributor;

    impl PromptContributor for MismatchedContributor {
        fn contributor_id(&self) -> CanonicalId {
            CanonicalId::new("declared").unwrap()
        }

        fn contribute<'a>(
            &'a self,
            _context: &'a PromptContext,
            out: &'a mut PromptBuilder,
        ) -> PromptFuture<'a, Result<(), PromptError>> {
            Box::pin(async move {
                out.add_contribution("different", vec![segment("bad")], 1)?;
                Ok(())
            })
        }
    }

    #[derive(Debug)]
    struct CountingContributor {
        calls: AtomicUsize,
    }

    impl PromptContributor for CountingContributor {
        fn contributor_id(&self) -> CanonicalId {
            CanonicalId::new("counted").unwrap()
        }

        fn contribute<'a>(
            &'a self,
            _context: &'a PromptContext,
            out: &'a mut PromptBuilder,
        ) -> PromptFuture<'a, Result<(), PromptError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                out.add_contribution("counted", vec![segment("valid")], 2)?;
                Ok(())
            })
        }
    }

    #[derive(Debug)]
    struct OversizeCompactor;

    impl Compactor for OversizeCompactor {
        fn compact(
            &self,
            _context: CompactionContext,
            input: CompactionInput,
        ) -> PromptFuture<'_, Result<CompactionResult, CompactionError>> {
            let result = CompactionResult::new(
                input.source_digest(),
                BoundedConversation::new(vec![entry(MessageRole::Assistant, "too large")]).unwrap(),
                3,
            )
            .unwrap();
            Box::pin(async move { Ok(result) })
        }
    }

    #[derive(Debug)]
    struct OversizePruner;

    impl ToolResultPruner for OversizePruner {
        fn prune(
            &self,
            _context: CompactionContext,
            input: ToolResultPruningInput,
        ) -> PromptFuture<'_, Result<ToolResultPruningResult, PruningError>> {
            let result = ToolResultPruningResult::new(input.results().clone());
            Box::pin(async move { Ok(result) })
        }
    }

    fn ready<T>(future: &mut PromptFuture<'_, T>) -> T {
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test future unexpectedly pending"),
        }
    }

    fn segment(value: &str) -> PromptSegment {
        PromptSegment::new(PromptSegmentKind::Instruction, value).unwrap()
    }

    fn entry(role: MessageRole, value: &str) -> ConversationEntry {
        ConversationEntry::new(role, vec![ConversationContent::text(value).unwrap()]).unwrap()
    }

    #[test]
    fn prompt_builder_enforces_identity_count_byte_and_token_bounds_before_retention() {
        let mut builder =
            PromptBuilder::new(NonZeroUsize::new(2).unwrap(), NonZeroUsize::new(8).unwrap())
                .unwrap();
        builder
            .add_contribution("base", vec![segment("four")], 1)
            .unwrap();
        assert_eq!(
            builder.add_contribution("base", vec![segment("x")], 1),
            Err(PromptError::DuplicateContributor)
        );
        assert_eq!(
            builder.add_contribution("next", vec![segment("12345")], 1),
            Err(PromptError::ByteLimitExceeded)
        );
        let prompt = builder.finish();
        assert_eq!(prompt.contributions().len(), 1);
        assert_eq!(prompt.byte_len(), 4);
    }

    #[test]
    fn conversation_and_tool_results_are_bounded_and_identity_complete() {
        let conversation = BoundedConversation::new(vec![
            entry(MessageRole::User, "question"),
            entry(MessageRole::Assistant, "answer"),
        ])
        .unwrap();
        assert_eq!(conversation.byte_len(), 14);

        let call = CallId::from_nonzero_u128(1).unwrap();
        let paired = BoundedConversation::new(vec![
            ConversationEntry::new(
                MessageRole::Assistant,
                vec![ConversationContent::tool_call(call, "read-file", "{}").unwrap()],
            )
            .unwrap(),
            ConversationEntry::new(
                MessageRole::Tool,
                vec![ConversationContent::tool_result(call, "result").unwrap()],
            )
            .unwrap(),
        ])
        .unwrap();
        assert_eq!(paired.block_count(), 2);
        assert_eq!(paired.entries()[0].content()[0].call_id(), Some(call));
        assert_eq!(paired.entries()[1].content()[0].call_id(), Some(call));

        let duplicate = ToolResultEntry::new(call, "second").unwrap();
        assert_eq!(
            ToolResultBatch::new(vec![
                ToolResultEntry::new(call, "first").unwrap(),
                duplicate,
            ]),
            Err(PruningError::DuplicateCallId)
        );
    }

    #[test]
    fn every_public_budget_is_capped_by_a_hard_limit() {
        assert_eq!(
            PromptBuilder::new(
                NonZeroUsize::new(MAX_PROMPT_CONTRIBUTIONS + 1).unwrap(),
                NonZeroUsize::new(1).unwrap(),
            )
            .unwrap_err(),
            PromptError::BudgetExceedsHardLimit
        );
        assert_eq!(
            TokenEstimate::new(MAX_TOKEN_ESTIMATE + 1),
            Err(TokenMeterError::EstimateExceeded)
        );
    }

    #[test]
    fn contributor_binding_rolls_back_identity_protocol_violations() {
        let binding = PromptContributorBinding::from_provider(Arc::new(MismatchedContributor));
        let mut builder = PromptBuilder::new(
            NonZeroUsize::new(2).unwrap(),
            NonZeroUsize::new(16).unwrap(),
        )
        .unwrap();
        let context = PromptContext::new(CancellationToken::new(), None);
        let mut future = binding.contribute(&context, &mut builder);
        assert_eq!(
            ready(&mut future),
            Err(PromptError::ContributorProtocolViolation)
        );
        drop(future);
        assert!(builder.finish().contributions().is_empty());
    }

    #[test]
    fn contributor_cancellation_precedes_callback_and_valid_call_is_audited() {
        let provider = Arc::new(CountingContributor {
            calls: AtomicUsize::new(0),
        });
        let binding = PromptContributorBinding::from_provider(provider.clone());
        let mut builder =
            PromptBuilder::new(NonZeroUsize::new(1).unwrap(), NonZeroUsize::new(8).unwrap())
                .unwrap();
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let context = PromptContext::new(cancelled, None);
        let mut future = binding.contribute(&context, &mut builder);
        assert_eq!(ready(&mut future), Err(PromptError::Cancelled));
        drop(future);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);

        let context = PromptContext::new(CancellationToken::new(), None);
        let mut future = binding.contribute(&context, &mut builder);
        ready(&mut future).unwrap();
        drop(future);
        let prompt = builder.finish();
        assert_eq!(prompt.contributions()[0].contributor_id(), "counted");
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn compaction_and_pruning_bindings_reject_provider_output_above_the_target() {
        let conversation =
            BoundedConversation::new(vec![entry(MessageRole::User, "input")]).unwrap();
        let input = CompactionInput::new(
            Digest::from_bytes([1; 32]),
            conversation,
            NonZeroUsize::new(4).unwrap(),
            NonZeroU64::new(2).unwrap(),
        )
        .unwrap();
        let binding = CompactorBinding::from_provider(Arc::new(OversizeCompactor));
        let mut future = binding.compact(
            CompactionContext::new(CancellationToken::new(), None),
            input,
        );
        assert_eq!(
            ready(&mut future),
            Err(CompactionError::ResultExceedsTarget)
        );

        let results = ToolResultBatch::new(vec![
            ToolResultEntry::new(CallId::from_nonzero_u128(2).unwrap(), "wide").unwrap(),
        ])
        .unwrap();
        let input = ToolResultPruningInput::new(results, NonZeroUsize::new(2).unwrap()).unwrap();
        let binding = ToolResultPrunerBinding::from_provider(Arc::new(OversizePruner));
        let mut future = binding.prune(
            CompactionContext::new(CancellationToken::new(), None),
            input,
        );
        assert_eq!(ready(&mut future), Err(PruningError::ResultExceedsTarget));
    }
}
