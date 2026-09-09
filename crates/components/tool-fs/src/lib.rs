//! Provider-neutral filesystem tools built only from typed filesystem bindings.

use std::{
    collections::{BTreeSet, VecDeque},
    num::{NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
    sync::Arc,
};

use globset::{GlobBuilder, GlobMatcher};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use regex::{Regex, RegexBuilder};
use rust_agent_core::SecurityEffects;
use rust_agent_fs::{
    AgentPath, ByteRange, DirPageCursor, DirPageRequest, FileKind, FileReadBinding,
    FileWriteBinding, FsCallContext, FsError, MAX_AGENT_PATH_BYTES, MAX_DIR_PAGE_BYTES,
    MAX_FS_CALL_BYTES, MAX_FS_RANGE_BYTES, WriteMode, WriteOptions,
};
use rust_agent_runtime_api::{
    CancellationToken, ComponentBuildError, ComponentOutput, RuntimeInstant,
    RuntimePrimitiveBindings,
};
use rust_agent_tools::{
    ExecutionPermit, Tool, ToolCallPolicy, ToolConcurrencyRule, ToolContext, ToolContribution,
    ToolDefinition, ToolError, ToolFuture, ToolRegistration, ToolRegistrationSnapshot, ToolSafety,
    ToolValue,
};
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

pub const SEARCH_MAX_VISITED_ENTRIES: usize = 4_096;
pub const SEARCH_MAX_PAGES: usize = 4_096;
pub const SEARCH_MAX_TOTAL_READ_BYTES: usize = MAX_FS_CALL_BYTES;
pub const SEARCH_MAX_IGNORE_BYTES: usize = 64 * 1024;
pub const SEARCH_MAX_IGNORE_RULES: usize = 4_096;
pub const SEARCH_MAX_RESULTS: usize = 2_000;
pub const SEARCH_MAX_PATTERN_BYTES: usize = 4 * 1024;
pub const SEARCH_MAX_LINE_BYTES: usize = 16 * 1024;
const SEARCH_PAGE_ENTRIES: usize = 256;
const DEFAULT_READ_BYTES: usize = 64 * 1024;
const DEFAULT_SEARCH_RESULTS: usize = 200;

#[derive(Clone, Debug, Default)]
pub struct Config;

#[derive(Clone, Debug)]
pub struct Dependencies {
    pub fs_read: FileReadBinding,
    pub fs_write: Option<FileWriteBinding>,
}

#[derive(Debug)]
pub struct FileSystemTools {
    read: FileReadBinding,
    write: Option<FileWriteBinding>,
}

pub fn build(
    _config: &Config,
    dependencies: Dependencies,
    runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<FileSystemTools>, ComponentBuildError> {
    if !runtime.allowed().is_empty() {
        return Err(ComponentBuildError::InvalidConfig(
            "tool-fs declares no runtime primitives".into(),
        ));
    }
    drop(runtime);
    Ok(ComponentOutput::stateless(FileSystemTools {
        read: dependencies.fs_read,
        write: dependencies.fs_write,
    }))
}

impl ToolContribution for FileSystemTools {
    fn snapshot(&self) -> Result<ToolRegistrationSnapshot, rust_agent_tools::ToolProviderError> {
        let mut registrations = vec![
            register(FsMetadataTool {
                read: self.read.clone(),
            })?,
            register(FsReadTool {
                read: self.read.clone(),
            })?,
            register(FsListTool {
                read: self.read.clone(),
            })?,
            register(FsGlobTool {
                read: self.read.clone(),
            })?,
            register(FsGrepTool {
                read: self.read.clone(),
            })?,
        ];
        if let Some(write) = &self.write {
            registrations.push(register(FsWriteTool {
                write: write.clone(),
            })?);
        }
        ToolRegistrationSnapshot::new("tool-fs", NonZeroU64::MIN, registrations)
    }
}

fn register<T>(tool: T) -> Result<ToolRegistration, rust_agent_tools::ToolProviderError>
where
    T: Tool + 'static,
{
    ToolRegistration::new(Arc::new(tool))
        .map_err(|_| rust_agent_tools::ToolProviderError::InvalidRegistration)
}

#[derive(Debug)]
struct FsMetadataTool {
    read: FileReadBinding,
}

impl Tool for FsMetadataTool {
    fn definition(&self) -> ToolDefinition {
        definition(
            "fs-metadata",
            "Inspect one path in the selected filesystem namespace.",
            json!({
                "type": "object",
                "properties": {"path": {"type": "string", "maxLength": MAX_AGENT_PATH_BYTES}},
                "required": ["path"],
                "additionalProperties": false
            }),
            safety_for(self.read.effects(), false),
            self.read.effects(),
            ToolConcurrencyRule::ParallelSafe,
        )
    }

    fn execute<'a>(
        &'a self,
        _permit: &'a ExecutionPermit,
        context: &'a ToolContext,
        input: JsonValue,
    ) -> ToolFuture<'a, Result<ToolValue, ToolError>> {
        Box::pin(async move {
            let input: PathInput = parse(input)?;
            let path = AgentPath::new(input.path).map_err(fs_error)?;
            let metadata = self
                .read
                .metadata(call_context(context, 1024, 1)?, &path)
                .await
                .map_err(fs_error)?;
            output(
                context,
                json!({
                    "path": path.as_str(),
                    "kind": kind_name(metadata.kind()),
                    "bytes": metadata.byte_len(),
                    "readonly": metadata.readonly(),
                }),
            )
        })
    }
}

#[derive(Debug)]
struct FsReadTool {
    read: FileReadBinding,
}

impl Tool for FsReadTool {
    fn definition(&self) -> ToolDefinition {
        definition(
            "fs-read",
            "Read one bounded UTF-8 byte range from the selected filesystem namespace.",
            json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "maxLength": MAX_AGENT_PATH_BYTES},
                    "offset": {"type": "integer", "minimum": 0},
                    "length": {"type": "integer", "minimum": 1, "maximum": MAX_FS_RANGE_BYTES}
                },
                "required": ["path"],
                "additionalProperties": false
            }),
            safety_for(self.read.effects(), false),
            self.read.effects(),
            ToolConcurrencyRule::ParallelSafe,
        )
    }

    fn execute<'a>(
        &'a self,
        _permit: &'a ExecutionPermit,
        context: &'a ToolContext,
        input: JsonValue,
    ) -> ToolFuture<'a, Result<ToolValue, ToolError>> {
        Box::pin(async move {
            let input: ReadInput = parse(input)?;
            if input.length == 0 || input.length > MAX_FS_RANGE_BYTES {
                return Err(ToolError::invalid_input("length is outside the read bound"));
            }
            let path = AgentPath::new(input.path).map_err(fs_error)?;
            let range = ByteRange::new(
                input.offset,
                NonZeroUsize::new(input.length)
                    .ok_or_else(|| ToolError::invalid_input("length must be positive"))?,
            )
            .map_err(fs_error)?;
            let bytes = self
                .read
                .read(call_context(context, input.length, 1)?, &path, range)
                .await
                .map_err(fs_error)?;
            let text = String::from_utf8(bytes.as_slice().to_vec())
                .map_err(|_| ToolError::provider("filesystem", "file range is not UTF-8"))?;
            output(
                context,
                json!({"path": path.as_str(), "offset": input.offset, "content": text}),
            )
        })
    }
}

#[derive(Debug)]
struct FsListTool {
    read: FileReadBinding,
}

impl Tool for FsListTool {
    fn definition(&self) -> ToolDefinition {
        definition(
            "fs-list",
            "List one bounded page from a directory in the selected filesystem namespace.",
            json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "maxLength": MAX_AGENT_PATH_BYTES},
                    "cursor": {"type": "string", "maxLength": 1024},
                    "max_entries": {"type": "integer", "minimum": 1, "maximum": SEARCH_PAGE_ENTRIES}
                },
                "additionalProperties": false
            }),
            safety_for(self.read.effects(), false),
            self.read.effects(),
            ToolConcurrencyRule::ParallelSafe,
        )
    }

    fn execute<'a>(
        &'a self,
        _permit: &'a ExecutionPermit,
        context: &'a ToolContext,
        input: JsonValue,
    ) -> ToolFuture<'a, Result<ToolValue, ToolError>> {
        Box::pin(async move {
            let input: ListInput = parse(input)?;
            if input.max_entries == 0 || input.max_entries > SEARCH_PAGE_ENTRIES {
                return Err(ToolError::invalid_input(
                    "max_entries is outside the directory-page bound",
                ));
            }
            let path = optional_path(input.path)?;
            let cursor = input
                .cursor
                .map(|value| decode_tool_cursor(self.read.provider_key(), path.clone(), &value))
                .transpose()?;
            let request = DirPageRequest::new(
                path.clone(),
                cursor,
                NonZeroUsize::new(input.max_entries)
                    .ok_or_else(|| ToolError::invalid_input("max_entries must be positive"))?,
                NonZeroUsize::new(MAX_DIR_PAGE_BYTES).expect("constant is nonzero"),
            )
            .map_err(fs_error)?;
            let page = self
                .read
                .list_page(
                    call_context(context, MAX_DIR_PAGE_BYTES, input.max_entries)?,
                    request,
                )
                .await
                .map_err(fs_error)?;
            let entries = page
                .entries()
                .iter()
                .map(|entry| {
                    json!({
                        "name": entry.name(),
                        "kind": kind_name(entry.kind()),
                        "bytes": entry.byte_len(),
                    })
                })
                .collect::<Vec<_>>();
            output(
                context,
                json!({
                    "path": path.as_str(),
                    "entries": entries,
                    "cursor": page.next_cursor().map(|cursor| hex::encode(cursor.token())),
                    "complete": page.complete(),
                }),
            )
        })
    }
}

#[derive(Debug)]
struct FsWriteTool {
    write: FileWriteBinding,
}

impl Tool for FsWriteTool {
    fn definition(&self) -> ToolDefinition {
        definition(
            "fs-write",
            "Create, replace, or append one bounded UTF-8 file in the selected filesystem namespace.",
            json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "maxLength": MAX_AGENT_PATH_BYTES},
                    "content": {"type": "string", "maxLength": MAX_FS_CALL_BYTES},
                    "mode": {"type": "string", "enum": ["create-new", "truncate", "append"]},
                    "create_parents": {"type": "boolean"}
                },
                "required": ["path", "content"],
                "additionalProperties": false
            }),
            safety_for(self.write.effects(), true),
            self.write.effects(),
            ToolConcurrencyRule::Exclusive,
        )
    }

    fn execute<'a>(
        &'a self,
        _permit: &'a ExecutionPermit,
        context: &'a ToolContext,
        input: JsonValue,
    ) -> ToolFuture<'a, Result<ToolValue, ToolError>> {
        Box::pin(async move {
            let input: WriteInput = parse(input)?;
            if input.content.len() > MAX_FS_CALL_BYTES {
                return Err(ToolError::invalid_input("content exceeds the write bound"));
            }
            let path = AgentPath::new(input.path).map_err(fs_error)?;
            let mode = match input.mode {
                ToolWriteMode::CreateNew => WriteMode::CreateNew,
                ToolWriteMode::Truncate => WriteMode::Truncate,
                ToolWriteMode::Append => WriteMode::Append,
            };
            self.write
                .write(
                    call_context(context, input.content.len().max(1), 1)?,
                    &path,
                    input.content.as_bytes(),
                    WriteOptions::new(mode, input.create_parents),
                )
                .await
                .map_err(fs_error)?;
            output(
                context,
                json!({"path": path.as_str(), "written": input.content.len()}),
            )
        })
    }
}

#[derive(Debug)]
struct FsGlobTool {
    read: FileReadBinding,
}

impl Tool for FsGlobTool {
    fn definition(&self) -> ToolDefinition {
        definition(
            "fs-glob",
            "Find bounded paths by glob while honoring namespace .gitignore files.",
            search_schema("Glob pattern relative to root"),
            safety_for(self.read.effects(), false),
            self.read.effects(),
            ToolConcurrencyRule::ParallelSafe,
        )
    }

    fn execute<'a>(
        &'a self,
        _permit: &'a ExecutionPermit,
        context: &'a ToolContext,
        input: JsonValue,
    ) -> ToolFuture<'a, Result<ToolValue, ToolError>> {
        Box::pin(async move {
            let input: SearchInput = parse(input)?;
            validate_search_input(&input)?;
            let root = optional_path(input.root)?;
            let glob_matcher = GlobBuilder::new(&input.pattern)
                .literal_separator(true)
                .build()
                .map_err(|_| ToolError::invalid_input("invalid glob pattern"))?
                .compile_matcher();
            let paths = search_paths(&self.read, context, root, &glob_matcher, input.limit).await?;
            output(context, json!({"matches": paths}))
        })
    }
}

#[derive(Debug)]
struct FsGrepTool {
    read: FileReadBinding,
}

impl Tool for FsGrepTool {
    fn definition(&self) -> ToolDefinition {
        definition(
            "fs-grep",
            "Search bounded UTF-8 files with a regular expression while honoring .gitignore.",
            json!({
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "maxLength": SEARCH_MAX_PATTERN_BYTES},
                    "root": {"type": "string", "maxLength": MAX_AGENT_PATH_BYTES},
                    "file_glob": {"type": "string", "maxLength": SEARCH_MAX_PATTERN_BYTES},
                    "case_sensitive": {"type": "boolean"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": SEARCH_MAX_RESULTS}
                },
                "required": ["pattern"],
                "additionalProperties": false
            }),
            safety_for(self.read.effects(), false),
            self.read.effects(),
            ToolConcurrencyRule::ParallelSafe,
        )
    }

    fn execute<'a>(
        &'a self,
        _permit: &'a ExecutionPermit,
        context: &'a ToolContext,
        input: JsonValue,
    ) -> ToolFuture<'a, Result<ToolValue, ToolError>> {
        Box::pin(async move {
            let input: GrepInput = parse(input)?;
            validate_pattern(&input.pattern)?;
            validate_pattern(&input.file_glob)?;
            validate_limit(input.limit)?;
            let root = optional_path(input.root)?;
            let file_matcher = GlobBuilder::new(&input.file_glob)
                .literal_separator(true)
                .build()
                .map_err(|_| ToolError::invalid_input("invalid file_glob"))?
                .compile_matcher();
            let regex = RegexBuilder::new(&input.pattern)
                .case_insensitive(!input.case_sensitive)
                .size_limit(1024 * 1024)
                .dfa_size_limit(1024 * 1024)
                .build()
                .map_err(|_| ToolError::invalid_input("invalid regular expression"))?;
            let matches = search_contents(
                &self.read,
                context,
                root,
                &file_matcher,
                &regex,
                input.limit,
            )
            .await?;
            output(context, json!({"matches": matches}))
        })
    }
}

fn definition(
    name: &str,
    description: &str,
    schema: JsonValue,
    safety: ToolSafety,
    effects: SecurityEffects,
    concurrency: ToolConcurrencyRule,
) -> ToolDefinition {
    ToolDefinition::new(
        name,
        description,
        schema,
        safety,
        effects,
        ToolCallPolicy::builder(concurrency)
            .build()
            .expect("static filesystem policy is bounded"),
    )
    .expect("static filesystem Tool definition is valid")
}

fn safety_for(effects: SecurityEffects, mutating: bool) -> ToolSafety {
    if mutating || !effects.is_subset_of(SecurityEffects::READ_LOCAL) {
        ToolSafety::Mutating
    } else {
        ToolSafety::ReadOnly
    }
}

fn search_schema(pattern_description: &str) -> JsonValue {
    json!({
        "type": "object",
        "properties": {
            "pattern": {"type": "string", "maxLength": SEARCH_MAX_PATTERN_BYTES, "description": pattern_description},
            "root": {"type": "string", "maxLength": MAX_AGENT_PATH_BYTES},
            "limit": {"type": "integer", "minimum": 1, "maximum": SEARCH_MAX_RESULTS}
        },
        "required": ["pattern"],
        "additionalProperties": false
    })
}

fn output(context: &ToolContext, value: JsonValue) -> Result<ToolValue, ToolError> {
    let mut output = context.output_builder();
    output.append_structured(value)?;
    Ok(output.build())
}

trait FsInvocationContext {
    fn cancellation(&self) -> CancellationToken;
    fn deadline(&self) -> Option<RuntimeInstant>;
}

impl FsInvocationContext for ToolContext {
    fn cancellation(&self) -> CancellationToken {
        self.cancellation()
    }

    fn deadline(&self) -> Option<RuntimeInstant> {
        self.deadline()
    }
}

fn call_context<C: FsInvocationContext + ?Sized>(
    context: &C,
    bytes: usize,
    entries: usize,
) -> Result<FsCallContext, ToolError> {
    FsCallContext::new(
        context.cancellation(),
        context.deadline(),
        NonZeroUsize::new(bytes.clamp(1, MAX_FS_CALL_BYTES)).expect("clamped nonzero"),
        NonZeroUsize::new(entries.clamp(1, 1024)).expect("clamped nonzero"),
    )
    .map_err(fs_error)
}

fn parse<T: for<'de> Deserialize<'de>>(input: JsonValue) -> Result<T, ToolError> {
    serde_json::from_value(input).map_err(|_| ToolError::invalid_input("invalid input shape"))
}

fn optional_path(path: Option<String>) -> Result<AgentPath, ToolError> {
    path.map_or_else(
        || Ok(AgentPath::root()),
        |path| AgentPath::new(path).map_err(fs_error),
    )
}

fn decode_tool_cursor(
    provider_key: &str,
    path: AgentPath,
    value: &str,
) -> Result<DirPageCursor, ToolError> {
    if value.len() > 1024 {
        return Err(ToolError::invalid_input("cursor exceeds its bound"));
    }
    let token = hex::decode(value).map_err(|_| ToolError::invalid_input("cursor is not hex"))?;
    DirPageCursor::new(provider_key, path, token).map_err(fs_error)
}

fn fs_error(error: FsError) -> ToolError {
    match error {
        FsError::Cancelled => ToolError::cancelled(),
        FsError::DeadlineExceeded => ToolError::deadline_exceeded(),
        FsError::InvalidPath
        | FsError::PathTooDeep
        | FsError::InvalidRange
        | FsError::InvalidCursor
        | FsError::ForeignCursor
        | FsError::BudgetExceedsHardLimit
        | FsError::BudgetExceeded => ToolError::invalid_input(error.to_string()),
        _ => ToolError::provider("filesystem", error.to_string()),
    }
}

fn kind_name(kind: FileKind) -> &'static str {
    match kind {
        FileKind::File => "file",
        FileKind::Directory => "directory",
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathInput {
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadInput {
    path: String,
    #[serde(default)]
    offset: u64,
    #[serde(default = "default_read_bytes")]
    length: usize,
}

const fn default_read_bytes() -> usize {
    DEFAULT_READ_BYTES
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListInput {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default = "default_page_entries")]
    max_entries: usize,
}

const fn default_page_entries() -> usize {
    SEARCH_PAGE_ENTRIES
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ToolWriteMode {
    CreateNew,
    #[default]
    Truncate,
    Append,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteInput {
    path: String,
    content: String,
    #[serde(default)]
    mode: ToolWriteMode,
    #[serde(default)]
    create_parents: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchInput {
    pattern: String,
    #[serde(default)]
    root: Option<String>,
    #[serde(default = "default_search_results")]
    limit: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrepInput {
    pattern: String,
    #[serde(default)]
    root: Option<String>,
    #[serde(default = "default_file_glob")]
    file_glob: String,
    #[serde(default = "default_true")]
    case_sensitive: bool,
    #[serde(default = "default_search_results")]
    limit: usize,
}

fn default_file_glob() -> String {
    "**/*".to_owned()
}

const fn default_true() -> bool {
    true
}

const fn default_search_results() -> usize {
    DEFAULT_SEARCH_RESULTS
}

fn validate_search_input(input: &SearchInput) -> Result<(), ToolError> {
    validate_pattern(&input.pattern)?;
    validate_limit(input.limit)
}

fn validate_pattern(pattern: &str) -> Result<(), ToolError> {
    if pattern.is_empty() || pattern.len() > SEARCH_MAX_PATTERN_BYTES {
        Err(ToolError::invalid_input(
            "search pattern is outside its bound",
        ))
    } else {
        Ok(())
    }
}

fn validate_limit(limit: usize) -> Result<(), ToolError> {
    if limit == 0 || limit > SEARCH_MAX_RESULTS {
        Err(ToolError::invalid_input(
            "search result limit is outside its bound",
        ))
    } else {
        Ok(())
    }
}

#[derive(Debug, Default)]
struct SearchBudget {
    visited: usize,
    pages: usize,
    read_bytes: usize,
}

impl SearchBudget {
    fn visit(&mut self) -> Result<(), ToolError> {
        self.visited = self
            .visited
            .checked_add(1)
            .ok_or_else(|| search_budget_error("visited-entry"))?;
        if self.visited > SEARCH_MAX_VISITED_ENTRIES {
            return Err(search_budget_error("visited-entry"));
        }
        Ok(())
    }

    fn page(&mut self) -> Result<(), ToolError> {
        self.pages = self
            .pages
            .checked_add(1)
            .ok_or_else(|| search_budget_error("page"))?;
        if self.pages > SEARCH_MAX_PAGES {
            return Err(search_budget_error("page"));
        }
        Ok(())
    }

    fn reserve_read(&mut self, bytes: usize) -> Result<(), ToolError> {
        self.read_bytes = self
            .read_bytes
            .checked_add(bytes)
            .ok_or_else(|| search_budget_error("read-byte"))?;
        if self.read_bytes > SEARCH_MAX_TOTAL_READ_BYTES {
            return Err(search_budget_error("read-byte"));
        }
        Ok(())
    }
}

fn search_budget_error(kind: &str) -> ToolError {
    ToolError::provider(
        "filesystem-search-budget",
        format!("{kind} budget exceeded"),
    )
}

type IgnoreRule = (PathBuf, String);

async fn search_paths<C: FsInvocationContext + ?Sized>(
    read: &FileReadBinding,
    context: &C,
    root: AgentPath,
    glob_matcher: &GlobMatcher,
    limit: usize,
) -> Result<Vec<String>, ToolError> {
    let mut budget = SearchBudget::default();
    let mut queue = VecDeque::from([(root.clone(), Arc::<[IgnoreRule]>::from([]))]);
    let mut paths = BTreeSet::new();
    while let Some((directory, inherited_rules)) = queue.pop_front() {
        let rules =
            load_ignore_rules(read, context, &directory, inherited_rules, &mut budget).await?;
        let ignore = compile_ignore(&root, &rules)?;
        for entry in list_directory(read, context, &directory, &mut budget).await? {
            if entry.name() == ".git" && entry.kind() == FileKind::Directory {
                continue;
            }
            let child = directory.join(entry.name()).map_err(fs_error)?;
            let relative = relative_path(&root, &child)?;
            if ignore
                .matched_path_or_any_parents(
                    Path::new(child.as_str()),
                    entry.kind() == FileKind::Directory,
                )
                .is_ignore()
            {
                continue;
            }
            match entry.kind() {
                FileKind::Directory => queue.push_back((child, Arc::clone(&rules))),
                FileKind::File if glob_matcher.is_match(&relative) => {
                    paths.insert(relative);
                    if paths.len() > limit {
                        paths.pop_last();
                    }
                }
                FileKind::File => {}
            }
        }
    }
    Ok(paths.into_iter().collect())
}

async fn search_contents<C: FsInvocationContext + ?Sized>(
    read: &FileReadBinding,
    context: &C,
    root: AgentPath,
    file_matcher: &GlobMatcher,
    regex: &Regex,
    limit: usize,
) -> Result<Vec<String>, ToolError> {
    let mut budget = SearchBudget::default();
    let mut queue = VecDeque::from([(root.clone(), Arc::<[IgnoreRule]>::from([]))]);
    let mut matches = BTreeSet::new();
    while let Some((directory, inherited_rules)) = queue.pop_front() {
        let rules =
            load_ignore_rules(read, context, &directory, inherited_rules, &mut budget).await?;
        let ignore = compile_ignore(&root, &rules)?;
        for entry in list_directory(read, context, &directory, &mut budget).await? {
            if entry.name() == ".git" && entry.kind() == FileKind::Directory {
                continue;
            }
            let child = directory.join(entry.name()).map_err(fs_error)?;
            let relative = relative_path(&root, &child)?;
            if ignore
                .matched_path_or_any_parents(
                    Path::new(child.as_str()),
                    entry.kind() == FileKind::Directory,
                )
                .is_ignore()
            {
                continue;
            }
            match entry.kind() {
                FileKind::Directory => queue.push_back((child, Arc::clone(&rules))),
                FileKind::File if file_matcher.is_match(&relative) => {
                    grep_file(
                        read,
                        context,
                        &child,
                        GrepFileSpec {
                            display: &relative,
                            byte_len: entry.byte_len(),
                            regex,
                            limit,
                        },
                        &mut budget,
                        &mut matches,
                    )
                    .await?;
                }
                FileKind::File => {}
            }
        }
    }
    Ok(matches.into_iter().take(limit).collect())
}

async fn list_directory<C: FsInvocationContext + ?Sized>(
    read: &FileReadBinding,
    context: &C,
    directory: &AgentPath,
    budget: &mut SearchBudget,
) -> Result<Vec<rust_agent_fs::DirEntry>, ToolError> {
    let mut cursor = None;
    let mut entries = Vec::new();
    loop {
        budget.page()?;
        let request = DirPageRequest::new(
            directory.clone(),
            cursor,
            NonZeroUsize::new(SEARCH_PAGE_ENTRIES).expect("constant is nonzero"),
            NonZeroUsize::new(MAX_DIR_PAGE_BYTES).expect("constant is nonzero"),
        )
        .map_err(fs_error)?;
        let page = read
            .list_page(
                call_context(context, MAX_DIR_PAGE_BYTES, SEARCH_PAGE_ENTRIES)?,
                request,
            )
            .await
            .map_err(fs_error)?;
        for entry in page.entries() {
            budget.visit()?;
            entries.push(entry.clone());
        }
        if page.complete() {
            break;
        }
        cursor = page.next_cursor().cloned();
    }
    entries.sort_by(|left, right| left.name().cmp(right.name()));
    Ok(entries)
}

async fn load_ignore_rules<C: FsInvocationContext + ?Sized>(
    read: &FileReadBinding,
    context: &C,
    directory: &AgentPath,
    inherited: Arc<[IgnoreRule]>,
    budget: &mut SearchBudget,
) -> Result<Arc<[IgnoreRule]>, ToolError> {
    let path = directory.join(".gitignore").map_err(fs_error)?;
    let metadata = match read.metadata(call_context(context, 1024, 1)?, &path).await {
        Ok(metadata) => metadata,
        Err(FsError::NotFound) => return Ok(inherited),
        Err(error) => return Err(fs_error(error)),
    };
    if metadata.kind() != FileKind::File || metadata.byte_len() == 0 {
        return Ok(inherited);
    }
    let length =
        usize::try_from(metadata.byte_len()).map_err(|_| search_budget_error("ignore-byte"))?;
    if length > SEARCH_MAX_IGNORE_BYTES || length > MAX_FS_RANGE_BYTES {
        return Err(search_budget_error("ignore-byte"));
    }
    budget.reserve_read(length)?;
    let range = ByteRange::new(
        0,
        NonZeroUsize::new(length).expect("positive metadata length"),
    )
    .map_err(fs_error)?;
    let bytes = read
        .read(call_context(context, length, 1)?, &path, range)
        .await
        .map_err(fs_error)?;
    let text = std::str::from_utf8(bytes.as_slice())
        .map_err(|_| ToolError::provider("filesystem", ".gitignore is not UTF-8"))?;
    let additional = text.lines().count();
    if inherited.len().saturating_add(additional) > SEARCH_MAX_IGNORE_RULES {
        return Err(search_budget_error("ignore-rule"));
    }
    let source = PathBuf::from(path.as_str());
    let mut rules = inherited.to_vec();
    rules.extend(text.lines().map(|line| (source.clone(), line.to_owned())));
    Ok(Arc::from(rules))
}

fn compile_ignore(root: &AgentPath, rules: &[IgnoreRule]) -> Result<Gitignore, ToolError> {
    let root = if root.is_root() { "." } else { root.as_str() };
    let mut builder = GitignoreBuilder::new(root);
    for (source, line) in rules {
        builder
            .add_line(Some(source.clone()), line)
            .map_err(|_| ToolError::provider("filesystem", "invalid .gitignore rule"))?;
    }
    builder
        .build()
        .map_err(|_| ToolError::provider("filesystem", "cannot compile .gitignore rules"))
}

struct GrepFileSpec<'a> {
    display: &'a str,
    byte_len: u64,
    regex: &'a Regex,
    limit: usize,
}

async fn grep_file<C: FsInvocationContext + ?Sized>(
    read: &FileReadBinding,
    context: &C,
    path: &AgentPath,
    spec: GrepFileSpec<'_>,
    budget: &mut SearchBudget,
    matches: &mut BTreeSet<String>,
) -> Result<(), ToolError> {
    if spec.byte_len == 0 {
        return Ok(());
    }
    let length = match usize::try_from(spec.byte_len) {
        Ok(length) if length <= MAX_FS_RANGE_BYTES => length,
        _ => return Ok(()),
    };
    budget.reserve_read(length)?;
    let range = ByteRange::new(
        0,
        NonZeroUsize::new(length).expect("positive metadata length"),
    )
    .map_err(fs_error)?;
    let bytes = read
        .read(call_context(context, length, 1)?, path, range)
        .await
        .map_err(fs_error)?;
    if bytes.as_slice().contains(&0) {
        return Ok(());
    }
    let Ok(text) = std::str::from_utf8(bytes.as_slice()) else {
        return Ok(());
    };
    for (line_index, line) in text.lines().enumerate() {
        if spec.regex.is_match(line) {
            let bounded_line = truncate_utf8(line, SEARCH_MAX_LINE_BYTES);
            matches.insert(format!(
                "{}:{}:{bounded_line}",
                spec.display,
                line_index + 1
            ));
            if matches.len() > spec.limit {
                matches.pop_last();
            }
        }
    }
    Ok(())
}

fn relative_path(root: &AgentPath, child: &AgentPath) -> Result<String, ToolError> {
    if root.is_root() {
        return Ok(child.as_str().to_owned());
    }
    child
        .as_str()
        .strip_prefix(root.as_str())
        .and_then(|value| value.strip_prefix('/'))
        .map(str::to_owned)
        .ok_or_else(|| ToolError::provider("filesystem", "provider returned a path outside root"))
}

fn truncate_utf8(value: &str, maximum: usize) -> &str {
    if value.len() <= maximum {
        return value;
    }
    let mut boundary = maximum;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    &value[..boundary]
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        future::Future,
        sync::Mutex,
        task::{Context, Poll, Waker},
    };

    use rust_agent_core::CanonicalId;
    use rust_agent_fs::{
        DirEntry, DirPage, FileBytes, FileMetadata, FileRead, FileWrite, FsFuture,
    };
    use rust_agent_runtime_api::{
        RuntimeClock, RuntimeFuture, RuntimePrimitiveError, RuntimeSleeper, RuntimeSpawner,
        RuntimeTaskOwner,
    };

    use super::*;

    #[derive(Clone, Debug)]
    enum MemoryEntry {
        Directory,
        File(Vec<u8>),
    }

    #[derive(Debug)]
    struct MemoryFs {
        entries: Mutex<BTreeMap<String, MemoryEntry>>,
        read_effects: SecurityEffects,
    }

    impl MemoryFs {
        fn fixture() -> Arc<Self> {
            Arc::new(Self {
                entries: Mutex::new(BTreeMap::from([
                    (String::new(), MemoryEntry::Directory),
                    (
                        ".gitignore".to_owned(),
                        MemoryEntry::File(b"ignored/\n*.log\n!important.log\n".to_vec()),
                    ),
                    (
                        "kept.rs".to_owned(),
                        MemoryEntry::File(b"needle\n".to_vec()),
                    ),
                    ("ignored".to_owned(), MemoryEntry::Directory),
                    (
                        "ignored/secret.rs".to_owned(),
                        MemoryEntry::File(b"needle secret\n".to_vec()),
                    ),
                    (
                        "discard.log".to_owned(),
                        MemoryEntry::File(b"needle\n".to_vec()),
                    ),
                    (
                        "important.log".to_owned(),
                        MemoryEntry::File(b"needle important\n".to_vec()),
                    ),
                    ("nested".to_owned(), MemoryEntry::Directory),
                    (
                        "nested/.gitignore".to_owned(),
                        MemoryEntry::File(b"skip.rs\n".to_vec()),
                    ),
                    (
                        "nested/skip.rs".to_owned(),
                        MemoryEntry::File(b"needle skip\n".to_vec()),
                    ),
                    (
                        "nested/visible.rs".to_owned(),
                        MemoryEntry::File(b"first\nneedle visible\n".to_vec()),
                    ),
                ])),
                read_effects: SecurityEffects::READ_LOCAL,
            })
        }

        fn entry(&self, path: &AgentPath) -> Result<MemoryEntry, FsError> {
            self.entries
                .lock()
                .unwrap()
                .get(path.as_str())
                .cloned()
                .ok_or(FsError::NotFound)
        }
    }

    impl FileRead for MemoryFs {
        fn provider_key(&self) -> CanonicalId {
            CanonicalId::new("memory").unwrap()
        }

        fn effects(&self) -> SecurityEffects {
            self.read_effects
        }

        fn metadata<'a>(
            &'a self,
            _context: FsCallContext,
            path: &'a AgentPath,
        ) -> FsFuture<'a, Result<FileMetadata, FsError>> {
            Box::pin(async move {
                match self.entry(path)? {
                    MemoryEntry::Directory => Ok(FileMetadata::new(FileKind::Directory, 0, false)),
                    MemoryEntry::File(bytes) => {
                        Ok(FileMetadata::new(FileKind::File, bytes.len() as u64, false))
                    }
                }
            })
        }

        fn read<'a>(
            &'a self,
            _context: FsCallContext,
            path: &'a AgentPath,
            range: ByteRange,
        ) -> FsFuture<'a, Result<FileBytes, FsError>> {
            Box::pin(async move {
                let MemoryEntry::File(bytes) = self.entry(path)? else {
                    return Err(FsError::NotFile);
                };
                let start = usize::try_from(range.start()).map_err(|_| FsError::InvalidRange)?;
                let end = start.saturating_add(range.length().get()).min(bytes.len());
                let bytes = if start >= bytes.len() {
                    Vec::new()
                } else {
                    bytes[start..end].to_vec()
                };
                FileBytes::new(bytes)
            })
        }

        fn list_page(
            &self,
            _context: FsCallContext,
            request: DirPageRequest,
        ) -> FsFuture<'_, Result<DirPage, FsError>> {
            Box::pin(async move {
                if !matches!(self.entry(request.path())?, MemoryEntry::Directory) {
                    return Err(FsError::NotDirectory);
                }
                if request.cursor().is_some() {
                    return Err(FsError::InvalidCursor);
                }
                let prefix = if request.path().is_root() {
                    String::new()
                } else {
                    format!("{}/", request.path().as_str())
                };
                let entries = self.entries.lock().unwrap();
                let mut children = Vec::new();
                for (path, entry) in entries.iter() {
                    let Some(name) = path.strip_prefix(&prefix) else {
                        continue;
                    };
                    if name.is_empty() || name.contains('/') {
                        continue;
                    }
                    let (kind, bytes) = match entry {
                        MemoryEntry::Directory => (FileKind::Directory, 0),
                        MemoryEntry::File(bytes) => (FileKind::File, bytes.len() as u64),
                    };
                    children.push(DirEntry::new(name, kind, bytes)?);
                }
                children.sort_by(|left, right| left.name().cmp(right.name()));
                if children.len() > request.max_entries().get() {
                    return Err(FsError::BudgetExceeded);
                }
                DirPage::new(children, None, true)
            })
        }
    }

    impl FileWrite for MemoryFs {
        fn provider_key(&self) -> CanonicalId {
            CanonicalId::new("memory").unwrap()
        }

        fn effects(&self) -> SecurityEffects {
            SecurityEffects::WRITE_LOCAL
        }

        fn write<'a>(
            &'a self,
            _context: FsCallContext,
            path: &'a AgentPath,
            data: &'a [u8],
            options: WriteOptions,
        ) -> FsFuture<'a, Result<(), FsError>> {
            Box::pin(async move {
                let mut entries = self.entries.lock().unwrap();
                match options.mode() {
                    WriteMode::CreateNew if entries.contains_key(path.as_str()) => {
                        Err(FsError::AlreadyExists)
                    }
                    WriteMode::Append => {
                        let entry = entries
                            .entry(path.as_str().to_owned())
                            .or_insert_with(|| MemoryEntry::File(Vec::new()));
                        let MemoryEntry::File(bytes) = entry else {
                            return Err(FsError::NotFile);
                        };
                        bytes.extend_from_slice(data);
                        Ok(())
                    }
                    WriteMode::CreateNew | WriteMode::Truncate => {
                        entries.insert(path.as_str().to_owned(), MemoryEntry::File(data.to_vec()));
                        Ok(())
                    }
                }
            })
        }
    }

    #[derive(Debug)]
    struct TestContext {
        cancellation: CancellationToken,
        deadline: Option<RuntimeInstant>,
    }

    #[derive(Debug)]
    struct RuntimeBackend;

    impl RuntimeClock for RuntimeBackend {
        fn now(&self) -> RuntimeInstant {
            RuntimeInstant::from_monotonic_duration(std::time::Duration::ZERO)
        }
    }

    impl RuntimeSleeper for RuntimeBackend {
        fn sleep_until(&self, _deadline: RuntimeInstant) -> RuntimeFuture<'static, ()> {
            Box::pin(async {})
        }
    }

    impl RuntimeSpawner for RuntimeBackend {
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

    impl FsInvocationContext for TestContext {
        fn cancellation(&self) -> CancellationToken {
            self.cancellation.clone()
        }

        fn deadline(&self) -> Option<RuntimeInstant> {
            self.deadline
        }
    }

    fn run<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("tool-fs future unexpectedly pending"),
        }
    }

    fn context() -> TestContext {
        TestContext {
            cancellation: CancellationToken::new(),
            deadline: None,
        }
    }

    #[test]
    fn readonly_snapshot_has_exact_binding_effects_and_no_write_schema() {
        let filesystem = MemoryFs::fixture();
        let service = build(
            &Config,
            Dependencies {
                fs_read: FileReadBinding::from_provider(filesystem),
                fs_write: None,
            },
            RuntimePrimitiveBindings::none(),
        )
        .unwrap()
        .into_service();
        let snapshot = service.snapshot().unwrap();
        let definitions = snapshot
            .registrations()
            .iter()
            .map(ToolRegistration::definition)
            .collect::<Vec<_>>();
        assert_eq!(definitions.len(), 5);
        assert!(definitions.iter().all(|definition| {
            definition.static_effects() == SecurityEffects::READ_LOCAL
                && definition.static_safety() == ToolSafety::ReadOnly
        }));
        assert!(
            !definitions
                .iter()
                .any(|definition| definition.name() == "fs-write")
        );
    }

    #[test]
    fn writable_snapshot_adds_only_the_optional_write_schema_and_effect_stamp() {
        let filesystem = MemoryFs::fixture();
        let service = build(
            &Config,
            Dependencies {
                fs_read: FileReadBinding::from_provider(Arc::clone(&filesystem)),
                fs_write: Some(FileWriteBinding::from_provider(filesystem)),
            },
            RuntimePrimitiveBindings::none(),
        )
        .unwrap()
        .into_service();
        let snapshot = service.snapshot().unwrap();
        let write = snapshot
            .registrations()
            .iter()
            .map(ToolRegistration::definition)
            .find(|definition| definition.name() == "fs-write")
            .unwrap();
        assert_eq!(snapshot.registrations().len(), 6);
        assert_eq!(write.static_effects(), SecurityEffects::WRITE_LOCAL);
        assert_eq!(write.static_safety(), ToolSafety::Mutating);
    }

    #[test]
    fn glob_and_grep_are_provider_only_sorted_bounded_and_gitignore_aware() {
        let filesystem = MemoryFs::fixture();
        let read = FileReadBinding::from_provider(filesystem);
        let glob = GlobBuilder::new("**/*.rs")
            .literal_separator(true)
            .build()
            .unwrap()
            .compile_matcher();
        let paths = run(search_paths(
            &read,
            &context(),
            AgentPath::root(),
            &glob,
            10,
        ))
        .unwrap();
        assert_eq!(paths, ["kept.rs", "nested/visible.rs"]);

        let regex = Regex::new("needle").unwrap();
        let lines = run(search_contents(
            &read,
            &context(),
            AgentPath::root(),
            &GlobBuilder::new("**/*")
                .literal_separator(true)
                .build()
                .unwrap()
                .compile_matcher(),
            &regex,
            10,
        ))
        .unwrap();
        assert_eq!(
            lines,
            [
                "important.log:1:needle important",
                "kept.rs:1:needle",
                "nested/visible.rs:2:needle visible",
            ]
        );
    }

    #[test]
    fn cancelled_search_and_undeclared_runtime_primitive_fail_before_work() {
        let filesystem = MemoryFs::fixture();
        let read = FileReadBinding::from_provider(filesystem);
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = TestContext {
            cancellation,
            deadline: None,
        };
        let glob = GlobBuilder::new("**/*").build().unwrap().compile_matcher();
        assert!(matches!(
            run(search_paths(
                &read,
                &cancelled,
                AgentPath::root(),
                &glob,
                10,
            )),
            Err(error) if error.kind() == rust_agent_tools::ToolErrorKind::Cancelled
        ));

        let backend = Arc::new(RuntimeBackend);
        let runtime = rust_agent_runtime_api::RuntimePrimitives::from_adapter(
            rust_agent_runtime_api::RuntimeAdapterIdentity::checked("tool-fs-test").unwrap(),
            Arc::clone(&backend),
            backend.clone(),
            backend.clone(),
            backend,
        );
        let projected = RuntimePrimitiveBindings::projected(
            runtime,
            &[rust_agent_runtime_api::RuntimePrimitiveKind::Clock],
        )
        .unwrap();
        assert!(
            build(
                &Config,
                Dependencies {
                    fs_read: read,
                    fs_write: None,
                },
                projected,
            )
            .is_err()
        );
    }
}
