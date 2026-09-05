# rust-agent 生产级编译期可插拔组件架构实现方案

> 架构原则：**Clean Architecture Reimplementation + Controlled Code Porting**。
>
> `rust-agent` 是独立的跨平台 Rust Agent Runtime。它以 deepseek-harness 的 **Capability Seam / Service Definition → Provider → Consumer** 为能力边界参考，以 AINS 现有 `crates/rust-agent` 的算法、实现和 regression tests 作为迁移输入；只有在 rust-agent 对应 target 重新通过测试的行为才视为已验证，不复制 Cordis、Fiber、Effect、运行时 Service Locator、HMR 动态插件图，也不继承 AINS 的产品依赖和旧单 crate 边界。
>
> 本方案的“编译期可插拔”不是用 Cargo feature 模拟运行时插件，而是通过 **Composition Compiler → Constraint Resolution → Generated Cargo Dependency Graph → Generated Static Composition** 决定最终 binary 中实际存在的组件、依赖和安全能力。Runtime Configuration 只能配置或选择已经编译进入 binary 的 provider，不能把未编译组件动态带回来。

文档状态：**v1 Architecture Contract / implementation baseline**。本文中的“必须/禁止/只能”是 normative requirement；示例代码用于固定 API 形状与失败语义，实施时若需要改变，必须先以 ADR 更新本文、相关 invariant 和 acceptance test，不能让代码与文档静默分叉。正式实施从 Phase 0 → Phase 1A 开始；后续 Phase 的边界是约束，但不代表对应能力已交付。任何 production/deployable 声明还必须单独通过 Phase 1B 的 Host-specific build enforcement gate。

---

## 1. 架构目标

新的 `rust-agent` 从第一天必须满足以下架构不变量：

1. `rust-agent-core` 只保存稳定、轻量、跨能力共享的基础类型，不拥有 Agent Loop、Tools、Session、Memory、HTTP、存储或产品语义。
2. Minimal Profile 的最短执行路径是 `Request → LanguageModel → Response`；该路径由 `driver-direct` 组合完成，而不是把 driver 放进 core。
3. Agent Loop 不是特权 kernel，而是一个可替换的 `AgentDriver` provider；Agent 的创建、所有权与销毁由 `AgentFactory` / `AgentHandle` 管理。
4. Tools、Session、Prompt、Memory、Compaction、Filesystem、Sandbox、MCP、Web、Subagent、Jobs、Workflow 等均为可删除组件。
5. Consumer 只能依赖 Capability API，禁止直接依赖 concrete Provider crate；最终 generated root 是唯一允许同时直接依赖多个 concrete Component crate 的装配边界。
6. **Build-Time 决定“哪些 package / dependency / implementation 存在于 binary”**；Runtime Configuration 只决定这些已编译组件如何运行、或在编译进来的 provider registry 中选哪个 provider。
7. Cargo feature 只用于**已选 crate 内部的正向编译选项**，不是用户级组件模型，也不是高风险组件删除的安全边界。
8. 高风险 capability（filesystem-write、persistent storage、network、process execution、remote execution、MCP、code-runtime、secret access 等）关闭后，其实现 crate 必须从 **generated Cargo dependency graph** 与最终 binary 中消失，而不是仅靠 `#[cfg]` 隐藏调用点。
9. Native / Linux / macOS / Windows / WASM browser / iOS / Android 的差异通过 provider target predicates 表达，业务层不得散布平台条件分支。
10. Runtime instance 必须存在明确 owner；Session/Agent-scoped 资源在创建事务提交前不得对外可见，创建失败必须完整 rollback。
11. Durable Agent 中任何 model-visible 输入都必须可从 SessionLog 重建；SessionLog 是会话领域事实的单一事实源。
12. Tool 执行只能通过 guarded `ToolExecutor` reference monitor；AgentDriver、MCP、Workflow、Subagent 等均不得绕过策略层直接调用 `Tool::execute`。
13. 独立仓库不得依赖 AINS、任何 UI/application framework、`client-api` 或任何 AINS 产品类型。
14. 相同 composition input 必须生成完全确定性的 resolution、Cargo graph、composition source 和 composition manifest；build attestation 的非确定性外层证明不参与 artifact identity。
15. 第一版中每个可独立选择的 Component 必须对应一个 Cargo package；一个 Component 可以提供多个 Capability，但不能与另一个可独立启停的 Component 共享实现 package。
16. 第一版 Durable resume 只接受完全相同的 composition hash 与 generated SessionEventCatalog digest；任何未知事件 fail closed，跨 composition 转换属于未来独立的离线 migration/import。
17. App、parent、child 与 stored Durable authority 只能做交集；runtime Agent binding projection 只能删除编译期已有能力，不能 fallback 或重新解析出新 provider。
18. Native outbound transport 必须在 DNS/proxy/socket side effect 前授权 logical intent，并对每个解析后的实际连接 hop 再授权。

最终依赖方向固定为：

```text
AINS / CLI / Server / Native UI / WebView IPC / WASM / Mobile / Third-party Host
                              │
                              ▼
                         rust-agent
```

禁止：

```text
rust-agent
    │
    ▼
   AINS
```

---

## 2. 两个参考项目应如何使用

### 2.1 deepseek-harness：借 capability architecture，不借动态运行时机制

deepseek-harness 中真正值得复用的是 seam 的职责分离：

```text
Service Definition
       ↓
Service Provider
       ↓
Consumer
```

映射为 Rust：

```text
Capability API
     ↓
Provider Component
     ↓
Consumer Component
```

同时吸收它已经验证的以下系统语义：

- Agent interface 与 concrete agent-loop 分离；
- Session 是 append-only event log，模型历史从 log 派生；
- Tools 是 registry + guarded execution pipeline，而不是工具 Map；
- filesystem / subprocess / shell / terminal / sandbox 各有独立 seam；
- Prompt 是有序 contributor/registry，而不是 kernel 内字符串拼接；
- Agent/Session 创建存在未发布准备态、所有权、回滚和有序 teardown；
- per-agent scoped registrations 能表达“只对某 Agent 可见”和“资源归谁销毁”；
- provider registry、singleton provider、ordered contribution、factory 等并非同一种 cardinality；
- cancellation、tool parallelism、persistence flush、crash recovery 都有明确生命周期语义。

重点 capability family：

- model / llm
- agent / agent-driver / agent-factory
- session / persistence / query / projection / title
- system prompt
- tools / guarded execution
- filesystem
- subprocess
- shell
- terminal
- sandbox
- approval / permission
- code runtime
- skills
- commands
- user interaction
- compaction / token meter / tool-result pruning
- subagent / agent team
- jobs
- web
- workflow
- lsp
- attachments
- spill
- settings / runtime configuration
- credentials
- telemetry

明确不复制：

- Cordis Context
- Runtime Service Locator
- Fiber
- Effect API
- runtime plugin loader
- HMR dynamic graph
- runtime type registry
- client plugin graph

Rust 替代物：

```text
Package Metadata / Component Catalog
            ↓
Capability + Binding Graph
            ↓
Composition Compiler
            ↓
Deterministic Constraint Resolver
            ↓
Generated Cargo Dependency Graph
            ↓
Generated Static Composition
            ↓
Scoped Compile-Time DI + Explicit Runtime Ownership
```

### 2.2 AINS rust-agent：借成熟实现与 regression，不继承旧边界

优先迁移的实现资产：

- filesystem path canonicalization、symlink/TOCTOU 防护、glob/grep、cwd anchoring
- MCP transport / tool adapter
- network SSRF / redirect 防护
- tool output budgeting / metadata / spill 经验
- permission engine
- Linux sandbox 与 process-tree regression；macOS/Windows/mobile 代码仅作为待验证实现输入
- process-group / process-tree cancellation
- bounded stdout/stderr 读取
- Redb KV store
- IndexedDB KV store
- encrypted KV decorator
- HNSW vector store
- document / Markdown / PDF parsing
- memory extraction / indexing 算法
- skill parsing / normalization
- streaming retry / cancellation / partial-output 语义
- Native `Send` / WASM `?Send` 兼容经验
- 已存在的 black-box、integration 与 security regression tests

不原样迁移的核心抽象：

- `AgentKernel`
- 当前 `ModelClient`
- chat/embed/stt/tts 聚合到同一 model trait 的设计
- 当前 `ContextStore` 的职责边界
- 当前 `ToolRuntime` 同时承担 registry / permission / approval / hook / output / cancellation 的设计
- 当前 Sandbox 直接包含 Shell execution 语义的边界
- 当前单 crate module graph
- 对 `client-api` 的直接依赖

迁移原则固定为：**先定义新 seam → 复制行为测试 → 再迁实现；不得整目录搬迁后再清理。**

---

## 3. Repository / Workspace 结构

仓库结构：

```text
rust-agent/
├── Cargo.toml                         # workspace only，不作为最终产品 composition
├── README.md
├── ARCHITECTURE.md
├── SECURITY.md
├── rust-agent.toml.example
├── docs/adr/                          # accepted architecture decision records
│
├── crates/
│   ├── api/
│   │   ├── rust-agent-core/          # 基础 DTO / IDs / common primitives
│   │   ├── rust-agent-model/         # LanguageModel / model wire-neutral DTO
│   │   ├── rust-agent-agent/         # Agent / AgentDriver / AgentFactory / AgentHandle
│   │   ├── rust-agent-tools/         # Tool contracts + private registry/guarded reference-monitor core
│   │   ├── rust-agent-session/       # SessionLog / SessionEvent / SessionHandle
│   │   ├── rust-agent-runtime-api/   # Cancellation / Clock/Sleeper/Spawner / shared lifecycle protocol DTO/errors
│   │   ├── rust-agent-fs/            # filesystem contracts
│   │   ├── rust-agent-process/       # subprocess / shell / terminal contracts
│   │   ├── rust-agent-policy/        # sandbox / permission / approval contracts
│   │   ├── rust-agent-prompt/        # prompt contributor / assembly contracts
│   │   ├── rust-agent-memory/        # KV / vector / retrieval / memory contracts
│   │   ├── rust-agent-skills/        # skills contracts
│   │   ├── rust-agent-credentials/   # credential contracts
│   │   ├── rust-agent-attachments/   # attachment contracts
│   │   ├── rust-agent-spill/         # spill contracts
│   │   ├── rust-agent-telemetry/     # telemetry contracts
│   │   ├── rust-agent-code-runtime/  # code runtime contracts
│   │   ├── rust-agent-commands/      # lightweight command contract / guarded dispatcher
│   │   └── rust-agent-extension-api/ # network / web / MCP / jobs / subagent 等轻量接口
│   │
│   ├── composition/
│   │   ├── rust-agent-composition/
│   │       ├── metadata.rs
│   │       ├── catalog.rs
│   │       ├── resolver.rs
│   │       ├── diagnostics.rs
│   │       ├── generator.rs
│   │       └── manifest.rs
│   │   └── rust-agent-build-executor/
│   │       ├── policy.rs
│   │       ├── fetch.rs
│   │       ├── sandbox.rs
│   │       ├── attestation.rs
│   │       └── platform/
│   │
│   ├── runtime-adapters/
│   │   ├── rust-agent-runtime-tokio/  # owned native RuntimePrimitives bundle
│   │   └── rust-agent-runtime-wasm/   # browser-local RuntimePrimitives bundle
│   │
│   ├── components/
│   │   ├── driver-direct/
│   │   ├── driver-tools/
│   │   ├── driver-planner/
│   │   ├── driver-team/
│   │   │
│   │   ├── tool-executor-guarded/
│   │   ├── compaction/
│   │   ├── retrieval-local/
│   │   ├── lsp-local/
│   │   │
│   │   ├── model-openai/
│   │   ├── model-deepseek/
│   │   ├── model-replay/
│   │   ├── model-host/
│   │   │
│   │   ├── resource-namespace-bootstrap-local/
│   │   ├── fs-read-local/
│   │   ├── fs-local/
│   │   ├── fs-memory/
│   │   ├── fs-sandbox/
│   │   ├── fs-remote/
│   │   ├── fs-e2b/
│   │   ├── subprocess-local/
│   │   ├── shell-local/
│   │   ├── shell-ssh/
│   │   ├── shell-e2b/
│   │   ├── terminal-local/
│   │   ├── sandbox-linux/
│   │   ├── sandbox-macos/
│   │   ├── sandbox-windows/
│   │   ├── mobile-policy/
│   │   ├── permission-default/
│   │   ├── approval-host/
│   │   │
│   │   ├── session-log-events/
│   │   ├── session-persistence-memory/
│   │   ├── session-persistence-jsonl/
│   │   ├── session-persistence-redb/
│   │   ├── session-persistence-remote/
│   │   ├── session-query-events/
│   │   ├── session-projection-events/
│   │   ├── session-title-basic/
│   │   ├── kv-memory/
│   │   ├── kv-redb/
│   │   ├── kv-indexeddb/
│   │   ├── kv-encrypted/
│   │   ├── vector-hnsw/
│   │   ├── vector-flat/
│   │   ├── embedding-openai/
│   │   ├── embedding-host/
│   │   ├── parser-markdown/
│   │   ├── parser-pdf/
│   │   ├── skill-filesystem/
│   │   ├── skill-embedded/
│   │   ├── skill-remote/
│   │   ├── credentials-env/
│   │   ├── credentials-host/
│   │   ├── telemetry-none/
│   │   ├── telemetry-otel/
│   │   ├── network-policy-default/
│   │   ├── network-policy-host/
│   │   ├── network-connector-native/
│   │   ├── http-client-native/
│   │   ├── web-http-native/
│   │   ├── web-fetch-host/
│   │   ├── web-search-deepseek/
│   │   ├── web-search-exa/
│   │   ├── web-search-perplexity/
│   │   ├── web-search-host/
│   │   │
│   │   ├── tool-fs/
│   │   ├── tool-shell/
│   │   ├── tool-terminal/
│   │   ├── tool-web/
│   │   ├── tool-lsp/
│   │   ├── tool-skill/
│   │   ├── prompt-assembly/
│   │   ├── prompt-skills/
│   │   ├── plan-mode/
│   │   ├── memory-context/
│   │   ├── rag/
│   │   ├── mcp-client/
│   │   ├── mcp-transport-http/
│   │   ├── mcp-transport-stdio/
│   │   ├── mcp-transport-host/
│   │   ├── user-interaction-host/
│   │   ├── attachment-memory/
│   │   ├── attachment-local/
│   │   ├── attachment-host/
│   │   ├── spill-memory/
│   │   ├── spill-local/
│   │   ├── spill-host/
│   │   ├── subagent-delegation/
│   │   ├── subagent-in-process/
│   │   ├── subagent-process/
│   │   ├── subagent-remote/
│   │   ├── subagent-codex-process/
│   │   ├── subagent-claude-process/
│   │   ├── job-runner/
│   │   ├── workflow-engine/
│   │   ├── code-runtime-sandboxed/
│   │   ├── code-runtime-host/
│   │   ├── tool-code-runtime/
│   │   └── command-code-runtime/
│
├── apps/
│   ├── rust-agent-cli/               # Composition CLI，不固定链接所有 provider
│   ├── rust-agent-host-cli/          # build-kind=bin 的内置 Host entry package
│   └── rust-agent-host-wasm/         # build-kind=wasm 的 ABI/glue helper
│
├── .rust-agent/                      # 默认 state root，整体 gitignored
│   ├── compositions/
│   │   └── <composition-hash>/
│   │       ├── Cargo.toml            # 真正决定最终依赖闭包
│   │       ├── Cargo.lock            # 经 compose --lock 生成并纳入 hash
│   │       ├── rust-agent-composition.json
│   │       ├── sources/              # selected path package closure 的只读规范化快照
│   │       └── src/
│   │           ├── lib.rs            # 始终生成 build() composition factory
│   │           ├── main.rs           # build-kind=bin 时生成
│   │           ├── wasm.rs           # build-kind=wasm 时生成
│   │           ├── config.rs
│   │           ├── session_events.rs  # 仅选中 Session plane 时生成 static catalog
│   │           ├── identity.rs       # hash 计算后生成的 COMPOSITION_HASH
│   │           └── composition.rs
│   ├── artifacts/                    # immutable successful build outputs
│   ├── attestations/                 # append-only evidence keyed by output + attestation digest
│   ├── cache/                        # verified registry/git source cache + isolated Cargo home
│   ├── target/                       # Cargo 可写 target dir
│   ├── refs/                         # mutable small composition refs
│   └── staging/                      # same-filesystem atomic publication staging
│
├── build-policies/                   # versioned production build execution policies
│   ├── ci-linux.toml
│   ├── ci-macos.toml                 # backend 通过 Phase 1B 等价门槛后才加入
│   └── ci-windows.toml               # backend 通过 Phase 1B 等价门槛后才加入
│
├── tests/
│   ├── resolver-golden/
│   ├── compile-matrix/
│   ├── dependency-negative/
│   ├── host-integration/             # independent Host Cargo graph + gitignored generated/
│   ├── security/
│   └── integration/
│
└── xtask/                            # 可选；开发期命令辅助
```

### Workspace taxonomy 规则

`crates/components/` 是 rust-agent 仓库内所有可被 Composition Compiler 选择、解析和编译进最终产物的 Component 的唯一 workspace 分类。Integrator 可以在自己的 workspace 中提供带相同 metadata schema 的外部 Component crate；Composition Compiler 从显式传入的 workspace manifest 统一发现它们。
Provider / Consumer / Contributor / Decorator / Factory 不是目录、crate 类型或互斥角色；它们只由 Component 的 `provides`、`requires` 和 `BindingKind` 关系推导。

因此：

```text
crates/components/
  = 所有可组合 Component

Provider / Consumer
  = Capability Graph 上的关系，不是 workspace taxonomy

crates/api/ + crates/composition/
  = 契约、基础接口和 Composition Compiler 基础设施

crates/runtime-adapters/
  = exactly-one generated runtime primitive implementation；不参与 Capability Catalog，
    但进入 composition source/build closure

apps/
  = Composition CLI 与 Host entry/export adapter；后者只进入 Host Boundary Catalog，
    不参与 Capability/Component Catalog
```

`model-deepseek`、`fs-local`、`shell-local`、`driver-tools`、`tool-shell`、`rag`、`mcp-client` 等都属于同一个 `components/` 空间；同一个 Component 可以同时提供某些 Capability 并消费另一些 Capability。

### 粒度规则

`Capability != crate`。一个 API crate 可以定义多个内聚的 Capability，一个 Component 也可以提供多个 Capability。

第一版固定：

```text
one selectable Component = one Cargo package = one component id
```

这是 generated Cargo graph 能够承担删除和审计语义的最小粒度。若两个实现需要独立启停、具有不同 target predicate、security effect、重依赖或版本生命周期，它们必须拆成两个 Component crate。普通非 Component helper crate 可以被多个 Component 复用，但 helper 的 security effects 必须计入所有引入它的 Component，且不得包含某个禁用高风险能力的隐藏实现。

只有以下场景优先拆独立 crate：

- 重依赖：`reqwest`、`redb`、HNSW、OTEL、PDF、SSH 等；
- 平台实现；
- 高风险安全边界；
- 明显影响 binary/WASM size；
- provider 可被独立替换；
- 独立 SemVer/public API 有价值。

轻量 API 可以按领域合并。第一版不应为了“架构纯度”创建数百个微 crate。

### Capability 与 Component metadata 的单一事实源

Capability API crate 在 Cargo package metadata 中声明 Capability 的绑定类型、Rust API 路径和 runtime scope：

```toml
[[package.metadata.rust-agent.capability]]
id = "cap:shell"
api = "rust_agent_process::Shell"
binding-type = "rust_agent_process::ShellBinding"
binding-adapter = "rust_agent_process::ShellCapabilityAdapter"
binding = "singleton"
scope = "agent"
```

`api` 指向 provider 必须实现的 trait 或 generated-only opaque service contract；`binding-type` 是 consumer 的最终静态字段类型。每个 binding-type 必须保留 API-owned assembly builder密封的 provider-owner identity（Component 或 schema-allowlisted generated infrastructure）、build-time provider properties 与 binding-level `SecurityEffects` stamp；业务 consumer 可以读取 effect 集合用于构造 Tool/Command definition 或进一步收紧 authority，但不能修改或伪造 stamp。Capability API crate 同时提供 `binding-adapter`，并满足固定 ABI：

```rust
pub trait CapabilityProviderAdapter<T> {
    type ProviderBinding: Clone;

    fn bind_provider(
        service: Arc<T>,
        provider: &BindingProviderContext,
    ) -> Result<Self::ProviderBinding, BindingBuildError>;
}

pub trait CapabilityBindingAssembler {
    type ProviderBinding: Clone;
    type ConsumerBinding;

    fn assemble(
        plan: ResolvedBindingPlan<Self::ProviderBinding>,
        consumer: &BindingConsumerContext,
    ) -> Result<Self::ConsumerBinding, BindingBuildError>;
}

/// 只能读取 opaque stamp；没有从 fields 构造 stamp 的 API。
#[derive(Clone)]
pub struct BindingStamp { _private: () }

impl BindingStamp {
    pub fn owner(&self) -> &BindingOwnerId;
    pub fn effects(&self) -> &SecurityEffects;
}

/// runtime-api 在成功调用 exact adapter 后创建的唯一 provider witness。
/// 字段私有；没有 public `From<B>`、struct literal 或 Deserialize 路径。
#[derive(Clone)]
pub struct AssembledProviderBinding<B> { /* private binding + assembly receipt */ }

/// consumer 的最终 metadata binding-type 是此 envelope 的 capability-specific
/// alias/facade；业务代码能借用 service 与读取 stamp，但不能自行盖章。
pub struct AssembledConsumerBinding<B> { /* private binding + assembly receipt */ }

impl<B> AssembledProviderBinding<B> {
    pub fn binding(&self) -> &B;
    pub fn binding_stamp(&self) -> &BindingStamp;
}

impl<B> AssembledConsumerBinding<B> {
    pub fn binding(&self) -> &B;
    pub fn binding_stamp(&self) -> &BindingStamp;
}

/// Generator emitted、可公开复制的静态 plan 不是 authority。
pub struct GeneratedBindingAssemblyManifest { /* app + child template plan digests */ }
pub struct GeneratedBindingAssemblyPlan { /* canonical nodes/edges + composition digest */ }
pub struct GeneratedAdapterDispatchTable { /* ordered exact typed adapter shims; private fields */ }
#[derive(Clone, Copy)]
pub struct GeneratedProviderNodeId(/* checked plan index */);
#[derive(Clone, Copy)]
pub struct GeneratedRequirementEdgeId(/* checked plan index */);

/// API-owned scope builder 内的 private authority；没有 public constructor/accessor。
pub struct BindingAssemblyOwner { _private: () }
pub struct AppScopeMarker;
pub struct ScopeAssemblyBuilder<S> { /* private owner + uninitialized scope transaction */ }
pub struct BindingAssembly<S> { /* owned scope transaction + plan cursor/tag */ }

impl GeneratedBindingAssemblyManifest {
    pub fn decode_canonical(bytes: &'static [u8]) -> Result<Self, BindingBuildError>;
}

impl GeneratedBindingAssemblyPlan {
    pub fn decode_canonical(
        bytes: &'static [u8],
        dispatch: GeneratedAdapterDispatchTable,
    ) -> Result<Self, BindingBuildError>;
}

impl GeneratedProviderNodeId {
    pub const fn from_plan_index(index: u32) -> Self;
}

impl GeneratedRequirementEdgeId {
    pub const fn from_plan_index(index: u32) -> Self;
}

/// Public cross-crate issuance creates only a fresh isolated root; caller never chooses its tag.
pub fn begin_composition_assembly(
    runtime_owner: RuntimeOwner,
    composition: CompositionHash,
    manifest: GeneratedBindingAssemblyManifest,
) -> Result<ScopeAssemblyBuilder<AppScopeMarker>, BindingBuildError>;

impl<S> ScopeAssemblyBuilder<S> {
    pub fn begin_binding_assembly(
        self,
        plan: GeneratedBindingAssemblyPlan,
    ) -> Result<BindingAssembly<S>, BindingBuildError>;
}

impl<S> BindingAssembly<S> {
    /// 创建 context、调用 plan 内固定的 exact adapter shim、盖章并 record
    /// 是一次不可拆分操作；caller不能传入 adapter type/function。
    pub fn bind_provider<T, B>(
        &mut self,
        node: GeneratedProviderNodeId,
        service: Arc<T>,
    ) -> Result<AssembledProviderBinding<B>, BindingBuildError>
    where
        T: 'static,
        B: Clone + 'static;

    /// 先核对所有 API-owned provider envelope，再在内部调用 exact assembler；
    /// raw plan、consumer context 与未记录的 consumer value 都不返回给 caller。
    pub fn bind_consumer<P, C>(
        &mut self,
        edge: GeneratedRequirementEdgeId,
        plan: ResolvedBindingPlan<AssembledProviderBinding<P>>,
    ) -> Result<AssembledConsumerBinding<C>, BindingBuildError>
    where
        P: Clone + 'static,
        C: 'static;

    pub fn finish(self) -> Result<ScopeAssemblyBuilder<S>, BindingBuildError>;
}

pub struct ResolvedRequirementIdentity { /* private assembly-issued identity */ }

impl ResolvedRequirementIdentity {
    pub fn field(&self) -> &RustFieldName;
    pub fn capability(&self) -> &CapabilityId;
    pub fn binding(&self) -> &ResolvedBindingIdentity;
}

impl BindingProviderContext {
    pub fn resolved_requirements(&self) -> Arc<[ResolvedRequirementIdentity]>;
    pub fn binding_stamp(&self) -> BindingStamp;
}

impl BindingConsumerContext {
    pub fn binding_stamp(&self) -> BindingStamp;
}
```

以上 assembly 类型、`BindingProviderContext`、`BindingConsumerContext`、`ResolvedRequirementIdentity`、`BindingStamp`、两种 `Assembled*Binding` 与全部 constructor 实现统一归 `rust-agent-runtime-api::binding_assembly`。`ScopeAssemblyBuilder<S>` 是 API-owned opaque builder，`AppScopeBuilder`及 prepared Session/Agent scope builder只是带固定 scope marker的 wrapper/type alias。独立 generated composition用 checked public decoder从 embedded canonical bytes构造 manifest/plan，并通过公开 `begin_composition_assembly`取得一个**新的** App root；该函数一次性消费字段私有、不可 Clone/Serialize的 `RuntimeOwner`，验证 composition与包含 App/child template plan digest的 manifest identity，并用 runtime-api的 process-local non-reusing authority counter签发 fresh tag，caller不能指定、导入或复用 tag，counter exhaustion fail closed。Dispatch table同样通过 runtime-api的 public checked `from_generated_shims` ABI由 generated helper构造；该 ABI接受 typed function items与canonical adapter ABI ids，不要求 friend-crate/private constructor。任意 caller都只能构造待验证的 candidate table，它不是 authority；`decode_canonical`逐 slot核对 embedded plan，generated source/manifest/build attestation再固定 exact shim，`begin_binding_assembly`后 table不可替换。Node/edge id的 public index constructor同样只产生待验证数据；任意 index必须命中 current plan exact cursor。复制或任意构造相同/不同 manifest、plan/table/index最多在取得另一 RuntimeOwner时创建另一个隔离 root，或得到 validation error，不能构造当前 root的 context/stamp。Session/Agent builder只能由现有 root的 `begin_child_scope`按 manifest中已承诺的 template/projection派生，三类 builder都没有 struct literal、owner extractor、Deserialize或“按 bytes/tag恢复 authority”的 API。`begin_binding_assembly`消费 scope builder并要求 plan命中该 scope已承诺 digest；`finish`在验证完成后才把它返还用于 install/initialize，避免 generated crate同时绕过 assembly transaction直接写 scope。Generated crate可以在返回值上调用 public builder methods；Component、Host和 adapter从不收到 active builder/owner。Generated manifest/plan/table/node/edge id只是可验证数据，不是 authority。

`begin_binding_assembly` 核对 composition/plan digest、scope variant与 parent lineage，随后把不可 Clone/Serialize/Debug 的 scope owner以及 validated dispatch table移入 transaction并为本次 scope生成 authority tag。Dispatch table由 generator按 normalized metadata发射，逐 node/edge固定 exact adapter/assembler shim、input/output Rust `TypeId`与ABI identity；canonical Rust type path/ABI identity进入source/plan digest，process-local `TypeId`只用于调用时的类型安全比较而不进入deterministic identity。Table与 generated source、Cargo types、canonical plan顺序一起通过 freshness/compile gate，且一旦进入 active transaction不能替换。Builder按 plan拓扑游标从已返回的 API-owned `Assembled*Binding` receipt自动产生实际 requirement identities。`bind_provider`/`bind_consumer`不接受 adapter generic/type/function参数，只根据 node/edge核对固定 shim、请求的 input/output `TypeId`与 expected pending slot，随后在方法内部创建不可 Clone/Serialize的 context、立即调用该 shim，并在返回 caller前直接用该 context的 assembly-owned stamp/slot产生字段私有的 envelope/receipt并完成 record；它从不要求或信任 raw adapter value实现 witness。Context、raw unrecorded result和 receipt永不单独返回。Adapter error、panic unwind、丢弃或 type/plan不匹配都会使该 transaction失败，不能把 raw value拿到另一次调用补记。Context与 envelope内的最终 `BindingStamp`携带同一 scope tag、plan digest和 node/edge identity；跨 scope/builder、错 adapter/type/edge、重复/跳序、缺失/额外 dependency或替换 plan均在方法返回前拒绝。`finish`消费 transaction并要求每个 expected node/edge恰好组装一次，只有成功才返还 scope builder；未完成或 drop时 transaction回滚且 scope不能 install/initialize/publish。公开 API 不再提供可由外部实现的 `BindingWitness`，也不提供 raw `record_provider`/`record_consumer`；因此持有 active assembly的 generated caller既不能选择另一个 adapter，也不能把 clone出的 stamp包进自定义类型后记账。即使普通 crate自建另一份静态 plan/table或直接调用公开 adapter，也不能替换 active transaction中的 dispatch、取得当前 context/owner、产生当前 receipt或提交结果。这一验证关系才是不可伪造边界，绝不依赖 crate 名、生成源码路径或 `#[doc(hidden)]`。

Adapter 对每个合法 concrete provider 实现 `CapabilityProviderAdapter<T>`，或由 API crate 对公开的 contribution trait 提供受约束 blanket impl，并实现一次 `CapabilityBindingAssembler`；两者的 raw `ProviderBinding` 必须相同。Metadata 的最终 `binding-type`规范展开后必须是 `AssembledConsumerBinding<A::ConsumerBinding>`，而不能是 raw `ConsumerBinding`；示例中的 `rust_agent_process::ShellBinding`只能是该 exact envelope的public type alias（业务方法用local extension trait提供），不能是另一个可从raw value构造的独立 newtype。“Facade”只允许隐藏泛型名称，不能增加第二条 constructor/receipt路径。该 envelope的 private constructor是唯一 assembly witness。它的 `clone`（若 capability允许）只克隆 opaque service handle、properties和 API-owned receipt/stamp，不复制 concrete service或 structural ownership，使 App provider plan可为每个短 scope重新组装 consumer binding。业务 API只能从 envelope借用 service并读取 owner/effects，所有 authority/effect判断使用 envelope stamp，不能信任 raw adapter value自报的 witness。两种 adapter函数都必须同步、确定、无 I/O、无外部 side effect。`ResolvedBindingPlan` 是 runtime-api 的封闭 enum，只能表达 resolver 已确定的 Singleton、带 key Registry、有序 Multi 或最终 decorator output，不执行候选选择；generated caller传入的是 API-owned provider envelope，`bind_consumer`在内部验证后才向 exact assembler暴露只含 raw provider values的临时 plan。

`BindingProviderContext` 只含 assembly-issued `BindingProviderOwnerId`、provide entry、scope variant、provider properties、owner own runtime ceiling、该 provide 的 resolved binding effects，以及按 `requires[].field` 排序的只读 `Arc<[ResolvedRequirementIdentity]>`。每个 requirement identity由 `BindingAssembly`从本次已返回且已记录的 dependency envelope stamp产生：Singleton/DecoratorChain密封最终 chain identity，Registry密封所选 key/provider identity集，OrderedMulti密封规范顺序的 contributor identity，未绑定的 `UsesIfPresent`密封 `Absent`；它不含 raw service、没有 public constructor，也不能由 generated crate、Component metadata或 `ToolRegistration::new` / `CommandRegistration::new`逐字段提供。Generated scope builder必须先取得 plan要求的 dependency envelope，再调用 `bind_provider`；该方法在内部创建 context并调用固定 adapter。缺失、额外、重复、field/capability/provider与 resolution plan不一致时在 adapter前失败。这样 Tool/Command adapter密封的是实际 dependency route，而不是 Component自报或仅由 capability名推测的 identity。

`BindingConsumerContext` 只含 assembly-issued consumer owner identity、requirement field、scope variant、consumer effective ceiling、可选 static session-event declaration reference、可选 private `CommittedEventPublisher`，以及 schema-allowlisted `GeneratedScopeCallAuthority`。Schema v1只允许 assembly builder根据 validated plan edge和 current scope owner自动安装以下精确 wiring：每个 Session-scope `cap:session-log` consumer取得同一 Session/Agent publication lineage的 publisher，其余 capability必须没有 publisher；`cap:model` consumer取得当前 model-caller scope的 `ModelRequestJournalVerifier`；selected `cap:agent-driver` provider对 `cap:tool-executor` 的 exact Agent-template requirement edge取得当前 Agent的 `ToolCallJournalVerifier`；每条合法Agent-scope `cap:user-interaction` requirement edge取得当前Agent的`UserInteractionJournalFacade`，App/Session-scope consumer在schema v1不合法；其余 consumer的 call authority必须为 `None`。这里的 “model-origin” 不是 metadata可填写的 flag，而是 resolver从唯一 selected AgentDriver provider edge推导并写入 resolution/manifest的 sealed fact；command/tool/其它 Component即使也 require `cap:tool-executor`仍只能得到 `None`，不能请求升级。缺少 required publisher/verifier/facade、variant/consumer/edge/scope不匹配，或 metadata/generated call试图手工传入这些 handle，均在 context生成前失败。Publisher、verifier与journal facade都是typed direct handle，不是service locator；composition hash/manifest只记录authority/publisher/facade kind与wiring，per-scope ephemeral identity不进入deterministic identity。

Generated code把 generator-emitted exact dispatch table与canonical bytes一起交给 `GeneratedBindingAssemblyPlan::decode_canonical`，随后只按 node/edge调用 current `BindingAssembly::bind_provider`/`bind_consumer`并取得已记录 envelope；adapter/assembler shim已固定在 active plan中，不能由调用点选择。Exact type path与ABI由 normalized metadata写入 generated source/table/plan digest，并由 source/Cargo/manifest freshness gate共同核对；调用方没有 context、receipt或手工 record seam可缓存、替换或跨 scope重用。`cap:session-log` assembler用 private publisher包装 raw consumer value，外层 assembly envelope继续保存权威 stamp；每个首次 confirmed committed 的 EventBatchId/range在 append返回前同步更新同一 event publisher，same-id resolution只去重而不重复发布。Registry保留每个 key各自的 effects，OrderedMulti保留每个 contributor的 effects，Singleton/DecoratorChain暴露最终 binding effects；另算全部 selected Component runtime ceiling 的并集作为 `component_runtime_effects`，供 App root authority与 Component graph审计使用。Host entry/export不产生 capability binding，其独立 runtime ceiling只进入最终 artifact security accounting，不得混进 AgentAuthority。DecoratorChain先组装 base consumer binding，按解析顺序把它注入下一个 decorator factory，最后只把 outermost provider组装成公开 binding；完整 base/decorator ownership仍留在 scope。Generated source不使用 `Any`、字符串 service locator或运行时类型注册表。

Capability-specific build-time provider property 由同一条 capability metadata 声明；例如 `cap:session-persistence` 同时声明 durability 与是否具有可选择的 NewEphemeral creation protocol：

```toml
provider-properties = [
  { name = "durability", kind = "enum", values = ["ephemeral", "durable"], required = true },
  { name = "ephemeral-creation", kind = "enum", values = ["unsupported", "staged-known-outcome"], required = true },
]
```

`cap:user-interaction` 同样声明 required provider property `answer-recovery = "unsupported" | "stable-until-commit-ack"`；该值进入 binding stamp、resolution manifest与composition identity，RuntimeConfig不能升级它。

Component crate 使用 `Cargo.toml` 的 package metadata 声明 rust-agent 组件语义。Provider / Consumer 不写入 `role` 字段，而由 `provides` / `requires` 自动推导：

```toml
[package.metadata.rust-agent]
schema = 1
id = "shell-local"
scope = "agent"
factory = "shell_local::build"
dependencies-type = "shell_local::Dependencies"
config-type = "shell_local::Config"
config-key = "shell-local"
config-source = "file"
targets = ['cfg(target_os = "linux")']
support = "production"
lifecycle-effects = []
provides = [
  { capability = "cap:shell", priority = 100, effects = ["process-exec", "read-local", "write-local"] },
]
requires = [
  { capability = "cap:subprocess", mode = "required", field = "subprocess" },
  { capability = "cap:sandbox", mode = "required", field = "sandbox" },
]
security = ["process-exec", "read-local", "write-local"]
runtime-primitives = []
build-requirements = { executables = [], read-inputs = [], environment = [] }
```

`security` 只声明最终 target artifact 中可达代码的完整 **runtime effect ceiling**，覆盖 Component 自身、链接进产物的 native code 以及 transitive non-Component runtime helper；它明确不包含 build.rs、proc-macro、compiler/code generator 或其它只在构建 Host 执行的行为。`runtime-primitives` 必须显式存在，使用第 31 节的封闭 id 集合，只声明该 Component 实际需要的 executor primitive；它既不是 Capability 选择，也不授予 runtime security effect。`build-requirements` 是与 runtime authority 完全分离的构建期需求，三个字段都必须显式存在并使用规范化 logical id：`executables` 指向 linker/C/C++ compiler/assembler/`pkg-config`/code generator 等预置 executable role，`read-inputs` 指向 SDK/header/schema 等只读 input role，`environment` 指向允许读取的额外非 secret build variable。普通 Cargo/rustc、verified source/toolchain/sysroot、target/temp 写入、受 sandbox 继承约束的 derived build-script executable，以及 schema 固定的 deterministic `PATH/LANG/LC_ALL/SOURCE_DATE_EPOCH` runner environment 属于构建基线，不在每个 Component 重复声明；build phase 永不允许 Component 申请 network、Host socket、credential 或任意 secret。

每个进入 generated root direct closure 的 first-party package——Component、mandatory API/infrastructure、selected runtime adapter、Host entry/export helper——都必须对它拥有的 build.rs/proc-macro/native build 和无法单独声明 rust-agent metadata 的 transitive third-party build helper 聚合 `build-requirements`。Component/runtime adapter/Host entry/Host export 使用各自 enclosing metadata 的内联字段；其它非 Component first-party package 使用 `[package.metadata.rust-agent.build-requirements]` 的同一封闭 schema。共享 helper 可以被多个 root 重复归因，normalization 按 kind/id 去重并拒绝同 id 异义；不得因为 helper 由 mandatory API 引入就跳过声明。Composition manifest 记录逐 root-package 需求与 union；`rust-agent build`/`build-host` 在启动 Cargo 前要求该 union 被 normalized `BuildExecutionPolicy` 的 logical ids 完整满足，未知、缺失、重复或无法映射的 requirement fail closed。Requirement 描述“需要哪类受控资源”，BuildExecutionPolicy 才把 logical id 映射到本次 Host 的 canonical path/digest；两者都不进入 AgentAuthority，也不转译成 `SecurityEffects`。Development runner 可以为缺失映射报错或使用明确记录的 development-only mapping，但 artifact 固定 `deployable=false`。

任何进入 generated runtime artifact closure、但不属于 Component 或 Host boundary 的 mandatory API/generated infrastructure package 必须具有空的 own runtime-effect surface：不得直接打开文件/socket/process/credential/persistent store 或调用 Host callback，只能进行纯计算、ownership/lifecycle 调度，或通过带不可伪造 effect stamp 的 selected capability binding 发起操作；binding closure 由实际 Component 负责记账。Composition compiler、build executor 与 CLI 是独立 control-plane executable，不进入该 runtime closure，按第 33/34 节的 build-tool trust/attestation 审计，不能与这里的 effect-free runtime infrastructure 混称。若 runtime-closure package 新增任何直接 runtime effect，必须把 effectful implementation 拆成 Component/Host boundary 并进入相应 ceiling，不能给普通 API/infrastructure 增加第三种未计入 `component_runtime_effects` 的隐式 security 字段。Architecture lint 结合 source/dependency allowlist 与 effectful fixture 验证这一规则；`unsafe`/FFI/runtime transport dependency 出现在普通 runtime API/infrastructure 时 fail closed。

非 Component first-party root package 使用独立版本字段：

```toml
[package.metadata.rust-agent.build-requirements]
schema = 1
executables = []
read-inputs = []
environment = []
```

Component/Host entry/Host export 的内联 `build-requirements` 继承各自 enclosing metadata 的 `schema = 1`，不得再声明第二个冲突版本。

每个 Component crate 必须导出 metadata 指定的工厂和依赖结构。同步工厂固定签名：

```rust
pub fn build(
    config: &Config,
    deps: Dependencies,
    runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<ConcreteComponent>, rust_agent_runtime_api::ComponentBuildError>;
```

Factory 固定为同步、无 I/O 的 construction step；异步资源打开、外部连接和后台任务准备必须放在 `Initializable` hook。Pre-identity resource-namespace preparation 也不是 infrastructure/factory I/O 例外：它只能在 authority projection 后经下述 stamped bootstrap binding 调用一个普通、已计入 effects 的 Component。`ComponentOutput` 包含 `Arc<ConcreteComponent>` service、可选 typed lifecycle hooks 与 scope ownership metadata；stateless Component 使用 `ComponentOutput::stateless`。`Dependencies` 的字段必须与 `requires[].field` 和 `decorates[].field` 一一对应，字段类型必须是 Capability API 定义的 `binding-type`；`UsesIfPresent` 字段使用 `Option<BindingType>`，decorator field 接收已经构造的 inner binding。`RuntimePrimitiveBindings` 与 Capability dependencies 分离，只包含 metadata 显式声明且由 build caller 注入的 primitive；未声明字段不可取得。Generated scope builder 安装 output、登记 hooks、保留 concrete owner，并通过每个 `provides` 对应的 `binding-adapter` 转换、组装 typed binding。Rust 编译器是 factory、adapter、trait implementation 与 wiring 类型一致性的最终门禁。

任一 `provides` 条目声明 `resource-namespace = { mode = "required", bootstrap = "<provider-key>" }` 时，Component metadata 还必须声明 `resource-namespace-preparer` 和 `prepared-config-type`。该 marker 显式派生一条从 exact Component/provide identity 到 App-scoped Registry `cap:resource-namespace-bootstrap` 对应 key 的 bootstrap requirement；它进入 resolver graph、effect closure、manifest/hash，不能由 generator 暗中打开资源。Bootstrap provider 是普通 App-scoped Component：例如 `resource-namespace-bootstrap-local` 的 provide effects/security 至少包含 `read-local`，但其 lifecycle-effects 必须为空，factory 只返回 stateless output，且不得声明普通 requires/decorates、initialize/activate hook或 required resource namespace；实际 canonicalize/open 只发生在 root/exact-scope projection 授权后的 stamped method call。这组封闭约束使 binding 能在其它 Component/final authority 之前纯构造，同时防止 pre-identity dependency cycle。Generator 在普通 factory 之前验证以下额外 ABI；该 Component 的 factory 第一个参数相应改为 `&PreparedConfig`，不能再接收未准备的 raw `Config`：

```rust
pub async fn prepare_resource_namespaces(
    config: &Config,
    context: ResourceNamespacePreparationContext<'_>,
) -> Result<PreparedComponentConfig<PreparedConfig>, ResourceNamespacePrepareError>;

pub fn build(
    config: &PreparedConfig,
    deps: Dependencies,
    runtime: RuntimePrimitiveBindings,
) -> Result<ComponentOutput<ConcreteComponent>, ComponentBuildError>;
```

`ResourceNamespacePreparationContext` 的 constructor 私有，只携带 deadline/cancellation、exact Component/provide/bootstrap binding identity、已经完成的 bootstrap authority projection 与字段私有的 `ResourceNamespaceBootstrapBinding`。Mandatory infrastructure 不实现 filesystem/network/Host locator operation；context 的 typed prepare 方法只把规范化 locator 转交该 stamped selected binding，并在返回后以纯计算校验 identity、构造 descriptor commitment。Preparer 禁止直接调用 OS/Host locator API、调用普通尚未构造的 dependency、创建/修改 namespace、启动 task 或接受业务请求。Local bootstrap Component 必须解析相对 root、逐段拒绝 symlink escape并打开 owner-scoped descriptor-relative root anchor；返回的 `PreparedConfig` 保存该不可伪造 anchor，后续 `initialize` 不得按原始字符串路径重新打开 root。Schema-owned context 根据 normalized locator、Host-stable namespace id 与 exact binding/provider identity 计算 descriptor commitment；bootstrap/provider 不能传入自报 digest。`PreparedComponentConfig` 必须为每个 required provide 恰好返回一个 descriptor 和配对 prepared value，缺失、重复、额外 identity 或 kind mismatch 均失败。

执行顺序按 scope 固定。App build 在任何 namespace I/O 前，先从 compiled App plan 与 RuntimeConfig root attenuation 计算 effect/binding/key 都只能收窄的 `BootstrapAuthorityProjection`，构造无 lifecycle effect 的 selected bootstrap provider binding，然后只为 projection 后仍保留的 App-scoped provide 调用 preparer，最后用结果完成 App root authority。Session/Agent-scoped namespace 不在 App build 预先打开；每次 create/resume 必须先对 exact deferred template 应用 parent/request/stored authority projection，删除的 binding 不调用 bootstrap，保留的 binding才以该 child projection 派生一次性 stamped bootstrap call，完成 descriptor后才可分配新 identity、prepare backend 或调用 scoped factory/initialize。Effect 被 deny、binding/key 被删除或 bootstrap route 缺失时，受影响 route 必须在任何 locator I/O 前 fail closed且 mock调用数为零；已授权 route 的 preparation失败则必须在后续 identity/admission前失败，并 drop全部已准备 sibling anchor。没有 required namespace 的 Component 不得声明这两个字段并继续使用普通 `Config` factory ABI。

`config-source` 只允许 `none | file | host`：

- `none` 必须配合 `config-type = "()"`，不生成配置字段；
- `file` 进入 generated `RuntimeConfig`，所有 file 配置统一位于 `[component.<component-id>]`；
- `host` 进入 generated `HostBindings`；library 由 Rust Host 以强类型值注入，wasm 由 generated JS conversion glue 构造，不记录 callback/value 到日志或 build manifest。

`config-source = "host"` 还必须声明 `host-api = "crate_path::host_api"`，指向只包含该 Component 的 public `Config`、callback trait 和 wire-neutral DTO 的模块；`none/file` 禁止声明。`config-type` 必须等于该模块内公开的 `Config` 类型。Generator 以规范化 component id 建立 `generated_crate::host_api::<component_module>`，整体 re-export metadata 指定模块；Host 只从该 namespace 实现 callback trait 并构造 Config，不直接依赖 snapshot package。Callback 签名、Config 字段和 DTO public API 引用的每个非 `std` 类型，以及实现 callback 所需的 attribute macro，都必须在同一 host-api module 以稳定名称 `pub use`，使 Host 不需要在 extern prelude 中直接命名 transitive snapshot crate。Host API 模块的公开 type closure 必须满足下述跨 workspace 边界规则，不能通过私有 generic/associated type 再泄漏 Integrator-local 或 provider concrete type。

file 配置示例：

```toml
[component.example-component]
```

生成的 `RuntimeConfig` 和 `HostBindings` 对每个 selected Component 使用其 `config-type`，并以 `config-key` 作为字段映射。`model-host`、`embedding-host`、`credentials-host`、`network-policy-host`、`approval-host`、`web-fetch-host`、`web-search-host`、`mcp-transport-host`、`user-interaction-host`、`attachment-host`、`spill-host`、`code-runtime-host` 等 Host callback Component 必须使用 `config-source = "host"`。Component 不得从全局字符串 map 或全局单例查找依赖/配置；只有用途明确且声明相应 security effect 的 provider（例如 `credentials-env`）可以把读取进程环境作为自身实现行为。

Library composition 的 host-source `Config` 是跨 generated snapshot 与活动 Host workspace 的 Rust 类型边界。它只能由 `std`、同一 locked source identity 的 rust-agent API 类型、`Arc<dyn HostCallback>`、owned byte/string DTO 和版本化 wire-neutral DTO 组成；禁止暴露 Integrator workspace-local concrete type、其泛型实例、对活动 workspace 对象的引用或只能由另一份 path-package 实例构造的类型。Host callback 可以闭包捕获 AINS `ClientApi` 等活动 Host 对象，但公开 Config 只保存 adapter crate 定义的 callback trait object。Generated compile fixture 同时构建 emitted composition 与一个独立 Host consumer，验证 HostBindings 可从 Host 依赖图构造且不存在 path snapshot 类型身份泄漏。

Host entry package 使用独立 metadata，不伪装成 Capability provider：

```toml
[package.metadata.rust-agent.host-entry]
schema = 1
id = "host-cli"
entry = "rust_agent_host_cli::run"
targets = ['cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))']
target-support = [
  { predicate = 'cfg(target_os = "linux")', tier = "production" },
  { predicate = 'cfg(any(target_os = "macos", target_os = "windows"))', tier = "experimental" },
]
security = ["read-local"]
runtime-adapters = ["runtime-tokio"]
build-requirements = { executables = [], read-inputs = [], environment = [] }
```

第一版 `host-cli` 只属于 desktop CLI topology：Linux 有 checked-in production Host-entry fixture；macOS/Windows 在各自真实 target fixture 与 production backend/attestation完成前保持 `Experimental`，只能进入显式 development composition。iOS、Android以及其它非上述 desktop OS不在 `targets` 中，即使同为 non-WASM也必须在 Host Boundary normalization阶段返回 `UnsupportedTarget`，不能进入 snapshot/Cargo。Mobile Rust Host 使用 `build-kind=library` 加产品 entry/integration attestation，不复用 `host-cli`。

WASM export helper 使用平行但不混用的 metadata；第一版内置 helper 为 `host-wasm`：

```toml
[package.metadata.rust-agent.host-export]
schema = 1
id = "host-wasm"
export-module = "rust_agent_host_wasm::export"
targets = ["cfg(target_arch = \"wasm32\")"]
support = "production"
security = ["host-bridge"]
runtime-adapters = ["runtime-wasm"]
build-requirements = { executables = ["wasm-bindgen-cli"], read-inputs = [], environment = [] }
```

`export-module` 指向版本化 helper module。Schema 1 固定要求该 module 导出以下 surface；类型字段保持私有，compile fixture 验证 path、签名与 target：

```rust
pub const ABI_VERSION: u32 = 1;

pub use rust_agent_runtime_api::WasmHostBindingError;

pub struct ValidatedHostBindings { /* private exact-key object */ }
pub struct WasmCancellation { /* private AbortSignal listener + token */ }

pub fn validate_host_bindings(
    value: wasm_bindgen::JsValue,
    exact_keys: &'static [&'static str],
) -> Result<ValidatedHostBindings, WasmHostBindingError>;

impl ValidatedHostBindings {
    pub fn take_required(
        &mut self,
        key: &'static str,
    ) -> Result<wasm_bindgen::JsValue, WasmHostBindingError>;
    pub fn finish(self) -> Result<(), WasmHostBindingError>;
}

pub fn bind_abort_signal(
    signal: Option<web_sys::AbortSignal>,
) -> Result<WasmCancellation, WasmHostBindingError>;

pub fn runtime_primitives(
    create: fn() -> Result<
        rust_agent_runtime_api::RuntimePrimitives,
        rust_agent_runtime_api::RuntimePrimitiveError,
    >,
) -> Result<rust_agent_runtime_api::RuntimePrimitives, WasmHostBindingError>;

impl WasmCancellation {
    pub fn token(&self) -> rust_agent_runtime_api::CancellationToken;
}

pub fn future_to_promise<F>(future: F) -> js_sys::Promise
where
    F: Future<Output = Result<wasm_bindgen::JsValue, WasmHostBindingError>> + 'static;
```

`validate_host_bindings` 只接受 plain object 和规范化 exact key set，拒绝缺失、未知、alias collision 与 prototype/accessor input；`take_required` 每个 key 只能消费一次，`finish` 要求全部字段恰好消费。`runtime_primitives` 只能调用 generated root 传入的 selected adapter constructor，把 adapter error 映射为 `WasmHostBindingError` 并返回原 bundle；Host export package 不直接依赖 concrete adapter，也不能用零参数 helper、ambient JavaScript promise state或 runtime service locator 自行选择 runtime。Generated `start` 从同一 snapshot direct dependency 取得 constructor，传给 helper，再把返回 bundle 显式传给 composition build。`WasmCancellation` 的 drop 必须移除 listener，AbortSignal 只收紧本次 exported operation 的 cancellation lineage。Generator 仍拥有最终 `#[wasm_bindgen]` export 名称、DTO conversion 和强类型 composition 调用，不允许 helper 用运行时 service locator 选择 Component。Host entry 与 Host export id 在同一 Host boundary namespace 唯一，二者都不是 Component id。

Host entry 的固定 ABI 由 compile fixture 验证：

```rust
pub fn run<C, H, R, F, Fut>(create_runtime: R, build: F) -> Result<(), HostEntryError>
where
    C: serde::de::DeserializeOwned + Send + 'static,
    H: Default + Send + 'static,
    R: FnOnce() -> Result<RuntimePrimitives, RuntimePrimitiveError> + Send + 'static,
    F: FnOnce(C, H, RuntimePrimitives) -> Fut + Send + 'static,
    Fut: Future<Output = Result<AppHandle, BuildError>> + Send + 'static;
```

bin composition 的 generated `HostBindings` 因不含 host-source 字段而实现 `Default`。`main.rs` 固定展开为 `fn main() -> Result<(), HostEntryError> { host_entry::run(create_runtime_primitives, composition::build) }`；`create_runtime_primitives` 来自 generated root 对 selected adapter snapshot 的直接依赖，而不是 Host entry package 的 dependency。Entry package 拥有用于 poll Host event loop 的具体 async executor，在其中调用传入 constructor、把 `RuntimePrimitiveError` 映射为 `HostEntryError`，再把经过校验的 `RuntimePrimitives` 传给 build；它负责读取 runtime config、执行 async build、监听 shutdown signal，并最终等待 `AppHandle::shutdown()` 完成。Host event-loop executor 与 injected Component runtime 可以共享底层实现，但不能靠 ambient current-executor 猜测绑定。`AppHandle` 由 `rust-agent-agent` 定义，`BuildError`、`RuntimePrimitiveError` 与 `RuntimePrimitives` 由 `rust-agent-runtime-api` 定义，`HostEntryError` 由 Host entry package 定义；generator 不临时定义同名类型。

`build-kind=bin` 必须显式选择一个 target-compatible Host entry package、拒绝 Host export，且只允许 `none/file` config source。`build-kind=library` 拒绝 Host entry/export，生成物必须作为 source dependency 进入最终 Rust Host Cargo graph，适用于 Native、Mobile、Server、同一 WASM module 内的 Rust Host 与其它 Rust Integrator；单独生成的 `.rlib` 不是 Host 集成接口。`build-kind=wasm` 只允许 `wasm32-unknown-unknown`，必须显式选择一个 target-compatible Host export package 并拒绝 Host entry，用于 JavaScript Host，由 generator 产生 `wasm-bindgen` export；每个 selected host-source Component 必须在 metadata 声明 `wasm-host-constructor`，把对应 JS object 转成其强类型 Config。CLI profile 选择 `host-cli`，web-wasm profile 选择 `host-wasm`。第一版不直接生成 native C `cdylib/staticlib` ABI；需要非 Rust native FFI 的产品在独立、版本化 adapter 中封装 library API。

### Framework-neutral Host integration topology

rust-agent 只按进程、模块、语言 ABI 与 target 事实选择 Host contract，不按 UI/application framework 品牌选择。第一版固定以下 integration topology：

| Host topology | composition/build contract | Host 侧边界 |
|---|---|---|
| 同进程 Native Rust Host | `build-kind=library` + native target | Host 以显式 `RuntimePrimitives` 调用 typed `build`/`AppHandle` |
| 同一 Rust WASM module 内的 Host | `build-kind=library --target wasm32-unknown-unknown` | Rust Host 注入 browser-local primitives并直接调用 typed handle；不经过 JS export |
| JavaScript Host | `build-kind=wasm --target wasm32-unknown-unknown` | 只经过版本化 `wasm-bindgen` DTO/export 与 `WasmAppHandle` |
| Native backend + WebView/frontend IPC | backend 使用 `build-kind=library` + native target | 产品 adapter 把 typed handle 映射为 command/channel/IPC；frontend 不直接取得 runtime internal type |

Dioxus Web、Dioxus Desktop/Mobile、Tauri 或其它框架只能作为上述 topology 的非规范示例；真正决定 contract 的是 runtime 与 Host 是否同进程、是否同一 WASM module、以及跨越 Rust/JS/IPC 的哪一条 ABI boundary。Framework identity 本身不是 resolver input、target fact、Capability、Component、security effect、composition identity 或 generated rust-agent Cargo feature；禁止引入 framework-branded Capability、rust-agent core 的 framework dependency，或用 framework-named feature 改写同一 composition。UI framework crate/feature 只存在于最终 Host/product adapter graph；与 emitted composition 共享 package 时仍按 `HostFeatureUnionPolicy` 审计真实 feature delta。`rust-agent-host-wasm` 只是通用 JS/WASM Host boundary helper，不是任何 UI framework adapter。

Framework adapter 属于 Integrator/product：它可以依赖 generated composition alias 和所选 framework，但只能做 lifecycle/DTO/IPC/view-model 映射，并必须保留 exact `AgentRequestId`、targeted cancellation、cursor/high-water、`Lagged`/`Closed`、bounded backpressure 和 shutdown 语义。纯映射 adapter 不是 Component；若它还提供需要独立选择和审计的真实外部能力，则以功能命名的普通 host-source Component 声明其 Capability、effects 与 build requirements，framework 只作为产品实现细节且不获得例外。仅有使用示例不得宣称 framework 正式受支持；任何具体 framework/version 的正式支持声明都必须绑定 Integrator/product 仓库中 checked-in 的 adapter/fixture、真实 target CI、版本范围和 product integration attestation，未满足时只标记为示例或 Development。

Library Host 集成固定使用 emitted composition source：

```text
content-addressed composition
  → rust-agent emit-integration --composition <hash> --output <integrator-owned-dir>
  → Host Cargo.toml exact path dependency
  → rust-agent verify-integration --host-manifest <Host Cargo.toml> \
      --dependency <alias> --composition <hash> --phase pre --write-receipt <receipt> \
      --execution-policy <policy.toml>
  → rust-agent build-host or a schema-compatible product executor builds final Host
  → rust-agent verify-integration --host-manifest <Host Cargo.toml> \
      --dependency <alias> --composition <hash> --phase post \
      --pre-receipt <receipt> --executor-attestation <executor-attestation> \
      --execution-policy <policy.toml> --write-attestation <product-attestation>
```

`emit-integration` 把已经发布且 digest 验证通过的 composition 复制到 Integrator 明确拥有的固定目录；输出必须包含完整 sources、Cargo.lock、composition manifest 和 derived identity，生成文件内不引用 state root。工具始终先在同文件系统 sibling staging 中生成并验证完整 tree，绝不向最终目录逐文件覆盖。目标不存在时以一次 rename 发布；目标已存在且内容相同则复用。目标是内容不同的现有目录时不存在跨支持平台的原子 directory replacement：`--replace` 因而是 **offline maintenance** 操作，传入它即声明 Integrator 已停止并排空所有可能读取该 path 的 Cargo build/metadata、IDE watcher 与其它进程，并独占该输出目录；工具随后才允许移走旧 tree、rename 已验证 staging。该替换不承诺在线 reader 的连续可见性或原子切换，进程中断也可能使最终 path 暂时缺失，此时 `verify-integration`/Host build 必须 fail closed，重新执行 `emit-integration --replace` 恢复。不能满足 offline 前置条件时，必须输出到新的 versioned directory，并由 Integrator 自己的协调发布协议切换 Host path/ref，不能对 live 固定目录使用 `--replace`。该目录可以提交到产品仓库，Host manifest 使用稳定 path dependency 和唯一 dependency alias。

Path dependency 内部的 Cargo.lock 不控制最终 Host resolution。Production `verify-integration --phase pre` 必须使用 BuildExecutionPolicy 的 fetch runner 按 Host Cargo.lock 物化并验证独立 cache；`cargo metadata` 只用于核对 locked package/source/file identity，不能作为实际编译图或 feature set 的证明。随后 runner 在无凭据、无网络环境中，用 policy 固定的 exact Cargo/rustc、Host build triple/facts、composition target/custom spec、profile、artifact selector 与 feature flags分别规划 verified emitted root 和最终 Host root，产生规范化 `HostCargoUnitGraph`。Reference runner 使用该 pinned Cargo 版本的 unit-graph planning interface，且 planning 不执行 build script/proc macro；该 Cargo 不支持受信 unit graph、输出 schema未知或无法规范化时，production integration verification 固定为 unsupported，不能退回 `--filter-platform <composition-target>` 猜测。

`HostCargoUnitGraph` schema 2 的 node identity 至少固定 package source/version/checksum/git precise revision、Cargo target name/kind、compile mode/profile、`CompilationKind::Host { build_triple } | Target { composition_target }`、必填的 `cargo-target-context = build-host | composition-target`、该 unit 的 exact sorted feature set 与 build-script/proc-macro标志；edge 固定 dependency kind、target predicate evaluation domain 与完整 dependent/dependency unit identity。`compilation-kind`表示该 unit 在哪里编译，`cargo-target-context`表示 Cargo 为哪个 target context实例化它：Target unit只能是`composition-target`；Host library/proc-macro/custom-build compile unit只能是`build-host`；`run-custom-build`虽在Host执行但可分别属于Host或composition target context，两者不得折叠。Raw platform缺失映射为`build-host`，只允许与 exact composition target相同的平台映射为`composition-target`，其它值fail closed；schema 1不得通过默认值迁移。Build dependency、build script与 proc macro及其 transitive依赖在 Host compilation domain求值，普通 target dependency在 Target domain求值；带`links`的普通依赖由Cargo注入指向其build-script output的边仍保留metadata的normal dependency kind，但dependency unit保持Host compilation domain。同一 package/source可以同时出现多个 feature或target-context不同的host/target unit，禁止把它们压回一个 package-global feature set。Pre 以同一 planner/build-host/target/profile从 verified emitted snapshot重算 standalone baseline unit graph，再从 final graph 中解析由 exact emitted alias可达的 unit projection。比较先要求每个 baseline first-party unit/edge/source identity及其 feature set原样存在，再逐 `(package identity, Cargo target, compilation kind, cargo target context, compile mode, profile)` 计算 external shared-unit feature/edge delta。全图所有 Host/Target unit都进入 input closure、SBOM与 build-requirement审计。Host unit自身执行时的filesystem/network/executable effect由BuildExecutionPolicy/build requirements记账；但它通过`cargo:rustc-cfg`、link directives、generated files、native artifacts或proc-macro token expansion注入最终Target artifact的行为属于**下游runtime contribution**，必须归入相应Target owner/product root的runtime ceiling与最终`compiled_runtime_effects`，不能因生产者是Host unit而消失。

Host feature unification 只按以下两类处理：

1. emitted snapshot 内的 generated root、rust-agent API、Component、Host boundary 与 first-party helper 的每个 Host/Target unit都必须保持 standalone baseline exact feature set。Host 不得为这些 unit 增加 feature；确需不同 first-party feature时必须重新 compose，或以不同 package version/source identity、独立进程/服务隔离，不能借 Host union改写已审计 Component行为。
2. 外部共享 dependency（例如 `tokio`、`reqwest`、`web-sys`）只允许对`CompilationKind::Target` library unit在同一个 Cargo feature-unification unit domain内把 actual feature set扩为 baseline严格超集，非空 delta必须由显式、规范化的 `HostFeatureUnionPolicy` 按 unit selector审批。Policy entry固定 package identity、Cargo target/compilation kind/compile mode/profile、允许新增的 feature、由这些 feature新增的 unit/edge closure、feature semantics attribution、composition-path effect delta、product-Host effect delta、build requirements与审计引用；`verify-integration` 从两份 `HostCargoUnitGraph` 计算真实 delta，要求它不删除 baseline feature/edge、不超出 entry、不得引回 excluded Component/first-party path package。Schema v1对任何external shared `CompilationKind::Host` unit的非空feature/edge delta一律返回`HostBuildUnitDeltaUnsupported`；Target delta若涉及带custom build的package、增加/改变build-script/proc-macro或其transitive Host unit、改变build-script feature environment/link/generated/native output，也同样拒绝，不能用普通audit-ref或只申报build requirements放行。Cargo feature provenance只证明谁请求 feature，不证明 feature对同一 target unit的哪条 API路径生效；默认 `composition-conservative` attribution必须把其余合法Target unit delta的全部可能 runtime effect计入 composition path，并要求它们已经是每个可达 selected Component/Host boundary runtime ceiling的子集。只有满足下述 source-semantics evidence的 `host-only-additive-api` 才能把经证明仅由产品新增 API使用的 Target unit effect只计入 product level。

没有 feature delta时不得要求空 policy；存在 delta时 pre/build-host/post都必须接收同一 `--host-feature-policy <policy.toml>`，其 canonical digest写入 `HostBuildInputClosure`、pre receipt、executor attestation和 post attestation。Policy不是放行任意 feature的通配表：unknown unit/feature、实际新增 unit/edge不等于 approved closure、default-feature隐式扩张、effect/build requirement漏报、patch/replace/source override、Host lock drift、duplicate rust-agent API source identity或 path snapshot类型分叉全部 fail closed。Composition hash与其 standalone manifest保持不变；product integration attestation另行记录逐 unit baseline/actual features、delta provenance、`host_feature_union_effects`和最终 `product_compiled_runtime_effects`。这样 Host可以合法共享 Cargo依赖，又不能把某一 Cargo unit的 feature union伪装成原 composition已审计内容。`verify-integration`仍重算全部 canonical payload、snapshot、Cargo.lock与 composition hash，确认 Host dependency alias指向所验证目录，并拒绝 dirty、symlink escape、hash/ref不一致或 development-only composition。

Schema v1 的最小 policy entry 为：

```toml
schema = 1

[[unit]]
name = "tokio"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "<exact-cargo-checksum>"
selector = { target-name = "tokio", target-kind = "lib", compilation-kind = "target", compile-mode = "build", profile = "release" }
allow-extra-features = ["rt-multi-thread"]
allow-added-units = []
attribution = "composition-conservative"
composition-effects = []
product-host-effects = []
build-requirements = { executables = [], read-inputs = [], environment = [] }
audit-ref = "AINS-HOST-FEATURE-0001"
```

`allow-added-units` 使用 `HostCargoUnitGraph` 的完整 package source identity与 unit selector，不接受仅 package name；git package还必须固定 precise revision。Policy normalization拒绝重复/重叠 selector、unknown target/compile mode/profile、重复或未知 feature、未排序集合、通配 version/source、空 audit ref和互相冲突的 effect归因；schema v1 selector必须是`compilation-kind = "target"`，Host selector或任何新增/改变Host build-unit closure直接拒绝。一个 package同时存在 Host与 Target unit时，Host unit必须保持standalone baseline exact，不能用package级allowlist或Target entry把host-only feature扩张到任一Host unit。`composition-conservative` 是 Target unit默认且不接受省略：对 exact unit source、baseline+actual feature set和新增 unit/edge closure做安全审计后，把每个可能新增的 runtime effect全部列入 `composition-effects`；Host同时使用的 effect可以重复列入 `product-host-effects`。Reverse dependency path只作为同一 unit的 feature requester provenance，不能把 effect自动判成 product-only。产品自身新增的build script/proc macro不作为shared delta批准；其执行effect进入product BuildExecutionPolicy，其生成/链接进artifact的runtime contribution必须进入product Host root exhaustive effect ceiling并由post attestation验证。

`host-only-additive-api` 是仅适用于 Target unit的严格例外：entry必须额外固定 `feature-semantics-evidence = { algorithm, digest, reviewer-policy }`，其 digest指向纳入 HostBuildInputClosure的规范化审计文档。证据必须绑定 exact package source/checksum、unit selector、baseline/actual features、delta unit/edge closure和审计的源码范围，并证明新增 feature只增加 product Host调用的新 API/实现、不会改变 composition已可调用 baseline API的语义、cfg、global initializer、trait impl selection或 transitive runtime behavior；unit-graph provenance还必须证明该 exact Target unit的全部 delta requester都位于 emitted composition之外的 product Host closure，任何 composition requester都使例外失效。Evidence signer/reviewer-policy必须在 BuildExecutionPolicy allowlist，pre/build/post校验同一 digest。任一条件无法机器验证或审计结论为 unknown时降级为 `composition-conservative`；只写 `product-host-effects`、只有 reverse path或普通 audit-ref均不足以成立 host-only。不同 compilation kind、版本/来源不同的 unit或独立进程不共享此批准，按各自 build/runtime accounting处理。

Pre verification 物化版本化 `HostBuildInputClosure`：Host workspace/root/member manifest链、Host Cargo.lock、从 Host root到构建工作目录生效的唯一 `.cargo/config.toml`、selected Host/path package的 `cargo package --list` 等价文件集、emitted composition tree、package resolution projection、standalone/final `HostCargoUnitGraph`及各自 digest、exact build-host/target facts与 planner identity、normalized HostFeatureUnionPolicy或显式 `none`、所有 referenced feature-semantics evidence bytes/signer-policy digest、逐 unit计算的 feature/dependency delta、显式 artifact selector，以及会决定 effective panic strategy的 Host Cargo profile、target与受控 rustc invocation setting。所有 file tree必须复制到隔离 closure snapshot，应用第 26节同一个 canonical metadata contract，并以 `snapshot-tree-digest` 作为 item digest；不得把已按 bytes验证、但 metadata仍可漂移的 live path package直接只读挂载。Runner使用隔离 `CARGO_HOME`、固定 logical working directory和该闭包的只读 mount；拒绝 legacy `.cargo/config`/`.cargo/config.toml`并存、闭包外 ancestor config、越出 Host trust root的 path/patch source、symlink escape、未进入 policy的 custom target/linker/runner或 rust-toolchain override。Pre receipt分别记录含 normalized metadata的各项 tree/unit-graph digest和 canonical aggregate digest；build-host与 post verification必须从实际 mount重算完全相同的闭包和 unit graph，不能依赖调用者当前目录或 ambient Cargo config。若 emitted manifest的 `requires_panic_unwind=true`，pre必须拒绝已知选择 abort的 profile/flag，executor attestation必须记录 artifact的 effective `panic=unwind`与 rustc/target evidence，post必须复验；unknown、abort或 target不支持 unwind都 fail closed，generated compile guard仍是防止外部 Host绕过 verifier的独立最终 gate。

`--phase pre` 在任何最终 Host build前原子写出带 schema的 verification receipt，固定 composition/emitted tree、HostBuildInputClosure、package resolution、两份 `HostCargoUnitGraph`、normalized BuildExecutionPolicy与 HostFeatureUnionPolicy/none digest；receipt不证明 artifact已构建。`rust-agent build-host` 是 Cargo Host的 reference product executor；它在受控 rustc wrapper/Cargo event recorder中逐 unit记录实际 compilation kind、features、extern edge、build-script/proc-macro执行与 artifact linkage，并要求 observed unit graph逐字节规范化后等于 pre final graph。Planner graph不能替代 build observation，Cargo JSON的 package级 feature汇总也不能替代 unit证据。Framework/bundler product executor（例如 framework CLI、Xcode/Gradle）必须输出相同 schema所需的 input/toolchain/policy/backend/artifact/逐-unit graph与 feature-delta证据，但 executor品牌不进入 composition resolution。`--phase post` 必须读取 pre receipt和已签名 executor attestation，重跑全部验证，要求所有 pre-build digest、policy digest、planned/observed unit graph与实际逐-unit feature delta未变，对每个显式 artifact执行文件 digest和 target/kind校验，然后以 policy trusted signer输出已签名 product integration attestation。Production证据必须包含 pre receipt、signed post attestation和产品 build executor对 filesystem/network/executable/toolchain/unit-observation的 signed enforcement attestation；缺任一者都不得宣称最终 Host artifact满足 rust-agent production build isolation。

`wasm-host-constructor` 的固定 ABI 为 `fn(wasm_bindgen::JsValue) -> Result<Config, rust_agent_runtime_api::WasmHostBindingError>`。该 error 是 mandatory lightweight runtime-api contract，只含封闭 category、field/key 与 redacted owned detail，不保存 `JsValue`、JS object、callback 或 Host export type；Host callback Component 不得为了构造 Config 而依赖 selected `rust-agent-host-wasm` package，Host export module 只 re-export 同一类型身份。Generated glue 以 `config-key` 从 `host_bindings` object 取值，拒绝缺失字段、未知字段、重复语义 key、非 object 输入和 constructor error；constructor 必须完成 callback shape、ABI version 与 origin binding 校验。

Host entry/export helper 虽不进入 Capability/Component Catalog，仍进入独立的 Host Boundary Catalog，以及 target/support/runtime-security/build-requirements validation、Cargo.lock、source digest、generated dependency graph 和 build manifest；它不能成为绕过 profile security ceiling 或 BuildExecutionPolicy 的未审计依赖。Host boundary 的 `security` 是该 helper package、linked native/WASM glue 与 transitive non-Component runtime helper 的完整 runtime ceiling；它不进入 capability binding stamp 或 AgentAuthority，但必须与 selected Component ceilings 合并为最终 artifact 的 `compiled_runtime_effects`。Runtime adapter 也不进入 Capability Catalog；schema v1 要求其 own/transitive direct runtime-effect ceiling 严格为空，只能提供 clock/sleep/owned task scheduling，任何直接 filesystem/network/process/credential effect 必须移入普通 Component/Host boundary。Selected adapter 仍进入 target/support/source/feature/build-requirements validation 和 manifest，bin/wasm 还必须命中 Host boundary 的 `runtime-adapters` allowlist。Schema v1 的 `host-wasm` Host export metadata 必须声明 `build-requirements.executables = ["wasm-bindgen-cli"]`；缺失、错 kind 或被其它 root 的偶然声明遮蔽都在 Cargo 前拒绝。

Composition Compiler 通过 `cargo metadata` 读取 Capability API、Component、Host boundary 与 direct-root build-requirements metadata，生成 Capability Catalog、Component Catalog、Host Boundary Catalog 和 root build policy records。不得再维护一份与 Cargo dependency graph 平行的手工全量 catalog。

CI 必须验证：

- 每个 component id 只对应一个 Cargo package，每个 Component package 只声明一个 component id；
- Component 的 factory/config/dependencies/runtime-primitive Rust path 与 Capability 的 api/binding/adapter path 存在并通过 generated compile fixture 类型检查；声明 required resource namespace 时 preparer/prepared-config path、异步 ABI、exact descriptor set 与 prepared factory ABI 也必须通过，未声明时这两个字段必须不存在；
- file-source Config 实现 `DeserializeOwned`，bin composition 的 `RuntimeConfig` 可完整反序列化；
- 每个 file-source Config 的 conformance test 拒绝未知字段、重复字段和非法范围；Config/diagnostic 中只允许 `CredentialRef`，不允许 resolved secret；
- Native Config/Dependencies/Concrete service 满足相应 `Send/Sync` binding，WASM lifecycle future 遵守 local-future ABI；
- Host entry 的 entry path 存在，且满足 generator 同时传入 selected runtime constructor 与 build closure 的 generic entry ABI；
- Host export 的 export-module path 存在，且满足 generator schema 固定、接收 selected runtime constructor 的 WASM helper ABI；bin/library/wasm 对 Host entry/export 的必选、互斥和 target 规则均 fail closed；
- selected runtime adapter 的 constructor/target/support/primitive set path 与 ABI 存在，security 必须为空且完整 requirement union 被满足；bin/wasm Host boundary allowlist 必须包含 exact adapter id，library emitted alias 必须 re-export 同一 snapshot constructor/type identity；
- wasm composition 的每个 host-source Component 都有可编译的 `wasm-host-constructor`，其共享错误类型来自 `rust-agent-runtime-api`，Component/API dependency graph 不得依赖 Host boundary package；
- library host-source 的 namespaced host-api module 可被独立 Host consumer 直接导入并实现 callback；其 Config/trait/DTO public type closure 不暴露 Integrator path-local concrete type；
- metadata 声明的跨 capability dependency 与真实 Cargo dependency 不矛盾；
- App Component 与 selected runtime adapter 的 `app-coexistence` mode/evidence bytes/reviewer policy 完整且 digest 匹配；adapter 只允许 concurrent-independent/requires-stop，shared-host mode 的每个字段属于 exact host-source Component Config、类型实现 sealed shared-handle identity ABI，并由 two-App compile/runtime fixture 证明同一 identity且没有 reopen；
- 高风险 crate 未被未声明路径偷偷引入；
- generated runtime artifact closure 内的 mandatory API/infrastructure 没有 direct runtime effect 或 effectful transport/FFI dependency；所有外部操作只能经 stamped binding 到 selected Component；
- 每个 lifecycle/provide/conditional own effect 都是 Component runtime ceiling 的子集；Tool/Command definition effect 是 sealed consumer effective ceiling 的子集，consumer effective effects 与真实 selected dependency binding closure 一致并且不得越过 `component_runtime_effects`；selected Host boundary runtime ceiling 进入 artifact union 但不进入 AgentAuthority；每个 selected/direct first-party root package 的 build requirements 都被 build policy logical ids 完整满足且不进入 runtime effects；
- component id、capability id 全局唯一，provider key 在同一 Capability 内唯一；
- session event kind/version/namespace/criticality/bounds 与 generated SessionEventCatalog 一致；
- Component scope 与其 provides 的 Capability scope 一致；
- target predicate 与 Cargo target dependencies 不冲突。
- library Host integration的 package metadata graph只用于 discovery；pre/build/post必须分别固定 standalone/final/observed `HostCargoUnitGraph`，逐 unit区分 build-host与 composition-target facts/features并拒绝 package级替代证明。

## 4. Minimal Core

`rust-agent-core` 不是“Agent Kernel”。它只保存多个能力共享、且不会把重依赖拉入图中的稳定基础类型。

包含：

```rust
pub struct Message { /* wire-neutral content */ }
pub enum ContentBlock { /* text / image ref / structured parts */ }
pub struct Usage { /* token/accounting primitives */ }

pub struct RequestId(/* ... */);
pub struct SessionId(/* ... */);
pub struct AgentId(/* ... */);
pub struct AgentLifecycleOperationId(/* ... */);
pub struct AgentOperationRecoveryKey(/* private fixed-width canonical bytes */);

pub enum AgentOperationRecoveryKeyEncodingError {
    UnsupportedVersion,
    InvalidCanonicalEncoding,
}

impl AgentOperationRecoveryKey {
    pub const V1_ENCODED_LEN: usize = 33;

    pub fn from_canonical_v1_bytes(
        bytes: [u8; AgentOperationRecoveryKey::V1_ENCODED_LEN],
    ) -> Result<Self, AgentOperationRecoveryKeyEncodingError>;

    pub fn to_canonical_v1_bytes(
        &self,
    ) -> [u8; AgentOperationRecoveryKey::V1_ENCODED_LEN];
}

pub struct CallId(/* ... */);
```

`AgentLifecycleOperationId` 是字段私有的 tagged identity。Volatile variant 只含当前 process issuer nonce/counter，编码器拒绝把它写入 durable Host journal；Persistent variant 固定包含 selected persistence `StoreIdentity`、issuer generation 与 counter，只有 backend issuer 能构造。其唯一性域是该 authoritative store/global locator；任何 API 在 lookup/consume 前先核对 StoreIdentity，因而不同 store 的相同 counter 不会互相别名。StoreIdentity 的 provisioning规则由第 7 节 persistence contract定义，不依赖 App-local entropy。

`AgentOperationRecoveryKey` 不是authority或operation id，而是caller在任何Durable seal/allocation前已经持久化的固定宽度幂等键。Host从自身durable operation journal的never-reused generation + counter或等强度随机键构造；`subagent-in-process`则从committed parent lineage + `SubagentOperationId` + child slot作domain-separated派生。`rust-agent-core`提供公开的versioned checked byte constructor/accessor，使独立Host crate能够合法重建同一key；constructor只验证固定长度、version、reserved bits与canonical encoding，不能授予binding或指定backend counter，类型字段仍私有且不实现随机`Default`。`CreateDurable`/`ResumeDurable` draft必须携带它，volatile intent禁止携带；同一StoreIdentity内key永不复用，重复key只能恢复同一exact sealed request，不能表示新操作。

跨 Agent control plane 与 Session persistence seam 共用、但不拥有任何 backend 的 lifecycle protocol 类型固定由 `rust-agent-runtime-api` 定义；它只依赖 `rust-agent-core` 的 `SessionId`/identity primitive，不能依赖 `rust-agent-agent` 或 `rust-agent-session`：

```rust
pub enum AgentLifecycleOperationIntent {
    CreateSessionless,
    CreateEphemeral,
    CreateDurable,
    ResumeDurable { session_id: SessionId },
}

pub enum LifecycleReservationEncodingError { InvalidCanonicalField }

/// 由 generated factory 在完整请求投影完成后密封；字段不公开。
pub struct LifecycleOperationReservationDraft {
    _private: (),
    recovery_key: AgentOperationRecoveryKey,
    intent: AgentLifecycleOperationIntent,
    request_fingerprint: Digest,
    projected_authority_digest: Digest,
    projected_plan_digest: Digest,
    composition: CompositionHash,
    catalog: Digest,
}

impl LifecycleOperationReservationDraft {
    #[doc(hidden)]
    pub fn from_projected_request(
        recovery_key: AgentOperationRecoveryKey,
        intent: AgentLifecycleOperationIntent,
        request_fingerprint: Digest,
        projected_authority_digest: Digest,
        projected_plan_digest: Digest,
        composition: CompositionHash,
        catalog: Digest,
    ) -> Result<Self, LifecycleReservationEncodingError>;

    pub fn recovery_key(&self) -> &AgentOperationRecoveryKey;
    pub fn intent(&self) -> &AgentLifecycleOperationIntent;
    pub fn request_fingerprint(&self) -> &Digest;
    pub fn projected_authority_digest(&self) -> &Digest;
    pub fn projected_plan_digest(&self) -> &Digest;
    pub fn composition(&self) -> &CompositionHash;
    pub fn catalog(&self) -> &Digest;
}

/// Backend 与 operation id 在同一 commit 固定的 authoritative reservation。
pub struct LifecycleOperationReservation {
    _private: (),
    draft: LifecycleOperationReservationDraft,
    reserved_session_id: Option<SessionId>,
}

impl LifecycleOperationReservation {
    #[doc(hidden)]
    pub fn from_committed_allocation(
        draft: LifecycleOperationReservationDraft,
        operation_id: &AgentLifecycleOperationId,
    ) -> Result<Self, LifecycleReservationEncodingError>;

    pub fn draft(&self) -> &LifecycleOperationReservationDraft;
    pub fn reserved_session_id(&self) -> Option<&SessionId>;
}

pub enum AgentOperationAllocationError {
    UnsupportedIntent,
    AppClosed,
    OwnerClosed,
    OwnerMismatch,
    StoreUnavailable,
    IssuerStateCorrupt,
    CounterExhausted,
    ReservationConflict,
    OperationNotFound,
    OperationConflict,
    ReservationStatusUnknown,
    UnsupportedRecovery,
}
```

`rust-agent-agent` 为 Host API ergonomics 原样 `pub use` intent/error 这两个类型，但不是定义 owner；reservation draft/state只属于 generated factory↔session persistence内部 seam，不作为 Host request DTO re-export。`rust-agent-session` 直接 import 同一 `rust-agent-runtime-api` identity，禁止经 agent re-export 反向依赖。按 `A → B` 表示 “A depends on B”，领域边固定为 `rust-agent-agent → rust-agent-session → rust-agent-runtime-api → rust-agent-core`；agent 还可直接依赖 core/runtime-api。`AgentShutdownError` 因封装 `SessionPersistenceError` 只形成 `agent → session` 的单向边，session 的 public trait/DTO/error closure 不得出现任何 agent-crate type。Sessionless composition 已经需要轻量 runtime-api；出现 session API DTO 不等于选择 session Component/backend implementation。

不得包含：

- `LanguageModel` implementation；
- `DirectAgent` / Tool Loop；
- `Tool` / `ToolDefinition`；
- Session persistence；
- Prompt assembly；
- Memory；
- HTTP / reqwest；
- Tokio；
- AINS Gateway；
- UI/application framework；
- provider-specific wire types。

### Minimal Profile，而不是“core 执行模型”

真正的最小运行路径由 composition 形成：

```text
rust-agent-core
      │
      ├── rust-agent-model
      ├── rust-agent-agent
      │
      ├── model-replay / model-host / selected model provider
      └── driver-direct

Request → LanguageModel → Response
```

因此 `DirectAgent` 必须位于 `driver-direct`，而不是 core。

### Core dependency gate

CI 对 `rust-agent-core` 建立硬门禁：

```text
forbidden direct/transitive families:
  tokio
  reqwest
  redb
  hnsw
  pdf
  ssh
  mcp
  opentelemetry
  AINS crates
```

若基础 DTO 确实需要序列化，应优先使用轻量、可选的 `serde`，并避免让 JSON 表示成为所有 domain API 的唯一类型系统。

### 跨 target 异步 trait 约定

所有需要作为 `dyn Trait` 使用的异步 Capability trait 统一使用 `async_trait` 展开；不得直接把原生 `async fn` trait 放入 `Arc<dyn Trait>`。以下属性是每个异步 Capability trait 定义的强制组成部分；后续接口片段省略重复属性：

```rust
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait Capability: MaybeSendSync {
    async fn call(&self) -> Result<(), CapabilityError>;
}
```

Native future 必须为 `Send`，WASM browser future 可以为 local future。Streaming 类型统一为：

```rust
#[cfg(not(target_arch = "wasm32"))]
pub type ModelStream = futures::stream::BoxStream<'static, Result<ModelEvent, ModelError>>;

#[cfg(target_arch = "wasm32")]
pub type ModelStream = futures::stream::LocalBoxStream<'static, Result<ModelEvent, ModelError>>;
```

## 5. Model Capability

不要继承 AINS 当前 `ModelClient` 将 chat/embed/stt/tts 聚合到一个 trait 的设计。

语言模型主能力统一为 streaming-first contract：

```rust
pub trait LanguageModel: MaybeSendSync {
    async fn stream(
        &self,
        context: ModelCallContext,
        request: ModelRequest,
    ) -> Result<ModelStream, ModelError>;

    async fn complete(
        &self,
        context: ModelCallContext,
        request: ModelRequest,
    ) -> Result<ModelResponse, ModelError> {
        let budget = context.output_budget();
        collect_stream(self.stream(context, request).await?, budget).await
    }
}
```

`ModelCallContext` 携带 `request_id`、deadline、cancellation lineage、output budget、非持久化 tracing context 与字段私有的 `RequestJournalProof`；它不是 model-visible request，也不序列化进 `ModelRequestRecord`。该类型没有 public constructor/反序列化入口，只有第 6/7 节的 request-journal facade 在对应 record 已达到所需 commit level 后才能生成。Provider stream 和默认 collector 都必须执行同一 budget。重建/replay 使用 record 恢复 `ModelRequest`，并为本次执行创建新的 call context。

`cap:model` 的 consumer binding 不暴露 raw `Arc<dyn LanguageModel>`；它只暴露保留 provider identity/effect stamp 的纯 `ModelRegistryBinding::plan_call` 与受控 `stream_prepared(PreparedModelCall)`。Binding 在调用 provider 前校验 journal proof 的 Agent/Session identity、plan/request digest、provider key/model id 与当前 route 完全匹配；不匹配或没有 proof 时不调用 provider。Raw `LanguageModel::stream` 只供同一 model capability adapter 在校验后委托 concrete provider。这样 reviewed driver 的 typed path 无法绕过 `RequestPrepared`，同时不要求 concrete model provider 依赖 Session API。

第一版独立实现 Embeddings：

```rust
pub trait Embeddings: MaybeSendSync {
    async fn embed(&self, context: CallContext, input: &[String]) -> Result<Vec<Embedding>, EmbeddingError>;
}
```

SpeechToText、TextToSpeech、ImageGeneration、Rerank 与 Vision-specific preprocessing 不进入第一版 canonical catalog；迁入时各自新增独立 Capability/API/Component，不扩大 `LanguageModel`。

### ModelRequest 的边界

`ModelRequest` 允许包含 provider-neutral tool-call representation，但不得依赖 concrete `Tool` implementation：

```rust
pub struct ModelRequest {
    pub messages: Vec<ModelMessage>,
    pub system: Option<String>,
    pub tools: Vec<ModelToolDefinition>,
    pub params: ModelParams,
}
```

`ModelToolDefinition` 是协议 DTO，不是 `Tool` trait：

```text
ToolRegistry
    ↓
schema adapter
    ↓
ModelToolDefinition
    ↓
ModelRequest
```

### Provider registry 与 runtime selection

模型能力默认采用 `BindingKind::Registry`：一个 binary 可以同时编译：

```text
model-openai
model-deepseek
model-replay
```

Runtime config 可以从**已编译 provider registry** 中选择路由；但不能指定未编译 provider。

`[binding.model]` 的 generated runtime schema 显式区分 `mode = "default"` 与 `mode = "explicit-per-request"`。`default` mode 必须同时给出命中 compiled registry 的 `default` key；每个 request 可以选择 `ConfiguredDefault` 或显式覆盖为另一个 compiled key。`explicit-per-request` mode 禁止 `default` 字段，并要求每个 `ModelCallDraft` 使用 `Explicit(ProviderKey)`；App initialize 只验证 mode/schema 与 compiled key set，不试图预测未来 request，缺少 route 只由 `plan_call` 返回 `ModelRouteRequired`，不调用 journal/provider。

`cap:model` 只有一个 compiled provider 且省略 `[binding.model]` 时，生成的 config 缺省为该唯一 key 的 `default` mode；存在多个 provider 时必须显式选择上述两种 mode，否则 App initialize 以 `AmbiguousModelRouting` 失败。其它 Registry 的 key 选择由其 typed consumer config 定义，不共享隐式“第一个 provider”规则。

这意味着 composition 输出必须区分：

```text
Compiled Provider Set
Generated Runtime Binding Schema
```

Resolver 只生成可选 key 集合、`ModelRoutingMode` schema 与 typed validation code，不读取 Runtime config；App initialize 验证 mode/default，`plan_call` 再验证 request route。不能把“编译了几个 provider”和“当前请求选哪个 provider”混为 `ExactlyOne`。

### Streaming production semantics

从 AINS 迁移并继续保留：

- retry 必须有稳定事件语义；
- 只有相同 provider/model、materialized ModelParams 与 model-visible payload 的 transport retry 可复用一次 `RequestPrepared`；fallback 改变 route 或语义参数时必须产生 linked 新 request id 与新 `RequestPrepared`；
- cancellation 必须能打断静默网络流；
- partial output 与最终 complete 的一致性；
- provider protocol violation 不得破坏 SessionLog；
- usage 与模型完成结果关联；
- provider error 保留结构化 category，不全部压成字符串。

## 6. Agent / AgentDriver / AgentFactory

公共 Agent contract、Agent 生命周期、concrete loop 必须分离。

```rust
pub trait Agent: MaybeSendSync {
    async fn send(&self, request: AgentSendRequest) -> Result<AgentOutput, AgentError>;
    fn cancel(
        &self,
        request_id: AgentRequestId,
        cause: CancelCause,
    ) -> Result<CancelOutcome, AgentCancelError>;
}

pub trait AgentDriver: MaybeSendSync {
    async fn run(
        &self,
        context: &AgentContext,
        request: AgentRequest,
    ) -> Result<AgentResponse, AgentError>;
}
```

每个 generated Agent scope 都向 driver 注入同一个字段私有的 `AgentContext::request_journal`，而不是让各 driver 自行、可选地寻找 SessionLog：

```rust
pub struct ModelCallDraft {
    pub request_id: ModelRequestId,
    pub purpose: ModelRequestPurpose,
    pub route: ModelRouteSelection,
    pub request: ModelRequest,
    pub linked_from: Option<ModelRequestId>,
}

pub enum ModelRouteSelection {
    ConfiguredDefault,
    Explicit(ProviderKey),
}

pub enum ModelRoutingMode {
    Default { provider: ProviderKey },
    ExplicitPerRequest,
}

pub struct ModelCallPlan {
    request_id: ModelRequestId,
    purpose: ModelRequestPurpose,
    provider_key: ProviderKey,
    model_id: ModelId,
    materialized_request: ModelRequest,
    plan_digest: Digest,
    linked_from: Option<ModelRequestId>,
}

pub struct PreparedModelCall {
    context: ModelCallContext,
    request: ModelRequest,
    record_digest: Digest,
}

impl ModelCallPlan {
    /// Read-only canonical provider/request projection; no scope identity or secret.
    pub fn journal_projection(&self) -> ModelCallJournalProjection;

    /// Consumes the immutable plan; succeeds only for a matching sealed proof.
    pub fn seal(
        self,
        proof: RequestJournalProof,
    ) -> Result<PreparedModelCall, ModelError>;
}

pub struct ModelRequestJournalIssuer { /* private authority tag */ }
pub struct ModelRequestJournalVerifier { /* paired private authority tag */ }

pub struct ModelRequestJournalAuthority;

pub struct ToolCallJournalIssuer { /* private authority tag */ }
pub struct ToolCallJournalVerifier { /* paired private authority tag */ }
pub struct ToolCallJournalProof { /* exact committed/volatile call witness */ }
pub struct ToolCallJournalAuthority;

pub enum GeneratedScopeCallAuthority {
    None,
    ModelRequestJournal(ModelRequestJournalVerifier),
    ToolCallJournal(ToolCallJournalVerifier),
}

impl ModelRequestJournalAuthority {
    /// Generated scope construction only; issuer is not Clone and neither half serializes.
    #[doc(hidden)]
    pub fn issue_for_generated_scope(
        scope: ModelCallScopeIdentity,
    ) -> (ModelRequestJournalIssuer, ModelRequestJournalVerifier) {
        /* runtime-api implementation allocates a process-local monotonic authority tag;
           counter exhaustion is a fatal construction error in the concrete API */
        unimplemented!("API shape: implemented by rust-agent-runtime-api")
    }
}

impl ToolCallJournalAuthority {
    /// Generated Agent scope construction only; same non-serialization rules.
    #[doc(hidden)]
    pub fn issue_for_generated_scope(
        scope: ToolCallScopeIdentity,
    ) -> (ToolCallJournalIssuer, ToolCallJournalVerifier) {
        unimplemented!("API shape: implemented by rust-agent-runtime-api")
    }
}

impl AgentContext {
    pub async fn prepare_model_call(
        &self,
        plan: ModelCallPlan,
    ) -> Result<PreparedModelCall, AgentError>;

    /// Returns a proof only after the route-required ToolCall journal checkpoint.
    pub async fn prepare_tool_call(
        &self,
        projection: ToolCallJournalProjection,
    ) -> Result<ToolCallJournalProof, AgentError>;
}

impl ModelRegistryBinding {
    /// Pure/deterministic: selects a compiled key and materializes provider defaults.
    pub fn plan_call(&self, draft: ModelCallDraft) -> Result<ModelCallPlan, ModelError>;

    /// Verifies the paired journal proof before touching the provider.
    pub async fn stream_prepared(
        &self,
        call: PreparedModelCall,
    ) -> Result<ModelStream, ModelError>;
}
```

调用顺序固定为 `model_binding.plan_call(draft) → context.prepare_model_call(plan) → same_model_binding.stream_prepared(call)`。`ModelCallPlan` 字段私有且不实现 Serialize/Deserialize；只有当前 binding 能按 compiled Registry、immutable `ModelRoutingMode` 与 request route 选择 provider、展开 provider/runtime defaults、固定 model id 并计算 plan digest。`Default` mode 的 `ConfiguredDefault` 使用已验证 default，`Explicit` route 在两种 mode 下都必须命中 projected compiled registry；`ExplicitPerRequest` mode 收到 `ConfiguredDefault` 时在 journal/provider 之前返回 `ModelRouteRequired`。跨 crate 的 Agent/Session journal 只能读取其 immutable `journal_projection()`；commit 后把 paired issuer 生成的 proof 交给 `plan.seal`，不能直接构造 `PreparedModelCall`。`prepare_model_call` 在 caller 不可覆盖的当前 Agent identity、optional Session identity、composition/catalog、authority epoch/projection digest、history boundary、materialized defaults、tool/prompt snapshot 与 plan 字段上构造 canonical `ModelRequestRecord`，并按 route 执行：

- Sessionless：写入当前 turn-owned、有界 volatile journal；不承诺 cold reconstruction，但仍生成只属于该 Agent/request 的 proof；
- Ephemeral：通过 generated Session scope 的 `SessionLog` 以稳定 batch id 确认 backend transaction committed 后生成 proof；
- Durable：以稳定 batch id 追加 Required `RequestPrepared`，只有 `AppendDurability::Durable` 返回/解析为 `Committed` 后生成 proof；`NotCommitted` 不发模型请求，`CommitStatusUnknown` 关闭 admission 并进入既有 recovery 语义。

Generated factory 根据 creation route 构造 facade：`Agent(AppParent)` 只能得到 volatile variant；`Agent(SessionParent)` 必须绑定同一 prepared Session scope 的 `cap:session-log`，Durable route 还验证 backend durability。同一个 facade 同时拥有 model-request issuer 与 model-origin tool-call issuer；Driver 的 metadata 不声明这些 generated infrastructure 参数，`Dependencies` 仍只与 capability requirements 一一对应；`AgentContext` 是 `AgentDriver::run` 已有的 scope-owned 调用参数。Driver 不能替换 journal mode、Session identity、commit level 或 proof。`session-title-basic` 等 Session-owned model caller 通过同一 Session scope 提供的 `SessionOperationContext::prepare_model_call` 走相同 model proof 协议，并使用独立 purpose。

`RequestJournalProof`、issuer/verifier pair 与 `GeneratedScopeCallAuthority` 位于轻量 `rust-agent-runtime-api`，只依赖 identity/digest/canonical witness primitive，不依赖 model provider、Session backend 或 generated crate；pair 使用同一私有、process-local 单调且不复用的 authority tag 加 scope identity 校验，不读取 OS randomness，因此不破坏 mandatory infrastructure 的 effect-free 约束。Tag counter 溢出必须 fail closed，不能 wrap/reuse。`rust-agent-model` 的 `ModelCallContext`/binding 与 `rust-agent-agent` 的 journal facade 都单向依赖它，避免 API dependency cycle。

Scope builder 为每个 Agent/Session model-caller identity 创建唯一 model issuer/verifier pair，并为每个 Agent identity 创建唯一 model-origin tool issuer/verifier pair。Issuer 只 owned 地进入 request-journal facade；model verifier 只通过 `GeneratedScopeCallAuthority::ModelRequestJournal` 密封进该 scope 的 `ModelRegistryBinding`，tool verifier 只通过 `GeneratedScopeCallAuthority::ToolCallJournal` 密封进该 Agent scope 的 `cap:tool-executor` consumer binding。Facade 在 commit witness 成立后 seal proof，相应 binding 校验 authority tag、scope identity、plan/request digest、step/snapshot 与 route。Issuer 不可 Clone；verifier 只允许克隆同一只读 authority tag以支持 typed binding/handle clone；各 half 都不可 Serialize/Deserialize/Debug，不进入 Component Dependencies、Host API 或 runtime config。`issue_for_generated_scope` 因 generated crate 与 runtime-api 分属 crate 必须是可链接函数，但 `#[doc(hidden)]` 不是安全边界；真正边界是 API-owned `BindingAssemblyOwner`：current Session/Agent scope owner保存 paired verifier，`BindingAssembly::bind_consumer`只在 validated exact edge的内部 context上自动安装它，并在返回 API-owned consumer envelope前把同一 assembly tag完成记录。Generated crate没有接收 verifier参数的 context constructor或 raw record API；普通 Component即使调用 issuance函数自建另一 pair，也没有 current owner/tag/receipt，不能加入 active scope，proof会因 assembly/scope authority不匹配而失败。这些机制只认证“这条 exact model request/tool call 已由当前 scope journal 准备”，不替代 provider effect/AgentAuthority 校验。

Concrete driver：

- `driver-direct`
- `driver-tools`
- `driver-planner`
- `driver-team`

Driver 对单个 Agent instance 通常是 `BindingKind::Singleton`，但“哪种 driver 可用”属于 build composition，不能硬编码进 agent API。

第一版每个 Agent 同时只允许一个 active turn。`send` 经过有界 admission queue；queue 满返回 `Busy`，shutdown 后返回 `Closed`。`cancel(request_id, cause)` 只在 lifecycle nonce 与当前 active request 完全匹配时取消该 turn，不销毁 Agent，也不删除或取消其它 queued request；idle、queued-only、已 terminal、foreign/stale lifecycle 都返回结构化 outcome/error且永不 arm 下一次 turn。Active request 的第一个 cancel cause 获胜；abort convergence 完成并提交对应 `TurnEnded(Aborted)` 后才替换 cancellation lineage 和启动下一条 queued request，在此窗口进入的新 send 保持 queued。`AgentHandle::shutdown` 使用独立 shutdown cause 关闭 admission、取消 active turn、使全部 queued waiter 得到 `Closed`、drain/kill owned work 后销毁 scope。Turn/request id 与 cancellation first-cause 分别在 admission/首次 cancel 时固定并用于 SessionLog ordering。

### AgentFactory 与 AgentHandle

Agent 创建不是简单 `new()`；生产级接口必须显式表达所有权：

```rust
pub trait AgentFactory: MaybeSendSync {
    async fn seal_operation(
        &self,
        owner: &AgentOwnerContext,
        draft: AgentOperationDraft,
    ) -> Result<SealedAgentOperationDraft, AgentOperationSealError>;

    async fn allocate_operation(
        &self,
        owner: &AgentOwnerContext,
        draft: SealedAgentOperationDraft,
    ) -> Result<AllocatedAgentOperation, AgentOperationAllocationError>;

    async fn recover_operation(
        &self,
        owner: &AgentOwnerContext,
        operation_id: AgentLifecycleOperationId,
        draft: SealedAgentOperationDraft,
    ) -> Result<AllocatedAgentOperation, AgentOperationAllocationError>;

    async fn create(
        &self,
        owner: AgentOwnerContext,
        req: CreateAgentRequest,
    ) -> Result<AgentHandle, AgentLifecycleError>;

    async fn resume(
        &self,
        owner: AgentOwnerContext,
        req: ResumeAgentRequest,
    ) -> Result<AgentHandle, AgentLifecycleError>;
}

#[derive(Clone)]
pub struct AgentHandle {
    agent: Arc<dyn Agent>,
    lifecycle: Arc<AgentLifecycle>,
}

impl AgentHandle {
    pub fn id(&self) -> AgentId;
    pub fn status(&self) -> AgentStatus;
    pub fn allocate_turn_request(&self) -> AgentRequestId;
    pub async fn send(
        &self,
        request: AgentSendRequest,
    ) -> Result<AgentOutput, AgentError>;
    pub fn cancel(
        &self,
        request_id: AgentRequestId,
        cause: CancelCause,
    ) -> Result<CancelOutcome, AgentCancelError>;
    pub async fn open_event_feed(
        &self,
        request: AgentEventFeedRequest,
    ) -> Result<AgentEventFeed, AgentEventFeedError>;
    pub fn command_definitions(&self) -> Arc<[CommandDefinition]>;
    pub fn allocate_command_invocation(&self) -> CommandInvocationId;
    pub async fn execute_command(
        &self,
        request: CommandRequest,
    ) -> Result<CommandResult, CommandError>;
    pub async fn shutdown(&self) -> Result<(), AgentShutdownError>;
}

#[derive(Clone)]
pub struct AppHandle { /* generated App scope + AgentFactory shared lifecycle */ }

pub use rust_agent_runtime_api::{
    AgentLifecycleOperationIntent,
    AgentOperationAllocationError,
};

impl AppHandle {
    pub async fn seal_agent_operation(
        &self,
        draft: AgentOperationDraft,
    ) -> Result<SealedAgentOperationDraft, AgentOperationSealError>;

    pub async fn allocate_agent_operation(
        &self,
        draft: SealedAgentOperationDraft,
    ) -> Result<AllocatedAgentOperation, AgentOperationAllocationError>;

    pub async fn recover_agent_operation(
        &self,
        operation_id: AgentLifecycleOperationId,
        draft: SealedAgentOperationDraft,
    ) -> Result<AllocatedAgentOperation, AgentOperationAllocationError>;

    pub async fn create_agent(
        &self,
        req: CreateAgentRequest,
    ) -> Result<AgentHandle, AgentLifecycleError>;

    pub async fn resume_agent(
        &self,
        req: ResumeAgentRequest,
    ) -> Result<AgentHandle, AgentLifecycleError>;

    pub fn publication_snapshot(&self) -> PublicationSnapshot;
    pub fn session_query(&self) -> Result<SessionQueryHandle, UnsupportedOperation>;
    pub fn verify_concurrent_handoff_from(
        &self,
        old: &AppHandle,
    ) -> Result<(), AppHandoffError>;
    pub fn status(&self) -> AppStatus;
    pub async fn shutdown(&self) -> Result<(), AppShutdownError>;
}

pub struct AgentEventFeedRequest {
    pub after: Option<AgentEventCursor>,
    pub max_buffered_events: NonZeroU32,
    pub max_buffered_bytes: NonZeroUsize,
}

#[cfg(not(target_arch = "wasm32"))]
pub type AgentEventStream =
    futures::stream::BoxStream<'static, Result<AgentEventStreamItem, AgentEventFeedError>>;

#[cfg(target_arch = "wasm32")]
pub type AgentEventStream =
    futures::stream::LocalBoxStream<'static, Result<AgentEventStreamItem, AgentEventFeedError>>;

pub struct AgentEventFeed {
    pub baseline: AgentEventBaseline,
    pub stream: AgentEventStream,
}

pub enum AgentEventBaseline {
    Sessionless {
        live: AgentLiveBaseline,
        first_live: AgentEventCursor,
    },
    SessionBacked {
        live: AgentLiveBaseline,
        session_id: SessionId,
        replay_after: Option<SessionEventCursor>,
        committed_high_water: SessionSequence,
        first_live: AgentEventCursor,
    },
}

pub struct AgentLiveBaseline {
    pub lifecycle: AgentLifecycleNonce,
    pub status: AgentStatus,
    pub active_request: Option<AgentRequestId>,
}

pub enum AgentEventStreamItem {
    Event(AgentEventEnvelope),
    Lagged {
        last_delivered: Option<AgentEventCursor>,
        committed_high_water: Option<SessionSequence>,
    },
    Closed { final_status: AgentStatus },
}

#[derive(Clone)]
pub struct SessionQueryHandle { /* private Arc<dyn SessionQuery> read facade */ }

pub enum SessionCompatibility {
    Compatible,
    IncompatibleComposition {
        stored_composition: CompositionHash,
        current_composition: CompositionHash,
        stored_catalog: Digest,
        current_catalog: Digest,
    },
}

impl SessionQueryHandle {
    pub async fn list_sessions(
        &self,
        request: SessionListPageRequest,
    ) -> Result<SessionListPage, SessionQueryError>;
    pub async fn read_events(
        &self,
        session_id: SessionId,
        request: StoredEventPageRequest,
    ) -> Result<StoredEventPage, SessionQueryError>;
    pub async fn read_projection(
        &self,
        session_id: SessionId,
        request: ProjectionRequest,
    ) -> Result<ProjectionSnapshot, SessionQueryError>;
}
```

`AgentFactory::seal_operation` 是 lifecycle operation 的唯一准备门：`AppHandle::seal_agent_operation` 以私有 App-root owner 调用它，`ChildAgentFactoryBinding::seal_operation` 则携带 exact parent Agent lifecycle/authority stamp 和匹配的 `ChildOwnerContext`。Host必须在调用它之前把Durable `AgentOperationRecoveryKey`与canonical `AgentOperationDraft`写入自己的operation journal；in-process Durable child的key则必须已由parent canonical operation state确定。Seal先规范化完整draft，读取Durable resume所需的committed descriptor，选择唯一template/route，并完成owner/request-specific authority与binding projection；任何retained resource namespace的accounted bootstrap preparation也在这之后、reservation mutation之前完成。然后它产生字段私有、不可修改/序列化/由Host构造的`SealedAgentOperationDraft`，密封recovery key、intent、规范化mode/Session/attenuation、stable structural owner lineage、composition/catalog、projected authority/plan/namespace commitment及canonical request fingerprint。Fingerprint使用domain-separated canonical encoding，覆盖所有会改变行为或authority的字段；recovery key作为独立幂等identity绑定同一sealed draft，不替代fingerprint，也不含尚不存在的operation id、secret/path或易失App instance nonce。seal/projection/bootstrap失败时persistence allocation调用数必须为零，Host可把pre-journaled entry标为rejected但不得把key复用于另一draft。

`AgentFactory::allocate_operation` 是唯一底层 lifecycle-operation allocator，且只接受上述 sealed draft；它不能接受裸 intent，也不能在 allocation 后重选 route、authority、recovery key或fingerprint。`CreateDurable`/`ResumeDurable` 必须经 selected `SessionPersistenceAdmin` 的 effect-stamped issuer：backend在该`StoreIdentity`的store-level atomic transaction/journal record中先查`AgentOperationRecoveryKey`。Absent时从持久、永不回退或复用的issuer generation + monotonic counter分配id，并在同一commit写入`recovery-key → operation-id`索引及包含exact recovery key、intent、request fingerprint、projected authority/plan digest、composition/catalog与optional SessionId的`Reserved` locator；Existing且全部sealed identity exact相同时直接返回原id而不增加counter，任一字段不同时返回`ReservationConflict`。只有该原子reservation confirmed或由same-key retry读回后才返回绑定的`AllocatedAgentOperation`。

并发App/process对同一key由store serialization point合并，different key各自分配；counter exhaustion、issuer state corrupt、store unavailable、owner mismatch或App/parent closed返回`AgentOperationAllocationError`。Commit/response unknown时不得返回猜测id或改用process-local candidate，但caller可在同一或重启后的App重新sealpre-journaled exact draft并再次调用allocate：若前次已commit则读回同一id，若确定未commit则才以同一key执行首次allocation。这样response丢失以及“allocation返回后、Host尚未来得及写id”都不会丢失candidate，也不会留下不可定位reservation。Genesis/ResumePrepared commit只原子消费recovery key、fingerprint与全部sealed identity exact匹配的reservation；它不再首次绑定或改写任何字段。

`CreateSessionless`/`CreateEphemeral` 使用只在当前 live App/process registry 有效的 volatile variant，并以 process-wide atomic issuer generation + monotonic counter 保证同进程共存 App 不碰撞；同一 registry entry也必须在返回前原子绑定 sealed request fingerprint/owner/plan，NewEphemeral proposed SessionId从 volatile operation id稳定派生，调用方不能拿 id另配请求或 Session。它不实现 durable serialization/replay，process loss 后旧 token必定无效且不能查询 durable locator。只有 persistent variant可以写入 Host durable operation journal并跨 same-composition App restart 复用。Durable Host的顺序固定为：先持久化never-reused recovery key + canonical draft，seal exact draft，调用幂等allocate；成功后把returned persistent id/fingerprint补写到同一Host journal entry，再首次create/resume。若id尚未补写就崩溃，恢复时重建App、重新seal journaled exact draft并以same-key allocate取回原id；已有id时也可用`recover_agent_operation(id, sealed_draft)`核对`Reserved`/`Located`状态。Different key/fingerprint返回`ReservationConflict`/`OperationConflict`；store状态unknown时保持fail closed并重试same key，绝不能发明新key/id或猜测/自增id。

每个 Agent 的 runtime-owned event publisher 独占 feed cursor、committed high-water 与 `AgentLiveBaseline`。SessionLog 在 durable/ephemeral batch 确认后、向 append caller 返回前，同步调用无 I/O 的 bounded `publish_committed`；它在一个短临界区更新 high-water/live baseline 并向每个 subscriber ring 写入或标记 `Lagged`，不调用 Host、不 await，也不等待容量。Provisional/runtime-only event 和 status/active-request transition 也由同一 publisher 排序。这样后述 feed registration/baseline/high-water 才有真实的共同 linearization point，而不是多个独立查询的约定；publisher 返回的内部错误使当前 Agent admission fail closed，不能让已 committed domain state 无声越过 feed high-water。未预期的 runtime implementation panic 不伪装成可移植错误路径：`panic=abort` 下会终止进程，只有 unwind-capable artifact 才可能由明确设置的 boundary 捕获。

Session-backed route 在 Session prepare 时先创建 publisher/hub，再用它 assemble `cap:session-log`；assembler 从同一 recovered committed snapshot 初始化并核对 high-water 后才允许 append，此时没有 subscriber且 admission 关闭。Agent prepare 把 exact Agent/lifecycle identity attach 到同一 hub，配对 publication 前不得更换。Sessionless route 在 Agent prepare 时直接创建 publisher。第一版一个 prepared Session writer lineage 只允许 attach 一个 live Agent incarnation；旧 incarnation 未 detach 或 lease 未释放时 attach 返回 `WriterConflict`。因此 cold baseline、Session-scope event commit 与当前 Agent public feed 共享 high-water，同时不会要求 Session Component 依赖 Agent API。

Public `AgentHandle` 只在 `AgentStatus::Ready` 后返回；`Preparing/PublishedAdmissionClosed` 只存在于 factory transaction 内部，不生成可执行 public handle。返回后的 status 只能沿 `Ready → Closing → Closed`，或 `Ready → RecoveryRequired → Closing → Closed` 单调变化；NewEphemeral 的 Ready 必须晚于 gated activation 和 genesis/index atomic commit，NewDurable create/resume 的 Ready 必须分别晚于 `AgentCreationCompleted`/`AgentResumeCompleted` durable confirmation，Completed cold reconstruction 的 Ready 必须晚于本次新 incarnation activation。PublicationSnapshot 的 published diagnostic state 不替代该 handle status。

`AgentRequestId` 是字段私有的 `(AgentId, lifecycle nonce, monotonic sequence)` typed identity，只能由对应 handle 分配；`AgentSendRequest` 固定携带该 id、bounded AgentInput、caller identity、deadline 和 cancellation。一个 live lifecycle 内 same id/same canonical caller+input 的 concurrent retry 合并到同一 active/completed turn，different fingerprint 返回 `RequestConflict`；首次 admission 固定 execution deadline/cancellation，retry 只能取消自身等待。有界 completed-result window 之外返回 `RequestExpired`，cold resume 拒绝旧 nonce；process loss 后没有 confirmed terminal event 的请求返回 `OutcomeUnknown`，不得自动重跑。Durable turn 的稳定 EventBatchId 从 composition/AgentId/AgentRequestId/domain event kind/exact logical coordinate 派生；logical coordinate 对 model request 使用 step id，对 ToolCall/ToolResult 使用 step id + normalized call id，对 terminal 使用 attempt/terminal identity，禁止只按 event kind 导致同 turn 多次 checkpoint 碰撞。Raw `Arc<dyn Agent>` 不从 AgentHandle、PublicationDirectory 或 Host API 暴露，native/library/WASM Host 都通过同一 handle admission path。

`open_event_feed` 是 Host/UI 的唯一 live observation seam，不是可回写 observer。Runtime 必须在同一个 feed registry linearization point 先注册 bounded subscriber，再捕获 baseline/high-water，保证 caller 读取 baseline 之前发生的新事件已在 feed buffer 中，不出现 query→subscribe 缝隙。注册前必须针对当前 Agent 的 `AgentResourceBudget` 原子预留一个 subscriber slot、`max_buffered_events` 和 `max_buffered_bytes`；预算至少分别包含 `max_event_feed_subscribers`、`max_event_feed_buffered_events_total` 与 `max_event_feed_buffered_bytes_total` 三个可衰减上限，并受 generated hard ceiling 限制。任一单 feed 上限或 count/events/bytes 聚合预留会超限时，`open_event_feed` 在分配 ring 前返回 `AgentEventFeedError::AdmissionBudgetExceeded`；失败不得留下 reservation。close/drop/idle expiry 在同一 registry 中恰好释放一次预留，因此 publisher 每次 publish 遍历的 subscriber 数和全部 ring 的最大保留空间都有 Agent 级上界，reconnect loop 不能累积旧 feed。Envelope 固定携带 AgentId、lifecycle nonce、monotonic AgentEventCursor、相关 AgentRequestId/step/call id、event kind，以及 Session-backed route 上的 canonical Session sequence/range；event 至少覆盖 status、turn/step、assistant delta/final、tool call/result/status、usage、command status 和 terminal error。Durable/ephemeral UI 先用 `SessionQueryHandle` 从 `replay_after` 读取到 `committed_high_water`，再消费 live stream；注册与 high-water 捕获之间的 committed event 允许同时出现在 query 和 feed，caller 以 canonical Session sequence/range + domain identity 丢弃不高于 baseline high-water 的重复项，runtime 不得产生无法按该键去重的 partial range。Sessionless 没有 cold replay承诺。Feed 满时不得阻塞 Agent/Session writer或使用无界内存，而是发送一次 terminal `Lagged` 并关闭该 feed；Durable caller 按给出的 high-water/query cursor 重建后重新订阅，Sessionless caller只能得到显式不可恢复 gap。每个 subscriber 有 max events/bytes 和 idle deadline，drop/close 幂等。

Durable feed 的事实来源仍是 SessionLog；provisional `AssistantDelta` 可以低延迟发布，但 envelope 必须标为 `Provisional`，最终 committed range 或 terminal replacement 用相同 domain identity 关联，cold replay 只承诺 committed events。Feed 不替代 `SessionObserver`：observer 是 composition 内部、非可靠的 committed notification；feed 是公开、bounded、可检测 gap 的 Host projection。`session_query()` 只在 composition 选中 `cap:session-query` 时返回 read-only handle，否则 `UnsupportedOperation`；它不能 append、prepare writer、取得 lease 或执行 recovery repair。每个 query request 固定 max items/bytes；event/projection cursor 固定 backend/store generation、Session identity 与 captured committed event high-water，session-list cursor 则固定 backend/store generation、captured session-index high-water 与 stable ordering key。后续页必须读取同一 snapshot，过期、backend/store/Session 不匹配返回结构化 `SessionQueryError`，不能静默换到最新 snapshot。App/Agent shutdown 先阻止 child publisher 注册新事件并 drain 当前 producer，再由 runtime-owned feed publisher发送唯一 `Closed` 后关闭 registry，晚到 callback 不得触达已关闭 subscriber。

`AgentOwnerContext` 绑定调用方 owner 与 factory 的 structural owner。任一 owner teardown 都触发同一个 `AgentLifecycle`；并发 `shutdown()` caller 共享同一个 in-flight teardown attempt 和 terminal success。若持久化 flush/lease release 返回 status unknown，attempt 返回同一结构化非终态错误但 lifecycle 保持 `Closing`；后续幂等 retry 只解析/重复同一 backend operation，确认后发布唯一 terminal success。Factory 必须跟踪其创建的全部 live lifecycle，App shutdown 不依赖外部 holder 主动释放 handle。

每个 owner 还持有不可伪造、只能衰减的 `AgentAuthority`；它不是 runtime service locator，也不能增加 binary 中不存在的 binding：

```rust
pub struct AgentAuthority {
    _private: (),
    effect_ceiling: SecurityEffects,
    allowed_bindings: AuthorityBindingSet,
    allowed_registry_keys: AuthorityRegistrySet,
    allowed_contributors: AuthorityContributorSet,
    resource_namespaces: AuthorityResourceNamespaceSet,
    confinement_ceiling: Option<SandboxPolicyCeiling>,
    resource_budget: AgentResourceBudget,
}

/// 只表达删除 key/contributor、增加 deny 和降低数值上限；不接受 allow-add。
pub struct AuthorityAttenuation {
    deny_effects: SecurityEffects,
    remove_bindings: AuthorityBindingSet,
    remove_registry_keys: AuthorityRegistrySet,
    remove_contributors: AuthorityContributorSet,
    confinement: Option<SandboxPolicyAttenuation>,
    resource_limits: AgentResourceLimitAttenuation,
}

pub enum SessionMode {
    None,
    NewEphemeral,
    NewDurable,
}

pub enum AgentOperationDraft {
    Create {
        session_mode: SessionMode,
        /// Required exactly for NewDurable; forbidden for None/NewEphemeral.
        recovery_key: Option<AgentOperationRecoveryKey>,
        authority: AuthorityAttenuation,
    },
    Resume {
        session_id: SessionId,
        recovery_key: AgentOperationRecoveryKey,
        authority: AuthorityAttenuation,
    },
}

pub enum AgentOperationSealError {
    UnsupportedOperation,
    OwnerClosed,
    OwnerMismatch,
    AuthorityEscalationDenied,
    RequiredBindingUnavailable,
    IncompatibleComposition,
    StoredStateUnavailable,
    InvalidRecoveryKeyMode,
    ResourceNamespacePreparationFailed,
}

pub enum AgentOperationKindError {
    CreateExpected,
    ResumeExpected,
}

/// 完成 owner/request-specific projection 后的 opaque、不可变草稿。
pub struct SealedAgentOperationDraft { /* private projected request + prepared anchors */ }

/// 已绑定 operation id 与 sealed request fingerprint 的 opaque capability。
#[derive(Clone)]
pub struct AllocatedAgentOperation { /* private id + sealed draft */ }

impl AllocatedAgentOperation {
    pub fn operation_id(&self) -> AgentLifecycleOperationId;
    pub fn request_fingerprint(&self) -> Digest;
    pub fn intent(&self) -> &AgentLifecycleOperationIntent;
    pub fn into_create_request(self) -> Result<CreateAgentRequest, AgentOperationKindError>;
    pub fn into_resume_request(self) -> Result<ResumeAgentRequest, AgentOperationKindError>;
}

pub struct CreateAgentRequest {
    _private: (),
    operation: AllocatedAgentOperation,
}

pub struct ResumeAgentRequest {
    _private: (),
    operation: AllocatedAgentOperation,
}
```

`AgentAuthority` 不实现 `Serialize/Deserialize`，也没有 public constructor。`AuthorityAttenuation` 提供 deny-only builder（`empty/deny_effects/remove_binding/remove_registry_key/remove_contributor/attenuate_confinement/lower_resource_limits`）；每个方法只累加删除或取更小上限。删除 binding 必须由 runtime 同时删除它拥有的 resource-namespace entry；attenuation 没有单独添加、替换或删除 namespace 的 API，因而不能留下一个仍可调用却不再绑定资源身份的 binding。Generated composition 再导出只接受当前 compiled capability/key/contributor 的 typed draft builder；WASM DTO `deny_unknown_fields` 并由 generated table 做相同校验。这样 Rust/JS Host 都有可用 draft 构造路径，但没有字符串 `allow`、resource rebind 或 authority 反序列化后门。

`AgentOperationDraft`不接受正向`allow`、provider class name或任意config map。Durable variant必须携带Host pre-journaled或parent-derived `AgentOperationRecoveryKey`，volatile variant禁止；Session mode、identity、key与authority在seal时一起验证。首次普通输入必须在handle发布且对应durable create/resume terminal success已确认后通过有界`AgentSendRequest`进入，不能把权限提升或隐式执行藏入provider-specific create payload。`CreateAgentRequest`/`ResumeAgentRequest`字段私有，只能由exact `AllocatedAgentOperation::into_create_request/into_resume_request`消费构造；因此allocation后无法替换mode、Session、attenuation、projected route、namespace commitment或key。Operation id的首次签发只能来自将执行初次调用的`AppHandle` allocator，或sole `subagent-in-process` self edge上与exact parent owner绑定的`ChildAgentFactoryBinding` async/fallible allocator。

Durable reservation在id可见前已经携带recovery key与完整request fingerprint。Host-root调用在seal/allocation前持久化key/canonical draft，取得id后再补写id/fingerprint且在create/resume前确认；in-process Durable child provider则先在parent canonical operation projection中固定/派生child key，same-key allocation取回或创建exact id，再补写`SubagentOperationId → AllocatedAgentOperation/request fingerprint`映射，才可调用create/resume。Genesis/ResumePrepared原子消费exact reservation并由`AgentCreationCompleted`或`AgentResumePrepared/Completed/Failed` operation index继续关联；token绑定StoreIdentity、issuer generation、recovery key、composition/catalog与sealed request而不绑定易失App instance nonce。Process-loss后尚无id时以same-key重新seal/allocate取回persistent token，已有id时以fingerprint exact相等的draft recover；不能跨store/key/composition/catalog/request使用。Same id/same canonical request的live retry join同一construction/result，不同key/fingerprint返回`OperationConflict`。Allocation/locator unknown不得换key、process-local id或自动创建第二个Agent。Volatile operation不进入该cold-recovery协议且不能跨process replay。

App root authority 由 generated composition 的 `component_runtime_effects`、binding identities/provider keys/contributor sets、resource-namespace descriptors、build confinement ceiling 与 generated RuntimeConfig 的更窄限制构造；Host entry/export helper 的 boundary effects 不进入 AgentAuthority，build requirements/BuildExecutionPolicy 也不进入 runtime authority。`AppHandle::seal_agent_operation`只能相对 root authority应用 draft attenuation；内部 `AgentFactory::seal_operation`只能相对 `AgentOwnerContext`中的 parent authority应用 attenuation。Self-factory路径的 `ChildOwnerContext`额外密封 binding已验证的 exact attenuation与 projected child-authority digest；factory要求 draft authority逐字节规范化后与该 seal匹配并使用同一 projection，不能在 allocate/create/resume阶段二次选择或换 attenuation。Durable genesis记录 authority epoch 0的完整 effective authority descriptor与 projection digest；resume seal使用 `latest committed stored authority ∩ current owner authority ∩ draft attenuation`，永不因新 runtime config或新 caller恢复历史上未授予的 key/effect/resource namespace。

每次 Durable resume 都必须在 `before_publish` validation 通过之后、scope publication 之前，以 stable lifecycle operation id 追加并确认 Required `AgentResumePrepared`，记录 operation id、canonical request fingerprint 与所用 authority epoch；若交集更窄，同一 atomic batch 还先记录 `AgentAuthorityEpochStarted` 的 monotonic epoch、完整规范化 descriptor 和 projection digest。Prepared 失败或 commit unknown 未解决时不发布 Agent；publication/activation 成功后、打开任何 Agent admission 前还必须追加并确认同 operation id 的 Required `AgentResumeCompleted`。Prepared 之后的 publication/activation/completion-commit failure 必须以稳定 terminal batch id 追加并确认 Required `AgentResumeFailed`；`before_publish` veto 发生在 Prepared 前，因此不创建 resume operation event。Terminal commit unknown 未解决时关闭 admission、撤销 publication 并进入 `RecoveryRequired`。

Same operation id 的 retry 只解析原 prepared + exact terminal 状态，不追加第二次 attempt；同 id/different fingerprint 返回 `OperationConflict`。同一 effective descriptor 复用 latest authority epoch。后续 `RequestPrepared` 引用 authority epoch + digest，旧 request 仍按当时 epoch 重建。Descriptor 只含 capability/binding/provider identity、effects、数值 budget、resource-namespace commitment 与 confinement policy digest，不含 secret、credential value 或实际 filesystem path。

凡 provider 的 RuntimeConfig/HostBindings 选择可寻址资源根、tenant/account、bucket/prefix、database 或其它 authority-bearing namespace，其 Capability provide metadata 必须把 `resource-namespace = { mode = "required", bootstrap = "<provider-key>" }` 声明为 binding ABI 的一部分；`fs-read-local`/`fs-local` 的 workspace root 固定属于此类并选择已审计 local bootstrap provider。Generated build 必须使用第 3 节的异步 pre-identity resource-namespace preparation ABI：先以 compiled/root 或 exact child template authority 做 monotonic bootstrap projection，再仅为仍获授权的 binding 经 stamped `cap:resource-namespace-bootstrap` Component 调用 locator I/O，最后从 typed config/result 产生 schema-owned `ResourceNamespaceDescriptor` 和配对 prepared value：binding/provider/bootstrap identity、封闭 resource kind，以及 `SHA-256("rust-agent-resource-namespace-v1\0" || canonical-CBOR(provider-specific normalized locator + Host-stable namespace id))`。Mandatory infrastructure、binding adapter、同步 factory 与 `before_publish` 都禁止直接 locator I/O，普通 `initialize` 只能消费已经验证并与最终 authority 配对的 prepared value。Locator 必须先解析相对路径、拒绝 symlink escape，并删除 credential/query secret；local filesystem prepared value 还必须保留 descriptor-relative root anchor 以避免 identity check 后按 raw path 重开造成 TOCTOU。持久化只保存 commitment。Host-stable id 不能替代 locator commitment，因而复用 id 但把 root 从 tenant A 改到 tenant B 仍得到不同 identity。Root/child attenuation 删除 route 时该 route 的 bootstrap 调用数必须为零；保留 route 的 preparation 失败时必须在 identity/admission 前失败并释放已经打开的 anchor。

Schema v1 对 resource namespace 只定义 runtime-owned `Exact` 比较，不接受 Component callback 或仅凭 provider 自报的 subset；同 binding 的 stored/current descriptor 必须逐字段相等。Durable resume 或 Completed cold reconstruction 发现 identity 不同，必须在 initialize/publication 前返回 `ResourceNamespaceChanged`，不能把它当成 same-composition handoff、confinement 等价或静默 rebind；显式 attenuation 可以删除整个 optional binding，但不能把旧 authority 投影到新 root。未来若要允许 prefix narrowing，必须增加版本化、封闭数据表示和 runtime 解释的 subset rule，并把 rule/version 写入 descriptor digest。该检查独立于 `cap:sandbox`/`ConfinementAuthority`，所以只有 filesystem capability、没有 subprocess/sandbox 的 profile 也受到约束。

`ChildOwnerContext`保存 parent effective authority、exact requested attenuation与 runtime验证后的 projected child-authority digest，Subagent/Job只能提交 `AuthorityAttenuation`。Canonical subset与 bootstrap projection在任何 child namespace locator I/O、新 Session/Agent identity、quota、lifecycle-operation backend transaction或 Session/Agent-scoped provider initialize前完成；请求删除不存在的 binding/key可以幂等接受，请求增加 binding/key/effect、提高 budget或放宽 confinement返回 `AuthorityEscalationDenied`。

Generated Agent scope template 保存完整 compiled binding plan，但每次 `prepare` 先确定性地产生 `AgentBindingProjection`：

```text
Compiled binding plan + parent authority + requested attenuation
  → 所有 BindingKind: 先按 capability/binding identity 应用 remove_bindings
  → Registry: 按 capability/key/effect ceiling 过滤，每个 key 保留独立 effect stamp
  → OrderedMulti: 按 provider ComponentId/effect ceiling 过滤并保持原 order
  → Tool/Command binding: 再按每个 sealed registration 的 exact effects 过滤
  → Singleton/DecoratorChain: binding 被删除或 effects 超 ceiling 时删除；Required consumer 因此失败
  → UsesIfPresent: 被删除后注入 None，不自动选择另一个未编译/未授权 provider
  → prune 不可达的 Agent-scoped Component initialization plan
  → validate every Required edge and driver/model/tool invariant
  → construct projected Agent scope
```

Projection 不运行通用 resolver、不改变 Cargo graph、不增加 Component，也不按运行时字符串 load implementation；它只能从 generated plan 删除已经编译的 provider/contributor/optional edge。Singleton 不做隐式 fallback；Registry 的 request route 只能选择 projection 后仍存在的 key。Model binding 为 `Default` mode 时 configured default 若被 projection 删除，该 Agent scope 在 publication 前失败，不能换成“第一个”剩余 key；`ExplicitPerRequest` mode 只要求 Required binding 的 projected registry 非空，并在每次 `plan_call` 校验 explicit key。Capability 若需要比“整个 binding 删除”更细的衰减，必须像 Tool/Command registration 一样在 API crate 定义 sealed item-level projection，不能由 generated code反射或猜测。`AgentBindingProjection` 的 digest、effective authority 与 provider-key set 写入 Agent genesis/每次 `AgentAuthorityEpochStarted`；`RequestPrepared` 只引用当前 authority epoch + digest。这样 Durable request 可重建，child 也不能在 resume 后恢复被移除的 route。

Authority 的 lifecycle 语义按 scope 划分。App build 先完成不产生 I/O 的 root bootstrap projection；只允许 selected namespace-bootstrap Component 在该 projection 下完成纯构造并经 stamped method 执行 locator I/O。Prepared descriptors 返回并完成 final App root authority 后，才能 construct/initialize 其它 App Component；final root authority 承担全部 selected App-scoped lifecycle effects。它们在 child Agent 创建前可能已经发生，child attenuation 不能追溯撤销、停止或声称隔离这些 root effects。Child effective authority 约束的是该 child 可见/可调用的 binding、该 child 新建的 Session/Agent-scoped lifecycle 以及从这些 binding 发起的 request effects：若一个 App binding 的 stamped effects 含被 child deny 的 effect，该 binding 必须从 child projection 删除，但这不影响同一共享 App provider 为 root 或其它 Agent 执行已授权工作。

App-scoped provider 不得仅凭持有全局实例就替某个 child 发起未绑定到 request/owner 的外部 effect。Child-specific 操作必须接收 generated scoped facade/request authority stamp，并在每次调用验证当前 child projection；自主 App background work 只能以 App root owner 运行并记账，不能归因于某个更窄 child authority。若产品要求“child 存活期间进程内绝不发生某 effect”的强隔离，必须使用独立 process/remote composition 与 sandbox/network boundary，不能用 in-process attenuation 宣称实现。Resolver 把 lifecycle effect 保守地并入 binding stamp，是为了删除具有该实现风险的 route，不表示 child 能控制 App initialization 的历史事实。

`AppHandle` 是 native/library/Host entry/WASM wrapper 的公共控制面；其 allocate/create/resume自动使用 App root owner。只有 `subagent-in-process`通过唯一 self-factory edge取得 `ChildAgentFactoryBinding`，并以 binding验证过的 `ChildOwnerContext`依次 allocate/create或 allocate/resume；它不取得 `AppHandle`、App-root owner或可解绑的 raw factory。Job/workflow必须经 `cap:subagent`，不直接取得 factory。所有 clone共享同一 App lifecycle；shutdown关闭新建 Agent的 admission、drain factory中全部 live Agent，再销毁 App scope。

Create draft 必须显式携带 `SessionMode::None | NewEphemeral | NewDurable`；对应 build-time `agent-modes` 条目只允许 `sessionless | ephemeral | durable`。`None` 使用 `Agent(AppParent)`；后两者使用 `Session + Agent(SessionParent)`。只有 `ephemeral-creation=staged-known-outcome` 的 provider 才满足 `NewEphemeral`；Durable provider 只有同时声明并通过该 process-lifetime volatile creation route 的 conformance 时，才可另外创建不承诺 cold resume 的 ephemeral Session，否则只满足 `NewDurable`。Resume draft 总是 Durable，并在 seal/构造任何 scope前校验 stored composition hash 与 SessionEventCatalog digest。Composition 未编译对应 mode、Session template 或所需 persistence 时返回结构化 `UnsupportedOperation`，identity/catalog 不匹配返回 `IncompatibleComposition`；不得在 mode 或 composition 之间静默降级。

`rust-agent-runtime-api` 定义 publication DTO、observer contract 和 internal directory write handle；generated infrastructure 在 App scope 内拥有 `PublicationDirectory`。它保存不可延长资源生命周期的 Agent/Session identity、状态和 weak diagnostic reference；不保存新的 structural owner。`PublicationSnapshot` 是一次不可变、带 generation 的只读快照，只公开 identity、mode、published/closing 状态和配对关系，不返回可执行的裸 service；其中 published 只表示 identity/directory transaction 已可见，不表示 admission 已开放，只有返回的 AgentHandle/其 status 能确认 Ready。对 NewEphemeral，published 也不表示 staged genesis 已进入 authoritative event/query/session index；observer 若需要该保证只能等待对应 handle Ready，不能从 notification 自行推断。所有 clone 的 AppHandle 读取同一 directory；Agent/Session 实际存活仍由 factory lifecycle、owner 与 handle 决定。`AppScopeBuilder` 在 generated assembly boundary 创建唯一 directory/write handle 并把 write handle owned 地交给 generated AgentFactory；它不进入 Capability binding、Component Dependencies 或 Host API，普通 Component 无法取得实际 App directory 的写权限。

Creation/disposal extension 是 App-scoped OrderedMulti capability：

```rust
pub struct LifecycleNotificationContext { /* private monotonic deadline + cancellation */ }

impl LifecycleNotificationContext {
    pub fn cancellation(&self) -> CancellationToken;
    pub fn is_expired(&self) -> bool;
    pub fn remaining(&self) -> Duration;
}

pub trait LifecycleObserver: MaybeSendSync {
    fn before_publish(
        &self,
        event: &PublicationCandidate,
        view: &PublicationTransactionView<'_>,
    ) -> Result<(), PublicationVeto>;

    async fn published(
        &self,
        context: LifecycleNotificationContext,
        event: &PublicationEvent,
        snapshot: &PublicationSnapshot,
    ) -> Result<(), LifecycleObserverError>;

    async fn disposed(
        &self,
        context: LifecycleNotificationContext,
        event: &DisposalEvent,
        snapshot: &PublicationSnapshot,
    ) -> Result<(), LifecycleObserverError>;
}
```

`before_publish` 同步、确定、禁止 I/O、禁止启动任务、禁止持久化传入引用，只能校验 candidate 与 transaction view；第一个 veto 中止 publication。`published/disposed` 是 commit 后异步通知，只能由 runtime-owned bounded lifecycle-notification dispatcher 调用；factory/teardown 只完成 infallible enqueue，不等待 listener completion。Directory transaction 在 commit 前为 published batch 和该 entry 将来的 disposed batch 预留容量；无容量时在 durable commit/publication 前失败，commit 后不得因队列满阻塞或丢失 paired enqueue。Dispatcher 按 notification generation，再按 metadata `order, component_id` 固定排序。

`LifecycleNotificationContext` 由 runtime 构造，携带 per-callback monotonic deadline 与 cancellation；callback 必须 cooperative、禁止 blocking I/O/无限 CPU loop/未托管 task，异步 I/O 必须受该 context 的 deadline/cancellation 约束。Dispatcher 在 `runtime.lifecycle_observer_timeout_ms` 到期时取消并 drop callback future，记录 timeout telemetry 后继续下一个 observer；error 同样隔离，二者都不能否决、重试、延迟 activation/teardown 或改变 directory state。Observer panic containment 只在 effective Rust panic strategy 为 `unwind` 且 target 支持 unwinding 时成立：只要 resolution 选中至少一个需要 runtime 隔离 panic 的 in-process `cap:lifecycle-observer` **或** `cap:session-observer` contributor，composition manifest 就必须记录 `requires_panic_unwind = true`，generated root 必须包含 `#[cfg(not(panic = "unwind"))] compile_error!(...)`，standalone build 与 library Host 的 pre/build/post evidence 也必须记录并验证 effective panic strategy；最终 Host 选择 `panic = "abort"`、rustc flag 覆盖为 abort 或 target 无 unwind 支持时必须在 build/verification gate 失败，不能生成声称具备 containment 的 artifact。Unwind-capable build 中，runtime 在 observer 的同步调用/future construction、每次 poll 以及取消/drop 外层设置 `catch_unwind` boundary；`before_publish` panic 作为 fail-closed validation error 中止尚未提交的 transaction，post-commit lifecycle/Session observer panic 只记录诊断并继续对应 dispatcher。没有这两类 in-process observer 时不声明这项 panic containment；需要支持 abort-only target 的不可信 observer 必须移到独立 process/Host observer bridge。App shutdown 对 dispatcher 只执行有界 drain，deadline 后取消剩余通知并记录 dropped diagnostics，不得延长资源释放。无法满足 cooperative async contract 的 observer 也不能作为 in-process Component。`PublicationEvent`、`DisposalEvent` 与 `PublicationSnapshot` 是 dispatcher-owned immutable values，不借用即将释放的 scope resource；`PublicationTransactionView` 仍只在 `before_publish` 回调栈内借用待提交的完整 Session/Agent 对，不能被保存，普通 `publication_snapshot()` 在线性化 commit 前看不到 candidate。

### Agent publication transaction

创建/恢复必须遵守：

```text
Prepare optional Session / Agent identity
        ↓
Create unpublished Agent scope
        ↓
Construct scoped dependencies
        ↓
Initialize providers without admitting externally triggered work
        ↓
Validate publication invariants
        ↓
Stage complete Session/Agent directory transaction
        ↓
Run ordered before_publish validation
        ↓
Commit NewDurable genesis or Durable resume Prepared transaction;
keep NewEphemeral genesis transaction staged and query-invisible
        ↓
Atomically publish one directory generation
        ↓
Enqueue contained published notification batch (nonblocking)
        ↓
Activate behind closed ScopeAdmissionGate
        ↓
Commit and index NewEphemeral genesis, or commit
AgentCreationCompleted / AgentResumeCompleted
(Durable new operation only; skip terminal for Completed cold reconstruction)
        ↓
Open AgentDriver/command admission
        ↓
Return AgentHandle
```

`NewEphemeral/NewDurable` 的 directory transaction 必须包含同一 identity 的完整 Session/Agent 对；所有 `before_publish` observer 通过 transaction view 看到完整 candidate，而普通 reader 仍看到旧 generation。全部 validation，以及适用的 NewDurable genesis/Durable resume Prepared commit 成功后，以一次线性化 map swap 发布新 generation；NewEphemeral 此时仍只持有 query-invisible staged genesis。随后按 `session/created → agent/created → agent/session-start` enqueue 一个 contained `published` batch；Sessionless mode 只含 Agent entry 和 `agent/created`。`before_publish` veto 不产生 published/disposed notification；directory 已发布后 activation 或 NewEphemeral genesis/index commit 失败，必须以一次原子 generation 更新删除完整配对，并按已发布 edge 的逆序 enqueue contained disposal batch。这里的顺序约束是 dispatcher delivery order，不要求 callback 在 activation/teardown 前完成。

NewEphemeral/NewDurable 的 Session genesis batch 在 prepare 阶段都只存在于 backend transaction，但 publication 时序不同。NewEphemeral 的 genesis transaction 必须一直保持 staged，且不得进入 authoritative event view、session index、`SessionQueryHandle` cursor/high-water 或其它 query projection；directory map swap 和 gated activation 成功后，才把 genesis 与 session-index insertion 作为一个 known-outcome atomic commit 发布，确认 committed 后才开放 admission。NewEphemeral route 因而只允许提供 atomic staged commit 且不会返回 `CommitStatusUnknown` 的 process-lifetime backend；Durable provider 若同时满足 NewEphemeral，也必须为该 route 提供这种 query-invisible volatile transaction，而不能提前复用 durable authoritative index。任何 veto、publication、activation 或 ephemeral commit failure 都 abort staged genesis，并撤销 directory pair，所以 rollback 后不存在 genesis-only、无 live owner 的 authoritative Session，也不需要 persistence deletion API；NewEphemeral 不写 `AgentCreationCompleted`，process loss 后仍不能 cold recover。

NewDurable genesis 则在 directory map swap 前原子写入，使用由 SessionId/create-operation id 派生的稳定 EventBatchId，记录 canonical create fingerprint，并且只有确认 durable committed 后才能 map swap；`CommitStatusUnknown` 必须先读回解析，不得将其当作 abort。Backend commit 前的 veto/failure 可以 abort transaction；genesis 一旦 durable 就不删除/改写。NewDurable publication/activation 成功后、admission 开放前必须用从 create-operation id 派生的稳定 batch id 追加并确认 Required `AgentCreationCompleted(operation_id, incarnation_generation)`。若 genesis 后 directory swap、activation 或 completion commit 确认失败，rollback 必须以另一稳定 terminal batch id 追加并确认 durable `SessionEnded(CreationFailed, operation_id, phase, normalized_reason)` 后关闭 writer lease；Completed 与 CreationFailed terminal 互斥，commit unknown 先解析，不得双写 terminal。

Cold recovery 看到 Durable genesis 没有 creation terminal 时，因为 admission 不可能在 `AgentCreationCompleted` 前打开，执行同一 deterministic `SessionEnded(CreationFailed::InterruptedBeforeAdmission)` closure；该 closed artifact 可审计但不能被普通 `resume` 当作成功创建的 Agent。看到 `SessionEnded(CreationFailed)` 时，same create operation/same fingerprint 永久返回由 terminal phase/reason 重建的 `CreationOperationFailed`，不得重新执行 construction；different fingerprint 仍返回 `OperationConflict`。看到 `AgentCreationCompleted` 时，same create operation/same fingerprint 可在 stored initial authority 仍被 current root owner 完整覆盖时重建 in-process incarnation；重建失败不改写 Completed terminal 并可重试。若 current owner 只能给出更窄 authority，则 create retry 返回携带 stored SessionId 的 `AuthorityChangedForCompletedOperation`，Host 使用该 SessionId 与新 resume operation 显式降权。这样成功但尚无首个业务事件的 idle Durable Session 不会被误判为 creation failure。NewEphemeral genesis 只在 activation 成功后进入 process-lifetime authoritative view，没有 durable terminal，process loss 后不能 cold recover。

Durable resume 使用独立的三态 operation protocol：

```text
absent
  → AgentResumePrepared(operation_id, fingerprint, authority_epoch, projection_digest)
  → AgentResumeCompleted(operation_id, incarnation_generation)
  | AgentResumeFailed(operation_id, phase, normalized_reason)
```

三类事件分别使用从 operation id + terminal kind 派生的稳定 EventBatchId；一个 prepared 最多有一个 terminal，Completed/Failed 互斥，重复或乱序 terminal 使 SessionLog 损坏并拒绝 resume。`AgentResumePrepared` 与可能的新 authority epoch 在同一 atomic batch 中提交。Prepared committed 后才允许 publication；activation 在 generated `ScopeAdmissionGate` 关闭状态下执行，成功后提交 `AgentResumeCompleted`，只有确认 Completed committed 才打开 Agent/driver/command ingress 并返回 handle。任何 Activatable 只能准备 idle worker、buffered listener 或其它仍受 gate 阻挡的资源，不得自行绕过 gate 接受外部业务请求。Failed terminal confirmed 后同 operation id 永久返回同一结构化 failure；显式的新 resume 必须使用新 operation id。

Cold recovery 取得新的 exclusive writer lease 并解析 operation index：只有 Prepared、没有 terminal 时，因为 admission 从未能在 Completed 前打开，固定追加 `AgentResumeFailed(InterruptedBeforeAdmission)`，完成 teardown/recovery 后允许 Host 用新 operation id 再次 resume；Completed 表示同一 logical resume operation 已越过 durable admission checkpoint，旧进程由 writer fencing/owner loss 视为死亡。Same id/same fingerprint 只有在 stored completed effective authority 仍完整属于 current root/owner authority 时，才可以在不追加第二个 Prepared/Completed 的情况下按该 exact descriptor 重建新的 in-process incarnation并返回 handle；若 current owner 只能给出更窄交集，则返回 `AuthorityChangedForCompletedOperation`，Host 必须用新 operation id 发起显式更窄 resume，从而提交新的 authority epoch 和完整三态 operation。Completed cold reconstruction 已有不可逆 success terminal；其 construct/initialize/publication/activation 失败只撤销本次 in-memory incarnation并返回 `CompletedOperationReconstructionFailed`，保持原 operation Completed、admission 关闭，允许 same id 再次恢复，绝不能再追加 Failed。Failed terminal 返回原失败；它结束本次 live resume attempt，但不追加 `SessionEnded`，Durable Session 在释放失败 incarnation/writer lease 后仍可用新 operation id resume。任一 terminal 状态仍 unknown 时不构造或发布 scope。这样 operation id 提供 durable idempotency，而 fencing generation 区分 process incarnation；它不声称复用已经死亡的内存 handle，也不让 completed retry 静默改变历史 authority。

任一步失败：

```text
close admission
→ stop activated work
→ if published, atomically remove the complete directory pair
→ enqueue exactly-once paired disposal notification batch for removed entries
→ reverse-shutdown scoped resources
→ release unpublished optional session/provider state
```

未进入 directory 的失败跳过 remove/notification；已发布失败必须先使整对 entry 对普通 snapshot 不可见，再销毁它们引用的 scope resources。

### driver-direct

Required：

```text
cap:model (BindingKind::Registry)
```

每次 model call 必须先让 model consumer binding 以纯 `plan_call` 固定 route/defaults，再调用 generated `AgentContext::prepare_model_call`，最后把 `PreparedModelCall` 交回同一 binding；这条 generated request-journal path 对所有 creation mode 都存在，Durable route 会在 stream 前提交 Required `RequestPrepared`。

不要求：

```text
cap:tool-executor
cap:tool-provider
cap:session-log
cap:prompt-assembly
cap:memory
```

这里“不要求 `cap:session-log`”仅表示 `driver-direct` 没有可选的 direct capability dependency，不表示 Durable model call 可跳过 journal。Sessionless route 使用 volatile journal；Ephemeral/Durable route 的 generated AgentContext 从 parent Session scope 取得强制 SessionLog facade。Minimal profile 仍可以完全没有 Session plane。

### driver-tools

Required：

```text
cap:model
cap:tool-executor
```

可按 composition 使用：

```text
cap:session-log (UsesIfPresent)
cap:prompt-assembly (UsesIfPresent)
cap:conversation-compaction (UsesIfPresent)
cap:tool-result-pruner (UsesIfPresent)
cap:token-meter (UsesIfPresent)
cap:telemetry (UsesIfPresent)
```

这里的 optional `cap:session-log` 只服务 driver-tools 自身额外的 turn/tool domain event 行为；所有 model call 的 `RequestPrepared` 和所有 model-origin `ToolCall` checkpoint 始终通过不可替换的 AgentContext request journal，不能因 optional binding 为 `None` 而跳过。Driver 只能取得带 paired tool verifier 的 model-origin `ToolExecutionSession`，固定执行 `plan_call → AgentContext::prepare_tool_call → seal → execute_prepared`；它不能取得 Command/Nested 使用的 raw borrowed session，也不能把 optional SessionLog 当成另一条 journal authority。

### Tool loop production state machine

```text
TurnStart
  ↓
AssembleRequest
  ↓
ModelCall
  ↓
ToolCalls?
  ├─ No → AssistantComplete → TurnEnd
  └─ Yes
       ↓
     Classify Calls
       ↓
     ToolCall journal checkpoint + paired proof
       ↓
     ToolExecutor guarded pipeline
       ↓
     Dispatch bounded parallel-safe groups
       ↓
     Commit results in model order
       ↓
     Next Step
```

必须保留的语义：

- cancellation 是有原因的协作式 lineage；
- stop 后不再启动新 side effect；
- 已启动操作必须 drain 到已定义 quiescence，或由 provider 明确 kill/abort；
- exclusive resource key 形成 barrier；
- parallel-safe calls 使用 bounded concurrency；
- result commit 保持 model order；
- model stream partial output 与中断一致；
- 未 dispatch 的 tool call 在 durable replay 需要时生成稳定 aborted/interrupted 结果；
- loop failure 结束当前 turn，不必摧毁 Agent service 生命周期；
- durable turn/step boundary 与 SessionLog 保持一致。

## 7. Session：事件溯源与可重建性优先

Session 不是数据库，也不是 UI conversation cache。对于启用 durable session 的 composition：

> **SessionLog 是 Agent interaction 的 append-only typed event source of truth。**

第一版 canonical event vocabulary：

```rust
pub enum SessionEvent {
    SessionStarted(...),
    AgentAuthorityEpochStarted(...),
    AgentCreationCompleted(...),
    AgentResumePrepared(...),
    AgentResumeCompleted(...),
    AgentResumeFailed(...),
    AgentBehaviorModeChanged(...),
    TurnStarted(...),
    StepStarted(...),
    UserMessage(...),
    ConversationCompacted(ConversationCompactionRecord),
    RequestPrepared(ModelRequestRecord),
    AssistantDelta(...),
    AssistantMessage(...),
    SessionTitleUpdated(...),
    ToolCall(...),
    ToolResult(...),
    UserInteractionAsked(UserInteractionAskedRecord),
    UserInteractionAnswered(UserInteractionAnsweredRecord),
    UserInteractionAcknowledged(UserInteractionAckRecord),
    UserInteractionClosed(UserInteractionTerminalRecord),
    CommandInvocationPrepared(CommandInvocationPreparedRecord),
    CommandInvocationDispatchPrepared(CommandInvocationDispatchRecord),
    CommandInvocationFinished(CommandInvocationTerminalRecord),
    SubagentOperationReserved(...),
    SubagentOperationStateChanged(...),
    SubagentLinked(...),
    JobStateChanged(...),
    WorkflowStateChanged(...),
    Extension(ExtensionSessionEvent),
    StepEnded(...),
    TurnEnded(...),
    SessionEnded(...),
}
```

```rust
pub struct ConversationCompactionRecord {
    schema_version: u32, // schema v1 必须等于 1
    compactor: ComponentId,
    input_history_boundary: SessionSequence,
    input_history_digest: Digest,
    replacement: BoundedModelHistory,
}
```

`ConversationCompacted` 是 `rust-agent-session` 拥有的 canonical Required event，不是 Component extension event。`replacement` 使用与 model message 相同的 canonical typed content，encoded bytes 最多 256 KiB、container depth 最多 16；unknown version、越界、digest/boundary 不匹配全部拒绝 append/load/resume。只有当前 Agent/Session 的 generated durable journal facade 可以从 `CompactionResult` 构造并 append 该 event；`compaction` Component 只返回结果，不能以自己的 extension namespace 或绕过 journal facade 写 SessionLog。Projection 以已提交 event 的 sequence 作为新的 history boundary，并用 replacement 加其后的 canonical events 重建 model history。

`AgentCreationCompleted` 与 `AgentResumePrepared/Completed/Failed` 是 rust-agent canonical Required lifecycle events，不是 extension event。SessionLog 为 create/resume 维护按 `AgentLifecycleOperationId` 的 durable operation index，并在 append/load 时验证 canonical fingerprint、authority epoch、stable batch-id derivation、genesis/Prepared-before-terminal、terminal uniqueness 与 success/failure 互斥；缺失 genesis/Prepared 的 terminal、同 id 不同 fingerprint、重复 terminal、success 后 failure 或 failure 后 success 均视为损坏/冲突并 fail closed。`incarnation_generation` 来自当前 exclusive writer fencing generation，用于诊断和防 stale writer，不改变 logical operation id。

`SubagentOperationReserved`/`SubagentOperationStateChanged` 同样是 runtime canonical Required events，用于 Durable parent的 subagent operation issuer与恢复表，不是任意 Component extension event。其无 extension-api依赖的 record DTO归 `rust-agent-runtime-api`：Reserved固定 stable parent lineage、durable recovery key、exact provider binding identity/key、`SubagentOperationId` canonical bytes、完整 request fingerprint与预算 reservation；StateChanged只允许按同 id从 `Reserved → DispatchPrepared → Accepted/OutcomeUnknown → terminal`推进，并可固定 `subagent-in-process`的 child `AgentLifecycleOperationId`/fingerprint映射。`DispatchPrepared`是在跨 raw provider/transport boundary**之前**确认 committed的不可逆意图 checkpoint，不宣称 provider已接受；Prepared-only recovery只能按同 id查询/安全续接或进入OutcomeUnknown，不能盲目首次/再次发送。`rust-agent-extension-api::SubagentOperationId`只包装/re-export该 opaque shared identity，不反向进入 session public type closure。SessionLog在 append/load时验证 stable batch-id derivation、recovery-key/id/provider/fingerprint uniqueness、合法状态迁移和 terminal唯一性；同 recovery key或id绑定不同 payload/provider属于 corruption/conflict。普通 provider不能直接构造这些事件，只有 generated Durable subagent-operation journal facade可以追加。

`CommandInvocationPrepared`/`CommandInvocationDispatchPrepared`/`CommandInvocationFinished` 是 runtime canonical Required events。其无 command-handler 依赖的 record DTO 归 `rust-agent-runtime-api`：Prepared 固定 exact `CommandInvocationId`、registered command/snapshot identity、caller/auth-context、bounded canonical args digest、authority epoch、declarative effect/exclusive-key 结果、deadline/cancellation lineage 与完整 request fingerprint；DispatchPrepared 只能在同 fingerprint 的 Prepared 之后出现，并表示 runtime 即将越过 raw `Command::execute` boundary，不表示 handler 已产生结果；Finished 固定 `Succeeded | Failed | Cancelled | InterruptedBeforeDispatch | OutcomeUnknown` 之一及有界 redacted result/error digest。状态只允许 `Prepared → DispatchPrepared → Finished` 或 `Prepared → Finished(InterruptedBeforeDispatch)`，terminal 唯一且不可互换。SessionLog 在 append/load 时验证每种 operation-kind 的 stable batch id、identity/fingerprint continuity 与状态迁移；只有 generated command journal gate 可以构造这些事件。

`UserInteractionAsked`/`UserInteractionAnswered`/`UserInteractionAcknowledged`/`UserInteractionClosed`也是runtime canonical Required events。其无Host callback/driver依赖的id、bounded answer与record DTO归`rust-agent-runtime-api`，`rust-agent-session`只引用这些lower-level定义。Asked固定stable `UserInteractionId`、expected `UserAnswerOperationId`、question/schema/options digest、model-visible placement与authority/driver coordinate；Answered固定同一answer operation、provider submission fingerprint及有界typed answer；Acknowledged只在Host provider确认matching operation/fingerprint的commit ack后记录；Closed只表达无answer的cancelled/failed terminal。状态只允许`Asked → Answered → Acknowledged`或`Asked → Closed`；Answered/Closed互斥，Acknowledged缺Answered、wrong fingerprint、重复冲突ack均fail closed。Same operation + same fingerprint幂等，不同answer冲突。只有generated interaction journal facade可以构造这些事件；影响后续model input的answer必须先成为confirmed `UserInteractionAnswered`，不能藏在provider callback、driver局部变量或informational extension event中。

External/Integrator Component 的 durable event 使用 build-time 声明、runtime 静态校验的扩展 envelope，不修改 Rust enum ABI：

```rust
pub struct ExtensionSessionEvent {
    producer: ComponentId,
    kind: SessionEventKind,
    payload_version: u32,
    criticality: RecordCriticality,
    payload: BoundedJsonValue,
}
```

Component metadata 的 `session-events` 为每个 kind 声明 payload version、criticality、maximum bytes/depth 和 `affects-reconstruction`。Kind 固定为 `<component-id>/<local-kind>`；Component 只能产生自己 namespace 下的 kind。Composition Compiler 在 `session_events.rs` 生成封闭 `SessionEventCatalog`，并以 generated-only App-scoped `cap:session-event-catalog` 注入 `session-log-events`，以及在选中时注入 `session-query-events`；SessionLog 在 append、load 和 resume 时校验，query provider 在 event/projection read 时校验。未知 producer/kind/version、超过上限、envelope criticality 与 catalog 不一致或声明不一致全部拒绝。Catalog 是 generated match/table，不支持 runtime 注册、动态 native type load 或任意 serde type registry。影响 Component durable state 或后续 model-visible input 的事件必须 `Required + affects-reconstruction=true`；已被当前 catalog 验证为 Informational 的事件可以被不关心它的 projection 跳过，但 SessionLog/query projection 不得依据未知 envelope 自报的 `criticality` 跳过未知事件。

第一版 resume 只接受 Session genesis、每个 `RequestPrepared` 与当前 generated identity 中完全相同的 composition hash 和 `SessionEventCatalog` digest。因为 composition identity 已固定 selected producer 与 event vocabulary，同 hash resume 时声明 Required 事件的 producer 必须仍 selected；出现未知事件表示损坏、伪造或 identity/catalog 不一致，必须拒绝。跨 composition hash 的事件迁移不属于第一版 runtime resume；未来只能通过独立、版本化、离线验证的 migration/import 协议创建新 Session seed，不能在 `resume()` 内隐式转换旧日志。

`rust-agent-session` 定义只读 `SessionEventCatalog` 与 `SessionEventCatalogBinding`；binding 内部仅持有 generated static declaration slice，不提供 insert/register API。`session_events.rs` 用 const/static constructor 物化排序后的 declaration，generated App builder 把同一 binding 注入每个 SessionLog factory和 selected `session-query-events` factory。Extension event constructor 接收 local kind 而不接收可自由设置的 producer；generated Component dependency wrapper 固定 producer `ComponentId`，SessionLog 在持久化前用 catalog 派生完整 kind 并验证声明。该 wrapper 只是防误用的 typed API；对恶意 in-process Component 的信任边界仍遵循第 33 节。

```rust
pub trait SessionLog: MaybeSendSync {
    async fn append(
        &self,
        batch: NewSessionEventBatch,
        durability: AppendDurability,
    ) -> Result<AppendOutcome, SessionError>;
    async fn resolve_batch(
        &self,
        batch_id: EventBatchId,
    ) -> Result<BatchCommitStatus, SessionError>;
    async fn read_page(&self, request: EventPageRequest) -> Result<EventPage, SessionError>;
    async fn flush(&self) -> Result<(), SessionError>;
}

pub enum AppendOutcome {
    Committed(EventRange),
    NotCommitted,
    CommitStatusUnknown(EventBatchId),
}

pub enum BatchCommitStatus {
    Committed(EventRange),
    NotCommitted,
    CommitStatusUnknown(EventBatchId),
}
```

`NewSessionEventBatch` 必须带由业务操作派生的稳定 `EventBatchId`；同 id 重试只能对应完全相同的 canonical event bytes，已提交时返回原 `EventRange`，bytes 不同时拒绝。`AppendDurability::Buffered` 在 backend transaction commit 后返回 `Committed`；`AppendDurability::Durable` 只在 commit 通过 writer fencing 且 durable flush 后返回 `Committed`。I/O 失败能证明 transaction 未提交时返回 `NotCommitted`；无法确定时返回 `CommitStatusUnknown(batch_id)`，调用方必须用 `resolve_batch` 读回 committed batch index，不得换 id 重试或假定未提交。`resolve_batch` 可以继续返回 unknown；只有持有 authoritative live-writer 或 cold-recovery lease、拒绝 stale fencing record 的 backend 能证明 batch index/range 已 durable 或 transaction 确定 absent 后，才能分别返回 `Committed` 或 `NotCommitted`。在不确定状态解决前，Agent 关闭新 turn/command admission；无法在当前进程解决时进入 `RecoveryRequired`，只能关闭并从持久 log 恢复。`flush()` 只是显式 quiescence/checkpoint API，不得用来赋予先前 Buffered append 一个无歧义的业务提交结果。

`append` 和 `read_page` 都执行配置上限；`EventPage` 返回 stable next cursor 与 observed high-water sequence，禁止以无界 `Vec` 加载完整长期会话。投影器固定读取同一 high-water snapshot，避免分页期间的新 append 改变重建边界。

`ModelRequestRecord` 固定记录 `request_id`、purpose、history boundary seq、最终 system text、完整 tool schema snapshot 与 ToolProvider snapshot versions、effective Agent behavior mode、provider key、model id、影响输出的 model params、composition identity、authority epoch、AgentBindingProjection/effective-authority digest 和所有 request-scoped model-visible contributor 结果。Agent genesis/`AgentAuthorityEpochStarted` 保存对应 epoch 可验证的完整 effective authority/projection descriptor，request record 只重复 epoch/digest 与本次 provider/tool snapshot。`ModelParams` 在写入前必须展开 provider/runtime defaults，不能让“字段缺失”在重建时重新读取当前默认值。Messages 从截至 boundary 的 log 投影；其余字段直接从该 record 恢复。Durable Agent 的 record batch 必须在 model stream 开始前确认 `AppendOutcome::Committed`；Ephemeral Agent 必须至少确认 backend transaction committed。Model provider 只能接收与刚写入 record 语义等价的请求。Credential value、Authorization/Cookie header、signed URL 和其它 secret-bearing transport field 不进入该 record；影响模型语义的非 secret protocol control 必须进入版本化 `ModelParams`，provider 不得用未记录的任意 header 改变请求语义。

### 单一写入口

普通 Agent/Tool/Driver 只能向 `SessionLog` 写领域事件：

```text
Agent / Driver / Tool
        ↓
     SessionLog
        ↓
SessionJournal (internal backend handle)
        ↓
SessionPersistenceAdmin backend
```

禁止让业务 consumer 同时持有 `SessionLog` 和 `SessionPersistenceAdmin` 两条平行 append API。

`cap:session-persistence` 的 binding 是 App-scoped backend admin factory，按 SessionId prepare 一个 unpublished `SessionJournal`；catalog 固定只允许 generated Agent/Session scope factory 与 `session-log-events` 消费。`SessionJournal` 只在 generated Session scope builder 与 `session-log-events` 之间移动，不作为普通 Capability 暴露。Persistence admin 是 SessionLog 的 backend seam，不是第二套 session domain，也不公开领域事件 append 入口。其 internal prepared-new ABI 必须支持 `abort_unpublished`；对 NewEphemeral 还必须支持 activation 后才调用的 `commit_ephemeral_genesis_and_index`，返回封闭的 `Committed | NotCommitted` known outcome，不能返回 unknown，并保证 commit 前 read-store 看不到 event、summary、index high-water 变化。查询组件只能依赖独立的 App-scoped `cap:session-read-store`，其 `SessionReadStore` facade 只提供 bounded envelope/page/index read，不提供 prepare、append、writer lease、locator mutation 或 recovery repair。每个 `session-persistence-*` Component 同时提供这两个 App-scoped capability；adapter 从同一 concrete backend 生成字段私有、权限不同的 typed binding。

NewDurable create 在返回 handle 前可能已经提交 genesis 却尚未把 `SessionId` 返回 Host，因此 persistence 必须提供按 lifecycle operation id 定位 Session 的 durable index；不能要求 Host 扫描目录或猜测 SessionId：

```rust
pub enum LifecycleOperationKind {
    Create,
    Resume,
}

pub enum LifecycleOperationLocation {
    Absent,
    Reserved {
        reservation: LifecycleOperationReservation,
    },
    Located {
        session_id: SessionId,
        kind: LifecycleOperationKind,
        reservation: LifecycleOperationReservation,
        terminal: Option<LifecycleTerminalSummary>,
    },
    CommitStatusUnknown,
}

pub trait SessionPersistenceAdmin: MaybeSendSync {
    async fn allocate_lifecycle_operation(
        &self,
        draft: LifecycleOperationReservationDraft,
    ) -> Result<AgentLifecycleOperationId, AgentOperationAllocationError>;

    async fn locate_lifecycle_operation(
        &self,
        operation_id: AgentLifecycleOperationId,
    ) -> Result<LifecycleOperationLocation, SessionPersistenceError>;

    async fn prepare_new(
        &self,
        reservation: NewSessionReservation,
    ) -> Result<PreparedSessionJournal, SessionPersistenceError>;

    async fn prepare_existing(
        &self,
        reservation: ExistingSessionReservation,
    ) -> Result<PreparedSessionJournal, SessionPersistenceError>;
}

pub enum WriterLeaseReleaseOutcome {
    Released,
    ReleaseStatusUnknown,
}

pub enum WriterLeaseStatus {
    Owned,
    Released,
    Superseded { current_generation: FencingGeneration },
}

impl PreparedSessionJournal {
    pub fn writer_lease(&self) -> WriterLeaseIdentity;
    pub async fn release_writer_lease(
        &self,
    ) -> Result<WriterLeaseReleaseOutcome, SessionPersistenceError>;
    pub async fn resolve_writer_lease_status(
        &self,
    ) -> Result<WriterLeaseStatus, SessionPersistenceError>;
}

pub struct StoredSessionListPageRequest {
    pub after: Option<SessionIndexCursor>,
    pub max_items: NonZeroU32,
    pub max_bytes: NonZeroUsize,
}

pub struct StoredSessionListPage {
    pub sessions: Vec<StoredSessionSummary>,
    pub next: Option<SessionIndexCursor>,
    pub captured_index_high_water: SessionIndexHighWater,
}

pub trait SessionReadStore: MaybeSendSync {
    async fn list_sessions_page(
        &self,
        request: StoredSessionListPageRequest,
    ) -> Result<StoredSessionListPage, SessionPersistenceError>;

    async fn read_session_page(
        &self,
        session_id: SessionId,
        request: StoredEventPageRequest,
    ) -> Result<StoredEventPage, SessionPersistenceError>;
}
```

以上 `SessionPersistenceAdmin`、`LifecycleOperationLocation`、`SessionPersistenceError`、prepared-journal/lease/read-store 类型归 `rust-agent-session`；其中 `LifecycleOperationReservationDraft`/`LifecycleOperationReservation`、`AgentLifecycleOperationIntent` 与 `AgentOperationAllocationError` 必须直接引用 `rust-agent-runtime-api` 的定义，`AgentLifecycleOperationId`/`SessionId` 引用 `rust-agent-core`。Draft/reservation字段私有且只能经 versioned checked constructor产生；constructor只负责 canonical well-formedness，不是 authority边界。真正边界是 generated scope builder密封进 factory facade的 caller stamp以及 selected admin binding对同一 stamp的验证，普通 Component/Host无法取得该 binding；session backend只读取 accessors，不能修改已收到的 draft/reservation。`rust-agent-session` 的 normal/development/all-feature Cargo graph都禁止出现 `rust-agent-agent`，generated compile fixture 对 public type closure 递归验证这一点；agent crate 只在更高层把 session error映射进 Host-facing lifecycle/shutdown error。

`allocate_lifecycle_operation` 必须接收已经完整密封且含caller-prejournaled `AgentOperationRecoveryKey`的 `LifecycleOperationReservationDraft`。Backend在store-level serialization point先查询authoritative recovery-key index：已有exact reservation就返回其原`AgentLifecycleOperationId`，已有不同fingerprint/intent/owner/projection/composition/catalog就冲突；只有Absent才在一个durability boundary增加issuer counter、从新id确定reserved Session identity，并原子写入`recovery-key → id`与`LifecycleOperationReservation`。禁止intent-only reservation、allocation后补写fingerprint或same key另配请求。`CreateDurable`的proposed SessionId固定为domain-separated `AgentLifecycleOperationId`派生值，`ResumeDurable`固定为intent中的existing SessionId；两者在首次key commit时固定，因此reservation后崩溃不能另选SessionId。其它intent不得调用该persistent allocator。

Durable persistence config必须携带Host-provisioned、对destructive reinitialize/fork永不复用的`StoreGeneration`；backend初始化时把`StoreIdentity = SHA-256(persistence resource-namespace descriptor commitment || StoreGeneration)`写入header，后续open必须exact核对，缺失/mismatch直接失败。`StoreIdentity`标识physical persistence namespace/generation，**不**等同composition identity；同一store允许包含多个composition的合法只读历史，逐Session的genesis/index header必须另存exact composition hash、SessionEventCatalog digest与event schema version。它不从clock、task runtime、random API或process-local counter猜测identity。Persistent operation id固定StoreIdentity/issuer generation/counter，所有共用store的进程由同一原子coordinator序列化，正常restart重开同一header且counter永不rollback、wrap或reuse。把旧snapshot恢复成可写store或clone成独立writer必须先经显式离线fork/import配置新StoreGeneration；复用旧generation属于unsupported deployment，旧token/key不能跨fork使用。首次allocation返回成功证明key-index与包含fingerprint/projection/plan/Session identity的reservation durable；commit/response outcome unknown返回错误，但same-key exact retry必须读回已commit id或在证明Absent后完成首次commit，不能产生不可定位reservation或第二个id。该方法是selected persistence Component的effectful binding operation；generated factory只允许`AppHandle` root facade或exact-parent-stamped `ChildAgentFactoryBinding`作为caller，mandatory infrastructure不直接读写store。

`ExistingSessionReservation` 固定SessionId、resume operation id、recovery key、canonical request fingerprint、projected authority/plan digest与composition/catalog identity；`prepare_existing`必须在取得writer lease前验证它们exact匹配`ResumeDurable { session_id }` Reserved locator，但只有后续`AgentResumePrepared` commit才把它原子转为Located。`prepare_new`对NewDurable同样验证`CreateDurable`的完整reservation并在genesis commit原子消费；NewEphemeral只验证process-local volatile token及其sealed fingerprint且不读写durable locator。`locate_lifecycle_operation`必须先校验StoreIdentity，并区分Absent、Reserved、Located与CommitStatusUnknown。`recover_operation`对Reserved或Located只在新sealed draft的recovery key/fingerprint/intent/projection/plan/composition/catalog全部相等时返回allocated capability；任何不同字段均返回conflict，且绝不能覆写原reservation。尚未取得id的recovery不调用该lookup，而是以pre-journaled same-key exact sealed draft重试幂等allocation以取回id。

`SessionIndexCursor` 是字段私有、版本化的 opaque token，固定 backend/store generation、第一页捕获的 committed session-index high-water 和最后一个稳定 ordering key；后续页必须读取同一快照，generation/identity 不匹配或 retention 已使快照不可用时返回结构化 cursor error，不能静默切到最新集合。`StoredSessionSummary` 只含由 committed canonical events/index 派生的有界只读字段，至少包括 SessionId、SessionMode、committed event high-water、optional terminal state、composition hash、SessionEventCatalog digest与 event schema version，不携带 writer lease、locator mutation 或 admin handle；这些 identity字段必须与该 Session committed genesis/header逐字节交叉验证并可从 authoritative journal重建。Provider 同时强制 `max_items` 与 `max_bytes`，按 `(creation commit order, SessionId)` 稳定排序，并维护可从 authoritative committed state 重建的 session index；正常 `list_sessions_page` 禁止扫描 session directories 或逐 Session 打开完整日志。

`session-query-events` 将 public `SessionListPageRequest` 映射到该方法并转换 cursor/error，不取得 `SessionPersistenceAdmin`。List 不把 foreign Session 伪装成损坏：每个 public summary携带 `SessionCompatibility`，identity exact相等时为 `Compatible`，composition hash或catalog digest任一不同则为 `IncompatibleComposition`，caller可以显式筛选。`read_events/read_projection` 必须先读取并核对 summary/header/genesis identity，发现 foreign identity时在解码 extension payload或运行 reducer之前返回 `SessionQueryError::IncompatibleComposition`。只有 identity声称与当前 generated composition/catalog exact相同之后，才用 `SessionEventCatalogBinding` 对 extension envelope做与 SessionLog相同的校验；此时未知 producer/kind/version、不匹配 envelope或 index/header/genesis互相矛盾才返回 `CorruptStore`。Catalog-known `Informational + affects-reconstruction=false` 可由不关心它的 projection跳过；已知 `Required` 或 `affects-reconstruction=true` 但 requested projection没有 generated reducer时返回 `UnsupportedProjectionEvent`。不得静默略过、以 current catalog解码 foreign Session，或信任 envelope自报分类。

`NewSessionReservation` 固定 proposed SessionId、allocated create operation、SessionMode、canonical fingerprint、composition/catalog identity 和 initial authority/plan digest；Durable proposed SessionId必须逐字节等于 allocated operation reservation中的派生值，其余字段必须来自同一个 sealed draft，不能由 caller逐字段换值。`prepare_new` 只建立 unpublished backend transaction。NewEphemeral transaction 可以跨 directory publication/gated activation 存活，但 `commit_ephemeral_genesis_and_index` 前不得改变 authoritative journal、batch index 或 session-list index；abort/drop 必须使其完全 absent，commit 则一次发布 genesis + batch index + session summary，并给出 known outcome。第一次 Durable genesis commit 必须在同一原子 durability boundary 中写入 Session genesis、batch-id index，并把 exact `CreateDurable` Reserved locator 转成全局 `operation_id → (SessionId, Create, complete reservation)` Located 状态；它只验证并携带 allocation时已经持久化的 fingerprint/projection/plan/Session identity，禁止在这里首次绑定或替换。Resume Prepared commit 同样把 exact `ResumeDurable { session_id }` reservation 原子转成 `(SessionId, Resume, complete reservation)`；同 operation id 缺少 reservation、reservation identity 不匹配或已定位到不同 kind/Session/fingerprint 时返回 `OperationConflict`。Terminal append 与 locator terminal summary 必须在同一 commit 更新；summary 是加速索引，load 时必须与 canonical SessionLog event bytes 交叉验证，不一致视为存储损坏。Durable backend 能证明 allocation/genesis 均未提交时返回 `Absent`，只有完整 reservation committed 时返回 `Reserved`；无法证明 authoritative state时返回 `CommitStatusUnknown` 并保持 create admission 关闭，这个 unknown outcome 不允许出现在 NewEphemeral genesis commit ABI。

JSONL v1 不允许把 per-session event file 与另一个 locator/index file 的两次 rename 宣称为原子事务。它必须使用 store-level exclusive commit coordinator/fencing lease 和一个权威 append-only commit journal：每个 checksum envelope 在同一条 committed record 内携带 SessionId、EventBatchId、event bytes/sequence range，以及可选 lifecycle locator/terminal mutation；完整 envelope 的 durable append + file/directory sync 是唯一 commit point。Per-session files、batch index、global operation locator、terminal summary 与 session-list index 都只是带 committed journal offset/generation 的派生 checkpoint，可用 same-directory temp+fsync+rename 发布，但 crash 后必须丢弃越过权威 high-water 的 checkpoint并从 commit journal 重建，不能反向把 derived index 当作提交证明。Store-level coordinator 序列化不同 Session 的 envelope commit，per-session writer lease/fencing 仍独立校验 logical owner，二者缺一不可。Open/recovery 可以顺序扫描一次 journal 建立 bounded/on-disk index；正常 `locate_lifecycle_operation` 与 `list_sessions_page` 必须走已验证 index，不扫描 session directories。不能实现该单一 commit point、跨进程 store lease、torn-tail resolution 和 deterministic rebuild 的 JSONL provider 只能声明 `durability=ephemeral`。Redb/remote provider 则使用其单事务原语。`SessionReadStore` 的实现读取同一 committed snapshot/index，但不能取得或升级 writer lease。

### Model-visible means reconstructable

对于 durable Agent，每个 model-visible request 必须能够由 SessionLog 逻辑重建：

```text
SessionLog
  ↓
Derived model history through recorded boundary
  + RequestPrepared.system/tools/route/params/composition
  ↓
ModelRequest
```

必须建立 architecture invariant：

> 任意归属于 Durable Session、会影响 Agent/Session 领域状态的模型调用，其 model-visible 输入必须先以带 purpose 的 `RequestPrepared` 进入 SessionLog。Sessionless/Ephemeral Agent 不提供 cold resume/replay/reconstructability 承诺。

该 invariant 由调用形状强制：AgentDriver 只能从 `AgentContext::prepare_model_call`、Session-owned caller 只能从 `SessionOperationContext::prepare_model_call` 获得 `PreparedModelCall`；model consumer binding 在 proof/digest/route 校验成功前不暴露 concrete provider 调用。Durable route 缺少 SessionLog、commit 未确认或 proof 与实际 request 不一致都必须在 provider stream 前失败，不能依赖 driver 自觉 append。

特别包括：

- user/model-visible messages；
- assistant final message；
- tool call/result；
- 最终 prompt composition 结果；
- 完整 tool schema snapshot；
- model route / relevant request header；
- effective Agent behavior mode；
- compaction replacement/summary；
- durable Agent preset/composition identity。

第一版 Resume 要求 Session genesis、record 的 composition hash、SessionEventCatalog digest 与当前 composition 完全相同；任一不一致返回结构化 `IncompatibleComposition`，不能用当前默认值、当前 tool schema 或 provider key 静默替换。需要升级 composition 的产品必须显式结束旧 Agent，并通过未来独立的 migration/import 工具验证旧 manifest、转换事件并创建具有新 identity 的 Session seed；该工具在定义版本化 mapping schema、转换 ABI、审计记录和失败原子性以前不进入第一版。

`session-title-basic` 等 Session component 的 model call 使用独立 purpose，完成后 append `SessionTitleUpdated`；不得在 SessionLog 外调用模型后直接修改持久 projection。纯 stateless、未归属 Session 的 Host model call 不属于该日志。

### Capability 拆分

```text
cap:session-log
cap:session-persistence
cap:session-read-store
cap:session-query
cap:session-projection
cap:session-title
cap:session-observer
```

Projection：Conversation、Goal、Usage、UI view 均从 event stream 派生。

禁止把纯 UI state 写入核心 event，除非它具有可恢复的领域语义。

### Persistence provider

Canonical components：

- `session-log-events`：Session scope 的唯一领域 log provider；
- `session-persistence-memory`：App scope，ephemeral，不支持 cold resume；
- `session-persistence-jsonl`：App scope，durable，local path-backed，admin/read facade都强制使用同一prepared local resource namespace；
- `session-persistence-redb`：App scope，durable，local path-backed，admin/read facade都强制使用同一prepared local resource namespace；
- `session-persistence-remote`：App scope，durability 由 provider contract 声明。

`session-log-events` requires `cap:session-persistence`。Catalog normalization 只允许 `session-log-events` 与 schema-allowlisted generated Agent/Session factory 消费该 admin capability；query/title/projection/Integrator Component 必须使用 `cap:session-read-store` 或 `cap:session-log` 的只读/领域接口。Provider 必须显式声明 `durability` 与 `ephemeral-creation` 两项 required property，并统一满足 append ordering、idempotent EventBatchId index/status lookup、atomic batch、monotonic seq、flush quiescence、schema version、catalog digest 保存与 fail-closed unknown event rejection；Durable provider 额外满足跨进程 persistent lifecycle-operation issuer、Reserved/global locator、genesis/Prepared/terminal-summary atomicity、durable append commit-status resolution、exclusive writer fencing、cold crash recovery 与 corruption diagnostics。`AgentFactory::resume` 只接受 Durable provider。

Durable `SessionPersistenceAdmin::prepare_new/prepare_existing` 必须取得 exclusive writer lease/fencing generation；每次 append 校验 generation，第二个 live writer 返回 `WriterConflict`。Lease release 是以 SessionId + owner id + fencing generation 标识的幂等 backend operation，并提供 authoritative status lookup；开始 release 后该 `PreparedSessionJournal` 永久关闭新 append，只有既已进入 quiescence 的 flush/release/status-resolution 能继续，不能因 release unknown 重新开放 writer。只有 backend 能证明该 generation 已不再拥有 append 权时，`AgentHandle::shutdown()` 才能报告成功。Release response 丢失且无法读回时返回 `WriterLeaseReleaseUnknown`，不能假定释放。此时 lifecycle 保持 `Closing` 并保留同一 lease identity；对同一 handle 的 idempotent shutdown retry 只调用 status lookup/重复同一 release，不创建新 owner 或 generation，确认 `Released` 后才转为 `Closed/Ok`。Live handle 若观察到 `Superseded`，说明 fencing invariant 已被破坏，必须保持 admission 关闭并返回 `WriterLeaseLost`，不能把它伪装成正常 handoff 成功。Cold recovery 只有在旧 lease 已明确释放，或旧 owner/process 已失效且 backend 原子取得更高 fencing generation 后，才能修复 torn tail、追加 synthetic recovery event 或开始 resume；新 App 存活期间不能用“更高 generation”强抢仍活跃旧 owner。

对应 metadata：

```toml
resource-namespace-preparer = "crate::prepare_resource_namespaces"
prepared-config-type = "crate::PreparedConfig"

provides = [
  { capability = "cap:session-persistence", properties = { durability = "durable", ephemeral-creation = "unsupported" }, resource-namespace = { mode = "required", bootstrap = "resource-namespace-bootstrap-local" }, effects = ["read-local", "write-local", "persistent-storage"] },
  { capability = "cap:session-read-store", properties = { durability = "durable" }, resource-namespace = { mode = "required", bootstrap = "resource-namespace-bootstrap-local" }, effects = ["read-local", "persistent-storage"] },
]
```

上例是`session-persistence-jsonl`/`session-persistence-redb`这类由Config选择本地database/journal path的规范形状；两个facade必须使用同一个prepared namespace descriptor/anchor，不能一个标Required、另一个默认为None，也不能在factory/initialize中按raw path重开。`StoreIdentity`只能从这次authority-projected preparation返回的descriptor commitment与StoreGeneration构造。若同一durable provider还实现第6节的volatile staged-known-outcome route，上例只把`ephemeral-creation`改为`"staged-known-outcome"`；字段不得省略，也不能在`cap:session-read-store`上重复声明该admin-only property。Memory provider无外部locator，声明`durability = "ephemeral", ephemeral-creation = "staged-known-outcome"`且namespace为None；remote provider若Config选择tenant/account/bucket/prefix同样必须选择对应audited bootstrap key，不能借“remote”省略namespace。

## 8. Prompt Assembly

Prompt 必须是 contributor pipeline，而不是 kernel 字符串拼接。

```rust
pub trait PromptContributor: MaybeSendSync {
    async fn contribute(
        &self,
        context: &PromptContext,
        out: &mut PromptBuilder,
    ) -> Result<(), PromptError>;
}
```

contributors：

- base identity
- workspace instructions
- tools
- skills
- memory
- RAG
- plan mode
- agent instructions
- time/environment

要求：

- deterministic ordering
- contributor id 唯一
- contribution 可 audit
- token estimate 可观测
- 可按 agent scope 选择 contributor
- minimal profile 不编译 prompt assembler

---

## 9. Tools / ToolRegistry / ToolExecutor

AINS 现有 Tool schema、安全分类、只读判断、exclusive key、query cancel、输出预算实现与 tests 作为迁移输入；迁入新边界并在目标平台重跑通过后才成为 rust-agent 保证。

```rust
/// 只能由 rust-agent-tools 内部的 guarded pipeline 构造。
/// 不实现 Clone、Default、Deserialize；字段保持私有。
pub struct ExecutionPermit {
    _private: (),
}

pub trait Tool: MaybeSendSync {
    fn definition(&self) -> ToolDefinition;

    async fn execute(
        &self,
        permit: &ExecutionPermit,
        ctx: &ToolContext,
        input: JsonValue,
    ) -> Result<ToolValue, ToolError>;
}
```

`ToolDefinition` 的 call policy 使用封闭数据类型；字段私有并在 bounded builder 保留每项前执行 count/string/depth/byte/evaluator bounds，不能由 struct literal、collection conversion或 serde 绕过：

```rust
pub struct ToolCallPolicy {
    rules: Arc<[ToolRiskRule]>,
    concurrency: ToolConcurrencyRule,
}

pub struct ToolRiskRule {
    all: Arc<[ToolArgumentPredicate]>,
    raise_to: ToolSafety,
    add_effects: SecurityEffects,
}

pub struct ToolCallPolicyBuilder { /* private bounded storage + canonical byte charge */ }
pub struct ToolRiskRuleBuilder { /* private bounded predicate storage + byte charge */ }

impl ToolCallPolicy {
    pub fn builder(concurrency: ToolConcurrencyRule) -> ToolCallPolicyBuilder;
    pub fn rules(&self) -> &[ToolRiskRule];
    pub fn concurrency(&self) -> &ToolConcurrencyRule;
}

impl ToolCallPolicyBuilder {
    pub fn try_push_rule(&mut self, rule: ToolRiskRule) -> Result<(), ToolPolicyBuildError>;
    pub fn build(self) -> Result<ToolCallPolicy, ToolPolicyBuildError>;
}

impl ToolRiskRule {
    pub fn builder(
        raise_to: ToolSafety,
        add_effects: SecurityEffects,
    ) -> ToolRiskRuleBuilder;
    pub fn predicates(&self) -> &[ToolArgumentPredicate];
    pub fn raise_to(&self) -> &ToolSafety;
    pub fn add_effects(&self) -> SecurityEffects;
}

impl ToolRiskRuleBuilder {
    pub fn try_push_predicate(
        &mut self,
        predicate: ToolArgumentPredicate,
    ) -> Result<(), ToolPolicyBuildError>;
    pub fn build(self) -> Result<ToolRiskRule, ToolPolicyBuildError>;
}

pub enum ToolArgumentPredicate {
    Present { pointer: BoundedJsonPointer },
    TypeIs { pointer: BoundedJsonPointer, kind: JsonKind },
    ScalarEquals { pointer: BoundedJsonPointer, value: BoundedJsonScalar },
}

pub enum ToolConcurrencyRule {
    Exclusive,
    ParallelSafe,
    ExclusiveByScalar { prefix: BoundedKey, pointer: BoundedJsonPointer },
}
```

Policy、rule 与两个 builder 的字段全部私有，且不实现 `Default` 或 derived `Deserialize`；如未来需要 wire decode，只能由 `rust-agent-tools` 的 custom decoder逐项调用同一 `try_push_*` 路径。Builder 在保留元素前同时检查 per-policy rule count、per-rule predicate count、pointer/scalar/key bounds、canonical aggregate bytes 与 evaluator step ceiling，超限立即返回 `ToolPolicyBuildError`；`build` 只把已验证 storage冻结为 `Arc`。只读 slice accessor不会破坏边界，因为 Safe Rust caller无法改写或构造其中元素集合。`ToolRegistration::new`/binding adapter仍重新验证 canonical charge与 effect monotonicity作为 defense in depth，但任何公开可持有的 `ToolCallPolicy`/`ToolRiskRule` 已经满足 bounds，不能先构造任意大 invalid state再等待 registration 拒绝。

`Tool` 只拥有自身 canonical execution contract，不拥有全局 permission/approval UI。Tool Component 实现 `ToolContribution`，通过 `ToolRegistration::new(Arc<dyn Tool>)` 提交字段私有的 opaque registration；只有 constructor 接受 raw handler，registration 不提供 handler accessor/execute。`rust-agent-tools` 对 `T: ToolContribution` 提供 `CapabilityProviderAdapter<T>` blanket impl，包装 concrete contribution 并用 `BindingProviderContext` 在每次 snapshot 时生成 sealed `RegisteredTool`。`RegisteredTool` 的 constructor、handler 和调用方法均为 `rust-agent-tools` 私有，对外只暴露不可变 definition/identity 读取；raw handler 不进入 capability consumer binding。`ToolSetSnapshot` 只能包含 `RegisteredTool`，不得包含或返回 `Arc<dyn Tool>`。Guarded executor 是唯一能从 `RegisteredTool` 取出 handler 并调用 `Tool::execute` 的代码。Safe Rust consumer 既无法从 provider snapshot 取得 raw Tool，也无法构造 `ExecutionPermit`；composite Tool 只能通过当前 `ToolContext` 的 nested facade 调用其它 tool，不 require `cap:tool-executor`。Tool Component 自身仍属于第 33 节定义的 trusted computing base。

`ToolValue` 字段与 constructors 保持在 `rust-agent-tools` 内部；Tool 只能通过 `ToolContext::output_builder()` 写入 text/structured/binary-reference，builder 在每次 append 时执行 byte/item/depth budget 并按 policy 使用 selected SpillStore。Executor 对完成值再次校验，ToolError message/source chain 也经过 redaction 与长度上限。Provider 不得直接返回无界 `JsonValue`、`Vec<u8>` 或任意文件路径伪装的结果。

`ToolDefinition` 声明 build-reviewed static safety floor/effects 和封闭、数据化的 `ToolCallPolicy`。第一版 policy DSL 只允许有界 JSON-pointer/type/enum predicates、只能提高风险或增加 effect 的 rule、以及从已验证 scalar argument 派生 exclusive-key 的规范化 template；禁止 function pointer、trait callback、regex backtracking、I/O、clock/random/global lookup 或 arbitrary code。Availability 由 `ToolContribution::snapshot` 是否贡献该 registration 决定，不在每次 call 回调 raw Tool。`rust-agent-tools` 自己解释 schema/policy/concurrency rule，所以 `plan_call` 不取得或调用 handler。Tool Component 从其 typed dependency binding 的不可伪造 effect stamp 构造 definition：例如同一个 `tool-fs` read schema 在 `fs-read-local` 下携带 `READ_LOCAL`，在 `fs-remote` 下携带对应 `NETWORK/SECRET_ACCESS`，而写 schema 只有 `cap:fs-write` binding 存在时才出现。ToolProvider binding adapter 用 `BindingProviderContext` 把 providing Component 的 sealed effective ceiling、ComponentId 和实际依赖 binding identities 密封进每个 `RegisteredTool`，并在每次 dynamic snapshot 替换时重验。这里的 effective ceiling 是该 Tool Component 当前 route 的 own lifecycle/provide/conditional effects 与实际 selected dependency binding effects 的规范化并集，可以大于该 package 自身的 `Component.security`，但必须是 top-level `component_runtime_effects` 的子集。Definition static/dynamic maximum effects 必须是该 effective ceiling 的子集；matched rule 只能保持或提高风险且不能把 static write/process/network/secret effect 降级为 readonly。Guarded executor 对 static 与 matched effect 求并集，先校验未越过 sealed ceiling，再交给 PermissionPolicy；schema/policy evaluation 异常、budget exhaustion 或超出 ceiling 一律拒绝执行。

### ToolProvider 与可见 schema

```rust
pub struct ToolRegistration {
    _private: (),
}

impl ToolRegistration {
    pub fn new(tool: Arc<dyn Tool>) -> Result<Self, ToolRegistrationError>;
}

pub trait ToolContribution: MaybeSendSync {
    fn snapshot(&self) -> Result<ToolRegistrationSnapshot, ToolProviderError>;
}

pub trait ToolProvider: MaybeSendSync {
    fn snapshot(&self) -> Result<ToolSetSnapshot, ToolProviderError>;
}
```

`ToolRegistrationSnapshot` 包含 provider id、monotonic schema version 和 immutable `Arc<[ToolRegistration]>`，只在 concrete contribution 与 adapter wrapper 之间流动；`ToolSetSnapshot` 具有同样的 header，但 item 是 `Arc<[RegisteredTool]>`，只存在于 sealed consumer binding。Static contribution 返回固定 version；MCP 等动态 contribution 只在自身 initialize/owned refresh task 中更新完整 registration snapshot，再原子替换；adapter 对每个新 version 全量校验并原子发布 sealed snapshot，不能让调用方看到半次 discovery 或部分 seal 结果。

`cap:tool-provider` metadata 的 `api` 固定为 `ToolContribution`，`ProviderBinding` 是 adapter 生成的 `Arc<dyn ToolProvider>`，`binding-type` 是只含 sealed provider 集合的 `ToolProviderBinding`。Concrete Component 不实现 sealed `ToolProvider`，普通 consumer 也不接收 `ToolRegistrationSnapshot`；这使 blanket adapter 可在 API crate 内访问 private registration payload，同时不要求 API crate 依赖 concrete provider crate。

Tool registry 是 `rust-agent-tools` 内部实现细节，不公开返回 raw Tool 的 lookup API。它负责：

- scoped visibility；
- deterministic schema ordering；
- name conflict；
- internal lookup；
- provider contribution。

Registry **不负责执行安全决策**。

### ToolExecutor：唯一执行 reference monitor

```rust
pub trait ToolExecutor: MaybeSendSync {
    fn prepare_model_step(
        &self,
        scope: &ToolScope,
        step: StepId,
    ) -> Result<Arc<ToolExecutionSession>, ToolExecutionError>;

    fn prepare_command<'a>(
        &'a self,
        grant: &'a CommandToolGrant<'a>,
    ) -> Result<BorrowedToolExecutionSession<'a>, ToolExecutionError>;
}

impl ToolExecutionSession {
    pub fn definitions(&self) -> Arc<[ToolDefinition]>;

    /// Pure/deterministic: pins lookup, schema, classification and snapshot identity.
    pub fn plan_call(
        &self,
        request: ToolExecutionRequest,
    ) -> Result<ToolCallPlan, ToolExecutionError>;

    /// Verifies the exact journal proof before permission/approval/handler dispatch.
    pub async fn execute_prepared(
        &self,
        call: PreparedToolCall,
    ) -> Result<ToolExecutionResult, ToolExecutionError>;
}

pub struct ToolCallPlan { /* private request/step/tool/snapshot/effect digests */ }
pub struct PreparedToolCall { /* private plan + ToolCallJournalProof */ }

impl ToolCallPlan {
    pub fn journal_projection(&self) -> ToolCallJournalProjection;
    pub fn seal(
        self,
        proof: ToolCallJournalProof,
    ) -> Result<PreparedToolCall, ToolExecutionError>;
}

impl ToolContext {
    pub fn prepare_nested<'a>(
        &'a self,
        parent: &'a ExecutionPermit,
    ) -> Result<BorrowedToolExecutionSession<'a>, ToolExecutionError>;
}

/// 不实现 Clone；字段私有，并以 invariant lifetime 借用 authority。
pub struct BorrowedToolExecutionSession<'a> {
    _authority: PhantomData<&'a mut &'a ()>,
    _private: (),
}

impl BorrowedToolExecutionSession<'_> {
    pub fn definitions(&self) -> Arc<[ToolDefinition]>;

    pub async fn execute(
        &self,
        request: ToolExecutionRequest,
    ) -> Result<ToolExecutionResult, ToolExecutionError>;
}
```

`ToolExecutionSession` 与 `BorrowedToolExecutionSession` 字段私有，只能由 guarded executor 创建；两者固定本次 origin、tool handle、schema、policy input 与 snapshot versions。Model origin 的 `Arc<ToolExecutionSession>` 支持同 step 的 bounded parallel calls，但只提供 `plan_call/execute_prepared`；Command/Nested origin 使用不同的 borrowed type 和其 raw `execute`，不能被 cast/转换为 model-origin session。`plan_call` 只由 `rust-agent-tools` 对 sealed snapshot 执行无 I/O 的 lookup、argument/schema validation 与 declarative `ToolCallPolicy` safety/effect/concurrency evaluation，并固定 Agent/Session/step/normalized call id、RegisteredTool identity、arguments digest、schema/provider snapshot version 与 classified effects；它不能取得/call raw Tool handler、Component callback、PermissionPolicy、Approval 或 middleware。DSL bounds violation 与定义内的 evaluation error 全部 fail closed；evaluator implementation panic 不是可移植的 policy error outcome，在 `panic=abort` artifact 中仍会终止进程。`ToolCallPlan`/`PreparedToolCall` 字段私有且不可 Serialize/Deserialize，只有同一 session 能验证并执行。

Driver 的固定顺序是：`prepare_model_step` → 把 `definitions()` 原样写入 `RequestPrepared`/ModelRequest → `same_session.plan_call(request)` → `AgentContext::prepare_tool_call(plan.journal_projection())` → `plan.seal(proof)` → `same_session.execute_prepared(call)`。Sessionless 使用有界 volatile ToolCall journal；Ephemeral 在 backend transaction committed 后发 proof；Durable 以稳定 batch id 提交 exact Required `ToolCall`，只有 `Committed` 才发 proof，`NotCommitted` 不进入 executor，`CommitStatusUnknown` 关闭 admission并按同 batch id 解析。`execute_prepared` 先用 consumer binding 中 paired verifier 校验 authority tag、Agent/Session、step/call、tool/snapshot/arguments/effects digest，再进入 PermissionPolicy/Approval/middleware 或构造 `ExecutionPermit`；因此 provider、Approval 和任何 external-effect hook 在 commit 前调用次数都必须为零。不得在 model call 与 tool dispatch 之间重新 lookup 最新 provider snapshot。

Command/Nested origin 必须返回不实现 `Clone` 的借用型 session，其 invariant lifetime 分别绑定当前 `CommandToolGrant` 或 `ExecutionPermit`，因此不能存入 `'static` task、Component state 或越过 raw body future。Command origin 继承 CommandInvocationId/caller/deadline/cancellation、Agent budget 和 dispatcher 已确认的 command effect ceiling，任何 tool static/dynamic effect 超出该 ceiling都拒绝；Nested origin 复用 parent 已 pin 的 RegisteredTool/provider snapshot，继承 root call id 和只能收紧的 depth/count/cost/effect ceiling，不在嵌套边界刷新 provider。Command 只能用 `CommandPermit::delegate_tools` 生成的 borrowed `CommandToolGrant` 调用 `prepare_command`。`ToolContext` 只持有指向当前 guarded executor/session 的 private weak handle；Tool body 只能用当前 `ExecutionPermit` 调用 `ToolContext::prepare_nested`，它不建立 ToolProvider → ToolExecutor capability edge，owner 已关闭时返回 `Closed`。Provider snapshot count、单 schema、总 schema bytes 和 retained active sessions 都有 hard cap，超限时在任何 external effect 前失败。

Driver 先按 model event 中的稳定顺序为每个 call 生成 `NormalizedToolCallId = H(composition, AgentId, AgentRequestId, StepId, ordinal)`；provider-supplied call id 只作为经过 bounds/uniqueness validation 的协议字段一并记录，不能作为 batch uniqueness 的唯一来源。Replay 必须从已记录的 step/ordinal 重建同一 normalized id，重复 ordinal、同 normalized id 不同 canonical tool/args 或乱序重写均视为损坏。

唯一合法路径：

```text
Tool request
   ↓
Internal ToolRegistry lookup
   ↓
Argument/schema validation
   ↓
Safety classification
   ↓
Model origin: ToolCall journal checkpoint + paired proof verification
   ↓
PermissionPolicy
   ↓
Approval (optional)
   ↓
Execution middleware / deadline / cancellation
   ↓
Tool::execute(&ExecutionPermit, ...)
   ↓
Output validation
   ↓
Output policy / spill / pruning
   ↓
Durable ToolResult
```

Architecture invariant：

```text
AgentDriver / MCP / Workflow / Subagent / Jobs / Host callback
cannot obtain ExecutionPermit and MUST use ToolExecutor.
Model-origin ToolExecutor cannot accept an unprepared ToolExecutionRequest;
Durable model-origin execution requires the exact committed ToolCall proof.
CodeRuntime additionally requires a non-cloneable CodeExecutionPermit
borrowed from the current authorized tool body.
```

### Canonical ToolExecutor composition

`ToolExecutor` 的默认生产 binding 是独立 Component package：`tool-executor-guarded`，但 reference monitor 的实现代码、private registry、`RegisteredTool` handler access、execution-session constructors 和 `ExecutionPermit` constructor 全部物理位于 `rust-agent-tools` crate 的同一 privacy boundary。`tool-executor-guarded` 是只承载 Component metadata 的薄装配 crate：它把 metadata 指定的 `build/Config/Dependencies` 从 `rust_agent_tools::guarded_component` 原样 re-export，不自行读取 registration payload，也不依赖 Rust 不存在的 friend-crate visibility。该内部实现通过 typed dependencies 注入 tool providers、permission、approval 和 middleware，并提供正式 `cap:tool-executor` binding。它不是 `driver-tools` 内部私有对象：

```text
tool-fs / tool-shell / tool-terminal / tool-web / tool-skill / mcp-client / tool-lsp
        │
        └── provides cap:tool-provider
                         │
                         ▼
                tool-executor-guarded
                         │
                  provides cap:tool-executor
                         │
                         ▼
                    driver-tools
```

`tool-executor-guarded` requires `cap:permission-policy`；`cap:tool-provider`、`cap:tool-execution-middleware`、`cap:approval`、`cap:spill-store` 与 `cap:attachment-store` 是 `UsesIfPresent`。空 tool-provider 集合产生合法的空 schema/registry，不得为满足 executor 而自动选择任意工具。`rust_agent_tools::guarded_component::build` 消费字段私有、由 binding adapter 产生的 typed binding wrappers，内部调用字段私有的 `GuardedToolExecutorBuilder`，只返回 opaque/field-private guarded executor；普通 crate 即使调用公开的 Component factory，也只能构造同一 reference monitor，不能取得 raw handler、private lookup 或 permit。Component wrapper 不得定义替代 factory、builder 或 dispatch path。依赖方向固定为 `tool-executor-guarded → rust-agent-tools`，`rust-agent-tools` 不反向依赖 Component wrapper。尽管 reference-monitor helper 物理位于 API crate，只有该 Component package 声明 `cap:tool-executor` provide；它的 metadata/runtime ceiling 必须聚合 guarded core 的全部 transitive runtime 行为，未选择 wrapper 时 generated composition 不产生 factory call、executor 实例或 capability binding。该 helper 不得链接高风险 provider implementation，dependency-negative test 仍以实际 selected provider package 为准。Resolver 从已显式选择或被其它 root 拉入的 tool-provider 集合构造统一、受 policy/approval/reference-monitor 约束的 ToolExecutor。

如果 composite tool 需要嵌套调用其它 tool，也必须通过 `ToolContext::prepare_nested` 返回的受控 session，并携带 root call id、caller identity、cancellation lineage、不可增加的 depth/count/cost budget；每一层重新执行 schema、permission、approval、concurrency 与 output policy。达到 depth/count 上限或检测到禁止的 call cycle 时 fail closed。`ExecutionPermit` 只在一次 raw body 调用的异步借用范围内存在，不能被 Tool 保存、克隆或转交。

### Tool execution middleware

不要建立万能字符串 hook bus。工具扩展点明确为：

```text
PreToolPolicy
AroundToolExecution
PostToolPolicy
ToolResultObserver
```

每个 middleware 明确：

- deterministic order；
- 是否可 short-circuit；
- failure policy；
- cancellation contract；
- 是否允许改变 signal/deadline；
- 是否影响 durable result。

### Concurrency

默认保守：

```text
Unknown → Exclusive
Explicit Safe → Parallel candidate
ResourceKey → same-key barrier
```

ToolExecutor/driver scheduler 负责 bounded parallel group，最终 durable/result commit 顺序按 model call order，而不是 completion order。

## 10. Filesystem

```rust
pub trait FileRead: MaybeSendSync {
    async fn metadata(&self, context: FsCallContext, path: &AgentPath) -> Result<Metadata, FsError>;
    async fn read(&self, context: FsCallContext, path: &AgentPath, range: ByteRange) -> Result<Bytes, FsError>;
    async fn list_page(&self, context: FsCallContext, request: DirPageRequest) -> Result<DirPage, FsError>;
}

pub trait FileWrite: MaybeSendSync {
    async fn write(
        &self,
        context: FsCallContext,
        path: &AgentPath,
        data: &[u8],
        opts: WriteOptions,
    ) -> Result<(), FsError>;
}
```

`FsCallContext`、`ByteRange` 和 `DirPageRequest` 强制 byte/entry/depth 上限；provider 返回 stable continuation cursor，禁止无界读取整个文件或目录。

对应两个独立 Capability：

```text
cap:fs-read
cap:fs-write
```

`AgentPath` 是 provider-neutral、已完成词法 normalization 的逻辑路径，不暴露宿主绝对 root。Local provider 把它锚定到配置的 workspace root；remote/browser provider 映射到自己的 namespace。Readonly profile 可以保留同一轻量 API crate 中的 `FileWrite` type 和 `tool-fs` 的可选适配代码，但 generated Dependencies 中 `cap:fs-write` 为 `None`，ToolProvider snapshot 不生成任何写 schema，Cargo graph 不含写 provider/implementation crate；API type 存在不表示写 capability 已启用。

providers：

- resource-namespace-bootstrap-local（App-scoped bootstrap provider；不提供 FileRead/FileWrite）
- fs-read-local
- fs-local
- fs-memory
- fs-sandbox
- fs-remote
- fs-e2b

### Capability bindings

```text
fs-read-local
  resource-namespace = { mode = required, bootstrap = resource-namespace-bootstrap-local }
  provides cap:fs-read

fs-local
  resource-namespace = { mode = required, bootstrap = resource-namespace-bootstrap-local }
  provides cap:fs-read + cap:fs-write

resource-namespace-bootstrap-local
  provides cap:resource-namespace-bootstrap[resource-namespace-bootstrap-local]
  stateless; effects/security = read-local; lifecycle-effects = []

tool-fs
  requires cap:fs-read (Required)
  requires cap:fs-write (UsesIfPresent)
  provides cap:tool-provider
```

`tool-fs` 不直接依赖 `fs-local`；readonly 与 writable composition 通过 Capability binding 选择不同 filesystem provider。选择 `fs-read-local` 或 `fs-local` 时，normalizer 的 derived exact bootstrap edge 必须把 `resource-namespace-bootstrap-local` package一并拉入 selected Component/Cargo closure；其 target/support 不满足时该 filesystem candidate为 unsatisfied，不能省略 bootstrap、回退到 generated I/O或等到 Cargo failure。

### AINS 迁移重点

迁移 filesystem.rs 中已经在目标平台成立的行为：

- path canonicalization
- Unix descriptor-relative symlink / TOCTOU 防护
- ignore/.gitignore 遍历语义
- glob/grep
- cwd anchoring
- file size/output limit

把“model-facing tool”与“filesystem provider”分开。Windows local provider 在完成 handle-relative reparse-point 防护及真实 Windows regression 前保持 unsupported/fail-closed；不得把 Unix 测试结果声明为 Windows 等价保证。

---

## 11. Subprocess / Shell / Terminal 分离

三个 capability 不得合并：

```rust
pub trait Subprocess: MaybeSendSync {
    async fn spawn(
        &self,
        spec: ConfinedProcessSpec,
        cancel: CancellationToken,
    ) -> Result<ProcessHandle, ProcessError>;
}

pub trait Shell: MaybeSendSync {
    fn resolve(&self, request: ShellRequest) -> Result<ShellSpec, ShellError>;
    async fn run(&self, spec: ShellSpec, cancel: CancellationToken) -> Result<ShellResult, ShellError>;
    async fn start(&self, spec: ShellSpec, cancel: CancellationToken) -> Result<ShellProcess, ShellError>;
}

pub trait TerminalManager: MaybeSendSync {
    async fn open(&self, spec: TerminalSpec, cancel: CancellationToken) -> Result<TerminalId, TerminalError>;
    async fn write(&self, id: TerminalId, data: Bytes) -> Result<(), TerminalError>;
    async fn read(&self, id: TerminalId, request: ReadRequest) -> Result<Bytes, TerminalError>;
    async fn resize(&self, id: TerminalId, size: TerminalSize) -> Result<(), TerminalError>;
    async fn close(&self, id: TerminalId) -> Result<(), TerminalError>;
}
```

### 正确 layering

```text
tool-shell
    ↓
cap:shell
    ↓
ShellLocal
    │
    ├── cap:sandbox / confinement
    │
    └── cap:subprocess
             ↓
      SubprocessLocal
             ↓
         OS process
```

Sandbox 不应继续像 AINS 当前抽象那样逐渐变成 Shell executor；Sandbox 负责把未授权执行描述转换成带强制约束证据的 `ConfinedProcessSpec`，Subprocess 只接受该类型并负责真实 process mechanics。

接口：

```rust
pub trait Sandbox: MaybeSendSync {
    async fn confine(
        &self,
        spec: ProcessSpec,
        policy: SandboxPolicy,
    ) -> Result<ConfinedProcessSpec, SandboxError>;
}
```

`ProcessSpec` 与 `ConfinedProcessSpec` 不是 type alias。后者不可 `Clone/Default/Deserialize`，字段私有，携带 selected backend plan、effective-policy digest、cwd/environment normalization 和 scope-local authority tag。`Subprocess` API 不提供接收 raw `ProcessSpec` 的旁路。平台 provider 无法完整表达 policy 时必须返回结构化 `UnsupportedPolicy`，不得降级为不受限进程。

每个 Agent scope 由 generated infrastructure 创建一次 `ConfinementAuthority::new(policy_ceiling)`，得到不可互换的 `ConfinementIssuer` 与 `ConfinementVerifier`。Issuer 只注入 selected sandbox provider；Verifier 只注入 selected subprocess provider。Sandbox 把 caller policy 与不可放宽的 ceiling 求交，完成 normalization/support validation 后用 Issuer seal `ConfinedProcessSpec`；Subprocess 在任何 OS spawn 前用自己的 Verifier 校验 authority tag/policy digest，并在 child 执行用户代码前原子应用 backend plan。另建 authority pair 产生的 spec 无法通过当前 Subprocess verifier。

`Subprocess::spawn` 只有在 child pre-exec/setup handshake 返回 `EnforcementReport` 后才成功返回 `ProcessHandle`；setup 失败必须保证用户代码尚未执行并完成 child reap。`ProcessHandle::enforcement_report()` 返回该不可变 report；它记录实际应用的 primitive 与 policy digest，供 audit/test 使用，不能在 Sandbox plan 阶段伪造“已实施”。

`BackendPlan` 是 `rust-agent-policy/process` API 中 versioned、target-gated 的封闭 enum；sandbox 与 subprocess provider 必须编译于同一 plan schema。新增 backend 先升级 API/schema 和 compile fixtures，再增加 provider；不得把任意 command/script/blob 塞进 plan 让 Subprocess 动态解释。

`cap:confinement-issuer` 与 `cap:confinement-verifier` 是 Agent-scoped、generated-only infrastructure Capability。Catalog normalization 固定限制：只有提供 `cap:sandbox` 的 Component 可以 require issuer，只有提供 `cap:subprocess` 的 Component 可以 require verifier；它们不能出现在 profile/provider-set/runtime config 中。

ShellLocal：

```text
ShellRequest
  ↓ resolve defaults/caps
ShellSpec
  ↓ build ProcessSpec
Sandbox::confine (required)
  ↓
Subprocess::spawn
```

其它 provider 可以完全不同：

```text
shell-ssh
shell-e2b
```

因此 `tool-shell` 只 requires `cap:shell`，不应知道本地 subprocess/sandbox。

Capability binding：

```text
shell-local / shell-ssh / shell-e2b
        └── provides cap:shell

tool-shell
        ├── requires cap:shell
        └── provides cap:tool-provider

subprocess-local
        ├── requires cap:confinement-verifier (Required, generated-only)
        └── provides cap:subprocess

shell-local
        ├── requires cap:subprocess (Required)
        ├── requires cap:sandbox (Required)
        └── provides cap:shell

sandbox-linux / sandbox-macos / sandbox-windows
        ├── requires cap:confinement-issuer (Required, generated-only)
        └── provides cap:sandbox

terminal-local
        ├── requires cap:subprocess (Required)
        ├── requires cap:sandbox (Required)
        └── provides cap:terminal

tool-terminal
        ├── requires cap:terminal
        └── provides cap:tool-provider
```

### AINS 可迁移实现与验证要求

从现有 sandbox/shell 代码迁出：

- process group / process tree kill；
- timeout/cancel first-cause classification；
- bounded stdout/stderr shared budget；
- canonical cwd / workspace containment；
- credential/environment scrub；
- Linux platform-specific confinement；
- regression tests。

process mechanics 必须从 Sandbox interface 中抽离。macOS 与 Windows 代码只能作为实现输入；在真实目标平台通过 policy enforcement、escape、process-tree 与 teardown 测试后，provider metadata 才能声明 production-supported。Mobile provider 只提供 deny/host-policy 能力，不声明 process execution。

## 12. Sandbox / Permission / Approval

三个概念必须分离：

```text
Permission: 这个动作是否允许？
Approval:   是否需要人类确认？
Sandbox:    即使允许，执行时如何限制？
```

```rust
pub trait PermissionPolicy: MaybeSendSync {
    fn evaluate(&self, action: &Action) -> PermissionDecision;
}

pub trait Approval: MaybeSendSync {
    async fn request(&self, request: ApprovalRequest) -> Result<ApprovalDecision, ApprovalError>;
}
```

Sandbox 的唯一接口是上一节的 `confine(ProcessSpec, SandboxPolicy) -> ConfinedProcessSpec`。Permission 与 Approval 决定动作是否获准，Sandbox 仍必须独立强制执行获准动作的最小 policy；Approval 不能生成或替代 confinement。

`PermissionDecision::Ask` 在没有 `cap:approval` binding、Host 断开、超时或返回无法识别结果时一律按 Deny 处理；不得因为 Approval 是 `UsesIfPresent` 而自动放行。

### AINS 迁移

Linux sandbox 代码按新 `ProcessSpec → ConfinedProcessSpec → Subprocess` 边界迁移并保留现有 regression tests。macOS/Windows provider 必须增加真实平台验证；mobile provider 固定 fail-closed，不提供 shell/process capability。

目标组件：

- sandbox-linux
- sandbox-macos
- sandbox-windows
- mobile-policy（提供 fail-closed `cap:permission-policy`，不提供 `cap:sandbox`）
- permission-default
- approval-host

---

Canonical provider bindings：

```text
permission-default
  provides cap:permission-policy

mobile-policy
  provides cap:permission-policy

approval-host
  provides cap:approval

tool-executor-guarded
  requires cap:permission-policy (Required)
  requires cap:approval (UsesIfPresent)
  requires cap:tool-provider (UsesIfPresent)
  provides cap:tool-executor
```

---

## 13. Memory / Retrieval

不要再建设一个巨型 `MemoryService`。

拆分：

```text
cap:memory
cap:kv-store
cap:vector-store
cap:embeddings
cap:document-parser
cap:retrieval
```

```rust
pub trait Memory: MaybeSendSync {
    async fn store(&self, context: MemoryCallContext, item: MemoryItem) -> Result<MemoryId, MemoryError>;
    async fn search(&self, context: MemoryCallContext, query: MemoryQuery) -> Result<Vec<MemoryHit>, MemoryError>;
    async fn forget(&self, context: MemoryCallContext, selector: MemorySelector) -> Result<(), MemoryError>;
}
```

底层：

```rust
pub trait KvStore: MaybeSendSync { ... }
pub trait VectorStore: MaybeSendSync { ... }
pub trait DocumentParser: MaybeSendSync { ... }
```

App-scoped KV/Vector backend 不公开无命名空间的全局 key/query。Agent/Session scope factory 从 backend 创建 opaque `StoreNamespace`，绑定 tenant/Agent/Session identity、quota 与 lifecycle；Agent-scoped Memory/Retrieval provider 持有该 handle，每次 backend operation 都必须传入，不能调用无 namespace 的 KV/Vector API。Provider 负责在本地 key prefix、Redb table、IndexedDB database 或 remote tenant 中强制隔离，不能依赖调用方自行拼字符串前缀。`MemoryCallContext/RetrievalCallContext` 继续携带 cancellation、deadline、input/output budget，但不允许调用方替换 namespace。

DocumentParser 把输入 bytes、expanded object count、page/depth、CPU deadline 与输出 bytes 作为硬预算；压缩炸弹、递归容器、损坏 PDF/Markdown 返回结构化错误。Native parser/FFI 属 trusted Component dependency，必须进入 parser security regression 与 supply-chain gate。

Providers：

- kv-memory
- kv-redb
- kv-indexeddb
- kv-encrypted decorator
- vector-hnsw
- vector-flat (WASM fallback)
- parser-markdown
- parser-pdf (native-only)

### 迁移原则

从 AINS memory 模块移植实现，但拆掉其对旧 `ModelClient`、旧 context、旧 tool/runtime 的依赖。

Memory 需要 embeddings 时依赖 `cap:embeddings`，不能调用 `ModelClient.embed()`。

Canonical bindings：

```text
kv-memory / kv-redb / kv-indexeddb
  provides cap:kv-store

vector-hnsw / vector-flat
  provides cap:vector-store

embedding-openai
  provides cap:embeddings

parser-markdown / parser-pdf
  provides cap:document-parser

memory-context
  provides cap:memory (Singleton)
  provides cap:prompt-contributor (OrderedMulti)
  requires cap:kv-store (Required)
  requires cap:vector-store (UsesIfPresent)
  requires cap:embeddings (UsesIfPresent)

retrieval-local
  provides cap:retrieval
  requires cap:vector-store (Required)
  requires cap:embeddings (UsesIfPresent)
```

`rag` 因此形成完整闭包：`rag → cap:retrieval → retrieval-local → cap:vector-store → vector-hnsw/vector-flat`。

---

## 14. Retrieval / RAG

```rust
pub trait Retrieval: MaybeSendSync {
    async fn search(
        &self,
        context: RetrievalCallContext,
        request: RetrievalRequest,
    ) -> Result<Vec<RetrievedItem>, RetrievalError>;
}
```

RAG 是 composition consumer：

```text
rag
 ├─ requires cap:retrieval
 ├─ optional cap:embeddings
 └─ contributes cap:prompt-contributor
```

RAG 不拥有数据库。

`rag` 的正式 binding：

```text
rag
  requires cap:retrieval (Required)
  requires cap:embeddings (UsesIfPresent)
  provides cap:prompt-contributor (OrderedMulti)
```

---

## 15. Skills

```rust
pub trait SkillProvider: MaybeSendSync {
    async fn list(&self, context: CallContext, query: SkillQuery) -> Result<Vec<SkillMetadata>, SkillError>;
    async fn load(&self, context: CallContext, id: &SkillId) -> Result<Skill, SkillError>;
    async fn resource(&self, context: CallContext, req: SkillResourceRequest) -> Result<Bytes, SkillError>;
}
```

providers：

- skill-filesystem
- skill-embedded
- skill-remote

consumers：

- prompt-skills
- tool-skill

迁移 AINS：frontmatter、NFKC normalization、resource loading 与相关 tests。

Canonical bindings：

```text
skill-filesystem / skill-embedded / skill-remote
  provides cap:skill-provider

skill-filesystem
  requires cap:fs-read (Required)

skill-remote
  requires cap:http-client (Required)
  requires cap:credentials (UsesIfPresent)

prompt-skills
  requires cap:skill-provider (Required)
  provides cap:prompt-contributor (OrderedMulti)

tool-skill
  requires cap:skill-provider (Required)
  provides cap:tool-provider
```

---

## 16. MCP

MCP client、transport 与 tool adapter 必须分离，均不进入 core/tools 基础 crate：

```text
mcp-client
  provides cap:tool-provider
  requires cap:mcp-transport (Required)

mcp-transport-http
  provides cap:mcp-transport (Registry key=http)
  requires cap:http-client (Required)
  requires cap:credentials (UsesIfPresent)

mcp-transport-stdio
  provides cap:mcp-transport (Registry key=stdio)
  requires cap:subprocess (Required)
  requires cap:sandbox (Required)

mcp-transport-host
  provides cap:mcp-transport (Registry key=host)
```

`mcp-client` 和 `mcp-transport-http` 不直接依赖 reqwest、socket、process 或 OS API。HTTP transport 只依赖 typed `HttpClient`；client 根据 runtime server config 从已编译 transport registry 选择 key，完成 capability discovery，并把 server 暴露的 remote tools 作为 `ToolProvider` 贡献给 guarded executor。未编译 transport key 导致启动失败。

MCP server id、tool name/schema/annotations 均是不可信输入。Adapter 对名称做 namespace 与冲突检查、限制 schema/description/result 大小；远端 `readOnlyHint` 等 annotation 不能降低本地 static safety floor。第一版 `mcp-client` Component 和其生成的每个 remote ToolDefinition 固定声明 `MCP_CONNECT + REMOTE_EXEC`；本地 reviewed mapping 只能增加更具体的 effect，不能删除 `REMOTE_EXEC`。没有 mapping 的 MCP tool 还必须标记 Unknown/Exclusive，并按 PermissionPolicy 要求 approval 或拒绝；approval 不能绕过 composition runtime security ceiling。需要可在禁止 `REMOTE_EXEC` 的 composition 中使用的远端只读协议必须拆成不提供通用 MCP tool invocation 的独立 typed Component。

Transport contract：

- HTTP endpoint必须经过`HttpClient → NetworkConnector → NetworkPolicy`的pre-resolution、post-resolution、TLS-handshake（HTTPS）与per-stream-use授权；允许private/local endpoint必须来自显式Host/user allow rule，不能因“配置可信”、握手完成或已有pooled connection绕过校验；
- Native connector 在任何 DNS side effect 前校验 logical endpoint，每次 resolution 后再校验并绑定实际连接地址。HttpClient 对每一跳 redirect先完成 destination-scoped header/body校验；新建HTTPS连接走完整 `authorize_resolution → resolve → authorize_connection → TCP/proxy connect → authorize_tls_handshake → verified TLS handshake → authorize_stream_use`，明文协议显式跳过TLS状态但记录`TlsIdentity::None`。仅复用exact destination-origin pool时可不重复DNS/handshake，但仍须以stored actual hop/TLS identity重新校验logical+resolved policy并取得fresh one-use grant；
- scheme、显式 typed proxy route 与 Unix socket 都属于 NetworkPolicy 输入；第一版禁止读取 ambient environment proxy，未显式允许时禁止非 HTTPS、proxy 和非 TCP escape hatch；
- stdio server 的 raw ProcessSpec 必须经过 Sandbox confinement，且 process tree 归 MCP connection owner；
- WASM 不直接实现无法观察 DNS/redirect 的 HTTP transport，只能使用 `mcp-transport-host` 受信 bridge；
- connection setup、request、cancellation、schema validation 与 shutdown quiescence 均属于 transport lifecycle。

关闭 `mcp-client` 后，MCP protocol/adapter crate 不进入 Cargo graph；关闭某 transport 后，其 http-client/process 依赖不得由 MCP 路径带入。其它被选 Web/Model Component 可以独立保留通用 HttpClient dependency，dependency-negative test 按 provenance 区分来源。

---

## 17. Web

不要把 search/fetch 写死成一个具体 tool。

Native network stack 固定分层：

```rust
pub trait NetworkPolicy: MaybeSendSync {
    /// DNS/proxy/socket activity 前校验 logical scheme、hostname、port、
    /// 显式 typed proxy route、Unix-socket 意图和 caller policy。
    async fn authorize_resolution(
        &self,
        intent: &OutboundIntent,
    ) -> Result<ResolutionGrant, NetworkPolicyError>;

    /// DNS 得到单个地址后再次校验实际连接 hop；不得放宽 resolution grant。
    async fn authorize_connection(
        &self,
        resolution: &ResolutionGrant,
        hop: &ResolvedOutboundHop,
    ) -> Result<NetworkGrant, NetworkPolicyError>;

    /// 仅授权TLS握手字节；绑定actual socket/proxy hop、requested SNI/ALPN、
    /// trust/pin policy与caller，不授权HTTP request bytes。
    async fn authorize_tls_handshake(
        &self,
        connection: &PreTlsConnectedHop,
        intent: &TlsHandshakeIntent,
    ) -> Result<TlsHandshakeGrant, NetworkPolicyError>;

    /// 首次 request use 以及每次 keep-alive/H2/H3 pool checkout 都重新授权；
    /// 不能把建连时的 grant 当成连接生命周期内的 ambient authority。
    async fn authorize_stream_use(
        &self,
        connection: &ConnectedOutboundHop,
        intent: &OutboundUseIntent,
    ) -> Result<NetworkUseGrant, NetworkPolicyError>;
}

pub trait NetworkConnector: MaybeSendSync {
    async fn connect(
        &self,
        context: NetworkCallContext,
        endpoint: NetworkEndpoint,
    ) -> Result<AuthorizedStream, NetworkError>;

    /// HttpClient 在首次使用或从 pool 取出 connection/logical stream时调用；
    /// connector以内部 ConnectedOutboundHop回调当前 policy并消费 one-use grant。
    async fn authorize_stream_use(
        &self,
        context: NetworkCallContext,
        stream: &AuthorizedStream,
        request: NetworkStreamUseRequest,
    ) -> Result<AuthorizedStreamUse, NetworkError>;
}

pub trait HttpClient: MaybeSendSync {
    async fn execute(
        &self,
        context: HttpCallContext,
        request: HttpRequest,
    ) -> Result<HttpResponse, HttpError>;
}
```

`network-connector-native` owns DNS resolution、IP pinning、socket/proxy mechanics与TLS，并 requires `cap:network-policy`。它必须先把 logical scheme、规范化 hostname/port、来自 typed RuntimeConfig/request 且已规范化的 proxy route、Unix socket intent 与 caller identity 组成 `OutboundIntent`，取得 `ResolutionGrant` 后才允许调用 resolver；没有 pre-resolution grant 时不得产生 DNS、proxy connection 或 socket side effect。第一版不读取 `HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY` 等 ambient environment proxy。解析后再把原 intent、proxy hop、单个实际 resolved socket address 与 scheme 组成不可变 `ResolvedOutboundHop`，逐地址取得 `NetworkGrant`，并只连接该地址，不再解析。每个候选地址、DNS refresh、重连、Happy Eyeballs 分支和 proxy hop 都重新执行相应授权。HTTPS socket connect后仍只是connector-private `PreTlsConnectedHop`，不能返回pool/consumer；connector必须以requested SNI/ALPN、trust roots/pins、actual address/proxy/caller取得并消费`TlsHandshakeGrant`，才可发送握手bytes，验证certificate/name/pin并生成actual TLS server identity。HTTPS proxy自身的TLS与CONNECT tunnel后的origin TLS是两个独立type-state transition，各自绑定自己的hop/SNI/ALPN/trust/pin与fresh handshake grant；不得把proxy identity/grant重用于origin，或在未授权tunnel上学习origin identity。`http-client-native`只owns HTTP framing、redirect、pool orchestration与streaming body budget，并 requires `cap:network-connector`；它不链接TLS实现或取得pre-TLS socket。Native DNS/socket/proxy/TLS依赖只允许在`network-connector-native`，HTTP framing/client依赖只允许在`http-client-native`；Model、Embedding、Web、MCP、remote persistence/skills/fs/subagent provider只依赖`cap:http-client`，SSH只依赖`cap:network-connector`。Architecture lint对越界transport dependency报错。

`ResolutionGrant`、`NetworkGrant`、`TlsHandshakeGrant`与`NetworkUseGrant`字段私有，均不可Clone/Serialize/Deserialize。Resolution grant绑定完整`OutboundIntent`、policy digest、短expiry、DNS candidate/refresh上限和只能收紧的connection rule；只允许同一次connector operation在限额内借用。`NetworkGrant`是不可Clone的单次**socket/proxy建连**授权，绑定resolution grant identity、完整`ResolvedOutboundHop`、policy digest与更短expiry；它不授权TLS或application bytes。`TlsHandshakeGrant`是不可Clone的one-use握手lease，只允许exact `PreTlsConnectedHop`按exact SNI/ALPN/trust/pin intent交换有界握手bytes；握手失败、identity/name/pin不匹配或grant过期都关闭socket。只有verified handshake完成后（明文则显式确认None）connector才创建API-owned `ConnectedOutboundHop`，固定actual address、verified TLS server identity/ALPN、规范化origin、proxy route/identity与connection id，并返回不含可复用grant的dormant `AuthorizedStream`。

连接可否复用与 socket 是否仍打开是两件事。`http-client-native` 的 private pool 每次 checkout——包括首次 HTTP request、每次 keep-alive request以及每个 HTTP/2/HTTP/3 logical stream——都必须把 current caller/authority identity、规范化 request origin、method/body class、exact proxy route、credential provenance、deadline和该 `ConnectedOutboundHop`组成 `OutboundUseIntent`，经 connector回调当前 `NetworkPolicy::authorize_stream_use`取得并在写出任何 header/body bytes前消费 fresh `NetworkUseGrant`。`NetworkStreamUseRequest`字段私有，由 HttpClient binding从 exact request/context生成；connector再与 stream保存的 actual hop/proxy/TLS identity组合，caller不能逐字段伪造。Per-use policy必须重新执行适用于 logical intent和stored resolved hop的全部 current rule，不能仅检查 connection id。Grant只授权 exact connection + caller + origin + proxy + one logical request use；过期、policy digest/epoch变化、caller变化、proxy变化或 hop不再允许时拒绝 checkout并关闭/隔离 candidate，不能回退使用建连时授权。底层 client的 automatic pool checkout必须关闭或被这个 audited seam完全包住；不能为每个 request detached 一个未记账 reauthorization task。

该规则由type-state enforcement支撑，而不是调用约定：connector-private raw socket只能处于`PreTlsConnectedHop → TlsHandshakeInProgress → ConnectedOutboundHop`单向状态，前两者没有public conversion、pool insertion或application I/O API；只有`TlsHandshakeGrant`临时开放握手codec。`AuthorizedStream`是字段私有、已经完成所需TLS验证的dormant connection handle，不实现/不暴露`AsyncRead`、`AsyncWrite`、raw socket、TLS handshake、HTTP send或可绕过的clone accessor；pool只能保存dormant handle。只有connector消费fresh `NetworkUseGrant`后返回的`AuthorizedStreamUse`才提供一个受deadline/cancellation/byte budget约束的logical application-I/O lease。Lease不能进入pool或用于第二个request，完成/drop后只把底层connection交还dormant state；HTTP/2/3 multiplexer也必须在每个logical stream lease外保持不可写。SSH等一次性protocol consumer同样先取得相应use lease，不能把一次建连或TLS握手授权当成无限I/O capability。

Pool key至少包含 normalized `(scheme, host, effective-port)`、proxy route identity、TLS server identity/ALPN 与 caller policy realm，但分池本身不替代逐 checkout授权。第一版禁止 HTTP/2/HTTP/3 cross-origin connection coalescing，即使 certificate/SAN、DNS或底层库认为另一 origin可复用；origin变化必须走独立 connection。未来若开放，必须新增显式 coalesced-origin policy fact和 fresh destination-scoped use grant。Proxy tunnel不能因已建立而把另一个 destination/caller带入，`Proxy-Authorization`也不能跨 caller或proxy identity复用。

`http-client-native` 禁用底层库 automatic redirect/environment proxy。每次 redirect的新 destination connection都触发新的 pre-DNS authorize → resolve → per-hop authorize → connect → stream-use authorize；若命中 exact destination-origin的既有 pool candidate，则不借用 source-origin grant，只以该 candidate的 stored hop执行 fresh stream-use authorize。`HttpResponse` body 为有 cancellation/deadline/byte ceiling 的 stream，不提供无界 `bytes()` convenience API。

Redirect follow 前还必须以规范化 `(scheme, host, effective-port)` 比较 origin。跨 origin 时，在任何 destination DNS/connect side effect 前从派生 request 删除 `Authorization`、`Proxy-Authorization`、`Cookie`、`Cookie2`，以及 typed request provenance 标记为 credential/sensitive 的自定义 header；即使 origin 相同，只要 proxy route identity 改变也必须删除 `Proxy-Authorization`。第一版 redirect chain 不自动重加这些字段，也不读取 ambient cookie jar。Destination network/use grant只授权 exact transport use，绝不授权转发 source-origin credential或body。若协议 provider 要为 destination 使用 credential，必须结束当前 redirect follow，并以 destination-scoped credential policy 显式构造一次新 request；原 header value 不得复用。Same-origin redirect 也必须重新执行 header/body budget 与 method rewrite 校验；HTTPS→HTTP downgrade 默认拒绝，即使 profile 将来显式允许，仍按 cross-origin sanitation 删除 sensitive header。

Redirect engine 还必须把 body 当成 source-origin authority，而不能只清理 header。对跨 origin 的 `307/308`，只要原 request body不是typed `Empty`（长度未知、chunked或streaming一律按非空处理），或 method不是 schema-fixed safe/idempotent allowlist中的无 body method，第一版就在 destination DNS/connect和pool checkout前返回 `CrossOriginBodyRedirectDenied`；不得自动 replay、clone、rewind或流式转发 body。对 `301/302/303`，只有 typed redirect policy明确允许把 method规范化为 `GET/HEAD`且派生 request的 body严格为`Empty`时才可跨 origin follow；不能保留原 body。任何需要 replay但不可证明 rewindable且在 byte ceiling内的 body，即使 same-origin也拒绝自动 follow。若 Model/MCP/Web provider确实要向 destination提交 payload，它必须结束当前 follow，重新执行 destination-scoped credential/body policy并从 typed domain input显式构造一个**新** request；redirect engine不把 source request body或body stream交给这个重建路径。这样 body内的 prompt、MCP payload、token或其它 secret不会因 `307/308` preservation语义外泄。

Proxy resolution mode 必须显式进入 `OutboundIntent`。默认只允许 connector 本地解析 origin/proxy 并分别验证实际地址；SOCKS remote-DNS、HTTP CONNECT 由 proxy 解析 origin 或其它无法观察 origin IP 的模式，只有 policy 明确返回 `TrustedProxyResolution` rule 时才允许。该 rule 同时绑定规范化 origin、proxy identity、实际 proxy hop、允许的 scheme/port 和审计标签，不能把“proxy 地址获准”解释成任意 destination 获准；未选择这种 trust-boundary policy 的 profile 对 remote-resolution proxy fail closed。

HttpClient 不自动 retry 非幂等 request；retry policy 属于 Model/MCP/Web 等协议 provider，必须基于 request method/idempotency key、first-cause、partial body 状态和 CallContext budget 显式决定。

```rust
pub trait WebFetch: MaybeSendSync {
    async fn fetch(&self, context: WebCallContext, request: WebFetchRequest) -> Result<WebFetchResult, WebError>;
}

pub trait WebSearch: MaybeSendSync {
    async fn search(&self, context: WebCallContext, request: WebSearchRequest) -> Result<WebSearchResult, WebError>;
}
```

providers：

- web-http-native
- web-fetch-host
- web-search-deepseek
- web-search-exa
- web-search-perplexity
- web-search-host

consumer：

- tool-web

Native SSRF、DNS pinning、redirect validation 属 `NetworkPolicy + NetworkConnector + HttpClient`，不属于 AgentDriver 或具体 Web/Model provider。WASM browser 不能可靠观察 DNS 与 redirect chain，`web-fetch-host` / `web-search-host` 必须调用 Host 提供的受信同源 bridge；WASM profile 禁止选择 native HTTP/search provider，也不把长期 API secret 放入 browser binary/runtime config。

Canonical bindings：

```text
web-http-native
  requires cap:http-client (Required)
  provides cap:web-fetch

web-fetch-host
  provides cap:web-fetch

web-search-deepseek / web-search-exa / web-search-perplexity
  requires cap:http-client (Required)
  requires cap:credentials (Required)
  provides cap:web-search

web-search-host
  provides cap:web-search

tool-web
  requires cap:web-fetch (Required)
  requires cap:web-search (UsesIfPresent)
  provides cap:tool-provider
```

---

## 18. Compaction

拆为：

```text
cap:conversation-compaction
cap:tool-result-pruner
cap:token-meter
```

```rust
pub trait Compactor: MaybeSendSync {
    async fn compact(&self, context: CallContext, input: CompactionInput) -> Result<CompactionResult, CompactionError>;
}
```

AgentDriver 在 request pressure / provider context overflow 时调用 capability；算法不进入 kernel。

Compaction 结果在用于下一次 model request 前必须通过 generated durable journal facade 以 canonical Required `ConversationCompacted(ConversationCompactionRecord)` 和 `AppendDurability::Durable` append，并确认 `Committed`；`RequestPrepared.history_boundary` 指向该 event 的 committed sequence。其 version、payload schema、bounds、owner 与 reconstruction 规则以第 7 节为准，不能改用未声明的 extension event。第一版 `compaction` 不发起隐藏 model call；后续 model-assisted compactor 必须作为独立 Component 声明 `cap:model` dependency，并把其 request/result 纳入 SessionLog。

第一版默认 provider Component 为 `compaction`：

```text
compaction
  provides cap:conversation-compaction (Singleton)
  provides cap:tool-result-pruner (Singleton)
  provides cap:token-meter (Singleton)
```

关闭 compaction 时，上述实现 crate 不进入 generated Cargo graph；`driver-tools` 只有在 profile 明确选择这些能力时才消费它们。

---

## 19. User Interaction / Commands / Plan Mode

分离：

```text
Commands        = Human → Host Action
Tools           = Model → Runtime Action
UserInteraction = Agent → Human Question
Approval        = Runtime Policy → Human Decision
PlanMode        = Agent behavior policy/state
```

```rust
/// Raw Host callback; AgentDriver/ordinary Component only receives UserInteractionBinding.
pub trait UserInteraction: MaybeSendSync {
    async fn present_or_resume(
        &self,
        context: CallContext,
        request: PresentedUserInteraction,
    ) -> Result<UserAnswerResolution, UserInteractionError>;

    async fn resolve_answer(
        &self,
        interaction: UserInteractionId,
        operation: UserAnswerOperationId,
    ) -> Result<UserAnswerResolution, UserInteractionError>;

    async fn acknowledge_committed(
        &self,
        operation: UserAnswerOperationId,
        answer_fingerprint: Digest,
    ) -> Result<(), UserInteractionError>;
}

pub enum UserAnswerResolution {
    Pending,
    Submitted(UserAnswerSubmission),
}

impl PresentedUserInteraction {
    pub fn interaction_id(&self) -> UserInteractionId;
    pub fn answer_operation_id(&self) -> UserAnswerOperationId;
    pub fn question(&self) -> &UserQuestion;
    pub fn question_fingerprint(&self) -> Digest;
}

pub struct UserAnswerSubmission { /* checked expected operation + bounded typed answer */ }

impl UserAnswerSubmission {
    pub fn new(
        operation: UserAnswerOperationId,
        answer: UserAnswer,
    ) -> Result<Self, UserAnswerValidationError>;
}

pub enum UserInteractionError {
    JournalNotCommitted { batch: EventBatchId },
    JournalCommitStatusUnknown { batch: EventBatchId },
    InteractionOutcomeUnknown { interaction: UserInteractionId },
    InteractionRecoveryRequired { pending: u32 },
    SubmissionConflict { operation: UserAnswerOperationId },
    Provider(UserInteractionProviderError),
    Closed,
}

/// Consumer-facing generated facade; fields/journal proof are private.
pub struct UserInteractionBinding { /* raw provider + volatile/durable journal facade */ }
pub struct CommittedUserAnswer { /* typed answer + confirmed journal proof */ }

impl UserInteractionBinding {
    pub async fn ask(
        &self,
        context: CallContext,
        question: UserQuestion,
    ) -> Result<CommittedUserAnswer, UserInteractionError>;
}

/// 只能由 AgentHandle 的 command dispatcher 构造。
/// 不实现 Clone、Default、Serialize 或 Deserialize，字段私有。
pub struct CommandPermit {
    _private: (),
}

/// 只能从当前 CommandPermit 借用派生；不实现 Clone/Serialize。
pub struct CommandToolGrant<'a> {
    _permit: &'a CommandPermit,
    _private: (),
}

impl CommandPermit {
    pub fn delegate_tools<'a>(
        &'a self,
        context: &'a CommandContext,
    ) -> Result<CommandToolGrant<'a>, CommandDelegationError>;
}

pub trait Command: MaybeSendSync {
    async fn execute(
        &self,
        permit: &CommandPermit,
        ctx: &CommandContext,
        args: CommandArgs,
    ) -> Result<CommandResult, CommandError>;
}

/// 字段私有；只由 bounded builder 构造并由 rust-agent-commands 解释。
pub struct CommandEffectPolicy {
    _private: (),
}

pub struct CommandRegistration {
    _private: (),
}

impl CommandRegistration {
    pub fn new(
        definition: CommandDefinition,
        effect_policy: CommandEffectPolicy,
        command: Arc<dyn Command>,
    ) -> Result<Self, CommandRegistrationError>;
}

pub trait CommandContribution: MaybeSendSync {
    fn snapshot(&self) -> Result<CommandRegistrationSnapshot, CommandProviderError>;
}

pub trait CommandProvider: MaybeSendSync {
    fn snapshot(&self) -> Result<CommandSetSnapshot, CommandProviderError>;
}
```

`UserInteractionId` 与 `UserAnswerOperationId` 字段私有，只能由当前 generated interaction journal facade 分配。Sessionless/Ephemeral variant绑定 current Agent lifecycle；Durable variant从 `(StoreIdentity, SessionId, AgentId, stable turn/step interaction coordinate)` domain-separated派生且不含 process/lifecycle nonce，同一 logical question重建得到同一对 id。Facade先规范化并密封 question/schema/options、model-visible placement、authority epoch和driver coordinate，以 stable batch id append `UserInteractionAsked`；Durable route只有 confirmed `Committed` 后才可调用 raw Host provider。Provider收到的 `PresentedUserInteraction`含 exact ids与question fingerprint，不能替换 question或自行分配 operation id。

声明 `answer-recovery=stable-until-commit-ack` 的 Host provider必须在返回 `Submitted` **之前**把同一 `UserAnswerOperationId` 的 canonical answer与submission fingerprint保留在可跨目标所承诺process/crash boundary恢复的Host-owned journal中，直到收到matching `acknowledge_committed`；same-id `present_or_resume/resolve_answer`必须返回同一 submission，不得再次收集或换 answer。Facade把submission以同一stable answer batch append为`UserInteractionAnswered`，只有confirmed commit后才向driver返回字段私有的`CommittedUserAnswer`。随后它以operation/fingerprint调用幂等`acknowledge_committed`；provider确认后，facade再以stable ack batch append/确认`UserInteractionAcknowledged`。Ack callback或ack-event commit失败不撤销已提交answer，但留下可恢复的Answered-without-Acknowledged状态；同一live owner以bounded single-worker重试，shutdown flush必须解析或明确返回pending ack错误，不能detached fire-and-forget。

Cold recovery先从canonical projection枚举有界的pending interactions，且在开放相关Agent正常admission前完成两类reconciliation：Asked-only只可用原ids调用`resolve_answer/present_or_resume`，Pending继续等待，Submitted重提同一answer batch；Answered-without-Acknowledged**不得**重新present/收集answer，而必须重放同一`acknowledge_committed(operation, fingerprint)`，成功后补同一stable `UserInteractionAcknowledged` batch。若provider已ack但ack event未commit，重放因provider幂等而安全；若ack event已commit，不再调用provider。Answer/ack commit status unknown都关闭相关admission并只解析原batch；pending数量超过hard ceiling、provider不能稳定解析已接受submission或ack reconciliation失败时返回结构化`InteractionRecoveryRequired/InteractionOutcomeUnknown`，不能忽略backlog、分配新interaction、换answer或直接发起后续model call。

Generated model-history builder只接受`CommittedUserAnswer` proof，且下一个`RequestPrepared.history_boundary`必须覆盖对应`UserInteractionAnswered` committed sequence，因此live request与cold reconstruction使用相同answer；Acknowledged是provider-retention控制状态，不改变model history。Raw `UserAnswer`/`UserAnswerSubmission`不能由driver直接插入model messages。`cap:user-interaction` provider property `answer-recovery`是required enum：`unsupported | stable-until-commit-ack`；任一generated Durable Agent route向driver暴露该capability时，resolver只接受后者及其answer/ack crash conformance suite，否则composition在Cargo前失败。Sessionless/Ephemeral route可选择`unsupported`并使用bounded volatile Asked/Answered gate，但不承诺process-loss恢复。

Command Component 实现 `CommandContribution`，在 Agent construction 阶段通过 `CommandRegistration::new(definition, effect_policy, Arc<dyn Command>)` 提交字段私有的 opaque registration；registration 不提供 handler accessor/execute。Definition 与 policy 在 registration 时完成 canonicalization/bounds 校验并被 sealed，per-request dispatcher 不再调用 Component 的 `definition`/`effects`/classification callback。`CommandEffectPolicy` 与 `ToolCallPolicy` 使用同类封闭数据 DSL：第一版只允许有界 JSON-pointer/type/enum predicates、只能增加 effect/风险的 rule，以及从已验证 scalar 派生的规范化 exclusive-key template；禁止 function pointer、trait callback、regex backtracking、I/O、clock/random/global lookup 或 arbitrary code。`rust-agent-commands` 对 `T: CommandContribution` 提供 `CapabilityProviderAdapter<T>` blanket impl，包装 concrete contribution 并用 `BindingProviderContext` 生成 sealed `RegisteredCommand`。`RegisteredCommand` constructor、字段和 handler access 为 `rust-agent-commands` 私有，只公开 definition/identity；raw handler 不进入 capability consumer binding。`CommandRegistrationSnapshot` 只在 contribution 与 adapter wrapper 之间流动，`CommandSetSnapshot` 只包含 immutable `Arc<[RegisteredCommand]>`，不暴露 `Arc<dyn Command>`。`cap:command-provider` 是 Agent-scoped OrderedMulti。Generated Agent scope 在 Agent construction 期间只读取一次 sealed provider snapshot，交给 `rust-agent-commands::CommandDispatcherBuilder` 组装字段私有的不可变 command registry；第一版不支持 live command schema 更新。AgentHandle 只持有 `Arc<CommandDispatcher>`，其 `command_definitions/execute_command` 委托 dispatcher。`CommandPermit` constructor、`RegisteredCommand` handler access 与 raw lookup 都留在 `rust-agent-commands` 内部，Component 和 `rust-agent-agent` 均不能构造或 raw dispatch。Command 名称在当前 Agent 内唯一，snapshot/version/definition count/schema/policy bytes 与 rule evaluation budget 有界；重复名称、非法 schema/policy、unknown predicate/effect 或 evaluation exhaustion 都 fail closed。Host 在调用前负责用户身份和产品级授权；dispatcher 校验 Agent lifecycle、compiled command、参数 schema、deadline/cancellation，再由 `rust-agent-commands` 纯解释 definition static effects 与 declarative policy 的结果并验证未越过 sealed ceiling，随后必须先通过 runtime-owned command journal gate，最后才可取得 raw handler、生成 permit 并进入 `Command::execute`。因此 permit 前没有任何 **Command Component** code 可执行；Session-backed journal I/O只能经该已计入的 runtime/session binding。Command 不能取得 `ExecutionPermit`；需要调用工具时，Command Component 必须显式 require `cap:tool-executor`，由 `CommandPermit::delegate_tools` 借用派生一次 `CommandToolGrant`，再调用 `ToolExecutor::prepare_command`。Grant 继承 caller/invocation/deadline/cancellation/budget，不含 raw Tool/ExecutionPermit；返回的 borrowed tool session 以 invariant lifetime 绑定该 Grant，两者都不得存入 Command、`'static` task 或跨出本次 execute future。

`cap:command-provider` metadata 的 `api` 固定为 `CommandContribution`，`ProviderBinding` 是 adapter 生成的 `Arc<dyn CommandProvider>`，`binding-type` 是只含 sealed provider 集合的 `CommandProviderBinding`。Concrete Component 不实现 sealed `CommandProvider`，Generated Agent scope 也不接收 raw registration snapshot。

`rust-agent-commands` 不依赖 `rust-agent-agent`、`rust-agent-session` 或 `rust-agent-tools`。`rust-agent-runtime-api`定义无 handler/session concrete type的 `CommandJournalProjection`、opaque checkpoint proof与轻量 `CommandAdmissionGate`/`CommandJournalGate` trait；`rust-agent-agent` 以字段私有的 Agent lifecycle/mutation gate和当前 route的 volatile/Session-backed journal facade实现它们。Dispatcher只保留 weak gates，每次 dispatch取得一次有界 admission lease。Agent关闭、active turn冲突、RecoveryRequired、lease无法升级或 journal proof不匹配时，dispatcher在构造 `CommandPermit` 前返回结构化错误。依赖边固定为 `rust-agent-agent → rust-agent-session + rust-agent-commands`、`rust-agent-tools → rust-agent-commands`、`rust-agent-commands → rust-agent-runtime-api/core`；禁止反向 import，因此 command checkpoint不形成 crate cycle，`ToolExecutor::prepare_command` 也可以消费 command grant。

`AgentHandle::allocate_command_invocation` 从当前 Agent lifecycle nonce 和原子单调 sequence 分配 `CommandInvocationId`。`CommandRequest` 必须带该 id、command name、bounded args、caller identity/auth-context digest、deadline 和 cancellation。在同一 live Agent lifecycle 内，同 invocation id 的并发重试必须具有相同 canonical caller/command/args；dispatcher 让它们等待同一个 in-flight execution，完成后只返回有界、已 redacted 的 retained result。首次 admission 固定 execution 的 deadline/cancellation lineage；后续 retry 只能取消自己的等待，不能延长、替换或重启 execution。Fingerprint 不同返回 `InvocationConflict`；已滑出有界 completed window 的 sequence 返回 `InvocationExpired`，不得重新执行可能有 side effect 的 command。Cold resume 分配新 lifecycle nonce 并拒绝旧 nonce；旧 Host token不能再次执行，但 Durable projection仍必须解析其已提交的 operation state。

Durable command dispatch固定为两道 pre-effect checkpoint和一道 terminal checkpoint：

```text
validate lifecycle/schema + pure declarative classification
  → append/confirm CommandInvocationPrepared(exact full request fingerprint)
  → construct CommandPermit / borrow optional CommandToolGrant
  → append/confirm CommandInvocationDispatchPrepared(same fingerprint)
  → call raw Command::execute exactly once
  → append/confirm CommandInvocationFinished(exact terminal projection)
  → return CommandResult
```

Prepared commit 之前 `CommandPermit` constructor、raw handler lookup、tool delegation及所有Command/Tool/Host callback调用数必须为零；唯一允许的effectful调用是accounted Session journal boundary。DispatchPrepared commit之前 `Command::execute`调用数必须为零。`NotCommitted` 不构造 permit/不dispatch；`CommitStatusUnknown`关闭 Agent command/turn admission并只用相同 batch id解析，不能换 id或跳过 checkpoint。Handler返回后，即使 terminal首次append失败，也只能重提/解析同一 terminal batch，不能再执行 handler；只有 terminal confirmed后才能向 Host返回 success/failure。Process loss时，Prepared-only证明未越过handler boundary，cold recovery以同 id提交 `InterruptedBeforeDispatch`；DispatchPrepared但无terminal表示 side effect可能发生，cold recovery提交/投影 `OutcomeUnknown`并永久禁止自动重放。这样 `command-code-runtime`、nested tool command和其它effectful command都能区分“确定未dispatch”与“可能已dispatch”。

三个 command operation kind的稳定 `EventBatchId` 从 composition hash、SessionId、AgentId、CommandInvocationId、request fingerprint及 `prepared | dispatch-prepared | terminal` domain派生；terminal domain另含 canonical terminal fingerprint。SessionLog same-id/same-payload幂等，不同payload返回 conflict。Resume projection必须在开放正常admission前terminalize全部非terminal command：Prepared-only为 `InterruptedBeforeDispatch`，DispatchPrepared-only为 `OutcomeUnknown`；已有 terminal只恢复其redacted status/result projection，绝不重跑 command body。

Command Component metadata 的 `security` 必须声明其自身实现与 transitive non-Component runtime helper 的完整 ceiling，不能把 nested Tool/provider 的 effect 伪装成自己的 package effect。Resolver 以该 Component own operation effects 加实际 `cap:tool-executor`/其它 dependency binding stamps 计算 sealed effective ceiling；CommandProvider binding adapter 用 `BindingProviderContext` 把该 effective ceiling、own Component ceiling、ComponentId 与 dependency identities 密封进 `RegisteredCommand`。每个 `CommandDefinition` 的 static effects 必须是 effective ceiling 子集，declarative policy matched rule 只能增加且不得越过 effective ceiling；`CommandToolGrant` 只携带本次 static+matched-policy 并集，nested Tool 不得越过，并且 requested nested tool effects 必须已包含在该 command 的分类结果中。Host 产品 attestation 负责证明调用身份与产品授权，generated composition runtime security ceiling 仍决定这些 effects 是否能进入 binary。`plan-mode` 本身不产生外部 effect。

第一版 `plan-mode` 是 Agent-scoped Component，同时提供 `cap:command-provider`、`cap:agent-step-middleware`、`cap:tool-execution-middleware` 与 `cap:prompt-contributor`，并对 `cap:session-log` 使用 `UsesIfPresent`。它注册 `plan` command，状态只有 `Normal | Plan`：

```text
AgentHandle.execute_command("plan", { mode })
  → validate + confirm CommandInvocationPrepared
  → construct CommandPermit + confirm CommandInvocationDispatchPrepared
  → Durable: append AgentBehaviorModeChanged with stable batch id + Durable mode
  → Committed: atomically publish new in-memory mode
  → NotCommitted: retain old mode and return failure
  → CommitStatusUnknown: close admission and resolve batch before publishing either result
  → confirm CommandInvocationFinished before returning
  → next prompt/step/tool policy reads the same generation
```

Plan mode 的 tool middleware 拒绝 static/dynamic safety 含 write/process/network/remote-exec/code-exec 的 Tool call，不能被 prompt、Tool schema 或 runtime config 放宽。Prompt contributor 输出当前 mode 的版本化 instruction；step middleware 把 mode 写入本次 step context；`RequestPrepared` 记录 effective behavior mode。Command dispatcher 与 turn admission 共用 Agent mutation gate；active turn 期间的 mode 变更返回 `Busy`，不得修改正在执行的 step generation。Durable resume 从已提交的 `AgentBehaviorModeChanged` 投影恢复；Sessionless/Ephemeral 只保存在 Agent lifecycle 内。`NotCommitted` 保持旧 mode；不确定提交结果在解析前不返回成功/失败也不开放 admission，最终 mode 必须与 log 投影一致。关闭 `plan-mode` 后其 command、middleware、prompt contribution 和状态事件 producer 全部从 composition 消失；reader 仍能按 event vocabulary 识别历史事件。

AINS UI（当前 Dioxus）实现 `UserInteraction` / `Approval` provider；AINS `commands/*` 按命令拆成 Agent-scoped Integrator Component，提供 `cap:command-provider`，不进入 rust-agent core。

---

## 20. Subagent / Jobs / Agent Team

### Subagent

```rust
pub trait SubagentProvider: MaybeSendSync {
    async fn spawn(
        &self,
        owner: ChildOwnerContext,
        request: SubagentRequest,
        cancel: CancellationToken,
    ) -> Result<SubagentHandle, SubagentError>;
    async fn continue_agent(
        &self,
        id: SubagentId,
        request: SubagentContinueRequest,
        cancel: CancellationToken,
    ) -> Result<(), SubagentError>;
}

/// Exact parent-Agent-scoped consumer binding for the sole legal self-factory edge.
pub struct ChildAgentFactoryBinding {
    /* private Weak<dyn AgentFactory> + sealed AgentOwnerContext + parent binding stamp */
}

impl ChildAgentFactoryBinding {
    pub async fn seal_operation(
        &self,
        owner: &ChildOwnerContext,
        draft: AgentOperationDraft,
    ) -> Result<SealedAgentOperationDraft, AgentOperationSealError>;

    pub async fn allocate_operation(
        &self,
        owner: &ChildOwnerContext,
        draft: SealedAgentOperationDraft,
    ) -> Result<AllocatedAgentOperation, AgentOperationAllocationError>;

    pub async fn recover_operation(
        &self,
        owner: &ChildOwnerContext,
        operation_id: AgentLifecycleOperationId,
        draft: SealedAgentOperationDraft,
    ) -> Result<AllocatedAgentOperation, AgentOperationAllocationError>;

    pub async fn create(
        &self,
        owner: ChildOwnerContext,
        req: CreateAgentRequest,
    ) -> Result<AgentHandle, AgentLifecycleError>;

    pub async fn resume(
        &self,
        owner: ChildOwnerContext,
        req: ResumeAgentRequest,
    ) -> Result<AgentHandle, AgentLifecycleError>;
}

/// Registry entry exposed to a consumer in one exact parent Agent lifecycle.
pub struct SubagentProviderBinding {
    /* private provider handle + exact provider identity + volatile issuer or durable journal */
}

impl SubagentProviderBinding {
    /// 先固定 Spawn/Continue kind、target、bounded payload、attenuation、caller、
    /// provider identity与完整 canonical fingerprint；draft/returned token字段均私有。
    pub fn seal_operation(
        &self,
        draft: SubagentOperationDraft,
    ) -> Result<SealedSubagentOperationDraft, SubagentOperationAllocationError>;

    /// 仅供本次 parent lifecycle内完成、不承诺 cold recovery的调用。
    pub fn allocate_volatile_operation(
        &self,
        draft: SealedSubagentOperationDraft,
    ) -> Result<AllocatedSubagentOperation, SubagentOperationAllocationError>;

    /// 仅 Durable parent可用；返回前 Required reservation与恢复映射已 durable。
    pub async fn reserve_durable_operation(
        &self,
        recovery_key: DurableSubagentRecoveryKey,
        draft: SealedSubagentOperationDraft,
    ) -> Result<AllocatedSubagentOperation, SubagentOperationAllocationError>;

    /// Cold resume从 committed projection取得原 id/key，并以重新 seal的 exact draft恢复。
    pub async fn recover_durable_operation(
        &self,
        operation_id: SubagentOperationId,
        recovery_key: DurableSubagentRecoveryKey,
        draft: SealedSubagentOperationDraft,
    ) -> Result<AllocatedSubagentOperation, SubagentOperationAllocationError>;

    pub async fn spawn(
        &self,
        request: &AllocatedSubagentSpawnRequest,
        cancel: CancellationToken,
    ) -> Result<SubagentHandle, SubagentError>;

    pub async fn continue_agent(
        &self,
        request: &AllocatedSubagentContinueRequest,
        cancel: CancellationToken,
    ) -> Result<(), SubagentError>;
}

impl AllocatedSubagentOperation {
    pub fn into_spawn_request(
        self,
    ) -> Result<AllocatedSubagentSpawnRequest, SubagentOperationKindError>;

    pub fn into_continue_request(
        self,
    ) -> Result<AllocatedSubagentContinueRequest, SubagentOperationKindError>;
}

pub enum SubagentOperationAllocationError {
    ParentClosed,
    ParentNotDurable,
    AdmissionBudgetExceeded,
    CounterExhausted,
    OperationExpired,
    OperationConflict,
    IncompatibleParentLineage,
    JournalUnavailable,
    CommitStatusUnknown { operation_id: SubagentOperationId },
}

pub enum SubagentError {
    OperationExpired,
    OperationConflict,
    OutcomeUnknown,
    ChildLifecycleAllocation(AgentOperationAllocationError),
    ParentClosed,
    ProviderFailure { diagnostic: DiagnosticRef },
}
```

`SubagentOperationId` facade、draft/sealed/allocated request、allocation error、provider trait、`SubagentProviderBinding`与 `ChildAgentFactoryBinding`归 `rust-agent-extension-api`；只有 durable id/record的无领域行为 opaque DTO归 `rust-agent-runtime-api`供 Session canonical event引用。该依赖保持 `extension-api → agent → session → runtime-api → core`，`rust-agent-agent`不得反向依赖 extension-api。Draft、recovery key、sealed/allocated token与两种 allocated request字段私有，不能 Clone/Serialize/Deserialize或逐字段替换；只有 exact binding可 seal/allocate/recover并按 kind消费为 request。Generated Agent scope按 route注入私有 volatile issuer或 Durable journal facade以及 factory binding state，普通 provider/consumer不能构造或替换它。

Volatile allocator在返回 token时原子预留一个有界 pending slot；未使用 slot到 schema-fixed deadline自动释放且该 id永久 expired，不能重新激活。Volatile pending/in-flight/completed table受当前 parent `AgentResourceBudget`的 entry/byte/retention上限约束，parent teardown后不可恢复。Durable reservation则进入同一 parent SessionLog的 canonical operation table：它不能因 `AgentLifecycleNonce`更换或普通 wall-clock pending deadline被删除，只能由 terminal/显式 canonical abandonment推进；active durable entry数量与bytes仍受 generated hard ceiling和可重建的 `AgentResourceBudget`约束，超限时在 append/provider effect前拒绝。只有在所有 Job/Workflow/operation projection引用都已终止并通过版本化 checkpoint保留冲突检测后才能 compact，不能把仍可能 cold resume的 id滑出 retention后重新执行。

providers：

- subagent-in-process
- subagent-process
- subagent-remote
- subagent-codex-process
- subagent-claude-process

`cap:subagent` 是 Agent-scoped Registry；每个 key向 consumer暴露 `SubagentProviderBinding`，而不是可绕过 parent issuer的 raw provider。Binding adapter从 generated parent Agent scope取得不可伪造的 current admission owner，并密封 exact provider key/binding identity；Sessionless/Ephemeral只安装 nonce-bound volatile issuer，Durable还安装同一 Session writer lineage的 private canonical operation journal/recovery projection。`subagent-in-process` requires `cap:agent-factory`，其 Dependencies字段类型固定为 `ChildAgentFactoryBinding`，并派生 child owner；`subagent-process/subagent-codex-process/subagent-claude-process` require `cap:subprocess + cap:sandbox`；`subagent-remote` requires `cap:http-client + cap:credentials`。`subagent-delegation` requires `cap:subagent` 并提供 `cap:tool-provider`；所有 live handle/task必须归 current parent Agent lifecycle，不能 detached；durable record只允许新 lifecycle恢复/查询同一 operation，不把旧 task ownership延长到进程外。

`ChildOwnerContext`携带 current parent lifecycle identity/effective authority、exact requested attenuation、projected child-authority digest以及不可增加的 depth、total-descendant、concurrency、token/cost budget；它没有 public constructor。`SubagentOperationDraft`的 Spawn variant只能携带 `AuthorityAttenuation`与bounded domain input；`seal_operation`在任何 durable journal、child lifecycle allocation或 raw provider effect前，相对 binding密封的 current parent authority验证 attenuation/binding projection并构造 exact context/fingerprint，再原子预留额度，失败/teardown归还。Provider交给 child factory的 create/resume request必须携带同一 attenuation；binding/factory核对 seal而不重新选择 projection。子 Agent的 registry key、contributors、Tool/Command registrations、effect/confinement ceiling和 budget必须是 parent effective authority的子集；projection后 Required driver/model dependency不满足则创建失败。子 Agent不能通过重新 compose、Singleton fallback、runtime route或选择其它 registry key获得 parent未编译/未授权能力。

调用方必须先让将执行请求的 exact binding seal完整 draft，再选择一种互斥 lifetime。Seal把 canonical domain payload/attenuation/projection与current live admission owner分开：payload fingerprint不含 `AgentLifecycleNonce`、process-local cancellation handle或其它cold resume后必变字段，而 live owner seal仍保证本次调用只能从current binding进入。`allocate_volatile_operation`签发的 id由 `(AgentId, AgentLifecycleNonce, exact provider binding identity, monotonic sequence)`构成，只能在当前 live lifecycle使用；cold resume、cross-parent/provider、stale/future/counter-wrap和same id/different payload都在 raw provider/transport前拒绝。

`reserve_durable_operation`只接受 Durable parent及由其 generated journal facade从**已 committed** Job/Workflow/logical action coordinate签发的 `DurableSubagentRecoveryKey`。该 key已包含 stable caller kind、domain-separated logical coordinate与journal-issued non-reusing sequence；同 parent lineage内一个 key只能表示一个 logical action。Durable id是字段私有的 canonical tuple/hash `(StoreIdentity, SessionId, AgentId, exact provider binding identity, recovery key)`，**不含** `AgentLifecycleNonce`，所以不同进程无需在 reservation前猜随机数或争用易失 counter。Binding以一个 `AppendDurability::Durable` batch原子写入 `SubagentOperationReserved`，固定 id/key、canonical payload fingerprint、attenuation/projection digest与budget reservation，不持久化live nonce/cancellation handle。同 key/different payload/provider在 append前后都冲突；NotCommitted后只能用同 key+draft重试同 id，CommitStatusUnknown返回该 deterministic candidate id并关闭 logical operation admission直到按 stable batch id解析，绝不能把该 key/id分配给别的 request。Commit confirmed前不得构造 allocated request或调用 raw provider。

Cold resume后，新 `SubagentProviderBinding`首先以 current Session writer lease、stored `(StoreIdentity, SessionId, AgentId)`和 exact selected provider binding identity恢复 projection；`recover_durable_operation`要求 caller提供 committed projection中的原 id/recovery key以及重新 seal后逐字节相同的 fingerprint。它验证 current authority仍允许该 route/budget后返回绑定**新** live admission/cancellation owner的 allocated token，而不是用新 `AgentLifecycleNonce`否定旧 durable id。Wrong store/Session/Agent/provider/recovery key、变更 payload/attenuation/projection、route已删除或预算变窄到无法接管时返回 conflict/incompatible并保持原 record，不 fallback到其它 Registry key或生成新 id。Nonce-bound volatile id仍一律拒绝 cold recovery。Remote/process wire可以传递两种 canonical id bytes，但本地 binding的 variant/lineage/provider/fingerprint验证不能由 remote acknowledgement替代。

Provider 对 same id/same canonical payload 的 live retry合并或返回已知结果，对冲突 payload拒绝；process/transport loss后不能证明远端是否接受的 operation返回并（Durable时）记录 `OutcomeUnknown`，不得自动换 id重放。Durable binding先由 Reserved event建立 authoritative mapping；准备跨 raw provider/transport boundary时还必须以 stable batch id追加并确认 `SubagentOperationStateChanged(DispatchPrepared)`，只有 `Committed`后才调用 provider。Prepared append的NotCommitted零provider调用，CommitStatusUnknown只解析原 batch；provider返回accepted/known terminal后再追加相应StateChanged。Crash在Reserved时可安全从未dispatch状态继续，crash在DispatchPrepared后则只能按同 id查询/由provider明确安全续接，否则保持 `OutcomeUnknown/Paused`等待显式 Host决策，不能把“可能未发送”当成未发送而盲目调用。

`subagent-in-process`首次接受 spawn operation后，用同一 `ChildOwnerContext`调用 `ChildAgentFactoryBinding::seal_operation`，把完整 child mode/Session/attenuation、projected child authority、exact template plan与 namespace commitments固定为 canonical fingerprint；只有 seal成功才把 opaque draft交给 child lifecycle `allocate_operation`。Sessionless/Ephemeral child取得 parent/App-live且 fingerprint-bound的 volatile lifecycle capability；Durable child create/resume经同一 selected persistence issuer取得已携带完整 fingerprint的 confirmed Reserved capability，并把 outer `SubagentOperationId` canonical bytes作为唯一 correlation key写入 locator。Outer volatile路径只在 parent-lifecycle table固定 `SubagentOperationId → AllocatedAgentOperation + child fingerprint`，process loss不续接该 outer operation，backend按既有 durable child lifecycle协议收敛未完成 reservation/genesis；outer Durable路径还必须在 child effect前以 `SubagentOperationStateChanged(ChildLifecycleBound)`确认相同映射。后者若 crash发生在 child allocator commit与该 event之间，只可用 stable outer id correlation从 persistence locator找回原 child lifecycle id再补记，绝不能再次分配。Same subagent operation retry复用该映射，cold recovery重新 seal并分别经 durable subagent operation projection与 `ChildAgentFactoryBinding::recover_operation`核对。Child创建成功后首次 send才从 child `AgentHandle`分配一个 `AgentRequestId`并关联到同一 SubagentOperationId，retry复用映射而不重新分配 child request。

### Jobs

```rust
pub trait JobManager: MaybeSendSync {
    fn allocate_operation_id(&self) -> JobOperationId;
    async fn spawn(&self, request: JobRequest, cancel: CancellationToken) -> Result<JobId, JobError>;
    async fn status(&self, id: JobId) -> Result<JobStatus, JobError>;
    async fn cancel(&self, id: JobId) -> Result<(), JobError>;
}
```

`cap:jobs` 是 Agent-scoped Singleton，由 `job-runner` 提供；`cap:workflow` 是 Agent-scoped Singleton，由 `workflow-engine` 提供并 requires `cap:jobs`。会在当前调用返回后继续运行的 job/workflow state 必须在调度前以稳定 EventBatchId 写入 Durable SessionLog 并确认 Committed；Sessionless/Ephemeral Agent shutdown 时取消并 drain，不能声称可 cold resume。

第一版 `JobSpec` 是 `rust-agent-extension-api` 定义的版本化封闭 DTO，只含 timer、child-Agent/subagent orchestration 和 selected workflow 所需的 typed operation，不允许携带 tool name/schema、raw Tool handle 或任意 native callback；缺少对应 compiled capability 时返回 `UnsupportedOperation`。`job-runner` 不依赖 `cap:tool-executor` 或 `cap:agent-factory`，Workflow 也不得把 ToolExecutor/AgentFactory 当通用后台任务 API。需要后台模型/tool loop 的操作必须通过 `cap:subagent` 创建继承 parent owner、budget、security ceiling 的 child Agent；若选择 `subagent-in-process`，只有该 provider 内部通过唯一合法 self-factory edge 使用 `cap:agent-factory`。未来新增 Job-origin tool execution 时必须定义不可伪造、可借用且不能越过 job lifecycle 的独立 grant，不得复用 model-step/command permit。

`JobOperationId` 由 Agent lifecycle identity 和单调 sequence 分配，`JobRequest` 固定携带该 id、bounded JobSpec、deadline 与 resource budget；同 id/same canonical spec 的 live retry 合并，同 id/different spec 返回 conflict。首次 admission 固定传入的 cancellation lineage，retry 只能取消自身等待。JobId 从 operation id 确定性派生。Durable Agent 对 `Scheduled → Running/Paused/OutcomeUnknown → terminal` 的每次状态转换使用按 JobId/transition kind 派生的稳定 EventBatchId，并在触发下一动作前确认 Committed；需要 subagent action 的 committed transition还由 generated journal facade按 `(JobId, step/attempt logical coordinate)`签发并投影 `DurableSubagentRecoveryKey`，所以新 Agent lifecycle不必重新发明 operation id。Cold recovery 只恢复 timer 或能够用该 key映射的同一 child/subagent operation id查询/续接的 operation；无法证明先前动作未发生或可安全续接时固定投影为 `OutcomeUnknown`/`Paused`，等待显式 Host决策，不能盲目重放。Workflow step 使用相同规则并把 child JobId/recovery key写入 durable state。

Subagent 可以在 jobs 之上异步收集，但两者不能合并。

### Agent Team

第一版 `driver-team` 只协调由当前 Agent owner 创建的 child subagents，不新增 AgentTeam Capability。无共同 parent owner 的 peer/team coordination 延后到独立 Capability/API/Component，不能伪装成现有 parent-child delegation。

### LSP

LSP 是独立 capability。第一版 native provider 为 `lsp-local`，tool adapter 为 `tool-lsp`：

```text
lsp-local
  requires cap:subprocess (Required)
  requires cap:sandbox (Required)
  provides cap:lsp

tool-lsp
  requires cap:lsp (Required)
  provides cap:tool-provider
```

如果目标平台没有 LSP provider，`tool-lsp` 为 `Auto` 时由 resolver 记录 `RequiredCapabilityUnavailable` 并排除；显式 `Enabled` 时返回 `MissingCapability`，其 candidate diagnostics 逐项标明 `UnsupportedTarget`，不得只输出无来源的 UNSAT。

### Code Runtime

```rust
/// 只能在一次受保护的 Tool body 调用中由 ExecutionPermit 派生。
/// 不实现 Clone、Default、Serialize 或 Deserialize，字段私有。
pub struct CodeExecutionPermit<'a> {
    grant: DelegatedExecutionGrant<'a>,
}

impl<'a> CodeExecutionPermit<'a> {
    pub fn from_tool(
        permit: &'a ExecutionPermit,
        context: &'a ToolContext,
    ) -> Result<Self, CodeExecutionDenied>;
}

pub trait CodeRuntime: MaybeSendSync {
    async fn execute(
        &self,
        permit: &CodeExecutionPermit<'_>,
        context: CodeExecutionContext,
        request: CodeExecutionRequest,
    ) -> Result<CodeExecutionResult, CodeExecutionError>;
}
```

`rust-agent-code-runtime` API 依赖轻量的 `rust-agent-tools` permit contract。`ExecutionPermit::delegate(DelegatedEffect::CodeRuntime, context)` 在 rust-agent-tools 内校验当前 Tool 的 static/dynamic effects 已包含并获准 `CODE_EXEC`，生成字段私有、借用原 permit 的 `DelegatedExecutionGrant`；`CodeExecutionPermit::from_tool` 只能封装该 grant，并继承 root call id、caller identity、cancellation、deadline、depth/count/cost ceiling，再与 build-time confinement ceiling 求交。任何普通 Component、Host callback、Job、Workflow 或 Subagent 都无法独立构造 grant/permit。`cap:code-runtime` 是 Agent-scoped Registry。`code-runtime-sandboxed` requires `cap:subprocess + cap:sandbox`，`code-runtime-host` 使用 host-source config；canonical `tool-code-runtime` requires `cap:code-runtime`、声明 `CODE_EXEC` static effect 并提供 `cap:tool-provider`。代码执行只能发生在 ToolExecutor 已授权的 code-exec Tool body 内；runtime provider 仍执行 language/runtime allowlist、resource ceiling、output budget、cancellation 与完整 teardown。需要非模型触发代码执行的 Host 只能调用已编译的 `command-code-runtime`；该 Component requires `cap:tool-executor` 和 `cap:tool-provider(required-providers=[tool-code-runtime])`，用 `CommandToolGrant + ToolExecutor::prepare_command` 调用 `tool-code-runtime`，由 guarded pipeline 构造 `ExecutionPermit`，再由 Tool body 派生 `CodeExecutionPermit`。Command 和 Host 都不取得任何 execution permit，第一版不提供 raw CodeRuntime Host API。

---

## 21. Attachments / Spill

Attachments：持久身份对象。

```rust
pub trait AttachmentStore: MaybeSendSync {
    async fn put(&self, context: StorageCallContext, input: AttachmentInput) -> Result<AttachmentRef, AttachmentError>;
    async fn get(&self, context: StorageCallContext, id: &AttachmentRef, range: ByteRange) -> Result<Bytes, AttachmentError>;
}
```

Spill：超大临时 payload / tool output 外置。

```rust
pub trait SpillStore: MaybeSendSync {
    async fn put(&self, context: StorageCallContext, data: Bytes) -> Result<SpillRef, SpillError>;
    async fn get(&self, context: StorageCallContext, id: &SpillRef, range: ByteRange) -> Result<Bytes, SpillError>;
}
```

`StorageCallContext` 包含 cancellation 与 byte budget；所有 put/get 强制大小上限和 range 上限。`AttachmentRef` 带 provider key/content digest，实际保留期由 provider 的 build-time `durability` property 决定；`SpillRef` 带 owner Agent id 与 expiry，Agent teardown 删除 owned spill。两者不得使用同一个 interface。

`cap:attachment-store` 是 App-scoped Registry，providers 为 `attachment-memory/attachment-local/attachment-host`；`cap:spill-store` 是 Agent-scoped Singleton，providers 为 `spill-memory/spill-local/spill-host`。`tool-executor-guarded` 对两者使用 `UsesIfPresent`。未选择 SpillStore 时超过 inline output hard limit 的结果返回 `OutputTooLarge`，不得无界保存在内存。Spill 只用于当前 Agent 的临时数据流，`SpillRef` 不得作为 Durable ToolResult 的唯一 model-visible 内容；下一次 durable model call 前必须把结果转换为有界内联表示，或写入声明 `durability=durable` 的 AttachmentStore 并记录 content digest。Generated registry 保留每个 provider 的 durability property，Durable Agent 初始化时拒绝把 promotion route 指向 ephemeral provider。若两种固化方式都不能完成，SessionLog 追加结构化 `ToolResult(ContentUnavailable)` 并结束 turn，不生成消费该结果的 `RequestPrepared`。

---

## 22. Settings / Credentials / Telemetry

### Settings

第一版不定义 `cap:settings`。Build composition 只来自 normalized build config；runtime settings 只来自 generated、封闭的 `RuntimeConfig`，在 `AppHandle` build 成功后不可原地替换。需要改变 component config、binding routing mode/default、budget 或 policy 时，只能在**相同 composition hash/catalog digest** 下按 composition manifest 的 `app-handoff` 执行替换；第一版不提供隐式或零停机 lease stealing。正常 handoff 的 resume operation必须由将实际执行初次 `resume_agent` 的new Host先把never-reused recovery key与canonical `Resume { session_id, recovery_key, authority }` draft写入Host durable operation journal，再由new `AppHandle` seal完整draft并以同一key异步分配；返回后在对应调用前把id/fingerprint补写到同一journal entry。Old App不得为尚未开始的new-App handoff预生成key、seal或分配。Concurrent handoff 因能预构造 new App，必须在关闭旧 handle前完成 pre-journal、request-specific projection与persistent reservation；stop-old-app 则只能在 old App完整关闭、new App build成功后执行这组顺序，且在此之前不得开始任何 resume。Seal/allocation失败保持旧/closed Session状态且不产生 request，不能猜测 id。任一 process-loss retry遵循第 6 节规则：重建的 same-store/same-composition App从pre-journaled key/draft重新seal，并以same-key exact allocation读回原id；即使allocation response或id补写丢失也不能换key、id或request。

只有 `app-handoff=concurrent` 才允许预构造新 App。`AppBuilder` 把 aggregate mode、composition/catalog identity 和每个 shared field path + opaque handle identity 密封进 AppHandle；`new.verify_concurrent_handoff_from(&old)` 要求两边 mode 都为 concurrent、composition/catalog 相同、field set相同且每个 shared identity 相同，否则在关闭任何旧 handle 前返回 `AppHandoffError`，Host 必须改走 stop-old-app（若新 App 已无外部 admission，则先完整 shutdown 它）：

```text
build new AppHandle without opening the Session
  → new.verify_concurrent_handoff_from(old)
  → await sealing and allocation of every complete Resume draft from new AppHandle
  → durably save every new operation id + canonical draft + fingerprint in Host journal
  → await old AgentHandle::shutdown()
      (first closes admission, then drains turn/command, flushes SessionLog,
       and confirms writer lease release)
  → new AppHandle::resume_agent(request from the same allocated/recovered operation)
  → after Ready, switch Host/UI ownership to the new handle
  → after all Agents move, shutdown old AppHandle
```

`app-handoff=stop-old-app` 禁止先 build 新 App，其固定停机顺序是：

```text
stop Host/UI admission for all old Agents
  → await every old AgentHandle::shutdown() and confirmed lease release
  → await old AppHandle::shutdown() to release every App-scoped resource
  → build new AppHandle
  → await sealing and allocation of every complete Resume draft from new AppHandle
  → durably save every new operation id + canonical draft + fingerprint in Host journal
  → resume each Session with its exact allocated/recovered request
  → switch Host/UI ownership only after each returned handle is Ready
```

新 App build 失败时保持 Session closed；由于尚未从 new App seal/分配 operation，Host 重试同一 build sequence。Build 成功但 seal/allocation返回 error时同样不构造 resume request；只有 fingerprint-bearing persistent reservation与 Host journal都成功后，任一 resume失败、response loss或 process loss才必须复用相应 stored operation id/draft/locator resolution。不能重启旧 App后伪造旧 in-memory lifecycle，也不能换 id或 attenuation猜测结果。产品可显式重新构造旧 RuntimeConfig 的 App：没有 pending stored id时由该重建 App seal完整 draft、调用同一 async allocator并持久化；有 pending id时重新 seal journaled draft并用 `recover_agent_operation`验证相同 store/composition/catalog/fingerprint。两者都仍遵守 stored authority/composition identity。

`AgentHandle::shutdown()` 对 Durable Agent 只有在 writer lease 已确认释放后才返回 `Ok`；释放结果 unknown 时返回结构化 `WriterLeaseReleaseUnknown`，旧进程仍存活时 Host 必须保持新 resume 关闭，不能用重试窃取 lease。若进程在切换中崩溃，重启 Host 从 operation journal 复用原 resume id；persistence 只有在确认旧 owner/lease 失效并取得更高 fencing generation 后才允许 cold resume。新 resume 得到 `WriterConflict` 时不得关闭旧 handle 后盲目换 operation id 重试，必须先解析 journal phase 与 lease owner。`concurrent` 只是 App resource coexistence 声明，不改变 writer lease 顺序。相同 composition 只允许 authority 相对 stored authority 收窄；若 build composition/source/catalog 改变，则第一版不能直接 resume，必须保留旧 build 处理旧 Session 或等待独立 migration/import 工具。

需要无停机升级的未来版本必须新增由 persistence backend 原子签发并消费、绑定 SessionId/old generation/new owner/expiry 的 `SessionLeaseTransferToken` 协议，同时证明旧 admission 已关闭；在该协议进入 schema、crash tests 和 fencing invariant 前禁止“先 resume、后 shutdown”。UI preference、窗口状态、主题和产品账户设置由 Host 保存，不进入 rust-agent。后续若需要 live reconfiguration，必须新增带 prepare/validate/commit/rollback、版本 generation 和 capability-specific subscriber 的独立 seam，不能用全局 mutable map。

### Credentials

```rust
pub trait CredentialProvider: MaybeSendSync {
    async fn resolve(&self, context: CallContext, reference: &CredentialRef) -> Result<SecretString, CredentialError>;
}
```

`SecretString` 不实现 `Clone/Serialize/Debug/Display`，通过受限 closure 暂时暴露内容并在 owned buffer drop 时 zeroize。禁止 provider 把 secret 长期复制进普通 config / session event / telemetry；HTTP/provider error 必须先做 header/query/body redaction 再进入日志。

`CredentialRef` 包含 compiled credential provider key 与 provider-local opaque name；Registry 只路由到该 key，不得把同一 secret name 依次广播给所有 provider。缺失 key、provider 未编译或 Host provider 不可用均 fail closed。

### Telemetry

```rust
pub trait Telemetry: MaybeSendSync {
    fn event(&self, event: TelemetryEvent);
}
```

`telemetry-none` 应为零/极低成本实现；关闭 OTEL 时不得链接 OTEL crates。

---

## 23. Component / Capability / Binding Model

Component system 必须同时表达：

1. 哪个 package/component 被编译；
2. 它提供什么 capability；
3. consumer 如何绑定 provider；
4. provider binding 是 singleton、registry、ordered contribution 还是 decorator chain，scope instance 如何由 factory 构造；
5. instance 属于哪个 runtime scope；
6. 目标平台与安全 effects。

### Canonical Capability Catalog 与最小闭包

以下关系是第一版 resolver、golden tests、profile 示例和架构文档共同遵守的 canonical capability baseline。它不是第二份手工 catalog；实际 Capability/Component Catalog 由 `cargo metadata` 生成，本节定义必须由 metadata 表达并由 golden test 固定的闭包。

```text
cap:model
  binding: Registry
  scope: App
  providers: model-openai, model-deepseek, model-replay, model-host
model-openai / model-deepseek
  requires cap:http-client (Required)
  requires cap:credentials (Required)
  provides cap:model
model-replay / model-host
  provides cap:model

cap:agent-driver
  binding: Singleton
  scope: Agent
  providers: driver-direct, driver-tools, driver-planner, driver-team

cap:agent-factory
  binding: Singleton
  scope: App
  provider: generated-agent-scope-factory (allowlisted composition infrastructure)
  sole Agent-template consumer binding: ChildAgentFactoryBinding
generated-agent-scope-factory
  owns Agent(AppParent) / optional Session / Agent(SessionParent) templates
  exposes owner-scoped async/fallible lifecycle-operation allocation before create/resume
  requires every requested creation mode to have a satisfiable cap:agent-driver root
  consumes cap:command-provider (UsesIfPresent) in each Agent template
  constructs a non-replaceable model/tool request-journal facade for every AgentContext
  seals the paired ModelRequestJournalVerifier into each cap:model consumer binding
  seals the paired ToolCallJournalVerifier only into the selected AgentDriver's exact cap:tool-executor edge
  Ephemeral/Durable mode adds cap:session-log as a required Session-template root
  and uses that same SessionLog for both model RequestPrepared and model-origin ToolCall proofs
  Durable mode constrains its transitive cap:session-persistence provider to durability=durable
  Ephemeral mode constrains it to ephemeral-creation=staged-known-outcome

cap:lifecycle-observer
  binding: OrderedMulti
  scope: App
  providers: Integrator lifecycle observer Components
generated PublicationDirectory
  selectable: false
  consumes cap:lifecycle-observer (UsesIfPresent)
  owns atomic Agent/Session publication generations

cap:resource-namespace-bootstrap
  binding: Registry
  scope: App
  providers: resource-namespace-bootstrap-local plus audited external/remote bootstrap Components
  consumers: generated exact preparation edges only
  every call carries the projected Component/provide identity and stamped effects
  mandatory infrastructure performs no locator I/O itself
resource-namespace-bootstrap-local
  scope: App; provider key: resource-namespace-bootstrap-local
  provides cap:resource-namespace-bootstrap with effects=[read-local]
  security=[read-local], lifecycle-effects=[], stateless, no requires/decorates/hooks/namespace
  targets: desktop/server local-filesystem targets supported by fs-read-local/fs-local
fs-read-local / fs-local
  each required local resource-namespace marker derives the exact
  resource-namespace-bootstrap-local Registry edge

driver-direct
  requires cap:model (Required)
  requires cap:agent-step-middleware (UsesIfPresent)
  uses generated AgentContext request journal for every model call
  provides cap:agent-driver

driver-tools
  requires cap:model (Required)
  requires cap:tool-executor (Required)
  requires cap:session-log (UsesIfPresent)
  uses generated AgentContext request journal for every model call and model-origin tool call;
  only plan_call → prepare_tool_call → seal → execute_prepared may reach ToolExecutor dispatch;
  optional cap:session-log is only for its additional selected domain-event behavior
  requires cap:prompt-assembly (UsesIfPresent)
  requires cap:conversation-compaction (UsesIfPresent)
  requires cap:tool-result-pruner (UsesIfPresent)
  requires cap:token-meter (UsesIfPresent)
  requires cap:telemetry (UsesIfPresent)
  requires cap:agent-step-middleware (UsesIfPresent)
  provides cap:agent-driver

driver-planner
  requires cap:model (Required)
  requires cap:tool-executor (UsesIfPresent)
  requires cap:agent-step-middleware (UsesIfPresent)
  provides cap:agent-driver

driver-team
  requires cap:model (Required)
  requires cap:subagent (Required)
  requires cap:jobs (UsesIfPresent)
  requires cap:agent-step-middleware (UsesIfPresent)
  provides cap:agent-driver

cap:tool-provider
  binding: OrderedMulti
  scope: Agent
  providers: tool-fs, tool-shell, tool-terminal, tool-web,
             tool-skill, tool-lsp, mcp-client, subagent-delegation,
             tool-code-runtime

cap:tool-executor
  binding: Singleton
  scope: Agent
  providers: tool-executor-guarded

tool-executor-guarded
  requires cap:tool-provider (UsesIfPresent)
  requires cap:tool-execution-middleware (UsesIfPresent)
  requires cap:permission-policy (Required)
  requires cap:approval (UsesIfPresent)
  requires cap:spill-store (UsesIfPresent)
  requires cap:attachment-store (UsesIfPresent)
  provides cap:tool-executor

cap:tool-execution-middleware
  binding: OrderedMulti
  scope: Agent
  providers: plan-mode, Integrator middleware Components
cap:agent-step-middleware
  binding: OrderedMulti
  scope: Agent
  providers: plan-mode, Integrator middleware Components

tool-fs
  requires cap:fs-read (Required)
  requires cap:fs-write (UsesIfPresent)
  provides cap:tool-provider

tool-shell
  requires cap:shell (Required)
  provides cap:tool-provider

tool-terminal
  requires cap:terminal (Required)
  provides cap:tool-provider

tool-web
  requires cap:web-fetch (Required)
  requires cap:web-search (UsesIfPresent)
  provides cap:tool-provider

tool-skill
  requires cap:skill-provider (Required)
  provides cap:tool-provider

tool-lsp
  requires cap:lsp (Required)
  provides cap:tool-provider

subagent-delegation
  requires cap:subagent (Required)
  provides cap:tool-provider

tool-code-runtime
  requires cap:code-runtime (Required)
  provides cap:tool-provider
  derives CodeExecutionPermit from current ExecutionPermit only inside Tool::execute

command-code-runtime
  requires cap:tool-executor (Required)
  requires cap:tool-provider (Required, required-providers=[tool-code-runtime])
  provides cap:command-provider
  delegates with CommandToolGrant; never receives ExecutionPermit/CodeExecutionPermit

cap:fs-read
  binding: Singleton
  scope: Agent
  providers: fs-read-local, fs-local, fs-memory, fs-sandbox, fs-remote, fs-e2b
cap:fs-write
  binding: Singleton
  scope: Agent
  providers: fs-local, fs-memory, fs-sandbox, fs-remote, fs-e2b
fs-remote
  requires cap:http-client (Required)
  requires cap:credentials (UsesIfPresent)
fs-e2b
  requires cap:http-client (Required)
  requires cap:credentials (Required)
cap:subprocess
  binding: Singleton
  scope: Agent
  providers: subprocess-local
subprocess-local
  requires cap:confinement-verifier (Required, generated-only)
cap:sandbox
  binding: Singleton
  scope: Agent
  providers: sandbox-linux, sandbox-macos, sandbox-windows
sandbox-linux / sandbox-macos / sandbox-windows
  requires cap:confinement-issuer (Required, generated-only)
cap:confinement-issuer
  binding: Singleton
  scope: Agent
  provider: generated ConfinementAuthority issuer
  selectable: false
cap:confinement-verifier
  binding: Singleton
  scope: Agent
  provider: generated ConfinementAuthority verifier
  selectable: false
cap:shell
  binding: Singleton
  scope: Agent
  providers: shell-local, shell-ssh, shell-e2b
shell-local
  requires cap:subprocess (Required)
  requires cap:sandbox (Required)
shell-ssh
  requires cap:network-connector (Required)
  requires cap:credentials (Required)
shell-e2b
  requires cap:http-client (Required)
  requires cap:credentials (Required)
cap:terminal
  binding: Singleton
  scope: Agent
  providers: terminal-local
terminal-local
  requires cap:subprocess (Required)
  requires cap:sandbox (Required)
cap:permission-policy
  binding: Singleton
  scope: Agent
  providers: permission-default, mobile-policy
cap:approval
  binding: Singleton
  scope: App
  providers: approval-host

cap:session-log
  binding: Singleton
  scope: Session
  providers: session-log-events
cap:session-event-catalog
  binding: Singleton
  scope: App
  provider: generated-session-event-catalog (allowlisted composition infrastructure)
generated-session-event-catalog
  selectable: false
  contains declarations from exactly the selected Components
cap:session-persistence
  binding: Singleton
  scope: App
  providers: session-persistence-memory, session-persistence-jsonl,
             session-persistence-redb, session-persistence-remote
cap:session-read-store
  binding: Singleton
  scope: App
  provider-selection-source: cap:session-persistence
  providers: session-persistence-memory, session-persistence-jsonl,
             session-persistence-redb, session-persistence-remote
session-persistence-* providers
  provide cap:session-persistence and cap:session-read-store
  both provides carry the same durability property
  resolver selects the admin provider once and derives the read facade from it
session-log-events
  requires cap:session-persistence (Required)
  requires cap:session-event-catalog (Required)
  requires cap:session-observer (UsesIfPresent)
  provides cap:session-log
cap:session-observer
  binding: OrderedMulti
  scope: Session
  providers: Integrator observer Components
cap:session-query
  binding: Singleton
  scope: App
  providers: session-query-events
session-query-events
  requires cap:session-read-store (Required)
  requires cap:session-event-catalog (Required, generated read-only binding)
  provides cap:session-query
  implements list_sessions only through bounded SessionReadStore::list_sessions_page
generated AppHandle public projection
  exposes a read-only SessionQueryHandle only when cap:session-query is selected
  never exposes SessionReadStore admin/writer/repair operations
cap:session-projection
  binding: OrderedMulti
  scope: Session
  providers: session-projection-events
session-projection-events
  requires cap:session-log (Required)
  provides cap:session-projection
cap:session-title
  binding: Singleton
  scope: Session
  providers: session-title-basic
session-title-basic
  requires cap:session-log (Required)
  requires cap:model (Required)
  uses SessionOperationContext request journal with purpose=session-title
  provides cap:session-title

cap:kv-store
  binding: DecoratorChain
  scope: App
  providers: kv-memory, kv-redb, kv-indexeddb, kv-encrypted
kv-memory / kv-redb / kv-indexeddb
  provides cap:kv-store (base)
kv-encrypted
  decorates cap:kv-store
  provides cap:kv-store (decorator)
  requires cap:credentials (Required)
cap:vector-store
  binding: Singleton
  scope: App
  providers: vector-hnsw, vector-flat
cap:embeddings
  binding: Registry
  scope: App
  providers: embedding-openai, embedding-host
embedding-openai
  requires cap:http-client (Required)
  requires cap:credentials (Required)
cap:document-parser
  binding: Registry
  scope: App
  providers: parser-markdown, parser-pdf
cap:memory
  binding: Singleton
  scope: Agent
  providers: memory-context
memory-context
  provides cap:memory
  provides cap:prompt-contributor
  requires cap:kv-store (Required)
  requires cap:vector-store (UsesIfPresent)
  requires cap:embeddings (UsesIfPresent)
cap:retrieval
  binding: Singleton
  scope: Agent
  providers: retrieval-local
retrieval-local
  requires cap:vector-store (Required)
  requires cap:embeddings (UsesIfPresent)
rag
  requires cap:retrieval (Required)
  requires cap:embeddings (UsesIfPresent)
  provides cap:prompt-contributor
cap:skill-provider
  binding: Registry
  scope: Agent
  providers: skill-filesystem, skill-embedded, skill-remote
skill-filesystem
  requires cap:fs-read (Required)
skill-remote
  requires cap:http-client (Required)
  requires cap:credentials (UsesIfPresent)
cap:prompt-contributor
  binding: OrderedMulti
  scope: Agent
  providers: prompt-skills, rag, memory-context, plan-mode
cap:prompt-assembly
  binding: Singleton
  scope: Agent
  providers: prompt-assembly
prompt-assembly
  requires cap:prompt-contributor (UsesIfPresent)
  provides cap:prompt-assembly
prompt-skills
  requires cap:skill-provider (Required)
  provides cap:prompt-contributor

cap:network-policy
  binding: Singleton
  scope: App
  providers: network-policy-default, network-policy-host
cap:network-connector
  binding: Singleton
  scope: App
  providers: network-connector-native
network-connector-native
  requires cap:network-policy (Required)
cap:http-client
  binding: Singleton
  scope: App
  providers: http-client-native
http-client-native
  requires cap:network-connector (Required)
cap:web-fetch
  binding: Singleton
  scope: App
  providers: web-http-native, web-fetch-host
cap:web-search
  binding: Registry
  scope: App
  providers: web-search-deepseek, web-search-exa, web-search-perplexity,
             web-search-host
web-http-native
  requires cap:http-client (Required)
  provides cap:web-fetch
web-search-deepseek / web-search-exa / web-search-perplexity
  requires cap:http-client (Required)
  requires cap:credentials (Required)
  provides cap:web-search

cap:credentials
  binding: Registry
  scope: App
  providers: credentials-env, credentials-host

session-persistence-remote
  requires cap:http-client (Required)
  requires cap:credentials (Required)

cap:mcp-transport
  binding: Registry
  scope: Agent
  providers: mcp-transport-http, mcp-transport-stdio, mcp-transport-host
mcp-transport-http
  requires cap:http-client (Required)
  requires cap:credentials (UsesIfPresent)
  provides cap:mcp-transport
mcp-transport-stdio
  requires cap:subprocess (Required)
  requires cap:sandbox (Required)
  provides cap:mcp-transport
mcp-client
  requires cap:mcp-transport (Required)
  provides cap:tool-provider

cap:conversation-compaction
  binding: Singleton
  scope: Agent
  providers: compaction
cap:tool-result-pruner
  binding: Singleton
  scope: Agent
  providers: compaction
cap:token-meter
  binding: Singleton
  scope: Agent
  providers: compaction
cap:lsp
  binding: Singleton
  scope: Agent
  providers: lsp-local
lsp-local
  requires cap:subprocess (Required)
  requires cap:sandbox (Required)

cap:user-interaction
  binding: Singleton
  scope: App
  providers: user-interaction-host
  provider property: answer-recovery = unsupported | stable-until-commit-ack (required)
user-interaction-host
  provides cap:user-interaction (answer-recovery = stable-until-commit-ack)

cap:command-provider
  binding: OrderedMulti
  scope: Agent
  providers: plan-mode, Integrator command Components
plan-mode
  provides cap:command-provider
  provides cap:agent-step-middleware
  provides cap:tool-execution-middleware
  provides cap:prompt-contributor
  requires cap:session-log (UsesIfPresent)

cap:attachment-store
  binding: Registry
  scope: App
  providers: attachment-memory, attachment-local, attachment-host
cap:spill-store
  binding: Singleton
  scope: Agent
  providers: spill-memory, spill-local, spill-host

cap:subagent
  binding: Registry
  scope: Agent
  providers: subagent-in-process, subagent-process, subagent-remote,
             subagent-codex-process, subagent-claude-process
  each consumer entry is a parent-lifecycle-stamped SubagentProviderBinding with an operation-id issuer
subagent-in-process
  requires cap:agent-factory (Required) as ChildAgentFactoryBinding
subagent-process / subagent-codex-process / subagent-claude-process
  requires cap:subprocess (Required)
  requires cap:sandbox (Required)
subagent-remote
  requires cap:http-client (Required)
  requires cap:credentials (Required)

cap:jobs
  binding: Singleton
  scope: Agent
  providers: job-runner
job-runner
  requires cap:subagent (UsesIfPresent)
  requires cap:session-log (UsesIfPresent)
cap:workflow
  binding: Singleton
  scope: Agent
  providers: workflow-engine
workflow-engine
  requires cap:jobs (Required)
  requires cap:session-log (UsesIfPresent)

cap:code-runtime
  binding: Registry
  scope: Agent
  providers: code-runtime-sandboxed, code-runtime-host
code-runtime-sandboxed
  requires cap:subprocess (Required)
  requires cap:sandbox (Required)

cap:telemetry
  binding: OrderedMulti
  scope: App
  providers: telemetry-none, telemetry-otel
telemetry-otel
  requires cap:http-client (Required)
  requires cap:credentials (UsesIfPresent)

```

关键闭包：

```text
driver-tools
  → cap:tool-executor
  → tool-executor-guarded
  → cap:tool-provider
  → selected tool providers
  → their required capabilities

rag
  → cap:retrieval
  → retrieval-local
  → cap:vector-store
  → selected vector provider

memory-context
  → cap:kv-store
  → selected KV provider
```

`Registry` / `OrderedMulti` 允许多个已解析 provider 同时存在；具体集合由显式 component roots、profile、target、SecurityPolicy 和 provider-set 配置决定。build-time 固定 provider set，runtime 只能在该已编译集合中选择或迭代。

`generated-agent-scope-factory` 是 schema v1 唯一的 **authority-mediated deferred factory**。它的 App-scope `cap:agent-factory` provider binding只代表纯调度/构造与 lifecycle-operation签发能力，own runtime ceiling与 binding effects固定为空；Durable签发的实际 persistence effect仍由 selected `cap:session-persistence` binding记账。各 Agent/Session template中尚未实例化的 provider effects不得预先并入该 App binding，否则一个只允许窄模板的 parent会因 composition中另有高权限模板而错误失去 factory。反过来，template dependency也不是免于记账：每次 owner-scoped `seal_operation`先验证 exact parent stamp与完整 draft，选择唯一 creation mode/template variant/Registry key/contributor route，读取 Durable resume的 stored descriptor并计算 exact selected binding/effective-effect closure，再按第 6、29、33节完成 monotonic authority projection。Required binding被投影删除、任何 effect/key/contributor/budget越界或 durable stored authority不兼容时，必须在 namespace bootstrap、lifecycle reservation mutation、新 Session/Agent identity和 scoped provider initialize之前失败；只有投影保留的 required namespace才能取得一次性 stamped bootstrap call。Bootstrap descriptor/anchor也密封进 draft和 fingerprint，然后 `allocate_operation`只能为该 exact sealed result签发 id，`create`/`resume`只能消费相应 allocated capability。生成的 scoped binding stamps和 authority只能来自这次 exact projection，不能从另一个 template fallback，也不能沿用 factory的空 stamp作为授权。

该 deferred语义不能由普通 metadata Component、profile或 runtime config申请；它只允许绑定到 `GeneratedInfrastructure(generated-agent-scope-factory)`，不改变其它 provider/consumer的常规 selected-dependency effect closure规则。App-root只能经 `AppHandle`使用 seal/allocate/recover facade；唯一 Agent-template self edge只能取得字段私有、绑定 exact parent lifecycle/authority的 `ChildAgentFactoryBinding`，不能取得 raw `Arc<dyn AgentFactory>`、AppHandle或另一个 owner的 allocator。Catalog normalization、resolver、generated factory compile fixture和 architecture lint必须共同拒绝第二个 deferred capability、缺少 seal/allocator/recovery API的 self binding、可伪造 owner或未在 reservation前完成逐次 projection的 factory route。

Generator为每条可用 creation route产生字段私有、不可由 Host/config构造的 `DeferredAgentTemplatePlan`，至少密封 creation mode、parent variant、template id、compiled binding/key/contributor set、exact pre-projection effect closure与 construction-plan digest。Factory在 seal阶段为完整 draft选择并投影唯一 exact plan，把 stable owner lineage、effective authority/namespace descriptor与 projected plan digest纳入 request fingerprint；allocator只接受该 opaque sealed draft，并在 id返回前把相同 fingerprint/plan identity写入 volatile registry或 Durable Reserved locator。Create/resume不得再次选择或投影，且要求 allocated capability的 issuer/owner/fingerprint与 request完全一致再构造 scope。同一次 operation从 reservation到 terminal commit固定使用同一 plan digest，不能在 crash/retry后换模板。App binding的空 effect stamp、每条 template的完整 pre-projection closure、projection-required标志、seal/allocator-required标志与 plan digest都进入 composition manifest/hash；因此“延迟校验”仍是静态可审计输入，不是 runtime service discovery。

### Component choice

```rust
pub enum ComponentChoice {
    Auto,
    Enabled,
    Disabled,
}
```

`Enabled` 表示用户要求该组件存在；`Disabled` 是 hard exclusion。不能把它们当成 Cargo feature 的正负开关。

### Component role inference

Provider / Consumer / Contributor / Decorator 都不是 `ComponentSpec` 的持久字段。它们从 `provides`、`requires`、`CapabilitySpec.binding` 与 provide layer 派生：

```text
provides only
    → Provider

requires only
    → Consumer

provides + requires
    → Provider + Consumer

provides OrderedMulti contribution
    → Contributor

provides DecoratorChain binding with ProvideLayer::Decorator
    → Decorator

provides a capability whose trait creates shorter-lived instances
    → Factory provider
```

Factory 是 Capability API 的运行时语义，例如 App-scoped `AgentFactory`；它不是 cardinality。CLI 的 `component explain` 可以显示派生角色，但 resolver 不得以 role label 作为依赖语义输入。

Capability provider/consumer 的 owner identity 使用封闭 enum，不把 generated infrastructure 伪装成 Component：

```rust
pub enum BindingOwnerId {
    Component(ComponentId),
    GeneratedInfrastructure(GeneratedInfrastructureId),
}

pub type BindingProviderOwnerId = BindingOwnerId;
pub type BindingConsumerOwnerId = BindingOwnerId;
```

Schema v1 的 `GeneratedInfrastructureId` 封闭集合固定为 `generated-agent-scope-factory`、`generated-session-event-catalog`、`generated-publication-directory`、`generated-confinement-issuer` 与 `generated-confinement-verifier`；新增 id 必须升级 schema、golden 与 architecture fixtures。用户 metadata、profile、runtime config 和外部 Component 都不能创建该 variant。Generated infrastructure 的 own runtime ceiling 固定为空；除前述唯一 deferred factory 外，仍按普通规则通过 selected stamped binding 累计 consumer effective effects。它不进入 Component choice、one-Component-one-package 或 provider candidate 搜索。普通 `CapabilityProviderAdapter` 可接受两类 owner，但 Tool/Command/extension registration adapter 必须要求 `Component` variant；Host boundary 永远不能成为 capability owner。

### BindingKind

```rust
pub enum BindingKind {
    /// 一个 scope 内只有一个 binding，例如当前 AgentDriver。
    Singleton,
    /// 多 provider 同时编译/注册，runtime 可按 key 选择，例如 model/web/subagent。
    Registry,
    /// 有序多贡献者，例如 prompt sections / middleware / observers。
    OrderedMulti,
    /// 包裹 base provider，例如 encrypted KV、policy wrapper。
    DecoratorChain,
}
```

BindingKind 属于 `CapabilitySpec`，同一 Capability 的所有 provider 共享，Component 不得各自声明不同 binding。Cardinality 由 requirement 与显式 provider set 共同决定：

| BindingKind | `Required` 在当前集合为空时 | 已显式选择多个 provider |
|---|---|---|
| Singleton | 按候选顺序回溯选择一个 | ERROR，除非 profile 用 binding override 替换父选择 |
| Registry | 回溯选择一个作为最小非空集合 | 全部保留，key 必须唯一 |
| OrderedMulti | 回溯选择一个作为最小非空集合 | 全部保留，按 `order, component_id` 排序 |
| DecoratorChain | 回溯选择一个 base | 一个 base；decorator 按 `order, component_id` 包裹 |

Resolver 不会因为 Registry/OrderedMulti 中存在 Auto provider 就把所有候选自动拉入。除为满足 `Required` 选择的最小 provider 外，额外 provider 必须来自 explicit/profile root 或 provider-set include；`Auto` 本身不是 root。

### Requirement mode

```rust
pub enum RequirementMode {
    Required,
    UsesIfPresent,
}

pub struct CapabilityRequirement {
    pub capability: CapabilityId,
    pub mode: RequirementMode,
    pub field: RustFieldName,
    pub required_providers: Vec<ComponentId>,
}
```

`UsesIfPresent` 语义：图中已经存在则消费；不存在时不会为了它自动拉入 provider。`required_providers` 默认为空，只允许用于 `Required` Registry/OrderedMulti requirement；每个列出的 Component 必须以 Provider layer 提供该 Capability，并作为显式 requirement root 进入解析闭包。目标不支持、被 disable/conflict/security ceiling 拒绝或未进入最终 binding 时，consumer 不可满足。Dependencies field 仍接收整个 typed Registry/OrderedMulti binding，不向 consumer 暴露 concrete provider 类型。Singleton 精确选择仍使用 profile binding override，Decorator 仍使用 `decorates`。

Decorator 使用独立 requirement mode：

```rust
pub struct CapabilityDecoration {
    pub capability: CapabilityId,
    pub field: RustFieldName,
}
```

它只能用于同一 Component 同时以 `ProvideLayer::Decorator` 提供的 DecoratorChain Capability，顺序取对应 provide 的 `order`。Resolver 先解析唯一 base，再由内到外按 `order, component_id` 构造 decorators；decorator 不算作 base provider，不能单独满足 Required。

### Scope

```rust
pub enum ScopeKind {
    App,
    Session,
    Agent,
}
```

第一版只支持这三个 scope，避免过早引入 Turn/Request scope。

Runtime parentage 固定为：

```text
App
├── Agent                         # sessionless mode
└── Session
      └── Agent                   # durable composition
```

依赖合法性：

```text
App component     → App
Session component → App + Session
Agent component   → App + optional parent Session + Agent
```

Component 的所有 `provides` 必须属于同一 scope。一个 App-scoped factory 可以创建 Session/Agent scope，但不得把具体短生命周期实例存入 App singleton；跨 scope 只能保存 factory、registry、weak observation 或 owned handle。

### CapabilitySpec

```rust
pub struct CapabilitySpec {
    pub id: CapabilityId,
    pub api_package: CargoPackageId,
    pub rust_api: RustPath,
    pub binding_type: RustPath,
    pub binding_adapter: RustPath,
    pub binding: BindingKind,
    pub scope: ScopeKind,
    pub provider_selection_source: Option<CapabilityId>,
    pub provider_properties: ProviderPropertySchema,
}
```

`provider_selection_source` 默认 `None`。非空时当前 Capability 是同一 concrete provider 的派生 facade：source 与 derived Capability 必须具有相同 scope/binding kind，每个候选 Component 必须同时 provide 两者且 provider key（若有）相同；resolver 只对 source 做一次候选选择，再从同一 selected Component 生成 derived binding，不能分别 backtrack、override 或 runtime route。Derived requirement 会反向建立 source requirement，但 profile/binding/provider-set 只能配置 source Capability。两个 provide 仍各自声明 effects/properties，adapter 生成权限不同的 binding；derived facade 不继承 source 的方法或更宽 effect stamp。Schema v1 仅用它表达 `cap:session-read-store.provider_selection_source = cap:session-persistence`。

### ComponentSpec

```rust
pub struct ComponentSpec {
    pub id: ComponentId,
    pub package: CargoPackageId,
    pub scope: ScopeKind,

    pub factory: RustPath,
    pub dependencies_type: RustPath,
    pub config_type: RustPath,
    pub config_key: Option<ConfigKey>,
    pub config_source: ConfigSource,
    pub host_api: Option<RustPath>,
    pub wasm_host_constructor: Option<RustPath>,
    pub resource_namespace_preparer: Option<RustPath>,
    pub prepared_config_type: Option<RustPath>,

    pub provides: Vec<CapabilityProvide>,
    pub requires: Vec<CapabilityRequirement>,
    pub decorates: Vec<CapabilityDecoration>,
    pub session_events: Vec<SessionEventDeclaration>,
    pub runtime_primitives: BTreeSet<RuntimePrimitiveId>,
    pub conflicts: Vec<ComponentId>,

    pub targets: TargetPredicate,
    pub target_support: Vec<TargetSupport>,
    /// 只要该 Component instance 被 construct/initialize/activate 就可能发生；
    /// 必须显式声明，即使为空。
    pub lifecycle_effects: SecurityEffects,
    pub security: SecurityEffects,
    pub security_when_bound: Vec<ConditionalSecurityEffects>,
    pub build_requirements: BuildRequirements,

    /// Required exactly for App-scoped Components; conservative live-handoff rule.
    pub app_coexistence: Option<AppCoexistence>,

    /// 只用于 selected crate 内部 additive compile options。
    pub cargo_features: Vec<FeatureId>,
}

pub enum AppCoexistence {
    /// Any two schema-valid configs may initialize/activate independent instances safely.
    ConcurrentIndependent { evidence: EvidenceRef },
    /// Both Apps receive the same typed Host-owned handle; Component does not reopen it.
    ConcurrentSharedHostHandle {
        evidence: EvidenceRef,
        host_config_fields: Vec<HostConfigFieldPath>,
    },
    /// Port/file lock/database/device/global runtime or unknown ownership requires full stop.
    RequiresStop,
}

pub struct EvidenceRef {
    pub source: PackageRelativePath,
    pub algorithm: EvidenceDigestAlgorithm,
    pub digest: Digest,
    pub reviewer_policy: ReviewerPolicyId,
}

pub struct HostConfigFieldPath {
    pub component: ComponentId,
    pub field: RustFieldName,
}

#[derive(Clone)]
pub struct SharedHostHandle<T: ?Sized> {
    inner: Arc<T>,
    identity: Arc<SharedHostHandleIdentity>,
}

impl<T: ?Sized> SharedHostHandle<T> {
    pub fn new(inner: Arc<T>) -> Self;
    pub fn service(&self) -> Arc<T>;
    pub fn same_identity(&self, other: &Self) -> bool;
}
```

Build requirements 与 Host boundary 使用同一规范化值模型；它们是 catalog/build 输入，不是 runtime capability：

```rust
pub struct BuildRequirements {
    pub executables: Vec<BuildExecutableRoleId>,
    pub read_inputs: Vec<BuildReadInputRoleId>,
    pub environment: Vec<BuildEnvironmentRoleId>,
}

pub enum HostBoundaryKind {
    Entry { entry: RustPath },
    WasmExport { export_module: RustPath },
}

pub struct HostBoundarySpec {
    pub id: HostBoundaryId,
    pub package: CargoPackageId,
    pub kind: HostBoundaryKind,
    pub targets: TargetPredicate,
    pub target_support: Vec<TargetSupport>,
    pub security: SecurityEffects,
    pub runtime_adapters: BTreeSet<RuntimeAdapterId>,
    pub build_requirements: BuildRequirements,
}

pub struct RuntimeAdapterSpec {
    pub id: RuntimeAdapterId,
    pub package: CargoPackageId,
    pub constructor: RustPath,
    pub targets: TargetPredicate,
    pub target_support: Vec<TargetSupport>,
    pub primitives: BTreeSet<RuntimePrimitiveId>,
    pub security: SecurityEffects,
    pub app_coexistence: AppCoexistence,
    pub build_requirements: BuildRequirements,
}
```

三个 build requirement id type 共用 Component id 的规范化 kebab-case lexical rule，但分属不同 kind namespace；同字面 id 跨 kind 不相等。Host boundary package 只能声明一个 `host-entry` 或一个 `host-export`，不能同时声明二者或 Component/runtime-adapter metadata。`runtime_adapters` 是保序无关、去重后的非空兼容 allowlist；bin/wasm resolver 必须以它校验 selected adapter，library 不生成 Host boundary。Runtime adapter package 只能声明一个 adapter，`security` 在 schema v1 必须为空，primitive/target/support/app-coexistence/build-requirement 都从 `RuntimeAdapterSpec` 参与选择、identity 与 attestation。`BuildKind::Bin/Library/Wasm` 的 Host boundary cardinality和 exactly-one runtime adapter 在 resolver normalization 前验证，错误不得靠 Cargo compile failure 才暴露。

```rust
pub struct SessionEventDeclaration {
    pub kind: SessionEventKind,
    pub payload_version: u32,
    pub criticality: RecordCriticality,
    pub max_bytes: u32,
    pub max_depth: u16,
    pub affects_reconstruction: bool,
}

pub struct ConditionalSecurityEffects {
    pub requirement_field: RustFieldName,
    pub effects: SecurityEffects,
}
```

Conditional rule 只能引用本 Component 的 `requires[].field`；对应 `UsesIfPresent` 为 `Some` 或 Required binding 成功时生效。它只描述“consumer 自己在该依赖存在时才启用”的额外 package 行为，只能增加 effect，不能删除 unconditional、provide 或 dependency effect，也不得重复硬编码 provider 的实现 effect。`tool-fs` 因此不声明无条件 `READ_LOCAL`：它从 `fs_read`/`fs_write` typed binding stamp 取得实际 provider effects，并只在 `fs_write` 存在时生成写工具 schema；绑定 `fs-memory`、`fs-remote`、`fs-read-local` 时分别得到对应的 memory/remote/local effect，而不是把 capability 名误当成 local implementation。Component runtime ceiling 是 metadata 固定的 own ceiling，不随 binding 改写；Resolver 在每个候选分支绑定完成后重算每条 resolved binding effects 与 consumer effective ceiling，并再次应用 SecurityPolicy。Registry/Multi 不能用 runtime route 隐藏任何 compiled provider，最终 policy 检查使用全部 selected Component ceilings 与 selected Host boundary ceiling 的 union。Build requirements 另行按全部 selected/direct first-party root package 求并集并交给 BuildExecutionPolicy 验证，不参与该 effect closure。

```rust
pub enum ConfigSource {
    None,
    File,
    Host,
}
```

```rust
pub enum SupportTier {
    Experimental,
    Production,
}

pub struct TargetSupport {
    pub predicate: TargetPredicate,
    pub tier: SupportTier,
}
```

`support = "production"` 是覆盖 Component/runtime adapter/Host boundary 全部 target predicate 的简写；同一 package 在不同 target 处于不同成熟度时必须声明无重叠、完整覆盖 `targets` 的 `target-support` 条目，且不能同时保留 blanket `support`：

```toml
[[package.metadata.rust-agent.target-support]]
predicate = 'cfg(target_os = "linux")'
tier = "production"
```

Resolver 按当前 target 得到唯一 SupportTier，缺口或多重匹配都是 metadata error。Host boundary 先检查其封闭 `targets`，再检查 tier；target predicate之外的 iOS/Android等目标必须返回 `HostBoundaryViolation::UnsupportedTarget`，不能因 `cfg(not(wasm32))`、Integrator environment或某个 runtime adapter可用而扩大 entry 支持面。

`None` 禁止 `config_key`，`File/Host` 的 `config_key` 必须等于 component id。Component id、provider key 与 Capability 的 `cap:` suffix 只允许规范化 kebab-case（`[a-z][a-z0-9]*(?:-[a-z0-9]+)*`）；Capability metadata/manifest/diagnostic 始终使用完整 `cap:<suffix>`，CLI 与 TOML 的 `[bindings]`、`[provider-sets]`、`[binding]` 固定使用 suffix，parser 只在该边界补一次 `cap:` 并拒绝带 prefix 的重复写法。Generator 仅把 `-` 转成 `_` 形成 Rust identifier；映射结果若是 Rust keyword/reserved identifier，或与同一 generated namespace 的固定字段冲突，catalog normalization 直接拒绝，不使用 raw identifier 自动改名。Catalog normalization 在求解前验证这些约束。

每个 App-scoped Component 必须显式声明 `app-coexistence`，Session/Agent scope 禁止该字段；selected runtime adapter 作为 generated App owner 也必须声明并参与同一 aggregate。Metadata 的封闭形状是 `app-coexistence = { mode = "concurrent-independent", evidence = {...} }`、`{ mode = "concurrent-shared-host-handle", host-config-fields = [...], evidence = {...} }` 或 `{ mode = "requires-stop" }`；unknown/missing field、空 shared field、重复 field 或 concurrent mode 缺 evidence 均失败。`EvidenceRef` 固定 package-relative source、algorithm/digest/reviewer-policy；source 必须是进入 package snapshot 的普通文件且不能 symlink escape，bytes/digest/reviewer policy 进入 catalog input closure 与 composition hash；它不是普通 prose audit-ref。`concurrent-independent` evidence 必须证明同进程内任意两个 schema-valid Config/bundle 都可同时 initialize/activate independent real-resource instances，并至少覆盖 identical config、不同 config 与边界值 regression；不能证明 universal pair safety 的 Component/adapter 使用 `requires-stop`。`concurrent-shared-host-handle` 只允许 `config-source=host` Component，列出的每个 Config 字段必须使用 `rust-agent-runtime-api` 提供的 opaque `SharedHostHandle<T>`（私有 non-serialized identity、owned `Arc<T>`、`same_identity`，无从 endpoint/path reopen 的 constructor），两个 App 的 HostBindings 必须携带同一个 identity，Component 只能 clone/borrow inner handle，不能按路径/endpoint 再 open。Generator 在 build 前保存每个声明字段的 identity，handoff coordinator 比较 old/new manifest field path 与 identity；Host 不能用同资源的第二个 wrapper 冒充共享。其它情况使用 `requires-stop`。持有 Redb/SQLite file lock、固定 listener port、device、process-global runtime、single-writer exporter 或无法证明 ownership 的 App provider/adapter 必须 `requires-stop`。Composition manifest 对 selected App Components 与 runtime adapter 求并集：全为两种 valid concurrent variant 才得到 `app-handoff=concurrent`，任一 `requires-stop` 即得到 `app-handoff=stop-old-app`；RuntimeConfig 不得把后者升级。

声明 `session-events` 的 Component 必须是 Session/Agent scope，并 require `cap:session-log`；`UsesIfPresent` 时只允许在 binding 为 Some 的 route 产生事件。Event local kind 使用相同 kebab-case 规则，完整 kind 必须等于 `<component-id>/<local-kind>`，在 catalog 全局唯一。`affects-reconstruction=true` 强制 `criticality=required`；`max_bytes/max_depth` 必须在 schema hard ceiling 内。`cap:session-event-catalog` 只允许 generated infrastructure 提供，并只允许 `session-log-events` 与 `session-query-events` 消费，不接受 profile binding/provider-set 选择。App-scoped Component 需要写特定 Session 时必须通过 Agent/Session-owned command、job 或 factory operation，不得持有短 scope SessionLog。

```rust
pub struct CapabilityProvide {
    pub capability: CapabilityId,
    pub key: Option<ProviderKey>,
    pub priority: i32,
    pub order: i32,
    pub layer: ProvideLayer,
    pub properties: BTreeMap<PropertyKey, PropertyValue>,
    pub resource_namespace: ResourceNamespaceMode,
    /// 通过此 capability binding 可实际触发的 effects；必须是 Component
    /// runtime ceiling 的子集。多 capability Component 用它区分各 binding。
    pub effects: SecurityEffects,
}

pub enum ResourceNamespaceMode {
    None,
    Required { bootstrap: ProviderKey },
}

pub enum ProvideLayer {
    Provider,
    Decorator,
}
```

Capability metadata 定义 provider property 的封闭 schema；Component 的 provide 只能填 schema 允许的 enum/bool/integer 值，未知或缺失 required property 直接报错。`cap:session-persistence`、`cap:session-read-store` 与 `cap:attachment-store` 固定要求 `durability = "ephemeral" | "durable"`；同一 persistence Component 的 admin/read-store 两个 provide 必须声明相同 durability。`cap:session-persistence` 还固定要求 `ephemeral-creation = "unsupported" | "staged-known-outcome"`，该 property 进入 catalog/resolution/manifest；resolver 只用后者满足 NewEphemeral。声明后者的 provider 必须通过 abort/query-invisibility/known-outcome conformance；`durability=durable` 本身不自动证明该 route，provider 可以用独立 volatile substore 实现。NewDurable creation 只接受 durable provider，只有 durable AttachmentStore 能承载 SessionLog 的长期 content reference。`cap:user-interaction` 固定要求 `answer-recovery = "unsupported" | "stable-until-commit-ack"`；只有后者可进入向 Durable driver暴露interaction的Agent template，并必须通过same-operation resolution、crash-before/after answer commit与commit-ack conformance。Runtime config 不能改变任何 build-time provider property。

`resource_namespace` 从每个 provide 的显式 marker 规范化，缺省只允许映射为 `None`；`Required` 必须携带非空 canonical bootstrap Registry key。只要任一 provide 为 `Required`，`ComponentSpec.resource_namespace_preparer` 与 `prepared_config_type` 就必须同时存在并通过第 2 节 ABI 校验，并派生一条只允许 generated preparation context 消费的 exact `cap:resource-namespace-bootstrap` Required edge；全部为 `None` 时两字段和派生 edge 必须同时缺失。Bootstrap key 必须命中 selected普通 App Component，其 provide effects 覆盖该 resource kind 的 locator I/O 且是其 security ceiling 子集；该 Component 只允许 empty lifecycle-effects、stateless factory、零普通 requires/decorates/hook/required namespace。违反这组 bootstrap 构造约束、generated infrastructure 直接链接 locator transport，或 root/child projection 删除 consumer binding/effect后仍调用，全部 fail closed。Marker/bootstrap key、preparer path、prepared config type、required provide identity、derived binding/effect stamp 与生成的 namespace plan 都进入 canonical catalog/composition identity；normalizer 不允许丢弃字段后再从 capability 名、config type 或 locator 猜测。

`CapabilityProvide.effects` 描述通过该 binding 的 operation 可触发的 effects，不等于整个 Component package 的 runtime ceiling；`lifecycle-effects` 描述只要该 Component instance 被 construct/initialize/activate 就可能发生的 runtime effects。Metadata 对 lifecycle 和每个 provide 都必须显式写空或非空集合，禁止依赖缺省推断。Component 的 `security` 声明最终 target artifact 中该 package、linked native code 和 transitive non-Component runtime helper 的完整 runtime ceiling；build.rs/proc-macro/build-only helper 的 Host 行为只能进入独立 `build-requirements`，不得进入 runtime ceiling。Lifecycle、所有 provide effects 与 `security-when-bound` 都必须是 runtime ceiling 的子集。Resolver 把 lifecycle effects 加入该 Component 的每个 resolved provider binding，再沿实际 requirement/decorator edge 计算 consumer effective effects，并把 per-provide/per-key 结果写进 typed binding stamp。因此 authority 删除一个 effect 时，不会在本次 Session/Agent scope 中保留一个会在 initialize 阶段产生该 effect 的同 scope provider。例：若 `fs-local` 初始化不做 I/O，则 lifecycle 为 `[]`，其 `cap:fs-read` provide 为 `[read-local]`，`cap:fs-write` provide 为 `[read-local, write-local]`；package runtime ceiling 仍为两者并集。这样 runtime policy 和 child authority 可以保留只读 binding，而 security/build manifest 仍诚实声明 binary 中存在写实现；App-scoped provider 已发生的 root lifecycle 行为遵循第 29 节的 scope-specific authority 规则，不能被 child attenuation 追溯撤销。

Registry provide 必须声明 `key`；其它 binding 禁止 `key`。OrderedMulti 与 Decorator 使用 `order`；其它 binding 的 `order` 必须为零。Singleton/Registry/OrderedMulti 使用 `Provider` layer；DecoratorChain 必须恰有一个 selected base `Provider`，其余 selected layer 为 `Decorator`。

### Target

```rust
pub struct Target {
    pub triple: TargetTriple,
    pub arch: Arch,
    pub os: Os,
    pub environment: Environment,
    pub cargo_facts: CanonicalTargetFacts,
    pub target_fact_digest: Digest,
    pub custom_target_spec_digest: Option<Digest>,
}
```

Target predicate 至少能表达：

- native desktop/server；
- Linux/macOS/Windows；
- wasm-browser；
- iOS/Android；
- arch-specific provider。

Component predicate 使用封闭语法：`all/any/not`、Cargo 内建 target facts（`target_arch/target_os/target_env/target_family` 等）以及独立的 composition fact `environment = browser | server | desktop | mobile`。`environment` 不是 Cargo cfg、不是 `RUSTFLAGS --cfg`，也不得出现在 Component 自身 `[target.'cfg(...)'.dependencies]` 中；它只由 Composition Resolver 决定整个 Component package 是否进入 generated Cargo graph。需要 browser/server/desktop/mobile 差异的实现必须拆成 environment-specific Component，不能把环境差异藏在同一 package 的 target dependency 中。

Compiler 在任何 `cargo metadata` 前，用显式 target triple 和 composition compiler 选定的 rustc/sysroot 查询完整 `rustc --print cfg --target ...`，将 key/value 按 schema 规范化为 `CanonicalTargetFacts`；sorted fact set、target triple 与 custom-spec digest/`none` 共同产生 domain-separated `target_fact_digest`。查询使用的 rustc bytes/sysroot identity作为 provenance 单独记录，不混入 fact digest，因此另一个 policy toolchain只有在产生完全相同 facts时才可复现该 input。Compose 的 rustc/toolchain source 必须是显式 build config 或 rust-agent distribution 的 pinned identity，不能从 ambient `PATH` 猜测。Custom target 必须把原始 spec 作为 compose input snapshot，按 canonical JSON + raw-bytes identity 产生 `custom_target_spec_digest`，generated metadata/build 只引用该 snapshot，不能在 build 时重新读取原路径。对 Cargo manifest 的 target-specific dependencies，只按这份已固定的内建 target facts 校验和重写；对 Component selection，再额外计算 environment predicate。Generator 不注入自定义 cfg，不依赖 ambient `RUSTFLAGS`；用于 package/catalog discovery的 `cargo metadata --filter-platform`也必须使用同一 triple/spec，但该输出不证明 build-host unit、实际编译 unit或 unit-specific feature，最终 build/Host integration仍必须按第 3节和第 27节的 unit-graph contract验证。禁止读取 Host probe、自定义 build-script cfg、环境变量或其它文件系统状态来改变 resolution。这样同一个 `wasm32-unknown-unknown` 可以有明确的 browser environment，而不会假设 Cargo 能理解产品级 environment。

Production build 在 fetch、build script 或 Cargo compilation 前，必须用 BuildExecutionPolicy 选中的 exact rustc/sysroot 对同一 triple/custom-spec snapshot 重算 canonical facts；rustc/toolchain identity可以不同于 compose 时的 identity，但重算的 `target_fact_digest` 与 `custom_target_spec_digest` 必须逐字节相等，否则返回 `TargetFactMismatch`。Build manifest/attestation 同时记录 expected/actual digest。这个 preflight 保证 Cargo build 看到的 target-dependent dependency facts正是 resolver 已纳入 closure 的 facts，不能只比较 triple。

App-coexistence `reviewer-policy` 的 allowlist 与所需 evidence schema/version 是 normalized catalog trust input；production compose 对 unknown policy、evidence document schema/rule-set mismatch 或 digest mismatch fail closed，并把 trust-input digest 写入 composition identity。它只认证被审查的 source/test evidence，不把一次测试结果伪装成任意配置/资源都安全的运行时证明；声明仍属于 Component TCB 和 code review 范围。

### Metadata 来源

CapabilitySpec、ComponentSpec、RuntimeAdapterSpec 与 HostBoundarySpec 不手工复制整个 workspace；由 `cargo metadata` 中的 API/Component/runtime-adapter/Host-boundary metadata 生成标准化 catalogs，再叠加 profile/config choice。Catalog normalization 必须拒绝未知字段、未知 schema version、重复 id/key、非法 Rust path、scope 不匹配、binding-specific 字段错误、runtime primitive/namespace ABI 字段不完整，以及 Host boundary kind/cardinality/adapter allowlist 错误。Component 的 `runtime_primitives` 保留为 canonical set，resolver 只从该字段与 schema-owned infrastructure requirement 计算 primitive union，并据此生成逐 Component projection；不得重读 raw TOML 或从实现依赖猜测。Production compose 只允许所选 target 上为 `Production` 的 Component、runtime adapter 与 Host boundary；提升 support tier 必须有对应 target 的 regression evidence，不能只因代码能交叉编译就提升。

## 24. Composition Resolver：确定性约束求解

`rust-agent-composition::resolver` 必须是纯算法模块：不读网络、不初始化 provider、不执行 Cargo build。

输入：

```text
Generated Capability + Component Catalog
Normalized Catalog Trust Policy
User Choices
Normalized Profile
Target
BuildKind + Selected Host Boundary
Required Agent Creation Modes
Provider Preferences
Singleton Binding Overrides
Registry/Ordered Provider Sets
Security Policy
```

Creation mode 是封闭 enum：`Sessionless | Ephemeral | Durable`。Resolver 不把它们压成布尔 `session_enabled`；每个 mode 分别进入 satisfiability、manifest 与 generated AgentFactory route。

输出：

```text
Compiled Component Set
Selected Host Boundary (bin/wasm only)
Excluded Components + provenance
Capability Bindings
Provider Registries
Scope Construction Plan
Per-App Component Coexistence Evidence + Aggregate App Handoff Mode
Session Event Catalog
Available Agent Creation Modes
Initialization DAG
Selected Internal Cargo Features
Generated Cargo Dependencies
Diagnostics
Security Manifest Input
Resolution Provenance Graph
```

### Hard constraints 与 requirements 分离

Hard constraints：

```text
Explicit Disabled
Unsupported Target
Security Policy Denial
Support Tier Denial
Hard Conflict
Invalid Scope Dependency
Invalid Binding Cardinality
Invalid Decorator Chain
Invalid Derived Provider Facade
Invalid Deferred Factory
Invalid Host Boundary Cardinality / Target
```

User/build requirements：

```text
Explicit Enabled
Profile Required Component
Required Capability
Explicit Singleton Binding
Explicit Provider-Set Include
```

如果显式要求的组件不可满足，production build 必须 ERROR；不能悄悄把显式 enabled 组件降成 disabled。Profile inheritance 必须先标准化：child 的 Singleton binding override 替换 parent 对同一 Capability 的 binding root；`agent-modes/targets/build-kind/host-entry/host-export/environment/security/confinement` 在 child 明写时整体替换、未写时继承；Component choice map 按 id 合并，child 覆盖 parent，同一 profile 内一个 id 同时 enable/disable 时 ERROR。Resolver 只接收标准化后的最终 requirements，不在求解过程中猜测继承优先级。标准化后 `host-entry` 与 `host-export` 互斥，并按 build kind 执行第 3 节的精确 cardinality/target 校验。

### Provider candidate ordering

候选 provider 的顺序确定：

```text
Explicit Singleton Binding / Explicit Provider-Set Include Order
> Profile Preferred Provider
> CapabilityProvide priority (descending)
> Stable Component ID order
```

但**顺序只是搜索顺序，不是 greedy final choice**。

### Deterministic bounded backtracking

Resolver 对 required capability：

```text
Need cap:X
   ↓
ordered candidates [X1, X2, X3]
   ↓
try X1
   ↓
propagate dependencies / conflicts / scope rules
   ↓
constraint failure?
   ├─ No  → keep
   └─ Yes → rollback branch → try X2
```

这样可以避免：第一候选因 conflict 失败，就错误地把本来可由第二 provider 满足的 consumer 关闭。

组件规模在几十到百级时不需要通用 SAT solver；自定义 deterministic CSP/backtracking 足够，并更容易输出人类可读 diagnostics。Production resolver 只使用 normalized input 中固定的 `resolver-decision-budget`，不使用依赖机器速度的 wall-clock 截止时间；未配置时把 metadata schema 规定的固定默认值物化进 normalized config。耗尽 budget 返回 `ResolutionLimitExceeded`，包含 budget、已探索 decision 数与 frontier digest；不得报告成 `Unsatisfiable`。外部取消单独返回 `Cancelled`，不写入可缓存 resolution。

### Fixed-point 仍用于闭包传播

每个候选分支内部执行：

```text
Normalize input
  ↓
Apply hard exclusions
  ↓
Seed explicit/profile requirements
  ↓
Resolve bindings / candidate branch
  ↓
Propagate required component/capability closure
  ↓
Validate target + conflicts + scope dependency
  ↓
Resolve ordered/registry/decorator bindings
  ↓
Detect construction cycles
  ↓
Topological order per scope
  ↓
Stable result
```

### Scope dependency legality

scope dependency 固定为：

```text
App provider      → App
Session provider  → App + Session
Agent provider    → App + Session(if present) + Agent
```

Session 与 Agent construction plan 是由 App scope 保存的 typed factory template，不是启动时创建的实例。Resolver 分别生成 `Agent(AppParent)` 与 `Agent(SessionParent)` 两个 template variant：前者的 `UsesIfPresent(Session capability)` 注入 `None`，且禁止 Required Session edge，只服务 Sessionless；后者在同一 prepared Session scope下把已选 Session binding注入 `Some`，是否已进入 authoritative event/index按具体 creation protocol决定。SessionParent 只有在 exact selected `cap:session-persistence` provide声明 `ephemeral-creation=staged-known-outcome`，且对应 provider conformance覆盖 staged abort、pre-commit query/index invisibility与 known commit outcome时，才生成 Ephemeral route；`durability=ephemeral|durable`都不能替代该 property/proof，`durability=durable, ephemeral-creation=unsupported`明确只可服务 Durable。Durable route则要求 `durability=durable`，不要求 provider同时支持 Ephemeral。某 route不可满足时只移除对应 creation mode，不删除其它合法 mode；profile/build requirement明确要求该 mode时 composition失败。禁止长生命周期 singleton静态持有具体短生命周期实例；跨 scope只能依赖 typed Factory、owned Handle或不延长生命周期的 observer。

Agent template中 `subagent-in-process`对 App-scoped `cap:agent-factory`的依赖是唯一允许的 late-bound self-factory edge。Generated infrastructure以 `Arc::new_cyclic`等等价机制创建 factory，template只保存 private weak factory与 parent lifecycle/authority stamp，并组装为 `ChildAgentFactoryBinding`；每次 allocate/create/resume时临时升级，App或 parent teardown/upgrade failure返回 `Closed`。Consumer永远不取得 raw `Arc<dyn AgentFactory>`。`job-runner`、workflow、Tool、Command和其它 Component均不得直接 require AgentFactory；它们通过 `cap:subagent`使用 child orchestration。该唯一 edge不在 App construction中调用 factory，不允许 Component自行声明其它 late-bound cycle，也不能跳过同 scope DAG cycle validation。

cycle validation 分四类：App construction DAG、Session-scope template DAG、Agent(AppParent) template DAG、Agent(SessionParent) template DAG。父 scope binding 作为已构造输入，不参与子 scope 的 cycle；同 scope Required/Decorator edge 必须无环，UsesIfPresent 一旦绑定也进入对应 variant 的 cycle 检查。

### Resolution provenance

每个结论必须可解释：

```text
tool-shell
  RequiredBy(profile:cli-coding)

shell-local
  CandidateFor(cap:shell)
  RejectedBecause(UnsupportedTarget(wasm32))

shell-ssh
  SelectedBecause(
    RequiredBy(tool-shell),
    FirstFeasibleCandidateAfterBacktracking
  )
```

`component explain`、support/debug、security audit 都从 provenance graph 生成。

## 25. Enable / Disable / Unsatisfied Requirement 语义

Build config：

```toml
[components]
tool-shell = "enabled"
shell-local = "disabled"
shell-ssh = "disabled"
```

解析：

```text
tool-shell explicitly required
  ↓
requires cap:shell
  ↓
all providers excluded by explicit disable
  ↓
UNSATISFIABLE BUILD
```

Production build 输出：

```text
error: explicitly enabled component `tool-shell` cannot be satisfied

required capability:
  cap:shell

candidate providers:
  shell-local  rejected: ExplicitDisabled
  shell-ssh    rejected: ExplicitDisabled
```

而不是把 `tool-shell` 悄悄标记成 disabled 后继续 build。

### Auto component 的 disable propagation

如果某 consumer 只是 `Auto`：

```text
tool-shell Auto
all cap:shell providers unavailable
```

可解析为：

```text
tool-shell Excluded(RequiredCapabilityUnavailable(cap:shell))
```

并继续 build。

### UsesIfPresent

如果 `driver-tools`：

```text
UsesIfPresent(cap:telemetry)
```

telemetry 不存在时 driver 继续工作；Resolver 不因 optional edge 自动拉入 telemetry provider。

### Explicit Disabled 的真正含义

`Disabled` 作用于 Composition Compiler 的 component graph：

> **被禁止组件不会进入 generated Cargo.toml。**

不通过 negative Cargo feature 实现，不依赖 feature precedence，也不允许其它 dependency path 把同一高风险实现 crate 重新带回。

## 26. Composition Compiler

用户级编译控制面：

```text
rust-agent.toml
      +
cargo metadata / component metadata
      +
target / security policy
      +
reviewed Cargo.lock
      ↓
Composition Compiler
      ↓
Resolution Plan
      ↓
Generated Cargo.toml
Generated Cargo.lock
Generated config.rs
Generated session_events.rs
Generated composition.rs
Build/Security Manifest
      ↓
rust-agent build → policy-controlled cargo --locked --offline
```

Composition Compiler 是 **Cargo 前置编译器**，而不是 `build.rs` 里试图修改当前 crate dependency graph 的脚本。

原因：当前 Cargo dependency closure 必须在 crate 编译前已经确定；正在编译的 crate 不能靠自身 source/build.rs 反向给本次构建增加任意新的依赖关系。

### Compose / Lock / Build

用户执行：

```bash
rust-agent compose --workspace-manifest Cargo.toml --profile cli-coding \
  --target x86_64-unknown-linux-gnu --lock
rust-agent build --composition <composition-hash> --locked \
  --execution-policy build-policies/ci-linux.toml
```

内部：

```text
Phase A: Compose in a staging directory
  1. normalize/reject Cargo resolution context in an isolated Cargo home
  2. query and snapshot canonical target facts/custom target spec
  3. discover packages
  4. normalize metadata
  5. solve constraints
  6. snapshot selected path-package dependency closure
  7. generate Cargo.toml / .cargo/config.toml / config.rs / composition.rs
  8. validate or materialize Cargo.lock under the same resolution context
  9. compute hash and atomically publish content-addressed directory

Phase B: Build and package
  10. validate BuildExecutionPolicy, target facts and locked source cache
  11. invoke cargo build --locked --offline in enforced sandbox
  12. for build-kind=wasm, invoke pinned wasm-bindgen in the same sandbox
```

`--lock` 允许 Cargo 为 staging composition 生成 lockfile；这是显式 dependency resolution 操作，可以访问配置的 registry。生产 `build --locked` 不生成或更新 lockfile，缺失或需要更新时直接失败。CI 和发布流程保存 generated Cargo.lock 并审查其 diff。`cargo build` 仍是最终 Rust compiler/build engine；Composition Compiler 只负责生成正确、最小、可审计的 Cargo input。

Schema v1 不继承 Cargo 的 ambient discovery context。Compiler 在执行第一次 `cargo metadata` 前，解析 trust root 可生效的 manifest/config chain并拒绝任一 `[patch]`、`[replace]`、named/alternate registry dependency，以及 trust root/ancestor 中可生效的 `.cargo/config` 或 `.cargo/config.toml`；两种 config 并存同样拒绝。Ambient `CARGO_HOME`、Cargo credentials、source replacement、registry default/index/protocol 和 git-fetch setting一律不可见，metadata/lock 使用 runner-owned empty Cargo home、隔离工作目录及 generator 产生的 schema-versioned canonical Cargo config。第一版 canonical context 只允许 schema 固定的 crates.io source、checksum-locked registry package、URL + precise commit 的 git package和 trust-root 内 path package；需要 patch、source replacement 或 private/named registry 的输入必须先发布为受支持的固定 source identity，不能由 discovery 隐式改写。

Compiler 生成 `cargo-resolution.json` 记录 canonical source identities、registry protocol/index、git transport mode、config schema 和 isolation flags，并从它逐字节派生 `.cargo/config.toml`；二者、其 digest及所有 Cargo invocation的 exact `--config`/isolated-home contract 进入 composition payload。Discovery metadata、`--lock`、locked fetch、standalone build与 graph verification全部复用这一 context；任何阶段出现不同 source identity、父目录 config、ambient home 或 Cargo 未识别的 config merge都 fail closed。这样 generated standalone workspace 要么精确复现 discovery resolution，要么在 composition 阶段拒绝，而不会到 build 时悄悄选择另一来源。

`build --locked` 把依赖获取与代码执行分开：先在隔离 Cargo home 的 fetch runner 执行 `cargo fetch --locked` 并验证 registry checksum/git precise revision；fetch runner 只允许 Cargo、配置的 registry/git endpoint、credential helper，以及 Cargo 固定会调用的 pinned toolchain identity query。根据 [ADR 0001](docs/adr/0001-cargo-fetch-target-information-query.md)，fetch request/observation schema v2 对后者仅允许 BuildExecutionPolicy 选中的 exact read-only rustc，以及逐字节匹配的 `rustc -vV` 或 Cargo 1.97.1 固定 read-only target-information query；后者只从 stdin 的空 crate source读取，以固定顺序请求 file-names/sysroot/split-debuginfo/crate-name/cfg，并且 Host query 不带 `--target`、target query只带 request固定的 exact normalized Cargo target input。不得经 wrapper/alias/response file替换，不允许 codegen、build script、proc macro、source tree binary或其它 rustc 参数。Linux backend为 Cargo 捕获 query输出所需的 null stdin提供 runtime-identity绑定的零长度普通只读文件和 exact `/dev/null` logical symlink，不挂载 Host device或其它 `/dev` entry。若 selected Cargo 版本需要新增 query surface，必须升级 schema/allowlist并纳入 runner identity，不能临时放宽为任意 rustc execution。随后 build runner 在 composition 外的 isolated working directory 中使用显式 target dir、`cargo build --locked --offline` 和继承到全部 descendant process 的 filesystem/network sandbox 编译。Production build 必须接收 versioned BuildExecutionPolicy；缺失 policy、Host backend 不支持或任一约束无法强制执行时失败。`--development-build` 可以使用未隔离 runner，但 build manifest 固定标记 `deployable = false`，其 artifact 不能用于 release packaging 或 production attestation；它不改变 composition identity，也不能充当 emitted composition 的 production Host 验证证据。

BuildExecutionPolicy 不进入 composition hash。Normalizer 同时产生两种 domain-separated digest：完整 `build-execution-policy-digest` 绑定本次 runner mapping、fetch/attestation trust 配置并只用于 receipt/attestation 一致性；path-free `build-enforcement-identity-digest` 才进入 build artifact identity：

```toml
schema = 1
id = "ci-linux-hermetic-v1"
host = 'cfg(target_os = "linux")'
backend = "linux-landlock-seccomp"

[fetch]
network-endpoints = ["https://index.crates.io:443", "https://static.crates.io:443"]
credential-helper = { path = "/opt/rust/bin/cargo-credential-helper", sha256 = "..." }
max-redirects = 0

[attestation]
allowed-executors = ["rust-agent-build-v1", "rust-agent-build-host-v1"]
trusted-signers = [
  { id = "ci-runner-2026", algorithm = "ed25519", public-key = "/opt/rust/keys/ci-runner-2026.pub", sha256 = "..." },
  { id = "security-review-2026", algorithm = "ed25519", public-key = "/opt/rust/keys/security-review-2026.pub", sha256 = "..." },
]
trusted-reviewer-policies = [
  { id = "cargo-feature-semantics-v1", signer-ids = ["security-review-2026"], min-signatures = 1 },
]
signing-helper = { signer-id = "ci-runner-2026", path = "/opt/rust/bin/rust-agent-ci-sign", sha256 = "..." }

[toolchain]
cargo = { path = "/opt/rust/bin/cargo", sha256 = "..." }
rustc = { path = "/opt/rust/bin/rustc", sha256 = "..." }
sysroot = { path = "/opt/rust/toolchains/pinned", tree_digest = "..." }

[[read-input]]
id = "target-sdk"
path = "/opt/sdk/x86_64-linux-gnu"
tree_digest = "..."

[[executable]]
id = "target-linker"
path = "/opt/sdk/bin/x86_64-linux-gnu-cc"
sha256 = "..."
version = "<exact-version>"

[[executable]]
id = "wasm-bindgen-cli"
path = "/opt/rust/bin/wasm-bindgen"
sha256 = "..."
version = "<exact-compatible-version>"

[[environment]]
id = "vendor-sdk-channel"
variable = "VENDOR_SDK_CHANNEL"
value = "stable"

[derived-executable]
roots = ["target"]
inherit-sandbox = true
```

`BuildEnforcementIdentity` 是完整 normalized policy 的 schema-owned semantic projection。它只包含会影响受控 build 的逻辑身份与强制语义：schema/backend semantic class、selected logical toolchain/executable/read-input/environment role、各自 content/tree digest、mode/version/target role、runner logical mount/variable value、deterministic baseline、derived-executable 与 descendant sandbox rule、实际 requirement→logical-id mapping，以及 target/resolution/prefix-remap 等 normalized build setting。它明确排除 policy administrative `id`、Host selector、全部 canonical Host path 和 credential/fetch runner concrete mapping，以及整个 `[attestation]` trust plane（allowed executor、trusted signer/reviewer key、signing helper path/digest）；这些仍由完整 policy digest 和 signed attestation约束。相同 bytes/version/tree/逻辑角色移动到另一 Host mount，或只轮换 signer/helper/trust policy，必须得到相同 `build-enforcement-identity-digest`；logical input bytes、normalized environment value或实际 sandbox semantics 变化则必须得到不同 digest。Projection 仍保留 logical mount path，所以 prefix remap 后的 build-visible path 可复现，但绝不能回填 concrete Host path。

`trusted-reviewer-policies` 可以为空；一旦 HostFeatureUnionPolicy 引用某 id，该 entry 必须存在、`min-signatures >= 1` 且不超过唯一 signer 数，所有 signer id 必须命中 `trusted-signers`。Feature-semantics evidence envelope 必须以 domain-separated digest 绑定 canonical evidence bytes、package identity/source checksum、policy id 和每个签名；pre/build-host/post 都验证 threshold 和同一 evidence digest，不能把 build executor 自签当成独立 source review。

Composition 中的 normalized build-requirement union 必须在 Cargo 启动前逐项解析到本 policy 的 exact logical id：`executables` 只能命中 `[[executable]].id`，`read-inputs` 只能命中 `[[read-input]].id`，`environment` 只能命中 `[[environment]].id`。每个 `[[executable]]` 固定唯一 kebab-case id、canonical path、bytes digest 与 normalized exact `version`；runner 在首次执行前同时验证 digest和 schema指定的无副作用 version probe，任一不符拒绝。每个 environment entry 把 kebab-case `BuildEnvironmentRoleId` 映射到 exact concrete variable 与 canonical non-secret value；`variable` 必须匹配 `[A-Z_][A-Z0-9_]*`，id/variable 均唯一，value 进入 normalized policy 与 attestation，其 schema-normalized logical value进入 `BuildEnforcementIdentity`。Host absolute path value 必须先映射为 runner logical mount path；concrete path 只留在 full policy/attestation，不进入 build-output identity。命中 rust-agent 固定 secret/proxy/credential denylist、重复映射或 unknown value encoding 均拒绝。Runner 只向实际 requirement union 引用的 entry 注入其 exact `variable=value`，policy 中未使用的 entry 不暴露给 build。

`PATH`、`LANG`、`LC_ALL`、`SOURCE_DATE_EPOCH` 是 schema 固定的 deterministic runner baseline，不是 Component 可申请的 environment role，也不得出现在 `[[environment]]`：`PATH` 只由已解析 executable allowlist 生成，后三者固定为 `C.UTF-8`、`C.UTF-8`、`0`。Policy 可以提供 composition 未使用的资源，但 runner 只挂载/暴露 union 实际引用的最小子集以及固定 toolchain/source/target/temp/deterministic-environment baseline；缺少命中、类型错配、同 id 不同 variable/value、Component 未声明而 dependency-family gate 检出实际使用，都使 production build 在执行任何 build script 前失败。该 requirement→policy resolution 的 logical id/content/version/role projection、逐项 provenance 和 aggregate identity digest进入 build manifest；含 concrete mapping/full policy item digest 的记录只进入 enforcement-attestation payload，二者都不进入 composition runtime effect set。

Policy normalization 固定验证：所有 path 必须绝对 canonical path；fetch endpoint 必须是规范化 HTTPS origin 或 exact SSH host/key policy，redirect 只能落到显式 allowlist 且计入上限；credential helper 与 fetch 所需的 `git` 必须作为带 digest 的 fetch-only executable 声明。Production policy 的 `allowed-executors`、`trusted-signers` 和唯一 `signing-helper` 均不得为空；每个 signer 固定 id、algorithm、public-key bytes digest，unknown algorithm 或重复 id 拒绝，helper 的 signer id 必须命中 trusted signer 且 executable digest 必须匹配。Signing helper 使用版本化协议，只接收 domain-separated canonical payload digest、CI workload identity 和由 trusted supervisor 产生且绑定 operation kind、executor/verifier identity、backend/upstream evidence digest 与 payload digest 的一次性 completion handle；它独立验证三者后返回 signer id/algorithm/signature，拒绝通用任意 digest 签名。Helper 可以连接 runner 外的 HSM/CI identity，但不得接收 artifact/source/secret bytes；没有可验证 completion handle 的本地环境只能产生 development evidence。Toolchain、SDK、linker、C/C++ compiler、assembler、`pkg-config`、code generator 和其它预置 build-time executable 必须分别进入 `executable` allowlist 并记录文件 digest；其只读数据目录进入 `read-input` 并记录 tree/package identity。位于 canonical target/temp root、由已受 sandbox 约束的 build process 写入的 build-script/host helper 可以作为 derived executable 运行；其首次执行记录 digest/provenance，且它与后代始终继承完整 sandbox，只能启动静态 allowlisted executable 或 target/temp 内的 derived executable。`BuildEnforcementIdentity` 使用 logical id、content digest、mode/version、target role 与 logical mount，不使用 Host absolute path；absolute path 只作为本次 runner mapping 进入 full policy digest 与 redacted attestation。Runner 为 composition/source/cache/toolchain/SDK/target/temp 注入固定 logical mount path，并强制 rustc/C/C++ 的 debug/file prefix remap，禁止 clone path、state root 或 temp path进入 artifact identity。Composition、verified Cargo source cache 与 policy inputs 在 build runner 中只读；只有独立 target、temp 和 runner-owned diagnostic directory 可写。未声明的 Host filesystem、用户目录、workspace、Unix socket、named pipe、device、credential store 与 network 全部不可见。所有 descendant 只能执行静态 allowlisted 或合法 derived binary 并继承相同或更窄 sandbox，禁止通过 wrapper、dynamic loader、response file 或 symlink 切换预置 executable identity。动态链接器和 system runtime 若为执行所需，必须作为只读 policy input 明列，不能使用隐式 Host 全盘读取。

Schema 3 production policy 可以声明一个 closed `host-linker` bundle：一个 linker executable id 和按 id 排序、无重复的 helper executable id 集合；每个 id 都必须分别命中带 digest/version 的 `[[executable]]`。Normalized build requirements 对该 bundle 只能全不选或全选，partial selection 必须在 Cargo 前失败。选中时，planner 与 build 固定传入 exact `target.<build-triple>.linker="/rust-agent/tools/<linker-id>"` Cargo command-line config，并固定 `COMPILER_PATH=/rust-agent/tools`；production build 还必须在 exact `--sysroot=/rust-agent/toolchain` 后注入唯一的 encoded rustc argument `-Clinker-features=-lld`，关闭 rustc 对 schema-selected helper 的隐式 self-contained LLD 替换。Component 不得覆盖。该选择及 logical paths 进入 schema 2 `BuildEnforcementIdentity`，其 backend semantic version 对该执行语义固定为 4；exact encoded rustc arguments 进入 Cargo invocation identity 与受监督 execution observation，concrete Host paths 仍仅进入 full policy/attestation。Linker、helper、startup object、linker script 与 compiler runtime 必须由 policy/runtime closure 分别绑定，禁止 wrapper、alias、runtime-tree executable fallback 或 ambient PATH/filesystem discovery。

普通 executable version probe 仍只能执行被探测文件且以 `/` 为只读 working directory。Schema 3 `ProductionInputIdentityRequest` 以 closed `host-linker`/`host-linker-helper` file role 区分 bundle probes，旧 schema 不得获得该语义。Host-linker helper（例如会在 `--version` 内部创建临时文件并派生 `ld` 的 GCC `collect2`）使用独立 schema-owned probe class：每个 probe 获得新的 runner-owned `/rust-agent/probe-tmp` writable mount、固定 `COMPILER_PATH=/rust-agent/tools`，且 descendant allowlist 只能是 fully selected Host-linker bundle；network 仍隔离，probe 后丢弃该目录。该 probe 的 observation 必须绑定主 executable、实际 descendant digest、logical working directory 与 writable mount；不得把这项例外授予 bundle 外 executable、复用 build target/temp，或暴露 Host temp/ambient helper。

Fetch runner 只挂载只读 composition/Cargo.lock 和独立可写 Cargo cache staging，只允许 Cargo、fetch-only executable 与 policy endpoint 网络。Registry token/SSH agent 不得通过 ambient environment、用户目录或 Host socket 继承；凭据只能由 runner 通过限时、限 endpoint 的管道交给 declared credential helper，不进入 cache、diagnostic 或 attestation。Fetch 成功后逐项验证 checksum/precise revision，再以同文件系统 staging 原子发布 immutable verified cache；build runner 无凭据、无网络、只读挂载该 cache。

生产 runner 清空 ambient `RUSTFLAGS/RUSTDOCFLAGS/CARGO_ENCODED_RUSTFLAGS/RUSTC_WRAPPER`、Cargo profile override、代理变量与未由 schema baseline或已解析 `[[environment]]` role 产生的 build environment；`PATH/LANG/LC_ALL/SOURCE_DATE_EPOCH` 使用固定 baseline，额外变量只使用 selected entry 的 exact `variable=value`，不得读取同名 ambient value。选中 schema-owned Host linker bundle 时，baseline 还包含固定 `COMPILER_PATH=/rust-agent/tools`，build-owned `CARGO_ENCODED_RUSTFLAGS` 必须且只能按顺序包含 exact `--sysroot=/rust-agent/toolchain` 与 `-Clinker-features=-lld`；未选 bundle 时后一个参数必须不存在。Build script/proc macro 可以读取 composition、verified source、toolchain和显式 read-input，可以在 target/temp 写入；不能读取 secret。Target linker、rustc flags、canonical Cargo resolution config、target-fact/custom-spec digest、toolchain/input/executable/environment-role 的 path-free identity、sandbox semantic class/version 和规范化 logical environment 通过 `BuildEnforcementIdentity`、exact Cargo invocation identity 与 execution observation进入 build-output digest；concrete mappings、完整 normalized policy 与 enforcement evidence 只进入 attestation。依赖预置环境可以跳过联网 fetch，但仍执行 locked source verification。

Linux runner 把 exact compiler dynamic-library closure 放在 `/rust-agent/runtime/lib`，并把 pinned Host `lib/rustlib/<build-triple>` subtree 放在同一 inferred sysroot；Host build-script/proc-macro 因而只能解析到该 closure。Target-compiled unit 仍显式使用 `/rust-agent/toolchain` sysroot。Host native link 所需的 system runtime、startup object、linker script、compiler support 与 plugin 文件按 canonical logical location复制进 isolated root；若 compiler driver 会按 `argv[0]` 重定位 install root，runner 必须用 sandbox 内的 exact logical linker `argv[0]` 派生并投影该 root（包括固定 `COMPILER_PATH` 下需要的 LTO plugin），不能只复制 Host 原始安装路径。选中 Host-linker bundle 时必须关闭 rustc 的 implicit self-contained LLD，因此 native link 只能执行该 bundle 已分别 descriptor-bind/probe 的 helper；不得把 Rust sysroot/runtime tree中的 `ld.lld` 或其它文件隐式提升为 executable。全部文件进入 runtime-tree digest；未复制的 Host path 不可见。

Build sandbox backend 支持矩阵固定为：Linux 使用受监控的 Landlock + seccomp/no-new-privileges 或等强度 namespace runner；macOS 使用由 CI runner 提供并 attested 的 deny-by-default filesystem/network sandbox；Windows 使用 restricted token、Job Object、filesystem ACL/virtualized workspace 与 runner-level outbound firewall。平台原语不能可靠阻止 descendant network/filesystem escape 时，只接受隔离 VM/container executor 的签名 attestation；仅设置环境变量、Cargo `--offline`、应用层 proxy 或 Job Object 不构成 network/filesystem isolation。Policy 声明的 backend 与 attestation backend 必须一致。Production executor 在 sandbox 退出、输入与 artifact digest 复验完成后，由 runner 外层 signer 对 domain-separated canonical attestation payload 签名；私钥、signing socket/service 和 credential 不挂载进 fetch/build runner。Verifier 必须校验 signer allowlist、公钥 digest、payload signature 和 executor/backend identity；签名、nonce、timestamp 与 transparency proof 只在 outer envelope，不进入 build-output identity。

Composition publish 只允许把完整 staging directory 原子 rename 到 `<state-dir>/compositions/<hash>`；目标已存在时逐字节验证 canonical payload、derived identity 与 manifest，完全一致则复用，任一差异返回 `CompositionStoreCorruption`，不得覆盖。

`build` 在 Cargo 前后都重算 composition manifest、generated sources、snapshot 与 Cargo.lock digest；任一不符即失败并丢弃本次 artifact。Production runner 把 published composition directory 挂载为只读，Cargo target/output 使用独立可写目录；不得让 build script 修改 source snapshot。

### Composition hash

Hash 输入至少包含：

- normalized build config；
- selected profile；
- target triple、rust-agent environment、canonical target-fact digest 与 custom target-spec digest/`none`；
- build kind、selected runtime-adapter package/metadata，以及 selected Host boundary package/kind（bin/wasm；library 为空）；
- normalized integration id / generated root package name；
- resolver/generator/metadata/identity schema version；
- resolved component set 与每个 selected Capability/Component/Host boundary 的 normalized metadata；
- provider binding、scope construction、creation-mode、event-catalog 与 security/confinement plan；
- selected internal features；
- canonical Cargo resolution config/record 的 schema、完整内容与 digest；
- generated Cargo.lock 完整内容；
- selected path package snapshot 的 logical package id、version、source revision 与 canonical snapshot-tree digest；该 tree digest 覆盖每个 entry 的 logical path、type、raw file-content digest 与下述 normalized build-visible metadata；
- deterministic resolution provenance 中会影响 manifest/exclusion 结果的字段。

生成器先在 state root 的 same-filesystem staging path 工作，最终目录名不参与 hash。Normalized build config 必须物化最长 40 bytes 的 kebab-case `integration-id`；未显式给出时固定为 `<build-kind>-p<profile-digest-12>-t<target-digest-12>`，digest 是对完整 normalized UTF-8 profile id/target triple 的 SHA-256 前 12 个小写 hex。Generated root package name 固定为 `rust-agent-composition-<integration-id>`，version 使用 generator schema 规定的常量，都不包含 composition hash，避免 Cargo.lock 与目录 hash 循环依赖。同一最终 Host Cargo.lock 中可同时可达的 emitted composition 必须使用不同 integration id；`verify-integration` 拒绝 digest prefix 或 generated package name/version/source 碰撞，碰撞时必须重新 compose 并提供显式唯一 id。Compiler 对 selected Component、selected Host boundary、direct API/infrastructure 以及它们的 transitive path helper dependency 做闭包，把 `cargo package --list` 等价文件集复制到 `sources/<logical-package-id>/`，解析 workspace inheritance，并把 path dependency 重写为 snapshot 间的稳定相对路径；generated Cargo 不引用活动工作区。Snapshot 覆盖 manifest/source/build.rs/proc-macro/assets 与 dirty working tree，排除 Cargo target、rust-agent state root 与原始 Host metadata。Discovery canonicalize 每个 package file，拒绝越出 trust root 的 symlink、非普通文件、case-fold collision 和重复 canonical path。

所有 composition/source/Host-input snapshot 使用同一个版本化 canonical metadata contract：regular file 固定只读且不可执行（POSIX view 为 `0444`），directory 固定只读可遍历（`0555`），uid/gid 使用 runner logical identity，atime/mtime/ctime/birthtime 固定为 schema epoch，link count、device/inode/generation 与其它 backend-exposed stat 字段使用 schema-defined deterministic value；不支持某字段的平台必须提供语义等价的固定 view。Source snapshot 中的文件不能作为 executable；可执行输入只能来自 BuildExecutionPolicy allowlist 或 target/temp 内合法 derived executable。Directory enumeration 与 canonical tree encoding 按 normalized logical path 排序。Production backend 若不能隐藏或规范化任一 build.rs/proc-macro 可观察的 Host metadata，不得生成 production evidence。

`snapshot-tree-digest = SHA-256("rust-agent-snapshot-tree-v1\0" || deterministic-CBOR(sorted entries(logical path, type, raw content digest, normalized metadata)))`。Materializer 在发布 snapshot 前验证实际 view 等于 canonical metadata，`build`、`build-host` 和 `verify-integration` 在 Cargo 前、mount 后及 Cargo 后均从实际只读 view 重算并比较 tree/item/aggregate digest；chmod、mtime 或其它 metadata 漂移即使文件 bytes 未变也必须在执行或接受产物前失败。Snapshot 完成后设为只读，Cargo.lock、composition hash 与 build 都只读取 snapshot；临时目录、clone 绝对路径和环境变量不得进入生成内容。构建完成后的 rustc/Cargo/Host 信息进入 build attestation，不进入 composition hash。相同 normalized config、catalog、target、source bytes 与 Cargo.lock 必须得到相同 hash、canonical metadata view 与生成内容。

Composition hash 使用 domain-separated canonical payload；payload 包含全部语义输入、snapshot、Cargo.lock 和不含 identity 的 generated source。Hash 算出后才生成 `identity.rs`、composition manifest 中的 hash 字段和 ref；这些 derived fields 不反向进入 payload，验证器要求它们严格等于重算结果。Runtime 只从 generated `identity::COMPOSITION_HASH` 读取 SessionLog composition identity，禁止从目录名、环境变量或 runtime config 注入。

Schema v1 的 identity algorithm 固定为：

```text
file-digest        = SHA-256(raw file bytes)
snapshot-tree-digest = SHA-256("rust-agent-snapshot-tree-v1\0" ||
                              RFC 8949 deterministic CBOR(sorted canonical tree entries))
canonical-payload  = RFC 8949 deterministic CBOR(normalized typed payload)
template-plan-digest = SHA-256("rust-agent-deferred-agent-template-v1\0" ||
                              RFC 8949 deterministic CBOR(template plan without composition identity))
composition-hash   = SHA-256("rust-agent-composition-v1\0" || canonical-payload)
manifest-digest    = SHA-256("rust-agent-manifest-v1\0" || RFC 8785 JCS(manifest object))
```

Template plan digest 的输入只含 creation mode、parent variant、template id、compiled binding/key/contributor set、pre-projection effect closure 与 construction plan，不含 composition hash、operation id 或 runtime authority，避免与 composition hash 循环；最终 projected plan 另进入 AgentBindingProjection digest。其它 typed payload 禁止 float、timestamp、Host absolute path 和 unordered collection；path 使用 `/`、相对 logical root、UTF-8 NFC，map/set 按 canonical encoding 排序。Generator 自己产生的文本固定 LF 与结尾 newline；snapshot source 和 Cargo.lock 作为原始 bytes 计算 digest，不改写源码换行。Composition directory 使用 `composition-hash` 的 64 字符小写 hex；manifest/ref 同时记录 algorithm/schema，未知 algorithm 拒绝读取。

Lifecycle request fingerprint 固定为 `SHA-256("rust-agent-lifecycle-request-v1\0" || deterministic-CBOR(normalized draft, stable structural owner lineage, composition hash, event-catalog digest, effective-authority descriptor digest, AgentBindingProjection/projected-template digest, sorted resource-namespace descriptor commitments))`。Create/Resume kind、SessionMode或 SessionId、完整 deny-only attenuation都在 normalized draft中；operation id刻意不在其中，使 allocator能在签发 id前持久化 fingerprint。实际 path、credential、prepared anchor handle、易失 App nonce和其它 secret不进入 bytes，但相应 schema-owned namespace commitment与稳定 owner lineage必须进入，因而 restart可以重做 preparation并验证同一 request，而不能把 reservation重绑定到另一个 authority/route。

## 27. Generated Cargo Dependency Graph 与 Static Composition

Composition Compiler 生成一个真正可独立构建的 composition crate：

```text
.rust-agent/compositions/<composition-hash>/
├── Cargo.toml
├── Cargo.lock
├── cargo-resolution.json
├── .cargo/
│   └── config.toml
├── rust-agent-composition.json
├── sources/
│   └── <logical-package-id>/
└── src/
    ├── lib.rs
    ├── main.rs          # 仅 build-kind=bin
    ├── wasm.rs          # 仅 build-kind=wasm
    ├── config.rs
    ├── session_events.rs # 仅选中 Session plane 时生成
    ├── identity.rs      # derived COMPOSITION_HASH
    └── composition.rs
```

Generated `Cargo.toml` 固定包含独立 `[workspace]`，避免 composition directory 位于源 workspace 下时被父 workspace membership 规则隐式接管；所有 path dependency 只指向同目录 `sources/` snapshot。Generated `.cargo/config.toml` 只能从相邻 `cargo-resolution.json` 派生，不能接纳用户片段；Cargo 总在无 ancestor config 的隔离 logical root、empty `CARGO_HOME` 下以该 exact config运行。Direct dependency、resolver version、edition、crate type 和 profile 设置均由 generator 明写，不继承用户 shell环境中的 Cargo feature/registry/source状态。所有 generated direct Component/API/Host dependency 固定写 `default-features = false`；这些 package 的 `[features].default` 必须为空，mandatory behavior 不得藏在 default feature 中。

`lib.rs` 始终 re-export 同一 snapshot source identity 的 `RuntimePrimitives` 与 selected adapter `create_runtime_primitives`，并导出 typed `async fn build(RuntimeConfig, HostBindings, RuntimePrimitives) -> Result<AppHandle, BuildError>`；integration verification 拒绝 Host 从第二份不兼容的 runtime-api/adapter package identity 构造 bundle。`build-kind=bin` 要求 selected Host entry package，且 composition 不得包含 `config-source=host` 的 Component；生成的 `main.rs` 调用 metadata 指定的 generic entry function，并同时传入 selected snapshot 的 `create_runtime_primitives` 与 `composition::build`。Host entry 只依赖 runtime API/Host contract，不能直接依赖 concrete adapter。`build-kind=library` 不生成额外入口；Rust Host 通过经过验证的 emitted composition path dependency 直接调用 `create_runtime_primitives` 和 `build`。`build-kind=wasm` 要求 selected Host export package，generated Cargo 直接依赖该 snapshot并只使用 metadata `export-module` 的固定 ABI；它生成 `wasm.rs` 和 `crate-type = ["cdylib"]`，把同一 selected constructor 传给 helper，由 helper 调用后再把 browser-local bundle传入内部 build，对 JavaScript 固定导出为：

```rust
#[wasm_bindgen]
pub async fn start(
    runtime_config: JsValue,
    host_bindings: JsValue,
) -> Result<WasmAppHandle, JsValue>;
```

Generated `start` 内部的 runtime edge 固定为 typed direct call，不是 helper 内部选择：

```rust
let runtime = host_export::runtime_primitives(create_runtime_primitives)?;
let app = composition::build(config, host, runtime).await?;
```

`runtime_config` 只反序列化 file-source config；每个 host-source 字段由 metadata 的 `wasm-host-constructor` 直接构造。

Cargo 为上述 `cdylib` 生成的 `.wasm` 只是 wasm-bindgen input，不是 JavaScript Host 可直接部署的 artifact。`build-kind=wasm` 在 locked Cargo 成功后必须在同一 deny-by-default sandbox 中执行 BuildExecutionPolicy 中 logical id 为 `wasm-bindgen-cli` 的 exact executable；其 bytes digest、`--version` 与 CLI/`wasm-bindgen` crate protocol version 必须和 selected `host-wasm` snapshot + Cargo.lock 记录的要求完全兼容，不允许从 ambient `PATH`、npm、`wasm-pack` 或用户脚本取得另一个 tool。固定 invocation 以 Cargo 产生且已验证 digest 的 raw module 为唯一输入、empty staging directory 为唯一输出，使用 schema 固定的 `--target web --out-name rust_agent` 及 TypeScript emission 选项；禁止联网和读取 composition/source 之外的额外输入。

Runner 递归收集 wasm-bindgen 生成的 transformed WASM、JavaScript loader、TypeScript declarations 与合法 snippets，按 normalized relative path 排序并逐文件计算 raw-byte digest；拒绝 symlink、绝对/父路径、重复/case-fold collision、越出 staging、缺少 JS/WASM 主文件或 schema/version 不允许的额外输出。Raw Cargo module 作为带 digest 的 intermediate 进入 attestation，但不得被标为 JavaScript Host deployable entry。最终 WASM artifact 是这一完整 bundle；bundle manifest 固定记录 postprocessor logical id/version/executable digest、normalized invocation、raw-input digest及每个 output 的 path/kind/bytes digest。任一 generated output未被列入 digest/SBOM，或 out-of-band 后处理改变 bytes，production packaging 必须失败。

WASM 的最小可用控制面固定为：

```text
WasmAppHandle.seal_agent_operation(JsValue draft) -> Promise<JsValue | JsError>
WasmAppHandle.allocate_agent_operation(JsValue sealed_draft) -> Promise<JsValue | JsError>
WasmAppHandle.recover_agent_operation(JsValue id, JsValue sealed_draft) -> Promise<JsValue | JsError>
WasmAppHandle.create_agent(JsValue)         -> Promise<WasmAgentHandle | JsError>
WasmAppHandle.resume_agent(JsValue)         -> Promise<WasmAgentHandle | JsError>
WasmAppHandle.session_query()               -> WasmSessionQueryHandle | JsError
WasmAppHandle.verify_concurrent_handoff_from(WasmAppHandle) -> void | JsError
WasmAppHandle.shutdown()                    -> Promise<void | JsError>
WasmAppHandle.status()                      -> JsValue
WasmSessionQueryHandle.list_sessions(JsValue) -> Promise<JsValue | JsError>
WasmSessionQueryHandle.read_events(JsValue)   -> Promise<JsValue | JsError>
WasmSessionQueryHandle.read_projection(JsValue) -> Promise<JsValue | JsError>

WasmAgentHandle.allocate_turn_request()     -> JsValue | JsError
WasmAgentHandle.id()                        -> JsValue
WasmAgentHandle.send(JsValue)               -> Promise<JsValue | JsError>
WasmAgentHandle.cancel(JsValue)             -> JsValue | JsError
WasmAgentHandle.open_event_feed(JsValue)    -> Promise<WasmAgentEventFeed | JsError>
WasmAgentEventFeed.next()                   -> Promise<JsValue | JsError>
WasmAgentEventFeed.close()                  -> void
WasmAgentHandle.allocate_command_invocation() -> JsValue | JsError
WasmAgentHandle.command_definitions()       -> JsValue | JsError
WasmAgentHandle.execute_command(JsValue)    -> Promise<JsValue | JsError>
WasmAgentHandle.shutdown()                  -> Promise<void | JsError>
WasmAgentHandle.status()                    -> JsValue
```

每个 request/input/output/error/event/cursor DTO 携带固定 ABI version，generated conversion 拒绝未知字段、非法 mode、超限 string/array/bytes 和未编译的 Registry key。Lifecycle draft是可 canonical journal的 versioned DTO；seal/allocate返回的则是带 private wasm-bindgen handle identity的 opaque JS object，不支持结构化 clone、JSON伪造或字段 mutation。Durable Host持久化 id、canonical input draft和 exposed fingerprint，restart后重新 seal draft并调用 recover，不能序列化 prepared anchor/opaque object代替恢复。`create_agent`/`resume_agent`只接受 allocated/recovered object产生的 exact request。`send`、`cancel` 和 `execute_command` 必须分别使用同一 handle 分配的 turn request id / command invocation id，并遵守 Host 身份/授权边界；未编译 command provider 时 definitions 为空、执行返回 `UnsupportedOperation`。`resume_agent` 在 composition 未提供 Durable mode时返回 `UnsupportedOperation`，`session_query` 在未选择 query capability 时同样返回该错误。WASM feed 使用 pull-based `next()` 承载与 native 相同的 bounded/lag/cursor/Closed 语义，不能把 unbounded JS callback queue 当作实现。Handle 只包装 core owned handle，不暴露 Rust trait object、裸 pointer 或 Host callback；JS object 被 GC 不能替代显式 shutdown，App shutdown 仍 drain 全部 live Agent。

Generated library 公开 `RuntimeConfig`、`HostBindings` 与按 selected host-source 字段生成的 `HostBindingsBuilder`。每个 host-source Component 的 `host-api` 模块整体 re-export 到 composition-specific `host_api::<component_module>` namespace，Host 从中取得同一 source identity 的 Config、callback trait 和 DTO，不需要也不得直接 path-depend snapshot 内的 Component crate。`HostBindings` 不实现 `Serialize/Deserialize/Debug`，非空时不实现 `Default`；builder 在缺少 required Host value、重复赋值或类型转换失败时返回结构化错误，不能以 `Option` 静默注入空 callback。Generated Cargo metadata 只记录 build kind 和 integration schema，不记录会引入 hash 循环的 composition/manifest digest；composition hash 只由 derived `identity.rs` 和相邻 `rust-agent-composition.json` 记录，manifest digest 只由 ref/receipt 记录。`verify-integration` 同时校验 Cargo metadata、manifest 与 source identity。

### Generated Cargo.toml 是 binary 存在性的安全边界

例如 `minimal-pure`：

```toml
[dependencies]
rust-agent-core = { path = "...", default-features = false }
rust-agent-runtime-api = { path = "...", default-features = false }
rust-agent-runtime-tokio = { path = "...", default-features = false }
rust-agent-model = { path = "...", default-features = false }
rust-agent-agent = { path = "...", default-features = false }
driver-direct = { path = "...", default-features = false }
model-replay = { path = "...", default-features = false }
serde = { version = "...", features = ["derive"] }
```

这里根本不存在：

```text
reqwest provider crates
fs-local
subprocess-local
shell-local
sandbox-linux
mcp-client
redb
hnsw
pdf parser
OTEL exporter
```

所以它们不会参与本 composition 的 Cargo dependency closure。

### Internal Cargo features

只有已选 crate 的 additive option 才投影为 feature，例如：

```toml
some-provider = { path = "...", default-features = false, features = ["rustls"] }
```

禁止用：

```text
feature = "no-shell"
feature = "disable-network"
```

这样的 negative feature 承担安全删除语义。

Catalog只接受Component metadata allowlist中声明的additive feature；unknown feature、default feature非空、feature暗含未声明security effect或激活另一selectable Component implementation都是architecture error。Standalone bin/wasm/composition build中，每个selected Component/API/Host package的实际feature set必须按exact Cargo target、compilation kind、compile mode与profile从受信`CargoUnitGraph`/实际rustc invocation回读，并与resolution plan完全相等；`cargo metadata`的package级`resolve.features`不能充当证明。Library进入最终Host graph时，emitted first-party snapshot的每个Host/Target unit及external shared Host unit仍要求exact；只有不含custom-build/proc-macro下游变化的external shared Target-library unit可按第3节`HostFeatureUnionPolicy`接受可审计feature超集，不能把Host unit feature、generated output或Host union反写为target composition feature/composition hash。

### Generated composition.rs

生成可读 Rust，不依赖 macro 黑盒或 runtime service locator：

```rust
pub async fn build(
    config: RuntimeConfig,
    _host: HostBindings,
    runtime_primitives: RuntimePrimitives,
) -> Result<AppHandle, BuildError> {
    let (runtime_owner, mut component_runtime) =
        runtime_plan::bind_and_project(runtime_primitives)?;
    let manifest = GeneratedBindingAssemblyManifest::decode_canonical(
        binding_plan::MANIFEST_BYTES,
    )?;
    let app_scope = binding_assembly::begin_composition_assembly(
        runtime_owner,
        identity::COMPOSITION_HASH,
        manifest,
    )?;
    let app_plan = GeneratedBindingAssemblyPlan::decode_canonical(
        binding_plan::APP_BYTES,
        binding_plan::app_adapter_dispatch_table()?,
    )?;
    let mut bindings = app_scope.begin_binding_assembly(app_plan)?;

    let replay_output = model_replay::build(
        &(),
        model_replay::Dependencies {},
        component_runtime.take_model_replay()?,
    )?;
    let replay_provider: AssembledProviderBinding<ModelProviderBinding> =
        bindings.bind_provider(
            binding_plan::APP_MODEL_REPLAY_PROVIDER,
            replay_output.service().clone(),
        )?;

    let model_provider_plan =
        ResolvedBindingPlan::registry([("replay", replay_provider)])?;

    let agent_factory = GeneratedAgentScopeFactory::new(
        config.runtime.agent_scope,
        model_provider_plan,
        /* AppBuilder later injects the root-derived private child-scope issuer;
           typed Session/Agent scope functions use it with their journal pair */
    );

    /* Elided selected nodes/edges use bind_provider/bind_consumer the same way. */
    let mut app_scope = bindings.finish()?;
    app_scope.install("model-replay", replay_output)?;

    AppBuilder::new(app_scope)
        .with_agent_factory(agent_factory)
        .publish()
        .await
}
```

该最小 native library 示例显式选择 `runtime-tokio`，故 generated Cargo 直接依赖同一 snapshot adapter。`runtime_plan::bind_and_project` 是 generated typed module：它先验证 root bundle 的 adapter/target/primitive identity，把 driver lease 移入 `runtime_owner`，并为每个 selected Component 生成恰好一个不可伪造、一次性取得的 `RuntimePrimitiveBindings` 字段；即使 `model-replay` 声明空集合，factory 的第三个参数也不能省略。缺失/重复取得或未声明 primitive 在任何 Component factory 前失败。

`AppBuilder::with_agent_factory` 在 API ownership boundary从完成的 App scope取出仅绑定该 root/manifest的 private child-scope issuer并注入 generated factory；`GeneratedAgentScopeFactory::new` 本身不能调用 fresh-root issuance假装成该 App的 child。每次 seal/create/resume由该 issuer按 committed template/projection派生新的 Session/Agent `ScopeAssemblyBuilder`，并自动携带当前 publication lineage与 paired journal verifier；issuer、builder和 context都不进入 `AppHandle`、Component Dependencies或 Host API。App shutdown使 issuer关闭，晚到 child assembly返回 `Closed`。

该最小示例故意使用无网络依赖的 `model-replay`，所以不省略任何 Required dependency，也没有 Host callback，`host` 为空。App scope 只保存含 typed provider handles/effect stamps 的 immutable `model_provider_plan`；每次 Agent/Session model-caller scope 创建自己的 journal issuer/verifier pair 后，generated template 才以该 scope 的 `BindingConsumerContext` 组装 `ModelRegistryBinding`，不能在 App build 时复用一个无 verifier 或跨 Agent 共享 verifier 的 consumer binding。`model-deepseek` 的独立 generated compile fixture 必须完整构造 `network-policy-default → network-connector-native → http-client-native` binding chain 和 `credentials` binding，并把 `http_client`、`credentials` 两个字段与它的 generated runtime projection都传入 metadata 指定的 factory；不得把不完整示例当作可编译生成物。含 `config-source=host` Component 时，factory 的 config 参数从对应 `host` 字段取得；含 `config-source=file` Component 时从 `config` 字段取得。生成器必须按 source 生成直接字段访问，不能把两者合并为动态 map。

Generator 按 scope 把 consumed config 移入 `AppConfig`、`SessionTemplateConfig`、`AgentTemplateConfig`；App factory 立即借用 App config，Session/Agent config 由对应 generated scope factory owned 并在每次实例构造时借用。Host callback Config 通过 owned Arc/factory handle 保留，不能要求 HostBindings 在 `build` 返回后继续存活，也不能用泄漏的 `'static` reference 延长借用。

每个 factory call 的函数 path、config type、Dependencies type 和字段来自 Component metadata；每个 binding builder/type 来自 Capability metadata。Generator 不需要猜测 concrete constructor，也不通过反射装配。实际生成代码按 App DAG 构造 App binding，并生成独立的 Session/Agent scope factory function；不能把所有 provider 都通过 `Option<dyn Trait>` 塞进一个巨型 App struct。

### Generated files policy

- 默认 gitignored；
- `compose --emit-composition <dir>` 可保存只读审计副本，不作为 Host dependency；
- `emit-integration` 生成唯一允许进入 Rust Host Cargo graph 的固定目录副本；
- emitted integration 的任何修改都使 `verify-integration` 失败；
- golden tests 固定输出；
- CI 验证生成器 deterministic；
- manifest 中保存 source 与 Cargo.lock hash；
- production `--locked` 禁止修改 generated files。

## 28. Compile-Time DI 与 Runtime Binding

禁止核心路径使用：

```rust
ctx.get::<dyn Shell>()
```

也禁止自行实现无类型字符串 service locator。

### Static DI 原则

- 热路径/单 provider：generic 或 concrete static fields；
- 多 provider registry：`Arc<dyn Trait>` keyed registry；
- ordered contributors：`Vec<Arc<dyn Trait>>`，顺序由 composition 固定；
- host boundary：trait object；
- factory boundary：explicit `Factory` trait；
- 不把所有 capability 泛型化，避免 type explosion。

例如：

```rust
pub struct ToolDriver<M, E> {
    model: M,
    tools: E,
}
```

Guarded executor 内部 tool registry：

```rust
Vec<RegisteredTool>
```

Model capability adapter 内部的 provider registry 可以保存 raw trait object，但 consumer 字段只得到密封 wrapper：

```rust
pub struct ModelRegistryBinding {
    providers: BTreeMap<ProviderKey, RegisteredModelProvider>, // private raw service
    routing: ModelRoutingMode,
    request_journal_verifier: ModelRequestJournalVerifier,
}
```

`RegisteredModelProvider`、raw lookup 与 raw `LanguageModel::stream` 都是 model API/adapter privacy boundary 内部实现；driver 只能调用 `ModelRegistryBinding::stream_prepared`。

### 编译集合与运行时选择分离

Composition 可以编译：

```text
model-openai
model-deepseek
model-replay
```

Runtime config：

```toml
[binding.model]
mode = "default"
default = "deepseek"
```

没有 default 的 per-request routing 必须显式写为：

```toml
[binding.model]
mode = "explicit-per-request"
```

但以下配置必须启动失败：

```toml
[binding.model]
mode = "default"
default = "anthropic"
```

如果 `anthropic` provider 没有进入 compiled registry。

Runtime selection 不能改变 dependency graph，只能在已编译 binding 内选择。

## 29. Runtime Scope / Ownership / Lifecycle

Compile-time pluggable 不代表运行时没有 lifecycle。必须显式区分：

```text
Component selection lifetime  ≠  Runtime instance lifetime
```

### Scope model

第一版只定义：

```rust
pub enum ScopeKind {
    App,
    Session,
    Agent,
}
```

典型结构：

```text
App Scope
│
├── Model Registry
├── Credential Provider
├── Session Persistence
├── Global Telemetry
├── Web Provider
└── SessionFactory / AgentFactory
       │
       ├── sessionless Agent Scope
       │     ├─ Driver
       │     ├─ Internal ToolRegistry / ToolExecutor
       │     ├─ Prompt
       │     └─ Policy
       │
       └── durable Session Scope
             ├─ SessionLog
             └── Agent Scope
                   ├─ Driver
                   ├─ Internal ToolRegistry / ToolExecutor
                   ├─ Prompt
                   └─ Policy
```

Session/Agent-scoped registration 必须同时表达：

1. 对哪个 Session/Agent identity 可见；
2. 谁拥有并负责 teardown。

### Scope construction

Generated composition 不在启动时创建所有 Agent-scoped实例；它创建 factory/composer：

```rust
pub trait AgentScopeFactory: MaybeSendSync {
    async fn prepare(
        &self,
        parent: AgentScopeParent,
        request: AgentScopeRequest, // includes validated effective AgentAuthority
    ) -> Result<PreparedAgentScope, AgentScopeError>;
}
```

`AgentScopeParent` 只能是 App 或已 prepared/committed 的 Session scope。Generated factory 对包含 Session requirement 的 Agent plan 拒绝 App-only parent。Factory 在 construction 前从 request authority 生成并验证 `AgentBindingProjection`，只 initialize projection 可达的 Agent-scoped Component；被 authority 删除的 optional binding 不得因原 compiled plan 中存在而偷偷初始化或产生 external effect。`PreparedSessionScope` / `PreparedAgentScope` 在 PublicationDirectory generation commit 前不可被普通 snapshot 发现。

### Lifecycle traits

不强迫每个组件都实现空 lifecycle trait。需要异步准备或运行的 provider 使用两个明确阶段：

`ComponentOutput<T>` 只允许从同一个 `Arc<T>` 构造：`stateless` 不登记 hook；`initializable` 要求 `T: Initializable + Shutdown`；`activatable` 要求 `T: Activatable + Shutdown`；`managed` 要求 `T: Initializable + Activatable + Shutdown`。它把同一个 Arc coercion 为所需 hook trait object，从类型上保证 initialize/activate 与 Shutdown 属于同一 owner；第一版不接受独立 hook object。Factory 返回 Error 前仍由 factory 负责清理尚未交给 scope 的临时资源；output 一旦被 `install` 接受，rollback/shutdown ownership 转移给 scope。若后续同步 construction/adapter/assembly 失败，scope 以 reverse ownership order 丢弃尚未 initialize 的 output；只有 initialize 或 activate 已被 attempted 的 output 才调用 async Shutdown。进入 `publish().await` 后的任意失败由 publication transaction 完成异步 rollback。

同步 factory 只能校验 config、建立内存状态并保存 dependency binding，不能调用 dependency 的 operational method、执行 I/O、spawn task 或产生外部 side effect。这样所有 dependency 都可先 construct，再严格按 DAG initialize；违反该规则属于 architecture test/code review failure。

```rust
pub trait Initializable: MaybeSendSync {
    /// 可以分配资源、打开存储或绑定尚未接收外部工作的资源。
    async fn initialize(&self) -> Result<(), InitializeError>;
}

pub trait Activatable: MaybeSendSync {
    /// owning scope directory publication 后准备受 ScopeAdmissionGate 阻挡的
    /// worker/ingress；不得自行向外开放 Agent 业务 admission。
    async fn activate(&self) -> Result<(), ActivateError>;
}

pub trait Shutdown: MaybeSendSync {
    async fn shutdown(&self) -> Result<(), ShutdownError>;
}
```

Generated composition 按 construction DAG 与 publication transaction 执行：

```text
validate typed config / HostBindings / RuntimePrimitives
→ project the exact root/scope plan and namespace-bootstrap edges under authority attenuation
→ construct stamped selected bootstrap bindings without locator I/O
→ asynchronously prepare only retained required resource namespaces through those bindings
→ finalize root/scope authority from the projection + prepared descriptors
→ construct
→ initialize in topological order
→ validate commit invariants
→ stage complete PublicationDirectory transaction
→ run ordered before_publish validation
→ commit required Durable backend transaction; keep NewEphemeral genesis staged
→ atomically publish one directory generation
→ enqueue contained published notification batch without awaiting callbacks
→ activate in topological order behind closed ScopeAdmissionGate
→ commit/index NewEphemeral genesis, or commit required Durable create/resume
  terminal success for a new operation; preserve the existing terminal for
  Completed cold reconstruction
→ open admission / return handle
```

App-scoped namespace preparation 在 App root attenuation/projection 后执行一次，其 descriptor/anchor 由 App owner 保存。Session/Agent-scoped namespace preparation 则在每次 exact template 的 parent/request/stored authority projection 后执行，不在 App build 预开资源；它的 anchor 由对应短 scope owner 保存并在 rollback/teardown 释放。两者都只能调用 selected普通 Component 提供的 stamped bootstrap binding，mandatory infrastructure 只做 projection、deadline/cancellation、结果校验与 commitment 纯计算。`initialize` 不得消费 inbox、接受请求或产生无法 rollback 的外部业务 side effect。确实必须在 publication 前占有的端口、文件锁或连接保持 inactive；`activate` 只能启动仍被 generated `ScopeAdmissionGate` 阻挡的 idle worker/listener，不能自行开放 Agent/driver/command ingress，公开 admission 只能由 publication transaction 在 NewEphemeral genesis 已原子进入 authoritative index，或全部 required Durable terminal commit 已确认后统一开放。Directory transaction 在 Durable backend commit 前完成 notification capacity 等资源预留和全部可能失败的验证；Durable commit 后的 generation swap 与 notification enqueue 不分配内存且不能失败。NewEphemeral 的 staged/query-invisible genesis 则跨 generation swap 保持到 gated activation 成功，并在 admission 前才以 known-outcome transaction commit；activation/commit failure 必须 abort 它。Activation 或 create/resume terminal commit 失败属于 publication transaction 失败，必须保持/关闭 admission、撤销已 activation 的 sibling、原子删除已发布 entry、enqueue 配对 disposal notification，并完整 reverse teardown；新 durable operation 按 protocol 写入/解析 failure terminal，已有 success terminal 的 cold reconstruction 则保留原 terminal、只返回 reconstruction failure。`published/disposed` observer timeout/error，以及满足 unwind gate 时捕获的 panic，只进入诊断，callback completion 不在 transaction critical path，也不改变 activation/teardown 结果。

销毁：

```text
stop accepting new work
→ atomically mark the complete published pair closing
→ cancel owned operations
→ drain/kill to quiescence
→ reverse shutdown
→ atomically remove the complete directory pair
→ enqueue contained disposed notification batch without awaiting callbacks
→ release resources
```

Sessionless Agent 对上述 pair 操作退化为单 Agent entry；任何 generation update 都不得只更新配对的一侧。

### 强制规则

- initialize/activate failure rollback 所有已经初始化或激活的 sibling/dependency；
- scope 在调用 initialize/activate 前先标记 hook 为 attempted；即使该 future 返回 Error，failing component 本身也进入 reverse shutdown，以清理部分建立的资源；
- shutdown idempotent；
- Durable `AgentHandle::shutdown()` 只有在 SessionLog flush/quiescence 与 writer lease release 都已确认后才返回成功；release unknown 返回结构化错误且不授权另一个 live owner 窃取 lease；
- background task 必须有 owner；
- provider 不允许 detached task 泄漏到 owner 生命周期之外；
- App teardown 必须 drain AgentFactory 创建的 live handles；
- AgentHandle 的 holder 是显式 teardown capability；
- Session/Agent publication 不得暴露半初始化对象；
- scope teardown 顺序可测试、可诊断。

## 30. Target Model

目标至少：

```text
x86_64/aarch64 Linux
macOS
Windows
wasm32 browser
iOS
Android
```

TargetSet 不能只存 `wasm/native` 两类；需要 OS/arch/environment 表达。

例：

```text
subprocess-local     native desktop/server
sandbox-linux        linux
sandbox-macos        macos
sandbox-windows      windows
kv-indexeddb         wasm-browser
vector-hnsw          native
parser-pdf           native
shell-local          desktop/server native
```

WASM target 对 Auto consumer 可以传播排除 native-only chain；任何 explicit/profile enabled component 或 binding root 落入该 chain 时必须报告 `UnsupportedTarget`，不能自动删除显式 requirement。

---

## 31. Runtime Adapter

新的 core 不应该强制 Tokio。

Schema v1 只定义三个小 primitive id；它们不是可由 resolver 任意选择的 Capability，也不组成无边界的“万能 RuntimeAdapter”：

```rust
pub trait Clock: MaybeSendSync { ... }
pub trait Sleeper: MaybeSendSync { ... }
pub trait Spawner: MaybeSendSync { ... }

pub struct RuntimePrimitives { /* private validated root bindings + driver lease */ }
pub struct RuntimePrimitiveBindings { /* private per-Component projection */ }
```

每个 Component metadata 必须以 `runtime-primitives = []` 或 `runtime-primitives = ["clock", "sleeper", "spawner"]` 的子集完整声明需求。Generator 计算全部 Component 声明与 schema-owned infrastructure（resource-namespace preparation 只需要 deadline/cancellation scheduling）的 primitive requirement union，但只把每个 Component 自己声明的子集投影进它的 `RuntimePrimitiveBindings` factory 参数；infrastructure projection 不向 Component 暴露。缺少 required primitive、target ABI 不兼容、重复/未知 id 或 Component 取得未声明 primitive 都在任何 namespace preparation/factory 前失败。Primitive bundle 不提供 filesystem/network/process/credential operation；namespace locator I/O 也必须经过 selected `cap:resource-namespace-bootstrap` Component binding并计入 effects。

Runtime adapter package 使用独立 metadata，不伪装成 Capability provider；normalized build config 对每个 composition 必须显式选择恰好一个 target-compatible adapter：

```toml
[package.metadata.rust-agent.runtime-adapter]
schema = 1
id = "runtime-tokio"
constructor = "rust_agent_runtime_tokio::create"
targets = ['cfg(not(target_arch = "wasm32"))']
support = "production"
primitives = ["clock", "sleeper", "spawner"]
security = []
app-coexistence = { mode = "concurrent-independent", evidence = { source = "runtime-coexistence.md", algorithm = "sha256", digest = "...", reviewer-policy = "runtime-adapter-v1" } }
build-requirements = { executables = [], read-inputs = [], environment = [] }
```

Constructor ABI 固定为 `fn() -> Result<RuntimePrimitives, RuntimePrimitiveError>`，返回的 bundle 必须拥有 lifecycle-managed driver lease，不接受只借用当前 thread/executor context 的 production constructor。Runtime adapter 作为 generated App owner 必须复用第 23 节同一封闭 `app-coexistence` schema/evidence，并与 selected App Components 一起决定 aggregate handoff；process-global runtime 或不能证明 two-bundle coexistence 的 adapter 必须 `requires-stop`。Selected adapter package、metadata、source/feature/build requirements 与 runtime ceiling 进入 generated direct dependency closure、composition hash/manifest 和 compiled runtime/build accounting；library emitted snapshot 也包含它，`lib.rs` 只从同一 snapshot package identity re-export `create_runtime_primitives`，Host 不得从另一份 product dependency 构造同名类型。bin/wasm selected Host boundary 的 `runtime-adapters` allowlist 必须包含该 id；library 没有 Host boundary，但仍按 target/support 与完整 primitive union验证。

Generated `build(RuntimeConfig, HostBindings, RuntimePrimitives)` 按值接收 root bundle，验证其 sealed adapter/target/primitive identity与 composition manifest完全匹配，并把 driver lease 转交 generated App owner。`build-kind=library` 的 Rust Host 必须显式调用 emitted alias re-export 的 `create_runtime_primitives()` 并传入结果；不存在“poll build 的当前 executor 自动成为 runtime”的 fallback。`build-kind=bin` 的 generated `main.rs` 把同一 selected constructor传给 Host entry，`build-kind=wasm` 的 generated `start` 把 selected browser constructor传给 `host-wasm` helper；两种 Host boundary 都只调用注入的 constructor，不能直接依赖或选择 concrete adapter。Generated/public future 可以由 Host 在其它兼容 executor 上 poll，但 Component 的 timer、background task 和 executor-bound I/O future 必须通过 injected `Sleeper`/owner-scoped `Spawner` 执行，不能直接调用 ambient `tokio::spawn`、依赖当前 Tokio reactor或创建 detached task。Spawner 创建的 task 全部登记到 scope owner，App/Agent shutdown 按第 29 节 cancel/drain；driver lease 必须活到这些 task quiescent，提前失效返回结构化 runtime error而不是 panic。

第一版 built-in packages 是 native `rust-agent-runtime-tokio` 与 browser-local `rust-agent-runtime-wasm`。Native adapter/provider 可以在这个边界后使用 Tokio，WASM adapter 使用 `wasm-bindgen-futures`；architecture lint 与 library fixture 必须在 non-Tokio Host executor 上 poll generated API，证明含 timer/spawn/I/O 的 Component 仍通过 injected driver工作。确实无法通过三个封闭 primitive 隔离的 executor-specific provider 必须自己拥有并 lifecycle-manage 一个 target-compatible runtime，将它的完整依赖/effects/size计入该 Component；不得读取 Host ambient executor context。

---

## 32. Error Model

每个 capability 有领域错误，composition/resolver 有结构化错误。

```rust
pub enum HostBoundaryViolation {
    Missing,
    Unexpected,
    EntryExportConflict,
    KindMismatch,
    UnsupportedTarget { target: Target },
    UnsupportedSupportTier { support: SupportTier },
    SecurityDenied { effects: SecurityEffects },
}

pub enum RuntimeAdapterViolation {
    Missing,
    Multiple,
    UnsupportedTarget { target: Target },
    UnsupportedSupportTier { support: SupportTier },
    MissingPrimitive { primitive: RuntimePrimitiveId },
    HostBoundaryIncompatible { boundary: HostBoundaryId, adapter: RuntimeAdapterId },
    NonEmptySecurity { effects: SecurityEffects },
    BundleIdentityMismatch,
}

pub enum DerivedProviderFacadeViolation {
    ScopeMismatch,
    BindingKindMismatch,
    CandidateSetMismatch,
    ProviderKeyMismatch,
    IndependentSelectionAttempt,
}

pub enum DeferredFactoryViolation {
    AdditionalDeferredCapability,
    InvalidProviderOwner,
    NonEmptyAppBindingEffects,
    MissingTemplateProjection,
}

pub enum ResolutionError {
    InvalidTargetFacts { target: TargetTriple, reason: String },
    UnsupportedCargoResolutionContext { field: String, reason: String },
    MissingCapability { consumer: BindingConsumerOwnerId, capability: CapabilityId },
    ProviderConflict { capability: CapabilityId, providers: Vec<BindingProviderOwnerId> },
    ComponentConflict { left: ComponentId, right: ComponentId },
    DependencyCycle { path: Vec<BindingOwnerId> },
    UnsupportedTarget { component: ComponentId, target: Target },
    UnsupportedSupportTier { component: ComponentId, support: SupportTier },
    InvalidBinding { capability: CapabilityId, binding: BindingKind, providers: Vec<BindingProviderOwnerId> },
    InvalidScopeDependency { consumer: BindingConsumerOwnerId, provider: BindingProviderOwnerId },
    InvalidDecoratorChain { capability: CapabilityId, reason: String },
    InvalidDerivedProviderFacade {
        capability: CapabilityId,
        source: CapabilityId,
        reason: DerivedProviderFacadeViolation,
    },
    InvalidDeferredFactory {
        capability: CapabilityId,
        provider: Option<BindingProviderOwnerId>,
        reason: DeferredFactoryViolation,
    },
    InvalidHostBoundary {
        build_kind: BuildKind,
        boundary: Option<HostBoundaryId>,
        reason: HostBoundaryViolation,
    },
    InvalidRuntimeAdapter {
        build_kind: BuildKind,
        adapter: Option<RuntimeAdapterId>,
        reason: RuntimeAdapterViolation,
    },
    ResolutionLimitExceeded { budget: u64, explored: u64, frontier_digest: Digest },
    Cancelled,
}

pub enum BuildRequirementRootKind {
    Component,
    MandatoryApi,
    Infrastructure,
    RuntimeAdapter,
    HostEntry,
    HostExport,
}

pub struct BuildRequirementRootId {
    pub package: CargoPackageId,
    pub kind: BuildRequirementRootKind,
}

pub enum HostFeatureUnionViolation {
    FirstPartyFeatureDrift { package: CargoPackageId, extra: Vec<FeatureId> },
    MissingPolicy { package: CargoPackageId, extra: Vec<FeatureId> },
    PackageIdentityMismatch { package: CargoPackageId },
    BaselineFeatureRemoved { package: CargoPackageId, feature: FeatureId },
    UnapprovedFeature { package: CargoPackageId, feature: FeatureId },
    UnapprovedDependency { package: CargoPackageId, dependency: CargoPackageId },
    MissingFeatureSemanticsEvidence { package: CargoPackageId },
    InvalidProductOnlyAttribution { package: CargoPackageId, reason: String },
    FeatureSemanticsEvidenceDigestMismatch { expected: Digest, actual: Digest },
    EffectAccountingMismatch { package: CargoPackageId, effects: SecurityEffects },
    BuildRequirementMismatch { package: CargoPackageId, requirement: String },
    PolicyDigestMismatch { expected: Digest, actual: Digest },
}

pub enum BuildExecutionError {
    InvalidPolicy { field: String, reason: String },
    PolicyHostMismatch { policy: BuildPolicyId, host: HostTarget },
    UnsatisfiedBuildRequirement { root: BuildRequirementRootId, kind: BuildRequirementKind, id: String },
    BuildRequirementKindMismatch { root: BuildRequirementRootId, id: String, expected: BuildRequirementKind },
    InputDigestMismatch { input: BuildInputId },
    ExecutableDigestMismatch { executable: BuildExecutableId },
    ExecutableVersionMismatch { executable: BuildExecutableId },
    TargetFactMismatch { expected: Digest, actual: Digest },
    CargoResolutionContextMismatch { expected: Digest, actual: Digest },
    SandboxUnavailable { backend: BuildSandboxBackend },
    SandboxViolation { operation: DeniedBuildOperation },
    FetchVerificationFailed { package: CargoPackageId },
    CargoFailed { status: ExitStatus, diagnostics: DiagnosticRef },
    WasmPostprocessorFailed { diagnostics: DiagnosticRef },
    WasmPostprocessorOutputInvalid { reason: String },
    AttestationInvalid { reason: String },
    IntegrationVerificationFailed { reason: String },
    HostFeatureUnionRejected { reason: HostFeatureUnionViolation },
    Cancelled,
}
```

Agent creation/resume 至少保留以下结构化分类，不能压成 backend string：

```rust
pub enum CancelOutcome {
    CancelledActive,
    AlreadyCancelling { first_cause: CancelCause },
    AlreadyTerminal,
    NotActive,
}

pub enum AgentCancelError {
    ForeignRequest { request: AgentRequestId },
    StaleLifecycle { request: AgentRequestId },
    Closed,
}

pub enum AgentEventFeedBudgetResource {
    SubscriberCount,
    BufferedEvents,
    BufferedBytes,
}

pub enum AgentEventFeedError {
    StaleLifecycle,
    CursorFromDifferentAgent,
    CursorExpired { oldest_available: Option<AgentEventCursor> },
    InvalidLimit,
    AdmissionBudgetExceeded {
        resource: AgentEventFeedBudgetResource,
        requested: u64,
        limit: u64,
    },
    UnsupportedReplay,
    Closed,
}

pub enum SessionQueryError {
    InvalidLimit,
    CursorExpired,
    CursorBackendMismatch,
    CursorSessionMismatch,
    SessionNotFound { session: SessionId },
    IncompatibleComposition {
        session: SessionId,
        stored_composition: CompositionHash,
        current_composition: CompositionHash,
        stored_catalog: Digest,
        current_catalog: Digest,
    },
    UnsupportedProjectionEvent { kind: SessionEventKind, payload_version: u32 },
    CorruptStore { diagnostic: DiagnosticRef },
    Closed,
}

pub enum AppHandoffError {
    StopOldAppRequired,
    CompositionMismatch,
    CatalogMismatch,
    SharedHandleFieldMismatch,
    SharedHandleIdentityMismatch { field: HostConfigFieldPath },
    AppNotReady,
}

pub enum ToolExecutionError {
    JournalNotCommitted { batch: EventBatchId },
    JournalCommitStatusUnknown { batch: EventBatchId },
    JournalProofMismatch,
    Closed,
    // lookup/schema/policy/approval/budget/provider 等其它领域分类
}

// AgentOperationAllocationError is defined by rust-agent-runtime-api and
// re-exported unchanged by rust-agent-agent; see section 4.
pub enum AgentLifecycleError {
    UnsupportedOperation { operation: AgentOperation },
    IncompatibleComposition {
        stored_composition: CompositionHash,
        current_composition: CompositionHash,
        stored_catalog: Digest,
        current_catalog: Digest,
    },
    AuthorityEscalationDenied { reason: AuthorityViolation },
    AuthorityUnsatisfied { capability: CapabilityId, requirement: String },
    ResourceNamespaceChanged { binding: AuthorityBindingId, stored: Digest, current: Digest },
    OperationConflict { operation: AgentLifecycleOperationId },
    CreationOperationFailed {
        operation: AgentLifecycleOperationId,
        phase: CreationPhase,
        reason: CreationFailureReason,
    },
    ResumeOperationFailed { operation: AgentLifecycleOperationId, phase: ResumePhase, reason: ResumeFailureReason },
    AuthorityChangedForCompletedOperation { operation: AgentLifecycleOperationId, session: SessionId },
    CompletedOperationReconstructionFailed {
        operation: AgentLifecycleOperationId,
        phase: ReconstructionPhase,
    },
    WriterConflict { session: SessionId },
    RecoveryRequired { session: SessionId },
    Construction(ComponentBuildError),
    Cancelled,
}

pub enum AgentShutdownError {
    QuiescenceFailed { reason: ShutdownFailureReason },
    SessionFlushFailed { session: SessionId, reason: SessionPersistenceError },
    WriterLeaseReleaseUnknown { session: SessionId, generation: FencingGeneration },
    WriterLeaseLost {
        session: SessionId,
        expected: FencingGeneration,
        current: FencingGeneration,
    },
}
```

不要所有错误都压成 `anyhow::Error` 作为公共 API。

---

## 33. Security Model

Generated Cargo graph 是代码存在性的 build-time 安全边界，不替代 runtime permission、sandbox 或供应链审计。一个组件可以同时具有多个安全效果，因此不能用互斥 enum 表达风险。

Selected in-process Component crate 属于 trusted computing base。`ExecutionPermit`、confinement authority、private registry 和 typed config 用于阻止普通 Safe Rust consumer 绕过既定 API；它们不声称能隔离恶意或被攻陷的同进程 Rust crate。对 Component source、`unsafe`、build script、proc macro、native dependency 和供应链的信任由 review、lockfile、advisory/license gate、provenance 与最小 Cargo graph承担；不可信代码只能位于受 Sandbox/Host/remote boundary 约束的进程或服务中。

Library composition 的调用方 Host 不属于 generated Cargo closure；manifest 中的 `HOST_BRIDGE/HOST_UI` 只声明边界存在，不证明 Host 实现安全。Desktop/Mobile/AINS 等产品必须对其最终 Host binary、callback 权限和依赖另行生成产品级 attestation；rust-agent manifest 不得把“Host 未被计入”表述为能力不存在。

### SecurityEffects

```rust
bitflags::bitflags! {
    pub struct SecurityEffects: u64 {
        const READ_LOCAL      = 1 << 0;
        const WRITE_LOCAL     = 1 << 1;
        const NETWORK         = 1 << 2;
        const PROCESS_EXEC    = 1 << 3;
        const REMOTE_EXEC     = 1 << 4;
        const SECRET_ACCESS   = 1 << 5;
        const HOST_UI         = 1 << 6;
        const HOST_BRIDGE     = 1 << 7;
        const PERSISTENT_STORAGE = 1 << 8;
        const CODE_EXEC       = 1 << 9;
        const MCP_CONNECT     = 1 << 10;
    }
}
```

例如：

```text
model-deepseek = [NETWORK, SECRET_ACCESS]
shell-ssh      = [NETWORK, REMOTE_EXEC, SECRET_ACCESS]
subprocess-local = [PROCESS_EXEC, READ_LOCAL, WRITE_LOCAL]
fs-read-local  = [READ_LOCAL]
resource-namespace-bootstrap-local = [READ_LOCAL]
model-host / web-fetch-host / web-search-host = [HOST_BRIDGE]
credentials-env = [SECRET_ACCESS]
web-http-native = [NETWORK]
network-connector-native / http-client-native = [NETWORK]
session-persistence-jsonl / session-persistence-redb = [READ_LOCAL, WRITE_LOCAL, PERSISTENT_STORAGE]
kv-redb = [READ_LOCAL, WRITE_LOCAL, PERSISTENT_STORAGE]
kv-indexeddb = [PERSISTENT_STORAGE]
embedding-host / network-policy-host / mcp-transport-host = [HOST_BRIDGE]
credentials-host = [HOST_BRIDGE, SECRET_ACCESS]
approval-host = [HOST_BRIDGE, HOST_UI]
user-interaction-host = [HOST_BRIDGE, HOST_UI]
attachment-local = [READ_LOCAL, WRITE_LOCAL, PERSISTENT_STORAGE]
attachment-host = [HOST_BRIDGE, PERSISTENT_STORAGE]
spill-local = [READ_LOCAL, WRITE_LOCAL]
spill-host = [HOST_BRIDGE]
code-runtime-sandboxed = [CODE_EXEC, PROCESS_EXEC]
code-runtime-host = [CODE_EXEC, HOST_BRIDGE]
mcp-client = [MCP_CONNECT, REMOTE_EXEC]
telemetry-otel = [NETWORK]
```

Runtime security effect 固定分三层，并与 build execution requirements 正交，禁止混用：

```text
Component runtime ceiling
  = Component.security
  = 最终 target artifact 中 package 自身 + linked native code
    + transitive non-Component runtime helper

Provide binding effects
  = Component.lifecycle-effects + CapabilityProvide.effects
    + active security-when-bound effects + selected dependency binding effects
  = 通过某个 capability/key/contribution 可触发的 effects

Composition component runtime effects
  = component_runtime_effects
  = 全部 selected Component runtime ceiling 的并集
  = 构造 App root AgentAuthority 的 runtime effect 上限

Selected Host boundary runtime effects
  = host_boundary_runtime_effects
  = build-kind=bin/wasm 时所选 Host entry/export helper runtime ceiling
  = library 时为空；不进入 Capability binding 或 AgentAuthority

Selected runtime-adapter runtime effects
  = runtime_adapter_runtime_effects
  = schema v1 固定为空；非空 adapter metadata/closure 在 composition 前拒绝
  = 不进入 Capability binding 或 AgentAuthority

Final artifact compiled runtime effects
  = compiled_runtime_effects
  = component_runtime_effects ∪ host_boundary_runtime_effects
    ∪ runtime_adapter_runtime_effects
  = runtime SecurityPolicy、artifact manifest 与发布审计的最终 union

Composition build requirements
  = 全部 selected Component + mandatory API/infrastructure + runtime adapter
    + Host entry/export root-package build-requirements 的规范化并集
  = 只由 BuildExecutionPolicy/runner 满足，不进入 SecurityEffects/AgentAuthority
```

上述三层是 composition artifact 自身的记账。`build-kind=library` 进入产品 Host 后另有不可回写 composition 的外层：

```text
Product final runtime effects
  = product_compiled_runtime_effects
  = compiled_runtime_effects
    ∪ approved HostFeatureUnionPolicy.product-host-effects
    ∪ product Host root/callback/other dependency effects

Product build requirements
  = composition build requirements
    ∪ approved Host feature-delta requirements
    ∪ product Host root requirements
```

Product Host必须声明 exhaustive effect ceiling并由 integration attestation验证该 union。`HostFeatureUnionPolicy.composition-effects`解释 external shared Target unit的 feature delta对既有 composition调用路径的可能影响，且必须已包含在相关 selected root ceiling内，所以不扩大 AgentAuthority。Cargo只在同一 feature-unification unit domain内合并 feature；在该 exact Target unit内，feature requester的 reverse path本身仍不能证明 `product-host-effects`与 composition隔离。只有第 3节验证通过的 `host-only-additive-api` evidence才允许某 effect只属于产品外层，否则必须同时按 composition-conservative计入。Host compilation unit的**执行时**effect不进入runtime union而由build requirements/BuildExecutionPolicy审计；它生成的cfg/code/token/native object/link directive若进入最终artifact，则作为downstream runtime contribution进入对应Component/Host root ceiling和`product_compiled_runtime_effects`。Schema v1禁止shared Host-unit feature delta以及会改变build-unit输出的Target delta；产品自有build units的下游contribution由Host root exhaustive声明和post artifact/effect attestation承担。Host root自身的runtime effects始终只属于产品外层。两类build requirement都由同一个最终Host BuildExecutionPolicy执行，但composition manifest保留自身原始unit/effect union，不能被产品字段改写。

上式适用于普通 Component/generated-infrastructure binding。唯一例外是 `generated-agent-scope-factory` 的 App binding：它不把尚未实例化的 template dependency effects 累计到自身，binding effects 固定为空；但这只是延迟记账，不是授权豁免。每次 create/resume 必须对 exact resolved template 重新累计 selected dependency effects，完成 authority projection 后才可构造任何 scoped provider，结果仍必须是 `component_runtime_effects` 的子集。其它 factory、provider 或 consumer 不得使用这一 deferred 规则。

每个 Component 和 selected Host boundary 必须对最终产物中自身代码与全部 transitive non-Component runtime helper 的行为声明完整 runtime ceiling；selected runtime adapter 的同一 closure 必须验证为空。每个 Component lifecycle、`CapabilityProvide.effects` 与 conditional own effect 都必须是该 Component ceiling 的子集。Resolved binding/consumer effective ceiling 在此 own ceiling 之上再累计实际 selected dependency binding effects；Tool/Command static+dynamic definition effects 必须是其 sealed effective ceiling 的子集，而不要求伪装成 consumer package 自身的 effect；任何 effective ceiling 最终都必须是 `component_runtime_effects` 的子集。Consumer 不得因 capability 名称推断 `READ_LOCAL/NETWORK` 等实现 effect，必须使用 generated binding stamp。共享 runtime helper 不得隐藏 effect；共享 build helper 不得隐藏 executable/read-input/environment requirement。CI 维护高风险 dependency family gate，例如 HTTP/TLS、process/FFI、credential/crypto、native parser，并分别验证 runtime dependency 声明相应 SecurityEffects、build-only dependency 声明相应 build requirements。Metadata 是需要 code review 与 regression 支撑的安全声明，不是从 Cargo package 名自动推导行为的证明。未知 security effect、缺失 runtime/build 声明、lifecycle/provide/conditional own effect 超出 Component ceiling、resolved/Tool/Command effect 超出 sealed effective ceiling、runtime-adapter effect 非空、Host boundary effect 未进入 artifact union、build requirement 无法被 policy logical id 满足或未知 metadata schema 必须 fail closed。Build script 对 verified source/toolchain 的读取、target/temp 的写入以及 Cargo/rustc/derived executable 的使用属于受 sandbox 强制的 runner baseline，不因此赋予最终 binary `READ_LOCAL/WRITE_LOCAL/PROCESS_EXEC`；反之，runtime ceiling 也不能替代 build runner 的 filesystem/network/executable enforcement。

### Composition runtime security policy

Composition config 必须声明 exhaustive runtime-effect allow 上限；`deny` 用于 profile/integrator 叠加不可放宽的禁令。它控制哪些 runtime implementation 可以进入 binary，与控制 Cargo/build.rs 如何执行的 `BuildExecutionPolicy` 是两个不同平面：

```toml
[security]
allow = ["network", "secret-access"]
deny = ["process-exec", "remote-exec", "write-local"]
```

Selected Component 或 Host boundary 的每个 effect 都必须属于 `allow` 且不属于 `deny`；`deny` 优先。未列入 `allow` 的 effect 默认禁止。Resolver 在选 provider/Host boundary 时把 security policy 当 hard constraint，而不是 build 完成后再告警。Profile 提供默认 policy；Integrator 可以施加独立 ceiling/deny。Child profile 可以替换 parent 默认值，但任何 profile 或 invocation 都不得放宽 Integrator ceiling。

对 subprocess/code runtime 这类 delegated execution，profile/build config 必须另行给出 `[confinement]` allow/deny；缺失时含 `cap:confinement-issuer` 的 composition 失败。Generator 把它与全局 security policy、Integrator ceiling 求交，编译成 `SandboxPolicyCeiling` 常量并用于创建 ConfinementAuthority。Runtime config 只能提供实际 workspace root、resource limits 和更窄 policy；请求、Host callback 或 child Agent 都不能打开 ceiling 禁止的 filesystem/network/process/code effect。这样允许模型 HTTP network 不等于允许 child process network。Effective ceiling 与每次 spec 的 digest 都进入 security diagnostics，build manifest 记录 ceiling 但不记录 secret/path contents。

### Security Manifest

```json
{
  "component_runtime_effects": ["network", "secret-access"],
  "host_boundary_runtime_effects": [],
  "runtime_adapter_runtime_effects": [],
  "compiled_runtime_effects": ["network", "secret-access"],
  "build_requirements_union": {
    "executables": [],
    "read_inputs": [],
    "environment": []
  },
  "build_requirement_roots": [
    {
      "package": "model-deepseek",
      "root_kind": "component",
      "requirements": { "executables": [], "read_inputs": [], "environment": [] }
    },
    {
      "package": "rust-agent-model",
      "root_kind": "mandatory-api",
      "requirements": { "executables": [], "read_inputs": [], "environment": [] }
    },
    {
      "package": "rust-agent-runtime-tokio",
      "root_kind": "runtime-adapter",
      "requirements": { "executables": [], "read_inputs": [], "environment": [] }
    }
  ],
  "capabilities": ["cap:model", "cap:agent-driver"],
  "runtime_adapter": {
    "id": "runtime-tokio",
    "package": "rust-agent-runtime-tokio",
    "primitives": ["clock", "sleeper", "spawner"],
    "app_coexistence": "concurrent-independent",
    "runtime_ceiling": []
  },
  "host_boundaries": [],
  "deferred_factory_routes": [
    {
      "capability": "cap:agent-factory",
      "provider_owner": "generated-agent-scope-factory",
      "binding_effects": [],
      "creation_mode": "sessionless",
      "template": "agent-app-parent",
      "template_effects": ["network", "secret-access"],
      "projection_required": true,
      "plan_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ],
  "components": [
    {
      "id": "model-deepseek",
      "runtime_ceiling": ["network", "secret-access"],
      "lifecycle_effects": [],
      "provides": [
        {
          "capability": "cap:model",
          "key": "deepseek",
          "binding_effects": ["network", "secret-access"]
        }
      ]
    }
  ],
  "forbidden_effects_present": false
}
```

Manifest 中每个 binding（Registry 按 key、OrderedMulti 按 contributor、DecoratorChain 按 final chain）都保存 normalized runtime effect closure 与来源；唯一 deferred factory 另以 `deferred_factory_routes` 同时记录空 App binding 和每条 template 的完整 pre-projection closure/projection-required/plan digest，不能用空 stamp 隐藏模板风险。`component_runtime_effects` 是全部 selected Component runtime ceiling 的并集，`host_boundary_runtime_effects` 是 selected Host entry/export helper ceiling，`runtime_adapter_runtime_effects` 在 schema v1 必须为空，top-level `compiled_runtime_effects` 必须严格等于三者并集，不能用较窄 runtime route 覆盖。`runtime_adapter` 恰有一个条目并记录 id/package/target/support/primitives/empty ceiling；`host_boundaries` 对 library 为空，对 bin/wasm 恰有一个条目并记录 id/package/kind/target/support/runtime ceiling。`build_requirement_roots` 逐 root package（Component、mandatory API/infrastructure、runtime adapter、Host entry/export）保存，`build_requirements_union` 保存规范化并集；build manifest 再记录每个 logical requirement 命中的 path-free item identity/digest，concrete BuildExecutionPolicy mapping 只在 attestation 中记录。Runtime/build 字段和 digest domain 分离，禁止把 build-only resource 映射为 runtime effect。

### Binary absence verification

高风险能力关闭的验证必须同时覆盖：

1. resolution graph 不包含 component；
2. generated Cargo.toml 不包含 provider crate；
3. `cargo tree` 不包含 provider/known heavy dependency；
4. binary symbol/size regression 可选辅助验证。

仅有 `#[cfg]` 或 runtime `disabled=true` 不能满足“能力从 binary 消失”的安全要求。

## 34. Build Manifest / SBOM Integration

`compose` 生成：

```text
rust-agent-composition.json
```

`build` 在 composition manifest 基础上生成：

```text
rust-agent-build.json
```

至少包含：

- manifest schema version
- profile
- build kind / selected runtime-adapter package/primitive set / selected Host boundary package and kind
- normalized build config hash
- target triple
- canonical target-fact/custom-target-spec digest
- composition hash
- enabled/compiled components
- excluded components + provenance
- capability bindings
- registry provider sets
- scope construction plan summary
- every selected App Component plus runtime-adapter coexistence declaration/evidence digest and aggregate `app-handoff` mode
- selected internal Cargo features
- canonical Cargo resolution config/record digest
- generated Cargo direct dependencies
- Component runtime ceilings、lifecycle effects、per-provide/binding runtime effect closures、deferred factory route/template effect plans、selected runtime-adapter empty ceiling、selected Host boundary runtime ceiling，以及 component/adapter/host/final compiled runtime unions
- per-direct-root-package/union build requirements，以及每项命中的 path-free logical id/content/version/role identity digest
- package versions
- git revision / workspace revision
- generated `Cargo.toml` hash
- generated `composition.rs` hash
- generated `SessionEventCatalog` digest（Session plane 存在时）
- selected path package content digests
- compiler / Cargo version 与不含 concrete Host path 的规范化 logical invocation
- production/development mode、deployable flag
- path-free `BuildEnforcementIdentity` digest 与 normalized enforcement-result identity projection；完整 BuildExecutionPolicy、concrete mapping、evidence 和 trust/envelope 不写入 content-addressed build manifest
- path-free toolchain/read-input/executable/environment logical identity
- wasm build 的 postprocessor identity/invocation/raw-input digest 与完整 generated bundle file set（其它 build kind 显式为空）
- artifact-directory-relative path、kind、digest 与 target metadata
- derived `build-manifest-digest` 与 `build-output-digest`

完整 `build-execution-policy-digest`、logical→concrete runner mapping、sandbox evidence、allowed executor/reviewer/signer/signing-helper trust 与 signature envelope 写入独立、可追加的 signed build attestation。其 signed canonical payload 必须同时绑定 exact `composition-hash`、`build-output-digest` 与 `build-manifest-digest`，attestation 以 `(composition-hash, build-output-digest, build-manifest-digest, attestation-digest)` 寻址，不属于 immutable artifact directory 的 byte set。多个不同 Host mapping或 trust generation 可以分别证明同一个 build-output digest；它们不能改写该目录内的 build manifest/SBOM，也不能因 attestation rotation 造成 content-address collision。

Library的product integration attestation在上述composition/build manifest外追加：HostFeatureUnionPolicy id/digest（无合法Target delta时显式`none`）、build-host/target/planner identity、standalone/final/observed`HostCargoUnitGraph` digest、每个shared unit的package/target/compilation-kind/compile-mode/profile与baseline/actual/extra feature set、实际新增unit/edge closure、Host-unit exact/rejection结果、attribution mode、所有source-semantics evidence/reviewer-policy digest、composition/product effect归因、Target-unit feature-delta build requirements、产品build-unit下游runtime contribution及其Host-root ceiling归属、Host root effects，以及规范化`product_compiled_runtime_effects`。Pre receipt固定planned delta/evidence，build-host attests actual observed units/generated/link outputs，post逐项比较；三者不能只记录package-level feature map或不透明“feature check passed”布尔值。

用途：

- support/debug
- reproducible build comparison
- security verification
- SBOM bridge
- deployment attestation
- binary capability inspection

Composition manifest 在 Cargo 启动前即可审计。Cargo artifact、build manifest 与 SBOM 先写入 state root 的 staging output。Generator 先把完整 schema-valid `rust-agent-build.json` 中恰好两个派生字段 `build-manifest-digest`、`build-output-digest` 省略，按 RFC 8785 JCS 编码其余全部字段，计算 `build-manifest-digest = SHA-256("rust-agent-build-manifest-v1\0" || canonical-build-manifest-payload)`；unknown field、缺失 required field或其它省略均失败。然后计算 `build-output-digest = SHA-256("rust-agent-build-output-v1\0" || deterministic-CBOR(path-free toolchain/build-Host logical identity, BuildEnforcementIdentity, normalized enforcement-result identity projection, normalized build options, artifact kind/target metadata, postprocessor identity + normalized invocation + raw-input digest/none, sorted artifact relative-path/kind/byte digests, canonical SBOM digest, build-manifest-digest))`，最后才把两个摘要字段写入 manifest。这样 `deployable`、effect/build-requirement accounting、artifact metadata 或任何其它 manifest security field 的变化都会改变 manifest/output identity，同时避免 self-reference。

上述 identity 不包含完整 normalized BuildExecutionPolicy、staging/final directory path、serialized manifest bytes 或两个派生摘要字段本身。WASM 的 artifact digests必须覆盖 post-bindgen bundle 的全部文件，而不是只覆盖 Cargo raw module。`enforcement-result identity projection` 只含实际 backend semantic class/version、logical mount/access/exec/network restriction result 和 normalized input/result identity；它从已验证的 enforcement attestation payload 重算，但排除 evidence blob/digest、concrete runner mapping、policy/trust id 与 envelope 字段。Signed enforcement-attestation payload 仍绑定完整 policy digest、backend/version、规范化输入、logical→concrete runner mapping 的 redacted record、强制结果和证据 digest，并显式绑定最终 `build-manifest-digest`/`build-output-digest`；wall-clock timestamp、runner instance id、nonce、signature 与 transparency-log inclusion proof 只存在证明 envelope。因而改变 tool/input bytes、logical role/value、enforcement semantics 或 canonical build manifest 会改变 build-output identity；只移动相同输入到另一 canonical Host path，或轮换 allowed executor、reviewer/signer key、signing helper、signature/nonce/timestamp/transparency proof，不会改变它，但新 envelope 仍必须按当前完整 policy 独立验证。成功后原子发布到 `<state-dir>/artifacts/<composition-hash>/<build-output-digest>/`。Verifier/packager/cache importer 必须从实际 manifest 重算两个摘要、验证目录名和 signed attestation 三者一致；不允许信任 manifest 自报摘要。Manifest 只记录该目录内的规范化相对路径，避免 identity/path 循环；发布后 artifact directory、manifest 与 SBOM 均不可修改。失败 staging 不产生可引用 build manifest。标准 SBOM（CycloneDX/SPDX）作为 build 的独立输出，rust-agent manifest 保留更高层的 capability/binding 语义；记录的 invocation 必须规范化并 redact credential、token、header 和 secret-bearing environment value。

## 35. CLI / Composition Control Plane

提供独立 `rust-agent` CLI；开发期 `cargo xtask` 只做仓库维护辅助。

全局 `--state-dir <dir>` 指定 composition/artifact/attestation/cache/target/ref/staging root。`compose` 省略时使用 workspace manifest 所在目录的 `.rust-agent`；`build/inspect` 省略时使用当前目录的 `.rust-agent`。State dir 的绝对路径不进入 composition hash 或 generated source；staging 与最终目标必须位于同一文件系统，才能使用 atomic rename 发布。

```bash
rust-agent component list
rust-agent component graph
rust-agent component explain tool-shell
rust-agent capability graph
rust-agent provider list model
rust-agent profile show cli-coding

rust-agent compose --workspace-manifest Cargo.toml --profile minimal-pure \
  --target x86_64-unknown-linux-gnu --environment server \
  --runtime-adapter runtime-tokio --lock
rust-agent compose --workspace-manifest Cargo.toml --profile web-wasm \
  --target wasm32-unknown-unknown --build-kind wasm --lock
rust-agent build --composition <composition-hash> --locked \
  --execution-policy build-policies/ci-linux.toml

rust-agent emit-integration --composition <composition-hash> \
  --output generated/rust-agent/desktop-x86_64-linux --replace
rust-agent verify-integration --host-manifest app/desktop/Cargo.toml \
  --dependency rust-agent-composition-desktop --composition <composition-hash> \
  --phase pre --write-receipt target/rust-agent-integration.pre.json \
  --execution-policy build-policies/ci-linux.toml \
  --host-feature-policy build-policies/host-features.toml
rust-agent build-host --host-manifest app/desktop/Cargo.toml \
  --dependency rust-agent-composition-desktop --composition <composition-hash> \
  --pre-receipt target/rust-agent-integration.pre.json --locked \
  --execution-policy build-policies/ci-linux.toml \
  --host-feature-policy build-policies/host-features.toml \
  --write-attestation target/rust-agent-host-build.json
rust-agent verify-integration --host-manifest app/desktop/Cargo.toml \
  --dependency rust-agent-composition-desktop --composition <composition-hash> \
  --phase post --pre-receipt target/rust-agent-integration.pre.json \
  --executor-attestation target/rust-agent-host-build.json \
  --execution-policy build-policies/ci-linux.toml \
  --host-feature-policy build-policies/host-features.toml \
  --write-attestation target/rust-agent-integration.post.json

rust-agent inspect resolution --composition <composition-hash>
rust-agent inspect dependencies --composition <composition-hash>
rust-agent inspect scopes --composition <composition-hash>
rust-agent inspect security --composition <composition-hash>
rust-agent inspect manifest --composition <composition-hash>
```

`component graph` 必须展示：

```text
consumer
  ↓ requires
capability
  ↓ binding kind
selected/compiled provider(s)
  ↓ package
Cargo dependency
```

`explain` 必须输出 provenance，而不是只显示当前 bool enabled/disabled。

### Build command

```text
rust-agent build --composition <composition-hash> --locked \
  --execution-policy <policy.toml>
  ↓
validate immutable composition manifest/source/lock
  ↓
normalize and validate BuildExecutionPolicy
  ↓
fetch locked sources in fetch runner
  ↓
invoke cargo --offline in production sandbox
  ↓
attach/finalize build manifest
```

### Host build command

`build-host` 只接受 `build-kind=library`、成功的 production pre receipt、Host manifest、exact dependency alias/composition、`--locked`、BuildExecutionPolicy，以及 pre存在 feature delta时同一 HostFeatureUnionPolicy。它重验 receipt，并要求命令行 policy的 normalized digest与 receipt固定的 policy digest完全相同；随后重算并只读挂载 receipt固定的 `HostBuildInputClosure`，用同一 pinned planner重算 standalone/final unit graph。它用 Host Cargo.lock在 fetch runner物化与验证独立 cache，再在同一 production sandbox contract中执行 `cargo build --manifest-path <Host Cargo.toml> --locked --offline --target <composition-target> --message-format=json-render-diagnostics`；受控 rustc wrapper与 Cargo event recorder同时采集 Host/Target compile unit、exact feature cfg、extern edge、build-script/proc-macro unit和 artifact linkage。Schema v1 production build使用新的空 target/incremental root，禁止因本地 Cargo cache跳过 unit observation；未来若允许 compiled-unit cache，必须先定义逐 unit输入/输出/provenance签名并让 cache hit产生等价 observed evidence。只允许 target/temp/diagnostic写入；build后 closure/package-resolution/planned-unit/observed-unit/逐-unit feature-delta digest必须未变且 planned/observed graph exact匹配。Cargo JSON中属于 selected Host package/target的 executable/cdylib/staticlib作为 artifact set，空集合、越出 runner target root、target/kind不匹配或多个未消歧义终产物均失败。`--package/--bin/--lib/--example`只能从 pre metadata中存在的 Host target显式选择，并作为 planner input、closure与 attestation的一部分。

Executor attestation 的 signed canonical payload固定包含 schema、pre receipt digest、normalized build/feature policy与 backend attestation、HostBuildInputClosure aggregate/item digests、build-host/target/planner identity、standalone/final planned与 actual observed unit-graph digest、逐-unit feature/edge delta、Cargo/toolchain invocation identity、artifact effective panic strategy及其 target/rustc evidence、artifact relative path/target/kind/byte digest和 `deployable`，不包含 secret或 Host absolute path；outer envelope携带 signer id、algorithm、signature、nonce/timestamp和可选 transparency proof。Framework/bundler外部 executor（例如 framework CLI、Xcode/Gradle）可产生同 schema attestation，但 production post verification只接受 build policy allowlist中的 executor/backend/attestation signer，并必须验证其输入闭包、planned/observed Host与 Target unit、逐-unit feature delta、panic strategy、artifact文件与声明 digest；executor品牌本身不构成 runtime feature或支持证明。

`compose` 提供：

```bash
--emit-composition <dir>
--workspace-manifest <Cargo.toml>
--config <rust-agent.toml>
--profile <profile-id>
--target <target-triple>
--build-kind <bin|library|wasm>
--runtime-adapter <runtime-adapter-id>
--integration-id <stable-kebab-id>
--environment <browser|server|desktop|mobile>
--host-entry <host-entry-id>
--host-export <host-export-id>
--write-ref <path>
--lock
--explain
--strict
--allow-experimental
```

`build` 的 composition locator 必须二选一：

```bash
--composition <composition-hash>
--composition-ref <path>
```

Production build 还必须提供 `--locked --execution-policy <policy.toml>`；`--development-build` 与 `--execution-policy` 互斥，且同样要求 `--locked`。`--emit-composition` 只导出审计副本，不建立 Host dependency；library Host 集成必须使用独立的 `emit-integration` 和 `verify-integration` 命令。`emit-integration` 只接受 `build-kind=library` composition、`--output <dir>`；目标内容不同时还要求 `--replace`，且该 flag 是调用者已停止并排空所有 Cargo/metadata/watcher reader、独占目标目录的 offline-maintenance 声明，不提供 portable atomic directory replacement。不能排空 reader 时必须改用新 versioned output。`verify-integration` 必须接收 Host manifest、唯一 Cargo dependency alias 和 exact composition hash/ref，并验证该 alias 的 target-specific path 正好解析到 emitted root。Production `--phase pre` 必须指定 `--write-receipt` 和用于 fetch/offline metadata runner 的 `--execution-policy`；production `--phase post` 必须指定 `--pre-receipt`、`--executor-attestation`、用于验证 backend/executor/signer 的同一 `--execution-policy` 和不覆盖已有文件的 `--write-attestation`。Pre receipt、executor attestation 与 post attestation 路径必须互不相同。默认按 production 验证并拒绝 development-only composition，只有显式 `--allow-development` 才可用于不可发布的本地 Host build，该模式的 receipt/attestation 固定 `deployable=false`。

`inspect` 同样必须接收 `--composition` 或 `--composition-ref`，只读取已经原子发布且 digest 验证通过的 composition。

`--host-feature-policy` 只用于 library Host integration。Final Host graph 没有 feature delta 时可省略；存在任何允许的外部共享 dependency feature delta 时，pre、build-host 与 post 三阶段都必须提供同一 canonical policy，路径内容不同或 digest 不一致即失败。Standalone `compose/build`、bin/wasm 以及 emitted first-party package 不接受该参数放宽自身 feature set。

`--workspace-manifest` 是 package/capability discovery 的唯一 trust root；省略时固定为当前目录的 `Cargo.toml`，canonicalize 失败即终止。Compiler 先只解析 root/workspace manifest并执行第 26 节 Cargo resolution-context gate：任何 patch/replace/named registry/applicable workspace Cargo config在调用 `cargo metadata` 前拒绝，ambient `CARGO_HOME` 不参与。Workspace member 可以贡献本地 Capability/Component/runtime-adapter/Host-boundary/direct-root build-requirements metadata；非 member package 必须在 `[workspace.metadata.rust-agent.catalog]` 以 exact package name/version/source kind显式 allowlist。它随后在 state staging 生成独立 discovery manifest，以唯一 alias 依赖全部 allowlist entry，并在 schema-owned canonical Cargo config、empty Cargo home和隔离 root下，对 workspace graph + discovery graph 执行 `cargo metadata`；registry entry 必须由 lock/checksum 固定，git entry 必须固定 URL + precise commit，path entry 必须 canonicalize 到 trust root 内。`--lock` 可以为该显式 discovery input 解析 lock，production regeneration 必须复用/核对 locked identity及相同 `cargo-resolution.json`。只有 workspace member 或顶层 allowlist entry 自身的 rust-agent metadata 可贡献 catalog；普通 transitive dependency 即使同名或携带 metadata 也一律忽略。Discovery manifest/path/state location 不进入 composition identity，规范化后的 Cargo resolution record、entry、resolved source identity、metadata 与 dependency closure 进入。Production compose 默认 strict、拒绝 Experimental；`--allow-experimental` 生成 manifest 中 `development_only = true` 的不可发布 composition。Production build 固定 locked并拒绝 development-only composition；development build 和 `verify-integration --allow-development` 只产生不可发布证据。没有 generated Cargo.lock 时拒绝 build。

`--config` 没有隐式默认文件；profile 必须由 CLI 或显式 build config 给出，同一 scalar 从多个来源出现时值必须一致，否则 normalization 失败。`--target` 必须由 CLI、build config 或只含一个 target 的 profile 明确给出；不得从运行 compose 的 Host triple 猜测。`build-kind` 未指定时：profile 声明 `host-entry` 则为 `bin`，声明 `host-export` 则必须同时显式声明 `build-kind=wasm`，二者都未声明则为 `library`；entry/export 同时存在或与 build kind 不匹配时 normalization 失败。`runtime-adapter` 同样必须由 CLI、build config 或 profile 显式给出且多来源值一致；不得从 compose Host 当前 executor、Cargo feature 或 ambient Tokio context猜测，target/support/Host-boundary compatibility 与 primitive union 不满足时在 snapshot/generation 前失败。`compose --write-ref` 在 content-addressed composition 原子发布成功后写入只含 schema version、composition hash 与 composition-manifest digest 的小文件。`build` 必须接收 exact hash 或 ref；不接受 profile 重新解析“最新”lock，ref 缺失、digest 不符或指向未完成 composition 时失败。

`environment` 必须由 CLI、build config 或 profile 明确给出，来源冲突时失败。`build-kind=wasm` 还强制 `environment=browser`；内置 host-cli profile 固定使用 `desktop`。Compiler 不从运行 compose 的 Host OS 或 target triple 猜测 environment。

## 36. Profiles

Profile 是 build composition preset，不是 runtime plugin bundle。

第一批内置 profile：

```toml
[profiles.minimal-pure]
agent-modes = ["sessionless"]
enable = [
  "model-replay",
]

[profiles.minimal-pure.bindings]
agent-driver = "driver-direct"

[profiles.minimal-pure.security]
allow = []
deny = ["network", "secret-access", "process-exec", "remote-exec", "write-local"]

[profiles.minimal-remote]
agent-modes = ["sessionless"]
enable = [
  "model-deepseek",
  "network-policy-default",
  "credentials-env",
]

[profiles.minimal-remote.bindings]
agent-driver = "driver-direct"

[profiles.minimal-remote.security]
allow = ["network", "secret-access"]
deny = ["process-exec", "remote-exec", "write-local"]

[profiles.cli-readonly]
extends = "minimal-remote"
host-entry = "host-cli"
runtime-adapter = "runtime-tokio"
environment = "desktop"
enable = [
  "prompt-assembly",
  "fs-read-local",
  "tool-fs",
]
disable = [
  "fs-local",
  "subprocess-local",
  "shell-local",
  "terminal-local",
]

[profiles.cli-readonly.bindings]
agent-driver = "driver-tools"

[profiles.cli-readonly.security]
allow = ["network", "secret-access", "read-local"]
deny = ["process-exec", "remote-exec", "write-local"]

[profiles.cli-coding]
extends = "minimal-remote"
host-entry = "host-cli"
runtime-adapter = "runtime-tokio"
environment = "desktop"
targets = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
agent-modes = ["sessionless", "durable"]
enable = [
  "prompt-assembly",
  "fs-local",
  "tool-fs",
  "subprocess-local",
  "sandbox-linux",
  "shell-local",
  "tool-shell",
  "kv-redb",
  "memory-context",
  "session-log-events",
  "session-persistence-jsonl",
]

[profiles.cli-coding.bindings]
agent-driver = "driver-tools"

[profiles.cli-coding.security]
allow = ["network", "secret-access", "read-local", "write-local", "process-exec", "persistent-storage"]
deny = ["remote-exec"]

[profiles.cli-coding.confinement]
allow = ["read-local", "write-local"]
deny = ["network", "secret-access", "remote-exec", "code-exec"]

[profiles.web-native]
extends = "minimal-remote"
runtime-adapter = "runtime-tokio"
environment = "server"
enable = [
  "prompt-assembly",
  "tool-web",
  "web-http-native",
  "web-search-deepseek",
  "prompt-skills",
  "skill-embedded",
]

[profiles.web-native.bindings]
agent-driver = "driver-tools"

[profiles.web-native.security]
allow = ["network", "secret-access"]
deny = ["read-local", "write-local", "process-exec", "remote-exec"]

[profiles.web-wasm]
build-kind = "wasm"
host-export = "host-wasm"
runtime-adapter = "runtime-wasm"
environment = "browser"
targets = ["wasm32-unknown-unknown"]
agent-modes = ["sessionless"]
enable = [
  "model-host",
  "prompt-assembly",
  "tool-web",
  "web-fetch-host",
  "web-search-host",
  "prompt-skills",
  "skill-embedded",
]
disable = [
  "subprocess-local",
  "shell-local",
  "terminal-local",
  "parser-pdf",
  "vector-hnsw",
  "fs-local",
]

[profiles.web-wasm.bindings]
agent-driver = "driver-tools"

[profiles.web-wasm.security]
allow = ["host-bridge"]
deny = ["network", "secret-access", "read-local", "write-local", "process-exec", "remote-exec"]
```

### 为什么需要 minimal-pure 与 minimal-remote

最严格的 dependency-negative test 必须有一个不需要 HTTP/network 的纯最小 composition；否则“minimal 不能出现 reqwest”和“minimal 使用 remote model provider”互相冲突。

`model-replay` 的 minimal-pure fixture 数据编译为只读内存常量，不读取文件、环境、网络或持久化存储。

### Driver replacement

Profile 的 `[profiles.<name>.bindings]` 是 Singleton binding root。Child 对同一 Capability 的值完全替换 parent 值；被替换 provider 不再是 profile requirement，除非它还被独立列入 child 的 `enable`。因此 `minimal-remote → cli-coding` 标准化后只要求 `driver-tools`，不会同时保留 `driver-direct`。

## 37. Component Pack

只作为 UX sugar：

```toml
[packs.coding]
components = [
  "tool-fs",
  "tool-shell",
  "tool-lsp",
  "skill-filesystem"
]
```

Pack 展开后立刻消失，不参与 resolver 底层语义。

---

## 38. Configuration 分层

必须严格分离 Build Composition 与 Runtime Behavior。

### Build config

```toml
[build]
profile = "minimal-remote"
target = "x86_64-unknown-linux-gnu"
environment = "desktop"
agent-modes = ["sessionless"]
resolver-decision-budget = 100000

[components]
tool-shell = "enabled"
shell-local = "disabled"
mcp-client = "enabled"

[bindings]
agent-driver = "driver-tools"
shell = "shell-ssh"

[provider-sets.mcp-transport]
include = ["mcp-transport-http"]

[security]
deny = ["process-exec", "write-local"]
allow = ["network", "remote-exec", "secret-access", "mcp-connect"]
```

Build config 影响：

- package 是否进入 generated Cargo graph；
- provider candidate/binding；
- target/security constraint；
- internal additive feature；
- generated composition source。

Singleton `[bindings]` 覆盖 profile binding root；Registry/OrderedMulti 的 `[provider-sets.<capability>]` 支持 `include`/`exclude`，条目是 Component id。显式 include 等价于 build requirement，无法满足时 ERROR。`preferences` 只改变自动候选搜索顺序，不产生 root。

### Runtime config

```toml
[runtime]
shutdown_timeout_ms = 30000
max_live_agents = 32
lifecycle_observer_timeout_ms = 1000
lifecycle_notification_max_pending = 128
session_observer_timeout_ms = 1000
session_observer_shutdown_timeout_ms = 5000
session_observer_max_pending_batches = 128
session_observer_max_pending_bytes = 8388608

[runtime.agent_authority]
deny_effects = ["remote-exec", "code-exec"]
max_child_depth = 4
max_total_descendants = 32
max_child_concurrency = 8

[binding.model]
mode = "default"
default = "deepseek"

[component.model-deepseek]
base_url = "..."
model = "..."
timeout_ms = 30000
api_key = { credential = { provider = "env", name = "deepseek/default" } }

[component.shell-ssh]
host = "..."
```

Runtime config 只能：

- 设置 timeout/cap/typed routing mode/default；
- 在已编译 Registry provider 中选 key；
- 配置 host path、endpoint、policy；
- 引用 credential。

`[runtime]` 是 generated infrastructure 的封闭、版本化 schema，用于 lifecycle/concurrency/budget 等运行参数；其中 `lifecycle_observer_timeout_ms` 与 `lifecycle_notification_max_pending` 必须为非零并受 generated hard ceiling 限制，queue capacity 还必须足以为允许的 live publication pair 预留 published/disposed batch，否则 App initialize 失败。四个 `session_observer_*` 字段也必须非零且不超过 generated per-callback/shutdown/pending-batch/pending-byte hard ceiling，shutdown deadline 不得大于 App `shutdown_timeout_ms`；选中 `cap:session-observer` 时缺少任一字段使 App initialize 失败，未选中时 generator 不构造 dispatcher。Generated `[runtime.agent_authority]` 只生成 build composition 中存在的 binding/effect/key/contributor 字段和可衰减数值 budget；event feed 至少生成 `max_event_feed_subscribers`、`max_event_feed_buffered_events_total`、`max_event_feed_buffered_bytes_total`，三者非零并受 compiled hard ceiling 限制。该 section 只允许 deny/remove/降低上限，不能出现 `allow`、新增 provider 或提高 feed aggregate budget。它在任何 App namespace bootstrap I/O 前与 compiled binding/effect/confinement ceiling 求交形成 root `BootstrapAuthorityProjection`，prepared descriptors 返回后才完成 root authority。`[binding.<capability>]` 只承载 typed Registry route/default；其中 model registry 的 `mode/default` 组合严格遵循第 5/28 节，`explicit-per-request` 不能携带 default。`[component.<id>]` 只承载对应 file-source Config。未知 section/field、重复 key、host-source Component 出现在 TOML 都导致启动失败。

Runtime config 不能：

- 引入未编译 crate；
- 创建新的 capability type；
- 绕过 composition runtime security policy；
- 通过字符串 class/module path 动态 load 任意 native code。

### Secret

Secret 只能通过 `CredentialRef`：

```toml
api_key = { credential = { provider = "env", name = "deepseek/default" } }
```

禁止把 resolved secret 长期复制进普通 config、SessionEvent、build manifest 或 telemetry。

## 39. AINS Integration

新 rust-agent 不实现 `AinsGatewayModel`。

AINS 自己建立 adapter crate，例如：

```text
AINS/app/agent-integration
```

```rust
use std::sync::Arc;

pub mod host_api {
    use std::sync::Arc;

    pub use async_trait::async_trait;
    pub use rust_agent_model::{
        ModelCallContext, ModelError, ModelRequest, ModelStream,
    };
    pub use rust_agent_runtime_api::MaybeSendSync;

    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    pub trait AinsGatewayHandle: MaybeSendSync {
        async fn stream(
            &self,
            context: ModelCallContext,
            request: ModelRequest,
        ) -> Result<ModelStream, ModelError>;
    }

    pub struct Config {
        pub gateway: Arc<dyn AinsGatewayHandle>,
    }
}

pub struct AinsGatewayModel {
    gateway: Arc<dyn host_api::AinsGatewayHandle>,
}

impl LanguageModel for AinsGatewayModel { ... }
```

该 adapter crate 作为 AINS workspace member 使用标准 Component metadata，提供 `cap:model`、Registry key `ains-gateway`、App scope factory，固定 `config-source = "host"`、`config-type = "ains_gateway_adapter::host_api::Config"` 和 `host-api = "ains_gateway_adapter::host_api"`。AINS Host 从 emitted alias 的 `host_api::ains_gateway` namespace 实现 `AinsGatewayHandle`；concrete type 可以闭包持有活动 workspace 的 `ClientApi`，但 Config/trait/DTO public closure 不出现 `ClientApi` concrete type，避免 emitted snapshot 与活动 workspace 产生不兼容的重复 path-package type identity。AINS workspace catalog allowlist 固定所用 rust-agent API/Component package 的 exact version 与 locked registry checksum 或 git precise commit；Generated root 可以依赖 adapter，但 rust-agent 的任何 API/Component crate 不依赖 AINS。

AINS 对每个产品 target/profile 生成独立 `build-kind=library` composition，并 emit 到固定、可提交目录：

```text
AINS/generated/rust-agent/<profile>-<target>/
```

每个产品 composition 必须在 AINS build config 中显式固定唯一 `integration-id`（例如 `ains-web-wasm`、`ains-desktop-linux`），不随 composition hash 改名；CI 在同一 Host lock 内校验这些 id 与 generated package name 不碰撞。

`app/web`、`app/desktop`、`app/mobile` 或 server Host 在 target-specific Cargo dependency 中用唯一 alias 直接 path-depend 对应 emitted composition；Host 只从该 alias 使用 generated `RuntimeConfig`、`HostBindingsBuilder`、`create_runtime_primitives`/`RuntimePrimitives` build contract、`AppHandle` 和 namespaced `host_api`，不得另依赖一份 active-workspace runtime adapter。CI 在最终产品 framework/Cargo build（当前为 Dioxus）前以该产品的 normalized BuildExecutionPolicy 执行 `verify-integration --phase pre`，产品 build executor 使用同一 policy 生成 sandbox/toolchain attestation，最终 artifact 生成后以同一 policy 执行 `verify-integration --phase post`。Rust browser Host 与 runtime 位于同一 WASM module 时使用 `build-kind=library --target wasm32-unknown-unknown`；只有 JavaScript Host 直接持有 `WasmAppHandle` 时使用 `build-kind=wasm`。选择依据始终是 Host topology，不是 Dioxus framework identity。

AINS与emitted composition共享的`tokio`、`reqwest`、`web-sys`等external package按Cargo unit-specific feature-unification规则处理。Schema v1中任何shared Host-unit非空delta直接拒绝；只有合法shared Target-library delta按target/profile/unit selector提交`HostFeatureUnionPolicy`并把同一policy传给pre/build-host/post，没有delta的graph显式记录`none`且不传空policy。AINS对shared Target unit默认使用`composition-conservative`并把delta的全部可能effect纳入composition-path ceiling；只有checked-in、绑定exact unit/source/checksum/range/delta closure且由allowlisted reviewer policy签核的source-semantics evidence才能使用`host-only-additive-api`，AINS是feature requester本身或reverse dependency path都不是充分证据。Target delta触达custom build/proc macro/generated/link output也拒绝；AINS自有build unit的执行要求进BuildExecutionPolicy，其下游runtime contribution进入AINS Host-root ceiling。Emitted first-party rust-agent/adapter snapshot的任何unit仍不得由AINS增加feature。AINS Cargo.lock、unit graph、feature或evidence bytes变化使实际delta改变时，CI必须先更新审计/policy或拒绝build，不能把新union当成composition原有feature。

AINS product Host（当前 Dioxus）同样实现：

- Approval
- UserInteraction
- credential bridge
- optional remote Session/Attachment storage adapter
- AINS command providers

DirectoryPicker 保持 AINS-local UI，输出只通过 typed RuntimeConfig、AttachmentStore 或 UserInteraction 进入 rust-agent，不新增隐式全局 Capability。

AINS UI/view-model adapter（当前 Dioxus）只通过 `AgentHandle::open_event_feed` 消费 bounded live events，通过 `AppHandle::session_query` 做 committed cold replay/lag recovery；adapter 不建立无界 `stream_rx`、不直接订阅内部 `SessionObserver`，也不通过轮询 runtime internal state 补事件。所有需要 history/resume 的 AINS target/profile 必须显式选择 `session-query-events`，否则 generated handle 按契约返回 `UnsupportedOperation`；纯 Sessionless profile 可省略。每个 UI turn 保存 exact `AgentRequestId`，Stop 只调用 targeted cancel；`Lagged` 时 Durable view 从 baseline/high-water 重建后重订阅，Sessionless 明示不可恢复 gap。

AINS 的 Redb/IndexedDB、账户级 cache 或其它 process/origin singleton 不得假定两个 App 可独立 open。直接拥有 Redb file/transaction manager 的 canonical provider 必须声明 `requires-stop`，按 stop-old-app 顺序完成切换；只有 AINS Host 先拥有一个可并发复用的 typed storage handle，adapter `config-source=host` 且两个 App 的 HostBindings 携带同一私有 handle identity、provider 不再按 path reopen 时，才可声明 `concurrent-shared-host-handle`。产品 inventory 必须逐 target/profile 记录这个选择和 regression evidence。

---

## 40. AINS 现有代码迁移矩阵

| AINS 当前模块 | 新架构目标 | 策略 |
|---|---|---|
| `kernel/event_loop.rs` | `driver-tools` | 不直接搬；按行为测试重写 |
| `kernel/messages.rs` | core/model DTO | 精简迁移 |
| `kernel/fsm.rs` | driver internal state | 可参考迁移 |
| `model_client.rs` | Model + Embeddings | 拆分重写；STT/TTS 第一版留在 AINS Host |
| `model_service.rs` | AINS adapter / generic provider logic | 分类迁移 |
| `tools/mod.rs` | Tool trait DTO | 选择性迁移 |
| `tools/runtime.rs` | internal ToolRegistry + guarded execution pipeline | 拆分迁移 |
| `tools/filesystem.rs` | fs-local + tool-fs | 大量迁移 |
| `tools/network.rs` | network-policy-default + network-connector-native + http-client-native + web-http-native | 迁移 hostname pre-DNS policy、Native SSRF/DNS pinning/redirect 行为；WASM 改用 Host bridge |
| `tools/mcp.rs` | mcp-client + mcp-transport-http/stdio | 拆 transport 后迁移，统一接 NetworkPolicy/Sandbox |
| `policy/permission_engine.rs` | permission provider | 大量迁移 |
| `policy/sandbox_linux.rs` | sandbox-linux | 迁移并保留 Linux regression |
| `policy/sandbox_macos.rs` / `sandbox_windows.rs` | 对应 platform provider | 真实 target 验证通过后启用 production support |
| `policy/sandbox_mobile.rs` | mobile-policy | 迁移 deny policy，不提供 sandbox/process capability |
| `context/session.rs` | 不作为新 SessionLog 来源 | 只迁移可复用 DTO；事件 vocabulary 按新模型实现 |
| `memory/kv_native.rs` | kv-redb | 直接迁移后解耦 |
| `memory/kv_web.rs` | kv-indexeddb | 直接迁移后解耦 |
| `memory/kv_crypto.rs` | kv-encrypted decorator | 直接迁移 |
| `memory/vector_native.rs` | vector-hnsw | 迁移 |
| `memory/parser.rs` | parser-* | 拆分迁移 |
| `memory/service.rs` | memory composition | 不直接搬，重新分解 |
| `skills/*` | skill provider / tool-skill | 分层迁移 |
| `commands/*` | AINS Agent-scoped `cap:command-provider` Components | 按 command 拆分；通用 PlanMode 语义迁入 `plan-mode`，产品动作留 AINS |
| `hooks/*` | driver/tool lifecycle hooks | 重新定义 seam 后迁移 |
| `swarm/*` | subagent/team | 重新建模 |
| `perception/*` | STT/vision host extensions | 拆 capability，部分应留 Host |
| `personalization/*` | memory/prompt contributors | 拆分 |
| `runtime_native/web` | provider-specific runtime / Host bridge | 不进入 core，WASM network 通过显式 Host provider |

---

## 41. Extension Model：Typed Contributors / Middleware / Observers

不复制 Cordis event bus，也不建立任意字符串事件总线作为 core API。

把不同扩展语义建模成不同 capability：

```text
PromptContributor        OrderedMulti
cap:tool-execution-middleware / ToolExecutionMiddleware  OrderedMulti, Agent scope
cap:agent-step-middleware / AgentStepMiddleware          OrderedMulti, Agent scope
cap:session-observer / SessionObserver                    OrderedMulti, Session scope
cap:telemetry / Telemetry                                OrderedMulti, App scope
cap:lifecycle-observer / LifecycleObserver                OrderedMulti, App scope
cap:command-provider / CommandProvider                    OrderedMulti, Agent scope
```

```rust
pub struct SessionObserverContext { /* private deadline + cancellation + Session/EventBatch identity */ }

pub trait SessionObserver: MaybeSendSync {
    async fn on_committed(
        &self,
        context: SessionObserverContext,
        events: Arc<[StoredEvent]>,
    ) -> Result<(), ObserverError>;
}
```

每个 live Session writer 在任何 append 前构造一个 owner-scoped、单 worker 的 bounded observer dispatcher，按 `runtime.session_observer_max_pending_batches` 与 `runtime.session_observer_max_pending_bytes` 同时限制 pending set，并受 generated hard ceiling 约束；pending 同时包含 queue 中和当前正在 dispatch 的 batch，其 reservation 直到最后一个 contributor完成或被取消/drop才释放。Byte charge 是 schema 固定的 canonical stored-event envelope bytes饱和求和加 per-batch/per-event 固定 overhead，不依赖 allocator capacity或 provider自报 size；单批 charge 超限直接走 drop。Dispatcher 预分配 queue/counter storage，复用 commit path 已拥有的 immutable `Arc<[StoredEvent]>`，绝不为每个 batch/observer spawn detached task。SessionLog 只在 EventBatchId 首次被确认 `Committed` 后，按 canonical sequence 对整个 batch做一次 allocation-free/nonblocking reserve-and-enqueue decision；`NotCommitted` 不通知，`CommitStatusUnknown` 只在 `resolve_batch` 首次确认 committed 后做同一 decision，同 id 的 append/resolve retry不得再次 enqueue。Batch/byte reservation都有容量时，`append`/`resolve_batch` 在 enqueue 完成后立即返回既定 commit outcome，不等待 callback；任一上限会超出时，整批 observer notification被 best-effort drop，以固定大小的饱和 counters + sequence range记录 dropped batch/event/byte telemetry 后仍返回 `Committed`。Observer pending状态绝不能改变、撤销或延迟已经 committed 的 domain result。

Dispatcher 按 Session sequence，再按 contributor metadata `order, component_id` 串行调用；每次构造字段私有的 `SessionObserverContext`，以 `runtime.session_observer_timeout_ms` 强制 monotonic deadline/cancellation。Timeout 时取消并 drop future，error/timeout 记录 diagnostics 后继续下一个 contributor；在满足统一 unwind gate 的 artifact 中，callback construction/poll/drop panic 也由 `catch_unwind` 隔离，否则不能声称 panic containment。一次 contributor attempt 不重试，cold resume 不重放历史 batch，queue drop也不补发，因此此 seam 既不是 at-least-once 也不是 exactly-once。Session shutdown 先关闭新 enqueue，在 `runtime.session_observer_shutdown_timeout_ms` 的总 deadline内 bounded drain；到期取消当前 callback、丢弃剩余 queue并释放 worker，任何 observer task 不得越过 Session owner teardown。Observer 必须幂等、只做观测，不能回写同一 SessionLog 或产生可靠外部业务 side effect；需要可靠处理的逻辑必须使用带 checkpoint 的 projection/query consumer。

示例：

```rust
pub trait AgentStepMiddleware: MaybeSendSync {
    async fn before_step(
        &self,
        ctx: &StepContext,
    ) -> Result<StepDecision, StepMiddlewareError>;

    async fn after_step(
        &self,
        result: &StepResult,
    ) -> Result<(), StepMiddlewareError>;
}
```

```rust
pub trait ToolExecutionMiddleware: MaybeSendSync {
    fn id(&self) -> &'static str;
    fn order(&self) -> i32;
    // pre / around / post contract 由 tools crate 明确定义
}
```

### Extension contract 必须声明

- ordering；
- scope（App/Agent/Session）；
- whether short-circuit allowed；
- failure containment；
- cancellation contract；
- durable state impact；
- mutation permissions；
- teardown ownership。

不要为“灵活”把所有扩展重新抽象成：

```text
emit("anything", JsonValue)
```

跨领域 runtime observer 必须定义独立 typed event enum/interface 和明确 dispatch semantics；durable Session 扩展事件只使用 generated `SessionEventCatalog` 约束的 `ExtensionSessionEvent`，不通过 observer bus 代写 SessionLog。

## 42. Cancellation / Concurrency

统一 cancellation abstraction：

```rust
pub trait Cancellation: MaybeSendSync {
    fn is_cancelled(&self) -> bool;
    async fn cancelled(&self);
}
```

`CallContext` 是 runtime-api 的非序列化执行上下文，至少包含 request/operation id、absolute deadline、`CancellationToken`、budget lineage 与 redacted tracing context；`ModelCallContext/WebCallContext/HttpCallContext/StorageCallContext/MemoryCallContext/RetrievalCallContext` 是增加领域字段的 newtype。其中 `ModelCallContext` 还强制携带 paired request-journal proof，不能从普通 `CallContext` public 转换。Provider 派生 child context 时只能收紧 deadline/budget，不能替换或脱离 parent cancellation。

生产规则：

- model stream、tool dispatch、subprocess、web、MCP 都接同一 turn cancellation lineage
- child operations 可派生 child token
- cancellation 只停止新 dispatch
- 已开始的 external side effect 需要定义是否可安全 abort
- subprocess 必须杀 process tree，不只 parent PID
- shutdown cancellation 与 user turn cancellation 区分 cause

Concurrency：

- ToolDefinition 提供 concurrency class / exclusive resource key
- 默认保守为 exclusive
- parallel-safe 使用 rolling bounded pool
- scheduler 失败不得伪造 Tool body output；durable mode 必须为已记录但未执行的 call 追加结构化 `Interrupted(SchedulerFailure)` result

---

## 43. Persistence Correctness / Crash Recovery / Reconstructability

Session persistence 必须解决：

- append ordering；
- atomic batch；
- event sequence monotonicity；
- crash recovery；
- flush barrier；
- schema version；
- catalog-validated Informational event projection 与 fail-closed unknown event handling；
- corruption diagnostics；
- live-session 与 cold-session recovery 区别；
- resume/fork seed boundary；
- lifecycle operation id 到 SessionId 的 durable global locator；
- model-visible state reconstructability。

### Durable checkpoint

Persistence 可以后台 batch Buffered event，但会触发外部动作或对调用方确认成功的业务 checkpoint 必须使用带稳定 EventBatchId 的 `AppendDurability::Durable`：

```text
SessionLog append(Durable, stable batch id)
    ↓
backend transaction + batch-id index
    ↓
durable sync + commit-status resolution
    ↓
Committed(range) / NotCommitted / CommitStatusUnknown(batch id)
```

Durable Agent 固定 checkpoint：

1. `UserMessage + RequestPrepared` batch 在 model request 发出前确认 Committed；
2. `ToolCall` 在可能产生外部 side effect 的 dispatch 前确认 Committed；
3. `TurnEnded` 在 `AgentHandle::send` 向调用方成功返回前确认 Committed；
4. fork/resume seed、behavior mode、goal/workflow 等会触发后续自主工作的状态，在发布内存状态或调度自主工作前确认 Committed。

第 1 项的 confirmed EventRange、canonical record digest、Session/Agent identity、provider route 与 fencing generation 被 request-journal facade 密封为 `RequestJournalProof`；第 2 项的 exact Agent/Session/step/call/tool/snapshot/arguments/effects digest 与 confirmed EventRange 被同一 facade 的独立 paired issuer 密封为 `ToolCallJournalProof`。两种 proof 都只活在本次 process/request lifecycle，不写回 event。Model consumer binding 必须在 provider stream 前核对 proof 与实际 `PreparedModelCall`；model-origin Tool consumer binding 必须在 PermissionPolicy、Approval、middleware external hook、permit 或 provider dispatch 前核对 proof 与实际 `PreparedToolCall`。因此两种 append checkpoint 与调用授权都是不可分叉的 typed path。

不要求每个 delta/informational event 都同步 fsync；上述 checkpoint 之间可以 Buffered append，`flush()` 用于 shutdown/checkpoint quiescence。`NotCommitted` 停止对应外部动作或成功返回；`CommitStatusUnknown` 关闭 admission 并按 batch id 读回，不得以未提交处理。Tool side effect 已开始后发生存储故障时，log 必须记录或在 crash recovery 中推导 `OutcomeUnknown`，不能自动重试非幂等调用。

### Crash recovery

如果冷加载发现：

```text
TurnStarted
...
(no TurnEnded)
```

不得简单截断整个 turn。应根据 event vocabulary 进行 deterministic interrupted recovery，并保证后续 replay 得到合法状态。

Live session 不允许另一个 persistence reader 擅自写 synthetic recovery event；live owner 是 authoritative writer。

### JSONL provider

- store-level commit coordinator 使用跨进程 exclusive lease/fencing，序列化所有 Session 的权威 journal append；per-session writer lease 继续防同一 Session 双写，不能替代 global coordinator；
- store header/journal 保存StoreIdentity与永不回退的lifecycle-operation issuer generation + counter；每次async allocation只接受含pre-journaled recovery key的完整sealed reservation，并在同一coordinator下以单个durable envelope原子写`recovery-key → id`、增加counter、记录intent/request fingerprint/projected authority+plan digest/composition/catalog/Session。Response unknown后same-key exact retry必须读回原id或在证明Absent后首次分配，不能留下不可定位reservation/第二个id；genesis/Prepared envelope只原子消费exact key+reservation，不能首次补写或改变fingerprint；同StoreIdentity的writable snapshot/clone不受支持，离线fork必须重写identity并禁止旧token/key进入；
- Buffered append 可以在内存合并，但 Durable append 与 `flush()` 必须把完整 authority envelope 写入唯一 store commit journal，并在目标文件系统执行所需的 file/directory sync barrier；
- journal/envelope version；每个 envelope 带 StoreGeneration、journal offset、SessionId、EventBatchId、event count、sequence range、checksum，以及同事务 lifecycle locator/terminal mutation；禁止把一个 batch 或 locator mutation拆成多个 commit record；
- torn tail 只有完整 checksum envelope 才 committed；stable batch/operation id lookup 能在 response loss 后区分 committed/absent/unknown；
- per-session artifacts、batch index、global locator、terminal-summary 与 bounded session-list index 是按 committed high-water 生成的派生 checkpoint，rename 只发布 checkpoint，绝不构成 domain commit；checkpoint 丢失/超前/损坏时从 authority journal deterministic rebuild；
- concurrent different-session create/resume 与 global operation-id uniqueness tests 必须证明没有 lost update；
- torn tail diagnostics/recovery；
- store 与 per-session artifact identity。

### Redb provider

- atomic transaction；
- StoreIdentity-scoped issuer generation + monotonic counter allocation、`recovery-key → id`唯一索引与完整sealed reservation（key/intent/fingerprint/authority+plan/composition/catalog/Session）在同一事务写入；same-key exact retry返回原id，conflicting payload拒绝，response unknown可按key恢复且不产生第二次allocation，genesis/Prepared只消费exact reservation，离线writable fork必须取得新StoreIdentity；
- EventBatchId 唯一索引与幂等 bytes 校验；
- lifecycle operation id 全局唯一索引、allocation-time完整 request fingerprint reservation与 genesis/Prepared/terminal 的同事务 locator 更新；
- monotonic sequence constraint；
- storage schema version；
- query index 与 canonical event 写入分离。

### Unknown event

长期事件 envelope 与 generated SessionEventCatalog 必须能区分：

```text
catalog-known Required event      → every faithful reader must understand/reconstruct
catalog-known Informational event → uninterested projection may skip after validation
unknown producer/kind/version     → reject load/resume
```

不能信任未知 envelope 自报的 `criticality`：新 reader 没有原始声明时无法证明它确实不影响 reconstruction。SessionLog 必须先用当前同 identity 的 generated catalog 校验 producer、kind、payload version、criticality、bounds 和 checksum；只有验证成功且 catalog 声明为 Informational 的事件，领域 projection 才可以跳过。任何未知、损坏或伪造 envelope 都拒绝 load/resume。

## 44. Data Versioning

所有长期存储 DTO 必须：

```rust
enum RecordCriticality {
    Required,
    Informational,
}

struct StoredEnvelope<T> {
    envelope_version: u32,
    kind: String,
    criticality: RecordCriticality,
    payload_version: u32,
    payload: T,
}
```

`criticality` 是 catalog 声明的持久化冗余校验值，不是 event producer 或 reader 可自行降级的提示。Append 时必须与 generated catalog 完全一致，load 时也必须复验；Session genesis 同时记录 composition hash 与 SessionEventCatalog digest，防止使用另一个 catalog 解释同一日志。

禁止把 crate 内部 struct 直接 bincode 后承诺永久兼容。

Encrypted store 需要把 key version / cipher suite / nonce schema 写进 envelope。

---

## 45. WASM 设计

WASM 不是“native 删掉 subprocess 就完事”。

WASM profile：

- no shell-local
- no subprocess-local
- no terminal-local
- no native PDF parser
- no HNSW unless verified WASM-friendly provider separately introduced
- IndexedDB provider only when storage is selected
- no direct browser Web/MCP transport that cannot enforce DNS/redirect policy
- model/web/MCP network capability uses explicit Host bridge provider
- host-granted filesystem/browser APIs 作为独立 provider，而不是伪装 local fs

Host bridge 是显式 trust boundary：generated `wasm-host-constructor` 必须验证 callback shape/version/origin binding，所有请求携带 request id、cancellation、deadline 与 input/output byte budget。Host 负责 credentials、NetworkPolicy、redirect/DNS enforcement 和审计；browser runtime 不接收长期 secret，也不得在 Host 拒绝/断开/返回超预算数据时 fallback 到 `fetch`。Security manifest 必须记录 `HOST_BRIDGE` 及每个 bridge Component。

Trait `Send`：

统一定义 target-aware marker：

```rust
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSendSync: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync + ?Sized> MaybeSendSync for T {}

#[cfg(target_arch = "wasm32")]
pub trait MaybeSendSync {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSendSync for T {}
```

`MaybeSend` 使用相同模式但只约束 `Send`。所有跨 target dyn async Capability 使用第 4 节的 `async_trait` 约定；不得在各 crate 自行发明不同的 `Send`/`?Send` cfg。

---

## 46. Testing Strategy

### 46.1 Resolver Unit Tests

覆盖：

- required closure
- auto exclusion propagation
- explicit disable hard exclusion
- explicit enabled unsatisfiable error
- provider preference
- provider conflict
- bounded backtracking fallback
- component conflict
- target unsupported
- composition environment predicate 与 Cargo built-in target predicate 分离
- support-tier rejection
- security policy rejection
- Component own ceiling/lifecycle/provide/conditional subset validation and selected-dependency consumer effective-closure validation
- confinement ceiling requirement
- BindingKind validation
- Registry/OrderedMulti required_providers closure and rejection
- provider-selection-source facade co-selection, mismatch rejection and independent override prohibition
- scope dependency legality
- `subagent-in-process` 是唯一可声明 Agent-template → App `cap:agent-factory` self edge；其 consumer type必须是含 owner-scoped async allocator的 `ChildAgentFactoryBinding`，raw factory/AppHandle、缺 allocator binding及 job/workflow/其它 consumer一律拒绝
- `cap:agent-factory` 是唯一 deferred factory，App binding effect-free；每次 seal校验 exact owner/full draft/route并完成 request-specific template/authority projection，allocate只接受 sealed draft，create/resume只消费 fingerprint-bound capability；第二个 deferred capability、owner spoof、cross-owner token、intent-only allocation、跨 template fallback和未校验 route一律拒绝
- `cap:subagent` 每个 Registry entry必须由 generated adapter密封 current parent admission/provider identity并暴露 seal + nonce-bound volatile allocator；Durable Agent entry还必须绑定同一 Session writer lineage的 canonical durable reservation/recovery facade。Raw provider consumer、无 issuer/journal entry、用 lifecycle nonce表示 durable id或可公开构造 operation/draft/token一律拒绝
- Agent(AppParent)/Agent(SessionParent) mode availability
- every Agent route has exactly one generated request-journal mode；Durable route without the same Session scope's durable cap:session-log is unsatisfiable even when driver-direct itself has no direct SessionLog requirement
- generated-only issuer/verifier consumer restriction
- generated authority wiring is exact: `cap:model` gets only its paired model verifier, only the selected AgentDriver's resolved `cap:tool-executor` edge gets its paired tool verifier, and every other consumer gets `None`
- generated infrastructure owner allowlist/spoof rejection
- session-persistence admin consumer allowlist and session-read-store facade split；creation-mode property matrix固定 `durable+unsupported → Durable only`、`durable+staged-known-outcome → Durable+Ephemeral`、`ephemeral+staged-known-outcome → Ephemeral only`、`ephemeral+unsupported → neither`。NewEphemeral route还必须通过 staged-known-outcome commit、abort与 pre-commit query/index invisibility conformance，`durability=durable`不能替代该证明
- construction cycle detection
- deterministic ordering
- provenance completeness
- session event namespace/version/criticality/bound validation
- App-scope `app-coexistence` is required, shorter scopes reject it, the selected runtime adapter must use the same evidence schema, unknown is never concurrent, and aggregate handoff becomes `stop-old-app` if any selected App Component or adapter is `requires-stop`

### 46.2 Property Tests

随机 component graph 验证：

```text
all selected Required capabilities are satisfied
no explicit disabled component selected
no security-denied effect selected
every lifecycle/provide/conditional own effect is within its selected Component runtime ceiling
every resolved binding/consumer/Tool/Command effect is within its sealed selected-dependency effective ceiling
the sole deferred AgentFactory App binding has empty effects and every route plan equals its exact template closure within component_runtime_effects
selected runtime adapter exists, satisfies the full primitive union and has an empty schema-v1 runtime ceiling
final compiled runtime effects equal selected Component ceilings union empty runtime-adapter ceiling union selected Host boundary ceiling
every selected/direct root-package build requirement resolves to the correct BuildExecutionPolicy logical-id kind
every Durable Agent driver route reaches model only through a journal-proof plan backed by its parent SessionLog
every Durable model-origin tool route reaches ToolExecutor only through an exact committed ToolCall proof backed by that same SessionLog
aggregate app-handoff is concurrent iff every selected App Component and the runtime adapter have valid concurrent coexistence evidence
scope dependency graph legal
construction DAG acyclic
every Ephemeral route selects exactly one staged-known-outcome-conformant persistence provider
deterministic input => deterministic resolution
if bounded search reports SAT, result validates
decision budget exhaustion never reports UNSAT
```

对小图可用 brute-force oracle 对比自定义 resolver，验证 resolver 不因 greedy choice 错误报告 UNSAT。

### 46.3 Golden Tests

固定 profile 输出：

- normalized resolution
- provenance diagnostics
- deferred AgentFactory 的空 App binding、逐 creation-route template effect closure 与 plan digest
- per-creation-route request-journal mode；minimal replay generated source 与完整 deepseek HTTP/credentials chain fixture
- generated Cargo.toml
- generated composition.rs，包括独立 generated crate只经 runtime-api opaque assembly builder构造/记录 context/stamp且无 private-field shortcut
- composition manifest / build manifest schema
- security manifest
- RuntimeConfig / HostBindings / wasm export source，包括 model `default`/`explicit-per-request` 的互斥 schema
- Host Boundary Catalog and bin/library/wasm selection diagnostics
- synthetic discovery manifest 对 exact registry/git/path allowlist 可发现顶层 Component，忽略未 allowlist transitive metadata，并拒绝 source/checksum/precise/path escape 漂移

### 46.4 Compile Matrix

至少：

- minimal-pure linux
- minimal-remote linux
- cli-readonly linux
- cli-coding linux
- minimal-pure/minimal-remote on real Windows runner
- minimal-pure/minimal-remote on real macOS runner
- web-wasm wasm32 build + wasm-bindgen browser integration
- Experimental macOS/Windows sandbox compile plus real-target confinement regression；通过后才进入 Production matrix
- minimal-pure library 在 iOS/Android target 交叉编译；声明 Production 的 mobile Host provider 还必须在 simulator/device runner 通过 lifecycle/bridge tests。

矩阵中每个 production artifact 必须由当前 build Host 对应的 checked-in BuildExecutionPolicy 和已通过 escape suite 的 backend 生成；target triple 可以交叉编译，但 attestation 同时记录 build Host 与 target。没有 production backend 的 Host 只能运行 `--development-build`，不得产生发布矩阵证据。

### 46.5 Negative Dependency Tests

`minimal-pure` 禁止：

```text
reqwest
redb
hnsw
pdf
opentelemetry
MCP deps
process/sandbox deps
network-connector/http-client deps
AINS crates
```

`cli-readonly` 禁止：

```text
write-local provider
subprocess
shell
process sandbox
```

验证对象不是 feature list，而是：

```text
generated Cargo.toml
cargo metadata resolved graph
cargo tree
```

### 46.6 Binary/WASM Size Regression

CI 为每个 profile 提交 artifact byte baseline、absolute ceiling 和允许增长百分比；超过任一阈值必须审查并更新 baseline，不能自动接受 accidental heavy dependency leakage。

### 46.7 Ported Implementation Regression

迁移 AINS filesystem/sandbox/MCP/memory 时：

```text
copy black-box behavior/security test first
→ implement new provider boundary
→ run old/new behavior suite
```

避免“架构更干净但安全行为退化”。

### 46.8 Scope / Lifecycle Tests

必须覆盖：

- unpublished Agent setup failure 不可被 PublicationDirectory snapshot 观察；
- `before_publish` transaction view 同时包含配对 Session/Agent，普通 snapshot 仍为旧 generation；
- `before_publish` veto 不发布 entry/notification；unwind-capable fixture 对 before_publish/published/disposed 和 SessionObserver callback 的 success/error/panic/never-ready future 分别验证 bounded dispatcher ordering、per-callback timeout/cancellation 与 failure containment；选中任一需要 panic containment 的 in-process lifecycle/session observer 时，standalone 与 emitted-library fixture 在 `panic=abort` 及无 unwind target 上必须命中 generated compile/verification gate，未选 observer 的 composition 不伪造声明；
- lifecycle notification capacity 在 Durable commit 或 NewEphemeral publication 前预留，容量不足 fail closed；activation failure 原子删除完整配对并 enqueue 一次逆序 disposal batch，慢 listener 不阻塞 teardown；
- publication + gated activation + mode-specific authoritative genesis/Durable lifecycle terminal success 后 first request 才可进入 driver；
- provider initialize/activate failure reverse rollback；
- Agent(AppParent) 与 Agent(SessionParent) 的 optional Session binding 不串位；
- Sessionless 不构造 Session；Ephemeral 拒绝 resume，其 genesis 在 activation 成功前对 event/query/session index 不可见，activation/commit failure abort transaction 且 `list_sessions` 不留下 genesis-only entry；Durable 必须使用 durable persistence；
- owner teardown drains children；
- idempotent concurrent shutdown；
- targeted cancel 在 idle、queued-only、已 terminal、foreign/stale lifecycle 时不影响下一请求；active request 的 first cause 获胜，abort terminal durable convergence 前后进入的 send 保持 queued，且 shutdown 单独关闭全部 queued waiter；
- event feed 的 subscriber registration 与 baseline/high-water 捕获没有 query→subscribe gap；单 feed event/byte cap 溢出只产生一次 `Lagged` 并关闭；反复 open/reconnect 同时命中 Agent 级 subscriber-count、aggregate-events、aggregate-bytes admission ceiling，超限在 ring 分配前拒绝且 publisher traversal 有界，close/drop/idle-expiry 恰好释放一次 reservation；Durable caller 可由 read-only SessionQueryHandle 重建后续接，Sessionless 返回不可恢复 gap，shutdown 只产生一次 `Closed`；
- native 与 WASM pull feed 对 cursor、provisional/committed、Lagged/Closed 和 query pagination 具有相同 ABI 语义，且 slow UI 不阻塞 Agent/Session writer；
- `SessionQueryHandle::list_sessions` 只能经 `SessionReadStore::list_sessions_page`：items/bytes 双上限、稳定 order、captured index high-water、跨页 snapshot、expired/wrong-backend cursor error 均验证；JSONL session-list checkpoint 删除/超前/损坏后从 authority journal 重建且正常查询不扫描 session directories。Mixed-composition store fixture中，summary/header/genesis携带并交叉验证composition/catalog/schema identity，list把foreign Session标为`IncompatibleComposition`，`read_events/read_projection`在解码extension前返回同名结构化错误而不是`CorruptStore`；只有声明current exact identity后出现unknown/mismatch event或identity索引矛盾才算corruption，catalog-known non-reconstructing Informational event可跳过，缺少Required reducer返回`UnsupportedProjectionEvent`；
- model registry 单 provider 省略配置得到唯一 default；多 provider 缺 mode 初始化失败，valid default/explicit-per-request 均可初始化；explicit mode 的 `ConfiguredDefault` 在 journal/provider 前返回 `ModelRouteRequired`，有效/未知/被 authority projection 删除的 explicit key 分别成功/失败且 actual route 进入 `RequestPrepared`；
- `concurrent-independent` fixture 对 identical/different/boundary Config pair 可同时打开两个真实 App resource instance，selected runtime adapter 也以 two-bundle fixture 证明同一声明；`concurrent-shared-host-handle` fixture 强制同一私有 typed Host handle identity且不重复 open；Redb/file-lock/port/global-runtime Component/adapter fixture 汇总为 `stop-old-app` 并拒绝预构造新 App；
- async/fallible lifecycle-operation seal/allocator对两个并发same-composition App、多个process与restart使用同一StoreIdentity/issuer generation/counter。Durable caller在seal前持久化never-reused recovery key + canonical draft；完整draft完成request-specific projection后，首次allocation原子写key-index与含request fingerprint/projected authority+plan identity的Reserved。Projection/bootstrap failure时persistence allocation mock为零；collision/counter exhaustion/corrupt issuer/store error都不构造request。逐点模拟commit成功但response丢失、return后Host尚未补写id即崩溃、并发same-key retry：重新sealpre-journaled draft并same-key allocate总是取回原id且counter只增加一次；different payload/owner/composition复用key冲突，different key不别名；wrong-store token/key与未先分配新StoreIdentity的writable snapshot/fork被拒绝，volatile operation不能序列化或跨process进入locator；
- 在Durable allocation key-index/reservation commit后、genesis/`AgentResumePrepared`前逐crash：尚无id的cold retry以same key +重新sealed exact draft取回id，已有id则recover同一capability；NewDurable proposed SessionId始终由该id得到同一reservation值。改动attenuation、mode、resume SessionId、owner lineage、template route、namespace commitment、composition或catalog，或尝试给同key/NewDurable换proposed SessionId，均返回conflict且reservation bytes保持不变，不能重新绑定或进入construction。Allocation/locator response unknown分别保持fail closed并只重试原key/id；
- same-composition live reconfiguration在旧Agent持lease时先resume必须得到`WriterConflict`；concurrent mode由prebuilt new App先pre-journal recovery key/draft、seal完整draft、await same-key fingerprint-bearing reservation并补写id/fingerprint后关闭旧admission，stop-old mode则先shutdown old Agent/App、build new App，再由该new App执行相同流程；两者都在resume调用前完成Host journal，等待confirmed lease release后resume。Allocation unknown/process loss只重试same key取回id，release unknown不允许新owner抢占，resume已开始后的crash仅以same id、exact resealed fingerprint和更高fencing generation恢复；
- Agent create/resume 的 same operation id/same fingerprint 并发重试只发布一个 scope/result，不同 fingerprint 拒绝，durable commit unknown 只按原 id 解析且不换 id 重建；
- NewDurable 在 Host 尚未获得 SessionId 的每个 crash point 都能凭 persistent operation id定位 exact Reserved/Session genesis/terminal；Absent/Reserved/Located/CommitStatusUnknown不混淆，reservation intent/request fingerprint/projected authority+plan/store/composition/catalog与 locator/canonical log不一致时拒绝恢复；
- NewDurable create 的 genesis/AgentCreationCompleted/SessionEnded(CreationFailed) 使用稳定 batch id 且 terminal 互斥；Completed 前 admission 关闭，genesis-only cold recovery 固定关闭为 InterruptedBeforeAdmission，CreationFailed retry 返回 exact `CreationOperationFailed` 且不重跑 construction，成功但尚无首个 turn 的 Session 不被误判失败；
- background task 不泄漏；
- Agent-scoped Tool/Prompt 不串到其它 Agent；
- ConfinementAuthority 跨 Agent/spec 伪造与 ceiling widening 全部被拒绝；
- App root/parent/child authority 只能取交集；binding、Registry key、OrderedMulti contributor、optional Singleton、Tool/Command registration 与 budget 的 widening 全部在任何新 Session/Agent-scoped provider initialize 前拒绝；被 projection prune 的 Component 不 initialize，Required binding 被删时创建失败，Durable resume 不恢复历史未授予 route；App lifecycle effect 只由 root authority 承担，child deny 删除 stamped App binding 但不声称撤销共享 provider 的历史/其它 owner effect；
- resource-namespace fixture 必须覆盖 filesystem-only Durable profile（不含 subprocess/sandbox）：normalizer 派生 exact `cap:resource-namespace-bootstrap` edge，`cli-readonly`/`cli-coding` positive resolution与 cargo tree均包含唯一 `resource-namespace-bootstrap-local` package/key，删除该 catalog entry、错 key或 target不兼容时在 Cargo前 unsatisfied；该普通 App Component声明 `read-local` effects/security并满足 empty lifecycle/stateless/zero-dependency 构造约束，mandatory infrastructure source/dependency lint证明无直接 locator I/O。RuntimeConfig root deny、child attenuation删除 binding/key或 effect时 bootstrap mock调用数为零。保留 route时先完成 root/exact-template projection，再由 stamped binding异步 canonicalize root并返回 descriptor-relative anchor；symlink escape、preparation cancellation/failure不分配 identity且已准备 sibling全部释放。App namespace只准备一次，Session/Agent namespace逐 scope准备且由该 owner释放；workspace root A create后以相同 composition + root A resume成功，改成 root B、复用同 Host namespace id但改 locator、缺失 descriptor或伪造 consumer/bootstrap/provider identity均在 factory/initialize/publication前返回 `ResourceNamespaceChanged`；identity check后替换 path/symlink也不能越过原 anchor，实际 path/credential不进入 event bytes；
- local persistence namespace fixture对`session-persistence-jsonl/redb`的admin/read-store两个provide都要求exact `resource-namespace-bootstrap-local` marker、同一prepared descriptor/anchor和preparer ABI；任一marker缺失/为None、两个facade descriptor不同、factory/initialize按raw Config path打开或identity check后reopen都在store I/O前失败。Database path A初始化/恢复成功，改成B或symlink替换必须在StoreIdentity/open前返回`ResourceNamespaceChanged`，bootstrap deny时file-open mock为零；memory provider保持None，remote authority-bearing locator必须选对应audited bootstrap而不能继承local key；
- Durable resume 的 Prepared/Completed/Failed batch id 稳定且 terminal 互斥；Prepared 与更窄 authority epoch 同 batch，Completed durable commit 前 admission 保持关闭，activation/completion failure 产生 Failed；Prepared-only cold recovery 固定关闭为 InterruptedBeforeAdmission，Completed cold recovery 用 fencing generation 重建 incarnation，重建失败不改写既有 Completed terminal，任一 commit unknown 时保持未发布/关闭 admission；
- native HTTP在pre-resolution deny时不调用resolver；redirect/DNS rebinding/Happy-Eyeballs/proxy escape/remote-DNS proxy的每个logical intent、可观察actual hop、HTTPS handshake和首次/复用stream use都只能经过connector/policy授权，未显式授予`TrustedProxyResolution`时拒绝remote resolution。TLS fixture证明NetworkGrant不能读写handshake bytes，缺少/wrong-hop/expired `TlsHandshakeGrant`时client-hello计数为零，certificate/name/pin/ALPN mismatch不产生`ConnectedOutboundHop`，verified identity后才可取得dormant stream；HTTPS proxy TLS与tunnel内origin TLS分别取得不同hop/identity-bound handshake grant，wrong-stage/grant reuse在下一阶段首字节前拒绝；HTTP client compile graph不含TLS implementation。Compile-fail fixture证明dormant`AuthorizedStream`不能raw read/write/send/handshake；pool fixture证明同origin不同caller、policy expiry/change、proxy route change和每个H2 stream都会fresh authorize且one-use lease不能复用，底层自动checkout与cross-origin coalescing关闭；authenticated A→B redirect在B connector/request mock中观察不到Authorization/Proxy-Authorization/Cookie/custom-sensitive header，带非空body或非安全method的307/308在B DNS/checkout前拒绝，301/302/303只可得到empty GET/HEAD，same-origin replayability、HTTPS downgrade与destination-scoped explicit body reconstruction分别覆盖；
- plan-mode Durable append 的 Committed/NotCommitted/CommitStatusUnknown 三条路径分别验证原子 mode publish、保留旧 mode、关闭 admission 后读回解析；
- AgentHandle turn request 的 same fingerprint 并发重试只执行一次，冲突/过期/cold nonce 拒绝，process-loss unknown 不重放；
- command invocation 的同 fingerprint 并发重试只执行一次，caller/args 冲突、retention 过期和 cold-resume 旧 nonce 均拒绝。Durable crash matrix逐点覆盖Prepared commit前后、permit construction前后、DispatchPrepared commit前后、raw handler进入/返回后及terminal commit/response unknown：Prepared未confirmed时permit/handler/tool调用均为零，DispatchPrepared未confirmed时handler为零，Prepared-only cold recovery terminalize为`InterruptedBeforeDispatch`，DispatchPrepared-only为`OutcomeUnknown`，handler返回后只可按原terminal batch补提交/解析且永不重放；
- Durable UserInteraction matrix覆盖Asked commit前后、Host收集/稳定submission前后、Answered commit/response unknown、ack callback前/response loss/成功后、Acknowledged commit/response unknown与shutdown。Asked未confirmed时Host调用为零，same interaction/answer operation恢复只返回同一submission，Answered未confirmed时driver/model provider调用为零，只有`CommittedUserAnswer`可进入下一`RequestPrepared` history boundary。Crash在Answered committed但ack未完成时，resume projection必须在正常admission前重放same operation/fingerprint ack并补stable Acknowledged；crash在provider已ack但Ack event未commit时同一重放幂等；已有Acknowledged时ack调用为零。Pending backlog有hard ceiling且shutdown不能静默丢弃。`answer-recovery=unsupported`的provider在Durable template于Cargo前拒绝；raw`UserAnswer`插入、换id/换answer、丢失accepted submission、跳过ack reconciliation或ack后改写均fail closed；
- command classification fixture 必须证明 malformed/unknown/over-budget/over-ceiling args只触发 runtime-owned declarative policy evaluator，raw `Command` 的计数器、I/O mock和全局状态在 `CommandPermit` 生成前始终为零；policy schema拒绝 callback/function pointer并与相同 input得到相同 effect/exclusive-key结果；
- ToolCallPolicy/ToolRiskRule 的 struct-literal、字段 mutation、`Default` 与 derived-deserialize compile-fail；bounded builder在第 N+1 条 rule/predicate及 canonical byte/evaluator ceiling越界前拒绝且不保留输入，合法 accessor/registration/evaluation保持 canonical顺序，registration的 defense-in-depth revalidation不能成为首个 bounds gate；
- Subagent caller必须先经 exact parent/provider `SubagentProviderBinding` seal完整 operation。Volatile id固定 current `AgentLifecycleNonce`且parent teardown/cold resume后拒绝；Durable id固定 stable `(StoreIdentity, SessionId, AgentId)+provider+committed recovery key`且不含 nonce，在 raw provider前确认 Required reservation。同 key重试得到同 id，跨进程并发、commit response unknown与restart不能把 key/id绑定给另一 payload。Same-id retry复用一次 execution，cross-parent/provider、stale volatile、wrong durable lineage/recovery key、future/counter-wrap、caller forge和 conflicting payload均拒绝；
- Durable parent在 reservation、pre-effect `DispatchPrepared`及后续每个 state transition前后逐 crash恢复同一 `SubagentOperationId`/fingerprint/provider映射；新 lifecycle nonce不得导致 `OperationExpired`。Reserved-only可继续，DispatchPrepared-only只能query/safe-continue或OutcomeUnknown，不能盲目发送；NotCommitted零provider调用，CommitStatusUnknown只解析原 stable batch/id。Route/authority变化返回incompatible而不fallback。Active durable table有界，仍被Job/Workflow引用的entry不能按volatile retention过期；remote/process不可查询的unknown保持Paused而不重放；
- `subagent-in-process`对Sessionless/Ephemeral/Durable child都必须先经同一`ChildAgentFactoryBinding` seal完整child draft，再分配fingerprint-bound lifecycle operation并固定`SubagentOperationId → AllocatedAgentOperation/fingerprint`映射后create/resume；outer volatile映射只在current parent-lifecycle table，outer Durable映射经canonical StateChanged durable。Durable child在allocation前从committed parent lineage + SubagentOperationId + child slot确定并记录child `AgentOperationRecoveryKey`；selected store的Reserved原子包含该key与完整fingerprint。Allocator commit与outer mapping补写之间崩溃只以same child key/draft取回原id，allocation unknown/error、wrong owner/draft、same-key conflicting retry或different-key二次分配时construction/child provider零调用；
- durable Job/Workflow transition 在动作前 committed，cold recovery 只续接可查询的 stable operation id，非幂等 unknown 不重放；
- SessionObserver dispatcher 的 batch/byte queue 与每 callback/shutdown deadline 均命中 hard ceiling；append/resolve 在首次 confirmed commit 后只做一次 nonblocking enqueue/drop decision并立即返回 Committed，queue overflow 合并记录 exact dropped range且不阻塞/改变 append，slow/never-ready/error/panic observer 被 timeout/cancellation（及 unwind gate）隔离，单 worker不产生 per-batch detached task，shutdown deadline 后取消当前并丢弃剩余，unknown resolution/same-id retry不重复，cold resume不重放；
- CommandPermit、CommandToolGrant、ExecutionPermit 和 CodeExecutionPermit 在普通 Component/Host compile-fail fixture 中不可构造，borrowed command/nested tool session 无法逃逸 permit future 或进入 `'static` task。

### 46.9 Session Reconstructability Tests

对每个 durable model request：

```text
record live request
rebuild from SessionLog
assert semantically equivalent model-visible input
```

包括 tool schemas、prompt state、compaction、route/versioned ModelParams durable state，以及不存在仅指向 ephemeral Spill/Attachment 的 model-visible reference。

Canonical compaction tests 必须证明 `ConversationCompacted` 只有 generated durable journal facade 能构造，confirmed `Committed` 前不会生成引用它的 `RequestPrepared` 或调用 model provider，cold replay 从 event 的 replacement 与后续 events 得到相同 model history；unknown schema version、超过 256 KiB/16-depth、input boundary/history digest 不匹配全部拒绝，`compaction` Component 不能用 extension event 或 raw SessionLog append 代替 canonical event。

Canonical interaction tests必须证明后续model-visible answer只能来自confirmed`UserInteractionAnswered`与匹配的`CommittedUserAnswer` proof；live request和从Asked/Answered重建的history逐字节规范等价，Acknowledged不改变history。只有Asked、answer batch unknown、provider submission identity/fingerprint冲突或Answered/Closed双terminal时都不能产生下一`RequestPrepared`或调用model provider；Answered-without-Acknowledged仍可重建answer，但resume必须先完成ack reconciliation且不能重新present。

对 `driver-direct`、`driver-tools`、`driver-planner`、`driver-team` 的每个 Durable route 都必须验证：provider stream 观察次数在 `RequestPrepared` durable commit 前为零；Committed 后收到的 request digest/provider key/model id 与 proof 完全一致；NotCommitted 不调用，CommitStatusUnknown 关闭 admission，proof/request mismatch fail closed；Agent/Session/authority-pair 之间交叉使用 proof 全部拒绝。Compile-fail fixture 证明 driver/普通 Component 不能构造 `ModelCallContext`/`RequestJournalProof` 或从 model consumer binding 取得 raw `LanguageModel`；Sessionless volatile path 与 Session-owned caller 的独立 purpose 另有 positive fixture。

对每个含 tools 的 Durable driver route 还必须验证：`ToolCall` confirmed committed 前 provider、PermissionPolicy、Approval、middleware external hook 与 permit construction 的观察次数全部为零；Committed 后 exact Agent/Session/step/call/tool/snapshot/arguments/effects digest 才可进入 guarded executor；NotCommitted、CommitStatusUnknown、proof mismatch、cross-Agent/Session/authority reuse 均 fail closed。Compile-fail/source lint 证明 model-origin `ToolExecutionSession` 没有 raw `execute`，driver 不能构造 `ToolCallJournalProof`/`PreparedToolCall`，也不能把 Command/Nested borrowed session 转成 model-origin session。

扩展事件测试必须证明 selected producer 的 Required state 可重建、未知 producer/kind/version 或 criticality 不匹配会拒绝 load/resume/query、catalog-known Informational event 可由不关心它的 projection 跳过、query projection 遇到无 reducer的 catalog-known Required/reconstructing event 返回结构化 unsupported、composition hash 或 catalog digest 不匹配返回 `IncompatibleComposition`，且 oversized/deep payload 在 append 前拒绝。Authority epoch 测试还必须证明 resume 后的 `RequestPrepared` 可解析到 exact descriptor/digest，旧 request 继续使用旧 epoch，缺失/重复/倒退 epoch 或 digest 不匹配均拒绝重建。Canonical lifecycle-operation 测试必须拒绝 creation terminal-without-genesis、resume terminal-without-prepared、同 id 不同 fingerprint、重复/冲突 terminal 和 stale fencing generation；Completed cold reconstruction 只有 exact stored authority 仍被 current owner 覆盖时成功，更窄 current owner 必须返回 `AuthorityChangedForCompletedOperation` 并要求新 resume operation id。

### 46.10 Build Execution / Host Integration Tests

每个 production build backend 必须验证：

- selected Component、mandatory API/infrastructure、runtime adapter 与 Host entry/export root package 的 executable/read-input/environment build requirement 全部以可表示的 distinct root kind 命中 policy logical id；缺失、错 kind、未声明实际 dependency-family requirement 在 Cargo/build.rs 前拒绝；
- normalized metadata round-trip 必须保留 Component runtime primitive set、provide resource-namespace mode/bootstrap key、preparer/prepared-config paths与派生 exact bootstrap edge，以及 Host boundary targets/逐 target support/runtime-adapter allowlist与完整 RuntimeAdapterSpec；bin/library/wasm 分别验证 exactly-one-entry/no-boundary/exactly-one-export，三者都验证 exactly-one runtime adapter；adapter missing/multiple/constructor/primitive/target/support/empty-security/Host-boundary compatibility 任一不符在 Cargo 前以 `ResolutionError::InvalidRuntimeAdapter` 保留 adapter identity和 exact `RuntimeAdapterViolation`；Host boundary target/support/security 漏项、entry/export 混选或其 effect 未进入 final compiled union 时同样拒绝；`host-cli` 的 Linux production、macOS/Windows experimental和 iOS/Android/其它 OS target rejection由 golden/real-target fixture固定，non-WASM事实不能扩大 predicate；
- compose target-fact fixture 用两个 rustc/custom target spec产生不同 cfg；composition hash、target edge closure随 fact/spec digest变化，production policy rustc重算不一致时在 fetch/Cargo/build.rs 前返回 `TargetFactMismatch`，只相同 triple不能通过；
- discovery fixture 的 `[patch]`、`[replace]`、named registry、workspace/ancestor Cargo config在第一次 metadata前拒绝，ambient `CARGO_HOME` source replacement不可见；受支持 graph 的 discovery/lock/build必须逐字节复用 generated `cargo-resolution.json`/`.cargo/config.toml`，任一 source/config digest漂移在 Cargo前失败；production fetch fixture 证明 `cargo fetch --locked` 只可调用 exact pinned `rustc -vV` 与 ADR 0001固定的 Host/target information query，query argv/target/schema漂移、wrapper/codegen/source binary均被 runner拒绝，并且只使用 runtime-identity绑定的合成只读 `/dev/null` 而非 Host device；ADR 0002/schema-3 networked fetch还必须绑定 exact TLS CA、outer resolved origin/IP/port与合成hosts/NSS/host.conf/空resolv.conf输入，只允许到该集合的IPv4/IPv6 TCP connect，拒绝DNS/UDP/命名或抽象Unix/raw/netlink、bind/listen/accept、destination-bearing send及未声明endpoint；ADR 0004只允许fetch/planner沙箱进程树内部使用`AF_UNIX + SOCK_STREAM + protocol 0`及可选`CLOEXEC/NONBLOCK`的匿名socketpair作为pinned Cargo/libcurl唤醒通道；ADR 0005另只允许networked fetch为files-only NSS fallback创建同参数的未连接Unix stream socket，并把exact `/var/run/nscd/socket` connect模拟为`ENOENT`，其它Unix connect与socketpair参数仍拒绝；ADR 0006仅为production Cargo build命令额外允许`AF_UNIX + SOCK_SEQPACKET + SOCK_CLOEXEC + protocol 0`的匿名Rust spawn-error pair，且该pair class、命令与attestation绑定，fetch/planner和pipe-only credential helper均不得获得；redirect只可落到已声明actual endpoint且不再声称可观察TLS内same-origin redirect计数；credential provider必须是exact policy helper的bounded Cargo protocol pipe，无helper时禁用全部provider，credential bytes不可进入任何输出证据；
- build.rs 对 source/toolchain baseline 的读与 target/temp 的写不会污染 `compiled_runtime_effects`，而最终 binary runtime effects 也不会自动扩张 runner mount/execute 权限；
- 未声明 filesystem、workspace、home、socket/device 读取失败；
- 只有 target/temp/diagnostic roots 可写；
- build script 及 descendant 的 network 连接失败；
- 未 allowlist executable、wrapper、dynamic-loader escape 失败；
- ambient flags、proxy、credential 和非 allowlisted environment 不可见；
- declared toolchain/SDK/linker/code generator 可正常构建 fixture；
- environment requirement 只按 kebab-case role id 命中 exact `[[environment]] id → variable → value`；unknown/duplicate id、duplicate/invalid variable、reserved baseline/secret/proxy variable、ambient value substitution 全部在 build.rs 前拒绝，未 selected policy entry 不可见且 PATH/LANG/LC_ALL/SOURCE_DATE_EPOCH 始终使用 schema baseline；
- path-package fixture 的 build.rs 读取 mode/mtime/uid/inode 等 metadata 时只能观察 canonical snapshot view；pre 后修改 live source 的 chmod/mtime 不能改变 mounted closure 或 build behavior，修改 closure snapshot 的任一 bytes/metadata 则必须在 Cargo 前或产物接受前因 tree digest/view mismatch 失败；
- `BuildEnforcementIdentity` 中任一 logical input/content/version/environment/enforcement semantic 变化，或 normalized enforcement-result identity projection 变化都会改变 build-output digest；仅把相同 tool/input 移到另一 canonical Host path，或改变完整 policy 的 allowed executor/reviewer/signer/signing-helper trust mapping、enforcement evidence digest、signature、nonce、timestamp 或 transparency proof，不改变 build-output identity，但 full policy/attestation/envelope 必须按本次配置重新验证并作为新的 append-only attestation 保存，不能改写/碰撞原 artifact directory、build manifest 或 SBOM；
- 修改 `rust-agent-build.json` 的 `deployable`、effect/build-requirement accounting、artifact metadata 或任一其它 payload field 必须改变 `build-manifest-digest` 与 build-output identity；伪造两个自报 digest、目录名或 cache copy 均因重算不符被拒绝，signed attestation 必须同时绑定 composition/output/manifest digest；
- development artifact 固定 `deployable=false`，不能通过 production packaging gate；
- emitted library 被独立 Host Cargo graph通过唯一 alias编译；pre必须用 pinned Cargo planner分别产生 emitted standalone与 final Host的 `HostCargoUnitGraph`。ADR 0003/schema-2 planner只允许 exact policy-pinned Cargo 1.97.1在请求/attestation绑定的固定 `__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS=nightly` 下启用自身 unit-graph-v1 producer；该开关不可来自ambient或user role，planner不得执行build script/proc macro/codegen或改变output roots。缺少该受信 interface、开关/Cargo digest/argv/descendant/output漂移或退回单一 `cargo metadata --filter-platform`时 production失败；
- cross-compile fixture固定 build-host与 composition target不同：target unit只含 target predicate依赖，build-script/proc-macro及其 transitive unit按 build-host predicate进入；同一 external package同时作为 host build dependency和 target dependency时可得到不同 exact feature set，任一漏 unit、合并成 package-global feature或把 host feature批准沿用到 target unit都拒绝；
- reference executor在空 target/incremental root观察到的 rustc/build-script/proc-macro unit、features与 edges必须逐项匹配 pre final graph；预填充未证明 cache、planner/actual compilation kind、feature cfg、extern edge或 artifact linkage任一漂移使 build-host/post失败，package级 Cargo JSON/metadata摘要不能替代该证据；
- `emit-integration` 对不存在目标使用 verified sibling staging + single rename、相同 tree 幂等复用；不同的非空目标在没有 `--replace` 时拒绝，带 `--replace` 也只按 offline-maintenance contract 测试且不得宣称 portable atomic replacement，模拟中断后的 missing target 使 verify/build fail closed；live reader 场景必须改发 versioned directory；
- emitted library fixture 在非 Tokio Host executor 上只通过 emitted alias 的 `create_runtime_primitives` 显式注入 target-compatible `RuntimePrimitives`，含 timer/spawn/executor-bound I/O 的 Component 正常运行并由 App shutdown drain；第二份 active-workspace adapter/type、缺少/错 target primitive、直接使用 ambient Tokio context、提前失效的 driver lease 和 detached task 均返回结构化失败而非 panic；bin main/wasm start fixture 证明 generated root 把 selected snapshot constructor传给不依赖 concrete adapter 的 Host entry/export ABI，constructor error 分别映射为 Host error，identity-matching native/browser bundle最终传入 build；
- emitted first-party Host/Target unit的feature addition始终拒绝；external shared Host unit的任何非空delta返回`HostBuildUnitDeltaUnsupported`，Target delta触达custom build/proc macro/generated/native/link output也拒绝。其余external shared Target-library delta在无exact selector policy、unknown feature、额外unit/edge/effect/build requirement漏报时拒绝；`composition-conservative`把全部可能delta effect纳入composition path，`host-only-additive-api`缺少exact source-semantics evidence、trusted reviewer policy或product-Host-only requester provenance时拒绝。Fixture还必须证明产品自有build unit注入的cfg/code/token/link行为进入Host-root runtime ceiling和post`product_compiled_runtime_effects`，不能只计build requirements；
- HostFeatureUnionPolicy digest在 pre/build-host/post完全相同，standalone/final/observed unit-graph digest、实际逐-unit feature/delta provenance、host feature effects与 product final runtime-effect union写入 product attestation；
- emitted tree mutation、错误 hash/ref、错误 alias、development-only composition 被 production `verify-integration` 拒绝；
- 同一 Host lock 中的 integration-id/digest-prefix/generated package identity 碰撞被拒绝；
- pre receipt之后 HostBuildInputClosure的 package file、manifest、lock、`.cargo/config.toml`、artifact selector、build-host/target/planner identity、package resolution或任一 unit graph变化使 build-host/post verification失败，闭包外 ancestor Cargo config不可见；
- pre/build-host/post 的 BuildExecutionPolicy 以及存在 delta 时的 HostFeatureUnionPolicy digest 必须分别一致，未 allowlist executor/backend/signer 的外部产品 attestation 被拒绝；
- post verification 拒绝缺失/错误 target artifact，并把 artifact digest 写入 product integration attestation；
- Host callback `host-api` public type closure 含 workspace-local concrete/private associated type 时 generated Host consumer compile fixture 失败，完整 namespaced Config/trait/DTO re-export 与 callback trait object 时通过；
- framework-neutral topology fixtures 分别覆盖同进程 Native Rust Host、同一 Rust WASM module、JavaScript/`wasm-bindgen` Host、Native backend + WebView/frontend IPC；前三者验证 build-kind/ABI/type identity，IPC mock 还验证 command/channel 映射不暴露 runtime internal type；
- JavaScript WASM fixture 必须证明 `host-wasm` 的 `wasm-bindgen-cli` executable requirement缺失、错 kind、digest/version/protocol不兼容或从 ambient PATH替换时在 post-link 前拒绝；成功产物含可实际调用 `WasmAppHandle` 的 transformed WASM/JS bundle，全部 generated JS/WASM/declaration/snippet bytes及 raw-input/postprocessor identity进入 manifest、SBOM 与 build-output digest，raw Cargo cdylib单独不能通过 packaging gate；
- composition profile/build config 中出现 framework identity、framework-branded Capability 或 generated rust-agent framework feature 时按 unknown input 拒绝；产品 Host 自有 framework feature 只作为最终 Host graph/feature-delta 接受审计；仅改变产品示例/framework 名称而 target、environment、Component 与 Host topology 不变时，resolution 与 composition hash 不变；
- product adapter contract suite 必须证明 exact `AgentRequestId`、targeted cancel、cursor/high-water、`Lagged`/`Closed`、bounded backpressure 与 shutdown 在 direct handle、WASM export 和 IPC mapping 上语义一致；slow/closed frontend 不得阻塞或重新打开 Agent writer；
- 具体 framework/version 的正式支持条目只有在对应 Integrator/product 仓库的 checked-in adapter fixture、真实 target CI 与匹配 product integration attestation 同时存在时通过；文档示例不能单独提升 support tier。

## 47. CI Quality Gates

必须有：

```text
cargo fmt --check
cargo clippy --workspace --all-targets
cargo test --workspace

component metadata validation
resolver unit/property/bruteforce-oracle tests
resolver golden tests
composition deterministic hash test
BuildExecutionPolicy normalization test
BuildEnforcementIdentity path/trust projection and attestation-rotation test
Host-linker rustc flag/helper-selection observation test
Cargo resolution-context normalization/rejection test
target-fact/spec reproduction test
HostFeatureUnionPolicy normalization/delta-closure test
Host feature semantics evidence/attribution test
Host Cargo host/target unit-graph planning/observation tests
production build sandbox escape tests
emitted library Host integration tests
explicit RuntimePrimitives/non-ambient-executor tests
framework-neutral Host topology contract tests

compile matrix
generated manifest freshness/golden checks
dependency negative tests
API crate DAG/public-type-closure cycle tests
cargo-deny / advisory audit
license audit
binary/WASM size regression
WASM build
wasm-bindgen bundle/output-digest test
security provider tests
scope/lifecycle tests
authority-projected resource-namespace bootstrap binding/anchor tests
targeted cancel and bounded Host event/query tests
bounded SessionObserver dispatcher/overflow/timeout/shutdown tests
persistent lifecycle-operation issuer/reservation/restart tests
volatile-lifecycle and durable-lineage SubagentOperationId issuer/recovery tests
ChildAgentFactoryBinding lifecycle-allocation tests
aggregate Agent event-feed admission budget tests
App coexistence/handoff mode tests
ported AINS regression tests
session reconstructability tests
Durable model-origin ToolCall journal-gate tests
generated SessionEventCatalog compatibility tests
```

### Architecture lint

增加自动检查：

- capability consumer crate 不得 import concrete provider crate；
- core/API crate 不得依赖 provider/host/product crate；
- lifecycle operation intent、opaque reservation DTO与 allocation error 的唯一定义 owner是 `rust-agent-runtime-api`；`rust-agent-agent` 只可 re-export，`rust-agent-session` 必须直接依赖 runtime-api且在 normal/development/all-feature graph均不得依赖 agent。CI 递归检查 `SessionPersistenceAdmin` public type closure并固定 `agent → session → runtime-api → core` 无环；Phase 2必须先独立编译lightweight session API，再编译其agent consumer，不能把所需error/query DTO推迟到Phase 3/5；
- subagent provider/binding/domain draft与 `ChildAgentFactoryBinding`归 `rust-agent-extension-api`，允许 `extension-api → agent`以包装 public factory contract；仅 canonical Session event需要的 durable operation identity/record DTO归 `rust-agent-runtime-api`且不包含 provider trait/domain payload。`rust-agent-session`只引用该 lower-level record，`rust-agent-agent`的 normal/development/all-feature graph不得反向依赖 extension-api；
- core/API/Component crate 不得依赖 UI/application framework；framework identity 不得成为 Capability、Component、resolver fact、generated rust-agent Cargo feature 或 composition identity input；
- Component/API package 不得依赖 Host boundary 或 concrete runtime-adapter package，Host boundary package 也不得依赖 concrete runtime adapter；Host entry/export 只能作为与 build kind 匹配的 generated direct root，library graph 中不得出现 Host boundary package；selected runtime adapter 则对所有 build kind 只能作为 generated direct root并保持 empty runtime ceiling，bin/wasm 的唯一 constructor edge 由 generated root 以 typed ABI 传给 Host boundary；
- generated runtime artifact closure 内的 mandatory API/infrastructure不得直接实现 filesystem/network/process/credential/persistence/Host-callback effect，也不得引入 effectful transport/FFI dependency；namespace context只可经 authority-projected `cap:resource-namespace-bootstrap` stamped binding调用普通 Component，选择 `fs-read-local`/`fs-local`必须把 exact `resource-namespace-bootstrap-local` package/provider key纳入 resolution与 Cargo closure，缺包/错 key/target不兼容均在 Cargo前 unsatisfied；AppHandle/ChildAgentFactoryBinding必须在 seal阶段完成 request-specific projection，durable allocation只可把 opaque完整 reservation交给 selected persistence binding，所有外部操作均归入对应 Component effect closure；
- `cap:subagent` consumer只能取得 generated `SubagentProviderBinding`并经 exact parent/provider seal后取得字段私有的 allocated request，不能取得 raw provider。Volatile issuer必须包含 lifecycle nonce且不可恢复；Durable issuer必须来自同一 Session canonical journal、稳定 parent lineage且不得包含 nonce，Sessionless/Ephemeral binding不可调用 durable reservation。`subagent-in-process`的 sole self edge只能取得 `ChildAgentFactoryBinding`，其 seal/allocate/recover/create/resume必须验证同一 parent owner stamp且不能导出 raw AgentFactory/AppHandle。Compile-fail/source lint固定 caller forge、cross-owner token、public construction/mutation of subagent draft/`DurableSubagentRecoveryKey`/sealed/allocated request、intent-only durable allocation、missing-allocator self binding与第二个 factory consumer均不可达；独立Host通过`rust-agent-core` checked bytes构造/重建 inert `AgentOperationRecoveryKey`是必须通过的positive fixture，但invalid version/encoding、struct literal、field mutation、把key当operation id或跳过pre-journal/seal都拒绝；
- `ToolRegistration` handler access、`RegisteredTool` constructor/handler access、`ExecutionPermit` constructor、private registry 与 guarded builder 仅存在于 `rust-agent-tools` 同一 crate privacy boundary；`tool-executor-guarded` 只 re-export `rust_agent_tools::guarded_component::{build, Config, Dependencies}`，依赖方向无反向边，compile-pass fixture 证明薄 wrapper 可装配、compile-fail fixture 证明普通 consumer/Component 无法 raw dispatch；
- `ToolCallPolicy`/`ToolRiskRule` 及其 bounded builder storage字段私有；普通 Component 的 struct literal、unbounded collection conversion、field mutation、Default/serde bypass必须 compile-fail，所有构造/自定义 decode只走 count/byte/evaluator-budget checked builder；
- `CodeExecutionPermit` 只能从当前 Tool body 借用的 `ExecutionPermit` 派生，普通 Component/Host compile-fail；
- `CommandRegistration` handler access、`RegisteredCommand` constructor/handler access、`CommandPermit` constructor 和 raw lookup 只存在于 rust-agent-commands adapter/CommandDispatcher；AgentHandle 只能委托其公开 dispatch；`Command` trait 不得包含 definition/effect-classifier callback，per-request permit 前只能解释封闭、无 callback 的 `CommandEffectPolicy` 数据并确认exact `CommandInvocationPrepared`，raw handler前还必须确认matching `CommandInvocationDispatchPrepared`；commands crate只依赖runtime-api-owned journal gate/DTO，不依赖session；
- `BorrowedToolExecutionSession` 对 authority 使用 invariant lifetime 且不可 Clone，command/nested compile-fail fixture 证明其不能越过 `CommandToolGrant`/`ExecutionPermit`；
- model-origin `ToolExecutionSession` 不导出 raw `execute`；`PreparedToolCall`/tool journal proof 不可由 driver/Component构造，API-owned `BindingAssembly::bind_consumer`只能在 selected AgentDriver 的 exact Agent-template `cap:tool-executor` edge的内部 context自动安装 paired `ToolCallJournalVerifier`并原子返回已记录 envelope，generated代码无 verifier参数/context constructor/raw record API，且 `plan_call`只解释 sealed declarative ToolCallPolicy、不能调用 raw Tool/Component callback；
- `cap:session-persistence` admin binding只允许generated Agent/Session factory与`session-log-events`消费；`cap:session-read-store`必须从同一selected persistence Component派生且不可独立override；`session-query-events`/Integrator只能取得`SessionReadStore`，compile-fail fixture证明read facade无prepare/append/writer-lease/locator mutation。Summary/header/genesis必须携带并核对per-Session composition/catalog/schema identity，foreign identity在extension decode前映射为`IncompatibleComposition`而非corruption。Normalizer/golden必须拒绝persistence provide缺少`ephemeral-creation`；local path-backed durable provider的admin/read两个provide任一缺required local namespace marker/preparer、marker不一致或factory重新打开raw path也必须拒绝，durable-only示例固定为`unsupported`。NewEphemeral provider conformance必须证明prepared genesis可abort、commit只有Committed/NotCommitted known outcome且commit前read facade的event/index/high-water完全不变；
- `cap:user-interaction` provide缺少required`answer-recovery`必须由normalizer拒绝；只有合法Agent-scope consumer edge由BindingAssembly自动取得current-Agent`UserInteractionJournalFacade`，App/Session consumer或generated caller手工传facade均拒绝。Durable route只组装`stable-until-commit-ack` provider与generated journal facade，driver不能取得raw provider/UserAnswer，Asked/Answered/Acknowledged proof或id的public构造、same-id换answer、Answered commit前model use、Answered-without-Acknowledged recovery跳过ack均compile-fail或在callback前fail closed；
- AgentHandle/PublicationDirectory/WASM wrapper 不暴露 raw `Arc<dyn Agent>`，Host send/targeted-cancel/event-feed/query 只能走 handle admission/read-only public projection；
- PublicationDirectory 只能由 generated factory transaction 写入，Component 只能提供 typed LifecycleObserver；
- host-source 必须声明可整体 re-export 的 `host-api` module，其 Config/trait/DTO public type closure 不得暴露 Integrator path-local concrete/private associated type；
- emitted integration 的 Host alias、tree digest、composition hash 和 Host Cargo.lock 必须一致，production Host artifact 必须具有匹配的 pre/post receipt 与 product executor attestation；
- emitted first-party的每个 Host/Target Cargo unit及external shared Host unit feature/edge set必须与standalone unit graph exact；schema v1只允许HostFeatureUnionPolicy按exact Target-library unit selector审批不触达custom-build/proc-macro/generated/native/link output的additive delta，任何Host-unit delta都返回`HostBuildUnitDeltaUnsupported`。Pre必须分别规划 build-host/target unit，executor必须观测同一实际 graph；package级 metadata、遗漏 build-dependency/proc-macro host unit、跨 compilation-kind复用批准或实际 unit/edge/effect/build-requirement closure与 policy/attestation不一致时 fail closed；产品自有Host build unit的执行effects进入build requirements，其注入artifact的cfg/code/token/native/link downstream runtime contribution必须归入Host-root ceiling和`product_compiled_runtime_effects`；
- production build 必须具有通过 backend escape suite 的 BuildExecutionPolicy/attestation；
- standalone discovery/lock/build 只能使用 hashed schema-owned Cargo resolution config和 isolated Cargo home；target-dependent graph必须绑定并在 policy rustc上复现 canonical target-fact/custom-spec digest；
- AINS dependency forbidden；
- provider metadata 的 Component runtime ceiling、lifecycle effects 与每个 provide effects 均 required；Host boundary runtime ceiling 必须进入 artifact union 且不得进入 AgentAuthority；所有 generated direct first-party root package 的 build requirements required，binding stamp/effective closure 必须一致，build requirement union 必须由 BuildExecutionPolicy 按 logical-id kind 满足且不得进入 AgentAuthority；
- native DNS/socket/proxy/TLS依赖只允许在`network-connector-native`，HTTP framing/client依赖只允许在`http-client-native`；后者不得拥有TLS handshake/raw socket或链接TLS implementation；
- native connector必须在resolver/DNS side effect前取得ResolutionGrant、每个actual socket/proxy hop前消费NetworkGrant、HTTPS handshake bytes前消费exact hop/SNI/ALPN/trust-bound `TlsHandshakeGrant`，并在首次request及每次keep-alive/H2/H3 checkout写出application bytes前消费绑定exact caller/origin/proxy/verified-TLS-identity/connection的fresh NetworkUseGrant；pre-TLS state与`AuthorizedStream`都不得暴露raw I/O，只有handshake codec lease或one-use`AuthorizedStreamUse`可在各自阶段读写，底层自动checkout和cross-origin coalescing必须关闭；
- one Component id ↔ one Cargo package；
- factory/config/dependencies 与 capability binding-adapter ABI generated compile fixture；
- model consumer binding 不暴露 raw provider，`ModelCallContext`/`RequestJournalProof` 不可由 driver/普通 Component 构造；每个 generated Agent route 安装唯一 journal facade，Durable route 必须来自同一 Session scope 的 durable SessionLog；
- 独立 generated-composition compile-pass fixture只能经 runtime-api `begin_composition_assembly → begin_binding_assembly → bind_provider/bind_consumer → finish`组装 App/Session/Agent scope；API/Component/Host compile-fail fixture证明 `BindingAssemblyOwner`、scope builder、context、requirement identity、stamp及 `Assembled*Binding` receipt均不可 struct-literal/Deserialize/按 tag构造或由 raw binding转换，generated代码也没有 context issuance、手工 publisher/verifier/call-authority或 raw `record_*` API。自定义 witness trait impl、包装 clone stamp、复制 manifest/plan、调用 fresh root issuance或跨 root/scope重放 envelope均不能加入 active assembly；替换 dispatch shim、伪报相同ABI label、错 adapter/type/digest/edge/order、缺失/额外/重复 identity、未 finish或 drop transaction分别由 plan/runtime type检查与 generated-source/build attestation在 install/initialize前拒绝；
- generated `BindingProviderContext`/`BindingConsumerContext`、sealed Component/generated-infrastructure owner identity、per-provide effect stamp、按 requirement field排序的 actual dependency binding identities与 resolution plan一致；缺失/额外/伪造 dependency identity在 fixed adapter调用前拒绝，type/stamp/receipt不一致在 `bind_*`返回前拒绝，Tool/Command dynamic snapshot密封同一 identities；用户 metadata不能伪造 `GeneratedInfrastructureId`，Tool/Command adapter拒绝非 Component owner，dynamic effects不超过 sealed effective ceiling；
- 只有 `GeneratedInfrastructure(generated-agent-scope-factory)` 可提供 deferred factory：其 App binding effect stamp 固定为空，而每条 create/resume route 必须在 identity allocation/scoped initialization 前以 exact template closure 完成 authority projection；普通 metadata、第二个 deferred capability、跨 template fallback 与漏校验 route fail closed；
- AgentAuthority projection 只能删除 compiled binding/key/contributor/registration，不能 fallback、增加或 initialize 已 prune Component；
- generated composition 只引用 selected component；
- generated direct dependency 与 resolution 完全一致。

### Supply-chain gate

高风险 provider 独立审计：

- network/TLS dependencies；
- process/FFI dependencies；
- parser dependencies；
- credential/crypto dependencies。

`minimal-pure` 应成为依赖泄漏的 canary profile。

## 48. SemVer / API Policy

稳定层级：

- core DTO / Capability trait、binding-type 与 binding-adapter ABI：严格 SemVer
- Host entry、WASM JS 与 stored event/envelope schema：显式 version + 兼容性测试
- BuildExecutionPolicy、sandbox attestation 与 emitted integration schema：显式 version + fail-closed reader
- PublicationDirectory snapshot、LifecycleObserver、Command/PlanMode、UserInteraction journal/ack 与 execution permit contract：严格 SemVer
- provider implementation：正常 SemVer
- component/composition/build manifest metadata schema：版本化
- generated internals：不承诺 API
- experimental：明确 feature/namespace

第一版 durable resume 的稳定契约是 exact composition hash + exact generated `SessionEventCatalog` digest；这两者任一变化都返回 `IncompatibleComposition`，不属于 SemVer reader 自动兼容范围。未来的跨 composition/schema 演进必须由独立、版本化、离线 migration/import 工具读取旧格式、生成新 genesis 并保留 provenance，不能在 live `resume` 中加入启发式映射。

不要公开 concrete driver internal structs 作为稳定 API。

---

## 49. Implementation Phases

### Phase 0 — 独立仓库与 Architecture Contract

创建 workspace、CI、deny rules、MSRV、target matrix、ADR template/decision index、无环 API crate DAG（含 runtime-api-owned shared lifecycle DTO/error）、Capability/Component/Host-boundary metadata schema（含分离的 Component/Host runtime ceiling、build requirements、resource namespace 与 App coexistence）、factory/Host entry/WASM export helper ABI、targeted cancel/event-feed/query DTO、canonical target-fact/Cargo-resolution record、BuildExecutionPolicy 与 HostFeatureUnionPolicy/source-semantics-evidence schema/backend contract，以及 compile-fail architecture fixtures。

验收：

```text
[P0-AC-01] no AINS dependency
[P0-AC-02] core/API dependency policy enforced
[P0-AC-03] session public API closure contains no rust-agent-agent type/dependency
[P0-AC-04] metadata/schema versions and canonical encodings frozen by golden tests
[P0-AC-05] unknown metadata, missing lifecycle/provide effects and invalid target facts fail closed
[P0-AC-06] App scope missing app-coexistence and shorter scope declaring it fail closed
[P0-AC-07] bin/library/wasm Host boundary cardinality, target, support and security accounting fail closed
[P0-AC-08] host-cli accepts only its declared desktop OS set; iOS/Android/other native targets fail before Cargo
[P0-AC-09] Host topology 由 process/module/ABI/target 决定；framework identity 作为 composition schema/resolver/generated-feature 输入 fail closed
[P0-AC-10] generated runtime API/infrastructure direct-effect lint and dependency gate fail closed
[P0-AC-11] runtime effects never contain build-only requirements; requirement/policy kind mismatch fails closed
[P0-AC-12] CI maps every implemented architecture invariant to a named test or lint
```

### Phase 1A — Composition Compiler / Generated Graph Proof

先实现：

- rust-agent-core / rust-agent-runtime-api 的最小 ID、error、lifecycle contract；
- 仅供 compiler proof 使用的 fixture capability/factory API；
- component metadata schema
- Host Boundary Catalog 与 bin/library/wasm normalization
- catalog normalization
- BindingKind / ScopeKind model
- deterministic resolver
- bounded backtracking
- provenance diagnostics
- generated Cargo.toml
- isolated Cargo resolution-context gate与 generated `cargo-resolution.json`/`.cargo/config.toml`
- canonical target-fact/custom-spec snapshot与 composition identity
- generated composition crate
- composition/security manifest
- locked development build executor（只产生 `deployable=false` artifact）
- CLI `compose`、`build --development-build`、`inspect`、`emit-integration`、`verify-integration --allow-development`
- independent Host compile fixture 与 development-only integration verification
- framework-neutral Native Rust、same-module Rust WASM、JavaScript WASM 与 WebView IPC mock topology fixtures
- controlled-policy wasm-bindgen post-link bundle packaging
- first-party exact feature 与 external shared-dependency additive feature-delta fixtures

使用 `tests/fixtures/components/` 中无产品语义的 `fixture-model`、`fixture-driver`、`fixture-fs-read` 证明两个 composition：

```text
fixture-model + fixture-driver
fixture-model + fixture-driver + fixture-fs-read
```

验收：

- [P1A-AC-01] Generated factory call通过 Rust类型检查，且 `cargo metadata/cargo tree`真实出现/消失 `fixture-fs-read` package，不能以代码 cfg 掉代替。
- [P1A-AC-02] Library fixture由独立 Host Cargo graph经 emitted path dependency编译，并通过 duplicate API类型身份 negative test。
- [P1A-AC-03] Host为 emitted first-party fixture的任一 unit增加 feature必须失败；synthetic external shared unit只有 exact unit-selector development HostFeatureUnionPolicy delta可通过。
- [P1A-AC-04] Synthetic Host entry/export fixtures固定 bin/library/wasm的 boundary cardinality、target rejection与 Component/Host/final runtime-effect union。
- [P1A-AC-05] Direct Rust、same-module WASM、JS export与 WebView IPC mock四类 framework-neutral topology fixture固定 contract，且不依赖真实 UI framework。
- [P1A-AC-06] Independent/shared-host/requires-stop App fixtures固定 aggregate handoff manifest，任一 unknown/exclusive resource都降为 `stop-old-app`。
- [P1A-AC-07] Development artifact/receipt固定 `deployable=false`，不能被 production inspection接受。
- [P1A-AC-08] Phase 1A generated composition只依赖最小 core/runtime contract与 `tests/fixtures/` API，不引用尚未实现的产品 Component、Model、Agent或 Driver API。
- [P1A-AC-09] Fixture Component/Host boundary显式声明空 build requirements；controlled-policy fixture只在 development policy下命中 synthetic executable/read-input logical id，且 requirement/policy resolution与 runtime `compiled_runtime_effects`完全独立。
- [P1A-AC-10] Checked-in custom-target spec必须以真实 pinned Rust/Cargo 1.97.1完成 compose、Cargo.lock生成与 locked offline development build；fake rustc/Cargo只能作为 failure-path补充证据。

Phase 1A 没有通过前，不进入几十个 capability 的大规模实现。

### Phase 1B — Linux Reference Production Build Track

Phase 1B 在 Phase 1A 接口稳定后开始，可以与 Phase 2/3 runtime spine 并行；它不是开始实现 minimal runtime 的前置条件，但在任何 artifact 标记 `deployable=true`、第一版 release packaging 或 AINS production cutover 前必须完成。

先只实现并承诺 checked-in Linux reference runner：

- BuildExecutionPolicy normalization；
- pinned Cargo host/target unit-graph planner、规范化 `HostCargoUnitGraph`与受控 rustc/Cargo unit observer；
- HostFeatureUnionPolicy normalization、逐 Cargo unit的真实 feature/dependency-edge delta closure、`composition-conservative` accounting与 `host-only-additive-api` source-semantics evidence/reviewer-policy verification；
- isolated fetch runner、locked source/checksum/git revision verification；
- Linux namespace/Landlock/seccomp 或等强度 backend；
- descendant filesystem/network/executable escape suite；
- toolchain/SDK/read-input/executable identity；
- target-fact/custom-spec preflight reproduction与 canonical Cargo config enforcement；
- schema-selected Host linker execution关闭 implicit self-contained LLD并只执行 digest-bound helper；
- pinned wasm-bindgen executable、sandboxed post-link output collection与 bundle attestation；
- outer signer/enforcement attestation protocol；
- `build-host`、production `verify-integration --phase pre/post`；
- production build/build-host manifest 与 SBOM output identity。

验收必须证明 Linux build-host交叉编译另一个 target时，build script/proc macro及其 host-only transitive dependency与 target artifact unit分别进入正确 graph，同 package的 host/target feature set不会被 package级合并；planned/observed unit任一漂移都失败。还必须证明 build script的未声明文件读取、network、executable、socket和 environment access被拒绝，声明的 SDK/linker input可用，descendant process不能逃逸，未由新有效 attestation解释的 enforcement payload/evidence、input、unit graph或 artifact digest漂移都会失败；合法重签或 evidence/trust rotation在 semantic projection未变时只触发完整 policy/envelope重新验证，不改变 build-output identity。没有外部 trusted supervisor/completion handle的本地环境只能运行 Phase 1A development path。

验收：

```text
[P1B-AC-01] normalized production policy is closed, pinned and separates full concrete identity from path-free build enforcement and attestation projections
[P1B-AC-02] trusted Cargo planning and observation preserve exact Host/Target units, build-host/composition-target contexts, build scripts, proc macros, dependency edges and planned/observed equality
[P1B-AC-03] Host feature union is exact per unit and verifies additive source semantics, reviewer policy, build requirements and runtime-effect accounting
[P1B-AC-04] fetch is isolated, locked and checksum/revision complete; rejected input or endpoint resolution has no source-cache publication side effect
[P1B-AC-05] the Linux reference backend proves namespace, immutable descriptor mount, Landlock, seccomp, no-new-privileges and canonical metadata enforcement on a real runner
[P1B-AC-06] build scripts and every descendant deny undeclared filesystem, network, executable, socket and environment access while exact declared SDK/linker inputs remain usable
[P1B-AC-07] toolchain, SDK, read-input, executable, target-fact/custom-spec and canonical Cargo-config identities are reproduced inside the trusted backend before Cargo side effects
[P1B-AC-08] the pinned wasm-bindgen executable runs in the sandbox and every raw/transformed WASM, JavaScript, declaration and snippet output is closed and attested
[P1B-AC-09] signed path-free executor attestation binds the normalized build/feature policy, backend, inputs, graphs, evidence and artifacts through a one-use trusted completion handle
[P1B-AC-10] production manifest, CycloneDX SBOM and output identity account for the complete artifact tree while path/trust/envelope rotation cannot change semantic build-output identity
[P1B-AC-11] production build and inspect CLI wiring fails closed and cannot publish deployable output without a verified trusted completion and append-only attestation
[P1B-AC-12] build-host and production integration pre/post rematerialize the live Host closure, verify the unique emitted dependency/config, replan both graphs and bind the final Host artifact
```

macOS/Windows production executor 不阻塞第一版 Linux runtime；只有各自 deny-by-default backend 或隔离 VM executor、签名 attestation 和 escape suite 均通过后才把对应 Host support 从 `Experimental`/development-only 提升为 `Production`。交叉编译 target 不等于该 Host build backend 已获 production 支持。

### Phase 2 — Minimal Runtime Spine

实现：

- 完成 rust-agent-core / rust-agent-runtime-api public contract
- 先完成轻量 `rust-agent-session` API contract：`SessionPersistenceError`、query DTO/error/handle seam、journal/read-store trait与 agent 所引用的 lower-level session types；本阶段不实现 Session Component或backend
- rust-agent-model
- 在上述 session API 可独立 `cargo check` 后实现 rust-agent-agent
- rust-agent-commands contract / empty guarded dispatcher
- model-replay
- model-host
- driver-direct
- volatile RequestJournalFacade、不可构造的 RequestJournalProof/ModelCallContext 与只接受 PreparedModelCall 的 model consumer binding
- App scope / AgentFactory minimal ownership
- PublicationDirectory / LifecycleObserver transaction
- volatile lifecycle-operation issuer（process-bound、不可序列化）
- targeted cancel request identity、bounded public Agent event feed 与 Sessionless baseline

验收：

```text
Request → LanguageModel → Response
```

并通过 `minimal-pure` 的 compose/lock/build、publication/rollback、每次 model stream 前 volatile proof 已生成，以及 deterministic regeneration tests。Phase 2 CI必须按 `core → runtime-api → session API → agent` 顺序分别编译 normal/development/all-feature public type closure，并证明 `rust-agent-session` 不依赖 `rust-agent-agent`；minimal-pure只链接轻量API，不能因此选择Session Component、persistence或query provider。

### Phase 3 — Tool Execution Plane

实现：

- Tool / RegisteredTool / ToolProvider / internal ToolRegistry
- ToolExecutor reference monitor
- `rust-agent-tools::guarded_component` implementation + metadata-only `tool-executor-guarded` re-export wrapper
- opaque ExecutionPermit compile-fail bypass test
- PermissionPolicy API 与 permission-default
- Prompt/Compaction/Telemetry/Attachment/Spill capability contracts（不实现 provider）；Session 的轻量 API 已在 Phase 2，不能在此阶段才补 agent 所需类型
- driver-tools
- typed middleware
- cancellation lineage
- model-origin ToolCall volatile journal issuer/verifier gate；raw execute 仅保留给借用的 Command/Nested origin
- bounded tool concurrency

从 AINS 迁 Tool DTO / runtime 行为测试，但不迁旧 `AgentKernel` / `ToolRuntime` 结构。验收必须包含薄 wrapper compile-pass、wrapper 尝试访问 handler/private registry 的 compile-fail、普通 consumer 构造/保存 permit 的 compile-fail，以及所有可执行路径都落到同一 `rust-agent-tools` guarded pipeline 的 dependency/source lint。ToolCallPolicy/ToolRiskRule 必须通过字段私有的 bounded builder正负边界测试与 struct-literal/serde-bypass compile-fail，不能依赖 registration才首次拒绝超限 state。Sessionless positive fixture 必须证明 volatile `ToolCall` proof 可执行；missing/wrong/cross-Agent verifier、raw model-origin execute 与 proof constructor 均 compile-fail 或在任何 policy/approval/provider callback 前 fail closed。Targeted cancel 的 idle/stale/queued/racing-send/first-cause/shutdown matrix 同阶段固定。

### Phase 4 — Local Execution Providers

实现并迁移 Linux/Unix production path：

- resource-namespace-bootstrap-local
- fs
- subprocess
- shell
- terminal
- sandbox
- permission
- tool-fs / tool-shell

重点验证：

- symlink/TOCTOU
- `resource-namespace-bootstrap-local` metadata/catalog exact key、authority-projected stamped locator call 与 descriptor-relative root anchor
- canonical cwd
- process tree kill
- output budgets
- fail-closed sandbox

macOS/Windows provider 只有在真实 target CI/runner 上通过 confinement 与 process-tree regression 后才加入 supported compile matrix；mobile 保持 deny/host-policy，不提供 process capability。

### Phase 5 — Session Plane

实现：

- 在 Phase 2 已可编译的 `rust-agent-session` API之上完成 event/journal/provider plane，不改变 `agent → session` 依赖方向
- session-log-events
- event vocabulary
- generated SessionEventCatalog / cap:session-event-catalog binding
- SessionPersistenceAdmin/SessionJournal backend contract、Host-provisioned StoreGeneration/StoreIdentity、sealed-full-request async/fallible store-scoped lifecycle-operation issuer、atomic recovery-key→operation-id index、fingerprint-bearing Reserved/Located locator 与只读 SessionReadStore facade
- session-persistence-memory/jsonl/redb provider
- JSONL/Redb admin/read facade共享authority-projected local namespace preparer/descriptor/anchor，raw Config path不得在factory/initialize/recovery中重开
- JSONL store-level commit coordinator、单一权威 commit journal、derived locator/index checkpoint rebuild
- projection
- title/read-only SessionQueryHandle seam，以及 Durable feed baseline/high-water/cold replay recovery
- owner-scoped bounded SessionObserver dispatcher、overflow telemetry 与 callback/shutdown deadline
- reconstructability invariant
- crash recovery / flush semantics
- Durable/Ephemeral RequestJournalFacade、stable RequestPrepared batch 与 model-call proof gate
- stable model-origin ToolCall batch 与 tool-call proof gate
- Durable command Prepared/DispatchPrepared/Finished journal gate、recovery terminal projection与pre-permit/pre-handler proof gate
- canonical UserInteraction Asked/Answered/Acknowledged/Closed journal facade、bounded ack-reconciliation projection与`CommittedUserAnswer` model-history proof gate（Host stable provider在Phase 7接入）
- shutdown flush/writer-lease-release confirmation 和 same-composition Host handoff crash matrix

再把所有已实现 AgentDriver（至少 `driver-direct` 与 `driver-tools`）接入同一 generated Durable journal route；driver metadata 不各自复制 SessionLog requirement。Durable tools 验收必须证明 ToolCall commit 前 Tool provider/Permission/Approval/permit 均零调用，JSONL crash matrix 必须从单一权威 journal 重建 per-session/index/locator checkpoint 且跨 Session 无 lost update，public feed/query 必须通过 atomic baseline、bounded lag/resync、shutdown Close 与 native/WASM parity。第一版验收只允许在 exact composition hash + exact catalog digest 下 resume；跨 composition、provider replacement 或 catalog 变化的 migration/import 明确不属于 Phase 5，不能用兼容表或 runtime fallback 代替。

### Phase 6 — Prompt / Memory / Skills / Compaction

实现/迁移：

- PromptContributor pipeline
- Redb/IndexedDB KV
- crypto decorator
- HNSW/flat vector providers
- embedding-host
- parser providers
- memory algorithms
- skills
- Credentials API 与 credentials-env
- `compaction` component
- token meter / tool-result pruning
- RegisteredCommand providers / plan-mode

严格按 capability 拆分。

### Phase 7 — Network Extensions

- HTTP/network policy
- Native NetworkConnector / HttpClient
- model-deepseek/model-openai
- embedding-openai
- MCP
- MCP HTTP/stdio/host transports
- Web
- Native HTTP 与 WASM Host bridge providers
- credentials-host
- remote fs/shell/skills/session-persistence providers
- Attachments
- Spill
- Approval/UserInteraction Host providers；Durable interaction provider实现stable-until-commit-ack resolution/ack协议并接入canonical Asked/Answered/Acknowledged journal facade与resume reconciliation
- telemetry-none/telemetry-otel

重点做 dependency-negative 与 SSRF/redirect regression。

### Phase 8 — Advanced Agent

- Jobs
- Subagent
- Planner
- Workflow
- LSP
- Code runtime / tool-code-runtime / command-code-runtime
- driver-team parent-owned coordination

这些都必须复用既有 AgentFactory/Scope/ToolExecutor，不得建立第二套生命周期或工具执行系统。Subagent验收必须证明 caller只能从 exact `SubagentProviderBinding`分配 parent-scoped operation id，`subagent-in-process`只能从 exact `ChildAgentFactoryBinding`先 seal完整 child draft、再分配 child lifecycle capability并在 retry复用同一映射；raw provider/factory、caller forge、cross-parent/provider、intent-only allocation和 Durable child绕过 fingerprint-bearing persistence reservation均 compile-fail或在 effect前拒绝。CodeRuntime的 compile-fail fixture必须证明没有当前 Tool body的 `ExecutionPermit`就无法构造 `CodeExecutionPermit`。

### Phase 9 — AINS Cutover

AINS 新建 integration adapter；为每个产品 target/profile 生成并提交 emitted library composition；把 Host Cargo dependency 切到唯一 target-specific alias；对存在 delta 的 graph 生成并审计 AINS HostFeatureUnionPolicy、对无 delta graph 固定 `none`；为每个最终 Host build 生成 pre receipt、产品 executor attestation 和 post integration attestation；双跑 integration tests；替换依赖；删除旧 `crates/rust-agent`。这里的“integration adapter”不是只替换几个 provider constructor：cutover 前必须提交一份可机器检查的 responsibility/migration inventory，把当前 AINS Host 装配层的每项职责映射到“新 rust-agent Component/runtime、AINS product binding、AINS UI/view-model adapter、离线 state migration”之一，并列出旧文件/API、目标 owner、状态格式、测试与删除条件；不得以未列项的 compatibility fallback 保留第二套 kernel/registry/lifecycle。

目标稳态下，AINS 只负责产品绑定和产品 UI/view-model 映射：

- Gateway model provider adapter
- Approval/UserInteraction product adapter（当前 Dioxus）
- AINS-local DirectoryPicker UI
- Credential bridge
- product Session/Attachment storage adapters
- bounded `AgentHandle::open_event_feed` + read-only `AppHandle::session_query` → AINS UI state/view-model projection（当前 Dioxus）；该层不能持有 raw AgentKernel/ToolRuntime、内部 observer 或无界 event channel

以下当前 Host 职责必须在 inventory 中显式迁移，不能假定已被上述五个 binding 自动覆盖：

- AgentBridge/Kernel spawn、targeted cancel、shutdown 与 session identity → rust-agent AppHandle/AgentHandle lifecycle；UI 必须保存 exact active AgentRequestId，idle/stale Stop 不得 arm 下一 turn；
- pending create/resume recovery key、operation id、canonical draft/fingerprint、operation→Session locator resolution与UI retry state → AINS durable Host operation journal；正常初次Durable operation必须先创建并持久化never-reused recovery key + canonical draft，再由将执行调用的AppHandle seal完整request/projection、以same key向selected store签发/读回fingerprint-bearing Reserved，返回后把id/fingerprint补写到同一entry，最后才调用create/resume。Seal/allocation失败不得构造request；response丢失或补写id前process loss后，same-composition/same-store App只可重新sealjournal draft并same-key allocate取回exact id，再recover/继续，不能因页面/进程重启换key/id或authority；
- live config/binding cutover → AINS Host handoff coordinator；`app-handoff=concurrent` 仅在全部 App Component coexistence evidence 有效且 shared Host handle identity 相同时允许预构造新 App，并由new Host在关闭old handle前pre-journal recovery key/canonical draft、由new App完成exact resume projection/seal、以same key await persistent allocation，再补写returned id/fingerprint；`stop-old-app` 必须先关闭全部旧 Agent并释放 lease、关闭旧 App/独占 Redb 等资源、再 build 新 App，由 new Host/App执行同一pre-journal/seal/allocation/id补写流程后 resume；任何模式都禁止先 resume 再释放旧 writer lease，allocation response或id补写丢失只能same-key恢复；
- 静态工具注册、schema snapshot 和工具可用性 → generated profile + `cap:tool-provider` composition；AINS 只保留用户禁用偏好/UI 投影；
- permission/interaction channel → typed Approval/UserInteraction Host callback；Durable profile还必须把pending `UserInteractionId`/`UserAnswerOperationId`、stable submission/fingerprint与commit-ack状态放入AINS Host-owned interaction journal，restart后按原operation resolve，不能只保存在Dioxus view state；
- Session restore、tool-state persistence、memory/backend singleton cache → 对应 Session/Memory/KV provider 及其 scope lifecycle；
- native/WASM `cfg` 装配分支 → target-specific emitted composition 与 HostBindings；
- 旧 DTO/event 到新 public handle/event 的映射 → 有版本的 AINS adapter；Durable lag 用 SessionQueryHandle 从 committed high-water 重建，Sessionless gap 明示不可恢复，不得直接 import 新 runtime internal type。

Cutover 顺序固定为：先冻结 inventory 与兼容测试 → 引入 adapter 并让旧/新实现对同一 golden input 双跑 → 执行 session/tool-preference/memory state compatibility 或显式离线 migration → 按 target/profile 切换唯一 Cargo alias → 验证 dependency-negative、lifecycle、UI integration 和 production pre/post attestation → 删除旧 imports、旧装配路径和 `crates/rust-agent`。双跑只比较可观察输出/事件，不允许两个实现同时执行 network/process/write 等外部 effect；effectful case 使用 replay/fake provider 或一次执行后比较投影。Rollback 只能切回完整旧 build，不得在一个 binary 中运行时 fallback 到旧 kernel。

Phase 9 验收至少证明：AINS Host 不再直接 import `AgentKernel`、旧 `ToolRuntime`、旧 policy/memory/session internals；不存在硬编码 raw tool registration；每个 persistent state 有兼容读取或版本化 migration/拒绝诊断；pending lifecycle operation 在 UI/process restart 后复用原 id 并能从 locator 得到 exact Session/terminal；live handoff 的 concurrent/shared-handle 与 stop-old-app/Redb old-owner/lease-release/crash cases 全部按 manifest 固定顺序恢复；UI observation 只有 bounded feed + query，覆盖 atomic baseline、Lagged/resync、Closed 与 native/WASM parity；targeted cancel 的 idle/stale/racing-send 回归不取消后续请求；AINS 额外共享 Cargo features 全部命中 exact HostFeatureUnionPolicy entry，product-only attribution 具有有效 source-semantics evidence，且产品 effect union 可审计；现有 product interaction、cancel、resume、tool preference 和 storage regression 在每个支持 target 通过；最终 cargo tree 不含旧 `crates/rust-agent`，且产品 artifact 通过匹配 composition 的 production integration verification。

最终 `rust-agent` 独立 clone/build/test 不需要 AINS。

## 50. 每阶段迁移规则

每迁一个旧模块必须完成：

1. 定义新 capability seam。
2. 明确 Provider / Consumer。
3. 建 behavior test。
4. 从 AINS 复制算法实现。
5. 删除对旧 kernel/context/client-api 的 import。
6. 替换成新 capability dependency。
7. target matrix 测试。
8. cargo tree 验证依赖隔离。
9. security regression。
10. 文档记录旧文件 → 新 crate mapping。

禁止整目录复制后再慢慢清理。

---

## 51. 第一版具体 crate 优先级

不要一开始创建完整几十个 crate。按稳定边界逐步拆。

P0：

```text
rust-agent-core
rust-agent-runtime-api
rust-agent-session
rust-agent-model
rust-agent-agent
rust-agent-commands
rust-agent-composition
rust-agent-build-executor
rust-agent-runtime-tokio
rust-agent-runtime-wasm
rust-agent-cli
rust-agent-host-cli
rust-agent-host-wasm
model-replay
model-host
driver-direct
```

P0 中的 `rust-agent-session` 先只交付 Phase 2供 `rust-agent-agent` 编译所需的轻量 API/error/DTO contract，event/backend Component仍按 Phase 5实现；它出现在 graph不代表启用Session plane。`rust-agent-build-executor` 先交付 Phase 1A 的 locked development runner 与统一 policy/attestation API；只有 Phase 1B Linux backend、escape suite 和签名 attestation 通过后，同一边界才允许生成 `deployable=true`。crate 出现在 P0 不代表 production sandbox 已在 Phase 1A 完成。

P0 是第一版 release tranche 的优先级集合，不是 Phase 1A 的依赖清单。Phase 1A 仍只实现最小 core/runtime contract 与 fixture capability/component；P0 中的 `rust-agent-model`、`rust-agent-agent`、Host 和真实 driver/model Component 按 Phase 2 开始接入，不能为了提前创建空 crate 而让 compiler proof 依赖尚未稳定的产品 API。

P1：

```text
rust-agent-tools
rust-agent-prompt
rust-agent-attachments
rust-agent-spill
rust-agent-telemetry
driver-tools
tool-executor-guarded
tool-fs
tool-shell
tool-terminal
resource-namespace-bootstrap-local
fs-read-local
fs-memory
fs-sandbox
rust-agent-fs
rust-agent-process
rust-agent-policy
permission-default
fs-local
subprocess-local
shell-local
sandbox-linux
terminal-local
```

P2：

```text
session-log-events
session-persistence-memory
session-persistence-jsonl
session-persistence-redb
session-query-events
session-projection-events
session-title-basic
prompt-assembly
rust-agent-memory
memory-context
kv-memory
kv-redb
kv-indexeddb
kv-encrypted
vector-hnsw
vector-flat
retrieval-local
embedding-host
parser-markdown
parser-pdf
rust-agent-skills
skill-filesystem
skill-embedded
prompt-skills
tool-skill
rag
rust-agent-credentials
credentials-env
compaction
plan-mode
```

P3：

```text
rust-agent-extension-api
attachment-memory
attachment-local
attachment-host
spill-memory
spill-local
spill-host
user-interaction-host
network-policy-default
network-policy-host
network-connector-native
http-client-native
credentials-host
approval-host
fs-remote
fs-e2b
shell-ssh
shell-e2b
model-deepseek
model-openai
embedding-openai
web-http-native
web-fetch-host
web-search-deepseek
web-search-exa
web-search-perplexity
web-search-host
skill-remote
tool-web
mcp-client
mcp-transport-http
mcp-transport-stdio
mcp-transport-host
telemetry-none
telemetry-otel
session-persistence-remote
```

P4：

```text
sandbox-macos
sandbox-windows
mobile-policy
job-runner
subagent-delegation
subagent-in-process
subagent-process
subagent-remote
subagent-codex-process
subagent-claude-process
workflow-engine
lsp-local
tool-lsp
rust-agent-code-runtime
code-runtime-sandboxed
code-runtime-host
tool-code-runtime
command-code-runtime
driver-planner
driver-team
```

列表中属于 `crates/components/` 的项均为独立 Component package；`crates/api/`、`crates/composition/` 与 `apps/` 项不是 Component。优先级只决定何时引入。API/helper crate 的进一步拆分继续以重依赖、安全边界、平台实现、binary size 和独立公共 API 为条件。

## 52. 关键 Invariants

以下必须写成 architecture tests / CI rules，而不仅是文档约定：

```text
I1   rust-agent-core has no product/runtime-heavy dependency.

I2   every selected Required capability is satisfied.

I3   an explicitly disabled component can never enter the
     generated Cargo dependency graph.

I4   an explicitly enabled but unsatisfiable component makes
     production composition fail.

I5   App, Session-template, Agent(AppParent) and Agent(SessionParent)
     construction graphs are acyclic for every enabled creation mode.

I6   Provider / Consumer / Contributor / Decorator / Factory are
     derived from Capability Graph relations, not stored as an
     independent mutually-exclusive Component role.

I7   consumer imports capability/API crate, not concrete provider crate.

I8   generated composition references selected components only.

I9   generated Cargo optional/component dependencies come only from
     resolved components; mandatory API Spine and Composition infrastructure
     dependencies are explicitly allowlisted and are not optional Components.

I10  unsupported-target components cannot enter composition.

I11  disabled high-risk capability leaves no implementation dependency
     in generated Cargo graph / cargo tree.

I12  rust-agent contains no AINS product dependency.

I13  every background task/resource belongs to exactly one idempotent runtime
     lifecycle, even when factory teardown and handle shutdown can both trigger it.

I14  durable events are ordered, validated and versioned.

I15  identical normalized config, catalog, target, build kind, source bytes
     and Cargo.lock produce identical resolution, generated sources and
     composition hash.

I16  every model-visible durable input is reconstructable from SessionLog, and
     no Durable model provider stream begins before its exact RequestPrepared
     batch is confirmed committed; model routing mode is validated at App build,
     explicit-per-request rejects a missing/projected-out key in plan_call, and
     the actual provider key/model id is always materialized into that record.

I17  Session/Agent-scoped resources remain outside PublicationDirectory until
     initialize and every commit required before publication for that route complete.
     NewDurable genesis and Durable resume Prepared obey that pre-publication rule.
     NewEphemeral is the explicit staged-publication exception: its complete directory
     pair is published while genesis remains query/index-invisible, activation runs
     behind a closed ScopeAdmissionGate, and a known-outcome genesis/index commit must
     succeed before admission opens. Any activation/commit failure aborts genesis and
     atomically removes the pair. Every route opens admission only after publication,
     gated activation and its required lifecycle success commit/checkpoint.

I18  failed App/Session/Agent construction rolls back every constructed,
     initialized or activated owned resource.

I19  Tool execution passes through ToolExecutor; ordinary safe Rust consumers
     cannot construct ExecutionPermit, access raw registry lookup or retain a
     command/nested execution session beyond its borrowed authority.

I20  Component runtime ceiling, lifecycle effects, per-provide binding effects,
     Host boundary runtime ceiling and final artifact runtime effects are distinct,
     cumulative and fail closed; every narrower Component runtime declaration is a
     subset of its selected Component ceiling; resolved consumer/Tool/Command
     effects are subsets of the sealed own-plus-selected-dependency effective
     closure; final compiled effects equal the Component union plus selected Host
     boundary ceiling; Host boundary effects do not enter AgentAuthority; and build
     requirements are a separate typed union satisfied only by BuildExecutionPolicy
     and never enter SecurityEffects or AgentAuthority.

I21  runtime config may select only providers present in the compiled binding.

I22  resolver must backtrack across provider candidates and must not report
     UNSAT merely because an earlier deterministic candidate failed.

I23  metadata/catalog and real Cargo dependency graph cannot silently drift.

I24  App singleton cannot retain a concrete shorter-lived Agent/Session instance
     except through an explicit Factory/Registry/Handle lifetime boundary.

I25  shutdown is idempotent and reaches defined quiescence for owned work.

I26  every selectable Component maps to exactly one Cargo package and every
     Component package declares exactly one component id.

I27  every generated factory call, config type, Dependencies struct and
     capability binding adapter is derived from metadata, returns/consumes
     ComponentOutput service and is verified by Rust type checking.

I28  production builds require the generated Cargo.lock and never update it.

I29  a resolver search limit returns ResolutionLimitExceeded, never UNSAT.

I30  host-source config never enters serde runtime config; bin rejects it and
     library/wasm requires typed HostBindings construction.

I31  native outbound HTTP/socket access is confined to selected audited
     NetworkConnector/HttpClient transport components; logical intent is
     authorized before resolver/DNS/proxy/socket side effects, and every actual
     resolved/proxy/redirect connection hop consumes a separate bound grant;
     every first or pooled logical stream use consumes a fresh grant bound to
     the exact caller/origin/proxy/connection, and cross-origin body-preserving
     redirects or connection coalescing are rejected by default.

I32  Subprocess accepts only a ConfinedProcessSpec authenticated by the
     verifier paired with the selected Sandbox issuer and immutable ceiling.

I33  durable Session append is protected by an exclusive writer lease and
     fencing generation.

I34  production composition rejects every Component, runtime adapter or Host
     entry/export helper whose support tier on the selected target is Experimental.

I35  resolver decision budget is deterministic input; external cancellation
     never produces a cacheable UNSAT result.

I36  a durable RequestPrepared or model-visible ToolResult never depends on
     an ephemeral-only SpillRef or AttachmentRef.

I37  a library composition enters a final Rust Host only as a verified emitted
     source dependency with an exact Host Cargo alias; production evidence binds
     pre/post integration receipts, product executor attestation and final artifact;
     a standalone rlib is never the integration interface, and replacing a different
     existing emitted path is explicitly offline rather than a portable atomic update.

I38  every production build is executed under a versioned BuildExecutionPolicy;
     all descendants inherit enforced filesystem/network/executable limits and
     every extra environment input maps one typed role id to an exact non-secret
     variable/value apart from the fixed runner baseline; a selected Host linker is
     an atomic, digest-bound executable/helper closure with schema-owned Cargo config,
     compiler path and exact encoded rustc flag disabling implicit self-contained LLD;
     the observed flag count and helper executions must match that selection and the
     backend semantic version must change when these execution semantics change; the
     full normalized policy and enforcement evidence remain signed attestation inputs,
     while only their path-free enforcement/result semantic projections participate in
     build-output identity and trust/mapping/envelope rotation does not.

I39  PublicationDirectory publishes or removes the complete Session/Agent pair
     in one generation update; before_publish veto precedes directory publication
     and any Durable genesis/resume-Prepared commit, while post-commit published/disposed
     notifications use pre-reserved bounded enqueue and timed, cancellable callbacks.
     Timeout/error cannot block activation or teardown; panic has that containment only
     for unwind-capable artifacts, and selecting an in-process observer makes abort or
     no-unwind builds fail at generated compile and integration-verification gates.

I40  CodeRuntime execution requires a CodeExecutionPermit borrowed from the
     current ToolExecutor-authorized tool body; ordinary Components and Hosts
     cannot construct or retain it.

I41  human commands enter through AgentHandle and a private CommandPermit;
     live-lifecycle invocation retry joins one execution and delegated tool authority
     cannot outlive the command future. Durable dispatch confirms the exact Prepared
     checkpoint before permit construction, confirms DispatchPrepared before the raw
     handler, and confirms one terminal before returning. Recovery maps Prepared-only
     to InterruptedBeforeDispatch and DispatchPrepared-only to OutcomeUnknown and never
     auto-replays either; Durable PlanMode state becomes visible only after its own
     idempotent event batch is confirmed committed, and every unknown commit closes
     admission until the original batch is resolved.

I42  first-version RuntimeConfig is immutable for one AppHandle lifetime and
     no untyped global settings map can reconfigure a live composition.

I43  every extension Session event kind/version/criticality/bound is declared by
     its selected producer in the generated static catalog; every unknown event
     is rejected, while only catalog-known Informational events may be skipped by
     an uninterested projection after full envelope validation.

I44  Host turn execution enters through AgentHandle with a lifecycle-bound
     request id; live retry joins one execution, process-loss outcome is never
     auto-replayed, and raw Agent service is not exposed outside the handle.

I45  child Agent authority is the monotonic intersection of compiled App/root,
     stored Durable, current owner and requested attenuation; projection can only
     remove compiled bindings/keys/contributors/registrations, never fallback or
     initialize a pruned Session/Agent Component; it does not retroactively undo
     App-scoped lifecycle effects already authorized by root authority.

I46  first-version live resume requires exact composition hash and exact
     SessionEventCatalog digest; cross-composition/schema conversion belongs to
     a separate versioned offline migration/import protocol.

I47  composition environment is a resolver fact, not a Cargo cfg; Component
     target dependencies use Cargo built-in target facts only, and environment-
     specific implementations are separate Component packages.

I48  native/library/WASM Agent handles expose the same identity and lifecycle
     status semantics and route send/cancel/command/shutdown through the same
     owned AgentHandle admission boundary; framework identity never changes the
     composition contract, and product adapters preserve request id, cursor,
     bounded backpressure, Lagged/Closed and shutdown semantics across Rust/JS/IPC.

I49  Phase 1A development execution always emits deployable=false; only a
     Phase 1B production backend whose policy enforcement and escape suite are
     attested may emit deployable=true for its declared build Host.

I50  every Durable resume operation has one stable Prepared batch and exactly one
     mutually-exclusive Completed or Failed terminal; admission cannot open before
     Completed is durably confirmed, Prepared-only recovery closes deterministically,
     and fencing generation distinguishes reconstructed process incarnations.

I51  App-scoped autonomous effects run only under App root ownership; a child may
     lose access to a stamped App binding but cannot suppress effects performed for
     root/other owners, and child-specific App-provider calls revalidate a scoped
     request authority stamp.

I52  NewDurable creation has a stable genesis and exactly one mutually-exclusive
     AgentCreationCompleted or SessionEnded(CreationFailed) terminal; admission
     cannot open before success is durable, and genesis-only recovery closes as
     InterruptedBeforeAdmission; a failed-operation retry returns its exact terminal
     failure without reconstruction, while an idle completed Session remains success.
     NewEphemeral instead keeps genesis transaction/query/index invisible until gated
     activation succeeds and atomically aborts it on rollback, so no failed creation
     leaves a genesis-only authoritative Session without a live owner.

I53  mandatory API/generated infrastructure in the generated runtime artifact has
     no direct runtime effect surface; every external operation crosses a stamped
     selected-Component binding, and
     any effectful implementation must be a Component or Host boundary accounted
     by the corresponding runtime ceiling. Namespace locator I/O crosses the
     projected resource-namespace-bootstrap Component binding, and persistent
     lifecycle-id allocation crosses the selected persistence binding.

I54  before any Durable lifecycle id allocation mutation, the caller durably records a
     never-reused recovery key and canonical create/resume draft; request-specific authority/
     template/namespace projection then completes and seals an immutable fingerprint. The
     StoreIdentity-scoped issuer atomically maps that key to the generated id and persists the
     exact intent, fingerprint, authority/plan digests, composition/catalog and Session identity.
     Same-key exact retry returns the original id without increasing the counter; conflicting
     reuse fails. Thus response loss and a crash before the Host records the id remain recoverable.
     Genesis/resume Prepared only consume that reservation, with no rebinding, fallback or
     invented SessionId.

I55  Session persistence admin and read access are different capability facades;
     both derive from the same selected backend Component, only generated scope
     construction and session-log-events can prepare journals or mutate locator/
     writer state, while query/Integrator code gets only bounded cursor-based
     session-index/event reads and cannot scan or upgrade to admin authority.

I56  cap:agent-factory is the only schema-v1 authority-mediated deferred factory;
     its App binding has no template effects, but every operation seal computes the
     exact resolved template effect closure and completes monotonic authority projection
     before namespace bootstrap and reservation mutation; allocate/create/resume can only
     consume the resulting opaque draft/capability and cannot reselect a route. Only retained
     namespace edges receive a stamped bootstrap call before their commitments are sealed;
     no ordinary Component, second capability or fallback route can defer this check.

I57  final Host Cargo feature unification keeps every emitted first-party and every shared
     Host compilation unit exact, including schema-2 Cargo target context so distinct Host-side
     and composition-target build-script executions cannot collapse. Schema v1 feature policy
     only permits audited Target-library deltas whose
     closure cannot add or alter build-script/proc-macro/generated/link output; all uncertain
     runtime effects are charged to the composition path. A Host unit's execution effects are
     build requirements, but every downstream cfg/code/token/native/link contribution is
     attributed to a Target/Host-root runtime ceiling and product_compiled_runtime_effects.

I58  a live Durable Session has one writer owner: concurrent handoff pre-journals a recovery
     key/draft and obtains/persists the resume id from the prebuilt new App before closing old
     admission; stop-old-app closes/drains old Agent/App first, builds the new App, then does
     the same. Both confirm lease release before resume. Response loss reuses only the same key
     and exact draft; neither path changes key/id, resumes first, or steals an unknown lease.

I59  every AgentDriver receives the generated route-specific request-journal facade;
     ModelCallContext and RequestJournalProof are not caller-constructible, and the
     model consumer binding accepts only a PreparedModelCall whose request/route
     digest matches the journal proof; Durable proof requires committed SessionLog.

I60  every model-origin Tool call is purely planned, journaled and sealed before it
     enters ToolExecutor permission/approval/middleware/permit/provider dispatch;
     Durable proof requires the exact ToolCall committed in the same SessionLog, and
     caller-constructed, missing, stale or cross-scope proofs fail before any external
     callback or effect.

I61  the public Host observation plane is a bounded cursor stream whose subscriber
     registration and baseline/high-water capture are one linearization point;
     every feed reserves count/events/bytes against an attenuable per-Agent aggregate
     budget, so both total ring storage and publisher traversal are bounded; overflow is
     an explicit terminal Lagged state, Durable gaps recover only through the read-only
     SessionQueryHandle, whose session enumeration is also bounded and snapshot-cursored
     through SessionReadStore; Sessionless gaps are explicitly unrecoverable, and
     shutdown publishes one terminal Closed without blocking writers.

I62  live App replacement may prebuild the new App only when every selected App
     Component declares and proves a compatible concurrent mode and every shared Host
     handle identity matches; any exclusive/unknown App resource selects stop-old-app,
     which releases all old Agent leases and App resources before building the new App.

I63  cancel targets one exact active AgentRequestId in one lifecycle; idle, queued-only,
     terminal, foreign or stale requests never arm/cancel a later turn, first cause wins,
     and the next queued turn starts only after the aborted turn reaches its required
     terminal convergence; shutdown remains a separate all-waiter close operation.

I64  every configured authority-bearing resource namespace is asynchronously resolved
     only after the exact root/scope binding/effect projection authorizes its derived
     resource-namespace-bootstrap edge and before final authority, Durable identity,
     factory or initialize; locator I/O belongs to the selected ordinary Component,
     infrastructure computes the commitment without direct I/O, local providers retain
     the descriptor-relative anchor, and deleted routes perform zero locator calls.

I65  generated build receives an explicit target-compatible RuntimePrimitives bundle;
     each Component sees only its declared primitive projection, executor-bound work is
     owner-scoped and drained, and library correctness never depends on the ambient
     executor that happens to poll build or a public future.

I66  build-output identity hashes the path-free BuildEnforcementIdentity, semantic
     enforcement-result projection and canonical build-manifest digest; the signed
     attestation binds composition/output/manifest identities. Full runner mappings and
     trust remain evidence, so path/trust rotation does not rename identical output, while
     changed logical input, selected Host linker closure, enforcement semantics or
     manifest security fields always does.

I67  SessionObserver delivery uses one owner-scoped dispatcher with bounded batch/byte
     storage and per-callback/shutdown deadlines. A first confirmed commit performs one
     nonblocking enqueue-or-drop decision; observer pressure, timeout, error or contained
     panic never changes or delays the committed append result, no callback task outlives
     Session teardown, and this best-effort seam provides no replay guarantee.

I68  lifecycle operation intent, opaque persistence-reservation DTO and allocation-error
     types are owned by runtime-api and merely re-exported by agent; session imports them
     directly and never depends on agent, so the agent-to-session error mapping leaves the
     API crate graph acyclic.

I69  every selected fs-read-local/fs-local namespace edge resolves the ordinary
     resource-namespace-bootstrap-local Component and exact Registry key into the Cargo
     closure; missing, mismatched or target-incompatible bootstrap providers fail before I/O/Cargo.

I70  ToolCallPolicy and ToolRiskRule have private storage and can be created/decoded only
     through builders that enforce rule/predicate/count/byte/evaluator ceilings before
     retaining each item; registration revalidation is defense in depth, not the first bound.

I71  host-cli targets only Linux/macOS/Windows desktop OSes, with Production limited to
     target-specific proven tiers; iOS, Android and every other native target are rejected
     by Host Boundary normalization rather than accepted by a blanket non-WASM predicate.

I72  Host integration verification plans and attests Cargo compilation units, not a
     package-level target-filtered metadata graph: build-script/proc-macro dependency
     units are evaluated for the build host, artifact units for the composition target,
     each unit retains its exact feature set, shared Host-unit deltas are rejected, and
     actual units plus downstream generated/link contributions must match the pre-committed
     graph/effect attribution before a product artifact is accepted.

I73  each subagent spawn/continue operation id is allocated only by the exact
     parent-lifecycle/provider-stamped SubagentProviderBinding; stale, cross-parent,
     cross-provider or caller-forged ids fail before provider/transport effects, while
     same-id retries retain one canonical operation.

I74  the sole in-process self-factory edge exposes an owner-scoped
     ChildAgentFactoryBinding with the same seal/allocate/recover protocol used by AppHandle.
     Every child draft is fully projected before allocation, every create/resume reuses its
     mapped fingerprint-bound capability, and Durable child allocation obtains a confirmed
     complete reservation from the selected persistence store.

I75  cross-crate generated assembly uses runtime-api-owned opaque scope builders. Public
     issuance creates only a fresh isolated App root; child authorities derive only from that
     root, contexts/stamps derive only from a consuming BindingAssembly transaction, and no
     caller can choose/recover a tag or inject owner/effect/dependency/call-authority fields.
     Every recorded witness must match the exact manifest plan and current scope before finish.

I76  an Ephemeral creation route exists only when the exact selected persistence provide
     declares and conforms to ephemeral-creation=staged-known-outcome. Durability=durable
     alone never supplies that route; NewEphemeral may publish its complete directory pair
     with genesis staged/query-invisible, but admission remains closed until the known-outcome
     genesis/index commit succeeds, and failure aborts genesis and removes the pair.

I77  every model-visible human answer crosses the generated interaction journal facade.
     Durable Asked is committed before Host presentation, the Host retains one stable answer
     until commit acknowledgement, and Answered is committed before CommittedUserAnswer.
     Host ack success is followed by canonical Acknowledged. Recovery reuses the same ids:
     Asked-only resolves the submission, while Answered-without-Acknowledged replays the
     idempotent ack and records Acknowledged before normal admission, so retention cannot orphan.

I78  StoreIdentity identifies a persistence namespace/generation, not one composition.
     Each Session summary/header/genesis carries exact composition/catalog/schema identity;
     query classifies a valid foreign identity as IncompatibleComposition before event
     decoding, while CorruptStore is reserved for contradictions or invalid events that
     claim the current exact identity.

I79  rust-agent-session is compiled as a lower-level lightweight API before
     rust-agent-agent in Phase 2. Its graph never imports agent, and the later Session
     plane adds providers behind that contract without making the agent consumer precede
     its required error/query/DTO definitions.

I80  every local path-backed Durable persistence provide declares the required
     resource-namespace-bootstrap-local marker and uses one projected prepared descriptor/
     anchor for both admin and read facades. StoreIdentity derives only from that descriptor;
     raw Config paths are never opened before projection or reopened after identity checks.

I81  native TLS belongs to NetworkConnector. A one-use handshake grant authorizes only
     bounded TLS bytes for the exact connected hop/SNI/ALPN/trust policy; only verified peer
     identity creates ConnectedOutboundHop/AuthorizedStream, after which every HTTP logical
     use still requires a fresh identity-bound NetworkUseGrant. HTTPS-proxy and tunneled-origin
     TLS are separate transitions and cannot reuse a grant or peer identity across stages.
```

其中 I3/I11 的验证对象是 generated dependency graph，而不是“某段代码没有被调用”；I10 则在 resolver 的 target predicate 阶段 fail。

## 53. 最终验收标准

### Architecture

- `rust-agent-core` 仅保留轻量共享类型。
- 独立 generated composition crate只能通过 runtime-api签发的 opaque `ScopeAssemblyBuilder/BindingAssembly`调用 exact adapter并取得 API-owned `Assembled*Binding` envelope；context、stamp receipt与record不可拆分，fresh root彼此隔离，generated caller/Component/Host均无法用自定义 witness或clone stamp伪造已记录 binding。
- Ephemeral creation mode只在 exact selected persistence provider声明并通过 `ephemeral-creation=staged-known-outcome`时生成；directory staged publication不等于 genesis/query publication，admission必须等 known-outcome commit成功。
- `driver-direct` 可在无 tools/session/memory 条件下以 volatile request journal 独立工作，并能在 generated Durable AgentContext 下无旁路地提交 RequestPrepared。
- `driver-tools` 的 model-origin tool call 只能通过 plan/journal/seal/execute-prepared，Durable ToolCall 未 confirmed committed 时 policy/approval/provider 均零调用。
- Tool loop 可从 binary 完全删除。
- Session persistence、projection、query、title 与 event-log implementation 可从 binary 完全删除；可选 API DTO 不构成启用 Session plane。
- Memory 可从 binary 完全删除。
- MCP/Web/Shell/Process 等高风险 provider 可从 dependency graph 完全删除。
- Consumer 不直接依赖 provider。
- API crate graph保持 `extension-api → agent → session → runtime-api → core` 单向无环（允许 agent直接依赖 core/runtime-api）；shared lifecycle intent/allocation error只有 runtime-api一个定义 owner，session public type closure不引用 agent，agent graph不引用 extension-api。
- Phase 2先交付并独立编译P0轻量`rust-agent-session` API，再编译`rust-agent-agent`；Phase 5只补event/provider实现，不能倒置该依赖。
- Session list明确报告per-Session composition/catalog compatibility；合法foreign Session不作为store corruption，且不会用current catalog解码。
- ToolCallPolicy/ToolRiskRule不能通过 public字段、struct literal、Default或serde构造超限状态，所有 retained policy state先经过 bounded builder。
- rust-agent core/API/Component 不依赖任何 UI/application framework，也不存在 framework-specific Capability、resolver fact 或 generated rust-agent Cargo feature。
- App / Session / Agent runtime ownership 清晰。
- Agent publication transaction 不暴露半初始化实例。
- Child Agent 只能得到 parent effective authority 的确定性投影，不能借 Registry fallback、未过滤 contributor 或 resume 恢复被删除能力。
- Subagent spawn/continue只能消费 exact parent/provider binding对完整 draft签发的 allocated request；volatile `SubagentOperationId`绑定 current lifecycle nonce且不可 cold replay，Durable id绑定 stable parent lineage/provider和 committed recovery mapping并可在新 nonce下恢复。In-process child只能通过 owner-scoped `ChildAgentFactoryBinding`签发 Agent lifecycle operation，不能伪造 ID或取得 raw factory/AppHandle。

### Composition / Build

- `minimal-pure / minimal-remote / cli-readonly / web-native` 在 resolver 判定全部 selected Production Component 支持的每个 CI target composition/lock/build；`cli-coding` 在声明的 Linux targets 构建，`web-wasm` 在 `wasm32-unknown-unknown` 构建。
- `web-native` 包含 `tool-web + web-http-native + web-search-deepseek`；`web-wasm` 包含 `model-host + tool-web + web-fetch-host + web-search-host`，不含 direct HTTP/secret provider。
- `cli-readonly`/`cli-coding` 的 local filesystem closure包含 exact `resource-namespace-bootstrap-local` Component；删除或 target/key不匹配时 resolver明确 unsatisfied。
- Resolver 对所有启停/候选回退提供 provenance explain。
- Resolver 对小图通过 brute-force oracle 完整性测试。
- generated Cargo.toml 可读、最小、稳定。
- generated Cargo.lock 可审计，production build locked。
- discovery/lock/build 使用同一 hashed canonical Cargo resolution record和 isolated Cargo home；patch/replace/named registry/ambient或 ancestor config不能改变 standalone graph。
- generated composition.rs 可读，无 runtime service locator。
- library/wasm HostBindings、显式 `RuntimePrimitives` build ABI、接收 selected constructor 的 bin Host entry/wasm Host export helper ABI 通过 generated compile fixture；Host boundary 不直接依赖 adapter，library 在非 Tokio Host executor 上仍只使用注入 driver。
- 同进程 Native Rust、同一 Rust WASM module、JavaScript/`wasm-bindgen` 与 Native backend + WebView IPC 四类 Host topology 通过 framework-neutral contract fixture；JavaScript topology发布的是由 policy-pinned wasm-bindgen产生且完整计入 digest/SBOM的可调用 bundle，而非 raw Cargo cdylib；framework 名称不改变 resolution/composition identity。
- bin/library/wasm 分别满足 exactly-one Host entry/no Host boundary/exactly-one Host export，并都选择 exactly-one target-compatible、empty-security runtime adapter；adapter constructor/primitive/source/build requirements 与 Host boundary compatibility 均进入 manifest/gate。
- `host-cli` 只匹配 Linux/macOS/Windows desktop target，第一版仅 Linux tier为 Production；iOS/Android/其它 native target的 bin composition在 Cargo前返回 Host boundary `UnsupportedTarget`，移动端只能使用经过产品验证的 library Host集成。
- library composition 通过 emitted source、唯一 Host alias、pre/post integration receipt 和 product executor attestation 进入独立 Host Cargo graph；不同的现有 emitted tree 只允许 offline `--replace`，online rollout 使用新 versioned directory，不宣称跨平台原子替换非空目录。
- library Host pre/build/post分别固定 standalone/final/observed schema-2 `HostCargoUnitGraph`；cross-compile的 build-host build-script/proc-macro unit、Host编译但分别服务于build-host/composition-target context的build-script execution和 composition-target artifact unit按各自 target facts与 exact feature set审计，package级 `cargo metadata --filter-platform`不能替代 unit证据。
- production build 的完整 policy、sandbox backend、concrete input/executable/environment-role runner mapping 与 attestation 可复验，path-free `BuildEnforcementIdentity` 与 canonical `build-manifest-digest` 可独立重算并进入 build-output identity；attestation 同时绑定 composition/output/manifest digest，development artifact 不可发布。
- Phase 1A development runner 与 Phase 1B Linux production runner 的 artifact/attestation 明确分轨；没有通过 escape suite 的 Host 不能生成 `deployable=true`。
- same normalized input（含 target facts/custom spec与 Cargo resolution record）→ same composition hash；相同 triple但不同 target facts/spec不能共享 identity，production rustc必须复现 exact digest。
- `environment` 仅参与 composition resolver；generated Cargo target dependency 不含自定义 environment cfg，environment-specific implementation 由独立 Component package 表达。
- Cargo optional dependency/feature不发生高风险实现泄漏；emitted first-party每个Host/Target unit及shared Host unit feature exact，external shared additive delta仅限不触达build-unit输出的Target-library unit并经exact selector policy审计；产品build-unit下游runtime contribution全部进入最终effect union。

### Security

- readonly profile 无 write/process/remote-exec provider。
- minimal-pure 无 network/secret/process/storage heavy dependencies。
- 每个声明 production-supported 的 platform sandbox provider 在真实目标平台有独立 regression tests。
- credentials 不进入普通日志/session/build manifest。
- composition runtime security policy 能在 resolver 阶段拒绝非法 runtime effect；BuildExecutionPolicy 独立拒绝无法满足或越权的 build requirement。
- security manifest 分别可审计 Component runtime ceiling、lifecycle、per-provide/binding effects、deferred AgentFactory 的空 App binding 与逐 template effect plan、runtime-adapter empty ceiling、Host boundary runtime ceiling 及 component/adapter/host/final compiled runtime effects，并验证 subset/union 关系；adapter/Host boundary effects 不进入 AgentAuthority；build manifest 独立审计逐 direct root package/union build requirements 及其 path-free logical item identity，concrete policy mapping/trust 只在独立 attestation 中审计。
- library product attestation额外记录 build-host/target/planner、standalone/final/observed unit-graph digest、baseline/actual shared-unit features、approved unit/edge delta closure、HostFeatureUnionPolicy digest、attribution/source-semantics-evidence/reviewer-policy digest、host feature effects/build requirements与 `product_compiled_runtime_effects`；这些字段不回写 composition hash或 AgentAuthority。
- generated runtime artifact 内的 mandatory API/infrastructure 不直接产生 runtime effect；namespace locator I/O 只经 authority-projected、stamped bootstrap Component，Durable operation allocation只经 selected persistence Component，effectful transport/FFI 只能存在于已计入 ceiling 的 Component/Host boundary。
- native provider不能绕过NetworkConnector/HttpClient直接链接transport；DNS/socket/proxy/TLS只能由connector拥有，HttpClient只拥有HTTP层。
- outbound logical intent在DNS/proxy/socket前授权，每个解析地址、重连、redirect、Happy-Eyeballs与proxy hop都需要独立post-resolution grant；HTTPS还必须在任何handshake bytes前消费exact hop/SNI/ALPN/trust-bound handshake grant，verified peer identity后才能形成dormant connection。首次request与每个pooled/H2/H3 stream checkout还需exact caller/origin/proxy/verified-identity/connection-bound fresh use grant，禁止cross-origin coalescing。Pre-resolution deny时resolver调用数为零，remote-DNS proxy未获`TrustedProxyResolution`时拒绝；跨origin的body-preserving redirect默认在destination side effect前拒绝。
- subprocess 拒绝 authority 不匹配、digest 不匹配或超过 confinement ceiling 的 spec。
- 未经 ToolExecutor 授权无法构造 CodeExecutionPermit，未经 AgentHandle dispatch与confirmed `CommandInvocationPrepared`无法构造 CommandPermit/CommandToolGrant；raw Command handler还要求confirmed `CommandInvocationDispatchPrepared`。Permit前只执行runtime-owned declarative policy与accounted journal gate、不能调用Command Component classifier，借用型tool session不能逃逸authority future。
- Durable UserInteraction在Asked confirmed前不调用Host，Answered confirmed前不向driver/model暴露answer；provider必须按stable answer operation保留submission到commit ack，facade在ack成功后提交Acknowledged。Answered-without-Acknowledged在live/cold recovery中只重放幂等ack并补原stable ack batch，不重新present或收集answer；raw answer不能绕过journal proof进入model history。
- runtime root/parent/request authority 只能求交；任何 effect/key/contributor/confinement/budget widening 在新 Session/Agent identity 分配与其 scoped provider initialize 前失败；App lifecycle 由预先验证的 root authority 承担。
- Durable authority descriptor绑定 filesystem及其它 configured resource namespace的 redacted commitment；root/exact child bootstrap projection 必须先于任何 locator I/O，只有仍获授权的 route 才经 accounted bootstrap Component 产生 schema-owned descriptor 和 local root anchor，mandatory infrastructure 零 locator I/O；final authority、identity、普通 factory/initialize 只能随后发生。Same-composition RuntimeConfig把 root/tenant从 A 改到 B时，即使没有 subprocess/sandbox capability也必须在 resume publication前失败。

### Runtime correctness

- tool cancellation 能停止新 dispatch 并正确处理已启动 side effect。
- process cancellation 杀完整 process tree。
- scoped tool/prompt 不跨 Agent 泄漏。
- teardown drain owned resources。
- persistence crash recovery 可恢复合法 SessionLog。
- JSONL Durable provider 使用 store-fenced 单一权威 commit journal 原子携带 event/locator/terminal mutation，所有 per-session/global index 都能在 crash 后按 high-water 重建且并发 Session 不丢更新。
- Durable lifecycle operation在任何store allocation mutation前必须由caller持久化never-reused recovery key/canonical draft，并seal完整规范化request及request-specific authority/template/namespace projection；allocation是只接受含该key的opaque sealed draft的async/fallible store serialization operation。两个App/进程与重启不能复用id或key；首次成功返回前exact `key → id`与fingerprint-bearing Reserved已durable。Counter exhaustion/store failure不得构造request或回退到process-local id；response unknown或return后id补写前崩溃只可以same-key exact resealed draft重试并取回原id。Reservation后、genesis/ResumePrepared前崩溃以same key/id + exact resealed draft恢复，任一authority/request差异冲突，genesis/ResumePrepared只原子消费且不改写reservation。
- Subagent volatile operation id只属于 current `AgentLifecycleNonce`；Durable id不含 nonce，必须在 raw provider前以 stable parent lineage、provider identity、recovery key和完整 fingerprint写入同一 SessionLog。Cold resume从 canonical operation projection恢复原 id并绑定新 live admission owner；wrong lineage/provider/fingerprint冲突，unknown不换 id重放。
- NewEphemeral genesis 在 gated activation 成功前不进入 authoritative event/query/session index，任何 rollback 都 abort staged transaction，不留下 genesis-only session；NewDurable creation 以 AgentCreationCompleted/SessionEnded(CreationFailed) 区分成功与失败，genesis-only recovery 不开放 admission。
- Durable resume 以 AgentResumePrepared/Completed/Failed 表达唯一 attempt/terminal，Completed 前和 commit unknown 期间不开放 admission。
- 每种 AgentDriver 的 Durable model stream 都只能消费已由同一 SessionLog durable commit 的 PreparedModelCall，且 durable ModelRequest 可从 SessionLog 重建；multiple-provider runtime 可显式选择 default 或 explicit-per-request，后者缺 route 在 journal/provider 前失败。
- 每种含 tools 的 Durable AgentDriver 都只能执行已由同一 SessionLog durable commit 并由 paired authority seal 的 exact ToolCall。
- 每个Durable command在permit前提交Prepared、handler前提交DispatchPrepared、返回前提交唯一Finished；Prepared-only/DispatchPrepared-only crash分别投影`InterruptedBeforeDispatch`/`OutcomeUnknown`，均不自动重放。
- 每个Durable human answer以stable interaction/answer operation写入canonical `Asked → Answered → Acknowledged`；只允许已由Answered commit证明的`CommittedUserAnswer`进入后续`RequestPrepared`。Cold recovery对Asked-only复用原submission，对Answered-without-Acknowledged重放同一幂等ack并补同一stable ack batch；不能换id/回答、再次present，或在pending ack backlog未有界解析时开放相关admission。
- Durable resume 仅接受 exact composition hash 与 exact SessionEventCatalog digest；任何未知 event 拒绝，只有 catalog-known Informational event 可被无关 projection 跳过。
- Mixed-composition persistence store的summary/header/genesis identity可重建且先于event decode校验；foreign Session查询返回`IncompatibleComposition`，只有current exact identity下的unknown/mismatch才返回`CorruptStore`。
- 更窄 authority 的 Durable resume 在 publication 前提交 monotonic authority epoch；每个 `RequestPrepared` 的 epoch/digest 都能解析到 exact 历史 descriptor。
- Durable stored/current resource namespace只按 schema-owned exact rule比较；不同 namespace不能静默 rebind、借用相同 Host id或被 confinement digest掩盖。
- Durable writer fencing 阻止双写，Agent(AppParent)/Agent(SessionParent) 两种 template 独立验证。
- same-composition live handoff的每个初次resume operation必须由执行resume的new App对应Host先持久化recovery key/draft，再seal完整draft/authority projection，以same key向同一selected store await allocation/读回fingerprint-bearing Reserved，并在调用前补写id/fingerprint；aggregate concurrent + shared handle identity验证通过时可预构造new App并在关闭old handle前完成该流程，否则先关闭/排空全部旧Agent并确认writer lease、关闭old App释放独占资源，build new App后才pre-journal/seal/allocate/save。Allocation unknown或id补写前process loss只可same-key重新seal/allocate取回exact token；release unknown、旧owner仍活跃、old-App/volatile preallocation、换key/id/request或先resume均fail closed。
- PublicationDirectory 原子发布/移除配对 entry；post-commit observer 使用预留 bounded queue 和 timed cancellation，slow/never-ready/error callback 不阻塞 activation、rollback、teardown 或 shutdown；panic containment 仅对通过 `panic=unwind` compile/attestation gate 的 in-process observer artifact 声明，abort/no-unwind 组合必须拒绝构建。
- SessionObserver 使用每个 live Session writer 一个 batch/byte 双界、单 worker dispatcher；首次 confirmed append 只做一次 nonblocking enqueue/drop decision，overflow、timeout、error或可隔离 panic不改变/延迟 Committed outcome，shutdown deadline 后没有 callback task 越过 Session owner teardown，cold resume 不补发。
- Durable PlanMode batch commit resolution、projection、resume 与 tool policy 使用同一 mode generation。
- Native/library/WASM handle 的 `id/status/send/targeted-cancel/event-feed/query/command/shutdown` 生命周期语义一致且不暴露 raw Agent；feed atomic baseline、Agent 级 aggregate subscriber/events/bytes admission budget、Lagged/resync、Sessionless gap 和 Closed 通过并发测试，session listing 只经 bounded snapshot-cursor `SessionReadStore` index。

### Porting

- AINS 关键 filesystem/sandbox/network/MCP/memory tests 被迁移。
- 旧 AgentKernel/ToolRuntime/ModelClient 结构没有被整体复制。
- AINS adapter 在 rust-agent 外部。
- AINS Host的shared dependency feature union逐Cargo unit审计：Host-unit delta拒绝，合法Target-library delta才使用checked-in HostFeatureUnionPolicy且product-only effect有exact source-semantics evidence；AINS build-unit下游runtime contribution进入product effect union。UI仅使用bounded feed/query与exact request targeted cancel；live Agent切换按manifest选择concurrent/shared-handle或stop-old-app/Redb顺序。
- 具体 framework 仅作为 product adapter/example 描述；任何正式 framework/version 支持声明都有产品侧 checked-in fixture、真实 target CI 与匹配的 integration attestation。
- AINS 删除旧 rust-agent 后功能回归通过。

### Product Independence

在声明支持 `build-policies/ci-linux.toml` 的 Linux reference runner 执行：

```bash
git clone <rust-agent-url> rust-agent
cd rust-agent
rustup target add wasm32-unknown-unknown
cargo test --workspace
cargo build -p rust-agent-cli
./target/debug/rust-agent compose --workspace-manifest Cargo.toml --profile minimal-pure \
  --target x86_64-unknown-linux-gnu --environment server --build-kind library \
  --runtime-adapter runtime-tokio --lock \
  --write-ref .rust-agent/refs/minimal-pure.ref
./target/debug/rust-agent build --composition-ref .rust-agent/refs/minimal-pure.ref --locked \
  --execution-policy build-policies/ci-linux.toml
./target/debug/rust-agent emit-integration \
  --composition-ref .rust-agent/refs/minimal-pure.ref \
  --output tests/host-integration/generated --replace
./target/debug/rust-agent verify-integration \
  --host-manifest tests/host-integration/Cargo.toml \
  --dependency generated-agent --composition-ref .rust-agent/refs/minimal-pure.ref \
  --phase pre --write-receipt tests/host-integration/target/integration.pre.json \
  --execution-policy build-policies/ci-linux.toml
./target/debug/rust-agent build-host \
  --host-manifest tests/host-integration/Cargo.toml \
  --dependency generated-agent --composition-ref .rust-agent/refs/minimal-pure.ref \
  --pre-receipt tests/host-integration/target/integration.pre.json --locked \
  --execution-policy build-policies/ci-linux.toml --bin host-integration-fixture \
  --write-attestation tests/host-integration/target/host-build.json
./target/debug/rust-agent verify-integration \
  --host-manifest tests/host-integration/Cargo.toml \
  --dependency generated-agent --composition-ref .rust-agent/refs/minimal-pure.ref \
  --phase post --pre-receipt tests/host-integration/target/integration.pre.json \
  --executor-attestation tests/host-integration/target/host-build.json \
  --execution-policy build-policies/ci-linux.toml \
  --write-attestation tests/host-integration/target/integration.post.json
./target/debug/rust-agent compose --workspace-manifest Cargo.toml --profile cli-coding \
  --target x86_64-unknown-linux-gnu --build-kind bin --lock \
  --write-ref .rust-agent/refs/cli-coding.ref
./target/debug/rust-agent build --composition-ref .rust-agent/refs/cli-coding.ref --locked \
  --execution-policy build-policies/ci-linux.toml
./target/debug/rust-agent compose --workspace-manifest Cargo.toml --profile web-wasm \
  --target wasm32-unknown-unknown --build-kind wasm --lock \
  --write-ref .rust-agent/refs/web-wasm.ref
./target/debug/rust-agent build --composition-ref .rust-agent/refs/web-wasm.ref --locked \
  --execution-policy build-policies/ci-linux.toml
```

全过程不需要 clone AINS。

## 54. 最终系统定义

`rust-agent` 不是 Rust 版 Cordis，也不是 AINS 内部 Agent crate，更不是一组由 Cargo feature 拼出来的“大一统 Agent”。

它被定义为：

> 一个以 **Capability Graph + Static Dependency Composition + Minimal API Spine + Typed Capability Interfaces + Composition Compiler + Deterministic Constraint Resolution + Scoped Static Composition + Event-Sourced Durable Runtime** 为核心的跨平台 Rust Agent Runtime。
>
> 它借鉴 deepseek-harness 的 Service Definition / Provider / Consumer、scoped ownership、guarded execution 与 event-sourced session 设计，但利用 Rust/Cargo 把“组件是否存在、依赖闭包、安全效果、目标平台裁剪”前移到构建期；运行时只管理已经进入 binary 的 provider registry、Agent/Session scope、生命周期和行为配置。

Capability Graph 与 Static Dependency Graph 必须明确分层：

```text
Capability Graph
  Component --provides--> Capability <--requires-- Component

Static Dependency Graph
  Root Components → Dependency Closure → Generated Cargo Packages → Binary
```

前者决定能力如何组合、替换和消费；后者决定哪些代码实际存在并被编译/链接。Composition Compiler 负责把前者的解析结果确定性地投影到后者。

最终架构：

```text
                              rust-agent
                                  │
                   ┌──────────────┴──────────────┐
                   │                             │
              Stable API Spine             Capability APIs
          core / model / agent / tools      fs / shell / session /
                   │                       memory / web / ...
                   │                             │
                   └──────────────┬──────────────┘
                                  │
                          Selected Components
                                  │
                    Derived Providers / Consumers / Middleware
                                  │
                         Runtime Scope Factories
                                  │
                  App Scope → Session/Agent Scopes
                                  │
                    Static / Scoped Runtime Binding

──────────────────────────── Build-Time Control Plane ────────────────────────────

rust-agent.toml + Profile + Target + Runtime Security Policy
                         │
                         ▼
            Cargo Capability / Component Metadata
                         │
                         ▼
                Composition Compiler
                         │
                         ▼
          Deterministic Constraint Resolver
                │                    │
                │                    ├─ BindingKind resolution
                │                    ├─ provider backtracking
                │                    ├─ scope validation
                │                    ├─ target validation
                │                    └─ security constraints
                ▼
                 Resolution + Provenance
                         │
            ┌────────────┼──────────────┐
            ▼            ▼              ▼
     Generated       Generated       Composition /
 Cargo.toml/lock   config/composition Build/Security Manifest
            │            │
            └──────┬─────┘
                   ▼
             cargo build
                   │
                   ▼
 Minimal-Pure / Minimal-Remote / Readonly / Coding / Web-Native / Web-WASM / Product
```

Runtime：

```text
App Scope
│
├── Model/Web/Subagent registries
├── Persistence/Credentials/Telemetry
└── AgentFactory
       │
       ▼
prepare unpublished Agent/Session
       │
       ▼
initialize Session/Agent Scope
       │
       ▼
validate + stage complete publication transaction
       │
       ▼
before_publish validation
       │
       ▼
commit NewDurable genesis / Durable resume Prepared;
keep NewEphemeral genesis staged and query-invisible
       │
       ▼
atomic PublicationDirectory generation + nonblocking contained-notification enqueue
       │
       ▼
activate behind closed ScopeAdmissionGate
       │
       ▼
commit/index NewEphemeral genesis or required Durable lifecycle success terminal
       │
       ▼
open driver/command admission
       │
       ▼
Request / Model / ToolExecutor / SessionLog
       │
       ▼
owned shutdown + reverse teardown
```

最终落地原则只有四条：

1. **架构从零按正确边界建立，不让 AINS 产品耦合进入新 runtime。**
2. **只迁移已经在对应 target 验证的安全行为；未验证平台实现保持 fail-closed。**
3. **组件删除以 generated Cargo dependency graph 为事实，不以 runtime disable 或 negative feature 为事实。**
4. **运行时灵活性通过 typed registry、scope、factory 和配置实现，但不能突破构建期已经确定的 capability/security 边界。**

当这些约束全部成立时，AINS、CLI、Server、Desktop、WASM、Mobile 和第三方项目都只是 `rust-agent` 的不同 Host/Integrator；`rust-agent` 本身保持独立、最小、可裁剪、可审计和可长期演进。
