# AINS migration inventory

This inventory records behavioral inputs inspected from AINS and the rust-agent
capability boundary that replaces them. No rust-agent test or package depends on
the checked-out AINS tree.

| Phase | AINS input | rust-agent owner | Migrated behavior | Status |
|---|---|---|---|---|
| 3.1 | `AINS/crates/rust-agent/src/tools/mod.rs` | `rust-agent-tools` | Object-safe Tool contract, immutable definition capture, opaque handler registration | Complete |
| 3.1 | `AINS/crates/rust-agent/src/tools/outputs.rs` | `rust-agent-tools` | Inline output item/byte/depth admission before retention; UTF-8-safe error bounds | Complete |
| 3.4 | `AINS/crates/rust-agent/src/tools/runtime.rs` | `rust-agent-tools` and `tool-executor-guarded` | Rewritten as sealed provider snapshots, a private bounded registry, pure model-origin planning and an exact ToolCall-proof-gated permission/approval/permit/provider path; the legacy public ToolRuntime/handler map is not copied. Generated AgentContext wiring and scheduling remain separate Phase 3 slices | Partial |
| 3.5 | New architecture boundary | `rust-agent-tools` and `tool-executor-guarded` | Bounded typed pre/around/post/observer middleware with immutable guarded context, deterministic order, reverse exit, stage-exact failure policy, read-only cancellation state, fixed deadline lineage and observer failure containment; no universal string hook bus or output fabrication path is introduced | Complete |
| 3.6 | `AINS/crates/rust-agent/src/tools/runtime.rs` composite-tool behavior | `rust-agent-tools` | Nested tools receive a non-cloneable invariant-lifetime borrowed session from the exact current permit/context pair; calls retain the sealed registry and root lineage, re-enter schema/policy/approval/middleware/output guards, tighten effects, and reject cancellation, depth/count/cycle or closed-owner violations before raw provider dispatch. Explicit cost/concurrency scheduling remains a later Phase 3 slice | Partial |
| 3.7 | New Command-to-Tool authority boundary | `rust-agent-commands` and `rust-agent-tools` | An exact Command permit/context pair derives a non-cloneable invariant-lifetime Tool grant with bounded call/output/effect authority. Tool preparation validates Agent/lifecycle, executor identity and the exact clock/sleep projection, then enters the same guarded dispatch; the complete non-empty CommandDispatcher and its journal-backed issuance remain assigned to later phases | Partial |
| 3.1 | `AINS/crates/rust-agent/tests/tool_runtime.rs` | `rust-agent-tools` unit and compile-fail suites | Registration, output budget and private-boundary regression shape without legacy `AgentKernel`/`ToolRuntime` imports | Complete |
| 3.2 | `AINS/crates/rust-agent/src/policy/permission_engine.rs` | `rust-agent-policy` and `permission-default` | Three-state allow/ask/deny seam; the default provider allows read-only actions and requires approval for higher-risk actions without importing mutable AINS mode/path state | Complete |
| 3.3 | `AINS/crates/rust-agent/src/context/prompt_pipeline.rs` | `rust-agent-prompt` | Deterministic contributor order is replaced by an identity-bound, transactional, bounded contributor contract; concrete prompt sections remain Phase 6 Components | Partial |
| 3.3 | `AINS/crates/rust-agent/src/context/compact.rs` | `rust-agent-prompt` | Conversation compaction, tool-result pruning and token metering are split into bounded capability seams; AINS algorithms and hidden model coupling are not ported in Phase 3 | Partial |
| 3.3 | `AINS/crates/rust-agent/src/perception/mod.rs` | `rust-agent-attachments` | Attachment bytes/media identity become a content-digested, range/budget/cancellation-checked storage contract; perception providers remain out of scope | Partial |
| 3.3 | New architecture boundary | `rust-agent-spill` | Agent-owned ephemeral spill references, expiry, bounded range access and owner teardown are separate from durable Attachments | Complete |
| 3.3 | New architecture boundary | `rust-agent-telemetry` | Closed structured event/attribute vocabulary prevents arbitrary secret-bearing strings and keeps sinks opaque | Complete |
