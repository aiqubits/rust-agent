# AINS migration inventory

This inventory records behavioral inputs inspected from AINS and the rust-agent
capability boundary that replaces them. No rust-agent test or package depends on
the checked-out AINS tree.

| Phase | AINS input | rust-agent owner | Migrated behavior | Status |
|---|---|---|---|---|
| 3.1 | `AINS/crates/rust-agent/src/tools/mod.rs` | `rust-agent-tools` | Object-safe Tool contract, immutable definition capture, opaque handler registration | Complete |
| 3.1 | `AINS/crates/rust-agent/src/tools/outputs.rs` | `rust-agent-tools` | Inline output item/byte/depth admission before retention; UTF-8-safe error bounds | Complete |
| 3.1 | `AINS/crates/rust-agent/src/tools/runtime.rs` | `rust-agent-tools` | Deterministic registration identity and duplicate-name rejection; execution pipeline intentionally remains in later Phase 3 slices | Partial |
| 3.1 | `AINS/crates/rust-agent/tests/tool_runtime.rs` | `rust-agent-tools` unit and compile-fail suites | Registration, output budget and private-boundary regression shape without legacy `AgentKernel`/`ToolRuntime` imports | Complete |
