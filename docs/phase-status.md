# Implementation phase status

Status is evidence-based: a phase is complete only when every acceptance item is
represented in `docs/invariant-tests.md` and all applicable gates pass.

| Phase | Status | Evidence / remaining gate |
|---|---|---|
| 0 — repository and contract | Complete | Workspace/CI/MSRV/deny/ADR, effect-free core/runtime contracts, checked lifecycle identities and reservation schema, closed metadata/target parsing, resource-namespace bootstrap graph, Host/runtime metadata, canonical Host Cargo unit-graph schema, privacy compile-fail tests and every Phase 0 acceptance mapping pass. The lightweight Session API remains a Phase 2 deliverable; Phase 0 has an automated absence guard so no Agent dependency is exposed early. |
| 1A — generated graph proof | In progress | Deterministic bounded resolver, property/oracle tests, source snapshots, real Cargo graph absence/presence, manifests, locked development build, controlled build requirements, integration emission/verification, independent Host/type-identity tests and six-target library matrix pass. JS WASM post-link bundle, external shared-feature Host fixture, and the remaining framework-neutral topology fixtures are not yet delivered. |
| 1B — Linux production build | Not started | Requires trusted supervisor/backend, escape suite and signed attestation. |
| 2 — minimal runtime spine | Blocked by Phase 1A gate | Must not be represented by empty product crates. |
| 3 — tool execution plane | Not started | Starts after the Phase 1A contract is stable. |
| 4 — local execution providers | Not started | Real-target security regressions required. |
| 5 — session plane | Not started | Exact composition/catalog durable compatibility required. |
| 6 — prompt/memory/skills | Not started | Depends on the Session plane where durable state is involved. |
| 7 — network extensions | Not started | Native connector authorization tests required. |
| 8 — advanced agents | Not started | Must reuse AgentFactory/Scope/ToolExecutor. |
| 9 — AINS cutover | Not started | Requires inventory, dual-run and product attestations. |

## Current gate evidence

The Phase 0/1A baseline is intentionally development-only. Named tests cover:

- closed metadata/profile parsing, effect ceilings, scope legality and Host boundary rejection;
- deterministic CBOR/JCS inputs, target-fact digests and reproducible composition hashes;
- resolver required closure, explicit disable, security denial, conflicts, bounded backtracking,
  decision exhaustion, provenance, property cases and a brute-force small-graph oracle;
- generated source/Cargo/manifest goldens, transient Trybuild diagnostic exclusion and canonical-tree mutation detection;
- real Cargo graph removal/addition of `rust-agent-fixture-fs-read`;
- generated factory type checking and execution under a locked, offline, isolated Cargo home;
- exact build-requirement kind authorization without runtime-effect expansion;
- checked lifecycle operation/Session identity and immutable durable reservation projection;
- exact resource-namespace bootstrap derivation, construction ordering, target rejection and
  unsafe/incomplete metadata rejection;
- canonical Host Cargo unit identity, Host/Target domain separation, deterministic graph digest,
  dependency-cycle rejection and planned/observed drift rejection;
- external Target-library feature delta policy and first-party/Host/generated-output rejection;
- independent Rust Host compilation and duplicate API source type-identity rejection;
- Linux, WASM, Android, iOS, macOS and Windows product-neutral library cross-compilation;
- development artifact/integration production rejection and end-to-end CLI mutation checks.

No test result above is evidence for Phase 1B deployability or for a Phase 2+ runtime capability.
