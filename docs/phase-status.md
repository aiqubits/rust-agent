# Implementation phase status

Status is evidence-based: a phase is complete only when every acceptance item is
represented in `docs/invariant-tests.md` and all applicable gates pass.

| Phase | Status | Evidence / remaining gate |
|---|---|---|
| 0 — repository and contract | Complete | Rust/Cargo 1.97.1 is synchronized across local toolchain targets, workspace MSRV, generated manifests and CI; workspace/deny/ADR, effect-free core/runtime contracts, checked lifecycle identities and reservation schema, closed metadata/target parsing, resource-namespace bootstrap graph, Host/runtime metadata, canonical Host Cargo unit-graph schema, privacy compile-fail tests and every Phase 0 acceptance mapping pass. The lightweight Session API remains a Phase 2 deliverable; Phase 0 has an automated absence guard so no Agent dependency is exposed early. |
| 1A — generated graph proof | Complete | Deterministic bounded resolver, property/oracle tests, source snapshots, real Cargo graph absence/presence, manifests, locked development build, controlled build requirements, integration emission/verification, independent Native Host/type-identity tests, same-module Rust WASM Host compilation, JavaScript WASM post-link packaging/Node execution, native backend/WebView IPC isolation, the six-target library matrix and the external shared-feature Host fixture pass. |
| 1B — Linux production build | In progress | Closed BuildExecutionPolicy/BuildEnforcementIdentity and HostBuildInputClosure schemas, typed artifact selection, exact pinned-Cargo planner invocation/unit-graph-v1 capability gates, Cargo.lock source closure/checksum/revision observations and non-deployable pre/build-host/post input receipts are implemented. A trusted unit-graph-enabled Cargo 1.97.1 runner and raw-to-HostCargoUnitGraph normalizer, isolated fetch executor, closure snapshot materializer/mount verifier, namespace/Landlock/seccomp backend, actual unit observer, descendant escape suite, completion-handle signer, signed production pre/build-host/post and deployable output remain required. |
| 2 — minimal runtime spine | Not started | Phase 1A gate passed; implementation must provide the real minimal runtime behavior and must not be represented by empty product crates. |
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
- real external Target-library `hex` feature unification (`alloc` standalone, `alloc+std` in an
  independent product Host), cross-checked between Cargo planning and actual rustc unit
  invocations, with first-party/Host/generated/native/closure/effect/provenance rejection;
- exact HostFeatureUnionPolicy closure and identical pre/build-host/post policy digests in a
  non-deployable development receipt, plus product build-unit downstream contribution accounting
  in the Host-root ceiling and final product runtime-effect union;
- registry use derived from the locked source set, with an explicit isolated offline cache required
  for every generated graph that resolves registry packages;
- independent Rust Host compilation and duplicate API source type-identity rejection;
- framework-neutral topology validation derived only from build kind, target facts and ABI boundary;
- same-module Rust WASM Host compilation through the emitted library alias with no JS export or
  `wasm-bindgen` dependency;
- JavaScript WASM generation with an identity-bound direct Host tool requirement, exact pinned
  `wasm-bindgen` crate/CLI protocol, explicit offline registry cache, closed post-link output set,
  callable `WasmAppHandle`, committed size budget, CycloneDX artifact coverage and recomputed
  build-manifest/build-output digests;
- pre-link rejection for a missing/wrong-kind/wrong-digest/wrong-version postprocessor policy,
  protocol drift and ambient PATH substitution, plus packaging rejection for raw-only, missing,
  mutated, symlinked or unaccounted output trees;
- native backend IPC command/channel mapping with bounded nonblocking delivery, exact request-id
  preservation, closed/full failure paths and a frontend Cargo graph that cannot import runtime
  internal types;
- Linux, WASM, Android, iOS, macOS and Windows product-neutral library cross-compilation;
- development artifact/integration production rejection and end-to-end CLI mutation checks.

No test result above is evidence for Phase 1B deployability or for a Phase 2+ runtime capability.

## Phase 1B evidence in progress

- the Linux production policy parser rejects unknown fields, non-Linux Host selectors, invalid
  executor identities, non-Ed25519 signers, invalid reviewer thresholds, redirects, non-HTTPS origins,
  ambient/secret environment roles, Host-path environment values, unpinned Rust/Cargo versions
  and derived executables that do not inherit the sandbox;
- normalization is ordering-independent and freezes separate domain digests for the complete
  runner/fetch/trust mapping and the path-free enforcement identity;
- only build-requirement-selected executable, read-input and environment identities enter the
  enforcement projection; exact build/target facts, Cargo resolution/config, profile, artifact,
  panic strategy, rustc settings and prefix-remap schema are also bound, while missing and
  cross-kind mappings fail closed;
- concrete Host path, fetch mirror, policy id and signer/reviewer/helper rotation change the full
  policy digest but not build-output enforcement identity, while selected tool/input/environment
  content or enforcement semantics change the latter.
- `HostBuildInputClosure` requires the Host manifest/lock/config chain, Host package and emitted
  composition snapshot trees, Cargo resolution, target facts/custom spec, rustc settings and any
  feature-semantics evidence as role-checked logical items under one canonical read-only metadata
  contract; missing, duplicate, path-escaping, wrong-kind or context-mismatched items fail closed;
- the closure cross-checks the normalized production policy and requirement-minimal enforcement
  identity, pinned Cargo/rustc planner identity, build-host/target/profile and standalone/final
  Cargo unit-graph digests. Trusted feature evidence must match a reviewer policy from the same
  normalized BuildExecutionPolicy;
- development pre/build-host/post receipts bind the exact same closure/policy/enforcement/graph/
  feature-delta inputs and are permanently `deployable=false`; stage reordering, mutation or mixed
  closures are rejected.
- final Host artifact selection is a closed package plus `lib`/named `bin`/`example`/`test`/`bench`
  value, has its own domain digest and is a required HostBuildInputClosure canonical-record item;
  invalid names, missing records and selector drift fail before planning;
- standalone and final planning requests derive their exact manifest, explicit Cargo config,
  Host closure aggregate, target, profile, selector, panic strategy, Rust/Cargo 1.97.1 identity,
  isolated logical environment and fixed `--locked --offline --unit-graph -Z unstable-options`
  argv from the normalized closure. The unit-graph-v1 envelope is closed, bounded, context
  checked, acyclic and mutation detecting;
  stable Cargo's unavailable interface is an explicit unsupported result and never falls back to
  `cargo metadata` or executes build.rs;
- Cargo.lock v4 registry checksums, HTTPS git precise revisions and path snapshot tree identities
  normalize into a domain-separated source closure. It must match the Host Cargo.lock item and
  every final Host unit package; fetched registry archive/git checkout/path snapshot observations
  require the exact locked package set and are order-independent and mutation detecting.

This evidence establishes policy, input-closure, planner/fetch input and observation contracts
only. The installed stable Cargo 1.97.1 correctly fails the trusted unit-graph capability gate; it
is not production planner evidence. No code here can authorize a production build or produce
`deployable=true` without the trusted unit-graph-enabled Cargo runner/normalizer, isolated fetch
and snapshot materializers, trusted backend, actual unit observation, escape suite and signed
attestation gates.
