# Implementation phase status

Status is evidence-based: a phase is complete only when every acceptance item is
represented in `docs/invariant-tests.md` and all applicable gates pass.

| Phase | Status | Evidence / remaining gate |
|---|---|---|
| 0 — repository and contract | In progress | Rust/Cargo 1.97.1 synchronization, workspace/deny/ADR gates, effect-free core/runtime contracts, checked lifecycle identities, closed target-fact/custom-target records, globally bounded catalog owners and symbolic per-target support analysis, resource-namespace bootstrap contracts, Host/runtime metadata, canonical Host Cargo unit-graph schemas and privacy fixtures are implemented. Production composition now discovers schema-owned Capability/Component/runtime/Host and direct-root build-requirement metadata from workspace package manifests through bounded, timed, offline, isolated `cargo metadata`; package/path ownership is derived from the exact workspace-member result, unknown/mixed/spoofed metadata and default-feature drift fail closed, and a real discovery round-trip is checked against the test-only catalog fixture. Phase 0 is not complete: every acceptance item still needs an exact non-wildcard invariant mapping plus a passing phase gate. |
| 1A — generated graph proof | In progress | The development-only generator/resolver/build path, path-free compose rustc executable/version/full-sysroot provenance, canonical target-fact and custom-spec snapshots with rustc/Cargo before/after drift checks, schema-owned Cargo package-metadata discovery, bounded/shared target-support analysis, bounded metadata/profile inputs, checked canonical resolution/manifests, exact Cargo.lock source projection, Cargo-config ancestor rejection, source snapshots, real graph presence/absence, integration verification, topology fixtures, target matrix and WASM packaging are implemented. Remaining gates include an identity-bound normalized catalog/resolver/generator-input commitment that lets verification rederive binding/diagnostic/effect/build-requirement attribution, generated Cargo and source closure; target-dependent Cargo dependency rewriting against the same facts; direct-serde early resource closure for remaining manifest/diagnostic/Cargo-source collections and composition-wide source bounds; a real pinned-toolchain custom-target compose/lock/build test; and completion of every exact acceptance mapping/gate. Phase 1A artifacts remain `deployable=false`; local before/after filesystem checks are not a same-UID immutable-view proof. |
| 1B — Linux production build | In progress | Closed BuildExecutionPolicy/BuildEnforcementIdentity and HostBuildInputClosure schemas, typed artifact selection, exact pinned-Cargo planner invocation/unit-graph-v1 capability gates, request-bound raw-to-HostCargoUnitGraph normalization, Cargo.lock source closure/checksum/revision observations, shared `CanonicalSnapshotTree` and raw-byte-bound closure identities, a Linux local content-snapshot materializer with atomic no-clobber publication, limited mode/mtime storage re-verification, a closed expected mount-observation verifier and non-deployable pre/build-host/post input receipts are implemented. A trusted Linux mounted-view producer/backend that observes/enforces every canonical metadata field and immutable read-only access, descriptor-relative/`openat2` resistance to malicious source/parent/staging TOCTOU and same-UID staging replacement, role-typed canonical-record semantic reparse, an isolated fetch runner, a trusted unit-graph-enabled Cargo 1.97.1 planner and exact edge-semantics producer, actual unit observer, production pre/mount/post command wiring, target/config/tool probes, signed completion-handle attestation path, namespace/Landlock/seccomp enforcement, production manifests/SBOM/output identity and the descendant escape suite remain required; this phase cannot emit `deployable=true`. |
| 2 — minimal runtime spine | Not started | Must not start until the Phase 1A gate passes; implementation must provide real minimal runtime behavior and must not be represented by empty product crates. |
| 3 — tool execution plane | Not started | Starts after the Phase 1A contract is stable. |
| 4 — local execution providers | Not started | Real-target security regressions required. |
| 5 — session plane | Not started | Exact composition/catalog durable compatibility required. |
| 6 — prompt/memory/skills | Not started | Depends on the Session plane where durable state is involved. |
| 7 — network extensions | Not started | Native connector authorization tests required. |
| 8 — advanced agents | Not started | Must reuse AgentFactory/Scope/ToolExecutor. |
| 9 — AINS cutover | Not started | Requires inventory, dual-run and product attestations. |

## Current gate evidence

The implemented Phase 0/1A baseline is intentionally development-only and is not yet phase-complete.
Named tests cover:

- closed metadata/profile parsing, effect ceilings, scope legality and Host boundary rejection;
- package-owned Capability/Component/runtime/Host and direct-root build-requirement discovery through
  bounded, timed, offline `cargo metadata`, with exact workspace-member/path ownership, empty
  default features, target normalization and a test-only catalog-fixture round-trip;
- deterministic CBOR/JCS inputs, target-fact digests and reproducible composition hashes;
- explicit compose rustc provenance binds the concrete compiler bytes, exact pinned verbose version
  and a bounded path-free digest of every regular file/directory in its reported sysroot; the
  provenance is separate from the target-fact digest but identity-bound to the composition, and
  rustc/sysroot drift after target query, metadata discovery or lockfile generation fails before
  later Cargo side effects;
- resolver required closure, explicit disable, security denial, conflicts, bounded backtracking,
  decision exhaustion, provenance, property cases and a brute-force small-graph oracle;
- generated source/Cargo/manifest goldens, preflight-bounded and streaming source snapshots,
  transient tree pruning, canonical-tree mutation detection, atomic no-clobber publication and
  fully verified exact-existing reuse;
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
  checked, request-bound, acyclic and mutation detecting;
  stable Cargo's unavailable interface is an explicit unsupported result and never falls back to
  `cargo metadata` or executes build.rs;
- verified raw unit graphs normalize into canonical `HostCargoUnitGraph` only when the Host input
  closure matches the planner request, its Cargo.lock matches the normalized source closure,
  path/registry/git package ids resolve to the exact locked source identities, the single root
  matches the typed artifact selector and a closed request/envelope-bound edge-semantics record
  covers every raw edge exactly once. Cross-compile build scripts, proc macros and their transitive
  units remain in the BuildHost domain while artifact and normal target dependencies remain in the
  Target domain; closure, lock, source, root, target kind, edge identity/kind/domain or sidecar
  schema drift fails closed;
- Cargo.lock v4 registry checksums, HTTPS git precise revisions and path snapshot tree identities
  normalize into a domain-separated source closure. It must match the Host Cargo.lock item and
  every final Host unit package; fetched registry archive/git checkout/path snapshot observations
  require the exact locked package set and are order-independent and mutation detecting.
- the shared closed `CanonicalSnapshotTree` schema sorts before domain-separated deterministic-CBOR
  identity; bounds paths/entries/per-file and aggregate bytes; rejects invalid, duplicate,
  case-fold-colliding or topologically incomplete paths; and fixes file/directory logical metadata
  to the `ReadOnlyEpochV1` contract. Raw file SHA-256, file length and any metadata drift change
  tree identity or fail closed;
- schema-1 `canonical-record` items now require a separate raw `bytes-sha256` alongside their
  semantic digest, while source-package manifests replace the old file-only records with the same
  canonical tree entries used by Host inputs. These are corrections to unreleased development
  contracts: old generated-composition goldens and identities, receipts, fixtures and closure
  identities using the old shapes are intentionally invalidated, with no compatibility or
  identity-preservation claim;
- before staging or hashing, the Linux local snapshot materializer metadata-plans and bounds the
  exact full-closure source set, source kind, entries, paths, per-file/aggregate bytes and union
  overlay, then verifies raw bytes and semantic digests. It constructs a deterministic `deployable=false`
  same-directory staging tree, projects file mode `0444`, directory mode `0555` and mtime epoch,
  reverifies stored bytes/tree/canonical manifest plus that limited projection, publishes with
  atomic no-clobber semantics and post-verifies the winner. An exact existing snapshot is reusable
  only after the supplied live sources pass preflight; conflicting or mutated content is never
  repaired or overwritten. Pre-publication rejection leaves no final destination. A failure after
  rename is reported explicitly as published-but-verification-failed or
  published-with-parent-durability-unknown, because deleting that published path would be unsafe;
- the closed mount-observation verifier binds the snapshot manifest digest, logical mount root,
  read-only claim and exact canonical entries, and rejects schema, context, entry or digest drift.

This evidence establishes policy, input-closure, planner/normalizer/fetch-observation, local
filesystem content-snapshot materialization and expected-observation verification contracts only.
The backing filesystem's mode/mtime projection is not proof of logical uid/gid, atime/ctime,
birthtime, link/device/inode/generation values or an immutable read-only mounted view. The
installed stable Cargo 1.97.1 correctly fails the trusted unit-graph capability gate; synthetic
edge semantics exercise normalization but are not production planner evidence. No code here can
authorize a production build or produce `deployable=true` without a trusted Linux mounted-view
producer/backend, descriptor-relative/`openat2` resistance to malicious source/parent/staging
TOCTOU and same-UID staging replacement, role-typed canonical-record semantic reparse, the
isolated fetch runner, trusted unit-graph planner and exact
edge-semantics producer, actual unit observer, namespace/Landlock/seccomp enforcement, signed
completion-handle attestation path and descendant escape suite. Production
`build`/`build-host`/`verify-integration` pre/mount/post wiring and mounted-view recomputation, real
rustc target-fact/custom-spec reproduction, canonical Cargo-config enforcement,
toolchain/SDK/executable digest and version probes, sandboxed WASM post-link attestation, and
production build/build-host manifests, SBOM and artifact-output identity also remain unimplemented
and therefore cannot be used as completion evidence.
