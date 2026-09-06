# Implementation phase status

Status is evidence-based: a phase is complete only when every acceptance item is
represented in `docs/invariant-tests.md` and all applicable gates pass.

| Phase | Status | Evidence / remaining gate |
|---|---|---|
| 0 — repository and contract | Complete | Rust/Cargo 1.97.1 synchronization, workspace/deny/ADR gates, effect-free core/runtime contracts, checked lifecycle identities, closed target-fact/custom-target records, globally bounded catalog owners and symbolic per-target support analysis, resource-namespace bootstrap contracts, Host/runtime metadata, canonical Host Cargo unit-graph schemas and privacy fixtures are implemented. Production composition discovers schema-owned Capability/Component/runtime/Host and direct-root build-requirement metadata from workspace package manifests through bounded, timed, offline, isolated `cargo metadata`; package/path ownership is derived from the exact workspace-member result, unknown/mixed/spoofed metadata and default-feature drift fail closed, and a real discovery round-trip is checked against the test-only catalog fixture. All 12 Phase 0 acceptance criteria have exact non-wildcard mappings, and the mapping/CI gate passes. |
| 1A — generated graph proof | Complete | The development-only generator/resolver/build path, path-free compose rustc executable/version/full-sysroot provenance, canonical target-fact and custom-spec snapshots with rustc/Cargo before/after drift checks, schema-owned Cargo package-metadata discovery, bounded/shared target-support analysis, direct-serde-bounded metadata/profile/trust/diagnostic/composition/security/Cargo-source collections, an identity-bound normalized catalog/trust-policy/evidence-byte/root-requirement generator-input commitment with resolver/attribution/generated-source/source-closure rederivation, selected-evidence snapshot verification, conservative aggregate App handoff, generated namespaced host APIs and required-field HostBindings builders, shared-host Config-field type/identity sealing with a real two-App same-identity/no-reopen external Host fixture, committed-built-in-fact Cargo target-dependency rewriting with transitive active path-package snapshots, composition-wide source entry/byte preflight before copy or hash, checked canonical resolution/manifests, exact Cargo.lock source projection, Cargo-config ancestor rejection, source snapshots, real graph presence/absence, integration verification, topology fixtures, target matrix and WASM packaging are implemented. A checked-in custom target now completes compose, lockfile generation and locked offline development build with the real pinned Rust/Cargo 1.97.1 toolchain. All 10 Phase 1A acceptance criteria have exact non-wildcard mappings, and every applicable local gate passes. Phase 1A artifacts remain `deployable=false`; immutable production mounted-view enforcement remains a Phase 1B gate. |
| 1B — Linux production build | Implementation complete; runner revalidation pending | All 12 acceptance criteria remain mapped. ADRs 0009 and 0010 close rustc's implicit self-contained LLD path through schema-4 Host configuration. ADR 0011 now binds the exact inherited `CargoDriverEnvironmentV1` into planner, build and enforcement identities, advances the backend semantic version to 5, rejects missing/changed/extra controls before Cargo, and proves the logical Cargo home is visible while ambient home and secrets remain absent. A fresh successful Ubuntu 24.04 production gate is still required before the phase or any artifact is called deployable. |
| 2 — minimal runtime spine | Not started | The Phase 1A gate has passed; implementation must provide real minimal runtime behavior and must not be represented by empty product crates. |
| 3 — tool execution plane | Not started | The Phase 1A contract is stable; no Phase 3 implementation has started. |
| 4 — local execution providers | Not started | Real-target security regressions required. |
| 5 — session plane | Not started | Exact composition/catalog durable compatibility required. |
| 6 — prompt/memory/skills | Not started | Depends on the Session plane where durable state is involved. |
| 7 — network extensions | Not started | Native connector authorization tests required. |
| 8 — advanced agents | Not started | Must reuse AgentFactory/Scope/ToolExecutor. |
| 9 — AINS cutover | Not started | Requires inventory, dual-run and product attestations. |

## Current gate evidence

The completed Phase 0/1A baseline is intentionally development-only; it does not satisfy the
separate Phase 1B production/deployability gate.
Named tests cover:

- closed metadata/profile parsing, effect ceilings, scope legality and Host boundary rejection;
- package-owned Capability/Component/runtime/Host and direct-root build-requirement discovery through
  bounded, timed, offline `cargo metadata`, with exact workspace-member/path ownership, empty
  default features, target normalization and a test-only catalog-fixture round-trip;
- deterministic CBOR/JCS inputs, target-fact digests and reproducible composition hashes;
- exact, non-wildcard mappings from all 12 Phase 0 and all 10 Phase 1A acceptance criteria to
  named runnable tests or CI gates, enforced by an explicit architecture test and CI step;
- a closed, bounded and domain-separated `generator-inputs.json` commits the exact normalized
  catalog, reviewer-policy/schema/rule-set trust projection, raw coexistence evidence bytes and
  package-owned root build requirements; selected evidence is re-read from the generated package
  snapshot, and manifest loading/full verification rerun
  resolution and rederive diagnostics, bindings, handoff, Component/Host effect attribution, direct
  build requirements, package source headers, `Cargo.toml`, `lib.rs` and WASM source, rejecting
  identity-consistent resealing and noncanonical sidecars;
- selected package manifests evaluate Cargo target selectors only against the committed rustc
  built-in facts, erase target tables into one deterministic dependency table, rewrite active path
  dependencies to stable snapshot-relative paths and recursively snapshot their bounded package
  closure. Native and WASM fixtures prove mutually exclusive helper presence/absence in the source
  tree, lockfile, filtered metadata and Cargo tree while helpers remain transitive rather than
  generated direct roots. Composition-only `environment`, Cargo `feature`, unknown/ambiguous
  dependency clauses, active optional path dependencies, target-specific build dependencies without
  committed BuildHost facts, path escape and selector/dependency/package bounds fail closed before
  lockfile generation; full verification rederives the closure and rejects a self-consistently
  resealed manifest that retains an unrewritten target table;
- explicit compose rustc provenance binds the concrete compiler bytes, exact pinned verbose version
  and a bounded path-free digest of every regular file/directory in its reported sysroot; the
  provenance is separate from the target-fact digest but identity-bound to the composition, and
  rustc/sysroot drift after target query, metadata discovery or lockfile generation fails before
  later Cargo side effects. A path-independent fixture fixes the hash vectors, while generated
  goldens rebind only validated exact-toolchain provenance and its derived record/hash so rustup
  installation bookkeeping cannot make otherwise identical schema/source snapshots stale;
- resolver required closure, explicit disable, security denial, conflicts, bounded backtracking,
  decision exhaustion, provenance, property cases and a brute-force small-graph oracle;
- generated source/Cargo/manifest goldens, direct-serde-bounded manifest/diagnostic/Cargo-source
  collections, composition-wide preflight-bounded and streaming source snapshots,
  transient tree pruning, canonical-tree mutation detection, atomic no-clobber publication and
  fully verified exact-existing reuse;
- real Cargo graph removal/addition of `rust-agent-fixture-fs-read`;
- generated factory type checking and execution under a locked, offline, isolated Cargo home;
- a checked-in target spec reproduced byte-for-byte by pinned rustc 1.97.1 and exercised through
  real compose, Cargo.lock generation and locked offline development build with pinned Cargo 1.97.1;
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
- generated host-source fields use composition-namespaced Config types and a required-field builder;
  shared-handle field paths are canonically bounded and compiled through an exact
  `SharedHostHandle<T>` sealing call, while opaque identity records bind composition/catalog/field
  sets. An external Host depending only on the emitted composition builds two Apps from one typed
  wrapper without reopening the resource, and rejects a second wrapper around the same resource;
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

## Phase 1B evidence

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
- schema-3 policy optionally declares one closed Host-linker bundle. Its linker and sorted unique
  helper ids resolve to separately digest/version-bound executables and requirements must select
  all or none. The schema-2 path-free enforcement identity binds the exact logical build-triple
  linker configuration and `COMPILER_PATH`; accepted ADRs 0009 and 0010 additionally require
  schema-4 Host-only Cargo linker/rustflag configuration, Target-only explicit sysroot flags,
  backend semantic version 5, the closed inherited `CargoDriverEnvironmentV1` and execution of only
  the selected helpers. The implementation and
  observation regressions pass locally; old schemas, missing/duplicate helpers, alternate or
  cross-kind flags and partial selection fail closed before Cargo;
- concrete Host path, fetch mirror, policy id and signer/reviewer/helper rotation change the full
  policy digest but not build-output enforcement identity, while selected tool/input/environment
  content or enforcement semantics change the latter.
- production input preflight derives a separate concrete request for each networked-fetch,
  preprovisioned-fetch or build scope. It selects only Cargo/rustc, the networked credential helper,
  or the closure's exact executable/read-input union plus sysroot as applicable; unused policy,
  signing and trust resources are never opened. Every selected file/tree is opened from the
  filesystem-root descriptor with `openat2` no-symlink resolution, executable mode and declared
  SHA-256/canonical-tree identity are checked, anchors are retained, and original path identity plus
  content are rechecked so same-content atomic pathname replacement also fails closed. No child is
  started by this preflight;
- the corresponding closed, bounded schema-3 probe request fixes Cargo to `-V`, rustc to `-vV` and
  selected build executables to `--version`, with distinct Host-linker and Host-linker-helper roles.
  Its observation must contain the exact ordered role/id/digest/argv set, successful exits and exact
  declared first stdout lines, and is revalidated between anchored input checks. A local Linux runner
  consumes retained ELF descriptors, clears ambient environment/cwd/stdin, bounds both UTF-8 output
  streams, enforces a fixed deadline and kills the complete process group including pipe-holding
  descendants. Ordinary probes remain single-executable and read-only; only a Host-linker helper gets
  a fresh disposable `/rust-agent/probe-tmp`, fixed logical `COMPILER_PATH` and the fully selected
  bundle as its descendant allowlist. Production preflight binds the helper, scratch mount and every
  descendant into signed executor evidence; old request schemas and ambient helper discovery fail;
- the Linux production backend now pins and rechecks exact bubblewrap and launcher ELF/version
  identities, creates a rootless descriptor-only filesystem, unshares mount/PID/network and all
  other namespaces, drops capabilities, clears the environment and disconnects stdin. Its closed
  Landlock policy requires full kernel enforcement and no-new-privileges, separates callable ELF
  identities from runtime interpreters, permits derived execution only below declared writable
  roots and is inherited by descendants. A seccomp supervisor blocks direct dynamic-loader use,
  x32 and shared-memory pathname races, dangerous mount/kernel/metadata escape syscalls and
  undeclared exec; it freezes related threads and confirms allowed exec at a ptrace exec boundary,
  including multithreaded vfork parents. Exact metadata-only ancestor directories avoid granting
  read access while keeping runtime path traversal viable;
- canonical Host/cache/sysroot/read-input mounts are bound read-only from retained descriptors.
  The supervisor projects `ReadOnlyEpochV1` through stat/newfstatat/fstat/statx, fixed inode flags/
  generation and deterministic sorted getdents records: file/directory permissions, logical uid/
  gid, epoch atime/mtime/ctime/birthtime, link/device/inode/mount values and directory order no
  longer expose backing metadata. Existing and absent undeclared paths receive the same denial,
  backing metadata is not rewritten, and the real bubblewrap test observes this view from inside
  the namespace. The execution observation binds exact canonical roots and the enforced semantic
  set;
- the production runtime tree carries the exact compiler dynamic-library closure, pinned Host
  `lib/rustlib/<build-triple>` subtree, required system runtime libraries, native startup objects,
  compiler runtime archives and linker support files. The selected Host linker/helper bundle is
  mounted under exact logical tool ids; Host build scripts/proc macros resolve their pinned `std`
  from the copied Host subtree while target units retain the explicit target sysroot. GCC support
  files are also projected at the install root derived from the linker's sandbox-logical `argv[0]`,
  so its fixed `COMPILER_PATH` finds the exact copied LTO plugin rather than falling back to Host
  discovery. Every copied file is runtime-tree-digest-bound and ambient Host linker/filesystem
  discovery remains invisible;
- a closed target-facts probe request now binds the exact build-input request, Host closure, policy,
  retained rustc digest, target/custom-spec logical mount, cleared environment and fixed
  `rustc --print cfg --target` invocation. For built-in targets, the local Linux runner consumes the
  retained rustc descriptor, reuses the bounded deadline/process-group executor, reparses the full
  cfg output and requires the result to equal the closure's target-facts digest. Failed exits,
  malformed/oversized output, request drift and semantically different records fail closed. Custom
  targets derive the exact canonical spec path and unstable-options argument from a normalized,
  byte/semantic-verified closure, remain bound to their trusted mounted-view path and are never
  redirected to an ambient Host path; production preflight attests the reproduced observation;
- `HostBuildInputClosure` requires the Host manifest/lock/config chain, Host package and emitted
  composition snapshot trees, Cargo resolution, target facts/custom spec, rustc settings and any
  feature-semantics evidence as role-checked logical items under one canonical read-only metadata
  contract. A custom spec uses a dedicated item kind whose primary identity is its composite
  raw/canonical digest while its file copy is independently bound by raw SHA-256; a generic file
  claim cannot substitute for it. Missing, duplicate, path-escaping, wrong-kind or
  context-mismatched items fail closed;
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
- schema-4 standalone and final planning requests derive their exact manifest, explicit Cargo
  config, Host closure aggregate, target, profile, selector, panic strategy, Rust/Cargo 1.97.1
  identity, isolated logical environment and fixed `--locked --offline --unit-graph -Z
  unstable-options` argv from the normalized closure. A selected Host-linker bundle adds only its
  exact Host-only linker/rustflags configuration, required Cargo opt-ins and `COMPILER_PATH`;
  schema 3 is rejected. The
  unit-graph-v1 envelope is closed, bounded, context checked, request-bound, acyclic and mutation
  detecting;
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
- Host Cargo fetch requests bind the normalized production policy, Host input closure,
  locked-source closure, manifest/lock/config topology, deterministic environment, minimal logical
  mounts and exact `cargo fetch --locked` argv. Networked requests require every remote locked
  source origin in the policy endpoint allowlist; preprovisioned requests use `--offline` and expose
  neither network nor credential helper. The closed observation verifier accepts only a successful
  Cargo exit, the exact requested sandbox contract, bounded `rustc -vV`/declared credential-helper
  descendants, exact fetched-source evidence and a cache-tree digest. The trusted fetch executor
  enforces this contract in the Linux backend and binds it into the outer attestation;
- the deterministic fetch-cache manifest binds that request/observation to the complete canonical
  Cargo-home tree and exact package set. Registry archive locations must use the matching
  `<name>-<version>.crate`, registry source roots the matching `<name>-<version>`, and registry/git
  source subtree digests are rederived from normalized non-overlapping cache paths; path packages
  remain closure inputs rather than being smuggled into the cache. Path escape, duplicate/overlap,
  archive checksum, source tree or manifest projection drift fail closed;
- the Linux cache materializer anchors the destination before scanning an `openat2`-anchored source
  Cargo home, retains source/staging/published descriptors, copies the exact cache tree and
  canonical manifest, applies the same read-only epoch local storage projection, syncs and uses
  same-parent `renameat2(NOREPLACE)`, then descriptor-reverifies the complete result. Existing exact
  content is reusable; mutation is rejected without repair, concurrent publication has one winner,
  and source/layout rejection leaves no output or staging residue. Opening a published cache now
  anchors it once, reads its canonical manifest through that directory descriptor, verifies the
  complete publication, and retains the same descriptor for later unchanged checks. An exact valid
  replacement at the original pathname and in-place content mutation both fail closed rather than
  being followed. The retained descriptor feeds the trusted read-only cache mount used by
  production planning and building;
- the shared closed `CanonicalSnapshotTree` schema sorts before domain-separated deterministic-CBOR
  identity; bounds paths/entries/per-file and aggregate bytes; rejects invalid, duplicate,
  case-fold-colliding or topologically incomplete paths; and fixes file/directory logical metadata
  to the `ReadOnlyEpochV1` contract. Raw file SHA-256, file length and any metadata drift change
  tree identity or fail closed;
- schema-1 `canonical-record` items now require a separate raw `bytes-sha256` alongside their
  semantic digest; custom-target items similarly use a dedicated raw-plus-composite-semantic
  content kind and rederive both identities from bounded object JSON before publication and on
  verification. Source-package manifests replace the old file-only records with the same
  canonical tree entries used by Host inputs. These are corrections to unreleased development
  contracts: old generated-composition goldens and identities, receipts, fixtures and closure
  identities using the old shapes are intentionally invalidated, with no compatibility or
  identity-preservation claim;
- Cargo resolution, target facts, rustc settings and artifact-selector records are reparsed through
  closed role-specific schemas before publication and on snapshot verification. Their semantic
  digests and shared build context are recomputed independently from raw byte hashes; malformed,
  wrong-role, unknown-field and cross-record drift fail before a snapshot can be published;
- the schema-v1 Cargo config is reconstructed from the verified Cargo-resolution target/custom-spec
  input before publication and on snapshot verification. Custom resolution additionally fixes the
  exact `targets/<logical-triple>.json` input and requires the custom-spec item at that path under
  the config's logical working root. Even a consistently resealed raw config, enclosing tree,
  closure context and enforcement identity is rejected if the bytes introduce an alias, forge the
  custom-spec composite identity or otherwise differ from that exact canonical projection;
- before staging or hashing, the Linux local snapshot materializer metadata-plans and bounds the
  exact full-closure source set, source kind, entries, paths, per-file/aggregate bytes and union
  overlay, then verifies raw bytes and semantic digests. Source mappings are opened from the
  filesystem-root descriptor with `openat2(BENEATH | NO_SYMLINKS | NO_MAGICLINKS)` and retain their
  file/root descriptors through preflight, hashing and copy; tree enumeration and entry opens are
  descriptor-relative, so symlink ancestors/descendants fail and later source-root replacement
  cannot redirect reads. The normalized destination parent is anchored before source reads;
  staging is created with a kernel-random private name through `mkdirat`, and parent/staging/
  published descriptors remain pinned through sealing, syncing and verification. Publication uses
  same-parent descriptor-relative `renameat2(NOREPLACE)` and rejects staging or published-name
  replacement rather than following it. It constructs a deterministic `deployable=false`
  staging tree, projects file mode `0444`, directory mode `0555` and mtime epoch,
  reverifies stored bytes/tree/canonical manifest plus that limited projection, publishes with
  atomic no-clobber semantics and post-verifies the winner. An exact existing snapshot is reusable
  only after the supplied live sources pass preflight; conflicting or mutated content is never
  repaired or overwritten. Pre-publication rejection leaves no final destination. A failure after
  rename is reported explicitly as published-but-verification-failed or
  published-with-parent-durability-unknown, because deleting that published path would be unsafe;
- the closed mount-observation verifier binds the snapshot manifest digest, logical mount root,
  read-only claim and exact canonical entries, and rejects schema, context, entry or digest drift.

The trusted executor composes the remaining contracts end to end. Real ignored fixtures exercise
preprovisioned and authenticated network fetch, the immutable Cargo planner, cross-compiled build
scripts/proc macros, exact observed graphs, standalone output, sandboxed pinned wasm-bindgen, and
Host integration pre/build/post. Completion requires an externally signed one-use handle; its
append-only attestation is durably published before an opaque permit can atomically expose the
`deployable=true` artifact, and production inspection rechecks both. GitHub run
`34024157819` passed Quality, the real Landlock ABI 2 gate and the namespace/descendant escape
matrix. Its trusted group passed fetch and planner coverage, and the Host link advanced through the
selected GCC/LTO/linker-script closure into the generated build script. All four build pipelines
still failed; the first complete Host diagnostic proved that Cargo 1.97.1 inherits the required
`CARGO_HOME=/rust-agent/cargo-home` driver control into that script, contradicting the fixture's old
ambient-variable expectation. Accepted ADR 0011 now distinguishes the exact identity-bound Cargo
driver environment from ambient input and advances the backend semantic version to 5. The
implementation and focused positive/failure-path regressions now pass locally; a full local
baseline and a fresh successful Ubuntu 24.04 Phase 1B run remain. The local host's Landlock ABI 1
still cannot supply the required `Refer` enforcement.
