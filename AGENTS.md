# rust-agent repository rules

These rules apply to the whole repository. `ARCHITECTURE.md` is the normative
architecture contract and implementation direction. Existing or incomplete code
does not override it: when code and the contract disagree, change the code toward
the contract. If implementation evidence shows that the contract itself must
change, stop the affected behavior change and first accept an ADR that updates the
contract, its invariants, and its acceptance tests. An ADR is accepted only when
its `Status` is `accepted` and the ADR plus the corresponding contract changes
have been committed before implementation of the affected behavior begins.

## Phase discipline

- Before starting a change, identify every affected phase in
  `docs/phase-status.md` and read its complete `ARCHITECTURE.md` phase definition
  together with the applicable capability sections and Sections 46, 47, 50, 52,
  and 53. Every acceptance criterion assigned there is mandatory for that
  phase's completion.
- Implement phases in the order defined by `ARCHITECTURE.md`. Phase 1A generated
  compositions use only the minimal core/runtime contracts and test fixtures;
  they must not depend on later product Component, Model, Agent, or Driver APIs.
  In Phase 2, independently compile the lightweight `rust-agent-session` API
  before implementing its `rust-agent-agent` consumer. Phase 1B may run alongside
  Phase 2/3 only after Phase 1A is complete; no artifact may be called deployable
  until the Phase 1B production gate passes.
- Do not create empty crates or placeholder APIs to claim a later phase. A phase
  is complete only when every acceptance criterion assigned to that phase by
  `ARCHITECTURE.md` is mapped in `docs/invariant-tests.md` to a named, runnable
  automated test, lint, or CI job and every phase gate passes. No criterion may
  be declared out of scope, deferred, or reassigned unless an accepted ADR first
  updates the contract, its invariant/acceptance-test map, and phase status.
- For every ported AINS module: define the capability seam and Provider/Consumer
  ownership, port behavior tests, port only the required algorithm, remove legacy
  kernel/product imports, test the target matrix and dependency isolation, add
  security regressions, and update the migration inventory.
- Never copy an AINS directory wholesale. This repository must not depend on
  AINS, `client-api`, UI/application frameworks, or AINS product types.

## Architecture and security

- Capability consumers depend only on API crates. Only generated composition
  roots may directly depend on multiple concrete Component crates.
- Selectable Components map one-to-one to Cargo packages. Disabled or unselected
  Components must be absent from the generated Cargo dependency graph.
- Runtime configuration may only narrow or configure providers already compiled
  into the artifact. It must never restore a compile-time-removed capability.
- Unknown schema fields/versions, unsupported targets, unaccounted runtime
  effects, missing build requirements, and ambiguous provider resolution fail
  closed before Cargo or provider side effects.
- Keep control-plane build requirements separate from runtime security effects.
  Development builds are always `deployable=false`.
- Preserve the API dependency direction and privacy boundaries documented in
  `ARCHITECTURE.md`; do not add runtime service locators or raw execution bypasses.
- Avoid `unsafe`. Any unavoidable use requires a security ADR, a narrow wrapper,
  platform regressions, and explicit review.

## Required tests for each change

- For every behavior changed, consider positive, negative, boundary,
  deterministic, and failure-path coverage and add every applicable category.
  An omitted category must be genuinely inapplicable to that behavior, not merely
  deferred. Security-sensitive code also needs bypass/regression tests and proof
  that rejected input produces no external side effect.
- Resolver changes require unit tests, deterministic/property coverage, a small
  graph brute-force oracle comparison, provenance assertions, and golden output
  updates.
- Generator/build changes require graph-presence and graph-absence checks,
  generated-source/manifest freshness tests, isolated locked builds, and CLI
  end-to-end coverage.
- `cargo tree` output alone is diagnostic, not dependency-isolation evidence.
  Dependency-presence and dependency-absence requirements need automated checks
  that fail when the resolved graph is wrong.
- Public privacy/ownership contracts require compile-fail fixtures. A production
  or runtime support claim for a target requires tests on that real target;
  cross-compilation is compile-compatibility evidence only and is not proof of
  production support.
- Tests must not depend on the checked-out `AINS/` or `deepseek-harness/` trees.

## Completion gate

Before committing, and again immediately before every push, run from the
repository root every command/check required by `.github/workflows/ci.yml` that
has a faithful local equivalent. Use the pinned toolchain, components, target
set, flags, features, and environment variables defined by CI; the local host OS
need not equal the runner OS. CI checks wrapped by an action must be run through
their local equivalent (for example, `cargo deny check`). A missing local tool is
not a passing result: install it or do not commit or push. Keep the baseline
commands below synchronized with the workflow, and retain any additional
repository gates listed here, whenever CI changes:

```text
cargo fmt --all --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo test -p rust-agent-cli --test e2e
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo tree --workspace --edges normal,build,dev
cargo deny check
```

Also run every target/build/packaging gate applicable to the changed behavior.
Before claiming a phase or support tier complete, run every gate assigned to it
by `ARCHITECTURE.md`. As applicable, this includes the real-target compile matrix,
resolver oracle and golden tests, generated composition compose/lock/build and
negative-dependency checks, isolated Host integration pre/build/post
verification, WASM bundle and size gates, production sandbox escape tests, and
signed enforcement/attestation verification. Every gate used as completion
evidence must have an exact runnable test, lint, script, or CI job recorded in
`docs/invariant-tests.md`; a prose claim or successful diagnostic command is not
evidence. If a gate, tool, production backend, or real target is unavailable, do
not mark the corresponding phase or support tier complete; record the exact
unverified gate in `docs/phase-status.md`. This exception applies only to
phase/support-tier gates without a faithful local equivalent, not to the local
baseline above. Such gates must pass on the matching required runner before
merge, release, or any completion/support claim; a push made solely to obtain
that remote evidence is allowed after all local baseline and otherwise available
applicable checks pass.

Commit and push only after:

1. all applicable checks pass;
2. `git diff --check` is clean;
3. generated and golden files are fresh and deterministic;
4. the architecture invariant-to-test map and phase status are updated when the
   change affects them, or verified unchanged when it does not;
5. the staged diff contains no secrets, build artifacts, reference-repository
   changes, or unrelated user work.

Use a concise conventional commit message. Push the current branch without force.
