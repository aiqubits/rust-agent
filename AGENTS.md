# rust-agent repository rules

These rules apply to the whole repository. `ARCHITECTURE.md` is the normative
architecture contract. If code and the contract disagree, update the contract
through an ADR and its invariant/acceptance tests before changing behavior.

## Phase discipline

- Implement phases in the order defined by `ARCHITECTURE.md`. Phase 1B may run
  alongside Phase 2/3 only after Phase 1A is complete; no artifact may be called
  deployable until the Phase 1B production gate passes.
- Do not create empty crates or placeholder APIs to claim a later phase. A phase
  is complete only when every in-scope acceptance criterion is mapped to a named
  automated test or lint and the phase gate passes.
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

- Add positive, negative, boundary, deterministic, and failure-path tests for
  every behavior changed. Security-sensitive code also needs bypass/regression
  tests and proof that rejected input produces no external side effect.
- Resolver changes require unit tests, deterministic/property coverage, a small
  graph brute-force oracle comparison, provenance assertions, and golden output
  updates.
- Generator/build changes require graph-presence and graph-absence checks,
  generated-source/manifest freshness tests, isolated locked builds, and CLI
  end-to-end coverage.
- Public privacy/ownership contracts require compile-fail fixtures. Cross-target
  claims require tests on the real target; cross-compilation alone is not proof
  of production support.
- Tests must not depend on the checked-out `AINS/` or `deepseek-harness/` trees.

## Completion gate

Before committing, run from the repository root:

```text
cargo fmt --all --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo test -p rust-agent-cli --test e2e
cargo doc --workspace --no-deps
cargo tree --workspace --edges normal,build,dev
cargo deny check
```

Also run every target/build/packaging gate applicable to the completed phase,
including generated-composition locked builds and end-to-end tests. If a tool or
real target is unavailable, do not mark the corresponding phase/support tier
complete; record the exact unverified gate in `docs/phase-status.md`.

Commit and push only after:

1. all applicable checks pass;
2. `git diff --check` is clean;
3. generated and golden files are fresh and deterministic;
4. the architecture invariant-to-test map and phase status are updated;
5. the staged diff contains no secrets, build artifacts, reference-repository
   changes, or unrelated user work.

Use a concise conventional commit message. Push the current branch without force.
