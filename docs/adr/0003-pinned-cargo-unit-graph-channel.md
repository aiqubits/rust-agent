# ADR 0003: Admit the pinned Cargo unit-graph channel override

- Status: accepted
- Date: 2026-09-05
- Contract sections/invariants: Sections 46, 52 (I38, I57, I66, I72) and 53; Phase 1B Cargo unit planner

## Context

Cargo 1.97.1 contains the required `--unit-graph` v1 producer, but the official
stable binary rejects the unstable option before planning. The same exact
binary and digest produces unit-graph v1 when Cargo's own test-only channel
override `__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS=nightly` is set. A real
probe confirms that this changes feature admission only; the planner remains
the policy-pinned Cargo 1.97.1 executable.

Treating the interface as unavailable would leave Phase 1B permanently unable
to satisfy its unit-level Host/target graph contract. Falling back to package
metadata would lose compilation-kind and feature information and remains
forbidden.

## Decision

The Cargo planner request advances to schema 2. It fixes the exact environment
entry `__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS=nightly` as a
planner-specific enforcement semantic. The variable is not accepted from
ambient process state or a user environment role. Its name and value, Cargo
version and digest, full argv, closure, target/profile and output schema are all
bound into the planner request and production attestation.

The planner runs inside the same Linux production backend as other build
commands. It may execute only the exact pinned Cargo/rustc identities and the
read-only target-information queries required by Cargo. Unit-graph planning
must not execute build scripts, proc macros or compiler code generation and
must leave declared output roots unchanged. The complete stdout is parsed as a
closed, bounded unit-graph v1 envelope. Stderr, an unexpected descendant,
filesystem/output mutation, another Cargo digest/version, a different override
value, package-level fallback or graph/context drift fails closed.

The internal override is supported only for the exact Cargo identities admitted
by a checked-in production policy and matching conformance test. A future Cargo
upgrade must re-prove the interface and accept a new ADR/schema if behavior or
output changes.

## Consequences

- Phase 1B can use the required unit graph without a second Rust/Cargo
  toolchain or an unpinned planner executable.
- The deliberately internal Cargo switch is a narrow, visible trust decision,
  not an ambient escape hatch.
- Stable Cargo without the exact bound override remains unsupported and the
  existing fail-closed negative test remains valid.
- Existing unreleased schema-1 planner requests are invalidated.

## Acceptance tests

- `cargo_planner::tests::schema_two_binds_the_exact_pinned_channel_override`
- `cargo_planner::tests::pinned_cargo_produces_a_real_unit_graph_without_build_side_effects`
- `cargo_planner::tests::channel_override_digest_argv_and_output_drift_fail_closed`
- `production_build::planned_and_observed_cross_compile_units_match_exactly`
