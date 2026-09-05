# ADR 0007: Preserve Cargo target context for build-host units

- Status: accepted
- Date: 2026-09-05
- Contract sections/invariants: Sections 3, 46, 47, 52 (I57) and 53; Phase 1B Cargo planner/build observer

## Context

`HostCargoUnitGraph` schema 1 distinguishes where a unit is compiled through
`CompilationKind::Host | Target`, but it does not distinguish the Cargo target
context for which a Host-compiled unit is instantiated. The distinction is
observable and security-relevant for build scripts.

Cargo 1.97.1 can emit two `run-custom-build` units with the same package,
target, features, profile and Host compilation kind when a package with
`links` is reachable from both a Host-side proc-macro/build closure and the
composition target closure. One unit has Cargo's Host target context and the
other has the composition target context. They can receive different `TARGET`
values and produce different generated, cfg, native or link outputs. Schema 1
collapses them to one selector and therefore cannot represent the exact pinned
Cargo graph or attest each downstream contribution.

Silently deduplicating the units would make planner/observer equality and Host
feature accounting unsound. Treating a real wasm-bindgen graph as unsupported
would prevent the required Phase 1B WASM acceptance path.

## Decision

`HostCargoUnitGraph` advances to schema 2. Every `CargoUnitSelector` has a
required, closed `cargo-target-context` field with exactly one of these values:

- `build-host`: Cargo emitted the unit without a target platform and the unit
  belongs to the Host-side target context;
- `composition-target`: Cargo emitted the unit for the exact attested
  composition target.

The field has no default and schema 1 input is rejected. The pair of
`compilation-kind` and `cargo-target-context` is interpreted as follows:

- every Target-compiled unit has `composition-target` context;
- a Host library, proc macro or custom-build compile unit has `build-host`
  context;
- a Host-compiled `run-custom-build` unit may have either context and the two
  selectors remain distinct;
- any other pair, an unknown raw platform or a platform different from the
  exact composition target fails closed.

Node and edge identity, canonical graph digest, Host feature selectors,
standalone/final projection, planner/build observation, SBOM and signed
attestation all bind the new field. A normal dependency's Cargo-generated
`links` edge to its build-script output retains metadata's normal dependency
kind while the dependency unit remains in the Host compilation domain.

## Consequences

- The reference runner can represent wasm-bindgen and native `links` graphs
  without collapsing distinct build-script executions.
- Target-specific build-script outputs remain visible to downstream runtime
  contribution and build-requirement accounting.
- Existing schema 1 graph fixtures and callers must migrate explicitly; there
  is no compatibility decoder that invents target context.
- Any future Cargo context not covered by the two closed values requires a new
  ADR/schema revision.

## Acceptance tests

- `cargo_unit_graph::tests::schema_two_distinguishes_build_script_target_contexts`
- `cargo_planner::tests::raw_duplicate_build_script_contexts_normalize_without_collapse`
- `production_cargo_fetch::production_wasm_pipeline_sandboxes_and_attests_the_complete_bundle`
