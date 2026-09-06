# ADR 0012: Bind target-linker execution independently from the Rust sysroot

- Status: accepted
- Date: 2026-09-06
- Contract sections/invariants: Sections 46, 47, 52 (I38 and I66), and 53; Phase 1B Linux production build

## Context

The pinned Rust 1.97.1 compiler links a `wasm32-unknown-unknown` `cdylib` by
executing the bundled `rust-lld` below the Host portion of its sysroot. The
production runner intentionally mounts the sysroot as non-executable data, and
ADR 0009 explicitly forbids making that complete tree executable or silently
admitting a bundled linker. The first complete Ubuntu 24.04 WASM production
build consequently failed closed when rustc attempted that execution.

The Target linker is also not a Component build requirement. It is a selected
toolchain input determined by the exact compilation target, and treating it as
a generic executable would let Component metadata choose or invoke a compiler
linker without the target/toolchain relationship being represented in the
build identity.

## Decision

`ProductionBuildExecutionPolicy` advances from schema 3 to schema 4 and adds a
sorted, target-exact `[[target-linker]]` collection. Each entry binds one target
triple to an id, absolute source path, SHA-256 digest and bounded version
identity. Schema 4 requires exactly one such entry before any Cargo side effect
for `wasm32-unknown-unknown`; duplicate target/id entries, overlap with generic
executable/read-input/environment ids, or an invalid identity fail closed.
The initial schema recognizes the pinned bundled LLD through the fixed
`["-flavor", "wasm", "--version"]` probe shape. Supporting another target
linker family or probe protocol requires a later schema.

The production-input request advances from schema 3 to schema 4 and its probe
observation advances from schema 2 to schema 3. The selected file has the new
`target-linker` role. It is independently descriptor-opened, digest checked,
probed inside the trusted backend, and mounted as the sole executable file at:

```text
/rust-agent/target-tools/<target-linker-id>
```

The separately mounted `/rust-agent/toolchain` sysroot remains non-executable.
The descriptor mount may refer to the same Host file bytes that also occur in
the sysroot tree, but no other sysroot entry thereby acquires execute authority.

`CargoPlannerRequest` advances from schema 4 to schema 5. Planning and build
append the exact schema-owned Cargo setting for the selected composition
target, before the existing Host-linker configuration and planner suffix:

```text
--config
target.wasm32-unknown-unknown.linker="/rust-agent/target-tools/<target-linker-id>"
```

The target linker is absent from `PATH` and `COMPILER_PATH`; rustc can reach it
only through that target-exact Cargo setting. Planner execution still permits
only pinned Cargo and rustc because unit-graph production must not link.

`BuildEnforcementIdentity` advances from schema 2 to schema 3 and records the
selected target, executable identity, logical mount and exact Cargo setting in
a distinct path-free target-linker projection. The enforcement backend semantic
version advances from 5 to 6. Production build execution admits that one
descriptor-mounted identity, rejects any unselected/wrong-path/wrong-digest
linker, and requires the observed count of selected target-linker executions to
equal the count of link-producing Target rustc compilations. Host-linker
selection and observation remain separate and unchanged.

## Consequences

- WASM production builds can use the pinned LLD without making the Rust sysroot
  or runtime closure an executable search source.
- The full policy and path-free output identity change when the selected target
  linker, target mapping, Cargo setting or execution semantics change.
- A policy without the required WASM target linker fails during normalization/
  enforcement rather than reaching Cargo and relying on an execution denial.
- Native Target defaults remain unchanged; extending the mandatory target set
  or linker/probe family requires an accepted contract update.

## Acceptance tests

- `production_policy::target_linker_is_target_exact_selected_and_path_free`
- `cargo_planner::tests::schema_five_binds_target_linker_configuration`
- `production_inputs::tests::target_linker_preflight_is_separate_descriptor_role`
- `production_build::tests::target_linker_observation_is_exact`
- `production_cargo_fetch::cross_compile_planner_keeps_host_and_target_units_distinct`
- `production_cargo_fetch::trusted_build_observer_covers_cross_compiled_build_and_proc_macro_units`
- `production_cargo_fetch::production_wasm_pipeline_sandboxes_and_attests_the_complete_bundle`
