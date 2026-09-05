# ADR 0009: Disable implicit Host LLD substitution

- Status: accepted
- Date: 2026-09-06
- Superseded in part by: ADR 0010 (Host/Target flag delivery mechanism)
- Contract sections/invariants: Sections 46, 47, 52 (I38 and I66), and 53; Phase 1B Linux production build

## Context

Rust 1.97.1 can add a self-contained linker prefix and `-fuse-ld=lld` when it
links native Host build scripts and proc macros. That implicit choice conflicts
with the schema-3 production policy's closed `host-linker` bundle: the compiler
may search for `liblto_plugin.so` beneath the Rust sysroot prefix and may execute
the bundled `ld.lld`, even though the policy selected and digest-bound a
different linker helper at `/rust-agent/tools/<helper-id>`.

Copying the LTO plugin into the Rust sysroot prefix would fix only discovery. It
would still let rustc substitute an executable that is neither a selected
Host-linker helper nor independently descriptor-mounted and probed. Allowing the
runtime tree to become an executable source would weaken the existing exact-file
execution boundary.

## Decision

When and only when the closed Host-linker bundle is selected, the production
Cargo build runner adds the exact encoded rustc argument
`-Clinker-features=-lld` after its exact
`--sysroot=/rust-agent/toolchain` argument. This disables rustc's implicit
self-contained LLD substitution. The selected compiler driver must therefore
resolve and execute only the helper files declared by the bundle through the
fixed `COMPILER_PATH=/rust-agent/tools`.

The encoded argument is schema-owned and cannot be supplied, removed or
overridden by a Component or ambient environment. The trusted observer requires
it exactly once on every build-flag-bearing rustc query and compilation spawned
by a selected Host-linker build, and requires it zero times otherwise. Cargo's
separately pre-authorized bare identity/target-discovery query shapes remain
exact and flag-free. The observer strips only the exact build-owned arguments
when matching the flagged query shape. Any alternate `linker-features` argument
or count fails closed.

The exact `CARGO_ENCODED_RUSTFLAGS` value is recorded in
`ProductionCargoInvocationIdentity` and the supervised rustc argv is recorded in
the execution observation. The path-free enforcement identity's backend
semantic version advances from 3 to 4, so artifacts built with the prior
implicit-linker semantics cannot share a build-output identity with this
decision. No policy or planner schema change is required because the existing
schema already selects the complete linker bundle and binds the exact Cargo
invocation and execution evidence.

ADR 0010 supersedes the global encoded-flag delivery mechanism above after
cross-target validation showed that Cargo applies those flags to Target units,
not Host build scripts and proc macros. The security decision to disable the
implicit Host LLD substitution remains in force, but it is delivered through
Cargo's Host-only configuration and a schema-4 planner request.

## Consequences

- Host native links use only the selected, digest-bound compiler driver and
  helper bundle; the Rust sysroot remains data/toolchain input rather than an
  ambient executable provider.
- GCC's LTO plugin is resolved from the logical install root already required by
  ADR 0008 instead of a rustc-injected `-B` prefix.
- Builds without a selected Host-linker bundle retain rustc's target-default
  linker behavior and do not receive the new argument.
- A future policy that intentionally selects bundled LLD requires a new
  executable role, descriptor-mounted identity, probe, observation rule and
  accepted ADR rather than reuse of the runtime tree.

## Acceptance tests

- `cargo_planner::tests::schema_four_binds_host_only_linker_configuration`
- `cargo_planner::tests::schema_three_is_rejected_after_host_config_scoping`
- `production_build::tests::host_and_target_rustc_flags_are_scope_exact`
- `production_build::tests::rustc_observation_rejects_cross_kind_linker_flags`
- `production_policy::host_linker_bundle_is_closed_selected_and_path_free`
- `production_cargo_fetch::trusted_build_observer_covers_cross_compiled_build_and_proc_macro_units`
- `production_cargo_fetch::production_standalone_pipeline_is_signed_and_reverified`
- `production_cargo_fetch::production_wasm_pipeline_sandboxes_and_attests_the_complete_bundle`
- `production_cargo_fetch::production_host_pre_build_post_pipeline_is_signed_and_reverified`
