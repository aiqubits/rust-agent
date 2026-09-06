# ADR 0010: Scope linker configuration to Host Cargo units

- Status: accepted
- Date: 2026-09-06
- Supersedes in part: ADR 0009 (Host/Target flag delivery mechanism)
- Contract sections/invariants: Sections 46, 47, 52 (I38 and I66), and 53; Phase 1B Linux production build

## Context

ADR 0009 requires `-Clinker-features=-lld` for native Host links so rustc cannot
replace the schema-selected linker with its self-contained LLD. Its original
delivery mechanism appended that argument to `CARGO_ENCODED_RUSTFLAGS` after the
explicit target sysroot argument.

Cargo 1.97.1 applies global encoded rustflags to Target units when a build uses
`--target`; it does not apply them to build scripts and proc macros compiled for
the build Host. The original mechanism therefore leaves the Host link unchanged
and instead sends the native-only linker feature to composition Target units.
For `wasm32-unknown-unknown`, rustc rejects that argument before compilation.
The trusted observer also cannot require one common flag vector from both
compilation kinds: Target units require the explicit target sysroot, while Host
units use the separately projected pinned Host sysroot.

Cargo's pinned unstable Host configuration can scope linker and rustflags to
Host artifacts. It is acceptable only if the complete opt-in and compatibility
switches are fixed by the planner request rather than inherited from ambient
Cargo configuration.

## Decision

`CargoPlannerRequest` advances from schema 3 to schema 4. When and only when the
closed Host-linker bundle is selected, both planning and build append the exact
ordered Cargo arguments:

```text
--config
target-applies-to-host=false
--config
host.<build-triple>.linker="/rust-agent/tools/<linker-id>"
--config
host.<build-triple>.rustflags=["-Clinker-features=-lld"]
-Z
target-applies-to-host
-Z
host-config
```

These arguments precede the planner-only `--unit-graph -Z unstable-options`
suffix. The build derives its invocation by replacing only that suffix with the
existing build-only arguments, so planning and execution share the exact Host
configuration. Because the pinned stable Cargo still gates that Host
configuration behind its channel checks, the build retains the exact
request-bound `__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS=nightly` value; it
may not inherit, remove or replace that value. No checked-in, ancestor or ambient
Cargo configuration may provide or override these settings. `COMPILER_PATH`
remains the fixed `/rust-agent/tools` value when the bundle is selected.

The build-owned `CARGO_ENCODED_RUSTFLAGS` remains exactly
`--sysroot=/rust-agent/toolchain` for composition Target units and never carries
the Host linker feature. Under the fixed `target-applies-to-host=false`
semantics, Host build scripts and proc macros receive neither that Target
sysroot nor Target rustflags; Cargo supplies the exact Host-only linker and
`-Clinker-features=-lld` settings instead.

The trusted rustc observer distinguishes the compilation kind before accepting
flags. A Target compilation has one `--target`, exactly one build-owned target
sysroot and no Host linker-feature override. A Host compilation has no
`--target`, no target sysroot and, when the bundle is selected, exactly one
`-Clinker-features=-lld`; builds without the bundle receive none. Cargo's
separately authorized bare compiler identity and target-discovery queries remain
exact and flag-free. The observer accepts a flagged query only after stripping
the exact flags allowed for its compilation kind. Alternate flags, duplicate
flags, cross-kind leakage or missing required flags fail closed.

`BuildEnforcementIdentity` remains schema 2 because its selected Host-linker
record already binds the schema-owned logical Cargo configuration and its
backend semantic version is the versioned interpretation of that record. The
record changes from `target.<build-triple>.linker` to the exact
`host.<build-triple>.linker` value, and backend semantic version advances from 3
to 4. The schema-4 planner digest, exact production Cargo invocation and
supervised rustc observations bind the remaining Host configuration arguments.

## Consequences

- Cross-target builds keep native Host linker semantics out of WASM and other
  composition Target units.
- Host build scripts and proc macros can execute only the selected linker/helper
  closure; the non-executable runtime-tree LLD cannot become an implicit helper.
- Planner schema 3 is rejected instead of silently acquiring Cargo Host-config
  semantics.
- Supporting another Cargo Host-config interface or changing flag scope requires
  a new schema/backend semantic version and acceptance evidence.

## Acceptance tests

- `cargo_planner::tests::schema_four_binds_host_only_linker_configuration`
- `cargo_planner::tests::schema_three_is_rejected_after_host_config_scoping`
- `production_build::tests::cargo_build_retains_the_request_bound_channel_override`
- `production_build::tests::host_and_target_rustc_flags_are_scope_exact`
- `production_build::tests::rustc_observation_rejects_cross_kind_linker_flags`
- `production_policy::host_linker_bundle_is_closed_selected_and_path_free`
- `production_cargo_fetch::trusted_build_observer_covers_cross_compiled_build_and_proc_macro_units`
- `production_cargo_fetch::production_standalone_pipeline_is_signed_and_reverified`
- `production_cargo_fetch::production_wasm_pipeline_sandboxes_and_attests_the_complete_bundle`
- `production_cargo_fetch::production_host_pre_build_post_pipeline_is_signed_and_reverified`
