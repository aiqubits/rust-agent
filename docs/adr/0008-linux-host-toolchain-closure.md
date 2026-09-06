# ADR 0008: Bind the Linux host toolchain closure

- Status: accepted
- Date: 2026-09-06
- Superseded in part by: ADR 0010 (Host linker Cargo configuration)
- Contract sections/invariants: Sections 3, 46, 47, 50, 52 (I38 and I66), and 53; Phase 1B Linux production build

## Context

The Linux production runner executes the pinned `rustc` from a bind-mounted
regular file. Rust 1.97.1 therefore derives its default Host sysroot from the
loaded compiler-driver library rather than from the original executable path.
Target units already receive an explicit target sysroot, but Cargo's
Host-compiled build scripts and proc macros do not. Copying only the compiler
driver libraries makes those units fail to locate the Host standard library.

Cross-target Host units can also invoke a native linker. Allowing the compiler
driver to discover an ambient linker, helper programs, startup objects or linker
scripts would violate the executable and filesystem closure required by the
production policy. A wrapper or alias would conceal executable identity and is
already forbidden by the architecture contract.

## Decision

`ProductionBuildExecutionPolicy` advances to schema 3 and may declare one closed
`host-linker` bundle. The bundle names one linker executable id and a sorted,
unique set of helper executable ids. Every id must resolve to a separately
digest- and version-bound `[[executable]]`. Build requirements select either no
member of the bundle or every member; partial selection fails before Cargo.

When the bundle is selected, planner and build use the exact Cargo command-line
configuration `target.<build-triple>.linker="/rust-agent/tools/<linker-id>"`
and the fixed `COMPILER_PATH=/rust-agent/tools`. These settings are
schema-owned, path-free logical enforcement inputs; Components cannot override
them. `CargoPlannerRequest` advances to schema 3 and
`BuildEnforcementIdentity` advances to schema 2 so both planning and attestation
bind the complete selection. A wrapper, alias or ambient PATH lookup remains
forbidden.

Some compiler helpers, notably GCC `collect2`, implement `--version` by creating
a temporary file and executing the selected `ld`. Such helpers use the
schema-owned Host-linker-helper probe class rather than the ordinary
single-executable probe class. The helper probe runs in a fresh, runner-owned
`/rust-agent/probe-tmp`, receives only fixed `COMPILER_PATH=/rust-agent/tools`,
and may execute only the fully selected Host linker bundle. The directory is
discarded after the individual probe, network remains isolated, and the
execution observation binds the helper and every descendant. Granting the same
scratch or descendant set to an unrelated executable is forbidden.
`ProductionInputIdentityRequest` advances to schema 3 and records the closed
`host-linker` and `host-linker-helper` file roles so old requests cannot acquire
the broader probe semantics.

The Linux runner places the exact compiler dynamic-library closure beneath
`/rust-agent/runtime/lib` and copies the exact pinned Host
`lib/rustlib/<build-triple>` subtree beneath the same inferred sysroot. It also
copies every required system runtime and native-link support file to its
canonical logical location in the isolated root. If the compiler driver
relocates its install root from `argv[0]`, the runner derives and projects that
root using the exact sandbox-logical linker `argv[0]`; this includes the LTO
plugin searched under the fixed `COMPILER_PATH`. The same digest-bound plugin is
also projected at `/rust-agent/tools/liblto_plugin.so`, so GCC versions that
resolve `-fuse-linker-plugin` directly through `COMPILER_PATH` do not fall back
to the Host. GNU linker scripts are read with fixed byte/file-count bounds and
their absolute `GROUP`/`INPUT` dependencies are copied at those exact logical
paths; a missing referenced file fails fixture construction instead of relying
on merged `/usr` Host layout. Copying only the original Host install path is
insufficient. Target-compiled units retain the explicit `/rust-agent/toolchain`
sysroot. All copied files participate in the runtime-tree digest; undeclared
Host files remain invisible.

## Consequences

- Host build scripts and proc macros use the pinned Host standard library while
  target units continue to use the selected target sysroot.
- Cross-target native linking is possible only through the fully selected,
  digest-bound linker closure.
- Linker helpers with composite version behavior remain verifiable without
  granting write access to `/` or access to an ambient descendant executable.
- Existing policy schema 2, planner schema 2 and enforcement-identity schema 1
  inputs are rejected rather than silently acquiring Host tools.
- Supporting another compiler/linker layout requires a schema change or another
  accepted ADR with equivalent closure and identity guarantees.

## Acceptance tests

- `production_policy::host_linker_bundle_is_closed_selected_and_path_free`
- `cargo_planner::tests::schema_five_binds_host_only_linker_configuration`
- `production_inputs::tests::host_linker_helper_preflight_roles_are_closed_and_schema_four`
- `production_cargo_fetch::host_linker_support_files_follow_logical_install_and_compiler_paths`
- `production_cargo_fetch::production_host_pre_build_post_pipeline_is_signed_and_reverified`
- `production_cargo_fetch::production_standalone_pipeline_is_signed_and_reverified`
- `production_cargo_fetch::production_wasm_pipeline_sandboxes_and_attests_the_complete_bundle`
