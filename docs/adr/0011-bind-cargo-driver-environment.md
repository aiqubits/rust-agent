# ADR 0011: Bind Cargo's inherited driver environment

- Status: accepted
- Date: 2026-09-06
- Contract sections/invariants: Sections 46, 47, 52 (I38 and I66), and 53; Phase 1B Linux production build

## Context

The production planner gives pinned Cargo a runner-owned logical home, target
directory, compiler path and other closed control variables. Cargo 1.97.1 needs
that home to locate the verified offline cache and inherits its process
environment when it executes build scripts and proc macros. The first complete
Ubuntu 24.04 Host-link build reached the fixture build script and proved that
`CARGO_HOME=/rust-agent/cargo-home` is observable there.

Treating every inherited Cargo control variable as ambient is not implementable
without changing or wrapping pinned Cargo. Allowing an arbitrary or Host-derived
value would violate the source-resolution and environment boundaries. The
contract therefore needs to distinguish a closed, identity-bound Cargo driver
environment from ambient input and Component-selected environment roles.

## Decision

The Linux production backend defines `CargoDriverEnvironmentV1`. The planner
invocation contains exactly the existing schema-owned Cargo/toolchain controls:

```text
__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS=nightly
CARGO_CACHE_RUSTC_INFO=0
CARGO_HOME=/rust-agent/cargo-home
CARGO_INCREMENTAL=0
CARGO_NET_OFFLINE=true
CARGO_TARGET_DIR=/rust-agent/target
LANG=C.UTF-8
LC_ALL=C.UTF-8
PATH=/rust-agent/toolchain/bin
RUSTC=/rust-agent/toolchain/bin/rustc
SOURCE_DATE_EPOCH=0
```

Selecting the closed Host-linker bundle additionally supplies
`COMPILER_PATH=/rust-agent/tools`. The build invocation additionally supplies
the existing exact Target-only `CARGO_ENCODED_RUSTFLAGS` and
`TMPDIR=/rust-agent/tmp`, followed by only the normalized environment roles
selected by the build-requirement union. Missing, duplicate, changed or extra
runner-supplied variables fail before Cargo. Ambient `HOME`, Cargo credentials,
proxy variables, profile overrides, wrappers and every unselected policy entry
remain absent.

Pinned Cargo may pass this exact driver environment, its own unit metadata
variables and selected environment roles to build scripts and proc macros. In
particular, a descendant may observe only the logical
`CARGO_HOME=/rust-agent/cargo-home`, never the invoking user's value. The path
names the verified, read-only, digest-bound cache already present in the
sandbox; observing it grants no new filesystem, network, executable or write
authority. The exact planner/build environments remain bound by the request and
production Cargo invocation identities and therefore by the build output and
attestation.

This correction advances the enforcement backend semantic version from 4 to 5.
Schema 4 planner records remain sufficient because their canonical projection
already binds the complete environment map; semantic version 5 changes the
interpretation of that bound map at the descendant boundary. Version 4 evidence
cannot be accepted as version 5 evidence.

## Consequences

- Build scripts can distinguish the schema-owned logical Cargo cache location,
  but cannot discover an ambient home or change source resolution through it.
- Filesystem and process isolation stay unchanged; the cache remains read-only
  and all undeclared Host paths remain invisible.
- Tests must reject ambient/alternate/missing driver values and prove the exact
  logical value is visible during a real Cargo build.
- Changing the driver-variable set, a fixed value or descendant visibility
  requires another backend semantic version.

## Acceptance tests

- `cargo_planner::tests::schema_five_binds_host_only_linker_configuration`
- `production_build::tests::cargo_build_retains_the_request_bound_channel_override`
- `production_policy::host_linker_bundle_is_closed_selected_and_path_free`
- `production_artifact::production_manifest_recomputes_identity_and_accounts_for_the_closed_artifact_tree`
- `production_cargo_fetch::trusted_build_observer_covers_cross_compiled_build_and_proc_macro_units`
- `production_cargo_fetch::production_host_pre_build_post_pipeline_is_signed_and_reverified`
