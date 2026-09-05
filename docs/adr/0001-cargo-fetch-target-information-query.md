# ADR 0001: Admit Cargo 1.97.1's exact fetch-time target-information query

- Status: accepted
- Date: 2026-09-05
- Contract sections/invariants: Sections 46 and 53; Phase 1B isolated fetch runner

## Context

The Phase 1B contract limited a fetch runner's rustc descendants to the exact
`rustc -vV` invocation. A real, pinned Cargo 1.97.1 `cargo fetch --locked`
run contradicts that assumption. After the version query, Cargo executes a
read-only target-information probe with standard input as the crate source. It
uses a fixed set and order of `--print` and `--crate-type` arguments and, for a
non-Host target, adds the exact normalized target after `--target`.

The behavior is necessary even when every dependency is a local path package
and the fetch is offline. Denying the additional invocation prevents the pinned
Cargo from completing. Allowing arbitrary rustc arguments would instead permit
code generation and violate the fetch/build separation.

Cargo captures this probe's output and opens `/dev/null` for the child's
standard input before `execve`. A rootless filesystem with no `/dev/null`
therefore fails with `ENOENT`. Mounting the Host device would introduce an
undeclared device input and is not acceptable production behavior.

## Decision

The trusted Cargo fetch request/observation protocol advances to schema 2.
Schema 1 is rejected rather than silently acquiring a wider executable
surface. Schema 2 permits the exact policy-selected rustc identity to execute
only these query forms:

1. `rustc -vV`;
2. `rustc - --crate-name ___ --print=file-names [--target <exact target>]
   --crate-type bin --crate-type rlib --crate-type dylib --crate-type cdylib
   --crate-type staticlib --crate-type proc-macro --print=sysroot
   --print=split-debuginfo --print=crate-name --print=cfg -Wwarnings`.

The `--target` pair must be absent for the Host query and present exactly once
with the request's normalized Cargo target input for the target query. No
response file, wrapper, extra argument, reordered argument, alternate
executable, source path or non-query rustc invocation is admitted. The
supervisor records every invocation and the fetch verifier rejects the complete
execution if any descendant lies outside this closed set.

The Linux backend runtime identity must also contain a zero-length regular file
and the exact logical symlink `/dev/null` to that file. This is a read-only,
content-addressed runtime input, not the Host device. The backend rejects a
missing, non-empty, non-regular or differently mapped null-input contract.
Other `/dev` entries remain absent.

## Consequences

- Fetch remains query-only: rustc cannot compile code, execute a build script,
  consume a response file or select an arbitrary target.
- The additional argv and the target value are request-/observation-bound and
  become part of the fetch evidence identity.
- Existing unreleased schema-1 fetch requests and observations are invalidated.
- Runtime packaging must add the deterministic empty null-input file and its
  exact logical symlink; no Host device tree is exposed.
- A future Cargo query change requires another schema/allowlist decision.

## Acceptance tests

- `host_input_closure::cargo_fetch_schema_two_binds_exact_host_and_target_queries`
- `host_input_closure::cargo_fetch_rejects_query_argument_target_and_schema_drift`
- `production_cargo_fetch::preprovisioned_fetch_runs_cargo_offline_and_publishes_a_verified_read_only_cache`
- `linux_namespace_backend::runtime_null_input_is_identity_bound_and_host_devices_remain_hidden`
