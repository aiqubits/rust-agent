# ADR 0006: Admit the pinned Cargo build spawn-error socketpair

- Status: accepted
- Date: 2026-09-05
- Contract sections/invariants: Sections 46, 47, 52 (I38, I66, I72) and 53; Phase 1B production Cargo build observer

## Context

The Linux production backend currently admits the anonymous Unix stream pair
required by Cargo's libcurl fetch path and rejects every non-stream socketpair.
That is sufficient for `cargo fetch`, metadata and unit-graph planning, but not
for an actual compile. Cargo 1.97.1 passes its jobserver descriptors to rustc;
this selects Rust standard library's fork/exec path, whose child-to-parent exec
error channel is exactly
`socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0)`. The pair is created
before the child exec, has no pathname or external destination, and is closed
after the parent receives either the exec error or EOF. The existing seccomp
policy rejects it before rustc executes.

Allowing every seqpacket pair globally would unnecessarily widen fetch and
planner sandboxes. Treating the failed spawn as an unsupported build would make
the Phase 1B production observer impossible with the repository's exact pinned
Cargo/Rust toolchain.

## Decision

The Linux sandbox command and Landlock/seccomp policy advance to schema 3 and
bind a sorted, closed list of anonymous socketpair classes. The caller cannot
provide arbitrary numeric arguments.

- Fetch and planner commands may request only the already accepted anonymous
  Unix stream wakeup class.
- A production Cargo build command may additionally request exactly anonymous
  `AF_UNIX`/`AF_LOCAL`, base type `SOCK_SEQPACKET`, flag `SOCK_CLOEXEC`, and
  protocol zero for the pinned Rust process-spawn error channel.
- `SOCK_NONBLOCK`, a missing `SOCK_CLOEXEC`, other flags/protocols/domains/types,
  direct Unix `socket`, every Unix `connect`, descriptor inheritance across the
  completed exec, and descriptor passing remain rejected for this class.
- Credential-helper processes remain pipe-only and cannot use either admitted
  pair class.

The requested class list, command, mounted inputs, backend identity and
enforcement report are bound into the sandbox request/observation and outer
attestation. The build observer must prove a real fresh-target Cargo compile
uses the exact pair while negative tests reject all neighboring shapes. A
future process-spawn shape change requires another ADR/schema change.

## Consequences

- The exact Cargo 1.97.1 compile path can start rustc and build-script
  descendants under the existing inherited Landlock/seccomp boundary.
- Fetch and planner do not receive the new capability.
- The anonymous pair carries only same-sandbox exec status and cannot name or
  reach a Host endpoint.

## Acceptance tests

- `linux_sandbox_launcher::socketpair_classes_are_command_bound_and_closed`
- `production_build::planned_and_observed_cross_compile_units_match_exactly`
- `production_build::build_descendant_escape_matrix_fails_closed`
