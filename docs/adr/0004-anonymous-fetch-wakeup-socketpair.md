# ADR 0004: Admit one anonymous fetch-runner wakeup socket class

- Status: accepted
- Date: 2026-09-05
- Contract sections/invariants: Sections 46.10, 52 (I38, I49) and 53; Phase 1B isolated fetch runner

## Context

ADR 0002 rejected every Unix socket and socketpair. Real execution with the
pinned Cargo 1.97.1 binary proved that this is incompatible with Cargo's linked
libcurl implementation: `curl_multi_init` requires an internal wakeup channel
and returns failure when that channel cannot be created. On this Linux runner
the fallback is `socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC |
SOCK_NONBLOCK, 0)`. Cargo consequently failed before making any policy-approved
network connection.

This anonymous pair does not name or connect to a Host endpoint. Treating it as
equivalent to a path-addressed or abstract Unix socket overstates its authority
and prevents the exact pinned production tool from operating.

## Decision

The Linux fetch sandbox admits only anonymous `socketpair` calls with domain
`AF_UNIX`/`AF_LOCAL`, base type `SOCK_STREAM`, optional `SOCK_CLOEXEC` and
`SOCK_NONBLOCK` flags, and protocol zero. Every other socketpair argument is
rejected. The pair remains inside the already-confined process tree and is not
an external network endpoint.

Direct `socket(AF_UNIX, ...)` remains rejected, so a descendant still cannot
create a pathname-addressed or abstract Unix endpoint. `bind`, `listen`,
`accept` and `accept4` remain rejected for all families. IPv4/IPv6 sockets are
still limited to TCP streams connected to the exact attested endpoint set;
UDP, raw, netlink, DNS sockets and undeclared addresses or ports remain
rejected. No inherited non-standard descriptor may survive the launcher
bootstrap.

Destination-bearing send operations cannot broaden the boundary: `sendto`
with a destination remains rejected, an admitted TCP descriptor is already
connected to one exact attested endpoint, and an anonymous pair has no external
destination. Descriptor passing on an anonymous pair cannot escape the sandbox
because no Host Unix socket or inherited non-standard descriptor exists.

## Consequences

- The pinned Cargo/libcurl multi implementation can create its internal wakeup
  channel without receiving access to any Host IPC endpoint.
- ADR 0002's phrase rejecting all Unix sockets is narrowed only for the exact
  anonymous stream-pair class above. Its external network, credential, TLS,
  redirect and attestation requirements are unchanged.
- The real escape test must prove both sides: the exact anonymous pair works,
  while direct Unix socket creation/connect, non-stream socketpairs and all
  previously forbidden external network operations fail.

## Acceptance tests

- `linux_sandbox_launcher::network_policy_allows_only_resolved_tcp_endpoints`
- `linux_namespace_backend::network_escape_matrix_denies_dns_udp_unix_listen_and_unlisted_tcp`
- `production_cargo_fetch::networked_fetch_uses_only_attested_https_endpoints`
