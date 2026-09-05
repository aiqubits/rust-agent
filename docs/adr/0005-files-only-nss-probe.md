# ADR 0005: Admit an inert files-only NSS daemon probe

- Status: accepted
- Date: 2026-09-05
- Contract sections/invariants: Sections 46.10, 52 (I38, I49) and 53; Phase 1B isolated fetch runner

## Context

After ADR 0004 admitted libcurl's anonymous wakeup pair, the real Linux
namespace fixture still could not resolve an origin from the exact synthesized
hosts file. A minimized fixture proved that the file and files-only NSS policy
were mounted and readable. Seccomp evidence then showed two rejected calls with
the exact arguments `socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC |
SOCK_NONBLOCK, 0)` before glibc read the files database.

glibc probes the conventional nscd Unix endpoint before falling back to the NSS
modules selected by `nsswitch.conf`. Returning `EPERM` from socket creation is
observably different from an unavailable daemon and makes the pinned runtime
fail name resolution. No nscd endpoint is mounted into the sandbox and no nscd
result may be used as DNS evidence.

## Decision

For a network-enabled fetch only, the Linux supervisor admits creation of an
otherwise inert Unix socket with domain `AF_UNIX`/`AF_LOCAL`, base type
`SOCK_STREAM`, optional `SOCK_CLOEXEC` and `SOCK_NONBLOCK`, and protocol zero.
It still supervises every `connect`. A connect naming exactly
`/var/run/nscd/socket` is not executed and deterministically returns `ENOENT`,
causing glibc to use the request-bound files-only NSS configuration. Every
other pathname or abstract Unix connect returns `EPERM`.

`bind`, `listen`, `accept` and `accept4` remain rejected. Destination-bearing
`sendto` remains rejected, and an unconnected stream socket cannot use ordinary
send operations as an endpoint. The sandbox mounts synthesized `hosts`,
`nsswitch.conf`, `host.conf` and an empty `resolv.conf`; it mounts no Host
resolver or nscd socket. DNS, UDP, raw and netlink sockets remain rejected.

## Consequences

- The exact pinned glibc/libcurl path can resolve policy origins solely from
  attested synthesized files.
- Unix socket creation alone is no longer reported as an external endpoint
  effect; all operations that could name or publish an endpoint remain denied
  or exactly emulated as unavailable.
- ADR 0004's blanket statement that direct Unix socket creation remains
  rejected is superseded only by the exact inert stream-socket class above.
  Its socketpair limits are unchanged.

## Acceptance tests

- `linux_sandbox_launcher::network_policy_allows_only_resolved_tcp_endpoints`
- `linux_namespace_backend::network_escape_matrix_denies_dns_udp_unix_listen_and_unlisted_tcp`
- `production_cargo_fetch::networked_fetch_uses_only_attested_https_endpoints`
