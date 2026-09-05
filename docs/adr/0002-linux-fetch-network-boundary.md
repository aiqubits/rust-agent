# ADR 0002: Define the Linux fetch network boundary at actual TCP endpoints

- Status: accepted
- Date: 2026-09-05
- Contract sections/invariants: Sections 46, 52 (I38, I49) and 53; Phase 1B isolated fetch runner

## Context

The original Phase 1B fetch policy required `max-redirects = 0`, but the
reference backend executes the official Cargo 1.97.1 binary and enforces its
network boundary outside that process. Cargo performs HTTPS with libcurl. An
outer namespace/seccomp supervisor can verify socket families, destination
addresses and ports, but it cannot read an HTTP redirect carried inside the
encrypted TLS stream. Cargo 1.97.1 exposes no configuration that disables or
reports redirects. Claiming that the outer backend observed a zero redirect
count would therefore be false.

The existing policy also omitted the TLS trust input and DNS evidence needed
for a rootless filesystem. Depending on the Host certificate store or resolver
configuration would make the fetch non-reproducible and would introduce
undeclared read/network effects.

## Decision

The production build policy advances to schema 2 and the Cargo fetch
request/observation protocol advances to schema 3. Older schemas are rejected.
The fetch policy replaces `max-redirects` with the closed value
`redirect-policy = "deny-unlisted-origin"` and adds one exact SHA-256-bound TLS
CA bundle. The fetch invocation fixes Cargo's CA configuration to the logical
mount of that bundle and disables every built-in credential provider.

Before entering the sandbox, the trusted executor resolves each declared
canonical HTTPS origin. It records the origin, canonical host, port and sorted
unique IP addresses in the sandbox request. It creates a deterministic,
request-bound hosts file and `hosts: files` NSS configuration; no Host resolver
file is mounted and DNS sockets are denied. Resolution evidence and both files
are immutable inputs to the execution request and attestation.

The network namespace may share the Host network only while seccomp enforces
the recorded endpoint set. It permits only IPv4/IPv6 TCP stream sockets and
`connect` to an exact recorded address and port. Unix, UDP, raw and netlink
sockets, undeclared IPs/ports, bind/listen/accept, destination-bearing
`sendto`/`sendmsg`, and inherited non-standard sockets are rejected. Each
actual TCP destination is therefore policy-bound, including a destination
selected after an HTTP redirect. A redirect can proceed only when its actual
destination is already a declared origin endpoint; a redirect to any unlisted
origin fails before connection. The backend does not claim to count encrypted
same-origin redirects.

When configured, Cargo may invoke exactly the policy-pinned credential helper
with the Cargo credential-provider protocol and `--cargo-plugin`. Cargo and
the helper communicate only through their bounded standard pipes. The helper
is a trusted endpoint-scoped implementation identified by its policy digest;
it receives no ambient token, credential file, proxy, home, resolver or extra
filesystem surface. Credential protocol bytes are never copied into cache,
diagnostics, execution reports, manifests or attestations. Without a declared
helper, all credential providers are disabled.

## Consequences

- The enforceable security claim is stronger and precise at the side-effect
  boundary: every actual socket destination is known and attested.
- The policy no longer makes an unobservable redirect-count claim.
- Certificate trust, DNS results and resolver files become explicit immutable
  request inputs instead of ambient Host state.
- Endpoint DNS changes rotate execution evidence but not the higher-level
  locked-source identity; a new connection can use only the addresses recorded
  for that execution.
- Existing unreleased production-policy schema 1 and fetch schema 2 networked
  records are invalidated. ADR 0001's exact rustc query rules remain mandatory
  in fetch schema 3.

## Acceptance tests

- `production_policy::network_fetch_schema_two_binds_ca_and_redirect_policy`
- `host_input_closure::cargo_fetch_schema_three_binds_network_and_credential_contract`
- `linux_sandbox_launcher::network_policy_allows_only_resolved_tcp_endpoints`
- `linux_namespace_backend::network_escape_matrix_denies_dns_udp_unix_listen_and_unlisted_tcp`
- `production_cargo_fetch::networked_fetch_uses_only_attested_https_endpoints`
- `production_cargo_fetch::credential_helper_is_exact_pipe_only_and_secret_free`
