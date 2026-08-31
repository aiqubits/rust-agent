# Security policy

Please report vulnerabilities privately to the repository maintainers rather
than opening a public issue. Include the affected composition/profile, target,
reproduction steps, and whether the issue can cross a capability or build-policy
boundary.

Security-sensitive changes must preserve fail-closed parsing and resolution,
prove that denied operations occur before external side effects, and add a
regression test. Runtime effects and build-time requirements are separate
accounting domains; neither may silently authorize the other.

No Phase 1A development artifact is deployable. Production claims require the
host-specific Phase 1B enforcement backend, escape suite, and attestation gate
defined by the architecture contract.
