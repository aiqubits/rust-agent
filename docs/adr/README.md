# Architecture decision records

Accepted ADRs amend the normative architecture contract. Add a numbered file
from `0000-template.md`, link it here, and update affected invariants and named
acceptance tests in the same change.

## Decisions

- [ADR 0001: Admit Cargo 1.97.1's exact fetch-time target-information query](0001-cargo-fetch-target-information-query.md)
- [ADR 0002: Define the Linux fetch network boundary at actual TCP endpoints](0002-linux-fetch-network-boundary.md)
- [ADR 0003: Admit the pinned Cargo unit-graph channel override](0003-pinned-cargo-unit-graph-channel.md)
- [ADR 0004: Admit one anonymous fetch-runner wakeup socket class](0004-anonymous-fetch-wakeup-socketpair.md)
- [ADR 0005: Admit an inert files-only NSS daemon probe](0005-files-only-nss-probe.md)
- [ADR 0006: Admit the pinned Cargo build spawn-error socketpair](0006-cargo-build-spawn-error-socketpair.md)
