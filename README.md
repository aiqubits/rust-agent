# rust-agent

`rust-agent` is an independent, cross-platform Rust Agent Runtime built around
compile-time capability composition. A composition compiler resolves typed
Capability/Provider/Consumer metadata and emits a standalone Cargo graph that
contains only the selected Components.

The project is being delivered in gated phases. The normative design is in
[`ARCHITECTURE.md`](ARCHITECTURE.md), current implementation status is in
[`docs/phase-status.md`](docs/phase-status.md), and repository contribution gates
are in [`AGENTS.md`](AGENTS.md).

## Development

Development uses exactly Rust and Cargo 1.97.1. `rustup` reads the checked-in
`rust-toolchain.toml` and selects the pinned compiler, formatter, Clippy, and CI
cross-compilation target set; do not override it with `+stable` or `+nightly`.

```sh
rustc --version
cargo --version
cargo fmt --all --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```

The checked-in `tests/fixtures` packages have no product semantics. They exist to
prove that generated Cargo dependency graphs physically add and remove selected
Component packages during Phase 1A.
