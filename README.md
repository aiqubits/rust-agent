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
The JavaScript WASM fixture additionally requires exactly `wasm-bindgen-cli`
version `0.2.127`; both its Rust protocol crates and the CI-installed executable
are pinned and checked by automated synchronization tests.

```sh
rustc --version
cargo --version
cargo fmt --all --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```

Install the pinned post-link executable before running the full suite:

```sh
cargo install wasm-bindgen-cli --version 0.2.127 --locked
wasm-bindgen --version
```

WASM `compose` and development `build` calls take `--registry-cache` explicitly.
The directory is used only as an offline Cargo source cache; it does not enter
composition identity, while `Cargo.lock` checksums and the canonical crates.io
source identity do. The build policy must map `wasm-bindgen-cli` to its canonical
absolute path, SHA-256 digest, and exact `wasm-bindgen 0.2.127` version output.

The checked-in `tests/fixtures` packages have no product semantics. They exist to
prove that generated Cargo dependency graphs physically add and remove selected
Component packages during Phase 1A.
