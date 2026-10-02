# Contributing

Thanks for looking. Resonance is young and small, so issues and pull requests are both welcome:
for anything bigger than a fix, open an issue first so we can agree on the shape.

How it's built: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The wire formats:
[docs/PROTOCOL.md](docs/PROTOCOL.md). Security issues: [SECURITY.md](SECURITY.md), not an issue.

## Building and testing

```sh
cargo build --release
cargo test --release                       # the core, a fuzz run, the relay loop on loopback
cd interop && go test ./...                # pion's client against the built node
```

The README's "Tests" has the rest (coturn, and Chromium, Firefox and WebKit in Docker). CI runs
all of it on every pull request.

## Before you open a pull request

- **Lint and format.** `cargo fmt` and `cargo clippy --all-targets -- -D warnings` must pass.
- **The minimum Rust version is 1.85** (`rust-version` in `Cargo.toml`; CI builds with it). Let-chains
  (`if let … && …`) aren't stable there; use nested `if`.
- **Rules go in the core.** A TURN rule belongs in `resonance-turn`, which never touches sockets
  or the clock, and it gets a test there. `resonance-node` only moves bytes and time in and out.
- **No allocation per packet.** Keep the relay path free of per-packet allocations.
- **Keep the API additive.** Within an API version (`resonance-proto::VERSION`), changes are
  additions only: new fields are optional on both sides (`#[serde(default)]`). If a wire type
  changes, update the fixtures shared with the control plane.
- **Update the changelog.** Add a line to [CHANGELOG.md](CHANGELOG.md) under today's date:
  what changed, and what it means for someone running a node.

## License

By contributing, you agree your work is licensed under the [MIT License](LICENSE).
