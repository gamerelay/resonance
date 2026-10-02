# Tech debt

What we know needs doing in the node, from the review of 2026-10-01 (main at `cdea8f1`): code
organization, tests, docs and security. Items 1–10 are the security ones: the fixed ones are listed below, the rest kept privately until fixed. Ranked within each section. Size: S (an hour or two), M (a
day), L (more). Strike an item when it's fixed, with its commit or PR.

## Security

Nothing critical was found: the ticket cryptography, the STUN parser, room isolation and the
signed control-plane requests all held up. The items it did find are tracked privately until
they're fixed (SECURITY.md), then listed here.

| # | Priority | Size | Item |
|---|---|---|---|
| 1 | ~~High~~ | S | ~~**Stream queues could exhaust a node's memory**: clients that sent over TCP or TLS and never read their answers piled them up, 256 KB a stream and 256 streams an IP.~~ Fixed in #9 (2026-10-02, deployed): 64 KB a stream, 16 MB in all, a fixed send buffer, streams holding the most closed past 32 MB, and their own caps (1,024; 64 per IP). |
| 2 | ~~High~~ | S | ~~**Channel bindings per allocation were unlimited**: one allocation could bind 16,384.~~ Fixed in #9 (2026-10-02, deployed): 16 at once, then 508. |

## Correctness

| # | Priority | Size | Item |
|---|---|---|---|
| 11 | **High** | S | **An IPv6 `TURN_PUBLIC_IP` is accepted but never served**: the node binds `0.0.0.0` only (`main.rs`), so it advertises URLs it doesn't answer. Fix: bind `[::]` dual-stack for a v6 address, or refuse v6 in settings until then. |
| 12 | **High** | S | **The version doesn't show the breaking change.** The crates are still 0.1.0 (tagged `v0.1.0`) though tickets removed the HMAC credentials, `/nodes/key` and `key_version`, and the heartbeat's `software` reads `resonance-node 0.1.0` for builds from before and after. The API `2026-09-29` was also changed in place (CHANGELOG says so). Fix: 0.2.0 and a tag now; next time a breaking wire change bumps `resonance_proto::VERSION`. |
| 13 | Low | S | A dead heartbeat thread goes unnoticed: `relay.rs` ignores `Disconnected` from its channel. Log it once. |

## Tests

`cargo test --workspace` passes (113 tests, about 4 s), clippy is clean, and MSRV 1.85 builds.

| # | Priority | Size | Item |
|---|---|---|---|
| 14 | Medium | S | **Overflow is never checked**: CI and the fuzz run use `--release`, which wraps integer overflow silently, so "nothing panics" misses it. Add a debug `cargo test` step, or `overflow-checks = true` for the fuzz run. |
| 15 | Medium | S | **MSRV isn't enforced in CI** (stable only). Add a `cargo +1.85 check --workspace --all-targets` job. |
| 16 | Medium | S | **A conformance test now tests the old format**: `malformed_rest_usernames_are_refused_without_a_panic` (`tests/conformance.rs`) feeds `expiry:i:r:p` usernames, which all fail at the `t1:` prefix. Rewrite with malformed `t1:` tickets through the server (field counts, empty parts, bad base64, expiry overflow). |
| 17 | Medium | M | **The control-plane client and heartbeat thread are untested**: `Client::post` (headers, the error fallback), `Heartbeats::run` (only control-plane issuers saved, the exit path, the first beat at once) and `post_alert`. Test against a tiny local HTTP server, checking the signature with proto's `signing_string`. |
| 18 | Medium | M | **The node's own Rust tests can't relay**: `tests/relay.rs` builds a config with no sealing key or issuers, so no allocation succeeds. The data path, TLS and the `mint`/`seal-key`/`issuer` commands are covered only by interop and the browsers in CI. Add an allocate-and-relay test over UDP and TCP. |
| 19 | Low | M | No tests for `tls.rs` (`reload_if_changed`, the certbot renewal path) or for `relay.rs`'s outbox drop and stream back-pressure. |
| 20 | Low | S | Two node tests lean on wall-clock time (`elapsed < 2500ms`, an 8 s probe deadline in `tests/relay.rs`). Widen them or inject the tick. |

## Organization

| # | Priority | Size | Item |
|---|---|---|---|
| 21 | Medium | M | **Issuers travel as strings and are parsed in five places** (`settings.rs`, `main.rs` twice, `control.rs`, `relay.rs`), and `main.rs` overwrites what `settings.rs` parsed. Parse once into `Issuer` (with `PartialEq` and its base64 form) and carry `Vec<Issuer>` in `Control::Issuers`. |
| 22 | Low | S | `seal_public` as base64 is written twice (`main.rs`, `control.rs`): one helper in `resonance_turn::ticket`. `State::from_env()` is read twice in `run_node`. |
| 23 | Low | M | **`server.rs` (942 lines) does too much.** Move authentication and the ticket cache to their own module, and the relaying path (`relay`, `channel_data`, `send_indication`) to another. In the node: `Stream`/`Outbox` out of `relay.rs`, `run_node` into the library (testable), `issuer`/`mint` into a `cli.rs`. |
| 24 | Low | M | **`resonance-turn`'s public API is wider than it needs**: every module is `pub` (`counts`, `limiter` included) and `Config`'s fields are all public, so any new field breaks callers. `pub(crate)` the internals, `#[non_exhaustive]` or a builder for `Config`, and `publish = false` until it's meant for crates.io. Matters once the embeddable module (ARCHITECTURE.md, "Where it's going") has users. |
| 25 | Low | S | At the next API version: make `seal_key` required in `JoinRequest` and `Heartbeat` (an `Option` now, always sent), and drop the proto tests' `key_version` (kept to show it's ignored). |

## Docs

Fixed in the same change as this file: the README's and SECURITY.md's descriptions of credentials
from before tickets, the proto and control-module comments, a stale line folded into
`accepting`'s doc, coturn's transports, pointers to the deleted Go relay, the bench's reproduce
steps, and HANDOFF.md (the nodes' state; host and deploy details moved to GameRelay's private
INFRASTRUCTURE.md).

| # | Priority | Size | Item |
|---|---|---|---|
| 26 | Low | S | The CHANGELOG's 2026-10-01 entry has no commit hashes, though its header promises them. Add them with the 0.2.0 release (#12). |
