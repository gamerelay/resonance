# Tech debt

What we know needs doing in the node, from the review of 2026-10-01 (main at `cdea8f1`): code
organization, tests, docs and security. Items 1–10 are the security ones, all fixed or informational as of 2026-10-02. Ranked within each section. Size: S (an hour or two), M (a
day), L (more). Strike an item when it's fixed, with its commit or PR.

## Security

Nothing critical was found: the ticket cryptography, the STUN parser, room isolation and the
signed control-plane requests all held up. What it did find was kept private until fixed
(SECURITY.md); all of it is fixed and deployed on both nodes now.

| # | Priority | Size | Item |
|---|---|---|---|
| 1 | ~~High~~ | S | ~~**Stream queues could exhaust a node's memory**: clients that sent over TCP or TLS and never read their answers piled them up, 256 KB a stream and 256 streams an IP.~~ Fixed in #9 (2026-10-02): 64 KB a stream, 16 MB in all, a fixed send buffer, streams holding the most closed past 32 MB, and their own caps (1,024; 64 per IP). |
| 2 | ~~High~~ | S | ~~**Channel bindings per allocation were unlimited**: one allocation could bind 16,384.~~ Fixed in #9 (2026-10-02): 16 at once, then 508. |
| 3 | ~~Medium~~ | S | ~~**Ticket checks were budgeted per IP only**: many IPs could fill the loop with them (~40 µs each).~~ Fixed in #11 (2026-10-02): 5,000/s from everyone too (`TURN_TICKET_CHECK_RATE`). |
| 4 | ~~Medium~~ | S | ~~**The control plane's replay check keyed on the signature's text**: padding or the standard base64 alphabet gave a used signature a second spelling.~~ Fixed in GameRelay (2026-10-02): one spelling only. |
| 5 | ~~Low~~ | M | ~~**The control plane's answers were trusted on TLS alone, `http://` was allowed, and the peer list was unbounded**~~ (it makes the node probe every 2 s). Fixed in #11: https only (except localhost), at most 64 peers, never unspecified, multicast or broadcast addresses. Signed answers: "Classes of bug to rule out", 3. |
| 6 | ~~Low~~ | S | ~~**A joined node could set any URLs in a heartbeat**, sending players and other nodes' probes anywhere.~~ Fixed in GameRelay (2026-10-02): its URLs stay on the IP it joined with, and its TLS names must resolve to it. |
| 7 | ~~Low~~ | S | ~~**Per-instance caps didn't bind an issuer**, which names its own instances.~~ Fixed in #11: 8,192 allocations per issuer, half the relay ports (`TURN_MAX_PER_ISSUER`). |
| 8 | ~~Low~~ | S | ~~**A node deleted from the registry while offline never learned it was revoked**, and kept relaying.~~ Fixed in #11: on `unknown_node` it takes no new allocations until it's known again (not an exit: a control plane that lost its registry mustn't stop every node). |
| 9 | ~~Low~~ | S | ~~**CI pinned actions by tag, and installed Playwright without a lockfile.**~~ Fixed in #11: commits, and `npm ci` from a committed lockfile. |
| 10 | Info | — | The issuer kid is 64 bits; a 2^64 second preimage would let another issuer into the control plane's rooms. Use 16 bytes in a ticket v2. |

## Classes of bug to rule out

The fixes above each close one instance. These change the design so the whole class can't
happen, best value first. Each names the items above it would have prevented.

| # | Size | Change | What can no longer happen |
|---|---|---|---|
| C1 | M | **One memory budget for everything a client can make the node hold**: queues, half-read messages, channels, permissions, cached tickets, each charged to its client (per IP and per allocation) and to a global budget, with fixed-capacity tables instead of growable `Vec`s and maps. A charge that doesn't fit is refused, never allocated. | A client filling the node's memory, by any path (1, 2). Today each path has its own cap; a new one added without a cap is the next bug. |
| C2 | S–M | **The control plane signs its heartbeat answers** with a key the node pins at join (`node.json`), and the node acts on an answer only if it checks out. | Anyone between the node and its control plane, or holding its DNS or a mis-issued certificate, telling the node whose tickets to take, what to probe, or to drain (5, 8). |
| C3 | S | **Ban panics and silent overflow on the packet path by type and lint**: `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]` in the core (with the few invariant `expect`s allowed by name), and the fuzz run with `overflow-checks = true` (Tests, 14). | A packet crashing the node: with `panic = "abort"`, any reachable panic is an outage, and this makes one a compile error. |
| C4 | M | **Unauthenticated answers no bigger than what was sent**, as QUIC does: a client's first request is padded to the size of the answer it wants. Needs checking against Chrome's, Firefox's and Safari's TURN clients first. | The node amplifying traffic at a third party, whatever the rates are set to. Today a per-IP budget bounds it (about 5x). |
| C5 | S | **A sequence number per node instead of a cache of seen signatures**: each signed request carries a counter that must go up; the control plane keeps one number per node. With the next API version. | Replays, however a signature is spelled (4), and the cache to bound. |
| C6 | S | **Newtypes for what's scoped**: `Room(kid, instance, room)`, `IssuerKid`, `NodeId`, instead of `String`s joined with `/` and `:` (Organization, 21). | One issuer's room or instance standing in for another's by string accident (7 was a missing count, the next would be a mixed-up key). |
| C7 | S | **Narrower sandbox and dependency policy**: `SystemCallFilter=@system-service` and `RestrictAddressFamilies=AF_INET AF_INET6` on the unit, tried on a staging host first; `cargo deny` for sources, duplicate crypto crates and licenses next to `cargo audit`. | A compromised node process reaching beyond its sockets; an unexpected dependency source or a second copy of a crypto crate slipping in. |

C1 and C2 first: they remove the two classes this review found most of. C3 is cheap insurance.

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
