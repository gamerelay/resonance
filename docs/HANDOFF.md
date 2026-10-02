# Handoff

Read this first when picking up work on the node. **Last updated:** 2026-10-01.

What changed and when: [CHANGELOG.md](../CHANGELOG.md). The design (roles, the registry API,
credentials, versioning, rollout) is GameRelay's
`docs/superpowers/specs/2026-09-29-resonance-v0-design.md`, a loose outline: what building
changed is in its "Changed while building" section. GameRelay's own `HANDOFF.md` has the
control-plane side.

## Where things stand

- **v0's node is done and in production.** The room-scoped TURN relay (UDP, and TCP and TLS),
  joined to GameRelay's registry: join, heartbeats, drain, revoke. Both nodes, `sfo-1` and
  `nyc-1`, run the ticket build (`cdea8f1`, 2026-10-01), each on its own droplet with TLS on
  443; they measure each other in GameRelay's Admin → Network, and both have
  `RESONANCE_ALERT_WEBHOOK` set.
- **Players' credentials are tickets** since 2026-10-01 (PR #7; docs/PROTOCOL.md, "Tickets"):
  the shared-key credentials are gone. A control plane that mints only tickets doesn't hand out
  a node that hasn't sent its sealing key (deployed 2026-10-01: control plane first, then each
  node; a leftover `TURN_SECRET` is ignored, and said to be).
- **Known debt:** [TECH_DEBT.md](../TECH_DEBT.md), from the 2026-10-01 review.
- **GameRelay is the only control plane** (`https://gamerelay.io/resonance/v0/…`, API
  `2026-09-29`). Nodes are minted, drained and revoked in its Admin → Nodes tab.
- CI (`.github/workflows/ci.yml`) is green: the core's tests and a fuzz run, pion's and coturn's
  clients, and Chromium, Firefox and WebKit over UDP, TCP and TLS.

## The nodes and deploying

How the nodes run (the systemd unit, its env file and sandbox, logs), the hosts, and the deploy
scripts (install, join, TLS) are in GameRelay's private `docs/INFRASTRUCTURE.md`, "TURN relays".
The scripts live in GameRelay's `deploy/turn/`, with this repo cloned next to it at
`../resonance`. This repo is public, so it doesn't map the hosts.

## Testing

The README's "Tests" has the commands. Locally on a Mac:

- `cargo test --release` (the core, the settings, and the relay loop in-process on loopback:
  `crates/resonance-node/tests/relay.rs`), then
  `cargo build --release && (cd interop && go test ./...)`.
- The browser test runs in the Playwright container (Linux), with the node built for Linux in
  Docker too. `TRANSPORT=tcp` or `tls`; TLS needs `libnss3-tools` in the container
  (`apt-get install -y libnss3-tools`) and `BROWSERS=chromium,firefox`.
- The benchmark: `docs/BENCH-2026-09-29.md`, "Reproduce".

## Things that bite

- **WebKit's TURN client trusts only roots built into it.** A test CA can't be added, and
  Playwright's Linux WebKit refused Let's Encrypt too (unknown CA), with the ECDSA chain and the
  RSA one. So the TLS browser test leaves WebKit out. Real Safari on macOS and iOS is still
  to check (GameRelay's HANDOFF has a console snippet for it).
- **The certificate is RSA on purpose.** Let's Encrypt's ECDSA chain goes YE1 → Root YE → ISRG
  Root X2 (cross-signed by X1); the RSA one goes to X1 directly, which older clients know.
  `tls-resonance.sh` asks for RSA. Let's Encrypt allows 5 certificates a week for one name, so
  don't reissue in a loop.
- **Firefox on macOS leaves loopback out of ICE**, so the browser test runs on Linux, against
  the machine's own non-loopback address.
- **In the Playwright container**, Firefox needs `HOME=/root` (GitHub sets another user's), and
  the job needs a C toolchain to build the node.
- **mio is edge-triggered**: a socket read for less than all it has is remembered in the loop
  (`again` in `relay.rs`), or it would never be read again.
- **Scanners probe 443 within minutes.** Their connections close at the 10 s first-message
  deadline or as junk; `TURN_DEBUG_STREAMS=1` shows them.

## Next

- **The UDP benchmark on a Linux host** for the new loop: in Docker on a Mac, 1,000 pairs were
  even and 200 pairs a little behind in most rounds, within that run's drift (CHANGELOG).
- **Safari over TLS:** check it against NYC. If it refuses Let's Encrypt too, Safari players on
  networks that block UDP just play through the game server (nothing breaks); a certificate
  from a CA in libwebrtc's list would be the fix.
- **The open security items** from the 2026-10-01 review (kept privately until fixed): two
  are high and small.
- **Capacity with load from another machine**: on one box the load generator runs out first.
- **Later in the design:** receipts and credits for node operators, community-run nodes, and the
  room "home" role (the envelope and receipts are drafted in the spec's appendices).
