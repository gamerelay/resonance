# Handoff

Read this first when picking up work on the node. **Last updated:** 2026-10-02.

What changed and when: [CHANGELOG.md](../CHANGELOG.md). The design (roles, the registry API,
credentials, versioning, rollout) is GameRelay's
`docs/superpowers/specs/2026-09-29-resonance-v0-design.md`, a loose outline: what building
changed is in its "Changed while building" section. GameRelay's own `HANDOFF.md` has the
control-plane side.

## Where things stand

- **v0's node is done and in production.** The room-scoped TURN relay (UDP, and TCP and TLS),
  joined to GameRelay's registry: join, heartbeats, drain, revoke. Both nodes, `sfo-1` and
  `nyc-1`, run `d1820f2` (installed 2026-10-02: v0.2.0, with signed answers and the memory
  budget), each on its own droplet with TLS on 443; they measure each other in GameRelay's
  Admin → Network, and both have `RESONANCE_ALERT_WEBHOOK` set. Both have the control plane's
  answer key pinned, given out of band (`RESONANCE_CONTROL_KEY`), and believe no other answer.
- **Players' credentials are tickets** since 2026-10-01 (PR #7; docs/PROTOCOL.md, "Tickets"):
  the shared-key credentials are gone. A control plane that mints only tickets doesn't hand out
  a node that hasn't sent its sealing key.
- **The 2026-10-01 review** ([TECH_DEBT.md](../TECH_DEBT.md)): every security item is fixed and
  deployed (#9, #11, and GameRelay's control plane), each with a test that fails without it. What's left
  is correctness, tests, organization and docs debt, and the "Classes of bug to rule out".
- **The control plane's answers are signed** (#16; PROTOCOL.md, "Signed answers"; TECH_DEBT
  C2): each names the whole request it answers, and a node believes only the key it pinned.
  Once nodes have the key, the control plane can't be rolled back to a build that doesn't sign:
  they'd treat it as out of reach. GameRelay's side is its `resonance.ts`.
- **A node's memory is bounded** whatever its clients do: one budget (96 MB, 16 MB per IP) that
  allocations, kept tickets and streams all charge, streams per IP, and channels per allocation
  (PROTOCOL.md, "Limits"; TECH_DEBT C1). GameRelay's unit caps the process at 384 MB.
- **GameRelay is the only control plane** (`https://gamerelay.io/resonance/v0/…`, API
  `2026-09-29`). Nodes are minted, drained, revoked and deleted in its Admin → Nodes tab.
- **Dependencies** are current as of #13 (dalek 3, RustCrypto 0.11). The crypto crates share
  `digest` and `curve25519-dalek`, so bump them together, not one Dependabot PR at a time.
- CI (`.github/workflows/ci.yml`, actions pinned to commits) is green: the core's tests and a
  fuzz run, pion's and coturn's clients, and Chromium, Firefox and WebKit over UDP, TCP and TLS.

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
- Tests that depend on kernel buffers (the streams that never read) behave differently on macOS
  and Linux: check them in Docker on Linux before trusting a pass on a Mac.
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
- **The repo is public.** Security findings stay in GameRelay's private
  `docs/RESONANCE-SECURITY.md` until fixed and deployed, then move to TECH_DEBT.md (SECURITY.md).

## Next

- **Serving IPv6** (TECH_DEBT 27): a v6 `TURN_PUBLIC_IP` is refused since v0.2.0. Serving it
  needs a v6 socket, core tests with a v6 public IP, and care with probes across families.
- **C3** from "Classes of bug to rule out": lints against panics and silent overflow on the
  packet path, cheap insurance (C1 and C2 are done: #17, #16). Then C5 (a sequence number per
  node, with the next API version) and C6 (newtypes for scoped ids).
- **The heartbeat thread's own tests** (TECH_DEBT 17): `Heartbeats::run` (saving a pinned key
  and the control plane's issuers, the exit path) and `post_alert`.
- **The UDP benchmark on a Linux host** for the new loop: in Docker on a Mac, 1,000 pairs were
  even and 200 pairs a little behind in most rounds, within that run's drift (CHANGELOG).
- **Safari over TLS:** check it against NYC. If it refuses Let's Encrypt too, Safari players on
  networks that block UDP just play through the game server (nothing breaks); a certificate
  from a CA in libwebrtc's list would be the fix.
- **Capacity with load from another machine**: on one box the load generator runs out first.
- **Later in the design:** receipts and credits for node operators, community-run nodes, and the
  room "home" role (the envelope and receipts are drafted in the spec's appendices).
