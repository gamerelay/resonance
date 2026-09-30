# Handoff

Read this first when picking up work on the node. **Last updated:** 2026-09-30.

What changed and when: [CHANGELOG.md](CHANGELOG.md). The design (roles, the registry API,
credentials, versioning, rollout) is GameRelay's
`docs/superpowers/specs/2026-09-29-resonance-v0-design.md`, a loose outline: what building
changed is in its "Changed while building" section. GameRelay's own `HANDOFF.md` has the
control-plane side.

## Where things stand

- **v0's node is done and in production.** The room-scoped TURN relay (UDP, and TCP and TLS),
  joined to GameRelay's registry: join, key, heartbeats, drain, revoke, key rotation. Both of
  GameRelay's relays run `9350911`.
- **GameRelay is the only control plane** (`https://gamerelay.io/resonance/v0/…`, API
  `2026-09-29`). Nodes are minted, drained and revoked in its Admin → Nodes tab.
- CI (`.github/workflows/ci.yml`) is green: the core's tests and a fuzz run, pion's and coturn's
  clients, and Chromium, Firefox and WebKit over UDP, TCP and TLS.

## The nodes

| | SF (`sfo-1`) | NYC (`nyc-1`) |
|---|---|---|
| Host | `asleepace.com`, `192.241.216.26`, shared with other services (Ubuntu 23.10, 2 vCPU) | `gamerelay-turn-nyc3-1`, `167.172.234.10`, its own $6 droplet (Debian 13, 1 vCPU) |
| Node id | `rn_mxuujbghsqg4bnt5n2lae3w54a` | `rn_hanrbqr7ezoznqcas43pibjmwu` |
| Serves | UDP 3478 | UDP 3478, TLS 443 (`turns:turn-nyc.gamerelay.io:443?transport=tcp`) |
| Firewall | ufw (UDP 3478; the old Go relay's 49152–65535 still open) | **none yet** (checked 2026-09-30): SSH and systemd-resolved's LLMNR (5355) are open to anyone. Wanted: a cloud firewall with UDP 3478, TCP 443 and 80 (certbot), SSH from one IP |
| Certificate | none (443 is nginx's) | Let's Encrypt, RSA, certbot's timer renews it |

Both run as the systemd unit `gamerelay-turn` (a dynamic user, `StateDirectory=resonance`,
`TURN_MAX_PER_IP=256`), from `/etc/gamerelay-turn.env` (`TURN_PUBLIC_IP`, and on NYC the
`TURN_TLS_*` settings). Logs: `journalctl -u gamerelay-turn`, with a stats line each minute
(`allocations N, streams N, …`).

## Deploying

The scripts live in GameRelay's repo, `deploy/turn/`, with this repo cloned next to it at
`../resonance`:

- `TURN_PUBLIC_IP=<ip> bash deploy/turn/install-resonance.sh root@<host>`: builds this repo for
  linux/amd64 in Docker and installs it (a new host: the env file, buffer caps, and the node
  left stopped until it joins). Re-run to update a node: it restarts it, so check the stats line
  for `allocations 0` first.
- `bash deploy/turn/join-resonance.sh root@<host> rjt_…`: joins it with a token from Admin →
  Nodes (a person mints and pastes it).
- `bash deploy/turn/tls-resonance.sh root@<host> <name>`: TLS on 443. It agrees to Let's
  Encrypt's terms, so a person says yes first. Needs the name's A record, and TCP 80 and 443
  open.

## Testing

The README's "Tests" has the commands. Locally on a Mac:

- `cargo test --release`, then `cargo build --release && (cd interop && go test ./...)`.
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

- **A firewall for NYC** (👤, DigitalOcean): UDP 3478, TCP 443 and 80, SSH from your IP only.
  Nothing else there needs to be reachable.
- **Safari over TLS:** check it against NYC. If it refuses Let's Encrypt too, Safari players on
  networks that block UDP just play through the game server (nothing breaks); a certificate
  from a CA in libwebrtc's list would be the fix.
- **The SF relay onto its own droplet**, off the shared box (GameRelay's HANDOFF, "Next, in
  order"), and then TLS there too. Close the old Go relay's UDP 49152–65535 on SF: nothing
  listens there now.
- **Capacity with load from another machine**: on one box the load generator runs out first.
- **Later in the design:** receipts and credits for node operators, community-run nodes, and the
  room "home" role (the envelope and receipts are drafted in the spec's appendices).
