# Changelog

What changed in the node, newest first, by date, with the commits. Releases are tagged
`v<version>` (the crates' version, `Cargo.toml`); an entry says where one was cut. The control plane's API is dated
separately (`resonance-proto::VERSION`, `2026-09-29`); an entry says when it changes.

## 2026-10-02

**A node's memory stays bounded whatever its clients do.** The review of 2026-10-01 (TECH_DEBT.md)
found two ways for clients to fill a node past its memory cap; both are closed.

- **Streams.** Clients that send over TCP or TLS and never read their answers could pile up
  queued answers: 256 KB a stream, 256 streams an IP. Now a stream's queue is 64 KB, all queues
  together 16 MB, and a stream's kernel send buffer fixed at 64 KB. Once a second, past 32 MB held
  by all streams (queues and half-read messages), the loop closes the streams holding the most.
  Streams have their own caps: `TURN_MAX_STREAMS` 1,024 (was 4,096), and
  `TURN_MAX_STREAMS_PER_IP` 64 (it was the allocation cap, `TURN_MAX_PER_IP`, 256 in GameRelay's
  production).
- **Channels.** An allocation could bind a channel to every port of the node (16,384). Now 16 at
  once; a new one past that gets 508, and a refresh still works.
- Tests for both: the loop closes streams that never read while keeping one that does, and an
  allocation stops at 16 channels and has room again once they expire. Each fails without its
  fix.

## 2026-10-01

**Players' credentials are tickets, from any issuer the node trusts.** The shared-key
credentials are gone.

- A ticket is signed by an issuer, an ed25519 key: a control plane, or a game's own server
  (`resonance_turn::ticket`). The password comes from key agreement between a fresh X25519 key in
  the ticket and the node's sealing key, so the node shares no secret with any issuer, and one
  ticket serves every node (docs/PROTOCOL.md, "Tickets").
- Rooms are scoped by issuer (`<kid>/<instance>`), so one issuer can't mint into another's rooms.
  A ticket lasts a day at most (plus 5 minutes of clock skew). An issuer no longer trusted is
  refused at its allocations' next request.
- Ticket checks (~40 µs each) are budgeted per IP on every transport, and a checked ticket is
  remembered (8,192 of them), so a flood can't hold the loop up and a player's other allocations
  cost a hash.
- The sealing key is derived from the node's ed25519 seed, so there's no new key file. It goes
  with the join and each heartbeat (`seal_key`); `seal-key` and `status` print it.
- Trusted issuers: `RESONANCE_ISSUERS`, and the control plane's list in each heartbeat's answer
  (`issuers`). The control plane's are saved to `issuers.json`, so a node restarted while its
  control plane is out of reach still relays ticket holders. Before, a node started then waited
  for the control plane, since it couldn't fetch its key.
- **Gone:** the HMAC credentials, a node key per node (`/nodes/key`, `key_version`, rotation),
  and running by hand with `TURN_SECRET`. A leftover `TURN_SECRET` or `RESONANCE_NODE_KEY` is
  ignored, and said to be. Removing `/nodes/key` and `key_version` breaks API `2026-09-29` for
  builds from before: done within it because nothing else speaks it (GameRelay's control plane
  changes with this, and its two nodes are redeployed).
- **On its own** (no control plane): `RESONANCE_ISSUERS` alone. `resonance-node issuer <file>`
  and `mint` are a minimal issuer.
- Tests: the fixture shared with the control plane, in three implementations (Rust, GameRelay's
  TypeScript, and Go in `interop/ticket`); untrusted, tampered, expired, over-long and wrongly
  keyed tickets; rooms scoped by issuer; an issuer dropped mid-allocation; a flood of bad
  tickets over a stream spending only its IP's budget. The interop tests (pion over UDP, TCP and
  TLS; coturn in six modes; the browsers) and the benchmark mint tickets. In GameRelay's e2e:
  Chrome players relaying through a joined node, and through it again restarted with its control
  plane cut off.
- The benchmark measures builds that take tickets; v0.1.0 and the Go relay need it as of v0.1.0.

**v0.1.0**, the first tagged release: everything below, as in production on both nodes since
2026-09-30, with these docs.

**Docs.** No change in the node.

- `docs/ARCHITECTURE.md`: the network's roles, what each leaked secret allows, inside a node
  (the sans-I/O core, the one event loop, the control thread), observing the network,
  performance, compatibility, and where it's going.
- `docs/PROTOCOL.md`: TURN as the node speaks it (transports, methods, credentials, nonces, the
  room rule, errors, limits), the control plane's API (identity, signed requests, the three
  endpoints, statuses, errors, versioning), and the peer probes.
- `SECURITY.md` (private reports through GitHub's advisories), `CONTRIBUTING.md`, issue and
  pull request templates. Dependabot for Cargo, Go and Actions, and `cargo audit` on dependency
  changes and weekly (`.github/workflows/audit.yml`).
- The hosts, firewalls and node ids left `docs/HANDOFF.md` for GameRelay's private
  infrastructure doc: this repo is public.
- The README has a banner, badges (CI, and the version, MSRV and API version read from the
  source), an overview and a diagram. This changelog moved to the root.

## 2026-09-30

**Nodes measure each other, and watch the control plane.** Additions within API `2026-09-29`.

- The heartbeat's answer names the other live nodes (`HeartbeatResponse.peers`: id and the
  `ip:port` of its relay socket). Each gets a STUN Binding every 2 s from this node's relay
  socket, so it takes players' path and firewalls; the answers are taken out before the core
  sees them (`probe.rs`, sans-I/O). Each heartbeat reports the last 30 s per peer
  (`Heartbeat.peers`: sent, answered, the median round trip). The control plane alerts on a
  node nobody's probes reach, and draws the matrix in its network view.
- `RESONANCE_ALERT_WEBHOOK` (a Discord or Slack incoming webhook): a node that can't reach the
  control plane for `RESONANCE_ALERT_AFTER_S` (120) in a row says so there, once, and again when
  it's back; the control plane can't say it's down itself. A refusal (a 4xx) is an answer, not
  an outage; a 5xx is.
- An old control plane sends no peers (nothing measured); an old node sends no reports.
- Tests: the prober (timing, the window sliding, unanswered and late probes, only our answers
  taken, peers changing), two nodes in-process measuring each other and one that's gone, the
  watch (once after a while, its return, blips), the peers fixture shared with the control plane.

**Small cleanups in the core.** No change in what it does.

- `resonance_turn::counts::Counts`: a count per key that forgets the key at zero, for the
  allocations per player, IP and game, and the node's streams per IP. The same few lines were
  written out four times.
- A refusal is `Refusal::unsigned(code)` or `Refusal::signed(code, key)`, its reason phrase from
  `stun::reason(code)`: 13 hand-built structs, each repeating its phrase.
- `Output::iter` is gone: `sends()` gives the address and the connection.

**Settings, read once.** No change in what they mean. `7870302`

- `resonance_node::settings::Settings` reads every setting at startup, from any lookup
  (`from_lookup`), and returns what's wrong instead of exiting: main.rs is the wiring. Before,
  the TCP and TLS settings were read three times over and every parser exited the process, so
  none of it could be tested.
- `join` checks every setting now, not only the ones for its URLs: a bad one fails at join
  rather than at the first `run`.
- Tests: the defaults (the Go relay's), `TURN_MAX_PER_IP` carrying the unauthenticated burst
  and the per-IP stream cap, the URLs' order (UDP first, the rule the control plane checks),
  the hand-run key, and each bad setting refused.

**The relay loop, taken apart.** No change in what it does. `8a0fa0b`

- `resonance-node` is a library and a thin binary. The loop (`relay::Relay`) is a struct with a
  method per job (UDP, accepting, a stream's turn, closing, the once-a-second and once-a-minute
  work) where it was one 320-line function; a stream's outgoing queue is its own type (`Outbox`),
  so its answers no longer need a copy of the queueing code.
- `relay::run` returns when the node is revoked (the binary then exits 0), and returns errors
  instead of exiting, so tests can run the loop in a thread.
- `Limits` carries the stream deadlines (10 s first message, 15 min idle) and
  `TURN_DEBUG_STREAMS`, which now gives every close's reason (not TURN, closed by the client, no
  message in time, idle, or the error).
- The heartbeat's numbers are updated before a revoke is acted on, so the last ones are sent.
- Connection numbers skip ones still open when they wrap (after 2^32 connections).
- Tests (`crates/resonance-node/tests/relay.rs`, on loopback): a stream that sends nothing is
  closed at its deadline, a silent one once idle, streams per IP are capped and a closed one's
  place freed, and a revoke stops the loop.
- Benchmark (old and new alternating, Docker on a Mac): 1,000 pairs even (p50 141–153 µs against
  126–154). 200 pairs: the new median higher in 6 of 8 rounds (median of medians 296 µs against
  279), within the run's drift (both went from about 210 to 360 µs); CPU the same. To check on a
  Linux host.

**A stalled TLS client keeps its connection.** `0fd9e53`, `89044fc`

- Fixed: a TLS stream with more than 64 KB queued (a client whose network stalled for a few
  seconds) was closed instead of dropping messages. rustls takes at most its own buffer's limit
  at a time, and the rest was handed over whole (`write_all`), which failed. Now what it takes
  is written, the rest waits for the next turn. Plain TCP was right already.
- `TURN_DEBUG_STREAMS=1` also says why a stream closed on a write, not only on a read.
- Tests: `TestAStalledTLSClientKeepsItsConnection` (a client that stops reading while 20 MB is
  sent its way, then carries on; it fails on the old build on Linux and macOS). It first shrank
  the client's receive buffer to 4 KB, which on Linux trickles the backlog out for over a minute
  and made it flaky in CI (it failed on `8a0fa0b`): now the buffers are the system's. The interop
  tests wait for the node to answer instead of sleeping 200 ms, which lost the race now and then.

**TURN over TCP and TLS** (RFC 8656 §12.5), for networks that block UDP. `26d3138`, `9350911`

- **TLS listener** when `TURN_TLS_CERT` and `TURN_TLS_KEY` name PEM files (certbot's
  `fullchain.pem` and `privkey.pem`), on `TURN_TLS_PORT` (default 5349; 443 gets through the
  most firewalls), for `TURN_TLS_HOST`, the certificate's name. The files are read again when
  they change, so a renewal needs no restart; open connections keep the certificate they started
  with. rustls with ring, the same copy ureq already brought.
- **Plain TCP** on `TURN_PORT` with `TURN_TCP=1`. Off by default: it needs its own firewall
  opening, and a URL players can't reach only costs them a try.
- **One event loop** (mio, one thread) for the UDP socket, both listeners and every connection.
  The core stays unlocked; a message is read, handled and answered in one go. Each stream is read
  for at most 256 KB a turn, and UDP for 1,024 datagrams, so one busy client can't hold up the
  rest. A stream's outgoing queue is capped at 256 KB: past it, messages are dropped whole.
- **Streams are their own clients.** The core keys clients by address and connection
  (`resonance_turn::Client`), so a TCP connection is its own 5-tuple even at an ip:port a UDP
  client also uses. An allocation ends when its connection closes (`Server::closed`).
- **A stream isn't budgeted as an unknown UDP source**: its handshake proved its address, so
  nothing it's sent can be aimed at anyone. A busy stream also no longer spends the UDP budget at
  its IP, which could lock out UDP players behind the same NAT (found by the flood test).
- **Stream framing** (`resonance_turn::stream`): STUN sized by its header (and its magic cookie
  checked), ChannelData padded to 4. The first message must be STUN, so HTTP, a TLS ClientHello
  on the plain port and other junk are hung up on at once. A stream that hasn't sent a whole
  message in 10 s is closed, and one silent for 15 minutes.
- **The node's URLs go with every heartbeat** (`Heartbeat.urls`: UDP first, then TCP, then
  `turns:` at its name), so a node that starts serving TLS says so without joining again. An
  addition within API `2026-09-29`: servers that don't know it ignore it.
- `TURN_MAX_STREAMS` (4096): open streams, all together; per IP, `TURN_MAX_PER_IP`.
- `TURN_DEBUG_STREAMS=1`: each stream's opening and why it closed.
- The stats line each minute counts streams.
- **Tests:** framing unit tests; core tests for stream clients (one address, two 5-tuples; a
  stream relaying with a UDP client; a closed stream freeing its allocation and quota; streams
  not budgeted). Interop (`interop/streams_test.go`): pion over TCP and TLS relaying with UDP
  players and each other, a closed stream freeing its allocation, junk hung up on, a flooding
  stream not stalling others, a certificate for another name refused. Browsers
  (`relay.mjs`, `TRANSPORT=udp|tcp|tls`): all 9 pairings over TCP; Chromium and Firefox over TLS
  with a trusted CA, and both refusing an untrusted one (`TLS_TRUST=none`). All in CI.
- **Benchmark:** UDP unchanged by the new loop (200 and 1,000 pairs, old and new alternating).
- CI refreshes apt before installing coturn (a stale index failed the job).

**Docs.** `d318209`, `671367f`

- `docs/CHANGELOG.md` (this file, since moved to the root) and `docs/HANDOFF.md` (where things stand, the deployed nodes,
  deploying, testing, what bites, what's next). The README says v0 is in production and covers
  TCP and TLS.

## 2026-09-29

**The node joins the network.** `5dd2f6f`

- `resonance-proto`: the control plane's wire types (node ids, signed requests, join, key,
  heartbeat, statuses), with fixtures shared with GameRelay's control plane.
- `resonance-node join <token>` (once: makes its ed25519 key, registers it), `run` (fetches its
  own key; a heartbeat every 15 s), `status`, `version`. State in `RESONANCE_STATE_DIR` (default
  `/var/lib/resonance`); the control plane at `RESONANCE_CONTROL` (default
  `https://gamerelay.io`).
- The control plane drains a node (no new allocations), revokes it (it stops), rotates its key
  (the old one accepted for an hour), or tells it to upgrade. A control plane that can't be
  reached changes nothing: the node keeps relaying.
- Still runs by hand with `TURN_SECRET`, like the Go relay.

**Limits are settings.** `32dc714`

- `TURN_MAX_PER_PLAYER` (8), `TURN_MAX_PER_IP` (64), `TURN_MAX_PER_INSTANCE` (4096),
  `TURN_UNAUTH_RATE` (20/s), `TURN_UNAUTH_BURST` (the per-IP cap), `TURN_RATE_BYTES` (131072),
  `TURN_BURST_BYTES` (twice the rate). Players behind one NAT hold an allocation per other player
  even when the LAN route wins, so GameRelay runs with `TURN_MAX_PER_IP=256`.

**Conformance pass** against what coturn, pion, eturnal, STUNner, LiveKit and the browsers' own
TURN clients (libwebrtc, Firefox's nICEr) check. `13bae5a`

- Fixed: the unknown-attribute scan read past MESSAGE-INTEGRITY (an RFC 8489 client would get a
  420); nonces are bound to the client's address; every unsigned answer to an unknown source is
  rate-limited, not only 401s (reflection); an invalid nonce gets 438.
- Added: RFC 5769's vectors, real Chrome and Firefox captures (from pion, `tests/testdata`),
  coturn's and eturnal's auth corner cases, coturn's client in six modes (`interop/coturn.sh`),
  and every pairing of Chromium, Firefox and WebKit (`interop/browsers/relay.mjs`).
- CI: the node is built before the interop steps, and a missing build fails in CI instead of
  skipping (`acc3f1e`); the browsers job's container gets a C toolchain (`5291203`) and
  `HOME=/root` for Firefox (`1755b76`).

**Benchmark against the Go relay** (`docs/BENCH-2026-09-29.md`). `0940a4e`, `6605e91`

- A flat ~0.2 ms median up to 2,000 pairs, where the Go relay goes from 1 ms to 31 ms and drops
  8% at the top; about a fifth of the CPU; 15–20 times less memory per allocation.
- On GameRelay's SF host before the swap: half the Go relay's median, a quarter to a third of
  its CPU, no loss.
- The small loss seen at low load was the bench counting packets still in flight as lost, not
  the relay: fixed in `interop/cmd/bench`.

**The room-scoped TURN relay in Rust.** `0f8cefd`

- `resonance-turn`, sans-I/O: every rule of GameRelay's Go relay (pion/turn), testable without
  sockets. Its own STUN codec, parsed in place with nothing allocated per packet.
- The only permitted peer is the node itself (both players of a pair allocate on it), so relay
  addresses are names, not sockets: every relayed packet goes from one allocation to another in
  memory, and nothing else on the machine is reachable through it.
- TURN REST credentials (`expiry:instance:room:player`, HMAC-SHA1 with the node's key); an
  allocation answers only to the room and player it was made for; stateless nonces; every error
  after authentication signed (Firefox drops unsigned ones).
- `resonance-node`: the core on one blocking UDP socket, 4 MB socket buffers.
- Tests: the Go relay's, ported; a fuzz run on stable; pion's client against the built node.
