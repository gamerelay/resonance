# Changelog

What changed in the node, newest first. Versions: the crates are all `0.1.0` until the first
tagged release; entries are by date, with the commits. The control plane's API is dated
separately (`resonance-proto::VERSION`, `2026-09-29`); an entry says when it changes.

## 2026-09-30

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

- `docs/CHANGELOG.md` (this) and `docs/HANDOFF.md` (where things stand, the deployed nodes,
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
