# Protocol

A node speaks two protocols:

1. **TURN to players** (RFC 8656 on RFC 8489's STUN): players' browsers and SDKs reach each other
   through it. It's the standard protocol with one rule added: an allocation can only reach
   another allocation of the same room on the same node.
2. **HTTP to the control plane**: the node joins the network, fetches its key and sends a
   heartbeat every 15 s. Requests are signed with the node's ed25519 key. The wire types are in
   [`resonance-proto`](../crates/resonance-proto/src/lib.rs).

The design and the reasons behind it are in [ARCHITECTURE.md](ARCHITECTURE.md).

## 1. TURN, to players

### Transports

| URL | Where | Setting |
|---|---|---|
| `turn:<ip>:3478` | UDP, always | `TURN_PORT` |
| `turn:<ip>:3478?transport=tcp` | TCP, off by default | `TURN_TCP=1` |
| `turns:<name>:443?transport=tcp` | TLS 1.2/1.3 (rustls) | `TURN_TLS_CERT`, `TURN_TLS_KEY`, `TURN_TLS_PORT`, `TURN_TLS_HOST` |

A node lists its URLs in this order: UDP first, then TCP, then TLS. On TCP and TLS, messages are
framed as RFC 8656 §12.5 describes:

- STUN is sized by its header, and its magic cookie is checked.
- ChannelData is padded to 4 bytes.
- The first message must be STUN. Anything else is hung up on at once: HTTP, a TLS ClientHello on
  the plain port, any other junk.

A stream that hasn't sent a whole message in 10 s is closed, and so is one silent for 15 minutes.
Each stream is its own client, even at an `ip:port` a UDP client also uses. Its allocation ends
when it closes.

### Methods

| Method | | Notes |
|---|---|---|
| Binding | request | Unauthenticated, rate-limited per IP |
| Allocate | request | UDP relays only (`REQUESTED-TRANSPORT` 17). Lifetime 600 s by default, 3600 s at most |
| Refresh | request | `LIFETIME 0` deletes the allocation |
| CreatePermission | request | Peers must be this node's own address (see below) |
| ChannelBind | request | Channels last 600 s, permissions 300 s |
| Send / Data | indication | |
| ChannelData | | Over UDP, TCP and TLS |

### Credentials

A node takes two kinds of credential: **tickets**, which any issuer it trusts can mint, and the
control plane's own **HMAC credentials**, which only work on one node.

#### Tickets

An issuer is an ed25519 key: a control plane, or a game's own server. A ticket names a room and
a player, and is signed by its issuer. The password comes from key agreement with the node, so
the node checks a ticket without sharing any secret with whoever minted it.

```
username = t1:<expiry>:<instance>:<room>:<player>:<kid>:<eph>:<sig>
kid      = base64url( SHA-256(issuer public key)[0..8] )
eph      = base64url( a fresh X25519 public key, one per ticket )
sig      = base64url( ed25519(issuer, "resonance/ticket/v1\n" + everything before ":<sig>") )
password = base64url( HMAC-SHA256( X25519(eph secret, node sealing key),
                                   "resonance/ticket/v1\n" + everything before ":<sig>" ) )
```

- **One ticket for every node.** Each node gets its own password from the same username: the
  issuer runs the key agreement once per node, and each node runs it with its own secret.
- **Nobody can compute a password from the username alone,** so a ticket seen on the wire is no
  use without its password.
- **The sealing key** is X25519, derived from the node's ed25519 seed:
  `HMAC-SHA256(seed, "resonance/seal/v1")`. Its public half goes with the join and every
  heartbeat (`seal_key`), and `resonance-node status` prints it.
- **Rooms are scoped by issuer.** On the node, a ticket's game is `<kid>/<instance>`, so one
  issuer can't mint a ticket into another issuer's rooms.
- **Limits.** A ticket lasts at most a day. A node refuses tickets from issuers it doesn't trust,
  and an issuer it stops trusting is refused at its allocations' next request.
- **Whom a node trusts.** Its own `RESONANCE_ISSUERS` (ed25519 public keys, base64url,
  comma-separated), and the issuers its control plane lists in each heartbeat's answer. It saves
  the last list (`issuers.json` in its state directory). If it restarts while its control plane
  is out of reach, it relays ticket holders from that list until the control plane is back,
  even before it has its own HMAC key.
- **Fixture.** `crates/resonance-turn/src/ticket.rs` and GameRelay's `test/turn.test.ts` mint
  the same ticket and password from the same keys.

#### HMAC credentials

TURN REST credentials (draft-uberti-behave-turn-rest), minted by the control plane for one node.
GameRelay's control plane mints them for nodes that haven't sent a sealing key:

```
username = <expiry unix s>:<instance>:<room>:<player>
password = base64( HMAC-SHA1( node_key, username ) )
key      = MD5( username ":" realm ":" password )        # RFC 8489 §9.2.2, realm "gamerelay"
```

- Every part of either kind of username must be non-empty. The room and the player are scoped
  to the instance, so two games' rooms never collide.
- An allocation answers only to the room and player it was made for.
- Each node has its own key, derived on the control plane:

  ```
  node_key = base64url( HMAC-SHA256( master, "resonance/turn/v<key_version>/<node_id>" ) )
  ```

  The master never leaves the control plane, and a node only ever sees its own key. A credential
  for one node is therefore worthless on any other, and a leaked node can't forge access to the
  rest of the network. A rotated key takes over at the node's next heartbeat, and the old one is
  still accepted for an hour.

### Nonces

Nonces are stateless:

```
nonce = <expiry hex>-<16 hex of HMAC-SHA256(startup key, expiry, client ip, client port)>
```

A nonce is bound to the client's address, so one seen on the wire is no use from anywhere else.
An expired or invalid nonce gets 438 Stale Nonce.

### The room rule

Both players of a pair allocate on the **same node**: the SDK picks one relay per pair. So the
only peer address an allocation may name is the node's own public IP.

- `CreatePermission` or `ChannelBind` with any other address of the same family gets 403.
  Another family gets 443.
- A packet to a relay address of this node is delivered in memory to that allocation, but only if
  it belongs to the same room.
- Relay addresses (ports 49152–65535) are names, not sockets. Nothing listens on them, so they
  need no firewall opening, and nothing else on the machine is reachable through the relay.

The relay is never an open proxy. It can't read what it relays either, since players' WebRTC
traffic is DTLS end to end.

### Errors

- **Signed errors.** Every error after authentication is signed with MESSAGE-INTEGRITY, because
  Firefox drops unsigned ones and retransmits until the allocation fails.
- **Unsigned answers.** Answers to unknown sources are rate-limited per IP: 20 a second, with a
  burst of the per-IP cap. This includes 401s, Binding answers and every other unsigned answer.
  A spoofed source could otherwise aim them at someone else (reflection).
- **Unknown attributes.** Unknown comprehension-required attributes before MESSAGE-INTEGRITY get
  420.

### Limits

All of these are settings; the defaults are the Go relay's.

| Limit | Default | Setting |
|---|---|---|
| Allocations per player | 8 | `TURN_MAX_PER_PLAYER` |
| Allocations per client IP | 64 | `TURN_MAX_PER_IP` |
| Allocations per game (instance) | 4,096 | `TURN_MAX_PER_INSTANCE` |
| Relay rate per allocation | 128 KB/s, 256 KB burst | `TURN_RATE_BYTES`, `TURN_BURST_BYTES` |
| Unsigned answers per IP | 20/s, burst = the per-IP cap | `TURN_UNAUTH_RATE`, `TURN_UNAUTH_BURST` |
| Open streams (TCP + TLS) | 4,096 | `TURN_MAX_STREAMS` |
| A stream's outgoing queue | 256 KB, then whole messages are dropped | |

## 2. The control plane API

The control plane serves the API at `<RESONANCE_CONTROL>/resonance/v0`, over HTTPS with JSON
bodies under 16 KB. GameRelay's is `https://gamerelay.io/resonance/v0`; its implementation is
`apps/server/src/resonance.ts` in GameRelay's repo.

### Identity

When it joins, a node makes an ed25519 key pair. The key stays in `RESONANCE_STATE_DIR` and never
leaves the box. Its id comes from the public key:

```
node_id = "rn_" + base32( SHA-256(pubkey)[0..16] )      # lowercase, no padding
```

For example, `rn_72asyextvngonlc5w2nmguxzay`.

### Signed requests

Every request, `join` included, carries these headers:

| Header | Value |
|---|---|
| `Resonance-Node` | the node id (not on `join`) |
| `Resonance-Version` | the API version, e.g. `2026-09-29` |
| `Resonance-Ts` | unix milliseconds; must be within 30 s of the control plane's clock |
| `Resonance-Sig` | base64url ed25519 signature over the signing string |

```
signing string = METHOD "\n" PATH "\n" VERSION "\n" TS "\n" hex( SHA-256(body) )
```

`PATH` is the path under `/resonance/v0`, e.g. `/nodes/heartbeat`. The control plane remembers
each signature until it can no longer be in time, so a replayed request gets 401 `replayed`.

The same fixture is tested on both sides: `resonance-proto`'s tests and GameRelay's
`test/resonance.test.ts` sign the same key, path and body to the same bytes.

### Endpoints

All three endpoints are `POST`.

**`/nodes/join`**: once, with a join token from the control plane's admin. A token is valid for an
hour and can be used once; it carries the node's region.

```json
→ { "token": "rjt_…", "pubkey": "<base64url>", "urls": ["turn:203.0.113.7:3478"], "software": "resonance-node 0.1.0", "seal_key": "<base64url>" }
← { "node_id": "rn_…", "region": "nyc", "heartbeat_s": 15 }
```

**`/nodes/key`**: at startup, and again whenever `key_version` changes.

```json
← { "node_key": "<base64url>", "key_version": 0 }
```

**`/nodes/heartbeat`**: every `heartbeat_s` seconds.

```json
→ {
    "allocations": 12, "bytes_in": 48211, "bytes_out": 47980, "cpu": 0.04, "uptime_s": 86400,
    "software": "resonance-node 0.1.0",
    "urls": ["turn:203.0.113.7:3478", "turns:turn.example.com:443?transport=tcp"],
    "peers": [{ "node": "rn_b…", "sent": 14, "answered": 14, "rtt_ms": 62.5 }],
    "seal_key": "<base64url>"
  }
← {
    "status": "active", "key_version": 0,
    "latest_version": "2026-09-29", "min_version": "2026-09-29",
    "peers": [{ "node_id": "rn_b…", "addr": "198.51.100.2:3478" }],
    "issuers": [{ "pubkey": "<base64url>" }]
  }
```

In the request:

- The byte counts are since the last heartbeat, and `cpu` is the cores used over that time.
- `urls` lets a node that starts serving TCP or TLS say so without joining again.
- `seal_key` is the node's X25519 sealing key, also sent at join. Issuers derive its ticket
  passwords with it.

In the answer, `issuers` lists the ed25519 public keys whose tickets the node should accept,
besides its own `RESONANCE_ISSUERS`.

### Statuses

| Status | The node |
|---|---|
| `active` | is handed out to players |
| `draining` | takes no new allocations, and exits once its allocations end |
| `revoked` | stops at once |
| `upgrade_required` | its API version is below `min_version`, so it takes no new allocations |
| anything else | carries on as before (a newer control plane, see Versioning) |

A node the control plane can't reach keeps relaying with the key it has. The control plane stops
handing out a node it hasn't heard from in 45 s.

### Errors

An error is `{ "error": "<code>", "message": "<for people>" }`, with a 4xx or 5xx status.

- **Refusals.** The codes include `bad_time`, `replayed`, `bad_signature`, `unknown_node`, `bad_token`,
  `revoked`, `bad_version`, `bad_request` and `too_large`. A 4xx is a refusal, not an outage.
- **Outages.** A 5xx or a transport error means the control plane is unreachable. After
  `RESONANCE_ALERT_AFTER_S` (120 s) of that, the node posts to `RESONANCE_ALERT_WEBHOOK` (a
  Discord or Slack incoming webhook), once, and again when the control plane is back.

### Versioning

The API is dated. A node is pinned to the version it joined with, and sends it in
`Resonance-Version`; the control plane upgrades the request and downgrades its answer to match.
Within a version, changes are additive only:

- New fields are optional on both sides (`#[serde(default)]`), and each side ignores fields it
  doesn't know.
- A status it doesn't know is `Unknown`, which changes nothing.

`urls`, `peers` and `seal_key` on the heartbeat, `seal_key` on the join, and `peers` and
`issuers` on the heartbeat's answer were added this way within `2026-09-29`.

## 3. Peer probes

The heartbeat's answer lists the other live nodes and the address of each one's relay socket.
The node then measures them:

- **Probes.** Every 2 s it sends each peer a STUN Binding request **from its relay socket**, so a
  probe takes the same path and firewall rules as players' traffic. A probe's transaction id
  starts with `rsnp` and a counter.
- **Answers.** The node takes the answers to its own probes out of the stream before the TURN
  core sees them. Everything else goes to the core as usual.
- **Reports.** Each heartbeat reports, per peer, the probes sent over the last 30 s (at least 1 s
  ago, so they've had time to be answered), how many were answered, and the median round trip.

The control plane uses the reports for two things: the network view (a matrix of links), and an
alert when no node's probes reach a node. A node can't report that it is unreachable itself, but
its peers can.
