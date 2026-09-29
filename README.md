# Resonance

An easy-to-deploy relay network for real-time games. [GameRelay](https://gamerelay.io) is its
first customer.

This repo is the **node**: a room-scoped TURN relay in Rust. It replaces GameRelay's Go relay,
rule for rule, and is the base for the network's later roles.

**Status: v0, in progress.** The TURN core and the node binary work: pion's TURN client and real
Chrome relay through it. Joining the network by itself (registry, heartbeats) is next.

## What it relays, and to whom

- **Only between allocations of the same room, on this node.** Both players of a pair allocate on
  the same node, so the only permitted peer is the node itself. Every relayed packet goes from one
  allocation to another in memory: relay addresses are names, not sockets. It is never an open
  proxy, and nothing else on the machine is reachable through it.
- **It can't read what it relays.** Players' WebRTC traffic is DTLS end to end.
- **Credentials are its own.** A node's key is derived from the control plane's master key, and
  mints credentials for that node only. A leaked node can't forge access to any other.
- **Limits:** 8 allocations per player, 64 per client IP, 4,096 per game, and 128 KB/s per
  allocation (256 KB burst). Unauthenticated requests are capped at 20 a second per IP, since a
  spoofed source could otherwise aim the relay's answers at someone.

## Layout

| Crate | What it does |
|---|---|
| [`resonance-turn`](crates/resonance-turn) | The TURN relay, sans-I/O: `handle(now, from, packet) → packets`. Every rule lives here, testable without sockets. Its own STUN codec: parsed in place, nothing allocated per packet. |
| [`resonance-node`](crates/resonance-node) | The binary: the core on one UDP socket, plus config and logs. |
| [`interop`](interop) | pion's TURN client against the built node, over real UDP. |

## Running a node

```sh
cargo build --release
TURN_SECRET=<this node's key> TURN_PUBLIC_IP=<its public IP> ./target/release/resonance-node
```

The node key comes from the control plane (in GameRelay, `bun apps/server/src/turn.ts key <id>`).
It listens on UDP 3478 (`TURN_PORT`). Relay addresses use ports 49152–65535 (`TURN_MIN_PORT`,
`TURN_MAX_PORT`), but nothing listens on them, so they need no firewall opening.

## Tests

```sh
cargo test --release                                     # the core, and a fuzz run
FUZZ_ITERS=5000000 cargo test --release --test fuzz      # a longer fuzz run
cd interop && go test ./...                              # pion's client against the node
```

The design is in GameRelay's repo:
`docs/superpowers/specs/2026-09-29-resonance-v0-design.md`.

## License

MIT
