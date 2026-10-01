# Security

Resonance nodes face the internet and relay other people's traffic, so we take reports seriously.

## Reporting a vulnerability

**Please don't open a public issue.** Report it privately through GitHub:
[Security → Report a vulnerability](https://github.com/gamerelay/resonance/security/advisories/new).

Please include what you found, how to reproduce it, and what it allows. We'll answer within
3 working days, keep you posted while we fix it, and credit you in the advisory unless you'd
rather we didn't.

## Supported versions

Only the latest commit on `main` gets fixes until the first tagged releases settle; production
nodes are kept on it.

## In scope

- **Relaying beyond the room rule.** Reaching any address other than another allocation of the
  same room on the same node, or another room's allocations (`docs/PROTOCOL.md`, "The room
  rule").
- **Credentials.** Forging or reusing them: for another room, player or node, or past their
  expiry.
- **Reflection or amplification.** Answers that can be aimed at a third party beyond the
  per-IP limits.
- **Crashes and resource exhaustion.** A packet or a stream that crashes a node, or exhausts it
  past its limits.
- **The control-plane protocol.** Forging or replaying signed requests, or a node obtaining
  another node's key.

## Out of scope

- Volumetric DDoS against a node's network.
- The content of relayed traffic: it's DTLS end to end, and nodes can't read it.
- Findings in GameRelay's own service (gamerelay.io): report those to GameRelay.
