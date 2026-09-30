//! A Resonance relay node (v0 §4): the room-scoped TURN core on one UDP socket.
//!
//! Two ways to run it:
//!
//! - **Joined** (the network): `resonance-node join <token>` once, with a token from the control
//!   plane's admin, then `resonance-node run`. It fetches its own key at startup and sends a
//!   heartbeat every 15 s; the control plane hands it out to players while it's active, and can
//!   drain or revoke it. State lives in RESONANCE_STATE_DIR (default /var/lib/resonance);
//!   RESONANCE_CONTROL is the control plane (default https://gamerelay.io).
//!   A joined node measures the other nodes the control plane names (a STUN Binding every 2 s from
//!   its relay socket, reported with each heartbeat), and with RESONANCE_ALERT_WEBHOOK (a Discord
//!   or Slack incoming webhook) says there when the control plane has been out of reach for
//!   RESONANCE_ALERT_AFTER_S (120) in a row, and when it's back.
//! - **By hand**, like the Go relay it replaces, from the same /etc/gamerelay-turn.env:
//!   `TURN_SECRET=<this node's key> TURN_PUBLIC_IP=192.0.2.1 resonance-node` (RESONANCE_NODE_KEY
//!   is the same as TURN_SECRET), and the control plane lists it in RESONANCE_NODES.
//!
//! TURN_PUBLIC_IP is always needed: where players reach it. One socket, UDP 3478 by default. Relay
//! addresses are names on TURN_PUBLIC_IP, ports TURN_MIN_PORT–TURN_MAX_PORT, but nothing listens
//! on them: every relayed packet goes from one allocation to another in memory (the only
//! permitted peer is this relay), so the relay port range needs no firewall opening.
//!
//! Streams (RFC 8656 §12.5), for networks that block UDP:
//!
//! - TCP on TURN_PORT too with TURN_TCP=1 (off by default: it needs its own firewall opening,
//!   and a URL players can't reach only costs them a try).
//! - TLS when TURN_TLS_CERT and TURN_TLS_KEY name PEM files (certbot's fullchain.pem and
//!   privkey.pem, read again when they change), on TURN_TLS_PORT (5349; 443 gets through the most
//!   firewalls), for TURN_TLS_HOST, the name on the certificate that players connect to.
//! - TURN_MAX_STREAMS (4096): open TCP and TLS connections, all together; per IP, TURN_MAX_PER_IP.
//!
//! Its URLs, sent when it joins and with every heartbeat, follow from these.
//!
//! Limits (defaults are the Go relay's):
//!
//! - TURN_MAX_PER_PLAYER (8): allocations per player, one per other player in a full room.
//! - TURN_MAX_PER_IP (64): per client IP. Every player takes one per other player even when the
//!   LAN route wins (ICE gathers the relay before it knows), so a school or office behind one NAT
//!   with a few full rooms needs more: 8 players × 7 others is 56.
//! - TURN_MAX_PER_INSTANCE (4096): per game, so one game can't take the whole node.
//! - TURN_UNAUTH_RATE (20/s) and TURN_UNAUTH_BURST (TURN_MAX_PER_IP): unsigned answers per
//!   unknown client IP; the burst follows the per-IP cap, so a shared address can fill it at once.
//! - TURN_RATE_BYTES (131072) and TURN_BURST_BYTES (twice that): per allocation.

use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use resonance_node::control::{self, Client, Snapshot};
use resonance_node::settings::Settings;
use resonance_node::state::{Joined, State};
use resonance_node::{relay, tls};
use resonance_turn::Server;
use socket2::{Domain, Protocol, Socket, Type};

/// The listener carries every client's traffic; the kernel's default buffer (about 200 KB) drops
/// packets in a burst long before the relay is busy. 4 MB is about 2,800 full-size packets.
const SOCKET_BUFFER: usize = 4 << 20;

fn fail(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(1)
}

fn usage() -> ! {
    fail("usage: resonance-node [run] | join <token> | status | version")
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        [] | ["run"] => run_node(settings()),
        ["join", token] => join(settings(), token),
        ["status"] => status(),
        ["version" | "--version"] => println!("{}", control::software()),
        _ => usage(),
    }
}

fn settings() -> Settings {
    Settings::from_env().unwrap_or_else(|e| fail(&e))
}

/// `join <token>`: this node's key (made now if new), registered with the control plane.
fn join(s: Settings, token: &str) {
    let state = State::from_env();
    let key = state
        .key()
        .unwrap_or_else(|e| fail(&format!("key in {}: {e}", state.dir().display())));
    let urls = s.urls();
    let client = Client::new(&s.control, key, None, resonance_proto::VERSION);
    let joined = client
        .join(token, urls.clone())
        .unwrap_or_else(|e| fail(&format!("join: {e}")));
    let j = Joined {
        node_id: joined.node_id,
        region: joined.region,
        control: s.control,
        api_version: resonance_proto::VERSION.into(),
    };
    state
        .save_joined(&j)
        .unwrap_or_else(|e| fail(&format!("saving {}: {e}", state.dir().display())));
    println!(
        "joined {} as {} in {}, reachable at {}",
        j.control,
        j.node_id,
        j.region,
        urls.join(" ")
    );
}

fn status() {
    let state = State::from_env();
    match state.joined() {
        Ok(Some(j)) => println!(
            "{} in {} (control plane {}, API {})",
            j.node_id, j.region, j.control, j.api_version
        ),
        Ok(None) => println!(
            "not joined (state in {}): run by hand with TURN_SECRET, or join <token>",
            state.dir().display()
        ),
        Err(e) => fail(&format!("state in {}: {e}", state.dir().display())),
    }
}

/// `run`: joined if there's a node.json, else by hand with TURN_SECRET.
fn run_node(s: Settings) {
    let state = State::from_env();
    let joined = state
        .joined()
        .unwrap_or_else(|e| fail(&format!("state in {}: {e}", state.dir().display())));
    let (key, network) = match joined {
        Some(j) => {
            let signing = state
                .key()
                .unwrap_or_else(|e| fail(&format!("key in {}: {e}", state.dir().display())));
            let client = Client::new(&j.control, signing, Some(j.node_id.clone()), &j.api_version);
            let k = fetch_key_patiently(&client);
            eprintln!("joined {} as {} in {}", j.control, j.node_id, j.region);
            let snapshot = Arc::new(Mutex::new(Snapshot::default()));
            let (tx, rx) = mpsc::channel();
            let beats = control::Heartbeats {
                client,
                every: s.heartbeat,
                snapshot: snapshot.clone(),
                key_version: k.key_version,
                urls: s.urls(),
                controls: tx,
                alert: s.alert_webhook.clone().map(|w| {
                    let who = format!("{} ({})", j.region, j.node_id);
                    (
                        w,
                        control::Watch::new(who, j.control.clone(), s.alert_after),
                    )
                }),
            };
            std::thread::Builder::new()
                .name("heartbeat".into())
                .spawn(move || beats.run())
                .expect("a thread");
            (
                k.node_key,
                Some(relay::Network {
                    controls: rx,
                    snapshot,
                }),
            )
        }
        None => match &s.node_key {
            Some(k) if k.len() >= 32 => (k.clone(), None),
            _ => fail(
                "not joined (resonance-node join <token>), and no TURN_SECRET (this node's key, 32+ chars) to run by hand",
            ),
        },
    };
    for k in &s.ignored {
        eprintln!("{k} is ignored: pairs of players share one relay");
    }
    let mut cfg = s.turn;
    cfg.node_key = key;
    getrandom::fill(&mut cfg.nonce_key).unwrap_or_else(|e| fail(&format!("random: {e}")));
    let any = IpAddr::from([0, 0, 0, 0]);
    let socket = bind(SocketAddr::new(any, s.port));
    let tcp = s.tcp.then(|| listen_tcp(SocketAddr::new(any, s.port)));
    let tls = s.tls.as_ref().map(|t| {
        let cert = tls::Certificate::open(t.cert.clone(), t.key.clone())
            .unwrap_or_else(|e| fail(&format!("TURN_TLS_CERT/TURN_TLS_KEY: {e}")));
        (listen_tcp(SocketAddr::new(any, t.port)), cert)
    });
    eprintln!(
        "{} on udp :{}{}{}, relay addresses {}:{}-{}",
        control::software(),
        s.port,
        if tcp.is_some() {
            format!(", tcp :{}", s.port)
        } else {
            String::new()
        },
        s.tls
            .as_ref()
            .map(|t| format!(", tls :{} as {}", t.port, t.host))
            .unwrap_or_default(),
        s.public_ip,
        cfg.min_port,
        cfg.max_port
    );
    eprintln!(
        "limits: {} allocations per player, {} per IP, {} per game; {} B/s per allocation (burst {}); unauthenticated answers {}/s per IP (burst {})",
        cfg.max_per_player,
        cfg.max_per_ip,
        cfg.max_per_instance,
        cfg.rate_bytes,
        cfg.burst_bytes,
        cfg.unauth_rate,
        cfg.unauth_burst
    );
    // It returns once the control plane revokes this node.
    relay::run(
        relay::Listeners {
            udp: socket,
            tcp,
            tls,
        },
        Server::new(cfg),
        network,
        s.limits,
    )
    .unwrap_or_else(|e| fail(&format!("the relay loop: {e}")));
}

fn listen_tcp(addr: SocketAddr) -> TcpListener {
    let s = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))
        .unwrap_or_else(|e| fail(&format!("socket: {e}")));
    // A restart shouldn't wait out the last run's connections in TIME_WAIT.
    let _ = s.set_reuse_address(true);
    s.bind(&addr.into())
        .unwrap_or_else(|e| fail(&format!("listen on tcp {addr}: {e}")));
    s.listen(1024)
        .unwrap_or_else(|e| fail(&format!("listen on tcp {addr}: {e}")));
    s.into()
}

/// The key, retried until the control plane answers: a node that can't get its key can't relay.
/// A refusal (revoked, unknown) is final.
fn fetch_key_patiently(client: &Client) -> resonance_proto::KeyResponse {
    let mut wait = Duration::from_secs(1);
    loop {
        match client.fetch_key() {
            Ok(k) => return k,
            Err(e @ control::Error::Refused { .. }) => {
                fail(&format!("the control plane refused this node its key: {e}"))
            }
            Err(e) => {
                eprintln!(
                    "fetching this node's key: {e}; again in {}s",
                    wait.as_secs()
                );
                std::thread::sleep(wait);
                wait = (wait * 2).min(Duration::from_secs(30));
            }
        }
    }
}

fn bind(addr: SocketAddr) -> UdpSocket {
    let s = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))
        .unwrap_or_else(|e| fail(&format!("socket: {e}")));
    for (what, set, get) in [
        (
            "read",
            Socket::set_recv_buffer_size as fn(&Socket, usize) -> std::io::Result<()>,
            Socket::recv_buffer_size as fn(&Socket) -> std::io::Result<usize>,
        ),
        (
            "write",
            Socket::set_send_buffer_size,
            Socket::send_buffer_size,
        ),
    ] {
        if let Err(e) = set(&s, SOCKET_BUFFER) {
            eprintln!("socket {what} buffer: {e}");
        }
        // Linux reports double what it keeps, and caps it at net.core.rmem_max / wmem_max.
        match get(&s) {
            Ok(n) if n < SOCKET_BUFFER => eprintln!(
                "socket {what} buffer capped by the kernel at {n}, wanted {SOCKET_BUFFER} (net.core.rmem_max and wmem_max)"
            ),
            _ => {}
        }
    }
    s.bind(&addr.into())
        .unwrap_or_else(|e| fail(&format!("listen on {addr}: {e}")));
    s.into()
}
