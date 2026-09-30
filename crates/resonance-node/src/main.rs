//! A Resonance relay node (v0 §4): the room-scoped TURN core on one UDP socket.
//!
//! Two ways to run it:
//!
//! - **Joined** (the network): `resonance-node join <token>` once, with a token from the control
//!   plane's admin, then `resonance-node run`. It fetches its own key at startup and sends a
//!   heartbeat every 15 s; the control plane hands it out to players while it's active, and can
//!   drain or revoke it. State lives in RESONANCE_STATE_DIR (default /var/lib/resonance);
//!   RESONANCE_CONTROL is the control plane (default https://gamerelay.io).
//! - **By hand**, like the Go relay it replaces, from the same /etc/gamerelay-turn.env:
//!   `TURN_SECRET=<this node's key> TURN_PUBLIC_IP=192.0.2.1 resonance-node` (RESONANCE_NODE_KEY
//!   is the same as TURN_SECRET), and the control plane lists it in RESONANCE_NODES.
//!
//! TURN_PUBLIC_IP is always needed: where players reach it. One socket, UDP 3478 by default. Relay
//! addresses are names on TURN_PUBLIC_IP, ports TURN_MIN_PORT–TURN_MAX_PORT, but nothing listens
//! on them: every relayed packet goes from one allocation to another in memory (the only
//! permitted peer is this relay), so the relay port range needs no firewall opening.
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

mod control;
mod state;

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use control::{Client, Control, Snapshot};
use resonance_turn::{Config, Output, Server};
use socket2::{Domain, Protocol, Socket, Type};
use state::{Joined, State};

/// How often the control plane hears from a joined node (it stops handing out one silent for 45 s).
const HEARTBEAT: Duration = Duration::from_secs(15);
/// How long a rotated-out node key is still accepted: credentials last an hour.
const KEY_OVERLAP: Duration = Duration::from_secs(3600);

/// The listener carries every client's traffic; the kernel's default buffer (about 200 KB) drops
/// packets in a burst long before the relay is busy. 4 MB is about 2,800 full-size packets.
const SOCKET_BUFFER: usize = 4 << 20;

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn port(key: &str, fallback: u16) -> u16 {
    match env(key) {
        None => fallback,
        Some(v) => v
            .parse()
            .unwrap_or_else(|_| fail(&format!("{key} must be a port, not {v:?}"))),
    }
}

/// A positive number from key, or fallback.
fn num<T: std::str::FromStr + PartialOrd + Default + Copy>(key: &str, fallback: T) -> T {
    match env(key) {
        None => fallback,
        Some(v) => match v.parse::<T>() {
            Ok(n) if n > T::default() => n,
            _ => fail(&format!("{key} must be a positive number, not {v:?}")),
        },
    }
}

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
        [] | ["run"] => run_node(),
        ["join", token] => join(token),
        ["status"] => status(),
        ["version" | "--version"] => println!("{}", control::software()),
        _ => usage(),
    }
}

fn public_ip() -> IpAddr {
    env("TURN_PUBLIC_IP")
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| fail("TURN_PUBLIC_IP (where players reach this node) is required"))
}

fn control_url() -> String {
    env("RESONANCE_CONTROL").unwrap_or_else(|| "https://gamerelay.io".into())
}

/// `join <token>`: this node's key (made now if new), registered with the control plane.
fn join(token: &str) {
    let state = State::from_env();
    let key = state
        .key()
        .unwrap_or_else(|e| fail(&format!("key in {}: {e}", state.dir().display())));
    let url = match public_ip() {
        IpAddr::V4(ip) => format!("turn:{ip}:{}", port("TURN_PORT", 3478)),
        IpAddr::V6(ip) => format!("turn:[{ip}]:{}", port("TURN_PORT", 3478)),
    };
    let control = control_url();
    let client = Client::new(&control, key, None, resonance_proto::VERSION);
    let joined = client
        .join(token, vec![url.clone()])
        .unwrap_or_else(|e| fail(&format!("join: {e}")));
    let j = Joined {
        node_id: joined.node_id,
        region: joined.region,
        control,
        api_version: resonance_proto::VERSION.into(),
    };
    state
        .save_joined(&j)
        .unwrap_or_else(|e| fail(&format!("saving {}: {e}", state.dir().display())));
    println!(
        "joined {} as {} in {}, reachable at {url}",
        j.control, j.node_id, j.region
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
fn run_node() {
    let public = public_ip();
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
            let (snap, kv) = (snapshot.clone(), k.key_version);
            // RESONANCE_HEARTBEAT_S: for tests; the control plane expects 15.
            let every = Duration::from_secs(num("RESONANCE_HEARTBEAT_S", HEARTBEAT.as_secs()));
            std::thread::Builder::new()
                .name("heartbeat".into())
                .spawn(move || control::heartbeats(client, every, snap, kv, tx))
                .expect("a thread");
            (k.node_key, Some((rx, snapshot)))
        }
        None => {
            let key = env("RESONANCE_NODE_KEY")
                .or_else(|| env("TURN_SECRET"))
                .unwrap_or_default();
            if key.len() < 32 {
                fail(
                    "not joined (resonance-node join <token>), and no TURN_SECRET (this node's key, 32+ chars) to run by hand",
                );
            }
            (key, None)
        }
    };
    if env("TURN_PEER_IPS").is_some() {
        eprintln!("TURN_PEER_IPS is ignored: pairs of players share one relay");
    }
    let listen = port("TURN_PORT", 3478);
    let mut nonce_key = [0u8; 32];
    getrandom::fill(&mut nonce_key).unwrap_or_else(|e| fail(&format!("random: {e}")));
    let mut cfg = Config::new(key, public, nonce_key);
    cfg.min_port = port("TURN_MIN_PORT", cfg.min_port);
    cfg.max_port = port("TURN_MAX_PORT", cfg.max_port);
    if cfg.min_port > cfg.max_port {
        fail(&format!(
            "TURN_MIN_PORT {} is above TURN_MAX_PORT {}",
            cfg.min_port, cfg.max_port
        ));
    }
    cfg.max_per_player = num("TURN_MAX_PER_PLAYER", cfg.max_per_player);
    cfg.max_per_ip = num("TURN_MAX_PER_IP", cfg.max_per_ip);
    cfg.max_per_instance = num("TURN_MAX_PER_INSTANCE", cfg.max_per_instance);
    cfg.unauth_rate = num("TURN_UNAUTH_RATE", cfg.unauth_rate);
    cfg.unauth_burst = num("TURN_UNAUTH_BURST", cfg.max_per_ip as f64);
    cfg.rate_bytes = num("TURN_RATE_BYTES", cfg.rate_bytes);
    cfg.burst_bytes = num("TURN_BURST_BYTES", cfg.rate_bytes * 2.0);
    let (min, max) = (cfg.min_port, cfg.max_port);
    let socket = bind(SocketAddr::new(IpAddr::from([0, 0, 0, 0]), listen));
    eprintln!(
        "{} on udp :{listen}, relay addresses {public}:{min}-{max}",
        control::software()
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
    run(socket, Server::new(cfg), network);
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

/// The relay loop. `network`: the heartbeat thread's controls, and the numbers it reports.
fn run(
    socket: UdpSocket,
    mut server: Server,
    network: Option<(Receiver<Control>, Arc<Mutex<Snapshot>>)>,
) -> ! {
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .expect("a nonzero timeout");
    let mut buf = vec![0u8; 65536];
    let mut out = Output::default();
    let mut last_tick = Instant::now();
    let mut last_log = last_tick;
    let (mut bytes_in, mut bytes_out) = (0u64, 0u64);
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                let now = Instant::now();
                bytes_in += n as u64;
                out.clear();
                server.handle(now, from, &buf[..n], &mut out);
                for (to, packet) in out.iter() {
                    // A full send buffer or an unreachable client is a lost packet, as UDP allows.
                    if socket.send_to(packet, to).is_ok() {
                        bytes_out += packet.len() as u64;
                    }
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            // A client's ICMP unreachable can surface here on some systems; it isn't ours to fix.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(e) => eprintln!("recv: {e}"),
        }
        let now = Instant::now();
        if now - last_tick >= Duration::from_secs(1) {
            server.tick(now);
            last_tick = now;
            if let Some((rx, snapshot)) = &network {
                while let Ok(c) = rx.try_recv() {
                    match c {
                        Control::Key(k) => server.set_node_key(k, now, KEY_OVERLAP),
                        Control::Accepting(yes) => server.set_accepting(yes),
                        Control::Exit => std::process::exit(0),
                    }
                }
                if let Ok(mut s) = snapshot.lock() {
                    *s = Snapshot {
                        allocations: server.allocations() as u64,
                        bytes_in,
                        bytes_out,
                    };
                }
            }
        }
        if now - last_log >= Duration::from_secs(60) {
            let s = server.stats();
            eprintln!(
                "allocations {}, permissions allowed {} denied {}, unauthenticated requests dropped {}, relayed {} packets {} bytes, dropped over rate {} unroutable {}",
                server.allocations(),
                s.permissions_allowed,
                s.permissions_denied,
                s.unauthenticated_dropped,
                s.relayed_packets,
                s.relayed_bytes,
                s.dropped_rate,
                s.dropped_route
            );
            last_log = now;
        }
    }
}
