//! A Resonance relay node (v0 §4): the room-scoped TURN core on one UDP socket.
//!
//! Configured like the Go relay it replaces, from the same /etc/gamerelay-turn.env:
//!
//!     TURN_SECRET=<this node's key> TURN_PUBLIC_IP=192.0.2.1 resonance-node
//!
//! (RESONANCE_NODE_KEY is the same as TURN_SECRET.) One socket, UDP 3478 by default. Relay
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

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use resonance_turn::{Config, Output, Server};
use socket2::{Domain, Protocol, Socket, Type};

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

fn main() {
    let key = env("RESONANCE_NODE_KEY")
        .or_else(|| env("TURN_SECRET"))
        .unwrap_or_default();
    let public: Option<IpAddr> = env("TURN_PUBLIC_IP").and_then(|v| v.parse().ok());
    let (Some(public), true) = (public, key.len() >= 32) else {
        fail("TURN_SECRET (this node's key, 32+ chars) and TURN_PUBLIC_IP are required")
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
        "resonance-node {} on udp :{listen}, relay addresses {public}:{min}-{max}",
        env!("CARGO_PKG_VERSION")
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
    run(socket, Server::new(cfg));
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

fn run(socket: UdpSocket, mut server: Server) -> ! {
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .expect("a nonzero timeout");
    let mut buf = vec![0u8; 65536];
    let mut out = Output::default();
    let mut last_tick = Instant::now();
    let mut last_log = last_tick;
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                let now = Instant::now();
                out.clear();
                server.handle(now, from, &buf[..n], &mut out);
                for (to, packet) in out.iter() {
                    // A full send buffer or an unreachable client is a lost packet, as UDP allows.
                    let _ = socket.send_to(packet, to);
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
