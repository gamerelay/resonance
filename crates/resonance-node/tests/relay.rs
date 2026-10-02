//! The relay loop in-process, on loopback: the rules about streams that only the loop knows
//! (deadlines, caps) and what a revoke does. The TURN rules are the core's (resonance-turn's
//! tests); TCP and TLS end to end with real clients are interop/streams_test.go.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use resonance_node::control::{Control, Snapshot};
use resonance_node::relay::{self, Limits, Listeners, Network};
use resonance_turn::{Config, Server};

struct Node {
    udp: SocketAddr,
    tcp: SocketAddr,
    thread: JoinHandle<()>,
}

/// A node on loopback with TCP, and its settings changed by `f`.
fn start(network: Option<Network>, f: impl FnOnce(&mut Limits)) -> Node {
    start_with(network, f, |_| {})
}

/// The same, with the core's settings changed by `g` too.
fn start_with(
    network: Option<Network>,
    f: impl FnOnce(&mut Limits),
    g: impl FnOnce(&mut Config),
) -> Node {
    let ip = IpAddr::from([127, 0, 0, 1]);
    let udp = UdpSocket::bind((ip, 0)).unwrap();
    let tcp = TcpListener::bind((ip, 0)).unwrap();
    let (udp_addr, tcp_addr) = (udp.local_addr().unwrap(), tcp.local_addr().unwrap());
    let mut limits = Limits::default();
    f(&mut limits);
    let mut cfg = Config::new(ip, [7; 32]);
    g(&mut cfg);
    let server = Server::new(cfg);
    let listeners = Listeners {
        udp,
        tcp: Some(tcp),
        tls: None,
    };
    let thread = std::thread::spawn(move || {
        relay::run(listeners, server, network, limits).unwrap();
    });
    Node {
        udp: udp_addr,
        tcp: tcp_addr,
        thread,
    }
}

const BINDING: [u8; 20] = [
    0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
];

/// A Binding over the stream, and its answer (a Binding success).
fn bind(s: &mut TcpStream) {
    s.write_all(&BINDING).unwrap();
    let mut head = [0u8; 20];
    s.read_exact(&mut head).unwrap();
    assert_eq!(&head[..2], &[0x01, 0x01], "a Binding success");
    let mut body = vec![0u8; u16::from_be_bytes([head[2], head[3]]) as usize];
    s.read_exact(&mut body).unwrap();
}

/// Whether the node hangs up on `s` within `wait` (reading and discarding anything else).
fn hung_up(s: &mut TcpStream, wait: Duration) -> bool {
    // macOS refuses socket options on a connection already reset.
    if s.set_read_timeout(Some(wait)).is_err() {
        return true;
    }
    let mut buf = [0u8; 1500];
    loop {
        match s.read(&mut buf) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::ConnectionReset => return true,
            Err(_) => return false,
        }
    }
}

#[test]
fn a_stream_that_sends_nothing_is_closed_at_its_deadline() {
    let node = start(None, |l| l.first_message = Duration::from_millis(100));
    let mut quiet = TcpStream::connect(node.tcp).unwrap();
    let mut talker = TcpStream::connect(node.tcp).unwrap();
    bind(&mut talker);
    // The loop looks once a second.
    let started = Instant::now();
    assert!(hung_up(&mut quiet, Duration::from_secs(3)));
    assert!(started.elapsed() < Duration::from_millis(2500));
    // One that spoke in time is kept.
    bind(&mut talker);
}

#[test]
fn a_silent_stream_is_closed_once_idle() {
    let node = start(None, |l| l.idle = Duration::from_millis(200));
    let mut s = TcpStream::connect(node.tcp).unwrap();
    bind(&mut s);
    assert!(hung_up(&mut s, Duration::from_secs(3)));
}

/// A client that takes little into its own kernel (a 4 KB receive buffer, set before connecting),
/// so what it doesn't read piles up in the node, as it would across a real network.
fn small_reader(to: SocketAddr) -> TcpStream {
    use socket2::{Domain, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    s.set_recv_buffer_size(4096).unwrap();
    s.connect(&to.into()).unwrap();
    s.into()
}

/// Binding requests back to back, `n` of them, never reading the answers.
fn flood(s: &mut TcpStream, n: usize) {
    let many: Vec<u8> = BINDING
        .iter()
        .copied()
        .cycle()
        .take(BINDING.len() * n)
        .collect();
    s.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    let _ = s.write_all(&many);
}

#[test]
fn streams_that_send_and_never_read_are_closed_and_a_reader_is_kept() {
    // The review of 2026-10-01: answers queued for clients that never read them filled the node.
    // A small memory budget here (all of it this IP's), so a few streams are enough to fill it.
    let node = start_with(
        None,
        |l| l.max_streams_per_ip = 16,
        |c| {
            c.memory_total = 512 * 1024;
            c.memory_per_ip = 512 * 1024;
        },
    );
    let mut reader = TcpStream::connect(node.tcp).unwrap();
    bind(&mut reader);
    // More than the budget can hold for all of them, so it fills past the sweep's mark.
    let mut hoarders: Vec<TcpStream> = (0..12).map(|_| small_reader(node.tcp)).collect();
    for h in &mut hoarders {
        // About 1.3 MB of answers each: past the kernel's buffers and the stream's queue.
        flood(h, 20_000);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut closed = 0;
    for h in &mut hoarders {
        let left = deadline.saturating_duration_since(Instant::now());
        // Each was sent far more than it read, so the node hangs up (the reads here come
        // after the fact; they drain what was already sent).
        if hung_up(h, left.max(Duration::from_millis(100))) {
            closed += 1;
        }
    }
    // On Linux the node's writes stop at the kernel's buffers (64 KB here), so what the hoarders
    // don't read piles up in their queues, charged, until the sweep closes the biggest. macOS's
    // loopback takes all of it into the kernel instead: nothing piles up in the node, so there's
    // nothing to close (the sweep itself is checked on every system by the next test).
    if cfg!(target_os = "linux") {
        assert!(closed >= 3, "only {closed} of 12 hoarders were closed");
    }
    bind(&mut reader);
    // What the closed streams held was given back: new ones are answered.
    for _ in 0..4 {
        let mut s = TcpStream::connect(node.tcp).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        bind(&mut s);
    }
}

#[test]
fn streams_sitting_on_half_a_message_are_closed_once_the_memory_budget_is_nearly_full() {
    // TECH_DEBT C1: what a stream holds is charged to the memory budget, and past three quarters
    // of it the streams holding the most are closed. These never read again, so only that sweep
    // can close them.
    let node = start_with(
        None,
        |l| {
            l.max_streams_per_ip = 16;
            l.first_message = Duration::from_secs(60);
        },
        |c| {
            c.memory_total = 512 * 1024;
            c.memory_per_ip = 512 * 1024;
        },
    );
    let mut reader = TcpStream::connect(node.tcp).unwrap();
    bind(&mut reader);
    // A STUN header for a 60 KB message, and 56 KB of it: about 448 KB held, past 384 KB.
    let mut half = vec![0x00, 0x01, 0xF0, 0x00, 0x21, 0x12, 0xA4, 0x42];
    half.extend_from_slice(&[7; 12]);
    half.resize(20 + 56 * 1024, 0);
    let mut sitters: Vec<TcpStream> = (0..8)
        .map(|_| {
            let mut s = TcpStream::connect(node.tcp).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            bind(&mut s);
            s.write_all(&half).unwrap();
            s
        })
        .collect();
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut closed = 0;
    for s in &mut sitters {
        let left = deadline.saturating_duration_since(Instant::now());
        if hung_up(s, left.max(Duration::from_millis(100))) {
            closed += 1;
        }
    }
    assert!((3..8).contains(&closed), "{closed} of 8 closed");
    bind(&mut reader);
}

#[test]
fn streams_from_one_ip_are_capped() {
    let node = start(None, |l| l.max_streams_per_ip = 2);
    let mut a = TcpStream::connect(node.tcp).unwrap();
    let mut b = TcpStream::connect(node.tcp).unwrap();
    bind(&mut a);
    bind(&mut b);
    let mut c = TcpStream::connect(node.tcp).unwrap();
    assert!(
        hung_up(&mut c, Duration::from_secs(2)),
        "a third is refused"
    );
    // One closes, and there's room again.
    drop(a);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let mut d = TcpStream::connect(node.tcp).unwrap();
        d.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        if d.write_all(&BINDING).is_ok() && d.read(&mut [0u8; 64]).is_ok_and(|n| n > 0) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the closed stream's place isn't freed"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    bind(&mut b);
}

#[test]
fn a_revoked_node_stops_relaying_and_returns() {
    let (tx, rx) = mpsc::channel();
    let snapshot = Arc::new(Mutex::new(Snapshot::default()));
    let node = start(
        Some(Network {
            controls: rx,
            snapshot: snapshot.clone(),
        }),
        |_| {},
    );
    // It answers until then.
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client.send_to(&BINDING, node.udp).unwrap();
    assert!(client.recv(&mut [0u8; 64]).unwrap() > 0);
    tx.send(Control::Exit).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !node.thread.is_finished() {
        assert!(Instant::now() < deadline, "still running after a revoke");
        std::thread::sleep(Duration::from_millis(20));
    }
    // Its numbers reached the heartbeat on the way.
    assert!(snapshot.lock().unwrap().bytes_in >= BINDING.len() as u64);
}

#[test]
fn a_node_measures_the_peers_its_told_about_from_its_relay_socket() {
    let network = || {
        let (tx, rx) = mpsc::channel();
        let snapshot = Arc::new(Mutex::new(Snapshot::default()));
        (
            tx,
            snapshot.clone(),
            Network {
                controls: rx,
                snapshot,
            },
        )
    };
    let (tx_a, snap_a, net_a) = network();
    let (_tx_b, _snap_b, net_b) = network();
    let _a = start(Some(net_a), |_| {});
    let b = start(Some(net_b), |_| {});
    // And one nobody answers at.
    let gone = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    tx_a.send(Control::Peers(vec![
        ("rn_b".into(), b.udp),
        ("rn_gone".into(), gone),
    ]))
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let peers = snap_a.lock().unwrap().peers.clone();
        let of = |n: &str| peers.iter().find(|p| p.node == n).cloned();
        if let (Some(b), Some(g)) = (of("rn_b"), of("rn_gone")) {
            if b.answered > 0 && g.sent > 0 {
                assert!(b.rtt_ms.is_some_and(|ms| ms < 100.0), "{b:?}");
                assert_eq!((g.answered, g.rtt_ms), (0, None));
                break;
            }
        }
        assert!(Instant::now() < deadline, "no measurements: {peers:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
}
