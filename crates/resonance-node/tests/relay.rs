//! The relay loop in-process, on loopback: the rules about streams that only the loop knows
//! (deadlines, caps) and what a revoke does. The TURN rules are the core's (resonance-turn's
//! tests); TCP and TLS end to end with real clients are interop/streams_test.go.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use resonance_node::control::{Control, Snapshot};
use resonance_node::relay::{self, Limits, Listeners, Network};
use resonance_node::tls::Certificate;
use resonance_turn::stun::{Class, Message, Writer, attr, method};
use resonance_turn::ticket::{self, Issuer};
use resonance_turn::{Config, Server};

struct Node {
    udp: SocketAddr,
    tcp: SocketAddr,
    /// With `start_tls`.
    tls: Option<SocketAddr>,
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
    start_on(network, f, g, None)
}

/// A node with TLS too, on a certificate for "turn.test".
fn start_tls(f: impl FnOnce(&mut Limits)) -> Node {
    let dir = std::env::temp_dir().join(format!(
        "resonance-relay-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = (dir.join("fullchain.pem"), dir.join("privkey.pem"));
    std::fs::write(&cert, TEST_CERT).unwrap();
    std::fs::write(&key, TEST_KEY).unwrap();
    let cert = Certificate::open(cert, key).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    start_on(None, f, |_| {}, Some((l, cert)))
}

fn start_on(
    network: Option<Network>,
    f: impl FnOnce(&mut Limits),
    g: impl FnOnce(&mut Config),
    tls: Option<(TcpListener, Arc<Certificate>)>,
) -> Node {
    let ip = IpAddr::from([127, 0, 0, 1]);
    let udp = UdpSocket::bind((ip, 0)).unwrap();
    let tcp = TcpListener::bind((ip, 0)).unwrap();
    let (udp_addr, tcp_addr) = (udp.local_addr().unwrap(), tcp.local_addr().unwrap());
    let tls_addr = tls.as_ref().map(|(l, _)| l.local_addr().unwrap());
    let mut limits = Limits::default();
    f(&mut limits);
    let mut cfg = Config::new(ip, [7; 32]);
    g(&mut cfg);
    let server = Server::new(cfg);
    let listeners = Listeners {
        udp,
        tcp: Some(tcp),
        tls,
    };
    let thread = std::thread::spawn(move || {
        relay::run(listeners, server, network, limits).unwrap();
    });
    Node {
        udp: udp_addr,
        tcp: tcp_addr,
        tls: tls_addr,
        thread,
    }
}

/// A self-signed P-256 certificate for "turn.test" (to 2126), and its key: the loop only needs
/// one to take TLS connections.
const TEST_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBlDCCATugAwIBAgIUTn0nfBi504jdZPj37k2J93uAJdUwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJdHVybi50ZXN0MCAXDTI2MTAxMDE2NDk1OVoYDzIxMjYwOTE2
MTY0OTU5WjAUMRIwEAYDVQQDDAl0dXJuLnRlc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQhiTs6E9hseZrURmxLHHEdbqceXkXfXxqi42U28+FDFEYiz4WsNYlK
AkmAEct/Md43oPt9pnQ3CUxZB8BkL2PNo2kwZzAdBgNVHQ4EFgQUUzm7L05BEFvG
/n963LSYN+L4dMYwHwYDVR0jBBgwFoAUUzm7L05BEFvG/n963LSYN+L4dMYwDwYD
VR0TAQH/BAUwAwEB/zAUBgNVHREEDTALggl0dXJuLnRlc3QwCgYIKoZIzj0EAwID
RwAwRAIgcqG+FhZ7Yb8wsCFwAPi8qUgyFgJdvUnhrkxmY9LdFGECIGysmcZd1X9M
brwpwufKUubR0o2e5xPCTbIPNKMIlMYH
-----END CERTIFICATE-----
";
const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBVTRk2LnnXCN0T27
LpeRqdwcg47L3TPY+B7dHox3ky2hRANCAAQhiTs6E9hseZrURmxLHHEdbqceXkXf
Xxqi42U28+FDFEYiz4WsNYlKAkmAEct/Md43oPt9pnQ3CUxZB8BkL2PN
-----END PRIVATE KEY-----
";

/// The node's ed25519 seed, which its sealing key comes from, and the issuer it trusts.
const SEED: [u8; 32] = [7; 32];

fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

/// The core takes `issuer()`'s tickets.
fn tickets(c: &mut Config) {
    c.seal = Some(ticket::seal_secret(&SEED));
    c.issuers = vec![Issuer::new(&issuer().verifying_key().to_bytes()).unwrap()];
}

/// A player over one stream: its ticket's username and key, and the nonce it was given.
struct Player {
    username: String,
    key: [u8; 16],
    nonce: String,
    tx: u8,
}

impl Player {
    /// Asks for a nonce (an unsigned Allocate gets a 401 with one).
    fn new(s: &mut TcpStream, player: &str) -> Self {
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let username = ticket::mint(&issuer(), [9; 32], unix + 3600, "ins", "g1", player).username;
        let password = ticket::parse(&username)
            .and_then(|t| t.password(&ticket::seal_secret(&SEED)))
            .unwrap();
        let key = resonance_turn::auth::long_term_key(&username, "gamerelay", &password);
        let mut first = Vec::new();
        Writer::new(&mut first, method::ALLOCATE, Class::Request, [1; 12]);
        let r = ask(s, &first);
        let nonce = Message::parse(&r)
            .and_then(|m| m.str_attr(attr::NONCE).map(str::to_owned))
            .expect("a 401 with a nonce");
        Player {
            username,
            key,
            nonce,
            tx: 1,
        }
    }

    /// A signed request; its error code, 0 for success.
    fn request(&mut self, s: &mut TcpStream, m: u16, attrs: &[(u16, [u8; 4])]) -> u16 {
        self.tx += 1;
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf, m, Class::Request, [self.tx; 12]);
        for (k, v) in attrs {
            w.attr(*k, v);
        }
        w.attr(attr::USERNAME, self.username.as_bytes())
            .attr(attr::REALM, b"gamerelay")
            .attr(attr::NONCE, self.nonce.as_bytes())
            .integrity(&self.key)
            .fingerprint();
        let r = ask(s, &buf);
        let m = Message::parse(&r).expect("a STUN answer");
        match m.class {
            Class::Success => 0,
            _ => m
                .get(attr::ERROR_CODE)
                .map_or(1, |v| v[2] as u16 * 100 + v[3] as u16),
        }
    }

    fn allocate(&mut self, s: &mut TcpStream) -> u16 {
        self.request(
            s,
            method::ALLOCATE,
            &[(attr::REQUESTED_TRANSPORT, [17, 0, 0, 0])],
        )
    }
}

/// A message over the stream, and the answer.
fn ask(s: &mut TcpStream, m: &[u8]) -> Vec<u8> {
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(m).unwrap();
    let mut msg = vec![0u8; 20];
    s.read_exact(&mut msg).unwrap();
    msg.resize(20 + u16::from_be_bytes([msg[2], msg[3]]) as usize, 0);
    s.read_exact(&mut msg[20..]).unwrap();
    msg
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
    // All of them bound first, while there's room: a stream that arrives once the budget is full
    // is closed on its first read, as it should be, so the halves go after.
    let mut sitters: Vec<TcpStream> = (0..8)
        .map(|_| {
            let mut s = TcpStream::connect(node.tcp).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            bind(&mut s);
            s
        })
        .collect();
    for s in &mut sitters {
        s.write_all(&half).unwrap();
    }
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

/// Whether the node hangs up on `s` within `wait` while it sends a Binding every 100 ms, so it's
/// never idle.
fn hung_up_while_chatting(s: &mut TcpStream, wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    let mut buf = [0u8; 1500];
    while Instant::now() < deadline {
        if s.write_all(&BINDING).is_err()
            || s.set_read_timeout(Some(Duration::from_millis(100)))
                .is_err()
        {
            return true;
        }
        match s.read(&mut buf) {
            Ok(0) => return true,
            Err(e) if e.kind() == ErrorKind::ConnectionReset => return true,
            _ => {}
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn a_stream_without_an_allocation_is_closed_soon_however_much_it_says() {
    // Browsers open TURN over TCP or TLS only to allocate, so a stream holding none is closed
    // after `unallocated`, not the idle limit; one holding one stays, until it's gone.
    let node = start_with(
        None,
        |l| l.unallocated = Duration::from_millis(500),
        tickets,
    );
    let mut player = TcpStream::connect(node.tcp).unwrap();
    let mut p = Player::new(&mut player, "p_a");
    assert_eq!(p.allocate(&mut player), 0);
    let mut talker = TcpStream::connect(node.tcp).unwrap();
    let started = Instant::now();
    assert!(hung_up_while_chatting(&mut talker, Duration::from_secs(4)));
    assert!(started.elapsed() >= Duration::from_millis(500));
    // Kept past it while its allocation lasts.
    assert!(!hung_up_while_chatting(
        &mut player,
        Duration::from_millis(1500)
    ));
    // Once its allocation ends, it's closed the same way.
    assert_eq!(
        p.request(&mut player, method::REFRESH, &[(attr::LIFETIME, [0; 4])]),
        0
    );
    assert!(hung_up_while_chatting(&mut player, Duration::from_secs(4)));
}

#[test]
fn new_streams_from_one_ip_are_rate_limited() {
    let node = start(None, |l| {
        l.stream_rate = 1.0;
        l.stream_burst = 3.0;
    });
    let mut open: Vec<TcpStream> = (0..3)
        .map(|_| {
            let mut s = TcpStream::connect(node.tcp).unwrap();
            bind(&mut s);
            s
        })
        .collect();
    let mut over = TcpStream::connect(node.tcp).unwrap();
    assert!(
        hung_up(&mut over, Duration::from_secs(1)),
        "past the burst: closed at once"
    );
    // A second on, one more.
    std::thread::sleep(Duration::from_millis(1100));
    let mut s = TcpStream::connect(node.tcp).unwrap();
    bind(&mut s);
    // Those already open carry on.
    for s in &mut open {
        bind(s);
    }
}

#[test]
fn tls_handshakes_are_budgeted_for_the_whole_node() {
    // Each is a key exchange and a signature on the loop's thread: the node starts at most
    // `tls_handshake_rate` a second, from everyone together.
    let node = start_tls(|l| l.tls_handshake_rate = 2.0);
    let tls = node.tls.unwrap();
    let mut first: Vec<TcpStream> = (0..2).map(|_| TcpStream::connect(tls).unwrap()).collect();
    let mut over = TcpStream::connect(tls).unwrap();
    assert!(
        hung_up(&mut over, Duration::from_secs(1)),
        "past the budget: closed at once"
    );
    for s in &mut first {
        assert!(
            !hung_up(s, Duration::from_millis(200)),
            "kept, waiting for its hello"
        );
    }
    // TCP isn't a handshake: it's taken meanwhile.
    let mut tcp = TcpStream::connect(node.tcp).unwrap();
    bind(&mut tcp);
    std::thread::sleep(Duration::from_millis(1100));
    let mut later = TcpStream::connect(tls).unwrap();
    assert!(!hung_up(&mut later, Duration::from_millis(500)));
}

#[test]
fn a_tls_stream_past_the_nodes_budget_doesnt_spend_its_ips_rate() {
    let node = start_tls(|l| {
        l.tls_handshake_rate = 1.0;
        l.stream_rate = 0.1;
        l.stream_burst = 3.0;
    });
    let tls = node.tls.unwrap();
    let _first = TcpStream::connect(tls).unwrap();
    for _ in 0..2 {
        let mut over = TcpStream::connect(tls).unwrap();
        assert!(hung_up(&mut over, Duration::from_secs(1)));
    }
    // Its IP still has two new streams left.
    for _ in 0..2 {
        let mut s = TcpStream::connect(node.tcp).unwrap();
        bind(&mut s);
    }
}
