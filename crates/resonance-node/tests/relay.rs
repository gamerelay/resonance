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

const KEY: &str = "fiahLYMg85YkiFJQ0Xp3Bl0x3pXkUhI4nMU8jj6QRio";

struct Node {
    udp: SocketAddr,
    tcp: SocketAddr,
    thread: JoinHandle<()>,
}

/// A node on loopback with TCP, and its settings changed by `f`.
fn start(network: Option<Network>, f: impl FnOnce(&mut Limits)) -> Node {
    let ip = IpAddr::from([127, 0, 0, 1]);
    let udp = UdpSocket::bind((ip, 0)).unwrap();
    let tcp = TcpListener::bind((ip, 0)).unwrap();
    let (udp_addr, tcp_addr) = (udp.local_addr().unwrap(), tcp.local_addr().unwrap());
    let mut limits = Limits::default();
    f(&mut limits);
    let server = Server::new(Config::new(KEY, ip, [7; 32]));
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
    s.set_read_timeout(Some(wait)).unwrap();
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
