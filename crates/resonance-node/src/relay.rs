//! The relay loop: one thread holds the TURN core and polls the UDP socket, the TCP and TLS
//! listeners (when configured) and every stream connection. Nothing is locked or handed between
//! threads on the way through: a message is read, handled and its answers written in one go.
//!
//! A stream is its own client (RFC 8656 §12.5): its messages are framed out of the bytes, what the
//! core sends it is queued on it, and when it closes its allocation goes with it. A slow stream
//! drops what doesn't fit in its queue, whole messages at a time, as UDP would.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mio::net::{TcpListener, TcpStream, UdpSocket};
use mio::{Events, Interest, Poll, Registry, Token};
use resonance_turn::counts::Counts;
use resonance_turn::stream::{Frame, Framer, padding};
use resonance_turn::ticket::Issuer;
use resonance_turn::{Client, Output, Server};
use rustls::{ServerConfig, ServerConnection};

use crate::control::{Control, Snapshot};
use crate::probe::Prober;
use crate::tls::Certificate;

const UDP: Token = Token(0);
const TCP: Token = Token(1);
const TLS: Token = Token(2);
/// Stream tokens are their connection number plus this.
const STREAMS: usize = 16;

/// What a stream may have waiting to go out. Past it, messages are dropped whole.
const QUEUE_CAP: usize = 256 * 1024;
/// What one stream may be read for in a turn of the loop, and how many datagrams: past it, the
/// rest waits for the next turn, so one busy client can't hold up everyone else.
const STREAM_BUDGET: usize = 256 * 1024;
const UDP_BUDGET: usize = 1024;

/// The sockets, bound and ready.
pub struct Listeners {
    pub udp: std::net::UdpSocket,
    pub tcp: Option<std::net::TcpListener>,
    pub tls: Option<(std::net::TcpListener, Arc<Certificate>)>,
}

/// A joined node's link to its heartbeat thread.
pub struct Network {
    pub controls: Receiver<Control>,
    pub snapshot: Arc<Mutex<Snapshot>>,
}

pub struct Limits {
    /// Open streams, all together.
    pub max_streams: usize,
    /// Open streams from one IP (the core's per-IP allocation cap).
    pub max_streams_per_ip: usize,
    /// How long a rotated-out node key is still accepted.
    pub key_overlap: Duration,
    /// A stream that hasn't sent a whole message by then (its TLS handshake included) is closed.
    pub first_message: Duration,
    /// Silence after which a stream is closed: longer than any client leaves between refreshes.
    pub idle: Duration,
    /// Log each stream's opening and why it closed (TURN_DEBUG_STREAMS=1).
    pub debug_streams: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_streams: 4096,
            max_streams_per_ip: 64,
            key_overlap: Duration::from_secs(3600),
            first_message: Duration::from_secs(10),
            idle: Duration::from_secs(15 * 60),
            debug_streams: false,
        }
    }
}

/// What a stream has waiting to go out: whole messages, each padded as a stream needs.
#[derive(Default)]
struct Outbox {
    /// Plaintext not yet taken: by the socket (TCP), or by rustls (TLS, which takes more only once
    /// it has written what it has, so the two together stay near QUEUE_CAP).
    bytes: Vec<u8>,
}

impl Outbox {
    /// One message, or false if it didn't fit (dropped whole, as UDP would).
    fn push(&mut self, packet: &[u8]) -> bool {
        let pad = padding(packet);
        if self.bytes.len() + packet.len() + pad.len() > QUEUE_CAP {
            return false;
        }
        self.bytes.extend_from_slice(packet);
        self.bytes.extend_from_slice(pad);
        true
    }
}

struct Stream {
    socket: TcpStream,
    client: Client,
    tls: Option<ServerConnection>,
    framer: Framer,
    queue: Outbox,
    opened: Instant,
    heard: Instant,
    spoke: bool,
    /// Registered for WRITABLE as well.
    waiting: bool,
}

impl Stream {
    fn token(&self) -> Token {
        Token(self.client.conn as usize + STREAMS)
    }

    /// Writes what it can without blocking. Err: the stream is broken.
    fn flush(&mut self) -> io::Result<()> {
        let queue = &mut self.queue.bytes;
        let Some(tls) = &mut self.tls else {
            while !queue.is_empty() {
                match self.socket.write(queue) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(n) => drop(queue.drain(..n)),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            return Ok(());
        };
        loop {
            // rustls takes up to its own buffer's limit (64 KB) at a time, the rest next time round.
            if !tls.wants_write() && !queue.is_empty() && !tls.is_handshaking() {
                let n = tls.writer().write(queue)?;
                queue.drain(..n);
            }
            if !tls.wants_write() {
                return Ok(());
            }
            match tls.write_tls(&mut self.socket) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Flushes, then asks for WRITABLE while something still waits, READABLE alone otherwise.
    fn settle(&mut self, registry: &Registry) -> io::Result<()> {
        self.flush()?;
        let want =
            !self.queue.bytes.is_empty() || self.tls.as_ref().is_some_and(|t| t.wants_write());
        if want != self.waiting {
            let interest = if want {
                Interest::READABLE | Interest::WRITABLE
            } else {
                Interest::READABLE
            };
            let token = self.token();
            registry.reregister(&mut self.socket, token, interest)?;
            self.waiting = want;
        }
        Ok(())
    }

    /// One read into the framer: a chunk (its size), nothing more for now, or the end.
    fn fill_some(&mut self, buf: &mut [u8]) -> io::Result<Fill> {
        loop {
            let Some(tls) = &mut self.tls else {
                return match self.socket.read(buf) {
                    Ok(0) => Ok(Fill::Closed),
                    Ok(n) => {
                        self.framer.push(&buf[..n]);
                        Ok(Fill::Read(n))
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(Fill::Drained),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => Err(e),
                };
            };
            return match tls.read_tls(&mut self.socket) {
                Ok(0) => Ok(Fill::Closed),
                Ok(n) => {
                    let state = tls
                        .process_new_packets()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    let mut plain = state.plaintext_bytes_to_read();
                    while plain > 0 {
                        let take = plain.min(buf.len());
                        let got = tls.reader().read(&mut buf[..take])?;
                        if got == 0 {
                            break;
                        }
                        self.framer.push(&buf[..got]);
                        plain -= got;
                    }
                    if state.peer_has_closed() {
                        Ok(Fill::Closed)
                    } else {
                        Ok(Fill::Read(n))
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(Fill::Drained),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => Err(e),
            };
        }
    }
}

enum Fill {
    Read(usize),
    Drained,
    Closed,
}

/// Why a stream was closed.
enum Why {
    Junk,
    Hangup,
    /// No whole message by `first_message`.
    Silent,
    Idle,
    Error(io::Error),
}

impl fmt::Display for Why {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Why::Junk => write!(f, "not TURN"),
            Why::Hangup => write!(f, "closed by the client"),
            Why::Silent => write!(f, "no message in time"),
            Why::Idle => write!(f, "idle"),
            Why::Error(e) => write!(f, "{e}"),
        }
    }
}

/// Where the core's answers go: the UDP socket, or a stream's queue.
struct Links {
    udp: UdpSocket,
    streams: HashMap<u32, Stream>,
    /// Streams something was just queued on, written after each piece of work.
    touched: Vec<u32>,
    bytes_in: u64,
    bytes_out: u64,
}

impl Links {
    fn send(&mut self, to: Client, packet: &[u8]) {
        let sent = if to.conn == Client::UDP {
            // A full send buffer or an unreachable client is a lost packet, as UDP allows.
            self.udp.send_to(packet, to.addr).is_ok()
        } else if let Some(s) = self.streams.get_mut(&to.conn) {
            let ok = s.queue.push(packet);
            if ok {
                self.touched.push(to.conn);
            }
            ok
        } else {
            false
        };
        if sent {
            self.bytes_out += packet.len() as u64;
        }
    }
}

pub struct Relay {
    poll: Poll,
    events: Events,
    server: Server,
    out: Output,
    buf: Vec<u8>,
    links: Links,
    tcp: Option<TcpListener>,
    tls: Option<(TcpListener, Arc<Certificate>, Arc<ServerConfig>)>,
    per_ip: Counts<IpAddr>,
    next_conn: u32,
    limits: Limits,
    network: Option<Network>,
    /// The other nodes, measured from the UDP socket.
    prober: Prober,
    /// Sockets with more to read than their budget allowed: read again next turn. mio reports
    /// readiness once (edge-triggered), so these are remembered here.
    again: Vec<Token>,
    /// This turn's sockets to see to, and whether each may be read.
    work: Vec<(Token, bool)>,
    last_tick: Instant,
    last_log: Instant,
}

/// Relays until the control plane revokes this node.
pub fn run(
    l: Listeners,
    server: Server,
    network: Option<Network>,
    limits: Limits,
) -> io::Result<()> {
    Relay::new(l, server, network, limits)?.run();
    Ok(())
}

fn listen(registry: &Registry, l: std::net::TcpListener, token: Token) -> io::Result<TcpListener> {
    l.set_nonblocking(true)?;
    let mut l = TcpListener::from_std(l);
    registry.register(&mut l, token, Interest::READABLE)?;
    Ok(l)
}

impl Relay {
    pub fn new(
        l: Listeners,
        server: Server,
        network: Option<Network>,
        limits: Limits,
    ) -> io::Result<Self> {
        let poll = Poll::new()?;
        l.udp.set_nonblocking(true)?;
        let mut udp = UdpSocket::from_std(l.udp);
        poll.registry()
            .register(&mut udp, UDP, Interest::READABLE)?;
        let tcp = l.tcp.map(|t| listen(poll.registry(), t, TCP)).transpose()?;
        let tls = match l.tls {
            Some((t, cert)) => {
                let config = cert.server_config();
                Some((listen(poll.registry(), t, TLS)?, cert, config))
            }
            None => None,
        };
        let now = Instant::now();
        Ok(Relay {
            poll,
            events: Events::with_capacity(1024),
            server,
            out: Output::default(),
            buf: vec![0u8; 65536],
            links: Links {
                udp,
                streams: HashMap::new(),
                touched: Vec::new(),
                bytes_in: 0,
                bytes_out: 0,
            },
            tcp,
            tls,
            per_ip: Counts::default(),
            next_conn: 1,
            limits,
            network,
            prober: Prober::default(),
            again: Vec::new(),
            work: Vec::new(),
            last_tick: now,
            last_log: now,
        })
    }

    pub fn run(mut self) {
        while self.turn() {}
    }

    /// One turn of the loop: what's ready, then the once-a-second and once-a-minute work.
    /// False once revoked.
    fn turn(&mut self) -> bool {
        let wait = if self.again.is_empty() {
            Duration::from_millis(250)
        } else {
            Duration::ZERO
        };
        if let Err(e) = self.poll.poll(&mut self.events, Some(wait)) {
            if e.kind() != io::ErrorKind::Interrupted {
                eprintln!("poll: {e}");
            }
        }
        let now = Instant::now();
        let mut work = std::mem::take(&mut self.work);
        work.clear();
        work.extend(self.again.drain(..).map(|t| (t, true)));
        work.extend(self.events.iter().map(|e| {
            (
                e.token(),
                e.is_readable() || e.is_read_closed() || e.is_error(),
            )
        }));
        for &(token, readable) in &work {
            match token {
                UDP => self.read_udp(now),
                TCP | TLS => self.accept(token == TLS, now),
                t => self.serve(t, readable, now),
            }
            self.write_touched();
        }
        self.work = work;

        if now - self.last_tick >= Duration::from_secs(1) {
            self.last_tick = now;
            if !self.every_second(now) {
                return false;
            }
        }
        if now - self.last_log >= Duration::from_secs(60) {
            self.last_log = now;
            self.every_minute();
        }
        true
    }

    fn read_udp(&mut self, now: Instant) {
        for _ in 0..UDP_BUDGET {
            match self.links.udp.recv_from(&mut self.buf) {
                Ok((n, from)) => {
                    // The other nodes answering our probes: not for the core.
                    if self.prober.answer(from, &self.buf[..n], now) {
                        continue;
                    }
                    self.links.bytes_in += n as u64;
                    self.out.clear();
                    self.server.handle(now, from, &self.buf[..n], &mut self.out);
                    for (to, packet) in self.out.sends() {
                        self.links.send(to, packet);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                // A client's ICMP unreachable can surface here on some systems.
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    eprintln!("recv: {e}");
                    return;
                }
            }
        }
        self.again.push(UDP);
    }

    fn accept(&mut self, tls: bool, now: Instant) {
        loop {
            let listener = if tls {
                self.tls.as_ref().map(|t| &t.0)
            } else {
                self.tcp.as_ref()
            };
            let Some(listener) = listener else { return };
            match listener.accept() {
                Ok((socket, addr)) => self.open(socket, addr, tls, now),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                // Out of file descriptors, or a connection reset before we took it.
                Err(e) => {
                    eprintln!("accept: {e}");
                    return;
                }
            }
        }
    }

    /// A new connection, unless it's over the caps (dropped: that closes it).
    fn open(&mut self, socket: TcpStream, addr: SocketAddr, tls: bool, now: Instant) {
        let ip = addr.ip().to_canonical();
        if self.links.streams.len() >= self.limits.max_streams
            || self.per_ip.get(&ip) as usize >= self.limits.max_streams_per_ip
        {
            return;
        }
        let tls_conn = match &self.tls {
            Some((_, _, config)) if tls => match ServerConnection::new(config.clone()) {
                Ok(c) => Some(c),
                Err(_) => return,
            },
            _ => None,
        };
        let _ = socket.set_nodelay(true);
        let conn = self.next_conn();
        let mut s = Stream {
            socket,
            client: Client {
                addr: SocketAddr::new(ip, addr.port()),
                conn,
            },
            tls: tls_conn,
            framer: Framer::default(),
            queue: Outbox::default(),
            opened: now,
            heard: now,
            spoke: false,
            waiting: false,
        };
        let token = s.token();
        if self
            .poll
            .registry()
            .register(&mut s.socket, token, Interest::READABLE)
            .is_err()
        {
            return;
        }
        if self.limits.debug_streams {
            eprintln!(
                "stream {conn}: opened from {addr} ({})",
                if tls { "tls" } else { "tcp" }
            );
        }
        self.per_ip.add(ip);
        self.links.streams.insert(conn, s);
    }

    /// The next connection number no open stream has (they wrap after 2^32).
    fn next_conn(&mut self) -> u32 {
        loop {
            let conn = self.next_conn;
            self.next_conn = conn.checked_add(1).unwrap_or(1);
            if !self.links.streams.contains_key(&conn) {
                return conn;
            }
        }
    }

    /// A stream that's ready: read for up to its budget, its answers written.
    fn serve(&mut self, token: Token, readable: bool, now: Instant) {
        let conn = (token.0 - STREAMS) as u32;
        // Out of the map while it's read, so the core's answers to other streams can be queued
        // on them.
        let Some(mut s) = self.links.streams.remove(&conn) else {
            return;
        };
        match self.read_stream(&mut s, readable, now) {
            Ok(()) => {
                self.links.streams.insert(conn, s);
            }
            Err(why) => self.close(s, why),
        }
    }

    fn read_stream(&mut self, s: &mut Stream, readable: bool, now: Instant) -> Result<(), Why> {
        if readable {
            let mut budget = STREAM_BUDGET;
            loop {
                let fill = s.fill_some(&mut self.buf);
                // What arrived before an end or an error still counts (a last Refresh).
                self.take_messages(s, now)?;
                match fill.map_err(Why::Error)? {
                    Fill::Read(n) => {
                        budget = budget.saturating_sub(n);
                        if budget == 0 {
                            self.again.push(s.token());
                            break;
                        }
                    }
                    Fill::Drained => break,
                    Fill::Closed => return Err(Why::Hangup),
                }
            }
        }
        s.settle(self.poll.registry()).map_err(Why::Error)
    }

    /// Hands each whole message to the core and routes its answers.
    fn take_messages(&mut self, s: &mut Stream, now: Instant) -> Result<(), Why> {
        while let Some(frame) = s.framer.next() {
            let Frame::Message(m) = frame else {
                return Err(Why::Junk);
            };
            self.links.bytes_in += m.len() as u64;
            self.out.clear();
            self.server.handle_from(now, s.client, m, &mut self.out);
            for (to, packet) in self.out.sends() {
                // This stream is out of the map: its own answers go straight on its queue.
                if to.conn != s.client.conn {
                    self.links.send(to, packet);
                } else if s.queue.push(packet) {
                    self.links.bytes_out += packet.len() as u64;
                }
            }
            s.spoke = true;
            s.heard = now;
        }
        Ok(())
    }

    /// Streams the core just queued something on (from UDP or another stream).
    fn write_touched(&mut self) {
        let mut touched = std::mem::take(&mut self.links.touched);
        touched.sort_unstable();
        touched.dedup();
        for conn in &touched {
            let Some(s) = self.links.streams.get_mut(conn) else {
                continue;
            };
            if let Err(e) = s.settle(self.poll.registry()) {
                if let Some(s) = self.links.streams.remove(conn) {
                    self.close(s, Why::Error(e));
                }
            }
        }
        touched.clear();
        self.links.touched = touched;
    }

    fn close(&mut self, mut s: Stream, why: Why) {
        if self.limits.debug_streams {
            eprintln!("stream {}: {why}", s.client.conn);
        }
        let _ = self.poll.registry().deregister(&mut s.socket);
        self.server.closed(s.client);
        self.per_ip.release(&s.client.addr.ip());
    }

    /// The core's expiries, streams past their deadlines, and the heartbeat thread's news. False
    /// once revoked.
    fn every_second(&mut self, now: Instant) -> bool {
        self.server.tick(now);
        let (first, idle) = (self.limits.first_message, self.limits.idle);
        let stale: Vec<(u32, Why)> = self
            .links
            .streams
            .iter()
            .filter_map(|(&c, s)| {
                if !s.spoke && now - s.opened > first {
                    Some((c, Why::Silent))
                } else if now - s.heard > idle {
                    Some((c, Why::Idle))
                } else {
                    None
                }
            })
            .collect();
        for (conn, why) in stale {
            if let Some(s) = self.links.streams.remove(&conn) {
                self.close(s, why);
            }
        }
        let Some(n) = &self.network else {
            return true;
        };
        let udp = &self.links.udp;
        self.prober.due(Instant::now(), |to, m| {
            // Lost like any datagram if the buffer's full.
            let _ = udp.send_to(m, to);
        });
        if let Ok(mut s) = n.snapshot.lock() {
            *s = Snapshot {
                allocations: self.server.allocations() as u64,
                bytes_in: self.links.bytes_in,
                bytes_out: self.links.bytes_out,
                peers: self.prober.report(now),
            };
        }
        while let Ok(c) = n.controls.try_recv() {
            match c {
                Control::Peers(peers) => self.prober.set_peers(peers, now),
                Control::Key(k) => self.server.set_node_key(k, now, self.limits.key_overlap),
                Control::Accepting(yes) => self.server.set_accepting(yes),
                Control::Issuers(keys) => self
                    .server
                    .set_issuers(keys.iter().filter_map(|k| Issuer::parse(k)).collect()),
                Control::Exit => return false,
            }
        }
        true
    }

    /// A renewed certificate, and the stats line.
    fn every_minute(&mut self) {
        if let Some((_, cert, _)) = &self.tls {
            cert.reload_if_changed();
        }
        let s = self.server.stats();
        eprintln!(
            "allocations {}, streams {}, permissions allowed {} denied {}, unauthenticated requests dropped {}, relayed {} packets {} bytes, dropped over rate {} unroutable {}",
            self.server.allocations(),
            self.links.streams.len(),
            s.permissions_allowed,
            s.permissions_denied,
            s.unauthenticated_dropped,
            s.relayed_packets,
            s.relayed_bytes,
            s.dropped_rate,
            s.dropped_route
        );
    }
}
