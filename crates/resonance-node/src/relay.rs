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
use resonance_turn::budget::Budget;
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

/// What a stream may have waiting to go out (half a second at its allocation's rate cap). Past
/// it, messages are dropped whole.
const QUEUE_CAP: usize = 64 * 1024;
/// The kernel's send buffer for a stream: fixed, so a client that never reads holds this much
/// there and no more (autotuning would let it grow to megabytes).
const STREAM_SNDBUF: usize = 64 * 1024;
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
    /// Open streams, all together. Each can hold about QUEUE_CAP waiting, a message being read
    /// and its TLS state, so this times ~200 KB has to fit the node's memory.
    pub max_streams: usize,
    /// Open streams from one IP.
    pub max_streams_per_ip: usize,
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
            max_streams: 1024,
            max_streams_per_ip: 64,
            first_message: Duration::from_secs(10),
            idle: Duration::from_secs(15 * 60),
            debug_streams: false,
        }
    }
}

/// A stream holding less than this isn't one the sweep closes (`close_hoarders`): a client that
/// reads what it's sent holds about a message.
const HOARDING: usize = 16 * 1024;

/// The least room a queue grows to, and keeps once drained.
const MIN_QUEUE: usize = 4096;

/// What a stream has waiting to go out: whole messages, each padded as a stream needs.
struct Outbox {
    /// Plaintext not yet taken: by the socket (TCP), or by rustls (TLS, which takes more only once
    /// it has written what it has, so the two together stay near QUEUE_CAP).
    bytes: Vec<u8>,
}

impl Outbox {
    fn new() -> Self {
        Outbox { bytes: Vec::new() }
    }

    /// One message, or None if it didn't fit in this stream's queue or in the memory budget
    /// (`ip`'s share, or everyone's): dropped whole, as UDP would. The queue's room is what's
    /// charged, as it grows (doubling, up to QUEUE_CAP), so nothing is allocated that wasn't
    /// charged: the bytes charged now, if any. The stream gives them back as its queue shrinks
    /// (`Stream::settle_charge`).
    fn push(&mut self, packet: &[u8], memory: &mut Budget, ip: IpAddr) -> Option<usize> {
        let pad = padding(packet);
        let n = packet.len() + pad.len();
        let (len, room) = (self.bytes.len(), self.bytes.capacity());
        if len + n > QUEUE_CAP {
            return None;
        }
        let mut grew = 0;
        if len + n > room {
            let want = (len + n).max(room * 2).clamp(MIN_QUEUE, QUEUE_CAP);
            if !memory.charge(ip, want - room) {
                return None;
            }
            self.bytes.reserve_exact(want - len);
            debug_assert_eq!(self.bytes.capacity(), want);
            grew = want - room;
        }
        self.bytes.extend_from_slice(packet);
        self.bytes.extend_from_slice(pad);
        Some(grew)
    }

    /// The first `n` bytes went out. A queue that's mostly drained gives its room back.
    fn sent(&mut self, n: usize) {
        self.bytes.drain(..n);
        let (len, room) = (self.bytes.len(), self.bytes.capacity());
        if room > MIN_QUEUE && len <= room / 4 {
            self.bytes.shrink_to((len * 2).max(MIN_QUEUE));
        }
    }
}

struct Stream {
    socket: TcpStream,
    client: Client,
    tls: Option<ServerConnection>,
    framer: Framer,
    queue: Outbox,
    /// What it's charged in the memory budget: its queue's room, and its framer's.
    charged: usize,
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

    /// What it holds now: its queue's room, and its framer's.
    fn holds(&self) -> usize {
        self.queue.bytes.capacity() + self.framer.held()
    }

    /// Brings its charge to what it holds now. False (and nothing changed) if it grew past the
    /// budget; shrinking always works.
    fn settle_charge(&mut self, memory: &mut Budget) -> bool {
        let (had, now) = (self.charged, self.holds());
        if !memory.recharge(self.client.addr.ip(), had, now) {
            return false;
        }
        self.charged = now;
        true
    }

    /// One message on its queue, charged.
    fn push(&mut self, packet: &[u8], memory: &mut Budget) -> bool {
        match self.queue.push(packet, memory, self.client.addr.ip()) {
            Some(grew) => {
                self.charged += grew;
                true
            }
            None => false,
        }
    }

    /// Writes what it can without blocking. Err: the stream is broken.
    fn flush(&mut self) -> io::Result<()> {
        let queue = &mut self.queue;
        let Some(tls) = &mut self.tls else {
            while !queue.bytes.is_empty() {
                match self.socket.write(&queue.bytes) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(n) => queue.sent(n),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            return Ok(());
        };
        loop {
            // rustls takes up to its own buffer's limit (64 KB) at a time, the rest next time round.
            if !tls.wants_write() && !queue.bytes.is_empty() && !tls.is_handshaking() {
                let n = tls.writer().write(&queue.bytes)?;
                queue.sent(n);
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

    /// Flushes (giving back what went out), then asks for WRITABLE while something still waits,
    /// READABLE alone otherwise.
    fn settle(&mut self, registry: &Registry, memory: &mut Budget) -> io::Result<()> {
        let flushed = self.flush();
        if self.holds() < self.charged {
            self.settle_charge(memory);
        }
        flushed?;
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
    /// Among the streams holding the most when the memory budget was nearly full.
    Hoarding,
    /// What it read wouldn't fit in the memory budget.
    OverBudget,
    Error(io::Error),
}

impl fmt::Display for Why {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Why::Junk => write!(f, "not TURN"),
            Why::Hangup => write!(f, "closed by the client"),
            Why::Silent => write!(f, "no message in time"),
            Why::Idle => write!(f, "idle"),
            Why::Hoarding => write!(f, "held too much (sent and didn't read)"),
            Why::OverBudget => write!(f, "past the memory budget"),
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
    fn send(&mut self, to: Client, packet: &[u8], memory: &mut Budget) {
        let sent = if to.conn == Client::UDP {
            // A full send buffer or an unreachable client is a lost packet, as UDP allows.
            self.udp.send_to(packet, to.addr).is_ok()
        } else if let Some(s) = self.streams.get_mut(&to.conn) {
            let ok = s.push(packet, memory);
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
                        self.links.send(to, packet, self.server.memory_mut());
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
        let _ = socket2::SockRef::from(&socket).set_send_buffer_size(STREAM_SNDBUF);
        let conn = self.next_conn();
        let mut s = Stream {
            socket,
            client: Client {
                addr: SocketAddr::new(ip, addr.port()),
                conn,
            },
            tls: tls_conn,
            framer: Framer::default(),
            queue: Outbox::new(),
            charged: 0,
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
                // A message half read is held too: past the budget, the stream goes.
                if !s.settle_charge(self.server.memory_mut()) {
                    return Err(Why::OverBudget);
                }
                // What arrived before an end or an error still counts (a last Refresh).
                self.take_messages(s, now)?;
                s.framer.trim();
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
        s.settle(self.poll.registry(), self.server.memory_mut())
            .map_err(Why::Error)
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
                    self.links.send(to, packet, self.server.memory_mut());
                } else if s.push(packet, self.server.memory_mut()) {
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
            if let Err(e) = s.settle(self.poll.registry(), self.server.memory_mut()) {
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
        self.server
            .memory_mut()
            .refund(s.client.addr.ip(), s.charged);
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
        self.close_hoarders();
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
                Control::Accepting(yes) => self.server.set_accepting(yes),
                Control::Issuers(keys) => self
                    .server
                    .set_issuers(keys.iter().filter_map(|k| Issuer::parse(k)).collect()),
                Control::Exit => return false,
            }
        }
        true
    }

    /// Past three quarters of the memory budget, closes the streams holding the most until it's
    /// back under half, so new players have room. A client that reads what it's sent holds about
    /// a message, so these are the ones sending and not reading, or sitting on half a message;
    /// streams holding less than HOARDING are left alone.
    fn close_hoarders(&mut self) {
        let m = self.server.memory();
        if m.used() <= m.total() / 4 * 3 {
            return;
        }
        let target = m.total() / 2;
        let mut by_size: Vec<(usize, u32)> = self
            .links
            .streams
            .iter()
            .map(|(&c, s)| (s.charged, c))
            .filter(|&(size, _)| size >= HOARDING)
            .collect();
        by_size.sort_unstable_by(|a, b| b.cmp(a));
        for (_, conn) in by_size {
            if self.server.memory().used() <= target {
                break;
            }
            if let Some(s) = self.links.streams.remove(&conn) {
                self.close(s, Why::Hoarding);
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, n])
    }

    #[test]
    fn a_queue_is_charged_its_room_as_it_grows_and_drops_past_its_own_cap() {
        let mut memory = Budget::new(usize::MAX, usize::MAX);
        let mut q = Outbox::new();
        let m = [0u8; 1000];
        let mut charged = 0;
        let fits = QUEUE_CAP / 1000;
        for _ in 0..fits {
            charged += q.push(&m, &mut memory, ip(1)).unwrap();
            // Everything it holds is charged, never more than its cap.
            assert_eq!((charged, memory.of(ip(1))), (q.bytes.capacity(), charged));
        }
        assert!(q.bytes.capacity() <= QUEUE_CAP);
        assert_eq!(
            q.push(&m, &mut memory, ip(1)),
            None,
            "past QUEUE_CAP: dropped whole"
        );
        assert_eq!(memory.of(ip(1)), charged, "and not charged");
    }

    #[test]
    fn a_drained_queue_gives_its_room_back() {
        let mut memory = Budget::new(usize::MAX, usize::MAX);
        let mut q = Outbox::new();
        let m = [0u8; 1000];
        while q.push(&m, &mut memory, ip(1)).is_some() {}
        let full = q.bytes.capacity();
        q.sent(1000);
        assert_eq!(q.bytes.capacity(), full, "still most of it waiting");
        let rest = q.bytes.len();
        q.sent(rest);
        assert!(q.bytes.capacity() <= MIN_QUEUE, "{}", q.bytes.capacity());
    }

    #[test]
    fn queues_stop_at_their_ips_share_and_at_everyones_total() {
        let mut memory = Budget::new(3 * MIN_QUEUE, 2 * MIN_QUEUE);
        let (mut a, mut b, mut c, mut d) =
            (Outbox::new(), Outbox::new(), Outbox::new(), Outbox::new());
        let m = [0u8; 1000];
        assert_eq!(a.push(&m, &mut memory, ip(1)), Some(MIN_QUEUE));
        assert_eq!(b.push(&m, &mut memory, ip(1)), Some(MIN_QUEUE));
        assert_eq!(
            b.push(&m, &mut memory, ip(1)),
            Some(0),
            "within its room: nothing more"
        );
        let mut e = Outbox::new();
        assert_eq!(
            e.push(&m, &mut memory, ip(1)),
            None,
            "its IP's share, whichever stream"
        );
        assert_eq!(c.push(&m, &mut memory, ip(2)), Some(MIN_QUEUE));
        assert_eq!(d.push(&m, &mut memory, ip(2)), None, "everyone's total");
        memory.refund(ip(1), MIN_QUEUE);
        assert!(
            d.push(&m, &mut memory, ip(2)).is_some(),
            "room once some is given back"
        );
    }
}
