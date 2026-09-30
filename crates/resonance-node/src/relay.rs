//! The relay loop: one thread holds the TURN core and polls the UDP socket, the TCP and TLS
//! listeners (when configured) and every stream connection. Nothing is locked or handed between
//! threads on the way through: a message is read, handled and its answers written in one go.
//!
//! A stream is its own client (RFC 8656 §12.5): its messages are framed out of the bytes, what the
//! core sends it is queued on it, and when it closes its allocation goes with it. A slow stream
//! drops what doesn't fit in its queue, whole messages at a time, as UDP would.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mio::net::{TcpListener, TcpStream, UdpSocket};
use mio::{Events, Interest, Poll, Token};
use resonance_turn::stream::{Frame, Framer, padding};
use resonance_turn::{Client, Output, Server};
use rustls::{ServerConfig, ServerConnection};

use crate::control::{Control, Snapshot};
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
/// A stream that hasn't sent a whole message by then (its TLS handshake included) is closed.
const FIRST_MESSAGE: Duration = Duration::from_secs(10);
/// Silence after which a stream is closed: longer than any client leaves between refreshes.
const IDLE: Duration = Duration::from_secs(15 * 60);

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
    pub key_overlap: Duration,
}

struct Stream {
    socket: TcpStream,
    client: Client,
    tls: Option<ServerConnection>,
    framer: Framer,
    /// Plaintext not yet taken: by the socket (TCP), or by rustls (TLS, which takes more only once
    /// it has written what it has, so the two together stay near QUEUE_CAP).
    queue: Vec<u8>,
    opened: Instant,
    heard: Instant,
    spoke: bool,
    /// Registered for WRITABLE as well.
    waiting: bool,
}

impl Stream {
    /// One message for this client, or false if it didn't fit.
    fn enqueue(&mut self, packet: &[u8]) -> bool {
        let pad = padding(packet);
        if self.queue.len() + packet.len() + pad.len() > QUEUE_CAP {
            return false;
        }
        self.queue.extend_from_slice(packet);
        self.queue.extend_from_slice(pad);
        true
    }

    /// Writes what it can without blocking. Err: the stream is broken.
    fn flush(&mut self) -> io::Result<()> {
        let Some(tls) = &mut self.tls else {
            while !self.queue.is_empty() {
                match self.socket.write(&self.queue) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(n) => drop(self.queue.drain(..n)),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            return Ok(());
        };
        loop {
            // rustls takes up to its own buffer's limit (64 KB) at a time, the rest next time round.
            if !tls.wants_write() && !self.queue.is_empty() && !tls.is_handshaking() {
                let n = tls.writer().write(&self.queue)?;
                self.queue.drain(..n);
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

    fn pending(&self) -> bool {
        !self.queue.is_empty() || self.tls.as_ref().is_some_and(|t| t.wants_write())
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

    /// Hands each whole message to the core and routes its answers. False: junk, close it.
    fn take_messages(
        &mut self,
        server: &mut Server,
        now: Instant,
        out: &mut Output,
        route: &mut Route,
    ) -> bool {
        while let Some(frame) = self.framer.next() {
            let Frame::Message(m) = frame else {
                return false;
            };
            *route.bytes_in += m.len() as u64;
            out.clear();
            server.handle_from(now, self.client, m, out);
            for (to, packet) in out.sends() {
                // `m` borrows the framer; answers to this stream only touch its queue.
                let sent = if to.conn == self.client.conn {
                    let pad = padding(packet);
                    let fits = self.queue.len() + packet.len() + pad.len() <= QUEUE_CAP;
                    if fits {
                        self.queue.extend_from_slice(packet);
                        self.queue.extend_from_slice(pad);
                    }
                    fits
                } else {
                    route.one(to, packet)
                };
                if sent {
                    *route.bytes_out += packet.len() as u64;
                }
            }
            self.spoke = true;
            self.heard = now;
        }
        true
    }
}

enum Fill {
    Read(usize),
    Drained,
    Closed,
}

/// Where the core's answers go: the UDP socket, the stream being read, or another stream.
struct Route<'a> {
    udp: &'a UdpSocket,
    streams: &'a mut HashMap<u32, Stream>,
    touched: &'a mut Vec<u32>,
    bytes_in: &'a mut u64,
    bytes_out: &'a mut u64,
}

impl Route<'_> {
    /// Everything in `out`, from a UDP datagram.
    fn send(&mut self, out: &Output) {
        for (to, packet) in out.sends() {
            if self.one(to, packet) {
                *self.bytes_out += packet.len() as u64;
            }
        }
    }

    fn one(&mut self, to: Client, packet: &[u8]) -> bool {
        if to.conn == Client::UDP {
            // A full send buffer or an unreachable client is a lost packet, as UDP allows.
            return self.udp.send_to(packet, to.addr).is_ok();
        }
        let Some(s) = self.streams.get_mut(&to.conn) else {
            return false;
        };
        let ok = s.enqueue(packet);
        if ok {
            self.touched.push(to.conn);
        }
        ok
    }
}

pub fn run(l: Listeners, mut server: Server, network: Option<Network>, limits: Limits) -> ! {
    let mut poll = Poll::new().unwrap_or_else(|e| crate::fail(&format!("poll: {e}")));
    let registry = poll.registry().try_clone().expect("a registry");
    l.udp.set_nonblocking(true).expect("nonblocking");
    let mut udp = UdpSocket::from_std(l.udp);
    registry
        .register(&mut udp, UDP, Interest::READABLE)
        .expect("register udp");
    let mut tcp = l.tcp.map(|t| {
        t.set_nonblocking(true).expect("nonblocking");
        let mut t = TcpListener::from_std(t);
        registry
            .register(&mut t, TCP, Interest::READABLE)
            .expect("register tcp");
        t
    });
    let (mut tls, cert, tls_config): (Option<TcpListener>, _, Option<Arc<ServerConfig>>) =
        match l.tls {
            Some((t, cert)) => {
                t.set_nonblocking(true).expect("nonblocking");
                let mut t = TcpListener::from_std(t);
                registry
                    .register(&mut t, TLS, Interest::READABLE)
                    .expect("register tls");
                let config = cert.server_config();
                (Some(t), Some(cert), Some(config))
            }
            None => (None, None, None),
        };

    // TURN_DEBUG_STREAMS=1: each stream's opening and why it closed.
    let debug = std::env::var("TURN_DEBUG_STREAMS").is_ok_and(|v| v == "1");
    let mut events = Events::with_capacity(1024);
    let mut buf = vec![0u8; 65536];
    let mut out = Output::default();
    let mut streams: HashMap<u32, Stream> = HashMap::new();
    let mut per_ip: HashMap<IpAddr, usize> = HashMap::new();
    let mut touched: Vec<u32> = Vec::new();
    let mut next_conn: u32 = 1;
    let mut last_tick = Instant::now();
    let mut last_log = last_tick;
    let (mut bytes_in, mut bytes_out) = (0u64, 0u64);

    let close = |s: Stream,
                 server: &mut Server,
                 per_ip: &mut HashMap<IpAddr, usize>,
                 registry: &mio::Registry| {
        let mut s = s;
        let _ = registry.deregister(&mut s.socket);
        server.closed(s.client);
        let ip = s.client.addr.ip();
        if let Some(n) = per_ip.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                per_ip.remove(&ip);
            }
        }
    };
    // After writing: WRITABLE interest while something waits, READABLE alone otherwise.
    let settle = |s: &mut Stream, registry: &mio::Registry| -> io::Result<()> {
        s.flush()?;
        let want = s.pending();
        if want != s.waiting {
            let token = Token(s.client.conn as usize + STREAMS);
            let interest = if want {
                Interest::READABLE | Interest::WRITABLE
            } else {
                Interest::READABLE
            };
            registry.reregister(&mut s.socket, token, interest)?;
            s.waiting = want;
        }
        Ok(())
    };

    // Sockets with more to read than their budget allowed: read again next turn. mio reports
    // readiness once (edge-triggered), so these are remembered here.
    let mut again: Vec<Token> = Vec::new();
    let mut work: Vec<(Token, bool)> = Vec::new();
    loop {
        let wait = if again.is_empty() {
            Duration::from_millis(250)
        } else {
            Duration::ZERO
        };
        if let Err(e) = poll.poll(&mut events, Some(wait)) {
            if e.kind() != io::ErrorKind::Interrupted {
                eprintln!("poll: {e}");
            }
        }
        let now = Instant::now();
        work.clear();
        work.extend(again.drain(..).map(|t| (t, true)));
        work.extend(events.iter().map(|e| {
            (
                e.token(),
                e.is_readable() || e.is_read_closed() || e.is_error(),
            )
        }));
        for &(token, readable) in &work {
            match token {
                UDP => {
                    for n in 0.. {
                        if n == UDP_BUDGET {
                            again.push(UDP);
                            break;
                        }
                        match udp.recv_from(&mut buf) {
                            Ok((n, from)) => {
                                bytes_in += n as u64;
                                out.clear();
                                server.handle(now, from, &buf[..n], &mut out);
                                Route {
                                    udp: &udp,
                                    streams: &mut streams,
                                    touched: &mut touched,
                                    bytes_in: &mut bytes_in,
                                    bytes_out: &mut bytes_out,
                                }
                                .send(&out);
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            // A client's ICMP unreachable can surface here on some systems.
                            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                            Err(e) => {
                                eprintln!("recv: {e}");
                                break;
                            }
                        }
                    }
                }
                t @ (TCP | TLS) => {
                    let listener = if t == TCP { tcp.as_mut() } else { tls.as_mut() };
                    let Some(listener) = listener else { continue };
                    loop {
                        let (mut socket, addr): (TcpStream, SocketAddr) = match listener.accept() {
                            Ok(a) => a,
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            // Out of file descriptors, or a connection reset before we took it.
                            Err(e) => {
                                eprintln!("accept: {e}");
                                break;
                            }
                        };
                        let ip = addr.ip().to_canonical();
                        let from_ip = per_ip.get(&ip).copied().unwrap_or(0);
                        if streams.len() >= limits.max_streams
                            || from_ip >= limits.max_streams_per_ip
                        {
                            continue; // dropped: closes it
                        }
                        let _ = socket.set_nodelay(true);
                        let conn = next_conn;
                        next_conn = next_conn.checked_add(1).unwrap_or(1);
                        let token = Token(conn as usize + STREAMS);
                        if registry
                            .register(&mut socket, token, Interest::READABLE)
                            .is_err()
                        {
                            continue;
                        }
                        let tls_conn = match (t, &tls_config) {
                            (TLS, Some(c)) => match ServerConnection::new(c.clone()) {
                                Ok(c) => Some(c),
                                Err(_) => continue,
                            },
                            _ => None,
                        };
                        if debug {
                            eprintln!(
                                "stream {conn}: opened from {addr} ({})",
                                if t == TLS { "tls" } else { "tcp" }
                            );
                        }
                        *per_ip.entry(ip).or_default() += 1;
                        streams.insert(
                            conn,
                            Stream {
                                socket,
                                client: Client {
                                    addr: SocketAddr::new(ip, addr.port()),
                                    conn,
                                },
                                tls: tls_conn,
                                framer: Framer::default(),
                                queue: Vec::new(),
                                opened: now,
                                heard: now,
                                spoke: false,
                                waiting: false,
                            },
                        );
                    }
                }
                Token(t) => {
                    let conn = (t - STREAMS) as u32;
                    let token = Token(t);
                    // Out of the map while it's read, so the core's answers to other streams can
                    // be queued on them.
                    let Some(mut s) = streams.remove(&conn) else {
                        continue;
                    };
                    let mut alive = true;
                    let mut budget = STREAM_BUDGET;
                    while readable && alive {
                        let fill = s.fill_some(&mut buf);
                        let mut route = Route {
                            udp: &udp,
                            streams: &mut streams,
                            touched: &mut touched,
                            bytes_in: &mut bytes_in,
                            bytes_out: &mut bytes_out,
                        };
                        // What arrived before an end or an error still counts (a last Refresh).
                        if !s.take_messages(&mut server, now, &mut out, &mut route) {
                            alive = false;
                            break;
                        }
                        match fill {
                            Ok(Fill::Read(n)) => {
                                budget = budget.saturating_sub(n);
                                if budget == 0 {
                                    again.push(token);
                                    break;
                                }
                            }
                            Ok(Fill::Drained) => break,
                            Ok(Fill::Closed) => {
                                alive = false;
                                break;
                            }
                            Err(e) => {
                                if debug {
                                    eprintln!("stream {conn}: {e}");
                                }
                                alive = false;
                                break;
                            }
                        }
                    }
                    if alive {
                        if let Err(e) = settle(&mut s, &registry) {
                            if debug {
                                eprintln!("stream {conn}: {e}");
                            }
                            alive = false;
                        }
                    }
                    if alive {
                        streams.insert(conn, s);
                    } else {
                        close(s, &mut server, &mut per_ip, &registry);
                    }
                }
            }
            // Streams the core just queued something on (from UDP or another stream).
            touched.sort_unstable();
            touched.dedup();
            for conn in touched.drain(..) {
                if let Some(s) = streams.get_mut(&conn) {
                    if let Err(e) = settle(s, &registry) {
                        if debug {
                            eprintln!("stream {conn}: {e}");
                        }
                        if let Some(s) = streams.remove(&conn) {
                            close(s, &mut server, &mut per_ip, &registry);
                        }
                    }
                }
            }
        }

        if now - last_tick >= Duration::from_secs(1) {
            server.tick(now);
            last_tick = now;
            let stale: Vec<u32> = streams
                .iter()
                .filter(|(_, s)| {
                    (!s.spoke && now - s.opened > FIRST_MESSAGE) || now - s.heard > IDLE
                })
                .map(|(&c, _)| c)
                .collect();
            for conn in stale {
                if let Some(s) = streams.remove(&conn) {
                    close(s, &mut server, &mut per_ip, &registry);
                }
            }
            if let Some(n) = &network {
                while let Ok(c) = n.controls.try_recv() {
                    match c {
                        Control::Key(k) => server.set_node_key(k, now, limits.key_overlap),
                        Control::Accepting(yes) => server.set_accepting(yes),
                        Control::Exit => std::process::exit(0),
                    }
                }
                if let Ok(mut s) = n.snapshot.lock() {
                    *s = Snapshot {
                        allocations: server.allocations() as u64,
                        bytes_in,
                        bytes_out,
                    };
                }
            }
        }
        if now - last_log >= Duration::from_secs(60) {
            if let Some(c) = &cert {
                c.reload_if_changed();
            }
            let s = server.stats();
            eprintln!(
                "allocations {}, streams {}, permissions allowed {} denied {}, unauthenticated requests dropped {}, relayed {} packets {} bytes, dropped over rate {} unroutable {}",
                server.allocations(),
                streams.len(),
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
