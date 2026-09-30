//! A TURN client for tests, speaking to the sans-I/O server directly.
#![allow(dead_code, clippy::too_many_arguments)]

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use resonance_turn::auth::password;
use resonance_turn::stun::{self, Class, Message, Writer, attr, method};
use resonance_turn::{Config, Output, Server};

pub const KEY: &str = "fiahLYMg85YkiFJQ0Xp3Bl0x3pXkUhI4nMU8jj6QRio";
pub const UNIX: u64 = 1_790_000_000;
pub const PUBLIC: &str = "192.0.2.1";

pub fn public() -> IpAddr {
    PUBLIC.parse().unwrap()
}

pub fn server(t: Instant) -> Server {
    Server::with_clock(Config::new(KEY, public(), [7; 32]), t, UNIX)
}

pub fn server_with(t: Instant, f: impl FnOnce(&mut Config)) -> Server {
    let mut cfg = Config::new(KEY, public(), [7; 32]);
    f(&mut cfg);
    Server::with_clock(cfg, t, UNIX)
}

pub fn user(room: &str, player: &str) -> String {
    format!("{}:ins:{room}:{player}", UNIX + 3600)
}

pub fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A TURN client over one 5-tuple: long-term credentials, fetching a nonce when it has none.
pub struct Client {
    pub from: SocketAddr,
    /// Its connection: 0 the UDP socket, else a TCP or TLS stream's number.
    pub conn: u32,
    pub nonce: Option<String>,
    pub tx: u32,
}

/// An answer, owned.
pub struct Reply(pub Vec<u8>);

impl Reply {
    pub fn msg(&self) -> Message<'_> {
        Message::parse(&self.0).expect("a STUN answer")
    }
    /// The error code, 0 for success.
    pub fn code(&self) -> u16 {
        let m = self.msg();
        match m.class {
            Class::Success => 0,
            Class::Error => {
                let v = m.get(attr::ERROR_CODE).unwrap();
                v[2] as u16 * 100 + v[3] as u16
            }
            c => panic!("{c:?}"),
        }
    }
}

pub type Attrs<'a> = &'a [(u16, Vec<u8>)];

pub fn transport() -> (u16, Vec<u8>) {
    (attr::REQUESTED_TRANSPORT, vec![17, 0, 0, 0])
}

pub fn lifetime(s: u32) -> (u16, Vec<u8>) {
    (attr::LIFETIME, s.to_be_bytes().to_vec())
}

/// The form the relay answers to: an IPv4-mapped IPv6 address is the IPv4 one.
pub fn canon(a: SocketAddr) -> SocketAddr {
    SocketAddr::new(a.ip().to_canonical(), a.port())
}

impl Client {
    pub fn new(from: &str) -> Self {
        Self::on(from, resonance_turn::Client::UDP)
    }

    /// A client on connection `conn` (a TCP or TLS stream).
    pub fn on(from: &str, conn: u32) -> Self {
        Client {
            from: addr(from),
            conn,
            nonce: None,
            tx: 0,
        }
    }

    pub fn core(&self) -> resonance_turn::Client {
        resonance_turn::Client {
            addr: self.from,
            conn: self.conn,
        }
    }

    /// What the relay sends, with the connection each goes on.
    pub fn send_on(
        &self,
        s: &mut Server,
        now: Instant,
        packet: &[u8],
    ) -> Vec<(resonance_turn::Client, Vec<u8>)> {
        let mut out = Output::default();
        s.handle_from(now, self.core(), packet, &mut out);
        out.sends().map(|(to, b)| (to, b.to_vec())).collect()
    }

    /// Unique across every client in the test binary.
    pub fn next_tx(&mut self) -> [u8; 12] {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        self.tx += 1;
        let mut tx = [0u8; 12];
        tx[4..].copy_from_slice(
            &NEXT
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .to_be_bytes(),
        );
        tx
    }

    pub fn send(&self, s: &mut Server, now: Instant, packet: &[u8]) -> Vec<(SocketAddr, Vec<u8>)> {
        self.send_on(s, now, packet)
            .into_iter()
            .map(|(to, b)| (to.addr, b))
            .collect()
    }

    /// Exactly one answer, to this client.
    pub fn ask(&self, s: &mut Server, now: Instant, packet: &[u8]) -> Reply {
        let mut got = self.send_on(s, now, packet);
        assert_eq!(got.len(), 1, "one answer");
        let (to, b) = got.pop().unwrap();
        assert_eq!(to.addr, canon(self.from));
        assert_eq!(to.conn, self.conn, "answers go on the connection asked on");
        Reply(b)
    }

    pub fn build(
        &self,
        m: u16,
        tx: [u8; 12],
        username: &str,
        pass: &str,
        realm: &str,
        attrs: Attrs,
        peer: Option<SocketAddr>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf, m, Class::Request, tx);
        for (k, v) in attrs {
            w.attr(*k, v);
        }
        if let Some(p) = peer {
            w.xor_address(attr::XOR_PEER_ADDRESS, p);
        }
        w.attr(attr::USERNAME, username.as_bytes())
            .attr(attr::REALM, realm.as_bytes())
            .attr(attr::NONCE, self.nonce.as_deref().unwrap_or("").as_bytes())
            .integrity(&resonance_turn::auth::long_term_key(username, realm, pass))
            .fingerprint();
        buf
    }

    /// An authenticated request as username, with its real password.
    pub fn request(
        &mut self,
        s: &mut Server,
        now: Instant,
        m: u16,
        username: &str,
        attrs: Attrs,
    ) -> Reply {
        self.request_to(s, now, m, username, attrs, None)
    }

    pub fn request_to(
        &mut self,
        s: &mut Server,
        now: Instant,
        m: u16,
        username: &str,
        attrs: Attrs,
        peer: Option<SocketAddr>,
    ) -> Reply {
        self.request_as(s, now, m, username, &password(KEY, username), attrs, peer)
    }

    pub fn request_as(
        &mut self,
        s: &mut Server,
        now: Instant,
        m: u16,
        username: &str,
        pass: &str,
        attrs: Attrs,
        peer: Option<SocketAddr>,
    ) -> Reply {
        if self.nonce.is_none() {
            let mut buf = Vec::new();
            let tx = self.next_tx();
            let mut w = Writer::new(&mut buf, m, Class::Request, tx);
            for (k, v) in attrs {
                w.attr(*k, v);
            }
            let r = self.ask(s, now, &buf);
            assert_eq!(r.code(), 401, "the first request gets a nonce");
            assert_eq!(r.msg().str_attr(attr::REALM), Some("gamerelay"));
            self.nonce = Some(r.msg().str_attr(attr::NONCE).unwrap().to_owned());
        }
        let tx = self.next_tx();
        let r = self.ask(
            s,
            now,
            &self.build(m, tx, username, pass, "gamerelay", attrs, peer),
        );
        if r.code() == 438 {
            self.nonce = Some(r.msg().str_attr(attr::NONCE).unwrap().to_owned());
            let tx = self.next_tx();
            return self.ask(
                s,
                now,
                &self.build(m, tx, username, pass, "gamerelay", attrs, peer),
            );
        }
        r
    }

    /// Allocates as username; the relay address it got.
    pub fn allocate(&mut self, s: &mut Server, now: Instant, username: &str) -> SocketAddr {
        let r = self.request(s, now, method::ALLOCATE, username, &[transport()]);
        assert_eq!(r.code(), 0, "allocate as {username}");
        let m = r.msg();
        assert!(m.integrity_ok(&resonance_turn::auth::long_term_key(
            username,
            "gamerelay",
            &password(KEY, username)
        )));
        assert_eq!(
            m.xor_address(attr::XOR_MAPPED_ADDRESS),
            Some(canon(self.from))
        );
        m.xor_address(attr::XOR_RELAYED_ADDRESS).unwrap()
    }

    pub fn permit(
        &mut self,
        s: &mut Server,
        now: Instant,
        username: &str,
        peer: SocketAddr,
    ) -> u16 {
        self.request_to(s, now, method::CREATE_PERMISSION, username, &[], Some(peer))
            .code()
    }

    pub fn bind(
        &mut self,
        s: &mut Server,
        now: Instant,
        username: &str,
        channel: u16,
        peer: SocketAddr,
    ) -> u16 {
        let number = (
            attr::CHANNEL_NUMBER,
            [channel.to_be_bytes(), [0, 0]].concat(),
        );
        self.request_to(
            s,
            now,
            method::CHANNEL_BIND,
            username,
            &[number],
            Some(peer),
        )
        .code()
    }

    pub fn send_indication(
        &mut self,
        s: &mut Server,
        now: Instant,
        peer: SocketAddr,
        data: &[u8],
    ) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut buf = Vec::new();
        let tx = self.next_tx();
        Writer::new(&mut buf, method::SEND, Class::Indication, tx)
            .xor_address(attr::XOR_PEER_ADDRESS, peer)
            .attr(attr::DATA, data);
        self.send(s, now, &buf)
    }

    pub fn channel_data(
        &self,
        s: &mut Server,
        now: Instant,
        channel: u16,
        data: &[u8],
    ) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut buf = Vec::new();
        stun::write_channel_data(&mut buf, channel, data);
        self.send(s, now, &buf)
    }
}

pub fn binding(tx: u8) -> Vec<u8> {
    let mut buf = Vec::new();
    Writer::new(&mut buf, method::BINDING, Class::Request, [tx; 12]);
    buf
}

/// Two players of one room, each allocated with a permission for this relay.
pub fn pair(s: &mut Server, t: Instant, room_b: &str) -> (Client, SocketAddr, Client, SocketAddr) {
    let (mut a, mut b) = (
        Client::new("198.51.100.1:5000"),
        Client::new("203.0.113.9:6000"),
    );
    let ra = a.allocate(s, t, &user("g1", "p_a"));
    let rb = b.allocate(s, t, &user(room_b, "p_b"));
    assert_eq!(a.permit(s, t, &user("g1", "p_a"), rb), 0);
    assert_eq!(b.permit(s, t, &user(room_b, "p_b"), ra), 0);
    (a, ra, b, rb)
}
