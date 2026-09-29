//! The room-scoped TURN relay (Resonance v0 §4), sans-I/O: packets and time in, packets out.
//!
//! Both players of a pair allocate here (the SDK picks one relay per pair,
//! packages/sdk/src/sync/relays.ts), and the only permitted peer is this relay itself. So every
//! relayed packet goes from one of this relay's allocations to another, and never leaves memory
//! in between: relay ports are names, not sockets. Nothing outside can reach a relay address,
//! and nothing relayed can reach anyone but another allocation of the same room.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::auth::{self, NonceCheck, Nonces, User};
use crate::limiter::{Bucket, Reflection};
use crate::stun::{self, Class, Message, Writer, attr, method};

pub struct Config {
    pub realm: String,
    /// This node's own key (Resonance v0 §1). It mints credentials for this node only.
    pub node_key: String,
    /// The address players reach this relay at, and the one relay addresses are named on.
    pub public_ip: IpAddr,
    /// Relay addresses are this IP with a port from here.
    pub min_port: u16,
    pub max_port: u16,
    /// One allocation per other player in a full room.
    pub max_per_player: u32,
    /// A household or a carrier's shared address can hold several players, each holding an
    /// allocation for every other player.
    pub max_per_ip: u32,
    /// One game, or one leaked game key, can't take the whole relay from the others.
    pub max_per_instance: u32,
    /// Per allocation: a player's copies to one peer (a game sends a few KB a second).
    pub rate_bytes: f64,
    pub burst_bytes: f64,
    pub unauth_rate: f64,
    pub unauth_burst: f64,
    pub unauth_tracked: usize,
    pub default_lifetime_s: u32,
    pub max_lifetime_s: u32,
    pub permission_lifetime: Duration,
    pub channel_lifetime: Duration,
    /// Makes nonces; any random bytes, new at each start.
    pub nonce_key: [u8; 32],
}

impl Config {
    /// The Go relay's limits (deploy/turn/main.go).
    pub fn new(node_key: impl Into<String>, public_ip: IpAddr, nonce_key: [u8; 32]) -> Self {
        let max_per_ip = 64;
        Config {
            realm: "gamerelay".into(),
            node_key: node_key.into(),
            public_ip: public_ip.to_canonical(),
            min_port: 49152,
            max_port: 65535,
            max_per_player: 8,
            max_per_ip,
            max_per_instance: 4096,
            rate_bytes: 128.0 * 1024.0,
            burst_bytes: 256.0 * 1024.0,
            unauth_rate: 20.0,
            unauth_burst: max_per_ip as f64,
            unauth_tracked: 65536,
            default_lifetime_s: 600,
            max_lifetime_s: 3600,
            permission_lifetime: Duration::from_secs(300),
            channel_lifetime: Duration::from_secs(600),
            nonce_key,
        }
    }
}

/// What to send, in one reused buffer.
#[derive(Default)]
pub struct Output {
    buf: Vec<u8>,
    sends: Vec<(SocketAddr, usize, usize)>,
}

impl Output {
    pub fn clear(&mut self) {
        self.buf.clear();
        self.sends.clear();
    }

    pub fn iter(&self) -> impl Iterator<Item = (SocketAddr, &[u8])> {
        self.sends.iter().map(|&(to, a, b)| (to, &self.buf[a..b]))
    }

    pub fn len(&self) -> usize {
        self.sends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sends.is_empty()
    }

    fn start(&mut self) -> usize {
        self.buf.len()
    }

    fn push(&mut self, to: SocketAddr, start: usize) {
        self.sends.push((to, start, self.buf.len()));
    }
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub permissions_allowed: u64,
    pub permissions_denied: u64,
    pub unauthenticated_dropped: u64,
    pub relayed_packets: u64,
    pub relayed_bytes: u64,
    /// Relayed packets dropped: over the allocation's rate.
    pub dropped_rate: u64,
    /// Relayed packets dropped: no such allocation, another room, or no permission.
    pub dropped_route: u64,
}

struct Channel {
    number: u16,
    peer_port: u16,
    expires: Instant,
}

struct Allocation {
    client: SocketAddr,
    port: u16,
    room: u32,
    user: User,
    /// The username last authenticated, and its key, so a refresh doesn't hash again.
    username: String,
    key: [u8; 16],
    expires: Instant,
    lifetime_s: u32,
    /// A permission is per peer IP, and the only permitted peer IP is this relay's.
    permission_expires: Option<Instant>,
    channels: Vec<Channel>,
    bucket: Bucket,
    /// Its Allocate's transaction, so a retransmission gets the same answer, not a 437.
    allocate_tx: [u8; 12],
}

const NONE: u32 = u32::MAX;

pub struct Server {
    cfg: Config,
    nonces: Nonces,
    limiter: Reflection,
    allocs: Vec<Option<Allocation>>,
    free: Vec<u32>,
    by_client: HashMap<SocketAddr, u32>,
    /// Relay port − min_port → allocation.
    by_port: Vec<u32>,
    next_port: usize,
    rooms: HashMap<String, (u32, u32)>,
    next_room: u32,
    per_player: HashMap<String, u32>,
    per_ip: HashMap<IpAddr, u32>,
    per_instance: HashMap<String, u32>,
    stats: Stats,
    clock: (Instant, u64),
}

/// Why a request was refused, and whether the answer can carry MESSAGE-INTEGRITY.
struct Refusal {
    code: u16,
    reason: &'static str,
    key: Option<[u8; 16]>,
}

impl Server {
    pub fn new(cfg: Config) -> Self {
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self::with_clock(cfg, Instant::now(), unix)
    }

    /// `base` is `unix` seconds since the epoch (tests set both).
    pub fn with_clock(cfg: Config, base: Instant, unix: u64) -> Self {
        assert!(cfg.min_port <= cfg.max_port, "min_port above max_port");
        let ports = (cfg.max_port - cfg.min_port) as usize + 1;
        Server {
            nonces: Nonces::new(cfg.nonce_key),
            limiter: Reflection::new(cfg.unauth_rate, cfg.unauth_burst, cfg.unauth_tracked),
            allocs: Vec::new(),
            free: Vec::new(),
            by_client: HashMap::new(),
            by_port: vec![NONE; ports],
            next_port: 0,
            rooms: HashMap::new(),
            next_room: 0,
            per_player: HashMap::new(),
            per_ip: HashMap::new(),
            per_instance: HashMap::new(),
            stats: Stats::default(),
            clock: (base, unix),
            cfg,
        }
    }

    pub fn stats(&self) -> Stats {
        Stats {
            unauthenticated_dropped: self.limiter.dropped,
            ..self.stats.clone()
        }
    }

    pub fn allocations(&self) -> usize {
        self.by_client.len()
    }

    fn unix(&self, now: Instant) -> u64 {
        self.clock.1 + now.saturating_duration_since(self.clock.0).as_secs()
    }

    /// Ends allocations, permissions and channels that ran out. Call about once a second.
    pub fn tick(&mut self, now: Instant) {
        let expired: Vec<u32> = self
            .allocs
            .iter()
            .enumerate()
            .filter_map(|(i, a)| a.as_ref().filter(|a| a.expires <= now).map(|_| i as u32))
            .collect();
        for i in expired {
            self.delete(i);
        }
        for a in self.allocs.iter_mut().flatten() {
            a.channels.retain(|c| c.expires > now);
            if a.permission_expires.is_some_and(|t| t <= now) {
                a.permission_expires = None;
            }
        }
    }

    /// One packet from a client. What to send goes into `out` (not cleared first).
    pub fn handle(&mut self, now: Instant, from: SocketAddr, packet: &[u8], out: &mut Output) {
        let from = SocketAddr::new(from.ip().to_canonical(), from.port());
        if stun::is_channel_data(packet) {
            if let Some((channel, data)) = stun::parse_channel_data(packet) {
                self.channel_data(now, from, channel, data, out);
            }
            return;
        }
        let Some(msg) = Message::parse(packet) else {
            return;
        };
        let allocated = self.live_alloc(from, now).is_some();
        if msg.class == Class::Request
            && !msg.has(attr::MESSAGE_INTEGRITY)
            && !allocated
            && !self.limiter.allow(from.ip(), now)
        {
            return;
        }
        match (msg.class, msg.method) {
            (Class::Indication, method::SEND) => self.send_indication(now, from, &msg, out),
            (Class::Request, m) => {
                if let Some(kind) = msg.unknown_required() {
                    let start = out.start();
                    let mut w = Writer::new(&mut out.buf, m, Class::Error, msg.tx);
                    w.error(420, "Unknown Attribute")
                        .attr(attr::UNKNOWN_ATTRIBUTES, &kind.to_be_bytes());
                    w.fingerprint();
                    out.push(from, start);
                    return;
                }
                let result = match m {
                    method::BINDING => {
                        let start = out.start();
                        Writer::new(&mut out.buf, m, Class::Success, msg.tx)
                            .xor_address(attr::XOR_MAPPED_ADDRESS, from)
                            .fingerprint();
                        out.push(from, start);
                        Ok(())
                    }
                    method::ALLOCATE => self.allocate(now, from, &msg, out),
                    method::REFRESH => self.refresh(now, from, &msg, out),
                    method::CREATE_PERMISSION => self.create_permission(now, from, &msg, out),
                    method::CHANNEL_BIND => self.channel_bind(now, from, &msg, out),
                    _ => Err(Refusal {
                        code: 400,
                        reason: "Bad Request",
                        key: None,
                    }),
                };
                if let Err(r) = result {
                    self.refuse(now, from, &msg, r, out);
                }
            }
            _ => {}
        }
    }

    fn refuse(&self, now: Instant, from: SocketAddr, msg: &Message, r: Refusal, out: &mut Output) {
        let start = out.start();
        let mut w = Writer::new(&mut out.buf, msg.method, Class::Error, msg.tx);
        w.error(r.code, r.reason);
        if matches!(r.code, 401 | 438) {
            let nonce = self.nonces.issue(self.unix(now));
            w.attr(attr::REALM, self.cfg.realm.as_bytes())
                .attr(attr::NONCE, nonce.as_bytes());
        }
        if let Some(key) = r.key {
            w.integrity(&key);
        }
        w.fingerprint();
        out.push(from, start);
    }

    fn live_alloc(&mut self, from: SocketAddr, now: Instant) -> Option<u32> {
        let &i = self.by_client.get(&from)?;
        if self.alloc(i).expires <= now {
            self.delete(i);
            return None;
        }
        Some(i)
    }

    fn alloc(&self, i: u32) -> &Allocation {
        self.allocs[i as usize].as_ref().expect("a live index")
    }

    fn alloc_mut(&mut self, i: u32) -> &mut Allocation {
        self.allocs[i as usize].as_mut().expect("a live index")
    }

    /// Long-term credentials (RFC 8489 §9.2), then: once a 5-tuple has an allocation, only a
    /// username for the same room and player (the Go relay's boundAuth). A player who left a room
    /// can't keep its allocation alive, or point it at another room, with another credential.
    fn authenticate(
        &mut self,
        now: Instant,
        from: SocketAddr,
        msg: &Message,
    ) -> Result<(User, String, [u8; 16]), Refusal> {
        let unauthorized = Refusal {
            code: 401,
            reason: "Unauthorized",
            key: None,
        };
        let (Some(username), Some(realm), Some(nonce)) = (
            msg.str_attr(attr::USERNAME),
            msg.str_attr(attr::REALM),
            msg.str_attr(attr::NONCE),
        ) else {
            return Err(unauthorized);
        };
        if !msg.has(attr::MESSAGE_INTEGRITY) || realm != self.cfg.realm {
            return Err(unauthorized);
        }
        match self.nonces.check(nonce, self.unix(now)) {
            NonceCheck::Ok => {}
            NonceCheck::Stale => {
                return Err(Refusal {
                    code: 438,
                    reason: "Stale Nonce",
                    key: None,
                });
            }
            NonceCheck::Bad => return Err(unauthorized),
        }
        let Some(user) = auth::parse_username(username) else {
            return Err(unauthorized);
        };
        // No request succeeds past the credential's expiry, so an allocation outlives it by at
        // most one lifetime.
        if user.expiry <= self.unix(now) {
            return Err(unauthorized);
        }
        let existing = self.live_alloc(from, now);
        let key = match existing.map(|i| self.alloc(i)) {
            Some(a) if a.username == username => a.key,
            _ => auth::long_term_key(
                username,
                &self.cfg.realm,
                &auth::password(&self.cfg.node_key, username),
            ),
        };
        if !msg.integrity_ok(&key) {
            return Err(unauthorized);
        }
        if let Some(i) = existing {
            let a = self.alloc(i);
            if a.user.room != user.room || a.user.player != user.player {
                return Err(Refusal {
                    code: 441,
                    reason: "Wrong Credentials",
                    key: Some(key),
                });
            }
        }
        Ok((user, username.to_owned(), key))
    }

    fn lifetime(&self, msg: &Message) -> u32 {
        let asked = msg
            .u32_attr(attr::LIFETIME)
            .unwrap_or(self.cfg.default_lifetime_s);
        asked.clamp(self.cfg.default_lifetime_s, self.cfg.max_lifetime_s)
    }

    fn allocate(
        &mut self,
        now: Instant,
        from: SocketAddr,
        msg: &Message,
        out: &mut Output,
    ) -> Result<(), Refusal> {
        let (user, username, key) = self.authenticate(now, from, msg)?;
        let refuse = |code, reason| Refusal {
            code,
            reason,
            key: Some(key),
        };
        if let Some(i) = self.live_alloc(from, now) {
            let a = self.alloc(i);
            if a.allocate_tx != msg.tx {
                return Err(refuse(437, "Allocation Mismatch"));
            }
            let (port, lifetime) = (a.port, a.lifetime_s);
            self.allocate_success(from, msg, port, lifetime, &key, out);
            return Ok(());
        }
        match msg.get(attr::REQUESTED_TRANSPORT) {
            Some(v) if v.len() == 4 && v[0] == 17 => {}
            Some(_) => return Err(refuse(442, "Unsupported Transport Protocol")),
            None => return Err(refuse(400, "Bad Request")),
        }
        if let Some(v) = msg.get(attr::REQUESTED_ADDRESS_FAMILY) {
            let ours = if self.cfg.public_ip.is_ipv4() {
                0x01
            } else {
                0x02
            };
            if v.len() != 4 || v[0] != ours {
                return Err(refuse(440, "Address Family not Supported"));
            }
        }
        let ip = from.ip();
        if self.per_player.get(&user.player).copied().unwrap_or(0) >= self.cfg.max_per_player
            || self.per_ip.get(&ip).copied().unwrap_or(0) >= self.cfg.max_per_ip
            || self.per_instance.get(&user.instance).copied().unwrap_or(0)
                >= self.cfg.max_per_instance
        {
            return Err(refuse(486, "Allocation Quota Reached"));
        }
        let Some(slot) = self.free_port() else {
            return Err(refuse(508, "Insufficient Capacity"));
        };
        let port = self.cfg.min_port + slot as u16;
        let lifetime_s = self.lifetime(msg);
        let room = self.intern_room(&user.room);
        *self.per_player.entry(user.player.clone()).or_default() += 1;
        *self.per_ip.entry(ip).or_default() += 1;
        *self.per_instance.entry(user.instance.clone()).or_default() += 1;
        let a = Allocation {
            client: from,
            port,
            room,
            user,
            username,
            key,
            expires: now + Duration::from_secs(lifetime_s.into()),
            lifetime_s,
            permission_expires: None,
            channels: Vec::new(),
            bucket: Bucket::full(self.cfg.burst_bytes, now),
            allocate_tx: msg.tx,
        };
        let i = match self.free.pop() {
            Some(i) => {
                self.allocs[i as usize] = Some(a);
                i
            }
            None => {
                self.allocs.push(Some(a));
                (self.allocs.len() - 1) as u32
            }
        };
        self.by_client.insert(from, i);
        self.by_port[slot] = i;
        self.allocate_success(from, msg, port, lifetime_s, &key, out);
        Ok(())
    }

    fn allocate_success(
        &self,
        from: SocketAddr,
        msg: &Message,
        port: u16,
        lifetime_s: u32,
        key: &[u8; 16],
        out: &mut Output,
    ) {
        let start = out.start();
        Writer::new(&mut out.buf, method::ALLOCATE, Class::Success, msg.tx)
            .xor_address(
                attr::XOR_RELAYED_ADDRESS,
                SocketAddr::new(self.cfg.public_ip, port),
            )
            .xor_address(attr::XOR_MAPPED_ADDRESS, from)
            .u32(attr::LIFETIME, lifetime_s)
            .integrity(key)
            .fingerprint();
        out.push(from, start);
    }

    /// The next free port after the last one given, so a port just freed isn't reused at once.
    fn free_port(&mut self) -> Option<usize> {
        let n = self.by_port.len();
        for k in 0..n {
            let slot = (self.next_port + k) % n;
            if self.by_port[slot] == NONE {
                self.next_port = (slot + 1) % n;
                return Some(slot);
            }
        }
        None
    }

    fn intern_room(&mut self, room: &str) -> u32 {
        if let Some((id, refs)) = self.rooms.get_mut(room) {
            *refs += 1;
            return *id;
        }
        let id = self.next_room;
        self.next_room = self.next_room.wrapping_add(1);
        self.rooms.insert(room.to_owned(), (id, 1));
        id
    }

    fn delete(&mut self, i: u32) {
        let Some(a) = self.allocs[i as usize].take() else {
            return;
        };
        self.free.push(i);
        self.by_client.remove(&a.client);
        self.by_port[(a.port - self.cfg.min_port) as usize] = NONE;
        if let Some((_, refs)) = self.rooms.get_mut(&a.user.room) {
            *refs -= 1;
            if *refs == 0 {
                self.rooms.remove(&a.user.room);
            }
        }
        fn release<K: std::hash::Hash + Eq>(m: &mut HashMap<K, u32>, k: &K) {
            if let Some(n) = m.get_mut(k) {
                *n -= 1;
                if *n == 0 {
                    m.remove(k);
                }
            }
        }
        release(&mut self.per_player, &a.user.player);
        release(&mut self.per_ip, &a.client.ip());
        release(&mut self.per_instance, &a.user.instance);
    }

    /// The allocation this request is for, after authenticating it; remembers a fresher username.
    fn authenticated_alloc(
        &mut self,
        now: Instant,
        from: SocketAddr,
        msg: &Message,
    ) -> Result<(u32, [u8; 16]), Refusal> {
        let (_, username, key) = self.authenticate(now, from, msg)?;
        let Some(i) = self.live_alloc(from, now) else {
            return Err(Refusal {
                code: 437,
                reason: "Allocation Mismatch",
                key: Some(key),
            });
        };
        let a = self.alloc_mut(i);
        if a.username != username {
            a.username = username;
            a.key = key;
        }
        Ok((i, key))
    }

    fn success(
        &self,
        from: SocketAddr,
        msg: &Message,
        key: &[u8; 16],
        lifetime: Option<u32>,
        out: &mut Output,
    ) {
        let start = out.start();
        let mut w = Writer::new(&mut out.buf, msg.method, Class::Success, msg.tx);
        if let Some(l) = lifetime {
            w.u32(attr::LIFETIME, l);
        }
        w.integrity(key).fingerprint();
        out.push(from, start);
    }

    fn refresh(
        &mut self,
        now: Instant,
        from: SocketAddr,
        msg: &Message,
        out: &mut Output,
    ) -> Result<(), Refusal> {
        let (i, key) = self.authenticated_alloc(now, from, msg)?;
        if msg.u32_attr(attr::LIFETIME) == Some(0) {
            self.delete(i);
            self.success(from, msg, &key, Some(0), out);
            return Ok(());
        }
        let lifetime_s = self.lifetime(msg);
        let a = self.alloc_mut(i);
        a.lifetime_s = lifetime_s;
        a.expires = now + Duration::from_secs(lifetime_s.into());
        self.success(from, msg, &key, Some(lifetime_s), out);
        Ok(())
    }

    /// Only this relay's own address: both players of a pair allocate here.
    fn peer_allowed(&mut self, peer: SocketAddr) -> bool {
        let ok = peer.ip().to_canonical() == self.cfg.public_ip;
        if ok {
            self.stats.permissions_allowed += 1;
        } else {
            self.stats.permissions_denied += 1;
        }
        ok
    }

    fn create_permission(
        &mut self,
        now: Instant,
        from: SocketAddr,
        msg: &Message,
        out: &mut Output,
    ) -> Result<(), Refusal> {
        let (i, key) = self.authenticated_alloc(now, from, msg)?;
        let mut peers = 0;
        for a in msg
            .attrs()
            .take_while(|a| a.kind != attr::MESSAGE_INTEGRITY)
        {
            if a.kind != attr::XOR_PEER_ADDRESS {
                continue;
            }
            let Some(peer) = stun::decode_xor_address(a.value, &msg.tx) else {
                return Err(Refusal {
                    code: 400,
                    reason: "Bad Request",
                    key: Some(key),
                });
            };
            if !self.peer_allowed(peer) {
                return Err(Refusal {
                    code: 403,
                    reason: "Forbidden",
                    key: Some(key),
                });
            }
            peers += 1;
        }
        if peers == 0 {
            return Err(Refusal {
                code: 400,
                reason: "Bad Request",
                key: Some(key),
            });
        }
        let lifetime = self.cfg.permission_lifetime;
        self.alloc_mut(i).permission_expires = Some(now + lifetime);
        self.success(from, msg, &key, None, out);
        Ok(())
    }

    fn channel_bind(
        &mut self,
        now: Instant,
        from: SocketAddr,
        msg: &Message,
        out: &mut Output,
    ) -> Result<(), Refusal> {
        let (i, key) = self.authenticated_alloc(now, from, msg)?;
        let bad = Refusal {
            code: 400,
            reason: "Bad Request",
            key: Some(key),
        };
        let number = match msg.get(attr::CHANNEL_NUMBER) {
            Some(v) if v.len() == 4 => u16::from_be_bytes([v[0], v[1]]),
            _ => return Err(bad),
        };
        if !(0x4000..=0x7FFF).contains(&number) {
            return Err(bad);
        }
        let Some(peer) = msg.xor_address(attr::XOR_PEER_ADDRESS) else {
            return Err(bad);
        };
        if !self.peer_allowed(peer) {
            return Err(Refusal {
                code: 403,
                reason: "Forbidden",
                key: Some(key),
            });
        }
        let (channel_life, permission_life) =
            (self.cfg.channel_lifetime, self.cfg.permission_lifetime);
        let a = self.alloc_mut(i);
        // A channel names one peer and a peer one channel, for the channel's life (RFC 8656 §11).
        let clash = a
            .channels
            .iter()
            .any(|c| (c.number == number) != (c.peer_port == peer.port()));
        if clash {
            return Err(bad);
        }
        match a.channels.iter_mut().find(|c| c.number == number) {
            Some(c) => c.expires = now + channel_life,
            None => a.channels.push(Channel {
                number,
                peer_port: peer.port(),
                expires: now + channel_life,
            }),
        }
        a.permission_expires = Some(now + permission_life);
        self.success(from, msg, &key, None, out);
        Ok(())
    }

    fn send_indication(&mut self, now: Instant, from: SocketAddr, msg: &Message, out: &mut Output) {
        let Some(i) = self.live_alloc(from, now) else {
            return;
        };
        let (Some(peer), Some(data)) =
            (msg.xor_address(attr::XOR_PEER_ADDRESS), msg.get(attr::DATA))
        else {
            return;
        };
        if peer.ip().to_canonical() != self.cfg.public_ip {
            self.stats.dropped_route += 1;
            return;
        }
        self.relay(now, i, peer.port(), data, out);
    }

    fn channel_data(
        &mut self,
        now: Instant,
        from: SocketAddr,
        channel: u16,
        data: &[u8],
        out: &mut Output,
    ) {
        let Some(i) = self.live_alloc(from, now) else {
            return;
        };
        let peer_port = self
            .alloc(i)
            .channels
            .iter()
            .find(|c| c.number == channel && c.expires > now)
            .map(|c| c.peer_port);
        match peer_port {
            Some(port) => self.relay(now, i, port, data, out),
            None => self.stats.dropped_route += 1,
        }
    }

    /// From allocation `src` to whichever allocation holds `peer_port`: only within one room, at
    /// most rate_bytes a second, with a permission on both ends (the sender's to send, the
    /// receiver's to accept from this relay).
    fn relay(&mut self, now: Instant, src: u32, peer_port: u16, data: &[u8], out: &mut Output) {
        let (rate, burst) = (self.cfg.rate_bytes, self.cfg.burst_bytes);
        let (src_port, src_room, src_permission) = {
            let s = self.alloc(src);
            (s.port, s.room, s.permission_expires)
        };
        let dst = peer_port
            .checked_sub(self.cfg.min_port)
            .and_then(|slot| self.by_port.get(slot as usize))
            .copied()
            .filter(|&d| d != NONE);
        let routable = src_permission.is_some_and(|t| t > now)
            && dst.is_some_and(|d| {
                let d = self.alloc(d);
                d.room == src_room
                    && d.expires > now
                    && d.permission_expires.is_some_and(|t| t > now)
            });
        let Some(dst) = dst.filter(|_| routable) else {
            self.stats.dropped_route += 1;
            return;
        };
        if !self
            .alloc_mut(src)
            .bucket
            .spend(data.len() as f64, now, rate, burst)
        {
            self.stats.dropped_rate += 1;
            return;
        }
        let d = self.alloc(dst);
        let start = out.start();
        match d
            .channels
            .iter()
            .find(|c| c.peer_port == src_port && c.expires > now)
        {
            Some(c) => stun::write_channel_data(&mut out.buf, c.number, data),
            None => {
                Writer::new(
                    &mut out.buf,
                    method::DATA,
                    Class::Indication,
                    indication_tx(src_port, self.stats.relayed_packets),
                )
                .xor_address(
                    attr::XOR_PEER_ADDRESS,
                    SocketAddr::new(self.cfg.public_ip, src_port),
                )
                .attr(attr::DATA, data);
            }
        }
        out.push(d.client, start);
        self.stats.relayed_packets += 1;
        self.stats.relayed_bytes += data.len() as u64;
    }
}

/// A Data indication's transaction id: anything unique enough (nobody answers an indication).
fn indication_tx(port: u16, n: u64) -> [u8; 12] {
    let mut tx = [0u8; 12];
    tx[..2].copy_from_slice(&port.to_be_bytes());
    tx[4..].copy_from_slice(&n.to_be_bytes());
    tx
}
