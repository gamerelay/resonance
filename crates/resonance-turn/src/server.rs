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
use crate::budget::Budget;
use crate::counts::Counts;
use crate::limiter::{Bucket, Reflection};
use crate::stun::{self, Class, Message, Writer, attr, method};
use crate::ticket::{self, Issuer};

pub struct Config {
    pub realm: String,
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
    /// One issuer: it names its own instances, so only this bounds what it can take. Half the
    /// relay ports by default, so no issuer can fill a node on its own.
    pub max_per_issuer: u32,
    /// Ticket checks a second from all clients together, on top of each IP's budget: each is a
    /// signature and a key agreement (~40 µs), so this keeps them to a fifth of the loop's time.
    pub ticket_check_rate: f64,
    /// Per allocation: a player's copies to one peer (a game sends a few KB a second).
    pub rate_bytes: f64,
    pub burst_bytes: f64,
    pub unauth_rate: f64,
    pub unauth_burst: f64,
    pub unauth_tracked: usize,
    /// Unsigned answers to a 5-tuple holding an allocation, per allocation: its source can be
    /// spoofed like any other's. Enough for a client's own (a Binding now and then, a 438 on a
    /// Refresh and its retransmissions); answers to requests that proved credentials don't count.
    pub alloc_unauth_rate: f64,
    pub alloc_unauth_burst: f64,
    pub default_lifetime_s: u32,
    pub max_lifetime_s: u32,
    pub permission_lifetime: Duration,
    pub channel_lifetime: Duration,
    /// Channels one allocation may have at once: one per peer it talks to, so a room's worth.
    /// Each is a few bytes, but without a cap one allocation could bind all 16,384.
    pub max_channels: usize,
    /// Bytes clients may make the node hold, all together (`budget`): allocations, the checked
    /// tickets kept, and the node's streams. Past it, a charge is refused, never allocated.
    pub memory_total: usize,
    /// Of `memory_total`, what one client IP may hold. The default fits everything one IP's caps
    /// allow (64 allocations, 64 streams with full queues and a message half read each), so a
    /// busy NAT within its caps is never refused for memory; the total is what binds when many
    /// IPs press at once.
    pub memory_per_ip: usize,
    /// How long past its lifetime an allocation is kept: a refresh that's late by a lost packet
    /// or two (Firefox refreshes only 10 s before the end) still finds it.
    pub grace: Duration,
    /// Makes nonces; any random bytes, new at each start.
    pub nonce_key: [u8; 32],
    /// This node's sealing secret (`ticket::seal_secret`): tickets are accepted only with one.
    pub seal: Option<[u8; 32]>,
    /// Whose tickets are accepted (`Server::set_issuers` changes them).
    pub issuers: Vec<Issuer>,
}

impl Config {
    /// The Go relay's limits (gamerelay.io deploy/turn/main.go, before f9e9334).
    pub fn new(public_ip: IpAddr, nonce_key: [u8; 32]) -> Self {
        let max_per_ip = 64;
        Config {
            realm: "gamerelay".into(),
            public_ip: public_ip.to_canonical(),
            min_port: 49152,
            max_port: 65535,
            max_per_player: 8,
            max_per_ip,
            max_per_instance: 4096,
            max_per_issuer: 8192,
            ticket_check_rate: 5000.0,
            rate_bytes: 128.0 * 1024.0,
            burst_bytes: 256.0 * 1024.0,
            unauth_rate: 20.0,
            unauth_burst: max_per_ip as f64,
            unauth_tracked: 65536,
            alloc_unauth_rate: 5.0,
            alloc_unauth_burst: 8.0,
            default_lifetime_s: 600,
            max_lifetime_s: 3600,
            permission_lifetime: Duration::from_secs(300),
            channel_lifetime: Duration::from_secs(600),
            max_channels: 16,
            memory_total: 96 * 1024 * 1024,
            memory_per_ip: 16 * 1024 * 1024,
            grace: Duration::from_secs(60),
            nonce_key,
            seal: None,
            issuers: Vec::new(),
        }
    }
}

/// Who a packet is from or for: an address, and the connection it came on. `conn` 0 is the UDP
/// socket; each TCP or TLS connection has its own number, so it is its own 5-tuple (RFC 8656
/// §2.2) even at an ip:port a UDP client also uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Client {
    pub addr: SocketAddr,
    pub conn: u32,
}

impl Client {
    pub const UDP: u32 = 0;

    pub fn udp(addr: SocketAddr) -> Self {
        Client {
            addr,
            conn: Self::UDP,
        }
    }
}

/// What to send, in one reused buffer.
#[derive(Default)]
pub struct Output {
    buf: Vec<u8>,
    sends: Vec<(Client, usize, usize)>,
}

impl Output {
    pub fn clear(&mut self) {
        self.buf.clear();
        self.sends.clear();
    }

    /// Each send's client (its address and connection) and bytes.
    pub fn sends(&self) -> impl Iterator<Item = (Client, &[u8])> {
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

    fn push(&mut self, to: Client, start: usize) {
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
    client: Client,
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
    /// Made with room for `max_channels`, so it never grows.
    channels: Vec<Channel>,
    bucket: Bucket,
    /// Its unsigned answers (`alloc_unauth_rate`).
    unsigned: Bucket,
    /// What it's charged in the budget, to its client's IP (`footprint`).
    charged: usize,
    /// Its Allocate's transaction, so a retransmission gets the same answer, not a 437.
    allocate_tx: [u8; 12],
}

const NONE: u32 = u32::MAX;

/// What one map entry costs besides its key and value: the hash table's control byte and spare
/// room, rounded up.
const MAP_ENTRY: usize = 32;

/// What an allocation holds: itself, its strings, its channels' room, and its share of the maps
/// keyed on it (by client, by port, its room, and the counts per player, IP, game and issuer,
/// which copy its strings).
fn footprint(username: &str, user: &User, channels: usize) -> usize {
    let strings = user.instance.len() + user.room.len() + user.player.len();
    std::mem::size_of::<Allocation>()
        + username.len()
        + 2 * strings
        + channels * std::mem::size_of::<Channel>()
        + 7 * MAP_ENTRY
}

/// A checked ticket kept: its key, who it's charged to and how much, and when it ends.
struct Kept {
    key: [u8; 16],
    ip: IpAddr,
    cost: usize,
    expiry: u64,
}

/// What a checked ticket kept costs: its username, the entry, and its share of the map.
fn ticket_footprint(username: &str) -> usize {
    username.len() + std::mem::size_of::<Kept>() + MAP_ENTRY
}

/// A ticket's instance is `<kid>/<instance>` (`Ticket::user`): its issuer is the part before.
fn issuer_of(user: &User) -> &str {
    user.instance.split_once('/').map_or("", |(kid, _)| kid)
}
/// Checked tickets remembered (`Server::tickets`): about a player each.
const TICKETS_KEPT: usize = 8192;

pub struct Server {
    cfg: Config,
    nonces: Nonces,
    limiter: Reflection,
    /// Ticket checks (a signature and a key agreement, ~40 µs) per IP, on every transport: a
    /// client reusing one nonce can't make the loop do them faster than this.
    ticket_checks: Reflection,
    /// And from everyone together (`ticket_check_rate`), so many IPs can't fill the loop either.
    all_ticket_checks: Bucket,
    /// Tickets already checked, username to key: a player's allocations share one ticket, and
    /// a replayed ticket costs a hash, not a check. Emptied when full. Each is charged to the IP
    /// that presented it (and its charge kept with it); with no room, it's checked, not kept.
    tickets: HashMap<String, Kept>,
    /// What clients make the node hold (`budget`), charged here and by the node's streams.
    memory: Budget,
    allocs: Vec<Option<Allocation>>,
    free: Vec<u32>,
    by_client: HashMap<Client, u32>,
    /// Relay port − min_port → allocation.
    by_port: Vec<u32>,
    next_port: usize,
    rooms: HashMap<String, (u32, u32)>,
    next_room: u32,
    per_player: Counts<String>,
    per_ip: Counts<IpAddr>,
    per_instance: Counts<String>,
    /// By issuer (its kid).
    per_issuer: Counts<String>,
    stats: Stats,
    clock: (Instant, u64),
    /// False while draining: no new allocations, existing ones carry on.
    accepting: bool,
}

/// Why a request was refused, whether the answer can carry MESSAGE-INTEGRITY, and whether the
/// request proved its credentials (an answer to one isn't budgeted).
struct Refusal {
    code: u16,
    key: Option<[u8; 16]>,
    proved: bool,
}

impl Refusal {
    /// To a client that hasn't proved its credentials.
    fn unsigned(code: u16) -> Self {
        Refusal {
            code,
            key: None,
            proved: false,
        }
    }

    /// Signed with the key it proved.
    fn signed(code: u16, key: [u8; 16]) -> Self {
        Refusal {
            code,
            key: Some(key),
            proved: true,
        }
    }
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
            ticket_checks: Reflection::new(cfg.unauth_rate, cfg.unauth_burst, cfg.unauth_tracked),
            all_ticket_checks: Bucket::full(cfg.ticket_check_rate, base),
            tickets: HashMap::new(),
            memory: Budget::new(cfg.memory_total, cfg.memory_per_ip),
            allocs: Vec::new(),
            free: Vec::new(),
            by_client: HashMap::new(),
            by_port: vec![NONE; ports],
            next_port: 0,
            rooms: HashMap::new(),
            next_room: 0,
            per_player: Counts::default(),
            per_ip: Counts::default(),
            per_instance: Counts::default(),
            per_issuer: Counts::default(),
            stats: Stats::default(),
            clock: (base, unix),
            accepting: true,
            cfg,
        }
    }

    pub fn stats(&self) -> Stats {
        Stats {
            unauthenticated_dropped: self.stats.unauthenticated_dropped + self.limiter.dropped,
            ..self.stats.clone()
        }
    }

    /// Whose tickets are accepted from now on. An allocation made with another's is refused at
    /// its next request, so it ends within a refresh.
    pub fn set_issuers(&mut self, issuers: Vec<Issuer>) {
        self.cfg.issuers = issuers;
    }

    /// While false (draining, or told to upgrade), new allocations get 508; existing ones carry on.
    pub fn set_accepting(&mut self, accepting: bool) {
        self.accepting = accepting;
    }

    pub fn allocations(&self) -> usize {
        self.by_client.len()
    }

    /// Whether this client (a 5-tuple: its address and connection) holds an allocation that
    /// hasn't run out. The node keeps a stream open for long only while it does.
    pub fn holds_allocation(&self, client: Client, now: Instant) -> bool {
        self.by_client
            .get(&canonical(client))
            .is_some_and(|&i| self.alloc(i).expires > now)
    }

    /// What clients make the node hold. The node charges its streams to it too.
    pub fn memory(&self) -> &Budget {
        &self.memory
    }

    pub fn memory_mut(&mut self) -> &mut Budget {
        &mut self.memory
    }

    /// A TCP or TLS connection closed: its allocation ends with it (RFC 8656 §2.2).
    pub fn closed(&mut self, client: Client) {
        if let Some(&i) = self.by_client.get(&canonical(client)) {
            self.delete(i);
        }
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
        // A ticket past its expiry is no use: what it was charged goes back.
        let unix = self.unix(now);
        let memory = &mut self.memory;
        self.tickets.retain(|_, t| {
            let keep = t.expiry > unix;
            if !keep {
                memory.refund(t.ip, t.cost);
            }
            keep
        });
        for a in self.allocs.iter_mut().flatten() {
            a.channels.retain(|c| c.expires > now);
            if a.permission_expires.is_some_and(|t| t <= now) {
                a.permission_expires = None;
            }
        }
    }

    /// One datagram on the UDP socket. What to send goes into `out` (not cleared first).
    pub fn handle(&mut self, now: Instant, from: SocketAddr, packet: &[u8], out: &mut Output) {
        self.handle_from(now, Client::udp(from), packet, out);
    }

    /// One message from a client on any connection (a TCP or TLS stream's, already framed).
    pub fn handle_from(&mut self, now: Instant, from: Client, packet: &[u8], out: &mut Output) {
        let from = canonical(from);
        if stun::is_channel_data(packet) {
            if let Some((channel, data)) = stun::parse_channel_data(packet) {
                self.channel_data(now, from, channel, data, out);
            }
            return;
        }
        let Some(msg) = Message::parse(packet) else {
            return;
        };
        // A Binding answer goes to whatever source the request claims, so an unknown source's are
        // budgeted (refusals are budgeted in `refuse`).
        if msg.class == Class::Request && msg.method == method::BINDING && !self.budget(from, now) {
            return;
        }
        match (msg.class, msg.method) {
            (Class::Indication, method::SEND) => self.send_indication(now, from, &msg, out),
            (Class::Request, m) => {
                if msg.unknown_required().next().is_some() {
                    if msg.method != method::BINDING && !self.budget(from, now) {
                        return;
                    }
                    // Every one of them, up to 16 (a request that big is junk anyway).
                    let mut unknown = [0u8; 32];
                    let mut n = 0;
                    for kind in msg.unknown_required().take(16) {
                        unknown[n..n + 2].copy_from_slice(&kind.to_be_bytes());
                        n += 2;
                    }
                    let start = out.start();
                    let mut w = Writer::new(&mut out.buf, m, Class::Error, msg.tx);
                    w.error(420, stun::reason(420))
                        .attr(attr::UNKNOWN_ATTRIBUTES, &unknown[..n]);
                    w.fingerprint();
                    out.push(from, start);
                    return;
                }
                let result = match m {
                    method::BINDING => {
                        let start = out.start();
                        Writer::new(&mut out.buf, m, Class::Success, msg.tx)
                            .xor_address(attr::XOR_MAPPED_ADDRESS, from.addr)
                            .fingerprint();
                        out.push(from, start);
                        Ok(())
                    }
                    method::ALLOCATE => self.allocate(now, from, &msg, out),
                    method::REFRESH => self.refresh(now, from, &msg, out),
                    method::CREATE_PERMISSION => self.create_permission(now, from, &msg, out),
                    method::CHANNEL_BIND => self.channel_bind(now, from, &msg, out),
                    _ => Err(Refusal::unsigned(400)),
                };
                if let Err(r) = result {
                    self.refuse(now, from, &msg, r, out);
                }
            }
            _ => {}
        }
    }

    /// May this source get an unsigned answer? Every such answer (a Binding response, a 401, a
    /// 438, a 400) goes to whatever source the request claims, a few times its size, so a
    /// spoofed source could aim this relay at someone: 20 a second per IP (burst 64, a shared
    /// address filling its allocation cap at once). A 5-tuple holding an allocation can be
    /// spoofed too, so it has a smaller budget of its own (`alloc_unauth_rate`) instead of its
    /// IP's. A stream's source can't be spoofed (its handshake answered it), so it can't aim
    /// anything at anyone: it isn't budgeted, and doesn't spend a UDP client's budget at its IP.
    fn budget(&mut self, from: Client, now: Instant) -> bool {
        if from.conn != Client::UDP {
            return true;
        }
        let Some(i) = self.live_alloc(from, now) else {
            return self.limiter.allow(from.addr.ip(), now);
        };
        let (rate, burst) = (self.cfg.alloc_unauth_rate, self.cfg.alloc_unauth_burst);
        let ok = self.alloc_mut(i).unsigned.spend(1.0, now, rate, burst);
        if !ok {
            self.stats.unauthenticated_dropped += 1;
        }
        ok
    }

    fn refuse(&mut self, now: Instant, from: Client, msg: &Message, r: Refusal, out: &mut Output) {
        // A signed refusal went to a client that proved its credentials.
        if !r.proved && !self.budget(from, now) {
            return;
        }
        let start = out.start();
        let mut w = Writer::new(&mut out.buf, msg.method, Class::Error, msg.tx);
        w.error(r.code, stun::reason(r.code));
        if matches!(r.code, 401 | 438) {
            let nonce = self.nonces.issue(self.unix(now), from.addr);
            w.attr(attr::REALM, self.cfg.realm.as_bytes())
                .attr(attr::NONCE, nonce.as_bytes());
        }
        if let Some(key) = r.key {
            w.integrity(&key);
        }
        w.fingerprint();
        out.push(from, start);
    }

    fn live_alloc(&mut self, from: Client, now: Instant) -> Option<u32> {
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
        from: Client,
        msg: &Message,
    ) -> Result<(User, String, [u8; 16]), Refusal> {
        // No MESSAGE-INTEGRITY: the first request of every client, answered with a nonce.
        // MESSAGE-INTEGRITY without the rest is malformed (RFC 8489 §9.2.4).
        if !msg.has(attr::MESSAGE_INTEGRITY) {
            return Err(Refusal::unsigned(401));
        }
        let (Some(username), Some(realm), Some(nonce)) = (
            msg.str_attr(attr::USERNAME),
            msg.str_attr(attr::REALM),
            msg.str_attr(attr::NONCE),
        ) else {
            return Err(Refusal::unsigned(400));
        };
        // USERNAME is under 513 bytes (RFC 8489 §14.3): nothing longer is hashed.
        if username.len() > 512 {
            return Err(Refusal::unsigned(400));
        }
        if realm != self.cfg.realm {
            return Err(Refusal::unsigned(401));
        }
        // Stale, from before a restart, or another client's: 438 with a fresh one, which every
        // browser retries (a 401 on a Refresh would end the allocation in Chrome).
        if self.nonces.check(nonce, self.unix(now), from.addr) != NonceCheck::Ok {
            // Unsigned, but not budgeted when the request checks out against the key this 5-tuple
            // allocated with: only its client (or a replay of its own request) can send that, and
            // the answer goes back to it. Spoofed requests from its address can spend its budget,
            // and its own Refresh must still get through when its nonce goes stale.
            let proved = self
                .live_alloc(from, now)
                .map(|i| self.alloc(i))
                .is_some_and(|a| a.username == username && msg.integrity_ok(&a.key));
            return Err(Refusal {
                proved,
                ..Refusal::unsigned(438)
            });
        }
        // A ticket (`t1:`) from an issuer this node trusts. One it no longer trusts ends at its
        // allocations' next request, cached or not.
        let Some(t) = ticket::parse(username) else {
            return Err(Refusal::unsigned(401));
        };
        if !self.cfg.issuers.iter().any(|i| i.kid == t.kid) {
            return Err(Refusal::unsigned(401));
        }
        let user = t.user();
        // No request succeeds past the ticket's expiry, so an allocation outlives it by at most
        // one lifetime. A ticket lasts a day at most.
        let unix = self.unix(now);
        if user.expiry <= unix || user.expiry > unix + ticket::MAX_LIFETIME_S + ticket::SKEW_S {
            return Err(Refusal::unsigned(401));
        }
        let existing = self.live_alloc(from, now);
        let cached = existing
            .map(|i| self.alloc(i))
            .filter(|a| a.username == username)
            .map(|a| a.key);
        // Its issuer's signature, then the password from its key and this node's sealing
        // secret: only when nothing cached matches, so a refresh or a player's next allocation
        // costs a hash, and only within the IP's budget.
        let known = cached.or_else(|| self.tickets.get(username).map(|t| t.key));
        let key = match known {
            Some(k) => msg.integrity_ok(&k).then_some(k),
            None if self.ticket_checks.allow(from.addr.ip(), now)
                && self.all_ticket_checks.spend(
                    1.0,
                    now,
                    self.cfg.ticket_check_rate,
                    self.cfg.ticket_check_rate,
                ) =>
            {
                let k = self.cfg.seal.as_ref().and_then(|seal| {
                    t.verify(&self.cfg.issuers)
                        .then(|| t.password(seal))
                        .flatten()
                        .map(|p| auth::long_term_key(username, &self.cfg.realm, &p))
                });
                // Only a ticket that checked out, and was used with its password, is remembered.
                let k = k.filter(|k| msg.integrity_ok(k));
                if let Some(k) = k {
                    self.keep_ticket(username, k, from.addr.ip(), user.expiry);
                }
                k
            }
            None => None,
        };
        let Some(key) = key else {
            return Err(Refusal::unsigned(401));
        };
        if let Some(i) = existing {
            let a = self.alloc(i);
            if a.user.room != user.room || a.user.player != user.player {
                return Err(Refusal::signed(441, key));
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
        from: Client,
        msg: &Message,
        out: &mut Output,
    ) -> Result<(), Refusal> {
        let (user, username, key) = self.authenticate(now, from, msg)?;
        let refuse = |code| Refusal::signed(code, key);
        if let Some(i) = self.live_alloc(from, now) {
            let a = self.alloc(i);
            if a.allocate_tx != msg.tx {
                return Err(refuse(437));
            }
            let (port, lifetime) = (a.port, a.lifetime_s);
            self.allocate_success(from, msg, port, lifetime, &key, out);
            return Ok(());
        }
        if !self.accepting {
            return Err(refuse(508));
        }
        match msg.get(attr::REQUESTED_TRANSPORT) {
            Some(v) if v.len() == 4 && v[0] == 17 => {}
            Some(_) => return Err(refuse(442)),
            None => return Err(refuse(400)),
        }
        if let Some(v) = msg.get(attr::REQUESTED_ADDRESS_FAMILY) {
            let ours = if self.cfg.public_ip.is_ipv4() {
                0x01
            } else {
                0x02
            };
            if v.len() != 4 || v[0] != ours {
                return Err(refuse(440));
            }
        }
        let ip = from.addr.ip();
        let charged = footprint(&username, &user, self.cfg.max_channels);
        if self.per_player.get(&user.player) >= self.cfg.max_per_player
            || self.per_ip.get(&ip) >= self.cfg.max_per_ip
            || self.per_instance.get(&user.instance) >= self.cfg.max_per_instance
            || self.per_issuer.get(issuer_of(&user)) >= self.cfg.max_per_issuer
        {
            return Err(refuse(486));
        }
        let Some(slot) = self.free_port() else {
            return Err(refuse(508));
        };
        // No room left in its IP's share of the memory, or in everyone's: as for no free port.
        // (The slot isn't taken until it's filled below.)
        if !self.memory.charge(ip, charged) {
            return Err(refuse(508));
        }
        let port = self.cfg.min_port + slot as u16;
        let lifetime_s = self.lifetime(msg);
        let room = self.intern_room(&user.room);
        self.per_player.add(user.player.clone());
        self.per_ip.add(ip);
        self.per_instance.add(user.instance.clone());
        self.per_issuer.add(issuer_of(&user).to_owned());
        let a = Allocation {
            client: from,
            port,
            room,
            user,
            username,
            key,
            expires: now + Duration::from_secs(lifetime_s.into()) + self.cfg.grace,
            lifetime_s,
            permission_expires: None,
            channels: Vec::with_capacity(self.cfg.max_channels),
            bucket: Bucket::full(self.cfg.burst_bytes, now),
            unsigned: Bucket::full(self.cfg.alloc_unauth_burst, now),
            charged,
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
        from: Client,
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
            .xor_address(attr::XOR_MAPPED_ADDRESS, from.addr)
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
        self.per_player.release(&a.user.player);
        self.per_ip.release(&a.client.addr.ip());
        self.per_instance.release(&a.user.instance);
        self.per_issuer.release(issuer_of(&a.user));
        self.memory.refund(a.client.addr.ip(), a.charged);
    }

    /// Keeps a checked ticket, charged to `ip`, if there's room for it, until it expires.
    fn keep_ticket(&mut self, username: &str, key: [u8; 16], ip: IpAddr, expiry: u64) {
        if self.tickets.len() >= TICKETS_KEPT {
            for (_, t) in self.tickets.drain() {
                self.memory.refund(t.ip, t.cost);
            }
        }
        let cost = ticket_footprint(username);
        if self.memory.charge(ip, cost) {
            let kept = Kept {
                key,
                ip,
                cost,
                expiry,
            };
            if let Some(old) = self.tickets.insert(username.to_owned(), kept) {
                self.memory.refund(old.ip, old.cost);
            }
        }
    }

    /// Checked tickets kept, for tests.
    pub fn tickets_kept(&self) -> usize {
        self.tickets.len()
    }

    /// The allocation this request is for, after authenticating it; remembers a fresher username.
    fn authenticated_alloc(
        &mut self,
        now: Instant,
        from: Client,
        msg: &Message,
    ) -> Result<(u32, [u8; 16]), Refusal> {
        let (_, username, key) = self.authenticate(now, from, msg)?;
        let Some(i) = self.live_alloc(from, now) else {
            return Err(Refusal::signed(437, key));
        };
        let a = self.alloc(i);
        if a.username != username {
            // A fresher ticket, maybe longer: charged the difference, or refused like a new
            // allocation past the budget.
            let (ip, had) = (a.client.addr.ip(), a.charged);
            let now_charged = footprint(&username, &a.user, self.cfg.max_channels);
            if !self.memory.recharge(ip, had, now_charged) {
                return Err(Refusal::signed(508, key));
            }
            let a = self.alloc_mut(i);
            a.username = username;
            a.key = key;
            a.charged = now_charged;
        }
        Ok((i, key))
    }

    fn success(
        &self,
        from: Client,
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
        from: Client,
        msg: &Message,
        out: &mut Output,
    ) -> Result<(), Refusal> {
        let (i, key) = self.authenticated_alloc(now, from, msg)?;
        if msg.u32_attr(attr::LIFETIME) == Some(0) {
            self.delete(i);
            self.success(from, msg, &key, Some(0), out);
            return Ok(());
        }
        let (lifetime_s, grace) = (self.lifetime(msg), self.cfg.grace);
        let a = self.alloc_mut(i);
        a.lifetime_s = lifetime_s;
        a.expires = now + Duration::from_secs(lifetime_s.into()) + grace;
        self.success(from, msg, &key, Some(lifetime_s), out);
        Ok(())
    }

    /// Only this relay's own address: both players of a pair allocate here. Another address
    /// family is 443 (RFC 8656 §9.3), anything else of ours 403; both are signed, since a
    /// Firefox that can't verify the answer retransmits until the whole allocation fails.
    fn peer_refusal(&mut self, peer: SocketAddr, key: [u8; 16]) -> Option<Refusal> {
        let ip = peer.ip().to_canonical();
        if ip == self.cfg.public_ip {
            self.stats.permissions_allowed += 1;
            return None;
        }
        self.stats.permissions_denied += 1;
        let code = if ip.is_ipv4() != self.cfg.public_ip.is_ipv4() {
            443
        } else {
            403
        };
        Some(Refusal::signed(code, key))
    }

    fn create_permission(
        &mut self,
        now: Instant,
        from: Client,
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
                return Err(Refusal::signed(400, key));
            };
            if let Some(r) = self.peer_refusal(peer, key) {
                return Err(r);
            }
            peers += 1;
        }
        if peers == 0 {
            return Err(Refusal::signed(400, key));
        }
        let lifetime = self.cfg.permission_lifetime;
        self.alloc_mut(i).permission_expires = Some(now + lifetime);
        self.success(from, msg, &key, None, out);
        Ok(())
    }

    fn channel_bind(
        &mut self,
        now: Instant,
        from: Client,
        msg: &Message,
        out: &mut Output,
    ) -> Result<(), Refusal> {
        let (i, key) = self.authenticated_alloc(now, from, msg)?;
        let bad = || Refusal::signed(400, key);
        let number = match msg.get(attr::CHANNEL_NUMBER) {
            Some(v) if v.len() == 4 => u16::from_be_bytes([v[0], v[1]]),
            _ => return Err(bad()),
        };
        if !(0x4000..=0x7FFF).contains(&number) {
            return Err(bad());
        }
        let Some(peer) = msg.xor_address(attr::XOR_PEER_ADDRESS) else {
            return Err(bad());
        };
        if let Some(r) = self.peer_refusal(peer, key) {
            return Err(r);
        }
        let (channel_life, permission_life, max_channels) = (
            self.cfg.channel_lifetime,
            self.cfg.permission_lifetime,
            self.cfg.max_channels,
        );
        let a = self.alloc_mut(i);
        // A channel names one peer and a peer one channel, for the channel's life (RFC 8656 §11).
        let clash = a
            .channels
            .iter()
            .any(|c| (c.number == number) != (c.peer_port == peer.port()));
        if clash {
            return Err(bad());
        }
        let full = a.channels.len() >= max_channels;
        match a.channels.iter_mut().find(|c| c.number == number) {
            Some(c) => c.expires = now + channel_life,
            // A new one past the cap: 508, as for an allocation past its caps.
            None if full => return Err(Refusal::signed(508, key)),
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

    fn send_indication(&mut self, now: Instant, from: Client, msg: &Message, out: &mut Output) {
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
        from: Client,
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

/// An IPv4 client on a dual-stack socket arrives as ::ffff:a.b.c.d; it's the same client.
fn canonical(c: Client) -> Client {
    Client {
        addr: SocketAddr::new(c.addr.ip().to_canonical(), c.addr.port()),
        ..c
    }
}

/// A Data indication's transaction id: anything unique enough (nobody answers an indication).
fn indication_tx(port: u16, n: u64) -> [u8; 12] {
    let mut tx = [0u8; 12];
    tx[..2].copy_from_slice(&port.to_be_bytes());
    tx[4..].copy_from_slice(&n.to_be_bytes());
    tx
}
