//! Fuzzing on stable: random bytes, and valid signed requests with bytes flipped, cut or spliced,
//! from clients that hold allocations (so the deep paths run). The relay must never panic, and
//! must only ever send to the packet's sender or to a client holding an allocation.
//! `FUZZ_ITERS=5000000 cargo test --release --test fuzz` for a longer run.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use resonance_turn::auth::{long_term_key, password};
use resonance_turn::stun::{self, Class, Message, Writer, attr, method};
use resonance_turn::{Config, Output, Server};

const KEY: &str = "fiahLYMg85YkiFJQ0Xp3Bl0x3pXkUhI4nMU8jj6QRio";
const UNIX: u64 = 1_790_000_000;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn signed(
    m: u16,
    tx: [u8; 12],
    name: &str,
    nonce: &str,
    extra: impl FnOnce(&mut Writer),
) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = Writer::new(&mut buf, m, Class::Request, tx);
    extra(&mut w);
    w.attr(attr::USERNAME, name.as_bytes())
        .attr(attr::REALM, b"gamerelay")
        .attr(attr::NONCE, nonce.as_bytes())
        .integrity(&long_term_key(name, "gamerelay", &password(KEY, name)))
        .fingerprint();
    buf
}

#[test]
fn nothing_panics_and_nothing_goes_astray() {
    let iters: usize = std::env::var("FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);
    let t = Instant::now();
    let public = "192.0.2.1".parse().unwrap();
    let mut s = Server::with_clock(Config::new(KEY, public, [3; 32]), t, UNIX);
    let clients: Vec<SocketAddr> = (0..6)
        .map(|i| {
            format!("198.51.100.{}:{}", i % 3 + 1, 5000 + i)
                .parse()
                .unwrap()
        })
        .collect();
    let names: Vec<String> = (0..6)
        .map(|i| format!("{}:ins:g{}:p{i}", UNIX + 7200, i % 2))
        .collect();

    // A nonce (each client's own: they're bound to its address), then an allocation and a
    // permission for each client.
    let mut out = Output::default();
    let mut nonces = Vec::new();
    let mut relayed = Vec::new();
    for (i, (&c, name)) in clients.iter().zip(&names).enumerate() {
        out.clear();
        let mut first = Vec::new();
        Writer::new(
            &mut first,
            method::ALLOCATE,
            Class::Request,
            [0x80 + i as u8; 12],
        );
        s.handle(t, c, &first, &mut out);
        let nonce = Message::parse(out.sends().next().unwrap().1)
            .unwrap()
            .str_attr(attr::NONCE)
            .unwrap()
            .to_owned();
        out.clear();
        let req = signed(method::ALLOCATE, [i as u8 + 1; 12], name, &nonce, |w| {
            w.attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
        });
        s.handle(t, c, &req, &mut out);
        let m = Message::parse(out.sends().next().unwrap().1).unwrap();
        relayed.push(m.xor_address(attr::XOR_RELAYED_ADDRESS).expect("allocated"));
        nonces.push(nonce);
    }
    let known: HashSet<SocketAddr> = clients.iter().copied().collect();

    // The seed corpus: every kind of valid packet a client sends.
    let mut corpus: Vec<(usize, Vec<u8>)> = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let nonce = &nonces[i];
        let peer = relayed[(i + 2) % relayed.len()];
        let tx = [0x40 + i as u8; 12];
        corpus.push((
            i,
            signed(method::CREATE_PERMISSION, tx, name, nonce, |w| {
                w.xor_address(attr::XOR_PEER_ADDRESS, peer);
            }),
        ));
        corpus.push((
            i,
            signed(method::CHANNEL_BIND, tx, name, nonce, |w| {
                w.attr(attr::CHANNEL_NUMBER, &[0x40, i as u8, 0, 0])
                    .xor_address(attr::XOR_PEER_ADDRESS, peer);
            }),
        ));
        corpus.push((
            i,
            signed(method::REFRESH, tx, name, nonce, |w| {
                w.u32(attr::LIFETIME, 600);
            }),
        ));
        let mut send = Vec::new();
        Writer::new(&mut send, method::SEND, Class::Indication, tx)
            .xor_address(attr::XOR_PEER_ADDRESS, peer)
            .attr(attr::DATA, b"payload");
        corpus.push((i, send));
        let mut cd = Vec::new();
        stun::write_channel_data(&mut cd, 0x4000 + i as u16, b"channel payload");
        corpus.push((i, cd));
        let mut binding = Vec::new();
        Writer::new(&mut binding, method::BINDING, Class::Request, tx);
        corpus.push((i, binding));
    }
    for (i, p) in &corpus {
        out.clear();
        s.handle(t, clients[*i], p, &mut out);
    }

    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut now = t;
    for n in 0..iters {
        let (who, mut p) = match rng.below(4) {
            0 => {
                let len = rng.below(200);
                (
                    rng.below(clients.len()),
                    (0..len).map(|_| rng.next() as u8).collect(),
                )
            }
            _ => {
                let (i, base) = &corpus[rng.below(corpus.len())];
                (*i, base.clone())
            }
        };
        for _ in 0..=rng.below(4) {
            if p.is_empty() {
                break;
            }
            match rng.below(4) {
                0 => {
                    let at = rng.below(p.len());
                    p[at] ^= 1 << rng.below(8);
                }
                1 => p.truncate(rng.below(p.len())),
                2 => {
                    let at = rng.below(p.len());
                    p[at] = rng.next() as u8;
                }
                _ => {
                    let (_, other) = &corpus[rng.below(corpus.len())];
                    let cut = rng.below(p.len());
                    p.truncate(cut);
                    p.extend_from_slice(&other[rng.below(other.len())..]);
                }
            }
        }
        // Mostly from a known client, sometimes from a stranger.
        let from = if rng.below(8) == 0 {
            format!("203.0.113.{}:{}", rng.below(255), rng.below(65535))
                .parse()
                .unwrap()
        } else {
            clients[who]
        };
        if n % 1000 == 0 {
            now += Duration::from_millis(250);
            s.tick(now);
        }
        out.clear();
        s.handle(now, from, &p, &mut out);
        for (to, _) in out.sends() {
            let to = to.addr;
            assert!(
                to == from || known.contains(&to),
                "sent to {to} (from {from})"
            );
        }
    }
    // It reached the deep paths, not only the parser.
    let st = s.stats();
    assert!(
        st.relayed_packets > 1000 && st.permissions_allowed > 100,
        "{st:?}"
    );
}
