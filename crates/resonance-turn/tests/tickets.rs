//! Tickets through the core: any trusted issuer's credential relays, scoped to its issuer's rooms.

mod common;

use std::net::SocketAddr;
use std::time::Instant;

use common::*;
use ed25519_dalek::SigningKey;
use resonance_turn::Server;
use resonance_turn::stun::{Class, Message, attr, method};
use resonance_turn::ticket::{self, Issuer, Minted};

const SEED: [u8; 32] = [7; 32];

fn issuer(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

fn trusted(keys: &[&SigningKey]) -> Vec<Issuer> {
    keys.iter()
        .map(|k| Issuer::new(&k.verifying_key().to_bytes()).unwrap())
        .collect()
}

/// A server that accepts issuer 1's tickets.
fn ticket_server(t: Instant) -> Server {
    server_with(t, |c| {
        c.seal = Some(ticket::seal_secret(&SEED));
        c.issuers = trusted(&[&issuer(1)]);
    })
}

fn mint(by: &SigningKey, expiry: u64, room: &str, player: &str) -> Minted {
    static EPH: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);
    let eph = [EPH.fetch_add(1, std::sync::atomic::Ordering::Relaxed); 32];
    ticket::mint(by, eph, expiry, "ins", room, player)
}

fn password(m: &Minted) -> String {
    m.password(&ticket::seal_public(&ticket::seal_secret(&SEED)))
}

fn allocate(c: &mut Client, s: &mut Server, t: Instant, m: &Minted) -> u16 {
    c.request_as(
        s,
        t,
        method::ALLOCATE,
        &m.username,
        &password(m),
        &[transport()],
        None,
    )
    .code()
}

fn relayed(c: &mut Client, s: &mut Server, t: Instant, m: &Minted) -> SocketAddr {
    let r = c.request_as(
        s,
        t,
        method::ALLOCATE,
        &m.username,
        &password(m),
        &[transport()],
        None,
    );
    assert_eq!(r.code(), 0);
    r.msg().xor_address(attr::XOR_RELAYED_ADDRESS).unwrap()
}

#[test]
fn a_trusted_issuers_ticket_allocates_refreshes_and_relays() {
    let t = Instant::now();
    let mut s = ticket_server(t);
    let (ma, mb) = (
        mint(&issuer(1), UNIX + 3600, "g1", "p_a"),
        mint(&issuer(1), UNIX + 3600, "g1", "p_b"),
    );
    let (mut a, mut b) = (
        Client::new("198.51.100.1:5000"),
        Client::new("198.51.100.2:5000"),
    );
    let (ra, rb) = (
        relayed(&mut a, &mut s, t, &ma),
        relayed(&mut b, &mut s, t, &mb),
    );
    for (c, m, peer) in [(&mut a, &ma, rb), (&mut b, &mb, ra)] {
        let r = c.request_as(
            &mut s,
            t,
            method::CREATE_PERMISSION,
            &m.username,
            &password(m),
            &[],
            Some(peer),
        );
        assert_eq!(r.code(), 0);
        let r = c.request_as(
            &mut s,
            t,
            method::REFRESH,
            &m.username,
            &password(m),
            &[lifetime(600)],
            None,
        );
        assert_eq!(r.code(), 0);
    }
    let got = a.send_indication(&mut s, t, rb, b"hello");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, b.from);
    let m = Message::parse(&got[0].1).unwrap();
    assert_eq!((m.method, m.class), (method::DATA, Class::Indication));
    assert_eq!(m.get(attr::DATA), Some(&b"hello"[..]));
}

#[test]
fn untrusted_tampered_or_wrongly_keyed_tickets_get_401() {
    let t = Instant::now();
    let mut s = ticket_server(t);
    let mut c = Client::new("198.51.100.1:5000");
    let stranger = mint(&issuer(2), UNIX + 3600, "g1", "p_a");
    assert_eq!(
        allocate(&mut c, &mut s, t, &stranger),
        401,
        "an issuer it doesn't trust"
    );
    let m = mint(&issuer(1), UNIX + 3600, "g1", "p_a");
    let tampered = m.username.replacen(":g1:", ":g2:", 1);
    let r = c.request_as(
        &mut s,
        t,
        method::ALLOCATE,
        &tampered,
        &password(&m),
        &[transport()],
        None,
    );
    assert_eq!(r.code(), 401, "another room than was signed");
    let other_node = m.password(&ticket::seal_public(&ticket::seal_secret(&[8; 32])));
    let r = c.request_as(
        &mut s,
        t,
        method::ALLOCATE,
        &m.username,
        &other_node,
        &[transport()],
        None,
    );
    assert_eq!(r.code(), 401, "another node's password");
    assert_eq!(allocate(&mut c, &mut s, t, &m), 0, "and the right one");
}

#[test]
fn a_ticket_is_refused_past_its_expiry_and_beyond_a_day() {
    let t = Instant::now();
    let mut s = ticket_server(t);
    let mut c = Client::new("198.51.100.1:5000");
    assert_eq!(
        allocate(&mut c, &mut s, t, &mint(&issuer(1), UNIX, "g1", "p_a")),
        401
    );
    let long = mint(&issuer(1), UNIX + ticket::MAX_LIFETIME_S + 1, "g1", "p_a");
    assert_eq!(allocate(&mut c, &mut s, t, &long), 401, "longer than a day");
    let day = mint(&issuer(1), UNIX + ticket::MAX_LIFETIME_S, "g1", "p_a");
    assert_eq!(allocate(&mut c, &mut s, t, &day), 0);
}

#[test]
fn a_node_without_a_sealing_key_takes_no_tickets() {
    let t = Instant::now();
    let mut s = server_with(t, |c| c.issuers = trusted(&[&issuer(1)]));
    let mut c = Client::new("198.51.100.1:5000");
    assert_eq!(
        allocate(
            &mut c,
            &mut s,
            t,
            &mint(&issuer(1), UNIX + 3600, "g1", "p_a")
        ),
        401
    );
    // The control plane's own credentials still work.
    c.allocate(&mut s, t, &user("g1", "p_a"));
}

#[test]
fn another_issuers_same_named_room_is_another_room() {
    let t = Instant::now();
    let mut s = server_with(t, |c| {
        c.seal = Some(ticket::seal_secret(&SEED));
        c.issuers = trusted(&[&issuer(1), &issuer(2)]);
    });
    let mine = mint(&issuer(1), UNIX + 3600, "g1", "p_a");
    let theirs = mint(&issuer(2), UNIX + 3600, "g1", "p_b");
    let (mut a, mut b) = (
        Client::new("198.51.100.1:5000"),
        Client::new("198.51.100.2:5000"),
    );
    let (ra, rb) = (
        relayed(&mut a, &mut s, t, &mine),
        relayed(&mut b, &mut s, t, &theirs),
    );
    let r = b.request_as(
        &mut s,
        t,
        method::CREATE_PERMISSION,
        &theirs.username,
        &password(&theirs),
        &[],
        Some(ra),
    );
    assert_eq!(r.code(), 0, "a permission names only the relay's IP");
    let r = a.request_as(
        &mut s,
        t,
        method::CREATE_PERMISSION,
        &mine.username,
        &password(&mine),
        &[],
        Some(rb),
    );
    assert_eq!(r.code(), 0);
    assert!(
        b.send_indication(&mut s, t, ra, b"hi").is_empty(),
        "nothing crosses issuers"
    );
    // And a ticket can't take over another issuer's allocation on the same 5-tuple.
    let r = a.request_as(
        &mut s,
        t,
        method::REFRESH,
        &theirs.username,
        &password(&theirs),
        &[lifetime(600)],
        None,
    );
    assert_eq!(r.code(), 441);
}

#[test]
fn an_issuer_no_longer_trusted_ends_its_allocations_at_the_next_request() {
    let t = Instant::now();
    let mut s = ticket_server(t);
    let mut c = Client::new("198.51.100.1:5000");
    let m = mint(&issuer(1), UNIX + 3600, "g1", "p_a");
    assert_eq!(allocate(&mut c, &mut s, t, &m), 0);
    s.set_issuers(trusted(&[&issuer(2)]));
    let r = c.request_as(
        &mut s,
        t,
        method::REFRESH,
        &m.username,
        &password(&m),
        &[lifetime(600)],
        None,
    );
    assert_eq!(r.code(), 401);
}

#[test]
fn a_node_without_its_key_yet_takes_tickets_and_nothing_signed_with_an_empty_key() {
    let t = Instant::now();
    let mut s = Server::with_clock(
        {
            let mut c = resonance_turn::Config::new("", public(), [7; 32]);
            c.seal = Some(ticket::seal_secret(&SEED));
            c.issuers = trusted(&[&issuer(1)]);
            c
        },
        t,
        UNIX,
    );
    let mut c = Client::new("198.51.100.1:5000");
    let name = user("g1", "p_a");
    let forged = resonance_turn::auth::password("", &name);
    let r = c.request_as(
        &mut s,
        t,
        method::ALLOCATE,
        &name,
        &forged,
        &[transport()],
        None,
    );
    assert_eq!(r.code(), 401, "an empty key signs nothing");
    let mut d = Client::new("198.51.100.2:5000");
    assert_eq!(
        allocate(
            &mut d,
            &mut s,
            t,
            &mint(&issuer(1), UNIX + 3600, "g1", "p_b")
        ),
        0
    );
    // Its key arrives: the control plane's credentials work, and the empty one isn't kept as
    // the previous key.
    s.set_node_key(KEY.into(), t, std::time::Duration::from_secs(3600));
    let r = c.request_as(
        &mut s,
        t,
        method::ALLOCATE,
        &name,
        &forged,
        &[transport()],
        None,
    );
    assert_eq!(r.code(), 401);
    c.allocate(&mut s, t, &name);
}
