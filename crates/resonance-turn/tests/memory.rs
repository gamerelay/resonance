//! The memory budget (TECH_DEBT C1): allocations and the tickets kept are charged to their
//! client's IP and to everyone's total, a charge that doesn't fit is refused, and what ends gives
//! back exactly what it took.

use std::net::IpAddr;
use std::time::Instant;

mod common;
use common::*;
use resonance_turn::stun::method;

fn ip(c: &Client) -> IpAddr {
    canon(c.from).ip()
}

/// What a first allocation costs its IP (its ticket kept included), and a second one for the
/// same player, whose ticket is already kept.
fn costs(t: Instant) -> (usize, usize) {
    let mut s = server(t);
    let name = user("g1", "p_a");
    let (mut a, mut b) = (Client::new("198.51.100.1:1"), Client::new("198.51.100.1:2"));
    a.allocate(&mut s, t, &name);
    let first = s.memory().of(ip(&a));
    b.allocate(&mut s, t, &name);
    let second = s.memory().of(ip(&b)) - first;
    assert!(first > second && second > 0, "{first} {second}");
    (first, second)
}

fn refused(c: &mut Client, s: &mut resonance_turn::Server, t: Instant, name: &str) -> u16 {
    c.request(s, t, method::ALLOCATE, name, &[transport()])
        .code()
}

#[test]
fn an_ip_past_its_share_of_the_memory_gets_508_and_others_dont() {
    let t = Instant::now();
    let (first, second) = costs(t);
    let mut s = server_with(t, |c| c.memory_per_ip = first + second - 1);
    let name = user("g1", "p_a");
    let mut a = Client::new("198.51.100.1:1");
    a.allocate(&mut s, t, &name);
    let mut b = Client::new("198.51.100.1:2");
    assert_eq!(
        refused(&mut b, &mut s, t, &name),
        508,
        "past its IP's share"
    );
    // Another IP has its own share.
    Client::new("203.0.113.9:1").allocate(&mut s, t, &user("g1", "p_b"));
    // The first one ending makes room again.
    assert_eq!(
        a.request(&mut s, t, method::REFRESH, &name, &[lifetime(0)])
            .code(),
        0
    );
    b.allocate(&mut s, t, &name);
}

#[test]
fn past_everyones_total_nobody_gets_more() {
    let t = Instant::now();
    let (first, second) = costs(t);
    let mut s = server_with(t, |c| c.memory_total = first + second - 1);
    Client::new("198.51.100.1:1").allocate(&mut s, t, &user("g1", "p_a"));
    let mut b = Client::new("203.0.113.9:1");
    assert_eq!(refused(&mut b, &mut s, t, &user("g1", "p_b")), 508);
    assert!(s.memory().used() <= s.memory().total());
}

#[test]
fn what_ends_gives_back_exactly_what_it_took() {
    let t = Instant::now();
    let mut s = server(t);
    let clients: Vec<(Client, String)> = (1..=5)
        .map(|n| {
            (
                Client::new(&format!("198.51.100.{n}:{n}")),
                user("g1", &format!("p_{n}")),
            )
        })
        .collect();
    let round = |s: &mut resonance_turn::Server, clients: &mut Vec<(Client, String)>| {
        for (c, name) in clients.iter_mut() {
            c.allocate(s, t, name);
            c.request(s, t, method::REFRESH, name, &[lifetime(0)]);
        }
        s.memory().used()
    };
    let mut clients = clients;
    // The first round keeps each player's ticket; after that, only allocations come and go.
    let kept = round(&mut s, &mut clients);
    assert!(kept > 0, "the tickets kept are charged");
    assert_eq!(round(&mut s, &mut clients), kept);
    assert_eq!(round(&mut s, &mut clients), kept);
    // And so does an expiry.
    for (c, name) in clients.iter_mut() {
        c.allocate(&mut s, t, name);
    }
    assert!(s.memory().used() > kept);
    s.tick(t + std::time::Duration::from_secs(1800));
    assert_eq!(s.allocations(), 0);
    assert_eq!(s.memory().used(), kept);
    // And once the tickets expire too, nothing at all.
    s.tick(t + std::time::Duration::from_secs(3601));
    assert_eq!((s.memory().used(), s.memory().ips()), (0, 0));
}

#[test]
fn a_kept_ticket_gives_its_charge_back_when_it_expires() {
    let t = Instant::now();
    let mut s = server(t);
    let name = ticket(UNIX + 100, "ins", "g1", "p_a");
    let mut c = Client::new("198.51.100.1:1");
    c.allocate(&mut s, t, &name);
    c.request(&mut s, t, method::REFRESH, &name, &[lifetime(0)]);
    assert_eq!((s.allocations(), s.tickets_kept()), (0, 1));
    assert!(s.memory().used() > 0, "the ticket kept");
    s.tick(t + std::time::Duration::from_secs(99));
    assert_eq!(s.tickets_kept(), 1, "not yet");
    s.tick(t + std::time::Duration::from_secs(101));
    assert_eq!(
        (s.tickets_kept(), s.memory().used(), s.memory().ips()),
        (0, 0, 0)
    );
}

#[test]
fn a_fresher_ticket_on_a_refresh_keeps_the_allocations_charge_and_the_old_ticket_goes_at_its_expiry()
 {
    let t = Instant::now();
    let mut s = server(t);
    let (old, fresh) = (
        ticket(UNIX + 100, "ins", "g1", "p_a"),
        ticket(UNIX + 3600, "ins", "g1", "p_a"),
    );
    let mut c = Client::new("198.51.100.1:1");
    c.allocate(&mut s, t, &old);
    let one = s.memory().used();
    assert_eq!(
        c.request(&mut s, t, method::REFRESH, &fresh, &[lifetime(600)])
            .code(),
        0
    );
    let two = s.memory().used();
    assert_eq!(s.tickets_kept(), 2);
    s.tick(t + std::time::Duration::from_secs(101));
    assert_eq!(s.allocations(), 1, "it lives on with the fresher ticket");
    assert_eq!(s.tickets_kept(), 1);
    assert_eq!(
        s.memory().used(),
        one,
        "the allocation's charge, and one ticket: {two}"
    );
}

#[test]
fn one_ip_within_its_caps_is_never_refused_for_memory() {
    // The default share fits what one IP's caps allow: 64 allocations (8 players × 8 here, as
    // a school behind one NAT), then 486 for the per-IP cap, not 508 for memory.
    let t = Instant::now();
    // Each client's first request is unsigned: room for all of them in the IP's budget for those.
    let mut s = server_with(t, |c| c.unauth_burst = 1000.0);
    for p in 0..8 {
        for k in 0..8 {
            Client::new(&format!("198.51.100.1:{}", 1000 + p * 8 + k)).allocate(
                &mut s,
                t,
                &user("g1", &format!("p_{p}")),
            );
        }
    }
    let mut more = Client::new("198.51.100.1:9999");
    assert_eq!(refused(&mut more, &mut s, t, &user("g1", "p_9")), 486);
    assert!(s.memory().of(IpAddr::from([198, 51, 100, 1])) < s.memory().per_ip() / 64);
}

#[test]
fn a_streams_allocation_gives_its_charge_back_when_the_stream_closes() {
    let t = Instant::now();
    let mut s = server(t);
    let name = user("g1", "p_a");
    let mut c = Client::on("198.51.100.1:1", 7);
    c.allocate(&mut s, t, &name);
    c.request(&mut s, t, method::REFRESH, &name, &[lifetime(0)]);
    let kept = s.memory().used();
    c.allocate(&mut s, t, &name);
    assert!(s.memory().used() > kept);
    s.closed(c.core());
    assert_eq!((s.allocations(), s.memory().used()), (0, kept));
}
