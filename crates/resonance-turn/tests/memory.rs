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
    s.tick(t + std::time::Duration::from_secs(3600 * 2));
    assert_eq!(s.allocations(), 0);
    assert_eq!(s.memory().used(), kept);
}
