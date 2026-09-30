//! The Go relay's tests (gamerelay.io deploy/turn/*_test.go), ported to the sans-I/O core, plus the
//! relay path itself. A few Go tests guard against pion creating and deleting allocations out of
//! step with the relay's own bookkeeping (reservations, late deletions); here one state machine
//! does both, so those cases become the invariants checked in `deleted_allocations_free_everything`.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use resonance_turn::auth::password;

mod common;
use common::*;
use resonance_turn::stun::{Class, Message, Writer, attr, method};

#[test]
fn binding_is_answered_with_the_senders_address() {
    let t = Instant::now();
    let mut s = server(t);
    let c = Client::new("198.51.100.1:5000");
    let r = c.ask(&mut s, t, &binding(1));
    assert_eq!(r.code(), 0);
    assert_eq!(r.msg().xor_address(attr::XOR_MAPPED_ADDRESS), Some(c.from));
    assert!(r.msg().has(attr::FINGERPRINT));
}

#[test]
fn an_allocation_is_named_on_this_relays_address() {
    let t = Instant::now();
    let mut s = server(t);
    let mut c = Client::new("198.51.100.1:5000");
    let relayed = c.allocate(&mut s, t, &user("g1", "p_a"));
    assert_eq!(relayed.ip(), public());
    assert!((49152..=65535).contains(&relayed.port()));
    assert_eq!(s.allocations(), 1);
}

#[test]
fn a_retransmitted_allocate_gets_the_same_answer_and_another_gets_437() {
    let t = Instant::now();
    let mut s = server(t);
    let mut c = Client::new("198.51.100.1:5000");
    let name = user("g1", "p_a");
    c.request(&mut s, t, method::ALLOCATE, &name, &[transport()]); // fetches the nonce
    let tx = c.next_tx();
    let req = c.build(
        method::ALLOCATE,
        tx,
        &name,
        &password(KEY, &name),
        "gamerelay",
        &[transport()],
        None,
    );
    let (first, again) = (c.ask(&mut s, t, &req), c.ask(&mut s, t, &req));
    assert_eq!(first.code(), 437, "this 5-tuple already allocated above");
    assert_eq!(again.code(), 437);
    // A fresh 5-tuple: its own retransmission is the same success.
    let mut d = Client::new("198.51.100.1:5001");
    // Its own nonce: c's is bound to c's address.
    d.nonce = c.nonce.clone();
    assert_eq!(
        d.request(&mut s, t, method::REFRESH, &name, &[]).code(),
        437,
        "d's own nonce, after a 438"
    );
    let tx = d.next_tx();
    let req = d.build(
        method::ALLOCATE,
        tx,
        &name,
        &password(KEY, &name),
        "gamerelay",
        &[transport()],
        None,
    );
    let (one, two) = (d.ask(&mut s, t, &req), d.ask(&mut s, t, &req));
    assert_eq!((one.code(), two.code()), (0, 0));
    assert_eq!(
        one.msg().xor_address(attr::XOR_RELAYED_ADDRESS),
        two.msg().xor_address(attr::XOR_RELAYED_ADDRESS)
    );
    assert_eq!(s.allocations(), 2);
}

#[test]
fn bad_credentials_get_401_and_a_stale_nonce_438() {
    let t = Instant::now();
    let mut s = server(t);
    let mut c = Client::new("198.51.100.1:5000");
    let name = user("g1", "p_a");
    let r = c.request_as(
        &mut s,
        t,
        method::ALLOCATE,
        &name,
        "wrong",
        &[transport()],
        None,
    );
    assert_eq!(r.code(), 401, "wrong password");
    let another_node = password("another-node-key-0123456789abcdef0123", &name);
    assert_eq!(
        c.request_as(
            &mut s,
            t,
            method::ALLOCATE,
            &name,
            &another_node,
            &[transport()],
            None
        )
        .code(),
        401,
        "another node's key"
    );
    let expired = format!("{}:ins:g1:p_a", UNIX - 1);
    assert_eq!(
        c.request(&mut s, t, method::ALLOCATE, &expired, &[transport()])
            .code(),
        401,
        "expired"
    );
    assert_eq!(
        c.request(
            &mut s,
            t,
            method::ALLOCATE,
            "not-a-username",
            &[transport()]
        )
        .code(),
        401
    );
    let tx = c.next_tx();
    let other_realm = c.build(
        method::ALLOCATE,
        tx,
        &name,
        &password(KEY, &name),
        "elsewhere",
        &[transport()],
        None,
    );
    assert_eq!(c.ask(&mut s, t, &other_realm).code(), 401, "another realm");
    // An hour on, the nonce is stale: 438 with a fresh one, and the retry succeeds.
    let later = t + Duration::from_secs(3601);
    let tx = c.next_tx();
    let req = c.build(
        method::ALLOCATE,
        tx,
        &format!("{}:ins:g1:p_a", UNIX + 7200),
        &password(KEY, &format!("{}:ins:g1:p_a", UNIX + 7200)),
        "gamerelay",
        &[transport()],
        None,
    );
    let r = c.ask(&mut s, later, &req);
    assert_eq!(r.code(), 438);
    assert!(r.msg().has(attr::NONCE));
    c.nonce = Some(r.msg().str_attr(attr::NONCE).unwrap().to_owned());
    assert_eq!(
        c.request(
            &mut s,
            later,
            method::ALLOCATE,
            &format!("{}:ins:g1:p_a", UNIX + 7200),
            &[transport()]
        )
        .code(),
        0
    );
}

#[test]
fn allocate_needs_udp_and_this_relays_address_family() {
    let t = Instant::now();
    let mut s = server(t);
    let mut c = Client::new("198.51.100.1:5000");
    let name = user("g1", "p_a");
    assert_eq!(
        c.request(&mut s, t, method::ALLOCATE, &name, &[]).code(),
        400
    );
    assert_eq!(
        c.request(
            &mut s,
            t,
            method::ALLOCATE,
            &name,
            &[(attr::REQUESTED_TRANSPORT, vec![6, 0, 0, 0])]
        )
        .code(),
        442
    );
    let v6 = (attr::REQUESTED_ADDRESS_FAMILY, vec![2, 0, 0, 0]);
    assert_eq!(
        c.request(&mut s, t, method::ALLOCATE, &name, &[transport(), v6])
            .code(),
        440
    );
    let v4 = (attr::REQUESTED_ADDRESS_FAMILY, vec![1, 0, 0, 0]);
    assert_eq!(
        c.request(&mut s, t, method::ALLOCATE, &name, &[transport(), v4])
            .code(),
        0
    );
}

#[test]
fn an_unknown_required_attribute_gets_420() {
    let t = Instant::now();
    let mut s = server(t);
    let mut c = Client::new("198.51.100.1:5000");
    // An unsigned request with one gets the 420 too, so fetch the nonce first.
    assert_eq!(
        c.request(&mut s, t, method::REFRESH, &user("g1", "p_a"), &[])
            .code(),
        437
    );
    let r = c.request(
        &mut s,
        t,
        method::ALLOCATE,
        &user("g1", "p_a"),
        &[transport(), (attr::RESERVATION_TOKEN, vec![0; 8])],
    );
    assert_eq!(r.code(), 420);
    assert_eq!(
        r.msg().get(attr::UNKNOWN_ATTRIBUTES),
        Some(&attr::RESERVATION_TOKEN.to_be_bytes()[..])
    );
    // Optional ones (0x8000 and up) are fine.
    let r = c.request(
        &mut s,
        t,
        method::ALLOCATE,
        &user("g1", "p_a"),
        &[transport(), (attr::SOFTWARE, b"test".to_vec())],
    );
    assert_eq!(r.code(), 0);
}

// The Go relay's TestAllocationKeepsItsRoomAndPlayer and TestBoundAuth.
#[test]
fn an_allocation_answers_only_to_its_room_and_player() {
    let t = Instant::now();
    let mut s = server(t);
    let mut c = Client::new("198.51.100.1:5000");
    let own = user("g1", "p_a");
    c.allocate(&mut s, t, &own);
    let me = SocketAddr::new(public(), 50000);
    for name in [
        user("g2", "p_a"),
        user("g1", "p_b"),
        format!("{}:other:g1:p_a", UNIX + 3600),
    ] {
        assert_eq!(
            c.request(&mut s, t, method::REFRESH, &name, &[lifetime(600)])
                .code(),
            441,
            "refresh as {name}"
        );
        assert_eq!(c.permit(&mut s, t, &name, me), 441, "permission as {name}");
        assert_eq!(
            c.bind(&mut s, t, &name, 0x4000, me),
            441,
            "channel as {name}"
        );
    }
    assert_eq!(
        c.request(
            &mut s,
            t,
            method::REFRESH,
            "not-a-username",
            &[lifetime(600)]
        )
        .code(),
        401
    );
    // Its own room and player, even with a fresher credential, still work.
    for name in [own.clone(), format!("{}:ins:g1:p_a", UNIX + 3660)] {
        assert_eq!(
            c.request(&mut s, t, method::REFRESH, &name, &[lifetime(600)])
                .code(),
            0,
            "refresh as {name}"
        );
        assert_eq!(c.permit(&mut s, t, &name, me), 0, "permission as {name}");
    }
    // Another 5-tuple is free to allocate for another room.
    Client::new("198.51.100.1:5001").allocate(&mut s, t, &user("g2", "p_a"));
}

// The Go relay's TestNoRefreshPastTheCredentialsExpiry.
#[test]
fn no_refresh_succeeds_past_the_credentials_expiry() {
    let t = Instant::now();
    let mut s = server(t);
    let mut c = Client::new("198.51.100.1:5000");
    let name = format!("{}:ins:g1:p_a", UNIX + 1);
    c.allocate(&mut s, t, &name);
    let later = t + Duration::from_secs(2);
    assert_eq!(
        c.request(&mut s, later, method::REFRESH, &name, &[lifetime(600)])
            .code(),
        401
    );
}

#[test]
fn lifetimes_are_clamped_and_a_zero_refresh_deletes() {
    let t = Instant::now();
    let mut s = server(t);
    let mut c = Client::new("198.51.100.1:5000");
    let name = user("g1", "p_a");
    let r = c.request(
        &mut s,
        t,
        method::ALLOCATE,
        &name,
        &[transport(), lifetime(99_999)],
    );
    assert_eq!(r.msg().u32_attr(attr::LIFETIME), Some(3600));
    let r = c.request(&mut s, t, method::REFRESH, &name, &[lifetime(1)]);
    assert_eq!(r.msg().u32_attr(attr::LIFETIME), Some(600));
    let r = c.request(&mut s, t, method::REFRESH, &name, &[lifetime(0)]);
    assert_eq!((r.code(), r.msg().u32_attr(attr::LIFETIME)), (0, Some(0)));
    assert_eq!(s.allocations(), 0);
    assert_eq!(
        c.request(&mut s, t, method::REFRESH, &name, &[lifetime(600)])
            .code(),
        437,
        "nothing left to refresh"
    );
}

#[test]
fn an_allocation_ends_a_minute_after_its_lifetime() {
    let t = Instant::now();
    let mut s = server(t);
    let mut c = Client::new("198.51.100.1:5000");
    c.allocate(&mut s, t, &user("g1", "p_a"));
    // Granted 600 s; kept 60 more for a refresh late by a lost packet (Firefox refreshes 10 s
    // before the end).
    s.tick(t + Duration::from_secs(659));
    assert_eq!(s.allocations(), 1);
    s.tick(t + Duration::from_secs(660));
    assert_eq!(s.allocations(), 0);
}

// The Go relay's TestQuotas and TestPerInstanceQuota.
#[test]
fn quotas_per_player_ip_and_instance() {
    let t = Instant::now();
    let mut s = server_with(t, |c| {
        c.max_per_player = 2;
        c.max_per_ip = 3;
        c.max_per_instance = 4;
    });
    let p_a = user("g1", "p_a");
    Client::new("198.51.100.1:1").allocate(&mut s, t, &p_a);
    Client::new("198.51.100.2:1").allocate(&mut s, t, &p_a);
    let mut third = Client::new("198.51.100.3:1");
    assert_eq!(
        third
            .request(&mut s, t, method::ALLOCATE, &p_a, &[transport()])
            .code(),
        486,
        "a third for one player"
    );
    // Two more players bring the instance to its 4.
    Client::new("203.0.113.1:1").allocate(&mut s, t, &user("g1", "p_b"));
    Client::new("203.0.113.1:2").allocate(&mut s, t, &user("g1", "p_c"));
    // The instance is now at 4: any player, any address, is refused.
    let mut fifth = Client::new("192.0.2.200:1");
    assert_eq!(
        fifth
            .request(
                &mut s,
                t,
                method::ALLOCATE,
                &user("g9", "p_z"),
                &[transport()]
            )
            .code(),
        486
    );
    let other_game = format!("{}:ins2:g1:p_a", UNIX + 3600);
    Client::new("192.0.2.200:2").allocate(&mut s, t, &other_game);
    // A deletion gives its slot back.
    let mut first = Client::new("198.51.100.1:1");
    first.request(&mut s, t, method::REFRESH, &p_a, &[lifetime(0)]);
    third.allocate(&mut s, t, &p_a);
}

#[test]
fn an_ip_cap_counts_every_port_of_that_ip() {
    let t = Instant::now();
    let mut s = server_with(t, |c| c.max_per_ip = 2);
    Client::new("198.51.100.1:1").allocate(&mut s, t, &user("g1", "p_a"));
    Client::new("198.51.100.1:2").allocate(&mut s, t, &user("g1", "p_b"));
    let mut c = Client::new("198.51.100.1:3");
    assert_eq!(
        c.request(
            &mut s,
            t,
            method::ALLOCATE,
            &user("g1", "p_c"),
            &[transport()]
        )
        .code(),
        486
    );
}

#[test]
fn a_full_port_range_gets_508() {
    let t = Instant::now();
    let mut s = server_with(t, |c| {
        c.min_port = 50000;
        c.max_port = 50001;
    });
    Client::new("198.51.100.1:1").allocate(&mut s, t, &user("g1", "p_a"));
    Client::new("198.51.100.2:1").allocate(&mut s, t, &user("g1", "p_b"));
    let mut c = Client::new("198.51.100.3:1");
    assert_eq!(
        c.request(
            &mut s,
            t,
            method::ALLOCATE,
            &user("g1", "p_c"),
            &[transport()]
        )
        .code(),
        508
    );
}

// The Go relay's TestAllowedPeerIsOnlyThisRelay and TestGuardedConnAddressForms.
#[test]
fn the_only_permitted_peer_is_this_relay() {
    let t = Instant::now();
    let mut s = server(t);
    let mut c = Client::new("198.51.100.1:5000");
    let name = user("g1", "p_a");
    c.allocate(&mut s, t, &name);
    // restund's matrix too: never loopback, "any", broadcast or link-local, only the advertised IP.
    for peer in [
        "192.0.2.2:50000",
        "127.0.0.1:50000",
        "127.0.0.2:50000",
        "10.0.0.1:50000",
        "0.0.0.0:50000",
        "255.255.255.255:50000",
        "169.254.0.1:50000",
        "203.0.113.9:6000",
    ] {
        assert_eq!(c.permit(&mut s, t, &name, addr(peer)), 403, "{peer}");
        assert_eq!(c.bind(&mut s, t, &name, 0x4000, addr(peer)), 403, "{peer}");
    }
    // Another address family: 443 (RFC 8656 §9.3).
    for peer in [
        "[2001:db8::1]:50000",
        "[::1]:50000",
        "[::]:50000",
        "[fe80::1]:50000",
    ] {
        assert_eq!(c.permit(&mut s, t, &name, addr(peer)), 443, "{peer}");
        assert_eq!(c.bind(&mut s, t, &name, 0x4000, addr(peer)), 443, "{peer}");
    }
    assert_eq!(c.permit(&mut s, t, &name, addr("192.0.2.1:50000")), 0);
    assert_eq!(
        c.permit(&mut s, t, &name, addr("[::ffff:192.0.2.1]:50000")),
        0,
        "IPv4-mapped is the same relay"
    );
    let stats = s.stats();
    assert_eq!(
        (stats.permissions_allowed, stats.permissions_denied),
        (2, 24)
    );
}

#[test]
fn an_ipv4_mapped_client_is_the_same_client() {
    let t = Instant::now();
    let mut s = server(t);
    let mut c = Client::new("[::ffff:198.51.100.1]:5000");
    c.allocate(&mut s, t, &user("g1", "p_a"));
    let mut plain = Client::new("198.51.100.1:5000");
    assert_eq!(
        plain
            .request(
                &mut s,
                t,
                method::ALLOCATE,
                &user("g1", "p_a"),
                &[transport()]
            )
            .code(),
        437
    );
}

#[test]
fn a_send_indication_reaches_the_peer_as_data_from_the_senders_relay_address() {
    let t = Instant::now();
    let mut s = server(t);
    let (mut a, ra, b, rb) = pair(&mut s, t, "g1");
    let got = a.send_indication(&mut s, t, rb, b"hello");
    assert_eq!(got.len(), 1);
    let (to, packet) = &got[0];
    assert_eq!(*to, b.from);
    let m = Message::parse(packet).unwrap();
    assert_eq!((m.method, m.class), (method::DATA, Class::Indication));
    assert_eq!(m.xor_address(attr::XOR_PEER_ADDRESS), Some(ra));
    assert_eq!(m.get(attr::DATA), Some(&b"hello"[..]));
    let stats = s.stats();
    assert_eq!((stats.relayed_packets, stats.relayed_bytes), (1, 5));
}

#[test]
fn channels_carry_channel_data_both_ways() {
    let t = Instant::now();
    let mut s = server(t);
    let (mut a, ra, mut b, rb) = pair(&mut s, t, "g1");
    assert_eq!(a.bind(&mut s, t, &user("g1", "p_a"), 0x4001, rb), 0);
    // Only a has a channel: b still gets a Data indication, a gets ChannelData.
    let to_b = a.channel_data(&mut s, t, 0x4001, b"ping");
    assert_eq!(
        Message::parse(&to_b[0].1).unwrap().get(attr::DATA),
        Some(&b"ping"[..])
    );
    let to_a = b.send_indication(&mut s, t, ra, b"pong");
    assert_eq!(
        to_a,
        vec![(a.from, [&[0x40, 0x01, 0, 4][..], b"pong"].concat())]
    );
    assert_eq!(b.bind(&mut s, t, &user("g1", "p_b"), 0x4abc, ra), 0);
    assert_eq!(
        a.channel_data(&mut s, t, 0x4001, b"x"),
        vec![(b.from, vec![0x4a, 0xbc, 0, 1, b'x'])]
    );
    // An unbound channel carries nothing.
    assert!(a.channel_data(&mut s, t, 0x4002, b"x").is_empty());
}

#[test]
fn a_channel_names_one_peer_and_a_peer_one_channel() {
    let t = Instant::now();
    let mut s = server(t);
    let (mut a, _, _, rb) = pair(&mut s, t, "g1");
    let name = user("g1", "p_a");
    let other = SocketAddr::new(public(), rb.port() ^ 1);
    assert_eq!(a.bind(&mut s, t, &name, 0x4001, rb), 0);
    assert_eq!(a.bind(&mut s, t, &name, 0x4001, rb), 0, "a refresh");
    assert_eq!(
        a.bind(&mut s, t, &name, 0x4001, other),
        400,
        "the channel is taken"
    );
    assert_eq!(
        a.bind(&mut s, t, &name, 0x4002, rb),
        400,
        "the peer has a channel"
    );
    assert_eq!(
        a.bind(&mut s, t, &name, 0x3FFF, other),
        400,
        "not a channel number"
    );
    assert_eq!(
        a.bind(&mut s, t, &name, 0x8000, other),
        400,
        "not a channel number"
    );
}

// The Go relay's TestGuardedConnOnlyReachesItsOwnRoom.
#[test]
fn nothing_crosses_rooms() {
    let t = Instant::now();
    let mut s = server(t);
    let (mut a, _, _, rb) = pair(&mut s, t, "g2");
    assert!(a.send_indication(&mut s, t, rb, b"hello").is_empty());
    assert_eq!(s.stats().dropped_route, 1);
}

#[test]
fn both_ends_need_a_permission() {
    let t = Instant::now();
    let mut s = server(t);
    let (mut a, mut b) = (
        Client::new("198.51.100.1:5000"),
        Client::new("203.0.113.9:6000"),
    );
    let ra = a.allocate(&mut s, t, &user("g1", "p_a"));
    let rb = b.allocate(&mut s, t, &user("g1", "p_b"));
    assert!(
        a.send_indication(&mut s, t, rb, b"x").is_empty(),
        "the sender has none"
    );
    assert_eq!(a.permit(&mut s, t, &user("g1", "p_a"), rb), 0);
    assert!(
        a.send_indication(&mut s, t, rb, b"x").is_empty(),
        "the receiver has none"
    );
    assert_eq!(b.permit(&mut s, t, &user("g1", "p_b"), ra), 0);
    assert_eq!(a.send_indication(&mut s, t, rb, b"x").len(), 1);
    // Permissions last 5 minutes.
    let later = t + Duration::from_secs(301);
    assert!(a.send_indication(&mut s, later, rb, b"x").is_empty());
}

#[test]
fn nothing_reaches_a_port_nobody_holds_or_another_host() {
    let t = Instant::now();
    let mut s = server(t);
    let (mut a, _, _, rb) = pair(&mut s, t, "g1");
    let free = SocketAddr::new(
        public(),
        if rb.port() == 65535 {
            65534
        } else {
            rb.port() + 1
        },
    );
    assert!(a.send_indication(&mut s, t, free, b"x").is_empty());
    assert!(
        a.send_indication(
            &mut s,
            t,
            SocketAddr::new(addr("192.0.2.2:1").ip(), rb.port()),
            b"x"
        )
        .is_empty(),
        "the same port on another host is not that allocation"
    );
    assert!(
        a.send_indication(&mut s, t, SocketAddr::new(public(), 3478), b"x")
            .is_empty(),
        "outside the relay ports"
    );
}

// The Go relay's TestGuardedConnForgetsDeletedAllocations, TestLateDeletion*, TestReservations.
#[test]
fn deleted_allocations_free_everything() {
    let t = Instant::now();
    let mut s = server_with(t, |c| {
        c.max_per_player = 1;
        c.min_port = 50000;
        c.max_port = 50001;
    });
    let (mut a, _, mut b, rb) = pair(&mut s, t, "g1");
    assert_eq!(
        b.request(
            &mut s,
            t,
            method::REFRESH,
            &user("g1", "p_b"),
            &[lifetime(0)]
        )
        .code(),
        0
    );
    // b's port is free: nothing reaches it, and a newcomer from another room can take it.
    assert!(a.send_indication(&mut s, t, rb, b"x").is_empty());
    let mut c = Client::new("192.0.2.77:1");
    let rc = c.allocate(&mut s, t, &user("g9", "p_c"));
    assert_eq!(rc.port(), rb.port(), "the only free port");
    assert_eq!(c.permit(&mut s, t, &user("g9", "p_c"), rb), 0);
    assert!(
        a.send_indication(&mut s, t, rb, b"x").is_empty(),
        "the port's new owner is in another room"
    );
    // b's player slot came back too.
    let mut b2 = Client::new("203.0.113.9:6001");
    assert_eq!(
        b2.request(
            &mut s,
            t,
            method::ALLOCATE,
            &user("g1", "p_b"),
            &[transport()]
        )
        .code(),
        508,
        "no port left, but not 486: the player slot was freed"
    );
}

// The Go relay's TestGuardedConnBandwidthCap.
#[test]
fn an_allocation_sends_at_most_its_rate() {
    let t = Instant::now();
    let mut s = server_with(t, |c| {
        c.rate_bytes = 1000.0;
        c.burst_bytes = 2000.0;
    });
    let (mut a, _, _, rb) = pair(&mut s, t, "g1");
    let chunk = [0u8; 500];
    let passed = (0..10)
        .filter(|_| !a.send_indication(&mut s, t, rb, &chunk).is_empty())
        .count();
    assert_eq!(passed, 4, "the burst");
    let passed = (0..10)
        .filter(|_| {
            !a.send_indication(&mut s, t + Duration::from_secs(1), rb, &chunk)
                .is_empty()
        })
        .count();
    assert_eq!(passed, 2, "a second's worth");
    assert_eq!(s.stats().dropped_rate, 14);
}

// The Go relay's TestReflectionLimiter and TestRelayCapsUnauthenticatedAnswers.
#[test]
fn unauthenticated_requests_are_capped_per_ip() {
    let t = Instant::now();
    let mut s = server(t);
    let victim = Client::new("198.51.100.7:1");
    let answered = (0..200)
        .filter(|_| !victim.send(&mut s, t, &binding(1)).is_empty())
        .count();
    assert_eq!(answered, 64, "the burst");
    let mut unsigned_allocate = Vec::new();
    Writer::new(
        &mut unsigned_allocate,
        method::ALLOCATE,
        Class::Request,
        [2; 12],
    )
    .attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
    assert!(
        Client::new("198.51.100.7:2")
            .send(&mut s, t, &unsigned_allocate)
            .is_empty(),
        "another port of the same IP"
    );
    let later = t + Duration::from_secs(1);
    let answered = (0..200)
        .filter(|_| !victim.send(&mut s, later, &binding(1)).is_empty())
        .count();
    assert_eq!(answered, 20, "a second's worth");
    // Another IP has its own bucket.
    let other = Client::new("203.0.113.1:1");
    assert_eq!(
        (0..100)
            .filter(|_| !other.send(&mut s, t, &binding(1)).is_empty())
            .count(),
        64
    );
    // Never slowed: authenticated requests, and a 5-tuple with an allocation.
    let mut c = Client::new("192.0.2.50:1");
    c.allocate(&mut s, t, &user("g1", "p_a")); // its nonce request used one token
    for _ in 0..100 {
        assert_eq!(
            c.request(
                &mut s,
                t,
                method::REFRESH,
                &user("g1", "p_a"),
                &[lifetime(600)]
            )
            .code(),
            0
        );
    }
    assert_eq!(
        (0..100)
            .filter(|_| !c.send(&mut s, t, &binding(1)).is_empty())
            .count(),
        100
    );
    assert_eq!(s.stats().unauthenticated_dropped, 136 + 1 + 180 + 36);
}

#[test]
fn junk_is_dropped_silently() {
    let t = Instant::now();
    let mut s = server(t);
    let c = Client::new("198.51.100.1:5000");
    for junk in [
        &b""[..],
        b"hello",
        &[0x40, 0, 0, 9, 1],
        &[0u8; 20],
        &[
            0x01, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    ] {
        assert!(c.send(&mut s, t, junk).is_empty(), "{junk:?}");
    }
}

#[test]
fn a_rotated_key_takes_over_and_the_old_one_lasts_its_overlap() {
    let t = Instant::now();
    let mut s = server(t);
    let name = user("g1", "p_a");
    let new_key = "the-rotated-node-key-0123456789abcdef";
    s.set_node_key(new_key.into(), t, Duration::from_secs(3600));
    // Credentials minted with the old key still work for the overlap…
    let mut old = Client::new("198.51.100.1:5000");
    old.allocate(&mut s, t, &name);
    // …and with the new one.
    let mut fresh = Client::new("198.51.100.2:5000");
    fresh.request(&mut s, t, method::REFRESH, &name, &[]);
    let r = fresh.request_as(
        &mut s,
        t,
        method::ALLOCATE,
        &name,
        &password(new_key, &name),
        &[transport()],
        None,
    );
    assert_eq!(r.code(), 0);
    // After it, only the new key.
    let later = t + Duration::from_secs(3601);
    let mut late = Client::new("198.51.100.3:5000");
    let other = format!("{}:ins:g1:p_b", UNIX + 7200);
    assert_eq!(
        late.request(&mut s, later, method::ALLOCATE, &other, &[transport()])
            .code(),
        401
    );
    assert_eq!(
        late.request_as(
            &mut s,
            later,
            method::ALLOCATE,
            &other,
            &password(new_key, &other),
            &[transport()],
            None
        )
        .code(),
        0
    );
}

#[test]
fn a_draining_node_refuses_new_allocations_and_keeps_the_old_ones() {
    let t = Instant::now();
    let mut s = server(t);
    let (mut a, _, _, rb) = pair(&mut s, t, "g1");
    s.set_accepting(false);
    let mut c = Client::new("192.0.2.9:1");
    assert_eq!(
        c.request(
            &mut s,
            t,
            method::ALLOCATE,
            &user("g1", "p_c"),
            &[transport()]
        )
        .code(),
        508
    );
    assert_eq!(a.send_indication(&mut s, t, rb, b"still here").len(), 1);
    assert_eq!(
        a.request(
            &mut s,
            t,
            method::REFRESH,
            &user("g1", "p_a"),
            &[lifetime(600)]
        )
        .code(),
        0
    );
    s.set_accepting(true);
    c.allocate(&mut s, t, &user("g1", "p_c"));
}

#[test]
fn a_stream_and_a_datagram_client_at_one_address_are_two_clients() {
    let t = Instant::now();
    let mut s = server(t);
    // One host's UDP socket and TCP connection can share a port number: two 5-tuples.
    let mut udp = Client::new("198.51.100.1:5000");
    let mut tcp = Client::on("198.51.100.1:5000", 7);
    let ru = udp.allocate(&mut s, t, &user("g1", "p_a"));
    let rt = tcp.allocate(&mut s, t, &user("g1", "p_b"));
    assert_ne!(ru, rt);
    assert_eq!(s.allocations(), 2);
    // Each one's requests reach its own allocation (a Refresh on the other would be 437).
    assert_eq!(
        udp.request(
            &mut s,
            t,
            method::REFRESH,
            &user("g1", "p_a"),
            &[lifetime(600)]
        )
        .code(),
        0
    );
    assert_eq!(
        tcp.request(
            &mut s,
            t,
            method::REFRESH,
            &user("g1", "p_b"),
            &[lifetime(600)]
        )
        .code(),
        0
    );
}

#[test]
fn a_stream_client_relays_with_a_datagram_client() {
    let t = Instant::now();
    let mut s = server(t);
    let mut a = Client::on("198.51.100.1:5000", 3);
    let mut b = Client::new("203.0.113.9:6000");
    let ra = a.allocate(&mut s, t, &user("g1", "p_a"));
    let rb = b.allocate(&mut s, t, &user("g1", "p_b"));
    assert_eq!(a.permit(&mut s, t, &user("g1", "p_a"), rb), 0);
    assert_eq!(b.permit(&mut s, t, &user("g1", "p_b"), ra), 0);
    let mut buf = Vec::new();
    let tx = a.next_tx();
    Writer::new(&mut buf, method::SEND, Class::Indication, tx)
        .xor_address(attr::XOR_PEER_ADDRESS, rb)
        .attr(attr::DATA, b"over tls");
    let got = a.send_on(&mut s, t, &buf);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, b.core(), "to b, on the UDP socket");
    // And back, onto a's stream.
    let mut buf = Vec::new();
    let tx = b.next_tx();
    Writer::new(&mut buf, method::SEND, Class::Indication, tx)
        .xor_address(attr::XOR_PEER_ADDRESS, ra)
        .attr(attr::DATA, b"over udp");
    let got = b.send_on(&mut s, t, &buf);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, a.core(), "to a, on its stream");
}

#[test]
fn a_closed_stream_ends_its_allocation() {
    let t = Instant::now();
    let mut s = server_with(t, |c| c.max_per_ip = 1);
    let mut a = Client::on("198.51.100.1:5000", 3);
    a.allocate(&mut s, t, &user("g1", "p_a"));
    assert_eq!(s.allocations(), 1);
    // The UDP client at the same address closing nothing: only that stream's.
    s.closed(resonance_turn::Client::udp(addr("198.51.100.1:5000")));
    assert_eq!(s.allocations(), 1);
    s.closed(a.core());
    assert_eq!(s.allocations(), 0);
    // Its per-IP quota is free again, on a new connection.
    let mut again = Client::on("198.51.100.1:5001", 4);
    again.allocate(&mut s, t, &user("g1", "p_a"));
    assert_eq!(s.allocations(), 1);
}
