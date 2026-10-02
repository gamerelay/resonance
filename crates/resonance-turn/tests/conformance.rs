//! What other TURN implementations and the browsers' own TURN clients check, that the Go relay's
//! tests didn't: RFC 5769's vectors, real Chrome and Firefox traffic, the auth corner cases
//! coturn and eturnal test, and how Chrome (libwebrtc) and Firefox (nICEr) behave on the wire.
//! Sources are named on each test.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use base64::Engine;
use resonance_turn::Output;
use resonance_turn::auth::long_term_key;
use resonance_turn::stun::{self, Class, Message, Writer, attr, method};

mod common;
use common::*;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn key_of(name: &str) -> [u8; 16] {
    long_term_key(name, "gamerelay", &pass(name))
}

/// A signed answer: its MESSAGE-INTEGRITY checks out with name's key.
fn signed_by(r: &Reply, name: &str) -> bool {
    r.msg().integrity_ok(&key_of(name))
}

// ---------------------------------------------------------------------------------------------
// RFC 5769 (bytes as in coturn src/apps/rfc5769/rfc5769check.c).

const RFC5769_REQUEST: &str = "000100582112a442b7e7a701bc34d686fa87dfae802200105354554e207465737420636c69656e74\
    002400046e0001ff80290008932ff9b151263b36000600096576746a3a68367659202020\
    000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a280280004e57a3bcf";

#[test]
fn rfc5769_all_four_vectors() {
    // §2.1 request (short-term): integrity and fingerprint.
    let req = hex(RFC5769_REQUEST);
    let m = Message::parse(&req).unwrap();
    assert!(m.integrity_ok(b"VOkJxbRl1RmTxUk/WvJxBt") && m.fingerprint_ok());
    // §2.2 IPv4 response.
    let v4 = hex(
        "0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220\
         002000080001a147e112a643000800142b91f599fd9e90c38c7489f92af9ba53f06be7d7\
         80280004c07d4c96",
    );
    let m = Message::parse(&v4).unwrap();
    assert!(m.integrity_ok(b"VOkJxbRl1RmTxUk/WvJxBt") && m.fingerprint_ok());
    assert_eq!(
        m.xor_address(attr::XOR_MAPPED_ADDRESS),
        Some(addr("192.0.2.1:32853"))
    );
    // §2.3 IPv6 response: the address is XORed with the transaction id as well.
    let v6 = hex(
        "010100482112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220\
         002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d900080014a382954e4be67bf1\
         1784c97c8292c275bfe3ed4180280004c8fb0b4c",
    );
    let m = Message::parse(&v6).unwrap();
    assert!(m.integrity_ok(b"VOkJxbRl1RmTxUk/WvJxBt") && m.fingerprint_ok());
    assert_eq!(
        m.xor_address(attr::XOR_MAPPED_ADDRESS),
        Some(addr("[2001:db8:1234:5678:11:2233:4455:6677]:32853"))
    );
    // §2.4 long-term credentials: MD5(username ":" realm ":" password), the key all our auth
    // rests on (the password after SASLprep is "TheMatrIX").
    let lt = hex(
        "000100602112a44278ad3433c6ad72c029da412e00060012e3839ee38388e383aae38383\
         e382afe382b900000015001c662f2f3439396b39353464364f4c33346f4c394653547679\
         363473410014000b6578616d706c652e6f72670000080014f67024656dd64a3e02b8e071\
         2e85c9a28ca89666",
    );
    let m = Message::parse(&lt).unwrap();
    let user = m.str_attr(attr::USERNAME).unwrap();
    assert_eq!(user, "マトリックス");
    assert_eq!(m.str_attr(attr::REALM), Some("example.org"));
    assert!(m.integrity_ok(&long_term_key(user, "example.org", "TheMatrIX")));
    // Any one byte flipped fails.
    for i in 0..lt.len() - 20 {
        let mut bad = lt.clone();
        bad[i] ^= 0x01;
        if let Some(m) = Message::parse(&bad) {
            assert!(
                !m.integrity_ok(&long_term_key(user, "example.org", "TheMatrIX")),
                "byte {i}"
            );
        }
    }
}

#[test]
fn our_own_answers_carry_a_valid_fingerprint() {
    let t = Instant::now();
    let mut s = server(t);
    let mut c = Client::new("198.51.100.1:5000");
    assert!(c.ask(&mut s, t, &binding(1)).msg().fingerprint_ok());
    let name = user("g1", "p_a");
    let r = c.request(&mut s, t, method::ALLOCATE, &name, &[transport()]);
    assert!(r.msg().fingerprint_ok() && signed_by(&r, &name));
    let mut bad = r.0.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    assert!(!Message::parse(&bad).unwrap().fingerprint_ok());
}

// ---------------------------------------------------------------------------------------------
// Real browser traffic (tests/testdata, from pion; see NOTICE.md).

#[test]
fn chrome_and_firefox_binding_requests_parse_and_are_answered() {
    let csv = include_str!("testdata/frombrowsers.csv");
    let t = Instant::now();
    let mut s = server(t);
    let mut seen = 0;
    for line in csv
        .lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with("ip,"))
    {
        let cols: Vec<&str> = line.split(',').collect();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(cols[1])
            .unwrap();
        let m = Message::parse(&bytes)
            .unwrap_or_else(|| panic!("{} {}: doesn't parse", cols[3], cols[4]));
        assert_eq!((m.method, m.class), (method::BINDING, Class::Request));
        assert!(
            m.fingerprint_ok(),
            "{} {}: our CRC disagrees with the browser's",
            cols[3],
            cols[4]
        );
        assert!(
            m.unknown_required().next().is_none(),
            "{} {}",
            cols[3],
            cols[4]
        );
        let c = Client::new(&format!("198.51.100.{}:5000", seen + 1));
        let r = c.ask(&mut s, t, &bytes);
        assert_eq!(r.code(), 0);
        assert_eq!(r.msg().tx, m.tx);
        seen += 1;
    }
    assert!(seen >= 10, "{seen}");
}

#[test]
fn chromes_allocate_flow_parses_and_its_first_allocate_gets_a_401() {
    let lines: Vec<Vec<u8>> = include_str!("testdata/01_chromeallocreq.hex")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(hex)
        .collect();
    assert_eq!(lines.len(), 4);
    for (i, b) in lines.iter().enumerate() {
        assert!(Message::parse(b).is_some(), "message {i}");
    }
    let t = Instant::now();
    let mut s = server(t);
    let c = Client::new("198.51.100.1:5000");
    // Chrome's first Allocate carries ORIGIN (0x802F, optional): a 401 with a nonce, never a
    // 420. Chrome only accepts 401 or 300 here and times out on anything else.
    let r = c.ask(&mut s, t, &lines[0]);
    assert_eq!(r.code(), 401);
    assert!(r.msg().has(attr::NONCE) && r.msg().has(attr::REALM));
    // Its signed Allocate was for coturn's realm and nonce: refused, cleanly.
    assert_eq!(c.ask(&mut s, t, &lines[2]).code(), 401);
}

#[test]
fn chromes_channel_data_including_an_unpadded_dtls_flight() {
    let frames: Vec<Vec<u8>> = include_str!("testdata/02_chandata.hex")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(hex)
        .collect();
    assert_eq!(frames.len(), 2);
    for f in &frames {
        let (channel, data) = stun::parse_channel_data(f).expect("ChannelData");
        assert_eq!(channel, 0x4000);
        assert_eq!(data.len(), u16::from_be_bytes([f[2], f[3]]) as usize);
    }
    // Relayed through the server, exactly LENGTH bytes arrive.
    let t = Instant::now();
    let mut s = server(t);
    let (mut a, _, b, rb) = pair(&mut s, t, "g1");
    assert_eq!(a.bind(&mut s, t, &user("g1", "p_a"), 0x4000, rb), 0);
    for f in &frames {
        let got = a.send(&mut s, t, f);
        let (_, data) = stun::parse_channel_data(f).unwrap();
        let (to, packet) = &got[0];
        assert_eq!(*to, b.from);
        assert_eq!(Message::parse(packet).unwrap().get(attr::DATA), Some(data));
    }
}

// ---------------------------------------------------------------------------------------------
// Attributes after MESSAGE-INTEGRITY (coturn tests/test_stun_msg.c, pion/stun integrity_test.go).

/// req with an attribute appended after its MESSAGE-INTEGRITY (and the length fixed up), as
/// someone on the path could.
fn append_after_integrity(req: &[u8], kind: u16, value: &[u8]) -> Vec<u8> {
    let m = Message::parse(req).unwrap();
    let mi = m
        .attrs()
        .find(|a| a.kind == attr::MESSAGE_INTEGRITY)
        .unwrap();
    let mut out = req[..mi.offset + 24].to_vec();
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    out.resize(out.len().next_multiple_of(4), 0);
    let len = (out.len() - 20) as u16;
    out[2..4].copy_from_slice(&len.to_be_bytes());
    out
}

#[test]
fn nothing_after_message_integrity_counts() {
    let t = Instant::now();
    let mut s = server(t);
    let mut c = Client::new("198.51.100.1:5000");
    let name = user("g1", "p_a");
    c.allocate(&mut s, t, &name);
    // A captured Refresh turned into LIFETIME 0 after the fact: still signed (the HMAC stops at
    // MESSAGE-INTEGRITY), and must not end the allocation.
    let tx = c.next_tx();
    let refresh = c.build(
        method::REFRESH,
        tx,
        &name,
        &pass(&name),
        "gamerelay",
        &[],
        None,
    );
    let forged = append_after_integrity(&refresh, attr::LIFETIME, &0u32.to_be_bytes());
    let r = c.ask(&mut s, t, &forged);
    assert_eq!((r.code(), r.msg().u32_attr(attr::LIFETIME)), (0, Some(600)));
    assert_eq!(s.allocations(), 1);
    // An RFC 8489 client puts MESSAGE-INTEGRITY-SHA256 (comprehension-required) there: no 420.
    let tx = c.next_tx();
    let refresh = c.build(
        method::REFRESH,
        tx,
        &name,
        &pass(&name),
        "gamerelay",
        &[lifetime(600)],
        None,
    );
    let sha256 = append_after_integrity(&refresh, attr::MESSAGE_INTEGRITY_SHA256, &[0; 32]);
    assert_eq!(c.ask(&mut s, t, &sha256).code(), 0);
    // A peer smuggled in after it is ignored too.
    let tx = c.next_tx();
    let perm = c.build(
        method::CREATE_PERMISSION,
        tx,
        &name,
        &pass(&name),
        "gamerelay",
        &[],
        None,
    );
    let mut peer = Vec::new();
    Writer::new(&mut peer, method::BINDING, Class::Request, tx)
        .xor_address(attr::XOR_PEER_ADDRESS, SocketAddr::new(public(), 50000));
    let value = Message::parse(&peer)
        .unwrap()
        .get(attr::XOR_PEER_ADDRESS)
        .unwrap()
        .to_vec();
    let smuggled = append_after_integrity(&perm, attr::XOR_PEER_ADDRESS, &value);
    assert_eq!(
        c.ask(&mut s, t, &smuggled).code(),
        400,
        "no peer before MESSAGE-INTEGRITY"
    );
}

#[test]
fn a_420_lists_every_unknown_attribute_and_only_those() {
    // pion server_test.go: 0x07AD and 0x7FFF are unknown; CHANNEL-NUMBER is known; 0x8000 is optional.
    let t = Instant::now();
    let mut s = server(t);
    let c = Client::new("198.51.100.1:5000");
    let mut req = Vec::new();
    Writer::new(&mut req, method::BINDING, Class::Request, [5; 12])
        .attr(0x07AD, &[1, 2, 3, 4])
        .attr(attr::CHANNEL_NUMBER, &[0x40, 0, 0, 0])
        .attr(0x7FFF, &[0; 4])
        .attr(0x8000, &[0; 4]);
    let r = c.ask(&mut s, t, &req);
    assert_eq!(r.code(), 420);
    assert_eq!(
        r.msg().get(attr::UNKNOWN_ATTRIBUTES),
        Some(&[0x07, 0xAD, 0x7F, 0xFF][..])
    );
}

// ---------------------------------------------------------------------------------------------
// Authentication corner cases (coturn examples/scripts/stateless_nonce_forged_mi.py,
// tests/test_stateless_nonce.c; eturnal/stun src/stun_test.erl).

/// A request with whatever USERNAME, REALM, NONCE and MESSAGE-INTEGRITY (None: leave it out).
fn crafted(
    m: u16,
    tx: [u8; 12],
    username: Option<&str>,
    nonce: Option<&str>,
    mi_key: Option<[u8; 16]>,
    zero_mi: bool,
) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = Writer::new(&mut buf, m, Class::Request, tx);
    w.attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
    if let Some(u) = username {
        w.attr(attr::USERNAME, u.as_bytes());
    }
    w.attr(attr::REALM, b"gamerelay");
    if let Some(n) = nonce {
        w.attr(attr::NONCE, n.as_bytes());
    }
    if zero_mi {
        w.attr(attr::MESSAGE_INTEGRITY, &[0; 20]);
    } else if let Some(k) = mi_key {
        w.integrity(&k);
    }
    buf
}

#[test]
fn auth_corner_cases() {
    let t = Instant::now();
    let mut s = server(t);
    let mut c = Client::new("198.51.100.1:5000");
    let name = user("g1", "p_a");
    // A real nonce for c.
    assert_eq!(
        c.request(&mut s, t, method::REFRESH, &name, &[]).code(),
        437
    );
    let nonce = c.nonce.clone().unwrap();
    let k = key_of(&name);
    // MESSAGE-INTEGRITY without USERNAME, or without NONCE: malformed, 400.
    assert_eq!(
        c.ask(
            &mut s,
            t,
            &crafted(
                method::ALLOCATE,
                [1; 12],
                None,
                Some(&nonce),
                Some(k),
                false
            )
        )
        .code(),
        400
    );
    assert_eq!(
        c.ask(
            &mut s,
            t,
            &crafted(method::ALLOCATE, [2; 12], Some(&name), None, Some(k), false)
        )
        .code(),
        400
    );
    // An issued nonce with forged integrity: 401.
    assert_eq!(
        c.ask(
            &mut s,
            t,
            &crafted(
                method::ALLOCATE,
                [3; 12],
                Some(&name),
                Some(&nonce),
                None,
                true
            )
        )
        .code(),
        401
    );
    // A well-formed nonce we never issued, with zeros for integrity: 438 and a real one.
    let r = c.ask(
        &mut s,
        t,
        &crafted(
            method::ALLOCATE,
            [4; 12],
            Some(&name),
            Some("6e0000000-0123456789abcdef"),
            None,
            true,
        ),
    );
    assert_eq!(r.code(), 438);
    assert!(r.msg().has(attr::NONCE));
    // c's nonce from another address: 438, so a nonce seen on the wire is no use elsewhere.
    let other = Client::new("203.0.113.5:5000");
    assert_eq!(
        other
            .ask(
                &mut s,
                t,
                &crafted(
                    method::ALLOCATE,
                    [5; 12],
                    Some(&name),
                    Some(&nonce),
                    Some(k),
                    false
                )
            )
            .code(),
        438
    );
    // An overlong username (RFC 8489: under 513 bytes) isn't even hashed.
    let long = ticket(UNIX + 3600, "ins", &"r".repeat(600), "p");
    assert_eq!(
        c.ask(
            &mut s,
            t,
            &crafted(
                method::ALLOCATE,
                [6; 12],
                Some(&long),
                Some(&nonce),
                Some(key_of(&long)),
                false
            )
        )
        .code(),
        400
    );
    // And the real thing works.
    assert_eq!(
        c.ask(
            &mut s,
            t,
            &crafted(
                method::ALLOCATE,
                [7; 12],
                Some(&name),
                Some(&nonce),
                Some(k),
                false
            )
        )
        .code(),
        0
    );
}

#[test]
fn malformed_rest_usernames_are_refused_without_a_panic() {
    // STUNner auth_test.go, LiveKit turn_test.go, pion lt_cred_test.go (a colon-less username
    // once panicked there).
    let t = Instant::now();
    let mut s = server(t);
    let mut c = Client::new("198.51.100.1:5000");
    let far = UNIX + 3600;
    for name in [
        String::new(),
        "1790003600".into(),
        format!("{far}:user"),
        format!("user:{far}"),
        format!("{far}:i:r"),
        format!("{far}:i:r:p:extra"),
        format!("{far}::r:p"),
        format!("{far}:i::p"),
        format!("{far}:i:r:"),
        "0:i:r:p".into(),
        "-5:i:r:p".into(),
        "1e9:i:r:p".into(),
        "99999999999999999999999:i:r:p".into(),
    ] {
        let code = c
            .request(&mut s, t, method::ALLOCATE, &name, &[transport()])
            .code();
        assert!(code == 401 || code == 400, "{name:?}: {code}");
    }
    assert_eq!(s.allocations(), 0);
}

#[test]
fn every_unsigned_answer_to_an_unknown_source_is_budgeted() {
    // coturn run_tests_ratelimit_401.sh: 438s count too, not only 401s and Binding answers.
    let t = Instant::now();
    let mut s = server(t);
    let spoofed = Client::new("198.51.100.7:1");
    let forged = crafted(
        method::ALLOCATE,
        [9; 12],
        Some(&user("g1", "p_a")),
        Some("6e0000000-0123456789abcdef"),
        None,
        true,
    );
    let answered = (0..200)
        .filter(|_| !spoofed.send(&mut s, t, &forged).is_empty())
        .count();
    assert_eq!(answered, 64);
    // Signed answers to a client that proved its credentials aren't: they're for a known client.
    let mut c = Client::new("192.0.2.50:1");
    c.allocate(&mut s, t, &user("g1", "p_a"));
    let name = user("g1", "p_a");
    for _ in 0..100 {
        let r = c.request_to(
            &mut s,
            t,
            method::CREATE_PERMISSION,
            &name,
            &[],
            Some(addr("203.0.113.1:1")),
        );
        assert_eq!(r.code(), 403);
    }
}

#[test]
fn a_stream_isnt_budgeted_and_doesnt_spend_its_ips_udp_budget() {
    // A TCP or TLS client's handshake proved its address: nothing it's sent can be aimed at
    // anyone else. A busy one mustn't lock out UDP players behind the same NAT either.
    let t = Instant::now();
    let mut s = server(t);
    let stream = Client::on("198.51.100.7:1", 5);
    let answered = (0u8..200)
        .filter(|&i| !stream.send(&mut s, t, &binding(i)).is_empty())
        .count();
    assert_eq!(answered, 200);
    let udp = Client::new("198.51.100.7:2");
    let answered = (0u8..100)
        .filter(|&i| !udp.send(&mut s, t, &binding(i)).is_empty())
        .count();
    assert_eq!(answered, 64, "the UDP budget at that IP is untouched");
}

// ---------------------------------------------------------------------------------------------
// How Chrome (libwebrtc turn_port.cc) and Firefox (nICEr turn_client_ctx.c) behave.

#[test]
fn every_error_after_authentication_is_signed() {
    // Firefox drops an error with neither a NONCE nor a valid MESSAGE-INTEGRITY and retransmits
    // until the request times out; a timed-out CreatePermission fails its whole allocation.
    let t = Instant::now();
    let mut s = server_with(t, |c| {
        c.max_per_player = 1;
        c.min_port = 50000;
        c.max_port = 50000;
    });
    let mut a = Client::new("198.51.100.1:5000");
    let name = user("g1", "p_a");
    let ra = a.allocate(&mut s, t, &name);
    let checks: Vec<(Reply, u16)> = vec![
        (
            a.request_to(
                &mut s,
                t,
                method::CREATE_PERMISSION,
                &name,
                &[],
                Some(addr("203.0.113.9:1")),
            ),
            403,
        ),
        (
            a.request_to(
                &mut s,
                t,
                method::CREATE_PERMISSION,
                &name,
                &[],
                Some(addr("[2001:db8::1]:1")),
            ),
            443,
        ),
        (
            a.request(&mut s, t, method::ALLOCATE, &name, &[transport()]),
            437,
        ),
        (
            a.request(&mut s, t, method::CREATE_PERMISSION, &name, &[]),
            400,
        ),
        (
            a.request(&mut s, t, method::REFRESH, &user("g2", "p_a"), &[]),
            441,
        ),
    ];
    let mut b = Client::new("198.51.100.2:5000");
    let quota = b.request(&mut s, t, method::ALLOCATE, &name, &[transport()]);
    let mut c = Client::new("198.51.100.3:5000");
    let full = c.request(
        &mut s,
        t,
        method::ALLOCATE,
        &user("g1", "p_c"),
        &[transport()],
    );
    let mut d = Client::new("198.51.100.4:5000");
    let udp_only = d.request(
        &mut s,
        t,
        method::ALLOCATE,
        &user("g1", "p_d"),
        &[(attr::REQUESTED_TRANSPORT, vec![6, 0, 0, 0])],
    );
    let family = d.request(
        &mut s,
        t,
        method::ALLOCATE,
        &user("g1", "p_d"),
        &[
            transport(),
            (attr::REQUESTED_ADDRESS_FAMILY, vec![2, 0, 0, 0]),
        ],
    );
    for (r, code) in &checks {
        assert_eq!(r.code(), *code);
        let who = if *code == 441 {
            user("g2", "p_a")
        } else {
            name.clone()
        };
        assert!(signed_by(r, &who), "{code} isn't signed");
    }
    assert_eq!(quota.code(), 486);
    assert!(signed_by(&quota, &name));
    assert_eq!(full.code(), 508);
    assert!(signed_by(&full, &user("g1", "p_c")));
    assert_eq!(udp_only.code(), 442);
    assert!(signed_by(&udp_only, &user("g1", "p_d")));
    assert_eq!(family.code(), 440);
    assert!(signed_by(&family, &user("g1", "p_d")));
    let _ = ra;
}

#[test]
fn an_unauthenticated_allocate_on_an_allocated_5_tuple_gets_401_not_437() {
    // Chrome's first Allocate has no credentials, and it only accepts 401 or 300 for it.
    let t = Instant::now();
    let mut s = server(t);
    let mut c = Client::new("198.51.100.1:5000");
    c.allocate(&mut s, t, &user("g1", "p_a"));
    let mut req = Vec::new();
    Writer::new(&mut req, method::ALLOCATE, Class::Request, [8; 12])
        .attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
    let r = c.ask(&mut s, t, &req);
    assert_eq!(r.code(), 401);
    assert!(r.msg().has(attr::NONCE));
}

#[test]
fn retransmissions_at_browser_rates_are_harmless() {
    // Chrome sends a request up to 9 times (250 ms doubling), Firefox 7 (100 ms).
    let t = Instant::now();
    let mut s = server(t);
    let (mut a, _, _, rb) = pair(&mut s, t, "g1");
    let name = user("g1", "p_a");
    let pw = pass(&name);
    for (m, attrs, peer) in [
        (method::REFRESH, vec![lifetime(600)], None),
        (method::CREATE_PERMISSION, vec![], Some(rb)),
        (
            method::CHANNEL_BIND,
            vec![(attr::CHANNEL_NUMBER, vec![0x40, 0x07, 0, 0])],
            Some(rb),
        ),
    ] {
        let tx = a.next_tx();
        let req = a.build(m, tx, &name, &pw, "gamerelay", &attrs, peer);
        for i in 0..9 {
            assert_eq!(a.ask(&mut s, t, &req).code(), 0, "method {m:#x}, copy {i}");
        }
    }
    // An Allocate retransmitted 9 times holds one slot, not 9.
    let mut c = Client::new("192.0.2.9:1");
    let p_c = user("g1", "p_c");
    c.request(&mut s, t, method::REFRESH, &p_c, &[]);
    let tx = c.next_tx();
    let alloc = c.build(
        method::ALLOCATE,
        tx,
        &p_c,
        &pass(&p_c),
        "gamerelay",
        &[transport()],
        None,
    );
    for _ in 0..9 {
        assert_eq!(c.ask(&mut s, t, &alloc).code(), 0);
    }
    assert_eq!(s.allocations(), 3);
    for port in 2..9 {
        Client::new(&format!("192.0.2.9:{port}")).allocate(&mut s, t, &p_c);
    }
    // A release retransmitted after it took effect gets a signed 437, and nothing else happens.
    let tx = a.next_tx();
    let release = a.build(
        method::REFRESH,
        tx,
        &name,
        &pw,
        "gamerelay",
        &[lifetime(0)],
        None,
    );
    assert_eq!(a.ask(&mut s, t, &release).code(), 0);
    let again = a.ask(&mut s, t, &release);
    assert_eq!(again.code(), 437);
    assert!(signed_by(&again, &name));
    // And the same 5-tuple can allocate again at once (an ICE restart).
    a.allocate(&mut s, t, &name);
}

#[test]
fn a_firefox_shaped_client_works_on_send_and_data_alone() {
    // Firefox: LIFETIME 3600 on Allocate, FINGERPRINT on every request and indication, and
    // never a ChannelBind: everything goes over Send and Data indications.
    let t = Instant::now();
    let mut s = server(t);
    let (mut a, mut b) = (
        Client::new("198.51.100.1:5000"),
        Client::new("203.0.113.9:6000"),
    );
    let (na, nb) = (user("g1", "p_a"), user("g1", "p_b"));
    let r = a.request(
        &mut s,
        t,
        method::ALLOCATE,
        &na,
        &[transport(), lifetime(3600)],
    );
    assert_eq!(r.msg().u32_attr(attr::LIFETIME), Some(3600));
    let ra = r.msg().xor_address(attr::XOR_RELAYED_ADDRESS).unwrap();
    let rb = b.allocate(&mut s, t, &nb);
    assert_eq!(a.permit(&mut s, t, &na, rb), 0);
    assert_eq!(b.permit(&mut s, t, &nb, ra), 0);
    let (fa, fb) = (a.from, b.from);
    for (from, to_peer, to) in [(&mut a, rb, fb), (&mut b, ra, fa)] {
        let mut ind = Vec::new();
        let tx = from.next_tx();
        Writer::new(&mut ind, method::SEND, Class::Indication, tx)
            .xor_address(attr::XOR_PEER_ADDRESS, to_peer)
            .attr(attr::DATA, b"dtls")
            .fingerprint();
        let got = from.send(&mut s, t, &ind);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, to);
        assert_eq!(
            Message::parse(&got[0].1).unwrap().get(attr::DATA),
            Some(&b"dtls"[..])
        );
    }
    // Its refresh comes 10 s before the end; the grace covers one that's a little later still
    // (with a fresh credential for the same room and player, and a fresh nonce after a 438).
    let late = t + Duration::from_secs(3600 + 30);
    s.tick(late);
    let fresh = ticket(UNIX + 7200, "ins", "g1", "p_a");
    assert_eq!(
        a.request(&mut s, late, method::REFRESH, &fresh, &[lifetime(3600)])
            .code(),
        0
    );
}

#[test]
fn a_channel_bind_refresh_also_refreshes_the_permission() {
    // Chrome stops sending CreatePermission once a channel is bound and refreshes the channel
    // every 4 minutes: that must keep the permission alive too. ChannelData alone doesn't.
    let t = Instant::now();
    let mut s = server(t);
    let (mut a, ra, mut b, rb) = pair(&mut s, t, "g1");
    let (na, nb) = (user("g1", "p_a"), user("g1", "p_b"));
    assert_eq!(a.bind(&mut s, t, &na, 0x4001, rb), 0);
    assert_eq!(b.bind(&mut s, t, &nb, 0x4002, ra), 0);
    let mut now = t;
    for _ in 0..5 {
        now += Duration::from_secs(240);
        // The allocation itself Chrome refreshes a minute before its end.
        assert_eq!(a.request(&mut s, now, method::REFRESH, &na, &[]).code(), 0);
        assert_eq!(b.request(&mut s, now, method::REFRESH, &nb, &[]).code(), 0);
        assert_eq!(a.bind(&mut s, now, &na, 0x4001, rb), 0);
        assert_eq!(b.bind(&mut s, now, &nb, 0x4002, ra), 0);
        assert_eq!(
            a.channel_data(&mut s, now, 0x4001, b"x").len(),
            1,
            "at {:?}",
            now - t
        );
    }
    // Streaming without refreshing: the permission lapses at 300 s, channel or not.
    let stop = now;
    assert_eq!(
        a.channel_data(&mut s, stop + Duration::from_secs(299), 0x4001, b"x")
            .len(),
        1
    );
    assert!(
        a.channel_data(&mut s, stop + Duration::from_secs(301), 0x4001, b"x")
            .is_empty()
    );
}

// ---------------------------------------------------------------------------------------------
// Channels, ChannelData, Send (coturn tests/test_turn_server_send.c, pion turn_test.go).

#[test]
fn channel_number_boundaries() {
    // RFC 8656 narrowed binding to 0x4000–0x4FFF; RFC 5766 (and libwebrtc, pion) allow up to
    // 0x7FFF. We accept the wider range, and never 0x8000 and up, which aren't ChannelData.
    let t = Instant::now();
    let mut s = server(t);
    let (mut a, _, _, rb) = pair(&mut s, t, "g1");
    let na = user("g1", "p_a");
    let peer = |n: u16| SocketAddr::new(public(), rb.port().wrapping_add(n));
    assert_eq!(a.bind(&mut s, t, &na, 0x3FFF, peer(0)), 400);
    assert_eq!(a.bind(&mut s, t, &na, 0x4000, peer(0)), 0);
    assert_eq!(a.bind(&mut s, t, &na, 0x4FFF, peer(1)), 0);
    assert_eq!(a.bind(&mut s, t, &na, 0x5000, peer(2)), 0);
    assert_eq!(a.bind(&mut s, t, &na, 0x7FFF, peer(3)), 0);
    assert_eq!(a.bind(&mut s, t, &na, 0x8000, peer(4)), 400);
    assert!(
        a.send(&mut s, t, &[0x80, 0x00, 0x00, 0x01, 0xAA])
            .is_empty(),
        "0x8000 is neither ChannelData nor STUN"
    );
}

#[test]
fn padded_channel_data_relays_exactly_its_length_and_an_overlong_one_is_dropped() {
    let t = Instant::now();
    let mut s = server(t);
    let (mut a, _, b, rb) = pair(&mut s, t, "g1");
    assert_eq!(a.bind(&mut s, t, &user("g1", "p_a"), 0x4001, rb), 0);
    // pjnath-style clients pad to 4 bytes over UDP too.
    let got = a.send(&mut s, t, &[0x40, 0x01, 0x00, 0x03, b'a', b'b', b'c', 0x00]);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, b.from);
    assert_eq!(
        Message::parse(&got[0].1).unwrap().get(attr::DATA),
        Some(&b"abc"[..])
    );
    assert!(
        a.send(&mut s, t, &[0x40, 0x01, 0x00, 0x09, b'a', b'b'])
            .is_empty()
    );
}

#[test]
fn send_edge_cases() {
    let t = Instant::now();
    let mut s = server(t);
    let (mut a, _, b, rb) = pair(&mut s, t, "g1");
    // Zero-length DATA is relayed.
    let got = a.send_indication(&mut s, t, rb, b"");
    assert_eq!(got.len(), 1);
    assert_eq!(
        Message::parse(&got[0].1).unwrap().get(attr::DATA),
        Some(&b""[..])
    );
    // No DATA, or no peer: dropped silently.
    let mut no_data = Vec::new();
    Writer::new(&mut no_data, method::SEND, Class::Indication, [1; 12])
        .xor_address(attr::XOR_PEER_ADDRESS, rb);
    assert!(a.send(&mut s, t, &no_data).is_empty());
    let mut no_peer = Vec::new();
    Writer::new(&mut no_peer, method::SEND, Class::Indication, [2; 12]).attr(attr::DATA, b"x");
    assert!(a.send(&mut s, t, &no_peer).is_empty());
    // Two peers: the first wins, so a permitted second one can't carry data past a forbidden first.
    let mut two = Vec::new();
    Writer::new(&mut two, method::SEND, Class::Indication, [3; 12])
        .xor_address(attr::XOR_PEER_ADDRESS, addr("203.0.113.1:1"))
        .xor_address(attr::XOR_PEER_ADDRESS, rb)
        .attr(attr::DATA, b"x");
    assert!(a.send(&mut s, t, &two).is_empty());
    // A big datagram (a full DTLS flight and then some) arrives whole.
    let big = vec![7u8; 60_000];
    let got = a.send_indication(&mut s, t, rb, &big);
    assert_eq!(got[0].0, b.from);
    assert_eq!(
        Message::parse(&got[0].1)
            .unwrap()
            .get(attr::DATA)
            .map(<[u8]>::len),
        Some(60_000)
    );
}

#[test]
fn create_permission_with_one_forbidden_peer_installs_nothing() {
    let t = Instant::now();
    let mut s = server(t);
    let (mut a, mut b) = (
        Client::new("198.51.100.1:5000"),
        Client::new("203.0.113.9:6000"),
    );
    let (na, nb) = (user("g1", "p_a"), user("g1", "p_b"));
    let ra = a.allocate(&mut s, t, &na);
    let rb = b.allocate(&mut s, t, &nb);
    assert_eq!(b.permit(&mut s, t, &nb, ra), 0);
    let tx = a.next_tx();
    let mut req = Vec::new();
    Writer::new(&mut req, method::CREATE_PERMISSION, Class::Request, tx)
        .xor_address(attr::XOR_PEER_ADDRESS, rb)
        .xor_address(attr::XOR_PEER_ADDRESS, addr("203.0.113.1:1"))
        .attr(attr::USERNAME, na.as_bytes())
        .attr(attr::REALM, b"gamerelay")
        .attr(attr::NONCE, a.nonce.clone().unwrap().as_bytes())
        .integrity(&key_of(&na));
    assert_eq!(a.ask(&mut s, t, &req).code(), 403);
    assert!(
        a.send_indication(&mut s, t, rb, b"x").is_empty(),
        "the permitted peer wasn't installed either"
    );
}

#[test]
fn a_rebound_port_is_a_stranger() {
    // A NAT rebinding (the client's port changes): the new 5-tuple is a stranger, and gets
    // nothing of the old allocation's.
    let t = Instant::now();
    let mut s = server(t);
    let (_, _, b, rb) = pair(&mut s, t, "g1");
    let rebound = Client::new("198.51.100.1:5001");
    let mut out = Output::default();
    let mut ind = Vec::new();
    Writer::new(&mut ind, method::SEND, Class::Indication, [4; 12])
        .xor_address(attr::XOR_PEER_ADDRESS, rb)
        .attr(attr::DATA, b"x");
    s.handle(t, rebound.from, &ind, &mut out);
    assert!(out.is_empty());
    let _ = b;
}
