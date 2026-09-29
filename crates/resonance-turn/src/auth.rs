//! Credentials: TURN REST style (draft-uberti-behave-turn-rest), minted by the control plane with
//! this node's own key (Resonance v0 §3). Username `expiry:instance:roomGroup:player`, password
//! base64(HMAC-SHA1(node key, username)).

use std::net::{IpAddr, SocketAddr};

use base64::Engine;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::Sha256;

/// Who a signed username names. The room and the player are scoped to the instance, so two games'
/// rooms never collide.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub expiry: u64,
    pub instance: String,
    pub room: String,
    pub player: String,
}

/// `expiry:instance:roomGroup:player`, every part non-empty (the control plane keeps colons out of
/// each, apps/server/src/turn.ts). Same rule as the Go relay's parseUsername.
pub fn parse_username(username: &str) -> Option<User> {
    let mut p = username.split(':');
    let (expiry, instance, room, player) = (p.next()?, p.next()?, p.next()?, p.next()?);
    if p.next().is_some() || instance.is_empty() || room.is_empty() || player.is_empty() {
        return None;
    }
    Some(User {
        expiry: expiry.parse().ok()?,
        instance: instance.to_owned(),
        room: format!("{instance}:{room}"),
        player: format!("{instance}:{player}"),
    })
}

/// The password the control plane minted for username: base64(HMAC-SHA1(node key, username)).
pub fn password(node_key: &str, username: &str) -> String {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(node_key.as_bytes()).expect("any key length");
    mac.update(username.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// The long-term credential key, MD5(username ":" realm ":" password) (RFC 8489 §9.2.2).
pub fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(username.as_bytes());
    h.update(b":");
    h.update(realm.as_bytes());
    h.update(b":");
    h.update(password.as_bytes());
    h.finalize().into()
}

/// Nonces need no state: the time they lapse and a MAC over it and the client's address, with a
/// key made at startup. `<expiry hex>-<16 hex of HMAC-SHA256(key, expiry, ip, port)>`. Bound to
/// the address, so a nonce seen on the wire is no use from anywhere else (a browser that changes
/// its source port starts over unauthenticated anyway).
pub struct Nonces {
    key: [u8; 32],
    pub lifetime_s: u64,
}

impl Nonces {
    pub fn new(key: [u8; 32]) -> Self {
        Nonces {
            key,
            lifetime_s: 3600,
        }
    }

    fn mac(&self, expiry: u64, client: SocketAddr) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("any key length");
        mac.update(&expiry.to_be_bytes());
        match client.ip().to_canonical() {
            IpAddr::V4(ip) => mac.update(&ip.octets()),
            IpAddr::V6(ip) => mac.update(&ip.octets()),
        }
        mac.update(&client.port().to_be_bytes());
        let sum = mac.finalize().into_bytes();
        sum[..8].iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn issue(&self, unix_now: u64, client: SocketAddr) -> String {
        let expiry = unix_now + self.lifetime_s;
        format!("{expiry:x}-{}", self.mac(expiry, client))
    }

    /// Ours, for this client, and unexpired. Ours but expired is `Stale` (the client retries
    /// with a fresh one); anything else, another client's included, is `Bad`.
    pub fn check(&self, nonce: &str, unix_now: u64, client: SocketAddr) -> NonceCheck {
        let Some((exp, mac)) = nonce.split_once('-') else {
            return NonceCheck::Bad;
        };
        let Ok(expiry) = u64::from_str_radix(exp, 16) else {
            return NonceCheck::Bad;
        };
        // A nonce isn't a credential, so timing here gives nothing away.
        if mac != self.mac(expiry, client) {
            return NonceCheck::Bad;
        }
        if expiry <= unix_now {
            NonceCheck::Stale
        } else {
            NonceCheck::Ok
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum NonceCheck {
    Ok,
    Stale,
    Bad,
}

#[cfg(test)]
mod tests {
    use super::*;

    // The same strings as apps/server/test/turn.test.ts and deploy/turn/cred_test.go
    // TestNodeKeyFixture: the control plane and this node can't drift.
    #[test]
    fn password_fixture_shared_with_the_control_plane() {
        let key = "fiahLYMg85YkiFJQ0Xp3Bl0x3pXkUhI4nMU8jj6QRio";
        assert_eq!(
            password(key, "1790000000:ins_x:2900f54a5bbdef76:be6f68eaf1fb826e"),
            "yb01xn6ocyuqIri2RKNgzOKQ9QA="
        );
        assert_eq!(
            password("test-secret-0123456789abcdef0123456789", "1790000000:p_abc"),
            "jLQpVvRbo3RM7CTKVTkvHGEJnVM="
        );
    }

    // The Go relay's TestParseUsername cases.
    #[test]
    fn usernames() {
        let u = parse_username("1790000000:ins_x:2900f54a5bbdef76:be6f68eaf1fb826e").unwrap();
        assert_eq!(u.expiry, 1790000000);
        assert_eq!(u.instance, "ins_x");
        assert_eq!(u.room, "ins_x:2900f54a5bbdef76");
        assert_eq!(u.player, "ins_x:be6f68eaf1fb826e");
        for bad in [
            "",
            "1:p_abc",
            "1:ins:g1",
            "1:ins:g1:p:x",
            "1::g1:p",
            "1:ins::p",
            "1:ins:g1:",
            "soon:ins:g1:p",
            "-1:ins:g1:p",
        ] {
            assert!(parse_username(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn nonces() {
        let n = Nonces::new([9; 32]);
        let me: SocketAddr = "198.51.100.1:5000".parse().unwrap();
        let nonce = n.issue(1000, me);
        assert_eq!(n.check(&nonce, 1000, me), NonceCheck::Ok);
        assert_eq!(
            n.check(&nonce, 1000, "[::ffff:198.51.100.1]:5000".parse().unwrap()),
            NonceCheck::Ok,
            "IPv4-mapped is the same client"
        );
        assert_eq!(n.check(&nonce, 1000 + 3600, me), NonceCheck::Stale);
        assert_eq!(
            Nonces::new([8; 32]).check(&nonce, 1000, me),
            NonceCheck::Bad,
            "another node's"
        );
        assert_eq!(
            n.check(&nonce, 1000, "198.51.100.2:5000".parse().unwrap()),
            NonceCheck::Bad,
            "another IP"
        );
        assert_eq!(
            n.check(&nonce, 1000, "198.51.100.1:5001".parse().unwrap()),
            NonceCheck::Bad,
            "another port"
        );
        for i in 0..nonce.len() {
            let mut b = nonce.clone().into_bytes();
            b[i] = if b[i] == b'0' { b'1' } else { b'0' };
            let tampered = String::from_utf8(b).unwrap();
            assert_ne!(n.check(&tampered, 1000, me), NonceCheck::Ok, "{tampered}");
        }
        for bad in [
            "",
            "x",
            "abc-def",
            "e10-0000000000000000",
            "ffffffffffffffffff-00",
        ] {
            assert_eq!(n.check(bad, 1000, me), NonceCheck::Bad);
        }
    }

    #[test]
    fn long_term_key_is_md5_of_user_realm_password() {
        let mut h = Md5::new();
        h.update(b"user:realm:pass");
        let want: [u8; 16] = h.finalize().into();
        assert_eq!(long_term_key("user", "realm", "pass"), want);
    }
}
