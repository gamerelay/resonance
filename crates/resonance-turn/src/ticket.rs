//! Tickets: credentials any trusted issuer mints, checked without a secret shared with it
//! (gamerelay.io's design, "Signed tickets"; docs/PROTOCOL.md, "Tickets").
//!
//! The username carries the issuer's ed25519 signature, so the node checks who minted it. The
//! password comes from key agreement: the ticket holds a fresh X25519 public key (`eph`), the
//! issuer derives each node's password from it and the node's sealing key, and the node derives
//! the same one from its sealing secret. Nobody who only sees the username can compute it.
//!
//! ```text
//! username  t1:<expiry>:<instance>:<room>:<player>:<kid>:<eph>:<sig>
//! sig       ed25519(issuer, DOMAIN + everything before ":<sig>")
//! password  base64url(HMAC-SHA256(X25519(eph, node seal key), DOMAIN + the same))
//! ```

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::auth::User;

pub const PREFIX: &str = "t1:";
/// A ticket lasts at most a day: an issuer can't mint one that outlives a revoked key by long.
pub const MAX_LIFETIME_S: u64 = 86_400;
/// How far ahead of this node an issuer's clock may be, on top of `MAX_LIFETIME_S`.
pub const SKEW_S: u64 = 300;
const DOMAIN: &[u8] = b"resonance/ticket/v1\n";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// An issuer's key id: base64url of the first 8 bytes of SHA-256(public key).
pub fn kid(public: &[u8; 32]) -> String {
    B64.encode(&Sha256::digest(public)[..8])
}

/// An issuer this node trusts.
#[derive(Clone, Debug)]
pub struct Issuer {
    pub kid: String,
    key: VerifyingKey,
}

impl Issuer {
    pub fn new(public: &[u8; 32]) -> Option<Issuer> {
        Some(Issuer {
            kid: kid(public),
            key: VerifyingKey::from_bytes(public).ok()?,
        })
    }

    /// From base64url (no padding), as settings and the control plane give it.
    pub fn parse(public: &str) -> Option<Issuer> {
        Issuer::new(&B64.decode(public).ok()?.try_into().ok()?)
    }
}

/// A node's sealing secret, from its ed25519 seed: HMAC-SHA256(seed, "resonance/seal/v1"). A
/// separate key, so no new file to keep.
pub fn seal_secret(node_seed: &[u8; 32]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(node_seed).expect("any key length");
    mac.update(b"resonance/seal/v1");
    mac.finalize().into_bytes().into()
}

/// What the node publishes, for issuers to derive its passwords with.
pub fn seal_public(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// A parsed ticket; nothing checked yet.
pub struct Ticket<'a> {
    pub expiry: u64,
    instance: &'a str,
    room: &'a str,
    player: &'a str,
    pub kid: &'a str,
    eph: [u8; 32],
    sig: Signature,
    /// Everything the signature covers, after DOMAIN.
    signed: &'a str,
}

/// A `t1:` username, well formed (every part non-empty), or none.
pub fn parse(username: &str) -> Option<Ticket<'_>> {
    let rest = username.strip_prefix(PREFIX)?;
    let (signed_rest, sig) = rest.rsplit_once(':')?;
    let mut p = signed_rest.split(':');
    let (expiry, instance, room, player, kid, eph) = (
        p.next()?,
        p.next()?,
        p.next()?,
        p.next()?,
        p.next()?,
        p.next()?,
    );
    if p.next().is_some() || [instance, room, player, kid].iter().any(|s| s.is_empty()) {
        return None;
    }
    let sig: [u8; 64] = B64.decode(sig).ok()?.try_into().ok()?;
    Some(Ticket {
        expiry: expiry.parse().ok()?,
        instance,
        room,
        player,
        kid,
        eph: B64.decode(eph).ok()?.try_into().ok()?,
        sig: Signature::from_bytes(&sig),
        signed: &username[..PREFIX.len() + signed_rest.len()],
    })
}

impl Ticket<'_> {
    /// Who it names, scoped by its issuer: another issuer can't mint into this one's rooms.
    pub fn user(&self) -> User {
        let instance = format!("{}/{}", self.kid, self.instance);
        User {
            expiry: self.expiry,
            room: format!("{instance}:{}", self.room),
            player: format!("{instance}:{}", self.player),
            instance,
        }
    }

    /// Minted by one of these.
    pub fn verify(&self, issuers: &[Issuer]) -> bool {
        issuers.iter().filter(|i| i.kid == self.kid).any(|i| {
            i.key
                .verify_strict(&message(self.signed), &self.sig)
                .is_ok()
        })
    }

    /// This node's password for it, or none if `eph` is a key that gives no secret.
    pub fn password(&self, seal_secret: &[u8; 32]) -> Option<String> {
        let shared = StaticSecret::from(*seal_secret).diffie_hellman(&PublicKey::from(self.eph));
        shared
            .was_contributory()
            .then(|| password_from(shared.as_bytes(), self.signed))
    }
}

fn message(signed: &str) -> Vec<u8> {
    [DOMAIN, signed.as_bytes()].concat()
}

fn password_from(shared: &[u8; 32], signed: &str) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(shared).expect("any key length");
    mac.update(&message(signed));
    B64.encode(mac.finalize().into_bytes())
}

/// What an issuer mints: one username for every node, and each node's password from it.
pub struct Minted {
    pub username: String,
    eph: StaticSecret,
    signed_len: usize,
}

/// Mints a ticket. `eph_secret` must be fresh random bytes for each ticket. The parts must be
/// non-empty and colon-free.
pub fn mint(
    issuer: &SigningKey,
    eph_secret: [u8; 32],
    expiry: u64,
    instance: &str,
    room: &str,
    player: &str,
) -> Minted {
    let eph = StaticSecret::from(eph_secret);
    let signed = format!(
        "{PREFIX}{expiry}:{instance}:{room}:{player}:{}:{}",
        kid(&issuer.verifying_key().to_bytes()),
        B64.encode(PublicKey::from(&eph).as_bytes()),
    );
    let sig = issuer.sign(&message(&signed));
    Minted {
        username: format!("{signed}:{}", B64.encode(sig.to_bytes())),
        eph,
        signed_len: signed.len(),
    }
}

impl Minted {
    /// The password for the node whose sealing key this is.
    pub fn password(&self, node_seal_public: &[u8; 32]) -> String {
        let shared = self.eph.diffie_hellman(&PublicKey::from(*node_seal_public));
        password_from(shared.as_bytes(), &self.username[..self.signed_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer() -> SigningKey {
        SigningKey::from_bytes(&[1; 32])
    }

    // The same values as gamerelay.io apps/server/test/turn.test.ts: what the control plane mints,
    // the node accepts.
    #[test]
    fn fixture_shared_with_the_control_plane() {
        let seal = seal_secret(&[7; 32]);
        assert_eq!(
            B64.encode(issuer().verifying_key().to_bytes()),
            "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"
        );
        assert_eq!(
            B64.encode(seal_public(&seal)),
            "_1XQc9Vk2S2KlA8GlnTSxeDhMe3CwYq-383J2nCL7V8"
        );
        let m = mint(&issuer(), [3; 32], 1790000000, "ins_x", "g1", "p1");
        assert_eq!(
            m.username,
            "t1:1790000000:ins_x:g1:p1:NHUPmL1Z_Pw:Xf7dO2vUf2-ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI:\
             cXuVnphwjGWacAMAD-2Fa9CV27VN59F4ccjIghbGr1eUlbh9jpvn2EoKz728Cry6iJubi7VlAoEzbuI3A7V3AQ"
        );
        let password = m.password(&seal_public(&seal));
        assert_eq!(password, "8dlvZZektqxUYgGG5LqPm_r5qYpR38zt1KJZ_X55msw");
        let t = parse(&m.username).unwrap();
        assert!(t.verify(&[Issuer::new(&issuer().verifying_key().to_bytes()).unwrap()]));
        assert_eq!(t.password(&seal).unwrap(), password);
    }

    #[test]
    fn the_node_derives_the_issuers_password() {
        let seal = seal_secret(&[9; 32]);
        let m = mint(&issuer(), [4; 32], 100, "ins_a", "room", "me");
        let t = parse(&m.username).unwrap();
        assert_eq!(t.password(&seal), Some(m.password(&seal_public(&seal))));
        // Another node's sealing key gives another password.
        let other = seal_secret(&[10; 32]);
        assert_ne!(t.password(&other), Some(m.password(&seal_public(&seal))));
    }

    #[test]
    fn rooms_are_scoped_by_issuer() {
        let a = mint(&issuer(), [4; 32], 100, "ins_a", "room", "me");
        let b = mint(
            &SigningKey::from_bytes(&[2; 32]),
            [4; 32],
            100,
            "ins_a",
            "room",
            "me",
        );
        let (ua, ub) = (
            parse(&a.username).unwrap().user(),
            parse(&b.username).unwrap().user(),
        );
        assert_ne!(ua.room, ub.room);
        assert_ne!(ua.player, ub.player);
        assert!(ua.room.starts_with(&format!(
            "{}/ins_a:",
            kid(&issuer().verifying_key().to_bytes())
        )));
    }

    #[test]
    fn only_a_trusted_issuers_untampered_ticket_verifies() {
        let trusted = [Issuer::new(&issuer().verifying_key().to_bytes()).unwrap()];
        let m = mint(&issuer(), [4; 32], 100, "ins_a", "room", "me");
        assert!(parse(&m.username).unwrap().verify(&trusted));
        let stranger = mint(
            &SigningKey::from_bytes(&[2; 32]),
            [4; 32],
            100,
            "ins_a",
            "room",
            "me",
        );
        assert!(!parse(&stranger.username).unwrap().verify(&trusted));
        assert!(!parse(&m.username).unwrap().verify(&[]));
        // Any change to the signed part: another room, a later expiry, another eph.
        for (from, to) in [
            (":room:", ":roon:"),
            ("t1:100:", "t1:900:"),
            (":me:", ":mf:"),
        ] {
            let tampered = m.username.replacen(from, to, 1);
            assert!(!parse(&tampered).unwrap().verify(&trusted), "{tampered}");
        }
        // A stranger's ticket relabelled with the trusted kid.
        let relabelled =
            stranger
                .username
                .replacen(parse(&stranger.username).unwrap().kid, &trusted[0].kid, 1);
        assert!(!parse(&relabelled).unwrap().verify(&trusted));
    }

    #[test]
    fn malformed_tickets_dont_parse() {
        let m = mint(&issuer(), [4; 32], 100, "ins_a", "room", "me");
        let parts: Vec<&str> = m.username.split(':').collect();
        let with = |i: usize, v: &str| {
            let mut p = parts.clone();
            p[i] = v;
            p.join(":")
        };
        assert!(parse(&m.username).is_some());
        for bad in [
            String::new(),
            "t1:".into(),
            m.username.replacen("t1:", "t2:", 1),
            with(1, "soon"),
            with(2, ""),
            with(3, ""),
            with(4, ""),
            with(5, ""),
            with(6, "short"),
            with(7, "short"),
            format!("{}:extra", m.username),
        ] {
            assert!(parse(&bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn a_low_order_eph_gives_no_password() {
        let m = mint(&issuer(), [4; 32], 100, "ins_a", "room", "me");
        let parts: Vec<&str> = m.username.split(':').collect();
        let zero = B64.encode([0u8; 32]);
        let username = [&parts[..6], &[zero.as_str()], &parts[7..]]
            .concat()
            .join(":");
        assert_eq!(
            parse(&username).unwrap().password(&seal_secret(&[9; 32])),
            None
        );
    }
}
