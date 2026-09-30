//! Resonance's control-plane protocol (v0 §2), as the node speaks it. The control plane's side is
//! gamerelay.io `apps/server/src/resonance.ts`; the fixtures in the tests below are checked there
//! too (`test/resonance.test.ts`), so the two can't drift.
//!
//! Every request after `join` is signed with the node's ed25519 key: `Resonance-Sig` (base64url)
//! over [`signing_string`], with `Resonance-Node`, `Resonance-Ts` (unix ms) and
//! `Resonance-Version`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The API version this build speaks (§5). A node is pinned to the one it joined with.
pub const VERSION: &str = "2026-09-29";
/// Under the control plane's URL.
pub const BASE: &str = "/resonance/v0";

pub mod header {
    pub const NODE: &str = "resonance-node";
    pub const TS: &str = "resonance-ts";
    pub const SIG: &str = "resonance-sig";
    pub const VERSION: &str = "resonance-version";
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// `rn_` + base32 (lowercase, no padding) of the first 16 bytes of SHA-256(public key).
pub fn node_id(pubkey: &[u8; 32]) -> String {
    let digest = Sha256::digest(pubkey);
    let mut out = String::from("rn_");
    let (mut bits, mut value) = (0u32, 0u32);
    for &b in &digest[..16] {
        value = (value << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(B32[((value >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(B32[((value << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// What a node signs: `method \n path \n version \n ts \n hex(sha256(body))`. `path` is under
/// [`BASE`] (e.g. `/nodes/heartbeat`).
pub fn signing_string(method: &str, path: &str, version: &str, ts: &str, body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    let mut hex = String::with_capacity(64);
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("{method}\n{path}\n{version}\n{ts}\n{hex}")
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct JoinRequest {
    pub token: String,
    /// ed25519, base64url (no padding), 32 bytes.
    pub pubkey: String,
    /// Where players reach it: `turn:ip:port`.
    pub urls: Vec<String>,
    pub software: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct JoinResponse {
    pub node_id: String,
    pub region: String,
    pub heartbeat_s: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct KeyResponse {
    /// This node's own key: it mints credentials for this node only.
    pub node_key: String,
    pub key_version: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Heartbeat {
    pub allocations: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Cores in use since the last heartbeat (0.5: half a core).
    pub cpu: f64,
    pub uptime_s: u64,
    pub software: String,
    /// Where players reach it, as at join: so a node that starts serving TCP or TLS says so
    /// without joining again. An addition within 2026-09-29 (servers that don't know it ignore it).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    /// How the other nodes it was told about answer it: a STUN Binding every few seconds from
    /// its relay socket, over the last 30 s. An addition within 2026-09-29.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<PeerReport>,
}

/// One peer's Bindings over the report's window.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct PeerReport {
    pub node: String,
    /// Sent long enough ago to have been answered.
    pub sent: u32,
    pub answered: u32,
    /// The median round trip of the answered ones, in ms; none if nothing was answered.
    pub rtt_ms: Option<f64>,
}

/// Another node to measure: its id, and the address its relay socket answers on.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Peer {
    pub node_id: String,
    pub addr: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Handed out to players.
    Active,
    /// No new allocations; exits once its allocations end.
    Draining,
    /// Stops at once.
    Revoked,
    /// Its API version is below the control plane's `min_version`: no new allocations.
    UpgradeRequired,
    /// A status from a newer control plane: carry on as before (§5, additive changes).
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HeartbeatResponse {
    pub status: Status,
    pub key_version: u32,
    pub latest_version: String,
    pub min_version: String,
    /// The other nodes to measure. An addition within 2026-09-29: a control plane that doesn't
    /// send it means none.
    #[serde(default)]
    pub peers: Vec<Peer>,
}

/// An error answer: `{ error, message }`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(default)]
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // The same values as gamerelay.io test/resonance.test.ts.
    #[test]
    fn fixture_shared_with_the_control_plane() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let pubkey = key.verifying_key().to_bytes();
        assert_eq!(
            B64.encode(pubkey),
            "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"
        );
        assert_eq!(node_id(&pubkey), "rn_72asyextvngonlc5w2nmguxzay");
        let s = signing_string(
            "POST",
            "/nodes/heartbeat",
            "2026-09-29",
            "1790000000000",
            br#"{"allocations":1}"#,
        );
        assert_eq!(
            s,
            "POST\n/nodes/heartbeat\n2026-09-29\n1790000000000\ne642ae3d166a3aea3e157e40308fa606bbe0775f221813a6bbc845f4513f8e17"
        );
        assert_eq!(
            B64.encode(key.sign(s.as_bytes()).to_bytes()),
            "4ouzZqtxvtuhwCVpoFdbIPlXyqwSQibcBU0iJUVZIS9U6-454Juxtd9lAfd5pSrSVOwXx4N60C_qPwuzXlWNCA"
        );
    }

    // The same JSON as gamerelay.io test/resonance.test.ts: what one side writes, the other reads.
    #[test]
    fn peers_fixture_shared_with_the_control_plane() {
        let h = Heartbeat {
            allocations: 1,
            software: "resonance-node 0.1.0".into(),
            peers: vec![
                PeerReport {
                    node: "rn_b".into(),
                    sent: 14,
                    answered: 13,
                    rtt_ms: Some(62.5),
                },
                PeerReport {
                    node: "rn_c".into(),
                    sent: 14,
                    answered: 0,
                    rtt_ms: None,
                },
            ],
            ..Heartbeat::default()
        };
        assert_eq!(
            serde_json::to_string(&h).unwrap(),
            r#"{"allocations":1,"bytes_in":0,"bytes_out":0,"cpu":0.0,"uptime_s":0,"software":"resonance-node 0.1.0","peers":[{"node":"rn_b","sent":14,"answered":13,"rtt_ms":62.5},{"node":"rn_c","sent":14,"answered":0,"rtt_ms":null}]}"#
        );
        let r: HeartbeatResponse = serde_json::from_str(r#"{"status":"active","key_version":0,"latest_version":"2026-09-29","min_version":"2026-09-29","peers":[{"node_id":"rn_b","addr":"198.51.100.2:3478"}]}"#).unwrap();
        assert_eq!(
            r.peers,
            vec![Peer {
                node_id: "rn_b".into(),
                addr: "198.51.100.2:3478".into()
            }]
        );
    }

    #[test]
    fn a_status_from_a_newer_control_plane_is_unknown_not_an_error() {
        let r: HeartbeatResponse = serde_json::from_str(r#"{"status":"paused","key_version":0,"latest_version":"2027-01-01","min_version":"2026-09-29","extra":1}"#).unwrap();
        assert_eq!(r.status, Status::Unknown);
        let r: HeartbeatResponse = serde_json::from_str(r#"{"status":"upgrade_required","key_version":2,"latest_version":"x","min_version":"y"}"#).unwrap();
        assert_eq!((r.status, r.key_version), (Status::UpgradeRequired, 2));
    }
}
