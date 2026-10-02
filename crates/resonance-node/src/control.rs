//! The control plane, as a node talks to it (v0 §2): join once, then send a heartbeat every
//! 15 s. Signed requests over HTTPS; the relay loop never waits on any of it.

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use resonance_turn::ticket;
use std::net::SocketAddr;

use resonance_proto::{
    self as proto, ErrorResponse, Heartbeat, HeartbeatResponse, JoinRequest, JoinResponse, Peer,
    PeerReport, Status,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub struct Client {
    agent: ureq::Agent,
    control: String,
    key: SigningKey,
    node_id: Option<String>,
    version: String,
}

#[derive(Debug)]
pub enum Error {
    /// The control plane said no: its `{ error, message }`.
    Refused {
        status: u16,
        error: String,
        message: String,
    },
    /// Couldn't reach it, or its answer made no sense.
    Transport(String),
}

impl Error {
    /// The control plane is out of reach, as against saying no: a network error, or a 5xx from
    /// whatever stands in front of it.
    pub fn unreachable(&self) -> bool {
        match self {
            Error::Transport(_) => true,
            Error::Refused { status, .. } => *status >= 500,
        }
    }
}

impl Error {
    /// The control plane says it has no such node (`unknown_node`).
    pub fn unknown_node(&self) -> bool {
        matches!(self, Error::Refused { status: 401, error, .. } if error == "unknown_node")
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Refused {
                status,
                error,
                message,
            } => write!(f, "{status} {error}: {message}"),
            Error::Transport(e) => write!(f, "{e}"),
        }
    }
}

impl Client {
    pub fn new(control: &str, key: SigningKey, node_id: Option<String>, version: &str) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(10)))
            .user_agent(concat!("resonance-node/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Client {
            agent,
            control: control.trim_end_matches('/').to_owned(),
            key,
            node_id,
            version: version.to_owned(),
        }
    }

    fn post<B: Serialize, R: DeserializeOwned>(&self, path: &str, body: &B) -> Result<R, Error> {
        let text = serde_json::to_vec(body).map_err(|e| Error::Transport(e.to_string()))?;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
            .to_string();
        let sig = self
            .key
            .sign(proto::signing_string("POST", path, &self.version, &ts, &text).as_bytes());
        let mut req = self
            .agent
            .post(format!("{}{}{}", self.control, proto::BASE, path))
            .header("content-type", "application/json")
            .header(proto::header::TS, &ts)
            .header(proto::header::SIG, B64.encode(sig.to_bytes()))
            .header(proto::header::VERSION, &self.version);
        if let Some(id) = &self.node_id {
            req = req.header(proto::header::NODE, id);
        }
        let mut res = req
            .send(&text[..])
            .map_err(|e| Error::Transport(e.to_string()))?;
        let status = res.status().as_u16();
        let body = res
            .body_mut()
            .read_to_string()
            .map_err(|e| Error::Transport(e.to_string()))?;
        if status != 200 {
            let e: ErrorResponse = serde_json::from_str(&body).unwrap_or(ErrorResponse {
                error: "http".into(),
                message: body.chars().take(200).collect(),
            });
            return Err(Error::Refused {
                status,
                error: e.error,
                message: e.message,
            });
        }
        serde_json::from_str(&body).map_err(|e| Error::Transport(format!("{path}: {e}")))
    }

    /// This node's sealing key (`resonance_turn::ticket`), base64url: issuers derive its ticket
    /// passwords with it. From its ed25519 seed, so it's the same at every start.
    pub fn seal_public(&self) -> String {
        B64.encode(ticket::seal_public(&ticket::seal_secret(
            &self.key.to_bytes(),
        )))
    }

    pub fn join(&self, token: &str, urls: Vec<String>) -> Result<JoinResponse, Error> {
        let req = JoinRequest {
            token: token.into(),
            pubkey: B64.encode(self.key.verifying_key().to_bytes()),
            urls,
            software: software(),
            seal_key: Some(self.seal_public()),
        };
        self.post("/nodes/join", &req)
    }

    pub fn heartbeat(&self, h: &Heartbeat) -> Result<HeartbeatResponse, Error> {
        self.post("/nodes/heartbeat", h)
    }

    /// One line to a Discord (`content`) or Slack (`text`) incoming webhook; each ignores the
    /// other. Best effort: a webhook that's down loses the alert.
    pub fn post_alert(&self, webhook: &str, text: &str) {
        let body = serde_json::json!({ "content": text, "text": text }).to_string();
        let sent = self
            .agent
            .post(webhook)
            .header("content-type", "application/json")
            .send(body.as_bytes());
        if let Err(e) = sent {
            eprintln!("alert webhook: {e}");
        }
    }
}

pub fn software() -> String {
    concat!("resonance-node ", env!("CARGO_PKG_VERSION")).into()
}

/// What the heartbeat thread tells the relay loop.
#[derive(Debug, PartialEq)]
pub enum Control {
    /// Take new allocations (true), or stop (false: draining, or told to upgrade).
    Accepting(bool),
    /// The other nodes to measure (`probe`).
    Peers(Vec<(String, SocketAddr)>),
    /// Whose tickets to accept: this node's own `RESONANCE_ISSUERS` and the control plane's, as
    /// base64url public keys, each one a valid key.
    Issuers(Vec<String>),
    /// Revoked: stop now.
    Exit,
}

/// The relay loop's numbers, for the heartbeat.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub allocations: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub peers: Vec<PeerReport>,
}

/// This process's CPU seconds so far (user + system).
fn cpu_seconds() -> f64 {
    // SAFETY: getrusage fills the struct we pass; RUSAGE_SELF is always valid.
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) } != 0 {
        return 0.0;
    }
    let t = |v: libc::timeval| v.tv_sec as f64 + v.tv_usec as f64 / 1e6;
    t(u.ru_utime) + t(u.ru_stime)
}

/// The heartbeat thread's settings.
pub struct Heartbeats {
    pub client: Client,
    pub every: Duration,
    pub snapshot: Arc<Mutex<Snapshot>>,
    pub urls: Vec<String>,
    pub controls: Sender<Control>,
    /// `RESONANCE_ISSUERS`: trusted whatever the control plane says.
    pub local_issuers: Vec<String>,
    /// The issuers the relay loop started with (the local ones and the control plane's last
    /// saved), and where to save the control plane's when they change.
    pub issuers: Vec<String>,
    pub state: crate::state::State,
    /// Where to say the control plane is out of reach (RESONANCE_ALERT_WEBHOOK), and who says it.
    pub alert: Option<(String, Watch)>,
}

impl Heartbeats {
    /// Every `every`, a heartbeat; its answer becomes `Control`s for the relay loop. A control
    /// plane that can't be reached changes nothing: the node keeps relaying what it has.
    pub fn run(mut self) {
        let started = Instant::now();
        let (mut last_cpu, mut last_at) = (cpu_seconds(), Instant::now());
        let mut seen = Seen {
            accepting: true,
            peers: Vec::new(),
            issuers: self.issuers.clone(),
        };
        let seal_key = Some(self.client.seal_public());
        let mut first = true;
        loop {
            // The first at once: a node is handed out to players from its first heartbeat.
            if !first {
                std::thread::sleep(self.every);
            }
            first = false;
            let snap = self.snapshot.lock().map(|s| s.clone()).unwrap_or_default();
            let (cpu, at) = (cpu_seconds(), Instant::now());
            let h = Heartbeat {
                allocations: snap.allocations,
                bytes_in: snap.bytes_in,
                bytes_out: snap.bytes_out,
                cpu: (cpu - last_cpu) / at.duration_since(last_at).as_secs_f64().max(0.001),
                uptime_s: started.elapsed().as_secs(),
                software: software(),
                urls: self.urls.clone(),
                peers: snap.peers,
                seal_key: seal_key.clone(),
            };
            (last_cpu, last_at) = (cpu, at);
            let result = self.client.heartbeat(&h);
            if let Some((webhook, watch)) = &mut self.alert {
                let said = match &result {
                    Err(e) if e.unreachable() => watch.failed(Instant::now(), &e.to_string()),
                    _ => watch.ok(Instant::now()),
                };
                if let Some(text) = said {
                    self.client.post_alert(webhook, &text);
                }
            }
            let reply = match result {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("heartbeat: {e}");
                    if let Some(c) = decide_error(&e, &mut seen) {
                        if self.controls.send(c).is_err() {
                            return;
                        }
                    }
                    continue;
                }
            };
            for c in decide(&reply, &mut seen, &self.local_issuers) {
                // Only the control plane's: the node's own come from RESONANCE_ISSUERS at each
                // start, so one taken out of it isn't kept trusted by the file.
                if let Control::Issuers(keys) = &c {
                    let theirs: Vec<String> = keys
                        .iter()
                        .filter(|k| !self.local_issuers.contains(k))
                        .cloned()
                        .collect();
                    if let Err(e) = self.state.save_issuers(&theirs) {
                        eprintln!("saving the issuers: {e}");
                    }
                }
                let exit = c == Control::Exit;
                if self.controls.send(c).is_err() || exit {
                    return;
                }
            }
        }
    }
}

/// The most other nodes a node measures.
pub const MAX_PEERS: usize = 64;

/// An address a peer node could have: not unspecified, multicast or broadcast, and with a port.
fn probeable(ip: std::net::IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !matches!(ip, std::net::IpAddr::V4(v4) if v4.is_broadcast())
}

/// What the relay loop was last told.
struct Seen {
    accepting: bool,
    peers: Vec<Peer>,
    issuers: Vec<String>,
}

/// What a refused heartbeat means for the relay loop. Deleted from the registry (while offline,
/// so it never heard it was revoked): no new allocations until the control plane knows it again,
/// and the ones in use carry on. Not an exit: a control plane that lost its registry would
/// otherwise stop every node.
fn decide_error(e: &Error, seen: &mut Seen) -> Option<Control> {
    if !e.unknown_node() || !seen.accepting {
        return None;
    }
    eprintln!("the control plane doesn't know this node: no new allocations");
    seen.accepting = false;
    Some(Control::Accepting(false))
}

/// What one heartbeat answer means for the relay loop.
fn decide(reply: &HeartbeatResponse, seen: &mut Seen, local_issuers: &[String]) -> Vec<Control> {
    let mut out = Vec::new();
    let want = match reply.status {
        Status::Revoked => {
            eprintln!("revoked by the control plane: stopping");
            return vec![Control::Exit];
        }
        Status::Active => true,
        Status::Draining => false,
        Status::UpgradeRequired => {
            eprintln!(
                "the control plane needs API {} or later; this build speaks {}: taking no new allocations",
                reply.min_version,
                proto::VERSION
            );
            false
        }
        Status::Unknown => seen.accepting,
    };
    if want != seen.accepting {
        eprintln!(
            "{}",
            if want {
                "active: taking new allocations"
            } else {
                "draining: no new allocations"
            }
        );
        seen.accepting = want;
        out.push(Control::Accepting(want));
    }
    if reply.peers != seen.peers {
        seen.peers = reply.peers.clone();
        // Probes go every 2 s to each: so at most MAX_PEERS of them, and only to addresses a
        // node could have, whatever the control plane says.
        let peers = reply
            .peers
            .iter()
            .filter_map(|p| Some((p.node_id.clone(), p.addr.parse::<SocketAddr>().ok()?)))
            .filter(|(_, a)| probeable(a.ip()))
            .take(MAX_PEERS)
            .collect::<Vec<_>>();
        eprintln!(
            "measuring {} other node{}",
            peers.len(),
            if peers.len() == 1 { "" } else { "s" }
        );
        out.push(Control::Peers(peers));
    }
    let mut issuers = local_issuers.to_vec();
    for i in &reply.issuers {
        if ticket::Issuer::parse(&i.pubkey).is_none() {
            eprintln!(
                "the control plane's issuer {:?} isn't an ed25519 key: ignored",
                i.pubkey
            );
        } else if !issuers.contains(&i.pubkey) {
            issuers.push(i.pubkey.clone());
        }
    }
    if issuers != seen.issuers {
        eprintln!(
            "accepting tickets from {} issuer{}",
            issuers.len(),
            if issuers.len() == 1 { "" } else { "s" }
        );
        seen.issuers = issuers.clone();
        out.push(Control::Issuers(issuers));
    }
    out
}

/// Watching the control plane from this node: out of reach for `after` in a row, it's said once,
/// and again when it's back.
pub struct Watch {
    /// Who's saying it: this node's region and id, and the control plane's URL.
    who: String,
    control: String,
    after: Duration,
    down_since: Option<Instant>,
    said: bool,
}

impl Watch {
    pub fn new(who: String, control: String, after: Duration) -> Self {
        Watch {
            who,
            control,
            after,
            down_since: None,
            said: false,
        }
    }

    /// A heartbeat that couldn't reach it: what to say, if it's time.
    pub fn failed(&mut self, now: Instant, why: &str) -> Option<String> {
        let since = *self.down_since.get_or_insert(now);
        if self.said || now - since < self.after {
            return None;
        }
        self.said = true;
        Some(format!(
            "🔴 {} can't reach the control plane {} (for {}): {why}",
            self.who,
            self.control,
            minutes(now - since)
        ))
    }

    /// A heartbeat that got through: what to say, if it had said it was down.
    pub fn ok(&mut self, now: Instant) -> Option<String> {
        let since = self.down_since.take()?;
        std::mem::take(&mut self.said).then(|| {
            format!(
                "🟢 {} reaches the control plane {} again (out of reach for {})",
                self.who,
                self.control,
                minutes(now - since)
            )
        })
    }
}

fn minutes(d: Duration) -> String {
    match d.as_secs() {
        s if s < 90 => format!("{s} s"),
        s => format!("{} min", (s + 30) / 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use resonance_proto::IssuerKey;

    fn reply(status: Status) -> HeartbeatResponse {
        HeartbeatResponse {
            status,
            latest_version: "2026-09-29".into(),
            min_version: "2026-09-29".into(),
            peers: Vec::new(),
            issuers: Vec::new(),
        }
    }
    fn seen() -> Seen {
        Seen {
            accepting: true,
            peers: Vec::new(),
            issuers: Vec::new(),
        }
    }

    #[test]
    fn heartbeat_answers_become_controls() {
        let mut s = seen();
        assert!(decide(&reply(Status::Active), &mut s, &[]).is_empty());
        assert_eq!(
            decide(&reply(Status::Draining), &mut s, &[]),
            vec![Control::Accepting(false)]
        );
        assert!(
            decide(&reply(Status::Draining), &mut s, &[]).is_empty(),
            "only changes are sent"
        );
        assert!(
            decide(&reply(Status::Unknown), &mut s, &[]).is_empty(),
            "unknown: as before"
        );
        assert_eq!(
            decide(&reply(Status::Active), &mut s, &[]),
            vec![Control::Accepting(true)]
        );
        assert_eq!(
            decide(&reply(Status::UpgradeRequired), &mut s, &[]),
            vec![Control::Accepting(false)]
        );
        assert_eq!(
            decide(&reply(Status::Revoked), &mut s, &[]),
            vec![Control::Exit]
        );
    }

    #[test]
    fn new_peers_are_passed_on_once() {
        let mut s = seen();
        let mut r = reply(Status::Active);
        r.peers = vec![
            Peer {
                node_id: "rn_b".into(),
                addr: "198.51.100.2:3478".into(),
            },
            Peer {
                node_id: "rn_x".into(),
                addr: "not an address".into(),
            },
        ];
        assert_eq!(
            decide(&r, &mut s, &[]),
            vec![Control::Peers(vec![(
                "rn_b".into(),
                "198.51.100.2:3478".parse().unwrap()
            )])]
        );
        assert!(decide(&r, &mut s, &[]).is_empty(), "the same again");
        r.peers.clear();
        assert_eq!(decide(&r, &mut s, &[]), vec![Control::Peers(vec![])]);
    }

    #[test]
    fn peers_are_capped_and_only_addresses_a_node_could_have() {
        // The review of 2026-10-01: the peer list makes the node send probes every 2 s, so a
        // control plane (or someone between) can't aim it at a crowd or a broadcast address.
        let mut s = Seen {
            accepting: true,
            peers: Vec::new(),
            issuers: Vec::new(),
        };
        let mut r = reply(Status::Active);
        r.peers = [
            "0.0.0.0:3478",
            "224.0.0.1:3478",
            "255.255.255.255:3478",
            "[ff02::1]:3478",
        ]
        .iter()
        .map(|a| Peer {
            node_id: "rn_bad".into(),
            addr: (*a).into(),
        })
        .chain((0..100).map(|i| Peer {
            node_id: format!("rn_{i}"),
            addr: format!("198.51.100.{}:3478", i + 1),
        }))
        .collect();
        let out = decide(&r, &mut s, &[]);
        let [Control::Peers(peers)] = &out[..] else {
            panic!("{out:?}")
        };
        assert_eq!(peers.len(), MAX_PEERS);
        assert!(peers.iter().all(|(id, _)| id != "rn_bad"));
    }

    #[test]
    fn unknown_node_is_told_apart_from_other_refusals() {
        let e = |status, error: &str| Error::Refused {
            status,
            error: error.into(),
            message: String::new(),
        };
        assert!(e(401, "unknown_node").unknown_node());
        assert!(!e(401, "replayed").unknown_node());
        assert!(!e(503, "unknown_node").unknown_node());
        assert!(!Error::Transport("down".into()).unknown_node());
    }

    #[test]
    fn a_node_the_control_plane_forgot_drains_once_and_comes_back_when_it_knows_it_again() {
        let mut s = Seen {
            accepting: true,
            peers: Vec::new(),
            issuers: Vec::new(),
        };
        let unknown = Error::Refused {
            status: 401,
            error: "unknown_node".into(),
            message: String::new(),
        };
        assert_eq!(
            decide_error(&unknown, &mut s),
            Some(Control::Accepting(false))
        );
        assert_eq!(decide_error(&unknown, &mut s), None, "once");
        assert_eq!(decide_error(&Error::Transport("down".into()), &mut s), None);
        assert_eq!(
            decide(&reply(Status::Active), &mut s, &[]),
            vec![Control::Accepting(true)],
            "known again: taking allocations"
        );
    }

    #[test]
    fn issuers_are_this_nodes_own_and_the_control_planes_passed_on_once() {
        const A: &str = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w";
        const B: &str = "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";
        let key = |pubkey: &str| IssuerKey {
            pubkey: pubkey.into(),
        };
        let local = vec![A.to_string()];
        let mut s = seen();
        s.issuers = local.clone();
        let mut r = reply(Status::Active);
        assert!(
            decide(&r, &mut s, &local).is_empty(),
            "the local ones from the start"
        );
        r.issuers = vec![key(B), key(A), key("not a key")];
        assert_eq!(
            decide(&r, &mut s, &local),
            vec![Control::Issuers(vec![A.into(), B.into()])]
        );
        assert!(decide(&r, &mut s, &local).is_empty(), "the same again");
        r.issuers.clear();
        assert_eq!(
            decide(&r, &mut s, &local),
            vec![Control::Issuers(vec![A.into()])],
            "the control plane's gone; the node's own stay"
        );
    }

    #[test]
    fn the_control_plane_out_of_reach_is_said_once_after_a_while_and_its_return() {
        let t = Instant::now();
        let mut w = Watch::new(
            "nyc-1 (rn_a)".into(),
            "https://gamerelay.io".into(),
            Duration::from_secs(120),
        );
        assert_eq!(w.ok(t), None, "fine all along");
        assert_eq!(w.failed(t, "timeout"), None);
        assert_eq!(w.failed(t + Duration::from_secs(60), "timeout"), None);
        let said = w.failed(t + Duration::from_secs(120), "timeout").unwrap();
        assert!(
            said.contains("nyc-1 (rn_a) can't reach") && said.contains("for 2 min"),
            "{said}"
        );
        assert_eq!(
            w.failed(t + Duration::from_secs(180), "timeout"),
            None,
            "once"
        );
        let back = w.ok(t + Duration::from_secs(300)).unwrap();
        assert!(back.contains("again") && back.contains("5 min"), "{back}");
        // A blip shorter than `after` says nothing either way.
        assert_eq!(w.failed(t + Duration::from_secs(400), "reset"), None);
        assert_eq!(w.ok(t + Duration::from_secs(415)), None);
    }

    #[test]
    fn only_a_control_plane_out_of_reach_counts() {
        assert!(Error::Transport("timeout".into()).unreachable());
        let refused = |status| Error::Refused {
            status,
            error: "x".into(),
            message: String::new(),
        };
        assert!(refused(502).unreachable());
        assert!(!refused(401).unreachable(), "it answered");
    }
}
