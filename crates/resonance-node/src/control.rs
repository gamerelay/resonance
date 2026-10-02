//! The control plane, as a node talks to it (v0 §2): join once, then fetch the key and send a
//! heartbeat every 15 s. Signed requests over HTTPS; the relay loop never waits on any of it.

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use resonance_turn::ticket;
use std::net::SocketAddr;

use resonance_proto::{
    self as proto, ErrorResponse, Heartbeat, HeartbeatResponse, JoinRequest, JoinResponse,
    KeyResponse, Peer, PeerReport, Status,
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

    pub fn fetch_key(&self) -> Result<KeyResponse, Error> {
        self.post("/nodes/key", &serde_json::json!({}))
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
    /// A rotated key (the old one stays good for an hour).
    Key(String),
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
    pub key_version: u32,
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
            key_version: self.key_version,
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
                    continue;
                }
            };
            for c in decide(&reply, &mut seen, &self.local_issuers, || {
                self.client.fetch_key()
            }) {
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

/// What the relay loop was last told.
struct Seen {
    accepting: bool,
    key_version: u32,
    peers: Vec<Peer>,
    issuers: Vec<String>,
}

/// What one heartbeat answer means for the relay loop.
fn decide(
    reply: &HeartbeatResponse,
    seen: &mut Seen,
    local_issuers: &[String],
    fetch_key: impl FnOnce() -> Result<KeyResponse, Error>,
) -> Vec<Control> {
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
    if reply.key_version != seen.key_version {
        match fetch_key() {
            Ok(k) => {
                eprintln!("node key rotated to version {}", k.key_version);
                seen.key_version = k.key_version;
                out.push(Control::Key(k.node_key));
            }
            Err(e) => eprintln!("fetching the rotated key: {e}"),
        }
    }
    if reply.peers != seen.peers {
        seen.peers = reply.peers.clone();
        let peers = reply
            .peers
            .iter()
            .filter_map(|p| Some((p.node_id.clone(), p.addr.parse().ok()?)))
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

    fn reply(status: Status, key_version: u32) -> HeartbeatResponse {
        HeartbeatResponse {
            status,
            key_version,
            latest_version: "2026-09-29".into(),
            min_version: "2026-09-29".into(),
            peers: Vec::new(),
            issuers: Vec::new(),
        }
    }
    fn seen() -> Seen {
        Seen {
            accepting: true,
            key_version: 0,
            peers: Vec::new(),
            issuers: Vec::new(),
        }
    }
    fn no_key() -> Result<KeyResponse, Error> {
        panic!("no key fetch expected")
    }

    #[test]
    fn heartbeat_answers_become_controls() {
        let mut s = seen();
        assert!(decide(&reply(Status::Active, 0), &mut s, &[], no_key).is_empty());
        assert_eq!(
            decide(&reply(Status::Draining, 0), &mut s, &[], no_key),
            vec![Control::Accepting(false)]
        );
        assert!(
            decide(&reply(Status::Draining, 0), &mut s, &[], no_key).is_empty(),
            "only changes are sent"
        );
        assert!(
            decide(&reply(Status::Unknown, 0), &mut s, &[], no_key).is_empty(),
            "unknown: as before"
        );
        assert_eq!(
            decide(&reply(Status::Active, 0), &mut s, &[], no_key),
            vec![Control::Accepting(true)]
        );
        assert_eq!(
            decide(&reply(Status::UpgradeRequired, 0), &mut s, &[], no_key),
            vec![Control::Accepting(false)]
        );
        assert_eq!(
            decide(&reply(Status::Revoked, 0), &mut s, &[], no_key),
            vec![Control::Exit]
        );
    }

    #[test]
    fn a_new_key_version_fetches_the_key_once() {
        let mut s = seen();
        let got = decide(&reply(Status::Active, 1), &mut s, &[], || {
            Ok(KeyResponse {
                node_key: "k1".into(),
                key_version: 1,
            })
        });
        assert_eq!(got, vec![Control::Key("k1".into())]);
        assert_eq!(s.key_version, 1);
        assert!(decide(&reply(Status::Active, 1), &mut s, &[], no_key).is_empty());
        // A failed fetch is tried again at the next heartbeat.
        let got = decide(&reply(Status::Active, 2), &mut s, &[], || {
            Err(Error::Transport("down".into()))
        });
        assert!(got.is_empty());
        assert_eq!(s.key_version, 1);
    }

    #[test]
    fn new_peers_are_passed_on_once() {
        let mut s = seen();
        let mut r = reply(Status::Active, 0);
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
            decide(&r, &mut s, &[], no_key),
            vec![Control::Peers(vec![(
                "rn_b".into(),
                "198.51.100.2:3478".parse().unwrap()
            )])]
        );
        assert!(decide(&r, &mut s, &[], no_key).is_empty(), "the same again");
        r.peers.clear();
        assert_eq!(
            decide(&r, &mut s, &[], no_key),
            vec![Control::Peers(vec![])]
        );
    }

    #[test]
    fn issuers_are_this_nodes_own_and_the_control_planes_passed_on_once() {
        const A: &str = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w";
        const B: &str = "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";
        let local = vec![A.to_string()];
        let mut s = seen();
        s.issuers = local.clone();
        let mut r = reply(Status::Active, 0);
        assert!(
            decide(&r, &mut s, &local, no_key).is_empty(),
            "the local ones from the start"
        );
        r.issuers = vec![
            IssuerKey { pubkey: A.into() },
            IssuerKey { pubkey: B.into() },
            IssuerKey {
                pubkey: "not a key".into(),
            },
        ];
        assert_eq!(
            decide(&r, &mut s, &local, no_key),
            vec![Control::Issuers(vec![A.into(), B.into()])]
        );
        assert!(
            decide(&r, &mut s, &local, no_key).is_empty(),
            "the same again"
        );
        r.issuers.clear();
        assert_eq!(
            decide(&r, &mut s, &local, no_key),
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
