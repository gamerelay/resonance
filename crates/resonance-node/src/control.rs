//! The control plane, as a node talks to it (v0 §2): join once, then fetch the key and send a
//! heartbeat every 15 s. Signed requests over HTTPS; the relay loop never waits on any of it.

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use resonance_proto::{
    self as proto, ErrorResponse, Heartbeat, HeartbeatResponse, JoinRequest, JoinResponse,
    KeyResponse, Status,
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

    pub fn join(&self, token: &str, urls: Vec<String>) -> Result<JoinResponse, Error> {
        let req = JoinRequest {
            token: token.into(),
            pubkey: B64.encode(self.key.verifying_key().to_bytes()),
            urls,
            software: software(),
        };
        self.post("/nodes/join", &req)
    }

    pub fn fetch_key(&self) -> Result<KeyResponse, Error> {
        self.post("/nodes/key", &serde_json::json!({}))
    }

    pub fn heartbeat(&self, h: &Heartbeat) -> Result<HeartbeatResponse, Error> {
        self.post("/nodes/heartbeat", h)
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
    /// Revoked: stop now.
    Exit,
}

/// The relay loop's numbers, for the heartbeat.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub allocations: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
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

/// Every `every`, a heartbeat; its answer becomes `Control`s for the relay loop. A control plane
/// that can't be reached changes nothing: the node keeps relaying what it has.
pub fn heartbeats(
    client: Client,
    every: Duration,
    snapshot: Arc<Mutex<Snapshot>>,
    mut key_version: u32,
    tx: Sender<Control>,
) {
    let started = Instant::now();
    let (mut last_cpu, mut last_at) = (cpu_seconds(), Instant::now());
    let mut accepting = true;
    let mut first = true;
    loop {
        // The first at once: a node is handed out to players from its first heartbeat.
        if !first {
            std::thread::sleep(every);
        }
        first = false;
        let snap = snapshot.lock().map(|s| s.clone()).unwrap_or_default();
        let (cpu, at) = (cpu_seconds(), Instant::now());
        let h = Heartbeat {
            allocations: snap.allocations,
            bytes_in: snap.bytes_in,
            bytes_out: snap.bytes_out,
            cpu: (cpu - last_cpu) / at.duration_since(last_at).as_secs_f64().max(0.001),
            uptime_s: started.elapsed().as_secs(),
            software: software(),
        };
        (last_cpu, last_at) = (cpu, at);
        let reply = match client.heartbeat(&h) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("heartbeat: {e}");
                continue;
            }
        };
        for c in decide(&reply, &mut accepting, &mut key_version, || {
            client.fetch_key()
        }) {
            let exit = c == Control::Exit;
            if tx.send(c).is_err() || exit {
                return;
            }
        }
    }
}

/// What one heartbeat answer means for the relay loop.
fn decide(
    reply: &HeartbeatResponse,
    accepting: &mut bool,
    key_version: &mut u32,
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
        Status::Unknown => *accepting,
    };
    if want != *accepting {
        eprintln!(
            "{}",
            if want {
                "active: taking new allocations"
            } else {
                "draining: no new allocations"
            }
        );
        *accepting = want;
        out.push(Control::Accepting(want));
    }
    if reply.key_version != *key_version {
        match fetch_key() {
            Ok(k) => {
                eprintln!("node key rotated to version {}", k.key_version);
                *key_version = k.key_version;
                out.push(Control::Key(k.node_key));
            }
            Err(e) => eprintln!("fetching the rotated key: {e}"),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(status: Status, key_version: u32) -> HeartbeatResponse {
        HeartbeatResponse {
            status,
            key_version,
            latest_version: "2026-09-29".into(),
            min_version: "2026-09-29".into(),
        }
    }
    fn no_key() -> Result<KeyResponse, Error> {
        panic!("no key fetch expected")
    }

    #[test]
    fn heartbeat_answers_become_controls() {
        let (mut accepting, mut kv) = (true, 0);
        assert!(decide(&reply(Status::Active, 0), &mut accepting, &mut kv, no_key).is_empty());
        assert_eq!(
            decide(&reply(Status::Draining, 0), &mut accepting, &mut kv, no_key),
            vec![Control::Accepting(false)]
        );
        assert!(
            decide(&reply(Status::Draining, 0), &mut accepting, &mut kv, no_key).is_empty(),
            "only changes are sent"
        );
        assert!(
            decide(&reply(Status::Unknown, 0), &mut accepting, &mut kv, no_key).is_empty(),
            "unknown: as before"
        );
        assert_eq!(
            decide(&reply(Status::Active, 0), &mut accepting, &mut kv, no_key),
            vec![Control::Accepting(true)]
        );
        assert_eq!(
            decide(
                &reply(Status::UpgradeRequired, 0),
                &mut accepting,
                &mut kv,
                no_key
            ),
            vec![Control::Accepting(false)]
        );
        assert_eq!(
            decide(&reply(Status::Revoked, 0), &mut accepting, &mut kv, no_key),
            vec![Control::Exit]
        );
    }

    #[test]
    fn a_new_key_version_fetches_the_key_once() {
        let (mut accepting, mut kv) = (true, 0);
        let got = decide(&reply(Status::Active, 1), &mut accepting, &mut kv, || {
            Ok(KeyResponse {
                node_key: "k1".into(),
                key_version: 1,
            })
        });
        assert_eq!(got, vec![Control::Key("k1".into())]);
        assert_eq!(kv, 1);
        assert!(decide(&reply(Status::Active, 1), &mut accepting, &mut kv, no_key).is_empty());
        // A failed fetch is tried again at the next heartbeat.
        let got = decide(&reply(Status::Active, 2), &mut accepting, &mut kv, || {
            Err(Error::Transport("down".into()))
        });
        assert!(got.is_empty());
        assert_eq!(kv, 1);
    }
}
