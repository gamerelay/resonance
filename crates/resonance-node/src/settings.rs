//! The node's settings, from its environment (/etc/gamerelay-turn.env), read once and checked
//! before anything starts. `from_lookup` takes any lookup, so they're tested without a process.
//! What each one means: the binary's doc (main.rs).

use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use resonance_turn::Config;
use resonance_turn::ticket::Issuer;

use crate::relay::Limits;

/// How often the control plane hears from a joined node (it stops handing out one silent for 45 s).
pub const HEARTBEAT: Duration = Duration::from_secs(15);

pub struct Settings {
    /// Where players reach this node.
    pub public_ip: IpAddr,
    /// UDP, and TCP with `tcp`.
    pub port: u16,
    pub tcp: bool,
    pub tls: Option<TlsSettings>,
    /// The core's settings. Its nonce key and sealing secret are filled in when it runs.
    pub turn: Config,
    pub limits: Limits,
    pub heartbeat: Duration,
    /// The control plane to join.
    pub control: String,
    /// A Discord or Slack incoming webhook this node says the control plane is out of reach on
    /// (RESONANCE_ALERT_WEBHOOK), after `alert_after` in a row.
    pub alert_webhook: Option<String>,
    pub alert_after: Duration,
    /// Issuers whose tickets this node accepts whatever its control plane says
    /// (RESONANCE_ISSUERS: ed25519 public keys, base64url, comma-separated). Also in `turn`.
    pub issuers: Vec<String>,
    /// Settings that mean nothing any more and are set, to say so at startup.
    pub ignored: Vec<(&'static str, &'static str)>,
}

pub struct TlsSettings {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub port: u16,
    /// The name on the certificate, that players connect to.
    pub host: String,
}

/// Reads settings by name; empty is the same as unset.
struct Env<F>(F);

impl<F: Fn(&str) -> Option<String>> Env<F> {
    fn get(&self, key: &str) -> Option<String> {
        (self.0)(key).filter(|v| !v.is_empty())
    }

    fn flag(&self, key: &str) -> bool {
        self.get(key).is_some_and(|v| v == "1")
    }

    fn port(&self, key: &str, fallback: u16) -> Result<u16, String> {
        match self.get(key) {
            None => Ok(fallback),
            Some(v) => v
                .parse()
                .map_err(|_| format!("{key} must be a port, not {v:?}")),
        }
    }

    /// A positive number, or fallback.
    fn num<T: FromStr + PartialOrd + Default>(&self, key: &str, fallback: T) -> Result<T, String> {
        match self.get(key) {
            None => Ok(fallback),
            Some(v) => match v.parse::<T>() {
                Ok(n) if n > T::default() => Ok(n),
                _ => Err(format!("{key} must be a positive number, not {v:?}")),
            },
        }
    }
}

impl Settings {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let env = Env(lookup);
        let public_ip: IpAddr = env
            .get("TURN_PUBLIC_IP")
            .and_then(|v| v.parse().ok())
            .ok_or("TURN_PUBLIC_IP (where players reach this node) is required")?;
        // The node listens on IPv4 only, so it would advertise URLs it doesn't answer.
        if public_ip.is_ipv6() {
            return Err(format!(
                "TURN_PUBLIC_IP {public_ip}: IPv6 isn't served yet (the node listens on IPv4 \
                 only); give the node's IPv4 address"
            ));
        }

        let tls = match (env.get("TURN_TLS_CERT"), env.get("TURN_TLS_KEY")) {
            (Some(cert), Some(key)) => Some(TlsSettings {
                cert: cert.into(),
                key: key.into(),
                port: env.port("TURN_TLS_PORT", 5349)?,
                host: env.get("TURN_TLS_HOST").ok_or(
                    "TURN_TLS_HOST (the name on the certificate players connect to) is required with TURN_TLS_CERT",
                )?,
            }),
            (None, None) => None,
            _ => return Err("TURN_TLS_CERT and TURN_TLS_KEY go together".into()),
        };

        let mut turn = Config::new(public_ip, [0; 32]);
        turn.min_port = env.port("TURN_MIN_PORT", turn.min_port)?;
        turn.max_port = env.port("TURN_MAX_PORT", turn.max_port)?;
        if turn.min_port > turn.max_port {
            return Err(format!(
                "TURN_MIN_PORT {} is above TURN_MAX_PORT {}",
                turn.min_port, turn.max_port
            ));
        }
        turn.max_per_player = env.num("TURN_MAX_PER_PLAYER", turn.max_per_player)?;
        turn.max_per_ip = env.num("TURN_MAX_PER_IP", turn.max_per_ip)?;
        turn.max_per_instance = env.num("TURN_MAX_PER_INSTANCE", turn.max_per_instance)?;
        turn.max_per_issuer = env.num("TURN_MAX_PER_ISSUER", turn.max_per_issuer)?;
        turn.ticket_check_rate = env.num("TURN_TICKET_CHECK_RATE", turn.ticket_check_rate)?;
        turn.memory_total = env.num("TURN_MEMORY_BYTES", turn.memory_total)?;
        // Unset, one IP's share is the default or the whole total, whichever is less.
        let per_ip = turn.memory_per_ip.min(turn.memory_total);
        turn.memory_per_ip = env.num("TURN_MEMORY_PER_IP_BYTES", per_ip)?;
        if turn.memory_per_ip > turn.memory_total {
            return Err("TURN_MEMORY_PER_IP_BYTES is above TURN_MEMORY_BYTES".into());
        }
        turn.unauth_rate = env.num("TURN_UNAUTH_RATE", turn.unauth_rate)?;
        // A shared address can fill its allocation cap at once.
        turn.unauth_burst = env.num("TURN_UNAUTH_BURST", turn.max_per_ip as f64)?;
        turn.rate_bytes = env.num("TURN_RATE_BYTES", turn.rate_bytes)?;
        turn.burst_bytes = env.num("TURN_BURST_BYTES", turn.rate_bytes * 2.0)?;

        let issuers: Vec<String> = env
            .get("RESONANCE_ISSUERS")
            .map(|v| {
                v.split(',')
                    .map(|k| k.trim().to_string())
                    .filter(|k| !k.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        for k in &issuers {
            turn.issuers.push(Issuer::parse(k).ok_or_else(|| {
                format!(
                    "RESONANCE_ISSUERS: {k:?} isn't an ed25519 public key (base64url, 32 bytes)"
                )
            })?);
        }

        let limits = Limits {
            max_streams: env.num("TURN_MAX_STREAMS", 1024)?,
            max_streams_per_ip: env.num("TURN_MAX_STREAMS_PER_IP", 64)?,
            debug_streams: env.flag("TURN_DEBUG_STREAMS"),
            ..Limits::default()
        };

        Ok(Settings {
            public_ip,
            port: env.port("TURN_PORT", 3478)?,
            tcp: env.flag("TURN_TCP"),
            tls,
            turn,
            limits,
            // RESONANCE_HEARTBEAT_S: for tests; the control plane expects 15.
            heartbeat: Duration::from_secs(env.num("RESONANCE_HEARTBEAT_S", HEARTBEAT.as_secs())?),
            control: control_url(env.get("RESONANCE_CONTROL"))?,
            alert_webhook: env.get("RESONANCE_ALERT_WEBHOOK"),
            alert_after: Duration::from_secs(env.num("RESONANCE_ALERT_AFTER_S", 120)?),
            issuers,
            ignored: [
                ("TURN_PEER_IPS", "pairs of players share one relay"),
                (
                    "TURN_SECRET",
                    "players' credentials are tickets (RESONANCE_ISSUERS)",
                ),
                (
                    "RESONANCE_NODE_KEY",
                    "players' credentials are tickets (RESONANCE_ISSUERS)",
                ),
            ]
            .into_iter()
            .filter(|(k, _)| env.get(k).is_some())
            .collect(),
        })
    }

    /// What players are told: UDP first (the SDK times a relay by it and names it by its first
    /// URL), then TCP, then TLS by its certificate's name.
    pub fn urls(&self) -> Vec<String> {
        let host = match self.public_ip {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        };
        let port = self.port;
        let mut urls = vec![format!("turn:{host}:{port}")];
        if self.tcp {
            urls.push(format!("turn:{host}:{port}?transport=tcp"));
        }
        if let Some(t) = &self.tls {
            urls.push(format!("turns:{}:{}?transport=tcp", t.host, t.port));
        }
        urls
    }
}

/// The control plane's address: https, except on this machine (tests, a control plane run
/// next to the node). Its answers say whose tickets to take, so they mustn't go over plain HTTP.
fn control_url(v: Option<String>) -> Result<String, String> {
    let url = v.unwrap_or_else(|| "https://gamerelay.io".into());
    let host = url
        .strip_prefix("http://")
        .map(|rest| rest.split(['/', '?']).next().unwrap_or(""))
        .map(|h| {
            h.rsplit_once(':')
                .filter(|(_, p)| p.parse::<u16>().is_ok())
                .map_or(h, |(h, _)| h)
        });
    match host {
        None if url.starts_with("https://") => Ok(url),
        Some("localhost" | "127.0.0.1" | "[::1]") => Ok(url),
        _ => Err(format!(
            "RESONANCE_CONTROL: {url:?} isn't https:// (plain http:// only for localhost)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(vars: &[(&str, &str)]) -> Result<Settings, String> {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Settings::from_lookup(move |k| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()))
    }

    fn error(vars: &[(&str, &str)]) -> String {
        settings(vars).err().expect("an error")
    }

    #[test]
    fn the_defaults_are_the_go_relays() {
        let s = settings(&[("TURN_PUBLIC_IP", "192.0.2.1")]).unwrap();
        assert_eq!(s.port, 3478);
        assert!(!s.tcp && s.tls.is_none());
        assert_eq!(s.urls(), ["turn:192.0.2.1:3478"]);
        let t = &s.turn;
        assert_eq!((t.min_port, t.max_port), (49152, 65535));
        assert_eq!(
            (t.max_per_player, t.max_per_ip, t.max_per_instance),
            (8, 64, 4096)
        );
        assert_eq!((t.unauth_rate, t.unauth_burst), (20.0, 64.0));
        assert_eq!((t.rate_bytes, t.burst_bytes), (131072.0, 262144.0));
        assert_eq!(
            (s.limits.max_streams, s.limits.max_streams_per_ip),
            (1024, 64)
        );
        assert_eq!(
            (t.memory_total, t.memory_per_ip),
            (96 * 1024 * 1024, 16 * 1024 * 1024)
        );
        assert_eq!(s.heartbeat, HEARTBEAT);
        assert_eq!(s.control, "https://gamerelay.io");
        assert!(s.ignored.is_empty());
        assert!(s.alert_webhook.is_none());
        assert_eq!(s.alert_after, Duration::from_secs(120));
    }

    #[test]
    fn the_control_plane_is_reached_over_https_or_on_this_machine() {
        let control = |v: &str| {
            settings(&[("TURN_PUBLIC_IP", "192.0.2.1"), ("RESONANCE_CONTROL", v)])
                .map(|s| s.control)
        };
        assert_eq!(control("https://cp.example").unwrap(), "https://cp.example");
        for ok in [
            "http://localhost:8787",
            "http://127.0.0.1:8787/",
            "http://[::1]:1",
        ] {
            assert!(control(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://cp.example",
            "http://localhost.evil.example",
            "http://127.0.0.1.nip.io",
            "ftp://x",
            "cp.example",
        ] {
            assert!(control(bad).unwrap_err().contains("https"), "{bad}");
        }
    }

    #[test]
    fn the_per_ip_cap_carries_the_burst_but_not_the_stream_cap() {
        let s = settings(&[("TURN_PUBLIC_IP", "192.0.2.1"), ("TURN_MAX_PER_IP", "256")]).unwrap();
        assert_eq!(s.turn.unauth_burst, 256.0);
        // Streams hold far more memory than UDP allocations: their own cap (the review of
        // 2026-10-01: 256 streams from one IP could fill a 128 MB node).
        assert_eq!(s.limits.max_streams_per_ip, 64);
        let s = settings(&[
            ("TURN_PUBLIC_IP", "192.0.2.1"),
            ("TURN_MAX_STREAMS_PER_IP", "16"),
        ])
        .unwrap();
        assert_eq!(s.limits.max_streams_per_ip, 16);
        let s = settings(&[
            ("TURN_PUBLIC_IP", "192.0.2.1"),
            ("TURN_MAX_PER_IP", "256"),
            ("TURN_UNAUTH_BURST", "10"),
            ("TURN_RATE_BYTES", "1000"),
        ])
        .unwrap();
        assert_eq!(s.turn.unauth_burst, 10.0);
        assert_eq!(s.turn.burst_bytes, 2000.0, "twice the rate");
    }

    #[test]
    fn urls_are_udp_first_then_tcp_then_tls_by_name() {
        let s = settings(&[
            ("TURN_PUBLIC_IP", "192.0.2.1"),
            ("TURN_PORT", "3479"),
            ("TURN_TCP", "1"),
            ("TURN_TLS_CERT", "/c"),
            ("TURN_TLS_KEY", "/k"),
            ("TURN_TLS_PORT", "443"),
            ("TURN_TLS_HOST", "turn.example.com"),
        ])
        .unwrap();
        assert_eq!(
            s.urls(),
            [
                "turn:192.0.2.1:3479",
                "turn:192.0.2.1:3479?transport=tcp",
                "turns:turn.example.com:443?transport=tcp",
            ]
        );
    }

    #[test]
    fn the_memory_budget_is_set_in_bytes_and_one_ips_share_fits_in_it() {
        let s = settings(&[
            ("TURN_PUBLIC_IP", "192.0.2.1"),
            ("TURN_MEMORY_BYTES", "1000000"),
            ("TURN_MEMORY_PER_IP_BYTES", "1000"),
        ])
        .unwrap();
        assert_eq!(
            (s.turn.memory_total, s.turn.memory_per_ip),
            (1_000_000, 1000)
        );
        let e = error(&[
            ("TURN_PUBLIC_IP", "192.0.2.1"),
            ("TURN_MEMORY_BYTES", "1000"),
            ("TURN_MEMORY_PER_IP_BYTES", "2000"),
        ]);
        assert!(e.contains("above"), "{e}");
        // A total under the per-IP default, with no share given: the share is the whole total.
        let s = settings(&[
            ("TURN_PUBLIC_IP", "192.0.2.1"),
            ("TURN_MEMORY_BYTES", "8000000"),
        ])
        .unwrap();
        assert_eq!(
            (s.turn.memory_total, s.turn.memory_per_ip),
            (8_000_000, 8_000_000)
        );
    }

    #[test]
    fn an_ipv6_public_ip_is_refused_until_its_served() {
        // The node binds 0.0.0.0, so it would hand out turn:[v6] URLs nothing answers.
        for ip in ["2001:db8::1", "::1"] {
            assert!(error(&[("TURN_PUBLIC_IP", ip)]).contains("IPv6 isn't served yet"));
        }
        assert!(error(&[("TURN_PUBLIC_IP", "nope")]).contains("is required"));
    }

    #[test]
    fn old_settings_are_ignored_and_said_to_be() {
        let s = settings(&[
            ("TURN_PUBLIC_IP", "192.0.2.1"),
            ("TURN_SECRET", "old"),
            ("RESONANCE_NODE_KEY", "old"),
            ("TURN_PEER_IPS", "10.0.0.1"),
        ])
        .unwrap();
        let keys: Vec<_> = s.ignored.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, ["TURN_PEER_IPS", "TURN_SECRET", "RESONANCE_NODE_KEY"]);
        assert!(s.ignored[1].1.contains("tickets"));
    }

    #[test]
    fn trusted_issuers() {
        let ip = ("TURN_PUBLIC_IP", "192.0.2.1");
        let a = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w";
        let b = "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";
        let s = settings(&[ip, ("RESONANCE_ISSUERS", &format!("{a}, {b},"))]).unwrap();
        assert_eq!(s.issuers, vec![a.to_string(), b.to_string()]);
        assert_eq!(s.turn.issuers.len(), 2);
        assert!(settings(&[ip]).unwrap().issuers.is_empty());
    }

    #[test]
    fn bad_settings_are_refused_before_anything_starts() {
        assert!(error(&[]).contains("TURN_PUBLIC_IP"));
        assert!(error(&[("TURN_PUBLIC_IP", "somewhere")]).contains("TURN_PUBLIC_IP"));
        let ip = ("TURN_PUBLIC_IP", "192.0.2.1");
        assert!(error(&[ip, ("TURN_PORT", "70000")]).contains("TURN_PORT must be a port"));
        assert!(error(&[ip, ("TURN_MAX_PER_IP", "0")]).contains("positive"));
        assert!(error(&[ip, ("TURN_RATE_BYTES", "-5")]).contains("positive"));
        assert!(
            error(&[ip, ("TURN_MIN_PORT", "60000"), ("TURN_MAX_PORT", "50000")]).contains("above")
        );
        assert!(error(&[ip, ("TURN_TLS_CERT", "/c")]).contains("go together"));
        assert!(
            error(&[ip, ("TURN_TLS_CERT", "/c"), ("TURN_TLS_KEY", "/k")]).contains("TURN_TLS_HOST")
        );
        assert!(error(&[ip, ("RESONANCE_ISSUERS", "nope")]).contains("RESONANCE_ISSUERS"));
        // Empty is unset.
        assert!(settings(&[ip, ("TURN_PORT", ""), ("TURN_TLS_CERT", "")]).is_ok());
    }
}
