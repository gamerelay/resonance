//! Measuring the other nodes (the control plane says which, in each heartbeat's answer): a STUN
//! Binding to each every couple of seconds, from the relay's own UDP socket, so it takes the path
//! players' packets take and goes through the same firewalls. Their answers come back to that
//! socket too, and are taken out before the core sees them. Sans-I/O: time and packets in.
//!
//! Reported over a sliding window, so the heartbeat can read it at any moment without resetting
//! anything: what was sent long enough ago to have been answered, what was, and the median round
//! trip. A peer every node reports as silent is unreachable (the control plane alerts on it).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use resonance_proto::PeerReport;

/// How often each peer gets a Binding.
pub const EVERY: Duration = Duration::from_secs(2);
/// What a report covers.
pub const WINDOW: Duration = Duration::from_secs(30);
/// An answer later than this counts as lost (and a probe younger than this isn't counted yet).
pub const WAIT: Duration = Duration::from_secs(1);

/// The start of our probes' transaction ids, so their answers are told apart from anything else.
const TAG: [u8; 4] = *b"rsnp";

struct Probe {
    tx: [u8; 12],
    sent: Instant,
    rtt: Option<Duration>,
}

struct Peer {
    node: String,
    addr: SocketAddr,
    next: Instant,
    probes: VecDeque<Probe>,
}

#[derive(Default)]
pub struct Prober {
    peers: Vec<Peer>,
    seq: u64,
}

impl Prober {
    /// The peers to measure now. One that stays keeps its history; a new one is probed at once.
    pub fn set_peers(&mut self, peers: Vec<(String, SocketAddr)>, now: Instant) {
        let mut old = std::mem::take(&mut self.peers);
        for (node, addr) in peers {
            let kept = old
                .iter()
                .position(|p| p.node == node && p.addr == addr)
                .map(|i| old.swap_remove(i));
            self.peers.push(kept.unwrap_or(Peer {
                node,
                addr,
                next: now,
                probes: VecDeque::new(),
            }));
        }
    }

    /// Bindings due now, each given to `send` as (where, the message).
    pub fn due(&mut self, now: Instant, mut send: impl FnMut(SocketAddr, &[u8])) {
        for p in &mut self.peers {
            if now < p.next {
                continue;
            }
            p.next = now + EVERY;
            self.seq += 1;
            let mut tx = [0u8; 12];
            tx[..4].copy_from_slice(&TAG);
            tx[4..].copy_from_slice(&self.seq.to_be_bytes());
            let mut msg = [0u8; 20];
            msg[..8].copy_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42]);
            msg[8..].copy_from_slice(&tx);
            while p.probes.front().is_some_and(|q| now - q.sent > WINDOW) {
                p.probes.pop_front();
            }
            p.probes.push_back(Probe {
                tx,
                sent: now,
                rtt: None,
            });
            send(p.addr, &msg);
        }
    }

    /// Whether `packet` answers one of our probes (and so isn't for the core). Cheap for anything
    /// else: only a Binding success with our tag is looked at further.
    pub fn answer(&mut self, from: SocketAddr, packet: &[u8], now: Instant) -> bool {
        if packet.len() < 20 || packet[..2] != [0x01, 0x01] || packet[8..12] != TAG {
            return false;
        }
        let from = SocketAddr::new(from.ip().to_canonical(), from.port());
        let Some(p) = self.peers.iter_mut().find(|p| p.addr == from) else {
            return true;
        };
        if let Some(q) = p
            .probes
            .iter_mut()
            .find(|q| q.tx[..] == packet[8..20] && q.rtt.is_none())
        {
            let rtt = now - q.sent;
            if rtt <= WAIT {
                q.rtt = Some(rtt);
            }
        }
        true
    }

    /// Each peer over the last `WINDOW`.
    pub fn report(&self, now: Instant) -> Vec<PeerReport> {
        self.peers
            .iter()
            .map(|p| {
                let settled = p
                    .probes
                    .iter()
                    .filter(|q| now - q.sent > WAIT && now - q.sent <= WINDOW);
                let mut rtts: Vec<f64> = settled
                    .clone()
                    .filter_map(|q| q.rtt)
                    .map(|d| d.as_secs_f64() * 1000.0)
                    .collect();
                rtts.sort_by(f64::total_cmp);
                PeerReport {
                    node: p.node.clone(),
                    sent: settled.count() as u32,
                    answered: rtts.len() as u32,
                    rtt_ms: (!rtts.is_empty())
                        .then(|| (rtts[rtts.len() / 2] * 100.0).round() / 100.0),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// The answer a node gives a Binding (success, same transaction id).
    fn answer_to(msg: &[u8]) -> Vec<u8> {
        let mut a = msg.to_vec();
        a[..2].copy_from_slice(&[0x01, 0x01]);
        a
    }

    fn sent(p: &mut Prober, now: Instant) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut out = Vec::new();
        p.due(now, |to, m| out.push((to, m.to_vec())));
        out
    }

    #[test]
    fn each_peer_is_probed_every_couple_of_seconds_and_timed() {
        let t = Instant::now();
        let mut p = Prober::default();
        p.set_peers(vec![("rn_b".into(), addr("198.51.100.2:3478"))], t);
        let first = sent(&mut p, t);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].0, addr("198.51.100.2:3478"));
        assert!(
            sent(&mut p, t + Duration::from_secs(1)).is_empty(),
            "not due yet"
        );
        assert!(p.answer(
            first[0].0,
            &answer_to(&first[0].1),
            t + Duration::from_millis(40)
        ));
        let r = p.report(t + Duration::from_secs(2));
        assert_eq!((r[0].sent, r[0].answered, r[0].rtt_ms), (1, 1, Some(40.0)));
        assert_eq!(sent(&mut p, t + EVERY).len(), 1);
    }

    #[test]
    fn unanswered_probes_count_once_theyve_had_their_chance() {
        let t = Instant::now();
        let mut p = Prober::default();
        p.set_peers(vec![("rn_c".into(), addr("198.51.100.3:3478"))], t);
        for i in 0..5 {
            sent(&mut p, t + EVERY * i);
        }
        let r = p.report(t + EVERY * 4 + Duration::from_millis(500));
        // The last one is too young to count.
        assert_eq!((r[0].sent, r[0].answered, r[0].rtt_ms), (4, 0, None));
        // A late answer is a lost one.
        let mut p = Prober::default();
        p.set_peers(vec![("rn_c".into(), addr("198.51.100.3:3478"))], t);
        let s = sent(&mut p, t);
        p.answer(s[0].0, &answer_to(&s[0].1), t + Duration::from_secs(3));
        assert_eq!(p.report(t + Duration::from_secs(4))[0].answered, 0);
    }

    #[test]
    fn the_window_slides() {
        let t = Instant::now();
        let mut p = Prober::default();
        p.set_peers(vec![("rn_b".into(), addr("198.51.100.2:3478"))], t);
        for i in 0..40 {
            let now = t + EVERY * i;
            for (to, m) in sent(&mut p, now) {
                p.answer(to, &answer_to(&m), now + Duration::from_millis(10));
            }
        }
        let r = p.report(t + EVERY * 39 + Duration::from_millis(1500));
        assert_eq!(r[0].sent, 15, "30 s of probes every 2 s");
        assert_eq!(r[0].answered, 15);
    }

    #[test]
    fn only_our_answers_from_our_peers_are_taken() {
        let t = Instant::now();
        let mut p = Prober::default();
        p.set_peers(vec![("rn_b".into(), addr("198.51.100.2:3478"))], t);
        let s = sent(&mut p, t);
        // A player's Binding, a request, a success without our tag: all the core's.
        let mut theirs = answer_to(&s[0].1);
        theirs[8] = b'x';
        assert!(!p.answer(s[0].0, &theirs, t));
        assert!(!p.answer(s[0].0, &s[0].1, t), "a request");
        assert!(!p.answer(s[0].0, &[0x40, 0, 0, 4, 1, 2, 3, 4], t));
        // Ours from somewhere else: taken (it's no use to the core) but not counted.
        assert!(p.answer(addr("203.0.113.9:3478"), &answer_to(&s[0].1), t));
        assert_eq!(p.report(t + Duration::from_secs(2))[0].answered, 0);
        // An IPv4-mapped source is the same peer.
        assert!(p.answer(
            addr("[::ffff:198.51.100.2]:3478"),
            &answer_to(&s[0].1),
            t + Duration::from_millis(5)
        ));
        assert_eq!(p.report(t + Duration::from_secs(2))[0].answered, 1);
    }

    #[test]
    fn a_peer_that_stays_keeps_its_history_and_one_that_goes_is_forgotten() {
        let t = Instant::now();
        let mut p = Prober::default();
        let b = ("rn_b".to_string(), addr("198.51.100.2:3478"));
        let c = ("rn_c".to_string(), addr("198.51.100.3:3478"));
        p.set_peers(vec![b.clone(), c.clone()], t);
        for (to, m) in sent(&mut p, t) {
            p.answer(to, &answer_to(&m), t + Duration::from_millis(10));
        }
        p.set_peers(vec![b], t + Duration::from_secs(1));
        let r = p.report(t + Duration::from_secs(2));
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].node.as_str(), r[0].answered), ("rn_b", 1));
    }
}
