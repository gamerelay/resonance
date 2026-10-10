//! Token buckets: bytes per allocation, and unauthenticated requests per client IP (and, in the
//! node, new streams per client IP).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    pub fn full(burst: f64, now: Instant) -> Self {
        Bucket {
            tokens: burst,
            last: now,
        }
    }

    fn refill(&mut self, now: Instant, rate: f64, burst: f64) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + dt * rate).min(burst);
        self.last = now;
    }

    /// Takes n tokens if there are that many.
    pub fn spend(&mut self, n: f64, now: Instant, rate: f64, burst: f64) -> bool {
        self.refill(now, rate, burst);
        if self.tokens < n {
            return false;
        }
        self.tokens -= n;
        true
    }

    /// Would be full by now: nothing is lost by forgetting it.
    fn idle(&self, now: Instant, rate: f64, burst: f64) -> bool {
        self.tokens + now.saturating_duration_since(self.last).as_secs_f64() * rate >= burst
    }
}

/// Unauthenticated requests per client IP (the Go relay's reflectionLimiter). A request without
/// MESSAGE-INTEGRITY gets an answer a few times its size (a 401 with realm and nonce, or a Binding
/// response) sent to whatever source it claims, so a spoofed source could aim this relay at
/// someone. The burst lets a shared address fill its allocation cap at once.
pub struct Reflection {
    rate: f64,
    burst: f64,
    tracked: usize,
    buckets: HashMap<IpAddr, Bucket>,
    last_sweep: Option<Instant>,
    pub dropped: u64,
}

impl Reflection {
    pub fn new(rate: f64, burst: f64, tracked: usize) -> Self {
        Reflection {
            rate,
            burst,
            tracked,
            buckets: HashMap::new(),
            last_sweep: None,
            dropped: 0,
        }
    }

    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        if !self.buckets.contains_key(&ip) {
            // When full, forget IPs idle long enough to have a full bucket, at most once a second;
            // until there's room, a new IP's requests are dropped (a real flood is to thank).
            let due = self
                .last_sweep
                .is_none_or(|t| now.saturating_duration_since(t) >= Duration::from_secs(1));
            if self.buckets.len() >= self.tracked && due {
                self.last_sweep = Some(now);
                let (rate, burst) = (self.rate, self.burst);
                self.buckets.retain(|_, b| !b.idle(now, rate, burst));
            }
            if self.buckets.len() >= self.tracked {
                self.dropped += 1;
                return false;
            }
            self.buckets.insert(ip, Bucket::full(self.burst, now));
        }
        let b = self.buckets.get_mut(&ip).expect("inserted above");
        let ok = b.spend(1.0, now, self.rate, self.burst);
        if !ok {
            self.dropped += 1;
        }
        ok
    }

    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bucket_refills_up_to_its_burst() {
        let t = Instant::now();
        let mut b = Bucket::full(10.0, t);
        assert!(b.spend(10.0, t, 5.0, 10.0));
        assert!(!b.spend(1.0, t, 5.0, 10.0));
        assert!(b.spend(5.0, t + Duration::from_secs(1), 5.0, 10.0));
        assert!(
            !b.spend(11.0, t + Duration::from_secs(100), 5.0, 10.0),
            "never more than the burst"
        );
    }

    // The Go relay's TestReflectionLimiterIsBounded.
    #[test]
    fn tracked_ips_are_bounded() {
        let t = Instant::now();
        let mut l = Reflection::new(20.0, 64.0, 2);
        let ip = |n: u8| IpAddr::from([198, 51, 100, n]);
        assert!(l.allow(ip(1), t));
        assert!(l.allow(ip(2), t));
        assert!(!l.allow(ip(3), t), "full, and nobody is idle yet");
        // A second on, both buckets would be full again: they're forgotten, and ip(3) gets one.
        assert!(l.allow(ip(3), t + Duration::from_secs(1)));
        assert_eq!(l.tracked(), 1);
        assert!(l.allow(ip(1), t + Duration::from_secs(1)));
        // A sweep at most once a second: ip(4) waits, even though nobody new is idle.
        assert!(!l.allow(ip(4), t + Duration::from_millis(1500)));
    }
}
