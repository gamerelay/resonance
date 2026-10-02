//! What clients make the node hold, in bytes, in one place (TECH_DEBT C1): each charge goes to the
//! client's IP and to everyone's total, and one that doesn't fit is refused, never allocated.
//! Allocations, the checked tickets kept, and the node's streams (their queues and messages half
//! read) all charge it, so a client can't fill the node's memory by any path, and a new path that
//! holds memory has one obvious place to charge.

use std::collections::HashMap;
use std::net::IpAddr;

pub struct Budget {
    total: usize,
    per_ip: usize,
    used: usize,
    by_ip: HashMap<IpAddr, usize>,
}

impl Budget {
    /// At most `total` bytes for everyone together, and `per_ip` for one client IP.
    pub fn new(total: usize, per_ip: usize) -> Self {
        Budget {
            total,
            per_ip,
            used: 0,
            by_ip: HashMap::new(),
        }
    }

    /// Charges `n` bytes to `ip`, or nothing if they don't fit its share or the total.
    pub fn charge(&mut self, ip: IpAddr, n: usize) -> bool {
        let had = self.of(ip);
        if had.saturating_add(n) > self.per_ip || self.used.saturating_add(n) > self.total {
            return false;
        }
        if n > 0 {
            self.by_ip.insert(ip, had + n);
            self.used += n;
        }
        true
    }

    /// Gives back `n` bytes `ip` was charged (never more than it holds); an IP is forgotten at
    /// zero.
    pub fn refund(&mut self, ip: IpAddr, n: usize) {
        let Some(had) = self.by_ip.get_mut(&ip) else {
            return;
        };
        let n = n.min(*had);
        *had -= n;
        self.used -= n;
        if *had == 0 {
            self.by_ip.remove(&ip);
        }
    }

    /// From `had` bytes charged to `ip` to `now`: the difference charged or refunded. False (and
    /// nothing changed) if the growth doesn't fit.
    pub fn recharge(&mut self, ip: IpAddr, had: usize, now: usize) -> bool {
        if now >= had {
            self.charge(ip, now - had)
        } else {
            self.refund(ip, had - now);
            true
        }
    }

    /// Everyone's charges together.
    pub fn used(&self) -> usize {
        self.used
    }

    /// What `ip` is charged.
    pub fn of(&self, ip: IpAddr) -> usize {
        self.by_ip.get(&ip).copied().unwrap_or(0)
    }

    pub fn total(&self) -> usize {
        self.total
    }

    pub fn per_ip(&self) -> usize {
        self.per_ip
    }

    /// IPs holding anything.
    pub fn ips(&self) -> usize {
        self.by_ip.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, n])
    }

    #[test]
    fn a_charge_fits_its_ips_share_and_the_total_or_is_refused_whole() {
        let mut b = Budget::new(100, 60);
        assert!(b.charge(ip(1), 60));
        assert!(!b.charge(ip(1), 1), "past its IP's share");
        assert!(b.charge(ip(2), 40));
        assert!(!b.charge(ip(3), 1), "past the total");
        assert_eq!(
            (b.used(), b.of(ip(1)), b.of(ip(2)), b.of(ip(3))),
            (100, 60, 40, 0)
        );
        assert_eq!(b.ips(), 2, "a refused charge leaves no entry");
        assert!(!b.charge(ip(3), usize::MAX), "no overflow");
    }

    #[test]
    fn refunds_free_room_and_an_ip_at_zero_is_forgotten() {
        let mut b = Budget::new(100, 60);
        b.charge(ip(1), 50);
        b.refund(ip(1), 20);
        assert_eq!((b.used(), b.of(ip(1))), (30, 30));
        b.refund(ip(1), 1000);
        assert_eq!((b.used(), b.ips()), (0, 0), "never more than it holds");
        b.refund(ip(2), 5);
        assert_eq!(b.used(), 0, "nothing to give back");
    }

    #[test]
    fn a_recharge_takes_the_difference() {
        let mut b = Budget::new(100, 60);
        assert!(b.charge(ip(1), 10));
        assert!(b.recharge(ip(1), 10, 50));
        assert_eq!(b.of(ip(1)), 50);
        assert!(!b.recharge(ip(1), 50, 70), "growth past its share");
        assert_eq!(b.of(ip(1)), 50, "unchanged");
        assert!(b.recharge(ip(1), 50, 5));
        assert_eq!((b.of(ip(1)), b.used()), (5, 5));
    }
}
