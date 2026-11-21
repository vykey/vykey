//! Fixed-window rate limiting per client address, in memory.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

/// Addresses tracked before expired windows are pruned.
const PRUNE_AT: usize = 50_000;

pub struct RateLimiter {
    max: u32,
    window: u64,
    map: Mutex<HashMap<IpAddr, (u64, u32)>>,
}

impl RateLimiter {
    /// At most `max` events per `window` seconds per address.
    pub fn new(max: u32, window: u64) -> Self {
        RateLimiter {
            max,
            window: window.max(1),
            map: Mutex::new(HashMap::new()),
        }
    }

    /// `Err(seconds to wait)` if `ip` is over the limit; counts nothing.
    pub fn check(&self, ip: IpAddr, now: u64) -> Result<(), u64> {
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(&bucket(ip)) {
            Some(&(start, n)) if now < start + self.window && n >= self.max => {
                Err(start + self.window - now)
            }
            _ => Ok(()),
        }
    }

    /// Counts one event; `Err(seconds to wait)` if it is over the limit.
    pub fn hit(&self, ip: IpAddr, now: u64) -> Result<(), u64> {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= PRUNE_AT {
            let window = self.window;
            map.retain(|_, (start, _)| now < *start + window);
        }
        let slot = map.entry(bucket(ip)).or_insert((now, 0));
        if now >= slot.0 + self.window {
            *slot = (now, 0);
        }
        if slot.1 >= self.max {
            return Err(slot.0 + self.window - now);
        }
        slot.1 += 1;
        Ok(())
    }
}

/// IPv6 clients usually own a whole /64, so they are limited per /64;
/// IPv4-mapped addresses count as IPv4.
fn bucket(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn limits_within_a_window_and_resets_after() {
        let l = RateLimiter::new(2, 60);
        let a = ip("192.0.2.1");
        assert_eq!(l.hit(a, 100), Ok(()));
        assert_eq!(l.check(a, 100), Ok(()));
        assert_eq!(l.hit(a, 110), Ok(()));
        assert_eq!(l.check(a, 120), Err(40));
        assert_eq!(l.hit(a, 120), Err(40));
        assert_eq!(l.hit(ip("192.0.2.2"), 120), Ok(()), "other address");
        assert_eq!(l.hit(a, 160), Ok(()), "new window");
    }

    #[test]
    fn ipv6_is_limited_per_64() {
        let l = RateLimiter::new(1, 60);
        assert_eq!(l.hit(ip("2001:db8:1:2::1"), 0), Ok(()));
        assert!(l.hit(ip("2001:db8:1:2:ffff::9"), 0).is_err());
        assert_eq!(l.hit(ip("2001:db8:1:3::1"), 0), Ok(()));
    }

    #[test]
    fn mapped_ipv4_shares_the_ipv4_bucket() {
        let l = RateLimiter::new(1, 60);
        assert_eq!(l.hit(ip("192.0.2.7"), 0), Ok(()));
        assert!(l.hit(ip("::ffff:192.0.2.7"), 0).is_err());
    }
}
