//! Request-rate protection against scripted abuse (a `curl` loop, credential stuffing, a crawler hammering the site).
//!
//! A fixed 10-second window per site and client address. The limit comes from `HDD_RATE_LIMIT_PER_10S` (default 600,
//! `0` switches the guard off). Block mode answers 429 with `Retry-After`; monitor mode only records `would_block`.
//! The table is bounded, so a flood of spoofed addresses cannot grow memory without limit.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::util;

/// The window length.
const WINDOW: Duration = Duration::from_secs(10);

/// The default number of requests one client may send to one site per window.
pub const DEFAULT_LIMIT: u32 = 600;

/// The most client/site pairs tracked at once.
const MAX_TRACKED: usize = 50_000;

/// A per-site, per-client fixed-window request counter.
pub struct RateLimiter {
    limit: u32,
    windows: Mutex<HashMap<(String, IpAddr), (Instant, u32)>>,
}

impl RateLimiter {
    /// A limiter with an explicit limit (`0` means off).
    #[must_use]
    pub fn new(limit: u32) -> Self {
        Self {
            limit,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// A limiter configured from `HDD_RATE_LIMIT_PER_10S` (default [`DEFAULT_LIMIT`]).
    #[must_use]
    pub fn from_env() -> Self {
        let limit = std::env::var("HDD_RATE_LIMIT_PER_10S")
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
            .unwrap_or(DEFAULT_LIMIT);
        Self::new(limit)
    }

    /// The configured limit (`0` = off).
    #[must_use]
    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// Count one request. Returns `true` when the client is over the limit for the current window.
    pub fn exceeded(&self, site: &str, ip: IpAddr) -> bool {
        if self.limit == 0 {
            return false;
        }
        let now = Instant::now();
        let mut windows = util::lock(&self.windows);
        if windows.len() >= MAX_TRACKED {
            windows.retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
            if windows.len() >= MAX_TRACKED {
                // Still full of live windows (an address flood): refuse to track more, never grow.
                return false;
            }
        }
        let entry = windows.entry((site.to_owned(), ip)).or_insert((now, 0));
        if now.duration_since(entry.0) >= WINDOW {
            *entry = (now, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        entry.1 > self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, last])
    }

    #[test]
    fn a_client_over_the_limit_is_flagged_and_another_client_is_not() {
        let limiter = RateLimiter::new(5);
        for _ in 0..5 {
            assert!(!limiter.exceeded("shop.test", ip(1)));
        }
        assert!(
            limiter.exceeded("shop.test", ip(1)),
            "the sixth request in the window is over"
        );
        assert!(
            !limiter.exceeded("shop.test", ip(2)),
            "another client has its own window"
        );
        assert!(
            !limiter.exceeded("other.test", ip(1)),
            "another site has its own window"
        );
    }

    #[test]
    fn a_zero_limit_switches_the_guard_off() {
        let limiter = RateLimiter::new(0);
        for _ in 0..10_000 {
            assert!(!limiter.exceeded("shop.test", ip(1)));
        }
    }
}
