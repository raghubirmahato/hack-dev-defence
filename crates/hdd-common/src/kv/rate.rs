//! The three rate-limit algorithms of C18.3 as pure state machines. `MemoryKv` runs them under a shard lock; the Lua scripts of
//! `RedisKv` implement the same arithmetic (integer microseconds, same rounding), and the conformance suite compares both with
//! reference models.
//!
//! All times are microseconds. A request is "allowed" or "denied"; only allowed requests are recorded, so a denied burst does not
//! extend its own penalty. `cost` is the number of units the request consumes (normally 1).
//!
//! * [`Algorithm::Counter`] (ordinary limits): sliding window counter with two sub-windows. With the window `W`, the current
//!   fixed window `i = floor(now / W)`, offset `off = now mod W`, and the counts `c` of window `i` and `p` of window `i - 1`, the
//!   estimate is `p * (W - off) / W + c`. A request is allowed when `estimate + cost <= limit`. **Documented error bound:** the
//!   estimate differs from the exact sliding count by at most `p` (the previous window's count assumed uniform), so at most one
//!   `limit` per window boundary. The conformance suite measures it.
//! * [`Algorithm::Exact`] (authentication endpoints, ban-triggering limits): sliding window log capped at `limit`. A request is
//!   allowed when the units recorded in the last `W` (an entry older than or exactly `W` is gone) plus `cost` fit in `limit`.
//!   Never approximate.
//! * [`Algorithm::Gcra`]: generic cell rate algorithm with the emission interval `T = floor(W / limit)` (at least 1 µs) and a
//!   burst allowance of `limit * T`. A request is allowed when the backlog `max(tat, now) - now + cost * T` fits in `limit * T`.
//!   Never approximate (the only deviation from `W` is the flooring of `T`).
//!
//! `violations` counts denials seen in the last `W` before the current one ended; it resets when no denial happened for `W`.

use std::collections::VecDeque;
use std::time::Duration;

use super::{KvError, KvResult};

/// Rate-limit algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// Sliding window counter with two sub-windows (approximate, documented bound).
    Counter,
    /// Sliding window log capped at the limit (exact).
    Exact,
    /// Generic cell rate algorithm (exact up to the flooring of the emission interval).
    Gcra,
}

impl Algorithm {
    /// Stable name (script argument, metric label).
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Counter => "counter",
            Algorithm::Exact => "exact",
            Algorithm::Gcra => "gcra",
        }
    }
}

/// One rate-limit question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateRequest {
    /// Units allowed per window.
    pub limit: u32,
    /// Window length.
    pub window: Duration,
    /// Algorithm.
    pub algorithm: Algorithm,
    /// Units this request consumes.
    pub cost: u32,
}

/// Largest accepted limit.
pub const MAX_LIMIT: u32 = 10_000_000;
/// Shortest accepted window.
pub const MIN_WINDOW: Duration = Duration::from_millis(1);
/// Longest accepted window.
pub const MAX_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
/// Largest `limit * window` in microseconds. The Lua scripts compute in doubles, which are exact only below 2^53; the counter
/// algorithm adds up to three such products, so the bound is 2^50 and every backend refuses more (identical behavior).
pub const MAX_LIMIT_WINDOW_US: u64 = 1 << 50;

impl RateRequest {
    /// A request that consumes one unit.
    pub fn new(limit: u32, window: Duration, algorithm: Algorithm) -> RateRequest {
        RateRequest {
            limit,
            window,
            algorithm,
            cost: 1,
        }
    }

    /// Window in microseconds.
    pub fn window_us(&self) -> u64 {
        u64::try_from(self.window.as_micros()).unwrap_or(u64::MAX)
    }

    /// Reject arguments no backend can honor, identically everywhere.
    pub fn validate(&self) -> KvResult<()> {
        if self.limit == 0 || self.limit > MAX_LIMIT {
            return Err(KvError::InvalidArgument("limit must be 1 to 10,000,000"));
        }
        if self.window < MIN_WINDOW || self.window > MAX_WINDOW {
            return Err(KvError::InvalidArgument("window must be 1 ms to 24 hours"));
        }
        if u64::from(self.limit).saturating_mul(self.window_us()) > MAX_LIMIT_WINDOW_US {
            return Err(KvError::InvalidArgument(
                "limit times window is too large (above 2^50 unit-microseconds)",
            ));
        }
        if self.cost == 0 || self.cost > self.limit {
            return Err(KvError::InvalidArgument("cost must be 1 to the limit"));
        }
        if self.algorithm == Algorithm::Gcra && self.window_us() < u64::from(self.limit) {
            return Err(KvError::InvalidArgument(
                "gcra needs a window of at least one microsecond per unit of the limit",
            ));
        }
        Ok(())
    }
}

/// The answer to a [`RateRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateDecision {
    /// The request fits.
    pub allowed: bool,
    /// Units still available after this request (denied: after nothing was recorded).
    pub remaining: u32,
    /// Allowed: milliseconds until the recorded state is fully free again. Denied: the minimum wait (rounded up) after which
    /// the same request would be allowed if nothing else happened (the `Retry-After`).
    pub reset_ms: u64,
    /// Denials seen recently (see the module documentation).
    pub violations: u32,
}

/// State of one counter key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateState {
    /// Two sub-windows.
    Counter {
        /// Index of the current fixed window.
        idx: u64,
        /// Units counted in it.
        curr: u64,
        /// Units counted in the previous window.
        prev: u64,
    },
    /// Log of `(timestamp, cost)` of allowed requests, oldest first.
    Exact {
        /// The log.
        log: VecDeque<(u64, u32)>,
        /// Sum of the costs in the log.
        sum: u64,
    },
    /// Theoretical arrival time.
    Gcra {
        /// Theoretical arrival time of the next unit.
        tat: u64,
    },
}

/// State of a key plus its violation counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateEntry {
    /// Algorithm state.
    pub state: RateState,
    /// Denials within the violation window.
    pub violations: u32,
    /// The violation counter resets at this time.
    pub viol_until: u64,
}

fn ceil_ms(us: u64) -> u64 {
    us.div_ceil(1000)
}

impl RateEntry {
    /// An empty entry for an algorithm.
    pub fn new(algorithm: Algorithm) -> RateEntry {
        RateEntry {
            state: match algorithm {
                Algorithm::Counter => RateState::Counter {
                    idx: 0,
                    curr: 0,
                    prev: 0,
                },
                Algorithm::Exact => RateState::Exact {
                    log: VecDeque::new(),
                    sum: 0,
                },
                Algorithm::Gcra => RateState::Gcra { tat: 0 },
            },
            violations: 0,
            viol_until: 0,
        }
    }

    /// The algorithm this entry holds state for.
    pub fn algorithm(&self) -> Algorithm {
        match self.state {
            RateState::Counter { .. } => Algorithm::Counter,
            RateState::Exact { .. } => Algorithm::Exact,
            RateState::Gcra { .. } => Algorithm::Gcra,
        }
    }

    /// Approximate size in bytes (memory accounting).
    pub fn approx_bytes(&self) -> usize {
        64 + match &self.state {
            RateState::Exact { log, .. } => log.len() * 16,
            _ => 0,
        }
    }

    /// Decide one request at `now` (the request is validated by the caller).
    pub fn check(&mut self, now: u64, req: &RateRequest) -> RateDecision {
        if self.algorithm() != req.algorithm {
            // The limit definition changed its algorithm: start afresh (a reset only forgives).
            *self = RateEntry::new(req.algorithm);
        }
        let w = req.window_us();
        let limit = u64::from(req.limit);
        let cost = u64::from(req.cost);
        let (allowed, remaining, wait_us) = match &mut self.state {
            RateState::Counter { idx, curr, prev } => {
                let cur_idx = now / w;
                let off = now % w;
                if *idx != cur_idx {
                    *prev = if cur_idx == idx.saturating_add(1) {
                        *curr
                    } else {
                        0
                    };
                    *curr = 0;
                    *idx = cur_idx;
                }
                let est =
                    u128::from(*prev) * u128::from(w - off) + u128::from(*curr) * u128::from(w);
                let cap = u128::from(limit) * u128::from(w);
                let need = u128::from(cost) * u128::from(w);
                if est + need <= cap {
                    *curr += cost;
                    let used = est + need;
                    let remaining = u32::try_from((cap - used) / u128::from(w)).unwrap_or(0);
                    let wait = if *curr > 0 {
                        (w - off) + w
                    } else if *prev > 0 {
                        w - off
                    } else {
                        0
                    };
                    (true, remaining, wait)
                } else {
                    let remaining =
                        u32::try_from((cap - est.min(cap)) / u128::from(w)).unwrap_or(0);
                    (
                        false,
                        remaining,
                        counter_retry_us(*prev, *curr, w, off, limit, cost),
                    )
                }
            }
            RateState::Exact { log, sum } => {
                while let Some(&(ts, c)) = log.front() {
                    if ts.saturating_add(w) <= now {
                        log.pop_front();
                        *sum -= u64::from(c);
                    } else {
                        break;
                    }
                }
                if *sum + cost <= limit {
                    match log.back_mut() {
                        Some((ts, c)) if *ts == now => *c += req.cost,
                        _ => log.push_back((now, req.cost)),
                    }
                    *sum += cost;
                    (true, u32::try_from(limit - *sum).unwrap_or(0), w)
                } else {
                    let need = *sum + cost - limit;
                    let mut freed = 0u64;
                    let mut wait = w;
                    for &(ts, c) in log.iter() {
                        freed += u64::from(c);
                        if freed >= need {
                            wait = ts.saturating_add(w).saturating_sub(now);
                            break;
                        }
                    }
                    (
                        false,
                        u32::try_from(limit.saturating_sub(*sum)).unwrap_or(0),
                        wait.max(1),
                    )
                }
            }
            RateState::Gcra { tat } => {
                let t = (w / limit).max(1);
                let cap = limit * t;
                let base = (*tat).max(now);
                let backlog = (base - now) + cost * t;
                if backlog <= cap {
                    *tat = now + backlog;
                    (
                        true,
                        u32::try_from((cap - backlog) / t).unwrap_or(0),
                        backlog,
                    )
                } else {
                    let current = base - now;
                    (
                        false,
                        u32::try_from(cap.saturating_sub(current) / t).unwrap_or(0),
                        (backlog - cap).max(1),
                    )
                }
            }
        };
        if !allowed {
            if now >= self.viol_until {
                self.violations = 0;
            }
            self.violations = self.violations.saturating_add(1);
            self.viol_until = now.saturating_add(w);
        }
        let violations = if now < self.viol_until {
            self.violations
        } else {
            0
        };
        RateDecision {
            allowed,
            remaining,
            reset_ms: ceil_ms(wait_us),
            violations,
        }
    }

    /// How long the key must be kept after the decision at `now`: until its state is free and its violations expired.
    pub fn keep_for_us(&self, now: u64, window_us: u64) -> u64 {
        let state = match &self.state {
            RateState::Counter { .. } => window_us.saturating_mul(2),
            RateState::Exact { .. } => window_us,
            RateState::Gcra { tat } => tat.saturating_sub(now),
        };
        state.max(self.viol_until.saturating_sub(now)).max(1)
    }
}

/// Minimum wait, in microseconds, after which a denied counter request would be allowed (derivation in the module comment of
/// the tests: first the rest of the current window, then the next window, then the one after).
pub fn counter_retry_us(prev: u64, curr: u64, w: u64, off: u64, limit: u64, cost: u64) -> u64 {
    let rest = w - off;
    // Within the current window: prev * (rest - t) <= (limit - cost - curr) * W.
    if limit >= cost + curr && prev > 0 {
        let b = u128::from(limit - cost - curr);
        let max_rest = (b * u128::from(w) / u128::from(prev)).min(u128::from(u64::MAX));
        let max_rest = u64::try_from(max_rest).unwrap_or(u64::MAX);
        if max_rest < rest {
            let t = rest - max_rest;
            if t < rest && t >= 1 {
                return t;
            }
        }
    }
    // Next window: the current count becomes the previous one.
    if curr == 0 {
        return rest;
    }
    if limit < cost {
        return rest + w;
    }
    let b = u128::from(limit - cost);
    let max_rest =
        u64::try_from((b * u128::from(w) / u128::from(curr)).min(u128::from(w))).unwrap_or(w);
    let o2 = w - max_rest;
    rest + o2.min(w)
}

#[cfg(test)]
mod tests;
