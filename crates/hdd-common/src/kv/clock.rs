//! Time source of the in-process backend. Monotonic microseconds, injectable so that TTL, window and decay behavior is tested
//! without sleeping.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Monotonic time in microseconds since an arbitrary start.
pub trait Clock: Send + Sync {
    /// Microseconds since the clock started. Never goes backwards.
    fn now_us(&self) -> u64;
}

/// The real clock.
#[derive(Debug)]
pub struct SystemClock {
    start: Instant,
}

impl SystemClock {
    /// Start counting now.
    pub fn new() -> SystemClock {
        SystemClock {
            start: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        SystemClock::new()
    }
}

impl Clock for SystemClock {
    fn now_us(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_micros()).unwrap_or(u64::MAX)
    }
}

/// A clock that moves only when told to (tests, replays).
#[derive(Debug, Default)]
pub struct ManualClock {
    now: AtomicU64,
}

impl ManualClock {
    /// Start at `start_us`.
    pub fn new(start_us: u64) -> ManualClock {
        ManualClock {
            now: AtomicU64::new(start_us),
        }
    }

    /// Move forward.
    pub fn advance_us(&self, by: u64) {
        self.now.fetch_add(by, Ordering::SeqCst);
    }

    /// Move forward by milliseconds.
    pub fn advance_ms(&self, by: u64) {
        self.advance_us(by.saturating_mul(1000));
    }
}

impl Clock for ManualClock {
    fn now_us(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}
