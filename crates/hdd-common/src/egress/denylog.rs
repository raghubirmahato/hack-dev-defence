//! Structured, rate-limited record of denied egress attempts (T-0009 step 6).
//!
//! Every denial is counted and kept in a small bounded ring, but only a limited number of events per window reach the sink
//! (the default sink writes one JSON line to standard error), so an attacker who can trigger denials cannot flood the log.
//! The first event emitted after a quiet period carries the number of events that were suppressed before it.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// One denied attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyEvent {
    /// Destination as `scheme://host:port/path` (never the query string).
    pub destination: String,
    /// Machine-readable reason, for example `not_on_allowlist` or `address_class:loopback`.
    pub reason: String,
    /// Which component asked (for example `acme`, `webhook`).
    pub caller: String,
    /// Egress class (`allowlist`, `user_url`, `target_guard`, `dns_resolution`).
    pub class: &'static str,
    /// Events dropped from the sink since the previous emitted event.
    pub suppressed_before: u64,
}

impl DenyEvent {
    /// The event as a single JSON line.
    pub fn to_json_line(&self) -> String {
        serde_json::json!({
            "event": "egress_denied",
            "destination": self.destination,
            "reason": self.reason,
            "caller": self.caller,
            "class": self.class,
            "suppressed_before": self.suppressed_before,
        })
        .to_string()
    }
}

type Sink = Box<dyn Fn(&DenyEvent) + Send + Sync>;

struct RateState {
    window_start: Instant,
    emitted_in_window: u32,
    suppressed: u64,
}

/// The deny log.
pub struct DenyLog {
    sink: Sink,
    max_per_window: u32,
    window: Duration,
    state: Mutex<RateState>,
    total: AtomicU64,
    recent: Mutex<VecDeque<DenyEvent>>,
}

/// Capacity of the in-memory ring of recent events.
pub const RECENT_CAPACITY: usize = 64;

impl DenyLog {
    /// A log with a custom sink, at most `max_per_window` emitted events per `window`.
    pub fn new(sink: Sink, max_per_window: u32, window: Duration) -> Self {
        DenyLog {
            sink,
            max_per_window,
            window,
            state: Mutex::new(RateState {
                window_start: Instant::now(),
                emitted_in_window: 0,
                suppressed: 0,
            }),
            total: AtomicU64::new(0),
            recent: Mutex::new(VecDeque::new()),
        }
    }

    /// Default: JSON lines on standard error, 20 per minute.
    pub fn stderr() -> Self {
        DenyLog::new(
            Box::new(|e| {
                // never panic on a closed or broken stderr (R-09): the denial is already counted and kept in the ring
                let _ = writeln!(std::io::stderr(), "{}", e.to_json_line());
            }),
            20,
            Duration::from_secs(60),
        )
    }

    /// Record a denial.
    pub fn record(&self, destination: &str, reason: &str, caller: &str, class: &'static str) {
        self.total.fetch_add(1, Ordering::Relaxed);
        let mut event = DenyEvent {
            destination: destination.to_owned(),
            reason: reason.to_owned(),
            caller: caller.to_owned(),
            class,
            suppressed_before: 0,
        };
        let emit = {
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if st.window_start.elapsed() >= self.window {
                st.window_start = Instant::now();
                st.emitted_in_window = 0;
            }
            if st.emitted_in_window < self.max_per_window {
                st.emitted_in_window += 1;
                event.suppressed_before = std::mem::take(&mut st.suppressed);
                true
            } else {
                st.suppressed += 1;
                false
            }
        };
        {
            let mut ring = self.recent.lock().unwrap_or_else(|p| p.into_inner());
            if ring.len() >= RECENT_CAPACITY {
                ring.pop_front();
            }
            ring.push_back(event.clone());
        }
        if emit {
            (self.sink)(&event);
        }
    }

    /// Total denials recorded since creation (emitted or not).
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// The most recent events (up to [`RECENT_CAPACITY`]), oldest first.
    pub fn recent(&self) -> Vec<DenyEvent> {
        self.recent
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn capturing(max: u32, window: Duration) -> (DenyLog, Arc<Mutex<Vec<DenyEvent>>>) {
        let store = Arc::new(Mutex::new(Vec::new()));
        let s2 = Arc::clone(&store);
        let log = DenyLog::new(
            Box::new(move |e| s2.lock().unwrap_or_else(|p| p.into_inner()).push(e.clone())),
            max,
            window,
        );
        (log, store)
    }

    #[test]
    fn events_are_structured_and_json_lines_carry_the_fields() {
        let (log, store) = capturing(10, Duration::from_secs(60));
        log.record(
            "https://evil.test:443/x",
            "not_on_allowlist",
            "acme",
            "allowlist",
        );
        let got = store.lock().expect("lock").clone();
        assert_eq!(got.len(), 1);
        let line = got[0].to_json_line();
        let v: serde_json::Value = serde_json::from_str(&line).expect("json");
        assert_eq!(v["event"], "egress_denied");
        assert_eq!(v["destination"], "https://evil.test:443/x");
        assert_eq!(v["reason"], "not_on_allowlist");
        assert_eq!(v["caller"], "acme");
        assert_eq!(v["class"], "allowlist");
        assert_eq!(v["suppressed_before"], 0);
    }

    #[test]
    fn the_log_is_rate_limited_but_nothing_is_lost_from_the_counters() {
        let (log, store) = capturing(3, Duration::from_millis(400));
        for i in 0..10 {
            log.record(
                &format!("https://h{i}.test:443/"),
                "not_on_allowlist",
                "t",
                "allowlist",
            );
        }
        assert_eq!(
            store.lock().expect("lock").len(),
            3,
            "only the first three reach the sink"
        );
        assert_eq!(log.total(), 10);
        assert_eq!(log.recent().len(), 10);
        std::thread::sleep(Duration::from_millis(500));
        log.record(
            "https://after.test:443/",
            "not_on_allowlist",
            "t",
            "allowlist",
        );
        let got = store.lock().expect("lock").clone();
        assert_eq!(got.len(), 4);
        assert_eq!(
            got.last().map(|e| e.suppressed_before),
            Some(7),
            "the next emitted event reports what was suppressed"
        );
    }

    #[test]
    fn the_recent_ring_is_bounded() {
        let (log, _) = capturing(1, Duration::from_secs(60));
        for i in 0..(RECENT_CAPACITY + 10) {
            log.record(&format!("https://h{i}.test:443/"), "r", "t", "allowlist");
        }
        let recent = log.recent();
        assert_eq!(recent.len(), RECENT_CAPACITY);
        assert_eq!(
            recent.first().map(|e| e.destination.as_str()),
            Some("https://h10.test:443/")
        );
    }
}
