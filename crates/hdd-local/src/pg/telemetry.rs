//! `MET-hdd_embedded_db_up` and the `AUD-runtime.embedded_db` events (T-0563 step 7). The central metrics registry and the audit
//! log arrive with later tasks; until then the manager records both here, and a consumer reads or forwards them.

use std::sync::Mutex;
use std::sync::PoisonError;
use std::sync::atomic::{AtomicBool, Ordering};

/// One `runtime.embedded_db` audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// Action (`installed`, `initialized`, `started`, `stopped`, `start_failed`, `backup`, `restore`, `reset`).
    pub action: String,
    /// Plain-language detail without secrets.
    pub detail: String,
}

/// Gauge and events of one manager.
#[derive(Debug, Default)]
pub struct Telemetry {
    up: AtomicBool,
    events: Mutex<Vec<AuditEvent>>,
}

/// Most events kept in memory.
pub const MAX_EVENTS: usize = 1000;

impl Telemetry {
    /// Empty telemetry, database down.
    pub fn new() -> Telemetry {
        Telemetry::default()
    }

    /// Record the state of the server.
    pub fn set_up(&self, up: bool) {
        self.up.store(up, Ordering::Relaxed);
    }

    /// Current gauge value.
    pub fn is_up(&self) -> bool {
        self.up.load(Ordering::Relaxed)
    }

    /// Record an `AUD-runtime.embedded_db` event.
    pub fn audit(&self, action: &str, detail: &str) {
        let mut g = self.events.lock().unwrap_or_else(PoisonError::into_inner);
        if g.len() >= MAX_EVENTS {
            g.remove(0);
        }
        g.push(AuditEvent {
            action: action.to_owned(),
            detail: detail.to_owned(),
        });
    }

    /// The recorded events, oldest first.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Prometheus text for `hdd_embedded_db_up`.
    pub fn render_prometheus(&self) -> String {
        format!(
            "# HELP hdd_embedded_db_up 1 when the embedded database answers (local profile)\n# TYPE hdd_embedded_db_up gauge\nhdd_embedded_db_up {}\n",
            u8::from(self.is_up())
        )
    }
}
