//! The event store: an in-memory ring of the last [`api::EVENT_RING_CAPACITY`] request events for the dashboard plus a
//! JSONL append log at `log_path` (one JSON object per line, same [`api::EventView`] shape as the ring, so the file and
//! the UI cannot drift apart). The log never contains request bodies or secrets (COLLAB.md: never log bodies).
//!
//! Admin mutations are audited through [`EventStore::audit`], which writes a separate `kind: "audit"` JSONL line; only
//! request events enter the in-memory ring.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use crate::api::{Counters, EVENT_RING_CAPACITY, EventView};
use crate::util;

/// The default number of events `GET /api/events` returns when `limit` is absent.
pub const DEFAULT_EVENT_LIMIT: usize = 200;

/// One retained event with the unix second it happened at (the wire type only carries the formatted timestamp).
struct Retained {
    /// The event as served by the API and written to the JSONL log.
    view: EventView,
    /// Unix seconds, used for the rolling counters.
    unix_seconds: u64,
}

/// The in-memory ring and the append-only JSONL writer.
pub struct EventStore {
    /// The ring and the log file handle, guarded together so a line is never written without its ring entry.
    inner: Mutex<Inner>,
    /// The next sequence number.
    next_sequence: AtomicU64,
    /// How many log write attempts failed (surfaced as an audit line, not hidden).
    write_errors: AtomicU64,
}

/// Mutable state behind one mutex.
struct Inner {
    /// Newest events are at the back.
    ring: VecDeque<Retained>,
    /// The append handle; `None` when the log could not be opened at start-up.
    file: Option<File>,
}

/// The query filter of `GET /api/events`.
#[derive(Debug, Clone, Copy, Default)]
pub struct EventFilter<'a> {
    /// Only this site host.
    pub site: Option<&'a str>,
    /// Only this action (`block`, `would_block`, `allow`).
    pub action: Option<&'a str>,
    /// A free-text search over the explainable fields.
    pub q: Option<&'a str>,
    /// The maximum number of events returned.
    pub limit: usize,
}

impl EventStore {
    /// Open the JSONL log (creating its parent directory) and an empty ring.
    ///
    /// # Errors
    /// Returns a message when the directory or file cannot be created.
    pub fn open(path: &Path) -> Result<Self, String> {
        let file = if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "cannot create the event log directory `{}`: {error}",
                    parent.display()
                )
            })?;
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|error| {
                    format!("cannot open the event log `{}`: {error}", path.display())
                })?
        } else {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|error| {
                    format!("cannot open the event log `{}`: {error}", path.display())
                })?
        };
        Ok(Self {
            inner: Mutex::new(Inner {
                ring: VecDeque::with_capacity(64),
                file: Some(file),
            }),
            next_sequence: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
        })
    }

    /// Open an in-memory-only store (the JSONL path is not used).
    ///
    /// # Errors
    /// Never fails today; the signature mirrors [`EventStore::open`] so callers stay uniform.
    pub fn in_memory() -> Result<Self, String> {
        Ok(Self {
            inner: Mutex::new(Inner {
                ring: VecDeque::with_capacity(64),
                file: None,
            }),
            next_sequence: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
        })
    }

    /// Record one request event: assign the sequence number, append the JSONL line, push into the ring.
    ///
    /// Returns the assigned sequence number.
    pub fn record(&self, mut view: EventView) -> u64 {
        let sequence = self.next_sequence.fetch_add(1, Ordering::Relaxed) + 1;
        view.seq = sequence;
        let unix_seconds = util::unix_secs(SystemTime::now());
        let line = serde_json::to_vec(&view).ok();
        let mut inner = util::lock(&self.inner);
        if let (Some(file), Some(line)) = (inner.file.as_mut(), line)
            && (file.write_all(&line).is_err() || file.write_all(b"\n").is_err())
        {
            self.write_errors.fetch_add(1, Ordering::Relaxed);
        }
        inner.ring.push_back(Retained { view, unix_seconds });
        while inner.ring.len() > EVENT_RING_CAPACITY {
            inner.ring.pop_front();
        }
        sequence
    }

    /// Append an administrative audit line (actor, action, target) to the JSONL log only.
    ///
    /// Audit lines carry no request body and no secret; `detail` is a short human summary.
    pub fn audit(&self, actor: &str, action: &str, target: &str, detail: &str) {
        let line = serde_json::json!({
            "kind": "audit",
            "time": util::rfc3339_now(),
            "actor": actor,
            "action": action,
            "target": target,
            "detail": detail,
        });
        let mut inner = util::lock(&self.inner);
        if let Some(file) = inner.file.as_mut() {
            let mut text = line.to_string();
            text.push('\n');
            if file.write_all(text.as_bytes()).is_err() {
                self.write_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Query the ring, newest first, applying the filter and the limit.
    #[must_use]
    pub fn query(&self, filter: &EventFilter<'_>) -> Vec<EventView> {
        let limit = filter.limit.clamp(1, EVENT_RING_CAPACITY);
        let needle = filter.q.map(str::to_ascii_lowercase);
        let inner = util::lock(&self.inner);
        let mut out = Vec::with_capacity(limit.min(inner.ring.len()));
        for retained in inner.ring.iter().rev() {
            let view = &retained.view;
            if let Some(site) = filter.site
                && view.site != site
            {
                continue;
            }
            if let Some(action) = filter.action
                && !view.action.eq_ignore_ascii_case(action)
            {
                continue;
            }
            if let Some(needle) = needle.as_deref()
                && !event_matches(view, needle)
            {
                continue;
            }
            out.push(view.clone());
            if out.len() >= limit {
                break;
            }
        }
        out
    }

    /// The requests / blocked / would_block counts over the retained events of the last hour.
    #[must_use]
    pub fn window_counts(&self) -> (u64, u64, u64) {
        let now = util::unix_secs(SystemTime::now());
        let hour_ago = now.saturating_sub(3_600);
        let inner = util::lock(&self.inner);
        let mut requests = 0_u64;
        let mut blocked = 0_u64;
        let mut would_block = 0_u64;
        for retained in &inner.ring {
            if retained.unix_seconds < hour_ago {
                continue;
            }
            requests += 1;
            match retained.view.action.as_str() {
                "block" => blocked += 1,
                "would_block" => would_block += 1,
                _ => {}
            }
        }
        (requests, blocked, would_block)
    }

    /// Build the [`Counters`] DTO for the last hour (`banned_ips` comes from the ban store).
    #[must_use]
    pub fn counters(&self, banned_ips: u64) -> Counters {
        let (requests, blocked, would_block) = self.window_counts();
        Counters {
            requests,
            blocked,
            would_block,
            banned_ips,
            window_seconds: 3_600,
        }
    }

    /// How many JSONL writes failed (a non-zero value is a real durability problem and must be surfaced).
    #[must_use]
    pub fn write_errors(&self) -> u64 {
        self.write_errors.load(Ordering::Relaxed)
    }
}

/// Whether the free-text search matches one event (case-insensitive over the explainable fields).
fn event_matches(view: &EventView, needle: &str) -> bool {
    let fields = [
        Some(view.site.as_str()),
        Some(view.client_ip.as_str()),
        Some(view.method.as_str()),
        Some(view.path.as_str()),
        Some(view.ray_id.as_str()),
        Some(view.action.as_str()),
        view.category.as_deref(),
        view.subtype.as_deref(),
        view.rule_id.as_deref(),
        view.vector.as_deref(),
        view.field.as_deref(),
        Some(view.evidence.as_str()),
    ];
    fields
        .iter()
        .flatten()
        .any(|value| value.to_ascii_lowercase().contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(action: &str, site: &str) -> EventView {
        EventView {
            seq: 0,
            time: util::rfc3339_now(),
            ray_id: util::new_ray_id(),
            site: site.to_owned(),
            client_ip: "127.0.0.1".to_owned(),
            method: "GET".to_owned(),
            path: "/login".to_owned(),
            action: action.to_owned(),
            category: None,
            subtype: None,
            rule_id: None,
            vector: None,
            field: None,
            field_kind: None,
            evidence: String::new(),
            mode: "block".to_owned(),
            config_revision: 1,
        }
    }

    #[test]
    fn ring_assigns_increasing_sequence_numbers_and_queries_newest_first() {
        let store = EventStore::in_memory().expect("in-memory store");
        store.record(event("allow", "a.test"));
        store.record(event("block", "a.test"));
        let events = store.query(&EventFilter {
            limit: 10,
            ..EventFilter::default()
        });
        assert_eq!(events.len(), 2);
        assert_eq!(events.first().map(|e| e.action.as_str()), Some("block"));
        assert_eq!(events.first().map(|e| e.seq), Some(2));
    }

    #[test]
    fn filters_by_site_action_and_free_text() {
        let store = EventStore::in_memory().expect("in-memory store");
        store.record(event("allow", "a.test"));
        store.record(event("block", "b.test"));
        let blocked = store.query(&EventFilter {
            site: Some("b.test"),
            action: Some("block"),
            q: Some("127.0.0.1"),
            limit: 10,
        });
        assert_eq!(blocked.len(), 1);
        let none = store.query(&EventFilter {
            site: Some("b.test"),
            action: Some("allow"),
            q: None,
            limit: 10,
        });
        assert!(none.is_empty());
    }

    #[test]
    fn ring_capacity_is_bounded() {
        let store = EventStore::in_memory().expect("in-memory store");
        for index in 0..(EVENT_RING_CAPACITY + 25) {
            let mut view = event("allow", "a.test");
            view.path = format!("/{index}");
            store.record(view);
        }
        let events = store.query(&EventFilter {
            limit: EVENT_RING_CAPACITY,
            ..EventFilter::default()
        });
        assert_eq!(events.len(), EVENT_RING_CAPACITY);
        let (requests, blocked, would_block) = store.window_counts();
        assert_eq!(requests, EVENT_RING_CAPACITY as u64);
        assert_eq!((blocked, would_block), (0, 0));
    }

    #[test]
    fn jsonl_log_appends_one_object_per_line_without_bodies() {
        let directory = std::env::temp_dir().join(format!(
            "hdd-proxy-events-{}-{}",
            std::process::id(),
            util::unix_millis(SystemTime::now())
        ));
        let path = directory.join("events.jsonl");
        let store = EventStore::open(&path).expect("log opens");
        store.record(event("block", "a.test"));
        store.audit("owner", "mode_change", "a.test", "block -> monitor");
        let text = std::fs::read_to_string(&path).expect("log is readable");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_str(lines.first().copied().unwrap_or("{}"))
            .expect("first line is JSON");
        assert_eq!(
            first.get("action").and_then(serde_json::Value::as_str),
            Some("block")
        );
        assert!(first.get("body").is_none());
        let second: serde_json::Value = serde_json::from_str(lines.get(1).copied().unwrap_or("{}"))
            .expect("second line is JSON");
        assert_eq!(
            second.get("kind").and_then(serde_json::Value::as_str),
            Some("audit")
        );
        assert_eq!(store.write_errors(), 0);
        let _ = std::fs::remove_dir_all(&directory);
    }
}
