//! The findings engine (Addendum 6 item 1): blocked events grouped into findings, each with the deterministic
//! explanation from [`hdd_waf_core::explain`] â€” what was detected, the inferred weakness, what an attacker could do and
//! how to fix it â€” plus the honest confidence (`attempt_observed` until the owner runs the confirm probe, then
//! `confirmed`).
//!
//! Grouping key: site + method + path + vector + field + family (`subtype`). The stable id is the first 16 hex
//! characters of the SHA-256 of that key, so the same attack group always maps to the same finding id.
//! Findings are in memory for the HK1 demo; the JSONL event log remains the durable raw record. Only *detector*
//! block events become findings: early-ban refusals and body-cap refusals (no rule id) stay in the event log because
//! they are not a newly detected attack shape.
//!
//! No request body, cookie, token or header value is stored here: the record keeps only the detector's redacted
//! evidence (at most [`hdd_waf_core::MAX_EVIDENCE_BYTES`]) and the request line metadata already shown in the UI.

use std::collections::HashMap;
use std::sync::Mutex;

use hdd_waf_core::{ExplainRequest, FieldKind, Stack, Vector, explain};
use sha2::{Digest, Sha256};

use crate::api::{CodeExampleView, EventView, FindingView, RemediationView};
use crate::util;

/// The confidence of a finding that only observed blocked attempts.
pub const CONFIDENCE_ATTEMPT: &str = "attempt_observed";
/// The confidence of a finding whose confirm probe reported `confirmed_injectable`.
pub const CONFIDENCE_CONFIRMED: &str = "confirmed";
/// The default number of findings returned by [`FindingsStore::list`] when no limit is given.
pub const DEFAULT_FINDING_LIMIT: usize = 100;
/// The largest number of findings returned in one response.
pub const MAX_FINDING_LIMIT: usize = 500;

/// One recorded finding group.
#[derive(Debug, Clone)]
struct FindingRecord {
    /// The stable finding id.
    id: String,
    /// The site host the blocked events were seen on.
    site: String,
    /// The request method.
    method: String,
    /// The request path.
    path: String,
    /// Where in the request the value was found.
    vector: Vector,
    /// The field name.
    field: String,
    /// The inferred field kind.
    field_kind: FieldKind,
    /// The detector rule id that fired.
    rule_id: String,
    /// The family/subtype of the attack shape.
    family: String,
    /// The attack category (`sqli`, `custom`, `policy`).
    category: String,
    /// RFC 3339 UTC time of the first blocked event.
    first_seen: String,
    /// RFC 3339 UTC time of the most recent blocked event.
    last_seen: String,
    /// How many blocked events were grouped.
    count: u64,
    /// The most recent redacted evidence (at most 128 bytes).
    evidence: String,
    /// The site's stack hint (picks the remediation code example).
    stack: Stack,
    /// Whether the owner's confirm probe reported the finding as confirmed.
    confirmed: bool,
}

/// The in-memory findings store.
///
/// `Mutex`-guarded so the store is `Send + Sync`; the data path records one finding per blocked *detector* event.
pub struct FindingsStore {
    /// The finding records keyed by id.
    inner: Mutex<HashMap<String, FindingRecord>>,
}

impl FindingsStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Record one blocked event into its finding group.
    ///
    /// Returns the updated [`FindingView`] when the event became part of a finding, or `None` when the event is not a
    /// newly detected attack (not a `block` action, or no detector rule id: early-ban and body-cap refusals).
    pub fn record(&self, event: &EventView, stack: Stack) -> Option<FindingView> {
        if event.action != "block" {
            return None;
        }
        let rule_id = event.rule_id.as_deref()?;
        let family = event
            .subtype
            .clone()
            .unwrap_or_else(|| "unknown".to_owned());
        let category = event.category.clone().unwrap_or_else(|| "sqli".to_owned());
        let vector = parse_vector(event.vector.as_deref());
        let field = event.field.clone().unwrap_or_default();
        let field_kind = parse_field_kind(event.field_kind.as_deref());
        let key = group_key(
            &event.site,
            &event.method,
            &event.path,
            vector,
            &field,
            &family,
        );
        let id = finding_id(&key);
        let mut inner = util::lock(&self.inner);
        let view = match inner.get_mut(&id) {
            Some(record) => {
                record.count = record.count.saturating_add(1);
                record.last_seen.clone_from(&event.time);
                record.evidence = redacted_evidence(&event.evidence);
                record.stack = stack;
                build_view(record)
            }
            None => {
                let record = FindingRecord {
                    id: id.clone(),
                    site: event.site.clone(),
                    method: event.method.clone(),
                    path: util::truncate_utf8(&event.path, 2_048).to_owned(),
                    vector,
                    field: util::truncate_utf8(&field, 256).to_owned(),
                    field_kind,
                    rule_id: rule_id.to_owned(),
                    family,
                    category,
                    first_seen: event.time.clone(),
                    last_seen: event.time.clone(),
                    count: 1,
                    evidence: redacted_evidence(&event.evidence),
                    stack,
                    confirmed: false,
                };
                let view = build_view(&record);
                inner.insert(id, record);
                view
            }
        };
        Some(view)
    }

    /// Mark a finding as confirmed by the owner's confirm probe. Returns whether the finding exists.
    pub fn mark_confirmed(&self, id: &str) -> bool {
        let mut inner = util::lock(&self.inner);
        match inner.get_mut(id) {
            Some(record) => {
                record.confirmed = true;
                true
            }
            None => false,
        }
    }

    /// The finding view for one id (AI explanation attached separately by the admin route).
    #[must_use]
    pub fn get(&self, id: &str) -> Option<FindingView> {
        let inner = util::lock(&self.inner);
        inner.get(id).map(build_view)
    }

    /// List findings, newest first by `last_seen`, applying the optional site/family/search filters and the limit.
    #[must_use]
    pub fn list(
        &self,
        site: Option<&str>,
        family: Option<&str>,
        query: Option<&str>,
        limit: usize,
    ) -> Vec<FindingView> {
        let limit = limit.clamp(1, MAX_FINDING_LIMIT);
        let needle = query.map(str::to_ascii_lowercase);
        let inner = util::lock(&self.inner);
        let mut records: Vec<&FindingRecord> = inner
            .values()
            .filter(|record| site.is_none_or(|wanted| record.site == wanted))
            .filter(|record| family.is_none_or(|wanted| record.family == wanted))
            .filter(|record| {
                needle.as_deref().is_none_or(|needle| {
                    [
                        record.site.as_str(),
                        record.method.as_str(),
                        record.path.as_str(),
                        record.field.as_str(),
                        record.rule_id.as_str(),
                        record.family.as_str(),
                        record.evidence.as_str(),
                    ]
                    .iter()
                    .any(|value| value.to_ascii_lowercase().contains(needle))
                })
            })
            .collect();
        records.sort_by(|left, right| {
            right
                .last_seen
                .cmp(&left.last_seen)
                .then_with(|| left.id.cmp(&right.id))
        });
        records.into_iter().take(limit).map(build_view).collect()
    }

    /// The total number of findings (before any list limit/filter).
    #[must_use]
    pub fn total(&self) -> u64 {
        let inner = util::lock(&self.inner);
        inner.len() as u64
    }
}

impl Default for FindingsStore {
    fn default() -> Self {
        Self::new()
    }
}

/// The display name of a stack hint (matches the frozen `FindingView.stack` string).
#[must_use]
pub fn stack_name(stack: Stack) -> &'static str {
    match stack {
        Stack::Node => "node",
        Stack::Php => "php",
        Stack::Python => "python",
        Stack::Java => "java",
        Stack::Other => "other",
    }
}

/// Build the API view for one record by calling the deterministic explanation module.
fn build_view(record: &FindingRecord) -> FindingView {
    let request = ExplainRequest {
        category: &record.category,
        family: &record.family,
        rule_id: &record.rule_id,
        vector: record.vector,
        field_name: &record.field,
        field_kind: record.field_kind,
        method: &record.method,
        path: &record.path,
        evidence: &record.evidence,
        stack: record.stack,
    };
    let explanation = explain(&request);
    FindingView {
        id: record.id.clone(),
        site: record.site.clone(),
        method: record.method.clone(),
        path: record.path.clone(),
        vector: util::vector_name(record.vector).to_owned(),
        field: record.field.clone(),
        field_kind: util::field_kind_name(record.field_kind).to_owned(),
        rule_id: record.rule_id.clone(),
        family: record.family.clone(),
        category: record.category.clone(),
        first_seen: record.first_seen.clone(),
        last_seen: record.last_seen.clone(),
        count: record.count,
        evidence: record.evidence.clone(),
        detected: explanation.detected,
        inferred_weakness: explanation.inferred_weakness,
        attacker_impact: explanation.attacker_impact,
        confidence: if record.confirmed {
            CONFIDENCE_CONFIRMED.to_owned()
        } else {
            CONFIDENCE_ATTEMPT.to_owned()
        },
        remediation: RemediationView {
            steps: explanation.remediation_steps,
            code_example: CodeExampleView {
                language: explanation.code_example.language,
                caption: explanation.code_example.caption,
                code: explanation.code_example.code,
            },
            virtual_patch_note: explanation.virtual_patch_note,
        },
        stack: stack_name(record.stack).to_owned(),
        ai: None,
    }
}

/// The grouping key whose SHA-256 becomes the stable finding id.
fn group_key(
    site: &str,
    method: &str,
    path: &str,
    vector: Vector,
    field: &str,
    family: &str,
) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        site,
        method,
        path,
        util::vector_name(vector),
        field,
        family
    )
}

/// The stable finding id: the first 16 hex characters of SHA-256 of the grouping key.
fn finding_id(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    let mut out = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Keep the evidence at most [`hdd_waf_core::MAX_EVIDENCE_BYTES`], on a UTF-8 boundary.
fn redacted_evidence(evidence: &str) -> String {
    util::truncate_utf8(evidence, hdd_waf_core::MAX_EVIDENCE_BYTES).to_owned()
}

/// Map the event's vector string back to the typed vector (unknown values fall back to `Query`).
fn parse_vector(value: Option<&str>) -> Vector {
    match value {
        Some("path") => Vector::Path,
        Some("form_body") => Vector::FormBody,
        Some("json_body") => Vector::JsonBody,
        Some("multipart_field") => Vector::MultipartField,
        Some("multipart_filename") => Vector::MultipartFilename,
        Some("header") => Vector::Header,
        Some("cookie") => Vector::Cookie,
        _ => Vector::Query,
    }
}

/// Map the event's field-kind string back to the typed kind (unknown values fall back to `Unknown`).
fn parse_field_kind(value: Option<&str>) -> FieldKind {
    match value {
        Some("password") => FieldKind::Password,
        Some("username") => FieldKind::Username,
        Some("numeric_id") => FieldKind::NumericId,
        Some("search") => FieldKind::Search,
        Some("free_text") => FieldKind::FreeText,
        Some("filename") => FieldKind::Filename,
        Some("header") => FieldKind::Header,
        Some("cookie") => FieldKind::Cookie,
        _ => FieldKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(rule_id: Option<&str>, family: Option<&str>, evidence: &str) -> EventView {
        EventView {
            seq: 1,
            time: util::rfc3339_now(),
            ray_id: util::new_ray_id(),
            site: "demo.test".to_owned(),
            client_ip: "127.0.0.1".to_owned(),
            method: "POST".to_owned(),
            path: "/admin/login".to_owned(),
            action: "block".to_owned(),
            category: Some("sqli".to_owned()),
            subtype: family.map(str::to_owned),
            rule_id: rule_id.map(str::to_owned),
            vector: Some("form_body".to_owned()),
            field: Some("username".to_owned()),
            field_kind: Some("username".to_owned()),
            evidence: evidence.to_owned(),
            mode: "block".to_owned(),
            config_revision: 1,
        }
    }

    #[test]
    fn grouping_counts_events_and_keeps_first_and_last_seen() {
        let store = FindingsStore::new();
        let mut first = event(Some("H2-001"), Some("comment_breakout"), "admin' --");
        first.time = "2026-10-24T00:00:00.000Z".to_owned();
        let mut second = first.clone();
        second.time = "2026-10-24T00:00:05.000Z".to_owned();
        second.seq = 2;
        assert_eq!(
            store.record(&first, Stack::Node).map(|view| view.count),
            Some(1)
        );
        let view = store
            .record(&second, Stack::Node)
            .expect("the second event joins the group");
        assert_eq!(view.count, 2);
        assert_eq!(view.first_seen, "2026-10-24T00:00:00.000Z");
        assert_eq!(view.last_seen, "2026-10-24T00:00:05.000Z");
        assert_eq!(store.total(), 1);
        assert_eq!(view.stack, "node");
        assert_eq!(view.confidence, CONFIDENCE_ATTEMPT);
        assert!(!view.detected.is_empty());
        assert!(!view.attacker_impact.is_empty());
        assert!(!view.remediation.steps.is_empty());
    }

    #[test]
    fn a_different_family_or_field_makes_a_new_finding() {
        let store = FindingsStore::new();
        store.record(
            &event(Some("H2-001"), Some("comment_breakout"), "x"),
            Stack::Other,
        );
        store.record(&event(Some("H1-001"), Some("tautology"), "x"), Stack::Other);
        assert_eq!(store.total(), 2);
    }

    #[test]
    fn ids_are_stable_and_hex() {
        let store = FindingsStore::new();
        let view = store
            .record(
                &event(Some("H2-001"), Some("comment_breakout"), "x"),
                Stack::Other,
            )
            .expect("recorded");
        assert_eq!(view.id.len(), 16);
        assert!(view.id.bytes().all(|b| b.is_ascii_hexdigit()));
        let again = store
            .record(
                &event(Some("H2-001"), Some("comment_breakout"), "x"),
                Stack::Other,
            )
            .expect("recorded");
        assert_eq!(view.id, again.id);
        assert_eq!(
            store.get(&view.id).map(|found| found.id),
            Some(view.id.clone())
        );
        assert!(store.get("0000000000000000").is_none());
    }

    #[test]
    fn non_detector_blocks_are_not_findings() {
        let store = FindingsStore::new();
        // An early-ban refusal: action block but no rule id.
        assert!(
            store
                .record(&event(None, None, "temporary ban active"), Stack::Other)
                .is_none()
        );
        // A would_block and an allow never become findings, even with a rule id.
        let mut would_block = event(Some("H1-001"), Some("tautology"), "x");
        would_block.action = "would_block".to_owned();
        assert!(store.record(&would_block, Stack::Other).is_none());
        assert_eq!(store.total(), 0);
    }

    #[test]
    fn evidence_is_redacted_to_the_evidence_cap() {
        let store = FindingsStore::new();
        let long = format!("{}' OR 1=1--", "A".repeat(500));
        let view = store
            .record(
                &event(Some("H1-001"), Some("tautology"), &long),
                Stack::Other,
            )
            .expect("recorded");
        assert!(view.evidence.len() <= hdd_waf_core::MAX_EVIDENCE_BYTES);
        assert!(!view.evidence.contains(&"A".repeat(200)));
        let long_path = "P".repeat(4_000);
        let mut deep = event(Some("H1-001"), Some("tautology"), "x");
        deep.path = long_path.clone();
        let view = store.record(&deep, Stack::Other).expect("recorded");
        assert!(view.path.len() <= 2_048);
    }

    #[test]
    fn mark_confirmed_transitions_confidence() {
        let store = FindingsStore::new();
        let view = store
            .record(
                &event(Some("H2-001"), Some("comment_breakout"), "x"),
                Stack::Other,
            )
            .expect("recorded");
        assert!(store.mark_confirmed(&view.id));
        assert_eq!(
            store.get(&view.id).map(|found| found.confidence),
            Some(CONFIDENCE_CONFIRMED.to_owned())
        );
        assert!(!store.mark_confirmed("ffffffffffffffff"));
    }

    #[test]
    fn list_filters_and_sorts_newest_first() {
        let store = FindingsStore::new();
        let mut older = event(Some("H1-001"), Some("tautology"), "x");
        older.time = "2026-10-24T00:00:00.000Z".to_owned();
        store.record(&older, Stack::Other);
        let mut newer = event(Some("H2-001"), Some("comment_breakout"), "y");
        newer.time = "2026-10-24T00:10:00.000Z".to_owned();
        newer.site = "other.test".to_owned();
        store.record(&newer, Stack::Other);
        let all = store.list(None, None, None, 10);
        assert_eq!(all.len(), 2);
        assert_eq!(
            all.first().map(|view| view.site.as_str()),
            Some("other.test")
        );
        assert_eq!(store.list(Some("demo.test"), None, None, 10).len(), 1);
        assert_eq!(store.list(None, Some("tautology"), None, 10).len(), 1);
        assert_eq!(store.list(None, None, Some("admin"), 10).len(), 2);
        assert_eq!(
            store.list(None, None, None, 0).len(),
            1,
            "limit clamps to at least 1"
        );
    }
}
