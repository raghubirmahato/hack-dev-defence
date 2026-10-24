//! `hdd-waf-core`: normalizer, detectors, tokenizers, scoring, rules, leak scanner (pure, no I/O).
//!
//! The HK1 demo track implements the SQL-injection detector C4.1 to C4.6 and C4.8 of the specification: a bounded
//! normaliser, a request-vector extractor, a field-kind inference and the hard rule families H1 to H8. The public
//! entry point is [`inspect`]; the shared types are in [`types`]. [`explain`] builds the deterministic finding
//! explanation and remediation text of COLLAB Addendum 6 item 1.
//!
//! The crate is pure: no I/O, no clock, no network (ARCHITECTURE.md). `inspect` never panics and runs in linear time
//! in the size of the inspected input (R-09, R-29).
#![forbid(unsafe_code)]

pub mod explain;
pub mod types;

mod custom;
mod detect;
mod evidence;
mod extract;
mod field_kind;
mod normalize;
mod tokenize;

pub use custom::validate_custom_rule;
pub use detect::inspect;
pub use explain::{CodeExample, ExplainRequest, Explanation, Stack, explain};
pub use types::{
    Action, CustomRule, FieldKind, INSPECT_BODY_CAP, InspectInput, MAX_EVIDENCE_BYTES,
    SiteSettings, Strictness, Vector, Verdict,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn ops_for(payload: &str) -> u64 {
        let input = InspectInput {
            method: "POST",
            path: "/login",
            query: Some(payload),
            headers: &[],
            content_type: Some("application/x-www-form-urlencoded"),
            body: payload.as_bytes(),
        };
        let settings = SiteSettings::default();
        detect::inspect_counted(&input, &settings).1
    }

    #[test]
    fn operation_count_is_linear_in_input_size() {
        // Four times the input of repeated quotes and `or` must cost at most eight times the operations of the
        // smaller input (a quadratic implementation would cost about sixteen times). Asserted by counting the
        // detector's own work units, never by wall-clock time.
        let unit = "'or1=1--";
        let small: String = std::iter::repeat_n(unit, 2_000).collect();
        let large: String = std::iter::repeat_n(unit, 8_000).collect();
        let small_ops = ops_for(&small);
        let large_ops = ops_for(&large);
        assert!(small_ops > 0, "the counter must observe work");
        assert!(
            large_ops <= small_ops.saturating_mul(8),
            "linear bound violated: {large_ops} > 8 * {small_ops}"
        );
    }

    #[test]
    fn operation_count_is_bounded_by_a_constant_per_byte() {
        let payload: String = std::iter::repeat_n("' or 1=1-- ", 16_000).collect();
        let input = InspectInput {
            method: "GET",
            path: "/",
            query: Some("q=x"),
            headers: &[],
            content_type: None,
            body: payload.as_bytes(),
        };
        let (verdict, ops) = detect::inspect_counted(&input, &SiteSettings::default());
        assert_eq!(verdict.action, Action::Block);
        let bound = (payload.len() as u64)
            .saturating_mul(64)
            .saturating_add(65_536);
        assert!(
            ops <= bound,
            "operations {ops} exceed the linear bound {bound}"
        );
    }

    fn ops_for_body(body: &str) -> u64 {
        let input = InspectInput {
            method: "POST",
            path: "/login",
            query: None,
            headers: &[],
            content_type: Some("text/plain"),
            body: body.as_bytes(),
        };
        detect::inspect_counted(&input, &SiteSettings::default()).1
    }

    #[test]
    fn operation_count_is_linear_on_quote_and_encoding_heavy_bodies() {
        // Review R1-2: the pathological shapes were quadratic (per-quote rescans). Four times the input must cost at
        // most eight times the operations; the count is the detector's own work units, never wall-clock time.
        let units = ["'", "/* ", "\u{FF07}", "%2527", "&#x27;"];
        for unit in units {
            let small: String = std::iter::repeat_n(unit, 4_000).collect();
            let large: String = std::iter::repeat_n(unit, 16_000).collect();
            let small_ops = ops_for_body(&small);
            let large_ops = ops_for_body(&large);
            assert!(small_ops > 0, "the counter must observe work for {unit:?}");
            assert!(
                large_ops <= small_ops.saturating_mul(8),
                "linear bound violated for {unit:?}: {large_ops} > 8 * {small_ops}"
            );
        }
    }

    #[test]
    fn a_256kb_quote_body_stays_inside_the_linear_operation_bound() {
        let body: String = std::iter::repeat_n("'", 256 * 1024).collect();
        let input = InspectInput {
            method: "POST",
            path: "/login",
            query: None,
            headers: &[],
            content_type: Some("text/plain"),
            body: body.as_bytes(),
        };
        let (_, ops) = detect::inspect_counted(&input, &SiteSettings::default());
        let bound = (body.len() as u64)
            .saturating_mul(64)
            .saturating_add(1_048_576);
        assert!(
            ops <= bound,
            "operations {ops} exceed the linear bound {bound} on a 256 KiB quote body"
        );
    }

    #[test]
    fn exceeding_the_work_budget_blocks_as_truncated_policy() {
        let input = InspectInput {
            method: "POST",
            path: "/login",
            query: None,
            headers: &[],
            content_type: Some("text/plain"),
            body: b"hello world",
        };
        let (counted_verdict, ops) = detect::inspect_counted(&input, &SiteSettings::default());
        assert_eq!(counted_verdict.action, Action::Allow);
        assert!(ops > 0);
        let verdict = detect::inspect_with_budget(&input, &SiteSettings::default(), 0);
        assert_eq!(verdict.action, Action::Block);
        assert_eq!(verdict.category, Some("policy"));
        assert_eq!(verdict.subtype, Some("truncated"));
        assert_eq!(verdict.rule_id, Some("LIMIT-001"));
    }
}
