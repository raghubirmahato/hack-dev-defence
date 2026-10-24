//! Property tests: `inspect` never panics on arbitrary bytes or text, its verdicts keep the documented invariants,
//! and the mandated payloads stay detected under arbitrary percent-encoding.
//!
//! The linear-time obligation is asserted by operation counting in the crate's unit tests (`src/lib.rs`), never by
//! wall-clock time.
//!
//! Every property also re-checks the verdict invariants (evidence cap, category only on Block).

use hdd_waf_core::{Action, InspectInput, MAX_EVIDENCE_BYTES, SiteSettings, Vector, inspect};
use proptest::prelude::*;

const MANDATED: [&str; 6] = [
    "' OR 1=1--",
    "' OR '1'='1",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' or 1=1 LIMIT 1 --",
];

fn invariant_checks(verdict: &hdd_waf_core::Verdict) {
    assert!(
        verdict.evidence.len() <= MAX_EVIDENCE_BYTES,
        "evidence larger than the cap: {}",
        verdict.evidence.len()
    );
    assert!(
        verdict.evidence.is_char_boundary(verdict.evidence.len()),
        "evidence cut inside a UTF-8 character"
    );
    assert!(verdict.score <= 100, "score {} out of range", verdict.score);
    if verdict.action == Action::Block {
        assert_eq!(verdict.category, Some("sqli"));
        assert!(!verdict.evidence.is_empty());
        assert!(verdict.vector.is_some());
        assert!(verdict.field.is_some());
        assert!(verdict.field_kind.is_some());
        assert!(verdict.subtype.is_some());
        assert!(verdict.rule_id.is_some());
    } else {
        assert_eq!(verdict.category, None);
        assert_eq!(verdict.subtype, None);
        assert_eq!(verdict.rule_id, None);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn arbitrary_body_bytes_never_panic(body in prop::collection::vec(any::<u8>(), 0..4096)) {
        let headers: Vec<(String, String)> = Vec::new();
        let input = InspectInput {
            method: "POST",
            path: "/login",
            query: Some("q=test"),
            headers: &headers,
            content_type: Some("application/json"),
            body: &body,
        };
        let verdict = inspect(&input, &SiteSettings::default());
        invariant_checks(&verdict);
    }

    #[test]
    fn arbitrary_header_value_never_panics(value in ".*") {
        let headers = vec![("User-Agent".to_owned(), value)];
        let input = InspectInput {
            method: "GET",
            path: "/login",
            query: Some("q=x"),
            headers: &headers,
            content_type: None,
            body: b"",
        };
        let verdict = inspect(&input, &SiteSettings::default());
        invariant_checks(&verdict);
    }

    #[test]
    fn arbitrary_query_and_path_never_panic(
        query in ".*",
        path_segment in "[^/]{0,128}",
    ) {
        let path = format!("/login/{path_segment}");
        let input = InspectInput {
            method: "GET",
            path: &path,
            query: Some(&query),
            headers: &[],
            content_type: None,
            body: b"",
        };
        let verdict = inspect(&input, &SiteSettings::default());
        invariant_checks(&verdict);
    }

    #[test]
    fn mandated_payloads_survive_arbitrary_percent_encoding(
        index in 0usize..6,
        mask in prop::collection::vec(any::<bool>(), 0..64),
    ) {
        let payload = MANDATED.get(index).copied().unwrap_or(MANDATED.first().copied().unwrap_or(""));
        let mut encoded = String::new();
        for (position, byte) in payload.as_bytes().iter().enumerate() {
            // Always encode the query-string and percent characters so the parser cannot split the payload;
            // the rest is encoded or left literal according to the arbitrary mask.
            let forced = matches!(*byte, b'&' | b'=' | b'%');
            let encode = forced || mask.get(position).copied().unwrap_or(false);
            if encode {
                encoded.push_str(&format!("%{byte:02X}"));
            } else {
                encoded.push(char::from(*byte));
            }
        }
        let headers = vec![("User-Agent".to_owned(), encoded.clone())];
        let input = InspectInput {
            method: "GET",
            path: "/login",
            query: None,
            headers: &headers,
            content_type: None,
            body: b"",
        };
        let verdict = inspect(&input, &SiteSettings::default());
        invariant_checks(&verdict);
        prop_assert_eq!(
            verdict.action,
            Action::Block,
            "encoded mandated payload not blocked: {:?} (encoded {:?})",
            payload,
            encoded
        );
        prop_assert_eq!(verdict.category, Some("sqli"));
        prop_assert_eq!(verdict.vector, Some(Vector::Header));
    }
}
