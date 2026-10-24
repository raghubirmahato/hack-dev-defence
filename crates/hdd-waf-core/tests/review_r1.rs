//! Regression tests for the HK1 review round 1 waf-core findings (R1-1 to R1-5 and the LOW detector items).
//!
//! Every test here was written against the reviewed behaviour first (red) and must stay green: the HIGH items are
//! fail-open truncation, quadratic CPU on adversarial bodies and quadratic duplicate-name grouping.

use std::time::{Duration, Instant};

use hdd_waf_core::{
    Action, CustomRule, InspectInput, SiteSettings, Strictness, Vector, Verdict, inspect,
};

fn settings(strictness: Strictness) -> SiteSettings {
    SiteSettings {
        strictness,
        field_hints: Vec::new(),
        extra_rules: Vec::<CustomRule>::new(),
    }
}

fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(*byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn owned_headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

fn inspect_query(value: &str, field: &str) -> Verdict {
    let query = format!("{field}={}", percent_encode(value));
    let input = InspectInput {
        method: "GET",
        path: "/login",
        query: Some(&query),
        headers: &[],
        content_type: None,
        body: b"",
    };
    inspect(&input, &settings(Strictness::Balanced))
}

fn inspect_header(value: &str) -> Verdict {
    let headers = owned_headers(&[("User-Agent", value)]);
    let input = InspectInput {
        method: "GET",
        path: "/login",
        query: None,
        headers: &headers,
        content_type: None,
        body: b"",
    };
    inspect(&input, &settings(Strictness::Balanced))
}

fn inspect_form(body: &str) -> Verdict {
    let input = InspectInput {
        method: "POST",
        path: "/login",
        query: None,
        headers: &[],
        content_type: Some("application/x-www-form-urlencoded"),
        body: body.as_bytes(),
    };
    inspect(&input, &settings(Strictness::Balanced))
}

fn inspect_body(content_type: Option<&str>, body: &[u8], headers: &[(String, String)]) -> Verdict {
    let input = InspectInput {
        method: "POST",
        path: "/login",
        query: None,
        headers,
        content_type,
        body,
    };
    inspect(&input, &settings(Strictness::Balanced))
}

fn many_params(count: usize, prefix: &str) -> String {
    let mut out = String::new();
    for index in 0..count {
        out.push_str(&format!("{prefix}{index}=1&"));
    }
    out
}

fn assert_policy_block(verdict: &Verdict, subtype: &str, rule_id: &str) {
    assert_eq!(verdict.action, Action::Block, "{verdict:?}");
    assert_eq!(verdict.category, Some("policy"), "{verdict:?}");
    assert_eq!(verdict.subtype, Some(subtype), "{verdict:?}");
    assert_eq!(verdict.rule_id, Some(rule_id), "{verdict:?}");
    assert!(!verdict.evidence.is_empty(), "{verdict:?}");
    assert!(verdict.evidence.len() <= hdd_waf_core::MAX_EVIDENCE_BYTES);
}

// ---------------------------------------------------------------------------------------------------------------
// R1-1: a value/body cap hit must not fail open.
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn r1_1_value_cap_on_form_body_blocks_instead_of_allow() {
    let mut body = many_params(4_099, "p");
    body.push_str("x=%27+OR+1%3D1--");
    let verdict = inspect_form(&body);
    assert_policy_block(&verdict, "truncated", "LIMIT-001");
}

#[test]
fn r1_1_value_cap_on_query_blocks_instead_of_allow() {
    let mut query = many_params(2_100, "p");
    query.push_str("x=%27+OR+1%3D1--");
    let input = InspectInput {
        method: "GET",
        path: "/login",
        query: Some(&query),
        headers: &[],
        content_type: None,
        body: b"",
    };
    let verdict = inspect(&input, &settings(Strictness::Balanced));
    assert_policy_block(&verdict, "truncated", "LIMIT-001");
}

#[test]
fn r1_1_value_cap_cannot_hide_a_header_payload() {
    let body = many_params(4_100, "p");
    let headers = owned_headers(&[("Cookie", "password=%27%20OR%201%3D1--")]);
    let verdict = inspect_body(
        Some("application/x-www-form-urlencoded"),
        body.as_bytes(),
        &headers,
    );
    assert_policy_block(&verdict, "truncated", "LIMIT-001");
}

#[test]
fn r1_1_body_over_the_cap_blocks_with_the_truncated_policy() {
    let body = vec![b'a'; 300 * 1024];
    let verdict = inspect_body(Some("text/plain"), &body, &[]);
    assert_policy_block(&verdict, "truncated", "LIMIT-001");
}

#[test]
fn r1_1_repeated_names_are_deduped_so_a_real_payload_is_still_detected() {
    // 3000 duplicate `a=` pairs: the repeated *name* is inspected once, so the payload at the end stays below the
    // value cap and is detected as SQLi (not merely as a policy truncation).
    let mut body = String::new();
    for _ in 0..3_000 {
        body.push_str("a=1&");
    }
    body.push_str("x=%27+OR+1%3D1--");
    let verdict = inspect_form(&body);
    assert_eq!(verdict.action, Action::Block, "{verdict:?}");
    assert_eq!(verdict.category, Some("sqli"), "{verdict:?}");
}

#[test]
fn r1_1_a_normal_request_with_many_params_is_still_allowed() {
    let body = many_params(100, "p");
    let verdict = inspect_form(&body);
    assert_eq!(verdict.action, Action::Allow, "{verdict:?}");
}

// ---------------------------------------------------------------------------------------------------------------
// R1-2: adversarial bodies must stay linear (generous prompt-return budgets, never tuned to a machine).
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn r1_2_quote_heavy_and_encoding_heavy_bodies_return_promptly() {
    let prompt = Duration::from_secs(5);
    let cases: Vec<(String, Vec<u8>)> = vec![
        ("quotes".to_owned(), "'".repeat(256 * 1024).into_bytes()),
        (
            "unterminated comments".to_owned(),
            "/* ".repeat(80 * 1024).into_bytes(),
        ),
        (
            "fullwidth quotes".to_owned(),
            "\u{FF07}".repeat(80 * 1024).into_bytes(),
        ),
        (
            "double-encoded quotes".to_owned(),
            "%2527".repeat(50 * 1024).into_bytes(),
        ),
        (
            "entity quotes".to_owned(),
            "&#x27;".repeat(40 * 1024).into_bytes(),
        ),
    ];
    for (name, body) in cases {
        let started = Instant::now();
        let verdict = inspect_body(Some("text/plain"), &body, &[]);
        let elapsed = started.elapsed();
        assert!(
            elapsed < prompt,
            "{name} body of {} bytes took {elapsed:?} (budget {prompt:?})",
            body.len()
        );
        // No assertion on the action: the point is that the detector answered within the generous budget and did
        // not take a quadratic path. A block is acceptable (a hostile body), an allow is acceptable for plain quotes.
        let _ = verdict;
    }
}

#[test]
fn r1_2_many_short_comment_openers_stay_prompt() {
    let body = "/*/".repeat(60 * 1024);
    let started = Instant::now();
    let _ = inspect_body(Some("text/plain"), body.as_bytes(), &[]);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "comment-opener body took {:?}",
        started.elapsed()
    );
}

// ---------------------------------------------------------------------------------------------------------------
// R1-3: duplicate-name grouping must not be quadratic; a 256 KB distinct-pair body is a cap hit, not a hang.
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn r1_3_distinct_pair_grouping_is_prompt_and_capped() {
    let mut body = String::with_capacity(256 * 1024);
    let mut index = 0usize;
    while body.len() < 250 * 1024 {
        body.push_str(&format!("p{index}=&"));
        index += 1;
    }
    let started = Instant::now();
    let verdict = inspect_body(
        Some("application/x-www-form-urlencoded"),
        body.as_bytes(),
        &[],
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "distinct-pair grouping took {elapsed:?} for {} bytes",
        body.len()
    );
    assert_policy_block(&verdict, "truncated", "LIMIT-001");
}

// ---------------------------------------------------------------------------------------------------------------
// R1-4: a request Content-Encoding we do not decode must be refused, never inspected as raw bytes and forwarded.
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn r1_4_non_identity_content_encoding_is_refused_as_policy() {
    for encoding in ["gzip", "deflate", "br", "GZIP", "x-custom"] {
        let headers = owned_headers(&[("Content-Encoding", encoding)]);
        let verdict = inspect_body(
            Some("application/x-www-form-urlencoded"),
            b"\x1f\x8b\x08\x00not-a-real-payload",
            &headers,
        );
        assert_policy_block(&verdict, "unsupported_content_encoding", "CE-001");
        assert_eq!(verdict.vector, Some(Vector::Header), "{verdict:?}");
        assert_eq!(verdict.field.as_deref(), Some("Content-Encoding"));
    }
}

#[test]
fn r1_4_identity_content_encoding_is_allowed() {
    let headers = owned_headers(&[("Content-Encoding", "identity")]);
    let verdict = inspect_body(Some("text/plain"), b"hello world", &headers);
    assert_eq!(verdict.action, Action::Allow, "{verdict:?}");
}

// ---------------------------------------------------------------------------------------------------------------
// R1-5: missed injection shapes from the review.
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn r1_5_numeric_context_tautologies_block_in_unknown_fields() {
    for payload in [
        "1 OR 1=1",
        "1 or 2>1",
        "1 OR 0x31=0x31",
        "'-0-'",
        "1 AND (CASE WHEN 1=1 THEN 1 ELSE 0 END)",
    ] {
        let verdict = inspect_query(payload, "data");
        assert_eq!(
            verdict.action,
            Action::Block,
            "missed numeric-context shape: {payload:?} -> {verdict:?}"
        );
        assert_eq!(verdict.category, Some("sqli"), "payload {payload:?}");
    }
}

#[test]
fn r1_5_numeric_id_blind_shapes_block() {
    for payload in [
        "1 ORDER BY 10--",
        "1 AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64",
        "1 AND SUBSTR(user(),1,1)='r'",
        "1 AND (SELECT 1)=1",
        "1 AND EXISTS(SELECT 1 FROM users)",
    ] {
        let verdict = inspect_query(payload, "id");
        assert_eq!(
            verdict.action,
            Action::Block,
            "missed numeric-id blind shape: {payload:?} -> {verdict:?}"
        );
        assert_eq!(verdict.category, Some("sqli"), "payload {payload:?}");
    }
}

#[test]
fn r1_5_quote_breakout_followed_by_subselect_blocks() {
    let verdict = inspect_query("1' AND (SELECT 1 FROM users)=1--", "username");
    assert_eq!(verdict.action, Action::Block, "{verdict:?}");
    assert_eq!(verdict.category, Some("sqli"));
}

// ---------------------------------------------------------------------------------------------------------------
// LOW: arbitrary header values (capped), JSON keys, multipart filename*/boundary mismatch, softened prose.
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn low_arbitrary_header_values_are_inspected() {
    let headers = owned_headers(&[("X-Api-Key", "' OR 1=1--")]);
    let input = InspectInput {
        method: "GET",
        path: "/login",
        query: None,
        headers: &headers,
        content_type: None,
        body: b"",
    };
    let verdict = inspect(&input, &settings(Strictness::Balanced));
    assert_eq!(verdict.action, Action::Block, "{verdict:?}");
    assert_eq!(verdict.category, Some("sqli"));
}

#[test]
fn low_header_values_are_capped_at_eight_kilobytes() {
    let mut long = String::from("' OR 1=1--");
    long.push_str(&"x".repeat(20 * 1024));
    let headers = owned_headers(&[("X-Api-Key", &long)]);
    let verdict = inspect_body(None, b"", &headers);
    assert_eq!(
        verdict.action,
        Action::Block,
        "a payload inside the first 8 KiB of a header is still inspected"
    );
    let benign = "x".repeat(20 * 1024);
    let headers = owned_headers(&[("X-Api-Key", &benign)]);
    let verdict = inspect_body(None, b"", &headers);
    assert_eq!(verdict.action, Action::Allow, "{verdict:?}");
}

#[test]
fn low_json_object_keys_are_inspected() {
    let input = InspectInput {
        method: "POST",
        path: "/login",
        query: None,
        headers: &[],
        content_type: Some("application/json"),
        body: br#"{"a' or 1=1--":1}"#,
    };
    let verdict = inspect(&input, &settings(Strictness::Balanced));
    assert_eq!(verdict.action, Action::Block, "{verdict:?}");
    assert_eq!(verdict.category, Some("sqli"));
}

#[test]
fn low_multipart_filename_star_is_inspected() {
    let body = "--X\r\nContent-Disposition: form-data; name=\"f\"; filename*=UTF-8''admin%27--\r\n\r\ncontent\r\n--X--\r\n";
    let input = InspectInput {
        method: "POST",
        path: "/upload",
        query: None,
        headers: &[],
        content_type: Some("multipart/form-data; boundary=X"),
        body: body.as_bytes(),
    };
    let verdict = inspect(&input, &settings(Strictness::Balanced));
    assert_eq!(verdict.action, Action::Block, "{verdict:?}");
    assert_eq!(verdict.category, Some("sqli"));
}

#[test]
fn low_multipart_boundary_mismatch_blocks() {
    let body = "--Y\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nbenign\r\n--Y--\r\n";
    let input = InspectInput {
        method: "POST",
        path: "/upload",
        query: None,
        headers: &[],
        content_type: Some("multipart/form-data; boundary=X"),
        body: body.as_bytes(),
    };
    let verdict = inspect(&input, &settings(Strictness::Balanced));
    assert_policy_block(&verdict, "boundary_mismatch", "MP-001");
}

#[test]
fn low_quoted_words_or_prose_does_not_block_but_paranoid_keeps_it() {
    // Balanced: a bare quoted literal after a break-out is soft unless a comment/terminator/statement keyword is
    // present. Paranoid keeps the stricter reading.
    let balanced = inspect_query("'a' or 'b'", "q");
    assert_eq!(balanced.action, Action::Allow, "{balanced:?}");
    let balanced = inspect_header("I said 'no' or 'yes'");
    assert_eq!(balanced.action, Action::Allow, "{balanced:?}");
    let paranoid = inspect_query("'a' or 'b'", "q");
    let _ = paranoid;
    let query = format!("q={}", percent_encode("'a' or 'b'"));
    let input = InspectInput {
        method: "GET",
        path: "/login",
        query: Some(&query),
        headers: &[],
        content_type: None,
        body: b"",
    };
    let strict = inspect(&input, &settings(Strictness::Paranoid));
    assert_eq!(
        strict.action,
        Action::Block,
        "Paranoid keeps the soft quoted-literal case hard: {strict:?}"
    );
}
