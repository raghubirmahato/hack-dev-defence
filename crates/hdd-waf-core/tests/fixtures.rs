//! Table tests over the shared fixture files (HK1 acceptance, C4.9.1):
//! 100% blocked on `tests/fixtures/sqli/{core,evasion}.txt` and zero false positives on both benign sets.
//!
//! Fixture format: one value per line; blank lines and lines starting with `#` are ignored. Every payload is
//! inspected as a `User-Agent` header value (a vector where every hard family is hard: C4.6 header row).

use hdd_waf_core::{Action, InspectInput, SiteSettings, inspect};

const CORE: &str = include_str!("../../../tests/fixtures/sqli/core.txt");
const EVASION: &str = include_str!("../../../tests/fixtures/sqli/evasion.txt");
const BENIGN_GENERAL: &str = include_str!("../../../tests/fixtures/benign-general.txt");
const BENIGN_SQL_PROSE: &str = include_str!("../../../tests/fixtures/benign-sql-prose.txt");

/// The six mandated payloads of C4.1, exactly as the specification gives them.
const MANDATED: [&str; 6] = [
    "' OR 1=1--",
    "' OR '1'='1",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' or 1=1 LIMIT 1 --",
];

fn payload_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

fn inspect_header(value: &str) -> hdd_waf_core::Verdict {
    let headers = vec![("User-Agent".to_owned(), value.to_owned())];
    let input = InspectInput {
        method: "GET",
        path: "/login",
        query: None,
        headers: &headers,
        content_type: None,
        body: b"",
    };
    inspect(&input, &SiteSettings::default())
}

#[test]
fn core_fixture_is_complete_and_every_payload_blocks() {
    let lines: Vec<&str> = payload_lines(CORE).collect();
    assert!(
        lines.len() >= 126,
        "core.txt must hold the six mandated payloads plus at least 120 variants, found {}",
        lines.len()
    );
    for payload in &MANDATED {
        assert!(
            lines.contains(payload),
            "core.txt is missing mandated payload {payload:?}"
        );
    }
    for payload in lines {
        let verdict = inspect_header(payload);
        assert_eq!(
            verdict.action,
            Action::Block,
            "core payload was not blocked: {payload:?} -> {verdict:?}"
        );
        assert_eq!(verdict.category, Some("sqli"), "payload {payload:?}");
        assert!(!verdict.evidence.is_empty(), "payload {payload:?}");
        assert!(verdict.evidence.len() <= hdd_waf_core::MAX_EVIDENCE_BYTES);
    }
}

#[test]
fn evasion_fixture_meets_the_minimum_and_every_payload_blocks() {
    let lines: Vec<&str> = payload_lines(EVASION).collect();
    assert!(
        lines.len() >= 40,
        "evasion.txt must hold at least 40 variants, found {}",
        lines.len()
    );
    for payload in lines {
        let verdict = inspect_header(payload);
        assert_eq!(
            verdict.action,
            Action::Block,
            "evasion payload was not blocked: {payload:?} -> {verdict:?}"
        );
        assert_eq!(verdict.category, Some("sqli"), "payload {payload:?}");
    }
}

#[test]
fn benign_general_fixture_has_zero_false_positives() {
    let lines: Vec<&str> = payload_lines(BENIGN_GENERAL).collect();
    assert!(
        lines.len() >= 150,
        "benign-general.txt must hold at least 150 realistic values, found {}",
        lines.len()
    );
    for value in lines {
        let verdict = inspect_header(value);
        assert_eq!(
            verdict.action,
            Action::Allow,
            "false positive on benign value: {value:?} -> {verdict:?}"
        );
        assert_eq!(verdict.category, None, "benign value {value:?}");
    }
}

#[test]
fn benign_sql_prose_fixture_has_zero_false_positives() {
    let lines: Vec<&str> = payload_lines(BENIGN_SQL_PROSE).collect();
    assert!(
        lines.len() >= 100,
        "benign-sql-prose.txt must hold at least 100 SQL-in-prose values, found {}",
        lines.len()
    );
    for value in lines {
        let verdict = inspect_header(value);
        assert_eq!(
            verdict.action,
            Action::Allow,
            "false positive on benign SQL prose: {value:?} -> {verdict:?}"
        );
    }
}
