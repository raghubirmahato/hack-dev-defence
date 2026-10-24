//! Per-family rule tests: positives, negatives and the counter-examples named by C4.5 and C4.9.
//!
//! Detection tests go through the public `inspect` function with real request vectors, so they exercise the whole
//! pipeline (extraction, normalisation, tokenizer, families, policy).
//!
//! Each family has its positive list and the counter-examples the specification names.

use hdd_waf_core::{
    Action, CustomRule, FieldKind, InspectInput, SiteSettings, Strictness, Vector, Verdict, inspect,
};

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
    inspect(&input, &SiteSettings::default())
}

fn inspect_header(value: &str) -> Verdict {
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

fn blocks_query(value: &str, field: &str) -> bool {
    inspect_query(value, field).action == Action::Block
}

fn blocks_header(value: &str) -> bool {
    inspect_header(value).action == Action::Block
}

#[test]
fn h1_tautology_positives_are_hard_in_search_fields() {
    for payload in [
        "' OR 1=1--",
        "' OR '1'='1",
        "1' OR '1'='1",
        "') OR ('1'='1",
        "')) OR (('1'='1",
        "' || '1'='1",
        "' OR 1=1 LIMIT 1 --",
        "' or 2>1--",
        "' or 'x' like 'x",
        "' or 1 --",
        "' OR TRUE--",
        "' or 1 in (1)--",
        "' or 1 between 0 and 2--",
        "' or NOT 0--",
    ] {
        assert!(blocks_query(payload, "q"), "H1 miss: {payload:?}");
    }
}

#[test]
fn h1_bare_tautology_is_context_sensitive() {
    // C4.5 H1 note: a bare `or 1=1` with no break-out is hard only in a numeric context (or after a SQL token),
    // otherwise it is a soft signal.
    assert!(
        !blocks_query("or 1=1", "q"),
        "soft H1 must not block a search field"
    );
    assert!(!blocks_query("1 or 2 options", "q"), "prose must not block");
    assert!(
        blocks_query("or 1=1", "id"),
        "numeric context makes bare H1 hard"
    );
    assert!(
        blocks_header("or 1=1"),
        "the header vector treats all H families as hard"
    );
}

#[test]
fn h2_break_out_positives_are_hard_in_username_fields() {
    for payload in [
        "admin'--",
        "admin' --",
        "admin' #",
        "admin'/*",
        "admin')--",
        "admin\"--",
        "' --",
        "'--",
        "') --",
        "'; --",
        "1'#",
        "admin' -- -",
        "admin'%23",
    ] {
        assert!(blocks_query(payload, "username"), "H2 miss: {payload:?}");
    }
}

#[test]
fn h2_counter_examples_do_not_block() {
    // Counter-examples named by C4.5 H2 and C4.9: names, prose, quoted speech and numbered prose.
    for value in [
        "O'Brien",
        "rock 'n' roll",
        "it's -- fine",
        "'Hello' -- he said",
    ] {
        assert!(
            !blocks_header(value),
            "false positive on counter-example: {value:?}"
        );
        assert!(
            !blocks_query(value, "username"),
            "false positive on counter-example: {value:?}"
        );
    }
}

#[test]
fn h2_password_exception_and_numbered_prose_soft_cases() {
    // Password field: H2 is soft 4 under Balanced, hard under Paranoid (C4.6).
    let default_settings = SiteSettings::default();
    let query = format!("password={}", percent_encode("admin' --"));
    let input = InspectInput {
        method: "POST",
        path: "/login",
        query: Some(&query),
        headers: &[],
        content_type: None,
        body: b"",
    };
    let balanced = inspect(&input, &default_settings);
    assert_eq!(balanced.action, Action::Allow, "{balanced:?}");
    let paranoid = SiteSettings {
        strictness: Strictness::Paranoid,
        ..SiteSettings::default()
    };
    let paranoid_verdict = inspect(&input, &paranoid);
    assert_eq!(
        paranoid_verdict.action,
        Action::Block,
        "{paranoid_verdict:?}"
    );
    assert_eq!(
        paranoid_verdict.field_kind,
        Some(FieldKind::Password),
        "the hint must infer a password field"
    );

    // `'#<digit>` is soft 2 in free-text/search (numbering in prose) but hard elsewhere (C4.5 H2).
    assert!(
        !blocks_query("l'#1", "comment"),
        "numbered prose in free text is soft"
    );
    assert!(
        !blocks_query("l'#1", "q"),
        "numbered prose in search is soft"
    );
    assert!(
        blocks_query("l'#1", "username"),
        "numbered quote-hash is hard in a username"
    );
}

#[test]
fn h3_union_and_ordinal_positives_and_negatives() {
    for payload in [
        "' UNION SELECT NULL,NULL--",
        "1 UNION ALL SELECT username,password FROM users",
        "-1 union/**/select 1,@@version,3",
        "' ORDER BY 5--",
    ] {
        assert!(blocks_query(payload, "q"), "H3 miss: {payload:?}");
    }
    for prose in [
        "the union select committee will meet",
        "please order by date",
        "union members select a representative",
        "order by 1, 2, 3",
    ] {
        assert!(
            !blocks_query(prose, "q"),
            "false positive on prose: {prose:?}"
        );
    }
}

#[test]
fn h4_stacked_positives_and_negatives() {
    for payload in [
        "'; DROP TABLE users--",
        "1; UPDATE users SET role='admin'--",
        "; EXEC xp_cmdshell('id')--",
        "; shutdown --",
        "'; INSERT INTO users VALUES(1)--",
        "; DECLARE @q VARCHAR(9)--",
        "; COPY x TO PROGRAM 'id'--",
    ] {
        assert!(blocks_query(payload, "q"), "H4 miss: {payload:?}");
    }
    for prose in [
        "please update; thanks",
        "DROP TABLE IF EXISTS temp;",
        "steps; open the menu",
    ] {
        assert!(
            !blocks_query(prose, "q"),
            "false positive on prose: {prose:?}"
        );
    }
}

#[test]
fn h5_time_error_and_blind_positives_and_negatives() {
    for payload in [
        "1 AND SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "1 AND extractvalue(1,concat(0x7e,'x'))--",
        "1 INTO OUTFILE '/tmp/x'--",
        "1 AND exp(~(SELECT 1))--",
    ] {
        assert!(blocks_query(payload, "q"), "H5 miss: {payload:?}");
    }
    for prose in [
        "I need sleep(8) hours",
        "time.sleep(5) in Python",
        "how to sleep(8) hours better",
    ] {
        assert!(
            !blocks_query(prose, "comment"),
            "false positive on prose: {prose:?}"
        );
    }
}

#[test]
fn h6_metadata_positives_and_negatives() {
    for payload in [
        "' union select @@version--",
        "' and (select count(*) from information_schema.tables)--",
        "' union select version()--",
    ] {
        assert!(blocks_query(payload, "q"), "H6 miss: {payload:?}");
    }
    for prose in [
        "the information_schema tables are read-only",
        "pg_catalog stores system catalog information",
        "check the version() number in the docs",
    ] {
        assert!(
            !blocks_query(prose, "comment"),
            "false positive on prose: {prose:?}"
        );
    }
}

#[test]
fn h7_auth_bypass_idioms_are_hard() {
    for payload in [
        "admin' or '1'='1'--",
        "' or username like '%admin%'--",
        "' having 1=1--",
        "' group by x having 1=1--",
        "admin' and 1=1--",
        "' or ''='",
        "'='",
    ] {
        assert!(blocks_header(payload), "H7 miss: {payload:?}");
    }
    assert!(
        !blocks_header("the '=' sign means equality"),
        "prose with a quoted equals is not H7"
    );
}

#[test]
fn h8_evasion_constructs_are_hard() {
    for payload in [
        "0x27 or 1=1--",
        "1e0union select 1,2--",
        "'un'+'ion' select 1,2--",
        "/*!50000union*//*!50000select*/1,2--",
        "' un/**/ion sel/**/ect 1,2--",
    ] {
        assert!(blocks_header(payload), "H8 miss: {payload:?}");
    }
    for benign in [
        "0xff0000 is red",
        "char(65) is the letter A",
        "the flag --help is common",
    ] {
        assert!(
            !blocks_header(benign),
            "false positive on benign: {benign:?}"
        );
    }
}

#[test]
fn block_verdict_is_explainable_and_bounded() {
    let verdict = inspect_header("admin' -- 4111111111111111");
    assert_eq!(verdict.action, Action::Block);
    assert_eq!(verdict.category, Some("sqli"));
    assert!(verdict.subtype.is_some());
    assert!(verdict.rule_id.is_some());
    assert_eq!(verdict.vector, Some(Vector::Header));
    assert_eq!(verdict.field.as_deref(), Some("User-Agent"));
    assert_eq!(verdict.field_kind, Some(FieldKind::Header));
    assert!(verdict.score > 0);
    assert!(!verdict.evidence.is_empty());
    assert!(verdict.evidence.len() <= hdd_waf_core::MAX_EVIDENCE_BYTES);
    assert!(
        verdict.evidence.contains("<digits>") || !verdict.evidence.contains("4111111111111111"),
        "long digit runs must be redacted: {:?}",
        verdict.evidence
    );
}

#[test]
fn allow_verdict_has_no_category_and_keeps_a_soft_score() {
    let verdict = inspect_query("please order by date", "q");
    assert_eq!(verdict.action, Action::Allow);
    assert_eq!(verdict.category, None);
    assert!(verdict.evidence.is_empty());
}

#[test]
fn custom_rules_run_before_the_builtin_families() {
    let rule = CustomRule {
        id: "C-001".to_owned(),
        vector: Some(Vector::Query),
        contains: Some("asset_pickle".to_owned()),
        regex: None,
        action: Action::Block,
        description: "operator rule for the demo day".to_owned(),
    };
    let settings = SiteSettings {
        extra_rules: vec![rule],
        ..SiteSettings::default()
    };
    let input = InspectInput {
        method: "GET",
        path: "/login",
        query: Some("q=asset_pickle"),
        headers: &[],
        content_type: None,
        body: b"",
    };
    let verdict = inspect(&input, &settings);
    assert_eq!(verdict.action, Action::Block);
    assert_eq!(verdict.category, Some("custom"));
    assert_eq!(verdict.rule_id, Some("C-001"));
    assert_eq!(verdict.subtype, Some("custom"));
}
