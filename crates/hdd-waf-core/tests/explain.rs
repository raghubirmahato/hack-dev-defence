//! Deterministic finding-explanation tests (Addendum 6 item 1): every SQLi family and policy/custom category
//! produces family-appropriate, deterministic text, a stack-specific remediation example and the honest
//! virtual-patch-is-not-a-fix line (R-11). The module is pure text: the UI escapes it, so the tests check that the
//! text stays plain (no markup is generated from the evidence).

use hdd_waf_core::explain::{ExplainRequest, Explanation, Stack, explain};
use hdd_waf_core::{FieldKind, MAX_EVIDENCE_BYTES, Vector};

#[allow(clippy::too_many_arguments)]
fn explanation_for(
    category: &str,
    family: &str,
    rule_id: &str,
    vector: Vector,
    field_kind: FieldKind,
    field_name: &str,
    method: &str,
    path: &str,
    evidence: &str,
    stack: Stack,
) -> Explanation {
    let request = ExplainRequest {
        category,
        family,
        rule_id,
        vector,
        field_kind,
        field_name,
        method,
        path,
        evidence,
        stack,
    };
    explain(&request)
}

fn sqli(family: &str, rule_id: &str, path: &str, evidence: &str) -> Explanation {
    explanation_for(
        "sqli",
        family,
        rule_id,
        Vector::FormBody,
        FieldKind::Username,
        "username",
        "POST",
        path,
        evidence,
        Stack::Other,
    )
}

#[test]
fn every_family_produces_distinct_text_and_the_family_impact() {
    // One representative per hard family H1 to H8 plus the generic fallback: every family must be deterministic,
    // non-empty and differ from the other families.
    let representatives = [
        ("tautology", "H1-001", "always-true"),
        ("comment_breakout", "H2-001", "comment"),
        ("union_select", "H3-001", "UNION"),
        ("stacked_query", "H4-001", "stacked"),
        ("time_based_function", "H5-001", "blind"),
        ("metadata_discovery", "H6-001", "schema"),
        ("auth_bypass", "H7-001", "authentication"),
        ("evasion_construct", "H8-001", "encoding"),
        ("", "", "SQL injection"),
    ];
    let mut detected_texts = std::collections::HashSet::new();
    let mut impact_texts = std::collections::HashSet::new();
    for (family, rule_id, impact_keyword) in representatives {
        let explanation = sqli(family, rule_id, "/shop/search", "' or 1=1--");
        assert!(!explanation.detected.is_empty(), "family {family:?}");
        assert!(
            !explanation.inferred_weakness.is_empty(),
            "family {family:?}"
        );
        assert!(!explanation.attacker_impact.is_empty(), "family {family:?}");
        assert!(
            explanation.remediation_steps.len() >= 6,
            "family {family:?} needs the full remediation list: {:?}",
            explanation.remediation_steps
        );
        assert!(
            explanation.detected.contains("SQL injection"),
            "family {family:?}: {}",
            explanation.detected
        );
        assert!(
            explanation
                .attacker_impact
                .to_ascii_lowercase()
                .contains(&impact_keyword.to_ascii_lowercase()),
            "family {family:?} impact must mention {impact_keyword:?}: {}",
            explanation.attacker_impact
        );
        assert!(
            detected_texts.insert(explanation.detected.clone()),
            "duplicate detected text for family {family:?}: {}",
            explanation.detected
        );
        assert!(
            impact_texts.insert(explanation.attacker_impact.clone()),
            "duplicate impact text for family {family:?}: {}",
            explanation.attacker_impact
        );
    }

    // Sub-types of the same family keep the family-appropriate impact (H2 terminator, H3 ordinal probe, H5 blind,
    // H8 hex/glued variants) even though the family sentence is shared.
    let subtypes = [
        ("terminator_breakout", "H2-002", "comment"),
        ("order_by_probe", "H3-002", "UNION"),
        ("blind_boolean", "H5-006", "blind"),
        ("hex_construction", "H8-003", "encoding"),
        ("glued_keyword", "H8-004", "encoding"),
    ];
    for (family, rule_id, impact_keyword) in subtypes {
        let explanation = sqli(family, rule_id, "/shop/search", "' or 1=1--");
        assert!(!explanation.detected.is_empty(), "subtype {family:?}");
        assert!(
            explanation
                .attacker_impact
                .to_ascii_lowercase()
                .contains(&impact_keyword.to_ascii_lowercase()),
            "subtype {family:?} impact must mention {impact_keyword:?}: {}",
            explanation.attacker_impact
        );
    }
}

#[test]
fn rule_id_picks_the_family_when_the_family_name_is_missing() {
    let from_rule = sqli("", "H3-001", "/shop/search", "1 union select 1");
    assert!(
        from_rule.attacker_impact.contains("UNION"),
        "{}",
        from_rule.attacker_impact
    );
    let generic = sqli("", "", "/shop/search", "odd");
    assert!(!generic.detected.is_empty());
    assert!(generic.detected.contains("SQL injection"));
}

#[test]
fn login_and_admin_paths_get_the_administrator_session_impact() {
    for path in ["/admin/login", "/login", "/auth/signin", "/administrator"] {
        let explanation = sqli("auth_bypass", "H7-001", path, "admin' --");
        let impact = explanation.attacker_impact.to_ascii_lowercase();
        assert!(
            impact.contains("administrator session") || impact.contains("administrator"),
            "login path {path:?} must describe the administrator-session impact: {}",
            explanation.attacker_impact
        );
        assert!(
            impact.contains("login") || impact.contains("authentication"),
            "path {path:?}: {}",
            explanation.attacker_impact
        );
    }
    let data = sqli("tautology", "H1-001", "/shop/search", "' or 1=1--");
    assert!(
        data.attacker_impact
            .contains("not an authentication endpoint"),
        "{}",
        data.attacker_impact
    );
}

#[test]
fn code_example_language_follows_the_site_stack() {
    let expected = [
        (Stack::Node, "javascript"),
        (Stack::Php, "php"),
        (Stack::Python, "python"),
        (Stack::Java, "java"),
        (Stack::Other, "sql"),
    ];
    for (stack, language) in expected {
        let explanation = explanation_for(
            "sqli",
            "comment_breakout",
            "H2-001",
            Vector::FormBody,
            FieldKind::Username,
            "username",
            "POST",
            "/login",
            "admin' --",
            stack,
        );
        assert_eq!(
            explanation.code_example.language, language,
            "stack {stack:?} must use a {language} example"
        );
        assert!(
            explanation.code_example.caption.contains("parameterised"),
            "stack {stack:?}: {}",
            explanation.code_example.caption
        );
        assert!(!explanation.code_example.code.is_empty());
    }
    let node = sqli("comment_breakout", "H2-001", "/login", "admin' --");
    assert!(node.code_example.code.contains('?') || node.code_example.code.contains(":username"));
}

#[test]
fn stack_serialises_lowercase_for_the_config_file() {
    assert_eq!(
        serde_json::to_string(&Stack::Node).ok().as_deref(),
        Some("\"node\"")
    );
    assert_eq!(
        serde_json::to_string(&Stack::Php).ok().as_deref(),
        Some("\"php\"")
    );
    assert_eq!(
        serde_json::to_string(&Stack::Python).ok().as_deref(),
        Some("\"python\"")
    );
    assert_eq!(
        serde_json::to_string(&Stack::Java).ok().as_deref(),
        Some("\"java\"")
    );
    assert_eq!(
        serde_json::to_string(&Stack::Other).ok().as_deref(),
        Some("\"other\"")
    );
    let parsed: Result<Stack, _> = serde_json::from_str("\"php\"");
    assert_eq!(parsed.ok(), Some(Stack::Php));
    assert_eq!(Stack::default(), Stack::Other);
}

#[test]
fn evidence_is_redacted_and_capped_in_the_generated_text() {
    let evidence = "' OR 1=1-- 4111111111111111 eyJhbGciOiJIUzI1NiJ9AbCdEf1234567890Zz"; // hdd-secret-scan:allow (test vector: JWT-shaped evidence must be redacted)
    let explanation = sqli("tautology", "H1-001", "/admin/login", evidence);
    assert!(
        explanation.detected.contains("<digits>"),
        "long digits must be redacted: {}",
        explanation.detected
    );
    assert!(!explanation.detected.contains("4111111111111111"));
    let redacted = between_backticks(&explanation.detected);
    assert!(
        redacted.len() <= MAX_EVIDENCE_BYTES,
        "redacted evidence too long: {}",
        redacted.len()
    );

    let long = format!("{}' or 1=1--", "A".repeat(1_000));
    let explanation = sqli("tautology", "H1-001", "/admin/login", &long);
    let redacted = between_backticks(&explanation.detected);
    assert!(redacted.len() <= MAX_EVIDENCE_BYTES);
}

/// The redacted evidence is the last backtick-quoted span of the sentence (the literal field name comes first).
fn between_backticks(text: &str) -> &str {
    let Some(close) = text.rfind('`') else {
        return "";
    };
    let Some(open) = text.get(..close).and_then(|head| head.rfind('`')) else {
        return "";
    };
    text.get(open + 1..close).unwrap_or("")
}

#[test]
fn html_and_script_evidence_stays_plain_text() {
    let evidence = "<script>alert('x')</script>";
    let explanation = sqli("comment_breakout", "H2-001", "/login", evidence);
    assert!(
        explanation.detected.contains("<script>"),
        "the module returns plain text; the UI escapes it: {}",
        explanation.detected
    );
    assert!(!explanation.detected.contains("&lt;script&gt;"));
}

#[test]
fn explanation_is_deterministic() {
    let first = sqli(
        "union_select",
        "H3-001",
        "/admin/login",
        "1 union select 1,2--",
    );
    let second = sqli(
        "union_select",
        "H3-001",
        "/admin/login",
        "1 union select 1,2--",
    );
    assert_eq!(first, second);
}

#[test]
fn detected_names_the_method_path_and_the_literal_field_name() {
    // Addendum 6 item 1 example: "SQL injection by comment break-out in form field `username` of POST /admin/login".
    let explanation = explanation_for(
        "sqli",
        "comment_breakout",
        "H2-001",
        Vector::FormBody,
        FieldKind::Username,
        "username",
        "POST",
        "/admin/login",
        "admin' --",
        Stack::Node,
    );
    for expected in ["POST", "/admin/login", "form field", "`username`"] {
        assert!(
            explanation.detected.contains(expected),
            "detected must name {expected:?}: {}",
            explanation.detected
        );
    }
    assert!(
        explanation.detected.starts_with("SQL injection by quote break-out with a comment in form field `username` of POST /admin/login"),
        "{}",
        explanation.detected
    );
}

#[test]
fn detected_falls_back_to_the_vector_label_when_the_field_name_is_empty() {
    for vector in [Vector::Path, Vector::Header, Vector::Cookie] {
        let explanation = explanation_for(
            "sqli",
            "comment_breakout",
            "H2-001",
            vector,
            FieldKind::Unknown,
            "  ",
            "POST",
            "/admin/login",
            "admin' --",
            Stack::Node,
        );
        assert_eq!(
            explanation.detected.matches('`').count(),
            2,
            "only the evidence is backtick-quoted when the field name is empty: {}",
            explanation.detected
        );
        assert!(
            explanation.detected.contains("of POST /admin/login"),
            "{}",
            explanation.detected
        );
    }
}

#[test]
fn every_vector_gets_its_own_label() {
    let expected = [
        (Vector::Path, "path segment"),
        (Vector::Query, "query parameter"),
        (Vector::FormBody, "form field"),
        (Vector::JsonBody, "JSON string"),
        (Vector::MultipartField, "multipart field"),
        (Vector::MultipartFilename, "multipart file name"),
        (Vector::Header, "request header"),
        (Vector::Cookie, "cookie value"),
    ];
    for (vector, label) in expected {
        let explanation = explanation_for(
            "sqli",
            "tautology",
            "H1-001",
            vector,
            FieldKind::Unknown,
            "",
            "GET",
            "/search",
            "' or 1=1--",
            Stack::Python,
        );
        assert!(
            explanation.detected.contains(label),
            "vector {vector:?} must be labelled {label:?}: {}",
            explanation.detected
        );
    }
}

#[test]
fn remediation_covers_the_required_topics_and_the_virtual_patch_is_honest() {
    let explanation = sqli("tautology", "H1-001", "/admin/login", "' or 1=1--");
    let joined = explanation.remediation_steps.join(" ").to_ascii_lowercase();
    for topic in [
        "parameterised",
        "least-privilege",
        "hash",
        "generic error",
        "rate-limit",
        "defence in depth",
        "virtual patch",
    ] {
        assert!(
            joined.contains(topic),
            "remediation must mention {topic:?}: {}",
            explanation.remediation_steps.join(" | ")
        );
    }
    let note = explanation.virtual_patch_note.to_ascii_lowercase();
    assert!(
        note.contains("virtual patch"),
        "{}",
        explanation.virtual_patch_note
    );
    assert!(
        note.contains("not a fix"),
        "{}",
        explanation.virtual_patch_note
    );
    assert!(
        note.contains("stays open"),
        "{}",
        explanation.virtual_patch_note
    );
    assert!(note.contains("r-11"), "{}", explanation.virtual_patch_note);
}

#[test]
fn policy_hits_explain_the_limit_without_inventing_a_vulnerability() {
    let truncated = explanation_for(
        "policy",
        "truncated",
        "LIMIT-001",
        Vector::FormBody,
        FieldKind::Unknown,
        "",
        "POST",
        "/login",
        "request too large",
        Stack::Node,
    );
    assert!(
        truncated.detected.contains("inspection"),
        "{}",
        truncated.detected
    );
    let inferred = truncated.inferred_weakness.to_ascii_lowercase();
    assert!(
        inferred.contains("inference"),
        "{}",
        truncated.inferred_weakness
    );
    assert!(
        inferred.contains("no application vulnerability"),
        "{}",
        truncated.inferred_weakness
    );
    assert!(
        truncated
            .attacker_impact
            .to_ascii_lowercase()
            .contains("not a confirmed vulnerability"),
        "{}",
        truncated.attacker_impact
    );

    let encoding = explanation_for(
        "policy",
        "unsupported_content_encoding",
        "CE-001",
        Vector::Header,
        FieldKind::Header,
        "Content-Encoding",
        "POST",
        "/login",
        "gzip",
        Stack::Php,
    );
    assert!(
        encoding
            .detected
            .to_ascii_lowercase()
            .contains("content-encoding")
            || encoding.detected.contains("encoding"),
        "{}",
        encoding.detected
    );

    let boundary = explanation_for(
        "policy",
        "boundary_mismatch",
        "MP-001",
        Vector::FormBody,
        FieldKind::Unknown,
        "",
        "POST",
        "/upload",
        "boundary mismatch",
        Stack::Other,
    );
    assert!(
        boundary.detected.to_ascii_lowercase().contains("multipart"),
        "{}",
        boundary.detected
    );
}

#[test]
fn custom_rule_hits_are_explained_as_an_operator_rule() {
    let explanation = explanation_for(
        "custom",
        "custom",
        "C-001",
        Vector::Query,
        FieldKind::Unknown,
        "asset_pickle",
        "GET",
        "/search",
        "asset_pickle",
        Stack::Java,
    );
    assert!(
        explanation
            .detected
            .to_ascii_lowercase()
            .contains("operator rule")
            || explanation.detected.to_ascii_lowercase().contains("custom"),
        "{}",
        explanation.detected
    );
    assert!(
        explanation
            .inferred_weakness
            .to_ascii_lowercase()
            .contains("inference")
    );
    assert!(!explanation.attacker_impact.is_empty());
}

#[test]
fn empty_and_odd_inputs_do_not_panic_and_stay_non_empty() {
    let explanation = explanation_for(
        "",
        "",
        "",
        Vector::Query,
        FieldKind::Unknown,
        "",
        "",
        "",
        "",
        Stack::Other,
    );
    for field in [
        &explanation.detected,
        &explanation.inferred_weakness,
        &explanation.attacker_impact,
        &explanation.virtual_patch_note,
    ] {
        assert!(!field.is_empty());
    }
    assert!(!explanation.remediation_steps.is_empty());
    assert!(!explanation.code_example.code.is_empty());

    let odd = explanation_for(
        "sqli",
        "tautology",
        "H1-001",
        Vector::Header,
        FieldKind::Header,
        "\u{0}\u{1}é",
        "",
        "",
        "\u{0}\u{1}é",
        Stack::Other,
    );
    assert!(!odd.detected.is_empty());
    assert!(!odd.detected.contains('\u{0}'));
}
