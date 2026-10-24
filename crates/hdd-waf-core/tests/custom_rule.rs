//! `CustomRule` validation and application tests (HK1 demo track: the operator can add a rule on the demo day).
//!
//! Rules are validated when the site configuration loads; a malformed pattern never fires and never panics.

use hdd_waf_core::{
    Action, CustomRule, FieldKind, InspectInput, SiteSettings, Vector, Verdict, inspect,
    validate_custom_rule,
};

fn rule(id: &str, contains: Option<&str>, regex: Option<&str>) -> CustomRule {
    CustomRule {
        id: id.to_owned(),
        vector: None,
        contains: contains.map(str::to_owned),
        regex: regex.map(str::to_owned),
        action: Action::Block,
        description: "operator rule".to_owned(),
    }
}

fn inspect_header(value: &str, settings: &SiteSettings) -> Verdict {
    let headers = vec![("User-Agent".to_owned(), value.to_owned())];
    let input = InspectInput {
        method: "GET",
        path: "/login",
        query: None,
        headers: &headers,
        content_type: None,
        body: b"",
    };
    inspect(&input, settings)
}

fn inspect_password(value: &str, settings: &SiteSettings) -> Verdict {
    let headers = vec![("Cookie".to_owned(), format!("password={value}"))];
    let input = InspectInput {
        method: "POST",
        path: "/login",
        query: None,
        headers: &headers,
        content_type: None,
        body: b"",
    };
    inspect(&input, settings)
}

#[test]
fn validation_accepts_valid_contains_and_regex_rules() {
    assert!(validate_custom_rule(&rule("C-1", Some("union select"), None)).is_ok());
    assert!(validate_custom_rule(&rule("C-2", None, Some(r"(?i)admin'\s*--"))).is_ok());
}

#[test]
fn validation_rejects_malformed_rules_with_a_message() {
    for bad in [
        rule("", Some("x"), None),
        rule("C-1", None, None),
        rule("C-1", Some("x"), Some("y")),
        rule("C-1", Some("   "), None),
        rule("C-1", None, Some("(")),
        rule(&"x".repeat(65), Some("x"), None),
    ] {
        let error = validate_custom_rule(&bad);
        assert!(error.is_err(), "rule {bad:?} should be rejected");
        if let Err(message) = error {
            assert!(!message.is_empty());
        }
    }
}

#[test]
fn contains_rule_blocks_and_reports_its_id() {
    let settings = SiteSettings {
        extra_rules: vec![rule("C-7", Some("asset_pickle"), None)],
        ..SiteSettings::default()
    };
    let verdict = inspect_header("asset_pickle", &settings);
    assert_eq!(verdict.action, Action::Block);
    assert_eq!(verdict.category, Some("custom"));
    assert_eq!(verdict.rule_id, Some("C-7"));
    assert_eq!(verdict.field_kind, Some(FieldKind::Header));
}

#[test]
fn regex_rule_blocks_a_demo_day_vulnerability() {
    let settings = SiteSettings {
        extra_rules: vec![rule("C-8", None, Some(r"admin'\s*--"))],
        ..SiteSettings::default()
    };
    assert_eq!(inspect_header("admin' --", &settings).action, Action::Block);
    assert_eq!(
        inspect_header("admin' --", &SiteSettings::default()).action,
        Action::Block
    );
    assert_eq!(
        inspect_header("nothing to see", &settings).action,
        Action::Allow
    );
}

#[test]
fn vector_filter_is_respected() {
    let mut filtered = rule("C-9", Some("asset_pickle"), None);
    filtered.vector = Some(Vector::Cookie);
    let settings = SiteSettings {
        extra_rules: vec![filtered],
        ..SiteSettings::default()
    };
    let headers = vec![("User-Agent".to_owned(), "asset_pickle".to_owned())];
    let input = InspectInput {
        method: "GET",
        path: "/",
        query: None,
        headers: &headers,
        content_type: None,
        body: b"",
    };
    assert_eq!(
        inspect(&input, &settings).action,
        Action::Allow,
        "rule is cookie-only"
    );
    assert_eq!(
        inspect_password("asset_pickle", &settings).action,
        Action::Block,
        "cookie vector matches"
    );
}

#[test]
fn allow_rule_overrides_the_builtin_families_for_its_match() {
    let mut exception = rule("C-10", Some("admin' --"), None);
    exception.action = Action::Allow;
    let settings = SiteSettings {
        extra_rules: vec![exception],
        ..SiteSettings::default()
    };
    assert_eq!(inspect_header("admin' --", &settings).action, Action::Allow);
    // A different attack is still blocked by the built-in rules.
    assert_eq!(
        inspect_header("' or 1=1--", &settings).action,
        Action::Block
    );
}

#[test]
fn invalid_rule_never_fires_and_never_panics() {
    let settings = SiteSettings {
        extra_rules: vec![rule("C-11", None, Some("("))],
        ..SiteSettings::default()
    };
    assert_eq!(inspect_header("admin' --", &settings).action, Action::Block);
    assert_eq!(inspect_header("hello", &settings).action, Action::Allow);
}

#[test]
fn custom_block_rule_wins_over_the_password_exception() {
    let settings = SiteSettings {
        extra_rules: vec![rule("C-12", Some("admin' --"), None)],
        ..SiteSettings::default()
    };
    assert_eq!(
        inspect_password("admin' --", &settings).action,
        Action::Block,
        "an explicit operator rule is applied before the field-kind policy"
    );
}
