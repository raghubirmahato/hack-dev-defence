//! Parsing, schema, redaction and hostile-input tests for the profile (T-0006 A1 to A5).
#![allow(
    clippy::field_reassign_with_default,
    reason = "tests build profiles by overriding single fields"
)]

use super::*;
use proptest::prelude::*;

const EXAMPLE: &str = include_str!("../../../../hdd.live.example.yaml");
const SCHEMA_FILE: &str = include_str!("../../../../docs/profile.schema.json");

#[test]
fn a1_the_example_file_validates_with_only_the_expected_required_field_failures() {
    let p = parse_yaml(EXAMPLE).expect("the example file must parse");
    let report = validate(&p, &Context::default());
    let mut failures: Vec<(&str, &str)> = report
        .findings
        .iter()
        .filter(|f| f.status == Status::Fail)
        .map(|f| (f.rule, f.field.as_str()))
        .collect();
    failures.sort_unstable();
    assert_eq!(
        failures,
        vec![
            ("PROF-REQUIRED", "acme.email"),
            ("PROF-REQUIRED", "operator_email")
        ],
        "{}",
        render_table(&report)
    );
    for f in report.findings.iter().filter(|f| f.status == Status::Fail) {
        assert!(
            f.remediation.starts_with("Set `"),
            "remediation text missing: {f:?}"
        );
    }
    // the placeholders in the example are reported as a warning, never silently accepted
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule == "PROF-PLACEHOLDER" && f.status == Status::Warn)
    );
}

#[test]
fn a2_runner_ip_in_admin_cidrs_fails_with_the_documented_message() {
    let yaml = EXAMPLE
        .replace("admin_cidrs: []", "admin_cidrs: ['198.51.100.0/24']")
        .replace("public_ip: auto", "public_ip: 198.51.100.77");
    let p = parse_yaml(&yaml).expect("parse");
    let report = validate(&p, &Context::default());
    let f = report
        .findings
        .iter()
        .find(|f| f.rule == "PROF-RUNNER-ADMIN")
        .expect("finding");
    assert_eq!(f.status, Status::Fail);
    assert!(
        f.message.starts_with(
            "admin_cidrs contains the runner IP 198.51.100.77 (matched by 198.51.100.0/24)."
        ),
        "{}",
        f.message
    );
}

#[test]
fn a3_unknown_keys_are_rejected_with_the_full_key_path() {
    let top = parse_yaml("schema_version: 5\nsurprise: 1\n").expect_err("unknown top-level key");
    assert_eq!(top.key_path, "surprise");
    let nested =
        parse_yaml("schema_version: 5\nruntime:\n  local:\n    ports: {web: 1, prots: 2}\n")
            .expect_err("unknown nested key");
    assert_eq!(nested.key_path, "runtime.local.ports.prots");
    assert!(nested.message.contains("unknown key"), "{}", nested.message);
    let typo =
        parse_yaml("schema_version: 5\nsignup:\n  mode: invite_only\n  min_password_lenght: 12\n")
            .expect_err("typo");
    assert_eq!(typo.key_path, "signup.min_password_lenght");
}

#[test]
fn wrong_types_and_enum_values_report_the_path() {
    let e = parse_yaml("schema_version: 5\nruntime:\n  local:\n    ports: {web: not-a-number}\n")
        .expect_err("type");
    assert_eq!(e.key_path, "runtime.local.ports.web");
    let e = parse_yaml("schema_version: 5\nlifecycle_stage: staging\n").expect_err("enum");
    assert_eq!(e.key_path, "lifecycle_stage");
    assert!(e.message.contains("unknown variant"), "{}", e.message);
    let e = parse_yaml("schema_version: 5\nsignup:\n  min_password_length: -1\n")
        .expect_err("negative");
    assert_eq!(e.key_path, "signup.min_password_length");
}

#[test]
fn schema_version_is_required_and_the_document_must_be_a_mapping() {
    assert_eq!(
        parse_yaml("lifecycle_stage: pilot\n")
            .expect_err("missing")
            .key_path,
        "schema_version"
    );
    assert!(
        parse_yaml("- a\n- b\n")
            .expect_err("sequence")
            .message
            .contains("mapping")
    );
    assert!(parse_yaml("").is_err());
}

#[test]
fn a4_no_secret_value_can_be_parsed_only_environment_variable_names() {
    let github = format!("{}_{}", "ghp", "abcdefghijklmnopqrstuvwxyz0123456789"); // hdd-secret-scan:allow (test vector)
    let aws = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
    for (field_yaml, path) in [
        (
            format!("registrar: {{provider: x, api_token_env: {github}}}"),
            "registrar.api_token_env",
        ),
        (
            format!("smtp: {{password_env: {aws}}}"),
            "smtp.password_env",
        ),
        (
            "smtp: {username_env: hunter2}".to_owned(),
            "smtp.username_env",
        ),
        (
            "alerts: {webhook_env: 'https://hooks.example.org/T000/B000/xxxx'}".to_owned(),
            "alerts.webhook_env",
        ),
        (
            "secondary_dns: {tsig_key_env: 'dGhpcyBpcyBhIGtleQ=='}".to_owned(),
            "secondary_dns.tsig_key_env",
        ),
        (
            "runtime: {hosting: {backups: {remote_env: 'my secret'}}}".to_owned(),
            "runtime.hosting.backups.remote_env",
        ),
        (
            // base32-looking uppercase string with an underscore: the one class a plain "UPPER_CASE" test would accept
            "alerts: {webhook_env: JBSWY3DP_EHPK3PXP}".to_owned(),
            "alerts.webhook_env",
        ),
        (
            "alerts: {heartbeat_url_env: KRSXG5CTMVRXEZLU_MFRGGZDF}".to_owned(),
            "alerts.heartbeat_url_env",
        ),
    ] {
        let e = parse_yaml(&format!("schema_version: 5\n{field_yaml}\n")).expect_err(&field_yaml);
        assert_eq!(e.key_path, path, "{field_yaml}");
        assert!(e.message.contains("environment variable"), "{}", e.message);
        assert!(
            !e.to_string().contains("abcdefghijklmnop"),
            "the rejected value must not be echoed: {e}"
        );
    }
    let ok = parse_yaml(
        "schema_version: 5\nsmtp: {username_env: HDD_SMTP_USER, password_env: HDD_SMTP_PASSWORD}\n",
    )
    .expect("names are accepted");
    assert_eq!(ok.smtp.password_env.as_str(), "HDD_SMTP_PASSWORD");
}

#[test]
fn printing_a_profile_never_shows_secret_file_locations() {
    let p = parse_yaml("schema_version: 5\nplatform:\n  deploy_mode: ssh\n  ssh: {host: 203.0.113.5, user: deploy, key_path: /home/operator/.ssh/id_ed25519}\nvantage_points:\n  - {name: v1, ssh_host: h, ssh_user: u, ssh_key_path: 'C:\\Users\\op\\keys\\vp.pem'}\n").expect("parse");
    let shown = redacted_json(&p);
    assert!(
        shown.contains("…/id_ed25519") && shown.contains("…/vp.pem"),
        "{shown}"
    );
    assert!(
        !shown.contains("home/operator") && !shown.contains(".ssh") && !shown.contains("Users"),
        "{shown}"
    );
    let debug = format!("{p:?}");
    assert!(
        !debug.contains("home/operator") && !debug.contains(".ssh"),
        "Debug must not leak the path"
    );
    assert_eq!(
        p.platform.ssh.key_path.expose_path(),
        "/home/operator/.ssh/id_ed25519"
    );
}

#[test]
fn a5_the_generated_schema_is_stable_and_matches_the_committed_file() {
    assert_eq!(
        schema_json(),
        SCHEMA_FILE,
        "docs/profile.schema.json is stale: run `cargo xtask profile schema`"
    );
    assert_eq!(schema_json(), schema_json(), "generation is deterministic");
    let v: serde_json::Value = serde_json::from_str(&schema_json()).expect("valid JSON");
    assert_eq!(
        v.get("additionalProperties"),
        Some(&serde_json::json!(false)),
        "unknown keys are rejected at the top level"
    );
    assert_eq!(
        v.pointer("/properties/schema_version/default"),
        Some(&serde_json::json!(5))
    );
    assert_eq!(
        v.pointer("/$defs/EnvVarName/type"),
        Some(&serde_json::json!("string"))
    );
}

#[test]
fn hostile_yaml_is_rejected_by_the_budget_not_by_the_schema() {
    // These documents are rejected at stage one (`parse_value`), before any key is checked against the profile types, so the
    // test fails if the budget is removed. Each one has a control that is accepted, to show the budget is what rejects it.
    let control = parse_value("schema_version: 5\nanything: [1, 2, 3]\nnested: {a: {b: [x, y]}}\n");
    assert!(control.is_ok(), "{control:?}");

    let bomb = "schema_version: 5\na: &a [x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]\nd: [*c, *c, *c, *c, *c, *c, *c, *c, *c]\n";
    let e = parse_value(bomb)
        .expect_err("anchors and aliases must be refused")
        .to_string();
    assert!(e.starts_with("YAML error"), "{e}");
    assert!(
        parse_value("schema_version: 5\na: &a [x]\nb: [*a]\n").is_err(),
        "even one alias is refused"
    );

    assert!(
        parse_value("schema_version: 5\nmerged:\n  <<: {a: 1}\n").is_err(),
        "merge keys are refused"
    );

    let deep = format!(
        "schema_version: 5\nx: {}1{}\n",
        "[".repeat(200),
        "]".repeat(200)
    );
    assert!(parse_value(&deep).is_err(), "deep flow nesting is refused");
    let deep_block: String = (0..40)
        .map(|i| format!("{}k{i}:\n", "  ".repeat(i)))
        .collect::<String>()
        + &"  ".repeat(40)
        + "v: 1\n";
    assert!(
        parse_value(&format!("schema_version: 5\n{deep_block}")).is_err(),
        "deep block nesting is refused"
    );

    let dup = parse_value("schema_version: 5\nschema_version: 5\n")
        .expect_err("duplicate keys")
        .to_string();
    assert!(dup.to_lowercase().contains("duplicate"), "{dup}");
    assert!(
        parse_value("schema_version: 5\n---\nschema_version: 5\n").is_err(),
        "multiple documents are refused"
    );

    let big = format!(
        "schema_version: 5\nnotes: {}\n",
        "a".repeat(MAX_PROFILE_BYTES)
    );
    assert!(
        parse_value(&big)
            .expect_err("too big")
            .message
            .contains("larger than")
    );
    assert!(
        parse_yaml(&big)
            .expect_err("too big")
            .message
            .contains("larger than")
    );

    // booleans are strict: `yes` is a string, so a boolean field rejects it
    assert!(parse_yaml("schema_version: 5\nload_profile_approved: yes\n").is_err());
    assert!(parse_yaml("schema_version: 5\nload_profile_approved: true\n").is_ok());
}

#[test]
fn the_parser_returns_quickly_on_hostile_input() {
    let started = std::time::Instant::now();
    let deep = format!(
        "schema_version: 5\nx: {}1{}\n",
        "[".repeat(5000),
        "]".repeat(5000)
    );
    let _ = parse_value(&deep);
    let wide = format!("schema_version: 5\nx: [{}]\n", "1,".repeat(100_000));
    let _ = parse_value(&wide);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "parsing hostile input took {:?}",
        started.elapsed()
    );
}

#[test]
fn rejected_values_are_scrubbed_out_of_parse_errors() {
    let token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"; // hdd-secret-scan:allow (test vector)
    for (yaml, path) in [
        (
            format!("schema_version: 5\nlifecycle_stage: {token}\n"),
            "lifecycle_stage",
        ),
        (
            format!("schema_version: 5\nsignup:\n  min_password_length: {token}\n"),
            "signup.min_password_length",
        ),
        (
            format!("schema_version: 5\nsignup:\n  mode: \"{token}\"\n"),
            "signup.mode",
        ),
    ] {
        let e = parse_yaml(&yaml).expect_err("rejected");
        assert_eq!(e.key_path, path);
        assert!(
            !e.to_string().contains("0123456789"),
            "the pasted value is repeated: {e}"
        );
    }
    let e = parse_yaml("schema_version: 5\nlifecycle_stage: staging\n").expect_err("rejected");
    assert!(
        e.message.contains("unknown variant `<value>`") && e.message.contains("`pilot`"),
        "expected variants are kept: {}",
        e.message
    );
}

#[test]
fn printed_profiles_drop_credentials_and_queries_from_urls() {
    let p = parse_yaml("schema_version: 5\nbranding:\n  terms_url: https://user:pw12345678@hdd-ops.dev/terms?token=abc123#frag\nsite:\n  crawl_start_url: http://a:b@host.test:8080/start?x=1\nvantage_points:\n  - {name: v, socks_proxy: 'proxy.test:1080'}\n").expect("parse"); // hdd-secret-scan:allow (test vector)
    let shown = redacted_json(&p);
    assert!(
        shown.contains("https://hdd-ops.dev/terms")
            && shown.contains("http://host.test:8080/start"),
        "{shown}"
    );
    for leak in ["pw12345678", "abc123", "user:", "a:b@", "frag"] {
        assert!(!shown.contains(leak), "{leak} leaked: {shown}");
    }
    assert!(shown.contains("proxy.test:1080"));
}

#[test]
fn required_field_renderers_list_how_to_provide_each_field() {
    let hosted = render_required_fields(false);
    assert!(
        hosted.contains("operator_email")
            && hosted.contains("test_hostname")
            && hosted.contains("hddtest.<domain>")
    );
    let local = render_required_fields(true);
    assert!(local.contains("operator_email") && !local.contains("test_hostname"));
    let mut p = Profile::default();
    p.operator_email = "ops@hdd-ops.dev".into();
    let missing = render_missing(&p);
    assert!(
        missing.contains("platform_domain") && !missing.contains("operator_email"),
        "{missing}"
    );
}

proptest! {
    #[test]
    fn parsing_arbitrary_text_never_panics(s in "[ -~\n\t]{0,600}") {
        let _ = parse_yaml(&s);
    }

    #[test]
    fn parsing_arbitrary_unicode_never_panics(s in ".{0,300}") {
        let _ = parse_yaml(&s);
        let _ = parse_yaml(&format!("schema_version: 5\n{s}"));
    }

    #[test]
    fn parsing_structured_noise_never_panics(key in "[a-z_]{1,12}", val in "[ -~]{0,40}") {
        let _ = parse_yaml(&format!("schema_version: 5\n{key}: {val}\nsignup: {{mode: {val}}}\n"));
    }
}
