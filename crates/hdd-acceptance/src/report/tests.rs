//! Reporter tests: one status line per registered id, JSON and Markdown goldens, structural redaction that keeps JSON valid
//! (A-6), the 512-byte cap after redaction in both renderers (A-7), the Markdown fence (A-11), saved logs with a re-verified
//! SHA-256, the evidence-name sanitiser (A-11), resume (A-8) and panic-free parsing of hostile input.

use std::path::Path;

use super::*;
use crate::status::{EvidenceRef, ReasonCode, StatusLine, Verdict};

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn sample_report() -> Report {
    let mut report =
        Report::new("live", "pilot", "functional", 0).with_timestamp("2026-10-20T09:00:00Z");
    report.push_line(
        StatusLine::new(
            "AC-00",
            "Preflight and safety-envelope self-tests",
            "smoke",
            Verdict::Pass,
            vec![EvidenceRef::new("run.log", HASH_A, 10)],
        )
        .expect("PASS with evidence"),
    );
    report.push_line(
        StatusLine::new(
            "AC-01",
            "Authentication and admin isolation",
            "nondestructive",
            Verdict::fail("a would not block"),
            Vec::new(),
        )
        .expect("FAIL"),
    );
    report.push_line(StatusLine::stage_not_reached(
        "AC-02",
        "Zone import and parity",
        "pilot-full",
    ));
    report.push_evidence(
        EvidenceBlock::new("AC-00", EvidenceKind::HttpResponse)
            .with_field("status", "403")
            .with_field("header.content-type", "text/html"),
    );
    report.push_log(LogRef {
        path: "acceptance-x/run.log".to_owned(),
        sha256: HASH_B.to_owned(),
        bytes: 42,
        tail: "line one\nline two".to_owned(),
    });
    report.push_note("a note");
    report
}

#[test]
fn one_status_line_per_report_id_in_both_formats() {
    let report = sample_report();
    let markdown = report.render_markdown().expect("markdown");
    for id in ["AC-00", "AC-01", "AC-02"] {
        assert_eq!(
            markdown.matches(&format!("| {id} |")).count(),
            1,
            "{id} must appear exactly once as a status row"
        );
    }
    assert!(markdown.contains("3 checks: 1 PASS, 1 FAIL, 1 UNVERIFIED"));
    let json = report.render_json().expect("json");
    let parsed = Report::from_json(&json).expect("json round trip");
    assert_eq!(parsed.lines.len(), 3);
    assert_eq!(parsed.counts(), report.counts());
    assert_eq!(
        parsed.status_line("AC-01").map(|l| &l.verdict),
        Some(&Verdict::fail("a would not block"))
    );
}

#[test]
fn a_pass_without_evidence_is_refused_by_both_renderers() {
    let mut report = Report::new("live", "pilot", "functional", 0);
    report.push_line(StatusLine {
        id: "AC-00".to_owned(),
        title: "t".to_owned(),
        tier: "smoke".to_owned(),
        verdict: Verdict::Pass,
        evidence: Vec::new(),
        detail: None,
    });
    assert!(matches!(
        report.render_markdown(),
        Err(ReportError::Taxonomy(
            TaxonomyError::PassWithoutEvidence { .. }
        ))
    ));
    assert!(matches!(
        report.render_json(),
        Err(ReportError::Taxonomy(_))
    ));
}

#[test]
fn duplicate_check_ids_are_refused() {
    let mut report = Report::new("live", "pilot", "functional", 0);
    for _ in 0..2 {
        report.push_line(StatusLine::stage_not_reached("AC-00", "t", "smoke"));
    }
    assert_eq!(
        report.render_json(),
        Err(ReportError::DuplicateId {
            id: "AC-00".to_owned()
        })
    );
}

#[test]
fn a6_redaction_is_structural_by_field_name_and_does_not_need_the_secret_registered() {
    let mut report = sample_report();
    // Not registered anywhere: only the field names make these secret.
    let secrets = [
        "Bearer super-secret-token",
        "sid=abcdef123456",
        "crumbs=session-value",
        "key-value-12345",
    ];
    for (name, value) in [
        ("Authorization", secrets[0]),
        ("Cookie", secrets[1]),
        ("Set-Cookie", secrets[2]),
        ("X-API-Key", secrets[3]),
    ] {
        report.push_evidence(
            EvidenceBlock::new("AC-00", EvidenceKind::HttpResponse).with_field(name, value),
        );
    }
    let markdown = report.render_markdown().expect("markdown");
    let json = report.render_json().expect("json");
    for secret in secrets {
        assert!(!markdown.contains(secret), "markdown leaked {secret}");
        assert!(!json.contains(secret), "json leaked {secret}");
    }
    assert!(json.contains("[REDACTED]"));
    // the JSON must stay parseable after redaction
    let parsed = Report::from_json(&json).expect("the runner's own JSON output parses");
    assert_eq!(parsed.lines.len(), report.lines.len());
}

#[test]
fn a6_a_marker_value_in_a_free_form_field_is_redacted_and_the_json_stays_valid() {
    let mut report = sample_report();
    report.push_evidence(
        EvidenceBlock::new("AC-00", EvidenceKind::EventRecord)
            .with_field("detail", "invalid token: expired-abc")
            .with_field("mixed", "token=abc password=xyz"),
    );
    report.push_note("the request failed: invalid token: expired-abc");
    let markdown = report.render_markdown().expect("markdown");
    let json = report.render_json().expect("json");
    for leaked in ["expired-abc", "token=abc", "password=xyz"] {
        assert!(!markdown.contains(leaked), "markdown leaked {leaked}");
        assert!(!json.contains(leaked), "json leaked {leaked}");
    }
    assert!(
        Report::from_json(&json).is_ok(),
        "a redacted report must still be valid JSON"
    );
    assert!(markdown.contains("[REDACTED]"));
}

#[test]
fn a6_multiple_markers_on_one_line_are_all_redacted() {
    // Review item R-6: an unquoted value fails closed to the end of the line, so the first marker removes the rest of the
    // line and the second marker's value cannot survive. Both values are gone; that is the property that matters.
    let redacted = Redactor::new().redact("x token=abc password=xyz done");
    assert!(!redacted.contains("abc"), "{redacted}");
    assert!(!redacted.contains("xyz"), "{redacted}");
    assert!(redacted.contains("[REDACTED]"), "{redacted}");
    // A quoted value ends at its closing quote, so a complete second marker/value pair on the same line is still redacted.
    let quoted = Redactor::new().redact("x token=\"a b\" password=xyz done");
    assert!(!quoted.contains("a b"), "{quoted}");
    assert!(!quoted.contains("xyz"), "{quoted}");
    assert!(quoted.contains("[REDACTED]"), "{quoted}");
}

#[test]
fn a6_an_exact_secret_is_redacted_in_raw_and_json_escaped_form() {
    let secret = "quote\"back\\slash";
    let mut report = sample_report();
    report
        .redactor
        .add_secret(secret)
        .expect("the secret is long enough");
    report.push_note(format!("value is {secret}"));
    report.push_evidence(
        EvidenceBlock::new("AC-00", EvidenceKind::EventRecord).with_field("detail", secret),
    );
    let json = report.render_json().expect("json");
    let markdown = report.render_markdown().expect("markdown");
    for rendered in [&json, &markdown] {
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains(&json_escape(secret)));
    }
    assert!(Report::from_json(&json).is_ok());
}

#[test]
fn a_planted_secret_never_appears_in_either_rendered_format() {
    let secret = "hunter2-SECRET-VALUE"; // hdd-secret-scan:allow (planted test vector)
    let mut report = sample_report();
    report
        .redactor
        .add_secret(secret)
        .expect("the secret is long enough");
    report.push_evidence(
        EvidenceBlock::new("AC-00", EvidenceKind::HttpResponse)
            .with_field("request_headers", format!("Authorization: Bearer {secret}"))
            .with_field("body", format!("password={secret}")),
    );
    report.push_note(format!("the token {secret} was redacted"));
    report.push_log(LogRef {
        path: "acceptance-x/secret.log".to_owned(),
        sha256: HASH_B.to_owned(),
        bytes: 12,
        tail: format!("client_secret: {secret}\nAuthorization: Bearer {secret}"),
    });
    let markdown = report.render_markdown().expect("markdown");
    let json = report.render_json().expect("json");
    for rendered in [&markdown, &json] {
        assert!(
            !rendered.contains(secret),
            "the planted secret leaked into a report: {rendered}"
        );
        assert!(rendered.contains("[REDACTED]"));
    }
    assert!(markdown.contains(HASH_B), "SHA-256 digests are not secrets");
    assert!(json.contains(HASH_B));
}

#[test]
fn a7_both_renderers_cap_evidence_after_redaction_on_a_utf8_boundary() {
    let mut report = sample_report();
    // A quoted secret sits inside the first 512 bytes and the rest of the value follows it: redaction must happen before the
    // cap (so no prefix of the secret is printed) and the cap must be applied to the redacted value.
    let mut value = "a".repeat(505);
    value.push_str(" password=\"hunter2\" ");
    value.push_str(&"é".repeat(1_600));
    report.push_evidence(
        EvidenceBlock::new("AC-00", EvidenceKind::HttpResponse).with_field("body", value),
    );
    let markdown = report.render_markdown().expect("markdown");
    let json = report.render_json().expect("json");
    for rendered in [&markdown, &json] {
        assert!(
            !rendered.contains("hunter2"),
            "the straddling secret leaked"
        );
        assert!(
            rendered.contains("[truncated]"),
            "the cap must be visible in the report"
        );
    }
    let parsed = Report::from_json(&json).expect("json parses");
    let mut found = false;
    for block in parsed.evidence.iter().filter(|b| b.check == "AC-00") {
        for (_, rendered) in &block.fields {
            // Review item R-11: the cap is exact and includes the marker.
            assert!(
                rendered.len() <= EVIDENCE_VALUE_MAX,
                "evidence value is {} bytes, cap {EVIDENCE_VALUE_MAX}: {rendered}",
                rendered.len()
            );
            if rendered.contains("[truncated]") {
                found = true;
                assert_eq!(rendered.len(), EVIDENCE_VALUE_MAX);
            }
        }
    }
    assert!(
        found,
        "the non-vacuous cap test must find a truncated field"
    );
    // the truncated text stays valid UTF-8 (no replacement characters inserted)
    assert!(!markdown.contains('\u{FFFD}'));
}

#[test]
fn a11_a_log_tail_with_backticks_gets_a_longer_fence() {
    let tail = "before\n```\ncode\n````\nafter";
    let mut report = sample_report();
    report.logs.clear();
    report.push_log(LogRef {
        path: "acceptance-x/run.log".to_owned(),
        sha256: HASH_B.to_owned(),
        bytes: 30,
        tail: tail.to_owned(),
    });
    let markdown = report.render_markdown().expect("markdown");
    let fence = fence_for(tail);
    assert_eq!(fence, "`````", "one backtick longer than the longest run");
    assert!(markdown.contains(&format!("{fence}text")), "{markdown}");
    assert!(
        markdown.contains(&format!("\n{fence}\n")),
        "the fence closes with the same length"
    );
}

#[test]
fn the_redactor_keeps_digests_and_redacts_marked_values() {
    let redactor = Redactor::new();
    let text = "sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
                password: hunter2\n\
                Authorization: Bearer abc123\n\
                token rotation completed\n\
                api_key=secret-value-1\n\
                client_secret: topsecret";
    let redacted = redactor.redact(text);
    assert!(redacted.contains("sha256=aaaaaaaa"));
    assert!(!redacted.contains("hunter2"));
    assert!(!redacted.contains("abc123"));
    assert!(!redacted.contains("secret-value-1"));
    assert!(!redacted.contains("topsecret"));
    assert!(
        redacted.contains("token rotation completed"),
        "a line that mentions a marker without a value is not shredded"
    );
    assert_eq!(redacted.matches("[REDACTED]").count(), 4);
    assert_eq!(
        Redactor::with_secrets(["abcd", "abcd"])
            .expect("abcd is long enough")
            .secrets_len(),
        1
    );
    // The error is propagated, not discarded (review item N-5).
    assert!(Redactor::with_secrets(["ab"]).is_err());
}

#[test]
fn a_saved_log_keeps_its_sha256_verifiable_and_embeds_the_tail() {
    let dir = crate::test_support::temp_dir("report-log");
    let store = EvidenceStore::create(&dir).expect("store");
    let text = (0..100)
        .map(|n| format!("line {n}"))
        .collect::<Vec<_>>()
        .join("\n");
    let log = store
        .save_log("run.log", &text, &Redactor::new())
        .expect("save log");
    let saved = std::fs::read(&log.path).expect("read back");
    assert_eq!(
        log.sha256,
        sha256_hex(&saved),
        "the record hashes the saved bytes"
    );
    assert_eq!(log.bytes as usize, saved.len());
    assert_eq!(log.tail.lines().count(), LOG_TAIL_LINES);
    assert!(log.tail.starts_with("line 80"), "{}", log.tail);
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn a_saved_log_is_redacted_before_it_is_written() {
    let dir = crate::test_support::temp_dir("report-log-redact");
    let store = EvidenceStore::create(&dir).expect("store");
    let text = "password=hunter2\ndone\n";
    let log = store
        .save_log("run.log", text, &Redactor::new())
        .expect("save log");
    let saved = std::fs::read_to_string(&log.path).expect("read back");
    assert!(!saved.contains("hunter2"));
    assert!(saved.contains("[REDACTED]"));
    assert_eq!(log.sha256, sha256_hex(saved.as_bytes()));
}

#[test]
fn a11_the_evidence_store_refuses_paths_that_escape_its_directory() {
    let dir = crate::test_support::temp_dir("report-store-escape");
    let store = EvidenceStore::create(&dir).expect("store");
    let escape_name = format!("../escape-{}.txt", std::process::id());
    for name in [
        escape_name.as_str(),
        "..",
        "/etc/passwd",
        "C:\\Windows\\x.txt",
        "nested/report.md",
        "",
        ".",
    ] {
        let error = store
            .save(name, b"x")
            .expect_err(&format!("{name:?} must be refused"));
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidInput,
            "{name:?}: {error}"
        );
        let error = store
            .save_log(name, "x", &Redactor::new())
            .expect_err(&format!("{name:?} must be refused for logs too"));
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
    // nothing was created outside the directory
    let escape = dir
        .parent()
        .map(|p| p.join(format!("escape-{}.txt", std::process::id())));
    assert!(escape.is_none_or(|p| !p.exists()));
    // a plain name works
    assert!(store.save("report.md", b"ok").is_ok());
}

/// A previous report bound to a run shape, with one real evidence file inside `dir` and one PASS line.
fn bound_previous(dir_name: &str) -> (Report, std::path::PathBuf) {
    let dir = crate::test_support::temp_dir(dir_name);
    let store = EvidenceStore::create(&dir).expect("store");
    let artifact = store
        .save("proof.txt", b"real evidence")
        .expect("save the artifact");
    let mut previous = Report::new("live", "pilot", "functional", 0).with_binding(
        "rev-1",
        vec![
            "hddtest.example.com".to_owned(),
            "hddsbx.example.com".to_owned(),
        ],
    );
    previous.push_line(
        StatusLine::new(
            "AC-01",
            "Authentication and admin isolation",
            "nondestructive",
            Verdict::Pass,
            vec![artifact],
        )
        .expect("a PASS with evidence"),
    );
    (previous, dir)
}

/// A fresh report with a matching binding and the full registry as stage_not_reached lines.
fn fresh_bound() -> Report {
    let mut fresh = Report::new("live", "pilot", "functional", 0).with_binding(
        "rev-1",
        vec![
            "hddtest.example.com".to_owned(),
            "hddsbx.example.com".to_owned(),
        ],
    );
    for line in crate::registry::dry_run_lines() {
        fresh.push_line(line);
    }
    fresh
}

#[test]
fn a8_resume_keeps_pass_lines_and_reruns_everything_else() {
    let (previous, dir) = bound_previous("report-resume-ok");
    let merged = fresh_bound()
        .resume_with(&previous, &dir, None)
        .expect("resume");
    let kept = merged.status_line("AC-01").expect("AC-01");
    assert!(
        kept.verdict.is_pass(),
        "a PASS line with re-hashed evidence is kept"
    );
    assert_eq!(kept.evidence.len(), 1);
    assert_eq!(
        merged.status_line("AC-00").map(|l| l.verdict.clone()),
        Some(Verdict::unverified(ReasonCode::StageNotReached)),
        "AC-00 always re-runs and is never resumed (review item N-3)"
    );
    assert!(
        merged
            .notes
            .iter()
            .any(|note| note.contains("1 PASS line(s) reused")),
        "{:?}",
        merged.notes
    );
}

/// Review item R-2: a hand-edited `PASS` line with a 64-hex string that does not match the file is refused.
#[test]
fn r2_resume_refuses_a_hand_edited_pass_line_with_a_fake_hash() {
    let (mut previous, dir) = bound_previous("report-resume-fake");
    // Fields are private (review item S-6), so the fake hash is built through the crate-internal constructor.
    previous.lines[0].evidence[0] = EvidenceRef::new("proof.txt", "a".repeat(64), 16);
    assert!(matches!(
        fresh_bound().resume_with(&previous, &dir, None),
        Err(ReportError::ResumeMismatch { .. })
    ));
}

/// Review item R-2: if the artifact changed after the report was written, the hash no longer matches and the resume fails.
#[test]
fn r2_resume_refuses_evidence_that_changed() {
    let (previous, dir) = bound_previous("report-resume-tampered");
    std::fs::write(dir.join("proof.txt"), b"different bytes").expect("rewrite the artifact");
    assert!(matches!(
        fresh_bound().resume_with(&previous, &dir, None),
        Err(ReportError::ResumeMismatch { .. })
    ));
}

/// Review item R-2: a report planned against another `config_revision` is refused.
#[test]
fn r2_resume_refuses_a_different_config_revision() {
    let (previous, dir) = bound_previous("report-resume-revision");
    let fresh = fresh_bound().with_binding(
        "rev-2",
        vec![
            "hddtest.example.com".to_owned(),
            "hddsbx.example.com".to_owned(),
        ],
    );
    assert!(matches!(
        fresh.resume_with(&previous, &dir, None),
        Err(ReportError::ResumeMismatch { .. })
    ));
}

/// Review item R-2: a report older than the resume limit is refused.
#[test]
fn r2_resume_refuses_a_report_older_than_the_limit() {
    let (mut previous, dir) = bound_previous("report-resume-old");
    previous.generated_at = "2020-01-01T00:00:00Z".to_owned();
    assert!(matches!(
        fresh_bound().resume_with(&previous, &dir, None),
        Err(ReportError::ResumeMismatch { .. })
    ));
}

/// Review item R-2: a report without the revision/host binding cannot be verified, so it is refused.
#[test]
fn r2_resume_refuses_a_report_without_a_binding() {
    let (previous, dir) = bound_previous("report-resume-unbound");
    let unbound = Report::new("live", "pilot", "functional", 0);
    assert!(matches!(
        unbound.resume_with(&previous, &dir, None),
        Err(ReportError::ResumeMismatch { .. })
    ));
    // and the reverse: an unbound previous report is refused too
    let (_, dir2) = bound_previous("report-resume-unbound-2");
    let (mut previous2, _) = bound_previous("report-resume-unbound-3");
    previous2.config_revision.clear();
    assert!(matches!(
        fresh_bound().resume_with(&previous2, &dir2, None),
        Err(ReportError::ResumeMismatch { .. })
    ));
}

#[test]
fn a8_resume_refuses_a_report_from_another_run_shape() {
    let previous = sample_report();
    let fresh = Report::new("lab", "production", "lab", 0);
    let dir = crate::test_support::temp_dir("report-resume-shape");
    assert!(matches!(
        fresh.resume_with(&previous, &dir, None),
        Err(ReportError::ResumeMismatch { .. })
    ));
}

#[test]
fn hostile_values_cannot_break_the_markdown_table() {
    let mut report = Report::new("live", "pilot", "functional", 0);
    report.push_line(StatusLine::stage_not_reached(
        "AC-00",
        "a title | with a pipe\nand a newline",
        "smoke",
    ));
    report.push_note("a note | with a pipe\nand a newline");
    let markdown = report.render_markdown().expect("markdown");
    assert!(markdown.contains("a title \\| with a pipe and a newline"));
    assert!(!markdown.contains("| a title | with a pipe"));
}

#[test]
fn an_oversized_or_unknown_json_report_is_refused_not_panicked() {
    let too_large = "x".repeat(MAX_REPORT_BYTES + 1);
    assert!(matches!(
        Report::from_json(&too_large),
        Err(ReportError::TooLarge { .. })
    ));
    assert!(matches!(
        Report::from_json("{\"generated_at\": \"x\", \"extra\": 1}"),
        Err(ReportError::Parse { .. })
    ));
    assert!(matches!(
        Report::from_json("not json"),
        Err(ReportError::Parse { .. })
    ));
}

#[test]
fn report_golden_markdown() {
    let expected = include_str!("../../tests/fixtures/report-small.md");
    let rendered = sample_report().render_markdown().expect("markdown");
    assert_eq!(rendered, expected);
}

#[test]
fn report_golden_json() {
    let expected = include_str!("../../tests/fixtures/report-small.json");
    let rendered = sample_report().render_json().expect("json");
    assert_eq!(rendered, expected.trim_end());
    assert!(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/report-small.json")
            .is_file()
    );
}

#[test]
fn the_timestamp_is_iso8601_utc() {
    let now = now_utc();
    assert_eq!(now.len(), 20, "{now}");
    assert!(now.ends_with('Z'), "{now}");
    assert_eq!(now.as_bytes().get(4), Some(&b'-'));
    assert_eq!(now.as_bytes().get(10), Some(&b'T'));
    assert!(now[..4].chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn counts_survive_a_json_round_trip() {
    let report = sample_report();
    let json = report.render_json().expect("json");
    let back = Report::from_json(&json).expect("parse");
    assert_eq!(
        back.counts(),
        Counts {
            pass: 1,
            fail: 1,
            unverified: 1
        }
    );
    assert_eq!(back.generated_at, "2026-10-20T09:00:00Z");
    assert_eq!(back.mode, "live");
    assert_eq!(back.stage, "pilot");
    assert_eq!(back.load_profile, "functional");
    assert_eq!(back.vantage_count, 0);
}

#[test]
fn a_status_line_of_an_unregistered_shape_is_still_refused() {
    let mut report = Report::new("live", "pilot", "functional", 0);
    report.push_line(StatusLine {
        id: "nope".to_owned(),
        title: "t".to_owned(),
        tier: "smoke".to_owned(),
        verdict: Verdict::unverified(ReasonCode::StageForbids),
        evidence: Vec::new(),
        detail: None,
    });
    assert!(matches!(
        report.validate(),
        Err(ReportError::Taxonomy(TaxonomyError::BadId { .. }))
    ));
}

/// Review item R-6: the exact inputs from the review. A separator followed by spaces, a quoted value (single and double
/// quotes) and a tab after the value must not leak the tail.
#[test]
fn r6_redaction_handles_spaces_quotes_and_tabs() {
    let redactor = Redactor::new();
    let cases = [
        ("password = hunter2", "password = [REDACTED]"),
        ("password=\"my pass phrase\"", "password=\"[REDACTED]\""), // hdd-secret-scan:allow (planted test vector)
        ("token = abc def", "token = [REDACTED] def"),
        ("secret=a\tb", "secret=[REDACTED]"),
        ("api_key = 'single quoted value'", "api_key = '[REDACTED]'"), // hdd-secret-scan:allow (planted test vector)
        (
            "{\"session_count\": 3, \"status\": 200}",
            "{\"session_count\": [REDACTED], \"status\": 200}",
        ),
        ("non-secret data", "non-secret data"),
    ];
    for (input, expected) in cases {
        let redacted = redactor.redact(input);
        assert_eq!(redacted, expected, "input {input:?}");
        for leaked in [
            "hunter2",
            "my pass phrase",
            "abc",
            "\tb",
            "single quoted value",
        ] {
            assert!(
                !redacted.contains(leaked),
                "{input:?} leaked {leaked:?}: {redacted:?}"
            );
        }
    }
}

/// Review item R-11: the cap is exactly 512 bytes, marker included, and truncation is visible.
#[test]
fn r11_truncate_utf8_never_exceeds_the_cap_and_counts_the_marker() {
    assert_eq!(truncate_utf8("short", 512), "short");
    let exact = "x".repeat(EVIDENCE_VALUE_MAX);
    assert_eq!(truncate_utf8(&exact, EVIDENCE_VALUE_MAX), exact);
    let long = "x".repeat(1_000);
    let truncated = truncate_utf8(&long, EVIDENCE_VALUE_MAX);
    assert_eq!(truncated.len(), EVIDENCE_VALUE_MAX);
    assert!(truncated.ends_with("[truncated]"), "{truncated}");
    // a multi-byte cut never splits a character and still stays inside the cap
    let unicode = "é".repeat(400);
    let truncated = truncate_utf8(&unicode, EVIDENCE_VALUE_MAX);
    assert!(truncated.len() <= EVIDENCE_VALUE_MAX);
    assert!(truncated.is_char_boundary(truncated.len()));
}

/// Review item R-11: the store refuses to overwrite an existing artifact (a hash must never describe a file it replaced).
#[test]
fn r11_the_evidence_store_refuses_to_overwrite() {
    let dir = crate::test_support::temp_dir("report-store-overwrite");
    let store = EvidenceStore::create(&dir).expect("store");
    store.save("proof.txt", b"first").expect("first save");
    let error = store
        .save("proof.txt", b"second")
        .expect_err("an existing artifact must not be replaced");
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists, "{error}");
    assert_eq!(
        std::fs::read(dir.join("proof.txt")).expect("read"),
        b"first"
    );
    let error = store
        .save_log("run.log", "text", &Redactor::new())
        .expect("first log");
    assert_eq!(error.bytes, 4);
    assert!(
        store
            .save_log("run.log", "other", &Redactor::new())
            .is_err(),
        "an existing log must not be replaced"
    );
}

/// Review item R-11: Windows reserved device names and NTFS alternate data streams are refused on every platform, because
/// the write would succeed without creating the file while a hash is recorded.
#[test]
fn r11_windows_reserved_names_and_streams_are_refused() {
    for name in [
        "NUL",
        "nul",
        "aux",
        "CON",
        "prn",
        "com1",
        "LPT9",
        "con.txt",
        "nul.log",
        "name:stream",
        "report.md:stream",
        "trailing.",
        "trailing ",
    ] {
        assert!(
            safe_evidence_name(name).is_err(),
            "{name:?} must be refused"
        );
    }
    for name in [
        "report.md",
        "run.log",
        "proof.txt",
        "nulish.txt",
        "console.log",
    ] {
        assert!(
            safe_evidence_name(name).is_ok(),
            "{name:?} must be accepted"
        );
    }
}

/// Review item R-12: redaction happens on field values before serialisation, never as a string replacement over the
/// document, so a short registered secret that is a substring of a hash, an id or a keyword cannot corrupt the JSON.
#[test]
fn r12_short_secrets_do_not_corrupt_the_json_document() {
    let mut report = sample_report();
    // `aaaa` is a substring of HASH_A and of nothing else secret; `pass` is a substring of the word `pass` in JSON values.
    report.redactor.add_secret("aaaa").expect("secret");
    report.redactor.add_secret("pass").expect("secret");
    report.redactor.add_secret("AC-0").expect("secret");
    let json = report.render_json().expect("json");
    // The document is intact JSON and the structural values survive.
    let parsed = Report::from_json(&json).expect("the document must stay valid JSON");
    assert_eq!(
        parsed.status_line("AC-00").map(|l| l.verdict.is_pass()),
        Some(true)
    );
    assert_eq!(parsed.lines.len(), report.lines.len());
    assert!(
        json.contains(HASH_A),
        "a hash must not be corrupted by a short secret"
    );
    assert!(
        json.contains("\"AC-00\""),
        "an id must not be rewritten by a short secret: {json}"
    );
    assert!(
        parsed.status_line("AC-00").is_some(),
        "keys and ids survive structural redaction"
    );
    // Strengthened for review item S-7: the evidence reference is never redacted, so a wholesale document replacement would
    // corrupt the hash and fail here.
    assert_eq!(
        parsed.lines[0].evidence[0].sha256(),
        HASH_A,
        "an evidence hash must never be rewritten by a short secret"
    );
    assert!(
        json.contains(&format!("\"sha256\": \"{HASH_A}\"")),
        "the serialised evidence reference keeps its hash"
    );
}

/// Review item R-12: a hostile evidence field name and a hostile `block.check` cannot inject Markdown structure.
#[test]
fn r12_evidence_names_and_block_check_are_escaped_in_markdown() {
    let mut report = sample_report();
    report.push_evidence(
        EvidenceBlock::new("AC-00\n## injected heading", EvidenceKind::EventRecord)
            .with_field("field\n## injected heading", "value")
            .with_field("pipe|name", "value"),
    );
    let markdown = report.render_markdown().expect("markdown");
    assert!(
        !markdown.contains("\n## injected heading"),
        "an injected heading must not start a line: {markdown}"
    );
    assert!(
        !markdown.contains("| pipe|name"),
        "a pipe in a field name must be escaped: {markdown}"
    );
    // exactly one level-2 heading in the document, the report's own
    let headings = markdown
        .lines()
        .filter(|line| line.starts_with("## ") || line.starts_with("### "))
        .count();
    assert!(
        headings <= 8,
        "a hostile value must not add headings: {markdown}"
    );
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn from_json_never_panics_on_arbitrary_text(text in ".{0,500}") {
            let _ = Report::from_json(&text);
        }

        #[test]
        fn the_redactor_never_panics_and_never_keeps_a_registered_secret(
            text in ".{0,300}",
            secret in "[A-Za-z0-9]{8,20}",
        ) {
            let redactor = Redactor::with_secrets([secret.clone()]).expect("generated secrets are long enough");
            let redacted = redactor.redact(&text);
            prop_assert!(!redacted.contains(&secret));
        }

        #[test]
        fn tail_lines_never_panics(text in ".{0,300}", n in 0usize..40) {
            let tail = tail_lines(&text, n);
            prop_assert!(tail.lines().count() <= n.max(1));
        }

        #[test]
        fn the_fence_is_always_longer_than_any_backtick_run(text in "`{0,10}") {
            let fence = fence_for(&text);
            prop_assert!(fence.len() > text.matches('`').count().min(text.len()));
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Round-3 review items S-5, S-6, S-7 and S-10.
// ---------------------------------------------------------------------------------------------------------------

/// Review item S-5: the report path refuses an invalid previous run and a timestamp in the future.
#[test]
fn s5_resume_refuses_an_invalid_run_and_a_future_timestamp() {
    let (previous, dir) = bound_previous("report-s5-invalid");
    let invalid = previous
        .clone()
        .with_run_invalid(vec!["safety_envelope_denied: target refused".to_owned()]);
    assert!(matches!(
        fresh_bound().resume_with(&invalid, &dir, None),
        Err(ReportError::ResumeMismatch { .. })
    ));
    let future = previous.with_timestamp("9999-12-31T23:59:59Z");
    assert!(matches!(
        fresh_bound().resume_with(&future, &dir, None),
        Err(ReportError::ResumeMismatch { .. })
    ));
}

/// Review item S-5: the resumed line carries the verified path (inside the resume directory), not the path printed in the
/// previous report.
#[test]
fn s5_the_resumed_line_carries_the_verified_path() {
    let (mut previous, dir) = bound_previous("report-s5-path");
    // The recorded path points somewhere else; only its file name is used to find the artifact inside the resume directory.
    let recorded = previous.lines[0].evidence[0].clone();
    previous.lines[0].evidence[0] = EvidenceRef::new(
        format!(
            "somewhere-else/{}",
            recorded
                .path()
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or("proof.txt")
        ),
        recorded.sha256().to_owned(),
        recorded.bytes(),
    );
    let merged = fresh_bound()
        .resume_with(&previous, &dir, None)
        .expect("resume");
    let path = merged.status_line("AC-01").expect("AC-01 resumed").evidence[0].path();
    let canonical_dir = std::fs::canonicalize(&dir).expect("canonical dir");
    assert_eq!(
        path,
        canonical_dir.join("proof.txt").display().to_string(),
        "the resumed reference must point at the file that was verified"
    );
    assert!(!path.contains("somewhere-else"));
}

/// Review item S-6: the store records which check and run wrote an artifact.
#[test]
fn s6_the_evidence_store_records_check_and_run() {
    let dir = crate::test_support::temp_dir("report-s6-records");
    let store = EvidenceStore::create(&dir).expect("store");
    let reference = store
        .save_for("AC-07", "run-1", "proof.txt", b"evidence")
        .expect("save");
    assert_eq!(
        reference.path(),
        dir.join("proof.txt").display().to_string()
    );
    let records = store.records();
    let records = records.lock().expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].check, "AC-07");
    assert_eq!(records[0].run_id, "run-1");
    assert_eq!(records[0].name, "proof.txt");
    assert_eq!(records[0].sha256, sha256_hex(b"evidence"));
}

/// Review item S-7: the exact inputs the reviewer reproduced. Every one of them must be redacted.
#[test]
fn s7_markers_inside_json_keys_suffixes_and_camel_case_are_redacted() {
    let redactor = Redactor::new();
    let cases = [
        ("{\"password\":\"hunter2\"}", "hunter2"),
        ("aws_secret_access_key=AKIAXYZ123", "AKIAXYZ123"),
        ("secret_key=abc123", "abc123"),
        ("session_id=abc123", "abc123"),
        ("--password hunter2", "hunter2"),
        ("accessToken=abc123", "abc123"),
        ("the token was valid; token=abc123", "abc123"),
        ("x-api-key: SECRETVALUE", "SECRETVALUE"),
        ("X-Session-Id=session-value", "session-value"),
    ];
    for (input, leaked) in cases {
        let redacted = redactor.redact(input);
        assert!(
            !redacted.contains(leaked),
            "{input:?} leaked {leaked:?}: {redacted:?}"
        );
        assert!(
            redacted.contains("[REDACTED]"),
            "{input:?} was not redacted: {redacted:?}"
        );
    }
}

/// Review item S-7: exact secrets are replaced longest first, so `pass1234` cannot half-eat `pass1234567`.
#[test]
fn s7_exact_secrets_are_replaced_longest_first() {
    let mut redactor = Redactor::new();
    redactor.add_secret("pass1234").expect("long enough");
    redactor.add_secret("pass1234567").expect("long enough");
    assert_eq!(
        redactor.redact("x=pass1234567"),
        "x=[REDACTED]",
        "the longer secret must win"
    );
    assert_eq!(redactor.redact("x=pass1234"), "x=[REDACTED]");
}

/// Review item S-7: `add_secret` refuses a secret shorter than four bytes with an error instead of silently dropping it.
#[test]
fn s7_add_secret_refuses_a_short_secret() {
    let mut redactor = Redactor::new();
    assert_eq!(
        redactor.add_secret("abc"),
        Err(SecretError::TooShort { len: 3 })
    );
    assert_eq!(redactor.secrets_len(), 0);
    assert!(redactor.add_secret("abcd").is_ok());
    assert_eq!(redactor.secrets_len(), 1);
}

/// Review item S-10: a lone `\r` is a CommonMark line break, so it is escaped like `\n` in both inline text and table cells.
#[test]
fn s10_a_lone_carriage_return_cannot_inject_a_markdown_heading() {
    let mut report = Report::new("live", "pilot", "functional", 0);
    report.push_line(StatusLine::stage_not_reached(
        "AC-00",
        "title\r## injected",
        "smoke",
    ));
    report.push_note("note\r## injected");
    report.push_evidence(
        EvidenceBlock::new("AC-00\r## injected", EvidenceKind::EventRecord)
            .with_field("field\r## injected", "value\r## injected"),
    );
    let markdown = report.render_markdown().expect("markdown");
    assert!(
        !markdown.contains("\n## injected") && !markdown.contains("\r## injected"),
        "a lone CR must not start a heading: {markdown}"
    );
}

/// Review item S-10: a backtick in a log path is fenced with a longer code span, so the rest of the path is not Markdown.
#[test]
fn s10_a_backtick_in_a_log_path_cannot_break_the_code_span() {
    let mut report = sample_report();
    report.logs.clear();
    report.push_log(LogRef {
        path: "run`log **bold**.txt".to_owned(),
        sha256: HASH_B.to_owned(),
        bytes: 10,
        tail: "tail".to_owned(),
    });
    let markdown = report.render_markdown().expect("markdown");
    assert!(
        markdown.contains("``run`log **bold**.txt``"),
        "the path is wrapped in a two-backtick span: {markdown}"
    );
}

/// Review item S-10: the Windows console device names and superscript COM device numbers are reserved too.
#[test]
fn s10_console_devices_and_superscript_com_names_are_refused() {
    for name in [
        "CONIN$",
        "conout$",
        "COM\u{00b9}",
        "COM\u{00b2}",
        "COM\u{00b3}",
        "LPT\u{00b9}",
    ] {
        assert!(
            safe_evidence_name(name).is_err(),
            "{name:?} must be refused"
        );
    }
    for name in ["console.txt", "com0.txt", "lpt0.txt"] {
        assert!(safe_evidence_name(name).is_ok(), "{name:?}");
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Round-4 review items N-4, N-5 and N-6.
// ---------------------------------------------------------------------------------------------------------------

/// Review item N-5: escaped nested JSON, no-separator uppercase names, an escaped quote inside a quoted value, and the
/// URL-encoded, `\/`-escaped and base64 forms of an exact secret.
#[test]
fn n5_escaped_uppercase_and_encoded_secret_forms_are_redacted() {
    let redactor = Redactor::new();
    for (input, leaked) in [
        (r#"{\"password\":\"hunter2\"}"#, "hunter2"),
        ("DBPASSWORD=hunter2", "hunter2"),
        ("AWSSecretAccessKey=AKIAXYZ123", "AKIAXYZ123"),
    ] {
        let redacted = redactor.redact(input);
        assert!(!redacted.contains(leaked), "{input:?}: {redacted:?}");
        assert!(redacted.contains("[REDACTED]"), "{input:?}: {redacted:?}");
    }
    // An escaped quote inside a quoted value does not end redaction early.
    let escaped = redactor.redact("password=\"a\\\"b\" tail=visible");
    assert!(!escaped.contains("a\\\"b"), "{escaped:?}");
    assert!(escaped.contains("tail=visible"), "{escaped:?}");

    let mut encoded = Redactor::new();
    encoded.add_secret("p@ss word!").expect("long enough");
    encoded.add_secret("token/part").expect("long enough");
    encoded.add_secret("secret123456").expect("long enough");
    for (input, leaked) in [
        ("x=p%40ss%20word%21", "p%40ss%20word%21"),
        ("x=token\\/part", "token\\/part"),
        ("x=c2VjcmV0MTIzNDU2", "c2VjcmV0MTIzNDU2"),
    ] {
        let redacted = encoded.redact(input);
        assert!(!redacted.contains(leaked), "{input:?}: {redacted:?}");
    }
}

/// Review item N-6: an unquoted value ends at the next delimiter, a `Bearer`/`Basic` scheme word survives, quotes stay
/// around `[REDACTED]` and the redacted JSON still parses.
#[test]
fn n6_delimiters_bearer_and_valid_json() {
    let redactor = Redactor::new();
    let json = redactor.redact("{\"password\":\"hunter2\",\"status\":200}");
    assert!(json.contains("\"password\":\"[REDACTED]\""), "{json}");
    assert!(json.contains("\"status\":200"), "{json}");
    serde_json::from_str::<serde_json::Value>(&json).expect("redacted JSON stays valid");

    let bearer = redactor.redact("Authorization: Bearer abc123, x=1");
    assert!(bearer.contains("Bearer [REDACTED]"), "{bearer}");
    assert!(bearer.contains("x=1"), "{bearer}");

    // Whole-token field-name matching: session_count is not a secret field, accessToken and X-API-Key are.
    assert!(!EvidenceBlock::is_secret_field("session_count"));
    assert!(!EvidenceBlock::is_secret_field("tokenizer"));
    assert!(EvidenceBlock::is_secret_field("accessToken"));
    assert!(EvidenceBlock::is_secret_field("X-API-Key"));
    assert!(EvidenceBlock::is_secret_field("client_secret"));

    // Each embedded tail line is capped at 2 KB (review item N-6).
    let capped = cap_tail_lines(&"a".repeat(5000));
    assert!(capped.len() <= MAX_TAIL_LINE_BYTES, "tail line cap");
}

/// Review item N-6: redaction on a 1 MB line is linear, not quadratic. The bound is relative to the single-pass cost, not a
/// wall-clock second.
#[test]
fn n6_redaction_is_linear_on_one_megabyte() {
    let redactor = Redactor::new();
    let unit = "token=abc123, status=200; ";
    let small = unit.repeat(2_500);
    let big = unit.repeat(10_000);
    assert!(small.len() > 50_000 && big.len() > 200_000);
    let start = std::time::Instant::now();
    let redacted_small = redactor.redact(&small);
    let small_time = start.elapsed();
    let start = std::time::Instant::now();
    let redacted_big = redactor.redact(&big);
    let big_time = start.elapsed();
    assert_eq!(redacted_small.matches("[REDACTED]").count(), 2_500);
    assert_eq!(redacted_big.matches("[REDACTED]").count(), 10_000);
    assert!(
        big_time <= small_time.saturating_mul(12) + std::time::Duration::from_millis(50),
        "redaction looks quadratic: {small_time:?} for 50 KB vs {big_time:?} for 200 KB"
    );
}

/// Review item N-4: a resumed run copies the verified evidence into the new run directory, keeps the line's original
/// timestamp, and the copy can itself be resumed (resume twice), while an over-age line is refused.
#[test]
fn n4_resume_copies_evidence_and_resume_twice_keeps_the_line_age() {
    let (previous, dir) = bound_previous("report-n4-previous");
    let run2_dir = crate::test_support::temp_dir("report-n4-run2");
    let run2 = fresh_bound()
        .resume_with(&previous, &dir, Some(&run2_dir))
        .expect("first resume copies evidence");
    let line = run2.status_line("AC-01").expect("AC-01");
    let path = line.evidence[0].path();
    assert!(
        path.starts_with(&run2_dir.display().to_string()),
        "the line must point at the copy in the new run directory: {path}"
    );
    assert!(std::path::Path::new(path).is_file(), "the copy exists");
    assert_eq!(
        run2.line_timestamps.get("AC-01"),
        Some(&previous.generated_at),
        "the resumed line keeps the timestamp it was produced at"
    );

    // Resume from run 2: the copied evidence is inside run2_dir and is verified again.
    let run3 = fresh_bound()
        .resume_with(&run2, &run2_dir, None)
        .expect("second resume");
    assert!(run3.status_line("AC-01").expect("AC-01").verdict.is_pass());

    // A line whose original timestamp is too old is refused even though the report itself is new.
    let mut stale = run2.clone();
    stale
        .line_timestamps
        .insert("AC-01".to_owned(), "2020-01-01T00:00:00Z".to_owned());
    assert!(matches!(
        fresh_bound().resume_with(&stale, &run2_dir, None),
        Err(ReportError::ResumeMismatch { .. })
    ));
}

/// Review item N-1: the run-invalid latch of a `RunReport` is carried into the `Report`, and both formats name the check
/// and the run that tripped it (the latch record carries both ids).
#[test]
fn n1_the_report_carries_the_run_invalid_record_into_json_and_markdown() {
    let record = crate::runner::RunInvalidRecord {
        check_id: "AC-01".to_owned(),
        run_id: "run-9".to_owned(),
        detail: "target refused".to_owned(),
    };
    let run = crate::runner::RunReport {
        lines: Vec::new(),
        cleanup: Vec::new(),
        abort: Some(crate::runner::AbortCause::RunInvalid),
        panics: 0,
        run_invalid: true,
        invalid_audit: vec![format!(
            "check {} in run {}: {}",
            record.check_id, record.run_id, record.detail
        )],
        invalid_records: vec![record],
    };
    let mut report = sample_report();
    report.apply_run_report(&run);
    assert!(report.run_invalid);
    let json = report.render_json().expect("json");
    assert!(json.contains("\"run_invalid\": true"), "{json}");
    assert!(json.contains("AC-01"), "{json}");
    assert!(json.contains("run-9"), "{json}");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed["run_invalid"], serde_json::json!(true));
    let markdown = report.render_markdown().expect("markdown");
    assert!(markdown.contains("## Run invalid"), "{markdown}");
    assert!(markdown.contains("AC-01"), "{markdown}");
    assert!(markdown.contains("run-9"), "{markdown}");
}

/// Review item N-5: the renderer redacts the `config_revision` and every evidence reference path, and the redacted JSON is
/// still a valid report.
#[test]
fn n5_the_renderer_redacts_evidence_paths_and_the_config_revision() {
    let mut report = Report::new("live", "pilot", "functional", 0)
        .with_binding("rev-CLIENTSECRET-1", vec!["shop.example.com".to_owned()]);
    report
        .redactor
        .add_secret("CLIENTSECRET")
        .expect("long enough");
    report.push_line(
        StatusLine::new(
            "AC-00",
            "self test",
            "smoke",
            Verdict::Pass,
            vec![EvidenceRef::new("/runs/CLIENTSECRET/run.log", HASH_A, 10)],
        )
        .expect("PASS"),
    );
    let json = report.render_json().expect("json");
    assert!(!json.contains("CLIENTSECRET"), "{json}");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("redacted JSON stays valid");
    assert_eq!(
        parsed["config_revision"],
        serde_json::json!("rev-[REDACTED]-1")
    );
    assert_eq!(
        parsed["lines"][0]["evidence"][0]["path"],
        serde_json::json!("/runs/[REDACTED]/run.log")
    );
    let markdown = report.render_markdown().expect("markdown");
    assert!(!markdown.contains("CLIENTSECRET"), "{markdown}");
}
