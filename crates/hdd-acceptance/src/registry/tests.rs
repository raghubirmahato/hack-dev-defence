//! Registry tests (A4): 63 whole-token ids, the specification cross-check by parsing `docs/spec/E3.md` and `docs/SPEC.md`
//! (never trusting the copied table), and a dry run that emits one status line per id.

use std::collections::BTreeSet;
use std::path::PathBuf;

use super::*;
use crate::status::{Counts, Verdict};

fn repo_file(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn read_repo_file(relative: &str) -> String {
    let path = repo_file(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

#[test]
fn the_registry_has_the_sixty_three_expected_ids_in_order() {
    assert_eq!(ids().len(), CHECK_COUNT);
    assert_eq!(
        ids(),
        expected_ids()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
    let unique: BTreeSet<&str> = ids().into_iter().collect();
    assert_eq!(unique.len(), CHECK_COUNT, "no duplicate registry id");
    assert_eq!(CHECK_COUNT, 63);
}

#[test]
fn every_registry_row_is_a_whole_token_id_with_a_title_and_a_tier() {
    for entry in entries() {
        assert!(is_check_id(entry.id), "{}", entry.id);
        assert!(!entry.title.trim().is_empty(), "{} has no title", entry.id);
        assert!(!entry.tier.trim().is_empty(), "{} has no tier", entry.id);
        assert!(
            !entry.built_in.trim().is_empty(),
            "{} has no build site",
            entry.id
        );
    }
}

#[test]
fn a4_the_split_specification_agrees_with_the_registry_whole_token() {
    let text = read_repo_file("docs/spec/E3.md");
    let rows =
        cross_check("docs/spec/E3.md", &text).expect("the split E3 agrees with the registry");
    assert_eq!(rows.len(), CHECK_COUNT);
    let parsed: Vec<&str> = rows.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        parsed,
        expected_ids()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
}

#[test]
fn a4_the_master_specification_agrees_with_the_registry_whole_token() {
    let text = read_repo_file("docs/SPEC.md");
    let rows = cross_check("docs/SPEC.md", &text)
        .expect("the master specification agrees with the registry");
    assert_eq!(rows.len(), CHECK_COUNT);
}

#[test]
fn the_ac_table_is_cross_checked_not_trusted() {
    // The registry is projected from the table; the specification parse above is the independent check. Here: the table's
    // own shape is asserted so a silently shortened table (62 rows) cannot hide behind the projection.
    assert_eq!(ACCEPTANCE_CHECKS.len(), CHECK_COUNT);
    let table_ids: BTreeSet<&str> = ACCEPTANCE_CHECKS.iter().map(|(id, _, _, _)| *id).collect();
    let expected: BTreeSet<String> = expected_ids().into_iter().collect();
    assert_eq!(
        table_ids,
        expected
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<&str>>()
    );
}

#[test]
fn the_parser_does_not_mistake_substrings_or_prose_for_ids() {
    let fixture = "\
## E3. Acceptance matrix (AC-00 to AC-62)

### E3.1 Rules common to every check

Prose mentions AC-0 inside AC-00 and AC-1 in AC-10, and a task id T-0215, and `AC-00` in backticks.

### E3.5 The checks

#### AC-00 · Preflight and safety-envelope self-tests

Body among AC-0 and AC-1 and AC-00x.

#### AC-01 · Authentication and admin isolation

### E3.6 Check-to-phase coverage table

#### AC-02 · not a check row, after the section ends
";
    let rows = parse_spec_rows("fixture", fixture).expect("parse");
    assert_eq!(
        rows,
        vec![
            SpecRow {
                id: "AC-00".to_owned(),
                title: "Preflight and safety-envelope self-tests".to_owned()
            },
            SpecRow {
                id: "AC-01".to_owned(),
                title: "Authentication and admin isolation".to_owned()
            },
        ]
    );
    // a heading that is not a whole token is a finding, not a row
    let bad = "### E3.5 The checks\n#### AC-0 · bad\n### E3.6 x\n";
    assert!(matches!(
        parse_spec_rows("fixture", bad),
        Err(RegistryMismatch::BadId { .. })
    ));
    let missing = "there is no e3.5 section here";
    assert!(matches!(
        parse_spec_rows("fixture", missing),
        Err(RegistryMismatch::SectionMissing { .. })
    ));
}

#[test]
fn a4_a_dry_run_emits_one_status_line_per_registered_id() {
    let dry = DryRun::new();
    assert_eq!(dry.len(), CHECK_COUNT);
    assert_eq!(
        dry.ids(),
        expected_ids()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
    assert!(
        dry.all_stage_not_reached(),
        "every line is UNVERIFIED(stage_not_reached)"
    );
    dry.validate().expect("dry run covers every id once");
    let counts = Counts {
        pass: 0,
        fail: 0,
        unverified: CHECK_COUNT,
    };
    assert_eq!(counts.total(), CHECK_COUNT);
    for line in dry.lines() {
        assert_eq!(
            line.verdict,
            Verdict::Unverified {
                reason: ReasonCode::StageNotReached
            }
        );
        assert!(
            line.evidence.is_empty(),
            "a stage_not_reached line has no evidence"
        );
    }
}

#[test]
fn a4_the_rendered_dry_run_report_has_one_row_per_id() {
    let dry = DryRun::new();
    let mut report = crate::report::Report::new("live", "pilot", "functional", 0)
        .with_timestamp("2026-10-20T09:00:00Z");
    for line in dry.lines() {
        report.push_line(line.clone());
    }
    let markdown = report.render_markdown().expect("dry-run markdown");
    assert!(markdown.contains("63 checks: 0 PASS, 0 FAIL, 63 UNVERIFIED"));
    for id in expected_ids() {
        assert_eq!(
            markdown.matches(&format!("| {id} |")).count(),
            1,
            "{id} must have exactly one status row"
        );
    }
    let rows = markdown
        .lines()
        .filter(|line| line.starts_with("| AC-"))
        .count();
    assert_eq!(rows, CHECK_COUNT);
}

#[test]
fn a_dry_run_with_a_missing_id_is_refused() {
    let mut dry = DryRun::new();
    dry.lines.pop();
    assert!(matches!(
        dry.validate(),
        Err(RegistryMismatch::NotSequential { .. })
    ));
}

#[test]
fn the_mismatch_messages_name_the_problem() {
    let mismatch = RegistryMismatch::NotSequential {
        source: "x".to_owned(),
        missing: vec!["AC-62".to_owned()],
        extra: Vec::new(),
    };
    assert!(mismatch.to_string().contains("AC-62"));
    assert!(
        RegistryMismatch::SectionMissing {
            source: "docs/SPEC.md".to_owned()
        }
        .to_string()
        .contains("E3.5")
    );
}
