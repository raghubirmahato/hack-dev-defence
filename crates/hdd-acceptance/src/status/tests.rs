//! Taxonomy tests: the closed reason set, whole-token ids and the PASS-needs-evidence rule.

use super::*;

#[test]
fn the_reason_set_is_closed_and_round_trips_by_code() {
    // Correction of the round-1 review: the spec closes the reason set to exactly these eight codes (section 0, E3.1 rule 1).
    // The round-1 items that named `no_hdd_evidence` and `dependency_not_met` are outside the set and removed.
    assert_eq!(ReasonCode::ALL.len(), 8);
    let expected = [
        "capability_not_supplied",
        "human_step_pending",
        "environment_unsupported",
        "oracle_unavailable",
        "tool_unavailable",
        "stage_not_reached",
        "stage_forbids",
        "skipped_by_operator",
    ];
    let mut codes: Vec<&str> = ReasonCode::ALL.iter().map(|r| r.code()).collect();
    codes.sort_unstable();
    let mut expected_sorted = expected.to_vec();
    expected_sorted.sort_unstable();
    assert_eq!(codes, expected_sorted, "the closed reason set");
    let mut unique = codes.clone();
    unique.dedup();
    assert_eq!(codes, unique, "reason codes are unique");
    for reason in ReasonCode::ALL {
        assert_eq!(ReasonCode::parse(reason.code()), Some(reason));
    }
    for bad in [
        "",
        "stage-not-reached",
        "STAGE_NOT_REACHED",
        "pending",
        "skipped",
        // the two round-1 codes outside the closed set must not parse or exist
        "no_hdd_evidence",
        "dependency_not_met",
    ] {
        assert_eq!(ReasonCode::parse(bad), None, "{bad}");
    }
}

#[test]
fn every_status_renders_the_taxonomy_of_e3_1() {
    assert_eq!(Verdict::Pass.to_string(), "PASS");
    assert_eq!(Verdict::fail("boom").to_string(), "FAIL(boom)");
    assert_eq!(
        Verdict::unverified(ReasonCode::StageNotReached).to_string(),
        "UNVERIFIED(stage_not_reached)"
    );
}

#[test]
fn check_ids_are_whole_tokens() {
    for good in ["AC-00", "AC-09", "AC-10", "AC-62"] {
        assert!(is_check_id(good), "{good}");
    }
    for bad in [
        "ac-00", "AC-0", "AC-000", "AC-00x", "xAC-00", "AC-00 ", "AC-0\n", "AC-100",
    ] {
        assert!(!is_check_id(bad), "{bad:?} must not be a check id");
    }
}

#[test]
fn a_pass_without_hashed_evidence_is_not_representable() {
    let none = StatusLine::new("AC-00", "t", "smoke", Verdict::Pass, Vec::new());
    assert_eq!(
        none,
        Err(TaxonomyError::PassWithoutEvidence { id: "AC-00".into() })
    );
    let bogus = EvidenceRef::new("a.txt", "not-a-hash", 1);
    assert_eq!(
        StatusLine::new("AC-00", "t", "smoke", Verdict::Pass, vec![bogus]),
        Err(TaxonomyError::PassWithoutEvidence { id: "AC-00".into() })
    );
    let good = EvidenceRef::new("a.txt", "a".repeat(64), 1);
    assert!(StatusLine::new("AC-00", "t", "smoke", Verdict::Pass, vec![good]).is_ok());
}

#[test]
fn fail_and_unverified_need_no_evidence_but_keep_their_reason() {
    let f = StatusLine::new("AC-07", "t", "pilot-full", Verdict::fail("x"), Vec::new());
    assert!(f.is_ok());
    let u = StatusLine::stage_not_reached("AC-08", "t", "pilot-full");
    assert!(u.validate().is_ok());
    assert_eq!(
        u.verdict,
        Verdict::Unverified {
            reason: ReasonCode::StageNotReached
        }
    );
}

#[test]
fn a_bad_id_is_refused() {
    assert_eq!(
        StatusLine::new("AC-0", "t", "smoke", Verdict::fail("x"), Vec::new()),
        Err(TaxonomyError::BadId { id: "AC-0".into() })
    );
}

#[test]
fn verdicts_serialise_with_their_status_tag() {
    let v = serde_json::to_value(Verdict::unverified(ReasonCode::StageNotReached)).expect("json");
    assert_eq!(
        v,
        serde_json::json!({"status": "unverified", "reason": "stage_not_reached"})
    );
    let back: Verdict = serde_json::from_value(v).expect("round trip");
    assert_eq!(
        back,
        Verdict::Unverified {
            reason: ReasonCode::StageNotReached
        }
    );
    assert!(
        serde_json::from_value::<Verdict>(serde_json::json!({"status": "pending"})).is_err(),
        "a status outside the taxonomy must not parse"
    );
}

#[test]
fn counts_total_every_line() {
    let counts = Counts {
        pass: 2,
        fail: 1,
        unverified: 60,
    };
    assert_eq!(counts.total(), 63);
}
