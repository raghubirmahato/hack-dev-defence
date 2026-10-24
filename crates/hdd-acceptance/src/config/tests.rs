//! Configuration tests: profile validation through `hdd_common::profile`, the lifecycle gates of section 2.7, the `load` run
//! approval of section 2.3, the profile/mode matrix of section 2.3 (review item R-1) and the run-id-bound approval (R-13),
//! and the runner-IP refusal before a run starts.

use std::net::IpAddr;

use hdd_common::egress::TargetMode;
use hdd_common::profile::types::LifecycleStage;

use super::*;
use crate::test_support::{profile, profile_missing_required};

fn ip(text: &str) -> IpAddr {
    text.parse().expect("test IP")
}

/// The example profile with a usable closed lab (the example ships `lab.enabled: false`).
fn lab_profile() -> hdd_common::profile::Profile {
    let mut p = profile();
    p.lab.enabled = true;
    p.lab.host = "lab.example.test".to_owned();
    p.lab.cidr = "10.99.0.0/24".to_owned();
    p
}

fn approval_for(run: &str) -> RunApproval {
    RunApproval::new(run, "2026-10-21 02:00-03:00 UTC")
        .expect("an approval with a run id and a window")
}

#[test]
fn the_example_profile_assembles_a_run_configuration() {
    let config = RunnerConfig::build(
        profile(),
        TargetMode::Live,
        LoadProfile::Functional,
        None,
        "run-test-1",
        Some(ip("198.51.100.77")),
    )
    .expect("a valid profile assembles");
    assert_eq!(config.lifecycle.stage(), LifecycleStage::Pilot);
    assert_eq!(config.run_id, "run-test-1");
    assert!(
        config
            .lifecycle
            .allows_destructive_for("run-test-1")
            .is_ok()
    );
    assert_eq!(config.vantage.count(), 0);
    assert!(config.runner.is_bannable());
    assert_eq!(config.load_profile, LoadProfile::Functional);
}

#[test]
fn an_unusable_profile_is_refused_with_its_failures() {
    let error = RunnerConfig::build(
        profile_missing_required(),
        TargetMode::Live,
        LoadProfile::Functional,
        None,
        "run-test-1",
        None,
    )
    .expect_err("required fields are missing");
    match error {
        ConfigError::InvalidProfile { failures } => {
            assert!(
                failures
                    .iter()
                    .any(|f| f.starts_with("PROF-REQUIRED") && f.contains("operator_email")),
                "{failures:?}"
            );
        }
        other => panic!("expected InvalidProfile, got {other:?}"),
    }
}

#[test]
fn a_profile_that_does_not_parse_reports_its_key_path() {
    let error = load_profile_text("schema_version: 5\nsurprise: 1\n").expect_err("unknown key");
    match error {
        ConfigError::Parse { message } => assert!(message.contains("surprise"), "{message}"),
        other => panic!("expected Parse, got {other:?}"),
    }
    let error = load_profile_text("schema_version: nonsense\n").expect_err("wrong type");
    assert!(matches!(error, ConfigError::Parse { .. }));
}

#[test]
fn a_missing_profile_file_is_an_io_error() {
    let error = load_profile_file(std::path::Path::new("definitely/not/a/profile.yaml"))
        .expect_err("missing file");
    assert!(matches!(error, ConfigError::Io { .. }), "{error:?}");
    assert!(error.to_string().contains("cannot read"));
}

#[test]
fn production_refuses_destructive_checks_without_this_runs_approval() {
    let production = LifecyclePolicy::new(LifecycleStage::Production, None);
    assert_eq!(
        production.allows_destructive_for("run-1"),
        Err(StageRefusal::ProductionRequiresApproval)
    );
    assert!(production.warning().is_none());

    let approved = LifecyclePolicy::new(LifecycleStage::Production, Some(approval_for("run-1")));
    assert!(approved.allows_destructive_for("run-1").is_ok());
}

#[test]
fn pilot_allows_destructive_checks_with_a_warning() {
    let pilot = LifecyclePolicy::new(LifecycleStage::Pilot, None);
    assert!(pilot.allows_destructive_for("run-1").is_ok());
    assert!(
        pilot
            .warning()
            .unwrap_or_default()
            .contains("destructive checks run with a warning")
    );
}

#[test]
fn an_approval_must_carry_its_run_id_and_its_maintenance_window() {
    assert!(matches!(
        RunApproval::new("", "02:00-03:00"),
        Err(ConfigError::BadApproval { .. })
    ));
    assert!(matches!(
        RunApproval::new("run-1", "   "),
        Err(ConfigError::BadApproval { .. })
    ));
    let approval = RunApproval::new(" run-1 ", " window ").expect("approval");
    assert_eq!(approval.run_id(), "run-1");
    assert_eq!(approval.maintenance_window(), "window");
}

#[test]
fn a_load_run_needs_the_profile_flag_and_the_runs_own_written_approval() {
    let mut p = profile();
    p.load_profile_approved = false;
    let error = RunnerConfig::build(
        p,
        TargetMode::Live,
        LoadProfile::Load,
        None,
        "run-test-1",
        None,
    )
    .expect_err("flag is false");
    assert!(
        matches!(error, ConfigError::LoadNotApproved { .. }),
        "{error:?}"
    );

    let mut p = profile();
    p.load_profile_approved = true;
    let error = RunnerConfig::build(
        p,
        TargetMode::Live,
        LoadProfile::Load,
        None,
        "run-test-1",
        None,
    )
    .expect_err("no approval for this run");
    assert!(
        error.to_string().contains("no recorded approval"),
        "{error}"
    );

    let mut p = profile();
    p.load_profile_approved = true;
    let approval = approval_for("run-test-1");
    assert!(
        RunnerConfig::build(
            p,
            TargetMode::Live,
            LoadProfile::Load,
            Some(approval),
            "run-test-1",
            Some(ip("198.51.100.77")),
        )
        .is_ok()
    );
}

#[test]
fn the_non_load_profiles_do_not_need_the_load_approval() {
    for (load, mode, profile) in [
        (LoadProfile::Functional, TargetMode::Live, profile()),
        (LoadProfile::Burst, TargetMode::Live, profile()),
        (LoadProfile::ProtocolAbuse, TargetMode::Live, profile()),
        (LoadProfile::Functional, TargetMode::Lab, lab_profile()),
        (LoadProfile::Burst, TargetMode::Lab, lab_profile()),
        (LoadProfile::Lab, TargetMode::Lab, lab_profile()),
    ] {
        assert!(
            RunnerConfig::build(
                profile,
                mode,
                load,
                None,
                "run-test-1",
                Some(ip("198.51.100.77"))
            )
            .is_ok(),
            "{load} in {mode:?}"
        );
    }
}

/// Review item R-1: the 5 x 2 profile/mode matrix of section 2.3. `lab` targets only lab addresses, so it runs only in lab
/// mode; `protocol-abuse` and `load` target only the sandbox host name of the live profile; `functional` and `burst` run in
/// both. The connector enforces the same matrix on its own (see `guard/tests.rs`), so a caller cannot bypass it.
#[test]
fn r1_every_profile_mode_pair_is_refused_or_accepted_by_the_specification_table() {
    let cases = [
        (LoadProfile::Functional, TargetMode::Live, true),
        (LoadProfile::Functional, TargetMode::Lab, true),
        (LoadProfile::Burst, TargetMode::Live, true),
        (LoadProfile::Burst, TargetMode::Lab, true),
        (LoadProfile::ProtocolAbuse, TargetMode::Live, true),
        (LoadProfile::ProtocolAbuse, TargetMode::Lab, false),
        (LoadProfile::Load, TargetMode::Live, true),
        (LoadProfile::Load, TargetMode::Lab, false),
        (LoadProfile::Lab, TargetMode::Live, false),
        (LoadProfile::Lab, TargetMode::Lab, true),
    ];
    for (load, mode, accepted) in cases {
        let mut p = if mode == TargetMode::Lab {
            lab_profile()
        } else {
            profile()
        };
        p.load_profile_approved = true;
        let approval = Some(approval_for("run-test-1"));
        let result = RunnerConfig::build(p, mode, load, approval, "run-test-1", None);
        if accepted {
            assert!(
                result.is_ok(),
                "{load} in {mode:?} must be accepted: {result:?}"
            );
        } else {
            match result {
                Err(ConfigError::ProfileModeMismatch {
                    profile: refused,
                    mode: observed,
                }) => {
                    assert_eq!(refused, load);
                    assert_eq!(observed, mode);
                }
                other => panic!(
                    "{load} in {mode:?} must be refused with ProfileModeMismatch, got {other:?}"
                ),
            }
        }
    }
}

/// Review item R-13: one coherent production rule, and the approval is bound to the run it names.
#[test]
fn r13_the_approval_is_bound_to_the_run_id_and_the_run_is_refused_otherwise() {
    let policy = LifecyclePolicy::new(
        LifecycleStage::Production,
        Some(approval_for("run-approved")),
    );
    assert!(policy.allows_destructive_for("run-approved").is_ok());
    assert_eq!(
        policy.allows_destructive_for("run-other"),
        Err(StageRefusal::ApprovalForAnotherRun {
            approved: "run-approved".to_owned(),
            run: "run-other".to_owned(),
        })
    );

    let p = profile();
    // The build-level refusal is independent of the stage; keep the example's pilot stage so the production cutover
    // validation (origin lockdown, upstream DDoS) does not mask the approval check.
    let error = RunnerConfig::build(
        p,
        TargetMode::Live,
        LoadProfile::Functional,
        Some(approval_for("run-approved")),
        "run-other",
        Some(ip("198.51.100.77")),
    )
    .expect_err("the ticket names another run");
    match error {
        ConfigError::ApprovalForAnotherRun { approved, run } => {
            assert_eq!(approved, "run-approved");
            assert_eq!(run, "run-other");
        }
        other => panic!("expected ApprovalForAnotherRun, got {other:?}"),
    }
}

#[test]
fn a_run_without_an_id_is_refused() {
    let error = RunnerConfig::build(
        profile(),
        TargetMode::Live,
        LoadProfile::Functional,
        None,
        "  ",
        None,
    )
    .expect_err("no run id");
    assert!(
        matches!(error, ConfigError::BadApproval { .. }),
        "{error:?}"
    );
}

#[test]
fn the_runner_ip_is_checked_before_the_run_starts() {
    let mut p = profile();
    p.admin_cidrs = vec!["198.51.100.0/24".to_owned()];
    let error = RunnerConfig::build(
        p,
        TargetMode::Live,
        LoadProfile::Functional,
        None,
        "run-test-1",
        Some(ip("198.51.100.77")),
    )
    .expect_err("the runner would be unbannable");
    match error {
        ConfigError::InvalidProfile { failures } => assert!(
            failures.iter().any(|f| f.starts_with("PROF-RUNNER-ADMIN")),
            "{failures:?}"
        ),
        other => panic!("expected InvalidProfile, got {other:?}"),
    }
}

#[test]
fn lab_mode_requires_a_configured_lab() {
    let error = RunnerConfig::build(
        profile(),
        TargetMode::Lab,
        LoadProfile::Lab,
        None,
        "run-test-1",
        Some(ip("198.51.100.77")),
    )
    .expect_err("the example profile has no lab");
    match error {
        ConfigError::Target { reason } => assert!(reason.to_string().contains("lab")),
        other => panic!("expected a target refusal, got {other:?}"),
    }
}

#[test]
fn an_invalid_dns_entry_in_the_egress_allowlist_is_refused_by_the_gate() {
    let mut p = profile();
    p.egress_allowlist = vec!["dns://not an address".to_owned()];
    let error = crate::guard::EgressGate::from_profile(&p).expect_err("invalid entry");
    assert_eq!(error.len(), 1);
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// The profile loader reuses the budgeted YAML parser; arbitrary hostile text must return an error, never panic.
        #[test]
        fn load_profile_text_never_panics_on_hostile_input(text in ".{0,600}") {
            let _ = load_profile_text(&text);
        }

        /// A truncated example profile (a real profile cut at an arbitrary byte boundary) must not panic either.
        #[test]
        fn a_truncated_profile_never_panics(cut in 0usize..2000) {
            let example = crate::test_support::profile_yaml();
            let end = cut.min(example.len());
            let mut boundary = end;
            while boundary > 0 && !example.is_char_boundary(boundary) {
                boundary -= 1;
            }
            let _ = load_profile_text(&example[..boundary]);
        }
    }
}

#[test]
fn a11_the_operator_approval_ticket_format_is_checked() {
    let ticket = "run=run-20261020-01; window=2026-10-21 02:00-03:00 UTC";
    let approval = RunApproval::parse_ticket(ticket).expect("valid ticket");
    assert_eq!(approval.run_id(), "run-20261020-01");
    assert_eq!(approval.maintenance_window(), "2026-10-21 02:00-03:00 UTC");
    // order and whitespace do not matter
    assert!(
        RunApproval::parse_ticket(" window=02:00-03:00 ; run=r1 ").is_ok(),
        "keys may be reordered"
    );
    for bad in [
        "",
        "run=r1",
        "window=02:00-03:00",
        "run=r1; window=",
        "run=; window=02:00-03:00",
        "run=r1; run=r2; window=w",
        "run=r1; window=w; window=w2",
        "run=r1; window=w; note=nope",
        "run=r1; window=w; extra",
    ] {
        assert!(
            matches!(
                RunApproval::parse_ticket(bad),
                Err(ConfigError::BadApproval { .. })
            ),
            "{bad:?}"
        );
    }
}
