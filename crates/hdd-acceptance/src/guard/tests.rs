//! Guard tests: A1 (a non-allowlisted target aborts before the sender), A-1 (single-use request and one token per send),
//! A-2 (the connector uses the run's shared budget), A-4 (path validation, per-hop resolution, no redirects), A-5 (the
//! inspect-first ticket is required and bound) and A-11 (runner must be bannable). All with recording senders, never a socket.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hdd_common::egress::allow::Allowlist;
use hdd_common::egress::resolver::Resolver;
use hdd_common::egress::{KillSwitch, TargetDenied, TargetMode};
use hdd_common::profile::types::LifecycleStage;

use super::*;
use crate::config::LifecyclePolicy;
use crate::control::Bannable;
use crate::inspect::{
    FixedRevision, InspectRequest, InspectTicket, RevisionSource, SiteMode, TicketError,
};
use crate::limits::{LimitDenial, Limiter, LoadProfile, RateBudget};
use crate::runner::{AbortLatch, CheckContext, CleanupStack};
use crate::test_support::{
    CountingSender, RecordingSender, ScriptedResolver, allowlisted_resolver, budget_over,
    kill_switch, manual_clock, profile, rate_budget, temp_dir,
};

const TEST_HOST: &str = "hddtest.example.com";
const SANDBOX_HOST: &str = "hddsbx.example.com";
const OUTSIDE: &str = "www.example.com";
const REVISION: &str = "rev-1";

fn attempt(target: &str, class: PayloadClass, method: Method) -> Attempt {
    Attempt {
        target: target.to_owned(),
        path: "/?probe=1".to_owned(),
        class,
        method,
        verb: method.as_str().to_owned(),
        body: Vec::new(),
        headers: Vec::new(),
    }
}

fn inspect_request_for(attempt: &Attempt) -> InspectRequest {
    InspectRequest::for_attempt(
        attempt.target.to_ascii_lowercase(),
        attempt.path.clone(),
        attempt.method,
        attempt.verb.clone(),
        attempt.class,
        &attempt.headers,
        &attempt.body,
    )
}

fn bannable() -> Bannable {
    Bannable::Bannable {
        runner: "198.51.100.77".parse().expect("runner ip"),
    }
}

fn ticket(attempt: &Attempt) -> InspectTicket {
    InspectTicket::for_test(
        inspect_request_for(attempt),
        REVISION,
        SiteMode::Block,
        false,
    )
}

struct Built {
    connector: Connector,
    kill: KillSwitch,
    abort: Arc<AbortLatch>,
    resolver: Arc<ScriptedResolver>,
    invalid: Arc<crate::runner::RunInvalidLatch>,
}

fn build_with(
    load: LoadProfile,
    stage: LifecycleStage,
    approval: Option<crate::config::RunApproval>,
    destructive: bool,
    runner: Bannable,
    budget: Arc<Mutex<RateBudget>>,
    resolver: Arc<ScriptedResolver>,
) -> Built {
    let dir = temp_dir("guard-connector");
    let kill = kill_switch(&dir);
    let abort = Arc::new(AbortLatch::new());
    let invalid = Arc::new(crate::runner::RunInvalidLatch::new());
    let profile = profile();
    let connector = Connector::new(
        &profile,
        ConnectorParts {
            mode: TargetMode::Live,
            load_profile: load,
            lifecycle: LifecyclePolicy::new(stage, approval),
            destructive,
            kill: kill.clone(),
            abort: Arc::clone(&abort),
            budget: Arc::clone(&budget),
            resolver: Arc::clone(&resolver) as Arc<dyn Resolver>,
            runner,
            expected_revision: REVISION.to_owned(),
            revision: Arc::new(crate::inspect::FixedRevision::new(REVISION)),
            run_invalid: Arc::clone(&invalid),
            run_id: "run-test".to_owned(),
            check_id: "AC-00".to_owned(),
            request_ttl: std::time::Duration::from_millis(500),
        },
    )
    .expect("connector");
    Built {
        connector,
        kill,
        abort,
        resolver,
        invalid,
    }
}

fn build(load: LoadProfile, stage: LifecycleStage, destructive: bool) -> Built {
    build_with(
        load,
        stage,
        None,
        destructive,
        bannable(),
        rate_budget(load),
        Arc::new(allowlisted_resolver()),
    )
}

#[tokio::test]
async fn a1_a_non_allowlisted_target_aborts_before_the_sender_is_called() {
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    let mut sender = RecordingSender::default();
    for target in [
        OUTSIDE,
        "evil.invalid",
        "hddtest.example.com.evil.invalid",
        "127.0.0.1",
        "203.0.113.9",
    ] {
        built.invalid.reset();
        let attempt = attempt(target, PayloadClass::A, Method::Get);
        let outcome = built
            .connector
            .dispatch(&attempt, Some(&ticket(&attempt)), &mut sender)
            .await;
        assert!(
            matches!(outcome, Err(Denial::Target(TargetDenied::NotInSet(_)))),
            "{target}: {outcome:?}"
        );
    }
    assert!(
        sender.sent.is_empty(),
        "nothing may reach the sender for a refused target; sent {:?}",
        sender.sent
    );
}

#[tokio::test]
async fn a1_the_allowlisted_targets_reach_the_sender_exactly_once() {
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    let mut sender = RecordingSender::default();
    let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    let sent = built
        .connector
        .dispatch(&a, Some(&ticket(&a)), &mut sender)
        .await
        .expect("allowlisted");
    assert_eq!(sent.target, TEST_HOST);
    assert_eq!(sender.sent.len(), 1);
    let b = attempt(SANDBOX_HOST, PayloadClass::B, Method::Other);
    let sent = built
        .connector
        .dispatch(&b, Some(&ticket(&b)), &mut sender)
        .await
        .expect("sandbox");
    assert_eq!(sent.target, SANDBOX_HOST);
    assert_eq!(sender.sent.len(), 2);
}

#[tokio::test]
async fn a1_one_prepared_request_covers_exactly_one_send_and_one_token() {
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    let mut sender = CountingSender::default();
    for index in 0..20 {
        let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
        built
            .connector
            .dispatch(&a, Some(&ticket(&a)), &mut sender)
            .await
            .unwrap_or_else(|denial| panic!("request {index}: {denial}"));
    }
    assert_eq!(sender.calls, 20);
    // the 21st send needs a 21st token; the send seam cannot reuse the already-sent request
    let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    let outcome = built
        .connector
        .dispatch(&a, Some(&ticket(&a)), &mut sender)
        .await;
    assert!(
        matches!(
            outcome,
            Err(Denial::Limit(LimitDenial::RateExceeded { .. }))
        ),
        "{outcome:?}"
    );
    assert_eq!(
        sender.calls, 20,
        "the refused send did not reach the sender"
    );
}

#[tokio::test]
async fn a2_twenty_tokens_spent_through_the_check_context_make_the_next_prepare_refuse() {
    // The connector must use the *run's* shared limiter, not a private one: spend the shared second through
    // CheckContext::acquire and the very next Connector::prepare in the same second must refuse (review item A-2).
    let clock = manual_clock();
    // The check-level limiter is generous (burst); the run-shared functional limiter is the binding ceiling, so a connector
    // with a private limiter would allow the request while the shared one must refuse it (review item A-2).
    let budget = budget_over(
        Limiter::new(LoadProfile::Functional, clock.clone()),
        LoadProfile::Burst,
        &clock,
    );
    let ctx = CheckContext::new(
        TargetMode::Live,
        LifecycleStage::Pilot,
        LoadProfile::Functional,
        false,
        LifecyclePolicy::new(LifecycleStage::Pilot, None),
        Arc::new(profile()),
        Arc::clone(&budget),
        Arc::new(Mutex::new(CleanupStack::new())),
        Arc::new(AbortLatch::new()),
        kill_switch(&temp_dir("guard-shared")),
        Arc::new(allowlisted_resolver()),
        bannable(),
        Arc::new(crate::inspect::FixedRevision::new(REVISION)),
        Arc::new(crate::runner::RunInvalidLatch::new()),
        "run-test",
        "AC-00",
        Arc::new(Mutex::new(crate::inspect::InspectGate::new(
            Box::new(crate::runner::NoInspectClient)
                as Box<dyn crate::inspect::InspectClient + Send>,
            REVISION,
        ))),
        None,
    );
    for _ in 0..20 {
        assert!(ctx.acquire(Lane::Http, 1).is_ok());
    }
    let mut built = build_with(
        LoadProfile::Functional,
        LifecycleStage::Pilot,
        None,
        false,
        bannable(),
        budget,
        Arc::new(allowlisted_resolver()),
    );
    let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    let mut sender = CountingSender::default();
    // Review item R-7: the budget token is spent at send, not at prepare, so prepare succeeds and the send is refused.
    let planned = built
        .connector
        .prepare(&a, Some(&ticket(&a)))
        .await
        .expect("prepare does not spend the budget");
    let outcome = built.connector.send(planned, &mut sender);
    assert!(
        matches!(
            outcome,
            Err(Denial::Limit(LimitDenial::RateExceeded { .. }))
        ),
        "a connector with its own limiter would have allowed this: {outcome:?}"
    );
    assert_eq!(sender.calls, 0);
}

#[tokio::test]
async fn a4_hostile_paths_are_refused_before_a_request_exists() {
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    let mut sender = CountingSender::default();
    for (path, expected) in [
        ("@203.0.113.9:80/x", PathError::MissingLeadingSlash),
        ("/x\r\nHost: evil", PathError::ControlCharacter),
        ("/x\nY", PathError::ControlCharacter),
        ("x/y", PathError::MissingLeadingSlash),
        ("/ x", PathError::Whitespace),
        ("//host/x", PathError::NetworkPath),
        ("/x\\y", PathError::Backslash),
        ("", PathError::Empty),
    ] {
        let mut a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
        a.path = path.to_owned();
        let outcome = built
            .connector
            .dispatch(&a, Some(&ticket(&a)), &mut sender)
            .await;
        assert_eq!(
            outcome,
            Err(Denial::InvalidPath {
                path: path.to_owned(),
                reason: expected
            }),
            "{path:?}"
        );
    }
    assert_eq!(sender.calls, 0);
    assert_eq!(
        built.resolver.call_count(),
        0,
        "no resolution before the path is valid"
    );
}

#[tokio::test]
async fn a4_the_planned_request_carries_the_resolved_addresses_and_never_follows_redirects() {
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    let planned = built
        .connector
        .prepare(&a, Some(&ticket(&a)))
        .await
        .expect("planned");
    assert_eq!(
        planned.resolved_addresses(),
        &crate::test_support::platform_addresses()[..]
    );
    assert!(!planned.follow_redirects(), "redirects are never followed");
    assert_eq!(planned.config_revision(), REVISION);
    assert_eq!(built.resolver.call_count(), 1);
}

#[tokio::test]
async fn a4_a_rebinding_name_is_refused_on_the_second_hop() {
    // first answer allowlisted, second answer external (DNS rebinding); every prepare resolves again.
    let resolver = Arc::new(ScriptedResolver::new(&[(
        TEST_HOST,
        vec![vec!["198.51.100.20"], vec!["203.0.113.9"]],
    )]));
    let mut built = build_with(
        LoadProfile::Functional,
        LifecycleStage::Pilot,
        None,
        false,
        bannable(),
        rate_budget(LoadProfile::Functional),
        Arc::clone(&resolver),
    );
    let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    built
        .connector
        .prepare(&a, Some(&ticket(&a)))
        .await
        .expect("first hop is allowlisted");
    let outcome = built.connector.prepare(&a, Some(&ticket(&a))).await;
    assert!(
        matches!(
            outcome,
            Err(Denial::Target(TargetDenied::AddressOutside { .. }))
        ),
        "{outcome:?}"
    );
    assert_eq!(resolver.call_count(), 2);
}

#[tokio::test]
async fn a4_a_cname_outside_the_set_is_refused() {
    let resolver = Arc::new(
        ScriptedResolver::new(&[(SANDBOX_HOST, vec![vec!["198.51.100.20"]])]).with_cname(
            SANDBOX_HOST,
            "tenant.third-party.example",
            vec!["198.51.100.20"],
        ),
    );
    let mut built = build_with(
        LoadProfile::Functional,
        LifecycleStage::Pilot,
        None,
        false,
        bannable(),
        rate_budget(LoadProfile::Functional),
        resolver,
    );
    let a = attempt(SANDBOX_HOST, PayloadClass::B, Method::Get);
    let outcome = built.connector.prepare(&a, Some(&ticket(&a))).await;
    assert!(
        matches!(
            outcome,
            Err(Denial::Target(TargetDenied::CnameOutside { .. }))
        ),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a5_an_attack_shaped_request_without_an_inspect_ticket_is_refused() {
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    let mut sender = CountingSender::default();
    for (target, class) in [
        (TEST_HOST, PayloadClass::A),
        (SANDBOX_HOST, PayloadClass::B),
    ] {
        built.invalid.reset();
        let a = attempt(target, class, Method::Get);
        let outcome = built.connector.dispatch(&a, None, &mut sender).await;
        assert!(
            matches!(outcome, Err(Denial::InspectRequired { .. })),
            "{class}: {outcome:?}"
        );
    }
    assert_eq!(sender.calls, 0);
}

#[tokio::test]
async fn a5_a_ticket_for_another_path_method_or_site_is_refused() {
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    let mut sender = CountingSender::default();
    for (site, method, path) in [
        (TEST_HOST, Method::Get, "/other"),
        (TEST_HOST, Method::Head, "/?probe=1"),
        (OUTSIDE, Method::Get, "/?probe=1"),
    ] {
        let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
        let ticket = InspectTicket::for_test(
            InspectRequest::for_attempt(
                site.to_owned(),
                path.to_owned(),
                method,
                method.as_str().to_owned(),
                PayloadClass::A,
                &a.headers,
                &a.body,
            ),
            REVISION,
            SiteMode::Block,
            false,
        );
        let outcome = built
            .connector
            .dispatch(&a, Some(&ticket), &mut sender)
            .await;
        assert!(
            matches!(outcome, Err(Denial::InspectMismatch { .. })),
            "{site} {method:?} {path}: {outcome:?}"
        );
    }
    assert_eq!(sender.calls, 0);
}

#[tokio::test]
async fn a5_a_stale_ticket_and_a_non_enforcing_site_are_refused() {
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    let mut sender = CountingSender::default();
    let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    let stale = InspectTicket::for_test(inspect_request_for(&a), "rev-0", SiteMode::Block, false);
    assert!(matches!(
        built
            .connector
            .dispatch(&a, Some(&stale), &mut sender)
            .await,
        Err(Denial::InspectStaleRevision { .. })
    ));
    for (mode, safe_mode) in [(SiteMode::Monitor, false), (SiteMode::Block, true)] {
        let ticket = InspectTicket::for_test(inspect_request_for(&a), REVISION, mode, safe_mode);
        assert!(matches!(
            built
                .connector
                .dispatch(&a, Some(&ticket), &mut sender)
                .await,
            Err(Denial::InspectNotEnforcing { .. })
        ));
    }
    assert_eq!(sender.calls, 0);
}

#[tokio::test]
async fn a11_an_unknown_runner_address_refuses_attack_shaped_sends() {
    let mut built = build_with(
        LoadProfile::Functional,
        LifecycleStage::Pilot,
        None,
        false,
        Bannable::Unverified {
            reason: crate::status::ReasonCode::StageNotReached,
        },
        rate_budget(LoadProfile::Functional),
        Arc::new(allowlisted_resolver()),
    );
    let mut sender = CountingSender::default();
    let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    assert!(matches!(
        built
            .connector
            .dispatch(&a, Some(&ticket(&a)), &mut sender)
            .await,
        Err(Denial::RunnerNotBannable { .. })
    ));
    assert_eq!(sender.calls, 0);
}

#[tokio::test]
async fn the_payload_class_rules_are_enforced_before_the_sender() {
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    let mut sender = CountingSender::default();
    let c = attempt(TEST_HOST, PayloadClass::C, Method::Get);
    assert!(matches!(
        built
            .connector
            .dispatch(&c, Some(&ticket(&c)), &mut sender)
            .await,
        Err(Denial::ClassCNeverSent { .. })
    ));
    built.invalid.reset();
    let b = attempt(TEST_HOST, PayloadClass::B, Method::Get);
    assert!(matches!(
        built
            .connector
            .dispatch(&b, Some(&ticket(&b)), &mut sender)
            .await,
        Err(Denial::ClassBNotSandbox { .. })
    ));
    built.invalid.reset();
    let a_body = attempt(TEST_HOST, PayloadClass::A, Method::Other);
    assert!(matches!(
        built
            .connector
            .dispatch(&a_body, Some(&ticket(&a_body)), &mut sender)
            .await,
        Err(Denial::ClassAWithBody { .. })
    ));
    assert_eq!(sender.calls, 0);
    built.invalid.reset();
    let b_sandbox = attempt(SANDBOX_HOST, PayloadClass::B, Method::Other);
    assert!(
        built
            .connector
            .dispatch(&b_sandbox, Some(&ticket(&b_sandbox)), &mut sender)
            .await
            .is_ok()
    );
    assert_eq!(sender.calls, 1);
}

#[tokio::test]
async fn load_and_protocol_abuse_may_only_target_the_sandbox() {
    for load in [LoadProfile::Load, LoadProfile::ProtocolAbuse] {
        let mut built = build(load, LifecycleStage::Pilot, false);
        let mut sender = CountingSender::default();
        let t = attempt(TEST_HOST, PayloadClass::A, Method::Get);
        assert!(matches!(
            built.connector.dispatch(&t, Some(&ticket(&t)), &mut sender).await,
            Err(Denial::ProfileOnlySandbox { profile, .. }) if profile == load
        ));
        assert_eq!(sender.calls, 0);
        built.invalid.reset();
        let s = attempt(SANDBOX_HOST, PayloadClass::B, Method::Get);
        assert!(
            built
                .connector
                .dispatch(&s, Some(&ticket(&s)), &mut sender)
                .await
                .is_ok()
        );
        assert_eq!(sender.calls, 1);
    }
}

#[tokio::test]
async fn production_refuses_a_destructive_check_from_the_spec_flag() {
    let mut built = build(LoadProfile::Functional, LifecycleStage::Production, true);
    let mut sender = CountingSender::default();
    let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    let outcome = built
        .connector
        .dispatch(&a, Some(&ticket(&a)), &mut sender)
        .await;
    assert!(
        matches!(
            outcome,
            Err(Denial::Stage(StageRefusal::ProductionRequiresApproval))
        ),
        "{outcome:?}"
    );
    assert_eq!(sender.calls, 0);

    let approval = crate::config::RunApproval::new("run-test", "02:00-03:00 UTC")
        .expect("an approval of this run");
    let mut approved = build_with(
        LoadProfile::Functional,
        LifecycleStage::Production,
        Some(approval),
        true,
        bannable(),
        rate_budget(LoadProfile::Functional),
        Arc::new(allowlisted_resolver()),
    );
    let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    assert!(
        approved
            .connector
            .dispatch(&a, Some(&ticket(&a)), &mut sender)
            .await
            .is_ok(),
        "with this run's approval the destructive check may send"
    );
}

#[tokio::test]
async fn pilot_allows_destructive_checks_with_a_warning() {
    let pilot = LifecyclePolicy::new(LifecycleStage::Pilot, None);
    assert!(pilot.allows_destructive_for("run-test").is_ok());
    assert!(pilot.warning().is_some());
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, true);
    let mut sender = CountingSender::default();
    let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    assert!(
        built
            .connector
            .dispatch(&a, Some(&ticket(&a)), &mut sender)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn the_kill_switch_and_the_abort_latch_stop_a_request_before_it_is_sent() {
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    let mut sender = CountingSender::default();
    let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    std::fs::write(built.kill.path(), b"stop").expect("trip the switch");
    assert_eq!(
        built
            .connector
            .dispatch(&a, Some(&ticket(&a)), &mut sender)
            .await,
        Err(Denial::KillSwitch)
    );
    std::fs::remove_file(built.kill.path()).expect("remove the switch");
    built.abort.trip(crate::runner::AbortCause::KillSwitch);
    assert!(matches!(
        built
            .connector
            .dispatch(&a, Some(&ticket(&a)), &mut sender)
            .await,
        Err(Denial::Aborted(_))
    ));
    assert_eq!(sender.calls, 0);
}

#[tokio::test]
async fn the_target_guard_is_derived_from_the_profile_only() {
    let mut p = profile();
    p.test_hostname = "only-this.example.com".into();
    p.sandbox_hostname = "only-sandbox.example.com".into();
    let dir = temp_dir("guard-derived");
    let kill = kill_switch(&dir);
    let mut connector = Connector::new(
        &p,
        ConnectorParts {
            mode: TargetMode::Live,
            load_profile: LoadProfile::Functional,
            lifecycle: LifecyclePolicy::new(LifecycleStage::Pilot, None),
            destructive: false,
            kill,
            abort: Arc::new(AbortLatch::new()),
            budget: rate_budget(LoadProfile::Functional),
            resolver: Arc::new(ScriptedResolver::new(&[(
                "only-this.example.com",
                vec![vec!["198.51.100.20"]],
            )])),
            runner: bannable(),
            expected_revision: REVISION.to_owned(),
            revision: Arc::new(crate::inspect::FixedRevision::new(REVISION)),
            run_invalid: Arc::new(crate::runner::RunInvalidLatch::new()),
            run_id: "run-test".to_owned(),
            check_id: "AC-00".to_owned(),
            request_ttl: std::time::Duration::from_millis(500),
        },
    )
    .expect("connector");
    let mut sender = CountingSender::default();
    let old = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    assert!(
        connector
            .dispatch(&old, Some(&ticket(&old)), &mut sender)
            .await
            .is_err(),
        "the old example hostname is no longer in the profile"
    );
    connector.reset_invalid();
    let new = attempt("only-this.example.com", PayloadClass::A, Method::Get);
    assert!(
        connector
            .dispatch(&new, Some(&ticket(&new)), &mut sender)
            .await
            .is_ok()
    );
    assert_eq!(sender.calls, 1);
}

#[tokio::test]
async fn lab_mode_refuses_live_names() {
    let mut p = profile();
    p.lab.enabled = true;
    p.lab.cidr = "10.99.0.0/24".into();
    p.lab.host = "vulnlab.lab.internal".into();
    let dir = temp_dir("guard-lab");
    let kill = kill_switch(&dir);
    let resolver: Arc<dyn Resolver> = Arc::new(ScriptedResolver::new(&[(
        "vulnlab.lab.internal",
        vec![vec!["10.99.0.5"]],
    )]));
    let mut connector = Connector::new(
        &p,
        ConnectorParts {
            mode: TargetMode::Lab,
            load_profile: LoadProfile::Lab,
            lifecycle: LifecyclePolicy::new(LifecycleStage::Pilot, None),
            destructive: false,
            kill,
            abort: Arc::new(AbortLatch::new()),
            budget: rate_budget(LoadProfile::Lab),
            resolver,
            runner: bannable(),
            expected_revision: REVISION.to_owned(),
            revision: Arc::new(crate::inspect::FixedRevision::new(REVISION)),
            run_invalid: Arc::new(crate::runner::RunInvalidLatch::new()),
            run_id: "run-test".to_owned(),
            check_id: "AC-00".to_owned(),
            request_ttl: std::time::Duration::from_millis(500),
        },
    )
    .expect("lab connector");
    let mut sender = CountingSender::default();
    let live = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    assert!(matches!(
        connector
            .dispatch(&live, Some(&ticket(&live)), &mut sender)
            .await,
        Err(Denial::Target(_))
    ));
    connector.reset_invalid();
    let lab = attempt("vulnlab.lab.internal", PayloadClass::A, Method::Get);
    assert!(
        connector
            .dispatch(&lab, Some(&ticket(&lab)), &mut sender)
            .await
            .is_ok()
    );
    assert_eq!(sender.calls, 1);
}

#[test]
fn an_empty_profile_yields_no_connector() {
    let dir = temp_dir("guard-empty");
    let empty = hdd_common::profile::Profile::default();
    let result = Connector::new(
        &empty,
        ConnectorParts {
            mode: TargetMode::Live,
            load_profile: LoadProfile::Functional,
            lifecycle: LifecyclePolicy::new(LifecycleStage::Pilot, None),
            destructive: false,
            kill: kill_switch(&dir),
            abort: Arc::new(AbortLatch::new()),
            budget: rate_budget(LoadProfile::Functional),
            resolver: Arc::new(allowlisted_resolver()),
            runner: bannable(),
            expected_revision: REVISION.to_owned(),
            revision: Arc::new(crate::inspect::FixedRevision::new(REVISION)),
            run_invalid: Arc::new(crate::runner::RunInvalidLatch::new()),
            run_id: "run-test".to_owned(),
            check_id: "AC-00".to_owned(),
            request_ttl: std::time::Duration::from_millis(500),
        },
    );
    assert!(matches!(
        result,
        Err(ConnectorError::Target(TargetDenied::EmptySet))
    ));
}

#[test]
fn a_connector_without_a_config_revision_is_refused() {
    let profile = profile();
    let result = Connector::new(
        &profile,
        ConnectorParts {
            mode: TargetMode::Live,
            load_profile: LoadProfile::Functional,
            lifecycle: LifecyclePolicy::new(LifecycleStage::Pilot, None),
            destructive: false,
            kill: kill_switch(&temp_dir("guard-rev")),
            abort: Arc::new(AbortLatch::new()),
            budget: rate_budget(LoadProfile::Functional),
            resolver: Arc::new(allowlisted_resolver()),
            runner: bannable(),
            expected_revision: String::new(),
            revision: Arc::new(crate::inspect::FixedRevision::new(REVISION)),
            run_invalid: Arc::new(crate::runner::RunInvalidLatch::new()),
            run_id: "run-test".to_owned(),
            check_id: "AC-00".to_owned(),
            request_ttl: std::time::Duration::from_millis(500),
        },
    );
    assert_eq!(result.err(), Some(ConnectorError::MissingConfigRevision));
}

#[test]
fn the_egress_gate_denies_by_default_and_allows_listed_infrastructure_destinations() {
    let p = profile();
    let gate = EgressGate::from_profile(&p).expect("the example allowlist parses");
    assert!(
        gate.check(
            Scheme::Https,
            "admin.example.com",
            443,
            "/api/v1/waf/inspect"
        )
        .is_err(),
        "an empty egress_allowlist denies everything"
    );
    let allow =
        Allowlist::parse(&["https://admin.example.com", "dns://1.1.1.1"]).expect("allowlist");
    let gate = EgressGate::new(allow);
    assert!(
        gate.check(Scheme::Https, "admin.example.com", 443, "/api/v1/health")
            .is_ok()
    );
    assert!(
        gate.check(Scheme::Http, "admin.example.com", 80, "/")
            .is_err(),
        "the scheme is part of the entry"
    );
    assert!(
        gate.check(Scheme::Https, "other.example.com", 443, "/")
            .is_err()
    );
    assert!(
        gate.check(Scheme::Dns, "1.1.1.1", 53, "/").is_ok(),
        "the resolver entry permits the dns class"
    );
}

#[tokio::test]
async fn a_normalised_target_reaches_the_sender_in_lower_case_without_a_trailing_dot() {
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    let mut sender = RecordingSender::default();
    let a = Attempt {
        target: "HDDTEST.example.com.".to_owned(),
        path: "/".to_owned(),
        class: PayloadClass::A,
        method: Method::Head,
        verb: Method::Head.as_str().to_owned(),
        body: Vec::new(),
        headers: Vec::new(),
    };
    let ticket = InspectTicket::for_test(
        InspectRequest::for_attempt(
            TEST_HOST,
            "/",
            Method::Head,
            "HEAD",
            PayloadClass::A,
            &[],
            b"",
        ),
        REVISION,
        SiteMode::Block,
        false,
    );
    built
        .connector
        .dispatch(&a, Some(&ticket), &mut sender)
        .await
        .expect("normalised target");
    assert_eq!(sender.sent, vec![(TEST_HOST.to_owned(), "/".to_owned())]);
}

/// A connector built for the extra review-item tests, with a controllable revision source and request TTL.
fn connector_with(
    load: LoadProfile,
    mode: TargetMode,
    revision: Arc<dyn RevisionSource>,
    request_ttl: Duration,
) -> Result<Connector, ConnectorError> {
    let mut p = profile();
    let resolver: Arc<dyn Resolver> = if mode == TargetMode::Lab {
        p.lab.enabled = true;
        p.lab.host = "vulnlab.lab.internal".to_owned();
        p.lab.cidr = "10.99.0.0/24".to_owned();
        Arc::new(ScriptedResolver::new(&[(
            "vulnlab.lab.internal",
            vec![vec!["10.99.0.5"]],
        )]))
    } else {
        Arc::new(allowlisted_resolver())
    };
    Connector::new(
        &p,
        ConnectorParts {
            mode,
            load_profile: load,
            lifecycle: LifecyclePolicy::new(LifecycleStage::Pilot, None),
            destructive: false,
            kill: kill_switch(&temp_dir("guard-extra")),
            abort: Arc::new(AbortLatch::new()),
            budget: rate_budget(load),
            resolver,
            runner: bannable(),
            expected_revision: REVISION.to_owned(),
            revision,
            run_invalid: Arc::new(crate::runner::RunInvalidLatch::new()),
            run_id: "run-test".to_owned(),
            check_id: "AC-00".to_owned(),
            request_ttl,
        },
    )
}

/// A revision source that fails to read the current revision (the fail-closed path of R-5).
struct FailingRevision;

impl RevisionSource for FailingRevision {
    fn current_revision(&self) -> Result<String, String> {
        Err("control plane unreachable".to_owned())
    }
}

/// A sender that records the pinned addresses it was told to connect to (R-7: no re-resolution).
#[derive(Default)]
struct PinRecordingSender {
    pinned: Vec<Vec<IpAddr>>,
}

impl Sender for PinRecordingSender {
    fn send(&mut self, request: PlannedRequest, pinned: &[IpAddr]) -> Sent {
        self.pinned.push(pinned.to_vec());
        Sent {
            target: request.target().to_owned(),
            path: request.path().to_owned(),
        }
    }
}

/// Review item R-1: the connector itself enforces the 5 x 2 profile/mode matrix, so a caller cannot bypass
/// `RunnerConfig::build`.
#[tokio::test]
async fn r1_the_connector_enforces_the_profile_mode_matrix() {
    for load in LoadProfile::ALL {
        for mode in [TargetMode::Live, TargetMode::Lab] {
            let result = connector_with(
                load,
                mode,
                Arc::new(FixedRevision::new(REVISION)),
                Duration::from_millis(500),
            );
            if load.allows_mode(mode) {
                assert!(
                    result.is_ok(),
                    "{load} in {mode:?} must be accepted: {result:?}"
                );
            } else {
                match result {
                    Err(ConnectorError::ProfileModeMismatch {
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
}

/// Review item R-5: a ticket authorises exactly one send.
#[tokio::test]
async fn r5_a_reused_inspect_ticket_is_refused() {
    let mut connector = connector_with(
        LoadProfile::Functional,
        TargetMode::Live,
        Arc::new(FixedRevision::new(REVISION)),
        Duration::from_millis(500),
    )
    .expect("connector");
    let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    let ticket = ticket(&a);
    assert!(connector.prepare(&a, Some(&ticket)).await.is_ok());
    assert_eq!(
        connector.prepare(&a, Some(&ticket)).await,
        Err(Denial::InspectTicket(TicketError::Reused))
    );
}

/// Review item R-5: a ticket has a short TTL and an expired ticket is refused.
#[tokio::test]
async fn r5_an_expired_inspect_ticket_is_refused() {
    let mut connector = connector_with(
        LoadProfile::Functional,
        TargetMode::Live,
        Arc::new(FixedRevision::new(REVISION)),
        Duration::from_millis(500),
    )
    .expect("connector");
    let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    let expired = InspectTicket::for_test_at(
        inspect_request_for(&a),
        REVISION,
        SiteMode::Block,
        false,
        Instant::now() - Duration::from_secs(120),
        Duration::from_secs(30),
    );
    assert_eq!(
        connector.prepare(&a, Some(&expired)).await,
        Err(Denial::InspectTicket(TicketError::Expired {
            ttl: Duration::from_secs(30)
        }))
    );
}

/// Review item R-5: the ticket digest binds the actual verb, not only `GET`/`HEAD`/`OTHER`.
#[tokio::test]
async fn r5_the_ticket_binds_the_actual_verb_not_only_method_other() {
    let mut connector = connector_with(
        LoadProfile::Functional,
        TargetMode::Live,
        Arc::new(FixedRevision::new(REVISION)),
        Duration::from_millis(500),
    )
    .expect("connector");
    // A body-bearing class A shape must target the sandbox (section 2.2), so that is where the verb binding is exercised.
    let a = Attempt::new(SANDBOX_HOST, "/", PayloadClass::A, Method::Other).with_verb("POST");
    // A ticket for a different verb but the same `Method::Other` shape and every other aspect.
    let mut ticket_request = inspect_request_for(&a);
    ticket_request.verb = "PUT".to_owned();
    let ticket = InspectTicket::for_test(ticket_request, REVISION, SiteMode::Block, false);
    assert_eq!(
        connector.prepare(&a, Some(&ticket)).await,
        Err(Denial::InspectTicket(TicketError::DigestMismatch))
    );
}

/// Review item R-5: the config revision is re-read at send time, not trusted from construction.
#[tokio::test]
async fn r5_a_revision_change_between_prepare_and_send_is_refused() {
    let revision = Arc::new(FixedRevision::new(REVISION));
    let mut connector = connector_with(
        LoadProfile::Functional,
        TargetMode::Live,
        Arc::clone(&revision) as Arc<dyn RevisionSource>,
        Duration::from_millis(500),
    )
    .expect("connector");
    let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    let planned = connector
        .prepare(&a, Some(&ticket(&a)))
        .await
        .expect("planned");
    revision.set("rev-2");
    let mut sender = CountingSender::default();
    assert_eq!(
        connector.send(planned, &mut sender),
        Err(Denial::RevisionChangedAtSend {
            expected: REVISION.to_owned(),
            observed: "rev-2".to_owned()
        })
    );
    assert_eq!(sender.calls, 0);
}

/// Review item R-5: an unreadable revision fails closed at send.
#[tokio::test]
async fn r5_an_unreadable_revision_at_send_fails_closed() {
    let mut connector = connector_with(
        LoadProfile::Functional,
        TargetMode::Live,
        Arc::new(FailingRevision),
        Duration::from_millis(500),
    )
    .expect("connector");
    let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    let planned = connector
        .prepare(&a, Some(&ticket(&a)))
        .await
        .expect("planned");
    let mut sender = CountingSender::default();
    assert!(matches!(
        connector.send(planned, &mut sender),
        Err(Denial::RevisionUnavailable { .. })
    ));
    assert_eq!(sender.calls, 0);
}

/// Review item R-7: a prepared request that outlived its short window is refused at send.
#[tokio::test]
async fn r7_a_stale_prepared_request_is_refused_at_send() {
    let mut connector = connector_with(
        LoadProfile::Functional,
        TargetMode::Live,
        Arc::new(FixedRevision::new(REVISION)),
        Duration::from_millis(1),
    )
    .expect("connector");
    let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    let planned = connector
        .prepare(&a, Some(&ticket(&a)))
        .await
        .expect("planned");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut sender = CountingSender::default();
    assert!(matches!(
        connector.send(planned, &mut sender),
        Err(Denial::RequestExpired { .. })
    ));
    assert_eq!(sender.calls, 0);
}

/// Review item R-7: the sender receives the pinned addresses and no name to re-resolve.
#[tokio::test]
async fn r7_the_sender_receives_the_pinned_addresses() {
    let mut connector = connector_with(
        LoadProfile::Functional,
        TargetMode::Live,
        Arc::new(FixedRevision::new(REVISION)),
        Duration::from_millis(500),
    )
    .expect("connector");
    let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    let planned = connector
        .prepare(&a, Some(&ticket(&a)))
        .await
        .expect("planned");
    let mut sender = PinRecordingSender::default();
    connector.send(planned, &mut sender).expect("send");
    assert_eq!(
        sender.pinned,
        vec![crate::test_support::platform_addresses()],
        "the sender must connect only to the addresses that passed the guard"
    );
}

/// Review item R-13: a class B payload implies destructive, even when the check's spec flag is false.
#[tokio::test]
async fn r13_a_class_b_send_implies_destructive() {
    let mut production = build(LoadProfile::Functional, LifecycleStage::Production, false);
    let mut sender = CountingSender::default();
    let b = attempt(SANDBOX_HOST, PayloadClass::B, Method::Get);
    let outcome = production
        .connector
        .dispatch(&b, Some(&ticket(&b)), &mut sender)
        .await;
    assert!(
        matches!(
            outcome,
            Err(Denial::Stage(StageRefusal::ProductionRequiresApproval))
        ),
        "a class B payload must not slip past the destructive gate: {outcome:?}"
    );
    assert_eq!(sender.calls, 0);

    // In pilot the same class B send is allowed.
    let mut pilot = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    assert!(
        pilot
            .connector
            .dispatch(&b, Some(&ticket(&b)), &mut sender)
            .await
            .is_ok()
    );
}

/// The (verb, path, body, headers) content a sender observed.
type SeenRequest = (String, String, Vec<u8>, Vec<(String, String)>);

/// A sender that records the exact content of the request it was handed (review item S-3).
#[derive(Default)]
struct ContentSender {
    seen: Vec<SeenRequest>,
}

impl Sender for ContentSender {
    fn send(&mut self, request: PlannedRequest, _pinned: &[IpAddr]) -> Sent {
        self.seen.push((
            request.verb().to_owned(),
            request.path().to_owned(),
            request.body().to_vec(),
            request.headers().to_vec(),
        ));
        Sent {
            target: request.target().to_owned(),
            path: request.path().to_owned(),
        }
    }
}

/// Review item S-3: the sender is handed exactly the verb, body and headers the inspect ticket bound.
#[tokio::test]
async fn s3_the_sender_gets_exactly_the_ticketed_verb_body_and_headers() {
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    let body = b"<script>alert(1)</script>".to_vec();
    let headers = vec![
        ("content-type".to_owned(), "text/html".to_owned()),
        ("x-probe".to_owned(), "1".to_owned()),
    ];
    let attempt = Attempt::new(SANDBOX_HOST, "/x", PayloadClass::B, Method::Other)
        .with_verb("POST")
        .with_body(body.clone())
        .with_headers(headers.clone());
    let mut sender = ContentSender::default();
    built
        .connector
        .dispatch(&attempt, Some(&ticket(&attempt)), &mut sender)
        .await
        .expect("the class B request is allowed to the sandbox");
    assert_eq!(
        sender.seen,
        vec![("POST".to_owned(), "/x".to_owned(), body, headers)],
        "what is sent must be what was ticketed"
    );
}

/// Review item S-3: `GET`/`HEAD` must have an empty body and the matching verb.
#[tokio::test]
async fn s3_get_and_head_with_a_body_or_a_mismatched_verb_are_refused() {
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    let sender = CountingSender::default();
    let get_with_body =
        Attempt::new(TEST_HOST, "/", PayloadClass::A, Method::Get).with_body(b"payload".to_vec());
    assert_eq!(
        built
            .connector
            .prepare(&get_with_body, Some(&ticket(&get_with_body)))
            .await,
        Err(Denial::RequestPart(RequestPartError::ReadOnlyWithBody {
            method: Method::Get
        }))
    );
    let head_with_verb =
        Attempt::new(TEST_HOST, "/", PayloadClass::A, Method::Head).with_verb("POST");
    assert_eq!(
        built
            .connector
            .prepare(&head_with_verb, Some(&ticket(&head_with_verb)))
            .await,
        Err(Denial::RequestPart(RequestPartError::VerbMismatch {
            method: Method::Head,
            verb: "POST".to_owned()
        }))
    );
    let get_with_verb =
        Attempt::new(TEST_HOST, "/", PayloadClass::A, Method::Get).with_verb("POST");
    assert!(matches!(
        built
            .connector
            .prepare(&get_with_verb, Some(&ticket(&get_with_verb)))
            .await,
        Err(Denial::RequestPart(RequestPartError::VerbMismatch { .. }))
    ));
    assert_eq!(sender.calls, 0);
}

/// Review item S-3: header names must be tokens and values must not contain control characters (a CR/LF would split the
/// request in two).
#[tokio::test]
async fn s3_header_injection_is_refused() {
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    let bad_value = Attempt::new(TEST_HOST, "/", PayloadClass::A, Method::Get)
        .with_headers(vec![("x-probe".to_owned(), "1\r\nHost: evil".to_owned())]);
    assert_eq!(
        built
            .connector
            .prepare(&bad_value, Some(&ticket(&bad_value)))
            .await,
        Err(Denial::RequestPart(RequestPartError::InvalidHeaderValue {
            name: "x-probe".to_owned()
        }))
    );
    let bad_name = Attempt::new(TEST_HOST, "/", PayloadClass::A, Method::Get)
        .with_headers(vec![("bad name".to_owned(), "1".to_owned())]);
    assert_eq!(
        built
            .connector
            .prepare(&bad_name, Some(&ticket(&bad_name)))
            .await,
        Err(Denial::RequestPart(RequestPartError::InvalidHeaderName {
            name: "bad name".to_owned()
        }))
    );
}

/// Review item S-3: the header digest is length-prefixed, so two header lists that would collide under `\n`-joining are
/// different.
#[test]
fn s3_the_header_digest_is_unambiguous() {
    let one = Attempt::new(TEST_HOST, "/", PayloadClass::A, Method::Get)
        .with_headers(vec![("a".to_owned(), "b\nc: d".to_owned())]);
    let two = Attempt::new(TEST_HOST, "/", PayloadClass::A, Method::Get).with_headers(vec![
        ("a".to_owned(), "b".to_owned()),
        ("c".to_owned(), "d".to_owned()),
    ]);
    assert_ne!(one.headers_sha256(), two.headers_sha256());
    // The same list hashes the same.
    let one_again = Attempt::new(TEST_HOST, "/", PayloadClass::A, Method::Get)
        .with_headers(vec![("a".to_owned(), "b\nc: d".to_owned())]);
    assert_eq!(one.headers_sha256(), one_again.headers_sha256());
}

/// Review items R-8 and S-8: every safety-envelope denial latches `run_invalid`, so a check that swallows the `Err` cannot
/// leave the run looking clean.
#[tokio::test]
async fn s8_every_safety_envelope_denial_marks_the_run_invalid() {
    // (attempt, expected denial, how to build the connector)
    let class_c = attempt(TEST_HOST, PayloadClass::C, Method::Get);
    let class_b = attempt(TEST_HOST, PayloadClass::B, Method::Get);
    let class_a_body = attempt(TEST_HOST, PayloadClass::A, Method::Other);
    let inspect_required = attempt(TEST_HOST, PayloadClass::A, Method::Get);

    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    assert!(matches!(
        built
            .connector
            .prepare(&class_c, Some(&ticket(&class_c)))
            .await,
        Err(Denial::ClassCNeverSent { .. })
    ));
    assert!(
        built.invalid.is_invalid(),
        "class C must latch the run invalid"
    );
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    assert!(matches!(
        built
            .connector
            .prepare(&class_b, Some(&ticket(&class_b)))
            .await,
        Err(Denial::ClassBNotSandbox { .. })
    ));
    assert!(
        built.invalid.is_invalid(),
        "class B must latch the run invalid"
    );
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    assert!(matches!(
        built
            .connector
            .prepare(&class_a_body, Some(&ticket(&class_a_body)))
            .await,
        Err(Denial::ClassAWithBody { .. })
    ));
    assert!(
        built.invalid.is_invalid(),
        "class A with body must latch the run invalid"
    );
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    assert!(matches!(
        built.connector.prepare(&inspect_required, None).await,
        Err(Denial::InspectRequired { .. })
    ));
    assert!(
        built.invalid.is_invalid(),
        "a missing inspect ticket must latch the run invalid"
    );

    // profile-only-sandbox: `load` may only target the sandbox host.
    let mut built = build(LoadProfile::Load, LifecycleStage::Pilot, false);
    let load_attempt = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    assert!(matches!(
        built
            .connector
            .prepare(&load_attempt, Some(&ticket(&load_attempt)))
            .await,
        Err(Denial::ProfileOnlySandbox { .. })
    ));
    assert!(
        built.invalid.is_invalid(),
        "a profile/target violation must latch the run invalid"
    );

    // an unknown runner address.
    let mut built = build_with(
        LoadProfile::Functional,
        LifecycleStage::Pilot,
        None,
        false,
        Bannable::Unverified {
            reason: crate::status::ReasonCode::CapabilityNotSupplied,
        },
        rate_budget(LoadProfile::Functional),
        Arc::new(allowlisted_resolver()),
    );
    let runner_attempt = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    assert!(matches!(
        built
            .connector
            .prepare(&runner_attempt, Some(&ticket(&runner_attempt)))
            .await,
        Err(Denial::RunnerNotBannable { .. })
    ));
    assert!(
        built.invalid.is_invalid(),
        "an unbannable runner must latch the run invalid"
    );

    // A target denial: the classic case.
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    let outside = attempt(OUTSIDE, PayloadClass::A, Method::Get);
    assert!(matches!(
        built
            .connector
            .prepare(&outside, Some(&ticket(&outside)))
            .await,
        Err(Denial::Target(_))
    ));
    assert!(
        built.invalid.is_invalid(),
        "a target denial must latch the run invalid"
    );
    assert!(
        !built.invalid.audit().is_empty(),
        "every latch records an audit line"
    );
}

/// Review item S-10: the ticket is consumed only at the very end of `prepare`, so a late refusal does not burn it.
#[tokio::test]
async fn s10_a_late_prepare_refusal_does_not_consume_the_ticket() {
    // The first answer resolves outside the allowed addresses (a refusal), the second is allowed.
    let resolver = Arc::new(ScriptedResolver::new(&[(
        TEST_HOST,
        vec![vec!["203.0.113.9"], vec!["198.51.100.20"]],
    )]));
    let mut built = build_with(
        LoadProfile::Functional,
        LifecycleStage::Pilot,
        None,
        false,
        bannable(),
        rate_budget(LoadProfile::Functional),
        Arc::clone(&resolver),
    );
    let a = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    let stale = InspectTicket::for_test(inspect_request_for(&a), "rev-0", SiteMode::Block, false);
    assert!(matches!(
        built.connector.prepare(&a, Some(&stale)).await,
        Err(Denial::InspectStaleRevision { .. })
    ));
    // The same ticket still reports stale (not Reused): the refused prepare did not consume it (review item S-10).
    assert!(
        matches!(
            built.connector.prepare(&a, Some(&stale)).await,
            Err(Denial::InspectStaleRevision { .. })
        ),
        "a late refusal must not burn the single-use ticket (review item S-10)"
    );
}

#[test]
fn no_send_function_exists_in_this_crate() {
    // A1 says the guard is tested before any send function exists. Assert that the crate's sources contain no socket or
    // process construction; the tokens are built with `concat!` so this test does not match itself.
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = manifest.join("src");
    let forbidden = [
        concat!("Tcp", "Stream"),
        concat!("Udp", "Socket"),
        concat!("Tcp", "Listener"),
        concat!("process", "::Command"),
        concat!("std", "::net::Tcp"),
        concat!("hyper", "::"),
        concat!("req", "west"),
    ];
    let mut checked = 0;
    for entry in std::fs::read_dir(&src).expect("read src") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read source");
        checked += 1;
        for token in forbidden {
            assert!(
                !text.contains(token),
                "{} contains `{token}`: the skeleton must have no send function or process execution",
                path.display()
            );
        }
    }
    assert!(
        checked >= 10,
        "the scan really read the crate sources ({checked} files)"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Round-4 review items N-1, N-2 and N-8.
// ---------------------------------------------------------------------------------------------------------------

/// Review item N-1: once the run-invalid latch is set nothing is prepared or sent, and the record names the check/run.
#[tokio::test]
async fn n1_the_run_invalid_latch_stops_prepare_and_send() {
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    let mut sender = CountingSender::default();
    let victim = attempt(OUTSIDE, PayloadClass::A, Method::Get);
    assert!(matches!(
        built
            .connector
            .prepare(&victim, Some(&ticket(&victim)))
            .await,
        Err(Denial::Target(_))
    ));
    let record = built.invalid.first_record().expect("a record");
    assert_eq!(record.check_id, "AC-00");
    assert_eq!(record.run_id, "run-test");
    assert!(
        record.detail.contains("target refused"),
        "{}",
        record.detail
    );
    // Both prepare and send now refuse with the run-invalid denial.
    let allowed = attempt(TEST_HOST, PayloadClass::A, Method::Get);
    assert!(matches!(
        built
            .connector
            .prepare(&allowed, Some(&ticket(&allowed)))
            .await,
        Err(Denial::RunInvalid { .. })
    ));
    let planned = PlannedRequest {
        target: TEST_HOST.to_owned(),
        path: "/".to_owned(),
        class: PayloadClass::A,
        method: Method::Get,
        verb: "GET".to_owned(),
        body: Vec::new(),
        headers: Vec::new(),
        resolved: crate::test_support::platform_addresses(),
        config_revision: REVISION.to_owned(),
        issued_at: Instant::now(),
        ttl: Duration::from_millis(500),
    };
    assert!(matches!(
        built.connector.send(planned, &mut sender),
        Err(Denial::RunInvalid { .. })
    ));
    assert_eq!(sender.calls, 0);
}

/// Review item N-2: the inspect request carries the headers, cookies and body, and a body over 64 KB is refused before
/// any ticket or send.
#[tokio::test]
async fn n2_the_inspect_request_carries_content_and_the_body_cap_is_refused() {
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    let attempt = Attempt::new(SANDBOX_HOST, "/x", PayloadClass::B, Method::Other)
        .with_verb("POST")
        .with_headers(vec![
            ("content-type".to_owned(), "application/json".to_owned()),
            ("cookie".to_owned(), "session=abc; theme=dark".to_owned()),
        ])
        .with_body(b"{\"q\":1}");
    let sender = CountingSender::default();
    let planned = built
        .connector
        .prepare(&attempt, Some(&ticket(&attempt)))
        .await
        .expect("planned");
    assert_eq!(planned.body(), b"{\"q\":1}");
    let request = InspectRequest::for_attempt(
        SANDBOX_HOST,
        "/x",
        Method::Other,
        "POST",
        PayloadClass::B,
        planned.headers(),
        planned.body(),
    );
    assert_eq!(
        request.cookies,
        vec![
            ("session".to_owned(), "abc".to_owned()),
            ("theme".to_owned(), "dark".to_owned()),
        ]
    );
    assert_eq!(request.content_type.as_deref(), Some("application/json"));
    assert!(request.body_within_cap());

    // A non-UTF-8 body is described as base64 (spec T-0260, review item N-2), and the digest still binds the exact bytes.
    let literal_bytes = [0xffu8, 0xfe, 0x00];
    let described = InspectRequest::for_attempt(
        SANDBOX_HOST,
        "/x",
        Method::Other,
        "POST",
        PayloadClass::B,
        &[],
        &literal_bytes,
    );
    assert!(described.body_text.is_none());
    assert_eq!(described.body_base64.as_deref(), Some("//4A"));
    assert_eq!(
        described.body_sha256,
        crate::report::sha256_hex(&literal_bytes)
    );
    let with_other_bytes = InspectRequest::for_attempt(
        SANDBOX_HOST,
        "/x",
        Method::Other,
        "POST",
        PayloadClass::B,
        &[],
        &[0xffu8, 0xfe, 0x01],
    );
    assert_ne!(
        described.digest(),
        with_other_bytes.digest(),
        "the digest must bind the body bytes, not only the path (review item N-2)"
    );

    let mut oversized = attempt;
    oversized.body = vec![b'a'; crate::inspect::MAX_INSPECT_BODY_BYTES + 1];
    assert_eq!(
        built
            .connector
            .prepare(&oversized, Some(&ticket(&oversized)))
            .await,
        Err(Denial::RequestPart(RequestPartError::BodyTooLarge {
            bytes: crate::inspect::MAX_INSPECT_BODY_BYTES + 1,
            max: crate::inspect::MAX_INSPECT_BODY_BYTES
        }))
    );
    assert_eq!(sender.calls, 0);
}

/// Review item N-8: sender-owned headers are denied, and the header count/size/whitespace caps are enforced.
#[tokio::test]
async fn n8_sender_owned_headers_and_header_caps_are_refused() {
    let mut built = build(LoadProfile::Functional, LifecycleStage::Pilot, false);
    for name in [
        "Content-Length",
        "Transfer-Encoding",
        "Host",
        "Expect",
        "Upgrade",
        "Connection",
        "X-HTTP-Method-Override",
    ] {
        let attempt = Attempt::new(TEST_HOST, "/", PayloadClass::A, Method::Get)
            .with_headers(vec![(name.to_owned(), "1".to_owned())]);
        assert_eq!(
            built
                .connector
                .prepare(&attempt, Some(&ticket(&attempt)))
                .await,
            Err(Denial::RequestPart(RequestPartError::DeniedHeader {
                name: name.to_owned()
            })),
            "{name}"
        );
    }
    let many = Attempt::new(TEST_HOST, "/", PayloadClass::A, Method::Get).with_headers(
        (0..65)
            .map(|n| (format!("x-h{n}"), "1".to_owned()))
            .collect(),
    );
    assert!(matches!(
        built.connector.prepare(&many, Some(&ticket(&many))).await,
        Err(Denial::RequestPart(RequestPartError::TooManyHeaders { .. }))
    ));
    let big = Attempt::new(TEST_HOST, "/", PayloadClass::A, Method::Get)
        .with_headers(vec![("x-big".to_owned(), "a".repeat(9000))]);
    assert!(matches!(
        built.connector.prepare(&big, Some(&ticket(&big))).await,
        Err(Denial::RequestPart(
            RequestPartError::HeadersTooLarge { .. }
        ))
    ));
    let padded = Attempt::new(TEST_HOST, "/", PayloadClass::A, Method::Get)
        .with_headers(vec![("x-probe".to_owned(), " value ".to_owned())]);
    assert_eq!(
        built
            .connector
            .prepare(&padded, Some(&ticket(&padded)))
            .await,
        Err(Denial::RequestPart(RequestPartError::HeaderWhitespace {
            name: "x-probe".to_owned()
        }))
    );
}
