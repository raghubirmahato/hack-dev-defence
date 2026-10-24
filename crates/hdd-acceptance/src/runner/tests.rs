//! Runner tests: the `finally` cleanup stack, A3 (kill switch aborts within one second and cleanup runs), A-3 (destructive
//! and profile gates before the body), A-8 (timeout fails one check, dependencies, AC-00, kill-switch status), A-9 (one latched
//! signal listener consulted between checks), panic isolation, dependency ordering and the shared budget inside a check.
//!
//! The literal SIGINT/SIGTERM delivery cannot be exercised honestly on this Windows builder (a test cannot press the real
//! Ctrl-C of its parent console); the same abort/cleanup path is tested through the injected signal source, and the literal
//! integration is `UNVERIFIED(environment_unsupported)` in the evidence and in `docs/ACCEPTANCE.md`.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hdd_common::egress::TargetMode;
use hdd_common::profile::types::LifecycleStage;
use tokio::sync::mpsc;

use super::*;
use crate::limits::{Lane, LoadProfile};
use crate::status::ReasonCode;
use crate::test_support::{kill_switch, limiter, temp_dir};

const NO_DEPS: &[&str] = &[];
const NO_REQUIREMENTS: &[&str] = &[];

/// The evidence fixture a PASS check points at: `proof.txt` in the executor's evidence root, with the hash of `PROOF_BYTES`.
const PROOF_NAME: &str = "proof.txt";
const PROOF_BYTES: &[u8] = b"real evidence";

enum Behaviour {
    PassWithoutEvidence,
    /// A PASS backed by the `proof.txt` fixture in the executor's evidence root (R-4).
    PassWithEvidence,
    /// A PASS whose evidence hash does not match `proof.txt` (a fabricated pass, R-4).
    PassWithFabricatedEvidence,
    Fail,
    SleepFor(Duration),
    CleanupThenSleep,
    CleanupThenFail,
    CleanupThenPanic,
    AcquireUntilDenied,
    SignalThenComplete,
}

struct TestCheck {
    spec: CheckSpec,
    behaviour: Behaviour,
    started: Option<Arc<AtomicBool>>,
    order: Option<Arc<Mutex<Vec<String>>>>,
    execution: Option<Arc<Mutex<Vec<String>>>>,
    acquisitions: Option<Arc<AtomicUsize>>,
    destructive_seen: Option<Arc<AtomicBool>>,
    signal: Option<mpsc::UnboundedSender<ShutdownSignal>>,
}

impl TestCheck {
    fn new(id: &'static str, behaviour: Behaviour) -> TestCheck {
        TestCheck {
            spec: CheckSpec {
                id,
                title: "test check",
                requirements: NO_REQUIREMENTS,
                destructive: false,
                profile: LoadProfile::Functional,
                dependencies: NO_DEPS,
                timeout: Duration::from_secs(30),
                tier: "smoke",
            },
            behaviour,
            started: None,
            order: None,
            execution: None,
            acquisitions: None,
            destructive_seen: None,
            signal: None,
        }
    }

    fn with_profile(mut self, profile: LoadProfile) -> TestCheck {
        self.spec.profile = profile;
        self
    }

    fn destructive(mut self) -> TestCheck {
        self.spec.destructive = true;
        self
    }

    fn with_dependencies(mut self, dependencies: &'static [&'static str]) -> TestCheck {
        self.spec.dependencies = dependencies;
        self
    }

    fn with_timeout(mut self, timeout: Duration) -> TestCheck {
        self.spec.timeout = timeout;
        self
    }

    fn starting(mut self, started: Arc<AtomicBool>) -> TestCheck {
        self.started = Some(started);
        self
    }

    fn ordered(mut self, order: Arc<Mutex<Vec<String>>>) -> TestCheck {
        self.order = Some(order);
        self
    }

    fn recorded(mut self, execution: Arc<Mutex<Vec<String>>>) -> TestCheck {
        self.execution = Some(execution);
        self
    }

    fn counting(mut self, acquisitions: Arc<AtomicUsize>) -> TestCheck {
        self.acquisitions = Some(acquisitions);
        self
    }

    fn observing_destructive(mut self, flag: Arc<AtomicBool>) -> TestCheck {
        self.destructive_seen = Some(flag);
        self
    }

    fn signalling(mut self, tx: mpsc::UnboundedSender<ShutdownSignal>) -> TestCheck {
        self.signal = Some(tx);
        self
    }
}

impl Check for TestCheck {
    fn spec(&self) -> &CheckSpec {
        &self.spec
    }

    fn run<'a>(
        &'a self,
        ctx: &'a CheckContext,
    ) -> Pin<Box<dyn Future<Output = CheckResult> + Send + 'a>> {
        if let Some(started) = &self.started {
            started.store(true, Ordering::SeqCst);
        }
        if let Some(execution) = &self.execution {
            match execution.lock() {
                Ok(mut execution) => execution.push(self.spec.id.to_owned()),
                Err(poisoned) => poisoned.into_inner().push(self.spec.id.to_owned()),
            }
        }
        if let Some(seen) = &self.destructive_seen {
            seen.store(ctx.destructive(), Ordering::SeqCst);
        }
        let order = self.order.clone();
        let acquisitions = self.acquisitions.clone();
        let signal = self.signal.clone();
        match self.behaviour {
            Behaviour::PassWithoutEvidence => Box::pin(async { CheckResult::pass(Vec::new()) }),
            Behaviour::PassWithEvidence => Box::pin(async move {
                // Review item S-6: the evidence is written through the context's store, so it is recorded as written by
                // this check in this run; the executor then verifies that record.
                match ctx.save_evidence(PROOF_NAME, PROOF_BYTES) {
                    Ok(reference) => CheckResult::pass(vec![reference]),
                    Err(_) => CheckResult::fail("cannot save evidence"),
                }
            }),
            Behaviour::PassWithFabricatedEvidence => Box::pin(async move {
                let _ = ctx.save_evidence(PROOF_NAME, PROOF_BYTES);
                CheckResult::pass(vec![EvidenceRef::new(
                    PROOF_NAME,
                    crate::report::sha256_hex(b"something else"),
                    PROOF_BYTES.len() as u64,
                )])
            }),
            Behaviour::Fail => Box::pin(async { CheckResult::fail("a deliberate test failure") }),
            Behaviour::CleanupThenPanic => Box::pin(async move {
                register_cleanup(ctx, &order, "unban 198.51.100.7");
                panic!("deliberate panic after cleanup registration")
            }),
            Behaviour::SleepFor(duration) => Box::pin(async move {
                tokio::time::sleep(duration).await;
                CheckResult::unverified(ReasonCode::StageNotReached)
            }),
            Behaviour::CleanupThenSleep => Box::pin(async move {
                register_cleanup(ctx, &order, "unban 198.51.100.7");
                loop {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }),
            Behaviour::CleanupThenFail => Box::pin(async move {
                register_cleanup(ctx, &order, "remove temporary rule");
                CheckResult::fail("failed after registering cleanup")
            }),
            Behaviour::AcquireUntilDenied => Box::pin(async move {
                let mut granted = 0usize;
                while ctx.acquire(Lane::Http, 1).is_ok() {
                    granted += 1;
                }
                if let Some(counter) = &acquisitions {
                    counter.store(granted, Ordering::SeqCst);
                }
                CheckResult::fail("stopped at the shared budget")
            }),
            Behaviour::SignalThenComplete => Box::pin(async move {
                if let Some(tx) = &signal {
                    let _ = tx.send(ShutdownSignal::Interrupt);
                }
                CheckResult::fail("sent the signal from inside the check")
            }),
        }
    }
}

fn register_cleanup(
    ctx: &CheckContext,
    order: &Option<Arc<Mutex<Vec<String>>>>,
    description: &str,
) {
    let order = order.clone();
    let description = description.to_owned();
    ctx.on_cleanup(
        description.clone(),
        Box::new(move || {
            if let Some(order) = &order {
                match order.lock() {
                    Ok(mut order) => order.push(description),
                    Err(poisoned) => poisoned.into_inner().push(description),
                }
            }
        }),
    );
}

/// A signal source that never fires.
struct NeverSignals;

impl SignalSource for NeverSignals {
    fn listen(self: Box<Self>) -> Pin<Box<dyn Future<Output = ShutdownSignal> + Send>> {
        Box::pin(std::future::pending())
    }
}

/// A signal source driven by a test channel.
struct ChannelSignals {
    rx: mpsc::UnboundedReceiver<ShutdownSignal>,
}

impl SignalSource for ChannelSignals {
    fn listen(self: Box<Self>) -> Pin<Box<dyn Future<Output = ShutdownSignal> + Send>> {
        let mut rx = self.rx;
        Box::pin(async move {
            match rx.recv().await {
                Some(signal) => signal,
                None => std::future::pending().await,
            }
        })
    }
}

fn executor(
    dir: &Path,
    signals: Box<dyn SignalSource>,
    run_profile: LoadProfile,
    stage: LifecycleStage,
) -> Executor {
    let mut executor = Executor::with_signals(
        kill_switch(dir),
        limiter(run_profile),
        TargetMode::Live,
        stage,
        run_profile,
        signals,
    );
    // The validated profile and the evidence store are the executor's; checks receive them through the context (S-1/S-6).
    let store = crate::report::EvidenceStore::create(dir).expect("evidence store");
    executor.set_evidence_store(store);
    executor.with_profile(crate::test_support::profile())
}

fn order_log(order: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    match order.lock() {
        Ok(order) => order.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

#[test]
fn the_cleanup_stack_runs_last_in_first_out() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut stack = CleanupStack::new();
    for action in ["first", "second", "third"] {
        let order = Arc::clone(&order);
        stack.push(
            action,
            Box::new(move || match order.lock() {
                Ok(mut order) => order.push(action.to_owned()),
                Err(poisoned) => poisoned.into_inner().push(action.to_owned()),
            }),
        );
    }
    assert_eq!(stack.len(), 3);
    let records = stack.run_all();
    assert_eq!(
        order_log(&order),
        vec!["third".to_owned(), "second".to_owned(), "first".to_owned()],
        "the most recent change is undone first"
    );
    assert_eq!(records.len(), 3);
    assert!(stack.is_empty());
    assert!(stack.run_all().is_empty());
}

#[test]
fn a_panicking_cleanup_action_does_not_stop_the_others() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut stack = CleanupStack::new();
    let first = Arc::clone(&order);
    stack.push(
        "ok-before",
        Box::new(move || match first.lock() {
            Ok(mut order) => order.push("ok-before".to_owned()),
            Err(poisoned) => poisoned.into_inner().push("ok-before".to_owned()),
        }),
    );
    stack.push("boom", Box::new(|| panic!("cleanup action panics")));
    let last = Arc::clone(&order);
    stack.push(
        "ok-after",
        Box::new(move || match last.lock() {
            Ok(mut order) => order.push("ok-after".to_owned()),
            Err(poisoned) => poisoned.into_inner().push("ok-after".to_owned()),
        }),
    );
    let records = stack.run_all();
    assert_eq!(records.len(), 3);
    assert_eq!(
        records[1].description,
        "boom (cleanup action panicked; recorded)"
    );
    assert_eq!(
        order_log(&order),
        vec!["ok-after".to_owned(), "ok-before".to_owned()]
    );
}

#[tokio::test]
async fn cleanup_runs_when_a_check_fails() {
    let dir = temp_dir("runner-cleanup-fail");
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let check = TestCheck::new("AC-00", Behaviour::CleanupThenFail).ordered(Arc::clone(&order));
    let report = executor.run_one(&check).await;
    assert!(matches!(report.line.verdict, Verdict::Fail { .. }));
    assert_eq!(
        order_log(&order),
        vec!["remove temporary rule".to_owned()],
        "the finally stack ran"
    );
    assert_eq!(report.abort, None);
}

#[tokio::test]
async fn a3_the_kill_switch_aborts_a_running_check_within_one_second_and_cleanup_runs() {
    let dir = temp_dir("runner-kill");
    let order = Arc::new(Mutex::new(Vec::new()));
    let kill = kill_switch(&dir);
    let mut executor = Executor::with_signals(
        kill.clone(),
        limiter(LoadProfile::Functional),
        TargetMode::Live,
        LifecycleStage::Pilot,
        LoadProfile::Functional,
        Box::new(NeverSignals),
    );
    let path = kill.path().to_path_buf();
    let toucher = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        std::fs::write(&path, b"stop").expect("trip the kill switch");
        tokio::time::Instant::now()
    });
    let check = TestCheck::new("AC-00", Behaviour::CleanupThenSleep).ordered(Arc::clone(&order));
    let started = tokio::time::Instant::now();
    let report = executor.run_one(&check).await;
    let elapsed = started.elapsed();
    let touched_at = toucher.await.expect("toucher task");
    assert_eq!(report.abort, Some(AbortCause::KillSwitch));
    assert_eq!(
        report.line.verdict,
        Verdict::unverified(ReasonCode::SkippedByOperator),
        "spec 2.8 step 5: a kill-switch abort is UNVERIFIED(skipped_by_operator)"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "the run must stop within one second of the file appearing; took {elapsed:?}"
    );
    assert!(
        touched_at.elapsed() < Duration::from_secs(1),
        "measured from the file write: {:?}",
        touched_at.elapsed()
    );
    assert_eq!(
        order_log(&order),
        vec!["unban 198.51.100.7".to_owned()],
        "the cleanup stack ran on the abort path"
    );
    assert_eq!(report.cleanup.len(), 1);
}

#[tokio::test]
async fn a_kill_switch_that_is_already_set_aborts_before_the_check_body_runs() {
    let dir = temp_dir("runner-kill-preset");
    let kill = kill_switch(&dir);
    std::fs::write(kill.path(), b"stop").expect("preset the switch");
    let mut executor = Executor::with_signals(
        kill,
        limiter(LoadProfile::Functional),
        TargetMode::Live,
        LifecycleStage::Pilot,
        LoadProfile::Functional,
        Box::new(NeverSignals),
    );
    let started = Arc::new(AtomicBool::new(false));
    let check = TestCheck::new("AC-00", Behaviour::Fail).starting(Arc::clone(&started));
    let report = executor.run_one(&check).await;
    assert_eq!(report.abort, Some(AbortCause::KillSwitch));
    assert_eq!(
        report.line.verdict,
        Verdict::unverified(ReasonCode::SkippedByOperator)
    );
    assert!(!started.load(Ordering::SeqCst), "the check body never ran");
}

#[tokio::test]
async fn a_signal_aborts_a_running_check_and_cleanup_runs() {
    let dir = temp_dir("runner-signal");
    let order = Arc::new(Mutex::new(Vec::new()));
    let (tx, rx) = mpsc::unbounded_channel();
    let mut executor = self::executor(
        &dir,
        Box::new(ChannelSignals { rx }),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let sender = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        tx.send(ShutdownSignal::Interrupt).expect("send signal");
    });
    let check = TestCheck::new("AC-00", Behaviour::CleanupThenSleep).ordered(Arc::clone(&order));
    let report = executor.run_one(&check).await;
    sender.await.expect("sender task");
    assert_eq!(
        report.abort,
        Some(AbortCause::Signal(ShutdownSignal::Interrupt))
    );
    assert_eq!(
        report.line.verdict,
        Verdict::unverified(ReasonCode::SkippedByOperator)
    );
    assert_eq!(order_log(&order), vec!["unban 198.51.100.7".to_owned()]);
}

#[tokio::test]
async fn a9_a_signal_between_two_checks_stops_the_run_before_the_next_body() {
    let dir = temp_dir("runner-signal-between");
    let execution = Arc::new(Mutex::new(Vec::new()));
    let started = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::unbounded_channel();
    let mut executor = self::executor(
        &dir,
        Box::new(ChannelSignals { rx }),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    // The first check sends the signal itself and then completes. The executor must observe it before starting the second
    // check (one persistent latched listener, review item A-9). AC-00 runs first and passes (review item R-8).
    let self_test =
        TestCheck::new("AC-00", Behaviour::PassWithEvidence).recorded(Arc::clone(&execution));
    let first = TestCheck::new("AC-01", Behaviour::SignalThenComplete)
        .recorded(Arc::clone(&execution))
        .signalling(tx);
    let second = TestCheck::new("AC-02", Behaviour::Fail)
        .starting(Arc::clone(&started))
        .recorded(Arc::clone(&execution));
    let checks: Vec<&dyn Check> = vec![&self_test, &first, &second];
    let report = executor.run_plan(&checks).await.expect("plan");
    assert_eq!(
        report.abort,
        Some(AbortCause::Signal(ShutdownSignal::Interrupt))
    );
    assert_eq!(
        order_log(&execution),
        vec!["AC-00".to_owned(), "AC-01".to_owned()]
    );
    assert!(
        !started.load(Ordering::SeqCst),
        "the second check never ran"
    );
    assert_eq!(report.lines.len(), 3);
    assert_eq!(
        report.lines[2].verdict,
        Verdict::unverified(ReasonCode::SkippedByOperator)
    );
}

#[tokio::test]
async fn a8_a_per_check_timeout_fails_only_that_check() {
    let dir = temp_dir("runner-timeout");
    let first_order = Arc::new(Mutex::new(Vec::new()));
    let started = Arc::new(AtomicBool::new(false));
    let self_test = TestCheck::new("AC-00", Behaviour::PassWithEvidence);
    let slow = TestCheck::new("AC-01", Behaviour::CleanupThenSleep)
        .with_timeout(Duration::from_millis(50))
        .ordered(Arc::clone(&first_order));
    let after = TestCheck::new("AC-02", Behaviour::Fail).starting(Arc::clone(&started));
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let checks: Vec<&dyn Check> = vec![&self_test, &slow, &after];
    let started_at = tokio::time::Instant::now();
    let report = executor.run_plan(&checks).await.expect("plan");
    assert_eq!(report.abort, None, "a timeout is not a run abort");
    assert!(started_at.elapsed() < Duration::from_secs(1));
    assert!(
        report.lines[1].verdict.to_string().contains("timeout"),
        "{}",
        report.lines[1].verdict
    );
    assert!(
        started.load(Ordering::SeqCst),
        "the next check still runs after another check timed out"
    );
    assert_eq!(
        report.lines[2].verdict,
        Verdict::fail("a deliberate test failure")
    );
    assert_eq!(
        order_log(&first_order),
        vec!["unban 198.51.100.7".to_owned()]
    );
}

#[tokio::test]
async fn a8_a_dependent_of_a_failed_check_is_unverified_stage_not_reached_naming_the_dependency() {
    let dir = temp_dir("runner-dependency");
    let started = Arc::new(AtomicBool::new(false));
    let self_test = TestCheck::new("AC-00", Behaviour::PassWithEvidence);
    let first = TestCheck::new("AC-01", Behaviour::Fail);
    let dependent = TestCheck::new("AC-02", Behaviour::PassWithoutEvidence)
        .with_dependencies(&["AC-01"])
        .starting(Arc::clone(&started));
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let checks: Vec<&dyn Check> = vec![&self_test, &first, &dependent];
    let report = executor.run_plan(&checks).await.expect("plan");
    // The status taxonomy of E3.1 rule 1 has no `dependency_not_met`: a dependent of a non-PASS dependency is
    // UNVERIFIED(stage_not_reached), and its detail names the dependency.
    assert_eq!(
        report.lines[2].verdict,
        Verdict::unverified(ReasonCode::StageNotReached)
    );
    let detail = report.lines[2].detail.as_deref().unwrap_or_default();
    assert!(detail.contains("AC-01"), "{detail}");
    assert!(
        !started.load(Ordering::SeqCst),
        "the dependent body never ran"
    );
}

#[tokio::test]
async fn a8_a_dependent_of_an_unverified_check_does_not_run() {
    let dir = temp_dir("runner-dependency-unverified");
    let started = Arc::new(AtomicBool::new(false));
    let self_test = TestCheck::new("AC-00", Behaviour::PassWithEvidence);
    let first = TestCheck::new("AC-01", Behaviour::Fail);
    let second =
        TestCheck::new("AC-02", Behaviour::PassWithoutEvidence).with_dependencies(&["AC-01"]);
    let third = TestCheck::new("AC-03", Behaviour::Fail)
        .with_dependencies(&["AC-02"])
        .starting(Arc::clone(&started));
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let checks: Vec<&dyn Check> = vec![&self_test, &first, &second, &third];
    let report = executor.run_plan(&checks).await.expect("plan");
    assert_eq!(
        report.lines[3].verdict,
        Verdict::unverified(ReasonCode::StageNotReached)
    );
    assert!(!started.load(Ordering::SeqCst));
}

#[tokio::test]
async fn a8_a_failing_ac00_stops_the_run() {
    let dir = temp_dir("runner-ac00");
    let started = Arc::new(AtomicBool::new(false));
    let self_test = TestCheck::new("AC-00", Behaviour::Fail);
    let after = TestCheck::new("AC-01", Behaviour::Fail).starting(Arc::clone(&started));
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let checks: Vec<&dyn Check> = vec![&self_test, &after];
    let report = executor.run_plan(&checks).await.expect("plan");
    assert_eq!(report.abort, Some(AbortCause::SelfTestFailed));
    assert!(
        matches!(report.lines[0].verdict, Verdict::Fail { .. }),
        "AC-00 itself fails"
    );
    assert_eq!(
        report.lines[1].verdict,
        Verdict::unverified(ReasonCode::StageNotReached)
    );
    assert!(
        report.lines[1]
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("AC-00"),
        "{:?}",
        report.lines[1].detail
    );
    assert!(!started.load(Ordering::SeqCst));
}

#[tokio::test]
async fn a_panicking_check_is_caught_counted_and_its_cleanup_runs() {
    let dir = temp_dir("runner-panic");
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let check = TestCheck::new("AC-00", Behaviour::CleanupThenPanic).ordered(Arc::clone(&order));
    let report = executor.run_one(&check).await;
    assert_eq!(executor.panics(), 1, "R-09: caught panics are counted");
    assert!(
        report.line.verdict.to_string().contains("panicked"),
        "{}",
        report.line.verdict
    );
    assert!(matches!(report.line.verdict, Verdict::Fail { .. }));
    assert_eq!(
        order_log(&order),
        vec!["unban 198.51.100.7".to_owned()],
        "the finally stack ran even though the check panicked"
    );
}

#[tokio::test]
async fn a_pass_without_evidence_is_turned_into_a_fail() {
    let dir = temp_dir("runner-pass-no-evidence");
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let check = TestCheck::new("AC-00", Behaviour::PassWithoutEvidence);
    let report = executor.run_one(&check).await;
    assert!(
        matches!(&report.line.verdict, Verdict::Fail { reason } if reason.contains("evidence invalid")),
        "{:?}",
        report.line.verdict
    );
}

#[tokio::test]
async fn a3_a_destructive_check_is_refused_in_production_before_the_body_runs() {
    let dir = temp_dir("runner-destructive-production");
    let started = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(AtomicBool::new(false));
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Production,
    );
    let check = TestCheck::new("AC-00", Behaviour::Fail)
        .destructive()
        .starting(Arc::clone(&started))
        .observing_destructive(Arc::clone(&seen));
    let report = executor.run_one(&check).await;
    assert_eq!(
        report.line.verdict,
        Verdict::unverified(ReasonCode::StageForbids)
    );
    assert!(!started.load(Ordering::SeqCst), "the body did not run");
    assert!(!seen.load(Ordering::SeqCst));
    assert_eq!(report.abort, None);
}

#[tokio::test]
async fn a3_a_destructive_check_runs_in_pilot_and_the_flag_reaches_the_context() {
    let dir = temp_dir("runner-destructive-pilot");
    let seen = Arc::new(AtomicBool::new(false));
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let check = TestCheck::new("AC-00", Behaviour::Fail)
        .destructive()
        .observing_destructive(Arc::clone(&seen));
    let report = executor.run_one(&check).await;
    assert!(matches!(report.line.verdict, Verdict::Fail { .. }));
    assert!(
        seen.load(Ordering::SeqCst),
        "the executor passes CheckSpec.destructive, not the attempt, to the check context"
    );
}

#[tokio::test]
async fn a3_a_check_profile_may_not_exceed_the_run_profile() {
    let dir = temp_dir("runner-profile-exceed");
    let started = Arc::new(AtomicBool::new(false));
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let check = TestCheck::new("AC-00", Behaviour::Fail)
        .with_profile(LoadProfile::Lab)
        .starting(Arc::clone(&started));
    let report = executor.run_one(&check).await;
    assert_eq!(
        report.line.verdict,
        Verdict::unverified(ReasonCode::StageForbids)
    );
    assert!(!started.load(Ordering::SeqCst), "the body did not run");
}

#[tokio::test]
async fn a3_the_check_level_limiter_uses_the_check_profile() {
    let dir = temp_dir("runner-check-profile");
    let acquisitions = Arc::new(AtomicUsize::new(usize::MAX));
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Lab,
        LifecycleStage::Pilot,
    );
    let check = TestCheck::new("AC-00", Behaviour::AcquireUntilDenied)
        .with_profile(LoadProfile::Functional)
        .counting(Arc::clone(&acquisitions));
    executor.run_one(&check).await;
    assert_eq!(
        acquisitions.load(Ordering::SeqCst),
        20,
        "a functional check in a lab run is capped at 20 per second"
    );
}

#[tokio::test]
async fn the_shared_limiter_is_one_instance_for_all_checks() {
    let dir = temp_dir("runner-shared-limiter");
    let first_count = Arc::new(AtomicUsize::new(usize::MAX));
    let second_count = Arc::new(AtomicUsize::new(usize::MAX));
    let self_test = TestCheck::new("AC-00", Behaviour::PassWithEvidence);
    let first =
        TestCheck::new("AC-01", Behaviour::AcquireUntilDenied).counting(Arc::clone(&first_count));
    let second =
        TestCheck::new("AC-02", Behaviour::AcquireUntilDenied).counting(Arc::clone(&second_count));
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let checks: Vec<&dyn Check> = vec![&self_test, &first, &second];
    executor.run_plan(&checks).await.expect("plan");
    assert_eq!(
        first_count.load(Ordering::SeqCst),
        20,
        "20 req/s in one instant"
    );
    assert_eq!(
        second_count.load(Ordering::SeqCst),
        0,
        "the second check shares the same window"
    );
}

#[test]
fn order_runs_dependencies_first_and_is_stable() {
    let c = TestCheck::new("AC-02", Behaviour::Fail).with_dependencies(&["AC-01"]);
    let b = TestCheck::new("AC-01", Behaviour::Fail).with_dependencies(&["AC-00"]);
    let a = TestCheck::new("AC-00", Behaviour::Fail);
    let checks: Vec<&dyn Check> = vec![&c, &b, &a];
    let order = order(&checks).expect("order");
    assert_eq!(
        order,
        vec![2, 1, 0],
        "AC-00 before AC-01 before AC-02, whatever the input order"
    );
}

#[test]
fn a_dependency_cycle_is_reported() {
    let a = TestCheck::new("AC-00", Behaviour::Fail).with_dependencies(&["AC-01"]);
    let b = TestCheck::new("AC-01", Behaviour::Fail).with_dependencies(&["AC-00"]);
    let checks: Vec<&dyn Check> = vec![&a, &b];
    match order(&checks) {
        Err(PlanError::Cycle { ids }) => {
            assert_eq!(ids.len(), 2);
            assert!(ids.contains(&"AC-00".to_owned()) && ids.contains(&"AC-01".to_owned()));
        }
        other => panic!("expected a cycle, got {other:?}"),
    }
}

#[test]
fn an_unknown_dependency_is_reported() {
    let a = TestCheck::new("AC-00", Behaviour::Fail).with_dependencies(&["AC-09"]);
    let checks: Vec<&dyn Check> = vec![&a];
    assert_eq!(
        order(&checks),
        Err(PlanError::UnknownDependency {
            check: "AC-00".to_owned(),
            dependency: "AC-09".to_owned()
        })
    );
}

#[test]
fn a_duplicate_id_a_bad_id_and_a_zero_timeout_are_reported() {
    let a = TestCheck::new("AC-00", Behaviour::Fail);
    let b = TestCheck::new("AC-00", Behaviour::Fail);
    assert_eq!(
        order(&[&a, &b]),
        Err(PlanError::DuplicateId {
            id: "AC-00".to_owned()
        })
    );
    let bad = TestCheck::new("AC-0", Behaviour::Fail);
    assert_eq!(
        order(&[&bad]),
        Err(PlanError::BadId {
            id: "AC-0".to_owned()
        })
    );
    let zero = TestCheck::new("AC-00", Behaviour::Fail).with_timeout(Duration::ZERO);
    assert_eq!(
        order(&[&zero]),
        Err(PlanError::ZeroTimeout {
            id: "AC-00".to_owned()
        })
    );
}

#[tokio::test]
async fn run_plan_executes_in_order_and_runs_ac00_first() {
    let dir = temp_dir("runner-plan-order");
    let execution = Arc::new(Mutex::new(Vec::new()));
    let a = TestCheck::new("AC-00", Behaviour::PassWithEvidence).recorded(Arc::clone(&execution));
    let b = TestCheck::new("AC-01", Behaviour::Fail).recorded(Arc::clone(&execution));
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let checks: Vec<&dyn Check> = vec![&b, &a];
    let report = executor.run_plan(&checks).await.expect("plan");
    // Review item R-8: the AC-00 self-test runs first whatever the input order.
    assert_eq!(
        order_log(&execution),
        vec!["AC-00".to_owned(), "AC-01".to_owned()]
    );
    assert_eq!(report.lines.len(), 2);
}

#[test]
fn the_abort_causes_display_honestly() {
    assert_eq!(
        AbortCause::KillSwitch.to_string(),
        "kill-switch file present"
    );
    assert_eq!(
        AbortCause::Signal(ShutdownSignal::Terminate).to_string(),
        "operator signal: termination (SIGTERM)"
    );
    assert_eq!(
        AbortCause::SelfTestFailed.to_string(),
        "the AC-00 safety self-test failed"
    );
}

#[tokio::test]
async fn a_completed_check_keeps_its_own_verdict() {
    let dir = temp_dir("runner-completed");
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let check = TestCheck::new("AC-00", Behaviour::SleepFor(Duration::from_millis(10)));
    let report = executor.run_one(&check).await;
    assert_eq!(report.abort, None);
    assert_eq!(
        report.line.verdict,
        Verdict::unverified(ReasonCode::StageNotReached)
    );
    assert!(report.cleanup.is_empty());
}

/// Review item R-4: the executor re-reads and re-hashes the evidence file before accepting a PASS.
#[tokio::test]
async fn r4_a_pass_backed_by_a_real_artifact_is_accepted() {
    let dir = temp_dir("runner-r4-real");
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let check = TestCheck::new("AC-00", Behaviour::PassWithEvidence);
    let report = executor.run_one(&check).await;
    assert_eq!(report.line.verdict, Verdict::Pass);
    assert_eq!(report.line.evidence.len(), 1);
}

/// Review item R-4: a check that reports a PASS with a hash that does not match the artifact gets a FAIL instead.
#[tokio::test]
async fn r4_a_fabricated_evidence_hash_is_turned_into_a_fail() {
    let dir = temp_dir("runner-r4-fabricated");
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let check = TestCheck::new("AC-00", Behaviour::PassWithFabricatedEvidence);
    let report = executor.run_one(&check).await;
    assert!(
        matches!(&report.line.verdict, Verdict::Fail { reason } if reason.contains("evidence invalid")),
        "{:?}",
        report.line.verdict
    );
    assert!(report.line.evidence.is_empty());
}

/// Review item R-8: a plan without AC-00 is refused, and an UNVERIFIED AC-00 stops the run just like a FAIL.
#[tokio::test]
async fn r8_a_plan_without_ac00_is_refused() {
    let dir = temp_dir("runner-r8-no-ac00");
    let check = TestCheck::new("AC-01", Behaviour::PassWithEvidence);
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    assert_eq!(
        executor.run_plan(&[&check]).await.err(),
        Some(PlanError::MissingSelfTest)
    );
}

#[tokio::test]
async fn r8_an_unverified_ac00_stops_the_run() {
    let dir = temp_dir("runner-r8-unverified-ac00");
    let started = Arc::new(AtomicBool::new(false));
    let self_test = TestCheck::new("AC-00", Behaviour::SleepFor(Duration::from_millis(1)));
    let after = TestCheck::new("AC-01", Behaviour::Fail).starting(Arc::clone(&started));
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let checks: Vec<&dyn Check> = vec![&self_test, &after];
    let report = executor.run_plan(&checks).await.expect("plan");
    assert_eq!(report.abort, Some(AbortCause::SelfTestFailed));
    assert!(!started.load(Ordering::SeqCst), "AC-01 never ran");
    assert_eq!(
        report.lines[1].verdict,
        Verdict::unverified(ReasonCode::StageNotReached)
    );
    assert!(
        report.lines[1]
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("AC-00"),
        "{:?}",
        report.lines[1].detail
    );
}

/// Review item R-8: `Executor.panics` is carried into the `RunReport` (R-09 alerting needs a number to read).
#[tokio::test]
async fn r8_caught_panics_are_carried_into_the_run_report() {
    let dir = temp_dir("runner-r8-panics");
    let self_test = TestCheck::new("AC-00", Behaviour::PassWithEvidence);
    let panicking = TestCheck::new("AC-01", Behaviour::CleanupThenPanic);
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let checks: Vec<&dyn Check> = vec![&self_test, &panicking];
    let report = executor.run_plan(&checks).await.expect("plan");
    assert_eq!(
        report.panics, 1,
        "the caught panic is counted in the report"
    );
    assert!(matches!(report.lines[1].verdict, Verdict::Fail { .. }));
}

/// A check that swallows a target-guard denial: the run must still be marked invalid and carry the audit line (R-8).
struct SwallowingCheck {
    spec: CheckSpec,
}

impl Check for SwallowingCheck {
    fn spec(&self) -> &CheckSpec {
        &self.spec
    }

    fn run<'a>(
        &'a self,
        ctx: &'a CheckContext,
    ) -> Pin<Box<dyn Future<Output = CheckResult> + Send + 'a>> {
        Box::pin(async move {
            let Ok(mut connector) = ctx.connector("rev-1") else {
                return CheckResult::fail("cannot build the connector");
            };
            let attempt = crate::guard::Attempt::new(
                "www.example.com",
                "/",
                crate::guard::PayloadClass::A,
                crate::guard::Method::Get,
            );
            // The guard denial is deliberately swallowed: the run-invalid latch must record it anyway.
            let _ = connector.prepare(&attempt, None).await;
            CheckResult::fail("the guard denial was swallowed")
        })
    }
}

#[tokio::test]
async fn r8_a_guard_denial_marks_the_run_invalid_and_records_the_audit_line() {
    let dir = temp_dir("runner-r8-invalid");
    let self_test = TestCheck::new("AC-00", Behaviour::PassWithEvidence);
    let swallowing = SwallowingCheck {
        spec: CheckSpec {
            id: "AC-01",
            title: "swallows a guard denial",
            requirements: NO_REQUIREMENTS,
            destructive: false,
            profile: LoadProfile::Functional,
            dependencies: NO_DEPS,
            timeout: Duration::from_secs(5),
            tier: "smoke",
        },
    };
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    )
    .with_runtime_facts(
        Arc::new(crate::test_support::allowlisted_resolver()),
        Arc::new(crate::inspect::FixedRevision::new("rev-1")),
        crate::control::Bannable::Bannable {
            runner: "198.51.100.77".parse().expect("runner ip"),
        },
    );
    let checks: Vec<&dyn Check> = vec![&self_test, &swallowing];
    let report = executor.run_plan(&checks).await.expect("plan");
    assert!(report.run_invalid, "a target denial marks the run invalid");
    assert!(
        report
            .invalid_audit
            .iter()
            .any(|line| line.contains("AC-01")),
        "{:?}",
        report.invalid_audit
    );
}

/// Review item R-9: the signal listener is polled once in the constructor, before the first check can start.
#[tokio::test]
async fn r9_the_signal_listener_is_primed_in_the_constructor() {
    struct CountingSignals {
        polled: Arc<AtomicBool>,
    }
    impl SignalSource for CountingSignals {
        fn listen(self: Box<Self>) -> Pin<Box<dyn Future<Output = ShutdownSignal> + Send>> {
            Box::pin(async move {
                self.polled.store(true, Ordering::SeqCst);
                std::future::pending::<ShutdownSignal>().await
            })
        }
    }
    let dir = temp_dir("runner-r9-prime");
    let polled = Arc::new(AtomicBool::new(false));
    let _executor = Executor::with_signals(
        kill_switch(&dir),
        limiter(LoadProfile::Functional),
        TargetMode::Live,
        LifecycleStage::Pilot,
        LoadProfile::Functional,
        Box::new(CountingSignals {
            polled: Arc::clone(&polled),
        }),
    );
    assert!(
        polled.load(Ordering::SeqCst),
        "the listener must be polled (and the OS handler registered) before the first check"
    );
}

/// Review item R-13: the production destructive gate is the lifecycle policy, bound to this run's id.
#[tokio::test]
async fn r13_the_destructive_gate_is_bound_to_the_run_id() {
    use crate::config::{LifecyclePolicy, RunApproval};
    let dir = temp_dir("runner-r13-bound");
    let mut wrong = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Production,
    )
    .with_run_context(
        LifecyclePolicy::new(
            LifecycleStage::Production,
            Some(RunApproval::new("another-run", "02:00-03:00").expect("approval")),
        ),
        "this-run",
    );
    let check = TestCheck::new("AC-00", Behaviour::Fail).destructive();
    let report = wrong.run_one(&check).await;
    assert_eq!(
        report.line.verdict,
        Verdict::unverified(ReasonCode::StageForbids)
    );
    assert!(
        report
            .line
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("another-run"),
        "{:?}",
        report.line.detail
    );

    let mut right = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Production,
    )
    .with_run_context(
        LifecyclePolicy::new(
            LifecycleStage::Production,
            Some(RunApproval::new("this-run", "02:00-03:00").expect("approval")),
        ),
        "this-run",
    );
    let report = right.run_one(&check).await;
    assert!(
        matches!(report.line.verdict, Verdict::Fail { .. }),
        "with this run's approval the destructive check body runs: {:?}",
        report.line.verdict
    );
}

/// Review items R-2 and S-5: a PASS resumed from a previous run satisfies a dependency that is not in this plan, while a
/// resumed AC-00 PASS never satisfies the self-test (AC-00 always re-runs) and the executor applies the same resume binding
/// checks as the report path.
#[tokio::test]
async fn r2_a_resumed_pass_satisfies_a_dependency_outside_the_plan() {
    use crate::report::{EvidenceStore, Report};
    let previous_dir = temp_dir("runner-r2-previous");
    let run_dir = temp_dir("runner-r2-run");
    let store = EvidenceStore::create(&previous_dir).expect("store");
    let artifact = store.save("proof.txt", b"previous evidence").expect("save");
    let hosts = vec![
        "hddtest.example.com".to_owned(),
        "hddsbx.example.com".to_owned(),
    ];
    let mut previous = Report::new("live", "pilot", "functional", 0).with_binding("rev-1", hosts);
    for id in ["AC-00", "AC-01"] {
        previous.push_line(
            StatusLine::new(
                id,
                "resumed",
                "smoke",
                Verdict::Pass,
                vec![artifact.clone()],
            )
            .expect("PASS"),
        );
    }
    let mut executor = self::executor(
        &run_dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    )
    .with_resume_binding(previous.binding());
    // Only AC-01 is resumed: the resumed AC-00 PASS is deliberately ignored (review item S-5).
    assert_eq!(
        executor
            .set_resume(&previous, &previous_dir)
            .expect("resume"),
        1
    );
    let ran = Arc::new(AtomicBool::new(false));
    let self_test = TestCheck::new("AC-00", Behaviour::PassWithEvidence);
    let dependent = TestCheck::new("AC-02", Behaviour::Fail)
        .with_dependencies(&["AC-01"])
        .starting(Arc::clone(&ran));
    // AC-00 runs again (it is in the plan), and AC-01 (the dependency) is not in the plan: it is satisfied by the resumed
    // PASS line.
    let report = executor
        .run_plan(&[&self_test, &dependent])
        .await
        .expect("resumed plan");
    assert!(
        ran.load(Ordering::SeqCst),
        "the dependency was satisfied by the resumed PASS"
    );
    assert_eq!(report.lines.len(), 3);
    assert!(report.lines[0].verdict.is_pass(), "the resumed AC-01 PASS");
    assert!(
        report.lines[1].verdict.is_pass(),
        "the re-run AC-00 self-test"
    );
    assert_eq!(
        report.lines[2].verdict,
        Verdict::fail("a deliberate test failure")
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Round-3 review items S-1, S-2, S-4, S-5, S-6, S-8, S-10.
// ---------------------------------------------------------------------------------------------------------------

/// A check that tries to build a connector for a target of its own choosing: the profile is the executor's, so the target
/// set cannot be widened (review item S-1).
struct TargetProbeCheck {
    spec: CheckSpec,
    target: &'static str,
}

impl Check for TargetProbeCheck {
    fn spec(&self) -> &CheckSpec {
        &self.spec
    }

    fn run<'a>(
        &'a self,
        ctx: &'a CheckContext,
    ) -> Pin<Box<dyn Future<Output = CheckResult> + Send + 'a>> {
        Box::pin(async move {
            let Ok(mut connector) = ctx.connector("rev-1") else {
                return CheckResult::fail("cannot build the connector");
            };
            let attempt = crate::guard::Attempt::new(
                self.target,
                "/",
                crate::guard::PayloadClass::A,
                crate::guard::Method::Get,
            );
            match connector.prepare(&attempt, None).await {
                Ok(_) => CheckResult::fail("the check widened the allowlist"),
                Err(denial) => CheckResult::fail(format!("denied: {denial}")),
            }
        })
    }
}

fn probe_spec(id: &'static str) -> CheckSpec {
    CheckSpec {
        id,
        title: "probe",
        requirements: NO_REQUIREMENTS,
        destructive: false,
        profile: LoadProfile::Functional,
        dependencies: NO_DEPS,
        timeout: Duration::from_secs(5),
        tier: "smoke",
    }
}

/// Review item S-1: a check cannot widen the allowlist: `connector()` takes no profile, and the executor's validated profile
/// is the only one a check can use.
#[tokio::test]
async fn s1_a_check_cannot_widen_the_allowlist() {
    let dir = temp_dir("runner-s1");
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    )
    .with_runtime_facts(
        Arc::new(crate::test_support::allowlisted_resolver()),
        Arc::new(crate::inspect::FixedRevision::new("rev-1")),
        crate::control::Bannable::Bannable {
            runner: "198.51.100.77".parse().expect("runner ip"),
        },
    );
    let victim = TargetProbeCheck {
        spec: probe_spec("AC-02"),
        target: "victim.example",
    };
    let report = executor.run_one(&victim).await;
    let reason = match report.line.verdict {
        Verdict::Fail { reason } => reason,
        other => panic!("expected a FAIL, got {other:?}"),
    };
    assert!(
        reason.contains("victim.example") && reason.contains("not in the set"),
        "the executor's profile must refuse the victim host: {reason}"
    );

    // The same probe against the profile's own test host is allowed by the target guard (it stops at the inspect gate, which
    // is the proof that the target was accepted) â€” the profile is the executor's, not a caller's.
    let mut executor = self::executor(
        &temp_dir("runner-s1-allowed"),
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    )
    .with_runtime_facts(
        Arc::new(crate::test_support::allowlisted_resolver()),
        Arc::new(crate::inspect::FixedRevision::new("rev-1")),
        crate::control::Bannable::Bannable {
            runner: "198.51.100.77".parse().expect("runner ip"),
        },
    );
    let allowed = TargetProbeCheck {
        spec: probe_spec("AC-03"),
        target: "hddtest.example.com",
    };
    let report = executor.run_one(&allowed).await;
    let reason = match report.line.verdict {
        Verdict::Fail { reason } => reason,
        other => panic!("expected a FAIL, got {other:?}"),
    };
    assert!(
        reason.contains("inspect-first ticket"),
        "the profile's own host is accepted by the guard: {reason}"
    );
}

/// The inspect request matching a class A GET to the example test host.
fn inspect_request_for_test_host(path: &str) -> crate::inspect::InspectRequest {
    crate::inspect::InspectRequest::for_attempt(
        "hddtest.example.com",
        path,
        crate::guard::Method::Get,
        "GET",
        crate::guard::PayloadClass::A,
        &[],
        b"",
    )
}

/// A check that can only inspect through the context's gate (review item S-2).
struct InspectProbeCheck {
    spec: CheckSpec,
}

impl Check for InspectProbeCheck {
    fn spec(&self) -> &CheckSpec {
        &self.spec
    }

    fn run<'a>(
        &'a self,
        ctx: &'a CheckContext,
    ) -> Pin<Box<dyn Future<Output = CheckResult> + Send + 'a>> {
        Box::pin(async move {
            let request = inspect_request_for_test_host("/inspect-probe");
            match ctx.inspect(&request) {
                Ok(ticket) => {
                    let Ok(mut connector) = ctx.connector("rev-1") else {
                        return CheckResult::fail("cannot build the connector");
                    };
                    let attempt = crate::guard::Attempt::new(
                        "hddtest.example.com",
                        "/inspect-probe",
                        crate::guard::PayloadClass::A,
                        crate::guard::Method::Get,
                    );
                    match connector.prepare(&attempt, Some(&ticket)).await {
                        Ok(_) => match ctx.save_evidence("inspect-proof.txt", b"inspect ok") {
                            Ok(reference) => CheckResult::pass(vec![reference]),
                            Err(_) => CheckResult::fail("cannot save evidence"),
                        },
                        Err(denial) => CheckResult::fail(format!("prepare: {denial}")),
                    }
                }
                Err(error) => CheckResult::fail(format!("inspect: {error}")),
            }
        })
    }
}

/// Review item S-2: the executor owns the one inspect gate; a check obtains a ticket only through `ctx.inspect`, and an
/// executor without a client fails closed.
#[tokio::test]
async fn s2_the_executor_owns_the_inspect_gate() {
    let dir = temp_dir("runner-s2");
    let client = crate::test_support::ScriptedInspectClient::blocking("rev-1");
    let calls = client.calls();
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    )
    .with_inspect_client(Box::new(client), "rev-1")
    .with_runtime_facts(
        Arc::new(crate::test_support::allowlisted_resolver()),
        Arc::new(crate::inspect::FixedRevision::new("rev-1")),
        crate::control::Bannable::Bannable {
            runner: "198.51.100.77".parse().expect("runner ip"),
        },
    );

    let probe = InspectProbeCheck {
        spec: probe_spec("AC-01"),
    };
    let report = executor.run_one(&probe).await;
    assert_eq!(
        report.line.verdict,
        Verdict::Pass,
        "the executor's scripted inspect client issues a ticket: {:?}",
        report.line.verdict
    );
    assert_eq!(
        calls.lock().map(|calls| calls.len()).unwrap_or(0),
        1,
        "the check inspected through the executor's gate"
    );

    // Without a client the default gate fails closed, so a check cannot mint a ticket on its own.
    let dir = temp_dir("runner-s2-closed");
    let mut closed = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    )
    .with_runtime_facts(
        Arc::new(crate::test_support::allowlisted_resolver()),
        Arc::new(crate::inspect::FixedRevision::new("rev-1")),
        crate::control::Bannable::Bannable {
            runner: "198.51.100.77".parse().expect("runner ip"),
        },
    );

    let report = closed.run_one(&probe).await;
    let reason = match report.line.verdict {
        Verdict::Fail { reason } => reason,
        other => panic!("expected a FAIL, got {other:?}"),
    };
    assert!(
        reason.contains("no inspect client supplied"),
        "an executor without an inspect client must fail closed: {reason}"
    );
}

/// Review item S-4: AC-00 with an unmet dependency stops the run; the AC-00 rule is evaluated before the dependency skip.
#[tokio::test]
async fn s4_ac00_with_an_unmet_dependency_stops_the_run() {
    let dir = temp_dir("runner-s4");
    let started = Arc::new(AtomicBool::new(false));
    let self_test =
        TestCheck::new("AC-00", Behaviour::PassWithEvidence).with_dependencies(&["AC-01"]);
    let dependency = TestCheck::new("AC-01", Behaviour::Fail);
    let after = TestCheck::new("AC-02", Behaviour::Fail).starting(Arc::clone(&started));
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let checks: Vec<&dyn Check> = vec![&self_test, &dependency, &after];
    let report = executor.run_plan(&checks).await.expect("plan");
    assert_eq!(report.abort, Some(AbortCause::SelfTestFailed));
    assert!(
        !started.load(Ordering::SeqCst),
        "the run stops: AC-02 must not run after AC-00's unmet dependency"
    );
    let ac00 = report
        .lines
        .iter()
        .find(|line| line.id == "AC-00")
        .expect("AC-00 line");
    assert_eq!(
        ac00.verdict,
        Verdict::unverified(ReasonCode::StageNotReached)
    );
    assert!(
        ac00.detail.as_deref().unwrap_or_default().contains("AC-01"),
        "{:?}",
        ac00.detail
    );
}

/// Review item S-5: the executor runs the same resume checks as the report path (binding, invalid run, future timestamp) and
/// a resumed AC-00 PASS never satisfies the self-test.
#[tokio::test]
async fn s5_the_executor_uses_the_report_resume_checks() {
    use crate::report::{EvidenceStore, Report, ReportError, RunBinding};
    let dir = temp_dir("runner-s5");
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let unbound = Report::new("live", "pilot", "functional", 0);
    assert!(matches!(
        executor.set_resume(&unbound, &dir),
        Err(ReportError::ResumeMismatch { .. })
    ));

    let binding = RunBinding {
        mode: "live".to_owned(),
        stage: "pilot".to_owned(),
        load_profile: "functional".to_owned(),
        config_revision: "rev-1".to_owned(),
        target_hostnames: vec!["hddtest.example.com".to_owned()],
    };
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    )
    .with_resume_binding(binding.clone());
    // An invalid previous run is refused.
    let mut invalid = Report::new("live", "pilot", "functional", 0)
        .with_binding("rev-1", binding.target_hostnames.clone())
        .with_run_invalid(vec!["safety_envelope_denied: test".to_owned()]);
    assert!(matches!(
        executor.set_resume(&invalid, &dir),
        Err(ReportError::ResumeMismatch { .. })
    ));
    // A future timestamp is refused (review item S-5).
    let future = Report::new("live", "pilot", "functional", 0)
        .with_timestamp("9999-12-31T23:59:59Z")
        .with_binding("rev-1", binding.target_hostnames.clone());
    assert!(matches!(
        executor.set_resume(&future, &dir),
        Err(ReportError::ResumeMismatch { .. })
    ));

    // A resumed AC-00 PASS is ignored: AC-00 always re-runs.
    let previous_dir = temp_dir("runner-s5-previous");
    let store = EvidenceStore::create(&previous_dir).expect("store");
    let artifact = store.save("proof.txt", b"previous evidence").expect("save");
    let mut previous = Report::new("live", "pilot", "functional", 0)
        .with_binding("rev-1", binding.target_hostnames.clone());
    previous.push_line(
        StatusLine::new(
            "AC-00",
            "resumed",
            "smoke",
            Verdict::Pass,
            vec![artifact.clone()],
        )
        .expect("PASS"),
    );
    invalid = previous;
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    )
    .with_resume_binding(binding.clone());
    assert_eq!(
        executor
            .set_resume(&invalid, &previous_dir)
            .expect("resume"),
        0
    );
    assert_eq!(
        executor.run_plan(&[]).await.err(),
        Some(PlanError::MissingSelfTest),
        "a resumed AC-00 PASS must not satisfy the self-test"
    );

    // Review item N-9: the check is not vacuous. A report with AC-00 and AC-01 PASS lines resumes exactly the non-self-test
    // line (a selector that reuses nothing fails the count below), and a plan without AC-00 still cannot start even though
    // AC-01 was resumed (a selector that wrongly reuses AC-00 would let it start).
    let ac01_artifact = store
        .save("proof2.txt", b"more previous evidence")
        .expect("save");
    let mut with_ac01 = Report::new("live", "pilot", "functional", 0)
        .with_binding("rev-1", binding.target_hostnames.clone());
    with_ac01.push_line(
        StatusLine::new("AC-00", "resumed", "smoke", Verdict::Pass, vec![artifact]).expect("PASS"),
    );
    with_ac01.push_line(
        StatusLine::new(
            "AC-01",
            "resumed too",
            "nondestructive",
            Verdict::Pass,
            vec![ac01_artifact],
        )
        .expect("PASS"),
    );
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    )
    .with_resume_binding(binding);
    assert_eq!(
        executor
            .set_resume(&with_ac01, &previous_dir)
            .expect("resume"),
        1,
        "exactly the non-self-test PASS is resumed"
    );
    assert_eq!(executor.resumed_ids(), vec!["AC-01".to_owned()]);
    let already_resumed = TestCheck::new("AC-01", Behaviour::PassWithEvidence);
    assert_eq!(
        executor.run_plan(&[&already_resumed]).await.err(),
        Some(PlanError::MissingSelfTest),
        "AC-00 is never resumed, so a plan without it cannot start even when AC-01 was resumed"
    );
}

/// A check whose PASS points at evidence somebody else wrote (review item S-6).
struct EvidenceReuseCheck {
    spec: CheckSpec,
    evidence: EvidenceRef,
}

impl Check for EvidenceReuseCheck {
    fn spec(&self) -> &CheckSpec {
        &self.spec
    }

    fn run<'a>(
        &'a self,
        _ctx: &'a CheckContext,
    ) -> Pin<Box<dyn Future<Output = CheckResult> + Send + 'a>> {
        Box::pin(async move { CheckResult::pass(vec![self.evidence.clone()]) })
    }
}

/// Review item S-6: the executor requires the evidence to have been written by THIS check in THIS run.
#[tokio::test]
async fn s6_evidence_from_another_check_or_run_is_refused() {
    use crate::report::EvidenceStore;
    let dir = temp_dir("runner-s6");
    let store = EvidenceStore::create(&dir).expect("store");
    let foreign = store
        .save_for(
            "AC-01",
            "some-other-run",
            "foreign.txt",
            b"foreign evidence",
        )
        .expect("save");
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    executor.set_evidence_store(store.clone());
    let check = EvidenceReuseCheck {
        spec: probe_spec("AC-02"),
        evidence: foreign,
    };
    let report = executor.run_one(&check).await;
    assert!(
        matches!(&report.line.verdict, Verdict::Fail { reason } if reason.contains("was not written by")),
        "{:?}",
        report.line.verdict
    );
    // A record for this check but another run is refused too.
    let other_run = store
        .save_for(
            "AC-03",
            "some-other-run",
            "other-run.txt",
            b"other run evidence",
        )
        .expect("save");
    let check = EvidenceReuseCheck {
        spec: probe_spec("AC-03"),
        evidence: other_run,
    };
    let report = executor.run_one(&check).await;
    assert!(
        matches!(&report.line.verdict, Verdict::Fail { reason } if reason.contains("was not written by")),
        "{:?}",
        report.line.verdict
    );
}

/// Review item S-10: a panic in `spec()` is caught and counted, and `run_plan` reports `PlanError::SpecPanicked`.
struct PanickingSpecCheck;

impl Check for PanickingSpecCheck {
    fn spec(&self) -> &CheckSpec {
        panic!("deliberate spec panic")
    }

    fn run<'a>(
        &'a self,
        _ctx: &'a CheckContext,
    ) -> Pin<Box<dyn Future<Output = CheckResult> + Send + 'a>> {
        Box::pin(async { CheckResult::fail("never runs") })
    }
}

#[tokio::test]
async fn s10_a_panicking_spec_is_caught_and_counted() {
    let dir = temp_dir("runner-s10-spec");
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let report = executor.run_one(&PanickingSpecCheck).await;
    assert!(
        matches!(report.line.verdict, Verdict::Fail { .. }),
        "{:?}",
        report.line.verdict
    );
    assert_eq!(executor.panics(), 1, "the spec panic is counted");
    assert_eq!(
        executor.run_plan(&[&PanickingSpecCheck]).await.err(),
        Some(PlanError::SpecPanicked)
    );
}

/// Review item S-10: `take_cleanup` releases the cleanup mutex before running the actions, so an action may lock the stack.
struct LockingCleanupCheck {
    spec: CheckSpec,
}

impl Check for LockingCleanupCheck {
    fn spec(&self) -> &CheckSpec {
        &self.spec
    }

    fn run<'a>(
        &'a self,
        ctx: &'a CheckContext,
    ) -> Pin<Box<dyn Future<Output = CheckResult> + Send + 'a>> {
        let cleanup = ctx.cleanup();
        Box::pin(async move {
            ctx.on_cleanup(
                "lock the cleanup stack from inside an action",
                Box::new(move || {
                    let _guard = cleanup.lock();
                }),
            );
            CheckResult::fail("registered a cleanup that locks the stack")
        })
    }
}

#[tokio::test]
async fn s10_cleanup_actions_run_without_holding_the_cleanup_mutex() {
    let dir = temp_dir("runner-s10-cleanup");
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    );
    let check = LockingCleanupCheck {
        spec: probe_spec("AC-04"),
    };
    let report = tokio::time::timeout(Duration::from_secs(5), executor.run_one(&check)).await;
    assert!(
        report.is_ok(),
        "take_cleanup must release the mutex before running the actions (review item S-10)"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Round-4 review items N-1 and N-7.
// ---------------------------------------------------------------------------------------------------------------

/// Review item N-1: the check that trips the latch ends FAIL("run invalid: ..."), even if it swallowed the denial.
#[tokio::test]
async fn n1_the_check_that_trips_the_latch_ends_fail_run_invalid() {
    let dir = temp_dir("runner-n1");
    let self_test = TestCheck::new("AC-00", Behaviour::PassWithEvidence);
    let swallowing = SwallowingCheck {
        spec: CheckSpec {
            id: "AC-01",
            title: "swallows a guard denial",
            requirements: NO_REQUIREMENTS,
            destructive: false,
            profile: LoadProfile::Functional,
            dependencies: NO_DEPS,
            timeout: Duration::from_secs(5),
            tier: "smoke",
        },
    };
    let mut executor = self::executor(
        &dir,
        Box::new(NeverSignals),
        LoadProfile::Functional,
        LifecycleStage::Pilot,
    )
    .with_runtime_facts(
        Arc::new(crate::test_support::allowlisted_resolver()),
        Arc::new(crate::inspect::FixedRevision::new("rev-1")),
        crate::control::Bannable::Bannable {
            runner: "198.51.100.77".parse().expect("runner ip"),
        },
    );
    let checks: Vec<&dyn Check> = vec![&self_test, &swallowing];
    let report = executor.run_plan(&checks).await.expect("plan");
    assert_eq!(report.abort, Some(AbortCause::RunInvalid));
    assert!(report.run_invalid);
    let line = report
        .lines
        .iter()
        .find(|line| line.id == "AC-01")
        .expect("AC-01 line");
    let reason = match &line.verdict {
        Verdict::Fail { reason } => reason.clone(),
        other => panic!("expected FAIL, got {other:?}"),
    };
    assert!(reason.starts_with("run invalid:"), "{reason}");
    assert!(reason.contains("target refused"), "{reason}");
}

/// A revision source for the empty-revision test.
struct EmptyRevision;

impl crate::inspect::RevisionSource for EmptyRevision {
    fn current_revision(&self) -> Result<String, String> {
        Err("control plane offline".to_owned())
    }
}

/// Review item N-7: `from_config` is the only builder, and every mismatch is a build error.
#[tokio::test]
async fn n7_from_config_refuses_mismatches() {
    let make_config = || {
        let mut config = crate::config::RunnerConfig::build(
            crate::test_support::profile(),
            TargetMode::Live,
            LoadProfile::Functional,
            None,
            "run-n7",
            None,
        )
        .expect("config");
        config.config_revision = "rev-1".to_owned();
        config
    };
    let facts = || RuntimeFacts {
        resolver: Arc::new(crate::test_support::allowlisted_resolver()),
        revision: Arc::new(crate::inspect::FixedRevision::new("rev-1")),
        runner: crate::control::Bannable::Bannable {
            runner: "198.51.100.77".parse().expect("runner ip"),
        },
    };
    let client = || {
        Box::new(crate::runner::NoInspectClient) as Box<dyn crate::inspect::InspectClient + Send>
    };

    // The limiter profile must match the run profile.
    let err = Executor::from_config(
        make_config(),
        kill_switch(&temp_dir("n7-kill")),
        limiter(LoadProfile::Lab),
        Box::new(NeverSignals),
        facts(),
        client(),
    )
    .expect_err("limiter mismatch");
    assert!(matches!(
        err,
        ExecutorBuildError::LimiterProfileMismatch { .. }
    ));

    // The lifecycle stage must match the configuration stage.
    let mut config = make_config();
    config.lifecycle = crate::config::LifecyclePolicy::new(LifecycleStage::Production, None);
    let err = Executor::from_config(
        config,
        kill_switch(&temp_dir("n7-kill2")),
        limiter(LoadProfile::Functional),
        Box::new(NeverSignals),
        facts(),
        client(),
    )
    .expect_err("stage mismatch");
    assert!(matches!(err, ExecutorBuildError::StageMismatch { .. }));

    // An empty configuration revision is refused.
    let mut config = make_config();
    config.config_revision.clear();
    let err = Executor::from_config(
        config,
        kill_switch(&temp_dir("n7-kill3")),
        limiter(LoadProfile::Functional),
        Box::new(NeverSignals),
        facts(),
        client(),
    )
    .expect_err("empty revision");
    assert_eq!(err, ExecutorBuildError::EmptyConfigRevision);

    // A revision source that disagrees with the configuration is refused.
    let bad_facts = RuntimeFacts {
        resolver: Arc::new(crate::test_support::allowlisted_resolver()),
        revision: Arc::new(crate::inspect::FixedRevision::new("rev-2")),
        runner: crate::control::Bannable::Bannable {
            runner: "198.51.100.77".parse().expect("runner ip"),
        },
    };
    let err = Executor::from_config(
        make_config(),
        kill_switch(&temp_dir("n7-kill4")),
        limiter(LoadProfile::Functional),
        Box::new(NeverSignals),
        bad_facts,
        client(),
    )
    .expect_err("revision mismatch");
    assert!(matches!(err, ExecutorBuildError::RevisionMismatch { .. }));

    // A readable, matching configuration builds the executor and binds its resume revision.
    let executor = Executor::from_config(
        make_config(),
        kill_switch(&temp_dir("n7-kill5")),
        limiter(LoadProfile::Functional),
        Box::new(NeverSignals),
        facts(),
        client(),
    )
    .expect("a matching configuration builds");
    assert!(format!("{executor:?}").contains("run-n7"));
    // The empty-revision source is reported as unavailable.
    let err = Executor::from_config(
        make_config(),
        kill_switch(&temp_dir("n7-kill6")),
        limiter(LoadProfile::Functional),
        Box::new(NeverSignals),
        RuntimeFacts {
            resolver: Arc::new(crate::test_support::allowlisted_resolver()),
            revision: Arc::new(EmptyRevision),
            runner: crate::control::Bannable::Bannable {
                runner: "198.51.100.77".parse().expect("runner ip"),
            },
        },
        client(),
    )
    .expect_err("unreadable revision");
    assert!(matches!(
        err,
        ExecutorBuildError::RevisionUnavailable { .. }
    ));
}
