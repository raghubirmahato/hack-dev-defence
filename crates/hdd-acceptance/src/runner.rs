//! The check framework: the [`Check`] trait, dependency ordering, the `finally` cleanup stack, the per-check timeout, and
//! abort handling for the kill switch and SIGINT/SIGTERM (sections 2.3, 2.4, 2.8 step 5; E3.1).
//!
//! Every check runs behind five controls:
//!
//! * the rate budget: the run's one shared [limiter](crate::limits::Limiter) plus a limiter at the check's own (never higher)
//!   profile (review items A-2 and A-3);
//! * the `CheckSpec.destructive` gate: `production` refuses a destructive check before its body runs, with
//!   `UNVERIFIED(stage_forbids)` (A-3);
//! * one persistent, latched signal listener shared by the whole run, consulted before every check (A-9);
//! * the [kill switch](hdd_common::egress::KillSwitch), watched by [`hdd_common::egress::KillSwitch::tripped`], which aborts a
//!   running check within one second (A3) and marks the run `UNVERIFIED(skipped_by_operator)` per spec 2.8 step 5 (A-8);
//! * the per-check timeout, which fails **that check only** and never aborts the run (A-8).
//!
//! Whatever ends the check — success, failure, panic, timeout, signal or kill switch — the cleanup stack is drained LIFO
//! before the status line is produced, so a ban, a temporary firewall rule or a partial record cannot survive a stop.

use std::fmt;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use hdd_common::egress::resolver::Resolver;
use hdd_common::egress::{KillSwitch, TargetMode};
use hdd_common::kv::clock::Clock;
use hdd_common::profile::Profile;
use hdd_common::profile::types::LifecycleStage;

use crate::config::{LifecyclePolicy, RunnerConfig};
use crate::control::Bannable;
use crate::guard::{Connector, ConnectorParts};
use crate::inspect::{
    InspectClient, InspectClientError, InspectGate, InspectGateError, InspectRequest,
    InspectResponse, InspectTicket, RevisionSource,
};
use crate::limits::{Lane, LimitDenial, Limiter, LoadProfile, RateBudget};
use crate::report::{EvidenceStore, Report, ReportError, RunBinding};
use crate::status::{EvidenceRef, ReasonCode, StatusLine, Verdict};

/// A signal that stops a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownSignal {
    /// SIGINT / Ctrl-C.
    Interrupt,
    /// SIGTERM (Unix only; a Windows console close is reported as an interrupt).
    Terminate,
}

impl fmt::Display for ShutdownSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShutdownSignal::Interrupt => f.write_str("interrupt (SIGINT/Ctrl-C)"),
            ShutdownSignal::Terminate => f.write_str("termination (SIGTERM)"),
        }
    }
}

/// Where a [`ShutdownSignal`] comes from. The source is consumed exactly once by [`Executor`], which keeps **one** listener for
/// the whole run: a signal arriving between checks is not lost (review item A-9). Production uses [`Signals`]; tests use their
/// own source, because a test must not depend on the console of the machine running it.
pub trait SignalSource: Send {
    /// Start the one listener that resolves with the next stop request.
    fn listen(self: Box<Self>) -> Pin<Box<dyn Future<Output = ShutdownSignal> + Send>>;
}

fn pending_signal() -> Pin<Box<dyn Future<Output = ShutdownSignal> + Send>> {
    Box::pin(std::future::pending())
}

/// Poll the signal listener once at construction so the OS-level handler is registered before the first check starts
/// (review item R-9). The first poll of `tokio::signal::ctrl_c` is what installs the handler; polling with a no-op waker
/// leaves the future pending and a later real waker still receives the signal. Outside a Tokio runtime the poll is skipped
/// (a signal cannot be delivered to a run that has not started its runtime yet).
fn prime_signal(
    listener: Pin<&mut (dyn Future<Output = ShutdownSignal> + Send)>,
) -> Option<ShutdownSignal> {
    if tokio::runtime::Handle::try_current().is_err() {
        return None;
    }
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    match listener.poll(&mut context) {
        Poll::Ready(signal) => Some(signal),
        Poll::Pending => None,
    }
}

/// The real signal source: `ctrl_c` on every platform, plus SIGTERM on Unix.
#[derive(Debug, Default)]
pub struct Signals;

impl SignalSource for Signals {
    fn listen(self: Box<Self>) -> Pin<Box<dyn Future<Output = ShutdownSignal> + Send>> {
        Box::pin(async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal};
                match signal(SignalKind::terminate()) {
                    Ok(mut term) => {
                        tokio::select! {
                            result = tokio::signal::ctrl_c() => {
                                let _ = result;
                                ShutdownSignal::Interrupt
                            }
                            _ = term.recv() => ShutdownSignal::Terminate,
                        }
                    }
                    Err(_) => {
                        let _ = tokio::signal::ctrl_c().await;
                        ShutdownSignal::Interrupt
                    }
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
                ShutdownSignal::Interrupt
            }
        })
    }
}

/// What ended a check early or the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortCause {
    /// The kill-switch file is present.
    KillSwitch,
    /// An operator signal arrived.
    Signal(ShutdownSignal),
    /// The AC-00 safety self-test failed: the rest of the run is not allowed to start.
    SelfTestFailed,
    /// A safety-envelope denial latched `run_invalid`: the rest of the run must not send (review item S-8).
    RunInvalid,
}

impl fmt::Display for AbortCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbortCause::KillSwitch => f.write_str("kill-switch file present"),
            AbortCause::Signal(signal) => write!(f, "operator signal: {signal}"),
            AbortCause::SelfTestFailed => f.write_str("the AC-00 safety self-test failed"),
            AbortCause::RunInvalid => f.write_str(
                "a safety-envelope denial marked the run invalid; the remaining checks could send, so the run stops",
            ),
        }
    }
}

/// The run's latched abort state: set by the kill switch or an operator signal, read by the executor before every check and
/// by the connector before every send (review item A-9).
#[derive(Debug)]
pub struct AbortLatch {
    tripped: AtomicBool,
    cause: Mutex<Option<AbortCause>>,
}

impl AbortLatch {
    /// An unset latch (crate-internal: only the executor builds it; the `Default` derive is removed so a check body cannot
    /// construct one, review item S-6).
    pub(crate) fn new() -> AbortLatch {
        AbortLatch {
            tripped: AtomicBool::new(false),
            cause: Mutex::new(None),
        }
    }

    /// Latch the run's abort cause (the first cause wins).
    pub fn trip(&self, cause: AbortCause) {
        let mut stored = match self.cause.lock() {
            Ok(stored) => stored,
            Err(poisoned) => poisoned.into_inner(),
        };
        if stored.is_none() {
            *stored = Some(cause);
        }
        self.tripped.store(true, Ordering::SeqCst);
    }

    /// True when the run has been aborted.
    pub fn is_tripped(&self) -> bool {
        self.tripped.load(Ordering::SeqCst)
    }

    /// The abort cause when the run has been aborted.
    pub fn check(&self) -> Result<(), AbortCause> {
        if !self.is_tripped() {
            return Ok(());
        }
        let stored = match self.cause.lock() {
            Ok(stored) => stored,
            Err(poisoned) => poisoned.into_inner(),
        };
        Err(stored.unwrap_or(AbortCause::KillSwitch))
    }
}

/// One recorded safety-envelope denial (review item N-1): which check, in which run, and the denial text. The report names the
/// check so a human can see which one tripped the latch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunInvalidRecord {
    /// The check whose connector tripped the latch.
    pub check_id: String,
    /// The run the check belongs to.
    pub run_id: String,
    /// The denial text.
    pub detail: String,
}

/// The run-invalid latch (review items R-8, S-8 and N-1): a safety-envelope denial marks the run invalid, records the audit
/// record (check id, run id, denial), and the report says so. The `Default` derive is removed so a check body cannot
/// construct one (review item S-6).
#[derive(Debug)]
pub struct RunInvalidLatch {
    tripped: AtomicBool,
    records: Mutex<Vec<RunInvalidRecord>>,
}

impl RunInvalidLatch {
    /// An unset latch (crate-internal: only the executor builds it).
    pub(crate) fn new() -> RunInvalidLatch {
        RunInvalidLatch {
            tripped: AtomicBool::new(false),
            records: Mutex::new(Vec::new()),
        }
    }

    /// Record a safety-envelope denial and latch the run invalid (review item N-1: the record names the check and the run).
    pub fn record(&self, check_id: &str, run_id: &str, detail: &str) {
        self.tripped.store(true, Ordering::SeqCst);
        let mut records = match self.records.lock() {
            Ok(records) => records,
            Err(poisoned) => poisoned.into_inner(),
        };
        records.push(RunInvalidRecord {
            check_id: check_id.to_owned(),
            run_id: run_id.to_owned(),
            detail: detail.to_owned(),
        });
    }

    /// True when a guard denial has marked the run invalid.
    pub fn is_invalid(&self) -> bool {
        self.tripped.load(Ordering::SeqCst)
    }

    /// The first record (the denial that tripped the latch), if any.
    pub fn first_record(&self) -> Option<RunInvalidRecord> {
        match self.records.lock() {
            Ok(records) => records.first().cloned(),
            Err(poisoned) => poisoned.into_inner().first().cloned(),
        }
    }

    /// Every record, in order.
    pub fn records(&self) -> Vec<RunInvalidRecord> {
        match self.records.lock() {
            Ok(records) => records.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Test-only: clear the latch so independent probes in one test do not see another probe's denial (the production
    /// path never resets it).
    #[cfg(test)]
    pub(crate) fn reset(&self) {
        self.tripped.store(false, Ordering::SeqCst);
        let mut records = match self.records.lock() {
            Ok(records) => records,
            Err(poisoned) => poisoned.into_inner(),
        };
        records.clear();
    }

    /// The human audit lines (`check <id> in run <id>`), for reports.
    pub fn audit(&self) -> Vec<String> {
        self.records()
            .into_iter()
            .map(|record| {
                format!(
                    "check {} in run {}: {}",
                    record.check_id, record.run_id, record.detail
                )
            })
            .collect()
    }
}

/// What one check achieved before it stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    /// The check ran to completion and returned a result.
    Completed(CheckResult),
    /// The check panicked; the panic is caught, counted and turned into a FAIL (R-09).
    Panicked {
        /// Panic message, if the payload had one.
        message: String,
    },
    /// The kill switch or a signal stopped the check.
    Aborted(AbortCause),
    /// The check's own timeout elapsed; this fails the check only and does not abort the run (review item A-8).
    TimedOut {
        /// The timeout that elapsed.
        after: Duration,
    },
}

/// The result a check returns when it completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
    /// Passed, backed by at least one hashed evidence artifact.
    Pass {
        /// Evidence artifacts.
        evidence: Vec<EvidenceRef>,
    },
    /// Failed, with a short reason.
    Fail {
        /// What failed.
        reason: String,
    },
    /// Could not be decided, with a closed reason code.
    Unverified {
        /// The reason.
        reason: ReasonCode,
    },
}

impl CheckResult {
    /// A PASS with evidence.
    pub fn pass(evidence: Vec<EvidenceRef>) -> CheckResult {
        CheckResult::Pass { evidence }
    }

    /// A FAIL with a reason.
    pub fn fail(reason: impl Into<String>) -> CheckResult {
        CheckResult::Fail {
            reason: reason.into(),
        }
    }

    /// An UNVERIFIED with a closed reason code.
    pub fn unverified(reason: ReasonCode) -> CheckResult {
        CheckResult::Unverified { reason }
    }
}

/// The static metadata of a check (E3.5, T-0491 step 1 subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckSpec {
    /// `AC-nn` whole token.
    pub id: &'static str,
    /// Title from Appendix E3.
    pub title: &'static str,
    /// Requirement ids the check traces to (R-07).
    pub requirements: &'static [&'static str],
    /// True when the check can change state (bans, resilience, chaos, load); refused in `production` without approval.
    pub destructive: bool,
    /// The rate/load profile the check may use; it may not exceed the run's profile.
    pub profile: LoadProfile,
    /// Ids of checks that must pass before this one runs; otherwise the result is
    /// `UNVERIFIED(stage_not_reached)` with a detail naming the dependency.
    pub dependencies: &'static [&'static str],
    /// Per-check timeout. A timeout fails this check only.
    pub timeout: Duration,
    /// Suite tier of E3.2.
    pub tier: &'static str,
}

impl CheckSpec {
    /// Validate the spec on its own: a whole-token id and a non-zero timeout.
    pub fn validate(&self) -> Result<(), PlanError> {
        if !crate::status::is_check_id(self.id) {
            return Err(PlanError::BadId {
                id: self.id.to_owned(),
            });
        }
        if self.timeout.is_zero() {
            return Err(PlanError::ZeroTimeout {
                id: self.id.to_owned(),
            });
        }
        Ok(())
    }
}

/// A check: static metadata plus one async body. Implementations live in later tasks; the skeleton ships none, so a dry run
/// cannot accidentally execute a live check.
pub trait Check: Send + Sync {
    /// The static metadata.
    fn spec(&self) -> &CheckSpec;

    /// Run the check. The body must not send anything that did not pass
    /// [`crate::guard::Connector::prepare`].
    fn run<'a>(
        &'a self,
        ctx: &'a CheckContext,
    ) -> Pin<Box<dyn Future<Output = CheckResult> + Send + 'a>>;
}

/// What a running check may use. The rate budget, the abort latch, the validated profile, the inspect gate and the evidence
/// store are shared with the rest of the run; a check receives this context and cannot replace any of them (review items
/// S-1, S-2, S-6).
pub struct CheckContext {
    /// Live or lab.
    pub mode: TargetMode,
    /// Lifecycle stage of the profile.
    pub stage: LifecycleStage,
    /// Rate/load profile of the run.
    pub run_profile: LoadProfile,
    destructive: bool,
    lifecycle: LifecyclePolicy,
    /// The validated profile the executor was given; a check cannot substitute another (review item S-1).
    profile: Arc<Profile>,
    budget: Arc<Mutex<RateBudget>>,
    cleanup: Arc<Mutex<CleanupStack>>,
    abort: Arc<AbortLatch>,
    kill: KillSwitch,
    resolver: Arc<dyn Resolver>,
    runner: Bannable,
    revision: Arc<dyn RevisionSource>,
    invalid: Arc<RunInvalidLatch>,
    run_id: String,
    check_id: String,
    /// The run's one inspect gate, owned by the executor (review item S-2).
    inspect: Arc<Mutex<InspectGate<Box<dyn InspectClient + Send>>>>,
    /// The run's evidence store, when the executor was given one (review item S-6).
    evidence_store: Option<EvidenceStore>,
}

impl CheckContext {
    /// A context over the run's budget, abort latch and cleanup stack. Crate-internal: the executor builds it from the run's
    /// shared state, so a check body cannot forge the destructive flag, a fresh latch, a fresh limiter or a profile
    /// (review items R-3 and S-1). The guarantee is against a check written by us that makes a mistake; Rust privacy is not
    /// a security boundary against code compiled into this crate.
    #[allow(
        clippy::too_many_arguments,
        reason = "the context is the run's shared state"
    )]
    pub(crate) fn new(
        mode: TargetMode,
        stage: LifecycleStage,
        run_profile: LoadProfile,
        destructive: bool,
        lifecycle: LifecyclePolicy,
        profile: Arc<Profile>,
        budget: Arc<Mutex<RateBudget>>,
        cleanup: Arc<Mutex<CleanupStack>>,
        abort: Arc<AbortLatch>,
        kill: KillSwitch,
        resolver: Arc<dyn Resolver>,
        runner: Bannable,
        revision: Arc<dyn RevisionSource>,
        invalid: Arc<RunInvalidLatch>,
        run_id: impl Into<String>,
        check_id: impl Into<String>,
        inspect: Arc<Mutex<InspectGate<Box<dyn InspectClient + Send>>>>,
        evidence_store: Option<EvidenceStore>,
    ) -> CheckContext {
        CheckContext {
            mode,
            stage,
            run_profile,
            destructive,
            lifecycle,
            profile,
            budget,
            cleanup,
            abort,
            kill,
            resolver,
            runner,
            revision,
            invalid,
            run_id: run_id.into(),
            check_id: check_id.into(),
            inspect,
            evidence_store,
        }
    }

    /// Take from the shared + check-level budget. A poisoned budget fails closed.
    pub fn acquire(&self, lane: Lane, cost: u64) -> Result<(), LimitDenial> {
        match self.budget.lock() {
            Ok(mut budget) => budget.acquire(lane, cost),
            Err(_) => Err(LimitDenial::Locked),
        }
    }

    /// The budget handle, so a check can build its [`crate::guard::Connector`] from the same limiter (review item A-2).
    pub fn budget(&self) -> Arc<Mutex<RateBudget>> {
        Arc::clone(&self.budget)
    }

    /// The run's abort latch, shared with the connector.
    pub fn abort(&self) -> Arc<AbortLatch> {
        Arc::clone(&self.abort)
    }

    /// The run's kill switch.
    pub fn kill(&self) -> KillSwitch {
        self.kill.clone()
    }

    /// True when the owning check's `CheckSpec.destructive` is set (never chosen by the check body).
    pub fn destructive(&self) -> bool {
        self.destructive
    }

    /// The id of the running check, as the evidence store records it (review item S-6).
    pub fn check_id(&self) -> &str {
        &self.check_id
    }

    /// Save an evidence artifact for **this check in this run** and return its reference (review items S-6). The store
    /// records `(check id, run id, name, hash)` and the executor refuses a PASS backed by any other record.
    pub fn save_evidence(&self, name: &str, bytes: &[u8]) -> std::io::Result<EvidenceRef> {
        let store = self.evidence_store.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "the executor was not given an evidence store",
            )
        })?;
        store.save_for(&self.check_id, &self.run_id, name, bytes)
    }

    /// Ask the control plane whether this request would be blocked, through the run's one inspect gate (review item S-2).
    /// A check cannot mint a ticket any other way: the gate and its client are created by the executor.
    pub fn inspect(&self, request: &InspectRequest) -> Result<InspectTicket, InspectGateError> {
        let mut gate = match self.inspect.lock() {
            Ok(gate) => gate,
            Err(poisoned) => poisoned.into_inner(),
        };
        gate.check(request)
    }

    /// The run's cleanup stack handle (review item S-10: cleanup actions may run without the executor holding the mutex).
    pub fn cleanup(&self) -> Arc<Mutex<CleanupStack>> {
        Arc::clone(&self.cleanup)
    }

    /// Register a `finally` action (unban, remove a temporary rule or record). Actions run LIFO even when the check fails,
    /// panics, times out, is interrupted or is stopped by the kill switch.
    pub fn on_cleanup(&self, description: impl Into<String>, action: Box<dyn FnOnce() + Send>) {
        let mut stack = match self.cleanup.lock() {
            Ok(stack) => stack,
            Err(poisoned) => poisoned.into_inner(),
        };
        stack.push(description, action);
    }
}

impl CheckContext {
    /// Build the connector for this check from the run's shared state. The validated profile comes from the executor
    /// (review item S-1); a check body cannot pass a profile of its own. Crate-internal construction: outside code cannot build
    /// the connector parts; the executor supplies the destructive flag, budget, abort latch, resolver, runner state and
    /// revision source. `expected_revision` is the ticket revision this run planned against.
    pub fn connector(
        &self,
        expected_revision: &str,
    ) -> Result<Connector, crate::guard::ConnectorError> {
        Connector::new(
            &self.profile,
            ConnectorParts {
                mode: self.mode,
                load_profile: self.run_profile,
                lifecycle: self.lifecycle.clone(),
                destructive: self.destructive,
                kill: self.kill.clone(),
                abort: Arc::clone(&self.abort),
                budget: Arc::clone(&self.budget),
                resolver: Arc::clone(&self.resolver),
                runner: self.runner,
                expected_revision: expected_revision.to_owned(),
                revision: Arc::clone(&self.revision),
                run_invalid: Arc::clone(&self.invalid),
                run_id: self.run_id.clone(),
                check_id: self.check_id.clone(),
                request_ttl: std::time::Duration::from_millis(500),
            },
        )
    }
}

/// The inspect client the executor starts with: it refuses every request, so an executor that was not given a real client
/// fails closed instead of inspecting anything (review item S-2).
pub(crate) struct NoInspectClient;

impl InspectClient for NoInspectClient {
    fn inspect(
        &mut self,
        _request: &InspectRequest,
    ) -> Result<InspectResponse, InspectClientError> {
        Err(InspectClientError::Transport {
            message: "no inspect client supplied to the executor".to_owned(),
        })
    }
}

/// A resolver that refuses every name: the fail-closed default until the executor is given real runtime facts.
struct NoResolver;

impl Resolver for NoResolver {
    fn resolve<'a>(
        &'a self,
        _host: &'a str,
    ) -> hdd_common::egress::resolver::BoxFuture<
        'a,
        std::io::Result<hdd_common::egress::resolver::Resolution>,
    > {
        Box::pin(async {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no resolver supplied to the executor",
            ))
        })
    }
}

/// A revision source that cannot answer: the fail-closed default until the executor is given real runtime facts.
struct NoRevision;

impl RevisionSource for NoRevision {
    fn current_revision(&self) -> Result<String, String> {
        Err("no revision source supplied to the executor".to_owned())
    }
}

/// One registered cleanup action.
struct CleanupAction {
    description: String,
    action: Box<dyn FnOnce() + Send>,
}

/// A record of one cleanup action that ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupRecord {
    /// What was undone (for example `unban 198.51.100.7`).
    pub description: String,
}

/// The `finally` stack. Actions run last-in, first-out: the most recent change is undone first.
#[derive(Default)]
pub struct CleanupStack {
    actions: Vec<CleanupAction>,
}

impl fmt::Debug for CleanupStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CleanupStack")
            .field("pending", &self.actions.len())
            .finish()
    }
}

impl CleanupStack {
    /// An empty stack.
    pub fn new() -> CleanupStack {
        CleanupStack::default()
    }

    /// Push an action.
    pub fn push(&mut self, description: impl Into<String>, action: Box<dyn FnOnce() + Send>) {
        self.actions.push(CleanupAction {
            description: description.into(),
            action,
        });
    }

    /// Number of pending actions.
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// True when nothing is pending.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Run every pending action LIFO and record what ran. An action that panics does not stop the others: the panic is caught
    /// and the remaining actions still run (a cleanup must not abort the cleanup).
    pub fn run_all(&mut self) -> Vec<CleanupRecord> {
        let mut records = Vec::with_capacity(self.actions.len());
        while let Some(entry) = self.actions.pop() {
            let description = entry.description;
            let result = std::panic::catch_unwind(AssertUnwindSafe(entry.action));
            let suffix = if result.is_err() {
                " (cleanup action panicked; recorded)"
            } else {
                ""
            };
            records.push(CleanupRecord {
                description: format!("{description}{suffix}"),
            });
        }
        records
    }
}

/// Why a plan cannot be executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// A dependency names a check that is not in the plan.
    UnknownDependency {
        /// The dependent check.
        check: String,
        /// The missing dependency.
        dependency: String,
    },
    /// The dependencies contain a cycle.
    Cycle {
        /// The checks in the cycle.
        ids: Vec<String>,
    },
    /// Two checks share an id.
    DuplicateId {
        /// The duplicated id.
        id: String,
    },
    /// An id is not an `AC-nn` whole token.
    BadId {
        /// The offending id.
        id: String,
    },
    /// A check has a zero timeout.
    ZeroTimeout {
        /// The offending id.
        id: String,
    },
    /// The plan has no AC-00 safety self-test, so the run cannot start (review item R-8).
    MissingSelfTest,
    /// A check's `spec()` panicked while the plan was being built (review item S-10): check code is not trusted to be
    /// panic-free, and building the plan must not unwind the executor.
    SpecPanicked,
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanError::UnknownDependency { check, dependency } => write!(
                f,
                "check {check} depends on {dependency}, which is not in the plan"
            ),
            PlanError::Cycle { ids } => write!(f, "dependency cycle between {ids:?}"),
            PlanError::DuplicateId { id } => write!(f, "check id `{id}` appears twice"),
            PlanError::BadId { id } => write!(f, "`{id}` is not an AC-nn check id"),
            PlanError::ZeroTimeout { id } => write!(f, "check {id} has a zero timeout"),
            PlanError::MissingSelfTest => f.write_str(
                "the plan has no AC-00 safety self-test; the acceptance run may not start without its self-test (review \
                 item R-8)",
            ),
            PlanError::SpecPanicked => f.write_str(
                "a check's spec() panicked while the plan was built, so the plan cannot be trusted (review item S-10)",
            ),
        }
    }
}

impl std::error::Error for PlanError {}

/// Read a check's static spec, catching a panic from check code (review item S-10). Check bodies are not trusted to be
/// panic-free; the executor's own calls into a check must be guarded too.
fn spec_or_panic(check: &dyn Check) -> Result<&CheckSpec, String> {
    match std::panic::catch_unwind(AssertUnwindSafe(|| check.spec())) {
        Ok(spec) => Ok(spec),
        Err(payload) => Err(panic_message(&*payload)),
    }
}

/// Order checks so that every dependency runs first. Ties keep the input order, so the plan is deterministic.
pub fn order(checks: &[&dyn Check]) -> Result<Vec<usize>, PlanError> {
    order_with_satisfied(checks, &[])
}

/// Order checks so that every dependency runs first, treating the ids in `satisfied` (PASS lines resumed from a previous
/// run) as already executed (review item R-2). A dependency outside the plan is accepted when it is satisfied, so a resumed
/// plan does not fail with `UnknownDependency` or re-send traffic. Ties keep the input order.
pub fn order_with_satisfied(
    checks: &[&dyn Check],
    satisfied: &[String],
) -> Result<Vec<usize>, PlanError> {
    let mut specs: Vec<&CheckSpec> = Vec::with_capacity(checks.len());
    for check in checks {
        specs.push(spec_or_panic(*check).map_err(|_| PlanError::SpecPanicked)?);
    }
    let mut ids: Vec<&str> = Vec::with_capacity(specs.len());
    for spec in &specs {
        spec.validate()?;
        if ids.contains(&spec.id) {
            return Err(PlanError::DuplicateId {
                id: spec.id.to_owned(),
            });
        }
        ids.push(spec.id);
    }
    for spec in &specs {
        for dependency in spec.dependencies {
            if !ids.contains(dependency) && !satisfied.iter().any(|id| id == dependency) {
                return Err(PlanError::UnknownDependency {
                    check: spec.id.to_owned(),
                    dependency: (*dependency).to_owned(),
                });
            }
        }
    }
    let mut scheduled: Vec<usize> = Vec::with_capacity(specs.len());
    let mut remaining: Vec<usize> = (0..specs.len()).collect();
    while !remaining.is_empty() {
        let mut picked = None;
        for (position, index) in remaining.iter().enumerate() {
            let spec = specs.get(*index).ok_or(PlanError::BadId {
                id: "<index>".to_owned(),
            })?;
            let ready = spec.dependencies.iter().all(|dependency| {
                satisfied.iter().any(|id| id == dependency)
                    || scheduled
                        .iter()
                        .filter_map(|scheduled_index| specs.get(*scheduled_index))
                        .any(|scheduled_spec| scheduled_spec.id == *dependency)
            });
            if ready {
                picked = Some((position, *index));
                break;
            }
        }
        match picked {
            Some((position, index)) => {
                remaining.remove(position);
                scheduled.push(index);
            }
            None => {
                return Err(PlanError::Cycle {
                    ids: remaining
                        .iter()
                        .filter_map(|index| specs.get(*index).map(|s| s.id.to_owned()))
                        .collect(),
                });
            }
        }
    }
    Ok(scheduled)
}

/// One check's execution record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    /// The status line (always produced).
    pub line: StatusLine,
    /// Cleanup actions that ran, in execution order.
    pub cleanup: Vec<CleanupRecord>,
    /// What aborted the **run** (kill switch or signal), if anything. A timeout is not a run abort (review item A-8).
    pub abort: Option<AbortCause>,
}

/// The result of a full sequential run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    /// One line per planned check.
    pub lines: Vec<StatusLine>,
    /// Cleanup actions that ran, in execution order.
    pub cleanup: Vec<CleanupRecord>,
    /// What ended the run early, if anything.
    pub abort: Option<AbortCause>,
    /// Number of caught panics in the run (R-09: counted and reported, never hidden).
    pub panics: u32,
    /// True when a guard denial of class target or stage marked the run invalid (review item R-8).
    pub run_invalid: bool,
    /// The audit lines of those guard denials (review item R-8); each names the check and the run (review item N-1).
    pub invalid_audit: Vec<String>,
    /// The structured invalid-run records, for a report that must name the offending check (review item N-1).
    pub invalid_records: Vec<RunInvalidRecord>,
}

/// Runs checks one at a time with every control in force.
pub struct Executor {
    kill: KillSwitch,
    shared: Arc<Mutex<Limiter>>,
    clock: Arc<dyn Clock>,
    latch: Arc<AbortLatch>,
    signal: Option<Pin<Box<dyn Future<Output = ShutdownSignal> + Send>>>,
    signal_latched: Option<ShutdownSignal>,
    cleanup: Arc<Mutex<CleanupStack>>,
    mode: TargetMode,
    stage: LifecycleStage,
    run_profile: LoadProfile,
    lifecycle: LifecyclePolicy,
    run_id: String,
    /// The validated profile this executor runs against; the check context can only use this one (review item S-1).
    profile: Arc<Profile>,
    resolver: Arc<dyn Resolver>,
    runner: Bannable,
    revision: Arc<dyn RevisionSource>,
    invalid: Arc<RunInvalidLatch>,
    evidence_root: Option<PathBuf>,
    evidence_store: Option<EvidenceStore>,
    /// The one inspect gate of the run, owned by the executor and shared with every check (review item S-2).
    inspect: Arc<Mutex<InspectGate<Box<dyn InspectClient + Send>>>>,
    /// The report binding a resume must match, when one was supplied (review item S-5).
    resume_binding: Option<RunBinding>,
    resumed: Vec<StatusLine>,
    panics: u32,
}

impl fmt::Debug for Executor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Executor")
            .field("mode", &self.mode)
            .field("stage", &self.stage)
            .field("run_profile", &self.run_profile)
            .field("run_id", &self.run_id)
            .field("panics", &self.panics)
            .field("run_invalid", &self.invalid.is_invalid())
            .finish_non_exhaustive()
    }
}

/// The runtime facts an executor needs beyond the validated configuration (review item N-7).
pub struct RuntimeFacts {
    /// The resolver used for the per-hop target validation.
    pub resolver: Arc<dyn Resolver>,
    /// The current-revision source, re-read at send time.
    pub revision: Arc<dyn RevisionSource>,
    /// Whether the runner IP is known to be bannable.
    pub runner: Bannable,
}

/// Why an executor could not be built from a [`RunnerConfig`] (review item N-7: every mismatch is a build error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutorBuildError {
    /// The limiter was built for another rate/load profile than the run's.
    LimiterProfileMismatch {
        /// The limiter's profile.
        limiter: LoadProfile,
        /// The configuration's run profile.
        run: LoadProfile,
    },
    /// The lifecycle policy's stage differs from the configuration's stage.
    StageMismatch {
        /// The lifecycle policy's stage.
        lifecycle: LifecycleStage,
        /// The configuration's stage.
        config: LifecycleStage,
    },
    /// The configuration carries no `config_revision`, so no gate revision can be derived.
    EmptyConfigRevision,
    /// The revision source could not report the current revision.
    RevisionUnavailable {
        /// Why.
        detail: String,
    },
    /// The revision source reports another revision than the one the configuration planned against.
    RevisionMismatch {
        /// The configuration revision.
        config: String,
        /// The revision source's answer.
        source: String,
    },
}

impl fmt::Display for ExecutorBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutorBuildError::LimiterProfileMismatch { limiter, run } => write!(
                f,
                "the limiter profile `{limiter}` does not match the run profile `{run}`"
            ),
            ExecutorBuildError::StageMismatch { lifecycle, config } => write!(
                f,
                "the lifecycle policy stage `{lifecycle:?}` does not match the configuration stage `{config:?}`"
            ),
            ExecutorBuildError::EmptyConfigRevision => {
                f.write_str("the run configuration has no config_revision")
            }
            ExecutorBuildError::RevisionUnavailable { detail } => {
                write!(f, "cannot read the current config_revision: {detail}")
            }
            ExecutorBuildError::RevisionMismatch { config, source } => write!(
                f,
                "the revision source reports `{source}` but the configuration planned against `{config}`"
            ),
        }
    }
}

impl std::error::Error for ExecutorBuildError {}

/// The `live`/`lab` name used in the report binding.
fn target_mode_name(mode: TargetMode) -> &'static str {
    match mode {
        TargetMode::Live => "live",
        TargetMode::Lab => "lab",
    }
}

impl Executor {
    /// An executor with an injected signal source (tests; a caller may also supply one for a non-interactive service).
    ///
    /// The signal listener is primed here, in the constructor: the first poll of a `ctrl_c` future is what registers the
    /// handler with the operating system, so waiting until the first check would let a signal in that window reach the
    /// default handler and kill the process without cleanup (review item R-9).
    pub(crate) fn with_signals(
        kill: KillSwitch,
        limiter: Limiter,
        mode: TargetMode,
        stage: LifecycleStage,
        run_profile: LoadProfile,
        signals: Box<dyn SignalSource>,
    ) -> Executor {
        let clock = limiter.clock();
        let shared = Arc::new(Mutex::new(limiter));
        let mut signal = Some(signals.listen());
        let mut signal_latched = None;
        if let Some(listener) = signal.as_mut()
            && let Some(ready) = prime_signal(listener.as_mut())
        {
            signal_latched = Some(ready);
            signal = None;
        }
        Executor {
            kill,
            shared,
            clock,
            latch: Arc::new(AbortLatch::new()),
            signal,
            signal_latched,
            cleanup: Arc::new(Mutex::new(CleanupStack::new())),
            mode,
            stage,
            run_profile,
            lifecycle: LifecyclePolicy::new(stage, None),
            run_id: String::new(),
            // Fail closed: an empty profile has no allowlisted host, so a connector built from it refuses every target.
            profile: Arc::new(Profile::default()),
            resolver: Arc::new(NoResolver),
            runner: Bannable::Unverified {
                reason: ReasonCode::CapabilityNotSupplied,
            },
            revision: Arc::new(NoRevision),
            invalid: Arc::new(RunInvalidLatch::new()),
            evidence_root: None,
            evidence_store: None,
            inspect: Arc::new(Mutex::new(InspectGate::new(
                Box::new(NoInspectClient) as Box<dyn InspectClient + Send>,
                String::new(),
            ))),
            resume_binding: None,
            resumed: Vec::new(),
            panics: 0,
        }
    }

    /// Build the run's executor from the validated [`RunnerConfig`] (review item N-7). This is the **only public way** to
    /// build an executor: the profile, mode, stage, load profile, run id, lifecycle policy, gate revision, revision source
    /// binding and resume binding all come from the configuration in one place, so a resumed run cannot be bound to one
    /// revision while executing against another.
    ///
    /// Refuses a limiter whose profile differs from the run's profile, a lifecycle policy whose stage differs from the
    /// configuration's stage, an empty configuration revision and a revision source that cannot confirm the configured
    /// revision.
    #[allow(
        clippy::too_many_arguments,
        reason = "the run's whole runtime input is assembled here in one place"
    )]
    pub fn from_config(
        config: RunnerConfig,
        kill: KillSwitch,
        limiter: Limiter,
        signals: Box<dyn SignalSource>,
        facts: RuntimeFacts,
        inspect_client: Box<dyn InspectClient + Send>,
    ) -> Result<Executor, ExecutorBuildError> {
        if limiter.profile() != config.load_profile {
            return Err(ExecutorBuildError::LimiterProfileMismatch {
                limiter: limiter.profile(),
                run: config.load_profile,
            });
        }
        if config.lifecycle.stage() != config.stage {
            return Err(ExecutorBuildError::StageMismatch {
                lifecycle: config.lifecycle.stage(),
                config: config.stage,
            });
        }
        if config.config_revision.trim().is_empty() {
            return Err(ExecutorBuildError::EmptyConfigRevision);
        }
        let observed = facts
            .revision
            .current_revision()
            .map_err(|detail| ExecutorBuildError::RevisionUnavailable { detail })?;
        if observed != config.config_revision {
            return Err(ExecutorBuildError::RevisionMismatch {
                config: config.config_revision,
                source: observed,
            });
        }
        let binding = RunBinding {
            mode: target_mode_name(config.mode).to_owned(),
            stage: format!("{:?}", config.stage).to_ascii_lowercase(),
            load_profile: config.load_profile.as_str().to_owned(),
            config_revision: config.config_revision.clone(),
            target_hostnames: vec![
                config.profile.test_hostname.trim().to_owned(),
                config.profile.sandbox_hostname.trim().to_owned(),
            ],
        };
        let mut executor = Executor::with_signals(
            kill,
            limiter,
            config.mode,
            config.stage,
            config.load_profile,
            signals,
        );
        executor.profile = Arc::new(config.profile);
        executor.lifecycle = config.lifecycle;
        executor.run_id = config.run_id;
        executor.resolver = facts.resolver;
        executor.revision = facts.revision;
        executor.runner = facts.runner;
        executor.resume_binding = Some(binding);
        executor.inspect = Arc::new(Mutex::new(InspectGate::new(
            inspect_client,
            config.config_revision,
        )));
        Ok(executor)
    }

    /// Give the executor the validated profile of the run. A check can only build a connector from this profile, so it cannot
    /// widen the allowlist by constructing a profile of its own (review item S-1). Crate-internal: use
    /// [`Executor::from_config`] (review item N-7).
    #[cfg(test)]
    pub(crate) fn with_profile(mut self, profile: Profile) -> Executor {
        self.profile = Arc::new(profile);
        self
    }

    /// Give the executor the run's one inspect gate: the client and the expected `config_revision` it was built against. The
    /// gate is shared with every check through `CheckContext::inspect`; a check cannot build another one (review item S-2).
    #[cfg(test)]
    pub(crate) fn with_inspect_client(
        mut self,
        client: Box<dyn InspectClient + Send>,
        expected_revision: impl Into<String>,
    ) -> Executor {
        self.inspect = Arc::new(Mutex::new(InspectGate::new(client, expected_revision)));
        self
    }

    /// Give the executor the run's evidence store (review item S-6). It is shared with every check: `CheckContext::save_evidence`
    /// writes through it and records `(check id, run id, name, hash)`, and the executor refuses a PASS backed by anything else.
    #[cfg(test)]
    pub(crate) fn set_evidence_store(&mut self, store: EvidenceStore) {
        self.evidence_root = Some(store.dir().to_path_buf());
        self.evidence_store = Some(store);
    }

    /// The report binding a resume must match (review item S-5): the executor runs the same `validate_resume` as the report
    /// path, so there is one resume rule.
    #[cfg(test)]
    pub(crate) fn with_resume_binding(mut self, binding: RunBinding) -> Executor {
        self.resume_binding = Some(binding);
        self
    }

    /// Bind this executor to the run's id and the profile's lifecycle policy (with this run's approval), so the destructive
    /// gate can compare the approval's run id with this run's (review item R-13).
    #[cfg(test)]
    pub(crate) fn with_run_context(
        mut self,
        lifecycle: LifecyclePolicy,
        run_id: impl Into<String>,
    ) -> Executor {
        self.lifecycle = lifecycle;
        self.run_id = run_id.into();
        self
    }

    /// Supply the runtime facts the connector needs to resolve names, re-read the config revision at send time and know
    /// whether the runner IP is bannable. Without them the connector fails closed (the defaults refuse every host).
    #[cfg(test)]
    pub(crate) fn with_runtime_facts(
        mut self,
        resolver: Arc<dyn Resolver>,
        revision: Arc<dyn RevisionSource>,
        runner: Bannable,
    ) -> Executor {
        self.resolver = resolver;
        self.revision = revision;
        self.runner = runner;
        self
    }

    /// Resume from a previous run directory (review items R-2 and S-5).
    ///
    /// The executor runs the **same** resume selection as the report path (review item N-3:
    /// [`crate::report::select_resumed_lines`]), so the binding, invalid-run, per-line age and AC-00 rules cannot drift. A
    /// resumed `PASS` counts as executed and satisfies a dependency of a check this plan re-runs, **except AC-00**: the safety
    /// self-test always re-runs.
    pub fn set_resume(
        &mut self,
        previous: &Report,
        resume_dir: &Path,
    ) -> Result<usize, ReportError> {
        let binding = self
            .resume_binding
            .clone()
            .ok_or_else(|| ReportError::ResumeMismatch {
                detail: "the executor has no resume binding; give it the run's binding with with_resume_binding before \
                         resuming (review item S-5)"
                    .to_owned(),
            })?;
        let resumed = crate::report::select_resumed_lines(previous, &binding, resume_dir, None)?;
        let count = resumed.len();
        self.resumed = resumed;
        Ok(count)
    }

    /// The ids resumed as PASS from a previous run (a dependency in this set counts as satisfied).
    pub fn resumed_ids(&self) -> Vec<String> {
        self.resumed.iter().map(|line| line.id.clone()).collect()
    }

    /// The run-invalid latch (review item R-8).
    pub fn invalid(&self) -> Arc<RunInvalidLatch> {
        Arc::clone(&self.invalid)
    }

    /// Number of caught panics (R-09: panics are counted and alerted, never hidden).
    pub fn panics(&self) -> u32 {
        self.panics
    }

    /// The run's abort latch (the connector shares it; review item A-9).
    pub fn latch(&self) -> Arc<AbortLatch> {
        Arc::clone(&self.latch)
    }

    /// The run's one shared limiter handle.
    pub fn shared_limiter(&self) -> Arc<Mutex<Limiter>> {
        Arc::clone(&self.shared)
    }

    /// The shared cleanup stack.
    pub fn cleanup(&self) -> &Arc<Mutex<CleanupStack>> {
        &self.cleanup
    }

    /// Drain the cleanup stack. The mutex is released **before** the actions run (review item S-10): an action is arbitrary
    /// code and may lock the same stack (or register another action), and running it under the lock would deadlock.
    fn take_cleanup(&mut self) -> Vec<CleanupRecord> {
        let actions = {
            let mut stack = match self.cleanup.lock() {
                Ok(stack) => stack,
                Err(poisoned) => poisoned.into_inner(),
            };
            std::mem::take(&mut stack.actions)
        };
        CleanupStack { actions }.run_all()
    }

    /// Look at the persistent signal listener without blocking: a signal that arrived between checks is caught here
    /// (review item A-9).
    async fn latch_pending_signal(&mut self) {
        if self.signal_latched.is_some() {
            return;
        }
        let Some(mut listener) = self.signal.take() else {
            return;
        };
        let outcome = tokio::select! {
            biased;
            signal = &mut listener => Some(signal),
            () = std::future::ready(()) => None,
        };
        match outcome {
            Some(signal) => {
                self.signal_latched = Some(signal);
                self.signal = None;
            }
            None => self.signal = Some(listener),
        }
    }

    /// Read the current abort state and latch it.
    fn observe_abort(&mut self) -> Option<AbortCause> {
        if let Some(signal) = self.signal_latched {
            let cause = AbortCause::Signal(signal);
            self.latch.trip(cause);
            return Some(cause);
        }
        if self.kill.check().is_err() {
            let cause = AbortCause::KillSwitch;
            self.latch.trip(cause);
            return Some(cause);
        }
        None
    }

    /// Run one check with every control in force; the cleanup stack is drained before returning, on every path.
    ///
    /// Before the body runs the executor enforces the static gates (review item A-3): the check's profile may not exceed the
    /// run's, and a destructive check is refused in `production` without this run's approval (`UNVERIFIED(stage_forbids)`).
    pub async fn run_one(&mut self, check: &dyn Check) -> CheckReport {
        // Review item S-10: reading the spec is itself an executor call into check code; a panic there must be caught and
        // counted like a body panic, not unwind the executor. There is no id to report when `spec()` panics, so the fallback
        // line uses the first registered id (`AC-00`) and says so.
        let spec = match spec_or_panic(check) {
            Ok(spec) => spec,
            Err(message) => {
                self.panics = self.panics.saturating_add(1);
                return CheckReport {
                    line: StatusLine {
                        id: "AC-00".to_owned(),
                        title: "check spec()".to_owned(),
                        tier: "smoke".to_owned(),
                        verdict: Verdict::Fail {
                            reason: redact_short(&format!(
                                "check spec() panicked before it produced an id: {message}"
                            )),
                        },
                        evidence: Vec::new(),
                        detail: Some(
                            "the check's spec() panicked; AC-00 is used as a placeholder id because the real id cannot \
                             be read"
                                .to_owned(),
                        ),
                    },
                    cleanup: self.take_cleanup(),
                    abort: None,
                };
            }
        };
        if let Some(cause) = self.observe_abort() {
            let line = skipped_line(spec);
            return CheckReport {
                line,
                cleanup: self.take_cleanup(),
                abort: Some(cause),
            };
        }
        if spec.profile.exceeds(self.run_profile) {
            let line = StatusLine {
                id: spec.id.to_owned(),
                title: spec.title.to_owned(),
                tier: spec.tier.to_owned(),
                verdict: Verdict::Unverified {
                    reason: ReasonCode::StageForbids,
                },
                evidence: Vec::new(),
                detail: Some(format!(
                    "the check profile `{}` exceeds the run profile `{}` (E3.1 rule 5)",
                    spec.profile, self.run_profile
                )),
            };
            return CheckReport {
                line,
                cleanup: self.take_cleanup(),
                abort: None,
            };
        }
        if spec.destructive
            && let Err(refusal) = self.lifecycle.allows_destructive_for(&self.run_id)
        {
            // One coherent rule (review item R-13): the lifecycle policy, bound to this run's id, is the only gate. The
            // connector consults the same policy before a destructive send; the executor refuses before the body runs.
            let line = StatusLine {
                id: spec.id.to_owned(),
                title: spec.title.to_owned(),
                tier: spec.tier.to_owned(),
                verdict: Verdict::Unverified {
                    reason: ReasonCode::StageForbids,
                },
                evidence: Vec::new(),
                detail: Some(refusal.to_string()),
            };
            return CheckReport {
                line,
                cleanup: self.take_cleanup(),
                abort: None,
            };
        }
        let own = Limiter::new(spec.profile, Arc::clone(&self.clock));
        let budget = Arc::new(Mutex::new(RateBudget::new(Arc::clone(&self.shared), own)));
        let ctx = CheckContext::new(
            self.mode,
            self.stage,
            self.run_profile,
            spec.destructive,
            self.lifecycle.clone(),
            Arc::clone(&self.profile),
            Arc::clone(&budget),
            Arc::clone(&self.cleanup),
            Arc::clone(&self.latch),
            self.kill.clone(),
            Arc::clone(&self.resolver),
            self.runner,
            Arc::clone(&self.revision),
            Arc::clone(&self.invalid),
            self.run_id.clone(),
            spec.id,
            Arc::clone(&self.inspect),
            self.evidence_store.clone(),
        );
        let outcome = self.execute(check, &ctx).await;
        let cleanup = self.take_cleanup();
        let abort = match &outcome {
            CheckOutcome::Aborted(cause) => Some(*cause),
            _ => None,
        };
        let mut verdict = match &outcome {
            CheckOutcome::Completed(CheckResult::Pass { .. }) => Verdict::Pass,
            CheckOutcome::Completed(CheckResult::Fail { reason }) => Verdict::Fail {
                reason: redact_short(reason),
            },
            CheckOutcome::Completed(CheckResult::Unverified { reason }) => {
                Verdict::Unverified { reason: *reason }
            }
            CheckOutcome::Panicked { message } => Verdict::Fail {
                reason: redact_short(&format!("check panicked: {message}")),
            },
            CheckOutcome::Aborted(_) => Verdict::Unverified {
                reason: ReasonCode::SkippedByOperator,
            },
            CheckOutcome::TimedOut { after } => Verdict::Fail {
                reason: format!(
                    "per-check timeout after {} ms; this check failed and the run continues",
                    after.as_millis()
                ),
            },
        };
        // Review items R-4 and S-6: a PASS is accepted only when every evidence reference was recorded by the store as written
        // by **this check in this run** and the file still hashes to the recorded SHA-256. A check cannot fabricate a pass,
        // reuse another check's file or pick up a leftover from an earlier run.
        if let CheckOutcome::Completed(CheckResult::Pass { evidence }) = &outcome
            && let Err(detail) = self.verify_pass_evidence(spec.id, evidence)
        {
            verdict = Verdict::Fail {
                reason: redact_short(&format!("evidence invalid: {detail}")),
            };
        }
        // Review item N-1: a check whose connector tripped the run-invalid latch ends FAIL, even if its body swallowed the
        // denial and returned PASS. The message names the denial that marked the run invalid.
        if let Some(record) = self
            .invalid
            .records()
            .into_iter()
            .find(|record| record.check_id == spec.id && record.run_id == self.run_id)
        {
            verdict = Verdict::Fail {
                reason: redact_short(&format!("run invalid: {}", record.detail)),
            };
        }
        let evidence = match (&verdict, &outcome) {
            (Verdict::Pass, CheckOutcome::Completed(CheckResult::Pass { evidence })) => {
                evidence.clone()
            }
            _ => Vec::new(),
        };
        let line = match StatusLine::new(spec.id, spec.title, spec.tier, verdict, evidence) {
            Ok(line) => line,
            Err(error) => StatusLine {
                id: spec.id.to_owned(),
                title: spec.title.to_owned(),
                tier: spec.tier.to_owned(),
                verdict: Verdict::Fail {
                    reason: format!("the check produced an invalid status line: {error}"),
                },
                evidence: Vec::new(),
                detail: None,
            },
        };
        CheckReport {
            line,
            cleanup,
            abort,
        }
    }

    /// Re-read and re-hash the evidence of a PASS and require that the store recorded it as written by **this check in this
    /// run** (review items R-4 and S-6). A missing store, an absent file, a record from another check or run, or a hash that
    /// does not match is a refusal, so a check cannot fabricate a pass or reuse a leftover.
    fn verify_pass_evidence(&self, check_id: &str, evidence: &[EvidenceRef]) -> Result<(), String> {
        let Some(store) = &self.evidence_store else {
            return Err(
                "the executor has no evidence store, so the evidence cannot be verified (review item S-6)"
                    .to_owned(),
            );
        };
        if evidence.is_empty() {
            return Err("a PASS carries no evidence artifact (E3.1 rule 1)".to_owned());
        }
        let Some(root) = &self.evidence_root else {
            return Err("the executor has no evidence directory (review item S-6)".to_owned());
        };
        let records = store.records();
        let records = match records.lock() {
            Ok(records) => records,
            Err(poisoned) => poisoned.into_inner(),
        };
        for artifact in evidence {
            if !artifact.hash_is_sha256() {
                return Err(format!(
                    "evidence `{}` has no 64-hex SHA-256",
                    artifact.path()
                ));
            }
            let name = Path::new(artifact.path())
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| format!("evidence path `{}` has no file name", artifact.path()))?;
            let recorded = records.iter().any(|record| {
                record.check == check_id
                    && record.run_id == self.run_id
                    && record.name == name
                    && record.sha256 == artifact.sha256()
            });
            if !recorded {
                return Err(format!(
                    "evidence `{name}` was not written by `{check_id}` in run `{}` (review item S-6)",
                    self.run_id
                ));
            }
            let bytes = std::fs::read(root.join(name))
                .map_err(|error| format!("cannot re-read evidence `{name}`: {error}"))?;
            let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            if length != artifact.bytes() || crate::report::sha256_hex(&bytes) != artifact.sha256()
            {
                return Err(format!(
                    "evidence `{name}` does not match its recorded SHA-256 or size"
                ));
            }
        }
        Ok(())
    }

    /// Run a whole plan in dependency order.
    ///
    /// * the run starts only when AC-00 is in the plan and ends `PASS`; a plan without AC-00 is refused and a non-PASS AC-00
    ///   (including `UNVERIFIED(context)`) stops the run (review items R-8 and S-4). AC-00 always re-runs: a resumed PASS for
    ///   it never satisfies the self-test (review item S-5);
    /// * a dependency that did not end `PASS` keeps its dependents from running: they are `UNVERIFIED(stage_not_reached)` with
    ///   a `detail` naming the dependency. **A dependency of AC-00 is evaluated before the self-test rule**: AC-00 with an
    ///   unmet dependency stops the run (review item S-4);
    /// * a safety-envelope denial that latched `run_invalid` stops the run: the remaining checks are `UNVERIFIED(stage_not_reached)`
    ///   (review item S-8);
    /// * a kill switch or a signal stops the run and the remaining checks are `UNVERIFIED(skipped_by_operator)` (spec 2.8
    ///   step 5);
    /// * a per-check timeout fails that check only;
    /// * PASS lines resumed from a previous run count as executed and satisfy dependencies (review items R-2 and S-5).
    pub async fn run_plan(&mut self, checks: &[&dyn Check]) -> Result<RunReport, PlanError> {
        let satisfied = self.resumed_ids();
        let order = order_with_satisfied(checks, &satisfied)?;
        let resumed: Vec<String> = satisfied;
        // AC-00 must be planned; a resumed AC-00 PASS never stands in for it (review item S-5).
        if !checks
            .iter()
            .any(|check| spec_or_panic(*check).is_ok_and(|spec| spec.id == "AC-00"))
        {
            return Err(PlanError::MissingSelfTest);
        }
        // AC-00 is the precondition of the run: it must execute before every other check, whatever the input order.
        let mut order = order;
        if let Some(position) = order.iter().position(|index| {
            checks
                .get(*index)
                .is_some_and(|check| spec_or_panic(*check).is_ok_and(|spec| spec.id == "AC-00"))
        }) {
            let self_test = order.remove(position);
            order.insert(0, self_test);
        }
        let mut lines: Vec<StatusLine> = Vec::with_capacity(order.len());
        lines.extend(self.resumed.iter().cloned());
        let mut cleanup = Vec::new();
        let mut abort = None;
        let mut stopped_at = None;
        for (position, index) in order.iter().enumerate() {
            let check = match checks.get(*index) {
                Some(check) => *check,
                None => continue,
            };
            let spec = match spec_or_panic(check) {
                Ok(spec) => spec,
                Err(message) => {
                    // A panicking spec cannot be identified; fail the line under the AC-00 placeholder and stop the run so
                    // the remaining checks do not run on a plan that cannot be trusted (review item S-10).
                    self.panics = self.panics.saturating_add(1);
                    lines.push(StatusLine {
                        id: "AC-00".to_owned(),
                        title: "check spec()".to_owned(),
                        tier: "smoke".to_owned(),
                        verdict: Verdict::Fail {
                            reason: redact_short(&format!(
                                "check spec() panicked before it produced an id: {message}"
                            )),
                        },
                        evidence: Vec::new(),
                        detail: Some(
                            "the check's spec() panicked; the run stops because the plan cannot be trusted".to_owned(),
                        ),
                    });
                    abort = Some(AbortCause::SelfTestFailed);
                    stopped_at = Some(position + 1);
                    break;
                }
            };
            if resumed.iter().any(|id| id == spec.id) {
                continue;
            }
            // a signal arriving between checks must not start the next check (review item A-9)
            self.latch_pending_signal().await;
            if let Some(cause) = self.observe_abort() {
                abort = Some(cause);
                stopped_at = Some(position);
                break;
            }
            let unmet = spec
                .dependencies
                .iter()
                .find(|dependency| {
                    lines
                        .iter()
                        .find(|line| line.id == **dependency)
                        .map(|line| !line.verdict.is_pass())
                        .unwrap_or(true)
                })
                .copied();
            // Review item S-4: the AC-00 rule is evaluated BEFORE the unmet-dependency `continue`. AC-00 with an unmet
            // dependency must stop the run, not be reported and skipped while the other checks send.
            if let Some(dependency) = unmet
                && spec.id == "AC-00"
            {
                lines.push(StatusLine {
                    id: spec.id.to_owned(),
                    title: spec.title.to_owned(),
                    tier: spec.tier.to_owned(),
                    verdict: Verdict::Unverified {
                        reason: ReasonCode::StageNotReached,
                    },
                    evidence: Vec::new(),
                    detail: Some(format!(
                        "the AC-00 safety self-test has an unmet dependency `{dependency}`, so the run stops (review \
                         item S-4)"
                    )),
                });
                abort = Some(AbortCause::SelfTestFailed);
                stopped_at = Some(position + 1);
                break;
            }
            if let Some(dependency) = unmet {
                lines.push(StatusLine {
                    id: spec.id.to_owned(),
                    title: spec.title.to_owned(),
                    tier: spec.tier.to_owned(),
                    verdict: Verdict::Unverified {
                        reason: ReasonCode::StageNotReached,
                    },
                    evidence: Vec::new(),
                    detail: Some(format!(
                        "dependency `{dependency}` did not pass, so {} was not run (status taxonomy: a dependent of a \
                         non-PASS dependency is UNVERIFIED(stage_not_reached))",
                        spec.id
                    )),
                });
                continue;
            }
            let report = self.run_one(check).await;
            cleanup.extend(report.cleanup);
            let failed_self_test = spec.id == "AC-00" && !report.line.verdict.is_pass();
            lines.push(report.line);
            if let Some(cause) = report.abort {
                abort = Some(cause);
                stopped_at = Some(position + 1);
                break;
            }
            if failed_self_test {
                abort = Some(AbortCause::SelfTestFailed);
                stopped_at = Some(position + 1);
                break;
            }
            // Review item S-8: a safety-envelope denial latches the run invalid; the run must stop so the remaining checks
            // do not send on an invalid run.
            if self.invalid.is_invalid() {
                abort = Some(AbortCause::RunInvalid);
                stopped_at = Some(position + 1);
                break;
            }
        }
        if let (Some(cause), Some(stopped)) = (abort, stopped_at) {
            let (reason, detail) = match cause {
                AbortCause::SelfTestFailed => (
                    ReasonCode::StageNotReached,
                    Some(
                        "AC-00 safety self-test did not pass; the run stopped before this check (review items R-8 and \
                         S-4)"
                            .to_owned(),
                    ),
                ),
                AbortCause::RunInvalid => (
                    ReasonCode::StageNotReached,
                    Some(
                        "a safety-envelope denial marked the run invalid; the run stopped before this check (review item \
                         S-8)"
                            .to_owned(),
                    ),
                ),
                AbortCause::KillSwitch | AbortCause::Signal(_) => {
                    (ReasonCode::SkippedByOperator, None)
                }
            };
            for index in order.iter().skip(stopped) {
                if let Some(check) = checks.get(*index) {
                    let Ok(spec) = spec_or_panic(*check) else {
                        continue;
                    };
                    if resumed.iter().any(|id| id == spec.id) {
                        continue;
                    }
                    let line = StatusLine {
                        id: spec.id.to_owned(),
                        title: spec.title.to_owned(),
                        tier: spec.tier.to_owned(),
                        verdict: Verdict::Unverified { reason },
                        evidence: Vec::new(),
                        detail: detail.clone(),
                    };
                    lines.push(line);
                }
            }
            cleanup.extend(self.take_cleanup());
        }
        let run_invalid = self.invalid.is_invalid();
        let invalid_audit = self.invalid.audit();
        let invalid_records = self.invalid.records();
        Ok(RunReport {
            lines,
            cleanup,
            abort,
            panics: self.panics,
            run_invalid,
            invalid_audit,
            invalid_records,
        })
    }

    async fn execute(&mut self, check: &dyn Check, ctx: &CheckContext) -> CheckOutcome {
        // Reading the spec again is a call into check code; catch a panic here too (review item S-10). `run_one` has read it
        // once already, so a panic here is a pathological implementation; fall back to the default timeout.
        let timeout_after = spec_or_panic(check)
            .map(|spec| spec.timeout)
            .unwrap_or(Duration::from_secs(30));
        let built = std::panic::catch_unwind(AssertUnwindSafe(|| check.run(ctx)));
        let future = match built {
            Ok(future) => future,
            Err(payload) => {
                self.panics = self.panics.saturating_add(1);
                return CheckOutcome::Panicked {
                    message: panic_message(&*payload),
                };
            }
        };
        let mut guarded = CatchUnwind { inner: future };
        let timeout = tokio::time::sleep(timeout_after);
        tokio::pin!(timeout);
        let mut listener = match self.signal.take() {
            Some(listener) => listener,
            None => pending_signal(),
        };
        let kill = self.kill.clone();
        enum SelectOutcome {
            Check(Result<CheckResult, String>),
            Kill,
            Signal(ShutdownSignal),
            Timeout,
        }
        let selected = tokio::select! {
            biased;
            result = &mut guarded => SelectOutcome::Check(result),
            () = kill.tripped() => SelectOutcome::Kill,
            signal = &mut listener => SelectOutcome::Signal(signal),
            () = &mut timeout => SelectOutcome::Timeout,
        };
        match selected {
            SelectOutcome::Check(Ok(result)) => {
                self.signal = Some(listener);
                CheckOutcome::Completed(result)
            }
            SelectOutcome::Check(Err(message)) => {
                self.signal = Some(listener);
                self.panics = self.panics.saturating_add(1);
                CheckOutcome::Panicked { message }
            }
            SelectOutcome::Kill => {
                self.signal = Some(listener);
                self.latch.trip(AbortCause::KillSwitch);
                CheckOutcome::Aborted(AbortCause::KillSwitch)
            }
            SelectOutcome::Signal(signal) => {
                self.signal_latched = Some(signal);
                let cause = AbortCause::Signal(signal);
                self.latch.trip(cause);
                CheckOutcome::Aborted(cause)
            }
            SelectOutcome::Timeout => {
                self.signal = Some(listener);
                CheckOutcome::TimedOut {
                    after: timeout_after,
                }
            }
        }
    }
}

fn skipped_line(spec: &CheckSpec) -> StatusLine {
    StatusLine {
        id: spec.id.to_owned(),
        title: spec.title.to_owned(),
        tier: spec.tier.to_owned(),
        verdict: Verdict::Unverified {
            reason: ReasonCode::SkippedByOperator,
        },
        evidence: Vec::new(),
        detail: None,
    }
}

/// Bound a reason so a hostile server response cannot flood the report.
fn redact_short(reason: &str) -> String {
    const MAX: usize = 512;
    let mut end = reason.len().min(MAX);
    while end > 0 && !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason[..end].to_owned()
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_owned()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "<non-string panic payload>".to_owned()
    }
}

/// A future wrapper that catches a panic from the polled check (R-09: the process must not unwind because a check did).
struct CatchUnwind<'a> {
    inner: Pin<Box<dyn Future<Output = CheckResult> + Send + 'a>>,
}

impl Future for CatchUnwind<'_> {
    type Output = Result<CheckResult, String>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        let inner = this.inner.as_mut();
        match std::panic::catch_unwind(AssertUnwindSafe(|| inner.poll(cx))) {
            Ok(Poll::Ready(result)) => Poll::Ready(Ok(result)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(payload) => Poll::Ready(Err(panic_message(&*payload))),
        }
    }
}

#[cfg(test)]
mod tests;
