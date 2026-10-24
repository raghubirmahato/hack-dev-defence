//! The rate and load profiles of section 2.3 and the one token-bucket limiter that every check shares.
//!
//! The five profiles are `functional`, `burst`, `protocol-abuse`, `load` and `lab`. Every ceiling is a constant of this
//! module, and a check may choose a **lower** profile or lower caps, never a higher one (E3.1 rule 5). The provenance of each
//! number matters: the rates, durations and totals marked `spec` in `docs/ACCEPTANCE.md` come from section 2.3, while the
//! bucket capacities and the `load` ceilings marked `authored guard rail` there are values this task chose because the
//! specification gives no number for them (section 2.3 says only that `load` "has its own hard caps in the profile", and the
//! v5 profile carries no numeric load caps). The `load` profile additionally needs the operator's written approval for that
//! specific run, and the profile flag `load_profile_approved` (section 2.3; see `docs/ACCEPTANCE.md`).
//!
//! A rate profile enforces **at most N requests in any 1000 ms sliding window**, not a bucket that can emit a burst and then
//! refill inside the same second: the limiter keeps the grant timestamps of the last second and refuses the (N+1)th. The
//! duration cap is half-open: grants are allowed while `elapsed < duration`, and a request at exactly the duration boundary is
//! refused. Both rules are measured in tests on an injected [`hdd_common::kv::clock::Clock`] at aligned and non-aligned
//! instants (task acceptance A2 and review item A-10).
//!
//! One [`Limiter`] instance is shared by every check of a run. A check may narrow its own budget further with
//! [`RequestedCaps`]; the executor combines the run's shared limiter with the check's profile limiter in a [`RateBudget`], so
//! the shared budget and the per-check ceiling are both enforced and a check cannot raise either.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};

use hdd_common::egress::TargetMode;
use hdd_common::kv::clock::Clock;

/// Bytes in one MiB, for the protocol-abuse wire cap (10 MiB).
pub const MIB: u64 = 1_048_576;

/// Length of the sliding rate window that every rate lane enforces.
pub const RATE_WINDOW_US: u64 = 1_000_000;

/// A rate/load profile (section 2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoadProfile {
    /// Benign and GET/HEAD attack shapes: at most 20 req/s sustained for up to 5 minutes.
    Functional,
    /// One capped burst: up to 100 HTTP requests and one DNS burst of up to 500 queries.
    Burst,
    /// Protocol abuse against the sandbox only: up to 5 connections, 2,000 frames, 10 MiB on the wire.
    ProtocolAbuse,
    /// Performance qualification; needs the operator's written approval for the run and targets the sandbox only.
    Load,
    /// The closed lab: at most 500 req/s per client process for up to 10 minutes.
    Lab,
}

impl LoadProfile {
    /// Every profile, in documentation order.
    pub const ALL: [LoadProfile; 5] = [
        LoadProfile::Functional,
        LoadProfile::Burst,
        LoadProfile::ProtocolAbuse,
        LoadProfile::Load,
        LoadProfile::Lab,
    ];

    /// The profile name as used on the command line and in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            LoadProfile::Functional => "functional",
            LoadProfile::Burst => "burst",
            LoadProfile::ProtocolAbuse => "protocol-abuse",
            LoadProfile::Load => "load",
            LoadProfile::Lab => "lab",
        }
    }

    /// Parse a whole-token profile name.
    pub fn parse(s: &str) -> Option<LoadProfile> {
        LoadProfile::ALL
            .into_iter()
            .find(|profile| profile.as_str() == s.trim())
    }

    /// The runner's ordering of how much rate budget a profile may use. A check's `CheckSpec.profile` may not exceed the
    /// run's profile (review item A-3); when it is lower, the executor gives the check that lower ceiling *and* keeps the
    /// run's shared limiter, so the narrower ceiling is the one that binds.
    pub fn rank(self) -> u8 {
        match self {
            LoadProfile::Functional => 0,
            LoadProfile::Burst => 1,
            LoadProfile::ProtocolAbuse => 2,
            LoadProfile::Lab => 3,
            LoadProfile::Load => 4,
        }
    }

    /// True when this profile asks for more budget than the run's profile allows.
    pub fn exceeds(self, run: LoadProfile) -> bool {
        self.rank() > run.rank()
    }

    /// True when this profile may run in `mode` (spec section 2.3, E3.1 rule 5). `lab` targets only lab addresses, so it
    /// requires the lab target set; `protocol-abuse` and `load` target only the sandbox host name of the live profile. The
    /// `functional` and `burst` profiles may run in either mode. Review item R-1: this is enforced both in
    /// [`crate::config::RunnerConfig::build`] and in [`crate::guard::Connector::new`], so no caller can bypass it.
    pub fn allows_mode(self, mode: TargetMode) -> bool {
        match self {
            LoadProfile::Functional | LoadProfile::Burst => true,
            LoadProfile::ProtocolAbuse | LoadProfile::Load => mode == TargetMode::Live,
            LoadProfile::Lab => mode == TargetMode::Lab,
        }
    }

    /// The hard ceilings of the profile. These are constants of the runner; no check can raise them. Provenance per field
    /// (`spec` from section 2.3 or an `authored guard rail` where the specification gives no number) is tabulated in
    /// `docs/ACCEPTANCE.md`.
    pub fn hard_caps(self) -> Caps {
        match self {
            LoadProfile::Functional => Caps {
                profile: self,
                http: Some(HttpLane {
                    rate_per_s: 20,
                    burst: 20,
                    duration_s: 300,
                }),
                dns_total: None,
                connections: None,
                frames: None,
                bytes: None,
            },
            LoadProfile::Burst => Caps {
                profile: self,
                http: Some(HttpLane {
                    rate_per_s: 0,
                    burst: 100,
                    duration_s: 60,
                }),
                dns_total: Some(500),
                connections: None,
                frames: None,
                bytes: None,
            },
            LoadProfile::ProtocolAbuse => Caps {
                profile: self,
                http: None,
                dns_total: None,
                connections: Some(5),
                frames: Some(2_000),
                bytes: Some(10 * MIB),
            },
            LoadProfile::Load => Caps {
                profile: self,
                http: Some(HttpLane {
                    rate_per_s: 100,
                    burst: 100,
                    duration_s: 600,
                }),
                dns_total: None,
                connections: None,
                frames: None,
                bytes: None,
            },
            LoadProfile::Lab => Caps {
                profile: self,
                http: Some(HttpLane {
                    rate_per_s: 500,
                    burst: 500,
                    duration_s: 600,
                }),
                dns_total: None,
                connections: None,
                frames: None,
                bytes: None,
            },
        }
    }

    /// `load` needs the operator's separate written approval for that run (section 2.3).
    pub fn requires_written_approval(self) -> bool {
        self == LoadProfile::Load
    }
}

impl fmt::Display for LoadProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One HTTP-shaped lane: a window rate (`rate_per_s`, `0` means "no rate, one capped total burst"), a burst capacity that
/// must never exceed the rate for a rate lane, and a duration ceiling.
///
/// `rate_per_s` and `duration_s` are section 2.3 values; `burst` is the window allowance for a rate lane, and for the `burst`
/// profile it is the total. The capacities and the `load` ceilings are authored guard rails where section 2.3 gives no number,
/// see `docs/ACCEPTANCE.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpLane {
    /// Requests allowed in any [`RATE_WINDOW_US`] window (or `0` for a single capped total burst).
    pub rate_per_s: u64,
    /// Burst capacity: for a rate lane this must equal `rate_per_s`; for the `burst` profile it is the total.
    pub burst: u64,
    /// Longest continuous run allowed, in seconds, half-open (`elapsed < duration`).
    pub duration_s: u64,
}

/// The hard ceilings of one profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// The profile these ceilings belong to.
    pub profile: LoadProfile,
    /// HTTP-shaped lane when the profile has one.
    pub http: Option<HttpLane>,
    /// Total DNS queries allowed, when the profile caps them.
    pub dns_total: Option<u64>,
    /// Total TCP connections allowed, when the profile caps them.
    pub connections: Option<u64>,
    /// Total protocol frames allowed, when the profile caps them.
    pub frames: Option<u64>,
    /// Total bytes on the wire allowed, when the profile caps them.
    pub bytes: Option<u64>,
}

impl Caps {
    /// The ceiling for one lane, applied to a request for the same lane.
    pub fn ceiling(&self, lane: Lane) -> Option<u64> {
        match lane {
            Lane::Http => self.http.map(|h| h.burst),
            Lane::Dns => self.dns_total,
            Lane::Connections => self.connections,
            Lane::Frames => self.frames,
            Lane::Bytes => self.bytes,
        }
    }
}

/// What a check asks to use. It may ask for less than the ceiling, never for more.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestedCaps {
    /// A lower HTTP lane than the profile's.
    pub http: Option<HttpLane>,
    /// Lower totals than the profile's, per lane.
    pub totals: BTreeMap<Lane, u64>,
}

impl RequestedCaps {
    /// A request with a lower HTTP rate/burst/duration.
    pub fn http(rate_per_s: u64, burst: u64, duration_s: u64) -> RequestedCaps {
        RequestedCaps {
            http: Some(HttpLane {
                rate_per_s,
                burst,
                duration_s,
            }),
            totals: BTreeMap::new(),
        }
    }

    /// Refuse a request that exceeds any hard ceiling. Returns the first violation found.
    pub fn within(&self, caps: &Caps) -> Result<(), LimitDenial> {
        if let Some((requested, ceiling)) = self.http.zip(caps.http) {
            if requested.burst > ceiling.burst || requested.rate_per_s > ceiling.rate_per_s {
                return Err(LimitDenial::AboveCeiling {
                    lane: Lane::Http,
                    requested: requested.burst.max(requested.rate_per_s),
                    ceiling: ceiling.burst.max(ceiling.rate_per_s),
                });
            }
            if requested.duration_s > ceiling.duration_s {
                return Err(LimitDenial::AboveCeiling {
                    lane: Lane::Http,
                    requested: requested.duration_s,
                    ceiling: ceiling.duration_s,
                });
            }
        }
        for (lane, asked) in &self.totals {
            let ceiling = caps
                .ceiling(*lane)
                .ok_or(LimitDenial::LaneNotInProfile { lane: *lane })?;
            if *asked > ceiling {
                return Err(LimitDenial::AboveCeiling {
                    lane: *lane,
                    requested: *asked,
                    ceiling,
                });
            }
        }
        Ok(())
    }
}

/// One counter lane of the limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Lane {
    /// HTTP requests to the allowlisted target.
    Http,
    /// DNS queries.
    Dns,
    /// TCP connections (protocol-abuse only).
    Connections,
    /// Protocol frames (protocol-abuse only).
    Frames,
    /// Bytes on the wire (protocol-abuse only).
    Bytes,
}

impl Lane {
    /// Every lane, in documentation order.
    pub const ALL: [Lane; 5] = [
        Lane::Http,
        Lane::Dns,
        Lane::Connections,
        Lane::Frames,
        Lane::Bytes,
    ];

    /// The lane name as written in findings.
    pub fn as_str(self) -> &'static str {
        match self {
            Lane::Http => "http",
            Lane::Dns => "dns",
            Lane::Connections => "connections",
            Lane::Frames => "frames",
            Lane::Bytes => "bytes",
        }
    }
}

impl fmt::Display for Lane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why the limiter refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitDenial {
    /// A requested cap is above the profile's hard ceiling.
    AboveCeiling {
        /// The lane.
        lane: Lane,
        /// What the check asked for.
        requested: u64,
        /// The ceiling (a constant of the runner).
        ceiling: u64,
    },
    /// The sliding window rate was exceeded.
    RateExceeded {
        /// The lane.
        lane: Lane,
        /// How long until a grant leaves the window, in milliseconds (rounded up).
        retry_after_ms: u64,
    },
    /// The duration ceiling of the profile was reached (half-open: at exactly the limit it is refused).
    DurationExceeded {
        /// The lane.
        lane: Lane,
        /// The ceiling in seconds.
        limit_s: u64,
    },
    /// A capped total burst is used up.
    TotalExceeded {
        /// The lane.
        lane: Lane,
        /// The ceiling.
        ceiling: u64,
    },
    /// The profile has no lane of this kind.
    LaneNotInProfile {
        /// The lane.
        lane: Lane,
    },
    /// A check requested a zero rate on a profile lane that is a rate lane (review item S-9): that would turn the lane into a
    /// total bucket with no rate limit, which a check may not do.
    ZeroRateOnRateLane {
        /// The lane.
        lane: Lane,
    },
    /// The shared limiter is unavailable (a previous check panicked while holding it): fail closed.
    Locked,
}

impl LimitDenial {
    /// The lane of the denial.
    pub fn lane(&self) -> Lane {
        match self {
            LimitDenial::AboveCeiling { lane, .. }
            | LimitDenial::RateExceeded { lane, .. }
            | LimitDenial::DurationExceeded { lane, .. }
            | LimitDenial::TotalExceeded { lane, .. }
            | LimitDenial::LaneNotInProfile { lane }
            | LimitDenial::ZeroRateOnRateLane { lane } => *lane,
            LimitDenial::Locked => Lane::Http,
        }
    }
}

impl fmt::Display for LimitDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LimitDenial::AboveCeiling {
                lane,
                requested,
                ceiling,
            } => write!(
                f,
                "a check asked for {requested} on lane `{lane}`; the hard ceiling is {ceiling} and checks cannot raise it"
            ),
            LimitDenial::RateExceeded {
                lane,
                retry_after_ms,
            } => write!(
                f,
                "lane `{lane}` sliding-window rate exceeded; retry after {retry_after_ms} ms"
            ),
            LimitDenial::DurationExceeded { lane, limit_s } => write!(
                f,
                "lane `{lane}` duration ceiling of {limit_s} s reached (half-open: a grant at exactly the limit is refused)"
            ),
            LimitDenial::TotalExceeded { lane, ceiling } => {
                write!(f, "lane `{lane}` capped burst of {ceiling} is used up")
            }
            LimitDenial::LaneNotInProfile { lane } => {
                write!(f, "the selected profile has no `{lane}` lane")
            }
            LimitDenial::ZeroRateOnRateLane { lane } => write!(
                f,
                "a check asked for a zero rate on the rate lane `{lane}`; that would remove the rate limit, and a check \
                 may only lower caps"
            ),
            LimitDenial::Locked => f.write_str(
                "the shared limiter is unavailable after a panic; refusing to continue (fail closed)",
            ),
        }
    }
}

impl std::error::Error for LimitDenial {}

/// A lane counter: a sliding window of grant timestamps for a rate lane, or one capped total for a burst lane.
#[derive(Debug, Clone)]
enum Kind {
    Rate {
        rate_per_s: u64,
        grants: VecDeque<u64>,
        duration_us: Option<u64>,
        first_us: Option<u64>,
    },
    Total {
        cap: u64,
        consumed: u64,
    },
}

/// One limiter lane.
#[derive(Debug, Clone)]
struct Bucket {
    kind: Kind,
}

impl Bucket {
    fn rate(rate_per_s: u64, duration_s: u64) -> Bucket {
        Bucket {
            kind: Kind::Rate {
                rate_per_s,
                grants: VecDeque::new(),
                duration_us: if duration_s == 0 {
                    None
                } else {
                    Some(duration_s.saturating_mul(1_000_000))
                },
                first_us: None,
            },
        }
    }

    fn total(cap: u64) -> Bucket {
        Bucket {
            kind: Kind::Total { cap, consumed: 0 },
        }
    }

    /// Drop grants that have left the sliding window. The window is **closed** (review item S-9): a grant counts while
    /// `now - grant <= RATE_WINDOW_US`, i.e. for exactly 1000 ms including both ends, so no 1000 ms interval can contain more
    /// than the profile rate. Called before every check, so the deque never grows beyond the window allowance and each grant
    /// is removed once (review item R-10).
    fn purge(&mut self, now_us: u64) {
        if let Kind::Rate { grants, .. } = &mut self.kind {
            while let Some(front) = grants.front() {
                if now_us.saturating_sub(*front) <= RATE_WINDOW_US {
                    break;
                }
                let _ = grants.pop_front();
            }
        }
    }

    /// Pop expired grants, check the ceiling and commit in one step (the check and the commit see the same time).
    fn try_acquire(&mut self, cost: u64, now_us: u64, lane: Lane) -> Result<(), LimitDenial> {
        if cost == 0 {
            return Err(LimitDenial::LaneNotInProfile { lane });
        }
        match &mut self.kind {
            Kind::Rate {
                rate_per_s,
                grants,
                duration_us,
                first_us,
            } => {
                if let (Some(first), Some(duration_us)) = (*first_us, *duration_us)
                    && now_us.saturating_sub(first) >= duration_us
                {
                    return Err(LimitDenial::DurationExceeded {
                        lane,
                        limit_s: duration_us / 1_000_000,
                    });
                }
                while let Some(front) = grants.front() {
                    if now_us.saturating_sub(*front) <= RATE_WINDOW_US {
                        break;
                    }
                    let _ = grants.pop_front();
                }
                let in_window = grants.len() as u64;
                if in_window.saturating_add(cost) > *rate_per_s {
                    // The closed window: a grant leaves at `grant + RATE_WINDOW_US + 1`, so the retry is that far away.
                    let retry_after_ms = grants
                        .front()
                        .map(|grant| {
                            (grant
                                .saturating_add(RATE_WINDOW_US)
                                .saturating_add(1)
                                .saturating_sub(now_us))
                            .div_ceil(1_000)
                        })
                        .unwrap_or(1)
                        .max(1);
                    return Err(LimitDenial::RateExceeded {
                        lane,
                        retry_after_ms,
                    });
                }
                if first_us.is_none() {
                    *first_us = Some(now_us);
                }
                for _ in 0..cost {
                    grants.push_back(now_us);
                }
                Ok(())
            }
            Kind::Total { cap, consumed } => {
                if consumed.saturating_add(cost) > *cap {
                    return Err(LimitDenial::TotalExceeded {
                        lane,
                        ceiling: *cap,
                    });
                }
                *consumed = consumed.saturating_add(cost);
                Ok(())
            }
        }
    }
    /// Give a grant back (used when a second limiter refused the same request, so a refusal never consumes budget). The
    /// duration clock (`first_us`) is **not** reset when the deque becomes empty (review item S-9): a refund after an idle
    /// second must not restart the check's duration window.
    fn refund(&mut self, cost: u64) {
        match &mut self.kind {
            Kind::Rate { grants, .. } => {
                for _ in 0..cost {
                    let _ = grants.pop_back();
                }
            }
            Kind::Total { consumed, .. } => {
                *consumed = consumed.saturating_sub(cost);
            }
        }
    }

    fn profile_clock_start(&self) -> Option<u64> {
        match &self.kind {
            Kind::Rate { first_us, .. } => *first_us,
            Kind::Total { .. } => None,
        }
    }
}

/// The one limiter shared by every check of a run.
pub struct Limiter {
    clock: Arc<dyn Clock>,
    caps: Caps,
    lanes: BTreeMap<Lane, Bucket>,
}

impl Limiter {
    /// A limiter at the hard ceilings of `profile`, counting on `clock`.
    pub(crate) fn new(profile: LoadProfile, clock: Arc<dyn Clock>) -> Limiter {
        let caps = profile.hard_caps();
        let mut lanes = BTreeMap::new();
        if let Some(http) = caps.http {
            let bucket = if http.rate_per_s == 0 {
                Bucket::total(http.burst)
            } else {
                Bucket::rate(http.rate_per_s, http.duration_s)
            };
            lanes.insert(Lane::Http, bucket);
        }
        for (lane, total) in [
            (Lane::Dns, caps.dns_total),
            (Lane::Connections, caps.connections),
            (Lane::Frames, caps.frames),
            (Lane::Bytes, caps.bytes),
        ] {
            if let Some(cap) = total {
                lanes.insert(lane, Bucket::total(cap));
            }
        }
        Limiter { clock, caps, lanes }
    }

    /// A limiter with lower caps requested by a check; refused when the request exceeds a hard ceiling.
    #[allow(
        dead_code,
        reason = "exercised by the limits tests now; the executor will call it when a check requests lower caps"
    )]
    pub(crate) fn with_requested(
        profile: LoadProfile,
        requested: &RequestedCaps,
        clock: Arc<dyn Clock>,
    ) -> Result<Limiter, LimitDenial> {
        let caps = profile.hard_caps();
        requested.within(&caps)?;
        let mut limiter = Limiter::new(profile, clock);
        if let Some(lower) = requested.http
            && let Some(bucket) = limiter.lanes.get_mut(&Lane::Http)
        {
            // Review item S-9: a zero rate on a profile rate lane would turn the lane into a total bucket with no rate
            // limit, which is not "lowering" the cap. Refuse it; the only legitimate total-shaped HTTP lane is the `burst`
            // profile's own hard lane, which `with_requested` does not replace.
            if lower.rate_per_s == 0 && caps.http.is_some_and(|http| http.rate_per_s > 0) {
                return Err(LimitDenial::ZeroRateOnRateLane { lane: Lane::Http });
            }
            bucket.kind = if lower.rate_per_s == 0 {
                Kind::Total {
                    cap: lower.burst,
                    consumed: 0,
                }
            } else {
                Kind::Rate {
                    rate_per_s: lower.rate_per_s,
                    grants: VecDeque::new(),
                    duration_us: if lower.duration_s == 0 {
                        None
                    } else {
                        Some(lower.duration_s.saturating_mul(1_000_000))
                    },
                    first_us: None,
                }
            };
        }
        for (lane, asked) in &requested.totals {
            if let Some(bucket) = limiter.lanes.get_mut(lane) {
                bucket.kind = Kind::Total {
                    cap: *asked,
                    consumed: 0,
                };
            }
        }
        Ok(limiter)
    }

    /// The profile.
    pub fn profile(&self) -> LoadProfile {
        self.caps.profile
    }

    /// The hard ceilings in force.
    pub fn caps(&self) -> &Caps {
        &self.caps
    }

    /// The injected clock (the executor reuses it for the per-check limiter so both read one timeline).
    pub fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.clock)
    }

    /// Take `cost` from `lane`, or refuse with the reason. Every check of the run shares this instance.
    pub fn acquire(&mut self, lane: Lane, cost: u64) -> Result<(), LimitDenial> {
        let now = self.clock.now_us();
        match self.lanes.get_mut(&lane) {
            Some(bucket) => bucket.try_acquire(cost, now, lane),
            None => Err(LimitDenial::LaneNotInProfile { lane }),
        }
    }

    /// Take `cost` at an explicit instant (the budget's own limiter shares the run's clock, review item R-10).
    fn try_acquire(&mut self, lane: Lane, cost: u64, now_us: u64) -> Result<(), LimitDenial> {
        match self.lanes.get_mut(&lane) {
            Some(bucket) => bucket.try_acquire(cost, now_us, lane),
            None => Err(LimitDenial::LaneNotInProfile { lane }),
        }
    }

    /// Give a grant back when another limiter refused the same request, so a refusal consumes no budget.
    fn refund(&mut self, lane: Lane, cost: u64) {
        if let Some(bucket) = self.lanes.get_mut(&lane) {
            bucket.refund(cost);
        }
    }

    /// When the current rate window opened (the first grant of the run), for tests and reports.
    pub fn window_started_us(&self) -> Option<u64> {
        self.lanes
            .get(&Lane::Http)
            .and_then(Bucket::profile_clock_start)
    }
}

impl fmt::Debug for Limiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Limiter")
            .field("profile", &self.caps.profile)
            .field("caps", &self.caps)
            .finish_non_exhaustive()
    }
}

/// The budget a check spends from: the run's one shared limiter plus the check's own (lower or equal) profile limiter.
///
/// The connector and `CheckContext::acquire` use the same `RateBudget`, so a request passes only when both ceilings allow it
/// (review items A-2, A-3); a refusal from either side consumes no budget.
pub struct RateBudget {
    shared: Arc<Mutex<Limiter>>,
    own: Limiter,
}

impl RateBudget {
    /// A budget over the run's shared limiter and the check's own limiter.
    pub(crate) fn new(shared: Arc<Mutex<Limiter>>, own: Limiter) -> RateBudget {
        RateBudget { shared, own }
    }

    /// The check-level limiter (the narrower ceiling).
    pub fn own_profile(&self) -> LoadProfile {
        self.own.profile()
    }

    /// Spend `cost` from `lane` only if both the check ceiling and the shared ceiling allow it. A check-level grant is
    /// refunded when the shared limiter refuses, so a refusal consumes nothing.
    pub fn acquire(&mut self, lane: Lane, cost: u64) -> Result<(), LimitDenial> {
        let now = self.own.clock().now_us();
        let mut shared = match self.shared.lock() {
            Ok(shared) => shared,
            Err(_) => return Err(LimitDenial::Locked),
        };
        self.own.try_acquire(lane, cost, now)?;
        if let Err(denial) = shared.try_acquire(lane, cost, now) {
            self.own.refund(lane, cost);
            return Err(denial);
        }
        Ok(())
    }

    /// The number of grants currently inside the check-level window (tests and diagnostics); grants older than the
    /// one-second window are not counted.
    pub fn own_window_len(&mut self) -> usize {
        let now = self.own.clock().now_us();
        self.own
            .lanes
            .get_mut(&Lane::Http)
            .map(|bucket| {
                bucket.purge(now);
                match &bucket.kind {
                    Kind::Rate { grants, .. } => grants.len(),
                    Kind::Total { consumed, .. } => {
                        usize::try_from(*consumed).unwrap_or(usize::MAX)
                    }
                }
            })
            .unwrap_or(0)
    }
}

impl fmt::Debug for RateBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RateBudget")
            .field("own_profile", &self.own.profile())
            .field("shared", &self.shared.lock().map(|s| s.caps.profile))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
