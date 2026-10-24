//! Shared test fixtures and recording doubles (compiled only under `cfg(test)`).
//!
//! The doubles are not fakes of a product behaviour: the recorded sender, the scripted resolver and the scripted inspect
//! client exist because the acceptance criteria of T-0215 (A1, A4, A5) must be tested before any real send function exists,
//! and the safety envelope sanctions a recording sender instead of a real socket (A1).
#![allow(
    clippy::field_reassign_with_default,
    reason = "tests build profiles by overriding single fields"
)]

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use hdd_common::egress::KillSwitch;
use hdd_common::egress::resolver::{BoxFuture, Resolution, Resolver};
use hdd_common::kv::clock::ManualClock;
use hdd_common::profile::Profile;

use crate::guard::{PlannedRequest, Sender, Sent};
use crate::inspect::{
    InspectClient, InspectClientError, InspectRequest, InspectResponse, SiteMode,
};
use crate::limits::{Limiter, LoadProfile, RateBudget};

/// A scripted inspect client for executor tests (compiled only under `cfg(test)`): it answers the first request with a
/// `would_block=true`, `block`, safe-mode-off response for `revision`, so the executor's gate can mint a ticket.
pub struct ScriptedInspectClient {
    /// The revision to report.
    pub revision: String,
    /// Requests seen.
    pub calls: Arc<Mutex<Vec<InspectRequest>>>,
    /// Whether to report `would_block`.
    pub would_block: bool,
}

impl ScriptedInspectClient {
    /// A client that would block on `revision`.
    pub fn blocking(revision: &str) -> ScriptedInspectClient {
        ScriptedInspectClient {
            revision: revision.to_owned(),
            calls: Arc::new(Mutex::new(Vec::new())),
            would_block: true,
        }
    }

    /// The requests this client was asked about.
    pub fn calls(&self) -> Arc<Mutex<Vec<InspectRequest>>> {
        Arc::clone(&self.calls)
    }
}

impl InspectClient for ScriptedInspectClient {
    fn inspect(&mut self, request: &InspectRequest) -> Result<InspectResponse, InspectClientError> {
        match self.calls.lock() {
            Ok(mut calls) => calls.push(request.clone()),
            Err(poisoned) => poisoned.into_inner().push(request.clone()),
        }
        Ok(InspectResponse {
            would_block: self.would_block,
            config_revision: self.revision.clone(),
            mode: SiteMode::Block,
            safe_mode: false,
            category: Some("sqli".to_owned()),
        })
    }
}

/// The example live profile with its two required placeholder values filled in, so `validate` has no FAIL findings.
pub const EXAMPLE_PROFILE: &str = include_str!("../../../hdd.live.example.yaml");

/// The example profile text with `operator_email` and `acme.email` set to a valid address.
pub fn profile_yaml() -> String {
    EXAMPLE_PROFILE
        .replace("operator_email: ''", "operator_email: 'ops@example.com'")
        .replace(
            "acme: {email: '', directory: staging}",
            "acme: {email: 'ops@example.com', directory: staging}",
        )
}

/// The parsed example profile (fails the test when the fixture itself stops parsing).
pub fn profile() -> Profile {
    hdd_common::profile::parse_yaml(&profile_yaml()).expect("the example profile fixture parses")
}

/// The parsed example profile without the two required values (used for validation-refusal tests).
pub fn profile_missing_required() -> Profile {
    hdd_common::profile::parse_yaml(EXAMPLE_PROFILE).expect("the raw example profile parses")
}

/// A manual clock at zero.
pub fn manual_clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(0))
}

/// A limiter at the hard ceilings of `profile` on a fresh manual clock.
pub fn limiter(profile: LoadProfile) -> Limiter {
    Limiter::new(profile, manual_clock())
}

/// A shared-plus-check budget at `profile` on a fresh manual clock.
pub fn rate_budget(profile: LoadProfile) -> Arc<Mutex<RateBudget>> {
    let clock = manual_clock();
    let shared = Arc::new(Mutex::new(Limiter::new(profile, clock.clone())));
    let own = Limiter::new(profile, clock);
    Arc::new(Mutex::new(RateBudget::new(shared, own)))
}

/// A budget over an explicit shared limiter and a check profile.
pub fn budget_over(
    shared: Limiter,
    own: LoadProfile,
    clock: &Arc<ManualClock>,
) -> Arc<Mutex<RateBudget>> {
    Arc::new(Mutex::new(RateBudget::new(
        Arc::new(Mutex::new(shared)),
        Limiter::new(own, clock.clone()),
    )))
}

/// A process-unique temporary directory, removed and recreated.
pub fn temp_dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("hdd-acceptance-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create test directory");
    dir
}

/// A kill switch over a file that does not exist yet.
pub fn kill_switch(dir: &Path) -> KillSwitch {
    KillSwitch::new(dir.join("stop"), std::time::Duration::from_millis(50))
}

/// A sender that records what it was asked to send and sends nothing.
#[derive(Debug, Default)]
pub struct RecordingSender {
    /// Every accepted request, in order.
    pub sent: Vec<(String, String)>,
}

impl Sender for RecordingSender {
    fn send(&mut self, request: PlannedRequest, _pinned: &[IpAddr]) -> Sent {
        self.sent
            .push((request.target().to_owned(), request.path().to_owned()));
        Sent {
            target: request.target().to_owned(),
            path: request.path().to_owned(),
        }
    }
}

/// A sender that only counts the accepted requests.
#[derive(Default)]
pub struct CountingSender {
    /// Number of accepted requests.
    pub calls: usize,
}

impl Sender for CountingSender {
    fn send(&mut self, request: PlannedRequest, _pinned: &[IpAddr]) -> Sent {
        self.calls += 1;
        Sent {
            target: request.target().to_owned(),
            path: request.path().to_owned(),
        }
    }
}

/// One scripted DNS answer.
#[derive(Debug, Clone)]
pub struct Answer {
    /// Addresses the resolver returns.
    pub addrs: Vec<IpAddr>,
    /// CNAME chain the resolver reports (empty when none).
    pub cnames: Vec<String>,
}

/// A resolver whose answers are scripted per host: each call pops the next answer and the last answer repeats. The second
/// call gives the rebinding fixture's external address (review item A-4).
pub struct ScriptedResolver {
    answers: Mutex<BTreeMap<String, VecDeque<Answer>>>,
    /// Hosts queried, in order.
    pub calls: Arc<Mutex<Vec<String>>>,
}

impl ScriptedResolver {
    /// Build from `(host, answers)` pairs; each answer is a list of addresses (as text) and no CNAMEs.
    pub fn new(entries: &[(&str, Vec<Vec<&str>>)]) -> ScriptedResolver {
        let mut answers = BTreeMap::new();
        for (host, sequence) in entries {
            let parsed: VecDeque<Answer> = sequence
                .iter()
                .map(|addrs| Answer {
                    addrs: addrs
                        .iter()
                        .map(|addr| addr.parse::<IpAddr>().expect("test address"))
                        .collect(),
                    cnames: Vec::new(),
                })
                .collect();
            answers.insert((*host).to_owned(), parsed);
        }
        ScriptedResolver {
            answers: Mutex::new(answers),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Add a CNAME answer for a host (one answer, repeats).
    pub fn with_cname(self, host: &str, cname: &str, addrs: Vec<&str>) -> ScriptedResolver {
        let answer = Answer {
            addrs: addrs
                .iter()
                .map(|addr| addr.parse::<IpAddr>().expect("test address"))
                .collect(),
            cnames: vec![cname.to_owned()],
        };
        let mut guard = match self.answers.lock() {
            Ok(answers) => answers,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.insert(host.to_owned(), VecDeque::from(vec![answer]));
        drop(guard);
        self
    }

    /// Number of resolve calls made.
    pub fn call_count(&self) -> usize {
        match self.calls.lock() {
            Ok(calls) => calls.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }
}

impl Resolver for ScriptedResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Resolution>> {
        Box::pin(async move {
            match self.calls.lock() {
                Ok(mut calls) => calls.push(host.to_owned()),
                Err(poisoned) => poisoned.into_inner().push(host.to_owned()),
            }
            let mut answers = match self.answers.lock() {
                Ok(answers) => answers,
                Err(poisoned) => poisoned.into_inner(),
            };
            let Some(sequence) = answers.get_mut(host) else {
                return Err(io::Error::new(io::ErrorKind::NotFound, "unknown host"));
            };
            let answer = if sequence.len() > 1 {
                sequence.pop_front()
            } else {
                sequence.front().cloned()
            }
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no answer"))?;
            Ok(Resolution {
                addrs: answer.addrs,
                cnames: answer.cnames,
            })
        })
    }

    fn sees_cnames(&self) -> bool {
        true
    }
}

/// The platform address the example profile names (`198.51.100.20`).
pub fn platform_addresses() -> Vec<IpAddr> {
    vec!["198.51.100.20".parse().expect("address")]
}

/// A scripted resolver that answers the test and sandbox host names with the profile's platform address.
pub fn allowlisted_resolver() -> ScriptedResolver {
    ScriptedResolver::new(&[
        ("hddtest.example.com", vec![vec!["198.51.100.20"]]),
        ("hddsbx.example.com", vec![vec!["198.51.100.20"]]),
    ])
}
