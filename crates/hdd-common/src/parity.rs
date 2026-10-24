//! The parity contract of R-31 (T-0561 step 5, AC-55): the same input must give the same verdict in `local` and `hosted`.
//!
//! The harness compares the decision fields (action, category, subtype, rule id, hardness, score, threshold, vector, field,
//! evidence) and the ban intent (reason, scope, TTL step) of two backends over the same cases. It ignores exactly the fields
//! the specification excludes: the identity key, the enforcement backend, `config_revision` and timestamps. Every other
//! difference is reported. The backends are supplied by the caller (the detection engine and the ban pipeline arrive with
//! later tasks); with no backend or no case the outcome is UNVERIFIED, never a vacuous pass.

use std::fmt;

/// The comparison suites of T-0561 step 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Suite {
    /// The six mandated SQL injection payloads (M1 to M6) and their variants.
    CoreSqli,
    /// The benign corpus.
    Benign,
    /// The cross-tenant (BOLA) suite.
    Bola,
    /// A ban lifecycle scenario.
    BanLifecycle,
}

/// One input shared by both backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    /// Stable id (for example the fixture file name).
    pub id: String,
    /// Suite.
    pub suite: Suite,
    /// The input the backends are given (a request description, owned by the fixture format).
    pub input: String,
}

/// The decision fields that must be identical.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decision {
    /// `allow`, `would_block`, `block`, ...
    pub action: String,
    /// Category such as `sqli`.
    pub category: String,
    /// Subtype.
    pub subtype: String,
    /// Rule id.
    pub rule_id: String,
    /// Hardness class of the rule.
    pub hardness: String,
    /// Score.
    pub score: u32,
    /// Threshold the score was compared with.
    pub threshold: u32,
    /// Vector (query, body, header, ...).
    pub vector: String,
    /// Field within the vector.
    pub field: String,
    /// Redacted evidence (at most 512 bytes, R-25).
    pub evidence: String,
}

/// The ban a decision would cause.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BanIntent {
    /// Reason code.
    pub reason: String,
    /// Scope (site, global).
    pub scope: String,
    /// Step on the TTL ladder.
    pub ttl_step: u32,
}

/// Everything one backend reports for one case. Only `decision` and `ban` take part in the comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observation {
    /// Decision fields.
    pub decision: Decision,
    /// Ban intent, when a ban would follow.
    pub ban: Option<BanIntent>,
    /// Identity key of the client (excluded: loopback clients are keyed differently in `local`).
    pub identity_key: String,
    /// Which enforcement backend acted (excluded: `Noop` in `local`).
    pub enforcement_backend: String,
    /// Config revision (excluded).
    pub config_revision: u64,
    /// Time of the decision (excluded).
    pub at_unix_ms: u64,
}

/// One side of the comparison, for example the pipeline wired for `local` or for `hosted`.
pub trait ParityBackend {
    /// Name used in reports.
    fn name(&self) -> &str;
    /// Run a case. An error is reported, never ignored.
    fn run(&self, case: &Case) -> Result<Observation, String>;
}

/// One difference between the two backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Difference {
    /// Case id.
    pub case: String,
    /// Compared field, for example `decision.rule_id` or `ban`.
    pub field: &'static str,
    /// Value on the first backend.
    pub left: String,
    /// Value on the second backend.
    pub right: String,
}

impl fmt::Display for Difference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}: `{}` != `{}`",
            self.case, self.field, self.left, self.right
        )
    }
}

/// The result of a comparison that ran.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParityReport {
    /// Number of cases compared.
    pub compared: usize,
    /// Differences in the compared fields.
    pub differences: Vec<Difference>,
    /// Cases a backend could not run, with the message.
    pub errors: Vec<(String, String)>,
}

impl ParityReport {
    /// Zero differences and zero errors.
    pub fn is_clean(&self) -> bool {
        self.differences.is_empty() && self.errors.is_empty()
    }
}

/// The outcome of a parity run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The comparison ran.
    Compared(ParityReport),
    /// It could not run; the reason is what is missing.
    Unverified(&'static str),
}

macro_rules! cmp_field {
    ($out:expr, $case:expr, $name:literal, $a:expr, $b:expr) => {
        if $a != $b {
            $out.push(Difference {
                case: $case.to_owned(),
                field: $name,
                left: $a.to_string(),
                right: $b.to_string(),
            });
        }
    };
}

/// Compare two observations of the same case on the compared fields only.
pub fn diff(case: &str, a: &Observation, b: &Observation) -> Vec<Difference> {
    let mut out = Vec::new();
    let (x, y) = (&a.decision, &b.decision);
    cmp_field!(out, case, "decision.action", x.action, y.action);
    cmp_field!(out, case, "decision.category", x.category, y.category);
    cmp_field!(out, case, "decision.subtype", x.subtype, y.subtype);
    cmp_field!(out, case, "decision.rule_id", x.rule_id, y.rule_id);
    cmp_field!(out, case, "decision.hardness", x.hardness, y.hardness);
    cmp_field!(out, case, "decision.score", x.score, y.score);
    cmp_field!(out, case, "decision.threshold", x.threshold, y.threshold);
    cmp_field!(out, case, "decision.vector", x.vector, y.vector);
    cmp_field!(out, case, "decision.field", x.field, y.field);
    cmp_field!(out, case, "decision.evidence", x.evidence, y.evidence);
    match (&a.ban, &b.ban) {
        (None, None) => {}
        (Some(p), Some(q)) => {
            cmp_field!(out, case, "ban.reason", p.reason, q.reason);
            cmp_field!(out, case, "ban.scope", p.scope, q.scope);
            cmp_field!(out, case, "ban.ttl_step", p.ttl_step, q.ttl_step);
        }
        (p, q) => out.push(Difference {
            case: case.to_owned(),
            field: "ban",
            left: p.as_ref().map_or("no ban".to_owned(), |b| {
                format!("{} {} step {}", b.reason, b.scope, b.ttl_step)
            }),
            right: q.as_ref().map_or("no ban".to_owned(), |b| {
                format!("{} {} step {}", b.reason, b.scope, b.ttl_step)
            }),
        }),
    }
    out
}

/// Run every case on both backends and compare. No case, a missing side or two sides with the same name is not a comparison.
pub fn run(
    cases: &[Case],
    left: Option<&dyn ParityBackend>,
    right: Option<&dyn ParityBackend>,
) -> Outcome {
    let (Some(left), Some(right)) = (left, right) else {
        return Outcome::Unverified("a backend for each profile has not been supplied");
    };
    if cases.is_empty() {
        return Outcome::Unverified("no cases were supplied");
    }
    if left.name() == right.name() {
        // two sides with the same name are the same backend (or a copy): they would always agree
        return Outcome::Unverified("both sides are the same backend");
    }
    let mut report = ParityReport::default();
    for case in cases {
        match (left.run(case), right.run(case)) {
            (Ok(a), Ok(b)) => {
                report.compared += 1;
                report.differences.extend(diff(&case.id, &a, &b));
            }
            (Err(e), _) => report
                .errors
                .push((case.id.clone(), format!("{}: {e}", left.name()))),
            (_, Err(e)) => report
                .errors
                .push((case.id.clone(), format!("{}: {e}", right.name()))),
        }
    }
    Outcome::Compared(report)
}

#[cfg(test)]
mod tests;
