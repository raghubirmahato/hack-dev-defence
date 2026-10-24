//! The status taxonomy of E3.1 rule 1 and the status line every report is built from.
//!
//! Exactly three statuses exist: `PASS`, `FAIL(reason)` and `UNVERIFIED(reason_code)`. The reason-code set is closed; there is
//! no "skipped" and no "pending" outside it. A `PASS` is only representable together with at least one evidence reference
//! carrying a SHA-256, because a pass without an artifact is not a pass (E3.1 rule 1, R-02).

use std::fmt;

use serde::{Deserialize, Serialize};

/// One UNVERIFIED reason code (E3.1 rule 1). The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    /// The operator has not supplied the capability, data or tool.
    CapabilityNotSupplied,
    /// A human step (delegation, provider confirmation) is pending.
    HumanStepPending,
    /// This environment cannot run the check.
    EnvironmentUnsupported,
    /// The external oracle (scanner, tool container) is not available.
    OracleUnavailable,
    /// A required tool is missing on this machine.
    ToolUnavailable,
    /// A later delivery stage owns the check; it is not implemented yet.
    StageNotReached,
    /// The lifecycle stage forbids the check (for example a destructive check in `production`).
    StageForbids,
    /// The operator stopped this run (kill switch or an explicit skip).
    SkippedByOperator,
}

impl ReasonCode {
    /// Every reason code, in documentation order.
    pub const ALL: [ReasonCode; 8] = [
        ReasonCode::CapabilityNotSupplied,
        ReasonCode::HumanStepPending,
        ReasonCode::EnvironmentUnsupported,
        ReasonCode::OracleUnavailable,
        ReasonCode::ToolUnavailable,
        ReasonCode::StageNotReached,
        ReasonCode::StageForbids,
        ReasonCode::SkippedByOperator,
    ];

    /// The code as written in reports (`stage_not_reached`).
    pub fn code(self) -> &'static str {
        match self {
            ReasonCode::CapabilityNotSupplied => "capability_not_supplied",
            ReasonCode::HumanStepPending => "human_step_pending",
            ReasonCode::EnvironmentUnsupported => "environment_unsupported",
            ReasonCode::OracleUnavailable => "oracle_unavailable",
            ReasonCode::ToolUnavailable => "tool_unavailable",
            ReasonCode::StageNotReached => "stage_not_reached",
            ReasonCode::StageForbids => "stage_forbids",
            ReasonCode::SkippedByOperator => "skipped_by_operator",
        }
    }

    /// Parse a report code (whole token only).
    pub fn parse(s: &str) -> Option<ReasonCode> {
        ReasonCode::ALL
            .into_iter()
            .find(|reason| reason.code() == s.trim())
    }
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// A reference to an evidence artifact: a path and its SHA-256.
///
/// The fields are private (review item S-6): a struct literal cannot bypass the hashing done by [`crate::report::EvidenceStore`].
/// The guarantee is against a check written by us that makes a mistake, not against hostile code inside this crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    path: String,
    sha256: String,
    bytes: u64,
}

impl EvidenceRef {
    /// A reference; the hash is not recomputed here (the evidence store did that). Crate-internal: only
    /// [`crate::report::EvidenceStore`] builds one from the bytes it wrote, and the executor re-reads and re-verifies the file
    /// before accepting a PASS (review item R-4).
    pub(crate) fn new(
        path: impl Into<String>,
        sha256: impl Into<String>,
        bytes: u64,
    ) -> EvidenceRef {
        EvidenceRef {
            path: path.into(),
            sha256: sha256.into(),
            bytes,
        }
    }

    /// Path of the artifact (relative to the acceptance run directory or absolute, as recorded).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Lowercase hex SHA-256 of the artifact, 64 characters.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Size of the artifact in bytes.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// True when the hash looks like a SHA-256 value, so a reference cannot satisfy the pass rule with an empty string.
    pub fn hash_is_sha256(&self) -> bool {
        self.sha256.len() == 64 && self.sha256.chars().all(|c| c.is_ascii_hexdigit())
    }
}

/// The verdict of one check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Verdict {
    /// The check passed; the evidence references live on the status line.
    Pass,
    /// The check failed, with a short reason that is safe to show.
    Fail {
        /// What went wrong, no secrets (redacted again by the renderer).
        reason: String,
    },
    /// The check could not decide, with a closed reason code.
    Unverified {
        /// The closed reason code.
        reason: ReasonCode,
    },
}

impl Verdict {
    /// A `FAIL` with a reason.
    pub fn fail(reason: impl Into<String>) -> Verdict {
        Verdict::Fail {
            reason: reason.into(),
        }
    }

    /// An `UNVERIFIED` with a reason code.
    pub fn unverified(reason: ReasonCode) -> Verdict {
        Verdict::Unverified { reason }
    }

    /// True for `PASS`.
    pub fn is_pass(&self) -> bool {
        matches!(self, Verdict::Pass)
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Pass => f.write_str("PASS"),
            Verdict::Fail { reason } => write!(f, "FAIL({reason})"),
            Verdict::Unverified { reason } => write!(f, "UNVERIFIED({})", reason.code()),
        }
    }
}

/// Why a status line is not representable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaxonomyError {
    /// A `PASS` without an evidence reference whose hash is a SHA-256.
    PassWithoutEvidence {
        /// The check id of the offending line.
        id: String,
    },
    /// An empty id, or an id that is not an `AC-nn` whole token.
    BadId {
        /// The offending id.
        id: String,
    },
    /// A report with two lines for one id.
    DuplicateId {
        /// The duplicated id.
        id: String,
    },
}

impl fmt::Display for TaxonomyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaxonomyError::PassWithoutEvidence { id } => write!(
                f,
                "{id}: a PASS needs at least one evidence artifact with a SHA-256 (E3.1 rule 1)"
            ),
            TaxonomyError::BadId { id } => {
                write!(f, "`{id}` is not an AC-nn check id")
            }
            TaxonomyError::DuplicateId { id } => write!(f, "check id `{id}` appears twice"),
        }
    }
}

impl std::error::Error for TaxonomyError {}

/// One line of the report: exactly one per registered check id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusLine {
    /// Check id, an `AC-nn` whole token such as `AC-00`.
    pub id: String,
    /// Human title from Appendix E3.
    pub title: String,
    /// Suite tier from Appendix E2 (`smoke`, `nondestructive`, ...).
    pub tier: String,
    /// The verdict.
    pub verdict: Verdict,
    /// Evidence artifacts backing the verdict.
    pub evidence: Vec<EvidenceRef>,
    /// Optional human message (for example which dependency did not pass). Rendered with the line; skipped when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl StatusLine {
    /// Build a status line, refusing a `PASS` that carries no hash-backed evidence.
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        tier: impl Into<String>,
        verdict: Verdict,
        evidence: Vec<EvidenceRef>,
    ) -> Result<StatusLine, TaxonomyError> {
        let line = StatusLine {
            id: id.into(),
            title: title.into(),
            tier: tier.into(),
            verdict,
            evidence,
            detail: None,
        };
        line.validate()?;
        Ok(line)
    }

    /// A line for a check that is not implemented yet (`UNVERIFIED(stage_not_reached)`).
    pub fn stage_not_reached(
        id: impl Into<String>,
        title: impl Into<String>,
        tier: impl Into<String>,
    ) -> StatusLine {
        StatusLine {
            id: id.into(),
            title: title.into(),
            tier: tier.into(),
            verdict: Verdict::unverified(ReasonCode::StageNotReached),
            evidence: Vec::new(),
            detail: None,
        }
    }

    /// Add a detail message naming the reason a check did not run (for example the dependency id).
    pub fn with_detail(mut self, detail: impl Into<String>) -> StatusLine {
        self.detail = Some(detail.into());
        self
    }

    /// Check the line's invariants: a well-formed id and a PASS backed by hashed evidence.
    pub fn validate(&self) -> Result<(), TaxonomyError> {
        if !is_check_id(&self.id) {
            return Err(TaxonomyError::BadId {
                id: self.id.clone(),
            });
        }
        if self.verdict.is_pass() && !self.evidence.iter().any(EvidenceRef::hash_is_sha256) {
            return Err(TaxonomyError::PassWithoutEvidence {
                id: self.id.clone(),
            });
        }
        Ok(())
    }
}

/// True when `id` is exactly `AC-` followed by two ASCII digits (whole token, so `AC-0` and `AC-100` are refused).
pub fn is_check_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    bytes.len() == 5
        && bytes.get(..3) == Some(b"AC-")
        && bytes.get(3).is_some_and(u8::is_ascii_digit)
        && bytes.get(4).is_some_and(u8::is_ascii_digit)
}

/// Counts per status for a report header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    /// Number of `PASS` lines.
    pub pass: usize,
    /// Number of `FAIL` lines.
    pub fail: usize,
    /// Number of `UNVERIFIED` lines.
    pub unverified: usize,
}

impl Counts {
    /// Total number of lines counted.
    pub fn total(&self) -> usize {
        self.pass + self.fail + self.unverified
    }
}

#[cfg(test)]
mod tests;
