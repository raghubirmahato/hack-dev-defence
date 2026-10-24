//! Profile loading, validation and the lifecycle/approval rules that decide whether a run may start.
//!
//! The profile is read with [`hdd_common::profile::parse_yaml`] and checked with [`hdd_common::profile::validate`]; the
//! runner never re-implements those rules. On top of them this module enforces the two human gates of the safety envelope:
//! `production` refuses destructive checks unless the operator approved that specific run (section 2.7), and the `load`
//! profile needs the operator's separate written approval for that run (section 2.3).

use std::fmt;
use std::path::Path;

use hdd_common::egress::allow::AllowError;
use hdd_common::egress::{TargetDenied, TargetGuard, TargetMode};
use hdd_common::profile::{Context, Profile, Status, parse_yaml, validate};

use crate::control::{Bannable, ControlError, VantagePlan, runner_bannable};
use crate::guard::EgressGate;
use crate::limits::LoadProfile;

/// The operator's approval of one specific run: the run id the ticket names and the maintenance window it covers. The run id
/// is what binds the ticket to *that run* (review item R-13): an approval for another run is refused, and the lifecycle gate
/// compares it with the run id of the executor that consults it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunApproval {
    run_id: String,
    maintenance_window: String,
}

impl RunApproval {
    /// Record an approval. The run id and the maintenance window must both be present: an empty string is not an approval
    /// (section 2.7 says the operator approves *that specific run*).
    pub fn new(
        run_id: impl Into<String>,
        maintenance_window: impl Into<String>,
    ) -> Result<RunApproval, ConfigError> {
        let run_id = run_id.into();
        let maintenance_window = maintenance_window.into();
        if run_id.trim().is_empty() {
            return Err(ConfigError::BadApproval {
                reason: "the approval names no run id".into(),
            });
        }
        if maintenance_window.trim().is_empty() {
            return Err(ConfigError::BadApproval {
                reason: "the maintenance window is empty".into(),
            });
        }
        Ok(RunApproval {
            run_id: run_id.trim().to_owned(),
            maintenance_window: maintenance_window.trim().to_owned(),
        })
    }

    /// Parse the `--operator-approval <ticket>` form the specification names (T-0492 step 7). The ticket format is
    /// `run=<run-id>; window=<maintenance window>`, both keys required, values non-empty, unknown or duplicate keys refused.
    /// This is the format the runner checks; it is documented in `docs/ACCEPTANCE.md`.
    pub fn parse_ticket(ticket: &str) -> Result<RunApproval, ConfigError> {
        let mut run: Option<String> = None;
        let mut window: Option<String> = None;
        for part in ticket.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let Some((key, value)) = part.split_once('=') else {
                return Err(ConfigError::BadApproval {
                    reason: format!("ticket part `{part}` is not `key=value`"),
                });
            };
            let value = value.trim();
            if value.is_empty() {
                return Err(ConfigError::BadApproval {
                    reason: format!("ticket key `{}` has an empty value", key.trim()),
                });
            }
            match key.trim() {
                "run" => {
                    if run.replace(value.to_owned()).is_some() {
                        return Err(ConfigError::BadApproval {
                            reason: "ticket gives `run=` twice".to_owned(),
                        });
                    }
                }
                "window" => {
                    if window.replace(value.to_owned()).is_some() {
                        return Err(ConfigError::BadApproval {
                            reason: "ticket gives `window=` twice".to_owned(),
                        });
                    }
                }
                other => {
                    return Err(ConfigError::BadApproval {
                        reason: format!(
                            "ticket key `{other}` is not part of the format (`run=<id>; window=<window>`)"
                        ),
                    });
                }
            }
        }
        let run = run.ok_or_else(|| ConfigError::BadApproval {
            reason: "the ticket has no `run=` key".to_owned(),
        })?;
        let window = window.ok_or_else(|| ConfigError::BadApproval {
            reason: "the ticket has no `window=` key".to_owned(),
        })?;
        RunApproval::new(run, window)
    }

    /// The run id the approval names.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// The maintenance window the approval covers.
    pub fn maintenance_window(&self) -> &str {
        &self.maintenance_window
    }
}

/// Why the lifecycle stage refused a destructive check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageRefusal {
    /// The profile is in `production` and this run has no recorded approval.
    ProductionRequiresApproval,
    /// The recorded approval names a different run: it does not authorise this one (review item R-13).
    ApprovalForAnotherRun {
        /// The run id the approval names.
        approved: String,
        /// The run id that tried to use it.
        run: String,
    },
}

impl fmt::Display for StageRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StageRefusal::ProductionRequiresApproval => f.write_str(
                "lifecycle_stage is production: destructive checks are refused for this run without the operator's \
                 explicit approval and a maintenance window (section 2.7)",
            ),
            StageRefusal::ApprovalForAnotherRun { approved, run } => write!(
                f,
                "lifecycle_stage is production: the operator's approval names run `{approved}`, not this run `{run}`; a \
                 destructive check is refused (section 2.7)"
            ),
        }
    }
}

impl std::error::Error for StageRefusal {}

/// The lifecycle rules of section 2.7, with the approval of this run when one was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecyclePolicy {
    stage: hdd_common::profile::types::LifecycleStage,
    approval: Option<RunApproval>,
}

impl LifecyclePolicy {
    /// The policy for this stage and run.
    pub fn new(
        stage: hdd_common::profile::types::LifecycleStage,
        approval: Option<RunApproval>,
    ) -> LifecyclePolicy {
        LifecyclePolicy { stage, approval }
    }

    /// The stage.
    pub fn stage(&self) -> hdd_common::profile::types::LifecycleStage {
        self.stage
    }

    /// The approval of this run, when one was given.
    pub fn approval(&self) -> Option<&RunApproval> {
        self.approval.as_ref()
    }

    /// May this run execute a destructive check?
    ///
    /// * `pilot`: yes, with a warning (see [`LifecyclePolicy::warning`]).
    /// * `production`: only with an explicit approval of **this** run; no approval, or an approval that names another run,
    ///   is refused.
    ///
    /// This is the one production rule (review item R-13): the executor consults it for every destructive check with its own
    /// run id, and the connector consults it before every destructive send; [`RunnerConfig::build`] also refuses a run whose
    /// approval names another run, so the two layers agree.
    pub fn allows_destructive_for(&self, run_id: &str) -> Result<(), StageRefusal> {
        use hdd_common::profile::types::LifecycleStage;
        match self.stage {
            LifecycleStage::Pilot => Ok(()),
            LifecycleStage::Production => match self.approval.as_ref() {
                None => Err(StageRefusal::ProductionRequiresApproval),
                Some(approval) if approval.run_id() == run_id => Ok(()),
                Some(approval) => Err(StageRefusal::ApprovalForAnotherRun {
                    approved: approval.run_id().to_owned(),
                    run: run_id.to_owned(),
                }),
            },
        }
    }

    /// The warning a destructive run must carry in its report, when the stage warrants one.
    pub fn warning(&self) -> Option<&'static str> {
        use hdd_common::profile::types::LifecycleStage;
        match self.stage {
            LifecycleStage::Pilot => Some(
                "lifecycle_stage is pilot: destructive checks run with a warning (section 2.7); no production traffic \
                 crosses HDD yet",
            ),
            LifecycleStage::Production => None,
        }
    }
}

/// Why loading or assembling the runner configuration failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The profile file could not be read.
    Io {
        /// Path that was read.
        path: String,
        /// What the operating system reported.
        message: String,
    },
    /// The profile did not parse (unknown key, wrong type, oversized document).
    Parse {
        /// The parser's message, with its key path.
        message: String,
    },
    /// The profile parsed but `validate` found FAIL findings; the runner refuses to start on an unusable profile.
    InvalidProfile {
        /// One line per FAIL finding.
        failures: Vec<String>,
    },
    /// The profile's `egress_allowlist` has invalid entries.
    Egress {
        /// The invalid entries.
        errors: Vec<(usize, AllowError)>,
    },
    /// The target set derived from the profile is not usable.
    Target {
        /// The reason from the target guard.
        reason: TargetDenied,
    },
    /// A `load` run was requested without both the profile flag and this run's written approval.
    LoadNotApproved {
        /// What is missing.
        detail: String,
    },
    /// The selected rate/load profile may not run in this target mode (spec section 2.3, review item R-1).
    ProfileModeMismatch {
        /// The profile that was asked for.
        profile: LoadProfile,
        /// The target mode of the run.
        mode: TargetMode,
    },
    /// The operator's approval names a different run than the one that would run (review item R-13).
    ApprovalForAnotherRun {
        /// The run id the approval names.
        approved: String,
        /// The run id of this run.
        run: String,
    },
    /// An approval was malformed (empty record or empty maintenance window).
    BadApproval {
        /// What is missing.
        reason: String,
    },
    /// The runner IP is not bannable, or the control-plane facts could not be established.
    Control {
        /// The reason.
        reason: ControlError,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io { path, message } => write!(f, "cannot read {path}: {message}"),
            ConfigError::Parse { message } => write!(f, "profile does not parse: {message}"),
            ConfigError::InvalidProfile { failures } => {
                writeln!(
                    f,
                    "profile validation failed ({} finding(s)):",
                    failures.len()
                )?;
                for failure in failures {
                    writeln!(f, "  - {failure}")?;
                }
                Ok(())
            }
            ConfigError::Egress { errors } => {
                write!(f, "egress_allowlist has {} invalid entries", errors.len())
            }
            ConfigError::Target { reason } => write!(f, "target guard: {reason}"),
            ConfigError::LoadNotApproved { detail } => write!(f, "load run refused: {detail}"),
            ConfigError::ProfileModeMismatch { profile, mode } => write!(
                f,
                "profile/mode refusal: the `{profile}` load profile may not run in {mode:?} target mode (section 2.3)"
            ),
            ConfigError::ApprovalForAnotherRun { approved, run } => write!(
                f,
                "run approval: the operator's approval names run `{approved}`, not this run `{run}`; an approval covers only \
                 the run it names (section 2.7)"
            ),
            ConfigError::BadApproval { reason } => write!(f, "run approval: {reason}"),
            ConfigError::Control { reason } => write!(f, "control plane: {reason}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Read and parse a profile file. Validation is a separate step ([`RunnerConfig::build`]) so a dry run can report parsing
/// problems without needing a complete live profile.
pub fn load_profile_file(path: &Path) -> Result<Profile, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;
    load_profile_text(&text)
}

/// Parse a profile from text (UTF-8, no BOM handling here: the parser rejects a BOM as an unknown key).
pub fn load_profile_text(text: &str) -> Result<Profile, ConfigError> {
    parse_yaml(text).map_err(|e| ConfigError::Parse {
        message: e.to_string(),
    })
}

/// The assembled runner configuration: everything a run needs before its first check starts.
#[derive(Debug, Clone)]
pub struct RunnerConfig {
    /// The validated live profile.
    pub profile: Profile,
    /// Live or lab target set.
    pub mode: TargetMode,
    /// The rate/load profile selected for this run.
    pub load_profile: LoadProfile,
    /// The id of this run; the operator's approval ticket must name it (review item R-13).
    pub run_id: String,
    /// The control-plane config_revision this run plans against; the executor derives its gate revision, revision source and
    /// resume binding from it in one place (review item N-7).
    pub config_revision: String,
    /// The lifecycle stage of the profile; checked against the lifecycle policy by Executor::from_config (review item N-7).
    pub stage: hdd_common::profile::types::LifecycleStage,
    /// Lifecycle rules with this run's approval.
    pub lifecycle: LifecyclePolicy,
    /// The egress allowlist gate derived from the profile.
    pub egress: EgressGate,
    /// How vantages are used (section 2.4, E3.1 rule 2).
    pub vantage: VantagePlan,
    /// Whether the runner IP is bannable (section 2.4).
    pub runner: Bannable,
}

impl RunnerConfig {
    /// Validate the profile and assemble the run configuration.
    ///
    /// Refuses to start when: `validate` reports a FAIL finding; the rate/load profile may not run in this target mode; the
    /// egress allowlist does not parse; the target set derived from the profile is empty or malformed; a `load` run lacks the
    /// profile flag or this run's written approval; the approval names another run; the runner IP is in `admin_cidrs`.
    #[allow(
        clippy::too_many_arguments,
        reason = "the assembled run configuration is the caller's whole input"
    )]
    pub fn build(
        profile: Profile,
        mode: TargetMode,
        load_profile: LoadProfile,
        approval: Option<RunApproval>,
        run_id: impl Into<String>,
        runner_ip: Option<std::net::IpAddr>,
    ) -> Result<RunnerConfig, ConfigError> {
        let run_id = run_id.into();
        let run_id = run_id.trim().to_owned();
        if run_id.is_empty() {
            return Err(ConfigError::BadApproval {
                reason: "the run has no id; an approval ticket is bound to a run id (section 2.7)"
                    .to_owned(),
            });
        }
        if !load_profile.allows_mode(mode) {
            return Err(ConfigError::ProfileModeMismatch {
                profile: load_profile,
                mode,
            });
        }
        let report = validate(&profile, &Context { runner_ip });
        let failures: Vec<String> = report
            .findings
            .iter()
            .filter(|f| f.status == Status::Fail)
            .map(|f| format!("{} {}: {} -> {}", f.rule, f.field, f.message, f.remediation))
            .collect();
        if !failures.is_empty() {
            return Err(ConfigError::InvalidProfile { failures });
        }

        let egress =
            EgressGate::from_profile(&profile).map_err(|errors| ConfigError::Egress { errors })?;
        TargetGuard::from_profile(&profile, mode)
            .map_err(|reason| ConfigError::Target { reason })?;

        if let Some(approval) = &approval
            && approval.run_id() != run_id
        {
            return Err(ConfigError::ApprovalForAnotherRun {
                approved: approval.run_id().to_owned(),
                run: run_id,
            });
        }

        if load_profile.requires_written_approval() {
            let reason = if !profile.load_profile_approved {
                Some(
                    "the profile sets load_profile_approved: false; the operator's written approval for this run must be \
                     recorded first (section 2.3)",
                )
            } else if approval.is_none() {
                Some(
                    "load_profile_approved is true but this run carries no recorded approval; a `load` run needs the \
                     operator's separate written approval for that run",
                )
            } else {
                None
            };
            if let Some(detail) = reason {
                return Err(ConfigError::LoadNotApproved {
                    detail: detail.to_owned(),
                });
            }
        }

        let runner = runner_bannable(&profile, runner_ip)
            .map_err(|reason| ConfigError::Control { reason })?;
        let vantage = VantagePlan::from_profile(&profile);
        let stage = profile.lifecycle_stage;
        let lifecycle = LifecyclePolicy::new(stage, approval);
        Ok(RunnerConfig {
            profile,
            mode,
            load_profile,
            run_id,
            config_revision: String::new(),
            stage,
            lifecycle,
            egress,
            vantage,
            runner,
        })
    }
}

#[cfg(test)]
mod tests;
