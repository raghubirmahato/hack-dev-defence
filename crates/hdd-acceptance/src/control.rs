//! Out-of-band control-plane plumbing, without any network access.
//!
//! The runner reaches the control plane over an SSH tunnel or WireGuard (section 2.4), never through the data plane. This
//! module contains the parts of step 4 that can be checked without a peer: the runner-IP bannability check (reusing
//! [`hdd_common::profile::validate`]'s `PROF-RUNNER-ADMIN` rule so the two never disagree), typed SSH argv construction that
//! never executes a command and never interpolates a secret through a shell, and the vantage-point plan of E3.1 rule 2.
//!
//! Everything that needs a real SSH or WireGuard peer is `UNVERIFIED(capability_not_supplied)` in reports and in
//! `docs/ACCEPTANCE.md`; no code here opens a socket or spawns a process.

use std::fmt;
use std::net::IpAddr;

use hdd_common::net::Cidr;
use hdd_common::profile::{Context, Profile, Status, validate};

use crate::status::ReasonCode;

/// The SSH options that make the command usable without a terminal and without a surprise host-key prompt.
pub const SSH_OPTIONS: [(&str, &str); 4] = [
    ("BatchMode", "yes"),
    ("StrictHostKeyChecking", "yes"),
    ("ConnectTimeout", "10"),
    ("IdentitiesOnly", "yes"),
];

/// Why the control-plane facts could not be established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlError {
    /// `admin_cidrs` contains the runner IP, so the runner is not bannable (section 2.4).
    NotBannable {
        /// The runner address.
        runner: IpAddr,
        /// The matching CIDR from `admin_cidrs`.
        matched: String,
    },
    /// `test_runner.public_ip` is neither `auto` nor an IP address.
    MalformedRunnerIp {
        /// The text in the profile (redacted to a short preview).
        text: String,
    },
    /// The SSH details the command needs are missing.
    MissingSshConfig {
        /// The dotted field that is empty.
        field: &'static str,
    },
    /// The profile selects WireGuard, so there is no SSH command to build.
    WireguardSelected,
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControlError::NotBannable { runner, matched } => write!(
                f,
                "the runner IP {runner} is inside admin_cidrs entry {matched}; the runner must stay bannable (section 2.4)"
            ),
            ControlError::MalformedRunnerIp { text } => write!(
                f,
                "test_runner.public_ip `{text}` is neither `auto` nor an IP address"
            ),
            ControlError::MissingSshConfig { field } => {
                write!(f, "the profile does not set `{field}`, so no SSH command can be built")
            }
            ControlError::WireguardSelected => f.write_str(
                "test_runner.control_plane_access is wireguard; WireGuard peer management is not supplied in this \
                 environment (UNVERIFIED(capability_not_supplied))",
            ),
        }
    }
}

impl std::error::Error for ControlError {}

/// The result of the preflight bannability check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bannable {
    /// The runner address is known and is not in `admin_cidrs`.
    Bannable {
        /// The runner address.
        runner: IpAddr,
    },
    /// The profile says `auto`: the address is only known after the canary echo, so the check cannot be completed here.
    Unverified {
        /// Always `stage_not_reached` for this check in the skeleton.
        reason: ReasonCode,
    },
}

impl Bannable {
    /// True when the runner address was known and is not in `admin_cidrs`.
    pub fn is_bannable(&self) -> bool {
        matches!(self, Bannable::Bannable { .. })
    }
}

impl fmt::Display for Bannable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bannable::Bannable { runner } => write!(f, "runner IP {runner} is not in admin_cidrs"),
            Bannable::Unverified { reason } => write!(
                f,
                "runner IP is `auto` and is discovered at run time: UNVERIFIED({})",
                reason.code()
            ),
        }
    }
}

/// Check that the runner IP is bannable: it must never be inside `admin_cidrs` (section 2.4).
///
/// The rule is the same one `validate` applies (`PROF-RUNNER-ADMIN`); this function reads that finding instead of
/// duplicating the comparison, so the two cannot drift.
pub fn runner_bannable(p: &Profile, runner_ip: Option<IpAddr>) -> Result<Bannable, ControlError> {
    let report = validate(p, &Context { runner_ip });
    let finding = report
        .findings
        .iter()
        .find(|f| f.rule == "PROF-RUNNER-ADMIN");
    let Some(finding) = finding else {
        return Err(ControlError::MalformedRunnerIp {
            text: "<the validator reported no PROF-RUNNER-ADMIN finding>".into(),
        });
    };
    match finding.status {
        Status::Pass => {
            let ip = runner_ip
                .or_else(|| p.test_runner.public_ip.trim().parse::<IpAddr>().ok())
                .ok_or_else(|| ControlError::MalformedRunnerIp {
                    text: preview(&p.test_runner.public_ip),
                })?;
            Ok(Bannable::Bannable { runner: ip })
        }
        Status::Unverified(_) => Ok(Bannable::Unverified {
            reason: ReasonCode::StageNotReached,
        }),
        _ => {
            let ip = runner_ip
                .or_else(|| p.test_runner.public_ip.trim().parse::<IpAddr>().ok())
                .ok_or_else(|| ControlError::MalformedRunnerIp {
                    text: preview(&p.test_runner.public_ip),
                })?;
            let matched = p
                .admin_cidrs
                .iter()
                .find(|c| c.parse::<Cidr>().is_ok_and(|cidr| cidr.contains(ip)))
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_owned());
            Err(ControlError::NotBannable {
                runner: ip,
                matched,
            })
        }
    }
}

fn preview(text: &str) -> String {
    let text = text.trim();
    if text.len() <= 40 {
        text.to_owned()
    } else {
        format!("{}...", text.chars().take(40).collect::<String>())
    }
}

/// An SSH command as an argv vector. It is constructed and tested, never executed by this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshCommand {
    argv: Vec<String>,
}

impl SshCommand {
    /// The argv vector: `argv[0]` is the program, the rest are arguments. No element is split, so a remote argument
    /// containing a shell metacharacter stays one argument.
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// The `user@host` destination.
    pub fn destination(&self) -> Option<&str> {
        self.argv
            .iter()
            .find(|a| a.contains('@') && !a.starts_with('-'))
            .map(String::as_str)
    }

    /// The remote program (the first element after the `--` separator).
    pub fn remote_program(&self) -> Option<&str> {
        let idx = self.argv.iter().position(|a| a == "--")?;
        self.argv.get(idx + 1).map(String::as_str)
    }
}

/// Build the SSH argv for an out-of-band command. Nothing is executed and no shell is involved: a remote argument such as
/// `; rm -rf /` remains one argv element, so it can never be interpreted as a second command by the local shell.
pub fn ssh_command(
    p: &Profile,
    remote_program: &str,
    remote_args: &[&str],
) -> Result<SshCommand, ControlError> {
    use hdd_common::profile::types::ControlPlaneAccess;
    if p.test_runner.control_plane_access == ControlPlaneAccess::Wireguard {
        return Err(ControlError::WireguardSelected);
    }
    let host = p.platform.ssh.host.trim();
    if host.is_empty() {
        return Err(ControlError::MissingSshConfig {
            field: "platform.ssh.host",
        });
    }
    let user = p.platform.ssh.user.trim();
    if user.is_empty() {
        return Err(ControlError::MissingSshConfig {
            field: "platform.ssh.user",
        });
    }
    let key = p.platform.ssh.key_path.expose_path().trim();
    if key.is_empty() {
        return Err(ControlError::MissingSshConfig {
            field: "platform.ssh.key_path",
        });
    }
    if remote_program.trim().is_empty() {
        return Err(ControlError::MissingSshConfig {
            field: "remote program",
        });
    }
    let mut argv = Vec::with_capacity(16 + remote_args.len());
    argv.push("ssh".to_owned());
    for (name, value) in SSH_OPTIONS {
        argv.push("-o".to_owned());
        argv.push(format!("{name}={value}"));
    }
    argv.push("-i".to_owned());
    argv.push(key.to_owned());
    argv.push(format!("{user}@{host}"));
    argv.push("--".to_owned());
    argv.push(remote_program.to_owned());
    for arg in remote_args {
        argv.push((*arg).to_owned());
    }
    Ok(SshCommand { argv })
}

/// How vantages are used by a run (E3.1 rule 2, section 2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VantageStrategy {
    /// Several sources are configured; each is used for its own vantage.
    PerPoint,
    /// No vantage point is configured: tests needing several sources run sequentially with an unban between each.
    SequentialWithUnban,
}

/// The vantage plan of a run: the configured points (names only) and the strategy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VantagePlan {
    points: Vec<String>,
    strategy: VantageStrategy,
}

impl VantagePlan {
    /// Derive the plan from the profile's `vantage_points`. The names are reported; no connection is made.
    pub fn from_profile(p: &Profile) -> VantagePlan {
        let points: Vec<String> = p
            .vantage_points
            .iter()
            .map(|v| {
                if v.name.trim().is_empty() {
                    v.ssh_host.trim().to_owned()
                } else {
                    v.name.trim().to_owned()
                }
            })
            .filter(|name| !name.is_empty())
            .collect();
        let strategy = if points.is_empty() {
            VantageStrategy::SequentialWithUnban
        } else {
            VantageStrategy::PerPoint
        };
        VantagePlan { points, strategy }
    }

    /// The vantage names.
    pub fn points(&self) -> &[String] {
        &self.points
    }

    /// The strategy.
    pub fn strategy(&self) -> VantageStrategy {
        self.strategy
    }

    /// The number of vantages the report must record (0 when the sequential strategy is used).
    pub fn count(&self) -> usize {
        self.points.len()
    }

    /// Live vantage use needs an SSH/SOCKS peer that this environment does not supply; every check that depends on it is
    /// `UNVERIFIED(capability_not_supplied)` until the peer exists.
    pub fn live_use_reason(&self) -> ReasonCode {
        ReasonCode::CapabilityNotSupplied
    }
}

#[cfg(test)]
mod tests;
