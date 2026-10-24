//! What can run on this machine: the build track and the acceptance plan (T-0561 steps 6 and 7).
//!
//! `hddctl preflight` gives a Windows builder without Docker an honest plan instead of an error. Everything here is pure: the
//! facts are passed in ([`Facts`]); [`Facts::detect`] only looks for executable files on `PATH` (it never starts a program,
//! so it cannot hang and touches no network). The acceptance checks come from the registry of Appendix E3 ([`ac_table`]).
//!
//! The verdict is about the environment and the runtime profile only. Whether a check is built yet depends on the task that
//! implements it and is tracked in `STATUS.md`.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::path::Path;

use crate::profile::capability::{Capability, availability};
use crate::profile::types::RuntimeProfile;

pub mod ac_table;

pub use ac_table::ACCEPTANCE_CHECKS;

/// Operating system of the builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// Windows.
    Windows,
    /// macOS.
    MacOs,
    /// Linux.
    Linux,
    /// Anything else.
    Other,
}

impl Os {
    /// The OS this binary was built for.
    pub fn current() -> Os {
        if cfg!(target_os = "windows") {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::MacOs
        } else if cfg!(target_os = "linux") {
            Os::Linux
        } else {
            Os::Other
        }
    }

    /// Name for output.
    pub fn name(self) -> &'static str {
        match self {
            Os::Windows => "Windows",
            Os::MacOs => "macOS",
            Os::Linux => "Linux",
            Os::Other => "another operating system",
        }
    }
}

/// What the builder offers, as far as the plan cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Facts {
    /// Operating system.
    pub os: Os,
    /// `docker` is installed.
    pub docker: bool,
    /// A PostgreSQL server (`postgres` or `pg_ctl`) is installed.
    pub postgres: bool,
    /// `redis-server` or `valkey-server` is installed.
    pub redis: bool,
    /// `nft` is installed.
    pub nft: bool,
    /// `dig` is installed.
    pub dig: bool,
    /// `bpf-linker` is installed.
    pub bpf_linker: bool,
}

impl Facts {
    /// A machine with nothing optional installed.
    pub fn bare(os: Os) -> Facts {
        Facts {
            os,
            docker: false,
            postgres: false,
            redis: false,
            nft: false,
            dig: false,
            bpf_linker: false,
        }
    }

    /// Look for the tools in the directories of `path_var` (an executable file with the tool's name, `.exe` and `.cmd`
    /// accepted on Windows). Nothing is executed.
    pub fn detect(path_var: Option<&OsStr>, os: Os) -> Facts {
        let dirs: Vec<std::path::PathBuf> = path_var
            .map(|p| std::env::split_paths(p).collect())
            .unwrap_or_default();
        let has = |names: &[&str]| names.iter().any(|n| on_path(&dirs, n, os));
        Facts {
            os,
            docker: has(&["docker"]),
            postgres: has(&["postgres", "pg_ctl"]),
            redis: has(&["redis-server", "valkey-server"]),
            nft: has(&["nft"]),
            dig: has(&["dig"]),
            bpf_linker: has(&["bpf-linker"]),
        }
    }
}

/// A regular file that can be run: on Unix the execute bit is set, elsewhere any file with the right name counts.
fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        p.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

fn on_path(dirs: &[std::path::PathBuf], name: &str, os: Os) -> bool {
    let suffixes: &[&str] = if os == Os::Windows {
        &["", ".exe", ".cmd", ".bat"]
    } else {
        &[""]
    };
    dirs.iter().any(|d| {
        !d.as_os_str().is_empty()
            && suffixes
                .iter()
                .any(|s| is_executable(&Path::new(d).join(format!("{name}{s}"))))
    })
}

/// The build track (T-0003 step 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Track {
    /// A Linux builder with Docker: testcontainers for PostgreSQL and Redis.
    H,
    /// No Docker (or not Linux): the embedded PostgreSQL and the in-process stores of `hdd-local`.
    L,
}

impl Track {
    /// Name for output.
    pub fn name(self) -> &'static str {
        match self {
            Track::H => "Track H",
            Track::L => "Track L",
        }
    }
}

/// Decide the track from the facts: Track H needs Linux and Docker, anything else is Track L.
pub fn track(f: &Facts) -> Track {
    if f.os == Os::Linux && f.docker {
        Track::H
    } else {
        Track::L
    }
}

/// Why a check cannot run here (the reason codes of section 3, R-02).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Why {
    /// The platform or the runtime profile cannot offer it.
    EnvironmentUnsupported,
    /// An optional tool is missing.
    ToolUnavailable,
    /// The operator has not supplied a lab, a server or access.
    CapabilityNotSupplied,
    /// A person has to do a step first.
    HumanStepPending,
}

impl Why {
    /// The code inside `UNVERIFIED(...)`.
    pub fn code(self) -> &'static str {
        match self {
            Why::EnvironmentUnsupported => "environment_unsupported",
            Why::ToolUnavailable => "tool_unavailable",
            Why::CapabilityNotSupplied => "capability_not_supplied",
            Why::HumanStepPending => "human_step_pending",
        }
    }
}

/// The environment verdict for one acceptance check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing in the environment or the profile prevents it.
    Runnable,
    /// It cannot run here, with the reason.
    Unverified(Why, &'static str),
}

/// Checks that need kernel enforcement (nftables sets, XDP) or kernel tuning.
const KERNEL: &[&str] = &["AC-26", "AC-29"];
/// Checks that need authoritative DNS on port 53, public delegation, ACME on a public name or an upstream DDoS contract
/// (the categories section 8.2 names as unavailable in `local`).
const PUBLIC_NAMES: &[&str] = &["AC-03", "AC-04", "AC-21", "AC-23", "AC-25", "AC-28"];

/// The verdict of one registry row for a runtime profile and a set of facts.
pub fn verdict(id: &str, tier: &str, profile: RuntimeProfile, f: &Facts) -> Verdict {
    if KERNEL.contains(&id) {
        if !availability(profile, Capability::KernelEnforcement).is_usable() {
            return Verdict::Unverified(
                Why::EnvironmentUnsupported,
                "the local profile has no kernel enforcement (the L7 jail enforces)",
            );
        }
        if f.os != Os::Linux {
            return Verdict::Unverified(
                Why::EnvironmentUnsupported,
                "kernel enforcement and XDP need a Linux host",
            );
        }
        if id == "AC-26" && !f.bpf_linker {
            return Verdict::Unverified(
                Why::ToolUnavailable,
                "XDP needs the nightly toolchain and bpf-linker",
            );
        }
        if !f.nft {
            return Verdict::Unverified(Why::ToolUnavailable, "nftables (`nft`) is not installed");
        }
    }
    if PUBLIC_NAMES.contains(&id) {
        if !availability(profile, Capability::AuthoritativeDns53).is_usable() {
            return Verdict::Unverified(
                Why::EnvironmentUnsupported,
                "authoritative DNS on port 53, delegation, public ACME and upstream DDoS contracts are hosted-only",
            );
        }
        return Verdict::Unverified(
            Why::HumanStepPending,
            "needs a server with public addresses and delegated names (STOP #1 or STOP #2)",
        );
    }
    if id == "AC-24" {
        return Verdict::Unverified(
            Why::HumanStepPending,
            "a load run needs the operator's separate written approval and a maintenance window",
        );
    }
    if tier.contains("lab-full") {
        return Verdict::Unverified(
            Why::CapabilityNotSupplied,
            "needs the operator's closed lab (Q-004)",
        );
    }
    // The remaining checks run against whatever instance is under test. In `local` that is the loopback instance (the
    // `local` tier of AC-55 and every unit, integration and browser test); in `hosted` it is the live pilot target.
    let live = ["smoke", "nondestructive", "pilot-full"]
        .iter()
        .any(|t| tier.contains(t));
    let build_time = tier.contains("release") || tier.contains("local");
    if live && !build_time && profile == RuntimeProfile::Hosted {
        return Verdict::Unverified(
            Why::HumanStepPending,
            "runs against the live pilot target; needs hdd.live.yaml and the pilot stop (STOP #1)",
        );
    }
    Verdict::Runnable
}

/// The plan for every registry row.
pub fn plan(profile: RuntimeProfile, f: &Facts) -> Vec<(&'static str, &'static str, Verdict)> {
    ACCEPTANCE_CHECKS
        .iter()
        .map(|&(id, name, _, tier)| (id, name, verdict(id, tier, profile, f)))
        .collect()
}

/// The section printed by `hddctl preflight` ("what can run here").
pub fn render(profile: RuntimeProfile, f: &Facts) -> String {
    let t = track(f);
    let mut s = String::new();
    let _ = writeln!(
        s,
        "Build track: {} ({} builder, Docker {}).",
        t.name(),
        f.os.name(),
        if f.docker { "found" } else { "not found" }
    );
    match t {
        Track::H => {
            let _ = writeln!(s, "  Database and Redis tests use testcontainers (Docker).");
        }
        Track::L => {
            let _ = writeln!(
                s,
                "  Database tests use the embedded PostgreSQL and the in-process stores of hdd-local (T-0563); checks that need a Redis"
            );
            let _ = writeln!(
                s,
                "  server or a container are UNVERIFIED(environment_unsupported) on this builder."
            );
        }
    }
    let tools = [
        ("PostgreSQL server", f.postgres),
        ("Redis or Valkey", f.redis),
        ("nft", f.nft),
        ("dig", f.dig),
        ("bpf-linker", f.bpf_linker),
    ];
    let _ = writeln!(
        s,
        "  Tools (listed for information; no check is excluded for a missing PostgreSQL, Redis or dig yet): {}.",
        tools
            .iter()
            .map(|(n, p)| format!("{n} {}", if *p { "found" } else { "not found" }))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let rows = plan(profile, f);
    let runnable: Vec<&str> = rows
        .iter()
        .filter(|(_, _, v)| *v == Verdict::Runnable)
        .map(|(id, _, _)| *id)
        .collect();
    let _ = writeln!(
        s,
        "\nAcceptance checks for runtime.profile: {} (environment view; whether a check is built yet is in STATUS.md):",
        match profile {
            RuntimeProfile::Local => "local",
            RuntimeProfile::Hosted => "hosted",
        }
    );
    let _ = writeln!(
        s,
        "  Can run here ({}): {}",
        runnable.len(),
        runnable.join(", ")
    );
    let mut groups: BTreeMap<(Why, &'static str), Vec<&str>> = BTreeMap::new();
    for (id, _, v) in &rows {
        if let Verdict::Unverified(why, text) = v {
            groups.entry((*why, *text)).or_default().push(*id);
        }
    }
    for ((why, text), ids) in groups {
        let _ = writeln!(
            s,
            "  UNVERIFIED({}) ({}): {}\n      {}",
            why.code(),
            ids.len(),
            ids.join(", "),
            text
        );
    }
    s
}

#[cfg(test)]
mod tests;
