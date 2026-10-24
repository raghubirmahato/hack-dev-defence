//! `hddctl`: break-glass CLI, deploy, hosting check.
//!
//! Implemented so far: `preflight` (T-0006) and `canary generate|verify` (T-0210). With `--profile-only` preflight validates
//! `hdd.live.yaml` without touching the network and prints one PASS/FAIL/UNVERIFIED line per rule with the exact remediation.
//! Without it, it additionally runs the two explicit reachability probes (DNS resolution of the nameserver names, TCP connect
//! to the SMTP relay), each only through the egress module. `canary generate` writes the C16.1 files plus a manifest with real
//! SHA-256 hashes; `canary verify` re-hashes them, fetches them directly and through HDD and checks query-string invariance,
//! every request through `hdd-common::egress`. Deploy, break-glass and the rest of the preflight checks belong to later tasks
//! (first: T-0212, T-0217).
#![forbid(unsafe_code)]
#![allow(clippy::print_stdout)]

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use hdd_common::buildplan::{self, Facts, Os};
use hdd_common::egress::allow::Allowlist;
use hdd_common::egress::probe::{ProbeContext, dns_probe, probe_resolver, tcp_probe};
use hdd_common::egress::{Client, DenyLog, EgressConfig, KillSwitch, Limits, Request};
use hdd_common::profile::capability;
use hdd_common::profile::env::RuntimeEnv;
use hdd_common::profile::types::{LockdownState, RuntimeProfile};
use hdd_common::profile::{self, Context, Finding, Profile, Reason, Report, Status};

/// Longest accepted header echo the canary probes expect (A3 of T-0210).
const CANARY_PROBE_HEADER: &str = "x-hdd-canary-probe";
/// Value of the probe header the canary echo must round-trip.
const CANARY_PROBE_TOKEN: &str = "hdd-canary-probe";
/// Connect timeout of every canary probe.
const CANARY_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Total timeout of every canary probe.
const CANARY_TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
/// Largest accepted canary response (the largest contract file is well under 1 KiB).
const CANARY_MAX_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Parser)]
#[command(name = "hddctl", about = "Hack Dev Defence control tool", version)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Validate the live target profile (and, without --profile-only, probe what the profile names).
    Preflight {
        /// Validate the profile file only: pure checks, no network access.
        #[arg(long)]
        profile_only: bool,
        /// Profile file.
        #[arg(long, default_value = "hdd.live.yaml")]
        file: PathBuf,
        /// The acceptance runner's public IP, when known (checked against admin_cidrs).
        #[arg(long)]
        runner_ip: Option<IpAddr>,
        /// With no profile file: list the required fields of the local profile instead of the hosted one.
        #[arg(long)]
        local: bool,
        /// Only print the build track and what can run on this machine (no profile file needed); always exits 0.
        #[arg(long)]
        plan: bool,
    },
    /// Generate and verify the inert canary fixtures on the origin (spec section C16.1, runbook CANARY.md).
    Canary {
        #[command(subcommand)]
        command: CanaryCmd,
    },
}

/// The `canary` subcommands (T-0210).
#[derive(Subcommand)]
enum CanaryCmd {
    /// Write the five C16.1 files and manifest.sha256 (real SHA-256) into a directory.
    Generate {
        /// Directory to write the files into (created when missing).
        #[arg(long)]
        dir: PathBuf,
        /// Base path the origin serves them under (the profile's `origin.canary.base_path`).
        #[arg(long, default_value = hdd_canary::DEFAULT_BASE_PATH)]
        base_path: String,
    },
    /// Re-hash the files, fetch them directly and through HDD, and check query-string invariance.
    Verify {
        /// Live profile file (git-ignored; never committed). A missing file is UNVERIFIED, not a failure.
        #[arg(long, default_value = "hdd.live.yaml")]
        file: PathBuf,
        /// Directory holding the generated files and manifest.sha256 for the local re-hash.
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Override the direct origin base URL (no canary path: the base path is appended); printed first.
        #[arg(long)]
        direct_url: Option<String>,
        /// Override the through-HDD base URL (no canary path: the base path is appended); printed first.
        #[arg(long)]
        through_url: Option<String>,
        /// Base path for this run; when given it takes precedence over the profile's origin.canary.base_path.
        #[arg(long)]
        base_path: Option<String>,
        /// The acceptance runner's public IP, checked against the canary header echo.
        #[arg(long)]
        runner_ip: Option<IpAddr>,
        /// Plant a bogus forwarding token in the echo probe (default off). HDD strips it and rebuilds the chain; without
        /// this flag the forwarding claim is shown and compared but never asserted as HDD evidence (P-8).
        #[arg(long)]
        with_spoof_probe: bool,
        /// Without a live profile: allow an override only when it is a loopback literal (tests and a local sidecar).
        #[arg(long)]
        local_only: bool,
        /// Kill-switch file (default: the conventional `/var/run/hdd-acceptance.stop`, or the temp dir on Windows).
        #[arg(long)]
        kill_switch: Option<PathBuf>,
    },
}

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

fn finding(
    rule: &'static str,
    status: Status,
    field: &str,
    message: String,
    remediation: &str,
) -> Finding {
    Finding {
        rule,
        status,
        field: field.to_owned(),
        message,
        remediation: remediation.to_owned(),
    }
}

/// The two reachability probes. Each goes through the egress module; nothing else touches the network.
fn run_probes(p: &Profile) -> Report {
    let mut out = Vec::new();
    if p.runtime.profile == RuntimeProfile::Local {
        out.push(finding(
            "PROBE-NS",
            Status::NotApplicable,
            "platform.ns_hostnames",
            "nameserver names are not used in the local profile".into(),
            "",
        ));
        out.push(finding("PROBE-SMTP", Status::NotApplicable, "smtp.host", "the local profile uses a local SMTP sink unless a relay is configured; not probed here".into(), ""));
        return Report { findings: out };
    }
    let allow = match Allowlist::parse(&p.egress_allowlist) {
        Ok(a) => a,
        Err(_) => {
            let msg =
                "egress_allowlist has invalid entries (see PROF-EGRESS); no probe was attempted"
                    .to_owned();
            out.push(finding(
                "PROBE-NS",
                Status::Unverified(Reason::HumanStepPending),
                "egress_allowlist",
                msg.clone(),
                "Fix the entries first.",
            ));
            out.push(finding(
                "PROBE-SMTP",
                Status::Unverified(Reason::HumanStepPending),
                "egress_allowlist",
                msg,
                "Fix the entries first.",
            ));
            return Report { findings: out };
        }
    };
    let deny = DenyLog::stderr();
    let kill = KillSwitch::new(KillSwitch::default_path(), Duration::from_millis(100));
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            out.push(finding(
                "PROBE-NS",
                Status::Fail,
                "",
                format!("cannot start the async runtime: {e}"),
                "Report this as a bug.",
            ));
            return Report { findings: out };
        }
    };

    // DNS resolution of the nameserver names, through the allowlisted resolvers only
    match probe_resolver(&allow, PROBE_TIMEOUT) {
        None => out.push(finding(
            "PROBE-NS",
            Status::Unverified(Reason::CapabilityNotSupplied),
            "egress_allowlist",
            "no `dns://` resolver is listed in egress_allowlist, so nameserver names are not resolved (the system resolver is deliberately not used)".into(),
            "Add at least one public resolver, for example `dns://1.1.1.1` and `dns://9.9.9.9`, to egress_allowlist (Q-040).",
        )),
        Some(resolver) => {
            if p.platform.ns_hostnames.is_empty() {
                out.push(finding("PROBE-NS", Status::Unverified(Reason::CapabilityNotSupplied), "platform.ns_hostnames", "no nameserver names to resolve".into(), "Fill platform.ns_hostnames."));
            }
            for (i, ns) in p.platform.ns_hostnames.iter().enumerate() {
                let field = format!("platform.ns_hostnames[{i}]");
                match rt.block_on(dns_probe(&resolver, ns, Some(&kill))) {
                    Ok(r) if !r.addrs.is_empty() => {
                        let list = r.addrs.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(", ");
                        let expected: Vec<&String> = p.platform.public_ipv4.iter().chain(p.platform.public_ipv6.iter()).collect();
                        let matches_platform = r.addrs.iter().any(|a| expected.iter().any(|e| e.parse::<IpAddr>().is_ok_and(|x| x == *a)));
                        if matches_platform || expected.is_empty() {
                            out.push(finding("PROBE-NS", Status::Pass, &field, format!("{ns} resolves to {list}"), ""));
                        } else {
                            out.push(finding("PROBE-NS", Status::Warn, &field, format!("{ns} resolves to {list}, which is none of platform.public_ipv4/ipv6"), "Point the glue / A record of the nameserver name at the server that runs HDD (needed before delegation)."));
                        }
                    }
                    Ok(_) => out.push(finding("PROBE-NS", Status::Fail, &field, format!("{ns} resolves to no address"), "Create an A (and AAAA) record for the nameserver name, and glue at the registrar if it lies inside the delegated zone.")),
                    Err(e) => out.push(finding("PROBE-NS", Status::Fail, &field, format!("{ns} could not be resolved: {e}"), "Create an A record for the nameserver name (glue at the registrar if it lies inside the delegated zone), or check the resolver entries.")),
                }
            }
        }
    }

    // TCP connect to the SMTP relay
    if p.smtp.host.trim().is_empty() {
        out.push(finding(
            "PROBE-SMTP",
            Status::Unverified(Reason::HumanStepPending),
            "smtp.host",
            "no SMTP relay configured; nothing to probe".into(),
            "Provide the relay (Q-011) before M3.",
        ));
    } else {
        let host = p.smtp.host.trim();
        // names are resolved through the allowlisted `dns://` resolvers only (the egress class `dns_resolution`); an IP literal
        // needs no resolution. The system resolver is deliberately not used.
        let resolver = probe_resolver(&allow, PROBE_TIMEOUT);
        let is_literal = host.parse::<IpAddr>().is_ok();
        let none = hdd_common::egress::resolver::NoResolver;
        let res: &dyn hdd_common::egress::resolver::Resolver = match &resolver {
            Some(r) => r,
            None if is_literal => &none,
            None => {
                out.push(finding(
                    "PROBE-SMTP",
                    Status::Unverified(Reason::CapabilityNotSupplied),
                    "egress_allowlist",
                    format!("smtp.host {host} is a name and egress_allowlist has no `dns://` resolver to resolve it with, so the connection was not attempted"),
                    "Add at least one public resolver such as `dns://1.1.1.1` to egress_allowlist (Q-040).",
                ));
                return Report { findings: out };
            }
        };
        let cx = ProbeContext {
            allow: &allow,
            resolver: res,
            timeout: PROBE_TIMEOUT,
            deny: &deny,
            kill: Some(&kill),
            caller: "preflight",
        };
        match rt.block_on(tcp_probe(&cx, host, p.smtp.port)) {
            Ok(addr) => out.push(finding("PROBE-SMTP", Status::Pass, "smtp.host", format!("TCP connect to {host}:{} succeeded ({addr})", p.smtp.port), "")),
            Err(hdd_common::egress::EgressError::Denied { .. }) => out.push(finding(
                "PROBE-SMTP",
                Status::Unverified(Reason::HumanStepPending),
                "egress_allowlist",
                format!("tcp://{host}:{} is not on egress_allowlist, so the connection was not attempted", p.smtp.port),
                &format!("Add `tcp://{host}:{}` to egress_allowlist (adding an egress destination needs your approval).", p.smtp.port),
            )),
            Err(e) => out.push(finding("PROBE-SMTP", Status::Fail, "smtp.host", format!("cannot connect to {host}:{}: {e}", p.smtp.port), "Check the relay host and port, the provider's outbound policy for 25/465/587 (Q-052) and your firewall.")),
        }
    }
    Report { findings: out }
}

/// The runtime profile the plan is about. The environment wins over everything (B10: `HDD_RUNTIME_PROFILE`), then the profile
/// file when there is one, then `--local`, else hosted. Variables that cannot be parsed are returned as messages: they are
/// printed, never silently turned into a different answer.
fn plan_profile(
    from_file: Option<RuntimeProfile>,
    local_flag: bool,
) -> (RuntimeProfile, Vec<String>) {
    let default = from_file.unwrap_or(if local_flag {
        RuntimeProfile::Local
    } else {
        RuntimeProfile::Hosted
    });
    match RuntimeEnv::from_process_env() {
        Ok(env) => (env.runtime_profile.unwrap_or(default), Vec::new()),
        Err(errors) => (default, errors.iter().map(ToString::to_string).collect()),
    }
}

/// "What can run here" (T-0561 step 6): the build track, the capability matrix and the acceptance plan for this machine.
fn plan_section(runtime: RuntimeProfile) -> String {
    let facts = Facts::detect(std::env::var_os("PATH").as_deref(), Os::current());
    let mut profile = Profile::default();
    profile.runtime.profile = runtime;
    format!(
        "{}
{}",
        buildplan::render(runtime, &facts),
        capability::render(&profile)
    )
}

fn preflight(
    profile_only: bool,
    file: &Path,
    runner_ip: Option<IpAddr>,
    local: bool,
    plan: bool,
) -> ExitCode {
    if plan {
        let (runtime, problems) = plan_profile(None, local);
        for m in &problems {
            println!("WARNING: environment: {m}");
        }
        println!("{}", plan_section(runtime));
        return ExitCode::SUCCESS;
    }
    let text = match std::fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) => {
            println!("FAIL: cannot read {} ({e}).", file.display());
            println!("{}", profile::render_required_fields(local));
            let (runtime, problems) = plan_profile(None, local);
            for m in &problems {
                println!("WARNING: environment: {m}");
            }
            println!(
                "
What can run on this machine meanwhile:
{}",
                plan_section(runtime)
            );
            return ExitCode::from(1);
        }
    };
    let parsed = match profile::parse_yaml(&text) {
        Ok(p) => p,
        Err(e) => {
            println!(
                "FAIL: {} is not a valid profile.\n  key path: {}\n  problem:  {}",
                file.display(),
                if e.key_path.is_empty() {
                    "(document)"
                } else {
                    &e.key_path
                },
                e.message
            );
            println!("Fix the file and run again; hdd.live.example.yaml shows every field.");
            return ExitCode::from(1);
        }
    };
    let report = profile::validate(&parsed, &Context { runner_ip });
    print!("{}", profile::render_table(&report));
    let (runtime, problems) = plan_profile(Some(parsed.runtime.profile), local);
    for m in &problems {
        println!("WARNING: environment: {m}");
    }
    println!(
        "
What can run on this machine:
{}",
        plan_section(runtime)
    );
    let mut failed = !report.is_ok();
    if !profile_only {
        println!("\nReachability probes (through the egress module only):");
        let probes = run_probes(&parsed);
        print!("{}", profile::render_table(&probes));
        failed |= !probes.is_ok();
        println!(
            "\nThe remaining preflight checks (AC-00: ports, firewall, NTP, canary, origin lockdown) arrive with T-0217: UNVERIFIED(stage_not_reached)."
        );
    }
    if failed {
        println!("\n{}", profile::render_missing(&parsed));
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// `hddctl canary generate`: write the C16.1 files and the manifest with real SHA-256 hashes (A1).
fn canary_generate(dir: &Path, base_path: &str) -> ExitCode {
    match hdd_canary::generate(dir, base_path) {
        Ok(manifest) => {
            println!(
                "canary generate: wrote {} files and {} into {}",
                hdd_canary::FILES.len(),
                hdd_canary::MANIFEST_NAME,
                dir.display()
            );
            println!("base path: {}", manifest.base_path);
            for entry in &manifest.entries {
                println!("  {}  {}", entry.sha256, entry.name);
            }
            println!(
                "\nInstall them as CANARY.md describes (sidecar or the origin's static web root). The manifest is not served."
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("canary generate: FAIL: {e}");
            ExitCode::from(1)
        }
    }
}

/// The exact operator steps printed when a profile-dependent canary check cannot run here.
fn canary_operator_instructions() -> String {
    "Create hdd.live.yaml from hdd.live.example.yaml (git-ignored, never committed) and fill operator_email, \
     platform_domain, test_hostname, sandbox_hostname, origin.url and origin.canary.base_path; install the canary files \
     as CANARY.md describes; delegate the pilot subzones to HDD (STOP #1); then run `hddctl canary verify` again. \
     Without the live profile this half of the check cannot be performed here."
        .to_owned()
}

/// The exact next step when no response arrived from the through-HDD target (C-6): before the pilot delegation this is a
/// pending human step, not a defect.
fn canary_through_pending_instructions() -> String {
    "no response arrived from the through-HDD target; this is the pilot DNS delegation / HDD route (STOP #1), not an \
     origin defect. Delegate the pilot subzones (test_hostname and sandbox_hostname) to HDD, install the canary files \
     (CANARY.md), then run `hddctl canary verify` again."
        .to_owned()
}

/// One canary verification run.
struct VerifyOptions {
    file: PathBuf,
    dir: Option<PathBuf>,
    direct_url: Option<String>,
    through_url: Option<String>,
    base_path: Option<String>,
    runner_ip: Option<IpAddr>,
    local_only: bool,
    kill_switch: Option<PathBuf>,
    with_spoof_probe: bool,
}

/// How to read the `echo-headers` endpoint, from the profile's declaration (`origin.canary.use_hdd_canary_agent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EchoMode {
    /// The profile expects the sidecar: a missing endpoint is a FAIL.
    Expected,
    /// The profile declares a static-file install: no echo endpoint exists.
    StaticInstall,
    /// No profile: a missing endpoint is UNVERIFIED, never a FAIL.
    Undeclared,
}

/// The closed reason set of the status taxonomy (spec section 0.4 / E3.1): exactly these eight codes, anything else is
/// a FAIL. `canary verify` picks from this enum, so an invented reason cannot be printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "the closed set must stay complete even though canary verify only emits some of the eight codes"
)]
enum CanaryReason {
    CapabilityNotSupplied,
    HumanStepPending,
    EnvironmentUnsupported,
    OracleUnavailable,
    ToolUnavailable,
    StageNotReached,
    StageForbids,
    SkippedByOperator,
}

impl CanaryReason {
    fn code(self) -> &'static str {
        match self {
            CanaryReason::CapabilityNotSupplied => "capability_not_supplied",
            CanaryReason::HumanStepPending => "human_step_pending",
            CanaryReason::EnvironmentUnsupported => "environment_unsupported",
            CanaryReason::OracleUnavailable => "oracle_unavailable",
            CanaryReason::ToolUnavailable => "tool_unavailable",
            CanaryReason::StageNotReached => "stage_not_reached",
            CanaryReason::StageForbids => "stage_forbids",
            CanaryReason::SkippedByOperator => "skipped_by_operator",
        }
    }
}

/// Status of one canary check. The exact token is printed (`PASS`, `FAIL`, `WARN`, `UNVERIFIED(<reason>)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CanaryStatus {
    /// The check holds.
    Pass,
    /// The served bytes/behaviour are wrong.
    Fail,
    /// Advisory: correct but a documented recommendation is missing.
    Warn,
    /// Cannot be decided here, with one of the closed reason codes.
    Unverified(CanaryReason),
}

impl std::fmt::Display for CanaryStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanaryStatus::Pass => f.write_str("PASS"),
            CanaryStatus::Fail => f.write_str("FAIL"),
            CanaryStatus::Warn => f.write_str("WARN"),
            CanaryStatus::Unverified(reason) => write!(f, "UNVERIFIED({})", reason.code()),
        }
    }
}

/// One canary check line.
struct CanaryFinding {
    rule: &'static str,
    status: CanaryStatus,
    field: String,
    message: String,
    remediation: String,
}

fn canary_check(
    rule: &'static str,
    status: CanaryStatus,
    field: impl Into<String>,
    message: impl Into<String>,
    remediation: impl Into<String>,
) -> CanaryFinding {
    CanaryFinding {
        rule,
        status,
        field: field.into(),
        message: message.into(),
        remediation: remediation.into(),
    }
}

/// Render the canary report: one `RULE  STATUS  FIELD: MESSAGE` line per check, plus its remediation.
fn render_canary(findings: &[CanaryFinding]) -> String {
    let w_rule = findings
        .iter()
        .map(|f| f.rule.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let w_status = findings
        .iter()
        .map(|f| f.status.to_string().len())
        .max()
        .unwrap_or(6)
        .max(6);
    let mut out = format!(
        "{:<w_rule$}  {:<w_status$}  FIELD / MESSAGE\n",
        "RULE", "STATUS"
    );
    out.push_str(&format!("{}\n", "-".repeat(w_rule + w_status + 20)));
    for finding in findings {
        let field = if finding.field.is_empty() {
            String::new()
        } else {
            format!("{}: ", finding.field)
        };
        out.push_str(&format!(
            "{:<w_rule$}  {:<w_status$}  {field}{}\n",
            finding.rule, finding.status, finding.message
        ));
        if !finding.remediation.is_empty() {
            out.push_str(&format!(
                "{:<w_rule$}  {:<w_status$}  -> {}\n",
                "", "", finding.remediation
            ));
        }
    }
    let count = |status: CanaryStatus| findings.iter().filter(|f| f.status == status).count();
    let unverified = findings
        .iter()
        .filter(|f| matches!(f.status, CanaryStatus::Unverified(_)))
        .count();
    out.push_str(&format!(
        "\n{} PASS, {} FAIL, {} WARN, {} UNVERIFIED\n",
        count(CanaryStatus::Pass),
        count(CanaryStatus::Fail),
        count(CanaryStatus::Warn),
        unverified
    ));
    out
}

/// Print the canary report and return 1 when any check FAILs (WARN and UNVERIFIED never fail the run).
fn finish_canary(findings: Vec<CanaryFinding>) -> ExitCode {
    print!("{}", render_canary(&findings));
    if findings.iter().any(|f| f.status == CanaryStatus::Fail) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// A canary target: the origin base URL with the canary base path appended, plus its host for the target checks.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CanaryTarget {
    /// `scheme://host:port<base_path>`.
    base: String,
    /// Where the target came from, for the Q-1 delegation decision.
    provenance: hdd_canary::TargetProvenance,
    /// Scheme as written in the URL.
    scheme: String,
    /// Port as written in the URL.
    port: u16,
}

/// Hosts the live profile itself names: the origin URL's host and `test_hostname` (C-3).
fn profile_target_hosts(profile: &Profile) -> Vec<String> {
    let mut hosts = Vec::new();
    if let Ok(url) = hdd_common::egress::url::parse_url(profile.origin.url.trim()) {
        hosts.push(hdd_canary::normalise_host_token(&url.host));
    }
    let test_hostname = hdd_canary::normalise_host_token(profile.test_hostname.trim());
    if !test_hostname.is_empty() {
        hosts.push(test_hostname);
    }
    hosts
}

/// Build a target from an explicit origin base URL: parse it strictly, require a bare host URL, append the base path.
fn build_canary_target(
    raw: &str,
    base_path: &str,
    provenance: hdd_canary::TargetProvenance,
) -> Result<CanaryTarget, String> {
    let url = hdd_common::egress::url::parse_url(raw.trim())
        .map_err(|e| format!("`{raw}` is refused before any request: {e}"))?;
    if url.path_and_query != "/" {
        return Err(format!(
            "`{raw}` is refused before any request: pass the host base URL (scheme://host:port), not a path; the canary base path `{base_path}` is appended"
        ));
    }
    let host_for_url = match url.ip {
        Some(IpAddr::V6(_)) => format!("[{}]", url.host),
        _ => url.host.clone(),
    };
    Ok(CanaryTarget {
        base: format!(
            "{}://{}:{}{base_path}",
            url.scheme.as_str(),
            host_for_url,
            url.port
        ),
        provenance,
        scheme: url.scheme.as_str().to_owned(),
        port: url.port,
    })
}

/// Validate an operator override before any request leaves the machine (C-3).
///
/// With a live profile the override host must equal a host the profile itself names (`test_hostname` or the origin URL
/// host). Without a profile only a loopback **literal** (127.0.0.0/8 or ::1) is accepted, and only with `--local-only`.
fn checked_canary_target(
    raw: &str,
    flag: &str,
    profile: Option<&Profile>,
    local_only: bool,
    base_path: &str,
) -> Result<CanaryTarget, String> {
    let url = hdd_common::egress::url::parse_url(raw.trim())
        .map_err(|e| format!("{flag} `{raw}` is refused before any request: {e}"))?;
    let host = hdd_canary::normalise_host_token(&url.host);
    if let Some(profile) = profile {
        let allowed = profile_target_hosts(profile);
        if allowed.is_empty() {
            return Err(format!(
                "{flag} `{raw}` is refused before any request: the live profile names no test_hostname and its origin.url has no usable host to match"
            ));
        }
        if !allowed
            .iter()
            .any(|named| named.eq_ignore_ascii_case(&host))
        {
            return Err(format!(
                "{flag} `{raw}` is refused before any request: host `{host}` is not named by the live profile (test_hostname or origin.url: {})",
                allowed.join(", ")
            ));
        }
    } else if !local_only {
        return Err(format!(
            "{flag} `{raw}` is refused before any request: no live profile is loaded, so an override is only allowed with --local-only and a loopback literal"
        ));
    } else if !url.ip.map(|ip| ip.is_loopback()).unwrap_or(false) {
        return Err(format!(
            "{flag} `{raw}` is refused before any request: --local-only accepts only a loopback literal (127.0.0.0/8 or ::1), not `{host}`"
        ));
    }
    // Q-5: with a profile, the scheme and port must be the profile's own for that host; --local-only may use any loopback port.
    // P-6: provenance follows the host identity, not the spelling of the flag (library helper, unit-tested).
    let provenance = match profile {
        Some(profile) => {
            let origin_host = hdd_common::egress::url::parse_url(profile.origin.url.trim())
                .ok()
                .map(|origin| hdd_canary::normalise_host_token(&origin.host));
            hdd_canary::classify_override_provenance(
                profile.test_hostname.trim(),
                origin_host.as_deref(),
                &host,
            )
        }
        None => hdd_canary::TargetProvenance::OverrideLiteral,
    };
    if let Some(profile) = profile {
        let (default_scheme, default_port) =
            match hdd_common::egress::url::parse_url(profile.origin.url.trim()) {
                Ok(origin) => (origin.scheme.as_str().to_owned(), origin.port),
                Err(_) => ("https".to_owned(), 443),
            };
        let test_hostname = hdd_canary::normalise_host_token(profile.test_hostname.trim());
        let origin_host = hdd_common::egress::url::parse_url(profile.origin.url.trim())
            .ok()
            .map(|origin| hdd_canary::normalise_host_token(&origin.host));
        // A host the origin URL itself names takes the origin URL's scheme/port; a test_hostname is served through HDD,
        // where https + 443 is the default the profile does not override.
        let (expected_scheme, expected_port) = if origin_host.as_deref() == Some(host.as_str()) {
            (default_scheme, default_port)
        } else if !test_hostname.is_empty() && host == test_hostname {
            ("https".to_owned(), 443)
        } else {
            (default_scheme, default_port)
        };
        let scheme = url.scheme.as_str();
        if scheme != expected_scheme || url.port != expected_port {
            return Err(format!(
                "{flag} `{raw}` is refused before any request: the profile serves host `{host}` as {expected_scheme}:{expected_port}, not {scheme}:{}",
                url.port
            ));
        }
    }
    build_canary_target(raw, base_path, provenance)
}

/// Re-hash the generated files against `manifest.sha256` (local, no network). The manifest's base path must be the base
/// path in use (C-7).
fn push_canary_manifest_finding(
    findings: &mut Vec<CanaryFinding>,
    dir: &Option<PathBuf>,
    base_path: Option<&str>,
) {
    let Some(dir) = dir else {
        findings.push(canary_check(
            "CANARY-MANIFEST",
            CanaryStatus::Unverified(CanaryReason::CapabilityNotSupplied),
            "--dir",
            "no directory was given, so the generated files were not re-hashed against the manifest",
            "Pass `--dir <directory>` (the directory `hddctl canary generate --dir` wrote) to re-hash the five files against manifest.sha256.",
        ));
        return;
    };
    let field = dir.display().to_string();
    match hdd_canary::check_manifest(dir) {
        Ok(report) if report.ok() => {
            if let Some(in_use) = base_path
                && report.base_path != in_use
            {
                findings.push(canary_check(
                    "CANARY-MANIFEST",
                    CanaryStatus::Fail,
                    &field,
                    format!(
                        "the manifest was generated for base path {} but this run uses {} (C-7)",
                        report.base_path, in_use
                    ),
                    "Regenerate the manifest for the base path in use (`hddctl canary generate --dir <dir> --base-path <path>`), or run verify with the matching base path.",
                ));
                return;
            }
            findings.push(canary_check(
                "CANARY-MANIFEST",
                CanaryStatus::Pass,
                &field,
                format!(
                    "{} files match {} (real SHA-256)",
                    hdd_canary::FILES.len(),
                    hdd_canary::MANIFEST_NAME
                ),
                "",
            ));
        }
        Ok(report) => {
            let broken: Vec<String> = report
                .checks
                .iter()
                .filter(|check| !check.matches())
                .map(|check| {
                    format!(
                        "{} (manifest {}, file {})",
                        check.name,
                        check.expected.as_deref().unwrap_or("no entry"),
                        check.actual.as_deref().unwrap_or("missing")
                    )
                })
                .collect();
            findings.push(canary_check(
                "CANARY-MANIFEST",
                CanaryStatus::Fail,
                &field,
                format!(
                    "{} file(s) do not match the manifest: {}",
                    broken.len(),
                    broken.join("; ")
                ),
                "The files were edited or truncated; run `hddctl canary generate --dir <dir>` again and re-install them.",
            ));
        }
        Err(e) => findings.push(canary_check(
            "CANARY-MANIFEST",
            CanaryStatus::Fail,
            &field,
            format!("{e}"),
            "Run `hddctl canary generate --dir <dir>` first.",
        )),
    }
}

/// Build the purpose-specific egress allowlist of the canary probes: only the targets that passed the checks, each
/// restricted to its base path. No wildcard, no other port, no other host.
fn build_canary_client(
    direct: Option<&CanaryTarget>,
    through: Option<&CanaryTarget>,
    kill_switch: Option<&PathBuf>,
) -> Result<Client, String> {
    let mut entries: Vec<String> = Vec::new();
    for target in [direct, through].into_iter().flatten() {
        entries.push(target.base.clone());
    }
    let allowlist = Allowlist::parse(&entries).map_err(|errors| {
        format!("cannot build the canary probe allowlist from {entries:?}: {errors:?}")
    })?;
    let kill_path = kill_switch
        .cloned()
        .unwrap_or_else(KillSwitch::default_path);
    let kill = KillSwitch::new(kill_path, Duration::from_millis(100));
    let config = EgressConfig::new("canary-verify")
        .kill_switch(kill)
        .limits(Limits {
            connect_timeout: CANARY_CONNECT_TIMEOUT,
            total_timeout: CANARY_TOTAL_TIMEOUT,
            max_response_bytes: CANARY_MAX_RESPONSE_BYTES,
            max_request_bytes: 0,
        });
    Client::with_config(allowlist, config)
}

/// A probe failure: `Transport` means no response arrived, `Aborted` is the operator's kill switch, `TooLarge` is the
/// response size cap, and `Refused` is a request/policy error (K-6).
enum ProbeFailure {
    /// No response arrived, with the transport class (Q-1: only a DNS failure of a profile test_hostname may be pending).
    Transport {
        /// What failed.
        message: String,
        /// The transport class.
        kind: hdd_canary::TransportKind,
    },
    /// The kill-switch file was present: the operator stopped the tool.
    Aborted(String),
    /// The response exceeded the canary response size cap.
    TooLarge(String),
    /// The request or its policy was wrong; this is a bug or an operator input error, never a transient state.
    Refused(String),
}

fn is_transient_egress_error(error: &hdd_common::egress::EgressError) -> bool {
    matches!(
        error,
        hdd_common::egress::EgressError::Connect(_)
            | hdd_common::egress::EgressError::Timeout(_)
            | hdd_common::egress::EgressError::Http(_)
    )
}

fn is_transport_egress_error(error: &hdd_common::egress::EgressError) -> bool {
    matches!(
        error,
        hdd_common::egress::EgressError::Connect(_)
            | hdd_common::egress::EgressError::Timeout(_)
            | hdd_common::egress::EgressError::Http(_)
            | hdd_common::egress::EgressError::Resolve(_)
    )
}

/// P-6: a resolver failure that is not a negative answer for the profile test_hostname cannot decide the delegation
/// state, so it is an environment limitation (UNVERIFIED(environment_unsupported)) rather than a FAIL or a pending step.
fn resolver_environment_failure(
    provenance: hdd_canary::TargetProvenance,
    kind: hdd_canary::TransportKind,
) -> bool {
    provenance == hdd_canary::TargetProvenance::ProfileTestHostname
        && kind == hdd_canary::TransportKind::ResolveOther
}

/// The message for an environment-limited resolver failure (P-6): say exactly what failed.
fn resolver_environment_message(message: &str) -> String {
    format!(
        "{message}: DNS resolution of the profile test_hostname failed for a reason other than a negative answer (resolver or network failure), so the pilot-delegation state cannot be decided here"
    )
}

/// The class of a transport failure, for the Q-1 decision.
fn transport_kind(error: &hdd_common::egress::EgressError) -> hdd_canary::TransportKind {
    match error {
        hdd_common::egress::EgressError::Resolve(message) => {
            if hdd_canary::resolver_negative_answer(message) {
                hdd_canary::TransportKind::Resolve
            } else {
                hdd_canary::TransportKind::ResolveOther
            }
        }
        hdd_common::egress::EgressError::Connect(_) => hdd_canary::TransportKind::Connect,
        hdd_common::egress::EgressError::Timeout(_) => hdd_canary::TransportKind::Timeout,
        hdd_common::egress::EgressError::Tls(_) => hdd_canary::TransportKind::Tls,
        _ => hdd_canary::TransportKind::Http,
    }
}

fn classify_probe_failure(
    url: &str,
    error: &hdd_common::egress::EgressError,
    first: Option<&hdd_common::egress::EgressError>,
) -> ProbeFailure {
    match error {
        hdd_common::egress::EgressError::Aborted => ProbeFailure::Aborted(format!(
            "GET {url} was stopped by the kill switch; remove the kill-switch file when the stop is intended to end"
        )),
        hdd_common::egress::EgressError::TooLarge { limit } => ProbeFailure::TooLarge(format!(
            "GET {url}: the response is larger than the {limit}-byte canary response cap"
        )),
        e if is_transport_egress_error(e) => ProbeFailure::Transport {
            message: match first {
                Some(first) => format!(
                    "GET {url} failed through hdd-common::egress after one retry: {e} (first error: {first})"
                ),
                None => format!("GET {url} failed through hdd-common::egress: {e}"),
            },
            kind: transport_kind(e),
        },
        e => ProbeFailure::Refused(format!("GET {url} was refused: {e}")),
    }
}

/// One benign GET through the egress client, carrying the probe header the echo must round-trip.
///
/// A single transport-level failure (connect, timeout, connection error) is retried once: a benign canary probe must not
/// become a false FAIL because of one transient reset, while a policy denial is never retried and a repeated failure is
/// reported. The retry is bounded (one extra request) and repeats only a plain `GET`.
async fn canary_get(
    client: &Client,
    url: &str,
) -> Result<hdd_common::egress::Response, ProbeFailure> {
    canary_get_with(client, url, &[]).await
}

/// One benign GET carrying the probe header plus caller-supplied headers (the echo probe plants the spoof tokens).
async fn canary_get_with(
    client: &Client,
    url: &str,
    extra: &[(&str, &str)],
) -> Result<hdd_common::egress::Response, ProbeFailure> {
    let build = || {
        let mut request = Request::get(url).header(CANARY_PROBE_HEADER, CANARY_PROBE_TOKEN);
        for (name, value) in extra {
            request = request.header(name, value);
        }
        request
    };
    match client.send(build()).await {
        Ok(response) => Ok(response),
        Err(first) if is_transient_egress_error(&first) => client
            .send(build())
            .await
            .map_err(|e| classify_probe_failure(url, &e, Some(&first))),
        Err(e) => Err(classify_probe_failure(url, &e, None)),
    }
}

/// Outcome of one probe.
enum ProbeOutcome {
    /// The probe answered as expected; `warning` carries an advisory finding, `hdd_evidence` the K-2 evidence.
    Pass {
        message: String,
        warning: Option<String>,
        hdd_evidence: Option<String>,
    },
    /// The operator's kill switch stopped the probe.
    Aborted(String),
    /// The response exceeded the size cap.
    TooLarge(String),
    /// No response arrived, with the transport class (Q-1).
    Transport {
        /// What failed.
        message: String,
        /// The transport class.
        kind: hdd_canary::TransportKind,
    },
    /// A response arrived but was wrong.
    Wrong(String),
}

/// Fetch the five files and compare the served bytes with the C16.1 contract.
async fn fetch_canary_files(client: &Client, base: &str) -> ProbeOutcome {
    let mut warning: Option<String> = None;
    let mut hdd_evidence: Option<String> = None;
    for file in &hdd_canary::FILES {
        let url = format!("{base}{}", file.name);
        let response = match canary_get(client, &url).await {
            Ok(response) => response,
            Err(ProbeFailure::Transport { message, kind }) => {
                return ProbeOutcome::Transport { message, kind };
            }
            Err(ProbeFailure::Aborted(message)) => return ProbeOutcome::Aborted(message),
            Err(ProbeFailure::TooLarge(message)) => return ProbeOutcome::TooLarge(message),
            Err(ProbeFailure::Refused(message)) => return ProbeOutcome::Wrong(message),
        };
        // K-2: HDD sets `Server: Hack-Dev-Defence` and `HDD-Ray-ID` on every response; either is HDD-specific evidence.
        if hdd_evidence.is_none() {
            hdd_evidence = hdd_canary::hdd_response_evidence(&header_structs(&response.headers));
        }
        if response.status != 200 {
            return ProbeOutcome::Wrong(format!(
                "{url}: HTTP {} (expected 200); the files must be installed under the base path",
                response.status
            ));
        }
        if response.body != file.content {
            return ProbeOutcome::Wrong(format!(
                "{}: the served bytes differ from the C16.1 contract ({} served, {} expected, sha256 {} vs {})",
                file.name,
                response.body.len(),
                file.content.len(),
                hdd_canary::sha256_hex(&response.body),
                hdd_canary::sha256_hex(file.content)
            ));
        }
        // C16.1 does not require nosniff on the five contract files (docs/SPEC.md line 3879); C16 does on the echo JSON
        // (line 3877). A missing header on the files is advisory (WARN), not a failure.
        match response.header("x-content-type-options") {
            Some("nosniff") => {}
            Some(other) => {
                warning = Some(format!(
                    "{url}: X-Content-Type-Options is `{other}`; advisory only (C16.1, docs/SPEC.md line 3879)",
                ));
            }
            None => {
                warning = Some(format!(
                    "{url}: no X-Content-Type-Options: nosniff; advisory only (C16.1, docs/SPEC.md line 3879 does not require it on the contract files; the documented static snippet sets it)"
                ));
            }
        }
    }
    ProbeOutcome::Pass {
        message: format!(
            "all {} C16.1 files are served byte for byte under {base}",
            hdd_canary::FILES.len()
        ),
        warning,
        hdd_evidence,
    }
}

/// Query strings must not change what is served and must not be reflected.
async fn check_canary_query(client: &Client, base: &str) -> ProbeOutcome {
    let query = "?hdd_canary_check=1&x=%2e%2e%2f";
    for file in &hdd_canary::FILES {
        let plain = match canary_get(client, &format!("{base}{}", file.name)).await {
            Ok(response) => response,
            Err(ProbeFailure::Transport { message, kind }) => {
                return ProbeOutcome::Transport { message, kind };
            }
            Err(ProbeFailure::Aborted(message)) => return ProbeOutcome::Aborted(message),
            Err(ProbeFailure::TooLarge(message)) => return ProbeOutcome::TooLarge(message),
            Err(ProbeFailure::Refused(message)) => return ProbeOutcome::Wrong(message),
        };
        let queried = match canary_get(client, &format!("{base}{}{query}", file.name)).await {
            Ok(response) => response,
            Err(ProbeFailure::Transport { message, kind }) => {
                return ProbeOutcome::Transport { message, kind };
            }
            Err(ProbeFailure::Aborted(message)) => return ProbeOutcome::Aborted(message),
            Err(ProbeFailure::TooLarge(message)) => return ProbeOutcome::TooLarge(message),
            Err(ProbeFailure::Refused(message)) => return ProbeOutcome::Wrong(message),
        };
        if plain.status != 200 || queried.status != 200 {
            return ProbeOutcome::Wrong(format!(
                "{}: HTTP {} without a query and {} with one (expected 200/200)",
                file.name, plain.status, queried.status
            ));
        }
        if plain.body != queried.body {
            return ProbeOutcome::Wrong(format!(
                "{}: a query string changed the served bytes ({} vs {} bytes)",
                file.name,
                plain.body.len(),
                queried.body.len()
            ));
        }
        if queried.body != file.content {
            return ProbeOutcome::Wrong(format!(
                "{}: the queried response differs from the contract",
                file.name
            ));
        }
    }
    ProbeOutcome::Pass {
        message: format!("query strings do not change the served bytes under {base}"),
        warning: None,
        hdd_evidence: None,
    }
}
/// Convert `(name, value)` response-header pairs into the library header type.
fn header_structs(pairs: &[(String, String)]) -> Vec<hdd_canary::Header> {
    pairs
        .iter()
        .map(|(name, value)| hdd_canary::Header {
            name: name.clone(),
            value: value.clone(),
        })
        .collect()
}

/// Parse the `echo-headers` JSON body into (name, value) pairs. K-8: the strict parser (with the literal `true`/`false`
/// check) lives in the library so the decision logic is unit-tested on this host.
fn parse_echo_json(body: &[u8]) -> Result<Vec<(String, String)>, String> {
    Ok(hdd_canary::parse_echo_json(body)?
        .into_iter()
        .map(|header| (header.name, header.value))
        .collect())
}
/// `echo-headers` probe result: the outcome plus the parsed headers, which are also the C-4 evidence.
struct EchoResult {
    outcome: EchoOutcome,
    headers: Option<Vec<(String, String)>>,
}

/// Outcome of the `echo-headers` probe.
enum EchoOutcome {
    /// The endpoint behaves as the canary contract requires.
    Pass(String),
    /// The endpoint cannot answer here, with a reason from the closed set.
    Unverified(CanaryReason, String),
    /// The echo shows a runner-IP claim (shown and compared), but only HDD response headers can make it evidence (P-7).
    Claim(String),
    /// The sidecar/origin answered but not as the contract requires.
    Fail(String),
}

/// Outcome of a transport failure of the echo probe (Q-1): only a DNS resolution failure of a profile-named
/// `test_hostname` may be a pending delegation step; every other transport failure is a FAIL.
fn echo_transport_outcome(
    message: String,
    kind: hdd_canary::TransportKind,
    provenance: hdd_canary::TargetProvenance,
    through_hdd: bool,
    sidecar_expected: bool,
) -> EchoOutcome {
    if through_hdd && hdd_canary::transport_means_pending_delegation(provenance, kind) {
        EchoOutcome::Unverified(
            CanaryReason::HumanStepPending,
            format!("{message}. {}", canary_through_pending_instructions()),
        )
    } else if resolver_environment_failure(provenance, kind) {
        EchoOutcome::Unverified(
            CanaryReason::EnvironmentUnsupported,
            resolver_environment_message(&message),
        )
    } else if through_hdd || sidecar_expected {
        EchoOutcome::Fail(message)
    } else {
        EchoOutcome::Unverified(CanaryReason::CapabilityNotSupplied, message)
    }
}

/// `echo-headers` must return the probe header, set `nosniff`, set no cookie and, through HDD, show the runner IP.
///
/// `sidecar_expected` is the profile's declaration (`origin.canary.use_hdd_canary_agent`, default `true`); with a
/// declared static install a missing endpoint is UNVERIFIED(`capability_not_supplied`) - C16 says the header checks
/// become UNVERIFIED unless `origin_access_log` is provided - while a missing endpoint that the profile expects is a
/// FAIL. `through_hdd` restricts the runner-IP assertion to the through-HDD echo and makes a transport failure a pending
/// step until delegation is recorded as done (K-6). The secret origin header's presence is reported, never its value (K-1).
async fn check_canary_echo(
    client: &Client,
    base: &str,
    runner_ip: Option<IpAddr>,
    sidecar_expected: bool,
    through_hdd: bool,
    provenance: hdd_canary::TargetProvenance,
    with_spoof_probe: bool,
) -> EchoResult {
    let url = format!("{base}{}", hdd_canary::ECHO_HEADERS_SEGMENT);
    // Q-2b: plant a bogus forwarding token; a HDD-built X-Forwarded-For must strip it (T-0361 A1), while an origin
    // terminator that merely appends leaves it in place.
    // P-8: the spoof probe is opt-in; without it the probe sends only the canary probe header.
    let spoof = hdd_canary::ECHO_SPOOF_TOKEN;
    let spoof_headers = if with_spoof_probe {
        vec![
            ("X-Forwarded-For", spoof),
            ("Forwarded", "for=203.0.113.99"),
            ("X-Real-IP", spoof),
        ]
    } else {
        Vec::new()
    };
    let response = match canary_get_with(client, &url, &spoof_headers).await {
        Ok(response) => response,
        Err(ProbeFailure::Transport { message, kind }) => {
            let outcome =
                echo_transport_outcome(message, kind, provenance, through_hdd, sidecar_expected);
            return EchoResult {
                outcome,
                headers: None,
            };
        }
        Err(ProbeFailure::Aborted(message)) => {
            return EchoResult {
                outcome: EchoOutcome::Unverified(CanaryReason::SkippedByOperator, message),
                headers: None,
            };
        }
        Err(ProbeFailure::TooLarge(message)) => {
            return EchoResult {
                outcome: EchoOutcome::Fail(message),
                headers: None,
            };
        }
        Err(ProbeFailure::Refused(message)) => {
            return EchoResult {
                outcome: EchoOutcome::Fail(message),
                headers: None,
            };
        }
    };
    if response.status != 200 {
        if through_hdd && !sidecar_expected {
            return EchoResult {
                outcome: EchoOutcome::Unverified(
                    CanaryReason::CapabilityNotSupplied,
                    format!(
                        "{url}: an HTTP response arrived (HTTP {}) from the through target, but echo-headers is not served there; a response arrived, so this is not a pending delegation step, and without the sidecar the per-request header check is UNVERIFIED unless origin-access-log is provided (C16, docs/SPEC.md line 3877)",
                        response.status
                    ),
                ),
                headers: None,
            };
        }
        if sidecar_expected {
            return EchoResult {
                outcome: EchoOutcome::Fail(format!(
                    "{url}: HTTP {} (expected 200); the profile expects the hdd-canary sidecar (origin.canary.use_hdd_canary_agent: true) but the echo endpoint is not served - install it as CANARY.md section 4 describes, or set origin.canary.use_hdd_canary_agent: false for a static install",
                    response.status
                )),
                headers: None,
            };
        }
        return EchoResult {
            outcome: EchoOutcome::Unverified(
                CanaryReason::CapabilityNotSupplied,
                format!(
                    "{url}: HTTP {}; no sidecar is declared (origin.canary.use_hdd_canary_agent is not true), so the header checks are UNVERIFIED(capability_not_supplied) unless origin_access_log is provided (C16, docs/SPEC.md line 3877)",
                    response.status
                ),
            ),
            headers: None,
        };
    }
    let headers = match parse_echo_json(&response.body) {
        Ok(headers) => headers,
        Err(message) => {
            return EchoResult {
                outcome: EchoOutcome::Fail(format!("{url}: {message}")),
                headers: None,
            };
        }
    };
    // K-1: report that the secret origin header is present (the sidecar already reduced it to `v1;<kid>`), never a value
    // beyond the version and key id.
    let origin_auth_presence = headers.iter().find_map(|(name, value)| {
        if name.eq_ignore_ascii_case(hdd_canary::ORIGIN_AUTH_HEADER) {
            Some(value.clone())
        } else {
            None
        }
    });
    let with_presence = |message: String| match &origin_auth_presence {
        Some(summary) if summary == hdd_canary::ECHO_REDACTED_VALUE => {
            format!("{message}; HDD-Origin-Auth is present (value not echoed)")
        }
        Some(summary) => {
            format!("{message}; HDD-Origin-Auth is present ({summary}), value not echoed")
        }
        None => message,
    };
    if response.header("x-content-type-options") != Some("nosniff") {
        return EchoResult {
            outcome: EchoOutcome::Fail(format!(
                "{url} does not set X-Content-Type-Options: nosniff (required for the echo JSON by C16, docs/SPEC.md line 3877)"
            )),
            headers: Some(headers),
        };
    }
    if response.header("set-cookie").is_some() {
        return EchoResult {
            outcome: EchoOutcome::Fail(format!(
                "{url} set a cookie; the canary endpoints set none"
            )),
            headers: Some(headers),
        };
    }
    let probe_round_tripped = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case(CANARY_PROBE_HEADER) && value == CANARY_PROBE_TOKEN
    });
    if !probe_round_tripped {
        return EchoResult {
            outcome: EchoOutcome::Fail(format!(
                "{url} did not return the probe header ({CANARY_PROBE_HEADER}: {CANARY_PROBE_TOKEN}); check that the sidecar is installed and that HDD forwards request headers unchanged"
            )),
            headers: Some(headers),
        };
    }
    match runner_ip {
        Some(ip) if through_hdd => {
            let evidence = hdd_canary::hdd_echo_evidence(&header_structs(&headers), Some(ip));
            match evidence {
                Ok(evidence) if with_spoof_probe => EchoResult {
                    outcome: EchoOutcome::Claim(with_presence(format!(
                        "echo-headers round-tripped the probe header; {evidence}"
                    ))),
                    headers: Some(headers),
                },
                Ok(evidence) => EchoResult {
                    outcome: EchoOutcome::Unverified(
                        CanaryReason::CapabilityNotSupplied,
                        with_presence(format!(
                            "the echo shows {evidence}, but --with-spoof-probe was not given, so the forwarding claim is only shown and never asserted (P-8)"
                        )),
                    ),
                    headers: Some(headers),
                },
                Err(reason) if with_spoof_probe => EchoResult {
                    outcome: EchoOutcome::Fail(format!(
                        "the echo contradicts the HDD claim: {reason}"
                    )),
                    headers: Some(headers),
                },
                Err(reason) => EchoResult {
                    outcome: EchoOutcome::Unverified(
                        CanaryReason::CapabilityNotSupplied,
                        with_presence(format!(
                            "the echo does not show a usable forwarding claim ({reason}); without --with-spoof-probe nothing is asserted (P-8)"
                        )),
                    ),
                    headers: Some(headers),
                },
            }
        }
        Some(ip) => EchoResult {
            outcome: EchoOutcome::Pass(with_presence(format!(
                "echo-headers round-tripped the probe header; the runner IP {ip} is only asserted through HDD (this echo was the direct origin), so it was not checked"
            ))),
            headers: Some(headers),
        },
        None => EchoResult {
            outcome: EchoOutcome::Pass(with_presence(
                "echo-headers round-tripped the probe header; the runner IP was not checked (--runner-ip not supplied)"
                    .to_owned(),
            )),
            headers: Some(headers),
        },
    }
}
/// Push a probe outcome as a PASS/FAIL finding, mapping a transport failure per target (C-6).
fn push_probe_outcome(
    findings: &mut Vec<CanaryFinding>,
    rule: &'static str,
    field: &str,
    outcome: ProbeOutcome,
    transport_is_pending: bool,
    provenance: hdd_canary::TargetProvenance,
) {
    match outcome {
        ProbeOutcome::Pass { message, warning, .. } => match warning {
            Some(warning) => findings.push(canary_check(
                rule,
                CanaryStatus::Warn,
                field,
                format!("{message}; advisory: {warning}"),
                "Set X-Content-Type-Options: nosniff in the static handler (the nginx/apache snippet in CANARY.md does); C16.1 does not require it on the contract files, so this is advisory.",
            )),
            None => findings.push(canary_check(rule, CanaryStatus::Pass, field, message, "")),
        },
        ProbeOutcome::Aborted(message) => findings.push(canary_check(
            rule,
            CanaryStatus::Unverified(CanaryReason::SkippedByOperator),
            field,
            message,
            "The kill switch stopped the run; remove the kill-switch file and run `hddctl canary verify` again when you intend to continue.",
        )),
        ProbeOutcome::TooLarge(message) => findings.push(canary_check(
            rule,
            CanaryStatus::Fail,
            field,
            message,
            "The response exceeded the canary size cap: investigate the response path (an echoing/compressing proxy can inflate a body); this is not an origin-file defect.",
        )),
        ProbeOutcome::Transport { message, kind } => {
            if transport_is_pending && hdd_canary::transport_means_pending_delegation(provenance, kind) {
                findings.push(canary_check(
                    rule,
                    CanaryStatus::Unverified(CanaryReason::HumanStepPending),
                    field,
                    format!("{message}. {}", canary_through_pending_instructions()),
                    "Delegate the pilot subzones to HDD and install the canary files, then run `hddctl canary verify` again.",
                ));
            } else if resolver_environment_failure(provenance, kind) {
                findings.push(canary_check(
                    rule,
                    CanaryStatus::Unverified(CanaryReason::EnvironmentUnsupported),
                    field,
                    resolver_environment_message(&message),
                    "Fix the resolver/network path (the name could not be resolved for a non-negative reason), then run `hddctl canary verify` again.",
                ));
            } else {
                findings.push(canary_check(
                    rule,
                    CanaryStatus::Fail,
                    field,
                    message,
                    "The direct origin must answer while origin.lockdown_state is pending; check the origin URL and the network path.",
                ));
            }
        }
        ProbeOutcome::Wrong(message) => findings.push(canary_check(
            rule,
            CanaryStatus::Fail,
            field,
            message,
            "Fix the origin/reverse proxy and run `hddctl canary verify` again.",
        )),
    }
}
/// `hddctl canary verify` (A5): every check ends PASS, FAIL, WARN or UNVERIFIED(reason), never a fabricated pass.
fn canary_verify(options: &VerifyOptions) -> ExitCode {
    let mut findings: Vec<CanaryFinding> = Vec::new();

    // The profile is optional: it is git-ignored and only exists on the operator's machine.
    let profile = match std::fs::read_to_string(&options.file) {
        Ok(text) => match profile::parse_yaml(&text) {
            Ok(parsed) => Some(parsed),
            Err(e) => {
                findings.push(canary_check(
                    "CANARY-PROFILE",
                    CanaryStatus::Fail,
                    options.file.display().to_string(),
                    format!("{} is not a valid profile: {e}", options.file.display()),
                    "Fix the profile; `hddctl preflight --profile-only` lists every problem.",
                ));
                None
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            findings.push(canary_check(
                "CANARY-PROFILE",
                CanaryStatus::Fail,
                options.file.display().to_string(),
                format!("cannot read {}: {e}", options.file.display()),
                "Check the file permissions or pass a different --file.",
            ));
            None
        }
    };

    // Base path: explicit override, then the profile, then the documented default.
    let raw_base_path = options
        .base_path
        .clone()
        .or_else(|| profile.as_ref().map(|p| p.origin.canary.base_path.clone()));
    let base_path = match raw_base_path {
        Some(raw) => match hdd_canary::normalise_base_path(&raw) {
            Ok(normalized) => Some(normalized),
            Err(e) => {
                findings.push(canary_check(
                    "CANARY-BASE-PATH",
                    CanaryStatus::Fail,
                    "origin.canary.base_path",
                    format!("{raw:?} is not an acceptable canary base path: {e}"),
                    "Use a path such as /__hdd_canary/ and keep the profile and the installed layout identical.",
                ));
                None
            }
        },
        None => Some(hdd_canary::DEFAULT_BASE_PATH.to_owned()),
    };
    let effective_base = base_path
        .clone()
        .unwrap_or_else(|| hdd_canary::DEFAULT_BASE_PATH.to_owned());

    // Local first: the manifest is an evidence artifact and needs no network (C-7 also checks its base path).
    push_canary_manifest_finding(&mut findings, &options.dir, base_path.as_deref());

    // Direct origin target (meaningful while origin.lockdown_state is pending).
    let mut direct: Option<CanaryTarget> = None;
    let mut direct_pending: Option<CanaryFinding> = None;
    if let Some(raw) = &options.direct_url {
        match checked_canary_target(
            raw,
            "--direct-url",
            profile.as_ref(),
            options.local_only,
            &effective_base,
        ) {
            Ok(target) => direct = Some(target),
            Err(message) => findings.push(canary_check(
                "CANARY-TARGET",
                CanaryStatus::Fail,
                "--direct-url",
                message,
                "Pass the profile's origin.url host, or --local-only with a loopback literal (tests and a local sidecar).",
            )),
        }
    } else if let Some(profile) = &profile {
        if profile.origin.url.trim().is_empty() {
            direct_pending = Some(canary_check(
                "CANARY-DIRECT",
                CanaryStatus::Unverified(CanaryReason::HumanStepPending),
                "origin.url",
                format!("origin.url is empty. {}", canary_operator_instructions()),
                "Fill origin.url with the origin's own URL (scheme included).",
            ));
        } else if profile.origin.lockdown_state == LockdownState::Applied {
            direct_pending = Some(canary_check(
                "CANARY-DIRECT",
                CanaryStatus::Unverified(CanaryReason::StageNotReached),
                "origin.lockdown_state",
                "origin.lockdown_state is applied (STOP #2: origin firewall and secret header), so the direct stage is no longer reachable; this check is only meaningful while lockdown_state is pending".to_owned(),
                "Run the direct check before applying the origin lockdown, or pass --direct-url when the origin firewalling still allows this host.",
            ));
        } else {
            match build_canary_target(
                &profile.origin.url,
                &effective_base,
                hdd_canary::TargetProvenance::ProfileOrigin,
            ) {
                Ok(target) => direct = Some(target),
                Err(message) => {
                    direct_pending = Some(canary_check(
                        "CANARY-DIRECT",
                        CanaryStatus::Fail,
                        "origin.url",
                        message,
                        "origin.url must be a full http(s) base URL.",
                    ))
                }
            }
        }
    } else {
        direct_pending = Some(canary_check(
            "CANARY-DIRECT",
            CanaryStatus::Unverified(CanaryReason::HumanStepPending),
            "origin.url",
            format!(
                "no live profile at {} and no --direct-url. {}",
                options.file.display(),
                canary_operator_instructions()
            ),
            "Pass --file <hdd.live.yaml> or --direct-url <origin base URL>.",
        ));
    }

    // Through-HDD target.
    let mut through: Option<CanaryTarget> = None;
    let mut through_pending: Option<CanaryFinding> = None;
    if let Some(raw) = &options.through_url {
        match checked_canary_target(
            raw,
            "--through-url",
            profile.as_ref(),
            options.local_only,
            &effective_base,
        ) {
            Ok(target) => through = Some(target),
            Err(message) => findings.push(canary_check(
                "CANARY-TARGET",
                CanaryStatus::Fail,
                "--through-url",
                message,
                "Pass the profile's test_hostname host, or --local-only with a loopback literal (tests and a local sidecar).",
            )),
        }
    } else if let Some(profile) = &profile {
        let host = profile.test_hostname.trim();
        if host.is_empty() {
            through_pending = Some(canary_check(
                "CANARY-HDD",
                CanaryStatus::Unverified(CanaryReason::HumanStepPending),
                "test_hostname",
                format!("test_hostname is empty. {}", canary_operator_instructions()),
                "Fill test_hostname in hdd.live.yaml.",
            ));
        } else {
            match build_canary_target(
                &format!("https://{host}"),
                &effective_base,
                hdd_canary::TargetProvenance::ProfileTestHostname,
            ) {
                Ok(target) => through = Some(target),
                Err(message) => {
                    through_pending = Some(canary_check(
                        "CANARY-HDD",
                        CanaryStatus::Fail,
                        "test_hostname",
                        message,
                        "test_hostname must be a DNS name, not a URL.",
                    ))
                }
            }
        }
    } else {
        through_pending = Some(canary_check(
            "CANARY-HDD",
            CanaryStatus::Unverified(CanaryReason::HumanStepPending),
            "test_hostname",
            format!(
                "no live profile at {} and no --through-url. {}",
                options.file.display(),
                canary_operator_instructions()
            ),
            "Pass --file <hdd.live.yaml> or --through-url <through-HDD base URL>.",
        ));
    }

    // How to read the echo endpoint, from the profile's declaration.
    let echo_mode = match &profile {
        Some(profile) if !profile.origin.canary.use_hdd_canary_agent => EchoMode::StaticInstall,
        Some(_) => EchoMode::Expected,
        None => EchoMode::Undeclared,
    };

    let echo_static: Option<CanaryFinding> = if echo_mode == EchoMode::StaticInstall {
        Some(canary_check(
            "CANARY-ECHO",
            CanaryStatus::Unverified(CanaryReason::CapabilityNotSupplied),
            "origin.canary.use_hdd_canary_agent",
            "the profile declares a static-file install (origin.canary.use_hdd_canary_agent: false), so there is no \
             echo-headers endpoint and the header checks are UNVERIFIED(capability_not_supplied) unless \
             origin_access_log is provided (C16, docs/SPEC.md line 3877)"
                .to_owned(),
            "Set origin.canary.use_hdd_canary_agent: true and install the sidecar (CANARY.md section 4) to check \
             headers, or provide origin_access_log and read the headers from there.",
        ))
    } else {
        None
    };

    // Announce every target before any request leaves the machine.
    println!("Canary verification (T-0210, spec C16.1 + C16 intro; runbook CANARY.md).");
    println!("Targets that will be contacted (benign GET through hdd-common::egress::Client):");
    println!(
        "  direct: {}",
        direct
            .as_ref()
            .map(|target| target.base.as_str())
            .unwrap_or("(none; the direct check is UNVERIFIED, see the table)")
    );
    println!(
        "  through: {}",
        through
            .as_ref()
            .map(|target| target.base.as_str())
            .unwrap_or("(none; the through-HDD check is UNVERIFIED, see the table)")
    );
    println!(
        "  spoof probe (--with-spoof-probe): {}",
        if options.with_spoof_probe {
            "enabled: plants X-Forwarded-For/Forwarded/X-Real-IP 203.0.113.99, which a HDD-built chain must strip"
        } else {
            "disabled: forwarding claims are shown and compared, but only HDD response headers can make them evidence (P-7/P-8)"
        }
    );

    let mut direct_result: Option<ProbeOutcome> = None;
    let mut through_result: Option<ProbeOutcome> = None;
    let mut query_result: Option<ProbeOutcome> = None;
    let mut echo_result: Option<EchoResult> = None;
    let query_via_hdd = through.is_some();

    if direct.is_some() || through.is_some() {
        match build_canary_client(
            direct.as_ref(),
            through.as_ref(),
            options.kill_switch.as_ref(),
        ) {
            Ok(client) => {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => Some(runtime),
                    Err(e) => {
                        findings.push(canary_check(
                            "CANARY-ALLOWLIST",
                            CanaryStatus::Fail,
                            "",
                            format!("cannot start the async runtime: {e}"),
                            "Report this as a bug.",
                        ));
                        None
                    }
                };
                if let Some(runtime) = runtime {
                    if let Some(target) = &direct {
                        direct_result =
                            Some(runtime.block_on(fetch_canary_files(&client, &target.base)));
                    }
                    if let Some(target) = &through {
                        through_result =
                            Some(runtime.block_on(fetch_canary_files(&client, &target.base)));
                    }
                    let echo_base = through.as_ref().or(direct.as_ref());
                    if let Some(target) = echo_base {
                        query_result =
                            Some(runtime.block_on(check_canary_query(&client, &target.base)));
                        if echo_mode != EchoMode::StaticInstall {
                            echo_result = Some(runtime.block_on(check_canary_echo(
                                &client,
                                &target.base,
                                options.runner_ip,
                                echo_mode == EchoMode::Expected,
                                through.is_some(),
                                target.provenance,
                                options.with_spoof_probe,
                            )));
                        }
                    }
                }
            }
            Err(message) => {
                findings.push(canary_check(
                    "CANARY-ALLOWLIST",
                    CanaryStatus::Fail,
                    "",
                    message,
                    "This is a bug in how the canary targets are derived; report it.",
                ));
            }
        }
    }
    let echo_headers = echo_result
        .as_ref()
        .and_then(|result| result.headers.as_deref());
    let direct_field = direct.as_ref().map(|t| t.base.clone()).unwrap_or_default();
    let through_field = through.as_ref().map(|t| t.base.clone()).unwrap_or_default();

    if let Some(outcome) = direct_result {
        push_probe_outcome(
            &mut findings,
            "CANARY-DIRECT",
            &direct_field,
            outcome,
            false,
            direct
                .as_ref()
                .map(|target| target.provenance)
                .unwrap_or(hdd_canary::TargetProvenance::ProfileOrigin),
        );
    } else if let Some(pending) = direct_pending {
        findings.push(pending);
    }

    // P-7: only HDD response headers make CANARY-HDD a PASS; the echo claim is shown and compared, never promoted on its own.
    let through_response_evidence = match &through_result {
        Some(ProbeOutcome::Pass { hdd_evidence, .. }) => hdd_evidence.clone(),
        _ => None,
    };
    if let Some(outcome) = through_result {
        match outcome {
            ProbeOutcome::Pass {
                message,
                warning,
                hdd_evidence: response_evidence,
            } => {
                let echo_claim = match (options.with_spoof_probe, options.runner_ip) {
                    (true, Some(ip)) => echo_headers.map(|headers| {
                        hdd_canary::hdd_echo_evidence(&header_structs(headers), Some(ip))
                    }),
                    _ => None,
                };
                match response_evidence {
                    Some(evidence) => {
                        let text = format!("{message}; HDD evidence: {evidence}");
                        if let Some(warning) = warning {
                            findings.push(canary_check(
                                "CANARY-HDD",
                                CanaryStatus::Warn,
                                &through_field,
                                format!("{text}; advisory: {warning}"),
                                "Set X-Content-Type-Options: nosniff in the static handler; advisory on the contract files (C16.1).",
                            ));
                        } else {
                            findings.push(canary_check(
                                "CANARY-HDD",
                                CanaryStatus::Pass,
                                &through_field,
                                text,
                                "",
                            ));
                        }
                    }
                    None => match echo_claim {
                        Some(Ok(shown)) => findings.push(canary_check(
                            "CANARY-HDD",
                            CanaryStatus::Unverified(CanaryReason::CapabilityNotSupplied),
                            &through_field,
                            format!(
                                "{message}; the echo shows {shown} - shown and compared, but the status stays UNVERIFIED because only `Server: Hack-Dev-Defence` or `HDD-Ray-ID` on the response makes CANARY-HDD a PASS (P-7)"
                            ),
                            "Fetch through the real HDD edge so the response carries `Server: Hack-Dev-Defence` or `HDD-Ray-ID`; an origin terminator can rewrite forwarding headers, so those can never prove the path by themselves.",
                        )),
                        Some(Err(reason)) => findings.push(canary_check(
                            "CANARY-HDD",
                            CanaryStatus::Fail,
                            &through_field,
                            format!("{message}; the echo contradicts the HDD claim: {reason}"),
                            "The forwarding chain was not rebuilt as HDD does (the planted spoof survived or the runner is absent); check the path from this machine to the HDD edge.",
                        )),
                        None => findings.push(canary_check(
                            "CANARY-HDD",
                            CanaryStatus::Unverified(CanaryReason::CapabilityNotSupplied),
                            &through_field,
                            format!(
                                "{message}; the response carried neither `Server: Hack-Dev-Defence` nor `HDD-Ray-ID` and no echo was available to compare (P-7)"
                            ),
                            "Run the check through the real HDD edge (the live profile's test_hostname), or install the sidecar echo and pass --runner-ip.",
                        )),
                    },
                }
            }
            ProbeOutcome::Aborted(message) => findings.push(canary_check(
                "CANARY-HDD",
                CanaryStatus::Unverified(CanaryReason::SkippedByOperator),
                &through_field,
                message,
                "The kill switch stopped the run; remove the kill-switch file and run `hddctl canary verify` again when you intend to continue.",
            )),
            ProbeOutcome::TooLarge(message) => findings.push(canary_check(
                "CANARY-HDD",
                CanaryStatus::Fail,
                &through_field,
                message,
                "The response exceeded the canary size cap: investigate the response path (an echoing/compressing proxy can inflate a body); this is not an origin-file defect.",
            )),
            ProbeOutcome::Transport { message, kind } => {
                let provenance = through
                    .as_ref()
                    .map(|target| target.provenance)
                    .unwrap_or(hdd_canary::TargetProvenance::OverrideLiteral);
                if hdd_canary::transport_means_pending_delegation(provenance, kind) {
                    findings.push(canary_check(
                        "CANARY-HDD",
                        CanaryStatus::Unverified(CanaryReason::HumanStepPending),
                        &through_field,
                        format!("{message}. {}", canary_through_pending_instructions()),
                        "Delegate the pilot subzones to HDD and install the canary files, then run `hddctl canary verify` again.",
                    ));
                } else if resolver_environment_failure(provenance, kind) {
                    findings.push(canary_check(
                        "CANARY-HDD",
                        CanaryStatus::Unverified(CanaryReason::EnvironmentUnsupported),
                        &through_field,
                        resolver_environment_message(&message),
                        "Fix the resolver/network path (the name could not be resolved for a non-negative reason), then run `hddctl canary verify` again.",
                    ));
                } else {
                    findings.push(canary_check(
                        "CANARY-HDD",
                        CanaryStatus::Fail,
                        &through_field,
                        message,
                        "Check the through target, the HDD edge and the path from this machine, then run `hddctl canary verify` again.",
                    ));
                }
            }
            ProbeOutcome::Wrong(message) => findings.push(canary_check(
                "CANARY-HDD",
                CanaryStatus::Fail,
                &through_field,
                message,
                "Fix the origin/reverse proxy and run `hddctl canary verify` again.",
            )),
        }
    } else if let Some(pending) = through_pending {
        findings.push(pending);
    }

    let query_field = if query_via_hdd {
        through_field.clone()
    } else {
        direct_field.clone()
    };
    if let Some(outcome) = query_result {
        push_probe_outcome(
            &mut findings,
            "CANARY-QUERY",
            &query_field,
            outcome,
            query_via_hdd,
            if query_via_hdd {
                through
                    .as_ref()
                    .map(|target| target.provenance)
                    .unwrap_or(hdd_canary::TargetProvenance::OverrideLiteral)
            } else {
                direct
                    .as_ref()
                    .map(|target| target.provenance)
                    .unwrap_or(hdd_canary::TargetProvenance::ProfileOrigin)
            },
        );
    } else {
        findings.push(canary_check(
            "CANARY-QUERY",
            CanaryStatus::Unverified(CanaryReason::HumanStepPending),
            "",
            format!(
                "no direct or through-HDD target is available, so query-string invariance was not checked. {}",
                canary_operator_instructions()
            ),
            "Pass --file <hdd.live.yaml>, --direct-url or --through-url.",
        ));
    }

    match echo_result {
        Some(result) => match result.outcome {
            EchoOutcome::Pass(message) => findings.push(canary_check(
                "CANARY-ECHO",
                CanaryStatus::Pass,
                &query_field,
                message,
                "",
            )),
            EchoOutcome::Unverified(reason, message) => findings.push(canary_check(
                "CANARY-ECHO",
                CanaryStatus::Unverified(reason),
                &query_field,
                message,
                "Provide origin_access_log (C16) or install the hdd-canary sidecar (CANARY.md section 4).",
            )),
            EchoOutcome::Claim(message) => match &through_response_evidence {
                Some(evidence) => findings.push(canary_check(
                    "CANARY-ECHO",
                    CanaryStatus::Pass,
                    &query_field,
                    format!("{message}; the response header corroborates the HDD path: {evidence}"),
                    "",
                )),
                None => findings.push(canary_check(
                    "CANARY-ECHO",
                    CanaryStatus::Unverified(CanaryReason::CapabilityNotSupplied),
                    &query_field,
                    format!(
                        "{message}; shown and compared, but without a HDD response header (`Server: Hack-Dev-Defence`/`HDD-Ray-ID`) the runner claim is not HDD-specific evidence (P-7)"
                    ),
                    "Fetch through the real HDD edge so the response carries `Server: Hack-Dev-Defence` or `HDD-Ray-ID`, or pass --with-spoof-probe and use the echo as a comparison only.",
                )),
            },
            EchoOutcome::Fail(message) => findings.push(canary_check(
                "CANARY-ECHO",
                CanaryStatus::Fail,
                &query_field,
                message,
                "Investigate the sidecar/proxy response path and run `hddctl canary verify` again.",
            )),
        },
        None => match echo_static {
            Some(pending) => findings.push(pending),
            None => findings.push(canary_check(
                "CANARY-ECHO",
                CanaryStatus::Unverified(CanaryReason::HumanStepPending),
                "",
                format!(
                    "no direct or through-HDD target is available, so echo-headers was not checked. {}",
                    canary_operator_instructions()
                ),
                "Pass --file <hdd.live.yaml>, --direct-url or --through-url.",
            )),
        },
    }

    finish_canary(findings)
}
fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Preflight {
            profile_only,
            file,
            runner_ip,
            local,
            plan,
        } => preflight(profile_only, &file, runner_ip, local, plan),
        Cmd::Canary { command } => match command {
            CanaryCmd::Generate { dir, base_path } => canary_generate(&dir, &base_path),
            CanaryCmd::Verify {
                file,
                dir,
                direct_url,
                through_url,
                base_path,
                runner_ip,
                local_only,
                kill_switch,
                with_spoof_probe,
            } => canary_verify(&VerifyOptions {
                file,
                dir,
                direct_url,
                through_url,
                base_path,
                runner_ip,
                local_only,
                kill_switch,
                with_spoof_probe,
            }),
        },
    }
}
