//! `cargo xtask verify`: the single command that enforces the rules mechanically (T-0005 step 5, R-29).
//!
//! Every step runs, prints a tail, and writes a full log with its SHA-256 under `acceptance-verify/<stamp>/`.
//! Statuses follow section 0.4: PASS, FAIL or UNVERIFIED(reason). Exit code 0 means no step FAILED; UNVERIFIED steps
//! are listed with the reason code and are never counted as a pass.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

use crate::util::{Finding, Result, now_utc, read_text, sha256_hex, tail_lines, write_text};
use crate::{
    claims, deps, matrix, profile_check, profile_lint, rules, rust_share, secrets, spec, tasks,
    ux_docs,
};

/// Outcome of one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// The check ran and passed.
    Pass,
    /// The check ran and failed (or could not run for a reason that is not an UNVERIFIED reason).
    Fail,
    /// The check could not run; `reason` is one of the section 0.4 codes (or `tool_unavailable`, see STATUS.md).
    Unverified {
        /// Reason code.
        reason: &'static str,
        /// What the operator must supply.
        needs: String,
    },
}

impl Status {
    /// Label such as `PASS` or `UNVERIFIED(tool_unavailable)`.
    pub fn label(&self) -> String {
        match self {
            Status::Pass => "PASS".into(),
            Status::Fail => "FAIL".into(),
            Status::Unverified { reason, .. } => format!("UNVERIFIED({reason})"),
        }
    }
}

type Internal = fn(&Path) -> (Status, String);

enum Kind {
    Cmd(&'static str, Vec<&'static str>),
    Internal(Internal),
}

struct Step {
    name: &'static str,
    kind: Kind,
}

/// One executed step.
#[derive(Debug, Clone)]
pub struct StepResult {
    /// Ordinal (1-based).
    pub n: usize,
    /// Step name.
    pub name: String,
    /// Command line or internal check label.
    pub command: String,
    /// Status.
    pub status: Status,
    /// Exit code for external commands.
    pub exit: Option<i32>,
    /// Log file name inside the run directory.
    pub log: String,
    /// SHA-256 of the full log.
    pub sha256: String,
    /// Last lines of the log.
    pub tail: String,
}

fn cmd_step(name: &'static str, program: &'static str, args: &[&'static str]) -> Step {
    Step {
        name,
        kind: Kind::Cmd(program, args.to_vec()),
    }
}

fn findings_status(findings: &[Finding], mut log: String) -> (Status, String) {
    for f in findings {
        log.push_str(&format!("{f}\n"));
    }
    if findings.is_empty() {
        log.push_str("no findings\n");
        (Status::Pass, log)
    } else {
        log.push_str(&format!("{} finding(s)\n", findings.len()));
        (Status::Fail, log)
    }
}

fn err_fail(e: crate::util::Error) -> (Status, String) {
    (Status::Fail, format!("error: {}\n", e.0))
}

fn step_spec(root: &Path) -> (Status, String) {
    findings_status(
        &spec::check(root),
        "spec check (docs/SPEC.md vs docs/spec/)\n".into(),
    )
}

fn step_tasks(root: &Path) -> (Status, String) {
    findings_status(
        &tasks::check(root),
        "tasks check (index, order, per-task files, STATUS rows)\n".into(),
    )
}

fn step_adr(root: &Path) -> (Status, String) {
    let ids = match spec::load_master(root).and_then(|t| tasks::parse(&t)) {
        Ok(m) => m.tasks.into_iter().map(|t| t.id).collect(),
        Err(e) => return err_fail(e),
    };
    findings_status(
        &deps::check_adrs(root, &ids),
        "adr check (numbers, index, deciding task, rollback plan)\n".into(),
    )
}

fn step_deps(root: &Path) -> (Status, String) {
    findings_status(
        &deps::check(root),
        "dependency-vetting lint (R-08, T-0008 step 5)\n".into(),
    )
}

fn step_rules(root: &Path) -> (Status, String) {
    findings_status(
        &rules::check(root),
        "grep rules: R-01 placeholders, R-22 egress path, AGENTS.md size\n".into(),
    )
}

fn step_vulnlab(root: &Path) -> (Status, String) {
    findings_status(&rules::check_vulnlab(root), "Vuln-Lab isolation: no default workspace member reaches hdd-vulnlab through normal or build dependencies (section 2.8, T-0004 A4)\n".into())
}

fn step_unsafe(root: &Path) -> (Status, String) {
    let mut log = String::from(
        "first-party unsafe scan (substitute for cargo-geiger, ADR-0018): forbid(unsafe_code) at every crate root, inherited workspace lints\n",
    );
    log.push_str(
        "dependency unsafe counts: not part of verify. cargo-geiger 0.14.0 runs on this builder (one-off run: docs/gates/evidence/G00/geiger-attempt.txt, exit 1 on warnings); whether and how to wire it in is decided by T-0517 (ADR-0018)\n",
    );
    findings_status(&rules::check_unsafe(root), log)
}

fn step_secrets(root: &Path) -> (Status, String) {
    match secrets::scan_tree(root) {
        Ok(f) => findings_status(&f, "secret scan (private keys, provider tokens, credential assignments, high entropy, .env files)\n".into()),
        Err(e) => err_fail(e),
    }
}

fn step_claims(root: &Path) -> (Status, String) {
    match claims::run(root) {
        Ok((f, summary)) => findings_status(&f, format!("{summary}\n")),
        Err(e) => err_fail(e),
    }
}

fn step_rust_share(root: &Path) -> (Status, String) {
    match rust_share::run(root) {
        Ok(rust_share::Outcome::Ran(f, text)) => findings_status(&f, text),
        Ok(rust_share::Outcome::Unverified(why)) => (
            Status::Unverified {
                reason: "tool_unavailable",
                needs: "install tokei: `cargo install --locked tokei`".into(),
            },
            format!("{why}\n"),
        ),
        Err(e) => err_fail(e),
    }
}

fn step_profile(root: &Path) -> (Status, String) {
    findings_status(&profile_check::check(root), "profile check (docs/profile.schema.json and hdd.live.example.yaml are current; the example fails only where expected)
".into())
}

fn step_profile_lint(root: &Path) -> (Status, String) {
    findings_status(&profile_lint::check_profile(root), "profile-lint (R-31: profile checks only where allowed; capability matrix and AC table complete)
".into())
}

fn step_kv_lint(root: &Path) -> (Status, String) {
    findings_status(
        &profile_lint::check_kv(root),
        "kv-lint (only hdd-common::kv talks to Redis)
"
        .into(),
    )
}

fn step_ux_docs(root: &Path) -> (Status, String) {
    findings_status(
        &ux_docs::check(root),
        "ux-docs (T-0011: charter, measures and decisions are structured and within budget; T-0012: the seven persona files, the persona-journey matrix and the C5 attack-registry ids are complete, the scenarios and accessibility sections meet A1 and A3, and no persona or matrix document carries mojibake text; T-0013: PATTERNS.md has twelve topics with the five labeled parts and a valid status, design-requirements.md has DR-01 to DR-20 with an existing screen or component and a real PATTERNS.md anchor, and no long sentence is copied between UX documents; T-0014: routes.toml covers every B12.1 screen against the B4.2 and B6.1 registries with valid patterns and consistent permission, surface and rate-class combinations, and IA.md has the required sections, a Test: line per URL rule and an identifier regex that matches its example; T-0015: NAVIGATION.md lists every sidebar item, tab and top-bar control with keyboard and ARIA cells and routes tied to routes.toml, its shortcut map covers B2.3 without conflicts and records every bound browser or screen-reader default in Documented conflicts with a real mitigation, and the focus, mobile, restricted-item and hover rules hold; T-0016: the six delivered journey maps match the B3 titles and the persona matrix, carry the required step, trust, security, accessibility, instrumentation and success content against the B7/C5/B8 registries, each error path has a step-fitting sentence checked against the B7 title, J-08 and J-09 carry a four-row Cutover safety table with a spec control in every guard and undo, and every proposed screen in spec-patches.md is absent from B12.1 and needed by a journey; relative links resolve)
".into(),
    )
}

fn step_profile_parity(_: &Path) -> (Status, String) {
    stub(
        "T-0564",
        "profile-parity (needs the detection engine, the ban pipeline and the seed fixtures; the harness itself is tested in hdd-common::parity)",
    )
}

/// Run `cargo` with `args` in the repository root, with some environment variables removed or set; the combined output.
fn cargo_output(
    root: &Path,
    args: &[&str],
    remove: &[&str],
    set: &[(&str, &str)],
) -> (Option<i32>, String) {
    let mut cmd = Command::new("cargo");
    cmd.args(args).current_dir(root);
    for k in remove {
        cmd.env_remove(k);
    }
    for (k, v) in set {
        cmd.env(k, v);
    }
    match cmd.output() {
        Ok(o) => (
            o.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ),
        ),
        Err(e) => (
            None,
            format!(
                "cannot run cargo: {e}
"
            ),
        ),
    }
}

/// The limiter budget of T-0562 step 8 for `MemoryKv` (p99 at most 5 microseconds); a budget is a test (R-29).
fn step_kv_bench(root: &Path) -> (Status, String) {
    let (code, out) = cargo_output(
        root,
        &["bench", "-p", "hdd-common", "--bench", "kv_limiter"],
        &["HDD_TEST_REDIS_URL"],
        &[],
    );
    let memory_lines = out
        .lines()
        .filter(|l| l.starts_with("MemoryKv") && l.ends_with(": PASS"))
        .count();
    let status = if code == Some(0) && memory_lines == 3 {
        Status::Pass
    } else {
        Status::Fail
    };
    (
        status,
        format!(
            "MemoryKv limiter budgets: {memory_lines} of 3 algorithms within the budget
{out}"
        ),
    )
}

/// The Redis half of T-0562 A1 and of the latency budget. Needs a server; without one the step is UNVERIFIED, never a pass.
fn step_kv_redis(root: &Path) -> (Status, String) {
    let url = std::env::var("HDD_TEST_REDIS_URL")
        .ok()
        .filter(|u| !u.is_empty());
    let Some(_) = url else {
        return (
            Status::Unverified {
                reason: "environment_unsupported",
                needs: "a Redis 7 or newer server: set HDD_TEST_REDIS_URL (a throw-away instance, rediss:// with a password, or redis:// on loopback)".into(),
            },
            "HDD_TEST_REDIS_URL is not set: the Redis backend (Lua scripts, pub/sub, latency budget) was not exercised on this builder
".into(),
        );
    };
    let (c1, o1) = cargo_output(
        root,
        &[
            "test",
            "-p",
            "hdd-common",
            "--features",
            "conformance",
            "--test",
            "kv_redis",
            "--",
            "--nocapture",
        ],
        &[],
        &[],
    );
    let (c2, o2) = cargo_output(
        root,
        &["bench", "-p", "hdd-common", "--bench", "kv_limiter"],
        &[],
        &[],
    );
    let redis_lines = o2
        .lines()
        .filter(|l| l.starts_with("RedisKv") && l.ends_with(": PASS"))
        .count();
    let unverified = o1.contains("UNVERIFIED") || o2.contains("RedisKv: UNVERIFIED");
    let status = if c1 == Some(0) && c2 == Some(0) && redis_lines == 3 && !unverified {
        Status::Pass
    } else {
        Status::Fail
    };
    (
        status,
        format!(
            "{o1}
{o2}"
        ),
    )
}

fn step_matrix(root: &Path) -> (Status, String) {
    findings_status(&matrix::check(root), "matrix check (R-07: every REQ maps to a test or an explicit deferral; done rows link evidence)\n".into())
}

fn stub(task: &'static str, what: &'static str) -> (Status, String) {
    (
        Status::Unverified {
            reason: "stage_not_reached",
            needs: format!("implemented by {task}"),
        },
        format!(
            "stub: `{what}` returns success with this note until {task} lands (tracked in STATUS.md as `stub`)\n"
        ),
    )
}

fn step_attack_matrix(_: &Path) -> (Status, String) {
    stub("T-0245", "attack-matrix check")
}
fn step_contrast(_: &Path) -> (Status, String) {
    stub("T-0030", "contrast-check")
}
fn step_i18n(_: &Path) -> (Status, String) {
    stub("T-0082", "i18n check")
}
fn step_routes(_: &Path) -> (Status, String) {
    stub("T-0073", "routes check")
}

/// Internal stub commands used both by `verify` and by the subcommands of the same name.
pub fn stub_message(command: &str) -> Option<String> {
    let (task, what) = match command {
        "attack-matrix" => ("T-0245", "attack-matrix check"),
        "contrast-check" => ("T-0030", "contrast-check"),
        "i18n" => ("T-0082", "i18n check"),
        "routes" => ("T-0073", "routes check"),
        "profile-parity" => (
            "T-0564",
            "profile-parity (needs the detection engine, the ban pipeline and the seed fixtures)",
        ),
        _ => return None,
    };
    Some(stub(task, what).1)
}

fn steps() -> Vec<Step> {
    vec![
        cmd_step("fmt", "cargo", &["fmt", "--all", "--check"]),
        cmd_step(
            "clippy",
            "cargo",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
        ),
        cmd_step(
            "nextest",
            "cargo",
            &["nextest", "run", "--workspace", "--no-tests=pass"],
        ),
        cmd_step("doc-tests", "cargo", &["test", "--workspace", "--doc"]),
        cmd_step("deny", "cargo", &["deny", "check"]),
        cmd_step("audit", "cargo", &["audit"]),
        cmd_step("vet", "cargo", &["vet", "--locked"]),
        Step {
            name: "unsafe-scan",
            kind: Kind::Internal(step_unsafe),
        },
        Step {
            name: "vulnlab-graph",
            kind: Kind::Internal(step_vulnlab),
        },
        Step {
            name: "rules",
            kind: Kind::Internal(step_rules),
        },
        cmd_step("machete", "cargo-machete", &["."]),
        Step {
            name: "spec-check",
            kind: Kind::Internal(step_spec),
        },
        Step {
            name: "tasks-check",
            kind: Kind::Internal(step_tasks),
        },
        Step {
            name: "adr-check",
            kind: Kind::Internal(step_adr),
        },
        Step {
            name: "dependency-vetting",
            kind: Kind::Internal(step_deps),
        },
        Step {
            name: "profile-check",
            kind: Kind::Internal(step_profile),
        },
        Step {
            name: "secret-scan",
            kind: Kind::Internal(step_secrets),
        },
        Step {
            name: "claims-lint",
            kind: Kind::Internal(step_claims),
        },
        Step {
            name: "rust-share",
            kind: Kind::Internal(step_rust_share),
        },
        Step {
            name: "matrix-check",
            kind: Kind::Internal(step_matrix),
        },
        Step {
            name: "profile-lint",
            kind: Kind::Internal(step_profile_lint),
        },
        Step {
            name: "kv-lint",
            kind: Kind::Internal(step_kv_lint),
        },
        Step {
            name: "ux-docs",
            kind: Kind::Internal(step_ux_docs),
        },
        Step {
            name: "profile-parity",
            kind: Kind::Internal(step_profile_parity),
        },
        Step {
            name: "kv-bench",
            kind: Kind::Internal(step_kv_bench),
        },
        Step {
            name: "kv-redis",
            kind: Kind::Internal(step_kv_redis),
        },
        Step {
            name: "attack-matrix-check",
            kind: Kind::Internal(step_attack_matrix),
        },
        Step {
            name: "contrast-check",
            kind: Kind::Internal(step_contrast),
        },
        Step {
            name: "i18n-check",
            kind: Kind::Internal(step_i18n),
        },
        Step {
            name: "routes-check",
            kind: Kind::Internal(step_routes),
        },
    ]
}

/// Classify the result of an external tool.
pub fn classify(name: &str, exit: Option<i32>, output: &str) -> Status {
    let lower = output.to_lowercase();
    if lower.contains("no such command")
        || lower.contains("is not recognized")
        || lower.contains("program not found")
    {
        return Status::Unverified {
            reason: "tool_unavailable",
            needs: format!("install the tool behind `{name}` (after vetting, R-08)"),
        };
    }
    // Windows Application Control (a code-integrity policy) refused to start an executable: the check did not run, so it is
    // UNVERIFIED, not FAIL (R-02). The remedy belongs to whoever administers the policy; it is never disabled from here.
    if lower.contains("application control policy has blocked") || lower.contains("os error 4551") {
        return Status::Unverified {
            reason: "tool_unavailable",
            needs: format!(
                "Windows Application Control blocked an executable needed by `{name}` (os error 4551): repeat after a rebuild, or ask the administrator of the policy to allow it"
            ),
        };
    }
    if name == "audit"
        && (lower.contains("couldn't fetch advisory database")
            || lower.contains("couldn't update advisory database"))
    {
        return Status::Unverified {
            reason: "capability_not_supplied",
            needs:
                "network access to the RustSec advisory database (egress allowlist entry, Q-040)"
                    .into(),
        };
    }
    if exit == Some(0) {
        Status::Pass
    } else {
        Status::Fail
    }
}

fn run_cmd(root: &Path, name: &str, program: &str, args: &[&str]) -> (Status, Option<i32>, String) {
    let line = format!("$ {program} {}\n", args.join(" "));
    match Command::new(program).args(args).current_dir(root).output() {
        Ok(o) => {
            let mut text = line;
            text.push_str(&String::from_utf8_lossy(&o.stdout));
            text.push_str(&String::from_utf8_lossy(&o.stderr));
            let code = o.status.code();
            text.push_str(&format!(
                "\n(exit {})\n",
                code.map_or("signal".to_owned(), |c| c.to_string())
            ));
            (classify(name, code, &text), code, text)
        }
        Err(e) => (
            Status::Unverified {
                reason: "tool_unavailable",
                needs: format!("`{program}` cannot be started: {e}"),
            },
            None,
            format!("{line}cannot start: {e}\n"),
        ),
    }
}

/// Run the pipeline; returns the process exit code.
pub fn run(root: &Path, only: &[String]) -> Result<i32> {
    let stamp = now_utc().replace([':', '-'], "");
    let dir: PathBuf = root
        .join("acceptance-verify")
        .join(format!("{stamp}-verify"));
    fs::create_dir_all(&dir)?;
    let mut results: Vec<StepResult> = Vec::new();
    for (i, step) in steps().into_iter().enumerate() {
        if !only.is_empty() && !only.iter().any(|o| o == step.name) {
            continue;
        }
        let n = i + 1;
        let (status, exit, command, text) = match &step.kind {
            Kind::Cmd(program, args) => {
                let (s, c, t) = run_cmd(root, step.name, program, args);
                (s, c, format!("{program} {}", args.join(" ")), t)
            }
            Kind::Internal(f) => {
                let (s, t) = f(root);
                (s, None, format!("cargo xtask (internal: {})", step.name), t)
            }
        };
        let log = format!("{n:02}-{}.log", step.name);
        write_text(&dir.join(&log), &text)?;
        let sha = sha256_hex(text.as_bytes());
        let tail = tail_lines(&text, 20);
        println!(
            "[{n:02}] {:<20} {}  (log {}, sha256 {})",
            step.name,
            status.label(),
            log,
            sha.get(..16).unwrap_or(&sha)
        );
        if status != Status::Pass {
            for l in tail_lines(&tail, 10).lines() {
                println!("       | {l}");
            }
        }
        results.push(StepResult {
            n,
            name: step.name.into(),
            command,
            status,
            exit,
            log,
            sha256: sha,
            tail,
        });
    }
    write_summary(&dir, &results)?;
    let fails = results.iter().filter(|r| r.status == Status::Fail).count();
    let unver = results
        .iter()
        .filter(|r| matches!(r.status, Status::Unverified { .. }))
        .count();
    let pass = results.iter().filter(|r| r.status == Status::Pass).count();
    println!(
        "verify: {pass} PASS, {fails} FAIL, {unver} UNVERIFIED; logs in {}",
        dir.display()
    );
    for r in &results {
        if let Status::Unverified { needs, .. } = &r.status {
            println!("  UNVERIFIED {}: {needs}", r.name);
        }
    }
    Ok(if fails == 0 { 0 } else { 1 })
}

fn write_summary(dir: &Path, results: &[StepResult]) -> Result<()> {
    let steps: Vec<Value> = results
        .iter()
        .map(|r| {
            let (reason, needs) = match &r.status {
                Status::Unverified { reason, needs } => (Value::from(*reason), Value::from(needs.clone())),
                _ => (Value::Null, Value::Null),
            };
            json!({"n": r.n, "name": r.name, "command": r.command, "status": r.status.label(), "exit": r.exit,
                   "log": r.log, "sha256": r.sha256, "tail": r.tail, "reason": reason, "needs": needs})
        })
        .collect();
    let doc = json!({"started": now_utc(), "dir": dir.file_name().map(|n| n.to_string_lossy().into_owned()), "steps": steps});
    write_text(
        &dir.join("summary.json"),
        &serde_json::to_string_pretty(&doc).map_err(|e| crate::util::Error(e.to_string()))?,
    )?;
    let mut sums = String::new();
    for r in results {
        sums.push_str(&format!("{}  {}\n", r.sha256, r.log));
    }
    write_text(&dir.join("SHA256SUMS"), &sums)?;
    if let Some(parent) = dir.parent() {
        write_text(
            &parent.join("LATEST"),
            &format!(
                "{}\n",
                dir.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ),
        )?;
    }
    Ok(())
}

/// Load the summary of the most recent full verify run (for `gate-report`).
pub fn latest_summary(root: &Path) -> Result<(String, Value)> {
    let base = root.join("acceptance-verify");
    let name = read_text(&base.join("LATEST"))?.trim().to_owned();
    let text = read_text(&base.join(&name).join("summary.json"))?;
    let v: Value = serde_json::from_str(&text)
        .map_err(|e| crate::util::Error(format!("summary.json: {e}")))?;
    Ok((name, v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_map_to_statuses() {
        assert_eq!(classify("fmt", Some(0), "ok"), Status::Pass);
        assert_eq!(classify("fmt", Some(1), "diff"), Status::Fail);
        assert!(matches!(
            classify("vet", Some(101), "error: no such command: `vet`"),
            Status::Unverified {
                reason: "tool_unavailable",
                ..
            }
        ));
        assert!(matches!(
            classify(
                "audit",
                Some(1),
                "error: couldn't fetch advisory database: network"
            ),
            Status::Unverified {
                reason: "capability_not_supplied",
                ..
            }
        ));
    }

    #[test]
    fn a_failing_command_step_fails_and_a_missing_program_is_unverified() {
        let tmp = std::env::temp_dir();
        let (s, code, log) = run_cmd(
            &tmp,
            "false-step",
            "cargo",
            &["definitely-not-a-cargo-subcommand-xyz"],
        );
        assert!(
            matches!(s, Status::Fail | Status::Unverified { .. }),
            "{log}"
        );
        assert_ne!(code, Some(0));
        let (s2, _, _) = run_cmd(&tmp, "x", "hdd-no-such-program-xyz", &[]);
        assert!(matches!(
            s2,
            Status::Unverified {
                reason: "tool_unavailable",
                ..
            }
        ));
    }

    #[test]
    fn an_executable_blocked_by_application_control_is_unverified_not_failed() {
        let out = "error: could not execute process `x.exe` (never executed)\n\nCaused by:\n  An Application Control policy has blocked this file. (os error 4551)";
        let s = classify("deny", Some(101), out);
        assert!(matches!(
            s,
            Status::Unverified {
                reason: "tool_unavailable",
                ..
            }
        ));
        assert_eq!(
            classify("deny", Some(101), "error: real failure"),
            Status::Fail
        );
    }

    #[test]
    fn findings_status_fails_on_any_finding() {
        let (s, log) = findings_status(&[Finding::new("t", "a:1", "bad")], String::new());
        assert_eq!(s, Status::Fail);
        assert!(log.contains("[t] a:1: bad"));
        assert_eq!(findings_status(&[], String::new()).0, Status::Pass);
    }

    #[test]
    fn stubs_are_named_and_unverified() {
        let (s, log) = step_contrast(Path::new("."));
        assert!(matches!(
            s,
            Status::Unverified {
                reason: "stage_not_reached",
                ..
            }
        ));
        assert!(log.contains("T-0030"));
        assert!(stub_message("nope").is_none());
    }
}
