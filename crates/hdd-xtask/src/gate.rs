//! `gate-report <Gnn>`: assemble the gate report in the Appendix E5.1 format (T-0010 step 3).
//!
//! Mechanical parts come from the evidence: the collected verify run (`docs/gates/evidence/Gnn/verify/summary.json` with its
//! logs and SHA-256), `STATUS.md`, `docs/DEVIATIONS.md`, the specification's Acceptance lists and the execution order. The
//! hand-recorded parts (criterion results, conditions, findings, risks, rollback) live in
//! `docs/gates/evidence/Gnn/gate-inputs.toml`, and a criterion with no recorded result is reported as such (never as a pass).
//! The report is deterministic: regenerating it from the same inputs yields the same bytes (`--check`).

use std::fs;
use std::path::Path;

use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use crate::tasks::{self, Model};
use crate::util::{
    Error, Finding, Result, md_cell, read_bytes, read_text, rel, sha256_hex, tail_lines, write_text,
};
use crate::{spec, verify};

/// Hand-recorded gate inputs.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct Inputs {
    /// Commit description (a sha, or an honest statement that no commit exists).
    pub commit: String,
    /// UTC date of the report.
    pub date: String,
    /// Author role.
    pub author_role: String,
    /// `pilot` or `production`.
    pub stage: String,
    /// `live`, `lab` or `ci`.
    pub mode: String,
    /// Host identifier.
    pub host: String,
    /// Kernel / OS release string.
    pub kernel: String,
    /// `rustc -V`.
    pub toolchain: String,
    /// One-paragraph verdict.
    pub verdict: String,
    /// Rollback description (section 9).
    pub rollback: String,
    /// Matrix evidence note.
    #[serde(default)]
    pub notes: Vec<String>,
    /// Gate pass-condition results.
    #[serde(default)]
    pub condition: Vec<Condition>,
    /// Per-criterion results.
    #[serde(default)]
    pub criterion: Vec<Criterion>,
    /// Acceptance checks (AC-xx) touched.
    #[serde(default)]
    pub ac: Vec<Ac>,
    /// Findings.
    #[serde(default)]
    pub finding: Vec<Finding2>,
    /// Risks.
    #[serde(default)]
    pub risk: Vec<Risk>,
    /// Extra UNVERIFIED rows beyond those of the verify run.
    #[serde(default)]
    pub unverified: Vec<Unverified>,
    /// Deviation ids to quote from docs/DEVIATIONS.md.
    #[serde(default)]
    pub deviations: Vec<String>,
    /// Questions awaiting the operator.
    #[serde(default)]
    pub questions: Vec<String>,
    /// Blockers of upcoming tasks by task id.
    #[serde(default)]
    pub blocker: Vec<Blocker>,
}

/// One pass condition of the gate and its result.
#[derive(Debug, Deserialize, Clone)]
pub struct Condition {
    /// Condition text.
    pub text: String,
    /// `PASS`, `FAIL` or `UNVERIFIED(reason)`.
    pub status: String,
    /// Evidence reference.
    pub evidence: String,
}

/// One acceptance criterion result.
#[derive(Debug, Deserialize, Clone)]
pub struct Criterion {
    /// Task id.
    pub task: String,
    /// `A1`..`A5`.
    pub id: String,
    /// Status.
    pub status: String,
    /// Evidence reference.
    pub evidence: String,
    /// Notes.
    #[serde(default)]
    pub notes: String,
}

/// An AC row.
#[derive(Debug, Deserialize, Clone)]
pub struct Ac {
    /// Check id.
    pub check: String,
    /// Status.
    pub status: String,
    /// Reason code.
    #[serde(default)]
    pub reason: String,
    /// What the operator must supply.
    #[serde(default)]
    pub needs: String,
    /// Evidence.
    #[serde(default)]
    pub evidence: String,
}

/// A finding row.
#[derive(Debug, Deserialize, Clone)]
pub struct Finding2 {
    /// Id.
    pub id: String,
    /// Severity.
    pub severity: String,
    /// Area.
    pub area: String,
    /// Summary.
    pub summary: String,
    /// `fixed`, `accepted-with-owner` or `open`.
    pub status: String,
    /// Link.
    #[serde(default)]
    pub link: String,
}

/// A risk row.
#[derive(Debug, Deserialize, Clone)]
pub struct Risk {
    /// Risk.
    pub risk: String,
    /// Mitigation.
    pub mitigation: String,
}

/// An UNVERIFIED row.
#[derive(Debug, Deserialize, Clone)]
pub struct Unverified {
    /// What is unverified.
    pub item: String,
    /// Reason code.
    pub reason: String,
    /// Operator action.
    pub needs: String,
}

/// Blocker text for a task.
#[derive(Debug, Deserialize, Clone)]
pub struct Blocker {
    /// Task id.
    pub task: String,
    /// Blocker.
    pub text: String,
}

/// Acceptance criteria `A1..An` of a task block: (id, text).
pub fn criteria_of(block: &str) -> Vec<(String, String)> {
    let Ok(re) = Regex::new(r"^- (A\d+): (.*)$") else {
        return vec![];
    };
    block
        .lines()
        .filter_map(|l| re.captures(l))
        .map(|c| (c[1].to_owned(), c[2].to_owned()))
        .collect()
}

fn cell_lines(text: &str) -> String {
    text.replace('\r', "")
        .split('\n')
        .map(md_cell)
        .collect::<Vec<_>>()
        .join("<br>")
}

fn evidence_dir(root: &Path, gate: &str) -> std::path::PathBuf {
    root.join("docs").join("gates").join("evidence").join(gate)
}

/// `--collect`: copy the latest verify run (logs, summary, SHA256SUMS) into `docs/gates/evidence/Gnn/verify/`.
pub fn collect(root: &Path, gate: &str) -> Result<String> {
    let (name, _) = verify::latest_summary(root)?;
    let src = root.join("acceptance-verify").join(&name);
    let dst = evidence_dir(root, gate).join("verify");
    if dst.exists() {
        fs::remove_dir_all(&dst)?;
    }
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(&src)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            fs::copy(entry.path(), dst.join(entry.file_name()))?;
        }
    }
    Ok(name)
}

fn step_status(summary: &Value, name: &str) -> String {
    summary
        .get("steps")
        .and_then(Value::as_array)
        .and_then(|s| {
            s.iter()
                .find(|x| x.get("name").and_then(Value::as_str) == Some(name))
        })
        .and_then(|x| x.get("status").and_then(Value::as_str))
        .unwrap_or("not run")
        .to_owned()
}

fn step_tail(summary: &Value, name: &str) -> String {
    summary
        .get("steps")
        .and_then(Value::as_array)
        .and_then(|s| {
            s.iter()
                .find(|x| x.get("name").and_then(Value::as_str) == Some(name))
        })
        .and_then(|x| x.get("tail").and_then(Value::as_str))
        .unwrap_or("")
        .to_owned()
}

fn nextest_count(summary: &Value) -> String {
    let tail = step_tail(summary, "nextest");
    tail.lines()
        .rev()
        .find(|l| l.contains("Summary"))
        .map_or_else(|| "not recorded".to_owned(), |l| l.trim().to_owned())
}

fn rust_share_line(summary: &Value) -> String {
    let tail = step_tail(summary, "rust-share");
    tail.lines()
        .find(|l| l.contains("Rust share"))
        .map_or("not recorded", str::trim)
        .to_owned()
}

fn deviation_rows(root: &Path, ids: &[String]) -> String {
    let text = read_text(&root.join("docs").join("DEVIATIONS.md")).unwrap_or_default();
    let mut out = String::from("| ID | Entry |\n| --- | --- |\n");
    for id in ids {
        let row = text.lines().find(|l| l.starts_with(&format!("| {id} |")));
        match row {
            Some(r) => {
                let rest = r
                    .trim_start_matches(&format!("| {id} |"))
                    .trim()
                    .trim_end_matches('|')
                    .trim();
                out.push_str(&format!("| {id} | {} |\n", md_cell(rest)));
            }
            None => out.push_str(&format!("| {id} | NOT FOUND in docs/DEVIATIONS.md |\n")),
        }
    }
    out
}

/// Render the gate report. Returns the Markdown and the list of problems (criteria without a recorded result, etc.).
pub fn render(
    root: &Path,
    gate: &str,
    model: &Model,
    inputs: &Inputs,
    summary: &Value,
    run_dir: &str,
) -> Result<(String, Vec<String>)> {
    let phase = model
        .phases
        .iter()
        .find(|p| p.gate == gate)
        .ok_or_else(|| Error(format!("unknown gate {gate}")))?;
    let states = tasks::status_states(root, model)?;
    let ord = tasks::order(model)?;
    let mut problems = Vec::new();
    let mut o = String::new();
    o.push_str(&format!("# Gate {gate}: {}\n\n", phase.name));
    o.push_str(&format!(
        "- Phase / milestone: {} / {}   - Commit: {}   - Date: {}   - Author role: {}\n",
        phase.id, phase.milestone, inputs.commit, inputs.date, inputs.author_role
    ));
    o.push_str(&format!(
        "- Environment: stage={} mode={} host={} kernel={} toolchain={}\n\n",
        inputs.stage, inputs.mode, inputs.host, inputs.kernel, inputs.toolchain
    ));
    o.push_str(&format!("**Verdict.** {}\n\n", inputs.verdict));
    o.push_str("### Gate pass condition (E5.4.1)\n\n| Condition | Status | Evidence |\n| --- | --- | --- |\n");
    for c in &inputs.condition {
        o.push_str(&format!(
            "| {} | {} | {} |\n",
            md_cell(&c.text),
            c.status,
            md_cell(&c.evidence)
        ));
    }
    o.push_str("\n## 1. Commands run (with output tails)\n");
    o.push_str(&format!("Run directory: `{run_dir}` (full logs and `SHA256SUMS` are committed under `docs/gates/evidence/{gate}/verify/`).\n\n"));
    o.push_str("| # | Command | Exit | Output tail (last 20 lines) | Full log sha256 |\n| --- | --- | --- | --- | --- |\n");
    if let Some(steps) = summary.get("steps").and_then(Value::as_array) {
        for s in steps {
            let g = |k: &str| s.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
            let exit = s
                .get("exit")
                .and_then(Value::as_i64)
                .map_or_else(|| "-".to_owned(), |e| e.to_string());
            o.push_str(&format!(
                "| {} | `{}` ({}) | {} (status {}) | {} | {} |\n",
                s.get("n").and_then(Value::as_i64).unwrap_or(0),
                md_cell(&g("command")),
                g("name"),
                exit,
                g("status"),
                cell_lines(&tail_lines(&g("tail"), 20)),
                g("sha256")
            ));
        }
    }
    o.push_str("\n## 2. Acceptance criteria\n| Task | Criterion | Status | Evidence ref | Notes |\n| --- | --- | --- | --- | --- |\n");
    for t in model.tasks.iter().filter(|t| t.phase == phase.id) {
        for (cid, text) in criteria_of(&t.block) {
            let rec = inputs
                .criterion
                .iter()
                .find(|c| c.task == t.id && c.id == cid);
            match rec {
                Some(c) => o.push_str(&format!(
                    "| {} | {cid}: {} | {} | {} | {} |\n",
                    t.id,
                    md_cell(&text),
                    c.status,
                    md_cell(&c.evidence),
                    md_cell(&c.notes)
                )),
                None => {
                    problems.push(format!("{} {cid}: no recorded result", t.id));
                    o.push_str(&format!("| {} | {cid}: {} | NOT RECORDED | | no result recorded in gate-inputs.toml |\n", t.id, md_cell(&text)));
                }
            }
        }
    }
    o.push_str("\n## 3. Acceptance checks (AC-xx) touched by this phase\n| Check | Status | Reason code if UNVERIFIED | What the operator must supply | Evidence |\n| --- | --- | --- | --- | --- |\n");
    for a in &inputs.ac {
        o.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            a.check,
            a.status,
            a.reason,
            md_cell(&a.needs),
            md_cell(&a.evidence)
        ));
    }
    o.push_str("\n## 4. Metrics\n| Metric | Value |\n| --- | --- |\n");
    o.push_str(&format!(
        "| rust-share | {} |\n",
        md_cell(&rust_share_line(summary))
    ));
    o.push_str(&format!(
        "| tokei totals | see the rust-share log (`{run_dir}`, step rust-share) |\n"
    ));
    o.push_str(&format!(
        "| test count | {} |\n",
        md_cell(&nextest_count(summary))
    ));
    o.push_str("| coverage (lines/branches) | UNVERIFIED(tool_unavailable): cargo-llvm-cov not installed |\n");
    o.push_str("| mutation score | UNVERIFIED(stage_not_reached): cargo-mutants runs on hdd-waf-core (T-0258) |\n");
    for (label, step) in [
        ("clippy", "clippy"),
        ("audit", "audit"),
        ("deny", "deny"),
        ("vet", "vet"),
        ("unsafe-scan", "unsafe-scan"),
        ("claims-lint", "claims-lint"),
        ("docs-test", "doc-tests"),
        ("machete", "machete"),
        ("secret-scan", "secret-scan"),
        ("dependency-vetting", "dependency-vetting"),
    ] {
        o.push_str(&format!("| {label} | {} |\n", step_status(summary, step)));
    }
    o.push_str("| a11y violations | not applicable (no UI yet) |\n| perf deltas | not applicable (no benchmarks yet) |\n");
    o.push_str("\n## 5. Deviations and assumptions\n");
    o.push_str(&deviation_rows(root, &inputs.deviations));
    o.push_str("\n## 6. UNVERIFIED register\n| Item | Reason code | What the operator must supply |\n| --- | --- | --- |\n");
    if let Some(steps) = summary.get("steps").and_then(Value::as_array) {
        for s in steps {
            let status = s.get("status").and_then(Value::as_str).unwrap_or("");
            if status.starts_with("UNVERIFIED") {
                let name = s.get("name").and_then(Value::as_str).unwrap_or("");
                let reason = s.get("reason").and_then(Value::as_str).unwrap_or("");
                let needs = s.get("needs").and_then(Value::as_str).unwrap_or("");
                o.push_str(&format!(
                    "| verify step `{name}` | {reason} | {} |\n",
                    md_cell(needs)
                ));
            }
        }
    }
    for u in &inputs.unverified {
        o.push_str(&format!(
            "| {} | {} | {} |\n",
            md_cell(&u.item),
            u.reason,
            md_cell(&u.needs)
        ));
    }
    o.push_str("\n## 7. Findings\n| Id | Severity | Area | Summary | Status (fixed / accepted-with-owner / open) | Link |\n| --- | --- | --- | --- | --- | --- |\n");
    for f in &inputs.finding {
        o.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            f.id,
            f.severity,
            f.area,
            md_cell(&f.summary),
            f.status,
            f.link
        ));
    }
    o.push_str("\n## 8. Risks and open questions\n| Risk | Mitigation |\n| --- | --- |\n");
    for r in &inputs.risk {
        o.push_str(&format!(
            "| {} | {} |\n",
            md_cell(&r.risk),
            md_cell(&r.mitigation)
        ));
    }
    o.push_str("\nQuestions awaiting the operator:\n\n");
    for q in &inputs.questions {
        o.push_str(&format!("- {q}\n"));
    }
    o.push_str(&format!("\n## 9. Rollback\n{}\n", inputs.rollback));
    o.push_str("\n## 10. Next steps\n| Order | Task | Title | State | Blockers |\n| --- | --- | --- | --- | --- |\n");
    let mut shown = 0;
    for (n, id) in ord.iter().enumerate() {
        let st = states.get(id).map_or("todo", String::as_str);
        if matches!(st, "done" | "accepted" | "verified") || shown >= 10 {
            continue;
        }
        let Some(t) = model.task(id) else { continue };
        let unmet: Vec<String> = t
            .deps
            .iter()
            .filter(|d| {
                !matches!(
                    states.get(*d).map_or("todo", String::as_str),
                    "done" | "accepted" | "verified"
                )
            })
            .cloned()
            .collect();
        let mut blockers = if unmet.is_empty() {
            "none".to_owned()
        } else {
            format!("waits for {}", unmet.join(", "))
        };
        if let Some(b) = inputs.blocker.iter().find(|b| b.task == *id) {
            blockers = format!("{blockers}; {}", b.text);
        }
        o.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            n + 1,
            id,
            md_cell(&t.title),
            st,
            md_cell(&blockers)
        ));
        shown += 1;
    }
    if !inputs.notes.is_empty() {
        o.push_str("\n## Notes\n");
        for n in &inputs.notes {
            o.push_str(&format!("- {n}\n"));
        }
    }
    Ok((o, problems))
}

/// `gate-report Gnn [--collect] [--check]`.
pub fn run(root: &Path, gate: &str, do_collect: bool, check_only: bool) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    if do_collect {
        let name = collect(root, gate)?;
        println!(
            "gate-report: collected verify run {name} into docs/gates/evidence/{gate}/verify/"
        );
    }
    let dir = evidence_dir(root, gate);
    let inputs: Inputs = toml::from_str(&read_text(&dir.join("gate-inputs.toml"))?)?;
    let summary_text = read_text(&dir.join("verify").join("summary.json"))?;
    let summary: Value =
        serde_json::from_str(&summary_text).map_err(|e| Error(format!("summary.json: {e}")))?;
    // the collected logs must match their recorded hashes
    if let Some(steps) = summary.get("steps").and_then(Value::as_array) {
        for s in steps {
            let log = s.get("log").and_then(Value::as_str).unwrap_or("");
            let want = s.get("sha256").and_then(Value::as_str).unwrap_or("");
            match read_bytes(&dir.join("verify").join(log)) {
                Ok(b) if sha256_hex(&b) == want => {}
                Ok(_) => findings.push(Finding::new(
                    "gate",
                    format!("docs/gates/evidence/{gate}/verify/{log}"),
                    "log hash differs from summary.json",
                )),
                Err(_) => findings.push(Finding::new(
                    "gate",
                    format!("docs/gates/evidence/{gate}/verify/{log}"),
                    "log missing",
                )),
            }
        }
    }
    let model = tasks::parse(&spec::load_master(root)?)?;
    let run_dir = summary
        .get("dir")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_owned();
    let (text, problems) = render(root, gate, &model, &inputs, &summary, &run_dir)?;
    for p in problems {
        findings.push(Finding::new("gate", gate, p));
    }
    let out = root.join("docs").join("gates").join(format!("{gate}.md"));
    if check_only {
        match read_text(&out) {
            Ok(cur) if cur == text => {}
            Ok(_) => findings.push(Finding::new(
                "gate",
                rel(root, &out),
                "differs from the regenerated report (A3: regenerate and compare)",
            )),
            Err(e) => findings.push(Finding::new("gate", rel(root, &out), e.0)),
        }
    } else {
        write_text(&out, &text)?;
        println!("gate-report: wrote {}", rel(root, &out));
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn criteria_are_parsed_from_the_acceptance_list() {
        let block =
            "**Acceptance.**\n- A1: first thing\n- A2: second `thing`\n**Tests.**\n- Unit: x\n";
        let c = criteria_of(block);
        assert_eq!(
            c,
            vec![
                ("A1".to_owned(), "first thing".to_owned()),
                ("A2".to_owned(), "second `thing`".to_owned())
            ]
        );
    }

    #[test]
    fn nextest_summary_is_extracted_from_the_tail() {
        let v: Value = serde_json::json!({"steps":[{"name":"nextest","tail":"x\n     Summary [   0.5s] 120 tests run: 120 passed, 0 skipped\n"}]});
        assert!(nextest_count(&v).contains("120 tests run"));
        assert_eq!(
            nextest_count(&serde_json::json!({"steps":[]})),
            "not recorded"
        );
    }

    #[test]
    fn cells_escape_pipes_and_newlines() {
        assert_eq!(cell_lines("a|b\nc"), "a\\|b<br>c");
    }

    const TINY_SPEC: &str = "<!-- PART:A0 -->\n# t\n<!-- PHASE:P00 -->\n## PHASE P00: Boot (T-0001 to T-0002) · milestone M0 · gate G00\n\nRequirement prefix `GOV`. Goal.\n\n### T-0001 · First\n`P00` `[DOC]` · deps: none · size: S · owner: docs\n**Objective.** x\n**Acceptance.**\n- A1: first thing holds\n- A2: second thing holds\n\n---\n\n### T-0002 · Second\n`P00` `[SEC]` · deps: T-0001 · size: M · owner: sec\n**Objective.** y\n**Acceptance.**\n- A1: only criterion\n";

    fn tiny_inputs(with_all: bool) -> Inputs {
        let mut i = Inputs {
            commit: "no commit".into(),
            date: "2026-10-18".into(),
            author_role: "agent".into(),
            stage: "pilot".into(),
            mode: "ci".into(),
            host: "h".into(),
            kernel: "k".into(),
            toolchain: "rustc".into(),
            verdict: "v".into(),
            rollback: "r".into(),
            ..Inputs::default()
        };
        let c = |task: &str, id: &str| Criterion {
            task: task.into(),
            id: id.into(),
            status: "PASS".into(),
            evidence: "e".into(),
            notes: String::new(),
        };
        i.criterion.push(c("T-0001", "A1"));
        i.criterion.push(c("T-0002", "A1"));
        if with_all {
            i.criterion.push(c("T-0001", "A2"));
        }
        i
    }

    #[test]
    fn the_gate_report_is_deterministic_follows_the_template_and_flags_unrecorded_criteria() {
        let root = std::env::temp_dir().join(format!("hdd-xtask-gate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("docs")).expect("mkdir");
        std::fs::write(root.join("STATUS.md"), "| [T-0001](docs/tasks/P00/T-0001.md) | First | verified | e | |\n| [T-0002](docs/tasks/P00/T-0002.md) | Second | todo | | |\n").expect("write");
        std::fs::write(
            root.join("docs").join("DEVIATIONS.md"),
            "| DEV-1 | thing | why | 2026-10-18 | op |\n",
        )
        .expect("write");
        let model = tasks::parse(TINY_SPEC).expect("model");
        let summary = serde_json::json!({"dir": "run", "steps": [{"n": 1, "name": "fmt", "command": "cargo fmt", "status": "PASS", "exit": 0, "sha256": "ab", "tail": "ok", "log": "01-fmt.log"}]});

        let (a, problems) =
            render(&root, "G00", &model, &tiny_inputs(true), &summary, "run").expect("render");
        let (b, _) =
            render(&root, "G00", &model, &tiny_inputs(true), &summary, "run").expect("render");
        assert_eq!(a, b, "regenerating gives the same bytes");
        assert!(problems.is_empty(), "{problems:?}");
        for heading in [
            "# Gate G00: Boot",
            "## 1. Commands run (with output tails)",
            "## 2. Acceptance criteria",
            "## 3. Acceptance checks",
            "## 4. Metrics",
            "## 5. Deviations and assumptions",
            "## 6. UNVERIFIED register",
            "## 7. Findings",
            "## 8. Risks and open questions",
            "## 9. Rollback",
            "## 10. Next steps",
        ] {
            assert!(a.contains(heading), "missing {heading}");
        }
        assert!(a.contains("| T-0001 | A1: first thing holds | PASS |"));
        assert!(a.contains("| 1 | `cargo fmt` (fmt) | 0 (status PASS) | ok | ab |"));

        let (c, missing) =
            render(&root, "G00", &model, &tiny_inputs(false), &summary, "run").expect("render");
        assert_eq!(missing, vec!["T-0001 A2: no recorded result".to_owned()]);
        assert!(
            c.contains("NOT RECORDED"),
            "an unrecorded criterion must never read as a pass"
        );
        assert!(render(&root, "G99", &model, &tiny_inputs(true), &summary, "run").is_err());
    }
}
