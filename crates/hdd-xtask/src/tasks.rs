//! Task model parsed from the master specification, plus `tasks index|order|check` (T-0005, section 0.9).
//!
//! The model is the single parser used by `spec show`, `tasks`, `matrix` and `gate-report`. It reproduces the
//! cross-checks of the bootstrap tool: the Appendix E14 index, the phase table, the delivery-slice counts and
//! the dependency graph (cycles are an error).

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::path::Path;

use regex::Regex;

use crate::spec::{self, Segment};
use crate::util::{Error, Finding, Result, md_cell, read_text, rel, write_text};

/// One task block of the specification.
#[derive(Debug, Clone)]
pub struct Task {
    /// `T-nnnn`.
    pub id: String,
    /// Title from the heading.
    pub title: String,
    /// Phase id (`P00`).
    pub phase: String,
    /// Tags without brackets (`SEC`, `API`).
    pub tags: Vec<String>,
    /// Direct dependencies.
    pub deps: Vec<String>,
    /// Size letter(s) (S, M, L, XL).
    pub size: String,
    /// Owner word.
    pub owner: String,
    /// Verbatim block text (heading through Notes, trailing blank/`---` lines removed).
    pub block: String,
    /// Line of the heading in `docs/SPEC.md` (1-based).
    pub spec_line: usize,
    /// Split file id holding the task.
    pub seg: String,
    /// Line of the heading inside the split file (1-based).
    pub seg_line: usize,
}

/// One phase of the specification.
#[derive(Debug, Clone)]
pub struct Phase {
    /// `Pnn`.
    pub id: String,
    /// Phase name.
    pub name: String,
    /// First task id.
    pub first: String,
    /// Last task id.
    pub last: String,
    /// Milestone (`M0`).
    pub milestone: String,
    /// Gate (`G00`).
    pub gate: String,
    /// Requirement prefix (`GOV`).
    pub prefix: String,
}

/// A delivery slice (section 0.8) with the counts the specification states in Appendix E13.
#[derive(Debug, Clone)]
pub struct Slice {
    /// `DSn`.
    pub id: String,
    /// Root tasks (empty means every task outside P32).
    pub roots: Vec<String>,
    /// (total, new) task counts stated by E13.
    pub stated: Option<(usize, usize)>,
}

/// One row of the Appendix E14 index: (phase, title, tags, size, owner, dependency count).
pub type E14Row = (String, String, Vec<String>, String, String, usize);

/// Everything parsed from the specification.
#[derive(Debug, Clone)]
pub struct Model {
    /// Tasks in specification order.
    pub tasks: Vec<Task>,
    /// Phases in specification order.
    pub phases: Vec<Phase>,
    /// Delivery slices.
    pub slices: Vec<Slice>,
    /// Appendix E14 rows: task -> (phase, title, tags, size, owner, dep count).
    pub e14: BTreeMap<String, E14Row>,
}

impl Model {
    /// Look up a task.
    pub fn task(&self, id: &str) -> Option<&Task> {
        self.tasks.iter().find(|t| t.id == id)
    }

    /// Look up a phase.
    pub fn phase(&self, id: &str) -> Option<&Phase> {
        self.phases.iter().find(|p| p.id == id)
    }
}

/// Parse the specification text into a [`Model`].
pub fn parse(text: &str) -> Result<Model> {
    let segs = spec::split(text)?;
    let lines: Vec<&str> = text.split('\n').collect();
    let task_head = Regex::new(r"^### (T-\d{4}) · (.*?)\r?$")?;
    let meta = Regex::new(r"^`(P\d\d)` (.*?)· deps: (.*?) · size: (\w+) · owner: (\w+)\s*$")?;
    let marker = Regex::new(r"^<!-- (PART|PHASE):([A-Za-z0-9]+) -->\r?$")?;
    let tag_re = Regex::new(r"\[([A-Z]+)\]")?;
    let dep_re = Regex::new(r"T-\d{4}")?;

    let seg_of_line = |i: usize| -> Option<&Segment> {
        segs.iter()
            .find(|s| i + 1 >= s.start_line && i < s.end_line)
    };

    let mut tasks = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(c) = task_head.captures(line) else {
            continue;
        };
        let id = c.get(1).map(|m| m.as_str().to_owned()).unwrap_or_default();
        let title = c.get(2).map(|m| m.as_str().to_owned()).unwrap_or_default();
        let mut j = i + 1;
        while let Some(l) = lines.get(j) {
            if task_head.is_match(l) || marker.is_match(l) {
                break;
            }
            j += 1;
        }
        let mut blk: Vec<&str> = lines.get(i..j).unwrap_or(&[]).to_vec();
        while blk
            .last()
            .is_some_and(|l| l.trim().is_empty() || l.trim() == "---")
        {
            blk.pop();
        }
        let meta_line = lines.get(i + 1).copied().unwrap_or("");
        let m = meta
            .captures(meta_line)
            .ok_or_else(|| Error(format!("{id}: meta line not recognised: {meta_line:?}")))?;
        let g = |n: usize| m.get(n).map(|x| x.as_str().to_owned()).unwrap_or_default();
        let seg = seg_of_line(i).ok_or_else(|| Error(format!("{id}: not inside any segment")))?;
        tasks.push(Task {
            id,
            title,
            phase: g(1),
            tags: tag_re
                .captures_iter(&g(2))
                .filter_map(|t| t.get(1).map(|x| x.as_str().to_owned()))
                .collect(),
            deps: dep_re
                .find_iter(&g(3))
                .map(|d| d.as_str().to_owned())
                .collect(),
            size: g(4),
            owner: g(5),
            block: blk.join("\n"),
            spec_line: i + 1,
            seg: seg.id.clone(),
            seg_line: i + 1 - seg.start_line + 1,
        });
    }

    let phase_head = Regex::new(
        r"^## PHASE (P\d\d): (.*) \((T-\d{4}) to (T-\d{4})\) · (?:milestone )?(.*?) · gate (G\d\d)\s*$",
    )?;
    let prefix_re = Regex::new(r"Requirement prefix `([A-Z0-9]+)`")?;
    let mut phases = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(c) = phase_head.captures(line) else {
            continue;
        };
        let g = |n: usize| c.get(n).map(|x| x.as_str().to_owned()).unwrap_or_default();
        let mut j = i + 1;
        while lines.get(j).is_some_and(|l| !task_head.is_match(l)) {
            j += 1;
        }
        let intro = lines.get(i + 1..j).unwrap_or(&[]).join("\n");
        let prefix = prefix_re
            .captures(&intro)
            .and_then(|p| p.get(1))
            .map(|p| p.as_str().to_owned())
            .unwrap_or_default();
        phases.push(Phase {
            id: g(1),
            name: g(2),
            first: g(3),
            last: g(4),
            milestone: g(5),
            gate: g(6),
            prefix,
        });
    }

    let e14_re = Regex::new(
        r"^\| (T-\d{4}) \| (P\d\d) \| (.*) \| ([A-Z ]*) \| (\w+) \| (\w+) \| (\d+) \|$",
    )?;
    let mut e14 = BTreeMap::new();
    for line in &lines {
        if let Some(c) = e14_re.captures(line) {
            let g = |n: usize| c.get(n).map(|x| x.as_str().to_owned()).unwrap_or_default();
            let tags = g(4).split_whitespace().map(str::to_owned).collect();
            e14.insert(
                g(1),
                (g(2), g(3), tags, g(5), g(6), g(7).parse().unwrap_or(0)),
            );
        }
    }

    let slice_re = Regex::new(r"^\| (DS\d) ([^|]*?) \| ([^|]*) \| ([^|]*) \|$")?;
    let count_re = Regex::new(r"^\| (DS\d) [^|]*\| [^|]*\| (\d+) \| (\d+) \|")?;
    let mut slice_map: BTreeMap<String, Slice> = BTreeMap::new();
    for line in &lines {
        if let Some(c) = slice_re.captures(line) {
            let id = c.get(1).map(|x| x.as_str().to_owned()).unwrap_or_default();
            let roots = dep_re
                .find_iter(c.get(4).map_or("", |x| x.as_str()))
                .map(|d| d.as_str().to_owned())
                .collect();
            slice_map.entry(id.clone()).or_insert(Slice {
                id,
                roots,
                stated: None,
            });
        }
    }
    for line in &lines {
        if let Some(c) = count_re.captures(line) {
            let id = c.get(1).map(|x| x.as_str().to_owned()).unwrap_or_default();
            let total = c.get(2).and_then(|x| x.as_str().parse().ok()).unwrap_or(0);
            let new = c.get(3).and_then(|x| x.as_str().parse().ok()).unwrap_or(0);
            if let Some(s) = slice_map.get_mut(&id) {
                s.stated = Some((total, new));
            }
        }
    }
    Ok(Model {
        tasks,
        phases,
        slices: slice_map.into_values().collect(),
        e14,
    })
}

/// Stable topological order of the dependency graph (ties broken by task number). Cycles are an error.
pub fn order(model: &Model) -> Result<Vec<String>> {
    let mut indeg: BTreeMap<&str, usize> = BTreeMap::new();
    let mut rev: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for t in &model.tasks {
        indeg.entry(t.id.as_str()).or_insert(0);
    }
    for t in &model.tasks {
        for d in &t.deps {
            if model.task(d).is_none() {
                return Err(Error(format!("{} depends on unknown task {d}", t.id)));
            }
            *indeg.entry(t.id.as_str()).or_insert(0) += 1;
            rev.entry(d.as_str()).or_default().push(t.id.as_str());
        }
    }
    let mut heap: BinaryHeap<Reverse<&str>> = indeg
        .iter()
        .filter(|(_, n)| **n == 0)
        .map(|(t, _)| Reverse(*t))
        .collect();
    let mut out = Vec::new();
    while let Some(Reverse(t)) = heap.pop() {
        out.push(t.to_owned());
        for u in rev.get(t).map(Vec::as_slice).unwrap_or(&[]) {
            if let Some(n) = indeg.get_mut(u) {
                *n -= 1;
                if *n == 0 {
                    heap.push(Reverse(u));
                }
            }
        }
    }
    if out.len() != model.tasks.len() {
        return Err(Error("dependency cycle detected".into()));
    }
    Ok(out)
}

/// Transitive dependency closure of `roots` (the roots included).
pub fn closure(model: &Model, roots: &[String]) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<String> = roots.to_vec();
    while let Some(t) = stack.pop() {
        if !seen.insert(t.clone()) {
            continue;
        }
        if let Some(task) = model.task(&t) {
            stack.extend(task.deps.iter().cloned());
        }
    }
    seen
}

/// `REQ-<PREFIX>-<k>` for every task (the k-th task of a phase owns `REQ-<PREFIX>-<k>`, section 0.9).
pub fn req_ids(model: &Model) -> BTreeMap<String, String> {
    let mut counters: BTreeMap<&str, usize> = BTreeMap::new();
    let mut out = BTreeMap::new();
    for t in &model.tasks {
        let n = counters.entry(t.phase.as_str()).or_insert(0);
        *n += 1;
        let prefix = model.phase(&t.phase).map_or("UNK", |p| p.prefix.as_str());
        out.insert(t.id.clone(), format!("REQ-{prefix}-{n:02}"));
    }
    out
}

/// Cross-checks of the parsed model against the specification's own generated index (Appendix E14), the phase
/// table and the delivery slices.
pub fn validate(model: &Model) -> Vec<Finding> {
    let mut f = Vec::new();
    let expected: Vec<String> = (1..=599).map(|n| format!("T-{n:04}")).collect();
    let got: Vec<String> = model.tasks.iter().map(|t| t.id.clone()).collect();
    if got != expected {
        f.push(Finding::new(
            "tasks",
            "docs/SPEC.md",
            "task ids are not exactly T-0001..T-0599 in order",
        ));
    }
    if model.e14.len() != 599 {
        f.push(Finding::new(
            "tasks",
            "docs/SPEC.md",
            format!("E14 has {} rows (expected 599)", model.e14.len()),
        ));
    }
    for t in &model.tasks {
        match model.e14.get(&t.id) {
            None => f.push(Finding::new("tasks", &t.id, "missing in E14")),
            Some((phase, title, tags, size, owner, deps)) => {
                if (phase, size, owner, *deps) != (&t.phase, &t.size, &t.owner, t.deps.len()) {
                    f.push(Finding::new(
                        "tasks",
                        &t.id,
                        "phase/size/owner/dependency count differ from E14",
                    ));
                }
                if tags != &t.tags {
                    f.push(Finding::new("tasks", &t.id, "tags differ from E14"));
                }
                if title != &t.title {
                    f.push(Finding::new("tasks", &t.id, "title differs from E14"));
                }
            }
        }
    }
    if model.phases.len() != 35 {
        f.push(Finding::new(
            "tasks",
            "docs/SPEC.md",
            format!("{} phases found (expected 35)", model.phases.len()),
        ));
    }
    for p in &model.phases {
        let ids: Vec<&Task> = model.tasks.iter().filter(|t| t.phase == p.id).collect();
        if ids.first().map(|t| &t.id) != Some(&p.first)
            || ids.last().map(|t| &t.id) != Some(&p.last)
        {
            f.push(Finding::new(
                "tasks",
                &p.id,
                "task range differs from the phase heading",
            ));
        }
        if p.prefix.is_empty() {
            f.push(Finding::new("tasks", &p.id, "no requirement prefix"));
        }
    }
    let mut prev: BTreeSet<String> = BTreeSet::new();
    for s in &model.slices {
        let roots: Vec<String> = if s.roots.is_empty() {
            model
                .tasks
                .iter()
                .filter(|t| t.phase != "P32")
                .map(|t| t.id.clone())
                .collect()
        } else {
            s.roots.clone()
        };
        let cl = closure(model, &roots);
        let new = cl.difference(&prev).count();
        if s.stated != Some((cl.len(), new)) {
            f.push(Finding::new(
                "tasks",
                &s.id,
                format!(
                    "slice counts computed ({}, {new}) differ from E13 {:?}",
                    cl.len(),
                    s.stated
                ),
            ));
        }
        prev.extend(cl);
    }
    if let Err(e) = order(model) {
        f.push(Finding::new("tasks", "deps", e.0));
    }
    f
}

/// Live task states from the table in `STATUS.md` (`T-nnnn` -> state).
pub fn status_states(root: &Path, model: &Model) -> Result<BTreeMap<String, String>> {
    let text = read_text(&root.join("STATUS.md"))?;
    let mut out = BTreeMap::new();
    let re = Regex::new(r"^\| \[(T-\d{4})\]\([^)]*\) \| ")?;
    for line in text.lines() {
        let Some(c) = re.captures(line) else { continue };
        let id = c.get(1).map(|x| x.as_str()).unwrap_or("");
        let rest = line.get(c.get(0).map_or(0, |m| m.end())..).unwrap_or("");
        let Some(task) = model.task(id) else { continue };
        let title = md_cell(&task.title);
        let after = rest
            .strip_prefix(title.as_str())
            .and_then(|r| r.strip_prefix(" | "))
            .unwrap_or("");
        let state = after.split(" | ").next().unwrap_or("").trim();
        out.insert(id.to_owned(), state.to_owned());
    }
    Ok(out)
}

/// States allowed in `STATUS.md` (section 0.6), with the parameterised forms.
pub fn state_is_valid(s: &str) -> bool {
    matches!(
        s,
        "todo" | "designing" | "red" | "green" | "verified" | "accepted" | "done"
    ) || (s.starts_with("blocked(") && s.ends_with(')'))
        || (s.starts_with("deferred(") && s.ends_with(')'))
}

/// Render `docs/spec/INDEX.md`.
pub fn render_spec_index(model: &Model, digest: &str) -> String {
    let mut out = String::from("# Specification index: task ID to file and line\n\n");
    out.push_str("Generated by `cargo xtask tasks index` (T-0005). Do not edit by hand.\n");
    out.push_str(&format!("Source: `docs/SPEC.md` sha256 `{digest}`.\n\n"));
    out.push_str("Parts and phases: see [MANIFEST.tsv](MANIFEST.tsv). Concatenating the files in manifest order reproduces `docs/SPEC.md` byte for byte.\n\n");
    out.push_str("| Task | Title | Phase | File | Start line | Tags | Size | Deps |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for t in &model.tasks {
        let deps = if t.deps.is_empty() {
            "none".to_owned()
        } else {
            t.deps.join(", ")
        };
        out.push_str(&format!(
            "| {} | {} | {} | docs/spec/{}.md | {} (SPEC.md {}) | {} | {} | {} |\n",
            t.id,
            md_cell(&t.title),
            t.phase,
            t.seg,
            t.seg_line,
            t.spec_line,
            t.tags.join(" "),
            t.size,
            deps
        ));
    }
    out
}

/// Render the root `INDEX.md` (execution order with the live state from `STATUS.md`).
pub fn render_root_index(
    model: &Model,
    ord: &[String],
    states: &BTreeMap<String, String>,
) -> String {
    let mut out = String::from("# Task index and execution order\n\n");
    out.push_str("Generated by `cargo xtask tasks index` (T-0005). Do not edit by hand; the state column is read from the task table of [STATUS.md](STATUS.md).\n\n");
    out.push_str("Execution order is the stable topological order of the `deps:` graph (ties broken by task number, section 0.9). ");
    out.push_str(
        "A dependency on a later number is legal and means the later-numbered task runs first. ",
    );
    out.push_str("Exception by instruction: section 0.8 and E13.2 start T-0561 to T-0563 (slice DS0) right after gate G00 even though their numbers place them last here.\n\n");
    out.push_str("| Order | Task | Phase | Title | Size | Owner | State |\n| --- | --- | --- | --- | --- | --- | --- |\n");
    for (n, id) in ord.iter().enumerate() {
        let Some(t) = model.task(id) else { continue };
        let st = states.get(id).map_or("todo", String::as_str);
        out.push_str(&format!(
            "| {} | [{}](docs/tasks/{}/{}.md) | {} | {} | {} | {} | {} |\n",
            n + 1,
            t.id,
            t.phase,
            t.id,
            t.phase,
            md_cell(&t.title),
            t.size,
            t.owner,
            st
        ));
    }
    out
}

/// `tasks index [--check]`: write (or verify) `docs/spec/INDEX.md` and `INDEX.md`.
pub fn index(root: &Path, check_only: bool) -> Result<Vec<Finding>> {
    let text = spec::load_master(root)?;
    let model = parse(&text)?;
    let mut findings = validate(&model);
    let ord = order(&model)?;
    let states = status_states(root, &model)?;
    let digest = crate::util::sha256_hex(text.as_bytes());
    let outputs = [
        (
            root.join("docs").join("spec").join("INDEX.md"),
            render_spec_index(&model, &digest),
        ),
        (
            root.join("INDEX.md"),
            render_root_index(&model, &ord, &states),
        ),
    ];
    for (path, content) in outputs {
        if check_only {
            match read_text(&path) {
                Ok(cur) if cur == content => {}
                Ok(_) => findings.push(Finding::new(
                    "tasks",
                    rel(root, &path),
                    "is stale; run `cargo xtask tasks index`",
                )),
                Err(e) => findings.push(Finding::new("tasks", rel(root, &path), e.0)),
            }
        } else {
            write_text(&path, &content)?;
            println!("tasks index: wrote {}", rel(root, &path));
        }
    }
    Ok(findings)
}

/// `tasks check`: model cross-checks, index freshness, per-task files, STATUS rows.
pub fn check(root: &Path) -> Vec<Finding> {
    let mut findings = match index(root, true) {
        Ok(f) => f,
        Err(e) => return vec![Finding::new("tasks", "docs/SPEC.md", e.0)],
    };
    let text = match spec::load_master(root) {
        Ok(t) => t,
        Err(e) => return vec![Finding::new("tasks", "docs/SPEC.md", e.0)],
    };
    let Ok(model) = parse(&text) else {
        return findings;
    };
    for t in &model.tasks {
        let path = root
            .join("docs")
            .join("tasks")
            .join(&t.phase)
            .join(format!("{}.md", t.id));
        match read_text(&path) {
            Ok(body) => {
                if !body.contains(&t.block) {
                    findings.push(Finding::new(
                        "tasks",
                        rel(root, &path),
                        "verbatim specification block differs from docs/SPEC.md",
                    ));
                }
            }
            Err(_) => findings.push(Finding::new("tasks", rel(root, &path), "missing")),
        }
    }
    match status_states(root, &model) {
        Ok(states) => {
            if states.len() != model.tasks.len() {
                findings.push(Finding::new(
                    "tasks",
                    "STATUS.md",
                    format!(
                        "task table has {} rows (expected {})",
                        states.len(),
                        model.tasks.len()
                    ),
                ));
            }
            for (id, s) in &states {
                if !state_is_valid(s) {
                    findings.push(Finding::new(
                        "tasks",
                        "STATUS.md",
                        format!("{id}: invalid state {s:?}"),
                    ));
                }
            }
        }
        Err(e) => findings.push(Finding::new("tasks", "STATUS.md", e.0)),
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny() -> Model {
        let mk = |id: &str, phase: &str, deps: &[&str]| Task {
            id: id.into(),
            title: format!("title {id}"),
            phase: phase.into(),
            tags: vec![],
            deps: deps.iter().map(|d| (*d).to_owned()).collect(),
            size: "S".into(),
            owner: "infra".into(),
            block: String::new(),
            spec_line: 1,
            seg: phase.into(),
            seg_line: 1,
        };
        Model {
            tasks: vec![
                mk("T-0001", "P00", &[]),
                mk("T-0002", "P00", &["T-0004"]),
                mk("T-0003", "P01", &["T-0001"]),
                mk("T-0004", "P01", &[]),
            ],
            phases: vec![
                Phase {
                    id: "P00".into(),
                    name: "a".into(),
                    first: "T-0001".into(),
                    last: "T-0002".into(),
                    milestone: "M0".into(),
                    gate: "G00".into(),
                    prefix: "GOV".into(),
                },
                Phase {
                    id: "P01".into(),
                    name: "b".into(),
                    first: "T-0003".into(),
                    last: "T-0004".into(),
                    milestone: "M1".into(),
                    gate: "G01".into(),
                    prefix: "UXR".into(),
                },
            ],
            slices: vec![],
            e14: BTreeMap::new(),
        }
    }

    #[test]
    fn order_is_stable_topological_and_later_numbers_may_run_first() {
        let ord = order(&tiny()).expect("order");
        assert_eq!(ord, vec!["T-0001", "T-0003", "T-0004", "T-0002"]);
    }

    #[test]
    fn cycle_is_an_error() {
        let mut m = tiny();
        m.tasks[3].deps = vec!["T-0002".into()]; // T-0002 -> T-0004 -> T-0002
        assert!(order(&m).is_err());
    }

    #[test]
    fn unknown_dependency_is_an_error() {
        let mut m = tiny();
        m.tasks[0].deps = vec!["T-9999".into()];
        assert!(order(&m).is_err());
    }

    #[test]
    fn req_ids_follow_phase_prefix_and_position() {
        let ids = req_ids(&tiny());
        assert_eq!(ids.get("T-0001").map(String::as_str), Some("REQ-GOV-01"));
        assert_eq!(ids.get("T-0002").map(String::as_str), Some("REQ-GOV-02"));
        assert_eq!(ids.get("T-0003").map(String::as_str), Some("REQ-UXR-01"));
        assert_eq!(ids.get("T-0004").map(String::as_str), Some("REQ-UXR-02"));
    }

    #[test]
    fn closure_includes_roots_and_transitive_deps() {
        let cl = closure(&tiny(), &["T-0002".to_owned()]);
        assert_eq!(cl.into_iter().collect::<Vec<_>>(), vec!["T-0002", "T-0004"]);
    }

    #[test]
    fn parse_small_spec_fixture() {
        let spec = "<!-- PART:A0 -->\n# t\n<!-- PHASE:P00 -->\n## PHASE P00: Boot (T-0001 to T-0002) · milestone M0 · gate G00\n\nRequirement prefix `GOV`. Goal.\n\n### T-0001 · First\n`P00` `[DOC][OPS]` · deps: none · size: S · owner: docs\n**Objective.** x\n\n---\n\n### T-0002 · Second\n`P00` `[SEC]` · deps: T-0001 · size: M · owner: sec\n**Objective.** y\n";
        let m = parse(spec).expect("parse");
        assert_eq!(m.tasks.len(), 2);
        assert_eq!(m.tasks[0].tags, vec!["DOC", "OPS"]);
        assert_eq!(m.tasks[1].deps, vec!["T-0001"]);
        assert_eq!(
            m.tasks[0].block,
            "### T-0001 · First\n`P00` `[DOC][OPS]` · deps: none · size: S · owner: docs\n**Objective.** x"
        );
        assert_eq!(m.tasks[0].seg, "P00");
        assert_eq!(m.tasks[0].seg_line, 6); // heading is the 6th line of the P00 segment
        assert_eq!(m.phases[0].prefix, "GOV");
        assert_eq!(
            req_ids(&m).get("T-0002").map(String::as_str),
            Some("REQ-GOV-02")
        );
    }

    #[test]
    fn state_validation() {
        assert!(state_is_valid("todo"));
        assert!(state_is_valid("blocked(operator)"));
        assert!(state_is_valid("deferred(x, 2d)"));
        assert!(!state_is_valid("finished"));
    }
}
