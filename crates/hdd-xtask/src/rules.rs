//! Source and repository grep rules enforced by `cargo xtask verify`:
//! R-01 placeholders, R-22 one egress path (T-0009 step 7), `forbid(unsafe_code)` per crate (T-0004 A5),
//! and the `AGENTS.md` size cap (T-0002 A1).
//!
//! Test code is exempt by location: any file under a `tests`, `benches` or `fuzz` directory, and everything after the
//! first `#[cfg(test)]` line of a source file (convention: the test module closes the file).

use std::path::Path;

use serde::Deserialize;

use crate::util::{Finding, Result, glob_match, read_text, rel, walk_files};

/// Crates allowed to contain `unsafe` (and therefore not to forbid it).
pub const UNSAFE_ALLOWED_CRATES: &[&str] = &["hdd-xdp-ebpf"];
/// Path of the only module allowed to open outbound connections (R-22).
pub const EGRESS_MODULE: &str = "crates/hdd-common/src/egress/";
/// Forbidden outbound-connection constructs outside the egress module.
/// (Spelled with `concat!` so that this file does not contain the literal constructs it forbids.)
pub const EGRESS_PATTERNS: &[&str] = &[
    concat!("reqwest::Client", "::new"),
    concat!("reqwest::Client", "::builder"),
    concat!("reqwest::Client", "Builder"),
    concat!("hyper::", "Client"),
    concat!("hyper_util::client::legacy::", "Client"),
    concat!("TcpStream", "::connect"),
];
/// Maximum number of lines of `AGENTS.md` (T-0002 A1).
pub const AGENTS_MAX_LINES: usize = 150;

/// Configuration of the exceptions (`docs/lint-rules.toml`).
#[derive(Debug, Deserialize, Default, Clone)]
pub struct Config {
    /// Listed exceptions to the egress grep rule.
    #[serde(default)]
    pub egress_exception: Vec<Exception>,
}

/// One listed exception.
#[derive(Debug, Deserialize, Clone)]
pub struct Exception {
    /// Path glob.
    pub path: String,
    /// Why this code may open sockets itself (documentation field; reviewed by humans, not by code).
    #[allow(
        dead_code,
        reason = "documentation field required in docs/lint-rules.toml"
    )]
    pub reason: String,
}

/// Load `docs/lint-rules.toml` (absent means no exceptions).
pub fn load_config(root: &Path) -> Result<Config> {
    let p = root.join("docs").join("lint-rules.toml");
    if !p.is_file() {
        return Ok(Config::default());
    }
    Ok(toml::from_str(&read_text(&p)?)?)
}

pub fn is_test_path(relpath: &str) -> bool {
    relpath
        .split('/')
        .any(|seg| matches!(seg, "tests" | "benches" | "fuzz" | "lab"))
}

/// Text of a source file up to its test module.
pub fn non_test_part(text: &str) -> &str {
    // the marker must be a line of its own: a mention inside a comment or a string must not hide the rest of the file
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        if line.trim() == "#[cfg(test)]" {
            return text.get(..offset).unwrap_or(text);
        }
        offset += line.len();
    }
    text
}

fn is_comment_or_doc(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//")
}

/// Scan one Rust source file for R-01 and R-22 violations.
pub fn scan_rust(cfg: &Config, relpath: &str, text: &str) -> Vec<Finding> {
    let mut f = Vec::new();
    if is_test_path(relpath) {
        return f;
    }
    let body = non_test_part(text);
    let in_egress = relpath.starts_with(EGRESS_MODULE);
    let excepted = cfg
        .egress_exception
        .iter()
        .any(|e| glob_match(&e.path, relpath));
    for (n, line) in body.lines().enumerate() {
        let loc = format!("{relpath}:{}", n + 1);
        let t = line.trim_start();
        if t.starts_with(concat!("// ", "TODO"))
            || t.starts_with(concat!("//", "TODO"))
            || t.starts_with(concat!("// ", "FIXME"))
        {
            f.push(Finding::new(
                "rules",
                &loc,
                "R-01: `// TODO`/`// FIXME` comment (no placeholders)",
            ));
        }
        if is_comment_or_doc(line) {
            continue;
        }
        for mac in [concat!("todo", "!("), concat!("unimplemented", "!(")] {
            if line.contains(mac) {
                f.push(Finding::new(
                    "rules",
                    &loc,
                    format!("R-01: `{mac})` is forbidden"),
                ));
            }
        }
        if !in_egress && !excepted {
            for p in EGRESS_PATTERNS {
                if line.contains(p) {
                    f.push(Finding::new("rules", &loc, format!("R-22: `{p}` outside hdd-common::egress (add a listed exception in docs/lint-rules.toml with a reason, or use the egress client)")));
                }
            }
        }
    }
    f
}

/// Check that a crate root forbids unsafe code.
pub fn check_forbid_unsafe(crate_name: &str, root_files: &[(String, String)]) -> Vec<Finding> {
    if UNSAFE_ALLOWED_CRATES.contains(&crate_name) {
        return vec![];
    }
    let mut f = Vec::new();
    for (path, text) in root_files {
        if !text.contains("#![forbid(unsafe_code)]") {
            f.push(Finding::new(
                "rules",
                path,
                "crate root lacks `#![forbid(unsafe_code)]` (T-0004 A5)",
            ));
        }
    }
    f
}

/// R-01 placeholders, R-22 egress path and the `AGENTS.md` size cap over the repository.
pub fn check(root: &Path) -> Vec<Finding> {
    let cfg = match load_config(root) {
        Ok(c) => c,
        Err(e) => return vec![Finding::new("rules", "docs/lint-rules.toml", e.0)],
    };
    let mut f = Vec::new();
    for path in walk_files(root) {
        let r = rel(root, &path);
        if r.ends_with(".rs")
            && let Ok(text) = read_text(&path)
        {
            f.extend(scan_rust(&cfg, &r, &text));
        }
    }
    f.extend(check_repo_state(root));
    f.extend(check_stride_tests(root));
    f.extend(check_first_response(root));
    match read_text(&root.join("AGENTS.md")) {
        Ok(t) if t.lines().count() <= AGENTS_MAX_LINES => {}
        Ok(t) => f.push(Finding::new(
            "rules",
            "AGENTS.md",
            format!(
                "{} lines exceeds the {AGENTS_MAX_LINES}-line cap (T-0002 A1)",
                t.lines().count()
            ),
        )),
        Err(e) => f.push(Finding::new("rules", "AGENTS.md", e.0)),
    }
    f
}

/// Every backticked test name in the last column of the tables of `docs/STRIDE.md` must exist as a Rust `fn` in the repository
/// (a claim that cites a test must cite a test that exists, section 0.7 `[DOC]`).
pub fn check_stride_tests(root: &Path) -> Vec<Finding> {
    let Ok(stride) = read_text(&root.join("docs").join("STRIDE.md")) else {
        return vec![];
    };
    let (Ok(fn_re), Ok(tick_re)) = (
        regex::Regex::new(r"\bfn\s+([A-Za-z0-9_]+)\s*[(<]"),
        regex::Regex::new(r"`([A-Za-z0-9_]+)`"),
    ) else {
        return vec![];
    };
    let mut known = std::collections::BTreeSet::new();
    for path in walk_files(root) {
        if path.extension().is_some_and(|e| e == "rs")
            && let Ok(text) = read_text(&path)
        {
            for c in fn_re.captures_iter(&text) {
                known.insert(c[1].to_owned());
            }
        }
    }
    let mut f = Vec::new();
    for (n, line) in stride.lines().enumerate() {
        if !line.starts_with("| ") || line.starts_with("| STRIDE") || line.starts_with("| ---") {
            continue;
        }
        let cells: Vec<&str> = line.trim_end_matches('|').split(" | ").collect();
        if cells.len() < 4 {
            continue;
        }
        let last = cells.last().copied().unwrap_or("");
        for t in tick_re.captures_iter(last) {
            let name = &t[1];
            if name.contains('_') && !known.contains(name) {
                f.push(Finding::new(
                    "rules",
                    format!("docs/STRIDE.md:{}", n + 1),
                    format!("cites test `{name}`, which does not exist"),
                ));
            }
        }
    }
    f
}

/// The first response (T-0007, section 9): exactly the six numbered items, no code beyond the one pasted output block, every
/// question of the register present with its blocked-task list, and every question classified with a level (A1 to A4).
pub fn check_first_response(root: &Path) -> Vec<Finding> {
    let Ok(text) = read_text(&root.join("docs").join("FIRST-RESPONSE.md")) else {
        return vec![Finding::new("rules", "docs/FIRST-RESPONSE.md", "missing")];
    };
    let mut f = Vec::new();
    let loc = "docs/FIRST-RESPONSE.md";
    let heads: Vec<&str> = text.lines().filter(|l| l.starts_with("## ")).collect();
    let numbered: Vec<char> = heads
        .iter()
        .filter_map(|h| h.strip_prefix("## ")?.chars().next())
        .collect();
    if heads.len() != 6 || numbered != ['1', '2', '3', '4', '5', '6'] {
        f.push(Finding::new(
            "rules",
            loc,
            format!(
                "expected exactly the six items of section 9 as `## 1.` to `## 6.`, found {heads:?}"
            ),
        ));
    }
    let fences: Vec<&str> = text.lines().filter(|l| l.starts_with("```")).collect();
    if fences != ["```text", "```"] {
        f.push(Finding::new(
            "rules",
            loc,
            "the only fenced block allowed is the pasted program output (```text)",
        ));
    }
    let register = read_text(&root.join("docs").join("OPERATOR-QUESTIONS.md")).unwrap_or_default();
    let (before, after) = register
        .split_once("## Blocking level of each question")
        .unwrap_or((register.as_str(), ""));
    let ids: Vec<String> = before
        .lines()
        .filter_map(|l| {
            l.strip_prefix("| ")?
                .split(' ')
                .next()
                .filter(|i| i.starts_with("Q-"))
                .map(str::to_owned)
        })
        .collect();
    if ids.len() != 58 {
        f.push(Finding::new(
            "rules",
            "docs/OPERATOR-QUESTIONS.md",
            format!("{} questions in the register (expected 58)", ids.len()),
        ));
    }
    for id in &ids {
        let line = text.lines().find(|l| l.starts_with(&format!("- **{id}**")));
        match line {
            None => f.push(Finding::new("rules", loc, format!("{id} is not asked"))),
            Some(l) if !l.contains("[tasks ") || !l.contains("Blocks (") => f.push(Finding::new(
                "rules",
                loc,
                format!("{id} lacks its level or blocked-task list (A2, A4)"),
            )),
            Some(_) => {}
        }
        if !after.contains(&format!("| {id} | ")) {
            f.push(Finding::new(
                "rules",
                "docs/OPERATOR-QUESTIONS.md",
                format!("{id} has no blocking level"),
            ));
        }
    }
    if !text.contains("| Unanswered or missing | Blocks |") {
        f.push(Finding::new(
            "rules",
            loc,
            "the table of blocking dependencies is missing (A3)",
        ));
    }
    for (needle, why) in [("pilot", "pilot"), ("cutover", "cutover")] {
        if !after.contains(&format!("| {needle}")) {
            f.push(Finding::new(
                "rules",
                "docs/OPERATOR-QUESTIONS.md",
                format!("no question is classified `{why}` (A4)"),
            ));
        }
    }
    f
}

/// State files every session starts from (T-0002).
pub const REQUIRED_STATE_FILES: &[&str] = &[
    "AGENTS.md",
    "STATUS.md",
    "HANDOFF.md",
    "docs/DEVIATIONS.md",
    "docs/SPEC.md",
    "docs/SPEC.sha256",
];
/// Ignore patterns that keep secrets and evidence out of git (T-0002 A4).
pub const REQUIRED_IGNORES: &[&str] = &[
    "hdd.live.yaml",
    "secrets/",
    "*.pem",
    ".env",
    "acceptance-*/",
    "target/",
];

/// The state files exist and `.gitignore` carries the required patterns.
pub fn check_repo_state(root: &Path) -> Vec<Finding> {
    let mut f = Vec::new();
    for name in REQUIRED_STATE_FILES {
        if !root.join(name).is_file() {
            f.push(Finding::new(
                "rules",
                *name,
                "required state file is missing (T-0002)",
            ));
        }
    }
    let ignore = read_text(&root.join(".gitignore")).unwrap_or_default();
    let lines: Vec<&str> = ignore.lines().map(str::trim).collect();
    for pat in REQUIRED_IGNORES {
        if !lines.contains(pat) {
            f.push(Finding::new(
                "rules",
                ".gitignore",
                format!("pattern `{pat}` is missing (T-0002 A4)"),
            ));
        }
    }
    f
}

/// No shipped (default-member) package may reach `hdd-vulnlab` through normal or build dependencies (T-0004 A4, section 2.8).
/// `metadata_json` is the output of `cargo metadata --format-version 1`.
pub fn check_vulnlab_graph(metadata_json: &str) -> Vec<Finding> {
    use std::collections::{BTreeMap, BTreeSet};
    let Ok(v) = serde_json::from_str::<serde_json::Value>(metadata_json) else {
        return vec![Finding::new(
            "rules",
            "cargo metadata",
            "output is not JSON",
        )];
    };
    let names: BTreeMap<&str, &str> = v
        .get("packages")
        .and_then(|p| p.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|p| Some((p.get("id")?.as_str()?, p.get("name")?.as_str()?)))
                .collect()
        })
        .unwrap_or_default();
    let mut edges: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    if let Some(nodes) = v.pointer("/resolve/nodes").and_then(|n| n.as_array()) {
        for n in nodes {
            let Some(id) = n.get("id").and_then(|i| i.as_str()) else {
                continue;
            };
            let deps = n
                .get("deps")
                .and_then(|d| d.as_array())
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            for d in deps {
                let shipped = d
                    .get("dep_kinds")
                    .and_then(|k| k.as_array())
                    .is_some_and(|ks| {
                        ks.iter().any(|k| {
                            k.get("kind")
                                .is_none_or(|x| x.is_null() || x.as_str() == Some("build"))
                        })
                    });
                if shipped && let Some(pkg) = d.get("pkg").and_then(|p| p.as_str()) {
                    edges.entry(id).or_default().push(pkg);
                }
            }
        }
    }
    let defaults: Vec<&str> = v
        .get("workspace_default_members")
        .and_then(|m| m.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    let mut f = Vec::new();
    if defaults.is_empty() {
        f.push(Finding::new(
            "rules",
            "cargo metadata",
            "no default members found",
        ));
    }
    for start in defaults {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut stack = vec![start];
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur) {
                continue;
            }
            if names.get(cur) == Some(&"hdd-vulnlab") {
                f.push(Finding::new(
                    "rules",
                    names.get(start).copied().unwrap_or(start),
                    "reaches hdd-vulnlab through its dependency graph (section 2.8, T-0004 A4)",
                ));
                break;
            }
            stack.extend(
                edges
                    .get(cur)
                    .map(Vec::as_slice)
                    .unwrap_or(&[])
                    .iter()
                    .copied(),
            );
        }
    }
    f
}

/// Run `cargo metadata` and apply [`check_vulnlab_graph`].
pub fn check_vulnlab(root: &Path) -> Vec<Finding> {
    match std::process::Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(root)
        .output()
    {
        Ok(o) if o.status.success() => check_vulnlab_graph(&String::from_utf8_lossy(&o.stdout)),
        Ok(o) => vec![Finding::new(
            "rules",
            "cargo metadata",
            String::from_utf8_lossy(&o.stderr)
                .lines()
                .last()
                .unwrap_or("failed")
                .to_owned(),
        )],
        Err(e) => vec![Finding::new(
            "rules",
            "cargo metadata",
            format!("cannot run cargo: {e}"),
        )],
    }
}

/// `forbid(unsafe_code)` at every crate root of the workspace crates and the Vuln-Lab, and inherited workspace lints
/// (the first-party substitute for `cargo geiger`, whose viability is ADR-0018).
pub fn check_unsafe(root: &Path) -> Vec<Finding> {
    let mut f = Vec::new();
    let mut crate_dirs: Vec<(String, std::path::PathBuf)> = Vec::new();
    for base in ["crates", "lab"] {
        if let Ok(rd) = std::fs::read_dir(root.join(base)) {
            for e in rd.flatten() {
                let p = e.path();
                if p.join("Cargo.toml").is_file() {
                    crate_dirs.push((e.file_name().to_string_lossy().into_owned(), p));
                }
            }
        }
    }
    crate_dirs.sort();
    for (name, dir) in crate_dirs {
        let mut roots = Vec::new();
        for cand in ["src/lib.rs", "src/main.rs"] {
            let p = dir.join(cand);
            if let Ok(t) = read_text(&p) {
                roots.push((rel(root, &p), t));
            }
        }
        let bin_dir = dir.join("src").join("bin");
        for p in walk_files(&bin_dir) {
            if p.extension().is_some_and(|e| e == "rs")
                && let Ok(t) = read_text(&p)
            {
                roots.push((rel(root, &p), t));
            }
        }
        f.extend(check_forbid_unsafe(&name, &roots));
        if !UNSAFE_ALLOWED_CRATES.contains(&name.as_str()) {
            let manifest = read_text(&dir.join("Cargo.toml")).unwrap_or_default();
            let has_ws_lints =
                manifest.contains("[lints]") && manifest.contains("workspace = true");
            if !has_ws_lints {
                f.push(Finding::new(
                    "rules",
                    rel(root, &dir.join("Cargo.toml")),
                    "crate does not inherit [workspace.lints] (`[lints] workspace = true`)",
                ));
            }
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config {
            egress_exception: vec![Exception {
                path: "crates/hdd-acceptance/src/raw.rs".into(),
                reason: "raw sockets".into(),
            }],
        }
    }

    #[test]
    fn egress_patterns_outside_the_module_are_flagged() {
        let src = "fn f() { let c = reqwest::Client::new(); let s = std::net::TcpStream::connect(\"a:1\"); }\n";
        let f = scan_rust(&cfg(), "crates/hdd-web/src/x.rs", src);
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(f.iter().all(|x| x.message.starts_with("R-22")));
    }

    #[test]
    fn the_egress_module_tests_and_listed_exceptions_are_exempt() {
        let src = "fn f() { std::net::TcpStream::connect(\"a:1\"); }\n";
        assert!(scan_rust(&cfg(), "crates/hdd-common/src/egress/client.rs", src).is_empty());
        assert!(scan_rust(&cfg(), "crates/hdd-web/tests/it.rs", src).is_empty());
        assert!(scan_rust(&cfg(), "crates/hdd-acceptance/src/raw.rs", src).is_empty());
        let with_tests = format!("fn ok() {{}}\n#[cfg(test)]\nmod tests {{ {src} }}\n");
        assert!(scan_rust(&cfg(), "crates/hdd-web/src/y.rs", &with_tests).is_empty());
    }

    #[test]
    fn comments_may_mention_the_patterns() {
        assert!(
            scan_rust(
                &cfg(),
                "crates/a/src/lib.rs",
                "// never call TcpStream::connect here\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn placeholders_are_flagged() {
        let f = scan_rust(
            &cfg(),
            "crates/a/src/lib.rs",
            "fn a() { todo!(); }\n// TODO later\nfn b() { unimplemented!() }\n",
        );
        assert_eq!(f.len(), 3, "{f:?}");
    }

    #[test]
    fn unsafe_code_is_a_compile_error_under_the_workspace_lints() {
        // the equivalent of a trybuild compile-fail test (T-0004 test) without another dependency: compile an `unsafe` block
        // under the same lint level the workspace sets, and require the compiler to refuse it
        let dir = std::env::temp_dir().join(format!("hdd-xtask-unsafe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let src = dir.join("lib.rs");
        std::fs::write(
            &src,
            "pub fn f() -> u8 {
    unsafe { 1 }
}
",
        )
        .expect("write");
        let out = std::process::Command::new("rustc")
            .args([
                "--edition",
                "2024",
                "--crate-type",
                "lib",
                "--emit=metadata",
                "-F",
                "unsafe_code",
                "--out-dir",
            ])
            .arg(&dir)
            .arg(&src)
            .output()
            .expect("rustc runs");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "unsafe must not compile: {stderr}");
        assert!(stderr.contains("usage of an `unsafe` block"), "{stderr}");
        // and the workspace really sets that level
        let manifest = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("Cargo.toml"),
        )
        .expect("workspace manifest");
        assert!(manifest.contains("unsafe_code = \"forbid\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn repo_state_requires_state_files_and_ignore_patterns() {
        let dir = std::env::temp_dir().join(format!("hdd-xtask-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("docs")).expect("mkdir");
        let empty = check_repo_state(&dir);
        assert!(empty.iter().any(|x| x.location == "AGENTS.md"), "{empty:?}");
        assert!(
            empty.iter().any(|x| x.message.contains("`hdd.live.yaml`")),
            "{empty:?}"
        );
        for n in REQUIRED_STATE_FILES {
            std::fs::write(dir.join(n), "x\n").expect("write");
        }
        std::fs::write(dir.join(".gitignore"), REQUIRED_IGNORES.join("\n")).expect("write");
        assert!(check_repo_state(&dir).is_empty());
        std::fs::write(dir.join(".gitignore"), "target/\n").expect("write");
        assert_eq!(check_repo_state(&dir).len(), REQUIRED_IGNORES.len() - 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stride_cites_only_tests_that_exist() {
        let dir = std::env::temp_dir().join(format!("hdd-xtask-stride-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("docs")).expect("mkdir");
        std::fs::create_dir_all(dir.join("crates")).expect("mkdir");
        std::fs::write(
            dir.join("crates").join("t.rs"),
            "#[test]
fn real_test_name() {}
",
        )
        .expect("write");
        std::fs::write(
            dir.join("docs").join("STRIDE.md"),
            "| STRIDE | Threat | Mitigation | Test |
| --- | --- | --- | --- |
| Spoofing | x | uses `deny_unknown_fields` | `real_test_name`, `made_up_test_name` |
| Tampering | y | z | n/a |
",
        )
        .expect("write");
        let f = check_stride_tests(&dir);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].message.contains("made_up_test_name"));
        assert_eq!(f[0].location, "docs/STRIDE.md:3");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_shipped_first_response_satisfies_its_acceptance_checks() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..");
        assert!(
            check_first_response(&root).is_empty(),
            "{:?}",
            check_first_response(&root)
        );
    }

    #[test]
    fn a_first_response_with_a_missing_question_or_an_extra_section_fails() {
        let dir = std::env::temp_dir().join(format!("hdd-xtask-firstresp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("docs")).expect("mkdir");
        std::fs::write(
            dir.join("docs").join("OPERATOR-QUESTIONS.md"),
            "| Id | x |
| Q-001 | a | b | c | d | e | f | g |
",
        )
        .expect("write");
        std::fs::write(
            dir.join("docs").join("FIRST-RESPONSE.md"),
            "## 1. a
## 2. b
## 3. c
## 4. d
## 5. e
## 6. f
## 7. extra
```
code
```
",
        )
        .expect("write");
        let msgs: Vec<String> = check_first_response(&dir)
            .into_iter()
            .map(|x| x.message)
            .collect();
        assert!(msgs.iter().any(|m| m.contains("six items")), "{msgs:?}");
        assert!(
            msgs.iter().any(|m| m.contains("only fenced block")),
            "{msgs:?}"
        );
        assert!(msgs.iter().any(|m| m.contains("58")), "{msgs:?}");
        assert!(
            msgs.iter().any(|m| m.contains("Q-001 is not asked")),
            "{msgs:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn agents_md_over_the_cap_is_a_finding() {
        let dir = std::env::temp_dir().join(format!("hdd-xtask-agents-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("AGENTS.md"), "line\n".repeat(AGENTS_MAX_LINES + 1))
            .expect("write");
        assert!(
            check(&dir)
                .iter()
                .any(|x| x.location == "AGENTS.md" && x.message.contains("exceeds"))
        );
        std::fs::write(dir.join("AGENTS.md"), "line\n".repeat(AGENTS_MAX_LINES)).expect("write");
        assert!(
            !check(&dir)
                .iter()
                .any(|x| x.location == "AGENTS.md" && x.message.contains("exceeds"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn metadata(edge_to_vulnlab: bool) -> String {
        let shipped_dep = r#"{"pkg":"vulnlab 0.0.0","dep_kinds":[{"kind":null,"target":null}]}"#;
        let dev_dep = r#"{"pkg":"vulnlab 0.0.0","dep_kinds":[{"kind":"dev","target":null}]}"#;
        let dep = if edge_to_vulnlab {
            shipped_dep
        } else {
            dev_dep
        };
        format!(
            r#"{{"packages":[{{"id":"proxy 0.0.0","name":"hdd-proxy"}},{{"id":"mid 0.0.0","name":"hdd-common"}},{{"id":"vulnlab 0.0.0","name":"hdd-vulnlab"}}],
                 "workspace_default_members":["proxy 0.0.0"],
                 "resolve":{{"nodes":[{{"id":"proxy 0.0.0","deps":[{{"pkg":"mid 0.0.0","dep_kinds":[{{"kind":null,"target":null}}]}}]}},
                                      {{"id":"mid 0.0.0","deps":[{dep}]}},{{"id":"vulnlab 0.0.0","deps":[]}}]}}}}"#
        )
    }

    #[test]
    fn a_shipped_binary_reaching_the_vuln_lab_is_a_finding_but_a_dev_dependency_is_not() {
        let bad = check_vulnlab_graph(&metadata(true));
        assert_eq!(bad.len(), 1, "{bad:?}");
        assert_eq!(bad[0].location, "hdd-proxy");
        assert!(check_vulnlab_graph(&metadata(false)).is_empty());
        assert_eq!(check_vulnlab_graph("not json").len(), 1);
    }

    #[test]
    fn forbid_unsafe_is_required_except_for_the_ebpf_crate() {
        let ok = [(
            "crates/a/src/lib.rs".to_owned(),
            "#![forbid(unsafe_code)]\n".to_owned(),
        )];
        let bad = [("crates/a/src/lib.rs".to_owned(), "fn x() {}\n".to_owned())];
        assert!(check_forbid_unsafe("a", &ok).is_empty());
        assert_eq!(check_forbid_unsafe("a", &bad).len(), 1);
        assert!(check_forbid_unsafe("hdd-xdp-ebpf", &bad).is_empty());
    }
}
