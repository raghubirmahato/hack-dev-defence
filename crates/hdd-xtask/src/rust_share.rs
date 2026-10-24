//! `rust-share` (DEV-V5-002, T-0005 step 4): Rust must be at least 90% of hand-written programming-language lines.
//!
//! Lines come from `tokei --output json`. Exclusions (generated, vendored, migrations, declarative configuration,
//! documents) are configured in `docs/rust-share.toml`, applied per file, and listed in the report together with
//! the three markup caps (CSS, HTML templates, first-party JavaScript).

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

use crate::util::{Error, Finding, Result, glob_match, read_text};

/// One exclusion rule.
#[derive(Debug, Deserialize, Clone)]
pub struct Exclude {
    /// Path glob (repository-relative).
    pub glob: String,
    /// Category: `generated`, `vendored`, `migrations`, `lab` or `other`.
    pub kind: String,
    /// Why the files are not hand-written first-party code.
    pub reason: String,
}

/// Parsed `docs/rust-share.toml`.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Minimum Rust percentage among programming-language lines.
    pub min_rust_percent: f64,
    /// tokei language names counted as programming languages.
    pub programming: Vec<String>,
    /// tokei language names counted as CSS.
    pub css_languages: Vec<String>,
    /// tokei language names counted as HTML templates.
    pub html_languages: Vec<String>,
    /// tokei language names counted as JavaScript.
    pub js_languages: Vec<String>,
    /// Cap for hand-written CSS lines.
    pub css_cap: u64,
    /// Cap for askama/HTML template lines.
    pub html_cap: u64,
    /// Cap for first-party JavaScript lines.
    pub js_cap: u64,
    /// Exclusion rules.
    #[serde(default)]
    pub exclude: Vec<Exclude>,
}

/// Result of the computation.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// Code lines per programming language after exclusions.
    pub programming: BTreeMap<String, u64>,
    /// Rust code lines.
    pub rust: u64,
    /// Sum of programming-language code lines.
    pub programming_total: u64,
    /// Rust share in percent (100 when there are no programming lines).
    pub percent: f64,
    /// CSS lines.
    pub css: u64,
    /// HTML template lines.
    pub html: u64,
    /// First-party JavaScript lines.
    pub js: u64,
    /// Excluded code lines per exclusion glob (with kind).
    pub excluded: BTreeMap<String, u64>,
    /// Code lines of non-programming languages (documents, configuration), by language.
    pub other_languages: BTreeMap<String, u64>,
}

#[derive(Deserialize)]
struct Stats {
    code: u64,
}

#[derive(Deserialize)]
struct FileReport {
    name: String,
    stats: Stats,
}

#[derive(Deserialize)]
struct Lang {
    #[serde(default)]
    reports: Vec<FileReport>,
}

/// Load the configuration.
pub fn load_config(root: &Path) -> Result<Config> {
    Ok(toml::from_str(&read_text(
        &root.join("docs").join("rust-share.toml"),
    )?)?)
}

/// Compute the report from tokei's JSON output.
pub fn evaluate(cfg: &Config, tokei_json: &str) -> Result<Report> {
    let langs: BTreeMap<String, serde_json::Value> = serde_json::from_str(tokei_json)
        .map_err(|e| Error(format!("cannot parse tokei JSON: {e}")))?;
    let mut rep = Report {
        programming: BTreeMap::new(),
        rust: 0,
        programming_total: 0,
        percent: 100.0,
        css: 0,
        html: 0,
        js: 0,
        excluded: BTreeMap::new(),
        other_languages: BTreeMap::new(),
    };
    for (name, value) in langs {
        if name == "Total" {
            continue;
        }
        let lang: Lang =
            serde_json::from_value(value).map_err(|e| Error(format!("tokei entry {name}: {e}")))?;
        for r in lang.reports {
            let path = r.name.replace('\\', "/");
            let path = path.strip_prefix("./").unwrap_or(&path).to_owned();
            if let Some(ex) = cfg.exclude.iter().find(|e| glob_match(&e.glob, &path)) {
                *rep.excluded
                    .entry(format!("{} [{}]", ex.glob, ex.kind))
                    .or_insert(0) += r.stats.code;
                continue;
            }
            let code = r.stats.code;
            if cfg.css_languages.contains(&name) {
                rep.css += code;
            }
            if cfg.html_languages.contains(&name) {
                rep.html += code;
            }
            if cfg.js_languages.contains(&name) {
                rep.js += code;
            }
            if cfg.programming.contains(&name) {
                *rep.programming.entry(name.clone()).or_insert(0) += code;
                rep.programming_total += code;
                if name == "Rust" {
                    rep.rust += code;
                }
            } else {
                *rep.other_languages.entry(name.clone()).or_insert(0) += code;
            }
        }
    }
    if rep.programming_total > 0 {
        rep.percent = rep.rust as f64 * 100.0 / rep.programming_total as f64;
    }
    Ok(rep)
}

/// Findings for a report: share below the minimum and exceeded caps.
pub fn findings(cfg: &Config, rep: &Report) -> Vec<Finding> {
    let mut f = Vec::new();
    if rep.percent < cfg.min_rust_percent {
        f.push(Finding::new(
            "rust-share",
            "workspace",
            format!(
                "Rust is {:.2}% of programming lines (minimum {}%)",
                rep.percent, cfg.min_rust_percent
            ),
        ));
    }
    for (label, have, cap) in [
        ("CSS", rep.css, cfg.css_cap),
        ("HTML templates", rep.html, cfg.html_cap),
        ("JavaScript", rep.js, cfg.js_cap),
    ] {
        if have > cap {
            f.push(Finding::new(
                "rust-share",
                "workspace",
                format!("{label}: {have} lines exceeds the cap of {cap}"),
            ));
        }
    }
    f
}

/// Render the table required by T-0005 A5 (exclusion list and the three markup caps).
pub fn render_report(cfg: &Config, rep: &Report) -> String {
    let mut o = String::from(
        "rust-share (DEV-V5-002): hand-written programming-language code lines (tokei)
",
    );
    for (lang, n) in &rep.programming {
        o.push_str(&format!(
            "  {lang:<12} {n:>8}
"
        ));
    }
    o.push_str(&format!(
        "  {:<12} {:>8}  Rust share {:.2}% (minimum {}%)
",
        "total", rep.programming_total, rep.percent, cfg.min_rust_percent
    ));
    o.push_str(
        "declarative markup (reported separately, capped):
",
    );
    o.push_str(&format!(
        "  CSS               {:>8} / {} lines
",
        rep.css, cfg.css_cap
    ));
    o.push_str(&format!(
        "  HTML templates    {:>8} / {} lines
",
        rep.html, cfg.html_cap
    ));
    o.push_str(&format!(
        "  JavaScript        {:>8} / {} lines
",
        rep.js, cfg.js_cap
    ));
    o.push_str(&format!(
        "exclusion list ({} rules; code lines excluded):
",
        cfg.exclude.len()
    ));
    for e in &cfg.exclude {
        let key = format!("{} [{}]", e.glob, e.kind);
        o.push_str(&format!(
            "  {:<44} {:>7}  {}
",
            key,
            rep.excluded.get(&key).copied().unwrap_or(0),
            e.reason
        ));
    }
    o.push_str(
        "non-programming languages (documents and configuration, excluded by definition):
",
    );
    for (lang, n) in &rep.other_languages {
        o.push_str(&format!(
            "  {lang:<12} {n:>8}
"
        ));
    }
    o
}

/// Outcome of running the check.
pub enum Outcome {
    /// tokei ran; findings may be empty. The string is the rendered report.
    Ran(Vec<Finding>, String),
    /// tokei is not installed: UNVERIFIED(`tool_unavailable`).
    Unverified(String),
}

/// Run tokei in `root` and evaluate.
pub fn run(root: &Path) -> Result<Outcome> {
    let cfg = load_config(root)?;
    let out = match Command::new("tokei")
        .arg("--output")
        .arg("json")
        .arg("--exclude")
        .arg("target")
        .arg(".")
        .current_dir(root)
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return Ok(Outcome::Unverified(format!(
                "tokei cannot be started ({e}); install it with `cargo install --locked tokei`"
            )));
        }
    };
    if !out.status.success() {
        return Err(Error(format!(
            "tokei failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let json = String::from_utf8_lossy(&out.stdout).into_owned();
    let rep = evaluate(&cfg, &json)?;
    let text = render_report(&cfg, &rep);
    let f = findings(&cfg, &rep);
    Ok(Outcome::Ran(f, text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config {
            min_rust_percent: 90.0,
            programming: vec![
                "Rust".into(),
                "JavaScript".into(),
                "SQL".into(),
                "Shell".into(),
            ],
            css_languages: vec!["CSS".into()],
            html_languages: vec!["HTML".into()],
            js_languages: vec!["JavaScript".into()],
            css_cap: 12_000,
            html_cap: 40_000,
            js_cap: 3_000,
            exclude: vec![
                Exclude {
                    glob: "migrations/**".into(),
                    kind: "migrations".into(),
                    reason: "schema SQL".into(),
                },
                Exclude {
                    glob: "**/vendor/**".into(),
                    kind: "vendored".into(),
                    reason: "vendored".into(),
                },
            ],
        }
    }

    fn json(rust: u64, js: u64, sql_mig: u64, js_vendor: u64, css: u64) -> String {
        format!(
            r#"{{"Rust":{{"reports":[{{"name":".\\crates\\a\\src\\lib.rs","stats":{{"code":{rust}}}}}]}},
                "JavaScript":{{"reports":[{{"name":"./web/app.js","stats":{{"code":{js}}}}},{{"name":"./web/vendor/htmx.js","stats":{{"code":{js_vendor}}}}}]}},
                "SQL":{{"reports":[{{"name":"./migrations/0001.sql","stats":{{"code":{sql_mig}}}}}]}},
                "CSS":{{"reports":[{{"name":"./web/a.css","stats":{{"code":{css}}}}}]}},
                "Markdown":{{"reports":[{{"name":"./README.md","stats":{{"code":500}}}}]}},
                "Total":{{"code":1}}}}"#
        )
    }

    #[test]
    fn exclusions_are_applied_and_listed() {
        let rep = evaluate(&cfg(), &json(950, 50, 400, 9000, 10)).expect("evaluate");
        assert_eq!(rep.rust, 950);
        assert_eq!(rep.programming_total, 1000);
        assert!((rep.percent - 95.0).abs() < 1e-9);
        assert_eq!(rep.excluded.get("migrations/** [migrations]"), Some(&400));
        assert_eq!(rep.excluded.get("**/vendor/** [vendored]"), Some(&9000));
        assert_eq!(rep.other_languages.get("Markdown"), Some(&500));
        assert_eq!(rep.css, 10);
        assert!(findings(&cfg(), &rep).is_empty());
    }

    #[test]
    fn below_ninety_percent_fails() {
        let rep = evaluate(&cfg(), &json(800, 200, 0, 0, 0)).expect("evaluate");
        assert!((rep.percent - 80.0).abs() < 1e-9);
        let f = findings(&cfg(), &rep);
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("80.00%"));
    }

    #[test]
    fn caps_fail_independently_of_the_share() {
        let rep = evaluate(&cfg(), &json(100_000, 3_001, 0, 0, 12_001)).expect("evaluate");
        let msgs: Vec<String> = findings(&cfg(), &rep)
            .into_iter()
            .map(|f| f.message)
            .collect();
        assert_eq!(msgs.len(), 2, "{msgs:?}");
        assert!(msgs.iter().any(|m| m.starts_with("CSS")));
        assert!(msgs.iter().any(|m| m.starts_with("JavaScript")));
    }

    #[test]
    fn empty_tree_is_one_hundred_percent() {
        let rep = evaluate(&cfg(), "{}").expect("evaluate");
        assert!((rep.percent - 100.0).abs() < 1e-9);
    }

    #[test]
    fn invalid_json_is_an_error() {
        assert!(evaluate(&cfg(), "not json").is_err());
    }
}
