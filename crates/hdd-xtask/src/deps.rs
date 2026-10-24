//! Dependency-vetting lint (T-0008 step 5, R-08) and ADR hygiene checks (T-0008 A1, A3, A4, A5).
//!
//! Every external crate declared in a workspace manifest needs an entry in `docs/vetting.toml` recording that it was
//! checked (exists, maintained, licence, MSRV, API fit). A crate that is FFI, has `unsafe` in its public API, or was last
//! released more than a year ago additionally needs an existing ADR that is referenced from its entry.

use std::collections::BTreeSet;
use std::path::Path;

use regex::Regex;
use serde::Deserialize;

use crate::util::{Finding, Result, parse_date_days, read_text, rel, today_days, walk_files};

/// One vetting record.
#[derive(Debug, Deserialize, Clone)]
pub struct Entry {
    /// Crate name as on crates.io.
    pub name: String,
    /// Version resolved from the registry when the entry was written.
    pub version: String,
    /// SPDX licence expression from the registry.
    pub license: String,
    /// `rust-version` from the registry (empty when unspecified).
    #[serde(default)]
    pub msrv: String,
    /// Date of the latest release (`YYYY-MM-DD`) from the registry.
    pub last_release: String,
    /// Date the entry was written.
    pub vetted_on: String,
    /// Why the crate fits (API checked against the need).
    pub note: String,
    /// The crate wraps a C/C++ library or builds native code.
    #[serde(default)]
    pub ffi: bool,
    /// The crate's public API exposes `unsafe`.
    #[serde(default)]
    pub unsafe_api: bool,
    /// ADR number (for example `0002`) required for ffi / unsafe API / unmaintained crates.
    #[serde(default)]
    pub adr: String,
}

/// Parsed `docs/vetting.toml`.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct Vetting {
    /// Crate entries.
    #[serde(default, rename = "crate")]
    pub crates: Vec<Entry>,
}

/// Maximum age of the latest release before the crate counts as unmaintained (R-08).
pub const UNMAINTAINED_DAYS: i64 = 365;

/// Names of the external dependencies declared by a manifest (path dependencies and workspace members are internal).
pub fn external_deps(manifest: &str) -> Result<BTreeSet<String>> {
    let v: toml::Value = toml::from_str(manifest)?;
    let mut out = BTreeSet::new();
    let mut take = |t: &toml::Value| {
        if let Some(tbl) = t.as_table() {
            for (name, spec) in tbl {
                let internal = spec.as_table().is_some_and(|s| s.contains_key("path"));
                let renamed = spec
                    .as_table()
                    .and_then(|s| s.get("package"))
                    .and_then(toml::Value::as_str);
                if !internal {
                    out.insert(renamed.unwrap_or(name).to_owned());
                }
            }
        }
    };
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(t) = v.get(key) {
            take(t);
        }
    }
    if let Some(t) = v.get("workspace").and_then(|w| w.get("dependencies")) {
        take(t);
    }
    if let Some(targets) = v.get("target").and_then(toml::Value::as_table) {
        for cfg in targets.values() {
            for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(t) = cfg.get(key) {
                    take(t);
                }
            }
        }
    }
    Ok(out)
}

/// Parse `1.85` / `1.85.0` into (major, minor).
pub fn parse_msrv(s: &str) -> Option<(u64, u64)> {
    let mut it = s.trim().split('.');
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

/// Core check: `manifests` are (path, content) pairs; `adrs` is the set of ADR numbers that exist as files;
/// `msrv_limit` is the workspace `rust-version` (a crate whose MSRV is higher cannot be used).
pub fn check_manifests(
    manifests: &[(String, String)],
    vetting: &Vetting,
    adrs: &BTreeSet<String>,
    today: i64,
    msrv_limit: (u64, u64),
) -> Vec<Finding> {
    let mut f = Vec::new();
    let mut declared: BTreeSet<String> = BTreeSet::new();
    for (path, content) in manifests {
        match external_deps(content) {
            Ok(names) => {
                for n in names {
                    if !vetting.crates.iter().any(|e| e.name == n) {
                        f.push(Finding::new("deps", path, format!("dependency `{n}` has no vetting entry in docs/vetting.toml and no ADR (R-08)")));
                    }
                    declared.insert(n);
                }
            }
            Err(e) => f.push(Finding::new("deps", path, e.0)),
        }
    }
    for e in &vetting.crates {
        let loc = format!("docs/vetting.toml:{}", e.name);
        for (label, val) in [
            ("version", &e.version),
            ("license", &e.license),
            ("note", &e.note),
        ] {
            if val.trim().is_empty() {
                f.push(Finding::new("deps", &loc, format!("empty `{label}`")));
            }
        }
        let last = parse_date_days(&e.last_release);
        if last.is_none() {
            f.push(Finding::new(
                "deps",
                &loc,
                "`last_release` is not YYYY-MM-DD",
            ));
        }
        if parse_date_days(&e.vetted_on).is_none() {
            f.push(Finding::new("deps", &loc, "`vetted_on` is not YYYY-MM-DD"));
        }
        if !e.msrv.is_empty() {
            match parse_msrv(&e.msrv) {
                Some(m) if m > msrv_limit => {
                    f.push(Finding::new(
                        "deps",
                        &loc,
                        format!(
                            "MSRV {} exceeds the workspace rust-version {}.{}",
                            e.msrv, msrv_limit.0, msrv_limit.1
                        ),
                    ));
                }
                Some(_) => {}
                None => f.push(Finding::new("deps", &loc, "`msrv` is not a version")),
            }
        }
        let unmaintained = last.is_some_and(|d| today - d > UNMAINTAINED_DAYS);
        let needs_adr = e.ffi || e.unsafe_api || unmaintained;
        if needs_adr {
            let why = if e.ffi {
                "FFI"
            } else if e.unsafe_api {
                "unsafe public API"
            } else {
                "last release over a year ago"
            };
            if e.adr.is_empty() {
                f.push(Finding::new(
                    "deps",
                    &loc,
                    format!("{why}: an ADR is required (set `adr`)"),
                ));
            } else if !adrs.contains(&e.adr) {
                f.push(Finding::new(
                    "deps",
                    &loc,
                    format!("{why}: ADR-{} does not exist in docs/adr/", e.adr),
                ));
            }
        }
        if !declared.contains(&e.name) {
            f.push(Finding::new("deps", &loc, "vetting entry for a crate that no manifest declares (remove it or declare the dependency)"));
        }
    }
    f
}

/// Load `docs/vetting.toml` (missing file means no entries).
pub fn load_vetting(root: &Path) -> Result<Vetting> {
    let p = root.join("docs").join("vetting.toml");
    if !p.is_file() {
        return Ok(Vetting::default());
    }
    Ok(toml::from_str(&read_text(&p)?)?)
}

/// ADR numbers present as files (`docs/adr/NNNN-*.md`).
pub fn adr_numbers(root: &Path) -> BTreeSet<String> {
    let re = Regex::new(r"^(\d{4})-.*\.md$");
    let mut out = BTreeSet::new();
    if let Ok(re) = re {
        for f in walk_files(&root.join("docs").join("adr")) {
            let name = f
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if let Some(c) = re.captures(&name) {
                out.insert(c.get(1).map(|m| m.as_str().to_owned()).unwrap_or_default());
            }
        }
    }
    out
}

/// The dependency-vetting lint over the repository.
pub fn check(root: &Path) -> Vec<Finding> {
    let vetting = match load_vetting(root) {
        Ok(v) => v,
        Err(e) => return vec![Finding::new("deps", "docs/vetting.toml", e.0)],
    };
    let mut manifests = Vec::new();
    for f in walk_files(root) {
        if f.file_name().is_some_and(|n| n == "Cargo.toml")
            && let Ok(t) = read_text(&f)
        {
            manifests.push((rel(root, &f), t));
        }
    }
    let limit = read_text(&root.join("Cargo.toml"))
        .ok()
        .and_then(|t| toml::from_str::<toml::Value>(&t).ok())
        .and_then(|v| {
            v.get("workspace")?
                .get("package")?
                .get("rust-version")?
                .as_str()
                .and_then(parse_msrv)
        })
        .unwrap_or((u64::MAX, u64::MAX));
    check_manifests(
        &manifests,
        &vetting,
        &adr_numbers(root),
        today_days(),
        limit,
    )
}

/// ADR hygiene: monotonic contiguous numbers, every ADR in the index, valid status, deciding task named, rollback plan
/// present, and no `accepted` ADR without a spike link or a stated reason.
pub fn check_adrs(root: &Path, task_ids: &BTreeSet<String>) -> Vec<Finding> {
    let mut f = Vec::new();
    let dir = root.join("docs").join("adr");
    let numbers = adr_numbers(root);
    let expected: Vec<String> = (0..numbers.len()).map(|n| format!("{n:04}")).collect();
    if numbers.iter().cloned().collect::<Vec<_>>() != expected {
        f.push(Finding::new(
            "adr",
            "docs/adr",
            "ADR numbers are not monotonic and contiguous from 0000",
        ));
    }
    let index = read_text(&dir.join("INDEX.md")).unwrap_or_default();
    let status_re =
        Regex::new(r"^- Status: \*{0,2}(proposed|spiking|accepted|superseded[^*\n]*)\*{0,2}\s*$");
    let task_re = Regex::new(r"^- Deciding task: \[(T-\d{4})\]");
    let (Ok(status_re), Ok(task_re)) = (status_re, task_re) else {
        return f;
    };
    for f_path in walk_files(&dir) {
        let name = f_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let Some((num, _)) = name.split_once('-') else {
            continue;
        };
        if num.len() != 4 || !num.chars().all(|c| c.is_ascii_digit()) || name == "0000-template.md"
        {
            continue;
        }
        let loc = rel(root, &f_path);
        if !index.contains(&format!("[{num}]({name})")) {
            f.push(Finding::new(
                "adr",
                &loc,
                "not referenced from docs/adr/INDEX.md",
            ));
        }
        let body = read_text(&f_path).unwrap_or_default();
        let status = body.lines().find_map(|l| {
            status_re
                .captures(l)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_owned())
        });
        match status {
            None => f.push(Finding::new("adr", &loc, "no valid `- Status:` line")),
            Some(s) => {
                if s == "accepted" && !(body.contains("Spike:") || body.contains("Reason:")) {
                    f.push(Finding::new(
                        "adr",
                        &loc,
                        "accepted without a `Spike:` link or a stated `Reason:` (T-0008 A5)",
                    ));
                }
            }
        }
        match body.lines().find_map(|l| {
            task_re
                .captures(l)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_owned())
        }) {
            None => f.push(Finding::new(
                "adr",
                &loc,
                "no `- Deciding task:` link (T-0008 A1)",
            )),
            Some(t) => {
                if !task_ids.contains(&t) {
                    f.push(Finding::new(
                        "adr",
                        &loc,
                        format!("deciding task {t} does not exist"),
                    ));
                }
            }
        }
        if !body.contains("## Rollback plan") {
            f.push(Finding::new("adr", &loc, "no `## Rollback plan` section"));
        }
    }
    match read_text(&dir.join("0000-template.md")) {
        Ok(t) if t.contains("## Rollback plan") => {}
        _ => f.push(Finding::new(
            "adr",
            "docs/adr/0000-template.md",
            "template lacks the rollback plan field (T-0008 A3)",
        )),
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, last: &str, ffi: bool, adr: &str) -> Entry {
        Entry {
            name: name.into(),
            version: "1.0.0".into(),
            license: "MIT".into(),
            msrv: "1.70".into(),
            last_release: last.into(),
            vetted_on: "2026-10-18".into(),
            note: "fits".into(),
            ffi,
            unsafe_api: false,
            adr: adr.into(),
        }
    }

    const MANIFEST: &str = "[package]\nname = \"x\"\n[dependencies]\nserde = \"1\"\nhdd-common = { path = \"../hdd-common\" }\n[dev-dependencies]\nproptest = \"1\"\n";

    fn today() -> i64 {
        parse_date_days("2026-10-18").unwrap_or(0)
    }

    const LIMIT: (u64, u64) = (1, 98);

    #[test]
    fn external_deps_skip_path_dependencies_and_include_dev() {
        let d = external_deps(MANIFEST).expect("parse");
        assert_eq!(d.into_iter().collect::<Vec<_>>(), vec!["proptest", "serde"]);
    }

    #[test]
    fn adding_a_crate_without_vetting_is_flagged() {
        let v = Vetting {
            crates: vec![entry("serde", "2026-09-01", false, "")],
        };
        let f = check_manifests(
            &[("crates/x/Cargo.toml".into(), MANIFEST.into())],
            &v,
            &BTreeSet::new(),
            today(),
            LIMIT,
        );
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].message.contains("`proptest` has no vetting entry"));
    }

    #[test]
    fn fully_vetted_manifest_passes() {
        let v = Vetting {
            crates: vec![
                entry("serde", "2026-09-01", false, ""),
                entry("proptest", "2026-08-01", false, ""),
            ],
        };
        assert!(
            check_manifests(
                &[("m".into(), MANIFEST.into())],
                &v,
                &BTreeSet::new(),
                today(),
                LIMIT
            )
            .is_empty()
        );
    }

    #[test]
    fn ffi_and_unmaintained_crates_need_an_existing_adr() {
        let adrs: BTreeSet<String> = ["0002".to_owned()].into();
        let v = Vetting {
            crates: vec![
                entry("serde", "2024-01-01", false, ""),
                entry("proptest", "2026-08-01", true, "0099"),
            ],
        };
        let f = check_manifests(&[("m".into(), MANIFEST.into())], &v, &adrs, today(), LIMIT);
        let msgs: Vec<&str> = f.iter().map(|x| x.message.as_str()).collect();
        assert!(
            msgs.iter().any(
                |m| m.contains("last release over a year ago") && m.contains("ADR is required")
            ),
            "{msgs:?}"
        );
        assert!(
            msgs.iter()
                .any(|m| m.contains("FFI") && m.contains("ADR-0099 does not exist")),
            "{msgs:?}"
        );
        let v2 = Vetting {
            crates: vec![
                entry("serde", "2024-01-01", false, "0002"),
                entry("proptest", "2026-08-01", true, "0002"),
            ],
        };
        assert!(
            check_manifests(&[("m".into(), MANIFEST.into())], &v2, &adrs, today(), LIMIT)
                .is_empty()
        );
    }

    #[test]
    fn stale_entries_and_bad_dates_are_flagged() {
        let v = Vetting {
            crates: vec![
                entry("serde", "soon", false, ""),
                entry("proptest", "2026-08-01", false, ""),
                entry("ghost", "2026-08-01", false, ""),
            ],
        };
        let f = check_manifests(
            &[("m".into(), MANIFEST.into())],
            &v,
            &BTreeSet::new(),
            today(),
            LIMIT,
        );
        let msgs: Vec<&str> = f.iter().map(|x| x.message.as_str()).collect();
        assert!(msgs.iter().any(|m| m.contains("not YYYY-MM-DD")));
        assert!(msgs.iter().any(|m| m.contains("no manifest declares")));
    }

    #[test]
    fn a_crate_whose_msrv_exceeds_the_workspace_is_flagged() {
        let mut high = entry("serde", "2026-09-01", false, "");
        high.msrv = "1.99".into();
        let v = Vetting {
            crates: vec![high, entry("proptest", "2026-08-01", false, "")],
        };
        let f = check_manifests(
            &[("m".into(), MANIFEST.into())],
            &v,
            &BTreeSet::new(),
            today(),
            LIMIT,
        );
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].message.contains("MSRV 1.99 exceeds"));
        assert_eq!(parse_msrv("1.85.0"), Some((1, 85)));
        assert_eq!(parse_msrv("x"), None);
    }

    #[test]
    fn workspace_and_target_tables_are_read() {
        let m = "[workspace]\nmembers=[]\n[workspace.dependencies]\nregex = \"1\"\n[target.'cfg(windows)'.dependencies]\nwindows-sys = \"0.61\"\n";
        let d = external_deps(m).expect("parse");
        assert!(d.contains("regex") && d.contains("windows-sys"));
    }
}
