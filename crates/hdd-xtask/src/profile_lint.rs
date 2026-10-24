//! `profile-lint` and `kv-lint` (T-0561 step 4, R-31) plus the two consistency checks that keep the capability matrix and the
//! acceptance-check table honest.
//!
//! * Profile-dependent code is confined to `hdd-local`, `hdd-common::kv`, `hdd-common::profile` and the `Enforcer` factory
//!   (C18.3). The detection, pipeline and authentication crates, and the egress and network modules of `hdd-common`, must not
//!   look at the runtime profile: no `runtime.profile`, no `Profile::`, no profile environment variable, no profile `cfg`.
//!   Tenancy has no crate of its own; it lives in the API and the migrations, which may ask the capability matrix but are
//!   listed in `docs/profile-lint.toml` once they exist.
//! * Only `hdd-common::kv` talks to Redis (A3): no Redis client crate in any other manifest, no Redis client path in any other
//!   source file.
//! * `Capability::ALL` lists exactly the variants of `enum Capability` (a capability that is not in the matrix fails).
//! * `hdd_common::buildplan::ACCEPTANCE_CHECKS` equals the registry of `docs/spec/E3.md`.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;

use crate::rules::{is_test_path, non_test_part};
use crate::util::{Finding, Result, glob_match, read_text, rel, walk_files};

/// Configuration (`docs/profile-lint.toml`).
#[derive(Debug, Deserialize, Default, Clone)]
pub struct Config {
    /// Globs of files that must not look at the runtime profile.
    #[serde(default)]
    pub profile_free_paths: Vec<String>,
    /// Literal patterns that mean "looks at the runtime profile".
    #[serde(default)]
    pub profile_patterns: Vec<String>,
    /// Literal patterns that mean "decides by the runtime profile" (the profile type, its settings, its environment
    /// variables). Anywhere outside `profile_allowed_paths` they are a finding; the capability matrix is the way to ask.
    #[serde(default)]
    pub profile_confined_patterns: Vec<String>,
    /// Globs of the places allowed to know the runtime profile (C18.3: hdd-local, hdd-common::kv, hdd-common::profile and the
    /// Enforcer factory, plus the build plan, the CLI and the build tooling).
    #[serde(default)]
    pub profile_allowed_paths: Vec<String>,
    /// Literal patterns that mean "talks to Redis".
    #[serde(default)]
    pub kv_patterns: Vec<String>,
    /// Redis client crate names (manifest dependency keys).
    #[serde(default)]
    pub kv_crates: Vec<String>,
    /// Globs of source files allowed to talk to Redis.
    #[serde(default)]
    pub kv_allowed_paths: Vec<String>,
    /// Manifests allowed to depend on a Redis client.
    #[serde(default)]
    pub kv_allowed_manifests: Vec<String>,
}

/// Load `docs/profile-lint.toml`; a missing file is an error (the rules must be written down).
pub fn load_config(root: &Path) -> Result<Config> {
    let p = root.join("docs").join("profile-lint.toml");
    Ok(toml::from_str(&read_text(&p)?)?)
}

fn code_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    non_test_part(text)
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
        .map(|(n, l)| (n + 1, l))
}

/// Profile checks in one Rust file.
pub fn scan_profile(cfg: &Config, relpath: &str, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if is_test_path(relpath)
        || !cfg
            .profile_free_paths
            .iter()
            .any(|g| glob_match(g, relpath))
    {
        return out;
    }
    for (n, line) in code_lines(text) {
        for p in &cfg.profile_patterns {
            if line.contains(p.as_str()) {
                out.push(Finding::new(
                    "profile-lint",
                    format!("{relpath}:{n}"),
                    format!("R-31: `{p}` in code that must not depend on the runtime profile (ask hdd-common::profile::capability or move the logic into hdd-local / hdd-common::kv)"),
                ));
            }
        }
    }
    out
}

/// Confinement: the runtime profile is read only in the places that may know it.
pub fn scan_confined(cfg: &Config, relpath: &str, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if is_test_path(relpath)
        || cfg.profile_confined_patterns.is_empty()
        || cfg
            .profile_allowed_paths
            .iter()
            .any(|g| glob_match(g, relpath))
    {
        return out;
    }
    for (n, line) in code_lines(text) {
        for p in &cfg.profile_confined_patterns {
            if line.contains(p.as_str()) {
                out.push(Finding::new(
                    "profile-lint",
                    format!("{relpath}:{n}"),
                    format!("R-31: `{p}` outside the places that may know the runtime profile (hdd-local, hdd-common::kv, hdd-common::profile, the Enforcer factory); ask `Profile::availability` instead"),
                ));
            }
        }
    }
    out
}

/// `[features]` named `local` or `hosted` in a manifest of a profile-free crate.
pub fn scan_profile_manifest(cfg: &Config, relpath: &str, text: &str) -> Vec<Finding> {
    let dir = relpath.strip_suffix("Cargo.toml").unwrap_or(relpath);
    if !cfg
        .profile_free_paths
        .iter()
        .any(|g| glob_match(g, &format!("{dir}x.rs")) || glob_match(g, &format!("{dir}src/x.rs")))
    {
        return Vec::new();
    }
    let mut in_features = false;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.starts_with('[') {
            in_features = t == "[features]";
            continue;
        }
        if in_features {
            let key = t.split('=').next().unwrap_or("").trim();
            if matches!(key, "local" | "hosted") {
                out.push(Finding::new(
                    "profile-lint",
                    format!("{relpath}:{}", n + 1),
                    format!("R-31: feature `{key}` is a profile switch compiled into a profile-free crate"),
                ));
            }
        }
    }
    out
}

/// True when the pattern at `at` is reached through hdd-common's own `kv` module (`kv::redis::...`, `super::redis::...`), which
/// is not the client crate.
fn is_own_kv_path(line: &str, at: usize) -> bool {
    let before = line.get(..at).unwrap_or("");
    ["kv::", "super::", "self::", "crate::"]
        .iter()
        .any(|p| before.ends_with(p))
}

/// Redis checks in one Rust file.
pub fn scan_kv(cfg: &Config, relpath: &str, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if cfg.kv_allowed_paths.iter().any(|g| glob_match(g, relpath)) {
        return out;
    }
    for (n, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for p in &cfg.kv_patterns {
            let hit = line
                .match_indices(p.as_str())
                .any(|(at, _)| !is_own_kv_path(line, at));
            if hit {
                out.push(Finding::new(
                    "kv-lint",
                    format!("{relpath}:{}", n + 1),
                    format!("`{p}` outside hdd-common::kv: runtime state goes through the KvStore, Bus and Limiter traits (T-0562)"),
                ));
            }
        }
    }
    out
}

/// Redis client dependencies in a manifest.
pub fn scan_kv_manifest(cfg: &Config, relpath: &str, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if cfg.kv_allowed_manifests.iter().any(|m| m == relpath) {
        return out;
    }
    for (n, line) in text.lines().enumerate() {
        let t = line.trim();
        // a renamed dependency (`x = { package = "redis" }`) is still the client
        if cfg.kv_crates.iter().any(|c| {
            t.contains(&format!("package = \"{c}\"")) || t.contains(&format!("package=\"{c}\""))
        }) {
            out.push(Finding::new(
                "kv-lint",
                format!("{relpath}:{}", n + 1),
                "a renamed dependency on a Redis client outside hdd-common::kv",
            ));
            continue;
        }
        let key = t
            .trim_start_matches('[')
            .split(['=', ']', '.'])
            .next()
            .unwrap_or("")
            .trim();
        let dotted = t
            .strip_prefix("[dependencies.")
            .or_else(|| t.strip_prefix("[dev-dependencies."))
            .or_else(|| t.strip_prefix("[build-dependencies."));
        let name = dotted.map_or(key, |d| d.trim_end_matches(']'));
        if cfg.kv_crates.iter().any(|c| c == name) {
            out.push(Finding::new(
                "kv-lint",
                format!("{relpath}:{}", n + 1),
                format!("dependency `{name}` (a Redis client) outside hdd-common::kv"),
            ));
        }
    }
    out
}

/// Walk the repository's crates.
fn crate_files(root: &Path) -> Vec<(String, std::path::PathBuf)> {
    walk_files(&root.join("crates"))
        .into_iter()
        .map(|p| (rel(root, &p), p))
        .collect()
}

/// `profile-lint` over the repository.
pub fn check_profile(root: &Path) -> Vec<Finding> {
    let cfg = match load_config(root) {
        Ok(c) => c,
        Err(e) => return vec![Finding::new("profile-lint", "docs/profile-lint.toml", e.0)],
    };
    let mut f = Vec::new();
    if cfg.profile_free_paths.is_empty() || cfg.profile_patterns.is_empty() {
        f.push(Finding::new(
            "profile-lint",
            "docs/profile-lint.toml",
            "profile_free_paths and profile_patterns must not be empty",
        ));
    }
    for (r, p) in crate_files(root) {
        if r.ends_with(".rs") {
            match read_text(&p) {
                Ok(t) => {
                    f.extend(scan_profile(&cfg, &r, &t));
                    f.extend(scan_confined(&cfg, &r, &t));
                }
                Err(e) => f.push(Finding::new("profile-lint", &r, e.0)),
            }
        } else if r.ends_with("/Cargo.toml") {
            match read_text(&p) {
                Ok(t) => f.extend(scan_profile_manifest(&cfg, &r, &t)),
                Err(e) => f.push(Finding::new("profile-lint", &r, e.0)),
            }
        }
    }
    f.extend(check_capability_matrix(root));
    f.extend(check_ac_table(root));
    f
}

/// `kv-lint` over the repository.
pub fn check_kv(root: &Path) -> Vec<Finding> {
    let cfg = match load_config(root) {
        Ok(c) => c,
        Err(e) => return vec![Finding::new("kv-lint", "docs/profile-lint.toml", e.0)],
    };
    let mut f = Vec::new();
    if cfg.kv_patterns.is_empty() || cfg.kv_crates.is_empty() {
        f.push(Finding::new(
            "kv-lint",
            "docs/profile-lint.toml",
            "kv_patterns and kv_crates must not be empty",
        ));
    }
    for (r, p) in crate_files(root) {
        if r.ends_with(".rs") {
            match read_text(&p) {
                Ok(t) => f.extend(scan_kv(&cfg, &r, &t)),
                Err(e) => f.push(Finding::new("kv-lint", &r, e.0)),
            }
        } else if r.ends_with("/Cargo.toml") {
            match read_text(&p) {
                Ok(t) => f.extend(scan_kv_manifest(&cfg, &r, &t)),
                Err(e) => f.push(Finding::new("kv-lint", &r, e.0)),
            }
        }
    }
    match read_text(&root.join("Cargo.toml")) {
        Ok(t) => f.extend(scan_kv_manifest(&cfg, "Cargo.toml", &t)),
        Err(e) => f.push(Finding::new("kv-lint", "Cargo.toml", e.0)),
    }
    f
}

/// Variants of `pub enum Capability` against the entries of `Capability::ALL`.
pub fn check_capability_text(path: &str, text: &str) -> Vec<Finding> {
    let mut variants = BTreeSet::new();
    let mut all = BTreeSet::new();
    let mut in_enum = false;
    let mut in_all = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("pub enum Capability") {
            in_enum = true;
            continue;
        }
        if in_enum {
            if t == "}" {
                in_enum = false;
            } else if !t.starts_with("//")
                && let Some(name) = t.strip_suffix(',')
                && name.chars().all(|c| c.is_ascii_alphanumeric())
                && !name.is_empty()
            {
                variants.insert(name.to_owned());
            }
            continue;
        }
        if t.starts_with("pub const ALL") {
            in_all = true;
            continue;
        }
        if in_all {
            if t.starts_with("];") {
                in_all = false;
            } else if let Some(rest) = t.strip_prefix("Capability::")
                && let Some(name) = rest.strip_suffix(',')
            {
                all.insert(name.to_owned());
            }
        }
    }
    let mut f = Vec::new();
    if variants.is_empty() {
        f.push(Finding::new(
            "profile-lint",
            path,
            "found no variants of `enum Capability`",
        ));
    }
    for v in variants.difference(&all) {
        f.push(Finding::new("profile-lint", path, format!("capability `{v}` is not listed in Capability::ALL, so the matrix and `profile-lint` do not see it")));
    }
    for v in all.difference(&variants) {
        f.push(Finding::new(
            "profile-lint",
            path,
            format!("Capability::ALL lists `{v}`, which is not a variant of `enum Capability`"),
        ));
    }
    f
}

/// The capability matrix is complete.
pub fn check_capability_matrix(root: &Path) -> Vec<Finding> {
    let p = "crates/hdd-common/src/profile/capability.rs";
    match read_text(&root.join(p)) {
        Ok(t) => check_capability_text(p, &t),
        Err(e) => vec![Finding::new("profile-lint", p, e.0)],
    }
}

/// Rows `| AC-nn | name | built in | tier |` of the registry text.
pub fn ac_rows(spec: &str) -> Vec<(String, String, String, String)> {
    spec.lines()
        .filter_map(|l| {
            let cells: Vec<&str> = l.split('|').map(str::trim).collect();
            let id = cells.get(1)?;
            let is_id = id.len() == 5
                && id.starts_with("AC-")
                && id
                    .get(3..)
                    .is_some_and(|d| d.chars().all(|c| c.is_ascii_digit()));
            if !is_id || cells.len() < 6 {
                return None;
            }
            Some((
                (*id).to_owned(),
                (*cells.get(2)?).to_owned(),
                (*cells.get(3)?).to_owned(),
                (*cells.get(4)?).to_owned(),
            ))
        })
        .collect()
}

/// `ACCEPTANCE_CHECKS` equals the registry of Appendix E3.
pub fn check_ac_table(root: &Path) -> Vec<Finding> {
    let p = "docs/spec/E3.md";
    let spec = match read_text(&root.join(p)) {
        Ok(t) => t,
        Err(e) => return vec![Finding::new("profile-lint", p, e.0)],
    };
    let rows = ac_rows(&spec);
    let table = hdd_common::buildplan::ACCEPTANCE_CHECKS;
    let mut f = Vec::new();
    if rows.len() != table.len() {
        f.push(Finding::new("profile-lint", p, format!("the registry has {} AC rows, hdd_common::buildplan::ACCEPTANCE_CHECKS has {}; run `cargo xtask build-plan table`", rows.len(), table.len())));
    }
    for (row, t) in rows.iter().zip(table.iter()) {
        if (
            row.0.as_str(),
            row.1.as_str(),
            row.2.as_str(),
            row.3.as_str(),
        ) != (t.0, t.1, t.2, t.3)
        {
            f.push(Finding::new("profile-lint", p, format!("{} differs from hdd_common::buildplan::ACCEPTANCE_CHECKS; run `cargo xtask build-plan table`", row.0)));
        }
    }
    f
}

/// Rust source of the table (`build-plan table`).
pub fn render_ac_table(spec: &str) -> String {
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let mut s = String::from(
        "//! The acceptance-check registry of Appendix E3 as data: id, name, where it is built, tier.\n//!\n//! Generated from `docs/spec/E3.md` by `cargo xtask build-plan table` and checked against it by `profile-lint` (so the table cannot\n//! drift from the specification). Do not edit by hand.\n\n/// One row of the registry: `(id, name, built in, tier)`.\npub const ACCEPTANCE_CHECKS: &[(&str, &str, &str, &str)] = &[\n",
    );
    for (a, b, c, d) in ac_rows(spec) {
        s.push_str(&format!(
            "    (\"{}\", \"{}\", \"{}\", \"{}\"),\n",
            esc(&a),
            esc(&b),
            esc(&c),
            esc(&d)
        ));
    }
    s.push_str("];\n");
    s
}

/// `build-plan table`: regenerate the Rust table from the registry.
pub fn write_ac_table(root: &Path) -> Result<()> {
    let spec = read_text(&root.join("docs").join("spec").join("E3.md"))?;
    let path = root.join("crates/hdd-common/src/buildplan/ac_table.rs");
    crate::util::write_text(&path, &render_ac_table(&spec))?;
    println!("build-plan table: wrote crates/hdd-common/src/buildplan/ac_table.rs");
    Ok(())
}

#[cfg(test)]
mod tests;
