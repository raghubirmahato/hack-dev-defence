//! Shared helpers: repository root discovery, hashing, UTC dates, file walking, a small error type.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

/// Error type of the xtask binary (a message; xtask is a binary so no error taxonomy is needed).
#[derive(Debug)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error(format!("io error: {e}"))
    }
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Error(format!("toml error: {e}"))
    }
}

impl From<regex::Error> for Error {
    fn from(e: regex::Error) -> Self {
        Error(format!("regex error: {e}"))
    }
}

/// Result alias used across the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Build an [`Error`] from anything printable.
pub fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error(msg.into()))
}

/// Lower-case hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for b in digest.iter() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Read a file as UTF-8 text with the path in the error message.
pub fn read_text(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|e| Error(format!("cannot read {}: {e}", path.display())))
}

/// Read a file as bytes with the path in the error message.
pub fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| Error(format!("cannot read {}: {e}", path.display())))
}

/// Write a file (creating parent directories) with LF line endings preserved as given.
pub fn write_text(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content.as_bytes())
        .map_err(|e| Error(format!("cannot write {}: {e}", path.display())))
}

/// Find the repository root: the nearest ancestor of the working directory that holds `docs/SPEC.sha256`.
pub fn repo_root() -> Result<PathBuf> {
    let mut dir = std::env::current_dir()?;
    loop {
        if dir.join("docs").join("SPEC.sha256").is_file() && dir.join("Cargo.toml").is_file() {
            return Ok(dir);
        }
        if !dir.pop() {
            return err(
                "not inside the HDD repository (no docs/SPEC.sha256 found above the working directory)",
            );
        }
    }
}

/// Directory names never descended into when walking the repository.
pub const SKIP_DIRS: &[&str] = &[
    "target",
    ".git",
    "node_modules",
    "acceptance-env",
    "acceptance-verify",
    "hdd-data",
];

/// Recursively collect files under `dir` (sorted, skipping [`SKIP_DIRS`] and anything under `acceptance-*`).
pub fn walk_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_into(dir, &mut out);
    out.sort();
    out
}

fn walk_into(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            if SKIP_DIRS.contains(&name.as_str()) || name.starts_with("acceptance-") {
                continue;
            }
            walk_into(&path, out);
        } else if ft.is_file() {
            out.push(path);
        }
    }
}

/// Repository-relative path with forward slashes.
pub fn rel(root: &Path, path: &Path) -> String {
    let p = path.strip_prefix(root).unwrap_or(path);
    p.to_string_lossy().replace('\\', "/")
}

/// Match a repository-relative path against a glob: `**/` matches any directories (or none), `**` anything,
/// `*` anything except `/`, `?` one character except `/`.
pub fn glob_match(glob: &str, path: &str) -> bool {
    let mut re = String::from("^");
    let chars: Vec<char> = glob.chars().collect();
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        match c {
            '*' if chars.get(i + 1) == Some(&'*') => {
                if chars.get(i + 2) == Some(&'/') {
                    re.push_str("(?:.*/)?");
                    i += 3;
                } else {
                    re.push_str(".*");
                    i += 2;
                }
                continue;
            }
            '*' => re.push_str("[^/]*"),
            '?' => re.push_str("[^/]"),
            c => re.push_str(&regex::escape(&c.to_string())),
        }
        i += 1;
    }
    re.push('$');
    regex::Regex::new(&re).is_ok_and(|r| r.is_match(path))
}

/// Civil date (year, month, day) for days since 1970-01-01 (proleptic Gregorian; Howard Hinnant's algorithm).
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Days since 1970-01-01 for a civil date.
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn now_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let tod = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Parse `YYYY-MM-DD` into days since the epoch.
pub fn parse_date_days(s: &str) -> Option<i64> {
    let mut it = s.trim().split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: u32 = it.next()?.parse().ok()?;
    let d: u32 = it.next()?.parse().ok()?;
    if it.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

/// Days since the epoch for today (UTC).
pub fn today_days() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64 / 86_400)
        .unwrap_or(0)
}

/// Last `n` lines of `text`.
pub fn tail_lines(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines.get(start..).unwrap_or(&[]).join("\n")
}

/// Escape `|` for Markdown table cells.
pub fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

/// A finding produced by a lint or check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Check name (for example `spec`, `claims`, `secrets`).
    pub check: &'static str,
    /// Repository-relative location, possibly with a line number.
    pub location: String,
    /// Human-readable message.
    pub message: String,
}

impl Finding {
    /// Construct a finding.
    pub fn new(
        check: &'static str,
        location: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Finding {
            check,
            location: location.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.check, self.location, self.message)
    }
}

/// Print findings and return a process exit code (0 when empty).
pub fn report_findings(label: &str, findings: &[Finding]) -> i32 {
    if findings.is_empty() {
        println!("{label}: PASS");
        0
    } else {
        for f in findings {
            println!("{f}");
        }
        println!("{label}: FAIL ({} finding(s))", findings.len());
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn civil_round_trip() {
        for days in [-1000_i64, 0, 59, 365, 19_000, 20_745, 30_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(
            parse_date_days("2026-10-18"),
            Some(days_from_civil(2026, 10, 18))
        );
        assert_eq!(parse_date_days("2026-13-18"), None);
        assert_eq!(parse_date_days("garbage"), None);
    }

    #[test]
    fn glob_semantics() {
        assert!(glob_match("docs/**", "docs/a/b.md"));
        assert!(glob_match("docs/*.md", "docs/a.md"));
        assert!(!glob_match("docs/*.md", "docs/a/b.md"));
        assert!(glob_match(
            "crates/**/templates/**",
            "crates/x/templates/a.html"
        ));
        assert!(glob_match(
            "crates/**/templates/**",
            "crates/templates/a.html"
        ));
        assert!(glob_match("README.md", "README.md"));
        assert!(!glob_match("README.md", "docs/README.md"));
        assert!(glob_match("**/*.rs", "a/b/c.rs"));
        assert!(glob_match("**/*.rs", "c.rs"));
    }

    #[test]
    fn tail_lines_takes_last() {
        assert_eq!(tail_lines("a\nb\nc\nd", 2), "c\nd");
        assert_eq!(tail_lines("a", 5), "a");
    }
}
