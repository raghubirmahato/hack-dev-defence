//! Secret scanner, `gen-secrets` and the git pre-commit hook installer (T-0005 step 6, R-03).
//!
//! The scanner never prints a matched value: findings show the rule, the location and the value's length with at
//! most its first four characters.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;

use crate::util::{Error, Finding, Result, read_bytes, rel, walk_files, write_text};

/// Largest file scanned (bigger files are reported as skipped, not silently ignored).
pub const MAX_SCAN_BYTES: usize = 2 * 1024 * 1024;
/// Marker that excuses a line (for documented test vectors).
pub const ALLOW_MARKER: &str = "hdd-secret-scan:allow";
/// Minimum Shannon entropy (bits per character) of a long token to be reported as a high-entropy secret.
pub const ENTROPY_THRESHOLD: f64 = 4.5;
/// Minimum token length for the entropy rule.
pub const ENTROPY_MIN_LEN: usize = 32;

/// Shannon entropy in bits per character.
pub fn entropy(s: &str) -> f64 {
    let mut counts = std::collections::BTreeMap::new();
    let mut n = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n as f64;
            -p * p.log2()
        })
        .sum()
}

fn redact(value: &str) -> String {
    let head: String = value.chars().take(4).collect();
    format!("{head}… ({} chars)", value.chars().count())
}

struct Rules {
    named: Vec<(&'static str, Regex)>,
    assignment: Regex,
    token: Regex,
}

fn rules() -> Result<Rules> {
    let named = vec![
        (
            "private key block",
            Regex::new(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")?,
        ),
        (
            "AWS access key id",
            Regex::new(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b")?,
        ),
        (
            "GitHub token",
            Regex::new(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")?,
        ),
        (
            "Slack token",
            Regex::new(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")?,
        ),
        ("Google API key", Regex::new(r"\bAIza[0-9A-Za-z_-]{35}\b")?),
        (
            "Stripe live key",
            Regex::new(r"\b[sr]k_live_[0-9A-Za-z]{16,}\b")?,
        ),
        (
            "JSON Web Token",
            Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")?,
        ),
        (
            "URL with embedded credentials",
            Regex::new(r"\b[a-z][a-z0-9+.-]*://[^\s/:@'\x22]+:[^\s/@'\x22]{3,}@[^\s/'\x22]+")?,
        ),
    ];
    Ok(Rules {
        named,
        assignment: Regex::new(
            r#"(?i)\b((?:password|passwd|secret|token|api[_-]?key|private[_-]?key)\w*)\s*[:=]\s*['"]([^'"\s]{8,})['"]"#,
        )?,
        token: Regex::new(r"[A-Za-z0-9+/=_-]{32,}")?,
    })
}

/// A value that is a name of an environment variable or an obvious placeholder is not a secret.
fn looks_like_reference(v: &str) -> bool {
    // an environment variable NAME has words separated by underscores; a bare upper-case word could be a password
    let upper_name = v
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && v.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && v.contains('_');
    let lower = v.to_lowercase();
    // placeholders are recognised by what they start with, not by containing a word: "mysecretexample1" is a password
    const PLACEHOLDERS: &[&str] = &[
        "changeme",
        "change-me",
        "example",
        "placeholder",
        "your-",
        "your_",
        "<",
        "${",
        "{{",
        "xxxx",
        "todo",
    ];
    upper_name || PLACEHOLDERS.iter().any(|p| lower.starts_with(p))
}

/// Scan one text; `name` is used for locations.
pub fn scan_text(name: &str, text: &str) -> Result<Vec<Finding>> {
    let r = rules()?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.contains(ALLOW_MARKER) {
            continue;
        }
        let loc = format!("{name}:{}", n + 1);
        let mut flagged = false;
        for (label, re) in &r.named {
            if let Some(m) = re.find(line) {
                out.push(Finding::new(
                    "secrets",
                    &loc,
                    format!("{label}: {}", redact(m.as_str())),
                ));
                flagged = true;
            }
        }
        if flagged {
            continue;
        }
        if let Some(c) = r.assignment.captures(line) {
            let key = c.get(1).map_or("", |m| m.as_str()).to_lowercase();
            let v = c.get(2).map_or("", |m| m.as_str());
            // a setting that names a method, not a secret: `password_encryption = 'scram-sha-256'`
            let names_a_method = ["_encryption", "_method", "_algorithm", "_policy", "_hash"]
                .iter()
                .any(|s| key.ends_with(s));
            if !names_a_method && !looks_like_reference(v) {
                out.push(Finding::new(
                    "secrets",
                    &loc,
                    format!("hard-coded credential assignment: {}", redact(v)),
                ));
                continue;
            }
        }
        let lower = line.to_lowercase();
        if lower.contains("sha256")
            || lower.contains("sha-256")
            || lower.contains("checksum")
            || lower.contains("digest")
        {
            continue;
        }
        for m in r.token.find_iter(line) {
            let t = m.as_str();
            if t.len() >= ENTROPY_MIN_LEN
                && entropy(t) >= ENTROPY_THRESHOLD
                && !t.contains("//")
                && t.chars().any(|c| c.is_ascii_digit())
            {
                out.push(Finding::new(
                    "secrets",
                    &loc,
                    format!("high-entropy token: {}", redact(t)),
                ));
                break;
            }
        }
    }
    Ok(out)
}

/// Paths (repository-relative) that are never scanned: the verbatim specification and lock files with only checksums.
const SKIP_PATHS: &[&str] = &["docs/SPEC.md", "Cargo.lock"];
/// Directory prefixes derived verbatim from the specification (ASM-004): they contain example payloads such as serialized
/// objects and sample tokens, which are test vectors and not credentials.
const SKIP_PREFIXES: &[&str] = &["docs/spec/", "docs/tasks/", "docs/phases/"];

/// True for `.env` files that must never be committed (`.env.example` is the allowed template).
pub fn is_forbidden_env_file(relpath: &str) -> bool {
    let name = relpath.rsplit('/').next().unwrap_or(relpath);
    (name == ".env" || name.starts_with(".env.")) && name != ".env.example"
}

/// Extensions of files that are binary by nature and not worth scanning.
const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "ico", "webp", "woff", "woff2", "ttf", "otf", "zip", "gz", "tgz",
    "xz", "bz2", "7z", "exe", "dll", "pdf", "bin", "so", "dylib", "class", "wasm", "o", "a",
    "rlib", "pdb",
];

/// True for files whose extension marks them as binary.
pub fn has_binary_extension(name: &str) -> bool {
    name.rsplit_once('.')
        .is_some_and(|(_, e)| BINARY_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
}

/// Decode bytes for scanning: UTF-16 (with a byte-order mark) is decoded; other text has NUL bytes removed.
pub fn decode_text(bytes: &[u8]) -> String {
    match bytes {
        [0xff, 0xfe, rest @ ..] => String::from_utf16_lossy(
            &rest
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect::<Vec<_>>(),
        ),
        [0xfe, 0xff, rest @ ..] => String::from_utf16_lossy(
            &rest
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes(*c))
                .collect::<Vec<_>>(),
        ),
        _ => {
            let cleaned: Vec<u8> = bytes.iter().copied().filter(|b| *b != 0).collect();
            String::from_utf8_lossy(&cleaned).into_owned()
        }
    }
}

fn scan_path(root: &Path, path: &Path, bytes: &[u8]) -> Result<Vec<Finding>> {
    let name = rel(root, path);
    if SKIP_PATHS.contains(&name.as_str()) || SKIP_PREFIXES.iter().any(|p| name.starts_with(p)) {
        return Ok(vec![]);
    }
    if is_forbidden_env_file(&name) {
        return Ok(vec![Finding::new(
            "secrets",
            name,
            "environment file with real values must not be committed (use .env.example)",
        )]);
    }
    if bytes.len() > MAX_SCAN_BYTES {
        return Ok(vec![Finding::new(
            "secrets",
            name,
            format!("not scanned: larger than {MAX_SCAN_BYTES} bytes"),
        )]);
    }
    if has_binary_extension(&name) {
        return Ok(vec![]);
    }
    // text with NUL bytes (UTF-16 from PowerShell redirection, a planted NUL) is decoded or stripped and scanned, not skipped
    scan_text(&name, &decode_text(bytes))
}

/// Scan the working tree (all non-ignored-directory files). `.gitignore`d secret files such as `hdd.live.yaml` are
/// left alone because they are never committed; `.env` files are reported only when git would track them.
pub fn scan_tree(root: &Path) -> Result<Vec<Finding>> {
    let ignored_secret_dirs = ["secrets/"];
    let mut out = Vec::new();
    for f in walk_files(root) {
        let r = rel(root, &f);
        if ignored_secret_dirs.iter().any(|d| r.starts_with(d)) || r == "hdd.live.yaml" {
            continue;
        }
        if is_forbidden_env_file(&r) {
            // present on disk but ignored by git: acceptable only when git ignores it.
            if !git_ignored(root, &r) {
                out.push(Finding::new(
                    "secrets",
                    r,
                    "environment file is not git-ignored",
                ));
            }
            continue;
        }
        out.extend(scan_file(root, &f)?);
    }
    Ok(out)
}

/// Read and scan one file. A file that cannot be read is a finding (fail closed), never a silent skip.
pub fn scan_file(root: &Path, f: &Path) -> Result<Vec<Finding>> {
    match read_bytes(f) {
        Ok(bytes) => scan_path(root, f, &bytes),
        Err(e) => Ok(vec![Finding::new(
            "secrets",
            rel(root, f),
            format!("could not be read, so it was not scanned: {}", e.0),
        )]),
    }
}

fn git_ignored(root: &Path, relpath: &str) -> bool {
    Command::new("git")
        .args(["check-ignore", "-q", "--", relpath])
        .current_dir(root)
        .status()
        .is_ok_and(|s| s.success())
}

fn git_root() -> Result<PathBuf> {
    let o = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|e| Error(format!("git not available: {e}")))?;
    if !o.status.success() {
        return Err(Error("not inside a git repository".into()));
    }
    Ok(PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()))
}

/// Scan the staged blobs (what a commit would contain). Used by the pre-commit hook.
pub fn scan_staged() -> Result<Vec<Finding>> {
    let root = git_root()?;
    let o = Command::new("git")
        .args([
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMRT",
            "-z",
        ])
        .current_dir(&root)
        .output()
        .map_err(|e| Error(format!("git diff failed: {e}")))?;
    let mut out = Vec::new();
    for name in String::from_utf8_lossy(&o.stdout)
        .split('\0')
        .filter(|s| !s.is_empty())
    {
        let blob = Command::new("git")
            .args(["show", &format!(":{name}")])
            .current_dir(&root)
            .output()
            .map_err(|e| Error(format!("git show failed: {e}")))?;
        if !blob.status.success() {
            // fail closed: a staged blob that cannot be read has not been scanned, so the commit must not pass
            out.push(Finding::new(
                "secrets",
                name.to_owned(),
                "staged content could not be read, so it was not scanned",
            ));
            continue;
        }
        let path = root.join(name);
        out.extend(scan_path(&root, &path, &blob.stdout)?);
    }
    Ok(out)
}

/// The pre-commit hook body written by `hooks install`.
pub const HOOK_BODY: &str = "#!/bin/sh\n# Installed by `cargo xtask hooks install` (T-0005). Blocks commits that contain secrets.\n\
if [ -n \"$HDD_XTASK_BIN\" ]; then exec \"$HDD_XTASK_BIN\" secrets scan --staged; fi\nexec cargo xtask secrets scan --staged\n";

/// `hooks install`: write `.githooks/pre-commit` and point `core.hooksPath` at it.
pub fn install_hooks(root: &Path) -> Result<()> {
    let hook = root.join(".githooks").join("pre-commit");
    write_text(&hook, HOOK_BODY)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755))?;
    }
    let st = Command::new("git")
        .args(["config", "core.hooksPath", ".githooks"])
        .current_dir(root)
        .status()
        .map_err(|e| Error(format!("git config failed: {e}")))?;
    if !st.success() {
        return Err(Error("git config core.hooksPath failed".into()));
    }
    println!(
        "hooks install: wrote {} and set core.hooksPath=.githooks",
        rel(root, &hook)
    );
    Ok(())
}

/// Names generated by `gen-secrets` (Appendix B10, 32 random bytes each).
pub const SECRET_NAMES: &[&str] = &[
    "HDD_MASTER_KEY",
    "HDD_JWT_SECRET",
    "HDD_SESSION_KEY",
    "HDD_CSRF_KEY",
    "HDD_CHALLENGE_KEY",
    "HDD_EMAIL_HMAC_KEY",
    "HDD_PEPPER",
];

/// Unpadded URL-safe base64.
pub fn base64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"; // hdd-secret-scan:allow (alphabet constant)
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        for (i, shift) in [18u32, 12, 6, 0].iter().enumerate() {
            if i <= chunk.len() {
                let idx = ((n >> shift) & 63) as usize;
                if let Some(c) = A.get(idx) {
                    out.push(char::from(*c));
                }
            }
        }
    }
    out
}

/// `gen-secrets`: write one random 32-byte secret per name into `dir`, owner-only, refusing to overwrite.
/// Values are never printed.
pub fn gen_secrets(dir: &Path, force: bool) -> Result<Vec<String>> {
    // restrict the ACL / mode only of a directory created here: an existing directory keeps the permissions its owner chose
    // (on Windows, removing inheritance would also strip SYSTEM and Administrators from a shared folder)
    let created = !dir.exists();
    fs::create_dir_all(dir)?;
    if created {
        restrict_dir(dir)?;
    } else {
        println!(
            "gen-secrets: {} already exists; its permissions are left as they are (check that only you can read it)",
            dir.display()
        );
    }
    let mut written = Vec::new();
    for name in SECRET_NAMES {
        let path = dir.join(name);
        if path.exists() && !force {
            println!("gen-secrets: {name} exists, kept (use --force to rotate)");
            continue;
        }
        let mut buf = [0u8; 32];
        getrandom::fill(&mut buf).map_err(|e| Error(format!("OS random source failed: {e}")))?;
        write_text(&path, &format!("{}\n", base64url(&buf)))?;
        restrict_file(&path)?;
        written.push((*name).to_owned());
    }
    Ok(written)
}

#[cfg(unix)]
fn restrict_file(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(unix)]
fn restrict_dir(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(windows)]
fn restrict_file(_p: &Path) -> Result<()> {
    // files inherit the owner-only ACL of the directory set by `restrict_dir`
    Ok(())
}

#[cfg(windows)]
fn restrict_dir(p: &Path) -> Result<()> {
    let sid = current_sid()?;
    let out = Command::new("icacls")
        .arg(p)
        .args(["/inheritance:r", "/grant:r"])
        .arg(format!("*{sid}:(OI)(CI)F"))
        .output()
        .map_err(|e| Error(format!("icacls failed to start: {e}")))?;
    if !out.status.success() {
        return Err(Error(format!(
            "icacls failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

/// SID of the current user, from `whoami /user` (the Windows tool, addressed through `SystemRoot` so that a Unix `whoami` earlier on `PATH` is not used).
#[cfg(windows)]
fn current_sid() -> Result<String> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    let exe = Path::new(&root).join("System32").join("whoami.exe");
    let out = Command::new(exe)
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .map_err(|e| Error(format!("whoami failed to start: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let sid = text
        .trim()
        .rsplit(',')
        .next()
        .unwrap_or("")
        .trim_matches('"')
        .to_owned();
    if !sid.starts_with("S-1-") {
        return Err(Error(
            "cannot determine the current user SID; refusing to change the ACL".into(),
        ));
    }
    Ok(sid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_private_key() -> String {
        // assembled at runtime so that no private-key header exists in the committed source (T-0005 A4)
        format!(
            "-----BEGIN {} PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END {} PRIVATE KEY-----\n",
            "RSA", "RSA"
        )
    }

    #[test]
    fn private_key_block_is_found_and_not_echoed() {
        let f = scan_text("a.txt", &fake_private_key()).expect("scan");
        assert_eq!(f.len(), 1);
        assert!(f[0].message.starts_with("private key block"));
        assert!(!f[0].message.contains("MIIE"));
    }

    #[test]
    fn aws_style_key_is_found() {
        let key = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
        let f = scan_text("a.env", &format!("aws_access_key_id = {key}\n")).expect("scan");
        assert_eq!(f.len(), 1);
        assert!(f[0].message.starts_with("AWS access key id"));
        assert!(!f[0].message.contains(&key));
    }

    #[test]
    fn high_entropy_token_is_found_but_hashes_and_words_are_not() {
        let token = "q8Zr3LmX0pVt9KcNw2BhYdJf7SgUaE5i"; // hdd-secret-scan:allow (test vector)
        assert!(entropy(token) >= ENTROPY_THRESHOLD);
        assert_eq!(
            scan_text("a.txt", &format!("value {token}\n"))
                .expect("scan")
                .len(),
            1
        );
        let hex = "630d5f0f46d2fd8b6c9983f2939b009a1c91d1a572ef9335fc512e040952985d";
        assert!(
            scan_text("a.txt", &format!("{hex}\n"))
                .expect("scan")
                .is_empty()
        );
        assert!(
            scan_text(
                "a.txt",
                "thequickbrownfoxjumpsoverthelazydogagainandagain\n"
            )
            .expect("scan")
            .is_empty()
        );
    }

    #[test]
    fn credential_assignment_ignores_env_var_names_and_placeholders() {
        assert_eq!(
            scan_text("a.toml", "password = \"hunter2hunter2\"\n")
                .expect("scan")
                .len(),
            1
        );
        assert!(
            scan_text(
                "a.yaml",
                "token_env: 'HDD_API_TOKEN'\npassword_env = \"SMTP_PASSWORD\"\n"
            )
            .expect("scan")
            .is_empty()
        );
        assert!(
            scan_text("a.toml", "password = \"changeme-example\"\n")
                .expect("scan")
                .is_empty()
        );
    }

    #[test]
    fn url_credentials_are_found() {
        assert_eq!(
            scan_text("a.txt", "db: postgres://app:s3cretpw@db.internal/prod\n") // hdd-secret-scan:allow (test vector)
                .expect("scan")
                .len(),
            1
        );
        assert!(
            scan_text("a.txt", "see https://example.com/path\n")
                .expect("scan")
                .is_empty()
        );
    }

    #[test]
    fn allow_marker_excuses_a_line() {
        let line = format!(
            "{} {ALLOW_MARKER}\n",
            fake_private_key().lines().next().unwrap_or("")
        );
        assert!(scan_text("a.txt", &line).expect("scan").is_empty());
    }

    #[test]
    fn env_files_are_forbidden_except_the_example() {
        assert!(is_forbidden_env_file(".env"));
        assert!(is_forbidden_env_file("deploy/.env.production"));
        assert!(!is_forbidden_env_file(".env.example"));
        assert!(!is_forbidden_env_file("docs/env.md"));
    }

    #[test]
    fn utf16_and_nul_padded_text_is_scanned_not_skipped() {
        let key = format!("-----BEGIN {} PRIVATE KEY-----\nabc\n", "RSA");
        let mut utf16le = vec![0xff, 0xfe];
        for u in key.encode_utf16() {
            utf16le.extend_from_slice(&u.to_le_bytes());
        }
        let mut utf16be = vec![0xfe, 0xff];
        for u in key.encode_utf16() {
            utf16be.extend_from_slice(&u.to_be_bytes());
        }
        let planted: Vec<u8> = key.bytes().flat_map(|b| [b, 0]).collect();
        let root = Path::new("/r");
        for (label, bytes) in [
            ("utf-16le", utf16le),
            ("utf-16be", utf16be),
            ("nul padded", planted),
        ] {
            let f = scan_path(root, &root.join("a.txt"), &bytes).expect("scan");
            assert_eq!(f.len(), 1, "{label}: {f:?}");
            assert!(f[0].message.starts_with("private key block"), "{label}");
        }
        assert!(
            scan_path(root, &root.join("logo.png"), &[0x89, b'P', 0, 0, 1])
                .expect("scan")
                .is_empty(),
            "binary extensions are skipped"
        );
    }

    #[test]
    fn placeholders_are_recognised_by_prefix_and_env_names_need_an_underscore() {
        assert!(
            scan_text("a.toml", "password = \"mysecretexample1\"\n")
                .expect("scan")
                .len()
                == 1,
            "a password that merely contains 'example'"
        );
        assert!(
            scan_text("a.toml", "password = \"SUPERSECRETPASSWORD\"\n")
                .expect("scan")
                .len()
                == 1,
            "a bare upper-case word is not an env name"
        );
        assert!(scan_text("a.toml", "password = \"changeme-please\"\ntoken = \"HDD_API_TOKEN\"\napi_key = \"<your key>\"\n").expect("scan").is_empty());
    }

    #[test]
    fn unreadable_files_are_findings_not_silent_skips() {
        let root = std::env::temp_dir();
        let missing = root.join(format!("hdd-xtask-no-such-file-{}.txt", std::process::id()));
        let f = scan_file(&root, &missing).expect("scan");
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(
            f[0].message
                .contains("could not be read, so it was not scanned"),
            "{}",
            f[0].message
        );
    }

    #[test]
    fn gen_secrets_leaves_an_existing_directory_alone_and_protects_a_new_one() {
        let base =
            std::env::temp_dir().join(format!("hdd-xtask-gensecrets-perm-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let fresh = base.join("fresh");
        fs::create_dir_all(&base).expect("mkdir");
        gen_secrets(&fresh, false).expect("gen");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&fresh).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "a new directory is owner-only");
            let file_mode = fs::metadata(fresh.join("HDD_PEPPER"))
                .expect("meta")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(file_mode, 0o600, "secret files are 0600");
        }
        #[cfg(windows)]
        {
            let out = Command::new("icacls").arg(&fresh).output().expect("icacls");
            let acl = String::from_utf8_lossy(&out.stdout).to_lowercase();
            for broad in ["everyone", "builtin\\users", "authenticated users"] {
                assert!(!acl.contains(broad), "{broad} must not have access:\n{acl}");
            }
        }
        let existing = base.join("existing");
        fs::create_dir_all(&existing).expect("mkdir");
        let before = fs::metadata(&existing)
            .expect("meta")
            .permissions()
            .readonly();
        gen_secrets(&existing, false).expect("gen");
        assert_eq!(
            fs::metadata(&existing)
                .expect("meta")
                .permissions()
                .readonly(),
            before
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn the_committed_hook_equals_what_hooks_install_writes() {
        let committed = include_str!("../../../.githooks/pre-commit");
        assert_eq!(committed, HOOK_BODY);
    }

    #[test]
    fn base64url_matches_known_vectors() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn gen_secrets_writes_distinct_32_byte_secrets_and_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("hdd-xtask-gensecrets-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let written = gen_secrets(&dir, false).expect("gen");
        assert_eq!(written.len(), SECRET_NAMES.len());
        let a = fs::read_to_string(dir.join("HDD_MASTER_KEY")).expect("read");
        let b = fs::read_to_string(dir.join("HDD_PEPPER")).expect("read");
        assert_eq!(a.trim().len(), 43);
        assert_ne!(a, b);
        assert!(gen_secrets(&dir, false).expect("gen again").is_empty());
        assert_eq!(
            fs::read_to_string(dir.join("HDD_MASTER_KEY")).expect("read"),
            a
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
