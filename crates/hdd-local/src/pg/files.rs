//! Owner-only files and generated secrets. Secrets are written to files with owner-only permission (mode 0600 / 0700 on Unix,
//! an ACL with only the current user on Windows) and are never placed on a command line or in an environment variable.

use std::fs;
use std::io::Write;
use std::path::Path;

use super::{PgError, PgResult};

/// 32 random bytes as 64 hexadecimal characters.
pub fn random_hex_32() -> PgResult<String> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| PgError::Io(format!("no random bytes available: {e}")))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Create a directory (and parents) that only the owner can enter.
pub fn create_private_dir(path: &Path) -> PgResult<()> {
    let existed = path.exists();
    fs::create_dir_all(path)?;
    if !existed {
        restrict_dir(path)?;
    }
    Ok(())
}

/// Write a file that only the owner can read. An existing file is replaced.
pub fn write_private_file(path: &Path, contents: &[u8]) -> PgResult<()> {
    if let Some(dir) = path.parent() {
        create_private_dir(dir)?;
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(contents)?;
    f.sync_all()?;
    restrict_file(path)?;
    Ok(())
}

/// Make an existing file owner-only (for files written by another program or by `File::create`).
pub fn protect_file(path: &Path) -> PgResult<()> {
    restrict_file(path)
}

/// Read a small text file written by [`write_private_file`].
pub fn read_text(path: &Path) -> PgResult<String> {
    fs::read_to_string(path)
        .map_err(|e| PgError::Io(format!("cannot read {}: {e}", path.display())))
}

#[cfg(unix)]
fn restrict_file(p: &Path) -> PgResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(unix)]
fn restrict_dir(p: &Path) -> PgResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(windows)]
fn restrict_file(p: &Path) -> PgResult<()> {
    // A file in a directory restricted by `restrict_dir` inherits its ACL; set it explicitly as well, so that a file written
    // into a directory that was not created by this module is still owner-only.
    windows_acl(p, "F")
}

#[cfg(windows)]
fn restrict_dir(p: &Path) -> PgResult<()> {
    windows_acl(p, "(OI)(CI)F")
}

#[cfg(windows)]
fn windows_acl(p: &Path, rights: &str) -> PgResult<()> {
    let sid = current_sid()?;
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    let icacls = Path::new(&root).join("System32").join("icacls.exe");
    let out = std::process::Command::new(icacls)
        .arg(p)
        .args(["/inheritance:r", "/grant:r"])
        .arg(format!("*{sid}:{rights}"))
        .output()
        .map_err(|e| PgError::Io(format!("icacls failed to start: {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(PgError::Io(format!(
            "icacls refused to restrict {}: {}",
            p.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// SID of the current user from `whoami /user` (addressed through `SystemRoot` so that a Unix `whoami` earlier on `PATH` is
/// not used).
#[cfg(windows)]
pub fn current_sid() -> PgResult<String> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    let exe = Path::new(&root).join("System32").join("whoami.exe");
    let out = std::process::Command::new(exe)
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .map_err(|e| PgError::Io(format!("whoami failed to start: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let sid = text
        .trim()
        .rsplit(',')
        .next()
        .unwrap_or("")
        .trim_matches('"')
        .to_owned();
    if sid.starts_with("S-1-") {
        Ok(sid)
    } else {
        Err(PgError::Io(
            "cannot determine the current user SID; refusing to change an ACL".into(),
        ))
    }
}

/// True when only the owner can access the path (Unix: no group or other bits; Windows: the ACL names only the current user,
/// SYSTEM and the Administrators group).
pub fn is_owner_only(path: &Path) -> PgResult<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)?.permissions().mode();
        Ok(mode & 0o077 == 0)
    }
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
        let icacls = Path::new(&root).join("System32").join("icacls.exe");
        let out = std::process::Command::new(icacls)
            .arg(path)
            .output()
            .map_err(|e| PgError::Io(format!("icacls failed to start: {e}")))?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let sid = current_sid()?;
        // every ACE line looks like `DOMAIN\name:(perm)` or `*SID:(perm)`; only the allowed principals may appear
        let allowed = [
            "NT AUTHORITY\\SYSTEM",
            "BUILTIN\\Administrators",
            sid.as_str(),
        ];
        let me = std::env::var("USERNAME").unwrap_or_default();
        let ok = text
            .lines()
            .filter(|l| l.contains(":("))
            .map(|l| {
                l.trim()
                    .trim_start_matches(&path.display().to_string())
                    .trim()
            })
            .all(|l| {
                allowed.iter().any(|a| l.starts_with(a))
                    || (!me.is_empty() && l.contains(&format!("\\{me}:")))
            });
        Ok(ok)
    }
}
