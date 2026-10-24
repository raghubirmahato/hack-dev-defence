//! Host facts the manager needs: free disk space (preflight, at least 2 GiB), total memory (sizes `shared_buffers`) and a free
//! loopback port. Programs are addressed through absolute system paths on Windows so that a look-alike earlier on `PATH` is not
//! run. Parsing is separate from running so that it is tested without the programs.

use std::net::{Ipv4Addr, TcpListener};
use std::path::Path;
use std::process::Command;

use super::{PgError, PgResult};

/// The embedded database refuses to start with less free space than this (T-0563 step 6).
pub const MIN_FREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[cfg(windows)]
fn powershell() -> std::path::PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    Path::new(&root)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe")
}

/// Parse the output of `df -Pk <path>` (POSIX format, 1024-byte blocks) into free bytes.
pub fn parse_df(output: &str) -> Option<u64> {
    let line = output.lines().filter(|l| !l.trim().is_empty()).nth(1)?;
    let cols: Vec<&str> = line.split_whitespace().collect();
    // Filesystem 1024-blocks Used Available Capacity Mounted-on
    let available: u64 = cols.get(3)?.parse().ok()?;
    available.checked_mul(1024)
}

/// The drive letter of an absolute Windows path (`D:\x` or `D:/x`).
pub fn drive_letter(path: &Path) -> Option<char> {
    let s = path.to_string_lossy();
    let mut chars = s.chars();
    let letter = chars.next()?;
    (letter.is_ascii_alphabetic() && chars.next() == Some(':')).then(|| letter.to_ascii_uppercase())
}

/// Free bytes on the volume that holds `path` (the path must exist).
pub fn free_disk_bytes(path: &Path) -> PgResult<u64> {
    #[cfg(windows)]
    {
        let abs = std::fs::canonicalize(path)?;
        let shown = abs.to_string_lossy().trim_start_matches(r"\\?\").to_owned();
        let letter = drive_letter(Path::new(&shown)).ok_or_else(|| {
            PgError::Io(format!("cannot tell the drive of {shown}; network paths are not supported for the data directory"))
        })?;
        let script = format!("[System.IO.DriveInfo]::new('{letter}').AvailableFreeSpace");
        let out = Command::new(powershell())
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .map_err(|e| {
                PgError::Io(format!(
                    "cannot run powershell to read the free disk space: {e}"
                ))
            })?;
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse::<u64>()
            .map_err(|_| {
                PgError::Io("could not read the free disk space of the data directory".into())
            })
    }
    #[cfg(not(windows))]
    {
        let out = Command::new("df")
            .arg("-Pk")
            .arg(path)
            .output()
            .map_err(|e| PgError::Io(format!("cannot run df to read the free disk space: {e}")))?;
        parse_df(&String::from_utf8_lossy(&out.stdout)).ok_or_else(|| {
            PgError::Io("could not read the free disk space of the data directory".into())
        })
    }
}

/// Refuse when less than `needed` bytes are free where `path` lives.
pub fn require_free_space(path: &Path, needed: u64) -> PgResult<u64> {
    let free = free_disk_bytes(path)?;
    if free < needed {
        Err(PgError::DiskSpace { free, needed })
    } else {
        Ok(free)
    }
}

/// Parse `/proc/meminfo` (`MemTotal: 16316412 kB`).
pub fn parse_meminfo(text: &str) -> Option<u64> {
    let line = text.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kb.checked_mul(1024)
}

/// Total physical memory in bytes, or `None` when it cannot be read (the caller then assumes a small machine).
pub fn total_memory_bytes() -> Option<u64> {
    #[cfg(windows)]
    {
        let out = Command::new(powershell())
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
            ])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout).trim().parse().ok()
    }
    #[cfg(target_os = "linux")]
    {
        parse_meminfo(&std::fs::read_to_string("/proc/meminfo").ok()?)
    }
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("/usr/sbin/sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout).trim().parse().ok()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// Memory settings for a machine with `total` bytes of RAM (`None`: assume 4 GiB). A quarter of the memory for
/// `shared_buffers` (128 MiB to 2 GiB), half for `effective_cache_size`; the machine keeps the rest for HDD and the browser.
pub fn memory_settings(total: Option<u64>) -> (u64, u64) {
    let total_mb = total.map_or(4096, |t| t / (1024 * 1024)).max(512);
    let shared = (total_mb / 4).clamp(128, 2048);
    let cache = (total_mb / 2).max(shared * 2);
    (shared, cache)
}

/// First port of `range` that nothing listens on (checked by binding the loopback address), preferring `preferred`.
pub fn pick_port(range: (u16, u16), preferred: Option<u16>) -> PgResult<u16> {
    let free = |p: u16| TcpListener::bind((Ipv4Addr::LOCALHOST, p)).is_ok();
    if let Some(p) = preferred
        && p >= range.0
        && p <= range.1
        && free(p)
    {
        return Ok(p);
    }
    (range.0..=range.1)
        .find(|p| free(*p))
        .ok_or(PgError::NoFreePort { range })
}

/// True when something already listens on the loopback port.
pub fn port_in_use(port: u16) -> bool {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_err()
}
