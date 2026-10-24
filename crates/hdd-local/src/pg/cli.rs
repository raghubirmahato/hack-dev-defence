//! The commands behind `cargo xtask db up|down|reset|status` and `hdd-local db|backup|restore`, kept here so that both front
//! ends do the same thing.

use std::path::{Path, PathBuf};

use super::cluster::{Embedded, PgConfig, Status, UpReport};
use super::fetch::download;
use super::{PgError, PgResult};

/// Options of `db up`.
#[derive(Debug, Clone, Default)]
pub struct UpOptions {
    /// An archive supplied by the operator (offline bundle). It is verified like a downloaded one.
    pub bundle: Option<PathBuf>,
    /// Download the pinned archive when none is installed or cached.
    pub download: bool,
    /// Egress allowlist entries for the download (the operator's approval of the destination).
    pub allow: Vec<String>,
}

/// The default data directory of the local profile: `HDD_DATA_DIR`, else the per-OS user data directory.
pub fn default_data_dir() -> PgResult<PathBuf> {
    if let Ok(d) = std::env::var("HDD_DATA_DIR")
        && !d.is_empty()
    {
        let p = PathBuf::from(d);
        if !p.is_absolute() {
            return Err(PgError::Io(
                "HDD_DATA_DIR must be an absolute path (a relative one would depend on the working directory)".into(),
            ));
        }
        return Ok(p);
    }
    let var = |k: &str| {
        std::env::var(k)
            .ok()
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let found = if cfg!(windows) {
        var("LOCALAPPDATA").map(|p| p.join("hdd"))
    } else if cfg!(target_os = "macos") {
        var("HOME").map(|p| p.join("Library").join("Application Support").join("hdd"))
    } else {
        var("XDG_DATA_HOME")
            .map(|p| p.join("hdd"))
            .or_else(|| var("HOME").map(|p| p.join(".local").join("share").join("hdd")))
    };
    found.ok_or_else(|| PgError::Io("cannot tell the user data directory; set HDD_DATA_DIR".into()))
}

/// Manager for a data directory.
pub fn manager(data_dir: &Path) -> PgResult<Embedded> {
    Embedded::new(PgConfig::new(data_dir))
}

/// `db up`: install (supplied, cached or downloaded archive), initialize, start, create the owner and the database.
pub fn up(data_dir: &Path, opts: &UpOptions) -> PgResult<UpReport> {
    let em = manager(data_dir)?;
    let target = em.manifest().for_current()?.clone();
    let cached = em.config().layout.cache().join(&target.file);
    let archive: Option<PathBuf> = if em.is_installed() {
        None
    } else if let Some(b) = &opts.bundle {
        Some(b.clone())
    } else if cached.is_file() {
        Some(cached)
    } else if opts.download {
        Some(download(
            em.manifest(),
            &target,
            &opts.allow,
            &em.config().layout.cache(),
        )?)
    } else {
        None
    };
    em.up(archive.as_deref())
}

/// `db status` text.
pub fn status(data_dir: &Path) -> PgResult<String> {
    let em = manager(data_dir)?;
    let installed = em.is_installed();
    let init = em.is_initialized();
    let st = em.status()?;
    let ready = matches!(st, Status::Running { .. }) && em.is_ready();
    Ok(format!(
        "PostgreSQL {} (embedded)\n  data directory: {}\n  installed: {installed}\n  initialized: {init}\n  running: {}\n  accepting connections: {ready}\n  hdd_embedded_db_up: {}\n",
        em.manifest().postgres_version,
        data_dir.display(),
        match st {
            Status::Running { port } => format!("yes, 127.0.0.1:{port}"),
            Status::Stopped => "no".to_owned(),
        },
        u8::from(em.telemetry().is_up()),
    ))
}
