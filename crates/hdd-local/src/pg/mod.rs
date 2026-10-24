//! The embedded PostgreSQL manager (T-0563): a real, private PostgreSQL that HDD installs, starts, stops and backs up, so that
//! a machine without Docker or a database server can build, test and run the local profile against real Postgres (R-31).
//!
//! * [`manifest`]: the pinned distribution (version, per-OS archive, size, SHA-256) and its download URL.
//! * [`fetch`]: the download, through the single egress path (R-22) and only to an allowlisted host.
//! * [`archive`]: checksum verification (a wrong digest refuses the archive before anything is extracted) and a bounded,
//!   path-checked extraction.
//! * [`cluster`]: `initdb`, configuration, start, stop, status, role and database creation.
//! * [`backup`]: encrypted logical backups and restore.
//! * [`sys`]: disk space, memory, free port.
//! * [`files`]: owner-only files and generated secrets.
//! * [`telemetry`]: `hdd_embedded_db_up` and the `runtime.embedded_db` audit events.
//!
//! Layout under the data directory:
//!
//! ```text
//! <data>/postgres/<version>/   the installed distribution (bin/, lib/, share/)
//! <data>/pgdata/               the cluster (scram-sha-256 only, loopback only, data checksums on)
//! <data>/secrets/              generated passwords, the connection URL file, the pgpass file, the backup key (owner only)
//! <data>/cache/                downloaded or supplied archives
//! <data>/backups/              encrypted logical backups
//! <data>/logs/                 server logs
//! <data>/pg.version            version marker; a different major version is migrated by dump and restore, never in place
//! ```

use std::fmt;
use std::path::{Path, PathBuf};

pub mod archive;
pub mod backup;
pub mod cli;
pub mod cluster;
pub mod fetch;
pub mod files;
pub mod manifest;
pub mod sys;
pub mod telemetry;

/// Why an embedded-database operation failed. Messages say what to do next and never contain a password or a connection URL.
#[derive(Debug)]
pub enum PgError {
    /// No distribution is pinned for this operating system and architecture.
    UnsupportedPlatform(String),
    /// The pinned manifest is malformed.
    Manifest(String),
    /// The archive does not match the pinned digest or size; nothing was extracted or started.
    Checksum {
        /// What was compared.
        what: &'static str,
        /// The pinned value (shortened).
        expected: String,
        /// The value found (shortened).
        actual: String,
    },
    /// The download failed or was denied by the egress policy.
    Download(String),
    /// The archive could not be unpacked safely.
    Extract(String),
    /// A file system operation failed.
    Io(String),
    /// A bundled program failed.
    Process {
        /// Program name.
        program: String,
        /// Exit code, when it ran.
        code: Option<i32>,
        /// The last lines of its error output (secrets are never passed on its command line, so none appear here).
        detail: String,
    },
    /// No free port in the configured range (`ERR-LOCAL-004` guidance).
    NoFreePort {
        /// The range that was searched.
        range: (u16, u16),
    },
    /// Less free disk space than the minimum.
    DiskSpace {
        /// Bytes free.
        free: u64,
        /// Bytes required.
        needed: u64,
    },
    /// The server did not become ready in time (`ERR-LOCAL-004`).
    NotReady(String),
    /// The data directory was written by another major version.
    VersionMismatch {
        /// Marker found.
        found: String,
        /// Version of this build.
        wanted: String,
    },
    /// The operation needs the database to be stopped (or running).
    State(String),
    /// A backup file is damaged, truncated or encrypted with another key.
    Backup(String),
}

impl fmt::Display for PgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PgError::UnsupportedPlatform(p) => write!(
                f,
                "no embedded PostgreSQL is pinned for {p}; use runtime.local.database: external (HDD_DATABASE_URL) or compose"
            ),
            PgError::Manifest(m) => write!(f, "the pinned PostgreSQL manifest is invalid: {m}"),
            PgError::Checksum {
                what,
                expected,
                actual,
            } => write!(
                f,
                "the archive does not match the pinned {what} (expected {expected}, found {actual}); it was refused and nothing was installed or started"
            ),
            PgError::Download(m) => write!(f, "download failed: {m}"),
            PgError::Extract(m) => write!(f, "the archive could not be unpacked safely: {m}"),
            PgError::Io(m) => write!(f, "{m}"),
            PgError::Process {
                program,
                code,
                detail,
            } => write!(
                f,
                "{program} failed{}: {detail}",
                code.map(|c| format!(" (exit {c})")).unwrap_or_default()
            ),
            PgError::NoFreePort { range } => write!(
                f,
                "ERR-LOCAL-004: no free port between {} and {}; stop whatever uses them or widen runtime.local ports",
                range.0, range.1
            ),
            PgError::DiskSpace { free, needed } => write!(
                f,
                "only {} MiB of disk space are free in the data directory; the embedded database needs at least {} MiB",
                free / (1024 * 1024),
                needed / (1024 * 1024)
            ),
            PgError::NotReady(m) => write!(
                f,
                "ERR-LOCAL-004: the embedded database did not become ready: {m}; run `hdd-local doctor` (T-0564) or read <data>/logs"
            ),
            PgError::VersionMismatch { found, wanted } => write!(
                f,
                "the data directory belongs to PostgreSQL {found}, this build ships {wanted}; migrate with `hdd-local backup`, a fresh data directory and `hdd-local restore` (never an in-place upgrade)"
            ),
            PgError::State(m) => write!(f, "{m}"),
            PgError::Backup(m) => write!(f, "backup problem: {m}"),
        }
    }
}

impl std::error::Error for PgError {}

impl From<std::io::Error> for PgError {
    fn from(e: std::io::Error) -> Self {
        PgError::Io(e.to_string())
    }
}

/// Result of an embedded-database operation.
pub type PgResult<T> = Result<T, PgError>;

/// Where everything lives, derived from the data directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// The data directory of the local profile (`HDD_DATA_DIR`).
    pub base: PathBuf,
}

impl Layout {
    /// Layout under `base`.
    pub fn new(base: impl Into<PathBuf>) -> Layout {
        Layout { base: base.into() }
    }

    /// Installed distribution of a version.
    pub fn install_dir(&self, version: &str) -> PathBuf {
        self.base.join("postgres").join(version)
    }

    /// The cluster directory.
    pub fn pgdata(&self) -> PathBuf {
        self.base.join("pgdata")
    }

    /// Secrets directory (owner only).
    pub fn secrets(&self) -> PathBuf {
        self.base.join("secrets")
    }

    /// Cache of archives.
    pub fn cache(&self) -> PathBuf {
        self.base.join("cache")
    }

    /// Backups.
    pub fn backups(&self) -> PathBuf {
        self.base.join("backups")
    }

    /// Server logs.
    pub fn logs(&self) -> PathBuf {
        self.base.join("logs")
    }

    /// Version marker file.
    pub fn version_marker(&self) -> PathBuf {
        self.base.join("pg.version")
    }

    /// File with the connection URL of `hdd_owner` (services read this file, never a command line or an environment variable).
    pub fn owner_url_file(&self) -> PathBuf {
        self.secrets().join("hdd_owner.url")
    }
}

/// Names fixed by the specification and the roles of T-0105.
pub mod names {
    /// The superuser the manager creates (not `postgres`, so a stray default name does not work).
    pub const SUPERUSER: &str = "hdd_admin";
    /// The role that owns the database and runs the migrations of T-0105.
    pub const OWNER: &str = "hdd_owner";
    /// The database.
    pub const DATABASE: &str = "hdd";
}

/// Last lines of a text, for error details.
pub(crate) fn tail(text: &str, lines: usize) -> String {
    let all: Vec<&str> = text.lines().collect();
    let start = all.len().saturating_sub(lines);
    all.get(start..).unwrap_or(&[]).join("\n")
}

/// `path` relative to the layout base, for messages.
pub(crate) fn shown(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_review;
