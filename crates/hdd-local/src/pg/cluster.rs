//! The cluster: install, `initdb`, configuration, lifecycle, roles.
//!
//! Security posture of what this module creates (R-31: embedded does not mean weaker):
//! * `scram-sha-256` is the only authentication method, for both `initdb` and `pg_hba.conf`; there is no `trust` line and no
//!   `local` (socket) line;
//! * the server listens on `127.0.0.1` only, on a port chosen from a configured range;
//! * `fsync`, `full_page_writes` and data checksums are on;
//! * the superuser is `hdd_admin` with a generated password; `hdd_owner` owns the database and runs the migrations;
//! * every password lives in an owner-only file under `<data>/secrets/` and is given to the bundled programs through a
//!   `PGPASSFILE`, never on a command line or in an environment variable. The connection URL for services is a file too.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use super::archive::{extract_tar_gz, find_root, verify_archive};
use super::files::{
    create_private_dir, is_owner_only, random_hex_32, read_text, write_private_file,
};
use super::manifest::Manifest;
use super::sys::{
    MIN_FREE_BYTES, memory_settings, pick_port, require_free_space, total_memory_bytes,
};
use super::telemetry::Telemetry;
use super::{Layout, PgError, PgResult, names, tail};

/// Settings of the manager.
#[derive(Debug, Clone)]
pub struct PgConfig {
    /// Where everything lives.
    pub layout: Layout,
    /// Ports the server may use (loopback only).
    pub port_range: (u16, u16),
    /// Minimum free disk space.
    pub min_free_bytes: u64,
    /// How long `start` waits for readiness before `ERR-LOCAL-004`.
    pub start_timeout: Duration,
    /// How long `stop` waits for a fast shutdown.
    pub stop_timeout: Duration,
}

impl PgConfig {
    /// Defaults for a data directory: ports 54320 to 54419, 2 GiB free, 60 s start, 30 s stop.
    pub fn new(base: impl Into<PathBuf>) -> PgConfig {
        PgConfig {
            layout: Layout::new(base),
            port_range: (54_320, 54_419),
            min_free_bytes: MIN_FREE_BYTES,
            start_timeout: Duration::from_secs(60),
            stop_timeout: Duration::from_secs(30),
        }
    }
}

/// Holds the exclusive lock of the data directory until dropped.
#[derive(Debug)]
pub struct LockGuard(#[allow(dead_code, reason = "held for its Drop")] fs::File);

/// State of the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Running and listening on this port.
    Running {
        /// The loopback port.
        port: u16,
    },
    /// Not running.
    Stopped,
}

/// What `up` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpReport {
    /// The archive was installed by this call.
    pub installed: bool,
    /// The cluster was initialized by this call.
    pub initialized: bool,
    /// The server was started by this call (false: it was already running).
    pub started: bool,
    /// The port.
    pub port: u16,
    /// File with the connection URL of `hdd_owner`.
    pub url_file: PathBuf,
}

/// The embedded PostgreSQL of one data directory.
pub struct Embedded {
    cfg: PgConfig,
    manifest: Manifest,
    telemetry: Arc<Telemetry>,
}

const BEGIN: &str =
    "# >>> hdd managed settings (rewritten at every start; edit nothing between the markers)";
const END: &str = "# <<< hdd managed settings";

/// The managed block of `postgresql.conf`.
pub fn render_conf(port: u16, shared_mb: u64, cache_mb: u64, log_dir: &str) -> String {
    // a single quote in the path (a user name such as O'Brien) must not end the quoted value
    let log_dir = log_dir.replace('\'', "''");
    format!(
        "{BEGIN}\n\
listen_addresses = '127.0.0.1'\n\
port = {port}\n\
max_connections = 100\n\
password_encryption = 'scram-sha-256'\n\
ssl = off\n\
fsync = on\n\
synchronous_commit = on\n\
full_page_writes = on\n\
shared_buffers = {shared_mb}MB\n\
effective_cache_size = {cache_mb}MB\n\
work_mem = 4MB\n\
logging_collector = on\n\
log_directory = '{log_dir}'\n\
log_filename = 'postgres-%a.log'\n\
log_truncate_on_rotation = on\n\
log_rotation_age = 1d\n\
log_min_messages = warning\n\
log_connections = off\n\
{END}\n"
    )
}

/// Replace (or append) the managed block in the text of a `postgresql.conf`.
pub fn apply_conf(existing: &str, block: &str) -> String {
    let mut out = String::new();
    let mut skipping = false;
    for line in existing.lines() {
        if line.starts_with(BEGIN) {
            skipping = true;
            continue;
        }
        if skipping {
            if line.starts_with(END) {
                skipping = false;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.push_str(block);
    out
}

/// The whole `pg_hba.conf`: scram-sha-256 on loopback, nothing else.
pub const PG_HBA: &str = "# Managed by hdd-local. scram-sha-256 only, loopback only; there is no trust line and no local-socket line.\n\
# TYPE  DATABASE  USER  ADDRESS        METHOD\n\
host    all       all   127.0.0.1/32   scram-sha-256\n\
host    all       all   ::1/128        scram-sha-256\n";

/// Text for the inside of a PowerShell single-quoted string: the ASCII quote and the typographic quotes PowerShell also treats as
/// quote characters are doubled.
pub fn ps_single_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        out.push(c);
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            out.push(c);
        }
    }
    out
}

/// Base64 of the UTF-16LE bytes of a script (the form `powershell -EncodedCommand` expects).
pub fn base64_utf16le(s: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; // hdd-secret-scan:allow (the base64 alphabet)
    let bytes: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        let idx = |shift: u32| {
            T.get(((n >> shift) & 63) as usize)
                .copied()
                .map_or('?', char::from)
        };
        out.push(idx(18));
        out.push(idx(12));
        out.push(if chunk.len() > 1 { idx(6) } else { '=' });
        out.push(if chunk.len() > 2 { idx(0) } else { '=' });
    }
    out
}

fn slash(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn exe(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}

impl Embedded {
    /// Manager for `cfg` with the manifest compiled into this build.
    pub fn new(cfg: PgConfig) -> PgResult<Embedded> {
        Embedded::with_manifest(cfg, Manifest::embedded()?)
    }

    /// Manager with an explicit manifest (tests).
    pub fn with_manifest(cfg: PgConfig, manifest: Manifest) -> PgResult<Embedded> {
        Ok(Embedded {
            cfg,
            manifest,
            telemetry: Arc::new(Telemetry::new()),
        })
    }

    /// Use a shared telemetry sink.
    #[must_use]
    pub fn with_telemetry(mut self, t: Arc<Telemetry>) -> Embedded {
        self.telemetry = t;
        self
    }

    /// The telemetry sink (`hdd_embedded_db_up`, audit events).
    pub fn telemetry(&self) -> &Arc<Telemetry> {
        &self.telemetry
    }

    /// The configuration.
    pub fn config(&self) -> &PgConfig {
        &self.cfg
    }

    /// The manifest in use.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    fn layout(&self) -> &Layout {
        &self.cfg.layout
    }

    fn install_dir(&self) -> PathBuf {
        self.layout().install_dir(&self.manifest.postgres_version)
    }

    /// Path of a bundled program.
    pub fn bin(&self, name: &str) -> PathBuf {
        self.install_dir().join("bin").join(exe(name))
    }

    /// True when the distribution is installed.
    pub fn is_installed(&self) -> bool {
        self.bin("pg_ctl").is_file()
            && self.bin("initdb").is_file()
            && self.bin("postgres").is_file()
    }

    /// True when the cluster directory holds a cluster.
    pub fn is_initialized(&self) -> bool {
        self.layout().pgdata().join("PG_VERSION").is_file()
    }

    fn major(&self) -> &str {
        self.manifest
            .postgres_version
            .split('.')
            .next()
            .unwrap_or("")
    }

    fn marker_text(&self) -> String {
        format!(
            "postgres_version={}\nmajor={}\n",
            self.manifest.postgres_version,
            self.major()
        )
    }

    /// Refuse to use a data directory written by another major version.
    pub fn check_version_marker(&self) -> PgResult<()> {
        let path = self.layout().version_marker();
        if !path.is_file() {
            return Ok(());
        }
        let text = read_text(&path)?;
        let found_major = text
            .lines()
            .find_map(|l| l.strip_prefix("major="))
            .unwrap_or("")
            .trim()
            .to_owned();
        if found_major == self.major() {
            Ok(())
        } else {
            Err(PgError::VersionMismatch {
                found: text
                    .lines()
                    .find_map(|l| l.strip_prefix("postgres_version="))
                    .unwrap_or("unknown")
                    .trim()
                    .to_owned(),
                wanted: self.manifest.postgres_version.clone(),
            })
        }
    }

    /// The environment of every bundled program: nothing inherited except what the program needs to run. On Windows that
    /// includes the variables the system components expand (`SystemDrive`, `ProgramData`, ...): without them a component can
    /// write a literal `%SystemDrive%` directory into the working directory (observed during T-0563).
    fn clean_env(cmd: &mut Command, bin_dir: &Path) {
        cmd.env_clear();
        let mut path = bin_dir.as_os_str().to_owned();
        if cfg!(windows)
            && let Ok(root) = std::env::var("SystemRoot")
        {
            path.push(";");
            path.push(Path::new(&root).join("System32"));
        }
        cmd.env("PATH", path);
        for var in [
            "SystemRoot",
            "SystemDrive",
            "windir",
            "ComSpec",
            "PATHEXT",
            "ProgramData",
            "ProgramFiles",
            "ALLUSERSPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "HOMEDRIVE",
            "HOMEPATH",
            "USERNAME",
            "USERDOMAIN",
            "COMPUTERNAME",
            "PROCESSOR_ARCHITECTURE",
            "NUMBER_OF_PROCESSORS",
            "OS",
            "TEMP",
            "TMP",
            "TMPDIR",
            "HOME",
            "USERPROFILE",
            "LANG",
        ] {
            if let Ok(v) = std::env::var(var) {
                cmd.env(var, v);
            }
        }
    }

    pub(super) fn command(&self, program: &str) -> Command {
        let mut cmd = Command::new(self.bin(program));
        Self::clean_env(&mut cmd, &self.install_dir().join("bin"));
        cmd.env("PGPASSFILE", self.pgpass());
        cmd.stdin(Stdio::null());
        cmd
    }

    fn pgpass(&self) -> PathBuf {
        self.layout().secrets().join("pgpass")
    }

    fn run(&self, program: &str, mut cmd: Command, stdin: Option<&str>) -> PgResult<Output> {
        use std::io::Write;
        if stdin.is_some() {
            cmd.stdin(Stdio::piped());
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| PgError::Process {
            program: program.to_owned(),
            code: None,
            detail: format!("cannot start: {e}"),
        })?;
        if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
            pipe.write_all(text.as_bytes())?;
        }
        let out = child.wait_with_output()?;
        Ok(out)
    }

    pub(super) fn run_ok(
        &self,
        program: &str,
        cmd: Command,
        stdin: Option<&str>,
    ) -> PgResult<Output> {
        let out = self.run(program, cmd, stdin)?;
        if out.status.success() {
            Ok(out)
        } else {
            let mut text = String::from_utf8_lossy(&out.stderr).into_owned();
            if text.trim().is_empty() {
                text = String::from_utf8_lossy(&out.stdout).into_owned();
            }
            Err(PgError::Process {
                program: program.to_owned(),
                code: out.status.code(),
                detail: tail(text.trim(), 12),
            })
        }
    }

    /// Create the data directory owner-only. A directory that already exists must be owner-only too: another local user who
    /// can write into it could replace the server binaries that run as this user.
    pub fn ensure_base(&self) -> PgResult<()> {
        let base = &self.layout().base;
        if base.exists() {
            if !is_owner_only(base)? {
                return Err(PgError::State(format!(
                    "{} can be used by other users of this computer; use a new directory (it is created owner-only) or restrict this one to yourself (chmod 700, or icacls /inheritance:r /grant:r <you>:(OI)(CI)F)",
                    base.display()
                )));
            }
            Ok(())
        } else {
            create_private_dir(base)
        }
    }

    /// Exclusive lock on the data directory for commands that change it, so that two `db up` runs cannot both initialize the
    /// cluster. Released when the guard is dropped (or the process ends).
    pub(super) fn lock(&self) -> PgResult<LockGuard> {
        self.ensure_base()?;
        let path = self.layout().base.join(".hdd-local.lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| PgError::Io(format!("cannot open the lock file: {e}")))?;
        match file.try_lock() {
            Ok(()) => Ok(LockGuard(file)),
            Err(fs::TryLockError::WouldBlock) => Err(PgError::State(
                "another hdd-local command is using this data directory; wait for it to finish"
                    .into(),
            )),
            Err(fs::TryLockError::Error(e)) => {
                Err(PgError::Io(format!("cannot lock the data directory: {e}")))
            }
        }
    }

    // -------------------------------------------------------------------------------------------------------------------
    // install

    /// Install the distribution from an archive: free-space preflight, digest and size check, bounded extraction into a
    /// temporary directory and an atomic rename. A wrong archive changes nothing (A2).
    pub fn install(&self, archive: &Path) -> PgResult<()> {
        let layout = self.layout();
        self.ensure_base()?;
        require_free_space(&layout.base, self.cfg.min_free_bytes)?;
        let target = self.manifest.for_current()?;
        // Verify and extract one private copy: the file the caller named could be swapped between the check and the unpacking.
        create_private_dir(&layout.cache())?;
        let copy = layout
            .cache()
            .join(format!(".verified-{}.tar.gz", std::process::id()));
        fs::copy(archive, &copy)
            .map_err(|e| PgError::Io(format!("cannot copy the archive: {e}")))?;
        let result = self.install_verified_copy(&copy, target);
        let _ = fs::remove_file(&copy);
        result
    }

    fn install_verified_copy(
        &self,
        archive: &Path,
        target: &super::manifest::Target,
    ) -> PgResult<()> {
        verify_archive(archive, target)?;
        let final_dir = self.install_dir();
        let parent = final_dir
            .parent()
            .ok_or_else(|| PgError::Io("no parent directory for the installation".into()))?
            .to_path_buf();
        create_private_dir(&parent)?;
        let partial = parent.join(format!(".partial-{}", std::process::id()));
        if partial.exists() {
            fs::remove_dir_all(&partial)?;
        }
        let result = (|| {
            extract_tar_gz(archive, &partial)?;
            let root = find_root(&partial)?;
            if final_dir.exists() {
                fs::remove_dir_all(&final_dir)?;
            }
            fs::rename(&root, &final_dir)?;
            Ok::<(), PgError>(())
        })();
        let _ = fs::remove_dir_all(&partial);
        result?;
        if !self.is_installed() {
            return Err(PgError::Extract(
                "the archive does not contain pg_ctl, initdb and postgres".into(),
            ));
        }
        self.telemetry.audit(
            "installed",
            &format!("PostgreSQL {}", self.manifest.postgres_version),
        );
        Ok(())
    }

    // -------------------------------------------------------------------------------------------------------------------
    // initialization

    /// `initdb` with generated secrets, the managed configuration and the restrictive `pg_hba.conf`.
    pub fn init(&self) -> PgResult<()> {
        if !self.is_installed() {
            return Err(PgError::State(
                "PostgreSQL is not installed; run `db up` with an archive first".into(),
            ));
        }
        if self.is_initialized() {
            return Ok(());
        }
        self.check_version_marker()?;
        let layout = self.layout();
        let pgdata = layout.pgdata();
        // refuse before any secret is written: a directory that is not a cluster is never touched
        if pgdata.exists() && fs::read_dir(&pgdata)?.next().is_some() {
            return Err(PgError::State(format!(
                "{} exists and is not an initialized cluster; move it away or run `db reset`",
                super::shown(&layout.base, &pgdata)
            )));
        }
        create_private_dir(&layout.secrets())?;
        create_private_dir(&layout.logs())?;
        let admin_pw = random_hex_32()?;
        let owner_pw = random_hex_32()?;
        write_private_file(&layout.secrets().join("pg_admin.pw"), admin_pw.as_bytes())?;
        write_private_file(&layout.secrets().join("hdd_owner.pw"), owner_pw.as_bytes())?;
        let key_file = layout.secrets().join("backup.key");
        if !key_file.is_file() {
            // an existing key is kept: it protects backups made before a reset
            write_private_file(&key_file, random_hex_32()?.as_bytes())?;
        }
        let pwfile = layout.secrets().join("initdb.pwfile");
        write_private_file(
            &pwfile,
            format!(
                "{admin_pw}
"
            )
            .as_bytes(),
        )?;
        let mut cmd = self.command("initdb");
        cmd.arg("-D")
            .arg(&pgdata)
            .args([
                "-U",
                names::SUPERUSER,
                "-A",
                "scram-sha-256",
                "-E",
                "UTF8",
                "--no-locale",
                "--data-checksums",
            ])
            .arg(format!("--pwfile={}", pwfile.display()));
        let res = self.run_ok("initdb", cmd, None);
        let _ = fs::remove_file(&pwfile);
        res?;
        fs::write(pgdata.join("pg_hba.conf"), PG_HBA)?;
        write_private_file(&layout.version_marker(), self.marker_text().as_bytes())?;
        self.telemetry.audit(
            "initialized",
            "cluster created with data checksums and scram-sha-256",
        );
        Ok(())
    }

    fn write_conf(&self, port: u16) -> PgResult<()> {
        let conf_path = self.layout().pgdata().join("postgresql.conf");
        let existing = fs::read_to_string(&conf_path)?;
        let (shared, cache) = memory_settings(total_memory_bytes());
        let block = render_conf(port, shared, cache, &slash(&self.layout().logs()));
        fs::write(&conf_path, apply_conf(&existing, &block))?;
        // pgpass for this port: both roles, nothing else
        let admin = read_text(&self.layout().secrets().join("pg_admin.pw"))?;
        let owner = read_text(&self.layout().secrets().join("hdd_owner.pw"))?;
        let pass = format!(
            "127.0.0.1:{port}:*:{}:{}\n127.0.0.1:{port}:*:{}:{}\n",
            names::SUPERUSER,
            admin.trim(),
            names::OWNER,
            owner.trim()
        );
        write_private_file(&self.pgpass(), pass.as_bytes())?;
        Ok(())
    }

    // -------------------------------------------------------------------------------------------------------------------
    // lifecycle

    /// Is the server running, and on which port?
    pub fn status(&self) -> PgResult<Status> {
        if !self.is_installed() || !self.is_initialized() {
            return Ok(Status::Stopped);
        }
        let mut cmd = self.command("pg_ctl");
        cmd.arg("status").arg("-D").arg(self.layout().pgdata());
        let out = self.run("pg_ctl", cmd, None)?;
        if out.status.code() != Some(0) {
            return Ok(Status::Stopped);
        }
        let pid_file = self.layout().pgdata().join("postmaster.pid");
        let text = fs::read_to_string(pid_file).unwrap_or_default();
        let port = text
            .lines()
            .nth(3)
            .and_then(|l| l.trim().parse::<u16>().ok())
            .ok_or_else(|| {
                PgError::State(
                    "the server runs but its port could not be read from postmaster.pid".into(),
                )
            })?;
        Ok(Status::Running { port })
    }

    /// Start the server and wait until it accepts connections. Returns the port.
    pub fn start(&self) -> PgResult<u16> {
        if let Status::Running { port } = self.status()? {
            self.telemetry.set_up(true);
            return Ok(port);
        }
        if !self.is_initialized() {
            return Err(PgError::State(
                "the cluster is not initialized; run `db up`".into(),
            ));
        }
        self.check_version_marker()?;
        require_free_space(&self.layout().base, self.cfg.min_free_bytes)?;
        let preferred = fs::read_to_string(self.layout().base.join("pg.port"))
            .ok()
            .and_then(|t| t.trim().parse::<u16>().ok());
        let port = pick_port(self.cfg.port_range, preferred)?;
        self.write_conf(port)?;
        fs::write(self.layout().base.join("pg.port"), port.to_string())?;
        create_private_dir(&self.layout().logs())?;
        let started_log = self.layout().logs().join("pg_ctl.log");
        let server_log = self.layout().logs().join("startup.log");
        let timeout = self.cfg.start_timeout.as_secs().to_string();
        let args: Vec<String> = vec![
            "start".into(),
            "-D".into(),
            self.layout().pgdata().display().to_string(),
            "-l".into(),
            server_log.display().to_string(),
            "-w".into(),
            "-t".into(),
            timeout,
        ];
        let status = self.run_pg_ctl_start(&args, &started_log)?;
        if !status.success() {
            let mut detail = fs::read_to_string(&started_log).unwrap_or_default();
            detail.push_str(&fs::read_to_string(&server_log).unwrap_or_default());
            self.telemetry.set_up(false);
            self.telemetry
                .audit("start_failed", "pg_ctl start did not succeed");
            return Err(PgError::NotReady(tail(detail.trim(), 12)));
        }
        // The launcher's exit code is not proof (a shell can lose it): the server must report itself running on this port.
        if !matches!(self.status()?, Status::Running { port: p } if p == port) {
            let mut detail = fs::read_to_string(&started_log).unwrap_or_default();
            detail.push_str(&fs::read_to_string(&server_log).unwrap_or_default());
            self.telemetry.set_up(false);
            self.telemetry.audit(
                "start_failed",
                "pg_ctl reported success but the server is not running",
            );
            return Err(PgError::NotReady(tail(detail.trim(), 12)));
        }
        self.telemetry.set_up(true);
        self.telemetry
            .audit("started", &format!("listening on 127.0.0.1:{port}"));
        Ok(port)
    }

    /// Run `pg_ctl start` so that the server it leaves behind holds no handle of ours.
    ///
    /// On Unix the standard handles are redirected to a file and everything else is close-on-exec. On Windows a child inherits
    /// every inheritable handle of this process, including a pipe the caller (a CI step, an IDE, a test runner) gave us to
    /// read our output: the server would keep that pipe open for as long as it runs and the caller would wait for it forever.
    /// `Start-Process` launches through the shell, which does not inherit our handles, so the pipe closes when we exit.
    fn run_pg_ctl_start(&self, args: &[String], log: &Path) -> PgResult<std::process::ExitStatus> {
        #[cfg(windows)]
        {
            let _ = log;
            // File names cannot contain a double quote on Windows; refuse rather than build a command line that could be bent.
            if args.iter().any(|a| a.contains('"')) {
                return Err(PgError::Io("a path contains a double quote".into()));
            }
            let arg_list = args
                .iter()
                .map(|a| format!("\"{a}\""))
                .collect::<Vec<_>>()
                .join(" ");
            let pg_ctl = self.bin("pg_ctl").display().to_string();
            let script = format!(
                "$p = Start-Process -FilePath '{}' -ArgumentList '{}' -WindowStyle Hidden -PassThru; $p.WaitForExit(); if ($null -eq $p.ExitCode) {{ exit 1 }}; exit $p.ExitCode",
                ps_single_quoted(&pg_ctl),
                ps_single_quoted(&arg_list)
            );
            // -EncodedCommand carries the script as UTF-16LE base64, so no command-line quoting layer can be bent by a path.
            let encoded = base64_utf16le(&script);
            let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
            let powershell = Path::new(&root)
                .join("System32")
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe");
            let mut cmd = Command::new(powershell);
            Self::clean_env(&mut cmd, &self.install_dir().join("bin"));
            cmd.args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            cmd.status().map_err(|e| PgError::Process {
                program: "pg_ctl".into(),
                code: None,
                detail: format!("cannot start: {e}"),
            })
        }
        #[cfg(not(windows))]
        {
            let sink = fs::File::create(log)?;
            let sink_err = sink.try_clone()?;
            let mut cmd = self.command("pg_ctl");
            cmd.args(args)
                .stdout(Stdio::from(sink))
                .stderr(Stdio::from(sink_err));
            cmd.status().map_err(|e| PgError::Process {
                program: "pg_ctl".into(),
                code: None,
                detail: format!("cannot start: {e}"),
            })
        }
    }

    /// Fast shutdown. Stopping a stopped server is not an error.
    pub fn stop(&self) -> PgResult<()> {
        if !matches!(self.status()?, Status::Running { .. }) {
            self.telemetry.set_up(false);
            return Ok(());
        }
        let mut cmd = self.command("pg_ctl");
        cmd.arg("stop")
            .arg("-D")
            .arg(self.layout().pgdata())
            .args(["-m", "fast", "-w", "-t"])
            .arg(self.cfg.stop_timeout.as_secs().to_string());
        self.run_ok("pg_ctl", cmd, None)?;
        self.telemetry.set_up(false);
        self.telemetry.audit("stopped", "fast shutdown");
        Ok(())
    }

    /// Does the server answer a readiness probe right now (`pg_isready`)? Updates `hdd_embedded_db_up`.
    pub fn is_ready(&self) -> bool {
        let Ok(Status::Running { port }) = self.status() else {
            self.telemetry.set_up(false);
            return false;
        };
        let mut cmd = self.command("pg_isready");
        cmd.args(["-h", "127.0.0.1", "-t", "2", "-p"])
            .arg(port.to_string());
        let ok = self
            .run("pg_isready", cmd, None)
            .is_ok_and(|o| o.status.success());
        self.telemetry.set_up(ok);
        ok
    }

    // -------------------------------------------------------------------------------------------------------------------
    // roles and SQL

    fn psql(&self, port: u16, role: &str, db: &str, sql: &str) -> PgResult<Output> {
        let mut cmd = self.command("psql");
        cmd.args([
            "-h",
            "127.0.0.1",
            "-w",
            "-X",
            "-q",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            role,
            "-d",
            db,
            "-p",
        ])
        .arg(port.to_string())
        .args(["-f", "-"]);
        self.run_ok("psql", cmd, Some(sql))
    }

    /// Create `hdd_owner` and the database `hdd` (idempotent) and write the connection URL file.
    pub fn ensure_roles(&self, port: u16) -> PgResult<PathBuf> {
        let owner_pw = read_text(&self.layout().secrets().join("hdd_owner.pw"))?;
        let owner_pw = owner_pw.trim();
        if !owner_pw.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(PgError::State(
                "the stored owner password is not hexadecimal; run `db reset`".into(),
            ));
        }
        let sql = format!(
            "SELECT 'CREATE ROLE {owner} LOGIN CREATEROLE PASSWORD ''{pw}''' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{owner}') \\gexec\n\
ALTER ROLE {owner} WITH LOGIN CREATEROLE PASSWORD '{pw}';\n\
SELECT 'CREATE DATABASE {db} OWNER {owner} ENCODING ''UTF8'' TEMPLATE template0' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '{db}') \\gexec\n\
REVOKE ALL ON DATABASE {db} FROM PUBLIC;\n",
            owner = names::OWNER,
            db = names::DATABASE,
            pw = owner_pw
        );
        self.psql(port, names::SUPERUSER, "postgres", &sql)?;
        let url = format!(
            "postgres://{}:{}@127.0.0.1:{port}/{}",
            names::OWNER,
            owner_pw,
            names::DATABASE
        );
        let url_file = self.layout().owner_url_file();
        write_private_file(&url_file, url.as_bytes())?;
        Ok(url_file)
    }

    /// Run SQL as `hdd_owner` in the database `hdd` (a migration, a check). The server must be running.
    pub fn run_sql_as_owner(&self, sql: &str) -> PgResult<String> {
        let Status::Running { port } = self.status()? else {
            return Err(PgError::State(
                "the database is not running; run `db up`".into(),
            ));
        };
        let out = self.psql(port, names::OWNER, names::DATABASE, sql)?;
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Run SQL as the superuser in a database (administration, tests).
    pub fn run_sql_as_admin(&self, db: &str, sql: &str) -> PgResult<String> {
        let Status::Running { port } = self.status()? else {
            return Err(PgError::State(
                "the database is not running; run `db up`".into(),
            ));
        };
        let out = self.psql(port, names::SUPERUSER, db, sql)?;
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    // -------------------------------------------------------------------------------------------------------------------
    // the commands of `cargo xtask db`

    /// Install (from `archive`, when not installed yet), initialize, start and create the owner and the database.
    pub fn up(&self, archive: Option<&Path>) -> PgResult<UpReport> {
        let layout = self.layout();
        self.ensure_base()?;
        let _lock = self.lock()?;
        self.check_version_marker()?;
        require_free_space(&layout.base, self.cfg.min_free_bytes)?;
        let mut installed = false;
        if !self.is_installed() {
            let archive = archive.ok_or_else(|| {
                PgError::State(
                    "PostgreSQL is not installed: pass --bundle <archive> or --download".into(),
                )
            })?;
            self.install(archive)?;
            installed = true;
        }
        let initialized = !self.is_initialized();
        self.init()?;
        let was_running = matches!(self.status()?, Status::Running { .. });
        let port = self.start()?;
        let url_file = self.ensure_roles(port)?;
        Ok(UpReport {
            installed,
            initialized,
            started: !was_running,
            port,
            url_file,
        })
    }

    /// Stop the server.
    pub fn down(&self) -> PgResult<()> {
        let _lock = self.lock()?;
        self.stop()
    }

    /// Delete the cluster and its secrets so that `up` starts from nothing. Installed binaries, the cache and the backups stay.
    /// Refuses while the server runs.
    pub fn reset(&self) -> PgResult<()> {
        let _lock = self.lock()?;
        if matches!(self.status()?, Status::Running { .. }) {
            return Err(PgError::State(
                "the database is running; run `db down` first".into(),
            ));
        }
        let layout = self.layout();
        if layout.pgdata().exists() {
            fs::remove_dir_all(layout.pgdata())?;
        }
        // the secrets go too, except the backup key: without it the backups could never be restored
        if layout.secrets().is_dir() {
            for entry in fs::read_dir(layout.secrets())? {
                let entry = entry?;
                if entry.file_name() != "backup.key" {
                    fs::remove_file(entry.path())?;
                }
            }
        }
        for file in [layout.version_marker(), layout.base.join("pg.port")] {
            if file.exists() {
                fs::remove_file(&file)?;
            }
        }
        self.telemetry.audit(
            "reset",
            "cluster and secrets deleted; binaries, cache, backups and the backup key kept",
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
