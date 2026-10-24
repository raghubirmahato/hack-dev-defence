//! `hdd-local`: local runtime: supervisor, embedded PostgreSQL manager, local CA, hosts helper, doctor, self-test, local backups.
//!
//! Implemented so far (T-0563): `db up|down|status|reset|url`, `backup` and `restore`. The supervisor (`run`, `stop`, `doctor`,
//! `selftest`, ...) is T-0564; until it lands those commands do not exist rather than pretending to work.
#![forbid(unsafe_code)]
#![allow(clippy::print_stdout)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use hdd_local::pg::cli::{self, UpOptions};
use hdd_local::pg::{PgError, PgResult};

#[derive(Parser)]
#[command(
    name = "hdd-local",
    about = "Hack Dev Defence on your own computer",
    version
)]
struct Cli {
    /// Data directory (default: HDD_DATA_DIR, else the per-user data directory).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// The embedded PostgreSQL.
    #[command(subcommand)]
    Db(DbCmd),
    /// Write an encrypted logical backup of the database.
    Backup,
    /// Restore an encrypted backup into the database.
    Restore {
        /// The backup file.
        file: PathBuf,
        /// Confirm: the restore replaces the objects of the database (as one transaction).
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum DbCmd {
    /// Install (when needed), initialize, start the database and create the owner role and the database.
    Up {
        /// Use this archive instead of downloading one (verified against the pinned SHA-256).
        #[arg(long)]
        bundle: Option<PathBuf>,
        /// Download the pinned archive when none is installed or cached.
        #[arg(long)]
        download: bool,
        /// Egress allowlist entry for the download (repeat). Giving it is your approval of that destination.
        #[arg(long = "allow")]
        allow: Vec<String>,
    },
    /// Stop the database (fast shutdown).
    Down,
    /// Show whether it is installed, initialized and running.
    Status,
    /// Delete the cluster and its secrets (the backup key, binaries, cache and backups stay).
    Reset {
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,
    },
    /// Print the file that holds the connection URL of the owner role (never the URL itself).
    Url,
}

fn run(cli: Cli) -> PgResult<()> {
    let data_dir = match cli.data_dir {
        Some(d) => d,
        None => cli::default_data_dir()?,
    };
    match cli.command {
        Cmd::Db(DbCmd::Up {
            bundle,
            download,
            allow,
        }) => {
            let r = cli::up(
                &data_dir,
                &UpOptions {
                    bundle,
                    download,
                    allow,
                },
            )?;
            println!(
                "database up on 127.0.0.1:{} (installed: {}, initialized: {}, started: {}); the connection URL is in {}",
                r.port,
                r.installed,
                r.initialized,
                r.started,
                r.url_file.display()
            );
        }
        Cmd::Db(DbCmd::Down) => {
            cli::manager(&data_dir)?.down()?;
            println!("database stopped");
        }
        Cmd::Db(DbCmd::Status) => print!("{}", cli::status(&data_dir)?),
        Cmd::Db(DbCmd::Reset { yes }) => {
            if !yes {
                return Err(PgError::State(
                    "this deletes the cluster and its secrets; repeat with --yes to confirm".into(),
                ));
            }
            cli::manager(&data_dir)?.reset()?;
            println!("cluster and secrets deleted; `db up` starts from nothing");
        }
        Cmd::Db(DbCmd::Url) => {
            let em = cli::manager(&data_dir)?;
            println!("{}", em.config().layout.owner_url_file().display());
        }
        Cmd::Backup => {
            let file = cli::manager(&data_dir)?.backup()?;
            println!("backup written: {}", file.display());
        }
        Cmd::Restore { file, yes } => {
            if !yes {
                return Err(PgError::State(
                    "a restore replaces the objects of the database; repeat with --yes to confirm"
                        .into(),
                ));
            }
            cli::manager(&data_dir)?.restore(&file)?;
            println!("backup restored");
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hdd-local: {e}");
            ExitCode::from(1)
        }
    }
}
