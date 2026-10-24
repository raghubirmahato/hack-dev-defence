//! `hdd-xtask`: build/verify/release automation (T-0005).
//!
//! Subcommands: `verify`, `spec split|check|show`, `tasks index|order|check`, `gen-secrets`, `claims-lint`, `rust-share`,
//! `matrix generate|check`, `secrets scan`, `hooks install`, `deps check`, `adr check`, and the stubs `attack-matrix check`,
//! `contrast-check`, `i18n check`, `routes check` (success with a note until the named task lands).
#![forbid(unsafe_code)]
#![allow(clippy::print_stdout)]

mod claims;
mod deps;
mod gate;
mod matrix;
mod profile_check;
mod profile_lint;
mod rules;
mod rust_share;
mod secrets;
mod spec;
mod tasks;
mod util;
mod ux_docs;
mod verify;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use util::{Result, repo_root, report_findings};

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "Hack Dev Defence build, verify and governance automation",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the whole verification pipeline; logs and SHA-256 under acceptance-verify/.
    Verify {
        /// Run only the named steps (for example `fmt clippy`).
        #[arg(long, num_args = 1..)]
        only: Vec<String>,
    },
    /// Split, check or show the master specification.
    #[command(subcommand)]
    Spec(SpecCmd),
    /// Task index, execution order and consistency checks.
    #[command(subcommand)]
    Tasks(TasksCmd),
    /// Generate random secrets into a directory (owner-only, never printed, never overwritten without --force).
    GenSecrets {
        /// Output directory.
        #[arg(long, default_value = "secrets")]
        dir: PathBuf,
        /// Rotate secrets that already exist.
        #[arg(long)]
        force: bool,
    },
    /// Scan documents, templates and catalogs for forbidden claim phrases (section 4).
    ClaimsLint,
    /// Rust share of hand-written programming-language lines (DEV-V5-002).
    RustShare,
    /// Capability matrix generation and checks.
    #[command(subcommand)]
    Matrix(MatrixCmd),
    /// Secret scanner.
    #[command(subcommand)]
    Secrets(SecretsCmd),
    /// Git hooks.
    #[command(subcommand)]
    Hooks(HooksCmd),
    /// Dependency-vetting lint (R-08).
    #[command(subcommand)]
    Deps(DepsCmd),
    /// ADR hygiene checks.
    #[command(subcommand)]
    Adr(AdrCmd),
    /// Live profile schema and example checks.
    #[command(subcommand)]
    Profile(ProfileCmd),
    /// Assemble a gate report in the Appendix E5.1 format from the collected evidence.
    GateReport {
        /// Gate id such as G00.
        gate: String,
        /// Copy the latest verify run into docs/gates/evidence/<gate>/verify/ first.
        #[arg(long)]
        collect: bool,
        /// Do not write; fail when the committed report differs from the regenerated one.
        #[arg(long)]
        check: bool,
    },
    /// The embedded PostgreSQL for builders without Docker (T-0563): `db up|down|reset|status`.
    #[command(subcommand)]
    Db(DbCmd),
    /// R-31: no runtime-profile checks outside the places allowed to have them; capability matrix and AC table complete.
    ProfileLint,
    /// Only hdd-common::kv talks to Redis.
    KvLint,
    /// T-0011: the UX charter, measures and decision records are structured, within budget and linked (relative links resolve).
    UxDocs,
    /// Compare the decisions of the local and hosted profiles (stub until T-0564: needs the engine and the fixtures).
    ProfileParity,
    /// Build-plan data.
    #[command(subcommand)]
    BuildPlan(BuildPlanCmd),
    /// Attack-matrix checks (stub until T-0245).
    #[command(subcommand)]
    AttackMatrix(StubCheck),
    /// Colour contrast check (stub until T-0030).
    ContrastCheck,
    /// Internationalization checks (stub until T-0082).
    #[command(subcommand)]
    I18n(StubCheck),
    /// Route checks (stub until T-0073).
    #[command(subcommand)]
    Routes(StubCheck),
}

#[derive(Subcommand)]
enum SpecCmd {
    /// Write docs/spec/*.md and MANIFEST.tsv from docs/SPEC.md.
    Split,
    /// Compare docs/spec/ with a fresh split; fails on any difference.
    Check,
    /// Print a task block and the registry rows it references.
    Show {
        /// Task id such as T-0123.
        task: String,
    },
}

#[derive(Subcommand)]
enum TasksCmd {
    /// Write docs/spec/INDEX.md and INDEX.md (or verify them with --check).
    Index {
        /// Do not write; fail when the files are stale or the graph is inconsistent.
        #[arg(long)]
        check: bool,
    },
    /// Print the stable topological execution order.
    Order,
    /// Cross-check the model, indexes, per-task files and STATUS.md.
    Check,
}

#[derive(Subcommand)]
enum MatrixCmd {
    /// Write docs/CAPABILITY-MATRIX.md.
    Generate,
    /// Verify the matrix is current and every row satisfies the link rules.
    Check,
}

#[derive(Subcommand)]
enum SecretsCmd {
    /// Scan the working tree, or the staged blobs with --staged (pre-commit hook).
    Scan {
        /// Scan what a commit would contain.
        #[arg(long)]
        staged: bool,
    },
}

#[derive(Subcommand)]
enum HooksCmd {
    /// Install the pre-commit secret-scan hook (sets core.hooksPath).
    Install,
}

#[derive(Subcommand)]
enum DepsCmd {
    /// Flag dependencies without a vetting entry or required ADR.
    Check,
}

#[derive(Subcommand)]
enum AdrCmd {
    /// Check ADR numbering, index, deciding task, rollback plan and acceptance rules.
    Check,
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// Write docs/profile.schema.json from the profile types.
    Schema,
    /// Verify the schema file and hdd.live.example.yaml are current.
    Check,
}

#[derive(Subcommand)]
enum DbCmd {
    /// Install (when needed), initialize and start the embedded database, create `hdd_owner` and the database `hdd`.
    Up {
        /// Data directory (default: target/hdd-db).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Use this archive (an offline bundle); it is verified against the pinned SHA-256.
        #[arg(long)]
        bundle: Option<PathBuf>,
        /// Download the pinned archive when none is installed or cached.
        #[arg(long)]
        download: bool,
        /// Egress allowlist entry for the download (repeat). Giving it is your approval of that destination.
        #[arg(long = "allow")]
        allow: Vec<String>,
    },
    /// Stop the embedded database.
    Down {
        /// Data directory (default: target/hdd-db).
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Delete the cluster and its secrets.
    Reset {
        /// Data directory (default: target/hdd-db).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,
    },
    /// Show whether the embedded database is installed, initialized and running.
    Status {
        /// Data directory (default: target/hdd-db).
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum BuildPlanCmd {
    /// Regenerate crates/hdd-common/src/buildplan/ac_table.rs from docs/spec/E3.md.
    Table,
}

#[derive(Subcommand)]
enum StubCheck {
    /// Stub check.
    Check,
}

fn dispatch(cmd: Cmd) -> Result<i32> {
    match cmd {
        Cmd::Verify { only } => verify::run(&repo_root()?, &only),
        Cmd::Spec(SpecCmd::Split) => spec::run_split(&repo_root()?).map(|()| 0),
        Cmd::Spec(SpecCmd::Check) => Ok(report_findings("spec check", &spec::check(&repo_root()?))),
        Cmd::Spec(SpecCmd::Show { task }) => {
            println!("{}", spec::show(&repo_root()?, &task)?);
            Ok(0)
        }
        Cmd::Tasks(TasksCmd::Index { check }) => {
            let f = tasks::index(&repo_root()?, check)?;
            Ok(report_findings("tasks index", &f))
        }
        Cmd::Tasks(TasksCmd::Order) => {
            let root = repo_root()?;
            let model = tasks::parse(&spec::load_master(&root)?)?;
            for (n, id) in tasks::order(&model)?.iter().enumerate() {
                let title = model.task(id).map_or("", |t| t.title.as_str());
                println!("{:>3} {id} {title}", n + 1);
            }
            Ok(0)
        }
        Cmd::Tasks(TasksCmd::Check) => {
            Ok(report_findings("tasks check", &tasks::check(&repo_root()?)))
        }
        Cmd::GenSecrets { dir, force } => {
            let root = repo_root()?;
            let dir = if dir.is_absolute() {
                dir
            } else {
                root.join(dir)
            };
            let written = secrets::gen_secrets(&dir, force)?;
            println!(
                "gen-secrets: wrote {} secret file(s) to {} (values are never printed)",
                written.len(),
                dir.display()
            );
            Ok(0)
        }
        Cmd::ClaimsLint => {
            let (f, summary) = claims::run(&repo_root()?)?;
            println!("{summary}");
            Ok(report_findings("claims-lint", &f))
        }
        Cmd::RustShare => match rust_share::run(&repo_root()?)? {
            rust_share::Outcome::Ran(f, text) => {
                print!("{text}");
                Ok(report_findings("rust-share", &f))
            }
            rust_share::Outcome::Unverified(why) => {
                println!("rust-share: UNVERIFIED(tool_unavailable): {why}");
                Ok(1)
            }
        },
        Cmd::Matrix(MatrixCmd::Generate) => matrix::generate(&repo_root()?).map(|()| 0),
        Cmd::Matrix(MatrixCmd::Check) => Ok(report_findings(
            "matrix check",
            &matrix::check(&repo_root()?),
        )),
        Cmd::Secrets(SecretsCmd::Scan { staged }) => {
            let f = if staged {
                secrets::scan_staged()?
            } else {
                secrets::scan_tree(&repo_root()?)?
            };
            Ok(report_findings(
                if staged {
                    "secret scan (staged)"
                } else {
                    "secret scan"
                },
                &f,
            ))
        }
        Cmd::Hooks(HooksCmd::Install) => secrets::install_hooks(&repo_root()?).map(|()| 0),
        Cmd::Deps(DepsCmd::Check) => Ok(report_findings(
            "dependency vetting",
            &deps::check(&repo_root()?),
        )),
        Cmd::Adr(AdrCmd::Check) => {
            let root = repo_root()?;
            let model = tasks::parse(&spec::load_master(&root)?)?;
            let ids = model.tasks.into_iter().map(|t| t.id).collect();
            Ok(report_findings("adr check", &deps::check_adrs(&root, &ids)))
        }
        Cmd::Profile(ProfileCmd::Schema) => profile_check::write_schema(&repo_root()?).map(|()| 0),
        Cmd::Profile(ProfileCmd::Check) => Ok(report_findings(
            "profile check",
            &profile_check::check(&repo_root()?),
        )),
        Cmd::GateReport {
            gate,
            collect,
            check,
        } => Ok(report_findings(
            "gate-report",
            &gate::run(&repo_root()?, &gate, collect, check)?,
        )),
        Cmd::Db(cmd) => db_command(cmd),
        Cmd::ProfileLint => Ok(report_findings(
            "profile-lint",
            &profile_lint::check_profile(&repo_root()?),
        )),
        Cmd::KvLint => Ok(report_findings(
            "kv-lint",
            &profile_lint::check_kv(&repo_root()?),
        )),
        Cmd::UxDocs => Ok(report_findings("ux-docs", &ux_docs::check(&repo_root()?))),
        Cmd::ProfileParity => stub("profile-parity"),
        Cmd::BuildPlan(BuildPlanCmd::Table) => {
            profile_lint::write_ac_table(&repo_root()?).map(|()| 0)
        }
        Cmd::AttackMatrix(_) => stub("attack-matrix"),
        Cmd::ContrastCheck => stub("contrast-check"),
        Cmd::I18n(_) => stub("i18n"),
        Cmd::Routes(_) => stub("routes"),
    }
}

/// `cargo xtask db ...`: the same code as `hdd-local db ...`, with the data directory under `target/` by default.
fn db_command(cmd: DbCmd) -> Result<i32> {
    use hdd_local::pg::cli;
    let dir = |d: Option<PathBuf>| -> Result<PathBuf> {
        Ok(d.unwrap_or(repo_root()?.join("target").join("hdd-db")))
    };
    let fail = |e: hdd_local::pg::PgError| util::Error(e.to_string());
    match cmd {
        DbCmd::Up {
            data_dir,
            bundle,
            download,
            allow,
        } => {
            let r = cli::up(
                &dir(data_dir)?,
                &cli::UpOptions {
                    bundle,
                    download,
                    allow,
                },
            )
            .map_err(fail)?;
            println!(
                "db up: 127.0.0.1:{} (installed: {}, initialized: {}, started: {}); connection URL file: {}",
                r.port,
                r.installed,
                r.initialized,
                r.started,
                r.url_file.display()
            );
        }
        DbCmd::Down { data_dir } => {
            cli::manager(&dir(data_dir)?)
                .map_err(fail)?
                .down()
                .map_err(fail)?;
            println!("db down: stopped");
        }
        DbCmd::Reset { data_dir, yes } => {
            if !yes {
                return Err(util::Error(
                    "db reset deletes the cluster and its secrets; repeat with --yes".into(),
                ));
            }
            cli::manager(&dir(data_dir)?)
                .map_err(fail)?
                .reset()
                .map_err(fail)?;
            println!("db reset: cluster and secrets deleted");
        }
        DbCmd::Status { data_dir } => {
            print!("{}", cli::status(&dir(data_dir)?).map_err(fail)?);
        }
    }
    Ok(0)
}

fn stub(name: &str) -> Result<i32> {
    if let Some(msg) = verify::stub_message(name) {
        print!("{msg}");
    }
    Ok(0)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli.command) {
        Ok(0) => ExitCode::SUCCESS,
        Ok(_) => ExitCode::from(1),
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::from(2)
        }
    }
}
