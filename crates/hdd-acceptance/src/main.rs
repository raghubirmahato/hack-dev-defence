//! `hdd-acceptance` command line: the registry, the dry run of the full list, and profile validation before a run.
//!
//! The skeleton deliberately has no live check and no real sender: every registered id is `UNVERIFIED(stage_not_reached)`,
//! and `--dry-run` is the only mode that needs no live profile. A `run` with a profile validates the profile, the lifecycle
//! stage, the load approval, the target guard, the egress allowlist and the runner-IP rule, writes the report and exits 0
//! without sending anything. `docs/ACCEPTANCE.md` documents the status taxonomy, the evidence layout and what lands next.
#![forbid(unsafe_code)]
#![allow(clippy::print_stdout)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use hdd_acceptance::config::{self, RunApproval, RunnerConfig};
use hdd_acceptance::limits::LoadProfile;
use hdd_acceptance::registry;
use hdd_acceptance::report::{EvidenceStore, Redactor, Report, now_utc};
use hdd_common::egress::{KillSwitch, TargetMode};

/// Exit code for a usage or environment error.
const EXIT_ERROR: u8 = 2;

/// Exit code for a profile or safety refusal (the run must not start).
const EXIT_REFUSED: u8 = 3;

/// Exit code for a tripped kill switch.
const EXIT_ABORTED: u8 = 4;

/// Output format of the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Json,
    Markdown,
    Both,
}

impl Format {
    fn parse(text: &str) -> Option<Format> {
        match text.trim().to_ascii_lowercase().as_str() {
            "json" => Some(Format::Json),
            "markdown" | "md" => Some(Format::Markdown),
            "both" => Some(Format::Both),
            _ => None,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "hdd-acceptance",
    about = "acceptance runner skeleton: registry, dry run, report (T-0215)",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
#[allow(
    clippy::large_enum_variant,
    reason = "the CLI enum is built once per process; boxing the run arguments would only obscure the clap definition"
)]
enum Cmd {
    /// Print the acceptance registry (AC-00 to AC-62).
    Registry,
    /// Dry-run the full check list, or validate a live profile and write a report without sending anything.
    Run {
        /// The live profile (hdd.live.yaml). Required unless --dry-run is given.
        #[arg(long)]
        profile: Option<PathBuf>,
        /// List every registered check as UNVERIFIED(stage_not_reached) without needing a profile.
        #[arg(long)]
        dry_run: bool,
        /// Target mode: live or lab.
        #[arg(long, default_value = "live")]
        mode: String,
        /// Rate/load profile: functional, burst, protocol-abuse, load or lab.
        #[arg(long = "load-profile", default_value = "functional")]
        load_profile: String,
        /// Output directory (default: acceptance-<utc stamp>).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Report format: json, markdown or both.
        #[arg(long, default_value = "both")]
        format: String,
        /// The operator's written approval ticket for this specific run (destructive checks and load runs):
        /// `run=<run-id>; window=<maintenance window>` (T-0492 step 7, section 2.7). The `run=` value must equal this run's
        /// id (`--run-id`), otherwise the run is refused (review item R-13).
        #[arg(long)]
        operator_approval: Option<String>,
        /// The id of this run. The approval ticket is bound to it (review item R-13). Default: a `run-<utc stamp>` id.
        #[arg(long)]
        run_id: Option<String>,
        /// The control plane's `config_revision` this run plans against. The report is bound to it and a `--resume` of a
        /// report with another revision is refused (review item R-2).
        #[arg(long, default_value = "")]
        config_revision: String,
        /// Register an exact secret value to redact from the report and log (repeatable; review item N-5). A value shorter
        /// than four bytes is refused with an error instead of being silently dropped.
        #[arg(long = "redact-secret", value_name = "VALUE")]
        redact_secret: Vec<String>,
        /// Resume a previous run directory: keep its PASS lines and re-run everything else (spec 2.8 step 5).
        #[arg(long)]
        resume: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Registry => print_registry(),
        Cmd::Run {
            profile,
            dry_run,
            mode,
            load_profile,
            out,
            format,
            operator_approval,
            run_id,
            config_revision,
            redact_secret,
            resume,
        } => run(RunArgs {
            profile,
            dry_run,
            mode,
            load_profile,
            out,
            format,
            operator_approval,
            run_id,
            config_revision,
            redact_secret,
            resume,
        }),
    }
}

struct RunArgs {
    profile: Option<PathBuf>,
    dry_run: bool,
    mode: String,
    load_profile: String,
    out: Option<PathBuf>,
    format: String,
    operator_approval: Option<String>,
    run_id: Option<String>,
    config_revision: String,
    redact_secret: Vec<String>,
    resume: Option<PathBuf>,
}

fn print_registry() -> ExitCode {
    println!("# | ID | Tier | Built in | Title");
    for entry in registry::entries() {
        println!(
            "| {} | {} | {} | {} |",
            entry.id, entry.tier, entry.built_in, entry.title
        );
    }
    println!(
        "\n{} checks registered (AC-00 to AC-62). Every check is UNVERIFIED(stage_not_reached) in this skeleton.",
        registry::ids().len()
    );
    ExitCode::SUCCESS
}

fn run(args: RunArgs) -> ExitCode {
    let mode = match args.mode.trim().to_ascii_lowercase().as_str() {
        "live" => TargetMode::Live,
        "lab" => TargetMode::Lab,
        other => {
            eprintln!("hdd-acceptance: --mode must be `live` or `lab`, not `{other}`");
            return ExitCode::from(EXIT_ERROR);
        }
    };
    let Some(load_profile) = LoadProfile::parse(&args.load_profile) else {
        eprintln!(
            "hdd-acceptance: --load-profile must be one of functional, burst, protocol-abuse, load, lab"
        );
        return ExitCode::from(EXIT_ERROR);
    };
    let Some(format) = Format::parse(&args.format) else {
        eprintln!("hdd-acceptance: --format must be json, markdown or both");
        return ExitCode::from(EXIT_ERROR);
    };
    let approval = match &args.operator_approval {
        Some(ticket) => match RunApproval::parse_ticket(ticket) {
            Ok(approval) => Some(approval),
            Err(error) => {
                eprintln!("hdd-acceptance: {error}");
                return ExitCode::from(EXIT_ERROR);
            }
        },
        None => None,
    };
    // Review item N-5: the CLI propagates the redactor's length error instead of silently dropping a short secret.
    let mut redactor = Redactor::new();
    for secret in &args.redact_secret {
        if let Err(error) = redactor.add_secret(secret.clone()) {
            eprintln!("hdd-acceptance: {error}");
            return ExitCode::from(EXIT_ERROR);
        }
    }
    let run_id = match &args.run_id {
        Some(id) if !id.trim().is_empty() => id.trim().to_owned(),
        Some(_) => {
            eprintln!("hdd-acceptance: --run-id must not be empty (review item R-13)");
            return ExitCode::from(EXIT_ERROR);
        }
        None => format!(
            "run-{}",
            now_utc().replace([':', 'T'], "-").replace('Z', "")
        ),
    };
    // Review item N-4: decide the output directory once, up front, and refuse an unusable one before any resume work.
    let out_dir = match resolve_out_dir(&args, mode) {
        Ok(dir) => dir,
        Err(code) => return code,
    };

    let kill = KillSwitch::new(
        KillSwitch::default_path(),
        hdd_common::egress::killswitch::DEFAULT_POLL,
    );
    if kill.check().is_err() {
        eprintln!(
            "hdd-acceptance: kill switch is set at {}; nothing runs (section 2.3). Remove the file and pass \
             `--resume <run-dir>` to continue a stopped run (spec 2.8 step 5).",
            kill.path().display()
        );
        return ExitCode::from(EXIT_ABORTED);
    }

    match args.profile.clone() {
        None if !args.dry_run => {
            eprintln!(
                "hdd-acceptance: a live run needs --profile; this skeleton implements no live check, so only `--dry-run` \
                 runs without a profile (docs/ACCEPTANCE.md)"
            );
            ExitCode::from(EXIT_ERROR)
        }
        None => {
            let mut report = dry_run_report(&args, mode, load_profile);
            report.redactor = redactor.clone();
            match apply_resume(report, &args, &out_dir) {
                Ok(report) => finish(report, &args, format, mode, &out_dir),
                Err(code) => code,
            }
        }
        Some(path) => {
            let profile = match config::load_profile_file(&path) {
                Ok(profile) => profile,
                Err(error) => {
                    eprintln!("hdd-acceptance: {error}");
                    return ExitCode::from(EXIT_REFUSED);
                }
            };
            let config =
                match RunnerConfig::build(profile, mode, load_profile, approval, &run_id, None) {
                    Ok(config) => config,
                    Err(error) => {
                        eprintln!("hdd-acceptance: run refused: {error}");
                        return ExitCode::from(EXIT_REFUSED);
                    }
                };
            let mut report = profile_report(&config, &args.config_revision);
            report.redactor = redactor.clone();
            match apply_resume(report, &args, &out_dir) {
                Ok(report) => finish(report, &args, format, mode, &out_dir),
                Err(code) => code,
            }
        }
    }
}

/// Decide and validate the output directory (review item N-4).
///
/// The runner writes a new run directory: a non-empty `--out` is refused, and resuming **in place** is refused explicitly
/// (the resume source must stay untouched; a resumed run copies its evidence into a fresh directory). This is the documented
/// rule: `--out` must be a new or empty directory, and `--resume <dir>` must be a different directory from `--out`.
fn resolve_out_dir(args: &RunArgs, mode: TargetMode) -> Result<PathBuf, ExitCode> {
    let stamp = now_utc().replace([':', 'T'], "-").replace('Z', "");
    let dir = args
        .out
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("acceptance-{stamp}-{}", mode_name(mode))));
    if let Some(resume) = &args.resume {
        let same = |a: &std::path::Path, b: &std::path::Path| -> bool {
            match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
                (Ok(a), Ok(b)) => a == b,
                _ => a == b,
            }
        };
        if same(&dir, resume) {
            eprintln!(
                "hdd-acceptance: refusing to resume in place: --out and --resume are the same directory ({}); choose a \
                 fresh --out so the resume source is not overwritten (review item N-4)",
                dir.display()
            );
            return Err(ExitCode::from(EXIT_ERROR));
        }
    }
    match std::fs::read_dir(&dir) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                eprintln!(
                    "hdd-acceptance: refusing to write into the non-empty directory {}; every run writes a new directory \
                     (review item S-6/N-4)",
                    dir.display()
                );
                return Err(ExitCode::from(EXIT_ERROR));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            eprintln!("hdd-acceptance: cannot inspect {}: {error}", dir.display());
            return Err(ExitCode::from(EXIT_ERROR));
        }
    }
    Ok(dir)
}

/// Merge a previous run's report into this one when `--resume <run-dir>` is given (spec 2.8 step 5, T-0492 step 5). The one
/// shared selection function re-hashes the evidence, refuses an invalid or stale run and skips AC-00 (review items R-2,
/// S-5, N-3, N-4); the verified evidence is **copied into the new run directory** so the new run is self-contained. A missing
/// or mismatched previous report refuses the resume instead of silently starting over.
fn apply_resume(report: Report, args: &RunArgs, out_dir: &Path) -> Result<Report, ExitCode> {
    let Some(dir) = &args.resume else {
        return Ok(report);
    };
    let path = dir.join("report.json");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!(
                "hdd-acceptance: cannot resume: cannot read {}: {error}",
                path.display()
            );
            return Err(ExitCode::from(EXIT_ERROR));
        }
    };
    let previous = match Report::from_json(&text) {
        Ok(previous) => previous,
        Err(error) => {
            eprintln!(
                "hdd-acceptance: cannot resume: {} is not a report: {error}",
                path.display()
            );
            return Err(ExitCode::from(EXIT_ERROR));
        }
    };
    report
        .resume_with(&previous, dir, Some(out_dir))
        .map_err(|error| {
            eprintln!("hdd-acceptance: cannot resume: {error}");
            ExitCode::from(EXIT_REFUSED)
        })
}

/// The dry-run report: every registered id, `UNVERIFIED(stage_not_reached)`, no profile facts.
fn dry_run_report(args: &RunArgs, mode: TargetMode, load_profile: LoadProfile) -> Report {
    let mut report = Report::new(
        mode_name(mode),
        if args.profile.is_some() {
            "unknown"
        } else {
            "not loaded"
        },
        load_profile.as_str(),
        0,
    );
    for line in registry::dry_run_lines() {
        report.push_line(line);
    }
    report.push_note(
        "dry run: every registered check is UNVERIFIED(stage_not_reached); no live check is implemented in this skeleton \
         (T-0215), so nothing was sent",
    );
    report.push_note(format!(
        "kill switch: {} (section 2.3); the full list always runs in dry-run mode from P11 (E3.3)",
        KillSwitch::default_path().display()
    ));
    report
}

/// The report of a profile-validated run: the environment facts plus the honest stage_not_reached lines. The report is bound
/// to the `config_revision` and target host names so a later `--resume` can refuse a report that does not describe this run
/// (review item R-2).
fn profile_report(config: &RunnerConfig, config_revision: &str) -> Report {
    let target_hostnames = vec![
        config.profile.test_hostname.trim().to_owned(),
        config.profile.sandbox_hostname.trim().to_owned(),
    ];
    let mut report = Report::new(
        mode_name(config.mode),
        format!("{:?}", config.lifecycle.stage()).to_ascii_lowercase(),
        config.load_profile.as_str(),
        config.vantage.count(),
    );
    report = report.with_binding(config_revision.to_owned(), target_hostnames);
    for line in registry::dry_run_lines() {
        report.push_line(line);
    }
    if let Some(warning) = config.lifecycle.warning() {
        report.push_note(warning.to_owned());
    }
    report.push_note(format!("runner IP: {} (section 2.4)", config.runner));
    report.push_note(format!(
        "target mode: {}; egress_allowlist entries: {}",
        mode_name(config.mode),
        config.egress.entries().len()
    ));
    report.push_note(format!(
        "vantage points: {} (strategy {:?}); live vantage use is UNVERIFIED(capability_not_supplied)",
        config.vantage.count(),
        config.vantage.strategy()
    ));
    report.push_note(
        "no live check is implemented in this skeleton (T-0215); every check is UNVERIFIED(stage_not_reached) and nothing \
         was sent",
    );
    report
}

fn mode_name(mode: TargetMode) -> &'static str {
    match mode {
        TargetMode::Live => "live",
        TargetMode::Lab => "lab",
    }
}

fn finish(
    mut report: Report,
    args: &RunArgs,
    format: Format,
    mode: TargetMode,
    out_dir: &Path,
) -> ExitCode {
    let _ = args;
    let _ = mode;
    let dir = out_dir.to_path_buf();
    let store = match EvidenceStore::create(&dir) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("hdd-acceptance: cannot create {}: {error}", dir.display());
            return ExitCode::from(EXIT_ERROR);
        }
    };
    let log_text = format!(
        "mode: {}\nstage: {}\nload profile: {}\nvantages: {}\nchecks: {}\nnotes:\n{}\n",
        report.mode,
        report.stage,
        report.load_profile,
        report.vantage_count,
        report.lines.len(),
        report
            .notes
            .iter()
            .map(|note| format!("- {note}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let log = match store.save_log("run.log", &log_text, &report.redactor) {
        Ok(log) => log,
        Err(error) => {
            eprintln!("hdd-acceptance: cannot save the run log: {error}");
            return ExitCode::from(EXIT_ERROR);
        }
    };
    report.push_log(log);
    let counts = report.counts();
    if matches!(format, Format::Markdown | Format::Both) {
        match report.render_markdown() {
            Ok(markdown) => {
                if let Err(error) = store.save("report.md", markdown.as_bytes()) {
                    eprintln!("hdd-acceptance: cannot save report.md: {error}");
                    return ExitCode::from(EXIT_ERROR);
                }
                let sha = hdd_acceptance::report::sha256_hex(markdown.as_bytes());
                println!(
                    "report.md: {} (sha256 {sha})",
                    dir.join("report.md").display()
                );
            }
            Err(error) => {
                eprintln!("hdd-acceptance: cannot render Markdown: {error}");
                return ExitCode::from(EXIT_ERROR);
            }
        }
    }
    if matches!(format, Format::Json | Format::Both) {
        match report.render_json() {
            Ok(json) => {
                if let Err(error) = store.save("report.json", json.as_bytes()) {
                    eprintln!("hdd-acceptance: cannot save report.json: {error}");
                    return ExitCode::from(EXIT_ERROR);
                }
                let sha = hdd_acceptance::report::sha256_hex(json.as_bytes());
                println!(
                    "report.json: {} (sha256 {sha})",
                    dir.join("report.json").display()
                );
            }
            Err(error) => {
                eprintln!("hdd-acceptance: cannot render JSON: {error}");
                return ExitCode::from(EXIT_ERROR);
            }
        }
    }
    println!(
        "{} checks: {} PASS, {} FAIL, {} UNVERIFIED; stage {}; mode {}; load profile {}; vantages {}",
        counts.total(),
        counts.pass,
        counts.fail,
        counts.unverified,
        report.stage,
        report.mode,
        report.load_profile,
        report.vantage_count
    );
    // Review item N-1: a run marked invalid by a safety-envelope denial exits with the documented refusal code (3) after the
    // report has been written, so the evidence is available and the automation sees the failure.
    if report.run_invalid {
        eprintln!(
            "hdd-acceptance: the run is invalid (a safety-envelope denial marked it; see the report's run-invalid section); \
             exit code {EXIT_REFUSED} (review item N-1)"
        );
        return ExitCode::from(EXIT_REFUSED);
    }
    ExitCode::SUCCESS
}
