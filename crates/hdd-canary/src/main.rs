//! `hdd-canary`: the origin-side sidecar of section C16.1 (T-0210).
//!
//! It serves only the five canary files and `GET <base_path>echo-headers`, reads no request body and never reflects input.
//! `CANARY.md` is the runbook (install both ways, query-string invariance, uninstall, security notes); `deploy/hdd-canary.service`
//! is the systemd unit with the sandbox options.
//!
//! Usage: `hdd-canary [--bind <addr>] [--base-path <path>] [--root <directory>] [--manifest <file>]`.
#![forbid(unsafe_code)]
#![allow(
    clippy::print_stdout,
    reason = "this binary reports its configuration to the operator"
)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use hdd_canary::{Config, DEFAULT_BASE_PATH, DEFAULT_BIND, DEFAULT_ROOT, MANIFEST_NAME, start};

/// Parsed command line.
struct Args {
    bind: SocketAddr,
    base_path: String,
    root: PathBuf,
    manifest: Option<PathBuf>,
}

const HELP: &str = "\
hdd-canary: origin-side canary fixture server (spec section C16.1, runbook CANARY.md)

Usage: hdd-canary [OPTIONS]

Options:
  --bind <ADDR>        address to listen on (default 127.0.0.1:8080)
  --base-path <PATH>   path the files are served under (default /__hdd_canary/)
  --root <DIR>         directory holding ok.txt, leak.txt, static.css, static.js and search.html
                       (default /var/lib/hdd-canary)
  --manifest <FILE>    verify this manifest.sha256 before serving; a mismatch stops the sidecar
  --version            print the version and exit
  --help               print this text and exit

The sidecar serves only the five canary files and GET <base-path>echo-headers. It never reads a request
body, never lists a directory and never serves any other path.";

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} needs a value (see --help)"))
}

fn parse_args() -> Result<Option<Args>, String> {
    let mut args = std::env::args().skip(1);
    let mut bind = DEFAULT_BIND.to_owned();
    let mut base_path = DEFAULT_BASE_PATH.to_owned();
    let mut root = PathBuf::from(DEFAULT_ROOT);
    let mut manifest: Option<PathBuf> = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--help" | "-h" => {
                println!("{HELP}");
                return Ok(None);
            }
            "--version" | "-V" => {
                println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            "--bind" => bind = next_value(&mut args, "--bind")?,
            "--base-path" => base_path = next_value(&mut args, "--base-path")?,
            "--root" => root = PathBuf::from(next_value(&mut args, "--root")?),
            "--manifest" => {
                manifest = Some(PathBuf::from(next_value(&mut args, "--manifest")?));
            }
            other => return Err(format!("unknown argument `{other}` (see --help)")),
        }
    }
    let bind: SocketAddr = bind
        .parse()
        .map_err(|e| format!("--bind `{bind}` is not an address:port ({e})"))?;
    Ok(Some(Args {
        bind,
        base_path,
        root,
        manifest,
    }))
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(Some(args)) => args,
        Ok(None) => return ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let config = match Config::new(args.bind, &args.root, &args.base_path) {
        Ok(mut config) => {
            config.manifest = args.manifest;
            config
        }
        Err(e) => {
            eprintln!("hdd-canary: {e}");
            return ExitCode::from(2);
        }
    };
    let manifest_note = match &config.manifest {
        Some(path) => format!("verified {}", path.display()),
        None => format!("not checked (pass --manifest to verify {MANIFEST_NAME} before serving)"),
    };
    let running = match start(config) {
        Ok(running) => running,
        Err(e) => {
            eprintln!("hdd-canary: {e}");
            return ExitCode::from(2);
        }
    };
    println!(
        "hdd-canary {}: serving the five C16.1 files and GET <base_path>echo-headers",
        env!("CARGO_PKG_VERSION")
    );
    println!("  root:      {}", args.root.display());
    println!("  base path: {}", running.base_path());
    println!("  listening: http://{}", running.local_addr());
    println!("  manifest:  {manifest_note}");
    // The listener runs in its own thread; block here until the process is stopped (systemd stops it with SIGTERM).
    // K-4 (R-09): a listener thread that died is an outage, so exit non-zero and let the supervisor restart the sidecar.
    if let Err(e) = running.wait() {
        eprintln!("hdd-canary: {e}");
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}
