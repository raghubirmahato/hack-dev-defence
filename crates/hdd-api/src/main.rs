//! `hdd-api`: control plane JSON API (:8000) + SSE; OpenAPI.
//!
//! Scaffold created by the bootstrap session (T-0004). The binary reports its version and otherwise
//! exits with status 2 so that nothing can mistake it for a working service. The first task that
//! mentions this crate is T-0073 (see `ARCHITECTURE.md` and `docs/tasks/`).
#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let name = env!("CARGO_PKG_NAME");
    if std::env::args().skip(1).any(|a| a == "--version") {
        let _ = writeln!(std::io::stdout(), "{name} {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    eprintln!("{name}: not implemented yet (first task: T-0073); see ARCHITECTURE.md");
    ExitCode::from(2)
}
