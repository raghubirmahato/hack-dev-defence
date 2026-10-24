//! `hdd-vulnlab`: intentionally vulnerable applications for the closed lab (section 2.8).
//!
//! LAB ONLY. Never shipped, never in a release artifact. The self-guard of section 2.8 item 2 is
//! implemented by T-0493; until then this binary refuses to run at all, which is the safe default.
#![forbid(unsafe_code)]
#![allow(clippy::print_stdout)]

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "hdd-vulnlab: refusing to start. The lab self-guard and the applications are not implemented yet (first task: T-0493)."
    );
    ExitCode::from(2)
}
