//! End-to-end tests of the `hdd-acceptance` binary: the registry, the dry run and the refusals. The binary is a real process
//! here (unlike the library unit tests), but nothing in it opens a socket.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_hdd-acceptance")
}

// A helper inside the integration-test crate; the lints for unwrap/expect/panic are allowed in test code.
#[allow(clippy::expect_used, clippy::panic)]
fn temp_dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("hdd-acceptance-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn example_profile_with_emails() -> String {
    let example = include_str!("../../../hdd.live.example.yaml");
    example
        .replace("operator_email: ''", "operator_email: 'ops@example.com'")
        .replace(
            "acme: {email: '', directory: staging}",
            "acme: {email: 'ops@example.com', directory: staging}",
        )
}

#[test]
fn the_registry_command_lists_all_sixty_three_checks() {
    let output = Command::new(bin())
        .arg("registry")
        .output()
        .expect("run registry");
    assert!(output.status.success(), "registry failed: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let rows = stdout
        .lines()
        .filter(|line| line.starts_with("| AC-"))
        .count();
    assert_eq!(rows, 63, "{stdout}");
    assert!(stdout.contains("63 checks registered"));
}

#[test]
fn the_dry_run_writes_both_report_formats_and_the_log() {
    let dir = temp_dir("dry-run");
    let out = dir.join("acceptance-dry-run");
    let output = Command::new(bin())
        .args(["run", "--dry-run"])
        .arg("--out")
        .arg(&out)
        .output()
        .expect("run dry-run");
    assert!(
        output.status.success(),
        "dry run failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let markdown = std::fs::read_to_string(out.join("report.md")).expect("report.md");
    assert_eq!(
        markdown
            .lines()
            .filter(|line| line.starts_with("| AC-"))
            .count(),
        63
    );
    assert!(markdown.contains("63 checks: 0 PASS, 0 FAIL, 63 UNVERIFIED"));
    let json = std::fs::read_to_string(out.join("report.json")).expect("report.json");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("report json");
    assert_eq!(parsed["lines"].as_array().map(Vec::len), Some(63));
    assert_eq!(parsed["notes"].as_array().map(Vec::len), Some(2));
    assert!(out.join("run.log").is_file());
    let log = std::fs::read_to_string(out.join("run.log")).expect("run.log");
    assert!(log.contains("nothing was sent"), "{log}");
    let recorded = parsed["logs"][0]["sha256"].as_str().expect("log sha256");
    assert_eq!(recorded.len(), 64);
    let bytes = std::fs::read(out.join("run.log")).expect("read log");
    assert_eq!(recorded, hdd_acceptance::report::sha256_hex(&bytes));
}

#[test]
fn a_run_without_a_profile_is_a_usage_error() {
    let output = Command::new(bin()).arg("run").output().expect("run");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--profile"), "{stderr}");
}

#[test]
fn a_profile_that_does_not_parse_is_refused() {
    let dir = temp_dir("bad-profile");
    let profile = dir.join("hdd.live.yaml");
    std::fs::write(&profile, "schema_version: 5\nsurprise: 1\n").expect("write");
    let output = Command::new(bin())
        .args(["run", "--profile"])
        .arg(&profile)
        .arg("--dry-run")
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("surprise"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_profile_with_missing_required_fields_is_refused() {
    let dir = temp_dir("missing-required");
    let profile = dir.join("hdd.live.yaml");
    std::fs::write(&profile, include_str!("../../../hdd.live.example.yaml")).expect("write");
    let output = Command::new(bin())
        .args(["run", "--profile"])
        .arg(&profile)
        .arg("--dry-run")
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("PROF-REQUIRED"), "{stderr}");
    assert!(stderr.contains("operator_email"), "{stderr}");
}

#[test]
fn a_load_run_without_the_operators_approval_is_refused() {
    let dir = temp_dir("load-refused");
    let profile = dir.join("hdd.live.yaml");
    std::fs::write(&profile, example_profile_with_emails()).expect("write");
    let output = Command::new(bin())
        .args(["run", "--profile"])
        .arg(&profile)
        .args(["--load-profile", "load"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("load_profile_approved"), "{stderr}");
}

#[test]
fn a_valid_profile_is_accepted_and_reports_the_environment_facts() {
    let dir = temp_dir("valid-profile");
    let profile = dir.join("hdd.live.yaml");
    std::fs::write(&profile, example_profile_with_emails()).expect("write");
    let out = dir.join("acceptance-valid");
    let output = Command::new(bin())
        .args(["run", "--profile"])
        .arg(&profile)
        .arg("--out")
        .arg(&out)
        .output()
        .expect("run");
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let markdown = std::fs::read_to_string(out.join("report.md")).expect("report.md");
    assert!(markdown.contains("| Stage | pilot |"), "{markdown}");
    assert!(markdown.contains("| Load profile | functional |"));
    assert!(markdown.contains("mode: live"));
    assert!(markdown.contains("63 checks: 0 PASS, 0 FAIL, 63 UNVERIFIED"));
    assert!(markdown.contains("pilot: destructive checks run with a warning"));
}

#[test]
fn an_unknown_load_profile_is_a_usage_error() {
    let output = Command::new(bin())
        .args(["run", "--dry-run", "--load-profile", "turbo"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--load-profile"));
}

#[test]
fn a_lab_run_without_a_lab_profile_is_refused() {
    let dir = temp_dir("lab-refused");
    let profile = dir.join("hdd.live.yaml");
    std::fs::write(&profile, example_profile_with_emails()).expect("write");
    let output = Command::new(bin())
        .args(["run", "--profile"])
        .arg(&profile)
        .args(["--mode", "lab", "--load-profile", "lab"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("lab"), "{stderr}");
}

#[test]
fn no_cli_invocation_reaches_the_network() {
    // The honest statement is structural: the crate has no sender; the CLI only writes files. Check that the dry run did not
    // create anything outside its output directory and that the process ended by itself within a bounded time.
    let dir = temp_dir("no-network");
    let out = dir.join("acceptance-no-network");
    let started = std::time::Instant::now();
    let output = Command::new(bin())
        .args(["run", "--dry-run", "--out"])
        .arg(&out)
        .output()
        .expect("run");
    assert!(output.status.success());
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "a dry run is a local file operation: {:?}",
        started.elapsed()
    );
    let count = std::fs::read_dir(&out).expect("read dir").count();
    assert_eq!(count, 3, "report.md, report.json and run.log");
    assert!(Path::new(&out).is_dir());
}

fn example_profile_with_load_approved() -> String {
    example_profile_with_emails().replace(
        "load_profile_approved: false",
        "load_profile_approved: true",
    )
}

#[test]
fn an_invalid_operator_approval_ticket_is_a_usage_error() {
    let output = Command::new(bin())
        .args(["run", "--dry-run", "--operator-approval", "no-keys-here"])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("BadApproval") || stderr.contains("ticket"),
        "{stderr}"
    );
}

#[test]
fn the_operator_approval_flag_is_named_as_the_spec_names_it() {
    let output = Command::new(bin())
        .arg("run")
        .arg("--help")
        .output()
        .expect("help");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--operator-approval"), "{stdout}");
    assert!(
        !stdout.contains("--maintenance-window"),
        "the old flag is gone: {stdout}"
    );
    assert!(stdout.contains("--resume"), "{stdout}");
}

#[test]
fn a_valid_operator_approval_ticket_is_accepted() {
    let dir = temp_dir("operator-approval");
    let profile = dir.join("hdd.live.yaml");
    std::fs::write(&profile, example_profile_with_load_approved()).expect("write");
    let out = dir.join("acceptance-approval");
    let output = Command::new(bin())
        .args(["run", "--profile"])
        .arg(&profile)
        .args([
            "--load-profile",
            "load",
            "--operator-approval",
            "run=run-20261020-01; window=2026-10-21 02:00-03:00 UTC",
            // Review item R-13: the ticket is bound to the run it names.
            "--run-id",
            "run-20261020-01",
            "--out",
        ])
        .arg(&out)
        .output()
        .expect("run");
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let markdown = std::fs::read_to_string(out.join("report.md")).expect("report.md");
    assert!(markdown.contains("| Load profile | load |"), "{markdown}");
}

/// Review item R-2: the old CLI test codified a hand-edited `PASS` line with `sha256 = "aaaa…"` being accepted. It is now
/// refused: the previous report carries no config-revision/hostname binding, so its PASS lines cannot be verified. (This is
/// the re-created red demonstration for R-2: before the fix this command exited 0 and the report said `1 PASS`.)
#[test]
fn a_resume_refuses_a_hand_edited_pass_line_with_a_fake_hash() {
    let dir = temp_dir("resume-fake");
    let first = Command::new(bin())
        .args(["run", "--dry-run", "--out"])
        .arg(dir.join("previous"))
        .output()
        .expect("first run");
    assert!(first.status.success());
    let report_path = dir.join("previous/report.json");
    let text = std::fs::read_to_string(&report_path).expect("read report");
    let mut value: serde_json::Value = serde_json::from_str(&text).expect("json");
    value["lines"][0]["verdict"] = serde_json::json!({"status": "pass"});
    value["lines"][0]["evidence"] = serde_json::json!([
        {"path": "run.log", "sha256": "a".repeat(64), "bytes": 10}
    ]);
    std::fs::write(
        &report_path,
        serde_json::to_string_pretty(&value).expect("json"),
    )
    .expect("write");
    let output = Command::new(bin())
        .args(["run", "--dry-run", "--resume"])
        .arg(dir.join("previous"))
        .arg("--out")
        .arg(dir.join("resumed"))
        .output()
        .expect("resume");
    assert_eq!(
        output.status.code(),
        Some(3),
        "a hand-edited PASS column must be refused, not reused: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot resume"), "{stderr}");
    assert!(stderr.to_ascii_lowercase().contains("binding"), "{stderr}");
    assert!(
        !dir.join("resumed/report.md").exists(),
        "a refused resume writes no report"
    );
}

/// Review item R-2: a PASS line is reused only when the report is bound to the same config revision and target host names
/// and the evidence file inside the resume directory still hashes to the recorded SHA-256.
#[test]
fn a_resume_keeps_a_previous_pass_line_with_matching_binding_and_evidence() {
    let dir = temp_dir("resume-bound");
    let profile = dir.join("hdd.live.yaml");
    std::fs::write(&profile, example_profile_with_emails()).expect("write");
    let previous = dir.join("previous");
    let first = Command::new(bin())
        .args(["run", "--profile"])
        .arg(&profile)
        .args(["--config-revision", "rev-1", "--out"])
        .arg(&previous)
        .output()
        .expect("first run");
    assert!(
        first.status.success(),
        "{} {}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    // Promote AC-01 to PASS with a real artifact, as a real run would have left it. AC-00 is promoted to PASS as well:
    // AC-00 always re-runs (review item N-3), so the shared selection function must ignore that PASS line.
    let proof = b"previous run evidence";
    std::fs::write(previous.join("proof.txt"), proof).expect("write artifact");
    let artifact = serde_json::json!([{
        "path": "proof.txt",
        "sha256": hdd_acceptance::report::sha256_hex(proof),
        "bytes": proof.len(),
    }]);
    let self_test_proof = b"previous self-test evidence";
    std::fs::write(previous.join("proof-ac00.txt"), self_test_proof)
        .expect("write self-test artifact");
    let self_test_artifact = serde_json::json!([{
        "path": "proof-ac00.txt",
        "sha256": hdd_acceptance::report::sha256_hex(self_test_proof),
        "bytes": self_test_proof.len(),
    }]);
    let report_path = previous.join("report.json");
    let text = std::fs::read_to_string(&report_path).expect("read report");
    let mut value: serde_json::Value = serde_json::from_str(&text).expect("json");
    value["lines"][0]["verdict"] = serde_json::json!({"status": "pass"});
    value["lines"][0]["evidence"] = self_test_artifact;
    value["lines"][1]["verdict"] = serde_json::json!({"status": "pass"});
    value["lines"][1]["evidence"] = artifact;
    std::fs::write(
        &report_path,
        serde_json::to_string_pretty(&value).expect("json"),
    )
    .expect("write");
    let output = Command::new(bin())
        .args(["run", "--profile"])
        .arg(&profile)
        .args(["--config-revision", "rev-1", "--resume"])
        .arg(&previous)
        .arg("--out")
        .arg(dir.join("resumed"))
        .output()
        .expect("resume");
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let markdown = std::fs::read_to_string(dir.join("resumed/report.md")).expect("report");
    assert!(markdown.contains("1 PASS line(s) reused"), "{markdown}");
    assert!(markdown.contains("1 PASS"), "{markdown}");
    // Review item N-3: the CLI path uses the shared selection function, so a resumed AC-00 PASS is never credited.
    let resumed_json =
        std::fs::read_to_string(dir.join("resumed/report.json")).expect("resumed report");
    let resumed: serde_json::Value = serde_json::from_str(&resumed_json).expect("json");
    let lines = resumed["lines"].as_array().expect("lines");
    let ac00 = lines
        .iter()
        .find(|line| line["id"] == "AC-00")
        .expect("AC-00 line");
    assert_eq!(
        ac00["verdict"]["status"], "unverified",
        "AC-00 must stay UNVERIFIED after a resume (review item N-3): {ac00}"
    );
    let ac01 = lines
        .iter()
        .find(|line| line["id"] == "AC-01")
        .expect("AC-01 line");
    assert_eq!(ac01["verdict"]["status"], "pass", "{ac01}");
    // Review item N-4: the resumed artifact is copied into the new run directory and the line points at the copy.
    let copied = dir.join("resumed/proof.txt");
    assert!(
        copied.is_file(),
        "the resumed evidence is copied: {copied:?}"
    );
    assert_eq!(std::fs::read(&copied).expect("read copy"), proof);
    let recorded_path = ac01["evidence"][0]["path"].as_str().expect("evidence path");
    assert!(
        recorded_path.contains("resumed"),
        "the resumed line points at the copy in the new run directory: {recorded_path}"
    );
}

#[test]
fn a_resume_without_a_previous_report_is_a_usage_error() {
    let dir = temp_dir("resume-missing");
    let output = Command::new(bin())
        .args(["run", "--dry-run", "--resume"])
        .arg(dir.join("nope"))
        .output()
        .expect("resume");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot resume"), "{stderr}");
}

/// Review item S-6: an existing non-empty `--out` is refused unless this is a resume.
#[test]
fn s6_a_non_empty_output_directory_is_refused_without_resume() {
    let dir = temp_dir("non-empty-out");
    let out = dir.join("acceptance");
    let first = Command::new(bin())
        .args(["run", "--dry-run", "--out"])
        .arg(&out)
        .output()
        .expect("first run");
    assert!(first.status.success(), "{first:?}");
    let second = Command::new(bin())
        .args(["run", "--dry-run", "--out"])
        .arg(&out)
        .output()
        .expect("second run");
    assert_eq!(
        second.status.code(),
        Some(2),
        "a non-empty --out must be refused without --resume: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("non-empty"),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
}

// ---------------------------------------------------------------------------------------------------------------
// Round-4 review items N-1, N-4, N-5 and N-3.
// ---------------------------------------------------------------------------------------------------------------

/// Review item N-4: resuming in place is refused with the documented rule; a fresh --out is required.
#[test]
fn n4_resuming_in_place_is_refused() {
    let dir = temp_dir("resume-in-place");
    let previous = dir.join("previous");
    let first = Command::new(bin())
        .args(["run", "--dry-run", "--out"])
        .arg(&previous)
        .output()
        .expect("first run");
    assert!(first.status.success());
    let output = Command::new(bin())
        .args(["run", "--dry-run", "--resume"])
        .arg(&previous)
        .arg("--out")
        .arg(&previous)
        .output()
        .expect("resume in place");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("in place"), "{stderr}");
}

/// Review item N-5: a short --redact-secret is an error, not silently dropped.
#[test]
fn n5_a_short_redact_secret_is_a_usage_error() {
    let dir = temp_dir("redact-short");
    let output = Command::new(bin())
        .args(["run", "--dry-run", "--redact-secret", "abc", "--out"])
        .arg(dir.join("run"))
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("at least 4"), "{stderr}");
}

/// Review item N-1: resuming an invalid previous run exits with the documented refusal code.
#[test]
fn n1_an_invalid_previous_run_is_refused_with_code_3() {
    let dir = temp_dir("invalid-previous");
    let previous = dir.join("previous");
    let first = Command::new(bin())
        .args(["run", "--dry-run", "--out"])
        .arg(&previous)
        .output()
        .expect("first run");
    assert!(first.status.success());
    let report_path = previous.join("report.json");
    let mut value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).expect("read report"))
            .expect("json");
    value["run_invalid"] = serde_json::json!(true);
    value["invalid_audit"] = serde_json::json!(["check AC-01 in run run-1: target refused"]);
    std::fs::write(
        &report_path,
        serde_json::to_string_pretty(&value).expect("json"),
    )
    .expect("write");
    let output = Command::new(bin())
        .args(["run", "--dry-run", "--resume"])
        .arg(&previous)
        .arg("--out")
        .arg(dir.join("resumed"))
        .output()
        .expect("resume");
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid"), "{stderr}");
}
