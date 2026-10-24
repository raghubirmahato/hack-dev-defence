//! End-to-end tests of `hddctl preflight` as a user runs it (T-0006 steps 6 and 7, A1 to A4).
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test helpers"
)]

use std::path::PathBuf;
use std::process::{Command, Output};

fn hddctl() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hddctl"))
}

fn example_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("hdd.live.example.yaml")
}

fn temp_file(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hddctl-preflight-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let p = dir.join("hdd.live.yaml");
    std::fs::write(&p, content).expect("write");
    p
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// A hosted profile with every required field filled.
fn complete_profile(extra: &str) -> String {
    let example = std::fs::read_to_string(example_path()).expect("example");
    example
        .replace("operator_email: ''", "operator_email: ops@hdd-ops.dev")
        .replace(
            "acme: {email: '', directory: staging}",
            "acme: {email: ops@hdd-ops.dev, directory: staging}",
        )
        + extra
}

#[test]
fn a1_the_example_file_fails_only_on_the_empty_required_fields_with_remediation() {
    let out = hddctl()
        .args(["preflight", "--profile-only", "--file"])
        .arg(example_path())
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(
        t.contains("PROF-REQUIRED") && t.contains("operator_email") && t.contains("acme.email"),
        "{t}"
    );
    assert!(
        t.contains("-> Set `operator_email` to the address that receives test mail"),
        "{t}"
    );
    assert!(t.matches("FAIL").count() >= 2, "{t}");
    assert!(t.contains("2 FAIL"), "{t}");
    assert!(
        t.contains("UNVERIFIED(human_step_pending)") && t.contains("PASS"),
        "{t}"
    );
}

#[test]
fn a_complete_profile_passes_profile_only_preflight() {
    let p = temp_file("complete", &complete_profile(""));
    let out = hddctl()
        .args(["preflight", "--profile-only", "--file"])
        .arg(&p)
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("0 FAIL"), "{t}");
}

#[test]
fn a2_the_runner_ip_inside_admin_cidrs_fails_with_the_documented_message() {
    let p = temp_file(
        "runner",
        &complete_profile("").replace("admin_cidrs: []", "admin_cidrs: ['198.51.100.0/24']"),
    );
    let out = hddctl()
        .args([
            "preflight",
            "--profile-only",
            "--runner-ip",
            "198.51.100.77",
            "--file",
        ])
        .arg(&p)
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(
        t.contains("admin_cidrs contains the runner IP 198.51.100.77 (matched by 198.51.100.0/24)"),
        "{t}"
    );
    assert!(t.contains("must stay bannable"), "{t}");
}

#[test]
fn a3_unknown_keys_are_rejected_with_the_key_path() {
    let p = temp_file(
        "unknown",
        &complete_profile("").replace("  mode: invite_only", "  mode: invite_only\n  modee: x"),
    );
    let out = hddctl()
        .args(["preflight", "--profile-only", "--file"])
        .arg(&p)
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("key path: signup.modee"), "{t}");
    assert!(t.contains("unknown key"), "{t}");
}

#[test]
fn a4_a_token_in_a_name_field_is_rejected_and_never_echoed() {
    let token = format!("{}_{}", "ghp", "abcdefghijklmnopqrstuvwxyz0123456789"); // hdd-secret-scan:allow (test vector)
    let p = temp_file(
        "token",
        &complete_profile("").replace(
            "registrar: {provider: '', api_token_env: ''}",
            &format!("registrar: {{provider: x, api_token_env: {token}}}"),
        ),
    );
    let out = hddctl()
        .args(["preflight", "--profile-only", "--file"])
        .arg(&p)
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("key path: registrar.api_token_env"), "{t}");
    assert!(t.contains("environment variable"), "{t}");
    assert!(
        !t.contains("abcdefghijklmnop"),
        "the rejected value must not be printed: {t}"
    );
}

#[test]
fn a_missing_file_prints_every_required_field_and_how_to_provide_it() {
    let missing = std::env::temp_dir()
        .join("hddctl-no-such-profile")
        .join("hdd.live.yaml");
    let out = hddctl()
        .args(["preflight", "--profile-only", "--file"])
        .arg(&missing)
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("FAIL: cannot read"), "{t}");
    for field in [
        "operator_email",
        "platform_domain",
        "test_hostname",
        "sandbox_hostname",
        "origin.url",
        "platform.ns_hostnames",
        "acme.email",
    ] {
        assert!(t.contains(field), "{field} missing in: {t}");
    }
    let local = hddctl()
        .args(["preflight", "--profile-only", "--local", "--file"])
        .arg(&missing)
        .output()
        .expect("run");
    let lt = text(&local);
    assert!(
        lt.contains("operator_email") && !lt.contains("test_hostname"),
        "{lt}"
    );
}

#[test]
fn full_preflight_runs_the_probes_but_only_through_the_allowlist() {
    // with an empty allowlist no probe may touch the network: the result must be UNVERIFIED, not a connect attempt
    let p = temp_file(
        "probes",
        &complete_profile("").replace("smtp: {host: ''", "smtp: {host: 'mail.hdd-ops.dev'"),
    );
    let out = hddctl()
        .args(["preflight", "--file"])
        .arg(&p)
        .output()
        .expect("run");
    let t = text(&out);
    assert!(
        t.contains("PROBE-NS") && t.contains("no `dns://` resolver"),
        "{t}"
    );
    assert!(
        t.contains("PROBE-SMTP")
            && t.contains("is a name and egress_allowlist has no `dns://` resolver"),
        "a relay given by name is never resolved through the system resolver: {t}"
    );
    assert!(t.contains("T-0217"), "{t}");

    // a relay given as an IP literal needs no resolution, but still needs its own tcp:// entry before any connection
    let lit = temp_file(
        "probes-literal",
        &complete_profile("").replace("smtp: {host: ''", "smtp: {host: '203.0.113.5'"),
    );
    let out = hddctl()
        .args(["preflight", "--file"])
        .arg(&lit)
        .output()
        .expect("run");
    let t = text(&out);
    assert!(
        t.contains(
            "tcp://203.0.113.5:587 is not on egress_allowlist, so the connection was not attempted"
        ),
        "{t}"
    );
}

#[test]
fn the_profile_only_mode_never_prints_probe_sections() {
    let p = temp_file("noprobes", &complete_profile(""));
    let out = hddctl()
        .args(["preflight", "--profile-only", "--file"])
        .arg(&p)
        .output()
        .expect("run");
    assert!(!text(&out).contains("PROBE-"));
}

/// A machine with nothing optional on its PATH (T-0561 A5).
fn bare_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hddctl-bare-path-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

#[test]
fn t0561_a5_a_machine_without_docker_postgres_redis_nft_and_dig_gets_track_l_and_exit_zero() {
    let path = bare_path("plan");
    let out = hddctl()
        .args(["preflight", "--plan", "--local"])
        .env("PATH", &path)
        .env_remove("HDD_RUNTIME_PROFILE")
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("Build track: Track L"), "{t}");
    for tool in [
        "Docker not found",
        "PostgreSQL server not found",
        "Redis or Valkey not found",
        "nft not found",
        "dig not found",
    ] {
        assert!(t.contains(tool), "{tool} in\n{t}");
    }
    assert!(t.contains("Can run here ("), "{t}");
    assert!(t.contains("AC-55"), "{t}");
    assert!(t.contains("UNVERIFIED(environment_unsupported)"), "{t}");
    assert!(t.contains("ERR-LOCAL-001"), "{t}");
}

#[test]
fn t0561_the_plan_follows_hdd_runtime_profile_and_a_missing_profile_file_still_prints_it() {
    let path = bare_path("env");
    let out = hddctl()
        .args(["preflight", "--plan"])
        .env("PATH", &path)
        .env("HDD_RUNTIME_PROFILE", "local")
        .output()
        .expect("run");
    assert!(
        text(&out).contains("runtime.profile: local"),
        "{}",
        text(&out)
    );
    let out = hddctl()
        .args(["preflight", "--profile-only", "--file", "no-such-file.yaml"])
        .env("PATH", &path)
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("Build track: Track L"), "{t}");
}
