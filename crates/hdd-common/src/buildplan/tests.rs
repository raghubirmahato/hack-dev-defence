//! T-0561 steps 6 and 7: the build track and the "what can run here" plan (A5).
#![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]

use super::*;

fn tmpdir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("hdd-buildplan-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

fn verdict_of(plan: &[(&'static str, &'static str, Verdict)], id: &str) -> Verdict {
    plan.iter()
        .find(|(i, _, _)| *i == id)
        .map(|(_, _, v)| v.clone())
        .expect("row")
}

#[test]
fn a_machine_without_docker_is_track_l_on_every_os() {
    for os in [Os::Windows, Os::MacOs, Os::Linux, Os::Other] {
        assert_eq!(track(&Facts::bare(os)), Track::L, "{os:?}");
    }
}

#[test]
fn track_h_needs_linux_and_docker() {
    let mut f = Facts::bare(Os::Linux);
    f.docker = true;
    assert_eq!(track(&f), Track::H);
    f.os = Os::Windows;
    assert_eq!(track(&f), Track::L);
}

#[test]
fn detect_finds_only_files_on_the_path_and_runs_nothing() {
    let empty = tmpdir("empty");
    let f = Facts::detect(Some(empty.as_os_str()), Os::Linux);
    assert_eq!(f, Facts::bare(Os::Linux));

    let dir = tmpdir("tools");
    std::fs::write(dir.join("docker"), b"not a program").expect("write");
    std::fs::write(dir.join("nft"), b"x").expect("write");
    let f = Facts::detect(Some(dir.as_os_str()), Os::Linux);
    assert!(f.docker && f.nft && !f.dig && !f.redis && !f.postgres);
    assert_eq!(track(&f), Track::H);

    // a directory named like a tool is not a tool
    let dir2 = tmpdir("dirs");
    std::fs::create_dir_all(dir2.join("dig")).expect("mkdir");
    assert!(!Facts::detect(Some(dir2.as_os_str()), Os::Linux).dig);

    // windows suffixes only count on windows
    let dir3 = tmpdir("exe");
    std::fs::write(dir3.join("docker.exe"), b"x").expect("write");
    assert!(Facts::detect(Some(dir3.as_os_str()), Os::Windows).docker);
    assert!(!Facts::detect(Some(dir3.as_os_str()), Os::Linux).docker);
    assert_eq!(Facts::detect(None, Os::Linux), Facts::bare(Os::Linux));
}

#[test]
fn the_registry_table_has_every_check_once_in_order() {
    assert_eq!(ACCEPTANCE_CHECKS.len(), 63);
    for (i, (id, name, built, tier)) in ACCEPTANCE_CHECKS.iter().enumerate() {
        assert_eq!(*id, format!("AC-{i:02}"));
        assert!(
            !name.is_empty() && !built.is_empty() && !tier.is_empty(),
            "{id}"
        );
    }
}

#[test]
fn local_on_a_bare_windows_builder_gets_an_honest_plan() {
    let f = Facts::bare(Os::Windows);
    let p = plan(RuntimeProfile::Local, &f);
    assert_eq!(p.len(), 63);
    // kernel, public DNS and the lab are not available; the reasons differ
    assert!(matches!(
        verdict_of(&p, "AC-26"),
        Verdict::Unverified(Why::EnvironmentUnsupported, _)
    ));
    assert!(matches!(
        verdict_of(&p, "AC-03"),
        Verdict::Unverified(Why::EnvironmentUnsupported, _)
    ));
    assert!(matches!(
        verdict_of(&p, "AC-39"),
        Verdict::Unverified(Why::CapabilityNotSupplied, _)
    ));
    // the local tier and release-tier build checks can run
    assert_eq!(verdict_of(&p, "AC-55"), Verdict::Runnable);
    assert_eq!(verdict_of(&p, "AC-40"), Verdict::Runnable);
    assert_eq!(verdict_of(&p, "AC-36"), Verdict::Runnable);
    // checks against a running instance use the loopback instance in local
    assert_eq!(verdict_of(&p, "AC-07"), Verdict::Runnable);
    // a load run is never started without the written approval
    assert!(matches!(
        verdict_of(&p, "AC-24"),
        Verdict::Unverified(Why::HumanStepPending, _)
    ));
    // upstream DDoS readiness is a hosted contract
    assert!(matches!(
        verdict_of(&p, "AC-25"),
        Verdict::Unverified(Why::EnvironmentUnsupported, _)
    ));
}

#[test]
fn hosted_live_checks_wait_for_a_person_and_kernel_checks_need_linux_tools() {
    let p = plan(RuntimeProfile::Hosted, &Facts::bare(Os::Windows));
    assert!(matches!(
        verdict_of(&p, "AC-07"),
        Verdict::Unverified(Why::HumanStepPending, _)
    ));
    assert!(matches!(
        verdict_of(&p, "AC-03"),
        Verdict::Unverified(Why::HumanStepPending, _)
    ));
    assert!(matches!(
        verdict_of(&p, "AC-29"),
        Verdict::Unverified(Why::EnvironmentUnsupported, _)
    ));
    let mut linux = Facts::bare(Os::Linux);
    assert!(matches!(
        verdict_of(&plan(RuntimeProfile::Hosted, &linux), "AC-29"),
        Verdict::Unverified(Why::ToolUnavailable, _)
    ));
    linux.nft = true;
    // with the tools present only the lab (tier lab-full) is still missing
    assert!(matches!(
        verdict_of(&plan(RuntimeProfile::Hosted, &linux), "AC-29"),
        Verdict::Unverified(Why::CapabilityNotSupplied, _)
    ));
    // XDP additionally needs bpf-linker
    assert!(matches!(
        verdict_of(&plan(RuntimeProfile::Hosted, &linux), "AC-26"),
        Verdict::Unverified(Why::ToolUnavailable, _)
    ));
    linux.bpf_linker = true;
    assert!(matches!(
        verdict_of(&plan(RuntimeProfile::Hosted, &linux), "AC-26"),
        Verdict::Unverified(Why::CapabilityNotSupplied, _)
    ));
}

#[test]
fn the_rendered_section_prints_track_l_and_both_lists_for_a_bare_machine() {
    let text = render(RuntimeProfile::Local, &Facts::bare(Os::Windows));
    assert!(text.contains("Build track: Track L"), "{text}");
    assert!(text.contains("Docker not found"));
    assert!(text.contains("Can run here ("));
    assert!(text.contains("AC-55"));
    assert!(text.contains("UNVERIFIED(environment_unsupported)"));
    assert!(text.contains("UNVERIFIED(capability_not_supplied)"));
    assert!(text.contains("dig not found") && text.contains("nft not found"));
    // every check appears exactly once, either runnable or in a group
    for (id, ..) in ACCEPTANCE_CHECKS {
        assert_eq!(text.matches(id).count(), 1, "{id} in\n{text}");
    }
}
