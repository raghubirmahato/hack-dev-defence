//! Control-plane tests: the runner-IP bannability rule (reusing the validator's rule), SSH argv construction without
//! execution, and the vantage-point plan. A real SSH or WireGuard peer is not supplied here; those checks are
//! `UNVERIFIED(capability_not_supplied)` and only their non-network halves are tested.

use std::net::IpAddr;

use hdd_common::profile::types::{ControlPlaneAccess, VantagePoint};

use super::*;
use crate::test_support::{profile, profile_missing_required};

fn ip(text: &str) -> IpAddr {
    text.parse().expect("test IP")
}

#[test]
fn the_runner_is_bannable_when_it_is_not_in_admin_cidrs() {
    let mut p = profile();
    p.admin_cidrs = vec!["203.0.113.0/24".to_owned()];
    let bannable = runner_bannable(&p, Some(ip("198.51.100.77"))).expect("check");
    assert_eq!(
        bannable,
        Bannable::Bannable {
            runner: ip("198.51.100.77")
        }
    );
    assert!(bannable.is_bannable());
    assert!(bannable.to_string().contains("not in admin_cidrs"));
}

#[test]
fn a_runner_inside_admin_cidrs_is_refused() {
    let mut p = profile();
    p.admin_cidrs = vec!["198.51.100.0/24".to_owned()];
    let error = runner_bannable(&p, Some(ip("198.51.100.77"))).expect_err("must refuse");
    assert_eq!(
        error,
        ControlError::NotBannable {
            runner: ip("198.51.100.77"),
            matched: "198.51.100.0/24".to_owned()
        }
    );
    assert!(error.to_string().contains("must stay bannable"));
}

#[test]
fn an_auto_runner_ip_is_unverified_stage_not_reached() {
    let p = profile();
    assert_eq!(p.test_runner.public_ip.trim(), "auto");
    let bannable = runner_bannable(&p, None).expect("auto is not an error");
    assert_eq!(
        bannable,
        Bannable::Unverified {
            reason: ReasonCode::StageNotReached
        }
    );
    assert!(!bannable.is_bannable());
    assert!(bannable.to_string().contains("stage_not_reached"));
}

#[test]
fn a_mistyped_runner_ip_is_refused() {
    let mut p = profile();
    p.test_runner.public_ip = "999.51.100.77".to_owned();
    assert!(matches!(
        runner_bannable(&p, None),
        Err(ControlError::MalformedRunnerIp { .. })
    ));
}

#[test]
fn the_runner_ip_from_the_profile_is_used_when_the_caller_supplies_none() {
    let mut p = profile_missing_required();
    p.test_runner.public_ip = "198.51.100.77".to_owned();
    p.admin_cidrs = vec!["203.0.113.0/24".to_owned()];
    let bannable = runner_bannable(&p, None).expect("check");
    assert_eq!(
        bannable,
        Bannable::Bannable {
            runner: ip("198.51.100.77")
        }
    );
}

fn ssh_profile() -> hdd_common::profile::Profile {
    let mut p = profile();
    p.platform.ssh.host = "vps.example.com".to_owned();
    p.platform.ssh.user = "runner".to_owned();
    p.platform.ssh.key_path = hdd_common::profile::SecretPath::new("/home/runner/.ssh/hdd_ed25519");
    p.test_runner.control_plane_access = ControlPlaneAccess::SshTunnel;
    p
}

#[test]
fn the_ssh_command_is_an_argv_vector_with_batch_mode_and_no_shell() {
    let p = ssh_profile();
    let command = ssh_command(&p, "hddctl", &["unban", "198.51.100.7"]).expect("ssh argv");
    let argv = command.argv();
    assert_eq!(argv.first().map(String::as_str), Some("ssh"));
    assert!(argv.iter().any(|a| a == "BatchMode=yes"));
    assert!(argv.iter().any(|a| a == "StrictHostKeyChecking=yes"));
    assert!(argv.iter().any(|a| a == "ConnectTimeout=10"));
    assert!(argv.iter().any(|a| a == "IdentitiesOnly=yes"));
    assert!(argv.iter().any(|a| a == "/home/runner/.ssh/hdd_ed25519"));
    assert!(
        !argv.iter().any(|a| a == "-c"),
        "no shell command string is ever built"
    );
    assert_eq!(command.destination(), Some("runner@vps.example.com"));
    assert_eq!(command.remote_program(), Some("hddctl"));
    assert_eq!(argv.last().map(String::as_str), Some("198.51.100.7"));
    // `--` separates the destination from the remote argv
    let separator = argv.iter().position(|a| a == "--").expect("separator");
    assert_eq!(argv.get(separator + 1).map(String::as_str), Some("hddctl"));
}

#[test]
fn hostile_remote_arguments_stay_one_argv_element() {
    let p = ssh_profile();
    let hostile = ["a; rm -rf /", "$(reboot)", "x\ny", "`id`", "&& whoami"];
    let command = ssh_command(&p, "hddctl", &hostile).expect("ssh argv");
    let argv = command.argv();
    for (index, arg) in hostile.iter().enumerate() {
        assert_eq!(
            argv.get(argv.len() - hostile.len() + index)
                .map(String::as_str),
            Some(*arg),
            "the argument must not be split or interpreted"
        );
    }
}

#[test]
fn wireguard_and_missing_ssh_fields_are_typed_refusals() {
    let mut p = ssh_profile();
    p.test_runner.control_plane_access = ControlPlaneAccess::Wireguard;
    assert_eq!(
        ssh_command(&p, "hddctl", &[]).expect_err("wireguard"),
        ControlError::WireguardSelected
    );
    let message = ControlError::WireguardSelected.to_string();
    assert!(message.contains("capability_not_supplied"));

    let mut p = ssh_profile();
    p.platform.ssh.host = String::new();
    assert_eq!(
        ssh_command(&p, "hddctl", &[]).expect_err("missing host"),
        ControlError::MissingSshConfig {
            field: "platform.ssh.host"
        }
    );
    let mut p = ssh_profile();
    p.platform.ssh.user = String::new();
    assert_eq!(
        ssh_command(&p, "hddctl", &[]).expect_err("missing user"),
        ControlError::MissingSshConfig {
            field: "platform.ssh.user"
        }
    );
    let mut p = ssh_profile();
    p.platform.ssh.key_path = hdd_common::profile::SecretPath::new("");
    assert_eq!(
        ssh_command(&p, "hddctl", &[]).expect_err("missing key"),
        ControlError::MissingSshConfig {
            field: "platform.ssh.key_path"
        }
    );
}

#[test]
fn the_vantage_plan_records_the_count_and_the_sequential_strategy_when_absent() {
    let p = profile();
    assert!(p.vantage_points.is_empty());
    let plan = VantagePlan::from_profile(&p);
    assert_eq!(plan.count(), 0);
    assert_eq!(plan.strategy(), VantageStrategy::SequentialWithUnban);
    assert_eq!(plan.live_use_reason(), ReasonCode::CapabilityNotSupplied);

    let mut p = profile();
    p.vantage_points = vec![
        VantagePoint {
            name: "eu-west".to_owned(),
            ssh_host: "eu.example.com".to_owned(),
            ..VantagePoint::default()
        },
        VantagePoint {
            name: String::new(),
            ssh_host: "us.example.com".to_owned(),
            ..VantagePoint::default()
        },
    ];
    let plan = VantagePlan::from_profile(&p);
    assert_eq!(plan.count(), 2);
    assert_eq!(plan.strategy(), VantageStrategy::PerPoint);
    assert_eq!(
        plan.points(),
        &["eu-west".to_owned(), "us.example.com".to_owned()]
    );
}
