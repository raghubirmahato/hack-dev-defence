//! Table-driven validator tests: valid and invalid profiles (T-0006 tests, A2).
#![allow(
    clippy::field_reassign_with_default,
    reason = "tests build profiles by overriding single fields"
)]

use std::net::IpAddr;

use super::*;
use crate::profile::secrets::{EnvVarName, SecretPath};
use crate::profile::types::*;

/// A complete hosted profile that passes every FAIL rule.
fn ok_hosted() -> Profile {
    let mut p = Profile::default();
    p.platform_domain = "hdd-ops.dev".into();
    p.domain = "shop-site.org".into();
    p.test_hostname = "hddtest.shop-site.org".into();
    p.sandbox_hostname = "hddsbx.shop-site.org".into();
    p.surfaces.public_host = "www.hdd-ops.dev".into();
    p.surfaces.app_host = "app.hdd-ops.dev".into();
    p.surfaces.admin_host = "admin.hdd-ops.dev".into();
    p.surfaces.api_host = "api.hdd-ops.dev".into();
    p.surfaces.status_host = "status.hdd-ops.dev".into();
    p.origin.url = "https://198.18.0.10".into();
    p.origin.tls_server_name = "shop-site.org".into();
    p.origin.host_header = "shop-site.org".into();
    p.platform.public_ipv4 = vec!["198.18.0.20".into()];
    p.platform.ns_hostnames = vec!["ns1.hdd-ops.dev".into(), "ns2.hdd-ops.dev".into()];
    p.platform.edge_cname_zone = "edge.hdd-ops.dev".into();
    p.platform.acme_cname_zone = "acme.hdd-ops.dev".into();
    p.acme.email = "ops@hdd-ops.dev".into();
    p.operator_email = "ops@hdd-ops.dev".into();
    p
}

fn ok_local() -> Profile {
    let mut p = Profile::default();
    p.runtime.profile = RuntimeProfile::Local;
    p.operator_email = "me@example.net".into();
    p
}

fn run(p: &Profile) -> Report {
    validate(p, &Context::default())
}

fn has(r: &Report, rule: &str, status: Status) -> bool {
    r.findings
        .iter()
        .any(|f| f.rule == rule && f.status == status)
}

fn has_field(r: &Report, rule: &str, status: Status, field: &str) -> bool {
    r.findings
        .iter()
        .any(|f| f.rule == rule && f.status == status && f.field == field)
}

#[test]
fn the_baseline_profiles_have_no_failures() {
    let r = run(&ok_hosted());
    assert!(r.is_ok(), "{}", crate::profile::render_table(&r));
    let l = run(&ok_local());
    assert!(l.is_ok(), "{}", crate::profile::render_table(&l));
}

#[test]
fn every_finding_uses_a_catalogued_rule_and_failures_carry_remediation() {
    let mut p = ok_hosted();
    p.operator_email.clear();
    p.egress_allowlist = vec!["ftp://x.example.org".into()];
    p.admin_cidrs = vec!["nope".into()];
    let r = run(&p);
    let ids: Vec<&str> = RULES.iter().map(|(id, _)| *id).collect();
    for f in &r.findings {
        assert!(ids.contains(&f.rule), "uncatalogued rule {}", f.rule);
        if f.status == Status::Fail {
            assert!(!f.remediation.is_empty(), "FAIL without remediation: {f:?}");
        }
    }
    let mut rule_ids = ids.clone();
    rule_ids.sort_unstable();
    rule_ids.dedup();
    assert_eq!(rule_ids.len(), ids.len(), "duplicate rule ids");
}

#[test]
fn missing_required_fields_fail_one_finding_per_field() {
    let mut p = ok_hosted();
    p.domain.clear();
    p.origin.url.clear();
    p.platform.ns_hostnames.clear();
    let r = run(&p);
    for f in ["domain", "origin.url", "platform.ns_hostnames"] {
        assert!(has_field(&r, "PROF-REQUIRED", Status::Fail, f), "{f}");
    }
    assert_eq!(
        r.of_rule("PROF-REQUIRED")
            .iter()
            .filter(|f| f.status == Status::Fail)
            .count(),
        3
    );
}

#[test]
fn local_profile_needs_only_operator_email() {
    let mut p = ok_local();
    p.operator_email.clear();
    let r = run(&p);
    let missing: Vec<&str> = r
        .of_rule("PROF-REQUIRED")
        .iter()
        .filter(|f| f.status == Status::Fail)
        .map(|f| f.field.as_str())
        .collect();
    assert_eq!(missing, vec!["operator_email"]);
    assert!(has(&r, "PROF-NA-LOCAL", Status::NotApplicable));
}

#[test]
fn schema_version_must_be_five() {
    let mut p = ok_hosted();
    p.schema_version = 4;
    assert!(has(&run(&p), "PROF-SCHEMA", Status::Fail));
}

#[test]
fn hostname_syntax_is_checked() {
    for bad in [
        "bad_host.example.org",
        "-x.example.org",
        "localhost",
        "a..b.org",
    ] {
        let mut p = ok_hosted();
        p.surfaces.app_host = bad.into();
        assert!(
            has_field(&run(&p), "PROF-HOSTNAME", Status::Fail, "surfaces.app_host"),
            "{bad}"
        );
    }
}

#[test]
fn test_and_sandbox_must_be_distinct_subdomains_of_domain() {
    let mut p = ok_hosted();
    p.sandbox_hostname = p.test_hostname.clone();
    assert!(has_field(
        &run(&p),
        "PROF-TEST-SANDBOX",
        Status::Fail,
        "sandbox_hostname"
    ));

    let mut p = ok_hosted();
    p.test_hostname = "hddtest.other-site.org".into();
    assert!(has_field(
        &run(&p),
        "PROF-TEST-SANDBOX",
        Status::Fail,
        "test_hostname"
    ));

    let mut p = ok_hosted();
    p.sandbox_hostname = "shop-site.org".into();
    assert!(
        has_field(
            &run(&p),
            "PROF-TEST-SANDBOX",
            Status::Fail,
            "sandbox_hostname"
        ),
        "the apex itself is not a subdomain"
    );

    let mut p = ok_hosted();
    p.test_hostname = "hddtest.shop-site.org.evil.net".into();
    assert!(has_field(
        &run(&p),
        "PROF-TEST-SANDBOX",
        Status::Fail,
        "test_hostname"
    ));

    assert!(has(&run(&ok_hosted()), "PROF-TEST-SANDBOX", Status::Pass));
}

#[test]
fn platform_domain_must_be_a_registrable_apex() {
    for (value, ok) in [
        ("hdd-ops.dev", true),
        ("www.hdd-ops.dev", false),
        ("com", false),
        ("co.uk", false),
        ("hdd-ops.co.uk", true),
        ("sub.hdd-ops.co.uk", false),
    ] {
        let mut p = ok_hosted();
        p.platform_domain = value.into();
        let r = run(&p);
        let failed = has(&r, "PROF-PLATFORM-DOMAIN", Status::Fail);
        assert_eq!(
            failed,
            !ok,
            "{value}: {:?}",
            r.of_rule("PROF-PLATFORM-DOMAIN")
        );
    }
}

#[test]
fn cidrs_must_parse_and_broad_admin_ranges_warn() {
    let mut p = ok_hosted();
    p.admin_cidrs = vec!["203.0.113.0/24".into(), "garbage".into()];
    assert!(has_field(
        &run(&p),
        "PROF-CIDR",
        Status::Fail,
        "admin_cidrs[1]"
    ));
    let mut p = ok_hosted();
    p.ssh_allow_cidrs = vec!["10.0.0.0/33".into()];
    assert!(has_field(
        &run(&p),
        "PROF-CIDR",
        Status::Fail,
        "ssh_allow_cidrs[0]"
    ));
    let mut p = ok_hosted();
    p.admin_cidrs = vec!["0.0.0.0/0".into()];
    assert!(
        has_field(&run(&p), "PROF-CIDR", Status::Fail, "admin_cidrs[0]"),
        "a never-ban list covering the internet is a failure"
    );
    let mut p = ok_hosted();
    p.ssh_allow_cidrs = vec!["0.0.0.0/0".into()];
    let r = run(&p);
    assert!(has(&r, "PROF-CIDR", Status::Warn) && r.is_ok());
    let mut p = ok_hosted();
    p.upstream_cdn.trusted_cidrs = vec!["bad".into()];
    assert!(has_field(
        &run(&p),
        "PROF-CIDR",
        Status::Fail,
        "upstream_cdn.trusted_cidrs[0]"
    ));
}

#[test]
fn runner_ip_inside_admin_cidrs_fails_with_the_documented_message() {
    let mut p = ok_hosted();
    p.admin_cidrs = vec!["198.51.100.0/24".into()];
    let ctx = Context {
        runner_ip: Some("198.51.100.77".parse::<IpAddr>().expect("ip")),
    };
    let r = validate(&p, &ctx);
    let f = r
        .findings
        .iter()
        .find(|f| f.rule == "PROF-RUNNER-ADMIN")
        .expect("finding");
    assert_eq!(f.status, Status::Fail);
    assert!(
        f.message
            .contains("admin_cidrs contains the runner IP 198.51.100.77"),
        "{}",
        f.message
    );
    assert!(f.message.contains("matched by 198.51.100.0/24"));
    assert!(f.message.contains("must stay bannable"));
    assert!(f.remediation.contains("ssh_allow_cidrs"));
}

#[test]
fn runner_ip_from_the_profile_is_used_and_mapped_addresses_match() {
    let mut p = ok_hosted();
    p.test_runner.public_ip = "203.0.113.9".into();
    p.admin_cidrs = vec!["203.0.113.9".into()];
    assert!(has(&run(&p), "PROF-RUNNER-ADMIN", Status::Fail));
    p.test_runner.public_ip = "::ffff:203.0.113.9".into();
    assert!(has(&run(&p), "PROF-RUNNER-ADMIN", Status::Fail));
    p.test_runner.public_ip = "203.0.113.10".into();
    assert!(has(&run(&p), "PROF-RUNNER-ADMIN", Status::Pass));
}

#[test]
fn runner_auto_is_unverified_not_passed() {
    let r = run(&ok_hosted());
    assert!(has(
        &r,
        "PROF-RUNNER-ADMIN",
        Status::Unverified(Reason::StageNotReached)
    ));
}

#[test]
fn ssh_allow_cidrs_may_contain_the_runner() {
    let mut p = ok_hosted();
    p.test_runner.public_ip = "203.0.113.9".into();
    p.ssh_allow_cidrs = vec!["203.0.113.9/32".into()];
    assert!(run(&p).is_ok());
}

#[test]
fn empty_egress_allowlist_is_unverified_with_a_human_step() {
    assert!(has(
        &run(&ok_hosted()),
        "PROF-EGRESS",
        Status::Unverified(Reason::HumanStepPending)
    ));
}

#[test]
fn invalid_egress_entries_fail_with_their_index() {
    let mut p = ok_hosted();
    p.egress_allowlist = vec![
        "acme.hdd-ops.dev".into(),
        "gopher://x.hdd-ops.dev".into(),
        "tcp://mail.hdd-ops.dev".into(),
    ];
    let r = run(&p);
    assert!(has_field(
        &r,
        "PROF-EGRESS",
        Status::Fail,
        "egress_allowlist[1]"
    ));
    assert!(has_field(
        &r,
        "PROF-EGRESS",
        Status::Fail,
        "egress_allowlist[2]"
    ));
    assert!(!has_field(
        &r,
        "PROF-EGRESS",
        Status::Fail,
        "egress_allowlist[0]"
    ));
}

#[test]
fn egress_must_cover_the_smtp_relay_and_other_configured_hosts() {
    let mut p = ok_hosted();
    p.smtp.host = "mail.hdd-ops.dev".into();
    p.smtp.port = 587;
    p.egress_allowlist = vec!["acme.hdd-ops.dev".into()];
    assert!(has_field(
        &run(&p),
        "PROF-EGRESS",
        Status::Fail,
        "smtp.host"
    ));
    p.egress_allowlist.push("tcp://mail.hdd-ops.dev:587".into());
    assert!(!has(&run(&p), "PROF-EGRESS", Status::Fail));
    p.signup.password_breach_check = BreachCheck::HibpRange;
    assert!(has_field(
        &run(&p),
        "PROF-EGRESS",
        Status::Fail,
        "signup.password_breach_check"
    ));
    p.egress_allowlist
        .push("api.pwnedpasswords.com/range".into());
    assert!(!has(&run(&p), "PROF-EGRESS", Status::Fail));
    p.geoip.source = "https://download.maxmind.example/geolite".into();
    assert!(has_field(
        &run(&p),
        "PROF-EGRESS",
        Status::Fail,
        "geoip.source"
    ));
}

#[test]
fn acme_defaults_to_staging_and_production_needs_approval() {
    assert!(has(&run(&ok_hosted()), "PROF-ACME", Status::Pass));
    let mut p = ok_hosted();
    p.acme.directory = AcmeDirectory::Production;
    assert!(has(
        &run(&p),
        "PROF-ACME",
        Status::Unverified(Reason::HumanStepPending)
    ));
    let mut p = ok_hosted();
    p.acme.email = "not-an-email".into();
    assert!(has_field(&run(&p), "PROF-ACME", Status::Fail, "acme.email"));
}

#[test]
fn open_signup_is_flagged_for_approval_on_hosted_and_refused_on_local() {
    let mut p = ok_hosted();
    p.signup.mode = SignupMode::Open;
    let r = run(&p);
    assert!(has(
        &r,
        "PROF-SIGNUP",
        Status::Unverified(Reason::HumanStepPending)
    ));
    assert!(r.is_ok(), "needs approval, but is not a failure");
    let mut l = ok_local();
    l.signup.mode = SignupMode::Open;
    assert!(has(&run(&l), "PROF-LOCAL", Status::Fail));
}

#[test]
fn local_profile_refuses_saas_routed_admin_and_port_clashes() {
    let mut l = ok_local();
    l.deployment_mode = DeploymentMode::Saas;
    assert!(has_field(
        &run(&l),
        "PROF-LOCAL",
        Status::Fail,
        "deployment_mode"
    ));
    let mut l = ok_local();
    l.surfaces.admin_exposure = AdminExposure::RoutedWithCidr;
    assert!(has_field(
        &run(&l),
        "PROF-LOCAL",
        Status::Fail,
        "surfaces.admin_exposure"
    ));
    let mut l = ok_local();
    l.runtime.local.ports.api = l.runtime.local.ports.web;
    assert!(has_field(
        &run(&l),
        "PROF-LOCAL",
        Status::Fail,
        "runtime.local.ports"
    ));
    let mut l = ok_local();
    l.runtime.local.ports.dns = 53;
    let r = run(&l);
    assert!(has(&r, "PROF-LOCAL", Status::Warn) && r.is_ok());
    let mut l = ok_local();
    l.runtime.local.lan_exposure = true;
    l.runtime.local.tls = LocalTls::HttpOnly;
    assert!(has_field(
        &run(&l),
        "PROF-LOCAL",
        Status::Fail,
        "runtime.local.tls"
    ));
    let mut l = ok_local();
    l.runtime.local.lan_exposure = true;
    let r = run(&l);
    assert!(r.is_ok() && has_field(&r, "PROF-LOCAL", Status::Warn, "runtime.local.lan_exposure"));
}

#[test]
fn origin_url_and_tls_verification_are_checked() {
    for bad in [
        "ftp://x.hdd-ops.dev",
        "198.18.0.10",
        "https://u:p@x.hdd-ops.dev",
        "https://",
        "https://host_name.org",
    ] {
        let mut p = ok_hosted();
        p.origin.url = bad.into();
        assert!(
            has_field(&run(&p), "PROF-ORIGIN", Status::Fail, "origin.url"),
            "{bad}"
        );
    }
    let mut p = ok_hosted();
    p.origin.url = "http://198.18.0.10:8080".into();
    let r = run(&p);
    assert!(has(&r, "PROF-ORIGIN", Status::Warn) && r.is_ok());
    let mut p = ok_hosted();
    p.origin.tls_verify.mode = TlsVerifyMode::PinnedSpki;
    assert!(has_field(
        &run(&p),
        "PROF-ORIGIN",
        Status::Fail,
        "origin.tls_verify.pin"
    ));
    p.origin.tls_verify.pin = "sha256/AAAA".into();
    assert!(!has(&run(&p), "PROF-ORIGIN", Status::Fail));
}

#[test]
fn platform_addresses_and_ssh_deploy_requirements() {
    let mut p = ok_hosted();
    p.platform.public_ipv4 = vec!["2001:db8::1".into()];
    assert!(has(&run(&p), "PROF-PLATFORM", Status::Fail));
    let mut p = ok_hosted();
    p.platform.public_ipv6 = vec!["198.18.0.1".into()];
    assert!(has(&run(&p), "PROF-PLATFORM", Status::Fail));
    let mut p = ok_hosted();
    p.platform.public_ipv4 = vec!["10.0.0.5".into()];
    let r = run(&p);
    assert!(has(&r, "PROF-PLATFORM", Status::Warn) && r.is_ok());
    let mut p = ok_hosted();
    p.platform.deploy_mode = DeployMode::Ssh;
    let r = run(&p);
    for f in [
        "platform.ssh.host",
        "platform.ssh.user",
        "platform.ssh.key_path",
    ] {
        assert!(has_field(&r, "PROF-PLATFORM", Status::Fail, f), "{f}");
    }
    p.platform.ssh = Ssh {
        host: "203.0.113.5".into(),
        user: "deploy".into(),
        key_path: SecretPath::new("/home/op/.ssh/id_ed25519"),
    };
    assert!(!has(&run(&p), "PROF-PLATFORM", Status::Fail));
}

#[test]
fn dns_topology_and_secondary_requirements() {
    let mut p = ok_hosted();
    p.dns.topology = DnsTopology::HiddenPrimary;
    assert!(has_field(
        &run(&p),
        "PROF-DNS",
        Status::Fail,
        "dns.public_ns"
    ));
    let mut p = ok_hosted();
    p.secondary_dns.provider = "provider-x".into();
    let r = run(&p);
    assert!(has_field(
        &r,
        "PROF-DNS",
        Status::Fail,
        "secondary_dns.addresses"
    ));
    assert!(has_field(
        &r,
        "PROF-DNS",
        Status::Fail,
        "secondary_dns.tsig_key_env"
    ));
    assert!(has(
        &run(&ok_hosted()),
        "PROF-DNS",
        Status::Unverified(Reason::CapabilityNotSupplied)
    ));
}

#[test]
fn production_lifecycle_requires_lockdown_and_a_ddos_statement() {
    let mut p = ok_hosted();
    p.lifecycle_stage = LifecycleStage::Production;
    let r = run(&p);
    assert!(has_field(
        &r,
        "PROF-LIFECYCLE",
        Status::Fail,
        "origin.lockdown_state"
    ));
    assert!(has_field(
        &r,
        "PROF-LIFECYCLE",
        Status::Fail,
        "upstream_ddos.mode"
    ));
    p.origin.lockdown_state = LockdownState::Applied;
    p.upstream_ddos.mode = DdosMode::AlwaysOn;
    p.upstream_ddos.provider = "scrub-co".into();
    p.upstream_ddos.advertised_capacity_gbps = 100.0;
    assert!(!has(&run(&p), "PROF-LIFECYCLE", Status::Fail));
    let pilot = run(&ok_hosted());
    assert!(
        has(&pilot, "PROF-LIFECYCLE", Status::Warn) && pilot.is_ok(),
        "pilot with no mitigation is a warning"
    );
}

#[test]
fn smtp_rules() {
    let mut p = ok_hosted();
    p.smtp.host = "mail.hdd-ops.dev".into();
    p.smtp.tls = SmtpTls::None;
    assert!(has_field(&run(&p), "PROF-SMTP", Status::Fail, "smtp.tls"));
    let mut p = ok_hosted();
    p.smtp.host = "mail.hdd-ops.dev".into();
    p.smtp.username_env = EnvVarName::parse("SMTP_USER").expect("name");
    assert!(has_field(
        &run(&p),
        "PROF-SMTP",
        Status::Fail,
        "smtp.username_env"
    ));
    let mut p = ok_hosted();
    p.smtp.host = "mail.hdd-ops.dev".into();
    p.smtp.from_address = "bad".into();
    assert!(has_field(
        &run(&p),
        "PROF-SMTP",
        Status::Fail,
        "smtp.from_address"
    ));
    assert!(has(
        &run(&ok_hosted()),
        "PROF-SMTP",
        Status::Unverified(Reason::HumanStepPending)
    ));
}

#[test]
fn floors_may_only_be_tightened() {
    let mut p = ok_hosted();
    p.retention.audit_days = 179;
    assert!(has_field(
        &run(&p),
        "PROF-POLICY",
        Status::Fail,
        "retention.audit_days"
    ));
    let mut p = ok_hosted();
    p.retention.events_days = 0;
    assert!(has_field(
        &run(&p),
        "PROF-POLICY",
        Status::Fail,
        "retention.events_days"
    ));
    let mut p = ok_hosted();
    p.signup.min_password_length = 11;
    assert!(has_field(
        &run(&p),
        "PROF-POLICY",
        Status::Fail,
        "signup.min_password_length"
    ));
    p.signup.min_password_length = 16;
    p.retention.audit_days = 180;
    assert!(!has(&run(&p), "PROF-POLICY", Status::Fail));
    let mut p = ok_hosted();
    p.locales = vec!["EN".into()];
    assert!(has_field(&run(&p), "PROF-POLICY", Status::Fail, "locales"));
    p.locales = vec!["en".into(), "de-DE".into()];
    assert!(!has(&run(&p), "PROF-POLICY", Status::Fail));
}

#[test]
fn lab_and_load_rules() {
    let mut p = ok_hosted();
    p.lab.vulnlab_enabled = true;
    assert!(has_field(
        &run(&p),
        "PROF-LAB",
        Status::Fail,
        "lab.vulnlab_enabled"
    ));
    let mut p = ok_hosted();
    p.lab.enabled = true;
    assert!(has_field(&run(&p), "PROF-LAB", Status::Fail, "lab.host"));
    p.lab.host = "lab.internal".into();
    p.lab.cidr = "10.99.0.0/24".into();
    assert!(has(&run(&p), "PROF-LAB", Status::Pass));
    let mut p = ok_hosted();
    p.load_profile_approved = true;
    assert!(has(
        &run(&p),
        "PROF-LOAD",
        Status::Unverified(Reason::HumanStepPending)
    ));
}

#[test]
fn placeholders_warn_but_do_not_fail() {
    let mut p = ok_hosted();
    p.test_hostname = "hddtest.example.com".into();
    p.sandbox_hostname = "hddsbx.example.com".into();
    p.domain = "example.com".into();
    p.platform.public_ipv4 = vec!["198.51.100.20".into()];
    let r = run(&p);
    assert!(r.is_ok(), "{}", crate::profile::render_table(&r));
    let w = r.of_rule("PROF-PLACEHOLDER");
    assert_eq!(w.len(), 1);
    assert_eq!(w[0].status, Status::Warn);
    assert!(w[0].field.contains("domain") && w[0].field.contains("platform.public_ip[0]"));
}

#[test]
fn probes_are_reported_as_not_run_by_the_validator() {
    assert!(has(
        &run(&ok_hosted()),
        "PROF-PROBES",
        Status::Unverified(Reason::StageNotReached)
    ));
}

#[test]
fn validation_is_deterministic() {
    let p = ok_hosted();
    assert_eq!(run(&p), run(&p));
}

#[test]
fn rendering_includes_remediation_and_totals() {
    let mut p = ok_hosted();
    p.operator_email.clear();
    let table = crate::profile::render_table(&run(&p));
    assert!(table.contains("PROF-REQUIRED"));
    assert!(table.contains("-> Set `operator_email` to the address that receives test mail"));
    assert!(table.contains("FAIL"));
    assert!(
        table
            .lines()
            .last()
            .is_some_and(|_| table.contains(" PASS, "))
    );
}

#[test]
fn rejected_values_are_never_repeated_in_full() {
    let secretish = "https://user:hunter2hunter2@hdd-ops.dev/x?token=abcdef123456"; // hdd-secret-scan:allow (test vector)
    let mut p = ok_hosted();
    p.egress_allowlist = vec![secretish.into()];
    p.origin.url = secretish.into();
    p.admin_cidrs = vec!["ghp-0123456789abcdefghijklmnopqrstuvwxyz".into()]; // hdd-secret-scan:allow (test vector)
    p.surfaces.app_host = "ghp_0123456789abcdefghijklmnopqrstuvwxyz".into(); // hdd-secret-scan:allow (test vector)
    p.operator_email = "ghp_0123456789abcdefghijklmnopqrstuvwxyz".into(); // hdd-secret-scan:allow (test vector)
    let table = crate::profile::render_table(&run(&p));
    for leak in ["hunter2", "abcdef123456", "0123456789abcdef"] {
        assert!(!table.contains(leak), "{leak} leaked:\n{table}");
    }
    assert!(table.contains("entry 0 is not valid"));
}

#[test]
fn lab_cidr_must_be_a_private_range_and_must_not_contain_the_platform() {
    let lab = |cidr: &str| {
        let mut p = ok_hosted();
        p.lab.enabled = true;
        p.lab.host = "lab.internal".into();
        p.lab.cidr = cidr.into();
        p
    };
    for bad in [
        "0.0.0.0/0",
        "8.8.8.0/24",
        "198.18.0.0/24",
        "10.0.0.0/7",
        "2001:db8::/32",
    ] {
        assert!(
            has_field(&run(&lab(bad)), "PROF-LAB", Status::Fail, "lab.cidr"),
            "{bad}"
        );
    }
    for good in [
        "10.99.0.0/24",
        "192.168.50.0/24",
        "172.16.0.0/16",
        "fd12:3456::/48",
        "127.0.0.0/8",
    ] {
        let r = run(&lab(good));
        assert!(
            has(&r, "PROF-LAB", Status::Pass) && r.is_ok(),
            "{good}: {}",
            crate::profile::render_table(&r)
        );
    }
    let mut overlapping = lab("10.99.0.0/24");
    overlapping.platform.public_ipv4 = vec!["10.99.0.20".into()];
    assert!(has_field(
        &run(&overlapping),
        "PROF-LAB",
        Status::Fail,
        "lab.cidr"
    ));
}

#[test]
fn domain_must_not_be_a_public_suffix() {
    for suffix in ["com", "co.uk", "org.au"] {
        let mut p = ok_hosted();
        p.domain = suffix.into();
        p.test_hostname = format!("hddtest.{suffix}");
        p.sandbox_hostname = format!("hddsbx.{suffix}");
        assert!(
            has_field(&run(&p), "PROF-TEST-SANDBOX", Status::Fail, "domain"),
            "{suffix}"
        );
    }
    let mut ok = ok_hosted();
    ok.domain = "shop-site.co.uk".into();
    ok.test_hostname = "hddtest.shop-site.co.uk".into();
    ok.sandbox_hostname = "hddsbx.shop-site.co.uk".into();
    assert!(!has_field(
        &run(&ok),
        "PROF-TEST-SANDBOX",
        Status::Fail,
        "domain"
    ));
}

#[test]
fn a_mistyped_runner_ip_is_a_failure_not_auto() {
    let mut p = ok_hosted();
    p.test_runner.public_ip = "203.0.113.9x".into();
    let r = run(&p);
    assert!(has_field(
        &r,
        "PROF-RUNNER-ADMIN",
        Status::Fail,
        "test_runner.public_ip"
    ));
    assert!(!has(
        &r,
        "PROF-RUNNER-ADMIN",
        Status::Unverified(Reason::StageNotReached)
    ));
    p.test_runner.public_ip = "AUTO".into();
    assert!(has(
        &run(&p),
        "PROF-RUNNER-ADMIN",
        Status::Unverified(Reason::StageNotReached)
    ));
}

#[test]
fn origin_url_with_text_after_an_ipv6_literal_is_refused() {
    for bad in [
        "https://[::1]garbage",
        "https://[::1",
        "https://[::1]:99999",
    ] {
        let mut p = ok_hosted();
        p.origin.url = bad.into();
        assert!(
            has_field(&run(&p), "PROF-ORIGIN", Status::Fail, "origin.url"),
            "{bad}"
        );
    }
    let mut ok = ok_hosted();
    ok.origin.url = "https://[2001:db8::1]:8443".into();
    assert!(!has(&run(&ok), "PROF-ORIGIN", Status::Fail));
}

#[test]
fn smtp_over_plain_text_is_allowed_only_for_a_loopback_relay_and_that_relay_is_a_valid_host() {
    for host in ["localhost", "127.0.0.1", "::1"] {
        let mut p = ok_hosted();
        p.smtp.host = host.into();
        p.smtp.tls = SmtpTls::None;
        let r = run(&p);
        assert!(!has(&r, "PROF-HOSTNAME", Status::Fail), "{host}");
        assert!(
            !has(&r, "PROF-SMTP", Status::Fail),
            "{host}: {}",
            crate::profile::render_table(&r)
        );
    }
}

#[test]
fn control_characters_in_free_text_fields_are_refused() {
    let mut p = ok_hosted();
    p.smtp.from_name = "Support\r\nBcc: attacker@example.net".into();
    p.branding.legal_entity = "Acme\u{0}Corp".into();
    let r = run(&p);
    assert!(has_field(&r, "PROF-POLICY", Status::Fail, "smtp.from_name"));
    assert!(has_field(
        &r,
        "PROF-POLICY",
        Status::Fail,
        "branding.legal_entity"
    ));
}

#[test]
fn local_domain_suffix_is_validated() {
    let local = |s: &str| {
        let mut p = ok_local();
        p.runtime.local.local_domain_suffix = s.into();
        p
    };
    for bad in ["", "com", "co.uk", "bad_name.test!", "a..b"] {
        assert!(
            has_field(
                &run(&local(bad)),
                "PROF-LOCAL",
                Status::Fail,
                "runtime.local.local_domain_suffix"
            ),
            "{bad:?}"
        );
    }
    assert!(!has(
        &run(&local("hdd.localhost")),
        "PROF-LOCAL",
        Status::Fail
    ));
    assert!(!has(&run(&local("localhost")), "PROF-LOCAL", Status::Fail));
    // a registrable domain is refused: the local CA's name constraint and the hosts helper would take over real names
    for real in [
        "google.com",
        "hdd.example.org",
        "corp.example.co.uk",
        "mybank.com",
    ] {
        let r = run(&local(real));
        assert!(
            has_field(
                &r,
                "PROF-LOCAL",
                Status::Fail,
                "runtime.local.local_domain_suffix"
            ) && !r.is_ok(),
            "{real}"
        );
    }
    // reserved names other than .localhost work, with the browser-resolution warning
    for reserved in ["hdd.test", "hdd.internal", "hdd.home.arpa", "docs.example"] {
        let r = run(&local(reserved));
        assert!(r.is_ok(), "{reserved}");
        assert!(
            has_field(
                &r,
                "PROF-LOCAL",
                Status::Warn,
                "runtime.local.local_domain_suffix"
            ),
            "{reserved}"
        );
    }
}

#[test]
fn t0561_a1_local_refuses_saas_and_open_signup_with_err_local_001_at_config_load() {
    for (what, field) in [("saas", "deployment_mode"), ("open", "signup.mode")] {
        let mut l = ok_local();
        if what == "saas" {
            l.deployment_mode = DeploymentMode::Saas;
        } else {
            l.signup.mode = SignupMode::Open;
        }
        let r = run(&l);
        assert!(!r.is_ok(), "{what}");
        let f = r
            .findings
            .iter()
            .find(|f| f.rule == "PROF-LOCAL" && f.field == field && f.status == Status::Fail)
            .expect("finding");
        assert!(f.message.contains("ERR-LOCAL-001"), "{}", f.message);
    }
    // the same profile in hosted is not refused by this rule
    let mut h = ok_local();
    h.runtime.profile = RuntimeProfile::Hosted;
    h.deployment_mode = DeploymentMode::Saas;
    assert!(
        run(&h)
            .findings
            .iter()
            .all(|f| !(f.rule == "PROF-LOCAL" && f.status == Status::Fail))
    );
}
