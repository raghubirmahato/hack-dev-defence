//! T-0561 step 3: the capability matrix of C18.2 as code (A1: refusals carry ERR-LOCAL-001).
#![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]

use super::*;
use crate::profile::types::{DeploymentMode, Profile, RuntimeProfile, SignupMode};

fn local() -> Profile {
    let mut p = Profile::default();
    p.runtime.profile = RuntimeProfile::Local;
    p
}

fn hosted() -> Profile {
    Profile::default()
}

#[test]
fn every_capability_has_a_decision_in_both_profiles() {
    for cap in Capability::ALL {
        for profile in [RuntimeProfile::Local, RuntimeProfile::Hosted] {
            let a = availability(profile, cap);
            if let Availability::Unavailable { code, reason } = a {
                assert!(code.starts_with("ERR-"), "{cap:?} {profile:?}");
                assert!(!reason.is_empty(), "{cap:?} {profile:?} has no reason");
            }
        }
        assert!(!cap.id().is_empty() && !cap.label().is_empty());
    }
}

#[test]
fn capability_ids_are_unique() {
    let mut ids: Vec<&str> = Capability::ALL.iter().map(|c| c.id()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), Capability::ALL.len());
}

#[test]
fn local_refuses_what_needs_a_server_with_err_local_001() {
    for cap in [
        Capability::AuthoritativeDns53,
        Capability::KernelEnforcement,
        Capability::Acme,
        Capability::SaasMode,
        Capability::OpenSignup,
        Capability::FullNs,
    ] {
        match local().availability(cap) {
            Availability::Unavailable { code, reason } => {
                assert_eq!(code, ERR_LOCAL_UNAVAILABLE, "{cap:?}");
                assert!(!reason.is_empty());
            }
            other => panic!("{cap:?} must be unavailable in local, got {other:?}"),
        }
    }
}

#[test]
fn hosted_allows_the_server_features_and_open_signup_needs_the_operator() {
    for cap in [
        Capability::AuthoritativeDns53,
        Capability::KernelEnforcement,
        Capability::Acme,
        Capability::SaasMode,
        Capability::FullNs,
        Capability::LanExposure,
    ] {
        assert_eq!(hosted().availability(cap), Availability::Allowed, "{cap:?}");
    }
    assert_eq!(
        hosted().availability(Capability::OpenSignup),
        Availability::AllowedWithAck {
            ack: Ack::OperatorApproval,
            code: None
        }
    );
}

#[test]
fn lan_exposure_in_local_needs_the_exact_acknowledgement() {
    assert_eq!(
        local().availability(Capability::LanExposure),
        Availability::AllowedWithAck {
            ack: Ack::LanExposureString,
            code: Some(ERR_LOCAL_ACK)
        }
    );
    assert_eq!(LAN_ACK, "I-UNDERSTAND-LOCAL-IS-NOT-24x7");
}

#[test]
fn stores_follow_the_comparison_table() {
    assert_eq!(
        local().availability(Capability::EmbeddedDatabase),
        Availability::Allowed
    );
    assert_eq!(
        local().availability(Capability::MemoryStore),
        Availability::Allowed
    );
    assert!(matches!(
        hosted().availability(Capability::EmbeddedDatabase),
        Availability::Unavailable {
            code: ERR_HOSTING,
            ..
        }
    ));
    assert!(matches!(
        hosted().availability(Capability::MemoryStore),
        Availability::AllowedWithAck {
            ack: Ack::SingleServiceProcess,
            ..
        }
    ));
}

#[test]
fn the_matrix_depends_on_the_runtime_profile_only() {
    let mut a = local();
    a.deployment_mode = DeploymentMode::Saas;
    a.signup.mode = SignupMode::Open;
    assert_eq!(a.capabilities(), local().capabilities());
}

#[test]
fn requested_capabilities_follow_the_profile_settings() {
    let mut p = local();
    p.deployment_mode = DeploymentMode::Saas;
    p.signup.mode = SignupMode::Open;
    p.runtime.local.lan_exposure = true;
    let r = p.requested();
    assert!(r.contains(&Capability::SaasMode));
    assert!(r.contains(&Capability::OpenSignup));
    assert!(r.contains(&Capability::LanExposure));
    assert!(r.contains(&Capability::EmbeddedDatabase));
    assert!(r.contains(&Capability::MemoryStore));
    assert!(!local().requested().contains(&Capability::SaasMode));
}

#[test]
fn refusals_lists_every_requested_capability_that_is_unavailable() {
    let mut p = local();
    p.deployment_mode = DeploymentMode::Saas;
    p.signup.mode = SignupMode::Open;
    let refused: Vec<Capability> = p.refusals().iter().map(|r| r.capability).collect();
    assert_eq!(refused, vec![Capability::SaasMode, Capability::OpenSignup]);
    assert!(p.refusals().iter().all(|r| r.code == ERR_LOCAL_UNAVAILABLE));
    assert!(local().refusals().is_empty());
    assert!(hosted().refusals().is_empty());
}

#[test]
fn render_table_names_every_capability_and_code() {
    let t = render(&local());
    for cap in Capability::ALL {
        assert!(t.contains(cap.label()), "{t}");
    }
    assert!(t.contains(ERR_LOCAL_UNAVAILABLE));
    assert!(t.contains(LAN_ACK));
}
