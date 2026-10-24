//! T-0561 step 2: environment variables of B10 with typed validation.
#![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]

use std::collections::BTreeMap;

use super::*;

fn env(pairs: &[(&str, &str)]) -> Result<RuntimeEnv, Vec<EnvError>> {
    let map: BTreeMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    RuntimeEnv::from_lookup(&|k| map.get(k).cloned())
}

#[test]
fn nothing_set_changes_nothing() {
    let e = env(&[]).unwrap();
    assert_eq!(e, RuntimeEnv::default());
    let mut p = Profile::default();
    let before = p.clone();
    e.apply(&mut p);
    assert_eq!(p, before);
}

#[test]
fn empty_values_count_as_unset() {
    assert_eq!(
        env(&[("HDD_RUNTIME_PROFILE", "")]).unwrap(),
        RuntimeEnv::default()
    );
}

#[test]
fn every_variable_is_applied_to_the_profile() {
    let e = env(&[
        ("HDD_RUNTIME_PROFILE", "local"),
        (
            "HDD_DATA_DIR",
            if cfg!(windows) {
                "C:\\hdd-test"
            } else {
                "/var/lib/hdd-test"
            },
        ),
        ("HDD_LOCAL_DATABASE", "external"),
        ("HDD_KV_BACKEND", "redis"),
        ("HDD_LOCAL_PORTS", "web=9443, api=9000"),
        ("HDD_LOCAL_SUFFIX", "Dev.localhost"),
        ("HDD_LOCAL_TLS", "http_only"),
        ("HDD_LOCAL_LAN_EXPOSURE", "false"),
        ("HDD_LOCAL_DOGFOOD", "true"),
        ("HDD_LOCAL_LOOPBACK_IDENTITY", "single"),
        ("HDD_HOSTING_PROFILE", "H3"),
    ])
    .unwrap();
    let mut p = Profile::default();
    e.apply(&mut p);
    assert_eq!(p.runtime.profile, RuntimeProfile::Local);
    let l = &p.runtime.local;
    assert_eq!(
        l.data_dir,
        if cfg!(windows) {
            "C:\\hdd-test"
        } else {
            "/var/lib/hdd-test"
        }
    );
    assert_eq!(l.database, LocalDatabase::External);
    assert_eq!(l.kv, LocalKv::Redis);
    assert_eq!((l.ports.web, l.ports.api, l.ports.dns), (9443, 9000, 5300));
    assert_eq!(l.local_domain_suffix, "dev.localhost");
    assert_eq!(l.tls, LocalTls::HttpOnly);
    assert!(!l.lan_exposure);
    assert!(l.dogfood);
    assert_eq!(l.loopback_client_identity, LoopbackIdentity::Single);
    assert_eq!(p.runtime.hosting.profile, HostingProfile::H3);
}

#[test]
fn every_bad_variable_is_reported_and_none_is_echoed_in_full() {
    let long = "x".repeat(200);
    let errs = env(&[
        ("HDD_RUNTIME_PROFILE", long.as_str()),
        ("HDD_KV_BACKEND", "memcached"),
        ("HDD_LOCAL_PORTS", "web=0"),
        ("HDD_HOSTING_PROFILE", "H9"),
        ("HDD_DATA_DIR", "relative/dir"),
        ("HDD_LOCAL_LAN_EXPOSURE", "yes"),
    ])
    .unwrap_err();
    let vars: Vec<&str> = errs.iter().map(|e| e.var).collect();
    for v in [
        "HDD_RUNTIME_PROFILE",
        "HDD_KV_BACKEND",
        "HDD_LOCAL_PORTS",
        "HDD_HOSTING_PROFILE",
        "HDD_DATA_DIR",
        "HDD_LOCAL_LAN_EXPOSURE",
    ] {
        assert!(vars.contains(&v), "{v} missing from {vars:?}");
    }
    for e in &errs {
        assert!(!e.to_string().contains(&long), "{e}");
    }
}

#[test]
fn ports_reject_unknown_services_duplicates_and_non_numbers() {
    for bad in [
        "db=5432",
        "web=8443,web=9443",
        "web=abc",
        "web",
        "web=70000",
    ] {
        let errs = env(&[("HDD_LOCAL_PORTS", bad)]).unwrap_err();
        assert_eq!(
            errs.first().map(|e| e.var),
            Some("HDD_LOCAL_PORTS"),
            "{bad}"
        );
    }
}

#[test]
fn data_dir_must_be_absolute_on_the_platform_it_runs_on() {
    let (ok, wrong_platform): (&[&str], &[&str]) = if cfg!(windows) {
        (
            &["C:\\Users\\me\\hdd", "C:/hdd", "\\\\server\\share\\hdd"],
            &["/var/lib/hdd"],
        )
    } else {
        (&["/var/lib/hdd"], &["C:\\Users\\me\\hdd", "C:/hdd"])
    };
    for p in ok {
        assert!(env(&[("HDD_DATA_DIR", p)]).is_ok(), "{p}");
    }
    // a path that is absolute only on the other platform would be relative here
    for p in wrong_platform {
        assert!(env(&[("HDD_DATA_DIR", p)]).is_err(), "{p}");
    }
    for bad in ["hdd", "./hdd", "..\\hdd", "C:hdd", "/ok\u{7}"] {
        assert!(env(&[("HDD_DATA_DIR", bad)]).is_err(), "{bad:?}");
    }
}

#[test]
fn the_lan_acknowledgement_must_match_exactly() {
    assert!(
        env(&[("HDD_LOCAL_LAN_ACK", LAN_ACK)])
            .unwrap()
            .local_lan_ack
    );
    for bad in [
        "i-understand-local-is-not-24x7",
        "I-UNDERSTAND",
        "I-UNDERSTAND-LOCAL-IS-NOT-24x7 ",
    ] {
        let errs = env(&[("HDD_LOCAL_LAN_ACK", bad)]).unwrap_err();
        assert!(errs.first().is_some_and(|e| e.message.contains(LAN_ACK)));
    }
    assert!(!env(&[]).unwrap().local_lan_ack);
}

#[test]
fn the_effective_store_follows_the_defaults_of_b10() {
    let none = RuntimeEnv::default();
    let mut local = Profile::default();
    local.runtime.profile = RuntimeProfile::Local;
    assert_eq!(none.effective_kv(&local), KvBackend::Memory);
    assert_eq!(none.effective_kv(&Profile::default()), KvBackend::Redis);
    let forced = env(&[("HDD_KV_BACKEND", "memory")]).unwrap();
    assert_eq!(forced.effective_kv(&Profile::default()), KvBackend::Memory);
}

#[test]
fn the_environment_wins_over_the_file_and_leaves_hosted_settings_alone() {
    let mut p = Profile::default();
    p.runtime.local.dogfood = false;
    let e = env(&[("HDD_LOCAL_DOGFOOD", "true")]).unwrap();
    e.apply(&mut p);
    assert!(p.runtime.local.dogfood);
    assert_eq!(p.runtime.hosting, Profile::default().runtime.hosting);
}

#[test]
fn the_schema_documents_every_variable() {
    let s = schema_json();
    for field in [
        "runtime_profile",
        "data_dir",
        "local_database",
        "kv_backend",
        "local_ports",
        "local_suffix",
        "local_tls",
        "local_lan_exposure",
        "local_lan_ack",
        "local_dogfood",
        "local_loopback_identity",
        "hosting_profile",
    ] {
        assert!(s.contains(field), "{field} missing from the schema");
    }
    assert!(s.ends_with('\n'));
}

#[test]
fn lan_exposure_without_the_acknowledgement_is_refused_with_err_local_002() {
    let mut p = Profile::default();
    p.runtime.profile = RuntimeProfile::Local;
    let no_ack = env(&[("HDD_LOCAL_LAN_EXPOSURE", "true")]).unwrap();
    let errs = no_ack.apply_checked(&mut p.clone()).unwrap_err();
    assert_eq!(errs.first().map(|e| e.var), Some("HDD_LOCAL_LAN_ACK"));
    assert!(
        errs.first()
            .is_some_and(|e| e.message.contains("ERR-LOCAL-002") && e.message.contains(LAN_ACK))
    );
    let acked = env(&[
        ("HDD_LOCAL_LAN_EXPOSURE", "true"),
        ("HDD_LOCAL_LAN_ACK", LAN_ACK),
    ])
    .unwrap();
    acked.apply_checked(&mut p.clone()).unwrap();
    // no exposure, no acknowledgement needed; hosted never needs one
    env(&[]).unwrap().apply_checked(&mut p.clone()).unwrap();
    let mut hosted = Profile::default();
    hosted.runtime.local.lan_exposure = true;
    env(&[]).unwrap().apply_checked(&mut hosted).unwrap();
}
