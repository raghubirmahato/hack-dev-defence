//! Configuration, access policy and state handling of the cluster module, without a server.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::fs;

use super::*;

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("hdd-local-cluster-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn manager(dir: &Path) -> Embedded {
    let mut cfg = PgConfig::new(dir.join("data"));
    cfg.min_free_bytes = 1;
    Embedded::new(cfg).unwrap()
}

#[test]
fn the_managed_configuration_listens_on_loopback_only_and_keeps_durability_on() {
    let c = render_conf(54_321, 512, 1024, "/data/logs");
    for line in [
        "listen_addresses = '127.0.0.1'",
        "port = 54321",
        "password_encryption = 'scram-sha-256'",
        "fsync = on",
        "full_page_writes = on",
        "synchronous_commit = on",
        "shared_buffers = 512MB",
        "effective_cache_size = 1024MB",
        "log_directory = '/data/logs'",
        "ssl = off",
    ] {
        assert!(c.contains(line), "missing `{line}` in\n{c}");
    }
    assert!(!c.contains("0.0.0.0") && !c.contains("'*'") && !c.contains("fsync = off"));
}

#[test]
fn the_managed_block_is_replaced_not_duplicated_and_the_rest_is_kept() {
    let base = "# stock settings\nmax_wal_size = 1GB\n";
    let first = apply_conf(base, &render_conf(5000, 128, 256, "/l"));
    assert!(first.starts_with("# stock settings\nmax_wal_size = 1GB\n"));
    let second = apply_conf(&first, &render_conf(5001, 128, 256, "/l"));
    assert_eq!(second.matches("port = ").count(), 1);
    assert!(second.contains("port = 5001") && !second.contains("port = 5000"));
    assert!(second.contains("max_wal_size = 1GB"));
    assert_eq!(
        apply_conf(&second, &render_conf(5001, 128, 256, "/l")),
        second,
        "idempotent"
    );
}

#[test]
fn a3_pg_hba_allows_scram_on_loopback_and_nothing_else() {
    let mut rules = 0;
    for line in PG_HBA
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
    {
        let cols: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(
            cols.first(),
            Some(&"host"),
            "no local-socket and no hostssl/hostnossl lines: {line}"
        );
        assert!(
            matches!(cols.get(3), Some(&"127.0.0.1/32") | Some(&"::1/128")),
            "only loopback addresses: {line}"
        );
        assert_eq!(cols.get(4), Some(&"scram-sha-256"), "{line}");
        rules += 1;
    }
    assert_eq!(rules, 2);
    let rules_only: String = PG_HBA
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join(
            "
",
        );
    for forbidden in [
        "trust",
        "md5",
        "password ",
        "peer",
        "ident",
        "0.0.0.0",
        "reject",
    ] {
        assert!(!rules_only.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn nothing_is_started_or_created_before_an_archive_is_supplied() {
    let dir = tmp("noarchive");
    let em = manager(&dir);
    assert!(!em.is_installed() && !em.is_initialized());
    assert_eq!(em.status().unwrap(), Status::Stopped);
    let err = em.up(None).unwrap_err();
    assert!(matches!(err, PgError::State(_)), "{err:?}");
    assert!(err.to_string().contains("--bundle"));
    assert!(!dir.join("data").join("pgdata").exists());
    assert!(matches!(em.init(), Err(PgError::State(_))));
    assert!(matches!(em.start(), Err(PgError::State(_))));
    assert!(
        em.stop().is_ok(),
        "stopping a stopped server is not an error"
    );
    assert!(!em.is_ready());
    assert!(!em.telemetry().is_up());
    assert!(matches!(
        em.run_sql_as_owner("select 1"),
        Err(PgError::State(_))
    ));
    assert!(matches!(em.backup(), Err(PgError::State(_))));
}

#[test]
fn a_data_directory_of_another_major_version_is_refused_not_upgraded_in_place() {
    let dir = tmp("marker");
    let em = manager(&dir);
    fs::create_dir_all(dir.join("data")).unwrap();
    fs::write(
        dir.join("data").join("pg.version"),
        "postgres_version=16.3\nmajor=16\n",
    )
    .unwrap();
    let err = em.check_version_marker().unwrap_err();
    assert!(matches!(err, PgError::VersionMismatch { .. }), "{err:?}");
    assert!(em.up(None).is_err());
    // the same major version is accepted (a minor update replaces the binaries, not the data)
    let major = em
        .manifest()
        .postgres_version
        .split('.')
        .next()
        .unwrap()
        .to_owned();
    fs::write(
        dir.join("data").join("pg.version"),
        format!("postgres_version={major}.0.1\nmajor={major}\n"),
    )
    .unwrap();
    em.check_version_marker().unwrap();
}

#[test]
fn reset_keeps_the_backup_key_the_binaries_and_the_backups() {
    let dir = tmp("reset");
    let em = manager(&dir);
    let base = dir.join("data");
    fs::create_dir_all(base.join("pgdata")).unwrap();
    fs::create_dir_all(base.join("secrets")).unwrap();
    fs::create_dir_all(base.join("backups")).unwrap();
    fs::create_dir_all(base.join("postgres").join("keep")).unwrap();
    for f in [
        "pg_admin.pw",
        "hdd_owner.pw",
        "pgpass",
        "hdd_owner.url",
        "backup.key",
    ] {
        fs::write(base.join("secrets").join(f), "x").unwrap();
    }
    fs::write(base.join("backups").join("a.hddbak"), "x").unwrap();
    fs::write(base.join("pg.version"), "x").unwrap();
    fs::write(base.join("pg.port"), "1").unwrap();
    em.reset().unwrap();
    assert!(
        !base.join("pgdata").exists()
            && !base.join("pg.version").exists()
            && !base.join("pg.port").exists()
    );
    assert!(
        base.join("secrets").join("backup.key").is_file(),
        "without the key the backups could never be restored"
    );
    for f in ["pg_admin.pw", "hdd_owner.pw", "pgpass", "hdd_owner.url"] {
        assert!(!base.join("secrets").join(f).exists(), "{f}");
    }
    assert!(base.join("backups").join("a.hddbak").is_file());
    assert!(base.join("postgres").join("keep").is_dir());
    assert!(em.telemetry().events().iter().any(|e| e.action == "reset"));
}

#[test]
fn the_start_timeout_and_port_range_defaults_follow_the_specification() {
    let c = PgConfig::new("/d");
    assert_eq!(c.start_timeout.as_secs(), 60);
    assert_eq!(c.min_free_bytes, 2 * 1024 * 1024 * 1024);
    assert!(c.port_range.0 > 1023 && c.port_range.0 < c.port_range.1);
}

#[test]
fn a_leftover_non_empty_pgdata_that_is_not_a_cluster_is_never_overwritten() {
    let dir = tmp("leftover");
    let em = manager(&dir);
    let base = dir.join("data");
    // fake installation so that init gets as far as the directory check
    let ext = if cfg!(windows) { ".exe" } else { "" };
    let bin = em
        .config()
        .layout
        .install_dir(&em.manifest().postgres_version)
        .join("bin");
    fs::create_dir_all(&bin).unwrap();
    for n in ["pg_ctl", "initdb", "postgres"] {
        fs::write(bin.join(format!("{n}{ext}")), "x").unwrap();
    }
    fs::create_dir_all(base.join("pgdata")).unwrap();
    fs::write(base.join("pgdata").join("precious.txt"), "do not touch").unwrap();
    let err = em.init().unwrap_err();
    assert!(matches!(err, PgError::State(_)), "{err:?}");
    assert!(err.to_string().contains("db reset"));
    assert_eq!(
        fs::read_to_string(base.join("pgdata").join("precious.txt")).unwrap(),
        "do not touch"
    );
    // the secrets written before the check do not contain a password that initdb never saw
    assert!(!base.join("secrets").join("initdb.pwfile").exists());
}
