//! End-to-end run of the embedded PostgreSQL (T-0563 A1, A3, A4) against the real archive.
//!
//! Needs `HDD_E2E_PG_ARCHIVE`: the path of the pinned archive for this operating system (`cargo xtask db up --download ...`
//! leaves it in `<data dir>/cache/`). Without it the test prints `UNVERIFIED(human_step_pending)` and returns; the
//! acceptance report then lists A1, A3 and A4 as unverified instead of counting the skipped run as a pass.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::indexing_slicing,
    reason = "test"
)]

use std::fs;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use hdd_local::pg::archive::sha256_bytes;
use hdd_local::pg::cluster::{Embedded, PgConfig, Status};
use hdd_local::pg::files;
use hdd_local::pg::names;

/// Stops the server and removes the directory when the test ends, also when an assertion fails.
struct Cleanup(Embedded, PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.0.stop();
        let _ = fs::remove_dir_all(&self.1);
    }
}

fn archive() -> Option<PathBuf> {
    std::env::var("HDD_E2E_PG_ARCHIVE")
        .ok()
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
}

/// The address of this machine on the network, found without sending a packet.
fn lan_address() -> Option<IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("203.0.113.1:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

#[test]
fn the_embedded_database_installs_listens_on_loopback_only_and_restores_its_backups() {
    let Some(archive) = archive() else {
        println!(
            "UNVERIFIED(human_step_pending): HDD_E2E_PG_ARCHIVE is not set; the real PostgreSQL was not started"
        );
        return;
    };
    let dir = std::env::temp_dir().join(format!("hdd-e2e-pg-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let mut cfg = PgConfig::new(&dir);
    cfg.port_range = (55_320, 55_419);
    let guard = Cleanup(Embedded::new(cfg).unwrap(), dir.clone());
    let em = &guard.0;

    // A1: a clean data directory and no PostgreSQL installed: db up produces a working database that takes a migration as hdd_owner
    assert!(!em.is_installed());
    let report = em.up(Some(&archive)).unwrap();
    assert!(report.installed && report.initialized && report.started);
    assert!(em.is_ready());
    assert!(em.telemetry().is_up());
    let who = em
        .run_sql_as_owner("SELECT current_user, current_database();")
        .unwrap();
    assert!(
        who.contains(names::OWNER) && who.contains(names::DATABASE),
        "{who}"
    );
    em.run_sql_as_owner(
        "CREATE TABLE sample_migration (id bigserial PRIMARY KEY, note text NOT NULL);\n\
         INSERT INTO sample_migration (note) VALUES ('one'), ('two'), ('three');\n\
         CREATE ROLE hdd_probe_role NOLOGIN;\n",
    )
    .unwrap();
    let count = em
        .run_sql_as_owner("SELECT count(*) FROM sample_migration;")
        .unwrap();
    assert!(count.contains('3'), "{count}");
    // data checksums are on and the cluster uses scram only
    let sums = em
        .run_sql_as_admin("postgres", "SHOW data_checksums;")
        .unwrap();
    assert!(sums.contains("on"), "{sums}");
    let enc = em
        .run_sql_as_admin("postgres", "SHOW password_encryption;")
        .unwrap();
    assert!(enc.contains("scram-sha-256"), "{enc}");
    let listen = em
        .run_sql_as_admin("postgres", "SHOW listen_addresses;")
        .unwrap();
    assert!(
        listen.contains("127.0.0.1") && !listen.contains('*') && !listen.contains("0.0.0.0"),
        "{listen}"
    );

    // A3: nothing but a password-authenticated loopback connection gets in
    let Status::Running { port } = em.status().unwrap() else {
        panic!("not running")
    };
    if let Some(ip) = lan_address() {
        let r = TcpStream::connect_timeout(&SocketAddr::new(ip, port), Duration::from_secs(3));
        assert!(
            r.is_err(),
            "the server must not accept a connection on the LAN address {ip}"
        );
    } else {
        println!(
            "UNVERIFIED(environment_unsupported): this machine has no non-loopback address for the LAN-address half of A3"
        );
    }
    // a wrong password is refused even from loopback
    let out = Command::new(em.bin("psql"))
        .env_clear()
        .env(
            "SystemRoot",
            std::env::var("SystemRoot").unwrap_or_default(),
        )
        .env("PGPASSWORD", "definitely-wrong")
        .args([
            "-h",
            "127.0.0.1",
            "-w",
            "-X",
            "-q",
            "-U",
            names::OWNER,
            "-d",
            names::DATABASE,
            "-c",
            "SELECT 1",
            "-p",
        ])
        .arg(port.to_string())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("authentication failed"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // no password at all is refused (never prompts: -w)
    let out = Command::new(em.bin("psql"))
        .env_clear()
        .env(
            "SystemRoot",
            std::env::var("SystemRoot").unwrap_or_default(),
        )
        .env("PGPASSFILE", dir.join("no-such-file"))
        .args([
            "-h",
            "127.0.0.1",
            "-w",
            "-X",
            "-q",
            "-U",
            names::SUPERUSER,
            "-d",
            "postgres",
            "-c",
            "SELECT 1",
            "-p",
        ])
        .arg(port.to_string())
        .output()
        .unwrap();
    assert!(!out.status.success());
    // secrets are owner-only and the URL file names the loopback address
    for f in [
        "pg_admin.pw",
        "hdd_owner.pw",
        "pgpass",
        "hdd_owner.url",
        "backup.key",
    ] {
        let p = dir.join("secrets").join(f);
        assert!(files::is_owner_only(&p).unwrap(), "{f} must be owner-only");
    }
    assert!(
        fs::read_to_string(dir.join("secrets").join("hdd_owner.url"))
            .unwrap()
            .contains("@127.0.0.1:")
    );

    // the lifecycle is idempotent: a second `up` finds it running
    let again = em.up(None).unwrap();
    assert!(!again.installed && !again.initialized && !again.started);

    // A4: backup, wipe, start a fresh cluster, restore, compare
    let before = em.canonical_dump().unwrap();
    assert!(before.contains("sample_migration"));
    let backup = em.backup().unwrap();
    let raw = fs::read(&backup).unwrap();
    assert!(
        !raw.windows(16).any(|w| w == b"sample_migration"),
        "the backup must be encrypted at rest"
    );
    em.down().unwrap();
    assert!(!em.is_ready());
    em.reset().unwrap();
    assert!(!dir.join("pgdata").exists());
    let fresh = em.up(None).unwrap();
    assert!(fresh.initialized && fresh.started);
    let empty = em.canonical_dump().unwrap();
    assert!(
        !empty.contains("sample_migration"),
        "the fresh cluster starts empty"
    );
    em.restore(&backup).unwrap();
    let after = em.canonical_dump().unwrap();
    assert_eq!(
        sha256_bytes(before.as_bytes()),
        sha256_bytes(after.as_bytes()),
        "schema and data must be reproduced exactly"
    );
    println!(
        "restore hash comparison: before {} after {}",
        sha256_bytes(before.as_bytes()),
        sha256_bytes(after.as_bytes())
    );

    // shutdown frees the port and the gauge goes down
    em.down().unwrap();
    assert!(!em.telemetry().is_up());
    assert!(matches!(em.status().unwrap(), Status::Stopped));
    let actions: Vec<String> = em
        .telemetry()
        .events()
        .into_iter()
        .map(|e| e.action)
        .collect();
    for a in [
        "installed",
        "initialized",
        "started",
        "stopped",
        "backup",
        "restore",
        "reset",
    ] {
        assert!(
            actions.iter().any(|x| x == a),
            "no `{a}` audit event in {actions:?}"
        );
    }
}
