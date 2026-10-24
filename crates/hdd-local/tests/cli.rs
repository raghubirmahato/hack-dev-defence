//! The `hdd-local` command line as a person uses it, without a PostgreSQL archive: refusals, guidance and the egress policy
//! of the download path.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test"
)]

use std::path::PathBuf;
use std::process::{Command, Output};

fn hdd_local(dir: &PathBuf) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_hdd-local"));
    c.arg("--data-dir").arg(dir).env_remove("HDD_DATA_DIR");
    c
}

fn fresh(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("hdd-local-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn version_status_and_reset_on_an_empty_data_directory() {
    let dir = fresh("basics");
    let v = Command::new(env!("CARGO_BIN_EXE_hdd-local"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(v.status.success() && text(&v).contains("hdd-local"));

    let s = hdd_local(&dir).args(["db", "status"]).output().unwrap();
    assert!(s.status.success(), "{}", text(&s));
    let t = text(&s);
    assert!(
        t.contains("installed: false")
            && t.contains("running: no")
            && t.contains("hdd_embedded_db_up: 0"),
        "{t}"
    );

    let r = hdd_local(&dir).args(["db", "reset"]).output().unwrap();
    assert_eq!(r.status.code(), Some(1));
    assert!(text(&r).contains("--yes"), "{}", text(&r));
    let r = hdd_local(&dir)
        .args(["db", "reset", "--yes"])
        .output()
        .unwrap();
    assert!(r.status.success(), "{}", text(&r));

    let u = hdd_local(&dir).args(["db", "url"]).output().unwrap();
    assert!(text(&u).contains("hdd_owner.url") && !text(&u).contains("postgres://"));
}

#[test]
fn up_without_an_archive_or_permission_to_download_explains_the_options_and_creates_nothing() {
    let dir = fresh("noarchive");
    let o = hdd_local(&dir).args(["db", "up"]).output().unwrap();
    assert_eq!(o.status.code(), Some(1));
    let t = text(&o);
    assert!(t.contains("--bundle") && t.contains("--download"), "{t}");
    assert!(!dir.join("pgdata").exists() && !dir.join("postgres").exists());
}

#[test]
fn a_download_without_allowlist_entries_lists_the_entries_it_needs_and_touches_no_network() {
    let dir = fresh("noallow");
    let o = hdd_local(&dir)
        .args(["db", "up", "--download"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    let t = text(&o);
    assert!(t.contains("no egress allowlist entries"), "{t}");
    assert!(
        t.contains("https://github.com/theseus-rs/postgresql-binaries/releases/download/"),
        "{t}"
    );
    assert!(t.contains("release-assets.githubusercontent.com"), "{t}");
}

#[test]
fn a_download_to_a_host_that_is_not_allowlisted_is_denied_before_any_connection() {
    let dir = fresh("denied");
    let o = hdd_local(&dir)
        .args([
            "db",
            "up",
            "--download",
            "--allow",
            "https://example.invalid/",
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    let t = text(&o);
    assert!(t.contains("denied by the egress policy"), "{t}");
    assert!(t.contains("needs these allowlist entries"), "{t}");
    assert!(!dir.join("cache").join("postgresql-17.partial").exists());
}

#[test]
fn a_bundle_that_is_not_the_pinned_archive_is_refused() {
    let dir = fresh("badbundle");
    std::fs::create_dir_all(&dir).unwrap();
    let bundle = dir.join("fake.tar.gz");
    std::fs::write(&bundle, b"not a postgres archive").unwrap();
    let o = hdd_local(&dir)
        .args(["db", "up", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(
        text(&o).contains("does not match the pinned"),
        "{}",
        text(&o)
    );
    assert!(!dir.join("pgdata").exists() && !dir.join("postgres").exists());
}

#[test]
fn backup_and_restore_need_a_running_database() {
    let dir = fresh("nobackup");
    let b = hdd_local(&dir).arg("backup").output().unwrap();
    assert_eq!(b.status.code(), Some(1));
    assert!(text(&b).contains("not running"), "{}", text(&b));
    let r = hdd_local(&dir)
        .args(["restore", "no-such-file.hddbak"])
        .output()
        .unwrap();
    assert_eq!(r.status.code(), Some(1));
}
