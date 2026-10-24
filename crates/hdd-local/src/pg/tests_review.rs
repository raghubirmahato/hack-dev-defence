//! Tests added for the findings of the independent review of 2026-10-19 (docs/evidence/P33/hostile-review.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::fs;
use std::path::PathBuf;

use super::PgError;
use super::backup::sweep_stale_temporaries;
use super::cluster::{Embedded, PgConfig, base64_utf16le, ps_single_quoted, render_conf};
use super::files;

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("hdd-local-review-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn manager(dir: &std::path::Path) -> Embedded {
    let mut cfg = PgConfig::new(dir.join("data"));
    cfg.min_free_bytes = 1;
    Embedded::new(cfg).unwrap()
}

#[test]
fn powershell_quoting_doubles_every_quote_character_and_the_script_is_passed_encoded() {
    assert_eq!(ps_single_quoted("plain"), "plain");
    assert_eq!(ps_single_quoted("O'Brien"), "O''Brien");
    assert_eq!(
        ps_single_quoted("a\u{2018}b\u{2019}c\u{201A}d\u{201B}e"),
        "a\u{2018}\u{2018}b\u{2019}\u{2019}c\u{201A}\u{201A}d\u{201B}\u{201B}e"
    );
    // a path that tries to end the string and run something else stays inside the string
    let evil = "x'; Remove-Item -Recurse C:\\ ; '";
    let q = ps_single_quoted(evil);
    assert_eq!(q.matches("''").count(), 2, "{q}");
    // known base64 of UTF-16LE: "A" -> 41 00 -> QQA=, "Hi" -> 48 00 69 00 -> SABpAA==
    assert_eq!(base64_utf16le("A"), "QQA=");
    assert_eq!(base64_utf16le("Hi"), "SABpAA==");
    assert_eq!(base64_utf16le(""), "");
    assert_eq!(base64_utf16le("abc"), "YQBiAGMA");
    // non-BMP characters are encoded as surrogate pairs
    // U+1F600 is D83D DE00 in UTF-16: bytes 3D D8 00 DE
    assert_eq!(base64_utf16le("\u{1F600}"), "PdgA3g==");
}

#[test]
fn a_single_quote_in_the_log_path_does_not_break_the_configuration() {
    let c = render_conf(5432, 128, 256, "C:/Users/O'Brien/hdd/logs");
    assert!(
        c.contains("log_directory = 'C:/Users/O''Brien/hdd/logs'"),
        "{c}"
    );
}

#[test]
fn two_commands_cannot_hold_the_data_directory_at_once() {
    let dir = tmp("lock");
    let em = manager(&dir);
    let first = em.lock().unwrap();
    let second = em.lock();
    assert!(
        matches!(second, Err(PgError::State(ref m)) if m.contains("another hdd-local command")),
        "{second:?}"
    );
    // a mutating command is refused too, before it touches anything
    assert!(matches!(em.up(None), Err(PgError::State(_))));
    assert!(matches!(em.reset(), Err(PgError::State(_))));
    assert!(matches!(em.down(), Err(PgError::State(_))));
    drop(first);
    assert!(
        em.lock().is_ok(),
        "the lock is released when the guard is dropped"
    );
}

#[test]
fn a_new_data_directory_is_owner_only_and_an_existing_open_one_is_refused() {
    let dir = tmp("base");
    let em = manager(&dir);
    let base = dir.join("data");
    em.ensure_base().unwrap();
    assert!(files::is_owner_only(&base).unwrap(), "created owner-only");
    em.ensure_base().unwrap();

    // a directory that other users can write into: the server binaries inside it could be replaced
    let open = dir.join("open");
    fs::create_dir_all(&open).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
    }
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap();
        let out = std::process::Command::new(format!("{root}\\System32\\icacls.exe"))
            .arg(&open)
            .args(["/grant", "*S-1-1-0:(OI)(CI)F"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let mut cfg = PgConfig::new(&open);
    cfg.min_free_bytes = 1;
    let open_em = Embedded::new(cfg).unwrap();
    let err = open_em.ensure_base().unwrap_err();
    assert!(matches!(err, PgError::State(_)), "{err:?}");
    assert!(err.to_string().contains("other users"));
    assert!(
        matches!(open_em.up(None), Err(PgError::State(_))),
        "up refuses before touching the directory"
    );
}

#[test]
fn installing_leaves_no_copy_of_the_archive_and_the_cache_is_owner_only() {
    use super::archive::sha256_bytes;
    use super::manifest::{Manifest, current_triple};
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let dir = tmp("copy");
    let ext = if cfg!(windows) { ".exe" } else { "" };
    let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
    {
        let mut b = tar::Builder::new(&mut gz);
        for n in ["pg_ctl", "initdb", "postgres"] {
            let mut h = tar::Header::new_gnu();
            h.set_size(3);
            h.set_mode(0o755);
            h.set_entry_type(tar::EntryType::Regular);
            b.append_data(&mut h, format!("bin/{n}{ext}"), &b"abc"[..])
                .unwrap();
        }
        b.finish().unwrap();
    }
    let bytes = gz.finish().unwrap();
    let triple = current_triple().unwrap_or("x86_64-unknown-linux-gnu");
    let m = Manifest::parse(&format!(
        "postgres_version = \"17.1.0\"\n[source]\nproject = \"p\"\nbase_url = \"https://example.test/dl\"\ntag = \"17.1.0\"\n[[target]]\ntriple = \"{triple}\"\nfile = \"postgresql-17.1.0-{triple}.tar.gz\"\nsha256 = \"{}\"\nsize = {}\n",
        sha256_bytes(&bytes),
        bytes.len()
    ))
    .unwrap();
    let mut cfg = PgConfig::new(dir.join("data"));
    cfg.min_free_bytes = 1;
    let em = Embedded::with_manifest(cfg, m).unwrap();
    let archive = dir.join("a.tar.gz");
    fs::write(&archive, &bytes).unwrap();
    em.install(&archive).unwrap();
    assert!(em.is_installed());
    let cache = dir.join("data").join("cache");
    assert!(files::is_owner_only(&cache).unwrap());
    let leftovers: Vec<_> = fs::read_dir(&cache).unwrap().flatten().collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    assert!(files::is_owner_only(&dir.join("data").join("postgres")).unwrap());
    let _ = std::io::stdout().flush();
}

#[test]
fn stale_plaintext_temporaries_are_swept_and_real_backups_are_kept() {
    let dir = tmp("sweep");
    for f in [
        ".dump-1.tmp",
        ".restore-22.tmp",
        "hdd-20261019T000000Z-aabbccdd.hddbak",
        "notes.txt",
        ".dump-keep",
    ] {
        fs::write(dir.join(f), "x").unwrap();
    }
    sweep_stale_temporaries(&dir);
    let mut left: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(
        left,
        vec![
            ".dump-keep",
            "hdd-20261019T000000Z-aabbccdd.hddbak",
            "notes.txt"
        ]
    );
}
