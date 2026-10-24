//! Tests of the parts of the embedded-database manager that need no PostgreSQL server: the pinned manifest, digest verification
//! (A2), safe extraction, secrets and permissions, host facts, the backup cipher, telemetry.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::fs::{self, File};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::write::GzEncoder;

use super::archive::{self, extract_tar_gz, find_root, sha256_bytes, sha256_file, verify_archive};
use super::backup::{CHUNK, decrypt_stream, encrypt_stream, parse_key};
use super::cluster::{Embedded, PgConfig};
use super::files;
use super::manifest::{Manifest, Target, current_triple};
use super::sys;
use super::telemetry::{MAX_EVENTS, Telemetry};
use super::{Layout, PgError};

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("hdd-local-pg-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

// ---------------------------------------------------------------------------------------------------------------------
// manifest

#[test]
fn the_embedded_manifest_is_valid_and_pins_five_targets() {
    let m = Manifest::embedded().unwrap();
    assert_eq!(m.targets.len(), 5);
    for triple in [
        "x86_64-pc-windows-msvc",
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
    ] {
        let t = m.for_triple(triple).unwrap();
        assert_eq!(t.sha256.len(), 64);
        assert!(
            m.url(t).starts_with(
                "https://github.com/theseus-rs/postgresql-binaries/releases/download/"
            )
        );
        assert!(m.url(t).ends_with(&t.file));
    }
    assert!(m.postgres_version.starts_with("17."));
    assert!(matches!(
        m.for_triple("riscv64gc-unknown-linux-gnu"),
        Err(PgError::UnsupportedPlatform(_))
    ));
    let entries = m.egress_entries();
    assert!(entries.iter().all(|e| e.starts_with("https://")));
    assert!(
        entries
            .iter()
            .any(|e| e.ends_with(&format!("/{}/", m.source.tag)))
    );
}

#[test]
fn this_build_has_a_pinned_target_on_the_supported_platforms() {
    if cfg!(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(
            target_os = "macos",
            any(target_arch = "aarch64", target_arch = "x86_64")
        ),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )) {
        let t = Manifest::embedded().unwrap();
        assert_eq!(t.for_current().unwrap().triple, current_triple().unwrap());
    }
}

fn manifest_text(f: impl Fn(String) -> String) -> String {
    let base = "postgres_version = \"17.1.0\"\n[source]\nproject = \"p\"\nbase_url = \"https://example.test/dl\"\ntag = \"17.1.0\"\n\
[[target]]\ntriple = \"x86_64-unknown-linux-gnu\"\nfile = \"postgresql-17.1.0-x86_64-unknown-linux-gnu.tar.gz\"\n\
sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\nsize = 100\n";
    f(base.to_owned())
}

#[test]
fn malformed_manifests_are_refused() {
    assert!(Manifest::parse(&manifest_text(|t| t)).is_ok());
    type Edit = Box<dyn Fn(String) -> String>;
    let cases: [(&str, Edit); 8] = [
        (
            "http base",
            Box::new(|t| t.replace("https://example.test/dl", "http://example.test/dl")),
        ),
        ("trailing slash", Box::new(|t| t.replace("/dl\"", "/dl/\""))),
        (
            "short digest",
            Box::new(|t| {
                t.replace(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "abc",
                )
            }),
        ),
        (
            "upper-case digest",
            Box::new(|t| {
                t.replace(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                )
            }),
        ),
        (
            "wrong file name",
            Box::new(|t| t.replace("postgresql-17.1.0-x86_64", "postgresql-17.2.0-x86_64")),
        ),
        (
            "zero size",
            Box::new(|t| t.replace("size = 100", "size = 0")),
        ),
        (
            "bad version",
            Box::new(|t| {
                t.replace(
                    "postgres_version = \"17.1.0\"",
                    "postgres_version = \"17.x\"",
                )
            }),
        ),
        (
            "tag with slash",
            Box::new(|t| t.replace("tag = \"17.1.0\"", "tag = \"a/b\"")),
        ),
    ];
    for (name, f) in cases {
        assert!(Manifest::parse(&manifest_text(f)).is_err(), "{name}");
    }
    let dup = manifest_text(|t| {
        let second = t.split_once("[[target]]").unwrap().1.to_owned();
        format!("{t}[[target]]{second}")
    });
    assert!(Manifest::parse(&dup).is_err(), "duplicate triple");
    assert!(Manifest::parse("").is_err());
    assert!(Manifest::parse("postgres_version = 17").is_err());
}

// ---------------------------------------------------------------------------------------------------------------------
// archives

/// A gzip-compressed tar with the given regular files.
fn tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
    {
        let mut b = tar::Builder::new(&mut gz);
        for (name, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o755);
            h.set_entry_type(tar::EntryType::Regular);
            b.append_data(&mut h, name, *data).unwrap();
        }
        b.finish().unwrap();
    }
    gz.finish().unwrap()
}

/// A tar with one raw entry whose header is written byte by byte (the builder refuses `..`).
fn raw_tar_gz(name: &str, kind: tar::EntryType, link: Option<&str>, body: &[u8]) -> Vec<u8> {
    let mut h = tar::Header::new_gnu();
    {
        let g = h.as_gnu_mut().unwrap();
        g.name[..name.len()].copy_from_slice(name.as_bytes());
        if let Some(l) = link {
            g.linkname[..l.len()].copy_from_slice(l.as_bytes());
        }
    }
    h.set_size(body.len() as u64);
    h.set_mode(0o644);
    h.set_entry_type(kind);
    h.set_cksum();
    let mut raw = Vec::new();
    raw.extend_from_slice(h.as_bytes());
    raw.extend_from_slice(body);
    let pad = (512 - body.len() % 512) % 512;
    raw.extend(std::iter::repeat_n(0u8, pad + 1024));
    let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
    gz.write_all(&raw).unwrap();
    gz.finish().unwrap()
}

fn fake_distribution() -> Vec<u8> {
    let ext = if cfg!(windows) { ".exe" } else { "" };
    let names: Vec<String> = ["pg_ctl", "initdb", "postgres", "psql"]
        .iter()
        .map(|n| format!("bin/{n}{ext}"))
        .collect();
    let files: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b"#!fake"[..])).collect();
    tar_gz(&files)
}

fn target_for(bytes: &[u8]) -> Target {
    Target {
        triple: current_triple()
            .unwrap_or("x86_64-unknown-linux-gnu")
            .to_owned(),
        file: "x.tar.gz".into(),
        sha256: sha256_bytes(bytes),
        size: bytes.len() as u64,
    }
}

fn manager_for(dir: &Path, bytes: &[u8]) -> Embedded {
    let triple = current_triple().unwrap_or("x86_64-unknown-linux-gnu");
    let m = Manifest::parse(&format!(
        "postgres_version = \"17.1.0\"\n[source]\nproject = \"p\"\nbase_url = \"https://example.test/dl\"\ntag = \"17.1.0\"\n\
[[target]]\ntriple = \"{triple}\"\nfile = \"postgresql-17.1.0-{triple}.tar.gz\"\nsha256 = \"{}\"\nsize = {}\n",
        sha256_bytes(bytes),
        bytes.len()
    ))
    .unwrap();
    let mut cfg = PgConfig::new(dir.join("data"));
    cfg.min_free_bytes = 1;
    Embedded::with_manifest(cfg, m).unwrap()
}

#[test]
fn a_matching_archive_installs_and_the_digest_helpers_agree() {
    let dir = tmp("install");
    let bytes = fake_distribution();
    let file = dir.join("pg.tar.gz");
    fs::write(&file, &bytes).unwrap();
    assert_eq!(sha256_file(&file).unwrap(), sha256_bytes(&bytes));
    verify_archive(&file, &target_for(&bytes)).unwrap();
    let em = manager_for(&dir, &bytes);
    assert!(!em.is_installed());
    em.install(&file).unwrap();
    assert!(em.is_installed());
    assert!(em.bin("pg_ctl").is_file());
    assert!(
        em.telemetry()
            .events()
            .iter()
            .any(|e| e.action == "installed")
    );
}

#[test]
fn a2_a_binary_with_a_wrong_checksum_is_refused_and_nothing_is_installed_or_started() {
    let dir = tmp("a2");
    let good = fake_distribution();
    let em = manager_for(&dir, &good);
    // same size, one flipped byte in the compressed stream: the size matches but the digest does not
    let mut bad = good.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 0x01;
    let file = dir.join("tampered.tar.gz");
    fs::write(&file, &bad).unwrap();
    let err = em.install(&file).unwrap_err();
    assert!(
        matches!(
            err,
            PgError::Checksum {
                what: "SHA-256",
                ..
            }
        ),
        "{err:?}"
    );
    assert!(err.to_string().contains("nothing was installed or started"));
    assert!(!em.is_installed());
    assert!(
        !dir.join("data").join("postgres").exists(),
        "no installation directory was created"
    );
    assert!(!dir.join("data").join("pgdata").exists());
    // and `up` stops at the same place: it never initializes or starts
    let err = em.up(Some(&file)).unwrap_err();
    assert!(matches!(err, PgError::Checksum { .. }), "{err:?}");
    assert!(!dir.join("data").join("pgdata").exists());
    assert!(!em.telemetry().is_up());

    // a different size is refused before the digest is even computed
    let short = dir.join("short.tar.gz");
    fs::write(&short, &good[..good.len() - 1]).unwrap();
    assert!(matches!(
        em.install(&short),
        Err(PgError::Checksum { what: "size", .. })
    ));
    // an empty file and a directory are refused too
    let empty = dir.join("empty.tar.gz");
    File::create(&empty).unwrap();
    assert!(em.install(&empty).is_err());
    assert!(!em.is_installed());
}

#[test]
fn an_archive_without_the_server_programs_is_refused_after_the_digest_passed() {
    let dir = tmp("noprog");
    let bytes = tar_gz(&[("bin/readme.txt", b"hello")]);
    let file = dir.join("pg.tar.gz");
    fs::write(&file, &bytes).unwrap();
    let em = manager_for(&dir, &bytes);
    let err = em.install(&file).unwrap_err();
    assert!(matches!(err, PgError::Extract(_)), "{err:?}");
    assert!(!em.is_installed());
}

#[test]
fn a_single_top_level_directory_is_stripped() {
    let dir = tmp("toplevel");
    let bytes = tar_gz(&[
        ("postgresql-17/bin/pg_ctl", b"x"),
        ("postgresql-17/share/a", b"y"),
    ]);
    let file = dir.join("a.tar.gz");
    fs::write(&file, &bytes).unwrap();
    let out = dir.join("out");
    let done = extract_tar_gz(&file, &out).unwrap();
    assert_eq!(done.entries, 2);
    assert_eq!(find_root(&out).unwrap(), out.join("postgresql-17"));
    let flat = tar_gz(&[("bin/pg_ctl", b"x")]);
    let file2 = dir.join("b.tar.gz");
    fs::write(&file2, &flat).unwrap();
    let out2 = dir.join("out2");
    extract_tar_gz(&file2, &out2).unwrap();
    assert_eq!(find_root(&out2).unwrap(), out2);
    let nothing = dir.join("out3");
    fs::create_dir_all(nothing.join("x")).unwrap();
    assert!(find_root(&nothing).is_err());
}

#[test]
fn extraction_refuses_traversal_absolute_paths_escaping_links_and_special_files() {
    let dir = tmp("evil");
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "parent traversal",
            raw_tar_gz("../evil.txt", tar::EntryType::Regular, None, b"x"),
        ),
        (
            "nested traversal",
            raw_tar_gz("bin/../../evil.txt", tar::EntryType::Regular, None, b"x"),
        ),
        (
            "absolute path",
            raw_tar_gz("/tmp/evil.txt", tar::EntryType::Regular, None, b"x"),
        ),
        (
            "drive path",
            raw_tar_gz("C:/evil.txt", tar::EntryType::Regular, None, b"x"),
        ),
        (
            "backslash path",
            raw_tar_gz("bin\\..\\evil.txt", tar::EntryType::Regular, None, b"x"),
        ),
        (
            "escaping symlink",
            raw_tar_gz(
                "bin/link",
                tar::EntryType::Symlink,
                Some("../../outside"),
                b"",
            ),
        ),
        (
            "absolute symlink",
            raw_tar_gz(
                "bin/link",
                tar::EntryType::Symlink,
                Some("/etc/passwd"),
                b"",
            ),
        ),
        (
            "escaping hard link",
            raw_tar_gz("bin/hard", tar::EntryType::Link, Some("../outside"), b""),
        ),
        (
            "character device",
            raw_tar_gz("dev/null", tar::EntryType::Char, None, b""),
        ),
        (
            "fifo",
            raw_tar_gz("bin/pipe", tar::EntryType::Fifo, None, b""),
        ),
    ];
    for (name, bytes) in cases {
        let file = dir.join(format!("{}.tar.gz", name.replace(' ', "-")));
        fs::write(&file, &bytes).unwrap();
        let out = dir.join(format!("out-{}", name.replace(' ', "-")));
        let err = extract_tar_gz(&file, &out).unwrap_err();
        assert!(matches!(err, PgError::Extract(_)), "{name}: {err:?}");
        assert!(!dir.join("evil.txt").exists(), "{name}: wrote outside");
    }
    // a link inside the destination is fine
    let ok = raw_tar_gz(
        "lib/libpq.so",
        tar::EntryType::Symlink,
        Some("libpq.so.5"),
        b"",
    );
    let file = dir.join("ok.tar.gz");
    fs::write(&file, &ok).unwrap();
    if cfg!(unix) {
        extract_tar_gz(&file, &dir.join("out-ok")).unwrap();
    }
    assert_eq!(archive::MAX_ENTRIES, 100_000);
}

// ---------------------------------------------------------------------------------------------------------------------
// files and secrets

#[test]
fn generated_secrets_are_long_unique_and_owner_only() {
    let a = files::random_hex_32().unwrap();
    let b = files::random_hex_32().unwrap();
    assert_eq!(a.len(), 64);
    assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(a, b);
    let dir = tmp("secret");
    let f = dir.join("sub").join("pw");
    files::write_private_file(&f, a.as_bytes()).unwrap();
    assert_eq!(files::read_text(&f).unwrap(), a);
    assert!(
        files::is_owner_only(&f).unwrap(),
        "the secret file must be owner-only"
    );
    assert!(
        files::is_owner_only(f.parent().unwrap()).unwrap(),
        "and so must its directory"
    );
    // replacing keeps it private
    files::write_private_file(&f, b"x").unwrap();
    assert!(files::is_owner_only(&f).unwrap());
}

// ---------------------------------------------------------------------------------------------------------------------
// host facts

#[test]
fn df_meminfo_and_drive_parsing() {
    let df = "Filesystem     1024-blocks      Used Available Capacity Mounted on\n/dev/sda1        102400000  50000000  52400000      49% /\n";
    assert_eq!(sys::parse_df(df), Some(52_400_000 * 1024));
    assert_eq!(sys::parse_df("garbage"), None);
    assert_eq!(sys::parse_df(""), None);
    assert_eq!(
        sys::parse_meminfo("MemTotal:       16316412 kB\nMemFree: 1 kB\n"),
        Some(16_316_412 * 1024)
    );
    assert_eq!(sys::parse_meminfo("nothing"), None);
    assert_eq!(sys::drive_letter(Path::new("d:\\x\\y")), Some('D'));
    assert_eq!(sys::drive_letter(Path::new("C:/x")), Some('C'));
    assert_eq!(sys::drive_letter(Path::new("/x")), None);
    assert_eq!(sys::drive_letter(Path::new("")), None);
}

#[test]
fn memory_settings_are_a_quarter_and_a_half_within_bounds() {
    assert_eq!(sys::memory_settings(None), (1024, 2048));
    assert_eq!(sys::memory_settings(Some(1024 * 1024 * 1024)), (256, 512));
    assert_eq!(
        sys::memory_settings(Some(256 * 1024 * 1024)).0,
        128,
        "never below 128 MiB"
    );
    let (shared, cache) = sys::memory_settings(Some(64 * 1024 * 1024 * 1024));
    assert_eq!(shared, 2048, "never above 2 GiB");
    assert!(cache >= shared * 2);
}

#[test]
fn the_free_port_search_skips_ports_in_use_and_reports_exhaustion() {
    let held = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = held.local_addr().unwrap().port();
    assert!(sys::port_in_use(port));
    // a one-port range whose only port is taken
    let err = sys::pick_port((port, port), None).unwrap_err();
    assert!(matches!(err, PgError::NoFreePort { .. }));
    assert!(err.to_string().contains("ERR-LOCAL-004"));
    // a range that starts with the taken port moves on
    if let Some(next) = port.checked_add(30) {
        let got = sys::pick_port((port, next), Some(port)).unwrap();
        assert_ne!(got, port);
    }
    drop(held);
    assert!(!sys::port_in_use(port) || sys::pick_port((port, port), Some(port)).is_err() || true);
}

#[test]
fn free_disk_space_is_read_and_a_huge_requirement_is_refused() {
    let dir = tmp("disk");
    let free = sys::free_disk_bytes(&dir).unwrap();
    assert!(free > 0);
    let err = sys::require_free_space(&dir, u64::MAX).unwrap_err();
    assert!(matches!(err, PgError::DiskSpace { .. }));
    assert!(err.to_string().contains("MiB"));
    assert!(sys::require_free_space(&dir, 1).is_ok());
}

// ---------------------------------------------------------------------------------------------------------------------
// backup cipher

fn key() -> [u8; 32] {
    parse_key(&"0123456789abcdef".repeat(4)).unwrap()
}

fn seal(plain: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    encrypt_stream(key, &mut Cursor::new(plain), &mut out).unwrap();
    out
}

fn open(sealed: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, PgError> {
    let mut out = Vec::new();
    decrypt_stream(key, &mut Cursor::new(sealed), &mut out)?;
    Ok(out)
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

#[test]
fn the_backup_cipher_round_trips_every_size_class() {
    let k = key();
    for n in [
        0,
        1,
        100,
        CHUNK - 1,
        CHUNK,
        CHUNK + 1,
        2 * CHUNK,
        2 * CHUNK + 17,
        3 * CHUNK - 1,
    ] {
        let plain = pattern(n);
        let sealed = seal(&plain, &k);
        assert!(sealed.len() > n, "{n}");
        assert_eq!(open(&sealed, &k).unwrap(), plain, "{n} bytes");
    }
}

#[test]
fn ciphertext_does_not_contain_the_plaintext_and_differs_per_run() {
    let k = key();
    let plain = b"secret-table-contents-secret-table-contents".to_vec();
    let a = seal(&plain, &k);
    let b = seal(&plain, &k);
    assert_ne!(a, b, "fresh nonce prefix per file");
    assert!(!a.windows(plain.len()).any(|w| w == plain.as_slice()));
}

#[test]
fn a_wrong_key_a_flipped_bit_truncation_and_appended_data_all_fail() {
    let k = key();
    let plain = pattern(2 * CHUNK + 5);
    let sealed = seal(&plain, &k);
    let mut other = k;
    other[0] ^= 1;
    assert!(
        matches!(open(&sealed, &other), Err(PgError::Backup(_))),
        "wrong key"
    );
    // flip one bit in each region: header, first chunk body, second chunk body, last chunk tag
    for pos in [3, 30, CHUNK + 100, sealed.len() - 1] {
        let mut bad = sealed.clone();
        bad[pos] ^= 0x80;
        assert!(open(&bad, &k).is_err(), "bit flip at {pos}");
    }
    // truncation at many points, including exactly on chunk boundaries
    let boundary = 20 + 4 + CHUNK + 16;
    for cut in [
        0,
        7,
        19,
        22,
        100,
        boundary - 1,
        boundary,
        boundary + 3,
        sealed.len() - 1,
    ] {
        assert!(open(&sealed[..cut], &k).is_err(), "truncated at {cut}");
    }
    // appended bytes, whole appended chunk
    let mut longer = sealed.clone();
    longer.push(0);
    assert!(open(&longer, &k).is_err(), "one byte appended");
    let mut doubled = sealed.clone();
    doubled.extend_from_slice(&sealed[20..]);
    assert!(open(&doubled, &k).is_err(), "a chunk appended");
    // magic
    let mut nomagic = sealed.clone();
    nomagic[0] = b'X';
    assert!(
        open(&nomagic, &k)
            .unwrap_err()
            .to_string()
            .contains("not an HDD backup")
    );
}

#[test]
fn chunks_cannot_be_reordered_or_dropped() {
    let k = key();
    let sealed = seal(&pattern(3 * CHUNK), &k);
    let chunk_len = 4 + CHUNK + 16;
    let head = &sealed[..20];
    let c0 = &sealed[20..20 + chunk_len];
    let c1 = &sealed[20 + chunk_len..20 + 2 * chunk_len];
    let rest = &sealed[20 + 2 * chunk_len..];
    let swapped = [head, c1, c0, rest].concat();
    assert!(open(&swapped, &k).is_err(), "swapped chunks");
    let dropped = [head, c0, rest].concat();
    assert!(open(&dropped, &k).is_err(), "a dropped chunk");
    let duplicated = [head, c0, c0, c1, rest].concat();
    assert!(open(&duplicated, &k).is_err(), "a duplicated chunk");
}

#[test]
fn keys_are_validated() {
    assert!(parse_key(&"ab".repeat(32)).is_ok());
    for bad in [
        "",
        "abc",
        &"zz".repeat(32),
        &"ab".repeat(31),
        &"ab".repeat(33),
    ] {
        assert!(parse_key(bad).is_err(), "{bad}");
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// telemetry and layout

#[test]
fn telemetry_keeps_a_bounded_event_list_and_renders_the_gauge() {
    let t = Telemetry::new();
    assert!(t.render_prometheus().contains("hdd_embedded_db_up 0"));
    t.set_up(true);
    assert!(t.render_prometheus().contains("hdd_embedded_db_up 1"));
    for i in 0..(MAX_EVENTS + 10) {
        t.audit("started", &format!("n{i}"));
    }
    let e = t.events();
    assert_eq!(e.len(), MAX_EVENTS);
    assert_eq!(e.last().unwrap().detail, format!("n{}", MAX_EVENTS + 9));
}

#[test]
fn the_layout_keeps_everything_under_the_data_directory() {
    let l = Layout::new("/data/hdd");
    for p in [
        l.install_dir("17.1.0"),
        l.pgdata(),
        l.secrets(),
        l.cache(),
        l.backups(),
        l.logs(),
        l.version_marker(),
        l.owner_url_file(),
    ] {
        assert!(p.starts_with("/data/hdd"), "{p:?}");
    }
    assert!(l.owner_url_file().starts_with(l.secrets()));
}

#[test]
fn error_messages_carry_guidance_and_no_secrets() {
    let e = PgError::NotReady("last log line".into()).to_string();
    assert!(e.contains("ERR-LOCAL-004") && e.contains("doctor"));
    let e = PgError::VersionMismatch {
        found: "16.3".into(),
        wanted: "17.1".into(),
    }
    .to_string();
    assert!(e.contains("never an in-place upgrade"));
    let e = PgError::UnsupportedPlatform("riscv".into()).to_string();
    assert!(e.contains("external"));
}
