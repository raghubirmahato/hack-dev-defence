//! Logical backups of the embedded database, encrypted at rest (T-0563 step 5).
//!
//! `pg_dump -Fc --no-unlogged-table-data` writes a custom-format dump, which is then sealed with ChaCha20-Poly1305 in chunks
//! and stored under `<data>/backups/`. The key is the file `<data>/secrets/backup.key` (owner only; it survives `db reset`).
//!
//! File format (all integers little endian):
//!
//! ```text
//! "HDDBK1\0\0"  8 bytes magic
//! nonce prefix  8 random bytes
//! chunk size    u32 (plaintext bytes per full chunk)
//! chunks        { u32 ciphertext length, ciphertext (plaintext + 16-byte tag) } ...
//! ```
//!
//! Chunk `i` is sealed with the nonce `prefix || i` (u32 big endian) and the associated data `magic || i || final` where `final`
//! is 1 for the last chunk. Reordering, truncating or splicing chunks, or using another key, fails authentication.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use super::cluster::{Embedded, Status};
use super::files::{create_private_dir, read_text};
use super::{PgError, PgResult, names};

const MAGIC: &[u8; 8] = b"HDDBK1\0\0";
/// Plaintext bytes per chunk.
pub const CHUNK: usize = 1 << 20;
const TAG: usize = 16;

/// Decode a 64-character hex key.
pub fn parse_key(hex: &str) -> PgResult<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PgError::Backup(
            "the backup key is not 64 hexadecimal characters".into(),
        ));
    }
    let mut key = [0u8; 32];
    for (i, slot) in key.iter_mut().enumerate() {
        let pair = hex.get(i * 2..i * 2 + 2).unwrap_or("00");
        *slot = u8::from_str_radix(pair, 16).map_err(|_| PgError::Backup("bad key".into()))?;
    }
    Ok(key)
}

fn nonce(prefix: &[u8; 8], index: u32) -> Nonce {
    let mut n = [0u8; 12];
    if let Some(head) = n.get_mut(..8) {
        head.copy_from_slice(prefix);
    }
    if let Some(tail) = n.get_mut(8..) {
        tail.copy_from_slice(&index.to_be_bytes());
    }
    Nonce::from(n)
}

fn aad(index: u32, last: bool) -> Vec<u8> {
    let mut a = MAGIC.to_vec();
    a.extend_from_slice(&index.to_le_bytes());
    a.push(u8::from(last));
    a
}

/// Fill `buf` from `r`; the number of bytes read (less than `buf.len()` only at the end of input).
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> PgResult<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = r.read(buf.get_mut(filled..).unwrap_or(&mut []))?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// Seal `input` into `output`.
pub fn encrypt_stream(
    key: &[u8; 32],
    input: &mut impl Read,
    output: &mut impl Write,
) -> PgResult<u64> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let mut prefix = [0u8; 8];
    getrandom::fill(&mut prefix).map_err(|e| PgError::Backup(format!("no random bytes: {e}")))?;
    output.write_all(MAGIC)?;
    output.write_all(&prefix)?;
    output.write_all(&u32::try_from(CHUNK).unwrap_or(u32::MAX).to_le_bytes())?;
    let mut buf = vec![0u8; CHUNK];
    let mut next = vec![0u8; CHUNK];
    let mut n = read_full(input, &mut buf)?;
    let mut index: u32 = 0;
    let mut total = 0u64;
    loop {
        // look ahead one chunk so that the last one can be marked
        let m = if n == CHUNK {
            read_full(input, &mut next)?
        } else {
            0
        };
        let last = n < CHUNK || m == 0;
        let sealed = cipher
            .encrypt(
                &nonce(&prefix, index),
                Payload {
                    msg: buf.get(..n).unwrap_or(&[]),
                    aad: &aad(index, last),
                },
            )
            .map_err(|_| PgError::Backup("encryption failed".into()))?;
        output.write_all(
            &u32::try_from(sealed.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        )?;
        output.write_all(&sealed)?;
        total += n as u64;
        if last {
            break;
        }
        std::mem::swap(&mut buf, &mut next);
        n = m;
        index = index
            .checked_add(1)
            .ok_or_else(|| PgError::Backup("the backup is too large".into()))?;
    }
    output.flush()?;
    Ok(total)
}

/// Open a sealed stream. Any change to the file, a wrong key, appended data or a truncated file is an error before wrong data
/// is trusted: every chunk is authenticated together with its index and with whether it is the last one.
pub fn decrypt_stream(
    key: &[u8; 32],
    input: &mut impl Read,
    output: &mut impl Write,
) -> PgResult<u64> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let bad = |m: &str| PgError::Backup(m.to_owned());
    let mut magic = [0u8; 8];
    if read_full(input, &mut magic)? != 8 || &magic != MAGIC {
        return Err(bad("this is not an HDD backup file"));
    }
    let mut prefix = [0u8; 8];
    if read_full(input, &mut prefix)? != 8 {
        return Err(bad("the file is truncated"));
    }
    let mut size = [0u8; 4];
    if read_full(input, &mut size)? != 4 {
        return Err(bad("the file is truncated"));
    }
    if usize::try_from(u32::from_le_bytes(size)).unwrap_or(usize::MAX) != CHUNK {
        return Err(bad("unsupported chunk size"));
    }
    let mut total = 0u64;
    let mut index: u32 = 0;
    // the first byte of the next length field, read ahead to learn whether the current chunk is the last one
    let mut pending: Option<u8> = None;
    loop {
        let mut len = [0u8; 4];
        let have = usize::from(pending.is_some());
        if let (Some(b), Some(slot)) = (pending.take(), len.get_mut(0)) {
            *slot = b;
        }
        let want = len.len() - have;
        if read_full(input, len.get_mut(have..).unwrap_or(&mut []))? != want {
            return Err(bad("the file is truncated (no final chunk)"));
        }
        let len = usize::try_from(u32::from_le_bytes(len)).unwrap_or(usize::MAX);
        if !(TAG..=CHUNK + TAG).contains(&len) {
            return Err(bad("a chunk has an impossible length"));
        }
        let mut sealed = vec![0u8; len];
        if read_full(input, &mut sealed)? != len {
            return Err(bad("the file is truncated"));
        }
        let mut probe = [0u8; 1];
        let more = read_full(input, &mut probe)? == 1;
        let last = !more;
        let plain = cipher
            .decrypt(
                &nonce(&prefix, index),
                Payload {
                    msg: &sealed,
                    aad: &aad(index, last),
                },
            )
            .map_err(|_| bad("authentication failed: wrong key, a damaged file, appended data or a truncated file"))?;
        output.write_all(&plain)?;
        total += plain.len() as u64;
        if last {
            return Ok(total);
        }
        pending = probe.first().copied();
        index = index
            .checked_add(1)
            .ok_or_else(|| bad("the backup is too large"))?;
    }
}

/// Timestamp for file names (`20261019T123456Z`).
fn stamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let tod = secs % 86_400;
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

impl Embedded {
    fn backup_key(&self) -> PgResult<[u8; 32]> {
        parse_key(&read_text(
            &self.config().layout.secrets().join("backup.key"),
        )?)
    }

    /// `pg_dump -Fc --no-unlogged-table-data` of the database `hdd`, sealed and stored under `<data>/backups/`. Returns the file.
    pub fn backup(&self) -> PgResult<PathBuf> {
        let _lock = self.lock()?;
        let Status::Running { port } = self.status()? else {
            return Err(PgError::State(
                "the database is not running; run `db up` first".into(),
            ));
        };
        let layout = &self.config().layout;
        create_private_dir(&layout.backups())?;
        sweep_stale_temporaries(&layout.backups());
        let tmp = layout
            .backups()
            .join(format!(".dump-{}.tmp", std::process::id()));
        let mut out_path: Option<PathBuf> = None;
        let result = (|| {
            let mut cmd = self.command("pg_dump");
            cmd.args([
                "-h",
                "127.0.0.1",
                "-w",
                "-Fc",
                "--no-unlogged-table-data",
                "-U",
                names::SUPERUSER,
                "-d",
                names::DATABASE,
                "-p",
            ])
            .arg(port.to_string())
            .arg("-f")
            .arg(&tmp);
            self.run_ok("pg_dump", cmd, None)?;
            let key = self.backup_key()?;
            // a name that cannot collide (second resolution plus 32 random bits) and a file that is never opened over another
            let mut suffix = [0u8; 4];
            getrandom::fill(&mut suffix)
                .map_err(|e| PgError::Backup(format!("no random bytes: {e}")))?;
            let suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
            let path = layout
                .backups()
                .join(format!("hdd-{}-{suffix}.hddbak", stamp()));
            let mut input = File::open(&tmp)?;
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            out_path = Some(path.clone());
            encrypt_stream(&key, &mut input, &mut output)?;
            output.sync_all()?;
            super::files::protect_file(&path)?;
            Ok::<PathBuf, PgError>(path)
        })();
        let _ = fs::remove_file(&tmp);
        if result.is_err()
            && let Some(p) = &out_path
        {
            // never leave a half-written backup that looks like a real one
            let _ = fs::remove_file(p);
        }
        let path = result?;
        self.telemetry()
            .audit("backup", "encrypted logical backup written");
        Ok(path)
    }

    /// Restore a backup into the database `hdd` (which must exist, normally freshly created by `db up`) as one transaction that
    /// stops at the first error: either everything is restored or the database is unchanged. Objects are created with
    /// `--clean --if-exists --no-owner --role hdd_owner`, so that they belong to the owner role. Roles and grants are not part
    /// of a logical dump of one database: once the migrations of T-0105 create roles, a restore into a fresh cluster must run
    /// those migrations first (or the backup must add `pg_dumpall --globals-only`; ASM-030).
    pub fn restore(&self, file: &Path) -> PgResult<()> {
        let _lock = self.lock()?;
        let Status::Running { port } = self.status()? else {
            return Err(PgError::State(
                "the database is not running; run `db up` first".into(),
            ));
        };
        let layout = &self.config().layout;
        create_private_dir(&layout.backups())?;
        sweep_stale_temporaries(&layout.backups());
        let tmp = layout
            .backups()
            .join(format!(".restore-{}.tmp", std::process::id()));
        let result = (|| {
            let key = self.backup_key()?;
            let mut input = File::open(file)?;
            let mut output = File::create(&tmp)?;
            decrypt_stream(&key, &mut input, &mut output)?;
            output.sync_all()?;
            drop(output);
            let mut cmd = self.command("pg_restore");
            cmd.args([
                "-h",
                "127.0.0.1",
                "-w",
                "--single-transaction",
                "--exit-on-error",
                "--clean",
                "--if-exists",
                "--no-owner",
                "--role",
                names::OWNER,
                "-U",
                names::SUPERUSER,
                "-d",
                names::DATABASE,
                "-p",
            ])
            .arg(port.to_string())
            .arg(&tmp);
            self.run_ok("pg_restore", cmd, None)?;
            Ok::<(), PgError>(())
        })();
        let _ = fs::remove_file(&tmp);
        result?;
        self.telemetry().audit("restore", "backup restored");
        Ok(())
    }

    /// Plain-text dump of the database without owners, comments and the per-run random tokens newer `pg_dump` versions write,
    /// for comparing two databases (T-0563 A4).
    pub fn canonical_dump(&self) -> PgResult<String> {
        let Status::Running { port } = self.status()? else {
            return Err(PgError::State("the database is not running".into()));
        };
        let mut cmd = self.command("pg_dump");
        cmd.args([
            "-h",
            "127.0.0.1",
            "-w",
            "-Fp",
            "--no-owner",
            "--no-privileges",
            "--no-unlogged-table-data",
            "-U",
            names::SUPERUSER,
            "-d",
            names::DATABASE,
            "-p",
        ])
        .arg(port.to_string());
        let out = self.run_ok("pg_dump", cmd, None)?;
        Ok(canonicalize_dump(&String::from_utf8_lossy(&out.stdout)))
    }
}

/// Remove plaintext leftovers (`.dump-*.tmp`, `.restore-*.tmp`) of an earlier run that was killed. They live in the
/// owner-only backups directory, but they hold an unencrypted dump and must not outlive the run that made them.
pub fn sweep_stale_temporaries(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if (name.starts_with(".dump-") || name.starts_with(".restore-")) && name.ends_with(".tmp") {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Drop comment lines and `\restrict` / `\unrestrict` lines (random per run) and blank lines.
pub fn canonicalize_dump(text: &str) -> String {
    text.lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty()
                && !t.starts_with("--")
                && !t.starts_with("\\restrict")
                && !t.starts_with("\\unrestrict")
        })
        .collect::<Vec<_>>()
        .join("\n")
}
