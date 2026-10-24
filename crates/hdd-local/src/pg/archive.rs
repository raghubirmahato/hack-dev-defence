//! Archive handling: digest verification and a bounded, path-checked extraction.
//!
//! The order is the point: [`verify_archive`] runs before [`extract_tar_gz`], and a wrong digest or size returns
//! [`PgError::Checksum`] without a single byte having been written outside the cache (A2). Extraction refuses absolute paths,
//! `..`, drive prefixes, links that leave the destination, device nodes, more than [`MAX_ENTRIES`] entries and more than
//! [`MAX_UNPACKED_BYTES`] bytes.

use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};

use super::manifest::Target;
use super::{PgError, PgResult};

/// Most entries an archive may contain.
pub const MAX_ENTRIES: usize = 100_000;
/// Most bytes an archive may unpack to.
pub const MAX_UNPACKED_BYTES: u64 = 3 * 1024 * 1024 * 1024;

/// SHA-256 of a file as lower-case hex, read in blocks.
pub fn sha256_file(path: &Path) -> PgResult<String> {
    let mut f = BufReader::new(File::open(path)?);
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(buf.get(..n).unwrap_or(&[]));
    }
    Ok(hex(&h.finalize()))
}

/// SHA-256 of bytes as lower-case hex.
pub fn sha256_bytes(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn short(s: &str) -> String {
    s.chars().take(16).collect::<String>() + "…"
}

/// Check the file against the pinned size and digest. Nothing is extracted.
pub fn verify_archive(path: &Path, target: &Target) -> PgResult<()> {
    let size = fs::metadata(path)?.len();
    if size != target.size {
        return Err(PgError::Checksum {
            what: "size",
            expected: target.size.to_string(),
            actual: size.to_string(),
        });
    }
    let actual = sha256_file(path)?;
    if actual != target.sha256 {
        return Err(PgError::Checksum {
            what: "SHA-256",
            expected: short(&target.sha256),
            actual: short(&actual),
        });
    }
    Ok(())
}

/// A relative path made of normal components only.
fn safe_relative(p: &Path) -> bool {
    !p.as_os_str().is_empty()
        && p.components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
        && !p.to_string_lossy().contains('\\')
}

/// Resolve a link target lexically against the directory of the link and report whether it stays inside the destination.
fn link_stays_inside(link_path: &Path, target: &Path) -> bool {
    if target.is_absolute() || target.to_string_lossy().contains('\\') {
        return false;
    }
    let mut depth: i64 = i64::try_from(link_path.parent().map_or(0, |p| {
        p.components()
            .filter(|c| matches!(c, Component::Normal(_)))
            .count()
    }))
    .unwrap_or(0);
    for c in target.components() {
        match c {
            Component::Normal(_) => depth += 1,
            Component::ParentDir => depth -= 1,
            Component::CurDir => {}
            _ => return false,
        }
        if depth < 0 {
            return false;
        }
    }
    true
}

/// What an extraction did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extracted {
    /// Entries written.
    pub entries: usize,
    /// Bytes written.
    pub bytes: u64,
}

/// Unpack a `.tar.gz` into `dest` (created if missing). The caller verifies the digest first ([`verify_archive`]).
pub fn extract_tar_gz(archive: &Path, dest: &Path) -> PgResult<Extracted> {
    fs::create_dir_all(dest)?;
    let gz = GzDecoder::new(BufReader::new(File::open(archive)?));
    let mut tar = tar::Archive::new(gz);
    tar.set_preserve_permissions(true);
    tar.set_overwrite(false);
    let mut entries = 0usize;
    let mut bytes = 0u64;
    let bad = |m: String| PgError::Extract(m);
    for entry in tar.entries().map_err(|e| bad(e.to_string()))? {
        let mut entry = entry.map_err(|e| bad(e.to_string()))?;
        entries += 1;
        if entries > MAX_ENTRIES {
            return Err(bad(format!("more than {MAX_ENTRIES} entries")));
        }
        let path: PathBuf = entry.path().map_err(|e| bad(e.to_string()))?.into_owned();
        if !safe_relative(&path) {
            return Err(bad(format!(
                "unsafe path `{}`",
                path.display()
                    .to_string()
                    .chars()
                    .take(80)
                    .collect::<String>()
            )));
        }
        let kind = entry.header().entry_type();
        use tar::EntryType as K;
        match kind {
            K::Regular | K::Directory | K::Continuous => {}
            K::Symlink | K::Link => {
                let target = entry
                    .link_name()
                    .map_err(|e| bad(e.to_string()))?
                    .ok_or_else(|| bad("a link without a target".into()))?
                    .into_owned();
                let ok = if kind == K::Link {
                    safe_relative(&target)
                } else {
                    link_stays_inside(&path, &target)
                };
                if !ok {
                    return Err(bad(format!(
                        "link `{}` points outside the destination",
                        path.display()
                            .to_string()
                            .chars()
                            .take(80)
                            .collect::<String>()
                    )));
                }
            }
            K::XGlobalHeader | K::XHeader | K::GNULongName | K::GNULongLink => continue,
            other => {
                return Err(bad(format!("entry type {other:?} is not allowed")));
            }
        }
        bytes = bytes.saturating_add(entry.header().size().unwrap_or(0));
        if bytes > MAX_UNPACKED_BYTES {
            return Err(bad(format!(
                "more than {} MiB unpacked",
                MAX_UNPACKED_BYTES / (1024 * 1024)
            )));
        }
        let wrote = entry.unpack_in(dest).map_err(|e| bad(e.to_string()))?;
        if !wrote {
            return Err(bad("an entry was skipped as unsafe by the unpacker".into()));
        }
    }
    Ok(Extracted { entries, bytes })
}

/// Where `bin/` lives after extraction: directly in `dir`, or inside a single top-level directory.
pub fn find_root(dir: &Path) -> PgResult<PathBuf> {
    let has_bin = |d: &Path| d.join("bin").is_dir();
    if has_bin(dir) {
        return Ok(dir.to_path_buf());
    }
    let mut subdirs = Vec::new();
    for e in fs::read_dir(dir)? {
        let e = e?;
        if e.file_type()?.is_dir() {
            subdirs.push(e.path());
        }
    }
    match subdirs.as_slice() {
        [only] if has_bin(only) => Ok(only.clone()),
        _ => Err(PgError::Extract(
            "the archive has no bin/ directory at its top level".into(),
        )),
    }
}
