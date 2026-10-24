//! The pinned distribution (ADR-0029): which PostgreSQL archive to use for each operating system and architecture, where it is
//! published and what its SHA-256 digest must be. The file is compiled into the binary, so a download can never choose its own
//! digest.

use serde::Deserialize;

use super::{PgError, PgResult};

const EMBEDDED: &str = include_str!("../../postgres-manifest.toml");

/// Where the archives are published.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Source {
    /// Project name (documentation).
    pub project: String,
    /// Base URL of the release downloads, without trailing slash.
    pub base_url: String,
    /// Release tag.
    pub tag: String,
}

/// One archive.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Target {
    /// Rust target triple the archive is built for.
    pub triple: String,
    /// File name inside the release.
    pub file: String,
    /// Pinned SHA-256 (64 lower-case hexadecimal characters).
    pub sha256: String,
    /// Size in bytes.
    pub size: u64,
}

/// The whole pinned distribution.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// PostgreSQL version (for example `17.11.1`).
    pub postgres_version: String,
    /// Source.
    pub source: Source,
    /// Archives.
    #[serde(rename = "target")]
    pub targets: Vec<Target>,
}

/// The Rust target triple of this build, when a distribution is pinned for it.
pub fn current_triple() -> Option<&'static str> {
    if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        Some("x86_64-pc-windows-msvc")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("aarch64-apple-darwin")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Some("x86_64-apple-darwin")
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("x86_64-unknown-linux-gnu")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Some("aarch64-unknown-linux-gnu")
    } else {
        None
    }
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Manifest {
    /// The manifest compiled into this build.
    pub fn embedded() -> PgResult<Manifest> {
        Manifest::parse(EMBEDDED)
    }

    /// Parse and validate manifest text.
    pub fn parse(text: &str) -> PgResult<Manifest> {
        let m: Manifest = toml::from_str(text).map_err(|e| PgError::Manifest(e.to_string()))?;
        m.validate()?;
        Ok(m)
    }

    fn validate(&self) -> PgResult<()> {
        let bad = |why: String| Err(PgError::Manifest(why));
        let v = &self.postgres_version;
        if v.is_empty()
            || !v.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            || v.starts_with('.')
            || v.ends_with('.')
        {
            return bad(format!("version `{v}` is not dotted digits"));
        }
        if !self.source.base_url.starts_with("https://") || self.source.base_url.ends_with('/') {
            return bad("base_url must be an https URL without a trailing slash".into());
        }
        if self.source.tag.is_empty() || self.source.tag.contains(['/', '?', '#', ' ']) {
            return bad("tag must be a plain release tag".into());
        }
        if self.targets.is_empty() {
            return bad("no targets".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for t in &self.targets {
            if !seen.insert(t.triple.as_str()) {
                return bad(format!("target {} is listed twice", t.triple));
            }
            if t.file != format!("postgresql-{v}-{}.tar.gz", t.triple) {
                return bad(format!(
                    "file name of {} does not follow the distributor's pattern",
                    t.triple
                ));
            }
            if !is_sha256(&t.sha256) {
                return bad(format!(
                    "sha256 of {} is not 64 lower-case hex characters",
                    t.triple
                ));
            }
            if t.size == 0 || t.size > 1 << 31 {
                return bad(format!("size of {} is not plausible", t.triple));
            }
        }
        Ok(())
    }

    /// The archive for this build's operating system and architecture.
    pub fn for_current(&self) -> PgResult<&Target> {
        let triple = current_triple().ok_or_else(|| {
            PgError::UnsupportedPlatform(format!(
                "{}/{}",
                std::env::consts::OS,
                std::env::consts::ARCH
            ))
        })?;
        self.for_triple(triple)
    }

    /// The archive for a given triple.
    pub fn for_triple(&self, triple: &str) -> PgResult<&Target> {
        self.targets
            .iter()
            .find(|t| t.triple == triple)
            .ok_or_else(|| PgError::UnsupportedPlatform(triple.to_owned()))
    }

    /// Download URL of an archive.
    pub fn url(&self, t: &Target) -> String {
        format!("{}/{}/{}", self.source.base_url, self.source.tag, t.file)
    }

    /// The egress allowlist entries needed to download from this source, as the operator must add them to `egress_allowlist`:
    /// the pinned release path and the host GitHub redirects release assets to.
    pub fn egress_entries(&self) -> Vec<String> {
        vec![
            format!("{}/{}/", self.source.base_url, self.source.tag),
            "https://release-assets.githubusercontent.com/".to_owned(),
        ]
    }
}
