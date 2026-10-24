//! `hdd-canary`: the origin-side sidecar of section C16/C16.1.
//!
//! It serves **only** the canary contract files (`ok.txt`, `leak.txt`, `static.css`, `static.js`, `search.html`) under the
//! profile's `origin.canary.base_path`, plus `GET <base_path>echo-headers`, which returns the received request headers as
//! JSON. It never executes or reflects request input, never reads a request body, never lists a directory and never answers
//! any other path: every request it does not serve gets one identical opaque response.
//!
//! Limits (documented in `CANARY.md` and enforced here): a request line of at most [`MAX_REQUEST_LINE`] bytes, header lines
//! of at most [`MAX_HEADER_BYTES`] bytes together and at most [`MAX_HEADERS`] of them, one connection at a time with a read
//! timeout of [`DEFAULT_READ_TIMEOUT`], a served file of at most [`MAX_FILE_BYTES`], and an `echo-headers` body of at most
//! [`MAX_ECHO_JSON_BYTES`] bytes.
//!
//! Filesystem model: the five files are read **once at startup** from the configured root directory, by their fixed names,
//! with `std::fs::read` (read-only); after that the process never touches the filesystem again. Restart the sidecar to pick
//! up changed files. When a manifest is configured it is verified before the first byte is served and a mismatch stops the
//! process (fail closed).

#![forbid(unsafe_code)]

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// The error class of a transport failure (Q-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// DNS resolution returned a negative answer (NXDOMAIN/no records): for a profile `test_hostname` this may mean the
    /// pilot delegation is not in place yet.
    Resolve,
    /// DNS resolution failed for another reason (timeout, SERVFAIL, resolver/network failure): the delegation question
    /// cannot be answered, so this is an environment limitation rather than a pending human step (P-6).
    ResolveOther,
    /// TCP connect failed.
    Connect,
    /// A timeout elapsed.
    Timeout,
    /// A connection/protocol error.
    Http,
    /// TLS failed.
    Tls,
}

/// Where a canary target came from (Q-1): only a profile-named `test_hostname` can make a DNS failure a pending
/// delegation step; a literal IP (or an explicit override with no profile) has nothing to delegate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetProvenance {
    /// The host came from the live profile's `test_hostname`.
    ProfileTestHostname,
    /// The host came from the live profile's origin.url.
    ProfileOrigin,
    /// The host came from an operator override that matched a profile-named host.
    OverrideNamed,
    /// The host came from --local-only with a loopback literal.
    OverrideLiteral,
}

/// True when a resolver error message describes a negative answer (NXDOMAIN/no records/no answer) rather than a resolver
/// or network failure (P-6).
pub fn resolver_negative_answer(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("nxdomain")
        || lower.contains("no records")
        || lower.contains("no answer")
        || lower.contains("not found")
        || lower.contains("does not exist")
}

/// Classify an override target by host identity, not by how the flag was spelled (P-6): an override naming the profile
/// `test_hostname` is as delegatable as the default through target for that host; one naming the origin URL host is the
/// origin; anything else is a named/literal override.
pub fn classify_override_provenance(
    test_hostname: &str,
    origin_host: Option<&str>,
    host: &str,
) -> TargetProvenance {
    let test_hostname = normalise_host_token(test_hostname);
    if !test_hostname.is_empty() && host == test_hostname {
        TargetProvenance::ProfileTestHostname
    } else if origin_host.is_some_and(|origin| origin == host) {
        TargetProvenance::ProfileOrigin
    } else {
        TargetProvenance::OverrideNamed
    }
}

/// True when a transport failure may mean the pilot delegation is not in place yet (Q-1). There is no delegation
/// field in the live profile (hdd.live.example.yaml has none; origin.lockdown_state is the STOP #2 origin
/// firewall/secret-header state), so only a DNS resolution failure of a profile-named `test_hostname` can be pending.
pub fn transport_means_pending_delegation(
    provenance: TargetProvenance,
    kind: TransportKind,
) -> bool {
    provenance == TargetProvenance::ProfileTestHostname && kind == TransportKind::Resolve
}

use sha2::{Digest, Sha256};

/// Longest accepted request line, in bytes, excluding the CRLF that ends it (C16.1).
pub const MAX_REQUEST_LINE: usize = 1024;
/// Largest accepted header section, in bytes: every header line with its CRLF (C16.1).
pub const MAX_HEADER_BYTES: usize = 8 * 1024;
/// Largest accepted number of request headers.
pub const MAX_HEADERS: usize = 100;
/// Largest accepted `echo-headers` response body, in bytes (A3: the answer has a size cap).
pub const MAX_ECHO_JSON_BYTES: usize = 16 * 1024;
/// Largest accepted canary file, in bytes.
pub const MAX_FILE_BYTES: usize = 64 * 1024;
/// Largest accepted `origin.canary.base_path`, in bytes.
pub const MAX_BASE_PATH_LEN: usize = 128;
/// Read/write timeout of one served connection.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Default bind address: loopback only, because the origin is reached by HDD or a tunnel.
pub const DEFAULT_BIND: &str = "127.0.0.1:8080";
/// Default base path, the same default as the profile (`Canary::default`).
pub const DEFAULT_BASE_PATH: &str = "/__hdd_canary/";
/// Default root directory of the canary files on a Linux origin (systemd unit uses it).
pub const DEFAULT_ROOT: &str = "/var/lib/hdd-canary";
/// Name of the generated manifest file. It is deliberately **not** served: only the C16.1 files and `echo-headers` are.
pub const MANIFEST_NAME: &str = "manifest.sha256";
/// Last path segment of the header-echo endpoint (full path: `<base_path>echo-headers`).
pub const ECHO_HEADERS_SEGMENT: &str = "echo-headers";
/// Value written in `echo-headers` instead of a credential-bearing request header value.
pub const ECHO_REDACTED_VALUE: &str = "[not-echoed]";
/// Length of a lower-case hexadecimal SHA-256 string.
pub const SHA256_HEX_LEN: usize = 64;
/// Largest request head read from a socket: request line + CRLF + headers + the final CRLF.
const MAX_REQUEST_HEAD_BYTES: usize = MAX_REQUEST_LINE + 2 + MAX_HEADER_BYTES + 2;
/// How much of a rejected connection's remaining bytes are discarded (without parsing) before closing, so the client can
/// read the rejection instead of seeing a reset. Nothing is inspected.
const MAX_DRAIN_BYTES: usize = 64 * 1024;

/// One inert canary file of the C16.1 contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanaryFile {
    /// File name as served relative to the base path.
    pub name: &'static str,
    /// `Content-Type` the sidecar sends for it.
    pub media_type: &'static str,
    /// Exact bytes served (and hashed into the manifest).
    pub content: &'static [u8],
}

/// The five C16.1 files, with their exact content. `hddctl canary generate` writes exactly these bytes.
pub const FILES: [CanaryFile; 5] = [
    CanaryFile {
        name: "ok.txt",
        media_type: "text/plain; charset=utf-8",
        content: b"hdd-canary-ok",
    },
    CanaryFile {
        name: "leak.txt",
        media_type: "text/plain; charset=utf-8",
        content: b"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
    },
    CanaryFile {
        name: "static.css",
        media_type: "text/css; charset=utf-8",
        content: b"/* hdd-canary static asset: byte-exact pass-through fixture. */\n:root { color-scheme: light; }\nbody { margin: 2rem; font-family: system-ui, sans-serif; color: #222; background: #fff; }\nh1 { font-size: 1.25rem; }\n",
    },
    CanaryFile {
        name: "static.js",
        media_type: "text/javascript; charset=utf-8",
        content: b"/* hdd-canary static asset: byte-exact pass-through fixture; no request data is read or executed. */\n(function () {\n  'use strict';\n  var node = document.getElementById('hdd-canary-marker');\n  if (node) { node.setAttribute('data-hdd-canary-js', 'ok'); }\n})();\n",
    },
    CanaryFile {
        name: "search.html",
        media_type: "text/html; charset=utf-8",
        content: b"<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>hdd-canary search</title>\n<link rel=\"stylesheet\" href=\"static.css\">\n</head>\n<body>\n<h1>hdd-canary search</h1>\n<p id=\"hdd-canary-marker\">This page is static: it echoes nothing and runs nothing from the request.</p>\n<script src=\"static.js\"></script>\n</body>\n</html>\n",
    },
];

/// Why a canary operation failed. Every message is fixed text: nothing a client sent is ever part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanaryError {
    /// A filesystem operation failed; the message names the file, never its content.
    Io(String),
    /// The manifest is missing, malformed or does not match the files.
    Manifest(String),
    /// `origin.canary.base_path` (or `--base-path`) is not acceptable.
    BasePath(String),
    /// A canary file is larger than [`MAX_FILE_BYTES`].
    FileTooLarge {
        /// File name.
        name: String,
        /// Size read from disk.
        size: u64,
    },
    /// The listener could not be started.
    Start(String),
}

impl fmt::Display for CanaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanaryError::Io(m) => write!(f, "file error: {m}"),
            CanaryError::Manifest(m) => write!(f, "manifest error: {m}"),
            CanaryError::BasePath(m) => write!(f, "base path error: {m}"),
            CanaryError::FileTooLarge { name, size } => {
                write!(f, "{name} is {size} bytes; the limit is {MAX_FILE_BYTES}")
            }
            CanaryError::Start(m) => write!(f, "cannot start: {m}"),
        }
    }
}

impl std::error::Error for CanaryError {}

/// Lower-case hexadecimal SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    hex(digest.as_slice())
}

/// Lower-case hexadecimal text of `bytes`.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let high = usize::from(byte >> 4);
        let low = usize::from(byte & 0x0f);
        if let (Some(h), Some(l)) = (DIGITS.get(high), DIGITS.get(low)) {
            out.push(char::from(*h));
            out.push(char::from(*l));
        }
    }
    out
}

/// True when `s` is exactly 64 lower-case hexadecimal characters.
fn is_sha256_hex(s: &str) -> bool {
    s.len() == SHA256_HEX_LEN
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// True when `path` (already query-stripped) is a `.` or `..` segment.
fn has_dot_segment(path: &str) -> bool {
    path.split('/')
        .any(|segment| segment == "." || segment == "..")
}

/// Accept a base path from the profile or the command line and normalize it to exactly one leading and one trailing `/`.
///
/// It may contain only printable non-space ASCII other than `?`, `#`, `%`, `\\` and it must not contain a `..` segment;
/// the canary files are matched literally, so a base path that a proxy could normalize differently is refused.
pub fn normalise_base_path(raw: &str) -> Result<String, CanaryError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CanaryError::BasePath("it is empty".into()));
    }
    if !trimmed.starts_with('/') {
        return Err(CanaryError::BasePath(format!(
            "`{trimmed}` must start with `/`"
        )));
    }
    if !trimmed
        .bytes()
        .all(|b| (0x21..=0x7e).contains(&b) && !matches!(b, b'?' | b'#' | b'%' | b'\\'))
    {
        return Err(CanaryError::BasePath(format!(
            "`{trimmed}` may contain only printable ASCII without whitespace, `?`, `#`, `%` or `\\`"
        )));
    }
    if trimmed.contains("//") {
        return Err(CanaryError::BasePath(format!(
            "`{trimmed}` contains an empty path segment"
        )));
    }
    if has_dot_segment(trimmed) {
        return Err(CanaryError::BasePath(format!(
            "`{trimmed}` contains a `.` or `..` segment"
        )));
    }
    let mut out = trimmed.to_owned();
    if !out.ends_with('/') {
        out.push('/');
    }
    if out.len() > MAX_BASE_PATH_LEN {
        return Err(CanaryError::BasePath(format!(
            "it is longer than {MAX_BASE_PATH_LEN} bytes"
        )));
    }
    Ok(out)
}

/// One `<sha256>  <name>` line of the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// File name relative to the base path.
    pub name: String,
    /// Lower-case hexadecimal SHA-256 of the file's exact bytes.
    pub sha256: String,
}

/// The generated manifest: the base path it was generated for and the hash of every C16.1 file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Base path the files were generated for.
    pub base_path: String,
    /// One entry per C16.1 file, in [`FILES`] order.
    pub entries: Vec<ManifestEntry>,
}

impl Manifest {
    /// SHA-256 recorded for `name`, if the manifest has an entry for it.
    pub fn sha256_of(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.sha256.as_str())
    }
}

/// Render the manifest file text: a header naming the base path and one `SHA256SUMS`-style line per file.
pub fn manifest_text(base_path: &str, entries: &[ManifestEntry]) -> String {
    let mut out = String::with_capacity(128 + entries.len() * 96);
    out.push_str("# hdd-canary manifest: generated by `hddctl canary generate` (T-0210, section C16.1 of docs/SPEC.md).\n");
    out.push_str(
        "# The five files below are the whole canary contract; this manifest is not served.\n",
    );
    out.push_str(&format!("# base_path: {base_path}\n"));
    out.push_str("# format: <sha256>  <relative file name>\n");
    for entry in entries {
        out.push_str(&format!("{}  {}\n", entry.sha256, entry.name));
    }
    out
}

/// Parse `<SHA256>  <name>` manifest text (syntax only; the C16.1 contract check lives in [`parse_manifest`]).
fn parse_manifest_entries(text: &str) -> Result<(String, Vec<ManifestEntry>), CanaryError> {
    let mut base_path: Option<String> = None;
    let mut entries: Vec<ManifestEntry> = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('#') {
            if let Some(value) = rest.trim().strip_prefix("base_path:") {
                let value = value.trim();
                if value.is_empty() {
                    return Err(CanaryError::Manifest(
                        "the base_path header is empty".into(),
                    ));
                }
                if base_path.is_some() {
                    return Err(CanaryError::Manifest(
                        "the base_path header appears twice".into(),
                    ));
                }
                base_path = Some(normalise_base_path(value)?.clone());
            }
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(hash), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(CanaryError::Manifest(format!(
                "`{line}` is not `<sha256>  <name>`"
            )));
        };
        if !is_sha256_hex(hash) {
            return Err(CanaryError::Manifest(format!(
                "`{hash}` is not 64 lower-case hexadecimal characters"
            )));
        }
        if entries.iter().any(|e| e.name == name) {
            return Err(CanaryError::Manifest(format!("`{name}` appears twice")));
        }
        entries.push(ManifestEntry {
            name: name.to_owned(),
            sha256: hash.to_owned(),
        });
    }
    let base_path =
        base_path.ok_or_else(|| CanaryError::Manifest("no `# base_path:` header".into()))?;
    Ok((base_path, entries))
}

/// Parse manifest file text, refusing anything that is not exactly the C16.1 contract.
pub fn parse_manifest(text: &str) -> Result<Manifest, CanaryError> {
    let (base_path, entries) = parse_manifest_entries(text)?;
    for entry in &entries {
        if !FILES.iter().any(|f| f.name == entry.name) {
            return Err(CanaryError::Manifest(format!(
                "`{}` is not a C16.1 canary file",
                entry.name
            )));
        }
    }
    if entries.len() != FILES.len() {
        return Err(CanaryError::Manifest(format!(
            "the manifest must list exactly the {} C16.1 files, not {}",
            FILES.len(),
            entries.len()
        )));
    }
    Ok(Manifest { base_path, entries })
}

/// Write the five C16.1 files and [`MANIFEST_NAME`] into `dir`, returning the manifest (real SHA-256 over the bytes written).
pub fn generate(dir: &Path, base_path: &str) -> Result<Manifest, CanaryError> {
    let base_path = normalise_base_path(base_path)?;
    std::fs::create_dir_all(dir)
        .map_err(|e| CanaryError::Io(format!("cannot create {}: {e}", dir.display())))?;
    ensure_real_directory(dir)?;
    let mut entries = Vec::with_capacity(FILES.len());
    for file in &FILES {
        let path = dir.join(file.name);
        // K-7: never follow a symlink (or write over a directory) when generating the files.
        if let Ok(metadata) = std::fs::symlink_metadata(&path) {
            ensure_regular(node_kind(&metadata), &path)?;
        }
        std::fs::write(&path, file.content)
            .map_err(|e| CanaryError::Io(format!("cannot write {}: {e}", path.display())))?;
        entries.push(ManifestEntry {
            name: file.name.to_owned(),
            sha256: sha256_hex(file.content),
        });
    }
    let text = manifest_text(&base_path, &entries);
    let manifest_path = dir.join(MANIFEST_NAME);
    std::fs::write(&manifest_path, text.as_bytes())
        .map_err(|e| CanaryError::Io(format!("cannot write {}: {e}", manifest_path.display())))?;
    Ok(Manifest { base_path, entries })
}

/// Result of re-hashing the files in a directory against its manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestReport {
    /// Base path recorded in the manifest.
    pub base_path: String,
    /// One check per file, in [`FILES`] order, plus any manifest entry whose file is not part of the contract.
    pub checks: Vec<ManifestCheck>,
}

/// One file compared against the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestCheck {
    /// File name.
    pub name: String,
    /// Hash recorded in the manifest (`None` when the manifest has no entry).
    pub expected: Option<String>,
    /// Hash of the bytes on disk (`None` when the file is missing or unreadable).
    pub actual: Option<String>,
}

impl ManifestCheck {
    /// True when the manifest records a hash and the file on disk has exactly that hash.
    pub fn matches(&self) -> bool {
        self.expected.is_some() && self.expected == self.actual
    }
}

impl ManifestReport {
    /// True when every manifest entry matches a file and every C16.1 file has a matching entry.
    pub fn ok(&self) -> bool {
        self.checks.len() == FILES.len() && self.checks.iter().all(ManifestCheck::matches)
    }
}

/// Re-hash the files in `dir` and compare them with `manifest.sha256` there.
pub fn check_manifest(dir: &Path) -> Result<ManifestReport, CanaryError> {
    ensure_real_directory(dir)?;
    let manifest_path = dir.join(MANIFEST_NAME);
    let text = std::fs::read_to_string(&manifest_path).map_err(|e| {
        CanaryError::Manifest(format!(
            "cannot read {}: {e}; run `hddctl canary generate --dir <dir>`",
            manifest_path.display()
        ))
    })?;
    let (base_path, entries) = parse_manifest_entries(&text)?;
    let mut checks = Vec::with_capacity(FILES.len());
    for file in &FILES {
        // K-7: the same regular-file decision as `start()`, with `symlink_metadata` and a bounded read, so `verify --dir`
        // cannot pass a directory or a symlink that the sidecar itself refuses.
        let path = dir.join(file.name);
        let actual = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                let kind = node_kind(&metadata);
                if ensure_regular(kind, &path).is_err() || metadata.len() > MAX_FILE_BYTES as u64 {
                    None
                } else {
                    match File::open(&path) {
                        Ok(opened) => {
                            let mut bytes = Vec::with_capacity(metadata.len() as usize);
                            let read = opened
                                .take(MAX_FILE_BYTES as u64 + 1)
                                .read_to_end(&mut bytes)
                                .is_ok();
                            if read && bytes.len() <= MAX_FILE_BYTES {
                                Some(sha256_hex(&bytes))
                            } else {
                                None
                            }
                        }
                        Err(_) => None,
                    }
                }
            }
            Err(_) => None,
        };
        let expected = entries
            .iter()
            .find(|e| e.name == file.name)
            .map(|e| e.sha256.clone());
        checks.push(ManifestCheck {
            name: file.name.to_owned(),
            expected,
            actual,
        });
    }
    for entry in &entries {
        if !FILES.iter().any(|f| f.name == entry.name) {
            checks.push(ManifestCheck {
                name: entry.name.clone(),
                expected: Some(entry.sha256.clone()),
                actual: None,
            });
        }
    }
    Ok(ManifestReport { base_path, checks })
}

/// HTTP method understood by the sidecar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`.
    Get,
    /// `HEAD` (same headers as `GET`, no body).
    Head,
}

/// One received request header, name lower-cased.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Header name, lower-case ASCII.
    pub name: String,
    /// Header value, printable ASCII and horizontal tabs only.
    pub value: String,
}

/// A parsed request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Method.
    pub method: Method,
    /// Request path without the query string, exactly as sent (no percent-decoding).
    pub path: String,
    /// Query string without the `?`, when present.
    pub query: Option<String>,
    /// Headers in the order received, names lower-cased.
    pub headers: Vec<Header>,
}

impl Request {
    /// First header with this (case-insensitive) name.
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|h| h.name == lower)
            .map(|h| h.value.as_str())
    }
}

/// Why a request head was not served. The server maps every variant to the same opaque response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    /// The head is not complete yet.
    Incomplete,
    /// One of the documented size limits was exceeded.
    TooLong(&'static str),
    /// The head is malformed.
    Malformed(&'static str),
}

/// What the sidecar does with a request path (after the query string has been removed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Serve this C16.1 file.
    File(&'static CanaryFile),
    /// Serve the header-echo JSON.
    EchoHeaders,
    /// Nothing: one opaque response, identical for every rejected request.
    Reject,
}

/// Route a request path to a served resource. Matching is literal on the raw bytes (no percent-decoding, no case folding,
/// no trailing-slash rewriting), so encoded or dot-segment variants can never reach a file.
pub fn route(base_path: &str, path: &str) -> Route {
    let Some(rest) = path.strip_prefix(base_path) else {
        return Route::Reject;
    };
    if rest == ECHO_HEADERS_SEGMENT {
        return Route::EchoHeaders;
    }
    FILES
        .iter()
        .find(|file| file.name == rest)
        .map_or(Route::Reject, Route::File)
}

/// Offset just after the first CRLF CRLF in `buf`, if present.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|start| start + 4)
}

/// Offset of the first CRLF in `buf`, if present.
fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|window| window == b"\r\n")
}

/// True for the ASCII token bytes allowed in a header name (RFC 9110 `tchar`).
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Parse a complete request head (up to and including the CRLF CRLF) from `buf`.
pub fn parse_request(buf: &[u8]) -> Result<Request, RequestError> {
    let Some(head_end) = find_head_end(buf) else {
        return if buf.len() > MAX_REQUEST_HEAD_BYTES {
            Err(RequestError::TooLong("request head"))
        } else {
            Err(RequestError::Incomplete)
        };
    };
    let head_len = head_end - 4;
    let head = buf.get(..head_len).ok_or(RequestError::Malformed("head"))?;
    // with no headers the whole head is the request line; otherwise the request line ends at the first CRLF
    let line_end = find_crlf(head).unwrap_or(head_len);
    let request_line = head
        .get(..line_end)
        .ok_or(RequestError::Malformed("request line"))?;
    if request_line.len() > MAX_REQUEST_LINE {
        return Err(RequestError::TooLong("request line"));
    }
    // every header line with its CRLF, as documented
    let header_bytes = head_len.saturating_sub(line_end);
    if header_bytes > MAX_HEADER_BYTES {
        return Err(RequestError::TooLong("headers"));
    }

    let mut parts = request_line.split(|byte| *byte == b' ');
    let (Some(method_raw), Some(target_raw), Some(version_raw), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(RequestError::Malformed("request line shape"));
    };
    let method = match method_raw {
        b"GET" => Method::Get,
        b"HEAD" => Method::Head,
        _ => return Err(RequestError::Malformed("method")),
    };
    let target = std::str::from_utf8(target_raw).map_err(|_| RequestError::Malformed("target"))?;
    if !target.starts_with('/') {
        return Err(RequestError::Malformed("target"));
    }
    if !matches!(version_raw, b"HTTP/1.1" | b"HTTP/1.0") {
        return Err(RequestError::Malformed("version"));
    } // the path and query stay exactly as sent: percent-encoding is never decoded
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query.to_owned())),
        None => (target, None),
    };

    let header_region = head.get(line_end + 2..).unwrap_or(&[]);
    let mut headers: Vec<Header> = Vec::new();
    let mut remaining = header_region;
    while !remaining.is_empty() {
        let (line, rest) = match find_crlf(remaining) {
            Some(end) => (
                remaining.get(..end).unwrap_or(&[]),
                remaining.get(end + 2..).unwrap_or(&[]),
            ),
            None => (remaining, &[] as &[u8]),
        };
        if line.is_empty() {
            return Err(RequestError::Malformed("empty header line"));
        }
        if headers.len() >= MAX_HEADERS {
            return Err(RequestError::TooLong("header count"));
        }
        if matches!(line.first().copied(), Some(b' ') | Some(b'\t')) {
            return Err(RequestError::Malformed("header folding"));
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(RequestError::Malformed("header name"))?;
        let (name, rest_after_name) = line.split_at(colon);
        let mut value = rest_after_name.get(1..).unwrap_or(&[]);
        while matches!(value.first().copied(), Some(b' ') | Some(b'\t')) {
            value = value.get(1..).unwrap_or(&[]);
        }
        if name.is_empty() || !name.iter().all(|byte| is_token_byte(*byte)) {
            return Err(RequestError::Malformed("header name"));
        }
        if !value
            .iter()
            .all(|byte| matches!(*byte, b'\t' | 0x20..=0x7e))
        {
            return Err(RequestError::Malformed("header value"));
        }
        let name = String::from_utf8(name.to_ascii_lowercase())
            .map_err(|_| RequestError::Malformed("header name"))?;
        let value = String::from_utf8(value.to_vec())
            .map_err(|_| RequestError::Malformed("header value"))?;
        headers.push(Header { name, value });
        remaining = rest;
    }
    // the sidecar never reads a body: a declared body is refused before any of it is read
    // K-8: `Content-Length: 0` declares no body and is accepted; any positive length and any Transfer-Encoding is refused.
    if headers.iter().any(|h| {
        h.name == "transfer-encoding"
            || (h.name == "content-length" && !h.value.trim().eq_ignore_ascii_case("0"))
    }) {
        return Err(RequestError::Malformed("request body"));
    }
    Ok(Request {
        method,
        path: path.to_owned(),
        query,
        headers,
    })
}

/// Append `s` as a JSON string literal to `out`.
fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Header names whose value the echo endpoint returns (P-9): only forwarding and HDD headers. Every other header is
/// counted as `[not-echoed-name]` and its name is never echoed (a credential can hide in a header *name* too).
pub const ECHOED_HEADERS: &[&str] = &[
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "forwarded",
    "x-real-ip",
    "hdd-connecting-ip",
    "hdd-ray-id",
    "x-hdd-canary-probe",
    "connection",
];

/// Header names echoed with a length and character cap (P-9), so a crafted value cannot bounce back unbounded.
pub const CAPPED_HEADERS: &[&str] = &["host", "user-agent"];

/// Maximum number of bytes echoed for a [`CAPPED_HEADERS`] value.
pub const MAX_CAPPED_HEADER_BYTES: usize = 256;

/// The value the echo endpoint returns for one header, or `None` when only its count may be reported (P-9).
///
/// `HDD-Origin-Auth` keeps presence, version and key id only, and only for the exact signed v1 shape; a static token or a
/// malformed v1 is fully redacted. `host`/`user-agent` are echoed only when they are short printable ASCII.
fn echoed_value(header: &Header) -> Option<String> {
    if header.name.eq_ignore_ascii_case(ORIGIN_AUTH_HEADER) {
        return Some(
            origin_auth_summary(&header.value).unwrap_or_else(|| ECHO_REDACTED_VALUE.to_owned()),
        );
    }
    let lower = header.name.to_ascii_lowercase();
    if ECHOED_HEADERS.contains(&lower.as_str()) {
        return Some(header.value.clone());
    }
    if CAPPED_HEADERS.contains(&lower.as_str()) {
        let short_and_printable = header.value.len() <= MAX_CAPPED_HEADER_BYTES
            && header.value.bytes().all(|b| (0x20..=0x7e).contains(&b));
        return Some(if short_and_printable {
            header.value.clone()
        } else {
            ECHO_REDACTED_VALUE.to_owned()
        });
    }
    None
}

/// `v1;<kid>` for a well-formed signed origin-auth header (C21.3), `None` otherwise.
///
/// The exact signed shape is `v1;<kid>;<unix-ts>;<nonce>;<sig>`: kid `^[A-Za-z0-9_-]{1,32}$`, a decimal timestamp, a
/// nonce of 16-64 hex or base64url characters and a 43-character base64url HMAC-SHA-256 signature.
fn origin_auth_summary(value: &str) -> Option<String> {
    let fields: Vec<&str> = value.trim().split(';').collect();
    let [version, kid, timestamp, nonce, signature] = fields.as_slice() else {
        return None;
    };
    if *version != "v1"
        || kid.is_empty()
        || kid.len() > 32
        || !kid.bytes().all(is_base64url_char)
        || timestamp.is_empty()
        || timestamp.len() > 10
        || !timestamp.bytes().all(|b| b.is_ascii_digit())
        || !is_nonce(nonce)
        || !is_base64url_of(signature, 43)
    {
        return None;
    }
    Some(format!("v1;{kid}"))
}

/// A base64url character (unpadded alphabet, C21.3 signatures and nonces).
fn is_base64url_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// True when `s` is exactly `len` base64url characters.
fn is_base64url_of(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(is_base64url_char)
}

/// A nonce: 16-64 characters, all hex or all base64url.
fn is_nonce(nonce: &str) -> bool {
    let len = nonce.len();
    (16..=64).contains(&len)
        && (nonce.bytes().all(|b| b.is_ascii_hexdigit()) || nonce.bytes().all(is_base64url_char))
}

/// Render the received headers as the `echo-headers` JSON body, bounded by [`MAX_ECHO_JSON_BYTES`].
///
/// P-9: values are returned only for [`ECHOED_HEADERS`], or for [`CAPPED_HEADERS`] within the cap. Unknown headers are
/// reported as one `[not-echoed-name]` count, so neither their name nor their value can be read back.
pub fn echo_headers_json(headers: &[Header]) -> Vec<u8> {
    // envelope: `{"headers":[` ... `],"truncated":false}` (20 bytes of trailer at most)
    const TRAILER_BYTES: usize = 20;
    let mut out = String::with_capacity(64 + headers.len() * 48);
    out.push_str("{\"headers\":[");
    let mut truncated = false;
    let mut first = true;
    let mut unknown_names = 0usize;
    for header in headers {
        let Some(value) = echoed_value(header) else {
            unknown_names += 1;
            continue;
        };
        let mut entry = String::with_capacity(header.name.len() + value.len() + 24);
        entry.push_str("{\"name\":");
        push_json_string(&mut entry, &header.name);
        entry.push_str(",\"value\":");
        push_json_string(&mut entry, &value);
        entry.push('}');
        let separator = usize::from(!first);
        if out.len() + separator + entry.len() + TRAILER_BYTES > MAX_ECHO_JSON_BYTES {
            truncated = true;
            break;
        }
        if !first {
            out.push(',');
        }
        out.push_str(&entry);
        first = false;
    }
    if !truncated && unknown_names > 0 {
        let entry = format!("{{\"name\":\"[not-echoed-name]\",\"value\":\"{unknown_names}\"}}");
        let separator = usize::from(!first);
        if out.len() + separator + entry.len() + TRAILER_BYTES > MAX_ECHO_JSON_BYTES {
            truncated = true;
        } else {
            if !first {
                out.push(',');
            }
            out.push_str(&entry);
        }
    }
    out.push_str("],\"truncated\":");
    out.push_str(if truncated { "true}" } else { "false}" });
    out.into_bytes()
}
/// Name of the secret origin header HDD adds to every upstream request (C21.3, `HDD-Origin-Auth: v1;<kid>;<ts>;<nonce>;<sig>`).
pub const ORIGIN_AUTH_HEADER: &str = "hdd-origin-auth";

/// The planting token the echo probe sends in forwarding headers (a documentation address, RFC 5737). HDD strips
/// untrusted inbound forwarding headers and rebuilds the chain (T-0361 A1), so if this token survives in the echoed
/// `X-Forwarded-For` the chain was not HDD-built (an origin terminator appending instead of stripping/rebuilding).
pub const ECHO_SPOOF_TOKEN: &str = "203.0.113.99";

/// Headers a proxy in front of the origin adds to a request; their presence is evidence that the request went through it.
pub const FORWARDING_HEADERS: &[&str] = &[
    "x-forwarded-for",
    "hdd-connecting-ip",
    "x-real-ip",
    "cf-connecting-ip",
    "true-client-ip",
    "forwarded",
];

/// Canonical form of an address for comparisons: an IPv4-mapped IPv6 address (`::ffff:1.2.3.4`) is the IPv4 address it
/// carries, so it compares equal to `1.2.3.4` (K-8).
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(_) => ip,
    }
}

/// Normalize a host taken from the profile or a URL: lower case, one trailing DNS dot removed (K-8).
pub fn normalise_host_token(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// One address token of a forwarding header, as a canonical IP address: plain IPv4/IPv6, `address:port`, `[v6]:port`,
/// and the RFC 7239 `for=` form (matched case-insensitively) (K-8).
pub fn address_token(raw: &str) -> Option<IpAddr> {
    let mut token = raw.trim().trim_matches('"').trim();
    if token.len() >= 4
        && token
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("for="))
    {
        token = token.get(4..).unwrap_or("").trim().trim_matches('"');
    }
    if let Some(rest) = token.strip_prefix('[')
        && let Some(end) = rest.find(']')
        && let Some(inner) = rest.get(..end)
        && let Ok(ip) = inner.parse::<IpAddr>()
    {
        return Some(canonical_ip(ip));
    }
    if let Ok(ip) = token.parse::<IpAddr>() {
        return Some(canonical_ip(ip));
    }
    if let Some((head, _port)) = token.rsplit_once(':')
        && let Ok(ip) = head.parse::<IpAddr>()
    {
        return Some(canonical_ip(ip));
    }
    None
}

/// The whole address tokens of every forwarding header, with the lower-case header name they came from.
pub fn forwarding_tokens(headers: &[Header]) -> Vec<(String, IpAddr)> {
    let mut tokens = Vec::new();
    for header in headers {
        let lower = header.name.to_ascii_lowercase();
        if !FORWARDING_HEADERS.contains(&lower.as_str()) {
            continue;
        }
        for raw in header.value.split([',', ';', ' ', '\t']) {
            if let Some(ip) = address_token(raw) {
                tokens.push((lower.clone(), ip));
            }
        }
    }
    tokens
}

/// `HDD-Connecting-IP` addresses reported by the echo endpoint, canonicalized.
pub fn hdd_connecting_ips(headers: &[Header]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for header in headers {
        if header.name.eq_ignore_ascii_case("hdd-connecting-ip") {
            for raw in header.value.split([',', ';', ' ', '\t']) {
                if let Some(ip) = address_token(raw) {
                    ips.push(ip);
                }
            }
        }
    }
    ips
}

/// Parse the `echo-headers` JSON body into (name, value) pairs (K-8: strict, so `"truncated":txxx` is refused).
pub fn parse_echo_json(body: &[u8]) -> Result<Vec<Header>, String> {
    struct Cursor<'a> {
        bytes: &'a [u8],
        at: usize,
    }
    impl Cursor<'_> {
        fn skip_space(&mut self) {
            while matches!(
                self.bytes.get(self.at),
                Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n')
            ) {
                self.at += 1;
            }
        }
        fn expect(&mut self, byte: u8) -> Result<(), String> {
            self.skip_space();
            if self.bytes.get(self.at) == Some(&byte) {
                self.at += 1;
                Ok(())
            } else {
                Err(format!(
                    "expected `{}` at byte {}",
                    char::from(byte),
                    self.at
                ))
            }
        }
        fn literal(&mut self, literal: &[u8]) -> Result<(), String> {
            self.skip_space();
            if self.bytes.get(self.at..self.at + literal.len()) == Some(literal) {
                self.at += literal.len();
                Ok(())
            } else {
                Err(format!(
                    "expected `{}` at byte {}",
                    String::from_utf8_lossy(literal),
                    self.at
                ))
            }
        }
        fn string(&mut self) -> Result<String, String> {
            self.expect(b'"')?;
            let mut out = String::new();
            loop {
                let Some(&byte) = self.bytes.get(self.at) else {
                    return Err("unterminated JSON string".to_owned());
                };
                self.at += 1;
                match byte {
                    b'"' => return Ok(out),
                    b'\\' => {
                        let Some(&escaped) = self.bytes.get(self.at) else {
                            return Err("unterminated JSON escape".to_owned());
                        };
                        self.at += 1;
                        match escaped {
                            b'"' => out.push('"'),
                            b'\\' => out.push('\\'),
                            b'/' => out.push('/'),
                            b'b' => out.push('\u{8}'),
                            b'f' => out.push('\u{c}'),
                            b'n' => out.push('\n'),
                            b'r' => out.push('\r'),
                            b't' => out.push('\t'),
                            b'u' => {
                                let digits = self
                                    .bytes
                                    .get(self.at..self.at + 4)
                                    .ok_or_else(|| "truncated \\u escape".to_owned())?;
                                let text = std::str::from_utf8(digits)
                                    .map_err(|_| "invalid \\u escape".to_owned())?;
                                let code = u32::from_str_radix(text, 16)
                                    .map_err(|_| "invalid \\u escape".to_owned())?;
                                let character = char::from_u32(code)
                                    .ok_or_else(|| "invalid \\u code point".to_owned())?;
                                out.push(character);
                                self.at += 4;
                            }
                            other => {
                                return Err(format!(
                                    "invalid JSON escape `\\{}`",
                                    char::from(other)
                                ));
                            }
                        }
                    }
                    other => out.push(char::from(other)),
                }
            }
        }
    }
    let mut cursor = Cursor { bytes: body, at: 0 };
    cursor.expect(b'{')?;
    cursor.skip_space();
    if cursor.string()? != "headers" {
        return Err("the echo JSON has no `headers` member".to_owned());
    }
    cursor.expect(b':')?;
    cursor.expect(b'[')?;
    let mut headers: Vec<Header> = Vec::new();
    loop {
        cursor.skip_space();
        if cursor.bytes.get(cursor.at) == Some(&b']') {
            cursor.at += 1;
            break;
        }
        if !headers.is_empty() {
            cursor.expect(b',')?;
        }
        cursor.expect(b'{')?;
        cursor.skip_space();
        if cursor.string()? != "name" {
            return Err("the echo JSON entry has no `name`".to_owned());
        }
        cursor.expect(b':')?;
        let name = cursor.string()?;
        cursor.expect(b',')?;
        cursor.skip_space();
        if cursor.string()? != "value" {
            return Err("the echo JSON entry has no `value`".to_owned());
        }
        cursor.expect(b':')?;
        let value = cursor.string()?;
        cursor.expect(b'}')?;
        headers.push(Header { name, value });
    }
    cursor.expect(b',')?;
    cursor.skip_space();
    if cursor.string()? != "truncated" {
        return Err("the echo JSON has no `truncated` member".to_owned());
    }
    cursor.expect(b':')?;
    // K-8: the literal bytes are checked, not just skipped
    cursor.skip_space();
    if cursor.bytes.get(cursor.at) == Some(&b't') {
        cursor.literal(b"true")?;
    } else {
        cursor.literal(b"false")?;
    }
    cursor.expect(b'}')?;
    cursor.skip_space();
    if cursor.at != body.len() {
        return Err("trailing data after the echo JSON object".to_owned());
    }
    Ok(headers)
}

/// Evidence that a response came through HDD: the response header `Server: Hack-Dev-Defence` (C16, response header
/// section: HDD strips the origin `Server` and sets its own) or the `HDD-Ray-ID` response header (C9.4, AC-05) (K-2).
pub fn hdd_response_evidence(headers: &[Header]) -> Option<String> {
    for header in headers {
        let name = header.name.to_ascii_lowercase();
        let value = header.value.trim();
        if name == "server" && value.eq_ignore_ascii_case("Hack-Dev-Defence") {
            return Some("the response carries `Server: Hack-Dev-Defence`".to_owned());
        }
        if name == "hdd-ray-id" && !value.is_empty() {
            return Some(format!(
                "the response carries the `HDD-Ray-ID` header ({value})"
            ));
        }
    }
    None
}

/// Evidence from `echo-headers` (Q-2/Q-2b): `HDD-Connecting-IP` equal to the runner IP, or a **HDD-built**
/// `X-Forwarded-For`. HDD strips untrusted inbound forwarding headers and rebuilds the chain (T-0361 A1); the probe
/// plants [`ECHO_SPOOF_TOKEN`] in `X-Forwarded-For`, `Forwarded` and `X-Real-IP`, so the X-Forwarded-For evidence
/// requires the runner token to be present **and** the planted spoof token to be absent. A terminator that merely appends
/// (nginx's `$proxy_add_x_forwarded_for`) leaves the spoof, so its header is not evidence. Without a known runner IP the
/// headers cannot be correlated and are not evidence.
pub fn hdd_echo_evidence(headers: &[Header], runner_ip: Option<IpAddr>) -> Result<String, String> {
    let Some(runner_ip) = runner_ip else {
        return Err(
            "no runner IP was supplied (--runner-ip), so the forwarding claims cannot be correlated".to_owned(),
        );
    };
    let runner = canonical_ip(runner_ip);
    let spoof: IpAddr = ECHO_SPOOF_TOKEN
        .parse()
        .map_err(|_| "invalid spoof token".to_owned())?;
    let connecting = hdd_connecting_ips(headers);
    if connecting.contains(&runner) {
        return Ok(format!(
            "echo-headers reports `HDD-Connecting-IP` = {runner} (the runner IP)"
        ));
    }
    let mut xff_tokens: Vec<IpAddr> = Vec::new();
    for header in headers {
        if header.name.eq_ignore_ascii_case("x-forwarded-for") {
            for raw in header.value.split([',', ';', ' ', '\t']) {
                if let Some(ip) = address_token(raw) {
                    xff_tokens.push(ip);
                }
            }
        }
    }
    if xff_tokens.is_empty() {
        return Err(
            "no HDD-specific evidence: `HDD-Connecting-IP` does not carry the runner IP and no `X-Forwarded-For` was echoed".to_owned(),
        );
    }
    let runner_present = xff_tokens.contains(&runner);
    let spoof_present = xff_tokens.contains(&spoof);
    match (runner_present, spoof_present) {
        (true, false) => Ok(format!(
            "echo-headers reports `X-Forwarded-For` with the runner IP {runner} present and the planted spoof token {spoof} stripped (the chain was rebuilt, T-0361 A1)"
        )),
        (false, true) => Err(format!(
            "the runner IP {runner} is not a token of the echoed `X-Forwarded-For` while the planted spoof token {spoof} survived; not HDD-built evidence"
        )),
        (true, true) => Err(format!(
            "the planted spoof token {spoof} survived in the echoed `X-Forwarded-For` (the chain was not stripped and rebuilt), so it is not HDD-built evidence even though the runner IP {runner} is present"
        )),
        (false, false) => Err(format!(
            "the echoed `X-Forwarded-For` contains neither the runner IP {runner} nor the planted spoof token {spoof}; it was not written by this HDD request path"
        )),
    }
}
/// Configuration of one sidecar instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Address to listen on.
    pub bind: SocketAddr,
    /// Normalized base path.
    pub base_path: String,
    /// Directory holding the five canary files and, optionally, the manifest.
    pub root: PathBuf,
    /// Manifest to verify before serving (`None` = serve without the extra check).
    pub manifest: Option<PathBuf>,
    /// Per-connection read timeout.
    pub read_timeout: Duration,
    /// Test-only failure injection: make the listener thread panic at startup (Q-6, R-09). Never set in production.
    #[cfg(test)]
    pub panic_listener: bool,
    /// Test hook (default false; never set in production): panic once inside a connection worker (P-1).
    pub panic_connection: bool,
    /// Test hook (default false; never set in production): make every worker exit immediately (P-1, all workers gone).
    pub kill_workers: bool,
    /// Test hook (default false; never set in production): fail the worker spawn (P-1).
    pub fail_worker_spawn: bool,
}

impl Config {
    /// A configuration with default timeouts; `base_path` is normalized and the manifest is not set.
    pub fn new(
        bind: SocketAddr,
        root: impl Into<PathBuf>,
        base_path: &str,
    ) -> Result<Config, CanaryError> {
        Ok(Config {
            bind,
            base_path: normalise_base_path(base_path)?,
            root: root.into(),
            manifest: None,
            read_timeout: DEFAULT_READ_TIMEOUT,
            #[cfg(test)]
            panic_listener: false,
            panic_connection: false,
            kill_workers: false,
            fail_worker_spawn: false,
        })
    }
}

/// Bounded request counters of one sidecar instance.
#[derive(Debug, Default)]
pub struct Metrics {
    served: AtomicU64,
    rejected: AtomicU64,
    echo_requests: AtomicU64,
    bytes_out: AtomicU64,
    accept_errors: AtomicU64,
    read_timeouts: AtomicU64,
    write_timeouts: AtomicU64,
    listener_panics: AtomicU64,
    worker_panics: AtomicU64,
    connections_shed: AtomicU64,
}

/// A point-in-time copy of [`Metrics`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MetricsSnapshot {
    /// Responses that served a file or the header echo.
    pub served: u64,
    /// Opaque rejection responses.
    pub rejected: u64,
    /// `echo-headers` responses (a subset of [`MetricsSnapshot::served`]).
    pub echo_requests: u64,
    /// Response bytes written.
    pub bytes_out: u64,
    /// `accept` failures (connections the OS refused to hand over); the drop counter of the accept queue.
    pub accept_errors: u64,
    /// Connections closed for the read timeout.
    pub read_timeouts: u64,
    /// Responses abandoned because the write did not finish by the connection deadline.
    pub write_timeouts: u64,
    /// Listener-thread panics (the sidecar then exits, so a supervisor restarts it; R-09).
    pub listener_panics: u64,
    /// Connection-worker panics that were caught, so the service kept running (P-1, R-09).
    pub worker_panics: u64,
    /// Connections shed because the accept queue was full; each got the fixed 503 (P-2).
    pub connections_shed: u64,
}

impl Metrics {
    fn bump(counter: &AtomicU64, by: u64) {
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_add(by))
        });
    }

    /// A copy of the counters.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            served: self.served.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            echo_requests: self.echo_requests.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            accept_errors: self.accept_errors.load(Ordering::Relaxed),
            read_timeouts: self.read_timeouts.load(Ordering::Relaxed),
            write_timeouts: self.write_timeouts.load(Ordering::Relaxed),
            listener_panics: self.listener_panics.load(Ordering::Relaxed),
            worker_panics: self.worker_panics.load(Ordering::Relaxed),
            connections_shed: self.connections_shed.load(Ordering::Relaxed),
        }
    }
}

/// A running sidecar: the listener thread and its address.
#[derive(Debug)]
pub struct Running {
    addr: SocketAddr,
    base_path: String,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    metrics: Arc<Metrics>,
    fatal: Arc<AtomicBool>,
}

impl Running {
    /// The bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The normalized base path served by this instance.
    pub fn base_path(&self) -> &str {
        &self.base_path
    }

    /// Absolute URL of a served resource (`name` is a C16.1 file name or [`ECHO_HEADERS_SEGMENT`]).
    pub fn url_for(&self, name: &str) -> String {
        format!("http://{}{}{}", self.addr, self.base_path, name)
    }

    /// The counters, for tests and embedding.
    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Ask the listener thread to stop and wait for it.
    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    /// Block until the listener thread returns (it does when [`Running::stop`] is called or the process is terminated).
    ///
    /// Returns an error when the listener thread died (a panic): the caller exits non-zero so a supervisor restarts the
    /// sidecar instead of running on with no listener (K-4, R-09).
    pub fn wait(mut self) -> Result<(), CanaryError> {
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        match handle.join() {
            Ok(()) if self.fatal.load(Ordering::SeqCst) => {
                let snapshot = self.metrics();
                Err(CanaryError::Start(format!(
                    "all connection workers are gone; the sidecar is no longer serving (worker panics: {}, listener panics: {})",
                    snapshot.worker_panics, snapshot.listener_panics
                )))
            }
            Ok(()) => Ok(()),
            Err(_) => {
                let panics = self.metrics().listener_panics;
                Err(CanaryError::Start(format!(
                    "the listener thread panicked; the sidecar is no longer serving (listener panics: {panics})"
                )))
            }
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Load the five files (checking the configured manifest) and start serving them in a background thread.
pub fn start(config: Config) -> Result<Running, CanaryError> {
    let base_path = normalise_base_path(&config.base_path)?;
    ensure_real_directory(&config.root)?;
    let mut files: Vec<ServedFile> = Vec::with_capacity(FILES.len());
    for file in &FILES {
        let path = config.root.join(file.name);
        // C-8: never follow a symlink out of the canary root, and serve only a regular file.
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|e| CanaryError::Io(format!("cannot read {}: {e}", path.display())))?;
        ensure_regular(node_kind(&metadata), &path)?;
        if metadata.len() > MAX_FILE_BYTES as u64 {
            return Err(CanaryError::FileTooLarge {
                name: file.name.to_owned(),
                size: metadata.len(),
            });
        }
        // the hard size limit is applied while reading, not only from metadata
        let opened = File::open(&path)
            .map_err(|e| CanaryError::Io(format!("cannot read {}: {e}", path.display())))?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        opened
            .take(MAX_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| CanaryError::Io(format!("cannot read {}: {e}", path.display())))?;
        if bytes.len() > MAX_FILE_BYTES {
            return Err(CanaryError::FileTooLarge {
                name: file.name.to_owned(),
                size: bytes.len() as u64,
            });
        }
        files.push(ServedFile {
            name: file.name,
            media_type: file.media_type,
            bytes,
        });
    }
    if let Some(manifest_path) = &config.manifest {
        let text = std::fs::read_to_string(manifest_path).map_err(|e| {
            CanaryError::Manifest(format!("cannot read {}: {e}", manifest_path.display()))
        })?;
        let manifest = parse_manifest(&text)?;
        if manifest.base_path != base_path {
            return Err(CanaryError::Manifest(format!(
                "the manifest was generated for {}, not {base_path}",
                manifest.base_path
            )));
        }
        for served in &files {
            let expected = manifest.sha256_of(served.name).ok_or_else(|| {
                CanaryError::Manifest(format!("no manifest entry for {}", served.name))
            })?;
            let actual = sha256_hex(&served.bytes);
            if actual != expected {
                return Err(CanaryError::Manifest(format!(
                    "{} does not match the manifest (manifest {expected}, file {actual})",
                    served.name
                )));
            }
        }
    }
    let listener = TcpListener::bind(config.bind)
        .map_err(|e| CanaryError::Start(format!("cannot bind {}: {e}", config.bind)))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| CanaryError::Start(format!("cannot configure the listener: {e}")))?;
    let addr = listener
        .local_addr()
        .map_err(|e| CanaryError::Start(format!("cannot read the local address: {e}")))?;
    let metrics = Arc::new(Metrics::default());
    let state = Arc::new(State {
        base_path: base_path.clone(),
        files,
        read_timeout: config.read_timeout,
        metrics: Arc::clone(&metrics),
        inject_connection_panic: AtomicBool::new(config.panic_connection),
    });
    let inject_panic = injected_listener_panic(&config);
    let injection = injected_worker_settings(&config);
    let shutdown = Arc::new(AtomicBool::new(false));
    let fatal = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = std::sync::mpsc::sync_channel::<Queued>(ACCEPT_QUEUE);
    let receiver = Arc::new(std::sync::Mutex::new(receiver));
    let alive = Arc::new(AtomicUsize::new(WORKER_THREADS));
    let mut workers = Vec::with_capacity(WORKER_THREADS);
    for index in 0..WORKER_THREADS {
        let receiver = Arc::clone(&receiver);
        let state = Arc::clone(&state);
        let alive = Arc::clone(&alive);
        let kill = injection.kill_workers;
        let builder = std::thread::Builder::new().name(format!("hdd-canary-worker-{index}"));
        // P-1: a worker that cannot be spawned must fail start(), not silently shrink the pool.
        let spawned = if injection.fail_spawn {
            Err(io::Error::other(
                "injected worker spawn failure (P-1 test path)",
            ))
        } else {
            builder.spawn(move || {
                if kill {
                    alive.fetch_sub(1, Ordering::SeqCst);
                    return;
                }
                loop {
                    let next = match receiver.lock() {
                        Ok(guard) => guard.recv(),
                        Err(poisoned) => poisoned.into_inner().recv(),
                    };
                    let Ok(queued) = next else { break };
                    // P-1: one connection's panic is caught and counted; the worker and the other connections live on.
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        maybe_inject_connection_panic(&state);
                        handle_connection(queued, &state);
                    }));
                    if outcome.is_err() {
                        Metrics::bump(&state.metrics.worker_panics, 1);
                    }
                }
                alive.fetch_sub(1, Ordering::SeqCst);
            })
        };
        match spawned {
            Ok(handle) => workers.push(handle),
            Err(error) => {
                drop(sender);
                for worker in workers {
                    let _ = worker.join();
                }
                return Err(CanaryError::Start(format!(
                    "cannot start a connection worker: {error}"
                )));
            }
        }
    }
    let shutdown_thread = Arc::clone(&shutdown);
    let fatal_thread = Arc::clone(&fatal);
    let metrics_for_thread = Arc::clone(&metrics);
    let handle = std::thread::Builder::new()
        .name("hdd-canary".into())
        .spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                maybe_inject_listener_panic(inject_panic);
                serve_loop(
                    listener,
                    &state,
                    &shutdown_thread,
                    &fatal_thread,
                    sender,
                    workers,
                    alive,
                );
            }));
            if let Err(payload) = outcome {
                // R-09: count the panic, then let it propagate so `wait()` reports it and the process exits non-zero.
                Metrics::bump(&metrics_for_thread.listener_panics, 1);
                std::panic::resume_unwind(payload);
            }
        })
        .map_err(|e| CanaryError::Start(format!("cannot start the listener thread: {e}")))?;
    Ok(Running {
        addr,
        base_path,
        shutdown,
        handle: Some(handle),
        metrics,
        fatal,
    })
}

/// One file loaded into memory at startup.
struct ServedFile {
    name: &'static str,
    media_type: &'static str,
    bytes: Vec<u8>,
}

/// Everything the listener thread needs. It never touches the filesystem: the five files are already in memory.
struct State {
    base_path: String,
    files: Vec<ServedFile>,
    read_timeout: Duration,
    metrics: Arc<Metrics>,
    /// Test hook (default false): panic once inside a connection worker to exercise the catch_unwind path (P-1).
    inject_connection_panic: AtomicBool,
}

/// Kind of a node in the canary directory, for the regular-file decision (K-7). A symbolic link is never followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeKind {
    /// A regular file: the only kind the sidecar serves or hashes.
    Regular,
    /// A symbolic link.
    Symlink,
    /// A directory, device, socket or anything else.
    Other,
}

/// Refuse a canary root/directory that is itself a symbolic link (or a Windows reparse point such as a junction), and
/// require it to be a directory (Q-7). The directory is expected to be root-controlled, so the small check-then-use
/// window between `symlink_metadata` and opening a child file is accepted: an attacker who can replace the directory is
/// already the root/owner of the origin host.
fn ensure_real_directory(path: &Path) -> Result<(), CanaryError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| CanaryError::Io(format!("cannot read {}: {e}", path.display())))?;
    if metadata.file_type().is_symlink() {
        return Err(CanaryError::Io(format!(
            "{} is a symbolic link; point the canary at the real directory",
            path.display()
        )));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(CanaryError::Io(format!(
                "{} is a reparse point (symbolic link or junction); point the canary at the real directory",
                path.display()
            )));
        }
    }
    if !metadata.is_dir() {
        return Err(CanaryError::Io(format!(
            "{} is not a directory",
            path.display()
        )));
    }
    Ok(())
}

/// Classify an already-`symlink_metadata`d node.
fn node_kind(metadata: &std::fs::Metadata) -> NodeKind {
    let kind = metadata.file_type();
    if kind.is_symlink() {
        NodeKind::Symlink
    } else if kind.is_file() {
        NodeKind::Regular
    } else {
        NodeKind::Other
    }
}

/// Refuse anything but a regular file (K-7). The decision takes the kind as an argument so it can be unit-tested on a
/// host that cannot create the node kind (the unix-only symlink test becomes a fake-kind logic test on Windows).
fn ensure_regular(kind: NodeKind, path: &Path) -> Result<(), CanaryError> {
    match kind {
        NodeKind::Regular => Ok(()),
        NodeKind::Symlink => Err(CanaryError::Io(format!(
            "{} is a symbolic link; only regular files are served",
            path.display()
        ))),
        NodeKind::Other => Err(CanaryError::Io(format!(
            "{} is not a regular file; only regular files are served",
            path.display()
        ))),
    }
}

/// The one opaque body of every rejected request.
const REJECT_BODY: &[u8] = b"not found\n";

/// The uniform rejection response. `include_body` is false for a rejected HEAD: the headers still carry the body's
/// `Content-Length` (metadata only), as HTTP requires, but no body is written.
fn reject_response(include_body: bool) -> Vec<u8> {
    response(
        "HTTP/1.1 404 Not Found\r\n",
        "text/plain; charset=utf-8",
        REJECT_BODY,
        include_body,
    )
}

/// The one opaque body of every shed response (P-2).
const SHED_BODY: &[u8] = b"unavailable\n";

/// The fixed opaque 503 for a shed connection: no input is read or reflected (P-2).
fn shed_response() -> Vec<u8> {
    response_with(
        "HTTP/1.1 503 Service Unavailable\r\n",
        "text/plain; charset=utf-8",
        SHED_BODY,
        true,
        &["Retry-After: 1\r\n"],
    )
}

/// Build a response with the fixed security headers every response carries.
fn response(status_line: &str, content_type: &str, body: &[u8], include_body: bool) -> Vec<u8> {
    response_with(status_line, content_type, body, include_body, &[])
}

/// Build a response with the fixed security headers plus caller-supplied extra header lines.
fn response_with(
    status_line: &str,
    content_type: &str,
    body: &[u8],
    include_body: bool,
    extra: &[&str],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(384 + body.len());
    out.extend_from_slice(status_line.as_bytes());
    for line in [
        "Server: hdd-canary\r\n",
        "X-Content-Type-Options: nosniff\r\n",
        "Cache-Control: no-store\r\n",
        "Referrer-Policy: no-referrer\r\n",
        "X-Frame-Options: DENY\r\n",
        "Content-Security-Policy: default-src 'none'; style-src 'self'; script-src 'self'\r\n",
        "Connection: close\r\n",
    ] {
        out.extend_from_slice(line.as_bytes());
    }
    for line in extra {
        out.extend_from_slice(line.as_bytes());
    }
    out.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    if include_body {
        out.extend_from_slice(body);
    }
    out
}

/// Number of connection workers: a fixed, small pool (P-1..P-5). Each worker handles one connection at a time and a
/// connection never outlives `accepted_at + read_timeout`, so one idle client cannot hold the service beyond the deadline.
pub const WORKER_THREADS: usize = 4;
/// Bounded accept queue. A burst of 32 quick probes fits (4 workers + 64 queued); anything beyond it is shed with the
/// fixed opaque 503 (P-2) and counted in `connections_shed`.
pub const ACCEPT_QUEUE: usize = 64;
/// After the response (served or rejected) the remaining client bytes are drained for at most this long, so a client that
/// does not close cannot hold a worker for the whole connection deadline (P-4).
pub const DRAIN_CAP: Duration = Duration::from_millis(200);

/// One accepted connection waiting for a worker, stamped with its accept time (P-3).
struct Queued {
    stream: TcpStream,
    accepted_at: Instant,
}

/// Test-only worker failure injection switches (P-1); production sees a constant "off".
struct WorkerInjection {
    kill_workers: bool,
    fail_spawn: bool,
}

/// Test-only worker failure injection switches (P-1); production sees a constant "off".
fn injected_worker_settings(config: &Config) -> WorkerInjection {
    WorkerInjection {
        kill_workers: config.kill_workers,
        fail_spawn: config.fail_worker_spawn,
    }
}

/// Test-only per-connection panic injection (P-1): a test hook, off by default and never set in production.
#[allow(clippy::panic, reason = "test-only failure injection, off by default")]
fn maybe_inject_connection_panic(state: &State) {
    if state.inject_connection_panic.swap(false, Ordering::SeqCst) {
        panic!("injected connection panic (P-1 test path)");
    }
}

/// Test-only failure injection for the real `start()` panic path (Q-6); production is a no-op.
#[cfg(test)]
#[allow(clippy::panic, reason = "test-only failure injection")]
fn maybe_inject_listener_panic(inject: bool) {
    if inject {
        panic!("injected listener panic (Q-6 test path)");
    }
}

/// Production no-op (the injection only exists in test builds).
#[cfg(not(test))]
fn maybe_inject_listener_panic(_inject: bool) {}

/// Test-only failure injection for the real `start()` panic path (Q-6); production always returns false.
fn injected_listener_panic(_config: &Config) -> bool {
    #[cfg(test)]
    {
        _config.panic_listener
    }
    #[cfg(not(test))]
    {
        false
    }
}

/// The listener loop: accept, stamp the accept time, hand the connection to the bounded worker queue, and shed with the
/// fixed opaque 503 when the queue is full (P-1..P-5). It owns the listener, so on stop the listener is closed before the
/// queued connections are dropped and the workers joined (P-5). If every worker is gone it marks the run fatal (exit 2).
fn serve_loop(
    listener: TcpListener,
    state: &Arc<State>,
    shutdown: &Arc<AtomicBool>,
    fatal: &Arc<AtomicBool>,
    sender: std::sync::mpsc::SyncSender<Queued>,
    workers: Vec<std::thread::JoinHandle<()>>,
    alive: Arc<AtomicUsize>,
) {
    while !shutdown.load(Ordering::SeqCst) {
        if alive.load(Ordering::SeqCst) == 0 {
            // P-1: no worker can serve anything, so the process must die instead of pretending to run.
            fatal.store(true, Ordering::SeqCst);
            break;
        }
        match listener.accept() {
            Ok((stream, _peer)) => {
                let queued = Queued {
                    stream,
                    accepted_at: Instant::now(),
                };
                match sender.try_send(queued) {
                    Ok(()) => {}
                    Err(std::sync::mpsc::TrySendError::Full(shed)) => {
                        shed_connection(shed.stream, &state.metrics);
                    }
                    Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                        fatal.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                Metrics::bump(&state.metrics.accept_errors, 1);
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    // P-5: close the listener first; the queued connections are dropped when the sender goes away.
    drop(listener);
    drop(sender);
    for worker in workers {
        let _ = worker.join();
    }
}

/// Answer a shed connection with the fixed opaque 503 (P-2): no request bytes are read or reflected, so the response can
/// never echo the client's input. It is counted in its own `connections_shed` counter.
fn shed_connection(mut stream: TcpStream, metrics: &Metrics) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
    let _ = stream.write_all(&shed_response());
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Write);
    Metrics::bump(&metrics.connections_shed, 1);
}
/// Time left until the absolute per-connection deadline, or `None` when it has passed (C-1).
fn remaining_until(deadline: Instant) -> Option<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() { None } else { Some(left) }
}

/// Read one request head, bounded by [`MAX_REQUEST_HEAD_BYTES`] and by the absolute connection `deadline`.
///
/// The remaining time is recomputed and applied as the read timeout before **every** read, so a client that drips one
/// byte per read timeout cannot hold the sidecar: the deadline is absolute, not per read (C-1).
fn read_head(
    stream: &mut TcpStream,
    metrics: &Metrics,
    deadline: Instant,
) -> Result<Vec<u8>, RequestError> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let Some(left) = remaining_until(deadline) else {
            Metrics::bump(&metrics.read_timeouts, 1);
            return Err(RequestError::Incomplete);
        };
        let _ = stream.set_read_timeout(Some(left));
        match stream.read(&mut chunk) {
            Ok(0) => return Err(RequestError::Incomplete),
            Ok(read) => {
                if let Some(part) = chunk.get(..read) {
                    buffer.extend_from_slice(part);
                }
                if let Some(end) = find_head_end(&buffer) {
                    buffer.truncate(end);
                    return Ok(buffer);
                }
                if buffer.len() > MAX_REQUEST_HEAD_BYTES {
                    return Err(RequestError::TooLong("request head"));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) {
                    Metrics::bump(&metrics.read_timeouts, 1);
                }
                return Err(RequestError::Incomplete);
            }
        }
    }
}

/// Answer one connection, then close it.
///
/// The connection has one absolute deadline covering the request head and the discard of a rejected request's remainder
/// (C-1). The accepted stream is set back to **blocking** explicitly (C-8): on Windows it inherits the listener's
/// non-blocking mode, which made a request arriving just after `accept()` read as `WouldBlock` and answered with the
/// opaque 404 (the F-B2-0 flake).
fn handle_connection(queued: Queued, state: &Arc<State>) {
    let Queued {
        mut stream,
        accepted_at,
    } = queued;
    // P-3: the absolute deadline starts at accept, not at dequeue. A connection that is already past it is closed without
    // any work (it is not the request's fault, but serving a request whose deadline is gone would be worse).
    let deadline = accepted_at + state.read_timeout;
    if Instant::now() >= deadline {
        Metrics::bump(&state.metrics.read_timeouts, 1);
        return;
    }
    let _ = stream.set_nonblocking(false);
    let (response, served, echo) = match read_head(&mut stream, &state.metrics, deadline) {
        Ok(head) => match parse_request(&head) {
            Ok(request) => {
                // a rejected HEAD gets the headers but no body
                let head_request = request.method == Method::Head;
                match route(&state.base_path, &request.path) {
                    Route::File(file) => match state.files.iter().find(|s| s.name == file.name) {
                        Some(served_file) => (
                            response(
                                "HTTP/1.1 200 OK\r\n",
                                served_file.media_type,
                                &served_file.bytes,
                                request.method == Method::Get,
                            ),
                            true,
                            false,
                        ),
                        None => (reject_response(!head_request), false, false),
                    },
                    Route::EchoHeaders if request.method == Method::Get => {
                        let body = echo_headers_json(&request.headers);
                        (
                            response(
                                "HTTP/1.1 200 OK\r\n",
                                "application/json; charset=utf-8",
                                &body,
                                true,
                            ),
                            true,
                            true,
                        )
                    }
                    Route::EchoHeaders | Route::Reject => {
                        (reject_response(!head_request), false, false)
                    }
                }
            }
            Err(_) => (reject_response(true), false, false),
        },
        Err(_) => (reject_response(true), false, false),
    };
    let mut set_write_timeout = |stream: &mut TcpStream, left: Duration| {
        let _ = stream.set_write_timeout(Some(left));
    };
    if write_with_deadline(&mut stream, &response, deadline, &mut set_write_timeout) {
        if served {
            Metrics::bump(&state.metrics.served, 1);
            Metrics::bump(
                &state.metrics.bytes_out,
                u64::try_from(response.len()).unwrap_or(u64::MAX),
            );
            if echo {
                Metrics::bump(&state.metrics.echo_requests, 1);
            }
        } else {
            Metrics::bump(&state.metrics.rejected, 1);
            Metrics::bump(
                &state.metrics.bytes_out,
                u64::try_from(response.len()).unwrap_or(u64::MAX),
            );
        }
        // Q-4: the same shutdown + bounded drain on BOTH paths. Closing with unread bytes in the receive buffer can reset
        // the connection and lose the body the client was reading; shutdown(Write) tells it that no more data follows.
        let _ = stream.shutdown(std::net::Shutdown::Write);
        drain(&mut stream, deadline);
    } else {
        Metrics::bump(&state.metrics.write_timeouts, 1);
    }
}

/// Write a complete response bounded by the absolute connection deadline (K-3).
///
/// `on_remaining` is called with the time left before every write attempt, so the caller can apply it as the socket write
/// timeout (recomputed before **every** write: a slow reader making a little progress must not reset the deadline).
fn write_with_deadline<W: Write>(
    writer: &mut W,
    bytes: &[u8],
    deadline: Instant,
    on_remaining: &mut dyn FnMut(&mut W, Duration),
) -> bool {
    let mut written = 0usize;
    while written < bytes.len() {
        let Some(left) = remaining_until(deadline) else {
            return false;
        };
        on_remaining(writer, left);
        match writer.write(bytes.get(written..).unwrap_or(&[])) {
            Ok(0) => return false,
            Ok(count) => written += count,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    writer.flush().is_ok()
}

/// Discard at most [`MAX_DRAIN_BYTES`] of already-sent client bytes so the close does not reset the connection before the
/// client reads the response (P-4). The bytes are never parsed; the discard stops at the connection deadline or after
/// [`DRAIN_CAP`], whichever comes first, and a drain that hits the cap is NOT counted as a read timeout: the response was
/// served, so the read-timeout counter must only describe requests that never got an answer.
fn drain(stream: &mut TcpStream, deadline: Instant) {
    let cap = Instant::now() + DRAIN_CAP;
    let drain_deadline = if cap < deadline { cap } else { deadline };
    let mut discarded = 0usize;
    let mut chunk = [0u8; 1024];
    while discarded < MAX_DRAIN_BYTES {
        let Some(left) = remaining_until(drain_deadline) else {
            break;
        };
        let _ = stream.set_read_timeout(Some(left));
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => discarded += read,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        reason = "unit tests"
    )]

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("hdd-canary-lib-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn t0210_sha256_is_real_sha256() {
        // standard SHA-256 test vectors; the manifest is an evidence artifact, so a wrong hash is a FAIL (A1)
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha256_hex(b"abc").len(), SHA256_HEX_LEN);
    }

    #[test]
    fn t0210_generate_writes_the_five_contract_files_and_real_hashes() {
        let dir = temp_dir("generate");
        let m = generate(&dir, "/__hdd_canary/").expect("generate");
        assert_eq!(m.base_path, "/__hdd_canary/");
        assert_eq!(m.entries.len(), FILES.len());
        for f in &FILES {
            let on_disk = std::fs::read(dir.join(f.name)).expect("file written");
            assert_eq!(on_disk, f.content, "{} bytes", f.name);
            assert_eq!(
                m.sha256_of(f.name),
                Some(sha256_hex(&on_disk).as_str()),
                "the manifest records the real hash of {}",
                f.name
            );
        }
        // the contract values of C16.1
        assert_eq!(std::fs::read(dir.join("ok.txt")).unwrap(), b"hdd-canary-ok");
        let leak = String::from_utf8(std::fs::read(dir.join("leak.txt")).unwrap()).unwrap();
        assert_eq!(
            leak,
            "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
        );
        let html = String::from_utf8(std::fs::read(dir.join("search.html")).unwrap()).unwrap();
        assert!(
            !html.contains("location.search"),
            "search.html reads no query"
        );
        assert!(
            !html.contains("innerHTML"),
            "search.html echo code is absent"
        );
        let manifest = std::fs::read_to_string(dir.join(MANIFEST_NAME)).expect("manifest written");
        assert!(manifest.contains("/__hdd_canary/"));
        // the manifest is not one of the served files
        assert!(FILES.iter().all(|f| f.name != MANIFEST_NAME));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn t0210_generate_is_idempotent() {
        let dir = temp_dir("generate-twice");
        let a = generate(&dir, "/c/").expect("first");
        let first = std::fs::read_to_string(dir.join(MANIFEST_NAME)).expect("manifest");
        let b = generate(&dir, "/c/").expect("second");
        let second = std::fs::read_to_string(dir.join(MANIFEST_NAME)).expect("manifest");
        assert_eq!(a, b);
        assert_eq!(first, second);
        assert!(check_manifest(&dir).expect("check").ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn t0210_check_manifest_detects_a_changed_file_and_names_it() {
        let dir = temp_dir("tamper");
        generate(&dir, "/c/").expect("generate");
        let report = check_manifest(&dir).expect("check clean");
        assert!(report.ok(), "{report:?}");
        std::fs::write(dir.join("static.js"), b"tampered").expect("tamper");
        let report = check_manifest(&dir).expect("check tampered");
        assert!(!report.ok());
        let bad = report
            .checks
            .iter()
            .find(|c| c.name == "static.js")
            .expect("static.js checked");
        assert!(!bad.matches());
        assert_ne!(bad.expected, bad.actual);
        // every other file still matches: the report is per file, not one bit
        assert_eq!(
            report.checks.iter().filter(|c| c.matches()).count(),
            FILES.len() - 1
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn t0210_check_manifest_detects_missing_file_and_missing_or_extra_entries() {
        let dir = temp_dir("missing");
        generate(&dir, "/c/").expect("generate");
        std::fs::remove_file(dir.join("static.css")).expect("remove");
        let report = check_manifest(&dir).expect("check");
        assert!(!report.ok());
        let missing = report
            .checks
            .iter()
            .find(|c| c.name == "static.css")
            .expect("checked");
        assert_eq!(
            missing.actual, None,
            "a missing file reports no actual hash"
        );

        let dir2 = temp_dir("extra-entry");
        generate(&dir2, "/c/").expect("generate");
        let text = std::fs::read_to_string(dir2.join(MANIFEST_NAME)).expect("manifest");
        let extra = format!(
            "{text}{}  not-a-canary-file\n",
            sha256_hex(b"x").to_uppercase().to_lowercase()
        );
        std::fs::write(dir2.join(MANIFEST_NAME), extra).expect("write");
        let report = check_manifest(&dir2).expect("check");
        assert!(
            !report.ok(),
            "a manifest entry outside the contract is not ok"
        );
        assert!(report.checks.iter().any(|c| c.name == "not-a-canary-file"));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn t0210_manifest_text_round_trips_and_rejects_bad_input() {
        let entries: Vec<ManifestEntry> = FILES
            .iter()
            .map(|f| ManifestEntry {
                name: f.name.to_owned(),
                sha256: sha256_hex(f.content),
            })
            .collect();
        let text = manifest_text("/c/", &entries);
        let parsed = parse_manifest(&text).expect("round trip");
        assert_eq!(parsed.base_path, "/c/");
        assert_eq!(parsed.entries, entries);
        for bad in [
            "",
            "no header\n",
            "# base_path: /c/\nabc  ok.txt\n",
            "# base_path: /c/\nabc\n",
            &format!("# base_path: /c/\n{}  ok.txt\n", "A".repeat(64)),
            &format!("# base_path: /c/\n{}  ok.txt\n", "0".repeat(63)),
        ] {
            assert!(parse_manifest(bad).is_err(), "must reject {bad:?}");
        }
        let not_contract = format!(
            "# base_path: /c/\n{}  ok.txt\n{}  extra.txt\n",
            sha256_hex(b"a"),
            sha256_hex(b"b")
        );
        assert!(
            parse_manifest(&not_contract).is_err(),
            "a manifest for a file outside the C16.1 contract is rejected"
        );
    }

    #[test]
    fn t0210_base_path_normalisation_table() {
        for (raw, want) in [
            ("/__hdd_canary/", "/__hdd_canary/"),
            ("/__hdd_canary", "/__hdd_canary/"),
            ("/x", "/x/"),
            ("/a/b/", "/a/b/"),
        ] {
            assert_eq!(normalise_base_path(raw).as_deref(), Ok(want), "{raw}");
        }
        for bad in [
            "", "x", "/a/../b/", "/a/%2e/", "/a b/", "/a\\b/", "/a?b/", "/a#b/", "/a//b/",
        ] {
            assert!(normalise_base_path(bad).is_err(), "must reject {bad:?}");
        }
        let long = format!("/{}/", "a".repeat(MAX_BASE_PATH_LEN));
        assert!(normalise_base_path(&long).is_err());
    }

    #[test]
    fn t0210_route_serves_only_the_exact_contract_paths() {
        let base = "/__hdd_canary/";
        for f in &FILES {
            assert_eq!(
                route(base, &format!("{base}{}", f.name)),
                Route::File(f),
                "{}",
                f.name
            );
        }
        assert_eq!(
            route(base, &format!("{base}{ECHO_HEADERS_SEGMENT}")),
            Route::EchoHeaders
        );
        for bad in [
            "/".to_owned(),
            base.to_owned(),
            base.to_owned(),
            format!("{base}manifest.sha256"),
            format!("{base}ok.txt/"),
            format!("{base}OK.TXT"),
            format!("{base}ok.txtx"),
            format!("{base}../etc/passwd"),
            format!("{base}%2e%2e/ok.txt"),
            format!("{base}ok%2etxt"),
            "/other/ok.txt".to_owned(),
            format!("{base}echo-headers/"),
        ] {
            assert_eq!(route(base, &bad), Route::Reject, "{bad}");
        }
        // the query string is stripped by parse_request before routing, not by route()
        assert_eq!(
            route(base, &format!("{base}ok.txt?x=1")),
            Route::Reject,
            "route() receives the path without a query"
        );
    }

    #[test]
    fn t0210_parse_request_accepts_the_documented_shapes() {
        let req = parse_request(
            b"GET /__hdd_canary/ok.txt HTTP/1.1\r\nHost: test.example.com\r\nX-HDD-Probe: yes\r\n\r\n",
        )
        .expect("parsed");
        assert_eq!(req.method, Method::Get);
        assert_eq!(req.path, "/__hdd_canary/ok.txt");
        assert_eq!(req.query, None);
        assert_eq!(req.header("host"), Some("test.example.com"));
        assert_eq!(req.header("X-HDD-PROBE"), Some("yes"));

        let head = parse_request(b"HEAD /x?a=1&b=%2e HTTP/1.0\r\n\r\n").expect("parsed");
        assert_eq!(head.method, Method::Head);
        assert_eq!(head.path, "/x");
        assert_eq!(head.query.as_deref(), Some("a=1&b=%2e"));
        assert!(head.headers.is_empty());
    }

    #[test]
    fn t0210_parse_request_enforces_the_request_line_limit() {
        let line = format!("/{}", "a".repeat(MAX_REQUEST_LINE - 14));
        let ok = format!("GET {} HTTP/1.1\r\n\r\n", line);
        assert_eq!(
            parse_request(ok.as_bytes())
                .expect("exactly at the limit")
                .path
                .len(),
            line.len()
        );
        let over = format!("GET {}x HTTP/1.1\r\n\r\n", line);
        assert_eq!(
            parse_request(over.as_bytes()).err(),
            Some(RequestError::TooLong("request line"))
        );
    }

    #[test]
    fn t0210_parse_request_enforces_the_header_size_and_count_limits() {
        let value = "v".repeat(MAX_HEADER_BYTES - "x-a: \r\n".len());
        let ok = format!("GET /x HTTP/1.1\r\nx-a: {value}\r\n\r\n");
        assert!(parse_request(ok.as_bytes()).is_ok(), "exactly 8 KB");
        let over = format!("GET /x HTTP/1.1\r\nx-a: {value}x\r\n\r\n");
        assert_eq!(
            parse_request(over.as_bytes()).err(),
            Some(RequestError::TooLong("headers"))
        );
        let mut many = String::from("GET /x HTTP/1.1\r\n");
        for i in 0..=MAX_HEADERS {
            many.push_str(&format!("x-{i}: 1\r\n"));
        }
        many.push_str("\r\n");
        assert_eq!(
            parse_request(many.as_bytes()).err(),
            Some(RequestError::TooLong("header count"))
        );
    }

    #[test]
    fn t0210_parse_request_rejects_methods_bodies_and_malformed_heads() {
        assert!(
            parse_request(b"GET /x HTTP/1.1\r\n\r\n").is_ok(),
            "a plain GET is valid"
        );
        for (raw, want) in [
            (
                b"POST /x HTTP/1.1\r\n\r\n".as_slice(),
                RequestError::Malformed("method"),
            ),
            (
                b"PUT /x HTTP/1.1\r\n\r\n".as_slice(),
                RequestError::Malformed("method"),
            ),
            (
                b"get /x HTTP/1.1\r\n\r\n".as_slice(),
                RequestError::Malformed("method"),
            ),
            (
                b"GET /x HTTP/1.1\r\nContent-Length: 1\r\n\r\n".as_slice(),
                RequestError::Malformed("request body"),
            ),
            (
                b"GET /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
                RequestError::Malformed("request body"),
            ),
            (
                b"GET x HTTP/1.1\r\n\r\n".as_slice(),
                RequestError::Malformed("target"),
            ),
            (
                b"GET http://evil/x HTTP/1.1\r\n\r\n".as_slice(),
                RequestError::Malformed("target"),
            ),
            (
                b"GET /x HTTP/9.9\r\n\r\n".as_slice(),
                RequestError::Malformed("version"),
            ),
            (
                b"GET /x HTTP/1.1\r\nBad Header: 1\r\n\r\n".as_slice(),
                RequestError::Malformed("header name"),
            ),
            (
                b"GET /x HTTP/1.1\r\nx-a: v\x01\r\n\r\n".as_slice(),
                RequestError::Malformed("header value"),
            ),
            (
                b"GET /x HTTP/1.1\r\n x-fold: 1\r\n\r\n".as_slice(),
                RequestError::Malformed("header folding"),
            ),
        ] {
            assert_eq!(
                parse_request(raw).err(),
                Some(want),
                "{}",
                String::from_utf8_lossy(raw)
            );
        }
        assert!(
            parse_request(b"GET /x HTTP/1.1\r\n\r\npartial").is_ok(),
            "extra bytes after the head are ignored (the connection closes after one response)"
        );
        assert_eq!(
            parse_request(b"GET /x HTTP/1.1\r\n").err(),
            Some(RequestError::Incomplete)
        );
        assert_eq!(parse_request(b"").err(), Some(RequestError::Incomplete));
    }

    #[test]
    fn t0210_echo_headers_json_is_bounded_and_redacts_credentials() {
        let headers = vec![
            Header {
                name: "x-forwarded-for".into(),
                value: "198.51.100.7".into(),
            },
            Header {
                name: "cookie".into(),
                value: "session=secret".into(),
            },
            Header {
                name: "authorization".into(),
                value: "Bearer secret".into(),
            },
            Header {
                name: "x-quote".into(),
                value: "a\"b\\c".into(),
            },
        ];
        let body = String::from_utf8(echo_headers_json(&headers)).expect("utf-8 JSON");
        assert!(body.starts_with(r#"{"headers":["#), "{body}");
        assert!(body.ends_with(r#"],"truncated":false}"#), "{body}");
        assert!(body.contains(r#"{"name":"x-forwarded-for","value":"198.51.100.7"}"#));
        assert!(!body.contains("session=secret"), "{body}");
        assert!(!body.contains("Bearer secret"), "{body}");
        assert!(
            body.contains(r#"{"name":"[not-echoed-name]","value":"3"}"#),
            "unknown headers are a count only (P-9): {body}"
        );
        for name in ["cookie", "authorization", "x-quote"] {
            assert!(
                !body.contains(name),
                "P-9: the name {name} must not be echoed: {body}"
            );
        }
        // no other fields: only names and values
        assert!(!body.contains("\"path\""), "{body}");

        // the size cap: many headers whose escaped values exceed MAX_ECHO_JSON_BYTES are truncated, never unbounded
        // Q-3: the cap is exercised with an allowlisted name whose value still has to be JSON-escaped.
        let many: Vec<Header> = (0..MAX_HEADERS)
            .map(|_| Header {
                name: "x-forwarded-for".to_owned(),
                value: "\"".repeat(70),
            })
            .collect();
        let body = echo_headers_json(&many);
        assert!(body.len() <= MAX_ECHO_JSON_BYTES, "{} bytes", body.len());
        let text = String::from_utf8(body).expect("utf-8 JSON");
        assert!(text.contains("\"truncated\":true"), "{text}");
        assert!(
            text.ends_with("\"truncated\":true}"),
            "still valid JSON: {text}"
        );
    }

    /// Assert the documented limits and token shapes of one accepted head (C-2).
    fn check_parsed(req: &Request, round: u32) {
        assert!(
            req.path.len() <= MAX_REQUEST_LINE,
            "round {round}: path longer than the request-line limit"
        );
        assert!(
            req.headers.len() <= MAX_HEADERS,
            "round {round}: more headers than the limit"
        );
        for header in &req.headers {
            assert!(
                header.name.bytes().all(is_token_byte),
                "round {round}: non-token header name {:?}",
                header.name
            );
            assert!(
                header
                    .value
                    .bytes()
                    .all(|b| matches!(b, b'\t' | 0x20..=0x7e)),
                "round {round}: header value outside the parsed ASCII set"
            );
        }
    }

    #[test]
    fn t0210_parser_never_panics_on_arbitrary_bytes_and_keeps_limits() {
        // C-2: a bounded, deterministic fuzz-style sweep that actually reaches the parser logic. It generates structured
        // heads (valid and invalid methods, versions, targets, header names/values, duplicates, folded lines, huge
        // values), mutates a valid head byte by byte, and also feeds raw noise. It counts the Ok and Err outcomes and
        // asserts that both occur in meaningful numbers, then asserts the documented limits for every Ok result.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let methods = ["GET", "HEAD", "POST", "get", "PROPFIND", "G", ""];
        let targets = [
            "/",
            "/__hdd_canary/ok.txt",
            "/a/b?q=1",
            "http://evil/x",
            "x",
            "/%2e%2e/x",
            "",
        ];
        let versions = ["HTTP/1.1", "HTTP/1.0", "HTTP/9.9", "http/1.1", ""];
        let names = [
            "host",
            "x-hdd",
            "Bad Header",
            "x:",
            "",
            "content-length",
            "transfer-encoding",
        ];
        let values = [
            "x",
            "198.51.100.7",
            "a\"b",
            "v v",
            "",
            "q=\"x\"",
            "!\"#$%&'()*+,-./",
        ];
        let mut ok_count = 0usize;
        let mut err_count = 0usize;

        // 1) structured heads: half are well-formed (so the accepted path is reached often), half mix invalid parts
        let safe_names = ["host", "x-hdd", "accept", "user-agent"];
        let safe_values = ["hddtest.example.com", "yes", "text/plain", "hdd-canary/1"];
        for round in 0..2_000u32 {
            let well_formed = next() % 2 == 0;
            let (method, target, version) = if well_formed {
                (
                    if next() % 2 == 0 { "GET" } else { "HEAD" },
                    if next() % 2 == 0 {
                        "/__hdd_canary/ok.txt"
                    } else {
                        "/a/b?q=1"
                    },
                    "HTTP/1.1",
                )
            } else {
                (
                    methods[(next() % methods.len() as u64) as usize],
                    targets[(next() % targets.len() as u64) as usize],
                    versions[(next() % versions.len() as u64) as usize],
                )
            };
            let mut head = format!("{method} {target} {version}\r\n");
            let header_count = (next() % 7) as usize;
            for index in 0..header_count {
                if !well_formed && next() % 17 == 0 {
                    // a folded continuation line: never accepted in this contract
                    head.push_str(&format!(" continuation-{index}: value\r\n"));
                    continue;
                }
                if !well_formed && next() % 23 == 0 {
                    head.push_str(&format!("x-huge: {}\r\n", "v".repeat(5_000)));
                    continue;
                }
                let (name, value) = if well_formed {
                    (
                        safe_names[(next() % safe_names.len() as u64) as usize],
                        safe_values[(next() % safe_values.len() as u64) as usize],
                    )
                } else {
                    (
                        names[(next() % names.len() as u64) as usize],
                        values[(next() % values.len() as u64) as usize],
                    )
                };
                head.push_str(&format!("{name}: {value}\r\n"));
                if !well_formed && next() % 11 == 0 {
                    head.push_str(&format!("{name}: {value}\r\n"));
                }
            }
            head.push_str("\r\n");
            match parse_request(head.as_bytes()) {
                Ok(req) => {
                    ok_count += 1;
                    check_parsed(&req, round);
                }
                Err(_) => err_count += 1,
            }
        }

        // 2) mutate a valid head byte by byte (fixed seed): both classes must survive the mutations
        let base_bytes =
            b"GET /__hdd_canary/ok.txt HTTP/1.1\r\nHost: hddtest.example.com\r\nX-HDD-Probe: yes\r\n\r\n"
                .to_vec();
        for round in 0..2_000u32 {
            let mut buf = base_bytes.clone();
            let mutations = 1 + (next() % 4) as usize;
            for _ in 0..mutations {
                let pick = (next() % 3) as u8;
                let index = (next() as usize) % buf.len();
                match pick {
                    0 => {
                        if let Some(slot) = buf.get_mut(index) {
                            *slot = (next() % 256) as u8;
                        }
                    }
                    1 => {
                        buf.insert(index, (next() % 256) as u8);
                    }
                    _ => {
                        buf.remove(index);
                    }
                }
                if buf.is_empty() {
                    break;
                }
            }
            match parse_request(&buf) {
                Ok(req) => {
                    ok_count += 1;
                    check_parsed(&req, round);
                }
                Err(_) => err_count += 1,
            }
        }

        // 3) raw noise (mostly incomplete/malformed) and short line-ending variants
        for round in 0..1_000u32 {
            let len = (next() % 2_000) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                buf.push((next() % 256) as u8);
            }
            match parse_request(&buf) {
                Ok(req) => {
                    ok_count += 1;
                    check_parsed(&req, round);
                }
                Err(_) => err_count += 1,
            }
        }
        // a valid head whose line endings are LF only is refused (uniform rejection), a known hostile set never aborts
        for raw in [
            b"GET / HTTP/1.1\nHost: x\n\n".as_slice(),
            b"\r\n\r\n".as_slice(),
            b"GET\r\n\r\n".as_slice(),
            b"GET /\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\n".as_slice(),
            b"GET / HTTP/1.1\r\n:\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nx:".as_slice(),
            b"\x00\x01\x02".as_slice(),
        ] {
            if parse_request(raw).is_ok() {
                ok_count += 1;
            } else {
                err_count += 1;
            }
        }

        // the sweep must reach BOTH parser outcomes in meaningful numbers, otherwise it proves nothing
        assert!(
            ok_count >= 500,
            "the structured sweep produced only {ok_count} accepted heads; it does not reach the parser logic"
        );
        assert!(
            err_count >= 500,
            "the sweep produced only {err_count} rejected heads; it does not reach the reject paths"
        );
    }

    #[test]
    fn t0210_start_refuses_a_non_regular_file() {
        // C-8: only regular files are served; a directory (or a device) in the canary root is refused at startup.
        let dir = temp_dir("non-regular");
        generate(&dir, "/c/").expect("generate");
        std::fs::remove_file(dir.join("ok.txt")).expect("remove");
        std::fs::create_dir(dir.join("ok.txt")).expect("mkdir");
        let config =
            Config::new("127.0.0.1:0".parse().expect("addr"), &dir, "/c/").expect("config");
        let error = start(config).expect_err("must refuse a non-regular file");
        let message = error.to_string();
        assert!(
            message.contains("not a regular file") || message.contains("symbolic link"),
            "{message}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn t0210_start_refuses_a_file_over_the_size_limit() {
        // C-8: the hard size limit is applied while reading, not only from metadata.
        let dir = temp_dir("oversize");
        generate(&dir, "/c/").expect("generate");
        std::fs::write(dir.join("static.js"), vec![b'x'; MAX_FILE_BYTES + 1]).expect("write");
        let config =
            Config::new("127.0.0.1:0".parse().expect("addr"), &dir, "/c/").expect("config");
        let error = start(config).expect_err("must refuse an oversize file");
        assert!(
            matches!(error, CanaryError::FileTooLarge { .. }),
            "{error:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn t0210_start_refuses_a_symlinked_file() {
        // C-8: a symbolic link is not a regular file; the sidecar must not follow it out of the root.
        let dir = temp_dir("symlink");
        generate(&dir, "/c/").expect("generate");
        let outside = dir.join("outside.txt");
        std::fs::write(&outside, b"outside").expect("write");
        std::fs::remove_file(dir.join("ok.txt")).expect("remove");
        std::os::unix::fs::symlink(&outside, dir.join("ok.txt")).expect("symlink");
        let config =
            Config::new("127.0.0.1:0".parse().expect("addr"), &dir, "/c/").expect("config");
        let error = start(config).expect_err("must refuse a symlink");
        let message = error.to_string();
        assert!(message.contains("symbolic link"), "{message}");
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn t0210_echo_headers_never_leaks_secret_bearing_headers() {
        // K-1: HDD-Origin-Auth is injected on every upstream request, and the echo endpoint is reachable through HDD, so
        // its value must never be returned. Only presence + version + key id are shown.
        let headers = vec![
            Header {
                name: "hdd-origin-auth".into(),
                value:
                    "v1;k_7;1700000000;0123456789abcdef;AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                        .into(),
            },
            Header {
                name: "cookie".into(),
                value: "session=supersecret".into(),
            },
            Header {
                name: "authorization".into(),
                value: "Bearer topsecret".into(),
            },
            Header {
                name: "x-api-key".into(),
                value: "api-secret-value".into(),
            },
            Header {
                name: "x-secret-thing".into(),
                value: "secret-planted".into(),
            },
            Header {
                name: "x-session-token".into(),
                value: "token-planted".into(),
            },
            Header {
                name: "x-auth-token".into(),
                value: "auth-planted".into(),
            },
            Header {
                name: "x-signature".into(),
                value: "signature-planted".into(),
            },
            Header {
                name: "x-key-id".into(),
                value: "key-planted".into(),
            },
            Header {
                name: "x-hdd-canary-probe".into(),
                value: "hdd-canary-probe".into(),
            },
        ];
        let body = String::from_utf8(echo_headers_json(&headers)).expect("utf-8 JSON");
        for planted in [
            "supersecret",
            "topsecret",
            "api-secret-value",
            "secret-planted",
            "token-planted",
            "auth-planted",
            "signature-planted",
            "key-planted",
            "1700000000",
            "0123456789abcdef",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(
                !body.contains(planted),
                "the echo leaked `{planted}`:\n{body}"
            );
        }
        assert!(
            body.contains(r#"{"name":"hdd-origin-auth","value":"v1;k_7"}"#),
            "origin auth keeps only presence + version + key id:\n{body}"
        );
        assert!(
            body.contains(r#"{"name":"x-hdd-canary-probe","value":"hdd-canary-probe"}"#),
            "the probe header still round-trips:\n{body}"
        );
        // P-9: an unknown header's NAME is never echoed; the whole set is one `[not-echoed-name]` count.
        assert!(
            body.contains(r#"{"name":"[not-echoed-name]","value":"8"}"#),
            "unknown headers are a count only:\n{body}"
        );
        for name in [
            "cookie",
            "authorization",
            "x-api-key",
            "x-secret-thing",
            "x-session-token",
            "x-auth-token",
            "x-signature",
            "x-key-id",
        ] {
            assert!(
                !body.contains(name),
                "{name} must not be echoed by name:\n{body}"
            );
        }
    }

    #[test]
    fn t0210_hdd_evidence_is_hdd_specific() {
        // K-2: only HDD-specific evidence counts; a different host or an origin/TLS proxy header does not.
        let server = [Header {
            name: "server".into(),
            value: "Hack-Dev-Defence".into(),
        }];
        assert!(hdd_response_evidence(&server).is_some());
        let ray = [Header {
            name: "hdd-ray-id".into(),
            value: "abc123".into(),
        }];
        assert!(hdd_response_evidence(&ray).is_some());
        for not_evidence in [
            vec![Header {
                name: "server".into(),
                value: "nginx".into(),
            }],
            vec![Header {
                name: "x-real-ip".into(),
                value: "198.51.100.7".into(),
            }],
            vec![Header {
                name: "x-forwarded-for".into(),
                value: "198.51.100.7".into(),
            }],
        ] {
            assert!(
                hdd_response_evidence(&not_evidence).is_none(),
                "{not_evidence:?}"
            );
        }
        let connecting = [Header {
            name: "hdd-connecting-ip".into(),
            value: "198.51.100.7".into(),
        }];
        let runner: IpAddr = "198.51.100.7".parse().expect("ip");
        assert!(hdd_echo_evidence(&connecting, Some(runner)).is_ok());
        assert!(
            hdd_echo_evidence(&connecting, None).is_err(),
            "without a known runner IP the header cannot be correlated"
        );
        let other: IpAddr = "198.51.100.8".parse().expect("ip");
        assert!(hdd_echo_evidence(&connecting, Some(other)).is_err());
        // Q-2: HDD appends the resolved client IP to X-Forwarded-For, so the runner as the last token is accepted; an
        // X-Real-IP (which an origin TLS terminator can add) is not.
        assert!(
            hdd_echo_evidence(
                &[Header {
                    name: "x-forwarded-for".into(),
                    value: "198.51.100.7".into()
                }],
                Some(runner)
            )
            .is_ok()
        );
    }

    #[test]
    fn t0210_address_tokens_are_case_insensitive_and_canonical() {
        // K-8: RFC 7239 `for=` is case-insensitive and `::ffff:1.2.3.4` equals `1.2.3.4`.
        for raw in ["for=198.51.100.7", "FOR=198.51.100.7", "For=198.51.100.7"] {
            assert_eq!(
                address_token(raw),
                Some("198.51.100.7".parse().expect("ip")),
                "{raw}"
            );
        }
        assert_eq!(
            address_token("::ffff:1.2.3.4"),
            Some("1.2.3.4".parse().expect("ip")),
            "IPv4-mapped IPv6 compares equal to IPv4"
        );
        assert_eq!(
            address_token("[2001:db8::1]:443"),
            Some("2001:db8::1".parse().expect("ip"))
        );
        assert_eq!(
            address_token("198.51.100.7:1234"),
            Some("198.51.100.7".parse().expect("ip"))
        );
        assert_eq!(address_token("garbage"), None);
    }

    #[test]
    fn t0210_normalise_host_token_strips_trailing_dot() {
        assert_eq!(normalise_host_token("Example.COM."), "example.com");
        assert_eq!(
            normalise_host_token("hddtest.example.com"),
            "hddtest.example.com"
        );
        assert_eq!(normalise_host_token("127.0.0.1."), "127.0.0.1");
    }

    #[test]
    fn t0210_parse_echo_json_requires_boolean_literals() {
        let ok_true = br#"{"headers":[],"truncated":true}"#;
        let ok_false = br#"{"headers":[],"truncated":false}"#;
        assert!(parse_echo_json(ok_true).is_ok());
        assert!(parse_echo_json(ok_false).is_ok());
        for bad in [
            br#"{"headers":[],"truncated":txxx}"#.as_slice(),
            br#"{"headers":[],"truncated":tru}"#.as_slice(),
            br#"{"headers":[],"truncated":falsy}"#.as_slice(),
            br#"{"headers":[],"truncated":1}"#.as_slice(),
        ] {
            assert!(
                parse_echo_json(bad).is_err(),
                "must reject {}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    struct SlowWriter {
        started: Instant,
        sleep: Duration,
        written: usize,
    }

    impl std::io::Write for SlowWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            std::thread::sleep(self.sleep);
            let take = buf.len().min(1);
            self.written += take;
            let _ = self.started;
            Ok(take)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn t0210_write_with_deadline_abandons_a_slow_reader_at_the_deadline() {
        // K-3: a reader consuming one byte every 20 ms must not let the single-threaded server exceed the deadline.
        let mut writer = SlowWriter {
            started: Instant::now(),
            sleep: Duration::from_millis(20),
            written: 0,
        };
        let started = Instant::now();
        let deadline = started + Duration::from_millis(300);
        let payload = vec![b'x'; 256];
        let finished =
            write_with_deadline(&mut writer, &payload, deadline, &mut |_writer, _left| {});
        let elapsed = started.elapsed();
        assert!(!finished, "the write must be abandoned at the deadline");
        assert!(
            writer.written < payload.len(),
            "only part of the body was written: {}",
            writer.written
        );
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
        // a fast writer finishes inside the deadline
        let mut fast = SlowWriter {
            started: Instant::now(),
            sleep: Duration::from_millis(0),
            written: 0,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        assert!(write_with_deadline(
            &mut fast,
            b"abc",
            deadline,
            &mut |_writer, _left| {}
        ));
        assert!(fast.started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn t0210_wait_reports_a_dead_listener_thread() {
        // K-4: a listener panic is an outage, not a normal exit.
        let dead = Running {
            addr: "127.0.0.1:0".parse().expect("addr"),
            base_path: "/__hdd_canary/".into(),
            shutdown: Arc::new(AtomicBool::new(false)),
            handle: Some(std::thread::spawn(|| panic!("listener thread died"))),
            metrics: Arc::new(Metrics::default()),
            fatal: Arc::new(AtomicBool::new(false)),
        };
        assert!(
            dead.wait().is_err(),
            "a dead listener thread must be an error"
        );
        let dir = temp_dir("clean-wait");
        generate(&dir, "/c/").expect("generate");
        let config =
            Config::new("127.0.0.1:0".parse().expect("addr"), &dir, "/c/").expect("config");
        let mut running = start(config).expect("start");
        running.stop();
        assert!(running.wait().is_ok(), "a clean stop is a normal exit");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn t0210_ensure_regular_decision_table() {
        // K-7: the regular-file decision is a pure function so it is covered on a host that cannot create a symlink.
        assert!(ensure_regular(NodeKind::Regular, Path::new("ok.txt")).is_ok());
        let symlink = ensure_regular(NodeKind::Symlink, Path::new("ok.txt"))
            .expect_err("a symlink must be refused");
        assert!(symlink.to_string().contains("symbolic link"), "{symlink}");
        let other = ensure_regular(NodeKind::Other, Path::new("ok.txt"))
            .expect_err("a non-regular file must be refused");
        assert!(other.to_string().contains("not a regular file"), "{other}");
    }

    #[test]
    fn t0210_parse_request_accepts_content_length_zero() {
        // K-8: a GET with `Content-Length: 0` has no body and is served; a positive length is refused.
        assert!(
            parse_request(b"GET /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n").is_ok(),
            "Content-Length: 0 declares no body"
        );
        assert!(parse_request(b"HEAD /x HTTP/1.1\r\ncontent-length: 0\r\n\r\n").is_ok());
        assert_eq!(
            parse_request(b"GET /x HTTP/1.1\r\nContent-Length: 1\r\n\r\n").err(),
            Some(RequestError::Malformed("request body"))
        );
    }
    #[test]
    fn t0210_delegation_pending_is_only_a_resolve_of_a_profile_test_hostname() {
        // Q-1: there is no delegation field in the profile; `origin.lockdown_state` is the STOP #2 origin state.
        // Only DNS resolution of a profile-named test_hostname may be a pending delegation step.
        assert!(transport_means_pending_delegation(
            TargetProvenance::ProfileTestHostname,
            TransportKind::Resolve
        ));
        for (provenance, kind) in [
            (
                TargetProvenance::ProfileTestHostname,
                TransportKind::Connect,
            ),
            (
                TargetProvenance::ProfileTestHostname,
                TransportKind::Timeout,
            ),
            (TargetProvenance::ProfileTestHostname, TransportKind::Http),
            (TargetProvenance::ProfileTestHostname, TransportKind::Tls),
            (TargetProvenance::ProfileOrigin, TransportKind::Resolve),
            (TargetProvenance::OverrideNamed, TransportKind::Resolve),
            (TargetProvenance::OverrideLiteral, TransportKind::Resolve),
            (TargetProvenance::OverrideLiteral, TransportKind::Connect),
        ] {
            assert!(
                !transport_means_pending_delegation(provenance, kind),
                "{provenance:?}/{kind:?} must not be a pending delegation step"
            );
        }
    }

    #[test]
    fn t0210_hdd_echo_evidence_uses_hdd_connecting_ip_and_hdd_built_xff_only() {
        // Q-2: HDD sets HDD-Connecting-IP and appends the resolved client IP to X-Forwarded-For (spec T-0361/C9).
        let runner: IpAddr = "198.51.100.7".parse().expect("ip");
        let connecting = [Header {
            name: "hdd-connecting-ip".into(),
            value: "198.51.100.7".into(),
        }];
        assert!(hdd_echo_evidence(&connecting, Some(runner)).is_ok());
        // Q-2b: HDD strips the planted spoof and appends the runner; the spoof is absent, so this is evidence.
        let xff = [Header {
            name: "x-forwarded-for".into(),
            value: "198.51.100.7".into(),
        }];
        assert!(hdd_echo_evidence(&xff, Some(runner)).is_ok());
        // the spoof surviving (an origin terminator that only appends) is never evidence
        for value in [
            "198.51.100.7, 203.0.113.99",
            "203.0.113.99, 198.51.100.7",
            "10.1.2.3, 198.51.100.7, 203.0.113.99",
        ] {
            let xff = [Header {
                name: "x-forwarded-for".into(),
                value: value.into(),
            }];
            let error = hdd_echo_evidence(&xff, Some(runner)).expect_err(value);
            assert!(error.contains("203.0.113.99"), "{value}: {error}");
        }
        // Q-2b: runner present + planted spoof absent is evidence even when a terminator appended after HDD's token; the
        // spoof absence (the chain was rebuilt) is the evidence property, not the token position.
        let xff_other = [Header {
            name: "x-forwarded-for".into(),
            value: "198.51.100.7, 10.1.2.3".into(),
        }];
        assert!(hdd_echo_evidence(&xff_other, Some(runner)).is_ok());
        // other forwarding headers are shown but never asserted
        for name in [
            "x-real-ip",
            "forwarded",
            "cf-connecting-ip",
            "true-client-ip",
        ] {
            let header = [Header {
                name: name.into(),
                value: "198.51.100.7".into(),
            }];
            assert!(
                hdd_echo_evidence(&header, Some(runner)).is_err(),
                "{name} must not satisfy the HDD assertion"
            );
        }
    }

    #[test]
    fn t0210_echo_headers_are_an_allowlist_not_a_denylist() {
        // Q-3: only the allowlisted names keep their value; everything else is listed by name with [not-echoed].
        let headers = vec![
            Header {
                name: "host".into(),
                value: "canary.test".into(),
            },
            Header {
                name: "accept".into(),
                value: "text/html".into(),
            },
            Header {
                name: "connection".into(),
                value: "close".into(),
            },
            Header {
                name: "user-agent".into(),
                value: "hdd-test/1".into(),
            },
            Header {
                name: "x-hdd-canary-probe".into(),
                value: "hdd-canary-probe".into(),
            },
            Header {
                name: "hdd-ray-id".into(),
                value: "ray-1".into(),
            },
            Header {
                name: "x-session-id".into(),
                value: "session-planted".into(),
            },
            Header {
                name: "x-amz-credential".into(),
                value: "amz-planted".into(),
            },
            Header {
                name: "x-password".into(),
                value: "password-planted".into(),
            },
            Header {
                name: "x-jwt-assertion".into(),
                value: "jwt-planted".into(),
            },
            Header {
                name: "cookie2".into(),
                value: "cookie2-planted".into(),
            },
            Header {
                name: "referer".into(),
                value: "http://a/?t=SECRET6".into(),
            },
        ];
        let body = String::from_utf8(echo_headers_json(&headers)).expect("utf-8 JSON");
        for planted in [
            "session-planted",
            "amz-planted",
            "password-planted",
            "jwt-planted",
            "cookie2-planted",
            "SECRET6",
        ] {
            assert!(!body.contains(planted), "leaked `{planted}`:\n{body}");
        }
        for allowed in [
            "host",
            "connection",
            "user-agent",
            "x-hdd-canary-probe",
            "hdd-ray-id",
        ] {
            assert!(
                body.contains(&format!(r#""name":"{allowed}","value":""#)),
                "{allowed} keeps its value:\n{body}"
            );
        }
        // P-9: accept is not a forwarding/HDD header, so it falls into the count with the secret-bearing names.
        for counted in [
            "accept",
            "x-session-id",
            "x-amz-credential",
            "x-password",
            "x-jwt-assertion",
            "cookie2",
            "referer",
        ] {
            assert!(
                !body.contains(counted),
                "{counted} must not be echoed by name:\n{body}"
            );
        }
        assert!(
            body.contains(r#"{"name":"[not-echoed-name]","value":"7"}"#),
            "the unknown names are one count:\n{body}"
        );
    }

    #[test]
    fn t0210_origin_auth_kid_is_echoed_only_for_the_exact_v1_shape() {
        // Q-3: the kid is shown only for `^v1;[A-Za-z0-9_-]{1,32}$` with the exact five-field v1 shape; a static
        // token and a malformed v1 are fully redacted.
        let sig43 = "A".repeat(43);
        let nonce16 = "0123456789abcdef";
        for (value, expected) in [
            (
                format!("v1;kid9;1700000000;{nonce16};{sig43}"),
                "v1;kid9".to_owned(),
            ),
            (
                format!("v1;Key_id-9;1;{nonce16};{sig43}"),
                "v1;Key_id-9".to_owned(),
            ),
            (
                "v1;has space;1;0123456789abcdef;AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    .to_owned(),
                ECHO_REDACTED_VALUE.to_owned(),
            ),
            (
                "v1;kid9;1;short;AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                ECHO_REDACTED_VALUE.to_owned(),
            ),
            (
                "v1;kid9;1;0123456789abcdef;short".to_owned(),
                ECHO_REDACTED_VALUE.to_owned(),
            ),
            (
                "v1;kid9;1;0123456789abcdef".to_owned(),
                ECHO_REDACTED_VALUE.to_owned(),
            ),
            (
                "v1;kid9;1;0123456789abcdef;AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;extra"
                    .to_owned(),
                ECHO_REDACTED_VALUE.to_owned(),
            ),
            (
                "v2;kid9;1;0123456789abcdef;AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                ECHO_REDACTED_VALUE.to_owned(),
            ),
            (
                "v;kid9;1;0123456789abcdef;AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                ECHO_REDACTED_VALUE.to_owned(),
            ),
            ("STATICSECRET".to_owned(), ECHO_REDACTED_VALUE.to_owned()),
            ("v7;STATICSECRET".to_owned(), ECHO_REDACTED_VALUE.to_owned()),
        ] {
            let headers = vec![Header {
                name: "hdd-origin-auth".into(),
                value: value.clone(),
            }];
            let body = String::from_utf8(echo_headers_json(&headers)).expect("utf-8 JSON");
            assert!(
                body.contains(&format!(r#""name":"hdd-origin-auth","value":"{expected}""#)),
                "{value}: expected {expected}, got:\n{body}"
            );
        }
    }

    #[test]
    fn t0210_override_provenance_follows_the_host_identity() {
        // P-6: an override naming the profile test_hostname must be classified exactly like the default target for that
        // host; the flag that carried it must not change the delegation decision.
        assert_eq!(
            classify_override_provenance(
                "hddtest.example",
                Some("origin.example"),
                "hddtest.example"
            ),
            TargetProvenance::ProfileTestHostname
        );
        assert_eq!(
            classify_override_provenance(
                "hddtest.example",
                Some("origin.example"),
                "origin.example"
            ),
            TargetProvenance::ProfileOrigin
        );
        assert_eq!(
            classify_override_provenance(
                "hddtest.example",
                Some("origin.example"),
                "other.example"
            ),
            TargetProvenance::OverrideNamed
        );
        assert_eq!(
            classify_override_provenance("", None, "127.0.0.1"),
            TargetProvenance::OverrideNamed
        );
        // trailing dot and case are normalised, so a differently spelled same host is the same identity
        assert_eq!(
            classify_override_provenance(
                "HDDTest.Example.",
                Some("origin.example"),
                "hddtest.example"
            ),
            TargetProvenance::ProfileTestHostname
        );
    }

    #[test]
    fn t0210_resolver_negative_answer_distinguishes_delegation_from_environment_failure() {
        // P-6: NXDOMAIN/no-answer is the delegation question; SERVFAIL/timeout is an environment failure.
        for negative in [
            "NXDOMAIN",
            "no records",
            "no answer",
            "not found",
            "does not exist",
        ] {
            assert!(
                resolver_negative_answer(negative),
                "{negative} is a negative answer"
            );
        }
        for other in [
            "SERVFAIL",
            "timed out",
            "network unreachable",
            "resolver socket error",
        ] {
            assert!(
                !resolver_negative_answer(other),
                "{other} is not a negative answer"
            );
        }
    }
    #[test]
    fn t0210_start_propagates_a_real_listener_panic_and_counts_it() {
        // Q-6: the real start() path, not a hand-built Running.
        let dir = temp_dir("real-panic");
        generate(&dir, "/c/").expect("generate");
        let mut config =
            Config::new("127.0.0.1:0".parse().expect("addr"), &dir, "/c/").expect("config");
        config.panic_listener = true;
        let running = start(config).expect("start");
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            running.metrics().listener_panics,
            1,
            "the panic is counted before the thread dies"
        );
        let error = running
            .wait()
            .expect_err("a dead listener must be an error");
        let message = error.to_string();
        assert!(
            message.contains("listener panics: 1"),
            "the exit error exports the panic count: {message}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn t0210_metrics_are_bounded_and_saturate() {
        let m = Metrics::default();
        let snap = m.snapshot();
        assert_eq!(snap, MetricsSnapshot::default());
        m.served.store(u64::MAX, Ordering::Relaxed);
        m.rejected.store(u64::MAX, Ordering::Relaxed);
        m.bytes_out.store(u64::MAX, Ordering::Relaxed);
        m.accept_errors.store(u64::MAX, Ordering::Relaxed);
        m.read_timeouts.store(u64::MAX, Ordering::Relaxed);
        m.echo_requests.store(u64::MAX, Ordering::Relaxed);
        Metrics::bump(&m.served, 1);
        Metrics::bump(&m.rejected, 1);
        Metrics::bump(&m.bytes_out, 10);
        Metrics::bump(&m.accept_errors, 1);
        Metrics::bump(&m.read_timeouts, 1);
        Metrics::bump(&m.echo_requests, 1);
        let snap = m.snapshot();
        assert_eq!(snap.served, u64::MAX, "saturating, never wrapping");
        assert_eq!(snap.rejected, u64::MAX);
        assert_eq!(snap.bytes_out, u64::MAX);
        assert_eq!(snap.accept_errors, u64::MAX);
        assert_eq!(snap.read_timeouts, u64::MAX);
        assert_eq!(snap.echo_requests, u64::MAX);
    }
}
