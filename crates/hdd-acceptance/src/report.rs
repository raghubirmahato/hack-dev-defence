//! The report: JSON and Markdown outputs, one status line per registered check id, evidence blocks, secret redaction and
//! saved logs with a SHA-256 and the tail embedded (E3.1, E3.4, section 2.1).
//!
//! The renderer refuses to print a `PASS` whose status line carries no hash-backed evidence, because a pass without an
//! artifact is not a pass (E3.1 rule 1). Evidence is redacted **structurally**, by field name as well as by value, before it is
//! serialised, so a secret cannot leak through a JSON-escaped form and the output stays parseable (review item A-6). Both
//! renderers cap an evidence value at 512 bytes on a UTF-8 boundary **after** redaction (A-7), and the Markdown fence around a
//! log tail is longer than any backtick run inside the tail (A-11). The evidence store refuses path escapes (A-11).

use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::status::{Counts, EvidenceRef, StatusLine, TaxonomyError, Verdict};

/// Largest report accepted from JSON (a report with 63 lines is far smaller; the cap bounds hostile input).
pub const MAX_REPORT_BYTES: usize = 4 * 1024 * 1024;

/// How many lines of a saved log are embedded in the report.
pub const LOG_TAIL_LINES: usize = 20;

/// Largest evidence value kept in a report (R-25: evidence at most 512 bytes, redacted).
pub const EVIDENCE_VALUE_MAX: usize = 512;

/// Largest age of a report a `--resume` may build on (review item R-2). A run older than this is not resumed: the world has
/// moved on and every check must run again.
pub const MAX_RESUME_AGE_SECS: u64 = 24 * 60 * 60;

/// The marker that replaces a truncated evidence value; counted inside [`EVIDENCE_VALUE_MAX`].
pub const TRUNCATION_MARKER: &str = "[truncated]";

/// Field or marker names whose value must never be printed. Matched case-insensitively (whole name for a structured field,
/// textual marker inside a free-form string).
pub const SECRET_MARKERS: [&str; 15] = [
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "x-api-key",
    "authorization",
    "private_key",
    "credential",
    "client_secret",
    "cookie",
    "set-cookie",
    "bearer",
    "session",
];

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest.iter() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ` (no external clock crate).
pub fn now_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let tod = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Civil date (year, month, day) for days since 1970-01-01 (proleptic Gregorian; Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The kind of an evidence block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// DNS answers (query, type, name, answers, resolver).
    DnsAnswers,
    /// HTTP status, headers and the inspected request line.
    HttpResponse,
    /// Event ids and audit records (`ray_id`, category, client IP key).
    EventRecord,
    /// Timestamps of the request and its observations.
    Timestamps,
}

impl EvidenceKind {
    /// The heading used in Markdown.
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceKind::DnsAnswers => "dns_answers",
            EvidenceKind::HttpResponse => "http_response",
            EvidenceKind::EventRecord => "event_record",
            EvidenceKind::Timestamps => "timestamps",
        }
    }
}

/// One evidence block: named fields, redacted by name and value, capped after redaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBlock {
    /// Check id the evidence belongs to.
    pub check: String,
    /// What kind of evidence this is.
    pub kind: EvidenceKind,
    /// Ordered name/value pairs. Bodies are never stored in full (R-25).
    pub fields: Vec<(String, String)>,
}

impl EvidenceBlock {
    /// A block with no fields yet.
    pub fn new(check: impl Into<String>, kind: EvidenceKind) -> EvidenceBlock {
        EvidenceBlock {
            check: check.into(),
            kind,
            fields: Vec::new(),
        }
    }

    /// Add a field.
    pub fn with_field(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> EvidenceBlock {
        self.fields.push((name.into(), value.into()));
        self
    }

    /// True when one of the secret markers is a **whole token** of a field name (review item N-6): the name is split on
    /// `_`, `-`, whitespace and camelCase boundaries, and the marker's own tokens must match the name's trailing tokens.
    /// `session_count` (tokens `session`,`count`) is therefore not a secret field, while `accessToken`, `X-API-Key` and
    /// `client_secret` are.
    pub fn is_secret_field(name: &str) -> bool {
        let tokens = Self::name_tokens(name);
        if tokens.is_empty() {
            return false;
        }
        SECRET_MARKERS.iter().any(|marker| {
            let marker_tokens = Self::name_tokens(marker);
            !marker_tokens.is_empty()
                && tokens.get(tokens.len().saturating_sub(marker_tokens.len())..)
                    == Some(marker_tokens.as_slice())
        })
    }

    /// Split a header or field name into lowercase tokens on `_`, `-`, whitespace and camelCase boundaries.
    fn name_tokens(name: &str) -> Vec<String> {
        let mut tokens: Vec<String> = Vec::new();
        let mut current = String::new();
        let chars: Vec<char> = name.chars().collect();
        for (index, ch) in chars.iter().enumerate() {
            if !ch.is_ascii_alphanumeric() {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current).to_ascii_lowercase());
                }
                continue;
            }
            let previous = index.checked_sub(1).and_then(|i| chars.get(i)).copied();
            let next = chars.get(index + 1).copied();
            let boundary = matches!(
                (previous, ch, next),
                (Some(prev), current, _) if prev.is_ascii_lowercase() && current.is_ascii_uppercase()
            ) || (ch.is_ascii_uppercase()
                && previous.is_some_and(|prev| prev.is_ascii_uppercase())
                && next.is_some_and(|n| n.is_ascii_lowercase()));
            if boundary && !current.is_empty() {
                tokens.push(std::mem::take(&mut current).to_ascii_lowercase());
            }
            current.push(*ch);
        }
        if !current.is_empty() {
            tokens.push(current.to_ascii_lowercase());
        }
        tokens
    }
}

/// A saved full log: path, SHA-256 of the saved bytes, size and the redacted tail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogRef {
    /// Path of the saved log.
    pub path: String,
    /// Lowercase hex SHA-256 of the saved bytes.
    pub sha256: String,
    /// Number of bytes saved.
    pub bytes: u64,
    /// The last [`LOG_TAIL_LINES`] lines, redacted.
    pub tail: String,
}

/// Why a report could not be rendered or parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportError {
    /// A status line broke the taxonomy (bad id, PASS without evidence).
    Taxonomy(TaxonomyError),
    /// Two status lines share an id.
    DuplicateId {
        /// The duplicated id.
        id: String,
    },
    /// The report could not be serialised.
    Serialize {
        /// Serialiser message.
        message: String,
    },
    /// The report could not be parsed.
    Parse {
        /// Parser message.
        message: String,
    },
    /// The report is larger than [`MAX_REPORT_BYTES`].
    TooLarge {
        /// Bytes offered.
        bytes: usize,
    },
    /// A resume attempt used a report from another mode, stage or profile.
    ResumeMismatch {
        /// What differs.
        detail: String,
    },
}

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReportError::Taxonomy(e) => write!(f, "{e}"),
            ReportError::DuplicateId { id } => write!(f, "check id `{id}` appears twice"),
            ReportError::Serialize { message } => write!(f, "cannot serialise report: {message}"),
            ReportError::Parse { message } => write!(f, "cannot parse report: {message}"),
            ReportError::TooLarge { bytes } => write!(
                f,
                "report is {bytes} bytes, larger than the {MAX_REPORT_BYTES}-byte cap"
            ),
            ReportError::ResumeMismatch { detail } => {
                write!(f, "cannot resume from that report: {detail}")
            }
        }
    }
}

impl std::error::Error for ReportError {}

/// Removes secrets from any text before it is written to a report or a log.
///
/// Two mechanisms: exact known secret values (registered by the caller, in raw and JSON-escaped form) and secret markers
/// (`password`, `x-api-key`, `set-cookie`, ...) whose value is replaced. It never removes a SHA-256 digest value: the report
/// needs its hashes. This is the text-level mechanism; the JSON renderer also redacts structurally by field name (A-6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Redactor {
    secrets: Vec<String>,
}

/// Why a secret could not be registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretError {
    /// The value is shorter than [`Redactor::MIN_SECRET_BYTES`] bytes: redacting it would shred unrelated text and it cannot
    /// be a real secret (review item S-7).
    TooShort {
        /// The length that was offered.
        len: usize,
    },
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretError::TooShort { len } => write!(
                f,
                "the secret is {len} bytes; a secret must be at least {} bytes to be redacted safely",
                Redactor::MIN_SECRET_BYTES
            ),
        }
    }
}

impl std::error::Error for SecretError {}

impl Redactor {
    /// Minimum length of a registered exact secret (review item S-7): shorter values would shred unrelated text and cannot be
    /// real secrets, so they are refused instead of being silently dropped.
    pub const MIN_SECRET_BYTES: usize = 4;

    /// An empty redactor.
    pub fn new() -> Redactor {
        Redactor::default()
    }

    /// A redactor that removes the given exact values, **propagating** the length error (review item N-5): a caller that
    /// loads secrets from the profile or the CLI must not silently lose a short one.
    pub fn with_secrets<I: IntoIterator<Item = S>, S: Into<String>>(
        secrets: I,
    ) -> Result<Redactor, SecretError> {
        let mut redactor = Redactor::new();
        for secret in secrets {
            redactor.add_secret(secret)?;
        }
        Ok(redactor)
    }

    /// Register one exact secret value. The JSON-escaped form is matched too. A value shorter than
    /// [`Redactor::MIN_SECRET_BYTES`] is **refused with an error** (review item S-7).
    pub fn add_secret(&mut self, secret: impl Into<String>) -> Result<(), SecretError> {
        let secret = secret.into();
        if secret.len() < Self::MIN_SECRET_BYTES {
            return Err(SecretError::TooShort { len: secret.len() });
        }
        if !self.secrets.contains(&secret) {
            self.secrets.push(secret);
        }
        Ok(())
    }

    /// The number of registered exact secrets.
    pub fn secrets_len(&self) -> usize {
        self.secrets.len()
    }

    /// The registered exact secrets.
    pub fn secrets(&self) -> &[String] {
        &self.secrets
    }

    /// Redact one free-form text value (review items N-5 and N-6):
    ///
    /// * exact secrets in raw, JSON-escaped, URL-encoded, `\/`-escaped JSON and base64 forms, **longest first**;
    /// * secret markers matched as whole tokens (quoted JSON keys, escaped nested JSON, `_`/`-` suffixes, camelCase and
    ///   upper-case names such as `DBPASSWORD`);
    /// * one lowercase pass per line (linear, not quadratic - the line is lowercased once, not once per hit);
    /// * unquoted values end at the next delimiter (`space`, `,`, `&`, `;`, `}`, `]`; a tab is value content so
    ///   `secret=a\<TAB>b` is still redacted as one value), except behind a `Bearer`/`Basic`
    ///   scheme word; quotes are kept around `[REDACTED]` so the result stays valid JSON.
    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_owned();
        let mut variants: Vec<String> = Vec::new();
        for secret in &self.secrets {
            for variant in secret_variants(secret) {
                if !variant.is_empty() && !variants.contains(&variant) {
                    variants.push(variant);
                }
            }
        }
        variants.sort_by_key(|variant| std::cmp::Reverse(variant.len()));
        for variant in variants {
            out = out.replace(&variant, "[REDACTED]");
        }
        let mut lines = Vec::new();
        for line in out.split('\n') {
            lines.push(redact_markers(line));
        }
        lines.join("\n")
    }
}
/// JSON-escape a string the way `serde_json` does (used so an escaped secret is still recognised).
fn json_escape(text: &str) -> String {
    serde_json::to_string(text)
        .map(|quoted| quoted.trim_matches('"').to_owned())
        .unwrap_or_else(|_| text.to_owned())
}

/// Every textual form a registered exact secret can take (review item N-5): raw, JSON-escaped, URL-encoded, `\/`-escaped and
/// base64.
fn secret_variants(secret: &str) -> Vec<String> {
    let mut variants = vec![secret.to_owned()];
    let json = json_escape(secret);
    if json != secret && !variants.contains(&json) {
        variants.push(json.clone());
    }
    let url: String = secret
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.' | '_' | '~') {
                ch.to_string()
            } else {
                format!("%{:02X}", ch as u32)
            }
        })
        .collect();
    if url != secret && !variants.contains(&url) {
        variants.push(url);
    }
    let slash = json.replace('/', "\\/");
    if slash != json && !variants.contains(&slash) {
        variants.push(slash);
    }
    let encoded = crate::inspect::base64_encode(secret.as_bytes());
    if !variants.contains(&encoded) {
        variants.push(encoded);
    }
    variants
}

/// True when the case-insensitive `marker` occurs at byte `index` of `line` as a marker token (review items S-7 and N-5):
/// the preceding byte may be a non-alphanumeric separator or a word boundary; a match that starts with an uppercase letter is
/// also accepted after an uppercase or lowercase letter, so `accessToken`, `DBPASSWORD` and `AWSSecretAccessKey` match.
fn is_marker_boundary(line: &str, index: usize, marker: &str) -> bool {
    let Some(matched) = line.get(index..index.saturating_add(marker.len())) else {
        return false;
    };
    if !matched.eq_ignore_ascii_case(marker) {
        return false;
    }
    match line[..index].chars().next_back() {
        None => true,
        Some(before) if !before.is_ascii_alphanumeric() => true,
        Some(before) => matched.chars().next().is_some_and(|first| {
            first.is_ascii_uppercase()
                && (before.is_ascii_lowercase() || before.is_ascii_uppercase())
        }),
    }
}

/// Skip whitespace from `pos`.
fn skip_ws(line: &str, mut pos: usize) -> usize {
    while let Some(ch) = line.get(pos..).and_then(|tail| tail.chars().next()) {
        if ch == ' ' || ch == '\t' {
            pos += ch.len_utf8();
        } else {
            break;
        }
    }
    pos
}

/// Redact the value of every secret marker on one line. Every occurrence is considered; the line is lowercased **once** (review
/// item N-6: linear, not quadratic) and the replacement ranges are applied in one pass.
fn redact_markers(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    let mut replacements: Vec<(usize, usize)> = Vec::new();
    for marker in SECRET_MARKERS {
        let mut from = 0usize;
        while from < lower.len() {
            let Some(offset) = lower.get(from..).and_then(|tail| tail.find(marker)) else {
                break;
            };
            let index = from + offset;
            if is_marker_boundary(line, index, marker)
                && let Some((start, end)) = marker_value_range(line, index, marker)
            {
                replacements.push((start, end));
            }
            from = index + marker.len().max(1);
        }
    }
    if replacements.is_empty() {
        return line.to_owned();
    }
    replacements.sort_by_key(|(start, _)| *start);
    let mut out = String::with_capacity(line.len() + 16);
    let mut last = 0usize;
    for (start, end) in replacements {
        if start < last {
            continue;
        }
        out.push_str(&line[last..start]);
        out.push_str("[REDACTED]");
        last = end;
    }
    out.push_str(&line[last..]);
    out
}

/// True when the marker at `index` is the value of a `--flag` (a run of dashes preceded by the start of the line or
/// whitespace). This stops `non-secret data` from being treated as a flag.
fn is_flag_marker(line: &str, index: usize) -> bool {
    let head = &line[..index];
    let trimmed = head.trim_end_matches('-');
    trimmed.len() < head.len() && (trimmed.is_empty() || trimmed.ends_with([' ', '\t']))
}

/// The byte range **inside** the value that follows a secret marker, or `None` when the marker is not followed by a value
/// (review items S-7, N-5 and N-6). Quotes and escape backslashes are excluded from the range so they survive around
/// `[REDACTED]` and the redacted text stays valid JSON.
fn marker_value_range(line: &str, index: usize, marker: &str) -> Option<(usize, usize)> {
    let mut pos = index.checked_add(marker.len())?;
    // Suffix characters: `aws_secret_access_key`, `secret_key`, `accessToken`.
    while let Some(ch) = line.get(pos..).and_then(|tail| tail.chars().next()) {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            pos += ch.len_utf8();
        } else {
            break;
        }
    }
    // Escaped nested JSON: skip whitespace, backslashes and quotes before the separator.
    pos = skip_ws(line, pos);
    while let Some(ch) = line.get(pos..).and_then(|tail| tail.chars().next()) {
        if ch == '\\' || ch == '"' || ch == '\'' {
            pos += ch.len_utf8();
            pos = skip_ws(line, pos);
        } else {
            break;
        }
    }
    let separator = line.get(pos..).and_then(|tail| tail.chars().next());
    match separator {
        Some(':') | Some('=') => pos += 1,
        _ if marker == "bearer" || is_flag_marker(line, index) => {}
        _ => return None,
    }
    pos = skip_ws(line, pos);
    // Skip an opening quote/escape sequence and remember the quote that opened the value.
    let mut value_quote: Option<char> = None;
    while let Some(ch) = line.get(pos..).and_then(|tail| tail.chars().next()) {
        if ch == '\\' {
            pos += ch.len_utf8();
        } else if ch == '"' || ch == '\'' {
            value_quote = Some(ch);
            pos += ch.len_utf8();
            break;
        } else {
            break;
        }
    }
    if pos >= line.len() {
        return None;
    }
    // A `Bearer`/`Basic` scheme word is skipped so only the credential is redacted (review item N-6).
    let rest = &line[pos..];
    for scheme in ["bearer ", "basic "] {
        if rest.len() >= scheme.len() && rest[..scheme.len()].eq_ignore_ascii_case(scheme) {
            pos += scheme.len();
            pos = skip_ws(line, pos);
            break;
        }
    }
    let value = &line[pos..];
    if value.starts_with("[REDACTED]") {
        return None;
    }
    if let Some(quote) = value_quote {
        // Quoted value: close at the first unescaped matching quote. An escaped quote (`\"`) is content.
        let start = pos;
        let mut cursor = pos;
        while cursor < line.len() {
            let ch = line[cursor..].chars().next()?;
            if ch == '\\' && cursor + 1 < line.len() {
                cursor += ch.len_utf8();
                let escaped = line[cursor..].chars().next()?;
                // `\"` followed by a delimiter/end is the closing quote of an escaped-JSON value.
                if escaped == quote {
                    let after = cursor + escaped.len_utf8();
                    let is_end = after >= line.len()
                        || line[after..].starts_with([',', '}', ']', ':', '\\'])
                        || line[after..].starts_with([' ', '\t']);
                    if is_end {
                        return Some((start, cursor.saturating_sub(1)));
                    }
                }
                cursor += escaped.len_utf8();
                continue;
            }
            if ch == quote {
                return Some((start, cursor));
            }
            cursor += ch.len_utf8();
        }
        return Some((start, line.len()));
    }
    // Unquoted value: end at the next delimiter (review item N-6), not at the end of the line.
    let end = value
        .char_indices()
        .find(|(_, ch)| matches!(ch, ' ' | ',' | '&' | ';' | '}' | ']'))
        .map(|(offset, _)| pos + offset)
        .unwrap_or(line.len());
    if end <= pos {
        return None;
    }
    Some((pos, end))
}
/// Truncate to at most `max` bytes on a UTF-8 character boundary and mark the truncation **inside** the cap: the returned
/// value is never longer than `max`, marker included (R-25, review item R-11).
pub fn truncate_utf8(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let marker = TRUNCATION_MARKER;
    let room = max.saturating_sub(marker.len());
    let mut end = text.len().min(room);
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{marker}", &text[..end])
}

/// The fence for a Markdown code block holding `text`: at least three backticks and longer than any backtick run in the text
/// (review item A-11).
pub fn fence_for(text: &str) -> String {
    let mut longest = 0usize;
    let mut run = 0usize;
    for c in text.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    "`".repeat((longest + 1).max(3))
}

/// Largest single line kept in an embedded log tail, after redaction (review item N-6: keep the tail readable and bounded).
pub const MAX_TAIL_LINE_BYTES: usize = 2 * 1024;

/// Cap every line of an embedded log tail to [`MAX_TAIL_LINE_BYTES`] on a UTF-8 boundary (review item N-6).
pub fn cap_tail_lines(text: &str) -> String {
    text.split('\n')
        .map(|line| truncate_utf8(line, MAX_TAIL_LINE_BYTES))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The last `n` lines of `text`.
pub fn tail_lines(text: &str, n: usize) -> String {
    let mut lines: Vec<&str> = text.lines().collect();
    if lines.len() > n {
        lines.drain(..lines.len() - n);
    }
    lines.join("\n")
}

/// The acceptance run report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    /// When the report was produced (`YYYY-MM-DDTHH:MM:SSZ`).
    pub generated_at: String,
    /// `live` or `lab`.
    pub mode: String,
    /// Lifecycle stage (`pilot` or `production`).
    pub stage: String,
    /// Rate/load profile of the run.
    pub load_profile: String,
    /// Number of vantage points used (E3.1 rule 2).
    pub vantage_count: usize,
    /// One status line per registered check id.
    pub lines: Vec<StatusLine>,
    /// Evidence blocks (DNS answers, HTTP status/headers, event ids, timestamps).
    pub evidence: Vec<EvidenceBlock>,
    /// Full saved logs with SHA-256 and tail.
    pub logs: Vec<LogRef>,
    /// Honest notes about what the run did not do.
    pub notes: Vec<String>,
    /// The `config_revision` the run planned against; a resume must match it (review item R-2).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub config_revision: String,
    /// Target host names derived from the profile; a resume must match them (review item R-2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_hostnames: Vec<String>,
    /// True when a guard denial of class target or stage marked the run invalid (review item R-8).
    #[serde(default, skip_serializing_if = "is_false")]
    pub run_invalid: bool,
    /// The audit lines of the guard denials that marked the run invalid (review item R-8).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invalid_audit: Vec<String>,
    /// Per-line timestamps (check id -> `YYYY-MM-DDTHH:MM:SSZ`). A resumed PASS keeps the timestamp it was first produced at,
    /// so a chain of resumes cannot extend the age limit (review item N-4).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub line_timestamps: std::collections::BTreeMap<String, String>,
    /// Redaction rules; never serialised.
    #[serde(skip)]
    pub redactor: Redactor,
}

/// `skip_serializing_if` helper for booleans.
fn is_false(value: &bool) -> bool {
    !*value
}

impl Report {
    /// An empty report for a run.
    pub fn new(
        mode: impl Into<String>,
        stage: impl Into<String>,
        load_profile: impl Into<String>,
        vantage_count: usize,
    ) -> Report {
        Report {
            generated_at: now_utc(),
            mode: mode.into(),
            stage: stage.into(),
            load_profile: load_profile.into(),
            vantage_count,
            lines: Vec::new(),
            evidence: Vec::new(),
            logs: Vec::new(),
            notes: Vec::new(),
            config_revision: String::new(),
            target_hostnames: Vec::new(),
            run_invalid: false,
            invalid_audit: Vec::new(),
            line_timestamps: std::collections::BTreeMap::new(),
            redactor: Redactor::new(),
        }
    }

    /// Bind the report to the facts a later `--resume` must match: the `config_revision` it planned against and the target
    /// host names derived from the profile (review item R-2).
    pub fn with_binding(
        mut self,
        config_revision: impl Into<String>,
        target_hostnames: Vec<String>,
    ) -> Report {
        self.config_revision = config_revision.into();
        self.target_hostnames = target_hostnames;
        self
    }

    /// Record the run-invalid latch of a guard denial and its audit lines (review item R-8).
    pub fn with_run_invalid(mut self, audit: Vec<String>) -> Report {
        self.run_invalid = !audit.is_empty();
        self.invalid_audit = audit;
        self
    }

    /// Convert a finished [`crate::runner::RunReport`] into report facts (review item N-1): the invalid latch state and its
    /// audit lines (each naming the check id and the run id) are carried into JSON and Markdown. The caller appends the
    /// status lines separately with [`Report::push_line`].
    pub fn apply_run_report(&mut self, run: &crate::runner::RunReport) {
        self.run_invalid = run.run_invalid;
        self.invalid_audit = run.invalid_audit.clone();
    }

    /// True when the report carries a binding a resume can check.
    pub fn has_resume_binding(&self) -> bool {
        !self.config_revision.trim().is_empty() && !self.target_hostnames.is_empty()
    }

    /// A report with a fixed timestamp (deterministic goldens and tests).
    pub fn with_timestamp(mut self, generated_at: impl Into<String>) -> Report {
        self.generated_at = generated_at.into();
        self
    }

    /// Append a status line.
    pub fn push_line(&mut self, line: StatusLine) {
        self.lines.push(line);
    }

    /// Append an evidence block.
    pub fn push_evidence(&mut self, block: EvidenceBlock) {
        self.evidence.push(block);
    }

    /// Append a note.
    pub fn push_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    /// Append a saved log reference.
    pub fn push_log(&mut self, log: LogRef) {
        self.logs.push(log);
    }

    /// The status line of one check, if present.
    pub fn status_line(&self, id: &str) -> Option<&StatusLine> {
        self.lines.iter().find(|line| line.id == id)
    }

    /// Counts per status.
    pub fn counts(&self) -> Counts {
        let mut counts = Counts::default();
        for line in &self.lines {
            match line.verdict {
                Verdict::Pass => counts.pass += 1,
                Verdict::Fail { .. } => counts.fail += 1,
                Verdict::Unverified { .. } => counts.unverified += 1,
            }
        }
        counts
    }

    /// Check the report's invariants: unique, well-formed ids and no unbacked PASS.
    pub fn validate(&self) -> Result<(), ReportError> {
        let mut seen: Vec<&str> = Vec::with_capacity(self.lines.len());
        for line in &self.lines {
            line.validate().map_err(ReportError::Taxonomy)?;
            if seen.contains(&line.id.as_str()) {
                return Err(ReportError::DuplicateId {
                    id: line.id.clone(),
                });
            }
            seen.push(&line.id);
        }
        Ok(())
    }

    /// Apply structural redaction (by field name, then by value) and the 512-byte cap to a copy used by the renderers. The
    /// redacted copy keeps every JSON type intact, so the JSON stays parseable (review items A-6, A-7 and R-12). Redaction is
    /// applied to field **values before serialisation**, never by replacing strings over the finished JSON document: a
    /// registered secret that happens to be a substring of a hash, an id or the word `pass` cannot corrupt the document.
    fn sanitized(&self) -> Report {
        let mut copy = Report {
            redactor: Redactor::new(),
            ..self.clone()
        };
        // Review item N-5: the `config_revision` is a control-plane value and is redacted like every other rendered string.
        copy.config_revision = self.redactor.redact(&self.config_revision);
        for block in &mut copy.evidence {
            block.check = self.redactor.redact(&block.check);
            for (name, value) in &mut block.fields {
                if EvidenceBlock::is_secret_field(name) {
                    *value = "[REDACTED]".to_owned();
                } else {
                    *name = self.redactor.redact(name);
                    let redacted = self.redactor.redact(value);
                    *value = truncate_utf8(&redacted, EVIDENCE_VALUE_MAX);
                }
            }
        }
        for log in &mut copy.logs {
            log.path = self.redactor.redact(&log.path);
            log.tail = cap_tail_lines(&self.redactor.redact(&log.tail));
        }
        for note in &mut copy.notes {
            *note = self.redactor.redact(note);
        }
        for audit in &mut copy.invalid_audit {
            *audit = self.redactor.redact(audit);
        }
        for line in &mut copy.lines {
            line.title = self.redactor.redact(&line.title);
            line.tier = self.redactor.redact(&line.tier);
            if let Some(detail) = &mut line.detail {
                *detail = self.redactor.redact(detail);
            }
            if let Verdict::Fail { reason } = &mut line.verdict {
                *reason = self.redactor.redact(reason);
            }
            // Review item N-5: an evidence reference's path is rendered in the JSON, so it goes through the redactor too.
            line.evidence = line
                .evidence
                .iter()
                .map(|artifact| {
                    EvidenceRef::new(
                        self.redactor.redact(artifact.path()),
                        artifact.sha256().to_owned(),
                        artifact.bytes(),
                    )
                })
                .collect();
        }
        copy
    }

    /// Render the report as Markdown, one status row per check id.
    pub fn render_markdown(&self) -> Result<String, ReportError> {
        self.validate()?;
        let sanitized = self.sanitized();
        let counts = sanitized.counts();
        let mut out = String::new();
        out.push_str("# Acceptance report\n\n");
        out.push_str("| Field | Value |\n| --- | --- |\n");
        out.push_str(&format!("| Generated | {} |\n", sanitized.generated_at));
        out.push_str(&format!("| Mode | {} |\n", sanitized.mode));
        out.push_str(&format!("| Stage | {} |\n", sanitized.stage));
        out.push_str(&format!("| Load profile | {} |\n", sanitized.load_profile));
        out.push_str(&format!("| Vantages | {} |\n\n", sanitized.vantage_count));
        out.push_str(&format!(
            "## Summary\n\n{} checks: {} PASS, {} FAIL, {} UNVERIFIED\n\n",
            counts.total(),
            counts.pass,
            counts.fail,
            counts.unverified
        ));
        out.push_str("## Checks\n\n| ID | Tier | Status | Title |\n| --- | --- | --- | --- |\n");
        for line in &sanitized.lines {
            let status = match &line.detail {
                Some(detail) => format!("{} — {}", line.verdict, md_inline(detail)),
                None => line.verdict.to_string(),
            };
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                line.id,
                md_cell(&line.tier),
                md_cell(&status),
                md_cell(&line.title)
            ));
        }
        out.push('\n');
        if !sanitized.evidence.is_empty() {
            out.push_str("## Evidence\n\n");
            for block in &sanitized.evidence {
                out.push_str(&format!(
                    "### {} / {}\n\n",
                    md_inline(&block.check),
                    block.kind.as_str()
                ));
                for (name, value) in &block.fields {
                    out.push_str(&format!("- {}: {}\n", md_inline(name), md_inline(value)));
                }
                out.push('\n');
            }
        }
        if !sanitized.logs.is_empty() {
            out.push_str("## Logs\n\n");
            for log in &sanitized.logs {
                let fence = fence_for(&log.tail);
                out.push_str(&format!(
                    "- {} ({} bytes, sha256 `{}`)\n\n{fence}text\n{}\n{fence}\n\n",
                    md_code(&log.path),
                    log.bytes,
                    log.sha256,
                    log.tail
                ));
            }
        }
        if !sanitized.invalid_audit.is_empty() {
            out.push_str("## Run invalid\n\n");
            for audit in &sanitized.invalid_audit {
                out.push_str(&format!("- {}\n", md_inline(audit)));
            }
            out.push('\n');
        }
        if !sanitized.notes.is_empty() {
            out.push_str("## Notes\n\n");
            for note in &sanitized.notes {
                out.push_str(&format!("- {}\n", md_inline(note)));
            }
            out.push('\n');
        }
        let out = out.trim_end_matches('\n').to_owned() + "\n";
        Ok(out)
    }

    /// Render the report as JSON.
    pub fn render_json(&self) -> Result<String, ReportError> {
        self.validate()?;
        let sanitized = self.sanitized();
        // No string replacement over the finished document (review item R-12): redaction already happened on field values
        // before serialisation, so a secret that is a substring of a hash, an id or a keyword cannot corrupt it.
        serde_json::to_string_pretty(&sanitized).map_err(|e| ReportError::Serialize {
            message: e.to_string(),
        })
    }

    /// Parse a report from JSON (bounded, refuses unknown fields).
    pub fn from_json(text: &str) -> Result<Report, ReportError> {
        if text.len() > MAX_REPORT_BYTES {
            return Err(ReportError::TooLarge { bytes: text.len() });
        }
        serde_json::from_str(text).map_err(|e| ReportError::Parse {
            message: e.to_string(),
        })
    }

    /// Merge a previous run's report into this one for `--resume` (spec 2.8 step 5 / T-0492 step 5): a check that already
    /// ended `PASS` with hash-backed evidence keeps that line (and its evidence), everything else is taken fresh.
    ///
    /// Review items R-2 and S-5: the previous report is only accepted when it is bound to the same mode, stage, load profile,
    /// `config_revision` and target host names, is at most [`MAX_RESUME_AGE_SECS`] old and not dated in the future, was not
    /// marked invalid, and every evidence file it references lives inside `resume_dir` and still hashes to the recorded
    /// SHA-256. **The binding fields are self-asserted JSON and there is no MAC**: the guarantee is against a stale report or
    /// an accidentally edited one, not against a deliberate forger.
    ///
    /// This is the **only** resume selection path (review item N-3: the executor uses the same [`select_resumed_lines`]).
    /// When `copy_dir` is given the verified evidence is copied into the new run directory and the line points at the copy, so
    /// the new run is self-contained and can itself be resumed (review item N-4).
    pub fn resume_with(
        mut self,
        previous: &Report,
        resume_dir: &Path,
        copy_dir: Option<&Path>,
    ) -> Result<Report, ReportError> {
        let selected = select_resumed_lines(previous, &self.binding(), resume_dir, copy_dir)?;
        let mut reused = 0usize;
        for selected_line in selected {
            let timestamp = resumed_line_timestamp(previous, &selected_line.id);
            if let Some(line) = self
                .lines
                .iter_mut()
                .find(|line| line.id == selected_line.id)
            {
                *line = selected_line;
                self.line_timestamps.insert(line.id.clone(), timestamp);
                reused += 1;
            }
        }
        self.notes.push(format!(
            "resumed from a previous run: {reused} PASS line(s) reused after re-hashing their evidence inside the resume \
             directory; every other check was run again (AC-00 always re-runs)"
        ));
        Ok(self)
    }

    /// The self-asserted facts a resume compares (mode, stage, load profile, config revision and target host names).
    pub fn binding(&self) -> RunBinding {
        RunBinding {
            mode: self.mode.clone(),
            stage: self.stage.clone(),
            load_profile: self.load_profile.clone(),
            config_revision: self.config_revision.clone(),
            target_hostnames: self.target_hostnames.clone(),
        }
    }
}

/// The binding a resume compares. These values are **self-asserted JSON fields** (review item S-5): there is no MAC, so this
/// detects a stale report, a report from another run shape or an accidentally edited report, not a deliberate forgery by
/// someone who can rewrite the JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunBinding {
    /// `live` or `lab`.
    pub mode: String,
    /// `pilot` or `production`.
    pub stage: String,
    /// Rate/load profile of the run.
    pub load_profile: String,
    /// The control plane revision the run planned against.
    pub config_revision: String,
    /// The target host names derived from the profile.
    pub target_hostnames: Vec<String>,
}

/// The single resume validation path (review items R-2 and S-5), used by [`Report::resume_with`] and by the executor's
/// `set_resume`, so the two cannot drift.
pub fn validate_resume(
    previous: &Report,
    binding: &RunBinding,
    resume_dir: &Path,
) -> Result<(), ReportError> {
    if binding.mode != previous.mode
        || binding.stage != previous.stage
        || binding.load_profile != previous.load_profile
    {
        return Err(ReportError::ResumeMismatch {
            detail: format!(
                "previous report is mode={} stage={} profile={}, this run is mode={} stage={} profile={}",
                previous.mode,
                previous.stage,
                previous.load_profile,
                binding.mode,
                binding.stage,
                binding.load_profile
            ),
        });
    }
    if previous.run_invalid {
        return Err(ReportError::ResumeMismatch {
            detail: "the previous run was marked invalid by a safety-envelope denial; it cannot be resumed (review item \
                     S-5)"
                .to_owned(),
        });
    }
    if !previous.has_resume_binding() {
        return Err(ReportError::ResumeMismatch {
            detail: "the previous report carries no config_revision and target-hostnames binding, so it cannot be verified \
                     for resume (review item R-2)"
                .to_owned(),
        });
    }
    if binding.config_revision.trim().is_empty() || binding.target_hostnames.is_empty() {
        return Err(ReportError::ResumeMismatch {
            detail: "this run has no config_revision and target-hostnames binding; run with --config-revision and a live \
                     profile before resuming"
                .to_owned(),
        });
    }
    if previous.config_revision != binding.config_revision {
        return Err(ReportError::ResumeMismatch {
            detail: format!(
                "the previous report planned against config_revision `{}`, this run against `{}`",
                previous.config_revision, binding.config_revision
            ),
        });
    }
    let mut previous_hosts = previous.target_hostnames.clone();
    previous_hosts.sort();
    let mut current_hosts = binding.target_hostnames.clone();
    current_hosts.sort();
    if previous_hosts != current_hosts {
        return Err(ReportError::ResumeMismatch {
            detail: format!(
                "the previous report targeted hosts {previous_hosts:?}, this run targets {current_hosts:?}"
            ),
        });
    }
    let delta = report_age_delta_secs(&previous.generated_at).ok_or_else(|| {
        ReportError::ResumeMismatch {
            detail: format!(
                "the previous report's timestamp `{}` is not a valid UTC stamp, so its age cannot be bounded (review \
                 item R-2)",
                previous.generated_at
            ),
        }
    })?;
    if delta < -(MAX_RESUME_FUTURE_SKEW_SECS as i64) {
        return Err(ReportError::ResumeMismatch {
            detail: format!(
                "the previous report is dated {} s in the future (more than the {} s clock skew); refusing to trust it \
                 (review item S-5)",
                -delta, MAX_RESUME_FUTURE_SKEW_SECS
            ),
        });
    }
    if delta > MAX_RESUME_AGE_SECS as i64 {
        return Err(ReportError::ResumeMismatch {
            detail: format!(
                "the previous report is {delta} s old, older than the {MAX_RESUME_AGE_SECS} s resume limit; every check \
                 must run again (review item R-2)"
            ),
        });
    }
    // Every PASS line must still be backed inside the resume directory before any of them is reused.
    for line in previous.lines.iter().filter(|line| line.verdict.is_pass()) {
        verified_evidence_inside(resume_dir, &line.evidence)?;
    }
    Ok(())
}

/// How far in the future a previous report may be dated before a resume refuses it (review item S-5: clock skew).
pub const MAX_RESUME_FUTURE_SKEW_SECS: u64 = 300;

/// The **one** resume selection function (review items N-3 and N-4), used by [`Report::resume_with`] (the CLI path) and by
/// the executor's `set_resume`. It validates the resume binding, refuses an invalid previous run, applies the age limit to
/// **each line's own timestamp** (a chain of resumes cannot extend it), skips AC-00 (the self-test always re-runs), re-hashes
/// every evidence file inside the resume directory, and - when `copy_dir` is given - copies the verified files into the new
/// run directory and returns references pointing at the copies.
pub fn select_resumed_lines(
    previous: &Report,
    binding: &RunBinding,
    resume_dir: &Path,
    copy_dir: Option<&Path>,
) -> Result<Vec<StatusLine>, ReportError> {
    validate_resume(previous, binding, resume_dir)?;
    let mut selected = Vec::new();
    for line in previous.lines.iter().filter(|line| line.verdict.is_pass()) {
        if line.id == "AC-00" {
            // The safety self-test always runs again (review item S-5/N-3).
            continue;
        }
        check_line_age(previous, &line.id)?;
        let verified = verified_evidence_inside(resume_dir, &line.evidence)?;
        let evidence = match copy_dir {
            Some(dir) => copy_verified_evidence(dir, &verified)?,
            None => verified,
        };
        let mut resumed = line.clone();
        resumed.evidence = evidence;
        selected.push(resumed);
    }
    Ok(selected)
}

/// The timestamp a resumed line keeps: the timestamp the line was first produced at, else the previous report's timestamp.
pub fn resumed_line_timestamp(previous: &Report, id: &str) -> String {
    previous
        .line_timestamps
        .get(id)
        .cloned()
        .unwrap_or_else(|| previous.generated_at.clone())
}

/// Apply the 24 h age limit and the future skew to one line's own timestamp (review item N-4).
fn check_line_age(previous: &Report, id: &str) -> Result<(), ReportError> {
    let stamp = resumed_line_timestamp(previous, id);
    let delta = report_age_delta_secs(&stamp).ok_or_else(|| ReportError::ResumeMismatch {
        detail: format!("the resumed line {id} has an invalid timestamp `{stamp}`"),
    })?;
    if delta < -(MAX_RESUME_FUTURE_SKEW_SECS as i64) {
        return Err(ReportError::ResumeMismatch {
            detail: format!(
                "the resumed line {id} is dated {} s in the future (more than the {} s clock skew)",
                -delta, MAX_RESUME_FUTURE_SKEW_SECS
            ),
        });
    }
    if delta > MAX_RESUME_AGE_SECS as i64 {
        return Err(ReportError::ResumeMismatch {
            detail: format!(
                "the resumed line {id} is {delta} s old, older than the {MAX_RESUME_AGE_SECS} s resume limit; a chain of \
                 resumes cannot extend a PASS (review item N-4)"
            ),
        });
    }
    Ok(())
}

/// Copy already-verified evidence into the new run directory and return references to the copies (review item N-4). Every copy
/// is re-hashed and compared with the verified reference, and an existing file is never overwritten.
pub fn copy_verified_evidence(
    dir: &Path,
    evidence: &[EvidenceRef],
) -> Result<Vec<EvidenceRef>, ReportError> {
    std::fs::create_dir_all(dir).map_err(|error| ReportError::ResumeMismatch {
        detail: format!(
            "cannot create the new run directory {}: {error}",
            dir.display()
        ),
    })?;
    let mut copied = Vec::with_capacity(evidence.len());
    for artifact in evidence {
        let name = Path::new(artifact.path())
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| ReportError::ResumeMismatch {
                detail: format!("evidence path `{}` has no file name", artifact.path()),
            })?;
        safe_evidence_name(name).map_err(|error| ReportError::ResumeMismatch {
            detail: format!("evidence path `{}` is refused: {error}", artifact.path()),
        })?;
        let bytes =
            std::fs::read(artifact.path()).map_err(|error| ReportError::ResumeMismatch {
                detail: format!("cannot read verified evidence `{name}`: {error}"),
            })?;
        let target = dir.join(name);
        write_new(&target, &bytes).map_err(|error| ReportError::ResumeMismatch {
            detail: format!("cannot copy evidence `{name}` into the new run directory: {error}"),
        })?;
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let hash = sha256_hex(&bytes);
        if hash != artifact.sha256() || length != artifact.bytes() {
            return Err(ReportError::ResumeMismatch {
                detail: format!("the copied evidence `{name}` does not match the verified hash"),
            });
        }
        copied.push(EvidenceRef::new(target.display().to_string(), hash, length));
    }
    Ok(copied)
}

/// The age of a `YYYY-MM-DDTHH:MM:SSZ` stamp relative to now, in seconds, signed so a future stamp is negative (review item
/// S-5). `None` when the stamp is not in that exact form or the value is out of range.
fn report_age_delta_secs(stamp: &str) -> Option<i64> {
    let bytes = stamp.as_bytes();
    if bytes.len() != 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || bytes.get(19) != Some(&b'Z')
    {
        return None;
    }
    let field = |start: usize, len: usize| -> Option<i64> {
        let text = stamp.get(start..start + len)?;
        if !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        text.parse().ok()
    };
    let (year, month, day) = (field(0, 4)?, field(5, 2)?, field(8, 2)?);
    let (hour, minute, second) = (field(11, 2)?, field(14, 2)?, field(17, 2)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let days = days_from_civil(year, month as u32, day as u32);
    let secs = days * 86_400 + hour * 3_600 + minute * 60 + second;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    Some(now.saturating_sub(secs))
}

/// Inverse of [`civil_from_days`]: days since 1970-01-01 for a civil date (proleptic Gregorian).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let month = i64::from(month);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Re-read every evidence file a PASS line references and refuse unless it lives inside `dir` and still hashes to the
/// recorded SHA-256 (review items R-2, R-4, S-5). Path containment: the file name is taken from the reference and joined to
/// `dir`, and the canonical parent must be `dir` itself; a `..`, an absolute escape or a symlink out of the directory is
/// refused. Returns references carrying the **verified** path (the canonical path inside `dir`), not the path printed in the
/// previous report, so the consumer cannot be pointed at an unverified file.
pub fn verified_evidence_inside(
    dir: &Path,
    evidence: &[EvidenceRef],
) -> Result<Vec<EvidenceRef>, ReportError> {
    if evidence.is_empty() {
        return Err(ReportError::ResumeMismatch {
            detail: "a PASS line carries no evidence artifact, so there is nothing to re-hash (E3.1 rule 1)".to_owned(),
        });
    }
    let canonical_dir =
        std::fs::canonicalize(dir).map_err(|error| ReportError::ResumeMismatch {
            detail: format!(
                "cannot resolve the evidence directory {}: {error}",
                dir.display()
            ),
        })?;
    let mut verified = Vec::with_capacity(evidence.len());
    for artifact in evidence {
        if !artifact.hash_is_sha256() {
            return Err(ReportError::ResumeMismatch {
                detail: format!(
                    "evidence `{}` has no 64-hex SHA-256, so the PASS is not backed by an artifact",
                    artifact.path()
                ),
            });
        }
        let name = Path::new(artifact.path())
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| ReportError::ResumeMismatch {
                detail: format!("evidence path `{}` has no file name", artifact.path()),
            })?;
        safe_evidence_name(name).map_err(|error| ReportError::ResumeMismatch {
            detail: format!("evidence path `{}` is refused: {error}", artifact.path()),
        })?;
        let candidate = canonical_dir.join(name);
        let canonical =
            std::fs::canonicalize(&candidate).map_err(|error| ReportError::ResumeMismatch {
                detail: format!(
                    "evidence `{name}` is not inside the evidence directory {} ({error})",
                    dir.display()
                ),
            })?;
        if canonical.parent() != Some(canonical_dir.as_path()) {
            return Err(ReportError::ResumeMismatch {
                detail: format!(
                    "evidence `{name}` resolves outside the evidence directory {} (path containment, review item R-2)",
                    dir.display()
                ),
            });
        }
        let bytes = std::fs::read(&canonical).map_err(|error| ReportError::ResumeMismatch {
            detail: format!("cannot read evidence `{name}`: {error}"),
        })?;
        let bytes_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if bytes_len != artifact.bytes() || sha256_hex(&bytes) != artifact.sha256() {
            return Err(ReportError::ResumeMismatch {
                detail: format!(
                    "evidence `{name}` does not match its recorded SHA-256 or size; the previous report was edited or the \
                     artifact changed (review item R-2)"
                ),
            });
        }
        verified.push(EvidenceRef::new(
            canonical.display().to_string(),
            sha256_hex(&bytes),
            bytes_len,
        ));
    }
    Ok(verified)
}

/// Escape a table cell: no raw pipes and no line breaks. Review item S-10: a lone `\r` is a line break in CommonMark
/// (`"x\r## h"` would inject a heading), so both `\n` and `\r` become spaces.
fn md_cell(text: &str) -> String {
    text.replace('|', "\\|").replace(['\n', '\r'], " ")
}

/// Escape inline text so a hostile or accidental value cannot break the Markdown structure (review items R-12, S-10).
fn md_inline(text: &str) -> String {
    text.replace('|', "\\|").replace(['\n', '\r'], " ")
}

/// Render `text` as an inline code span whose fence is longer than any backtick run inside it (review item S-10): a backtick
/// in a log path would otherwise close the code span and let the rest of the path be read as Markdown.
fn md_code(text: &str) -> String {
    let mut longest = 0usize;
    let mut run = 0usize;
    for ch in text.chars() {
        if ch == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    let fence = "`".repeat(longest + 1);
    format!("{fence}{text}{fence}")
}

/// True when a relative evidence file name is safe: no absolute path, no parent/root/prefix component, no separators, no
/// Windows reserved device name and no NTFS alternate data stream (review item R-11).
pub fn safe_evidence_name(name: &str) -> Result<&str, std::io::Error> {
    let invalid = |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, why.to_owned());
    if name.is_empty() {
        return Err(invalid("the evidence file name is empty"));
    }
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(invalid("the evidence file name must be relative"));
    }
    let path = Path::new(name);
    if path.is_absolute() {
        return Err(invalid("the evidence file name must not be absolute"));
    }
    if path.components().count() != 1 {
        return Err(invalid(
            "the evidence file name must be a single file name (no directory components)",
        ));
    }
    match path.components().next() {
        Some(Component::Normal(_)) => {}
        Some(Component::ParentDir) => {
            return Err(invalid("the evidence file name must not contain `..`"));
        }
        Some(Component::RootDir) | Some(Component::Prefix(_)) => {
            return Err(invalid(
                "the evidence file name must not be an absolute path",
            ));
        }
        _ => return Err(invalid("the evidence file name is not a plain file name")),
    }
    if name.contains(':') {
        return Err(invalid(
            "the evidence file name must not contain `:` (an NTFS alternate data stream such as `name:stream` would be \
             written as a stream, not a file)",
        ));
    }
    if name.ends_with(' ') || name.ends_with('.') {
        return Err(invalid(
            "the evidence file name must not end with a space or a dot (Windows silently strips both, so the recorded \
             hash would belong to a different file)",
        ));
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or(name)
        .trim_end_matches(' ')
        .to_ascii_lowercase();
    // Review item S-10: the Windows console device names (`CONIN$`, `CONOUT$`) and the superscript COM/LPT device numbers
    // are reserved too. `name` keeps the `$`, so the stem is compared as-is as well.
    const RESERVED: [&str; 30] = [
        "con", "prn", "aux", "nul", "conin$", "conout$", "com1", "com2", "com3", "com4", "com5",
        "com6", "com7", "com8", "com9", "com¹", "com²", "com³", "lpt1", "lpt2", "lpt3", "lpt4",
        "lpt5", "lpt6", "lpt7", "lpt8", "lpt9", "lpt¹", "lpt²", "lpt³",
    ];
    if RESERVED.contains(&stem.as_str()) || RESERVED.contains(&name.to_ascii_lowercase().as_str()) {
        return Err(invalid(
            "the evidence file name is a Windows reserved device name; the write would succeed without creating a file",
        ));
    }
    Ok(name)
}

/// One recorded write: which check wrote which artifact, in which run, with which hash (review item S-6). The executor uses it
/// to require that a PASS is backed by a file **this check wrote in this run**, not by another check's file or a leftover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRecord {
    /// The check id that wrote the artifact.
    pub check: String,
    /// The run id the artifact was written for.
    pub run_id: String,
    /// The artifact file name.
    pub name: String,
    /// Lowercase hex SHA-256 of the bytes written.
    pub sha256: String,
}

/// A directory of saved evidence (`acceptance-<stamp>/`).
#[derive(Debug, Clone)]
pub struct EvidenceStore {
    dir: PathBuf,
    records: std::sync::Arc<std::sync::Mutex<Vec<EvidenceRecord>>>,
}

impl EvidenceStore {
    /// A store over an existing directory.
    pub fn new(dir: impl Into<PathBuf>) -> EvidenceStore {
        EvidenceStore {
            dir: dir.into(),
            records: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// Create the directory (and parents) and return a store over it.
    pub fn create(dir: impl Into<PathBuf>) -> std::io::Result<EvidenceStore> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(EvidenceStore::new(dir))
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The write records shared with the executor (review item S-6).
    pub fn records(&self) -> std::sync::Arc<std::sync::Mutex<Vec<EvidenceRecord>>> {
        std::sync::Arc::clone(&self.records)
    }

    /// Save an artifact written by `check` for `run` and record `(check, run, name, hash)`. The name is sanitised first: an
    /// absolute path, a `..` component, a Windows reserved device name or a stream is refused (review items A-11, R-11), and
    /// an existing file is **not** overwritten.
    pub fn save_for(
        &self,
        check: &str,
        run: &str,
        name: &str,
        bytes: &[u8],
    ) -> std::io::Result<EvidenceRef> {
        let reference = self.save(name, bytes)?;
        let mut records = match self.records.lock() {
            Ok(records) => records,
            Err(poisoned) => poisoned.into_inner(),
        };
        records.push(EvidenceRecord {
            check: check.to_owned(),
            run_id: run.to_owned(),
            name: name.to_owned(),
            sha256: sha256_hex(bytes),
        });
        Ok(reference)
    }

    /// Save an artifact and return its reference with the SHA-256 of the saved bytes. The name is sanitised first: an
    /// absolute path, a `..` component, a Windows reserved device name or a stream is refused (review items A-11, R-11), and
    /// an existing file is **not** overwritten: a run never silently replaces evidence it or another run already wrote.
    pub fn save(&self, name: &str, bytes: &[u8]) -> std::io::Result<EvidenceRef> {
        let name = safe_evidence_name(name)?;
        let path = self.dir.join(name);
        write_new(&path, bytes)?;
        Ok(EvidenceRef::new(
            path.display().to_string(),
            sha256_hex(bytes),
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        ))
    }

    /// Save a full log redacted, hash the saved bytes and embed the redacted tail. The name is sanitised first and an
    /// existing file is not overwritten (review items A-11, R-11).
    pub fn save_log(&self, name: &str, text: &str, redactor: &Redactor) -> std::io::Result<LogRef> {
        let name = safe_evidence_name(name)?;
        let redacted = cap_tail_lines(&redactor.redact(text));
        let bytes = redacted.as_bytes();
        let path = self.dir.join(name);
        write_new(&path, bytes)?;
        Ok(LogRef {
            path: path.display().to_string(),
            sha256: sha256_hex(bytes),
            bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            tail: tail_lines(&redacted, LOG_TAIL_LINES),
        })
    }
}

/// Write a new file, refusing to overwrite an existing one (review item R-11: `EvidenceStore::save` silently overwrote and
/// recorded a hash for a file it replaced).
fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(test)]
mod tests;
