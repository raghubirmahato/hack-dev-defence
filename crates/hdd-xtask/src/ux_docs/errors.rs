//! `ux-docs` checks for T-0020 (error-handling UX model and visitor-facing error philosophy).
//!
//! The model document is `docs/UX/ERRORS.md`; the new copy it needs is `i18n/en/errors.ftl`. The rules this module
//! enforces, stated here because the module is what makes the document testable:
//!
//! * the document has the sections the task names (class matrix, classification, pattern selection, request id and
//!   Ray ID, retry and idempotency, visitor pages, visitor constraints, offline behaviour, job failures, logging,
//!   accessibility, security, journey coverage, copy inventory);
//! * the nine classes of T-0020 step 1 are mapped to patterns from the five-pattern vocabulary, each with the place
//!   it appears, when it clears, its focus behaviour and an example `ERR-` code that exists in B7, is classified as
//!   that class and whose family and HTTP status fit the class (A1; review lesson 3: a borrowed code that exists but
//!   does not fit is a defect); review D-1 adds the explicit authentication row (a named subset of the permission
//!   family) and the check fails when a code's class differs between the matrix, the classification tables and the
//!   journey-coverage table;
//! * the conflict class is reserved for version and key conflicts (review D-2): every other 409 code is an exception
//!   with a recorded `Why`, and the reload control appears only for the reviewed conflict codes;
//! * pattern selection is a numbered set of decision rules that orders the nine classes and names the five patterns,
//!   and a pattern-copy table names the copy key of every pattern;
//! * the HTTP-status classification table and the exception table written in the document are exactly the reviewed
//!   ones this module applies, and every `ERR-` code cited by the document exists in B7 (whole token);
//! * the journey error-path coverage table names exactly the codes that the `Error path` column of the delivered
//!   journeys cite, each under the class the rules assign, so a class change in the model or a new code in a journey
//!   cannot silently drift (cross-document rule);
//! * the request-id section names `request_id` on API errors, the Ray ID shape `[0-9a-f]{16}-HDD1`, the copy
//!   affordance, the real support lookups of B6 and the values that are never shown;
//! * the retry and idempotency table classifies real B6 actions by method, names a real B6 `METHOD path` pair for
//!   every row, marks POST creates and job triggers as requiring `Idempotency-Key`, updates as requiring `If-Match`
//!   and states `Retry-After` for 429 (A3, B6.1); the background-poll table bounds every poll with an interval, a
//!   capped backoff and a stop condition;
//! * the visitor pages S-140 to S-148 each appear once with their real B12.1 name, a status, an optional real B7
//!   code whose status must match, copy keys that resolve and an `Accept: application/json` policy; S-140 carries the
//!   Ray ID and the `access_denied` JSON body of B12.2, S-144 is a neutral 404 and S-148 names no tenant detail (A2);
//! * the visitor-page constraints are numbered, testable statements that each name how a test detects a violation,
//!   and the copy values of the pages those statements govern are scanned for rule names, stack traces, internal
//!   hostnames, blame and tenant variables;
//! * offline and flaky-network behaviour is a numbered, testable set that keeps the last confirmed values on screen,
//!   keeps a retry affordance, never fails silently and never re-sends a mutation automatically;
//! * long-running job failures surface as a notification, an inline status and an event reference; client-side
//!   logging is nothing and server-side logging is structured with a request id and no body or PII (A2, R-25);
//! * the accessibility section states focus, `role="alert"` and text-not-colour behaviour per pattern, names
//!   components that exist in B11.8 and criteria that exist in B11.11, and points at `ACCESSIBILITY.md` and
//!   `SECURITY-UX.md` (A4);
//! * every copy key the document cites is defined exactly once in B13, the copy deck or `errors.ftl`, its quoted
//!   text is exact, `errors.ftl` passes the key-shape, markup, duplicate-value and claims rules, and no document or
//!   copy value carries a forbidden claims phrase (A1, R-10);
//! * the security notes cover enumeration, stack traces and the R-20 rule that a cross-tenant read is the neutral
//!   404 `ERR-PERM-002`, never a 403 that would reveal existence.
//!
//! Whole-token matching is used for every id and key. Malformed or missing input produces a finding, never a panic:
//! no indexing, no `unwrap`, no `expect` outside tests.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use regex::Regex;

use crate::claims;
use crate::util::{Finding, read_text, walk_files};

use super::{cells, column, section_body, section_table, subsection_body};

/// The T-0020 model document.
pub const ERRORS: &str = "docs/UX/ERRORS.md";
/// The copy keys the model needs that B13 does not define.
pub const ERRORS_COPY: &str = "i18n/en/errors.ftl";
/// The shipped copy deck (B13 mirrored to Fluent).
pub const COPY_DECK: &str = "i18n/en/copy-deck.ftl";
/// The journey-map directory.
pub const JOURNEYS: &str = "docs/UX/journeys";

/// The nine error classes of T-0020 step 1, in the task's order.
pub const CLASSES: [&str; 9] = [
    "validation",
    "permission",
    "not found",
    "conflict",
    "rate limit",
    "quota",
    "upstream",
    "system",
    "maintenance",
];

/// The authentication row added by review D-1: a named subset of the permission family whose errors ask the person to
/// authenticate, verify or re-authenticate, so it carries its own patterns and focus rule instead of inheriting the
/// permission page/banner rule.
pub const AUTHENTICATION: &str = "authentication";

/// Every class row the matrix and the coverage table carry: the nine task classes plus the authentication row.
pub const ROW_CLASSES: [&str; 10] = [
    "validation",
    "permission",
    "authentication",
    "not found",
    "conflict",
    "rate limit",
    "quota",
    "upstream",
    "system",
    "maintenance",
];

/// The five UI patterns of T-0020 step 1.
pub const PATTERNS: [&str; 5] = ["inline", "summary", "toast", "banner", "page"];

/// The patterns each class must be mapped to (the first entry is its primary pattern). Validation also allows a
/// banner for the acknowledgement of a change that would affect recent traffic (ERR-APIDISC-002, review D-2).
const CLASS_PATTERNS: [(&str, &[&str]); 10] = [
    ("validation", &["inline", "summary", "banner"]),
    ("permission", &["page", "banner"]),
    ("authentication", &["inline", "summary", "page", "banner"]),
    ("not found", &["page"]),
    ("conflict", &["banner", "toast"]),
    ("rate limit", &["banner", "toast"]),
    ("quota", &["page", "banner"]),
    ("upstream", &["page", "banner"]),
    ("system", &["page", "toast"]),
    ("maintenance", &["page", "banner"]),
];

/// The `ERR-` families that may stand as the class's example (review lesson 3: the family must fit the class).
const EXAMPLE_FAMILIES: [(&str, &[&str]); 10] = [
    ("validation", &["VAL"]),
    ("permission", &["PERM"]),
    ("authentication", &["AUTH"]),
    ("not found", &["PERM", "BAN", "APPEAL"]),
    ("conflict", &["CONC", "IDEMP"]),
    ("rate limit", &["RATE"]),
    ("quota", &["RATE"]),
    ("upstream", &["ORIGIN", "ACME", "HOOK"]),
    ("system", &["SYS"]),
    ("maintenance", &["SYS"]),
];

/// The HTTP statuses that may stand as the class's example.
const CLASS_STATUSES: [(&str, &[u16]); 10] = [
    ("validation", &[400, 413, 415, 422]),
    ("permission", &[401, 403]),
    ("authentication", &[401, 403]),
    ("not found", &[404, 421]),
    ("conflict", &[409, 412, 428]),
    ("rate limit", &[429]),
    ("quota", &[409, 422, 429]),
    ("upstream", &[502, 503, 504]),
    ("system", &[500, 503]),
    ("maintenance", &[503]),
];

/// The default class of a B7 HTTP status. Every status the master B7 catalog uses has a row.
pub const STATUS_CLASS: [(&str, &str); 16] = [
    ("400", "validation"),
    ("413", "validation"),
    ("415", "validation"),
    ("422", "validation"),
    ("401", "permission"),
    ("403", "permission"),
    ("404", "not found"),
    ("421", "not found"),
    ("409", "conflict"),
    ("412", "conflict"),
    ("428", "conflict"),
    ("429", "rate limit"),
    ("500", "system"),
    ("503", "system"),
    ("502", "upstream"),
    ("504", "upstream"),
];

/// The codes review D-1 names as authentication: the credential, session, verification and step-up errors whose
/// remedy is to authenticate or verify, with inline+summary for credential mistakes and page/banner for a required
/// step. The remaining 401/403 codes stay in the permission class.
pub const AUTHENTICATION_CODES: [&str; 9] = [
    "ERR-AUTH-001",
    "ERR-AUTH-002",
    "ERR-AUTH-003",
    "ERR-AUTH-005",
    "ERR-AUTH-006",
    "ERR-AUTH-007",
    "ERR-AUTH-008",
    "ERR-AUTH-012",
    "ERR-GATE-001",
];

/// The reviewed code-level refinements of the status default. Each entry must refine its status default, so it can
/// never be used to move a code to an unrelated class without a recorded reason. Review D-1 (authentication) and
/// review D-2 (the 409 causes that are not a version or key conflict) are folded in here.
pub const EXCEPTIONS: [(&str, &str); 39] = [
    ("ERR-AUTH-001", "authentication"),
    ("ERR-AUTH-002", "authentication"),
    ("ERR-AUTH-003", "authentication"),
    ("ERR-AUTH-005", "authentication"),
    ("ERR-AUTH-006", "authentication"),
    ("ERR-AUTH-007", "authentication"),
    ("ERR-AUTH-008", "authentication"),
    ("ERR-AUTH-012", "authentication"),
    ("ERR-GATE-001", "authentication"),
    ("ERR-AUTH-017", "validation"),
    ("ERR-ORG-001", "validation"),
    ("ERR-ORG-003", "validation"),
    ("ERR-ORG-004", "validation"),
    ("ERR-DOM-002", "validation"),
    ("ERR-DOM-004", "upstream"),
    ("ERR-DOM-005", "system"),
    ("ERR-DOM-007", "upstream"),
    ("ERR-DNS-002", "validation"),
    ("ERR-DNS-005", "validation"),
    ("ERR-TLS-005", "upstream"),
    ("ERR-ACME-005", "upstream"),
    ("ERR-WAF-006", "maintenance"),
    ("ERR-BAN-002", "permission"),
    ("ERR-PLAT-002", "permission"),
    ("ERR-LOCAL-001", "system"),
    ("ERR-GATE-004", "permission"),
    ("ERR-SENT-002", "validation"),
    ("ERR-BYPASS-001", "upstream"),
    ("ERR-APIDISC-002", "validation"),
    ("ERR-ACME-002", "upstream"),
    ("ERR-BAN-004", "quota"),
    ("ERR-DNS-007", "quota"),
    ("ERR-DOM-006", "quota"),
    ("ERR-KEY-001", "permission"),
    ("ERR-ORG-005", "permission"),
    ("ERR-RATE-002", "quota"),
    ("ERR-SYS-003", "maintenance"),
    ("ERR-SYS-004", "maintenance"),
    ("ERR-WAF-007", "permission"),
];

/// The only codes that keep the conflict class by their status default: a version conflict, a replayed idempotency
/// key or a single-flight duplicate operation. Every other 409 code is an exception with a recorded cause (review
/// D-2), and the reload control belongs to these codes only.
const CONFLICT_DEFAULTS: [&str; 6] = [
    "ERR-CONC-001",
    "ERR-CONC-002",
    "ERR-IDEMP-001",
    "ERR-ACME-001",
    "ERR-WAF-004",
    "ERR-PLAT-003",
];

/// The copy key of each pattern (the page pattern has two keys; both are required).
const PATTERN_KEYS: [(&str, &[&str]); 5] = [
    ("inline", &["error-validation-inline"]),
    ("summary", &["error-summary-title"]),
    ("toast", &["error-toast-retry"]),
    ("banner", &["error-banner-persistent"]),
    ("page", &["error-page-title", "error-page-body"]),
];

/// Copy keys each model section must name (the copy inventory must define exactly the used keys).
const SECTION_KEYS: [(&str, &[&str]); 4] = [
    (
        "Request ID and Ray ID",
        &[
            "error-request-id-label",
            "error-ray-id-label",
            "error-copy-ray-id",
            "error-copy-request-id",
        ],
    ),
    ("Retry and idempotency", &["error-retry-action"]),
    (
        "Offline and flaky networks",
        &[
            "error-offline-banner",
            "error-reconnect-status",
            "error-stale-partial",
        ],
    ),
    (
        "Long-running job failures",
        &["error-job-failed-inline", "error-job-failed-notification"],
    ),
];

/// The visitor-facing pages of B12.1.
pub const VISITOR_PAGES: [&str; 9] = [
    "S-140", "S-141", "S-142", "S-143", "S-144", "S-145", "S-146", "S-147", "S-148",
];

/// Sections the model document must carry, with the minimum number of numbered testable statements each rule set
/// needs.
const REQUIRED_SECTIONS: [&str; 16] = [
    "Class and pattern matrix",
    "Classification rules",
    "Classification exceptions",
    "Authentication class",
    "Pattern selection",
    "Request ID and Ray ID",
    "Retry and idempotency",
    "Visitor pages S-140 to S-148",
    "Visitor page constraints",
    "Offline and flaky networks",
    "Long-running job failures",
    "Logging of errors",
    "Accessibility of errors",
    "Security notes",
    "Journey error-path coverage",
    "Copy inventory",
];

/// The words a visitor-facing string must never contain (a rule name or a detection detail).
const RULE_WORDS: [&str; 8] = [
    "rule",
    "signature",
    "paranoia",
    "subtype",
    "modsecurity",
    "crs",
    "threshold",
    "rule id",
];

/// The words that would expose a stack trace or an internals detail.
const TRACE_WORDS: [&str; 7] = [
    "stack trace",
    "backtrace",
    "panicked",
    "rust_backtrace",
    "os error",
    "exception",
    ".rs:",
];

/// The words that would expose an internal hostname or a dependency.
const INTERNAL_WORDS: [&str; 9] = [
    "internal host",
    "internal hostname",
    "localhost",
    "127.0.0.1",
    "::1",
    ".internal",
    "postgres",
    "redis",
    "kubernetes",
];

/// The words that would blame the visitor or repeat the payload.
const BLAME_WORDS: [&str; 5] = [
    "your fault",
    "you caused",
    "you are banned",
    "illegal",
    "matched payload",
];

/// The tenant variables and words a neutral page must not carry (S-144, S-148).
const TENANT_WORDS: [&str; 7] = [
    "tenant",
    "organisation",
    "organization",
    "$org",
    "$tenant",
    "$domain",
    "$brand",
];

/// Shape of a semantic hyphenated i18n key.
const KEY_SHAPE: &str = r"^[a-z0-9]+(-[a-z0-9]+)*$";

/// Shape of one `ERR-` code token.
const ERR_SHAPE: &str = r"^ERR-[A-Z]+-[0-9]{3}$";

/// One catalog row of B7.
struct CatalogEntry {
    /// HTTP status.
    status: u16,
    /// The `ERR-` family (`VAL`, `PERM`, `VISITOR`, ...).
    family: String,
}

/// One row of the class and pattern matrix.
struct ClassRow {
    /// 1-based line number.
    line: usize,
    /// The `Class` cell, lower case.
    class: String,
    /// The `Patterns` cell split on commas, lower case.
    patterns: Vec<String>,
    /// The `Where it appears` cell.
    location: String,
    /// The `Clears` cell.
    clears: String,
    /// The `Focus` cell.
    focus: String,
    /// The `Example` cell.
    example: String,
}

/// One row of the visitor-page table.
struct PageRow {
    /// 1-based line number.
    line: usize,
    /// The `S-nnn` id.
    id: String,
    /// The `Name` cell.
    name: String,
    /// The `Status` cell as parsed status numbers.
    statuses: Vec<u16>,
    /// The `B7 code` cell as `ERR-` tokens.
    codes: Vec<String>,
    /// The `B7 code` cell, raw.
    code_cell: String,
    /// The backticked copy keys of the `Copy keys` cell.
    keys: Vec<String>,
    /// The `JSON variant` cell.
    json: String,
}

/// One row of the retry and idempotency table.
struct RetryRow {
    /// 1-based line number.
    line: usize,
    /// The `User action` cell.
    action: String,
    /// The HTTP method.
    method: String,
    /// The `B6 row` cell.
    b6: String,
    /// The `Retry` cell.
    retry: String,
    /// The `Idempotency-Key` cell.
    key: String,
    /// The `Precondition` cell.
    precondition: String,
}

/// One message of a Fluent file.
struct Message {
    /// 1-based line number.
    line: usize,
    /// The key on the left of `=`.
    key: String,
    /// The value on the right of `=`, trimmed.
    value: String,
}

/// A `ux-docs` finding at `location`.
fn at(location: impl Into<String>, message: impl Into<String>) -> Finding {
    Finding::new("ux-docs", location, message)
}

/// True when `text` contains `token` as a whole word (case-insensitive).
fn has_token(text: &str, token: &str) -> bool {
    Regex::new(&format!(r"(?i)\b{}\b", regex::escape(token))).is_ok_and(|re| re.is_match(text))
}

/// True when any of `tokens` is present as a whole word.
fn has_any(text: &str, tokens: &[&str]) -> bool {
    tokens.iter().any(|token| has_token(text, token))
}

/// True when `text` contains `phrase` with non-word characters around it (case-insensitive), so an id or a word is
/// never satisfied by a substring of a longer word (review lesson 1).
fn has_phrase(text: &str, phrase: &str) -> bool {
    let pattern = format!(r"(?i)(^|[^a-z0-9_]){}([^a-z0-9_]|$)", regex::escape(phrase));
    Regex::new(&pattern).is_ok_and(|re| re.is_match(text))
}

/// The numbered list items of a section body whose marker starts with `prefix` (`P-`, `V-`, `O-`, ...). Continuation
/// lines are appended to their item.
fn numbered_items(body: &[(usize, String)], prefix: &str) -> Vec<(u32, String)> {
    let mut out: Vec<(u32, String)> = Vec::new();
    let Ok(re) = Regex::new(&format!(
        r"^\s*(?:[-*+]|\d+\.)\s+{}(\d+)\b",
        regex::escape(prefix)
    )) else {
        return out;
    };
    for (_, line) in body {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('|') || trimmed.starts_with('#') {
            continue;
        }
        if let Some(caps) = re.captures(line) {
            let number = caps
                .get(1)
                .and_then(|m| m.as_str().parse::<u32>().ok())
                .unwrap_or(0);
            let text = caps
                .get(0)
                .map(|m| line.get(m.end()..).unwrap_or("").trim().to_owned())
                .unwrap_or_default();
            out.push((number, text));
            continue;
        }
        if (line.starts_with(' ') || line.starts_with('\t'))
            && let Some((_, text)) = out.last_mut()
            && !has_phrase(text, "Detect:")
        {
            text.push(' ');
            text.push_str(trimmed);
        }
    }
    out
}

/// The joined text of a section body.
fn body_text(body: &[(usize, String)]) -> String {
    body.iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Header cells and body rows of a parsed Markdown table.
type ParsedTable = (Vec<String>, Vec<(usize, Vec<String>)>);

/// The first table of a section body, read through the parent parser (line numbers are relative to the synthetic
/// text, as the other module checks do).
fn table_in_body(body: &[(usize, String)], title: &str) -> Option<ParsedTable> {
    let synthetic = format!("## {title}\n{}\n", body_text(body));
    section_table(&synthetic, title)
}

/// The numbered testable statements of a required section.
fn statement_findings(
    doc: &str,
    section: &str,
    prefix: &str,
    minimum: usize,
) -> (Vec<Finding>, Vec<(u32, String)>, String) {
    let mut out = Vec::new();
    let Some(body) = section_body(doc, section) else {
        out.push(at(
            ERRORS,
            format!("no `## {section}` section (T-0020 deliverable)"),
        ));
        return (out, Vec::new(), String::new());
    };
    let items = numbered_items(&body, prefix);
    if items.len() < minimum {
        out.push(at(
            ERRORS,
            format!(
                "the `## {section}` section has {} `{prefix}n` statements; at least {minimum} are required",
                items.len()
            ),
        ));
    }
    let mut seen = BTreeSet::new();
    for (number, text) in &items {
        if !seen.insert(*number) {
            out.push(at(
                format!("{ERRORS} {section}"),
                format!("the statement `{prefix}{number}` appears more than once"),
            ));
        }
        if !text.contains("Detect:") {
            out.push(at(
                format!("{ERRORS} {section}"),
                format!(
                    "the statement `{prefix}{number}` does not name how a test detects a violation (A2: write `Detect: ...`)"
                ),
            ));
        }
    }
    for expected in 1..=u32::try_from(items.len()).unwrap_or(u32::MAX) {
        if !seen.contains(&expected) {
            out.push(at(
                format!("{ERRORS} {section}"),
                format!("the numbered statements of `{section}` are not contiguous: `{prefix}{expected}` is missing"),
            ));
        }
    }
    let text = body_text(&body);
    (out, items, text)
}

/// Assert that each required word appears in `text` as a whole phrase.
fn required_words(text: &str, location: &str, section: &str, words: &[&str]) -> Vec<Finding> {
    let mut out = Vec::new();
    for word in words {
        if !has_phrase(text, word) {
            out.push(at(
                location.to_owned(),
                format!("the `## {section}` section never names `{word}`"),
            ));
        }
    }
    out
}

/// The `ERR-` candidates of a text, including malformed ones such as `ERR-VAL-001X`, so a malformed citation is a
/// finding instead of a silently ignored token.
fn err_candidates(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(re) = Regex::new(r"\bERR-[A-Za-z0-9_-]+") else {
        return out;
    };
    for found in re.find_iter(text) {
        let token = found.as_str().trim_end_matches('-');
        if !token.is_empty() {
            out.push(token.to_owned());
        }
    }
    out
}

/// The `ERR-` code tokens of a text, whole tokens only.
fn err_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(re) = Regex::new(r"\bERR-[A-Z]+-[0-9]{3}\b") else {
        return out;
    };
    for found in re.find_iter(text) {
        out.push(found.as_str().to_owned());
    }
    out
}

/// The backticked tokens of a cell that look like i18n keys.
fn key_tokens(cell: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(shape) = Regex::new(KEY_SHAPE) else {
        return out;
    };
    for span in cell.split('`').skip(1).step_by(2) {
        let key = span.trim();
        if shape.is_match(key) {
            out.push(key.to_owned());
        }
    }
    out
}

/// The `ERR-` family of a code (`ERR-VAL-001` gives `VAL`).
fn family_of(code: &str) -> Option<String> {
    let rest = code.strip_prefix("ERR-")?;
    let (family, number) = rest.rsplit_once('-')?;
    if family.is_empty() || number.len() != 3 {
        return None;
    }
    Some(family.to_owned())
}

/// The class a code belongs to, from the reviewed exception table and the status default.
fn classify(code: &str, catalog: &BTreeMap<String, CatalogEntry>) -> Option<&'static str> {
    if let Some((_, class)) = EXCEPTIONS.iter().find(|(candidate, _)| *candidate == code) {
        return Some(*class);
    }
    let status = catalog.get(code)?.status;
    status_class(status)
}

/// The default class of one HTTP status.
fn status_class(status: u16) -> Option<&'static str> {
    let wanted = status.to_string();
    STATUS_CLASS
        .iter()
        .find(|(candidate, _)| *candidate == wanted)
        .map(|(_, class)| *class)
}

/// The body lines of every section of the master specification whose heading token starts with `prefix`
/// (`B7.`, `B11.8`, `B6.1`, ...). Unlike the parent [`super::spec_section`] this accumulates every such section,
/// so a fixture can append its own rows to a section the fixture specification already has.
fn spec_sections(spec: &str, prefix: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut inside = false;
    for (n, line) in spec.lines().enumerate() {
        let trimmed = line.trim_start();
        let hashes = trimmed.chars().take_while(|c| *c == '#').count();
        let is_heading = (2..=4).contains(&hashes)
            && trimmed
                .get(hashes..)
                .is_some_and(|rest| rest.starts_with(' '));
        if is_heading {
            let title = trimmed.trim_start_matches('#').trim();
            inside = title.starts_with(prefix);
            continue;
        }
        if inside {
            out.push((n + 1, line.to_owned()));
        }
    }
    out
}

/// The B7 error catalog of the master specification: code to status, title, notes and family.
fn error_catalog(spec: &str) -> BTreeMap<String, CatalogEntry> {
    let mut out = BTreeMap::new();
    let Ok(shape) = Regex::new(ERR_SHAPE) else {
        return out;
    };
    for (_, line) in spec_sections(spec, "B7.") {
        let Some(row) = cells(&line) else {
            continue;
        };
        let Some(code) = row.first() else {
            continue;
        };
        let code = code.trim();
        if !shape.is_match(code) {
            continue;
        }
        let Some(status) = row.get(1).and_then(|cell| cell.trim().parse::<u16>().ok()) else {
            continue;
        };
        let Some(family) = family_of(code) else {
            continue;
        };
        let entry = CatalogEntry { status, family };
        out.entry(code.to_owned()).or_insert(entry);
    }
    out
}

/// The `METHOD path` pairs of the B6 catalog, in the spec's shorthand (`POST O/domains`).
fn b6_pairs(spec: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(method_re) = Regex::new(r"^(GET|HEAD|POST|PUT|PATCH|DELETE)$") else {
        return out;
    };
    for (_, line) in spec_sections(spec, "B6.") {
        let Some(row) = cells(&line) else {
            continue;
        };
        let Some(first) = row.first() else {
            continue;
        };
        let mut last_method: Option<String> = None;
        for span in first.split('`').skip(1).step_by(2) {
            let span = span.trim();
            if span.is_empty() {
                continue;
            }
            let mut words = span.split_whitespace();
            let Some(first_word) = words.next() else {
                continue;
            };
            if method_re.is_match(first_word) {
                let rest = words.collect::<Vec<_>>().join(" ");
                if !rest.is_empty() {
                    out.insert(format!("{} {}", first_word.to_uppercase(), rest));
                }
                last_method = Some(first_word.to_uppercase());
            } else if span.starts_with('/')
                && let Some(method) = last_method.as_ref()
            {
                out.insert(format!("{method} {span}"));
            }
        }
    }
    out
}

/// The text of every B6.1 conventions section of the master specification.
fn b6_conventions(spec: &str) -> String {
    spec_sections(spec, "B6.1")
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The component names of every B11.8 inventory section (`Button / IconButton` gives `Button` and `IconButton`).
fn component_names(spec: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(paren) = Regex::new(r"\([^)]*\)") else {
        return out;
    };
    for (_, line) in spec_sections(spec, "B11.8") {
        let Some(row) = cells(&line) else {
            continue;
        };
        let Some(first) = row.first() else {
            continue;
        };
        let first = first.trim();
        if first.is_empty()
            || first.eq_ignore_ascii_case("component")
            || first.chars().all(|c| c == '-' || c == ':')
        {
            continue;
        }
        let stripped = paren.replace_all(first, "");
        for part in stripped.split('/') {
            let name = part.trim();
            if !name.is_empty() {
                out.insert(name.to_owned());
            }
        }
    }
    out
}

/// The WCAG criteria of every B11.11 section.
fn a11y_criteria(spec: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(re) = Regex::new(r"\b[0-9]+\.[0-9]+\.[0-9]+\b") else {
        return out;
    };
    for (_, line) in spec_sections(spec, "B11.11") {
        for found in re.find_iter(&line) {
            out.insert(found.as_str().to_owned());
        }
    }
    out
}

/// The B12.1 visitor-page rows: `S-14x` to its name.
fn visitor_screens(spec: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(shape) = Regex::new(r"^S-14[0-9]$") else {
        return out;
    };
    for line in spec.lines() {
        let Some(row) = cells(line) else {
            continue;
        };
        let Some(first) = row.first() else {
            continue;
        };
        let id = first.trim();
        if !shape.is_match(id) {
            continue;
        }
        let Some(name) = row.get(1) else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        out.entry(id.to_owned()).or_insert(name.to_owned());
    }
    out
}

/// The `#### S-140` detail section of the master specification (the JSON body of B12.2).
fn s140_detail(spec: &str) -> Option<String> {
    let mut out = String::new();
    let mut inside = false;
    for line in spec.lines() {
        let trimmed = line.trim_start();
        let hashes = trimmed.chars().take_while(|c| *c == '#').count();
        let is_detail = (3..=4).contains(&hashes);
        if is_detail && inside {
            break;
        }
        if is_detail {
            inside = trimmed.trim_start_matches('#').trim().starts_with("S-140 ");
            continue;
        }
        if inside {
            out.push_str(line);
            out.push('\n');
        }
    }
    (!out.is_empty()).then_some(out)
}

/// The B13 copy rows of the master specification.
fn b13_rows(spec: &str) -> Vec<(String, String)> {
    super::content::b13_rows(spec)
}

/// Parse the messages of a Fluent file; comment and blank lines are skipped.
fn parse_ftl(text: &str) -> Vec<Message> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match trimmed.split_once('=') {
            Some((key, value)) => out.push(Message {
                line: n + 1,
                key: key.trim().to_owned(),
                value: value.trim().to_owned(),
            }),
            None => out.push(Message {
                line: n + 1,
                key: String::new(),
                value: trimmed.to_owned(),
            }),
        }
    }
    out
}

/// The first value of each Fluent key.
fn ftl_values(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for message in parse_ftl(text) {
        if message.key.is_empty() {
            continue;
        }
        out.entry(message.key).or_insert(message.value);
    }
    out
}

/// The class and pattern matrix rows.
fn class_rows(doc: &str) -> Vec<ClassRow> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(doc, "Class and pattern matrix") else {
        return out;
    };
    let class = column(&header, "Class");
    let patterns = column(&header, "Patterns");
    let location = column(&header, "Where it appears");
    let clears = column(&header, "Clears");
    let focus = column(&header, "Focus");
    let example = column(&header, "Example");
    for (n, row) in rows {
        let Some(class_cell) = class.and_then(|index| row.get(index)) else {
            continue;
        };
        out.push(ClassRow {
            line: n,
            class: class_cell.trim().to_lowercase(),
            patterns: patterns
                .and_then(|index| row.get(index))
                .map(|cell| {
                    cell.split(',')
                        .map(|part| part.trim().to_lowercase())
                        .filter(|part| !part.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            location: location
                .and_then(|index| row.get(index))
                .map(|cell| cell.trim().to_owned())
                .unwrap_or_default(),
            clears: clears
                .and_then(|index| row.get(index))
                .map(|cell| cell.trim().to_owned())
                .unwrap_or_default(),
            focus: focus
                .and_then(|index| row.get(index))
                .map(|cell| cell.trim().to_owned())
                .unwrap_or_default(),
            example: example
                .and_then(|index| row.get(index))
                .map(|cell| cell.trim().to_owned())
                .unwrap_or_default(),
        });
    }
    out
}

/// The visitor-page table rows.
fn page_rows(doc: &str) -> Vec<PageRow> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(doc, "Visitor pages S-140 to S-148") else {
        return out;
    };
    let page = column(&header, "Page");
    let name = column(&header, "Name");
    let status = column(&header, "Status");
    let code = column(&header, "B7 code");
    let keys = column(&header, "Copy keys");
    let json = column(&header, "JSON variant");
    let Ok(status_numbers) = Regex::new(r"\b[1-5][0-9]{2}\b") else {
        return out;
    };
    for (n, row) in rows {
        let Some(id) = page.and_then(|index| row.get(index)) else {
            continue;
        };
        let id = id.trim().to_owned();
        if id.is_empty() {
            continue;
        }
        let status_cell = status
            .and_then(|index| row.get(index))
            .map(|cell| cell.trim().to_owned())
            .unwrap_or_default();
        let statuses = status_numbers
            .find_iter(&status_cell)
            .filter_map(|found| found.as_str().parse::<u16>().ok())
            .collect();
        let code_cell = code
            .and_then(|index| row.get(index))
            .map(|cell| cell.trim().to_owned())
            .unwrap_or_default();
        out.push(PageRow {
            line: n,
            id,
            name: name
                .and_then(|index| row.get(index))
                .map(|cell| cell.trim().to_owned())
                .unwrap_or_default(),
            statuses,
            codes: err_tokens(&code_cell),
            code_cell,
            keys: keys
                .and_then(|index| row.get(index))
                .map(|cell| key_tokens(cell))
                .unwrap_or_default(),
            json: json
                .and_then(|index| row.get(index))
                .map(|cell| cell.trim().to_owned())
                .unwrap_or_default(),
        });
    }
    out
}

/// The retry and idempotency table rows.
fn retry_rows(doc: &str) -> Vec<RetryRow> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(doc, "Retry and idempotency") else {
        return out;
    };
    let action = column(&header, "User action");
    let method = column(&header, "Method");
    let b6 = column(&header, "B6 row");
    let retry = column(&header, "Retry");
    let key = column(&header, "Idempotency-Key");
    let precondition = column(&header, "Precondition");
    for (n, row) in rows {
        let Some(method_cell) = method.and_then(|index| row.get(index)) else {
            continue;
        };
        let method = method_cell.trim().to_uppercase();
        if method.is_empty() {
            continue;
        }
        out.push(RetryRow {
            line: n,
            action: action
                .and_then(|index| row.get(index))
                .map(|cell| cell.trim().to_owned())
                .unwrap_or_default(),
            method,
            b6: b6
                .and_then(|index| row.get(index))
                .map(|cell| cell.trim().to_owned())
                .unwrap_or_default(),
            retry: retry
                .and_then(|index| row.get(index))
                .map(|cell| cell.trim().to_lowercase())
                .unwrap_or_default(),
            key: key
                .and_then(|index| row.get(index))
                .map(|cell| cell.trim().to_lowercase())
                .unwrap_or_default(),
            precondition: precondition
                .and_then(|index| row.get(index))
                .map(|cell| cell.trim().to_lowercase())
                .unwrap_or_default(),
        });
    }
    out
}

/// The `METHOD path` pair named by a retry row's `B6 row` cell, whole tokens only.
fn b6_cell_pair(cell: &str) -> Option<String> {
    let Ok(method_re) = Regex::new(r"^(GET|HEAD|POST|PUT|PATCH|DELETE)$") else {
        return None;
    };
    for span in cell.split('`').skip(1).step_by(2) {
        let span = span.trim();
        let mut words = span.split_whitespace();
        let Some(first) = words.next() else {
            continue;
        };
        if !method_re.is_match(first) {
            continue;
        }
        let rest = words.collect::<Vec<_>>().join(" ");
        if !rest.is_empty() {
            return Some(format!("{} {}", first.to_uppercase(), rest));
        }
    }
    None
}

/// The `HTTP status -> class` rows stated in the document's classification table.
fn stated_status_classes(doc: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some((header, rows)) = section_table(doc, "Classification rules") else {
        return out;
    };
    let (Some(status_col), Some(class_col)) =
        (column(&header, "HTTP status"), column(&header, "Class"))
    else {
        return out;
    };
    for (_, row) in rows {
        let Some(status) = row
            .get(status_col)
            .and_then(|cell| cell.trim().parse::<u16>().ok())
        else {
            continue;
        };
        let Some(class) = row.get(class_col).map(|cell| cell.trim().to_lowercase()) else {
            continue;
        };
        out.entry(status.to_string()).or_insert(class);
    }
    out
}

/// The `code -> class` rows stated in the document's classification exception table.
fn stated_exceptions(doc: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some((header, rows)) = section_table(doc, "Classification exceptions") else {
        return out;
    };
    let (Some(code_col), Some(class_col)) = (column(&header, "Code"), column(&header, "Class"))
    else {
        return out;
    };
    for (_, row) in rows {
        let Some(code) = row
            .get(code_col)
            .map(|cell| cell.trim().trim_matches('`').trim().to_owned())
        else {
            continue;
        };
        let Some(class) = row.get(class_col).map(|cell| cell.trim().to_lowercase()) else {
            continue;
        };
        if !code.is_empty() {
            out.entry(code).or_insert(class);
        }
    }
    out
}

/// The `code -> class` assignments of the journey error-path coverage table.
fn coverage_classes(doc: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some((header, rows)) = section_table(doc, "Journey error-path coverage") else {
        return out;
    };
    let (Some(class_col), Some(codes_col)) =
        (column(&header, "Class"), column(&header, "Error codes"))
    else {
        return out;
    };
    for (_, row) in rows {
        let Some(class) = row.get(class_col).map(|cell| cell.trim().to_lowercase()) else {
            continue;
        };
        let Some(codes) = row.get(codes_col) else {
            continue;
        };
        for code in err_tokens(codes) {
            out.entry(code).or_insert(class.clone());
        }
    }
    out
}

/// The `example code -> class` assignments of the class and pattern matrix.
fn example_classes(doc: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for row in class_rows(doc) {
        if let Some(code) = err_tokens(&row.example).first() {
            out.entry(code.clone()).or_insert(row.class.clone());
        }
    }
    out
}

/// Findings when a required section is missing or empty.
fn structure_findings(doc: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for title in REQUIRED_SECTIONS {
        match section_body(doc, title) {
            Some(body) if body.iter().any(|(_, line)| !line.trim().is_empty()) => {}
            _ => out.push(at(
                ERRORS,
                format!("no non-empty `## {title}` section (T-0020 step 1 to 8)"),
            )),
        }
    }
    out
}

/// Findings of the class and pattern matrix (T-0020 step 1, A1).
fn class_table_findings(
    doc: &str,
    catalog: &BTreeMap<String, CatalogEntry>,
    components: &BTreeSet<String>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let rows = class_rows(doc);
    if rows.is_empty() {
        out.push(at(
            ERRORS,
            "no `## Class and pattern matrix` table with a Class, Patterns, Where it appears, Clears, Focus and Example column (T-0020 step 1)",
        ));
        return out;
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for row in &rows {
        let loc = format!("{ERRORS}:{}", row.line);
        let Some((_, required_patterns)) = CLASS_PATTERNS
            .iter()
            .find(|(class, _)| *class == row.class.as_str())
        else {
            out.push(at(
                loc,
                format!(
                    "`{}` is not one of the class rows (the nine task classes plus authentication, T-0020 step 1 and D-1)",
                    row.class
                ),
            ));
            continue;
        };
        if !seen.insert(row.class.clone()) {
            out.push(at(
                format!("{ERRORS}:{}", row.line),
                format!("the class `{}` has more than one row", row.class),
            ));
        }
        for pattern in &row.patterns {
            if !PATTERNS.contains(&pattern.as_str()) {
                out.push(at(
                    format!("{ERRORS}:{}", row.line),
                    format!(
                        "`{pattern}` is not one of the five UI patterns (inline, summary, toast, banner, page)"
                    ),
                ));
            }
        }
        for required in *required_patterns {
            if !row.patterns.iter().any(|pattern| pattern == required) {
                out.push(at(
                    format!("{ERRORS}:{}", row.line),
                    format!(
                        "the class `{}` is not mapped to the `{required}` pattern (T-0020 step 1, A1)",
                        row.class
                    ),
                ));
            }
        }
        if row.location.is_empty() {
            out.push(at(
                format!("{ERRORS}:{}", row.line),
                format!("the class `{}` has no `Where it appears` cell", row.class),
            ));
        } else if !components.iter().any(|name| has_token(&row.location, name)) {
            out.push(at(
                format!("{ERRORS}:{}", row.line),
                format!(
                    "the `Where it appears` cell of `{}` names no component of the B11.8 inventory (T-0020 step 1)",
                    row.class
                ),
            ));
        }
        if !has_any(
            &row.clears,
            &["when", "until", "never", "after", "on", "once"],
        ) {
            out.push(at(
                format!("{ERRORS}:{}", row.line),
                format!(
                    "the `Clears` cell of `{}` does not say when it clears (use when, until, never, after or on)",
                    row.class
                ),
            ));
        }
        if !has_token(&row.focus, "focus") {
            out.push(at(
                format!("{ERRORS}:{}", row.line),
                format!(
                    "the `Focus` cell of `{}` does not state a focus behaviour (T-0020 step 8, A4)",
                    row.class
                ),
            ));
        } else {
            let primary = row.patterns.first().map(String::as_str).unwrap_or_default();
            let focus_ok = match primary {
                "page" => has_any(&row.focus, &["heading", "h1"]),
                "banner" => has_token(&row.focus, "banner"),
                "toast" => has_token(&row.focus, "toast"),
                "summary" => has_token(&row.focus, "summary"),
                "inline" => has_any(&row.focus, &["field", "summary"]),
                _ => true,
            };
            if !focus_ok {
                out.push(at(
                    format!("{ERRORS}:{}", row.line),
                    format!(
                        "the `Focus` cell of `{}` does not name the {primary} focus target (T-0020 step 8)"
                    , row.class),
                ));
            }
        }
        let examples = err_tokens(&row.example);
        if examples.len() != 1 {
            out.push(at(
                format!("{ERRORS}:{}", row.line),
                format!(
                    "the class `{}` must name exactly one example `ERR-` code, found {}",
                    row.class,
                    examples.len()
                ),
            ));
            continue;
        }
        let example = examples.first().map(String::as_str).unwrap_or_default();
        let Some(entry) = catalog.get(example) else {
            out.push(at(
                format!("{ERRORS}:{}", row.line),
                format!(
                    "the example `{example}` of the class `{}` is not a row of the B7 error catalog (A1, whole token)",
                    row.class
                ),
            ));
            continue;
        };
        let classified = classify(example, catalog).unwrap_or_default();
        if classified != row.class {
            out.push(at(
                format!("{ERRORS}:{}", row.line),
                format!(
                    "the example `{example}` of the class `{}` is classified as `{classified}` by the model rules (A1: a borrowed code does not fit)"
                , row.class),
            ));
        }
        let status_ok = CLASS_STATUSES
            .iter()
            .find(|(class, _)| *class == row.class.as_str())
            .is_some_and(|(_, statuses)| statuses.contains(&entry.status));
        if !status_ok {
            out.push(at(
                format!("{ERRORS}:{}", row.line),
                format!(
                    "the example `{example}` of the class `{}` has HTTP status {}, which is not one of the class statuses (A1)"
                    , row.class, entry.status),
            ));
        }
        let family_ok = EXAMPLE_FAMILIES
            .iter()
            .find(|(class, _)| *class == row.class.as_str())
            .is_some_and(|(_, families)| families.contains(&entry.family.as_str()));
        if !family_ok {
            out.push(at(
                format!("{ERRORS}:{}", row.line),
                format!(
                    "the example `{example}` of the class `{}` has the family {}, which does not fit the class (A1, review F-12)"
                    , row.class, entry.family),
            ));
        }
    }
    for (class, _) in CLASS_PATTERNS {
        if !seen.contains(class) {
            out.push(at(
                ERRORS,
                format!(
                    "the class `{class}` has no row in the class and pattern matrix (T-0020 step 1)"
                ),
            ));
        }
    }
    out
}

/// Findings of the pattern-selection and pattern-copy rules (T-0020 step 1).
fn pattern_selection_findings(doc: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(body) = section_body(doc, "Pattern selection") else {
        out.push(at(
            ERRORS,
            "no `## Pattern selection` section (T-0020 step 1)",
        ));
        return out;
    };
    let items = numbered_items(&body, "P-");
    if items.len() < 8 {
        out.push(at(
            ERRORS,
            format!(
                "the pattern-selection rules number {} items; at least 8 decision rules are required (T-0020 step 1)",
                items.len()
            ),
        ));
    }
    let mut seen = BTreeSet::new();
    for (number, text) in &items {
        if !seen.insert(*number) {
            out.push(at(
                ERRORS,
                format!("the decision rule `P-{number}` appears more than once"),
            ));
        }
        if text.trim().is_empty() {
            out.push(at(
                ERRORS,
                format!("the decision rule `P-{number}` is empty"),
            ));
        }
    }
    let mut precedence_seen = false;
    for (_, text) in &items {
        if text.to_lowercase().contains("order:") {
            precedence_seen = true;
            for class in ROW_CLASSES {
                if !has_phrase(text, class) {
                    out.push(at(
                        ERRORS,
                        format!(
                            "the precedence rule does not list the class `{class}` (T-0020 step 1: which pattern wins when several classes apply)"
                        ),
                    ));
                }
            }
        }
    }
    if !precedence_seen {
        out.push(at(
            ERRORS,
            "no decision rule states the precedence order of the nine classes (T-0020 step 1)",
        ));
    }
    let section_text = body_text(&body);
    for pattern in PATTERNS {
        if !has_phrase(&section_text, pattern) {
            out.push(at(
                ERRORS,
                format!("the `## Pattern selection` section never names the `{pattern}` pattern"),
            ));
        }
    }
    let Some(sub) = subsection_body(doc, "Pattern selection", "Pattern copy") else {
        out.push(at(
            ERRORS,
            "no `### Pattern copy` table inside `## Pattern selection` (a copy key per pattern)",
        ));
        return out;
    };
    let Some((header, rows)) = table_in_body(&sub, "Pattern copy") else {
        out.push(at(
            ERRORS,
            "the `### Pattern copy` table cannot be read (a Pattern and Copy keys column are required)",
        ));
        return out;
    };
    let pattern_col = column(&header, "Pattern");
    let keys_col = column(&header, "Copy keys");
    let mut covered: BTreeSet<String> = BTreeSet::new();
    for (_, row) in &rows {
        let Some(pattern) = pattern_col
            .and_then(|index| row.get(index))
            .map(|cell| cell.trim().to_lowercase())
        else {
            continue;
        };
        let keys = keys_col
            .and_then(|index| row.get(index))
            .map(|cell| key_tokens(cell))
            .unwrap_or_default();
        let Some((_, required)) = PATTERN_KEYS.iter().find(|(name, _)| *name == pattern) else {
            out.push(at(
                ERRORS,
                format!("the pattern-copy table names `{pattern}`, which is not one of the five patterns"),
            ));
            continue;
        };
        covered.insert(pattern.clone());
        for key in *required {
            if !keys.iter().any(|candidate| candidate == key) {
                out.push(at(
                    ERRORS,
                    format!(
                        "the pattern-copy table does not name the copy key `{key}` for the `{pattern}` pattern"
                    ),
                ));
            }
        }
    }
    for (pattern, _) in PATTERN_KEYS {
        if !covered.contains(pattern) {
            out.push(at(
                ERRORS,
                format!("the pattern-copy table has no `{pattern}` row (T-0020 step 1)"),
            ));
        }
    }
    out
}

/// Findings of the status classification table and the exception table.
fn classification_findings(doc: &str, catalog: &BTreeMap<String, CatalogEntry>) -> Vec<Finding> {
    let mut out = Vec::new();
    let (Ok(shape), Ok(exception_shape)) =
        (Regex::new(ERR_SHAPE), Regex::new(r"^ERR-[A-Z]+-[0-9]{3}$"))
    else {
        return out;
    };
    match section_table(doc, "Classification rules") {
        None => out.push(at(
            ERRORS,
            "no `## Classification rules` table with an HTTP status and a Class column (T-0020 step 1)",
        )),
        Some((header, rows)) => {
            let (Some(status_col), Some(class_col)) = (
                column(&header, "HTTP status"),
                column(&header, "Class"),
            ) else {
                out.push(at(
                    ERRORS,
                    "the classification table has no `HTTP status` and `Class` columns (T-0020 step 1)",
                ));
                return out;
            };
            let mut stated: BTreeMap<String, String> = BTreeMap::new();
            for (n, row) in &rows {
                let Some(status_cell) = row.get(status_col) else {
                    continue;
                };
                let Some(class_cell) = row.get(class_col) else {
                    continue;
                };
                let loc = format!("{ERRORS}:{n}");
                let status = status_cell.trim();
                let Ok(parsed) = status.parse::<u16>() else {
                    out.push(at(
                        loc,
                        format!("`{status}` is not an HTTP status number"),
                    ));
                    continue;
                };
                let class = class_cell.trim().to_lowercase();
                if !CLASSES.contains(&class.as_str()) {
                    out.push(at(
                        loc.clone(),
                        format!("`{class}` is not one of the nine error classes"),
                    ));
                    continue;
                }
                if local_duplicate(&mut stated, &parsed.to_string(), &class) {
                    out.push(at(
                        loc,
                        format!("the HTTP status {parsed} has more than one classification row"),
                    ));
                }
            }
            for (status, class) in STATUS_CLASS {
                match stated.get(status) {
                    Some(stated_class) if stated_class == class => {}
                    Some(stated_class) => out.push(at(
                        ERRORS,
                        format!(
                            "the document classifies HTTP status {status} as `{stated_class}`; the reviewed rule is `{class}`"
                        ),
                    )),
                    None => out.push(at(
                        ERRORS,
                        format!(
                            "the classification table has no row for HTTP status {status} (`{class}`), so a B7 code with that status cannot be classified"
                        ),
                    )),
                }
            }
            for status in stated.keys() {
                if !STATUS_CLASS.iter().any(|(known, _)| known == status) {
                    out.push(at(
                        ERRORS,
                        format!("the classification table has an extra row for HTTP status {status}"),
                    ));
                }
            }
        }
    }
    match section_table(doc, "Classification exceptions") {
        None => out.push(at(
            ERRORS,
            "no `## Classification exceptions` table with Code, Class and Why columns (T-0020 step 1)",
        )),
        Some((header, rows)) => {
            let (Some(code_col), Some(class_col), Some(why_col)) = (
                column(&header, "Code"),
                column(&header, "Class"),
                column(&header, "Why"),
            ) else {
                out.push(at(
                    ERRORS,
                    "the exception table has no `Code`, `Class` and `Why` columns (T-0020 step 1)",
                ));
                return out;
            };
            let mut stated: BTreeMap<String, String> = BTreeMap::new();
            for (n, row) in &rows {
                let Some(code_cell) = row.get(code_col) else {
                    continue;
                };
                let Some(class_cell) = row.get(class_col) else {
                    continue;
                };
                let loc = format!("{ERRORS}:{n}");
                let code = code_cell.trim().trim_matches('`').trim();
                if !exception_shape.is_match(code) {
                    out.push(at(
                        loc,
                        format!("`{code}` is not a whole-token `ERR-` code (the exception table)"),
                    ));
                    continue;
                }
                let class = class_cell.trim().to_lowercase();
                if !ROW_CLASSES.contains(&class.as_str()) {
                    out.push(at(
                        loc.clone(),
                        format!(
                            "`{class}` is not one of the class rows (the nine task classes plus authentication)"
                        ),
                    ));
                    continue;
                }
                let why = row.get(why_col).map(|cell| cell.trim()).unwrap_or_default();
                if why.split_whitespace().count() < 4 {
                    out.push(at(
                        loc.clone(),
                        format!("the exception `{code}` has no reason in its `Why` cell"),
                    ));
                }
                if local_duplicate(&mut stated, code, &class) {
                    out.push(at(
                        loc,
                        format!("the exception `{code}` has more than one row"),
                    ));
                }
            }
            for (code, class) in EXCEPTIONS {
                match stated.get(code) {
                    Some(stated_class) if stated_class == class => {}
                    Some(stated_class) => out.push(at(
                        ERRORS,
                        format!(
                            "the document lists the exception `{code}` as `{stated_class}`; the reviewed class is `{class}`"
                        ),
                    )),
                    None => out.push(at(
                        ERRORS,
                        format!(
                            "the exception table has no row for `{code}` (`{class}`), which the model rules apply"
                        ),
                    )),
                }
            }
            for code in stated.keys() {
                if !EXCEPTIONS.iter().any(|(known, _)| known == code) {
                    out.push(at(
                        ERRORS,
                        format!(
                            "the exception table lists `{code}`, which the model rules do not apply (add it with a test)"
                        ),
                    ));
                }
            }
            for (code, class) in &stated {
                if !shape.is_match(code) || !catalog.contains_key(code) {
                    out.push(at(
                        ERRORS,
                        format!("the exception `{code}` is not a row of the B7 error catalog (whole token)"),
                    ));
                    continue;
                }
                let Some(entry) = catalog.get(code) else {
                    continue;
                };
                if status_class(entry.status) == Some(class.as_str()) {
                    out.push(at(
                        ERRORS,
                        format!(
                            "the exception `{code}` maps to `{class}`, which is already the default of its HTTP status {}, so it refines nothing"
                        , entry.status),
                    ));
                }
            }
        }
    }
    out
}

/// Insert a key into a map and return true when it was already present.
fn local_duplicate(map: &mut BTreeMap<String, String>, key: &str, value: &str) -> bool {
    map.insert(key.to_owned(), value.to_owned()).is_some()
}

/// Findings of the journey error-path coverage table (cross-document rule).
fn journey_coverage_findings(
    doc: &str,
    journeys: &[(String, String)],
    catalog: &BTreeMap<String, CatalogEntry>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(doc, "Journey error-path coverage") else {
        out.push(at(
            ERRORS,
            "no `## Journey error-path coverage` table with Class and Error codes columns (T-0020 step 3, journeys cross-check)",
        ));
        return out;
    };
    let (Some(class_col), Some(codes_col)) =
        (column(&header, "Class"), column(&header, "Error codes"))
    else {
        out.push(at(
            ERRORS,
            "the coverage table has no `Class` and `Error codes` columns",
        ));
        return out;
    };
    let mut stated: BTreeMap<String, BTreeSet<String>> = ROW_CLASSES
        .iter()
        .map(|class| ((*class).to_owned(), BTreeSet::new()))
        .collect();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (n, row) in &rows {
        let Some(class_cell) = row.get(class_col) else {
            continue;
        };
        let class = class_cell.trim().to_lowercase();
        let loc = format!("{ERRORS}:{n}");
        if !ROW_CLASSES.contains(&class.as_str()) {
            out.push(at(
                loc,
                format!(
                    "`{class}` is not one of the class rows (the nine task classes plus authentication)"
                ),
            ));
            continue;
        }
        if !seen.insert(class.clone()) {
            out.push(at(
                format!("{ERRORS}:{n}"),
                format!("the class `{class}` has more than one coverage row"),
            ));
        }
        let cell = row
            .get(codes_col)
            .map(|cell| cell.as_str())
            .unwrap_or_default();
        let codes = err_tokens(cell);
        let marker = cell
            .to_lowercase()
            .contains("none in the delivered journeys");
        if !codes.is_empty() && marker {
            out.push(at(
                format!("{ERRORS}:{n}"),
                format!("the `{class}` row names codes and says none in the delivered journeys"),
            ));
        }
        if codes.is_empty() && !marker {
            out.push(at(
                format!("{ERRORS}:{n}"),
                format!(
                    "the `{class}` row names no code and does not say `none in the delivered journeys`"
                ),
            ));
        }
        for code in codes {
            if stated
                .iter()
                .any(|(other, listed)| other != &class && listed.contains(&code))
            {
                out.push(at(
                    format!("{ERRORS}:{n}"),
                    format!("the code `{code}` is listed under more than one class"),
                ));
            }
            if let Some(entry) = stated.get_mut(&class) {
                entry.insert(code);
            }
        }
    }
    for class in ROW_CLASSES {
        if !seen.contains(class) {
            out.push(at(
                ERRORS,
                format!("the coverage table has no row for the class `{class}`"),
            ));
        }
    }
    let harvested = journey_error_codes(journeys);
    let covered: BTreeSet<String> = stated.values().flatten().cloned().collect();
    for code in harvested.difference(&covered) {
        out.push(at(
            ERRORS,
            format!(
                "the journeys cite `{code}` on an Error path, but the coverage table does not list it (collect the codes with a script)"
            ),
        ));
    }
    for code in covered.difference(&harvested) {
        out.push(at(
            ERRORS,
            format!(
                "the coverage table lists `{code}`, which no delivered journey cites on an Error path"
            ),
        ));
    }
    for (class, codes) in &stated {
        if !codes.is_empty() {
            continue;
        }
        for code in &harvested {
            if classify(code, catalog) == Some(class.as_str()) {
                out.push(at(
                    ERRORS,
                    format!(
                        "the `{class}` row says none in the delivered journeys, but `{code}` is classified as `{class}`"
                    ),
                ));
            }
        }
    }
    for (class, codes) in &stated {
        for code in codes {
            if !catalog.contains_key(code) {
                out.push(at(
                    ERRORS,
                    format!("the coverage table cites `{code}`, which is not a row of the B7 error catalog"),
                ));
                continue;
            }
            match classify(code, catalog) {
                Some(classified) if classified == class => {}
                Some(classified) => out.push(at(
                    ERRORS,
                    format!(
                        "the coverage table lists `{code}` under `{class}`, but the classification rules put it in `{classified}`"
                    ),
                )),
                None => out.push(at(
                    ERRORS,
                    format!("the coverage table cites `{code}`, which the classification rules cannot classify"),
                )),
            }
        }
    }
    out
}

/// Findings of the request-id and Ray ID section.
fn request_id_findings(
    doc: &str,
    _catalog: &BTreeMap<String, CatalogEntry>,
    b6: &BTreeSet<String>,
    detail: Option<&str>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(body) = section_body(doc, "Request ID and Ray ID") else {
        out.push(at(
            ERRORS,
            "no `## Request ID and Ray ID` section (T-0020 step 2)",
        ));
        return out;
    };
    let text = body_text(&body);
    let location = format!("{ERRORS} Request ID and Ray ID");
    if !has_phrase(&text, "request_id") {
        out.push(at(
            location.clone(),
            "the section does not name `request_id` on API errors (T-0020 step 2, B6.1)",
        ));
    }
    if !text.contains("[0-9a-f]{16}-HDD1") {
        out.push(at(
            location.clone(),
            "the section does not state the Ray ID shape `[0-9a-f]{16}-HDD1` (B7, section 0.10)",
        ));
    }
    if !text.to_lowercase().contains("ray id") {
        out.push(at(
            location.clone(),
            "the section never says `Ray ID` (T-0020 step 2)",
        ));
    }
    if !has_token(&text, "copy") {
        out.push(at(
            location.clone(),
            "the section never states the copy affordance for the id (T-0020 step 2)",
        ));
    }
    for (pair, what) in [
        ("GET P/support/ray/{ray}", "the support lookup"),
        ("GET D/events/{ray}", "the event lookup by Ray ID"),
    ] {
        if !text.contains(pair) {
            out.push(at(
                location.clone(),
                format!("the section does not name {what} as `{pair}` (T-0020 step 2)"),
            ));
        } else if !b6.contains(pair) {
            out.push(at(
                location.clone(),
                format!("`{pair}` is not a row of the B6 API catalog (T-0020 step 2)"),
            ));
        }
    }
    if !has_token(&text, "never") {
        out.push(at(
            location.clone(),
            "the section never states what is never shown (trace ids, internal hostnames, stack traces)",
        ));
    }
    for word in ["trace", "internal hostname", "stack trace", "rule"] {
        if !has_phrase(&text, word) {
            out.push(at(
                location.clone(),
                format!("the never-shown list does not name `{word}` (T-0020 step 2)"),
            ));
        }
    }
    for (key, _) in [("error-request-id-label", 0), ("error-ray-id-label", 0)] {
        if !has_phrase(&text, key) {
            out.push(at(
                location.clone(),
                format!("the section never names the copy key `{key}`"),
            ));
        }
    }
    if let Some(detail) = detail
        && (!has_phrase(detail, "access_denied") || !has_phrase(detail, "ray_id"))
    {
        out.push(at(
            "docs/SPEC.md",
            "the B12.2 S-140 detail does not state the `access_denied` JSON body with `ray_id` (T-0020 step 4)",
        ));
    }
    out
}

/// Findings of the retry and idempotency table (T-0020 step 3, A3).
fn retry_findings(doc: &str, b6: &BTreeSet<String>, conventions: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for token in ["Idempotency-Key", "If-Match", "Retry-After"] {
        if !has_phrase(conventions, token) {
            out.push(at(
                "docs/SPEC.md",
                format!(
                    "the B6.1 conventions never state `{token}`, so the retry rules cannot be cross-checked (T-0020 step 3)"
                ),
            ));
        }
    }
    let Some(body) = section_body(doc, "Retry and idempotency") else {
        out.push(at(
            ERRORS,
            "no `## Retry and idempotency` section (T-0020 step 3)",
        ));
        return out;
    };
    let rows = retry_rows(doc);
    if rows.is_empty() {
        out.push(at(
            ERRORS,
            "the retry and idempotency table has no rows (T-0020 step 3)",
        ));
        return out;
    }
    let text = body_text(&body);
    for token in ["Retry-After", "countdown"] {
        if !has_phrase(&text, token) {
            out.push(at(
                ERRORS,
                format!("the retry section never states `{token}` (T-0020 step 3)"),
            ));
        }
    }
    let mut post_key = 0usize;
    let mut post_unsafe = 0usize;
    let mut unsafe_pairs: Vec<String> = Vec::new();
    let mut get_safe = 0usize;
    let mut write_safe = 0usize;
    let mut patch_rows = 0usize;
    let mut if_match_rows = 0usize;
    for row in &rows {
        let loc = format!("{ERRORS}:{}", row.line);
        if !super::METHODS.contains(&row.method.as_str()) {
            out.push(at(
                loc,
                format!("`{}` is not an HTTP method (T-0020 step 3)", row.method),
            ));
            continue;
        }
        let Some(pair) = b6_cell_pair(&row.b6) else {
            out.push(at(
                format!("{ERRORS}:{}", row.line),
                format!(
                    "the row `{}` names no backticked `METHOD path` pair of the B6 catalog",
                    row.action
                ),
            ));
            continue;
        };
        if !b6.contains(&pair) {
            out.push(at(
                format!("{ERRORS}:{}", row.line),
                format!("`{pair}` is not a row of the B6 API catalog (T-0020 step 3)"),
            ));
        }
        if !pair.starts_with(&format!("{} ", row.method)) {
            out.push(at(
                format!("{ERRORS}:{}", row.line),
                format!(
                    "the row names `{pair}` but its Method column says `{}`",
                    row.method
                ),
            ));
        }
        let key_required = match row.key.as_str() {
            "required" => true,
            "not required" => false,
            other => {
                out.push(at(
                    format!("{ERRORS}:{}", row.line),
                    format!(
                        "the Idempotency-Key cell `{other}` is neither `required` nor `not required`"
                    ),
                ));
                false
            }
        };
        let precondition = match row.precondition.as_str() {
            cell if cell.contains("if-match") => true,
            cell if cell.contains("none") => false,
            other => {
                out.push(at(
                    format!("{ERRORS}:{}", row.line),
                    format!(
                        "the Precondition cell `{other}` is neither `If-Match` nor `none (<reason>)`"
                    ),
                ));
                false
            }
        };
        let expected = match row.method.as_str() {
            "GET" | "HEAD" | "PUT" | "DELETE" => "safe",
            "PATCH" => "safe with if-match",
            "POST" if key_required => "safe with idempotency-key",
            "POST" => "unsafe",
            _ => "unsafe",
        };
        if row.retry != expected {
            out.push(at(
                format!("{ERRORS}:{}", row.line),
                format!(
                    "the row `{}` says `{}` but a {} row is `{expected}` (T-0020 step 3, A3)",
                    row.action, row.retry, row.method
                ),
            ));
        }
        match row.method.as_str() {
            "POST" => {
                if key_required {
                    post_key += 1;
                } else {
                    post_unsafe += 1;
                    unsafe_pairs.push(pair.clone());
                }
                if precondition {
                    out.push(at(
                        format!("{ERRORS}:{}", row.line),
                        format!(
                            "the POST row `{}` claims an If-Match precondition; B6.1 applies If-Match to updates",
                            row.action
                        ),
                    ));
                }
            }
            "GET" | "HEAD" => {
                get_safe += 1;
                if key_required {
                    out.push(at(
                        format!("{ERRORS}:{}", row.line),
                        format!(
                            "the read row `{}` requires an Idempotency-Key; B6.1 requires it on POST creates and job triggers",
                            row.action
                        ),
                    ));
                }
            }
            "PUT" | "PATCH" | "DELETE" => {
                write_safe += 1;
                if row.method == "PATCH" {
                    patch_rows += 1;
                }
                if !precondition {
                    let reason = row.precondition.trim_start_matches("none").trim();
                    if row.method == "DELETE" && !reason.is_empty() {
                        // A delete with no ETag (a ban set membership) may state why it needs no precondition.
                    } else {
                        out.push(at(
                            format!("{ERRORS}:{}", row.line),
                            format!(
                                "the {} row `{}` does not require `If-Match`; B6.1 applies it to updates (T-0020 step 3)",
                                row.method, row.action
                            ),
                        ));
                    }
                } else {
                    if_match_rows += 1;
                }
                if key_required {
                    out.push(at(
                        format!("{ERRORS}:{}", row.line),
                        format!(
                            "the write row `{}` requires an Idempotency-Key; B6.1 requires it on POST creates and job triggers",
                            row.action
                        ),
                    ));
                }
            }
            _ => {}
        }
    }
    if post_key == 0 {
        out.push(at(
            ERRORS,
            "no POST create or job-trigger row requires `Idempotency-Key` (T-0020 step 3, B6.1)",
        ));
    }
    if post_unsafe < 5 {
        out.push(at(
            ERRORS,
            format!(
                "the table lists {post_unsafe} unsafe POST rows; at least five are required (T-0020 D-4: an email POST, a webhook or integration POST, a secret rotation, an emergency action and a POST with no idempotency key)"
            ),
        ));
    }
    let names_any = |needles: &[&str]| {
        unsafe_pairs
            .iter()
            .any(|pair| needles.iter().any(|n| pair.contains(n)))
    };
    for (what, needles) in [
        (
            "POST that sends email (resend verification, password reset or contact)",
            &[
                "/auth/resend-verification",
                "/auth/forgot-password",
                "/public/contact",
            ][..],
        ),
        (
            "POST that sends a webhook or integration test",
            &["/webhooks/", "/integrations/"][..],
        ),
        ("POST that rotates a secret", &["rotate-secret"][..]),
        ("POST that enters an emergency action", &["emergency"][..]),
    ] {
        if !names_any(needles) {
            out.push(at(
                ERRORS,
                format!(
                    "the table lists no unsafe {what}; review D-4 requires one (T-0020 step 3)"
                ),
            ));
        }
    }
    if get_safe == 0 {
        out.push(at(ERRORS, "no safe GET row is listed (T-0020 step 3, A3)"));
    }
    if write_safe == 0 {
        out.push(at(
            ERRORS,
            "no safe write row is listed (T-0020 step 3, A3)",
        ));
    }
    if patch_rows == 0 {
        out.push(at(
            ERRORS,
            "no PATCH row is listed, so the `ETag`/`If-Match` update rule is never shown (T-0020 step 3)",
        ));
    }
    if if_match_rows == 0 {
        out.push(at(
            ERRORS,
            "no row requires `If-Match`, so the update precondition is never shown (T-0020 step 3)",
        ));
    }
    out
}

/// Findings of the background-poll table (T-0020 step 3).
fn poll_findings(doc: &str, b6: &BTreeSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(sub) = subsection_body(doc, "Retry and idempotency", "Background polls") else {
        out.push(at(
            ERRORS,
            "no `### Background polls` table inside `## Retry and idempotency` (T-0020 step 3)",
        ));
        return out;
    };
    let Some((header, rows)) = table_in_body(&sub, "Background polls") else {
        out.push(at(
            ERRORS,
            "the `### Background polls` table cannot be read (Poll, Method and path, First interval, Backoff and Stop are required)",
        ));
        return out;
    };
    let poll_col = column(&header, "Poll");
    let path_col = column(&header, "Method and path");
    let interval_col = column(&header, "First interval");
    let backoff_col = column(&header, "Backoff");
    let stop_col = column(&header, "Stop");
    let mut count = 0usize;
    for (n, row) in &rows {
        let Some(poll) = poll_col.and_then(|index| row.get(index)) else {
            continue;
        };
        if poll.trim().is_empty() {
            continue;
        }
        count += 1;
        let loc = format!("{ERRORS}:{n} (background polls)");
        let path = path_col
            .and_then(|index| row.get(index))
            .map(|cell| cell.as_str())
            .unwrap_or_default();
        match b6_cell_pair(path) {
            None => out.push(at(
                loc.clone(),
                format!(
                    "the poll `{}` names no backticked `METHOD path` pair",
                    poll.trim()
                ),
            )),
            Some(pair) => {
                if !b6.contains(&pair) {
                    out.push(at(
                        loc.clone(),
                        format!("`{pair}` is not a row of the B6 API catalog"),
                    ));
                }
            }
        }
        let interval = interval_col
            .and_then(|index| row.get(index))
            .map(|cell| cell.as_str())
            .unwrap_or_default();
        if !interval.chars().any(|c| c.is_ascii_digit()) {
            out.push(at(
                loc.clone(),
                format!("the poll `{}` has no numeric first interval", poll.trim()),
            ));
        }
        let backoff = backoff_col
            .and_then(|index| row.get(index))
            .map(|cell| cell.as_str())
            .unwrap_or_default();
        if !has_token(backoff, "cap") || !backoff.chars().any(|c| c.is_ascii_digit()) {
            out.push(at(
                loc.clone(),
                format!(
                    "the poll `{}` has no bounded backoff (a numeric cap is required)",
                    poll.trim()
                ),
            ));
        }
        let stop = stop_col
            .and_then(|index| row.get(index))
            .map(|cell| cell.trim().to_owned())
            .unwrap_or_default();
        if stop.split_whitespace().count() < 2 {
            out.push(at(
                loc,
                format!("the poll `{}` has no stop condition", poll.trim()),
            ));
        }
    }
    if count < 3 {
        out.push(at(
            ERRORS,
            format!(
                "the background-poll table has {count} rows; at least 3 polls with backoff are required (T-0020 step 3)"
            ),
        ));
    }
    out
}

/// Findings of the visitor-page table (T-0020 step 4, A2).
fn visitor_page_findings(
    doc: &str,
    screens: &BTreeMap<String, String>,
    catalog: &BTreeMap<String, CatalogEntry>,
    detail: Option<&str>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let rows = page_rows(doc);
    if rows.is_empty() {
        out.push(at(
            ERRORS,
            "no `## Visitor pages S-140 to S-148` table with Page, Name, Status, B7 code, Copy keys and JSON variant columns (T-0020 step 4)",
        ));
        return out;
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for row in &rows {
        let loc = format!("{ERRORS}:{}", row.line);
        if !VISITOR_PAGES.contains(&row.id.as_str()) {
            out.push(at(
                loc.clone(),
                format!(
                    "`{}` is not one of the nine visitor pages S-140 to S-148",
                    row.id
                ),
            ));
            continue;
        }
        if !seen.insert(row.id.clone()) {
            out.push(at(
                loc.clone(),
                format!("the visitor page `{}` appears more than once", row.id),
            ));
        }
        match screens.get(&row.id) {
            Some(name) if row.name.eq_ignore_ascii_case(name) => {}
            Some(name) => out.push(at(
                loc.clone(),
                format!(
                    "the page `{}` is named `{}`; the B12.1 screen table names it `{name}`",
                    row.id, row.name
                ),
            )),
            None => out.push(at(
                loc.clone(),
                format!("the B12.1 screen table has no row for `{}`", row.id),
            )),
        }
        if row.statuses.is_empty() {
            out.push(at(
                loc.clone(),
                format!("the page `{}` has no numeric HTTP status", row.id),
            ));
        }
        for code in &row.codes {
            match catalog.get(code) {
                None => out.push(at(
                    loc.clone(),
                    format!(
                        "the page `{}` cites `{code}`, which is not a row of the B7 error catalog",
                        row.id
                    ),
                )),
                Some(entry) => {
                    if entry.family != "VISITOR" {
                        out.push(at(
                            loc.clone(),
                            format!(
                                "the data-plane page `{}` cites `{code}` from the `{}` family; a visitor page must cite a visitor-facing B7 code (`ERR-VISITOR-*`) or state `none in B7`, because an API problem type borrowed here is a filler code (T-0020 step 4, review lesson 3)",
                                row.id, entry.family
                            ),
                        ));
                    }
                    if !row.statuses.contains(&entry.status) {
                        out.push(at(
                            loc.clone(),
                            format!(
                                "the page `{}` cites `{code}` with HTTP status {}, but its Status cell says {:?}",
                                row.id, entry.status, row.statuses
                            ),
                        ));
                    }
                }
            }
        }
        if row.codes.is_empty()
            && !row
                .code_cell
                .to_lowercase()
                .contains("none in the delivered journeys")
            && !row.code_cell.to_lowercase().contains("none in b7")
        {
            out.push(at(
                loc.clone(),
                format!(
                    "the page `{}` names no B7 code and does not say `none in B7`",
                    row.id
                ),
            ));
        }
        if !row.json.to_lowercase().contains("application/problem+json") {
            out.push(at(
                loc.clone(),
                format!(
                    "the page `{}` has no `Accept: application/json` policy: the JSON variant must be `application/problem+json` (T-0020 step 4, T-0065 A5)",
                    row.id
                ),
            ));
        }
        if row.keys.is_empty() {
            out.push(at(
                loc.clone(),
                format!(
                    "the page `{}` cites no copy key, so its copy is never checked against the constraints",
                    row.id
                ),
            ));
        }
    }
    for id in VISITOR_PAGES {
        if !seen.contains(id) {
            out.push(at(
                ERRORS,
                format!("the visitor-page table has no row for `{id}` (T-0020 step 4, A2)"),
            ));
        }
    }
    if let Some(row) = rows.iter().find(|row| row.id == "S-140") {
        let loc = format!("{ERRORS}:{}", row.line);
        if !row.statuses.contains(&403) {
            out.push(at(
                loc.clone(),
                "the block page S-140 must carry the 403 status of B12.2 (T-0020 step 4)",
            ));
        }
        if !has_phrase(&row.json, "access_denied") || !has_phrase(&row.json, "ray_id") {
            out.push(at(
                loc.clone(),
                "the S-140 JSON variant must name the `access_denied` body and `ray_id` (B12.2, T-0020 step 4)",
            ));
        }
        if has_phrase(&row.json, "request_id") || has_phrase(&row.json, "trace") {
            out.push(at(
                loc,
                "the S-140 JSON variant carries `request_id` or a trace id; the visitor page carries the Ray ID only and the API `request_id` never mixes with it (T-0020 step 2)",
            ));
        }
    }
    if let Some(row) = rows.iter().find(|row| row.id == "S-144")
        && !row.statuses.contains(&404)
    {
        out.push(at(
            format!("{ERRORS}:{}", row.line),
            "the unknown host page S-144 must be the neutral 404 (B12.1, T-0020 step 4)",
        ));
    }
    if let Some(detail) = detail
        && detail.to_lowercase().contains("status 403")
        && !rows
            .iter()
            .find(|row| row.id == "S-140")
            .is_some_and(|row| row.statuses.contains(&403))
    {
        out.push(at(
            ERRORS,
            "the B12.2 S-140 detail states Status 403, which the visitor-page table does not repeat",
        ));
    }
    out
}

/// Findings of the numbered visitor-page constraints and the copy values they govern (T-0020 step 4, A2).
fn visitor_constraint_findings(doc: &str, values: &BTreeMap<String, String>) -> Vec<Finding> {
    let (mut out, items, text) = statement_findings(doc, "Visitor page constraints", "V-", 8);
    let required: [(&str, &[&str]); 8] = [
        ("V-1", &["rule"]),
        ("V-2", &["stack trace"]),
        ("V-3", &["internal hostname"]),
        ("V-4", &["404", "tenant"]),
        ("V-5", &["tenant"]),
        ("V-6", &["payload"]),
        ("V-7", &["ray"]),
        ("V-8", &["json"]),
    ];
    for (id, words) in required {
        let Some((_, text)) = items.iter().find(|(number, _)| format!("V-{number}") == id) else {
            out.push(at(
                format!("{ERRORS} Visitor page constraints"),
                format!("the constraint `{id}` is missing"),
            ));
            continue;
        };
        for word in words {
            if !has_phrase(text, word) {
                out.push(at(
                    format!("{ERRORS} Visitor page constraints"),
                    format!("the constraint `{id}` never names `{word}`"),
                ));
            }
        }
    }
    let _ = text;
    let pages = page_rows(doc);
    for row in &pages {
        for key in &row.keys {
            let Some(value) = values.get(key) else {
                continue;
            };
            let loc = format!("{ERRORS} visitor page {}", row.id);
            for (kind, words) in [
                ("rule", &RULE_WORDS[..]),
                ("trace", &TRACE_WORDS[..]),
                ("internal", &INTERNAL_WORDS[..]),
                ("blame", &BLAME_WORDS[..]),
            ] {
                for word in words {
                    if has_phrase(value, word) {
                        out.push(at(
                            loc.clone(),
                            format!(
                                "the copy key `{key}` carries a forbidden {kind} word `{word}` (T-0020 step 4)"
                            ),
                        ));
                    }
                }
            }
            if row.id == "S-144" || row.id == "S-148" {
                if value.contains('$') {
                    out.push(at(
                        loc.clone(),
                        format!(
                            "the copy key `{key}` of the neutral page {} carries a tenant variable",
                            row.id
                        ),
                    ));
                }
                for word in TENANT_WORDS {
                    if has_phrase(value, word) {
                        out.push(at(
                            loc.clone(),
                            format!(
                                "the copy key `{key}` of the neutral page {} names `{word}` (no tenant leakage)",
                                row.id
                            ),
                        ));
                    }
                }
            }
        }
    }
    if let Some(row) = pages.iter().find(|row| row.id == "S-140") {
        let ray = row.keys.iter().any(|key| {
            values
                .get(key)
                .is_some_and(|value| has_phrase(value, "ray_id"))
        });
        if !ray {
            out.push(at(
                ERRORS,
                "no S-140 copy key shows the Ray ID (`ray_id`), so the block page has no reference (T-0020 step 2 and 4)",
            ));
        }
    }
    out
}

/// True when a value contains an emoji or a decorative dingbat (the copy-deck rule).
fn has_emoji(text: &str) -> bool {
    text.chars().any(|c| {
        let u = c as u32;
        (0x1F000..=0x1FAFF).contains(&u)
            || (0x1F1E6..=0x1F1FF).contains(&u)
            || (0x2600..=0x27BF).contains(&u)
            || (0xFE00..=0xFE0F).contains(&u)
            || u == 0x2B50
            || u == 0x2B55
    })
}

/// Findings of the copy inventory, the Fluent style and the definition-once rule (T-0020 A1, R-10).
fn copy_key_findings(
    doc: &str,
    b13: &BTreeMap<String, String>,
    deck: &str,
    ftl: &str,
    claims_cfg: Option<&claims::Config>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let deck_values = ftl_values(deck);
    let ftl_map = ftl_values(ftl);
    let messages = parse_ftl(ftl);
    let Ok(key_shape) = Regex::new(KEY_SHAPE) else {
        out.push(at(ERRORS_COPY, "cannot compile the i18n key pattern"));
        return out;
    };
    let mut key_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut seen_values: BTreeMap<String, String> = BTreeMap::new();
    for message in &messages {
        if message.key.is_empty() {
            out.push(at(
                ERRORS_COPY,
                format!(
                    "line {} is not a `key = value` message in errors.ftl",
                    message.line
                ),
            ));
            continue;
        }
        if !key_shape.is_match(&message.key) {
            out.push(at(
                ERRORS_COPY,
                format!(
                    "the i18n key \"{}\" at line {} is not a semantic hyphenated stem",
                    message.key, message.line
                ),
            ));
        }
        *key_counts.entry(message.key.clone()).or_insert(0) += 1;
        if message.value.is_empty() {
            out.push(at(
                ERRORS_COPY,
                format!("the copy key `{}` has an empty value", message.key),
            ));
        }
        if has_emoji(&message.value) {
            out.push(at(
                ERRORS_COPY,
                format!("the value of `{}` contains an emoji", message.key),
            ));
        }
        if message.value.contains('<') {
            out.push(at(
                ERRORS_COPY,
                format!("the value of `{}` contains `<` markup", message.key),
            ));
        }
        if message.value.contains('!')
            && !(message.key.starts_with("success-") || message.key.ends_with("-success"))
        {
            out.push(at(
                ERRORS_COPY,
                format!(
                    "the value of `{}` contains an exclamation mark; only a success key may",
                    message.key
                ),
            ));
        }
        if let Some(first) = seen_values.insert(message.value.clone(), message.key.clone()) {
            out.push(at(
                ERRORS_COPY,
                format!(
                    "the copy keys `{first}` and `{}` have the same value",
                    message.key
                ),
            ));
        }
    }
    for (key, count) in &key_counts {
        if *count > 1 {
            out.push(at(
                ERRORS_COPY,
                format!("the copy key `{key}` is defined more than once in errors.ftl"),
            ));
        }
    }
    for key in ftl_map.keys() {
        if b13.contains_key(key) || deck_values.contains_key(key) {
            out.push(at(
                ERRORS_COPY,
                format!(
                    "the copy key `{key}` is defined in errors.ftl and also in B13 or the copy deck; it must be defined exactly once"
                ),
            ));
        }
    }
    let mut used: BTreeSet<String> = BTreeSet::new();
    for row in page_rows(doc) {
        for key in row.keys {
            used.insert(key);
        }
    }
    if let Some(sub) = subsection_body(doc, "Pattern selection", "Pattern copy")
        && let Some((_, rows)) = table_in_body(&sub, "Pattern copy")
    {
        for (_, row) in rows {
            for cell in row {
                for key in key_tokens(&cell) {
                    used.insert(key);
                }
            }
        }
    }
    for (section, keys) in SECTION_KEYS {
        let text = section_body(doc, section)
            .map(|body| body_text(&body))
            .unwrap_or_default();
        for key in keys {
            if !has_phrase(&text, key) {
                out.push(at(
                    ERRORS,
                    format!("the `## {section}` section never names the copy key `{key}`"),
                ));
            }
            used.insert((*key).to_owned());
        }
    }
    let defined = |key: &str| {
        b13.contains_key(key) || deck_values.contains_key(key) || ftl_map.contains_key(key)
    };
    for key in &used {
        if !defined(key) {
            out.push(at(
                ERRORS,
                format!(
                    "the copy key `{key}` is not defined in B13, i18n/en/copy-deck.ftl or i18n/en/errors.ftl (defined exactly once)"
                ),
            ));
        }
    }
    match section_table(doc, "Copy inventory") {
        None => out.push(at(
            ERRORS,
            "no `## Copy inventory` table with Key, Source and Exact English text columns (T-0020 A1)",
        )),
        Some((header, rows)) => {
            let (Some(key_col), Some(source_col), Some(text_col)) = (
                column(&header, "Key"),
                column(&header, "Source"),
                column(&header, "Exact English text"),
            ) else {
                out.push(at(
                    ERRORS,
                    "the copy inventory has no `Key`, `Source` and `Exact English text` columns",
                ));
                return out;
            };
            let mut inventory: BTreeMap<String, String> = BTreeMap::new();
            for (n, row) in &rows {
                let Some(key_cell) = row.get(key_col) else {
                    continue;
                };
                let key = key_cell.trim().trim_matches('`').trim().to_owned();
                if !key_shape.is_match(&key) {
                    out.push(at(
                        format!("{ERRORS}:{n}"),
                        format!("the copy inventory row `{key}` is not a semantic hyphenated key"),
                    ));
                    continue;
                }
                let source = row
                    .get(source_col)
                    .map(|cell| cell.trim().to_lowercase())
                    .unwrap_or_default();
                let text = row
                    .get(text_col)
                    .map(|cell| cell.trim().to_owned())
                    .unwrap_or_default();
                if inventory.insert(key.clone(), text.clone()).is_some() {
                    out.push(at(
                        format!("{ERRORS}:{n}"),
                        format!("the copy inventory lists the key `{key}` more than once"),
                    ));
                }
                match source.as_str() {
                    "b13" => match b13.get(&key) {
                        None => out.push(at(
                            format!("{ERRORS}:{n}"),
                            format!("the copy key `{key}` is not a row of B13"),
                        )),
                        Some(expected) => {
                            if &text != expected {
                                out.push(at(
                                    format!("{ERRORS}:{n}"),
                                    format!(
                                        "the copy inventory quotes \"{text}\" for `{key}`, but B13 says \"{expected}\" (exact text)"
                                    ),
                                ));
                            }
                            if !deck_values.contains_key(&key) {
                                out.push(at(
                                    format!("{ERRORS}:{n}"),
                                    format!("the B13 key `{key}` is not defined in i18n/en/copy-deck.ftl"),
                                ));
                            }
                        }
                    },
                    "errors.ftl" => match ftl_map.get(&key) {
                        None => out.push(at(
                            format!("{ERRORS}:{n}"),
                            format!("the copy key `{key}` is not defined in i18n/en/errors.ftl"),
                        )),
                        Some(expected) => {
                            if &text != expected {
                                out.push(at(
                                    format!("{ERRORS}:{n}"),
                                    format!(
                                        "the copy inventory quotes \"{text}\" for `{key}`, but errors.ftl says \"{expected}\" (exact text)"
                                    ),
                                ));
                            }
                        }
                    },
                    other => out.push(at(
                        format!("{ERRORS}:{n}"),
                        format!(
                            "the copy inventory source `{other}` is neither `B13` nor `errors.ftl`"
                        ),
                    )),
                }
            }
            for key in &used {
                if !inventory.contains_key(key) {
                    out.push(at(
                        ERRORS,
                        format!(
                            "the copy key `{key}` is cited by the model but has no copy inventory row (exact text required)"
                        ),
                    ));
                }
            }
            for key in inventory.keys() {
                if !used.contains(key) {
                    out.push(at(
                        ERRORS,
                        format!(
                            "the copy inventory defines `{key}`, which no page, pattern or rule section uses"
                        ),
                    ));
                }
            }
        }
    }
    if let Some(cfg) = claims_cfg {
        out.extend(claims_doc_findings(cfg, ERRORS_COPY, ftl));
    }
    out
}

/// Findings of the offline and flaky-network section (T-0020 step 5).
fn offline_findings(doc: &str) -> Vec<Finding> {
    let section = "Offline and flaky networks";
    let (mut out, _, text) = statement_findings(doc, section, "O-", 6);
    out.extend(required_words(
        &text,
        &format!("{ERRORS} {section}"),
        section,
        &[
            "htmx", "offline", "retry", "stale", "silently", "never", "partial",
        ],
    ));
    out
}

/// Findings of the long-running job failure section (T-0020 step 6).
fn job_failure_findings(doc: &str) -> Vec<Finding> {
    let section = "Long-running job failures";
    let (mut out, _, text) = statement_findings(doc, section, "L-", 4);
    out.extend(required_words(
        &text,
        &format!("{ERRORS} {section}"),
        section,
        &["notification", "inline", "event", "reference", "job"],
    ));
    out
}

/// Findings of the logging section (T-0020 step 7, R-25).
fn logging_findings(doc: &str) -> Vec<Finding> {
    let section = "Logging of errors";
    let (mut out, _, text) = statement_findings(doc, section, "LG-", 5);
    out.extend(required_words(
        &text,
        &format!("{ERRORS} {section}"),
        section,
        &[
            "nothing",
            "structured",
            "request_id",
            "R-25",
            "512",
            "PII",
            "stack trace",
            "body",
        ],
    ));
    out
}

/// Findings of the accessibility-per-pattern table (T-0020 step 8, A4).
fn accessibility_findings(
    doc: &str,
    components: &BTreeSet<String>,
    criteria: &BTreeSet<String>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(doc, "Accessibility of errors") else {
        out.push(at(
            ERRORS,
            "no `## Accessibility of errors` table with Pattern, Focus, Role, Text not colour and Component columns (T-0020 step 8, A4)",
        ));
        return out;
    };
    let (Some(pattern_col), Some(focus_col), Some(role_col), Some(text_col), Some(component_col)) = (
        column(&header, "Pattern"),
        column(&header, "Focus"),
        column(&header, "Role"),
        column(&header, "Text not colour"),
        column(&header, "Component"),
    ) else {
        out.push(at(
            ERRORS,
            "the accessibility table has no `Pattern`, `Focus`, `Role`, `Text not colour` and `Component` columns (A4)",
        ));
        return out;
    };
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (n, row) in &rows {
        let Some(pattern) = row.get(pattern_col).map(|cell| cell.trim().to_lowercase()) else {
            continue;
        };
        if !PATTERNS.contains(&pattern.as_str()) {
            out.push(at(
                format!("{ERRORS}:{n}"),
                format!("`{pattern}` is not one of the five UI patterns (A4)"),
            ));
            continue;
        }
        if !seen.insert(pattern.clone()) {
            out.push(at(
                format!("{ERRORS}:{n}"),
                format!("the pattern `{pattern}` has more than one accessibility row"),
            ));
        }
        let loc = format!("{ERRORS}:{n}");
        let focus = row.get(focus_col).cloned().unwrap_or_default();
        if !has_token(&focus, "focus") {
            out.push(at(
                loc.clone(),
                format!("the `{pattern}` row does not state the focus behaviour (A4)"),
            ));
        } else {
            let ok = match pattern.as_str() {
                "inline" => has_any(&focus, &["field", "aria"]),
                "summary" => has_token(&focus, "summary"),
                "toast" => has_token(&focus, "toast"),
                "banner" => has_token(&focus, "banner"),
                "page" => has_any(&focus, &["heading", "h1"]),
                _ => true,
            };
            if !ok {
                out.push(at(
                    loc.clone(),
                    format!("the `{pattern}` row does not name its focus target (A4)"),
                ));
            }
        }
        let role = row
            .get(role_col)
            .map(|cell| cell.trim().to_owned())
            .unwrap_or_default();
        if role.is_empty() {
            out.push(at(loc.clone(), format!("the `{pattern}` row has no role")));
        } else {
            match pattern.as_str() {
                "summary" | "toast" | "banner" => {
                    if !role.contains("role=\"alert\"") {
                        out.push(at(
                            loc.clone(),
                            format!(
                                "the `{pattern}` row must announce the error with `role=\"alert\"` (A4)"
                            ),
                        ));
                    }
                }
                "inline" => {
                    if !role.contains("aria-describedby") {
                        out.push(at(
                            loc.clone(),
                            "the `inline` row must link the message with `aria-describedby` (A4)",
                        ));
                    }
                }
                "page" if !has_any(&role, &["main", "heading", "h1"]) => {
                    out.push(at(
                        loc.clone(),
                        "the `page` row must name the main landmark or the heading (A4)",
                    ));
                }
                _ => {}
            }
        }
        let not_colour = row.get(text_col).cloned().unwrap_or_default();
        let colour_ok = has_token(&not_colour, "text")
            && (has_phrase(&not_colour, "never colour")
                || has_phrase(&not_colour, "not colour")
                || has_phrase(&not_colour, "never color")
                || has_phrase(&not_colour, "not color"));
        if !colour_ok {
            out.push(at(
                loc.clone(),
                format!(
                    "the `{pattern}` row does not state that the error is text and not colour only (A4)"
                ),
            ));
        }
        let component = row
            .get(component_col)
            .map(|cell| cell.trim().to_owned())
            .unwrap_or_default();
        if component.is_empty() {
            out.push(at(
                loc.clone(),
                format!("the `{pattern}` row names no component"),
            ));
        } else if !components.iter().any(|name| has_token(&component, name)) {
            out.push(at(
                loc,
                format!(
                    "the component `{component}` of the `{pattern}` row is not a component of the B11.8 inventory (A4)"
                ),
            ));
        }
    }
    for pattern in PATTERNS {
        if !seen.contains(pattern) {
            out.push(at(
                ERRORS,
                format!("the accessibility table has no `{pattern}` row (T-0020 step 8, A4)"),
            ));
        }
    }
    let text = section_body(doc, "Accessibility of errors")
        .map(|body| body_text(&body))
        .unwrap_or_default();
    for criterion in ["3.3.1", "3.3.3", "4.1.3"] {
        if !has_phrase(&text, criterion) {
            out.push(at(
                ERRORS,
                format!(
                    "the accessibility section does not cite WCAG criterion {criterion} (A4, ACCESSIBILITY.md)"
                ),
            ));
        } else if !criteria.contains(criterion) {
            out.push(at(
                "docs/SPEC.md",
                format!(
                    "the accessibility section cites WCAG criterion {criterion}, which is not a row of the B11.11 contract"
                ),
            ));
        }
    }
    for (path, what) in [
        ("ACCESSIBILITY.md", "the accessibility document"),
        ("SECURITY-UX.md", "the security UX document"),
    ] {
        if !doc.contains(&format!("]({path})")) {
            out.push(at(
                ERRORS,
                format!("the model does not link {what} `{path}` (consistency rule)"),
            ));
        }
    }
    out
}

/// Findings of the security notes (T-0020 A5, R-20).
fn security_findings(doc: &str) -> Vec<Finding> {
    let section = "Security notes";
    let (mut out, items, text) = statement_findings(doc, section, "SEC-", 5);
    out.extend(required_words(
        &text,
        &format!("{ERRORS} {section}"),
        section,
        &[
            "enumeration",
            "R-20",
            "stack trace",
            "ERR-PERM-002",
            "404",
            "403",
            "internal hostname",
            "exists",
        ],
    ));
    let stated = items.iter().any(|(_, item)| {
        item.to_lowercase().contains("existence") || item.to_lowercase().contains("exists")
    }) && items
        .iter()
        .any(|(_, item)| item.to_lowercase().contains("permission"));
    if !stated {
        out.push(at(
            format!("{ERRORS} {section}"),
            "the notes do not state that a permission denial never reveals whether a resource exists (T-0020 A5, R-20)",
        ));
    }
    out
}

/// Findings of the explicit authentication row of the class matrix (review D-1).
fn authentication_findings(doc: &str, catalog: &BTreeMap<String, CatalogEntry>) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some((header, rows)) = section_table(doc, "Authentication class") else {
        out.push(at(
            ERRORS,
            "no `## Authentication class` table with Code, Status, Pattern and Remedy columns (T-0020 D-1)",
        ));
        return out;
    };
    let (Some(code_col), Some(status_col), Some(pattern_col), Some(remedy_col)) = (
        column(&header, "Code"),
        column(&header, "Status"),
        column(&header, "Pattern"),
        column(&header, "Remedy"),
    ) else {
        out.push(at(
            ERRORS,
            "the authentication table has no `Code`, `Status`, `Pattern` and `Remedy` columns (T-0020 D-1)",
        ));
        return out;
    };
    let exceptions = stated_exceptions(doc);
    let coverage = coverage_classes(doc);
    let auth_patterns = CLASS_PATTERNS
        .iter()
        .find(|(class, _)| *class == AUTHENTICATION)
        .map(|(_, patterns)| *patterns)
        .unwrap_or(&[]);
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (n, row) in &rows {
        let Some(code) = row
            .get(code_col)
            .map(|cell| cell.trim().trim_matches('`').trim().to_owned())
        else {
            continue;
        };
        if code.is_empty() {
            continue;
        }
        if !seen.insert(code.clone()) {
            out.push(at(
                format!("{ERRORS}:{n}"),
                format!("the authentication code `{code}` appears more than once"),
            ));
        }
        if !AUTHENTICATION_CODES.contains(&code.as_str()) {
            out.push(at(
                format!("{ERRORS}:{n}"),
                format!(
                    "`{code}` is not one of the reviewed authentication codes (T-0020 D-1; the list is the reviewed subset, not every 401)"
                ),
            ));
        }
        let status = row
            .get(status_col)
            .and_then(|cell| cell.trim().parse::<u16>().ok());
        let Some(status) = status else {
            out.push(at(
                format!("{ERRORS}:{n}"),
                format!("the authentication row `{code}` has no numeric B7 status"),
            ));
            continue;
        };
        match catalog.get(&code) {
            None => out.push(at(
                format!("{ERRORS}:{n}"),
                format!("the authentication code `{code}` is not a row of the B7 error catalog"),
            )),
            Some(entry) if entry.status != status => out.push(at(
                format!("{ERRORS}:{n}"),
                format!(
                    "the authentication row says `{code}` has status {status}, but B7 says {}",
                    entry.status
                ),
            )),
            Some(_) => {}
        }
        if !CLASS_STATUSES
            .iter()
            .find(|(class, _)| *class == AUTHENTICATION)
            .is_some_and(|(_, statuses)| statuses.contains(&status))
        {
            out.push(at(
                format!("{ERRORS}:{n}"),
                format!("status {status} is not a reviewed authentication status (401 or 403)"),
            ));
        }
        let pattern = row
            .get(pattern_col)
            .map(|cell| cell.trim().to_lowercase())
            .unwrap_or_default();
        if !auth_patterns.contains(&pattern.as_str()) {
            out.push(at(
                format!("{ERRORS}:{n}"),
                format!(
                    "the pattern `{pattern}` of the authentication row `{code}` is not one of the authentication patterns (inline, summary, page, banner)"
                ),
            ));
        }
        let remedy = row
            .get(remedy_col)
            .map(|cell| cell.trim().to_owned())
            .unwrap_or_default();
        if remedy.split_whitespace().count() < 4 {
            out.push(at(
                format!("{ERRORS}:{n}"),
                format!("the authentication row `{code}` has no remedy in words (T-0020 D-1)"),
            ));
        }
        match exceptions.get(&code) {
            Some(class) if class == AUTHENTICATION => {}
            Some(class) => out.push(at(
                format!("{ERRORS}:{n}"),
                format!(
                    "the exception table lists `{code}` as `{class}`, but the authentication class owns it (T-0020 D-1)"
                ),
            )),
            None => out.push(at(
                format!("{ERRORS}:{n}"),
                format!(
                    "`{code}` has no exception row mapping it to the authentication class (T-0020 D-1)"
                ),
            )),
        }
        if let Some(class) = coverage.get(&code)
            && class != AUTHENTICATION
        {
            out.push(at(
                format!("{ERRORS}:{n}"),
                format!(
                    "the journey coverage table lists the authentication code `{code}` under `{class}` (T-0020 D-1: the tables must agree)"
                ),
            ));
        }
    }
    for code in AUTHENTICATION_CODES {
        if !seen.contains(code) {
            out.push(at(
                ERRORS,
                format!("the authentication table has no row for `{code}` (T-0020 D-1)"),
            ));
        }
    }
    if !class_rows(doc)
        .iter()
        .any(|row| row.class == AUTHENTICATION)
    {
        out.push(at(
            ERRORS,
            "the class and pattern matrix has no `authentication` row (T-0020 D-1)",
        ));
    }
    out
}

/// Findings when a code's class differs between the document's tables (review D-1).
fn cross_table_findings(
    doc: &str,
    journeys: &[(String, String)],
    catalog: &BTreeMap<String, CatalogEntry>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let status = stated_status_classes(doc);
    if status.is_empty() {
        out.push(at(
            ERRORS,
            "the classification-rules table cannot be read, so the tables cannot be compared (T-0020 D-1)",
        ));
        return out;
    }
    let exceptions = stated_exceptions(doc);
    let coverage = coverage_classes(doc);
    let examples = example_classes(doc);
    let stated_class = |code: &str| -> Option<String> {
        if let Some(class) = exceptions.get(code) {
            return Some(class.clone());
        }
        let entry = catalog.get(code)?;
        status.get(&entry.status.to_string()).cloned()
    };
    let mut compared: BTreeSet<String> = coverage.keys().cloned().collect();
    compared.extend(examples.keys().cloned());
    compared.extend(journey_error_codes(journeys));
    for code in compared {
        let Some(expected) = stated_class(&code) else {
            out.push(at(
                ERRORS,
                format!(
                    "the classification tables cannot place `{code}`, so the other tables cannot agree with them (T-0020 D-1)"
                ),
            ));
            continue;
        };
        if let Some(class) = coverage.get(&code)
            && class != &expected
        {
            out.push(at(
                ERRORS,
                format!(
                    "the journey error-path coverage table lists `{code}` under `{class}`, but the status and exception tables give `{expected}` (T-0020 D-1: one class per code)"
                ),
            ));
        }
        if let Some(class) = examples.get(&code)
            && class != &expected
        {
            out.push(at(
                ERRORS,
                format!(
                    "the class matrix gives `{code}` as the example of `{class}`, but the status and exception tables give `{expected}` (T-0020 D-1)"
                ),
            ));
        }
    }
    for code in AUTHENTICATION_CODES {
        match stated_class(code) {
            Some(class) if class == AUTHENTICATION => {}
            Some(class) => out.push(at(
                ERRORS,
                format!(
                    "the reviewed authentication code `{code}` classifies as `{class}` in the document tables (T-0020 D-1)"
                ),
            )),
            None => out.push(at(
                ERRORS,
                format!(
                    "the reviewed authentication code `{code}` has no classification row (T-0020 D-1)"
                ),
            )),
        }
    }
    for (code, class) in coverage.iter().chain(examples.iter()) {
        if !ROW_CLASSES.contains(&class.as_str()) {
            out.push(at(
                ERRORS,
                format!(
                    "`{code}` is listed under `{class}`, which is not a class row (T-0020 D-1)"
                ),
            ));
        }
    }
    out
}

/// Findings of the reviewed conflict scope: only version and key conflicts keep the conflict class (review D-2).
fn conflict_scope_findings(doc: &str, catalog: &BTreeMap<String, CatalogEntry>) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut scope = section_body(doc, "Classification rules")
        .map(|body| body_text(&body))
        .unwrap_or_default();
    scope.push('\n');
    scope.push_str(
        &section_body(doc, "Classification exceptions")
            .map(|body| body_text(&body))
            .unwrap_or_default(),
    );
    if !has_phrase(&scope, "version or key conflict") {
        out.push(at(
            ERRORS,
            "the classification section does not state that the conflict class means a version or key conflict only (T-0020 D-2)",
        ));
    }
    if !has_phrase(&scope, "reload") {
        out.push(at(
            ERRORS,
            "the classification section does not say that the reload control belongs to the reviewed conflict codes only (T-0020 D-2)",
        ));
    }
    if let Some(row) = class_rows(doc)
        .into_iter()
        .find(|row| row.class == "conflict")
    {
        if !(has_token(&row.clears, "reload") || has_token(&row.focus, "reload")) {
            out.push(at(
                ERRORS,
                "the conflict row no longer names the reload control for a version or key conflict (T-0020 D-2)",
            ));
        }
        if !has_any(&row.clears, &["version", "key", "idempotency"]) {
            out.push(at(
                ERRORS,
                "the conflict row's `Clears` cell does not name a version, key or idempotency conflict (T-0020 D-2)",
            ));
        }
    }
    let exceptions = stated_exceptions(doc);
    for (code, entry) in catalog {
        if !matches!(entry.status, 409 | 412 | 428) {
            continue;
        }
        let documented = exceptions.contains_key(code);
        let reviewed_default = CONFLICT_DEFAULTS.contains(&code.as_str());
        if !documented && !reviewed_default {
            out.push(at(
                ERRORS,
                format!(
                    "`{code}` falls to the conflict class only by its {} status; it is not a version or key conflict, so it needs an exception row with a Why (T-0020 D-2)",
                    entry.status
                ),
            ));
        }
        if documented && reviewed_default {
            out.push(at(
                ERRORS,
                format!(
                    "`{code}` is a reviewed conflict default and must not also carry an exception row (T-0020 D-2)"
                ),
            ));
        }
    }
    for code in CONFLICT_DEFAULTS {
        if !catalog.contains_key(code) {
            out.push(at(
                "docs/SPEC.md",
                format!(
                    "the reviewed conflict default `{code}` is not a row of the B7 error catalog (T-0020 D-2)"
                ),
            ));
            continue;
        }
        if classify(code, catalog) != Some("conflict") {
            out.push(at(
                ERRORS,
                format!("the reviewed conflict default `{code}` must classify to the conflict class (T-0020 D-2)"),
            ));
        }
        if exceptions.contains_key(code) {
            out.push(at(
                ERRORS,
                format!(
                    "`{code}` is a reviewed conflict default and must not carry an exception row (T-0020 D-2)"
                ),
            ));
        }
    }
    out
}

/// Findings when the one-cause-once-per-channel rule disagrees with itself (review D-3).
fn consistency_findings(doc: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(body) = section_body(doc, "Pattern selection") else {
        out.push(at(
            ERRORS,
            "no `## Pattern selection` section, so the once-per-channel rule cannot be read (T-0020 D-3)",
        ));
        return out;
    };
    let items = numbered_items(&body, "P-");
    match items.iter().find(|(number, _)| *number == 8) {
        None => out.push(at(
            ERRORS,
            "the pattern-selection rules have no `P-8` rule (T-0020 D-3)",
        )),
        Some((_, text)) => {
            if has_phrase(text, "shown once") {
                out.push(at(
                    ERRORS,
                    "P-8 still says one cause is shown once; the rule is once per channel with the same text (T-0020 D-3)",
                ));
            }
            if !has_phrase(text, "per channel") {
                out.push(at(
                    ERRORS,
                    "P-8 does not say that one cause appears once per channel (T-0020 D-3)",
                ));
            }
            if !(has_phrase(text, "same text")
                || has_phrase(text, "same wording")
                || has_phrase(text, "same sentence"))
            {
                out.push(at(
                    ERRORS,
                    "P-8 does not say that a repeat uses the same text (T-0020 D-3)",
                ));
            }
            if !has_phrase(text, "toast") {
                out.push(at(
                    ERRORS,
                    "P-8 does not cover the toast repeat that a validation failure and a job failure may show (T-0020 D-3)",
                ));
            }
            if !has_phrase(text, "summary") {
                out.push(at(
                    ERRORS,
                    "P-8 does not cover the summary-and-inline repeat of a validation failure (T-0020 D-3)",
                ));
            }
        }
    }
    for (number, text) in &items {
        if has_phrase(text, "shown once") {
            out.push(at(
                ERRORS,
                format!(
                    "the rule `P-{number}` still claims one cause is shown once; the rule is once per channel (T-0020 D-3)"
                ),
            ));
        }
    }
    let Some(job_body) = section_body(doc, "Long-running job failures") else {
        out.push(at(
            ERRORS,
            "no `## Long-running job failures` section, so L-5 cannot be compared with P-8 (T-0020 D-3)",
        ));
        return out;
    };
    let job_items = numbered_items(&job_body, "L-");
    match job_items.iter().find(|(number, _)| *number == 5) {
        None => out.push(at(
            ERRORS,
            "the job-failure rules have no `L-5` rule (T-0020 D-3)",
        )),
        Some((_, text)) => {
            if !has_phrase(text, "notification") {
                out.push(at(
                    ERRORS,
                    "L-5 does not name the durable notification (T-0020 D-3)",
                ));
            }
            if !has_phrase(text, "inline") {
                out.push(at(
                    ERRORS,
                    "L-5 does not name the inline status (T-0020 D-3)",
                ));
            }
            if !has_phrase(text, "toast") {
                out.push(at(
                    ERRORS,
                    "L-5 does not say that a toast may repeat the news (T-0020 D-3)",
                ));
            }
            if !(has_phrase(text, "repeat") || has_phrase(text, "same")) {
                out.push(at(
                    ERRORS,
                    "L-5 does not say that the toast repeats the same text (T-0020 D-3)",
                ));
            }
        }
    }
    out
}

/// Findings for `ERR-` codes cited anywhere in the document (whole token, exists in B7).
fn citation_findings(doc: &str, catalog: &BTreeMap<String, CatalogEntry>) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut reported: BTreeSet<String> = BTreeSet::new();
    for (n, line) in doc.lines().enumerate() {
        for token in err_candidates(line) {
            if catalog.contains_key(&token) || !reported.insert(token.clone()) {
                continue;
            }
            out.push(at(
                format!("{ERRORS}:{}", n + 1),
                format!("`{token}` is not a row of the B7 error catalog (whole token)"),
            ));
        }
    }
    out
}

/// No forbidden claims phrase in a document or copy value (R-10).
fn claims_doc_findings(cfg: &claims::Config, path: &str, text: &str) -> Vec<Finding> {
    claims::scan_text(cfg, path, text)
        .into_iter()
        .map(|finding| {
            at(
                finding.location,
                format!("forbidden claims phrase: {}", finding.message),
            )
        })
        .collect()
}

/// The model document and the copy file must exist.
fn documents_findings(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    for path in [ERRORS, ERRORS_COPY] {
        if read_text(&root.join(path)).is_err() {
            out.push(at(path, "the file does not exist (T-0020 deliverable)"));
        }
    }
    out
}

/// The delivered journey texts, keyed by their repository path.
fn journey_texts(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for file in walk_files(&root.join(JOURNEYS)) {
        if !file
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("md"))
        {
            continue;
        }
        let Ok(text) = read_text(&file) else {
            continue;
        };
        let name = file
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        out.push((format!("{JOURNEYS}/{name}"), text));
    }
    out
}

/// The `Error path` codes of every journey's `## Steps` table.
fn journey_error_codes(journeys: &[(String, String)]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (_, text) in journeys {
        let Some((header, rows)) = section_table(text, "Steps") else {
            continue;
        };
        let Some(index) = column(&header, "Error path") else {
            continue;
        };
        for (_, row) in rows {
            let Some(cell) = row.get(index) else {
                continue;
            };
            for code in err_tokens(cell) {
                out.insert(code);
            }
        }
    }
    out
}

/// Whole T-0020 check on the repository at `root`, reading the checksum-verified master specification.
pub fn check(root: &Path, spec: &str) -> Vec<Finding> {
    check_with_spec(root, spec)
}

/// Whole T-0020 check on the repository at `root`, with the master specification text.
pub fn check_with_spec(root: &Path, spec: &str) -> Vec<Finding> {
    let mut out = documents_findings(root);
    let doc = read_text(&root.join(ERRORS)).unwrap_or_default();
    let ftl = read_text(&root.join(ERRORS_COPY)).unwrap_or_default();
    let deck = read_text(&root.join(COPY_DECK)).unwrap_or_default();
    let catalog = error_catalog(spec);
    if catalog.is_empty() {
        out.push(at(
            "docs/SPEC.md",
            "the B7 error catalog has no ERR rows, so the error classes cannot be checked (T-0020 step 1)",
        ));
    }
    let b6 = b6_pairs(spec);
    if b6.is_empty() {
        out.push(at(
            "docs/SPEC.md",
            "the B6 API catalog has no METHOD path rows, so the retry table cannot be checked (T-0020 step 3)",
        ));
    }
    let conventions = b6_conventions(spec);
    let components = component_names(spec);
    let criteria = a11y_criteria(spec);
    let screens = visitor_screens(spec);
    let detail = s140_detail(spec);
    let journeys = journey_texts(root);
    let b13: BTreeMap<String, String> = b13_rows(spec).into_iter().collect();
    let mut values: BTreeMap<String, String> = b13.clone();
    for (key, value) in ftl_values(&ftl) {
        values.entry(key).or_insert(value);
    }
    out.extend(structure_findings(&doc));
    out.extend(class_table_findings(&doc, &catalog, &components));
    out.extend(pattern_selection_findings(&doc));
    out.extend(classification_findings(&doc, &catalog));
    out.extend(journey_coverage_findings(&doc, &journeys, &catalog));
    out.extend(request_id_findings(&doc, &catalog, &b6, detail.as_deref()));
    out.extend(retry_findings(&doc, &b6, &conventions));
    out.extend(poll_findings(&doc, &b6));
    out.extend(visitor_page_findings(
        &doc,
        &screens,
        &catalog,
        detail.as_deref(),
    ));
    out.extend(visitor_constraint_findings(&doc, &values));
    let claims_cfg = claims::load_config(root).ok();
    out.extend(copy_key_findings(
        &doc,
        &b13,
        &deck,
        &ftl,
        claims_cfg.as_ref(),
    ));
    out.extend(offline_findings(&doc));
    out.extend(job_failure_findings(&doc));
    out.extend(logging_findings(&doc));
    out.extend(accessibility_findings(&doc, &components, &criteria));
    out.extend(security_findings(&doc));
    out.extend(authentication_findings(&doc, &catalog));
    out.extend(cross_table_findings(&doc, &journeys, &catalog));
    out.extend(conflict_scope_findings(&doc, &catalog));
    out.extend(consistency_findings(&doc));
    out.extend(citation_findings(&doc, &catalog));
    if let Some(cfg) = claims_cfg.as_ref() {
        out.extend(claims_doc_findings(cfg, ERRORS, &doc));
    }
    out
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Fixtures shared by the T-0020 tests and the `ux-docs` fixture tree.
    //!
    //! The Lead appends [`spec_section`] to the fixture specification and writes [`documents`] into the fixture tree.
    //! The section is self-contained: it carries its own B7, B6, B11.8, B11.11, B12.1 and B12.2 rows, because the
    //! specification readers of this module accumulate every section whose heading starts with the registry prefix.

    /// The fixture model document.
    pub(crate) fn errors_document() -> String {
        String::from(
            r#"# Error handling (fixture)

The fixture model: nine task classes plus the authentication row, five patterns and the numbered rules the check enforces.

## Class and pattern matrix

| Class | Patterns | Where it appears | Clears | Focus | Example |
| --- | --- | --- | --- | --- | --- |
| validation | inline, summary, banner | Each field via FormField, the top of the form via ErrorSummary and the acknowledgement banner via Banner | when the field becomes valid or the acknowledgement is given | focus moves to the summary and then the first invalid field | ERR-VAL-001 |
| permission | page, banner | The page frame via ErrorState and the problem bar via Banner | when the role or the session changes | focus moves to the page heading | ERR-PERM-001 |
| authentication | inline, summary, page, banner | The credential field and the form via FormField and ErrorSummary, the sign-in page via ErrorState and the step-up notice via Banner | when the credential, the code or the session succeeds | focus moves to the credential field or the summary and the page names the next step | ERR-AUTH-002 |
| not found | page | The response page via ErrorState | never for the same address | focus moves to the page heading | ERR-PERM-002 |
| conflict | banner, toast | The edited region via Banner and a transient notice via Toast | when the resource is reloaded after a version or key conflict | focus stays on the reload control in the banner | ERR-CONC-001 |
| rate limit | banner, toast | The affected region via Banner and a transient notice via Toast | when the reset time passes | focus stays on the retry control in the banner | ERR-RATE-001 |
| quota | page, banner | The plan section via Banner and the plan page via ErrorState | when the plan changes | focus moves to the plan heading | ERR-RATE-002 |
| upstream | page, banner | The response page via ErrorState and the problem bar via Banner | when the dependency answers again | focus moves to the page heading | ERR-ORIGIN-003 |
| system | page, toast | The response page via ErrorState and a transient notice via Toast | when the next request succeeds | focus moves to the page heading | ERR-SYS-001 |
| maintenance | page, banner | The app frame via Banner and the maintenance page via ErrorState | when the maintenance window ends | focus moves to the maintenance heading | ERR-SYS-003 |

## Classification rules

| HTTP status | Class |
| --- | --- |
| 400 | validation |
| 413 | validation |
| 415 | validation |
| 422 | validation |
| 401 | permission |
| 403 | permission |
| 404 | not found |
| 421 | not found |
| 409 | conflict |
| 412 | conflict |
| 428 | conflict |
| 429 | rate limit |
| 500 | system |
| 503 | system |
| 502 | upstream |
| 504 | upstream |

## Classification exceptions

Conflict means a version or key conflict only, so the reload control belongs to these codes and to no other 409 cause.

| Code | Class | Why |
| --- | --- | --- |
| ERR-AUTH-001 | authentication | The remedy is to sign in; a credential challenge is not an authorisation role decision. |
| ERR-AUTH-002 | authentication | The remedy is to correct the credential; the message is field-level and identical for an unknown account. |
| ERR-AUTH-003 | authentication | The remedy is a fresh verification code; the message is field-level. |
| ERR-AUTH-005 | authentication | The remedy is to verify the email address first; the page names the next step. |
| ERR-AUTH-006 | authentication | The remedy is to set up the second factor; the page redirects to enrolment. |
| ERR-AUTH-007 | authentication | The remedy is to sign in again; the session redirect carries a return URL. |
| ERR-AUTH-008 | authentication | The remedy is step-up re-authentication for this action. |
| ERR-AUTH-012 | authentication | The remedy is a valid API key; the message says nothing about the key prefix. |
| ERR-GATE-001 | authentication | The remedy is to authenticate to the protected area; no application detail is revealed. |
| ERR-AUTH-017 | validation | This passkey is already on the account, so the message is inline on the credential field. |
| ERR-ORG-001 | validation | The slug is a field value the person changes; nothing has a version or a key. |
| ERR-ORG-003 | validation | A pending invitation is an inline condition on the email field that the person resends or revokes. |
| ERR-ORG-004 | validation | The last-owner rule is a form rule the person fixes before saving. |
| ERR-DOM-002 | validation | The claim failure is a field problem with a dispute path, not a version conflict. |
| ERR-DOM-004 | upstream | Ownership proof waits on an external DNS or HTTP check; the interface re-checks. |
| ERR-DOM-005 | system | The domain is in an internal lifecycle state; the interface waits and re-checks. |
| ERR-DOM-007 | upstream | Delegation is observed by external resolvers; the interface shows the observed NS and re-checks. |
| ERR-DNS-002 | validation | The record set conflicts on the form; the person edits the record before saving. |
| ERR-DNS-005 | validation | The change would remove required records; the person adjusts it after the preview. |
| ERR-TLS-005 | upstream | The authority refuses because an external CAA record forbids issuance; the person fixes DNS. |
| ERR-ACME-005 | upstream | The authority is blocked by an external CAA set; the message shows the offending records. |
| ERR-WAF-006 | maintenance | Safe mode is a deliberate time-boxed operator state; the person waits or ends it. |
| ERR-BAN-002 | permission | The self-lockout policy refuses the ban; the preview names the address and the exemption path. |
| ERR-PLAT-002 | permission | The never-ban policy refuses the action; the person changes the exemption with step-up. |
| ERR-LOCAL-001 | system | The local runtime profile does not supply this capability; the page explains the profile. |
| ERR-GATE-004 | permission | The self-lockout guard refuses the rule; the person acknowledges it after the preview. |
| ERR-SENT-002 | validation | The promotion request is incomplete; the message lists the missing prerequisites. |
| ERR-BYPASS-001 | upstream | The lockdown proof depends on the external path to the origin; the interface offers verification steps. |
| ERR-APIDISC-002 | validation | The change must be acknowledged after the preview; there is no version or key to reload. |
| ERR-ACME-002 | upstream | The authority refused the order, so the cause is upstream of HDD. |
| ERR-BAN-004 | quota | The ban list limit is a plan capacity and not a state conflict. |
| ERR-DNS-007 | quota | The zone size limit is a plan capacity and not a state conflict. |
| ERR-DOM-006 | quota | The domain limit is a plan capacity and not a field validation. |
| ERR-KEY-001 | permission | A scope the role lacks is an authorisation refusal with a 422 status. |
| ERR-ORG-005 | permission | A role that this action excludes is an authorisation refusal. |
| ERR-RATE-002 | quota | The plan quota is exhausted, so waiting does not clear it. |
| ERR-SYS-003 | maintenance | Maintenance is an operator-planned state, not an unexpected failure. |
| ERR-SYS-004 | maintenance | A paused signup window is an operator-planned state. |
| ERR-WAF-007 | permission | The self-lockout policy refuses the change; the preview names the current address. |

## Authentication class

Authentication is a named subset of the permission family: the errors whose remedy is to authenticate, verify or
re-authenticate. Credential mistakes use inline and summary; a required verification or step-up uses a page or a
banner with the next step. The role, scope and suspension refusals stay in the permission class.

| Code | Status | Pattern | Remedy |
| --- | --- | --- | --- |
| ERR-AUTH-001 | 401 | page | Redirect to sign-in with a return URL and no account hint. |
| ERR-AUTH-002 | 401 | inline | Correct the email or password; both fields share one message. |
| ERR-AUTH-003 | 401 | inline | Request a fresh verification code and enter it. |
| ERR-AUTH-005 | 403 | page | Verify the email address through the link that was sent. |
| ERR-AUTH-006 | 403 | page | Enrol a second factor before continuing to the console. |
| ERR-AUTH-007 | 401 | page | Sign in again and return to the interrupted action. |
| ERR-AUTH-008 | 403 | banner | Re-authenticate for this action and continue where it stopped. |
| ERR-AUTH-012 | 401 | banner | Replace the API key or use a key with the required scope. |
| ERR-GATE-001 | 401 | page | Authenticate to the protected area through its own sign-in form. |

## Pattern selection

- P-1 One response carries one B7 code, so the interface derives one class from the code and the status table.
- P-2 When several classes are present at once, the page-level message shows the highest class in this order: maintenance, system, upstream, quota, rate limit, conflict, authentication, permission, not found, validation.
- P-3 Validation never becomes a page: the fields show inline messages and the form shows ErrorSummary.
- P-4 A toast carries a transient notice only and a banner carries a persistent condition; a page carries an error with no screen left.
- P-5 Focus goes to the summary after a validation failure, to the page heading after a page error, and never into a toast or a banner.
- P-6 Inline messages persist until the field is valid; toasts clear after 8 seconds or on dismissal; banners persist until the condition clears; pages persist.
- P-7 A class never renders with a lower pattern than the matrix allows: when in doubt the more persistent pattern wins.
- P-8 One cause appears once per channel and every repeat uses the same text: a validation failure may show the summary, the inline message and a toast that repeats the sentence, and a job failure may show a notification, an inline status and a repeating toast.

### Pattern copy

| Pattern | Copy keys |
| --- | --- |
| inline | `error-validation-inline` |
| summary | `error-summary-title` |
| toast | `error-toast-retry` |
| banner | `error-banner-persistent` |
| page | `error-page-title`, `error-page-body` |

## Request ID and Ray ID

Every API problem document carries `request_id` from the B6.1 conventions. A visitor page shows a Ray ID whose shape is `[0-9a-f]{16}-HDD1`.

- RID-1 The API surface shows `request_id` in a copy field labelled with `error-request-id-label`.
- RAY-1 Show the Ray ID on S-140 and S-143 with `error-ray-id-label`; the copy button is `error-copy-ray-id`.
- RAY-2 The copy buttons are progressive enhancement: `error-copy-request-id` copies the request id and `error-copy-ray-id` copies the Ray ID.
- RAY-3 Support looks up a Ray ID with `GET P/support/ray/{ray}` and reads the request with `GET D/events/{ray}`.
- RAY-4 Never shown: trace ids, span ids, an internal hostname, a stack trace and a rule id.

## Retry and idempotency

B6.1 requires `Idempotency-Key` on every POST that creates a resource or triggers a job, `If-Match` on updates and `Retry-After` on a 429 answer. The table separates the safe actions from the unsafe ones.

| User action | Method | B6 row | Retry | Idempotency-Key | Precondition |
| --- | --- | --- | --- | --- | --- |
| Load the audit log | GET | `GET O/audit` | safe | not required | none |
| Set the integration mode | PUT | `PUT D/integration` | safe | not required | If-Match |
| Delete a DNS record | DELETE | `DELETE D/dns/records/{rec}` | safe | not required | If-Match |
| Update a DNS record | PATCH | `PATCH D/dns/records/{rec}` | safe with If-Match | not required | If-Match |
| Add a domain | POST | `POST O/domains` | safe with Idempotency-Key | required | none |
| Start an existing-DNS scan | POST | `POST D/scan` | safe with Idempotency-Key | required | none |
| Sign in | POST | `POST /auth/login` | unsafe | not required | none |
| Send a verification email | POST | `POST /auth/resend-verification` | unsafe | not required | none |
| Start a password reset email | POST | `POST /auth/forgot-password` | unsafe | not required | none |
| Test a webhook delivery | POST | `POST O/webhooks/{whk}/test` | unsafe | not required | none |
| Rotate a webhook signing secret | POST | `POST O/webhooks/{whk}/rotate-secret` | unsafe | not required | none |
| Enter platform emergency safe mode | POST | `POST P/emergency/safe-mode` | unsafe | not required | none |
| Remove a ban | DELETE | `DELETE D/bans/{ip}` | safe | not required | none (a ban has no ETag) |

- RID-2 A 429 answer carries `Retry-After` and shows a countdown with `error-retry-after`; nothing is re-sent before it.
- RID-3 A retried mutation reuses the same Idempotency-Key; a new intent gets a new key and the button uses `error-retry-action`.
- RID-4 A background poll backs off and stops at a terminal state, as the next table states.

### Background polls

| Poll | Method and path | First interval | Backoff | Stop |
| --- | --- | --- | --- | --- |
| Scan progress | `GET D/scan/{scan}` | 2 s | doubles to a 30 s cap | terminal state or 15 min |
| Certificate order | `GET D/tls/acme-status` | 5 s | doubles to a 60 s cap | issued, failed or stopped |
| Event stream | `GET D/events/stream` | 1 s connect | reconnect doubles to a 30 s cap | page hidden or closed |

## Visitor pages S-140 to S-148

| Page | Name | Status | B7 code | Copy keys | JSON variant |
| --- | --- | --- | --- | --- | --- |
| S-140 | Block page | 403 | ERR-VISITOR-403 | `visitor-block-page-title`, `visitor-block-page-body`, `visitor-block-page-ray` | application/problem+json {"error":"access_denied","ray_id"} |
| S-141 | Challenge page | 200 | none in B7 | `visitor-challenge-title`, `visitor-challenge-progress` | application/problem+json |
| S-142 | Rate-limit page | 429 | ERR-VISITOR-429 | `visitor-rate-limit-title`, `visitor-rate-limit-body`, `error-retry-after` | application/problem+json |
| S-143 | Origin error page | 502/504 | ERR-VISITOR-502, ERR-VISITOR-504 | `visitor-origin-error-title`, `visitor-origin-error-body` | application/problem+json |
| S-144 | Unknown host page | 404 | none in B7 (data-plane neutral 404) | `visitor-unknown-host-title`, `visitor-unknown-host-body` | application/problem+json |
| S-145 | Appeal form | 200 | none in B7 | `visitor-appeal-title` | application/problem+json |
| S-146 | Appeal received | 200 | none in B7 | `visitor-appeal-sent` | application/problem+json |
| S-147 | Under attack interstitial | 200 | none in B7 | `visitor-under-attack-title`, `visitor-under-attack-body` | application/problem+json |
| S-148 | Domain suspended page | 503 | none in B7 | `visitor-suspended-title`, `visitor-suspended-body` | application/problem+json |

## Visitor page constraints

- V-1 No rule name or rule id appears in any visitor copy string. Detect: the check scans every cited page key value for rule words.
- V-2 No stack trace, exception text or source path appears in visitor copy. Detect: the same value scan looks for trace words.
- V-3 No internal hostname, private address or dependency name appears. Detect: the value scan looks for internal words.
- V-4 S-144 is a neutral 404 whose copy carries no tenant or brand variable. Detect: the value scan of the S-144 keys for $ variables and tenant words.
- V-5 S-148 names no tenant detail and carries no tenant variable. Detect: the same scan of the S-148 keys.
- V-6 No copy blames the visitor or repeats the matched payload. Detect: the value scan looks for blame words.
- V-7 The Ray ID appears on S-140 and matches the Ray shape. Detect: the S-140 keys must include a key whose value carries ray_id.
- V-8 The JSON variant is application/problem+json and S-140 names error and ray_id. Detect: the page table column and the body check.
- V-9 Every visitor page loads no external request and stays inside the 20 KB page budget. Detect: the page-weight test of T-0065 A4.
- V-10 Every visitor page uses inline CSS with a nonce and dark or light from prefers-color-scheme. Detect: the CSP test of T-0065 step 4.

## Offline and flaky networks

- O-1 HTMX partial updates never fail silently: a failed swap shows an inline message or a toast in the same region. Detect: a browser test forces an offline answer and asserts a visible message and a role="alert" announcement.
- O-2 The last confirmed values stay on screen and are marked stale with `error-stale-partial`; a failed optimistic value is reverted. Detect: the test asserts the stale marking and the reverted value.
- O-3 The failed region shows `error-retry-action` and only that region is retried. Detect: the test forces one region to fail and asserts the retry target.
- O-4 Automatic retry applies to GET and poll swaps with backoff; a mutation is never re-sent automatically and waits for the user. Detect: the test forces a POST failure and asserts no second request.
- O-5 An offline banner uses `error-offline-banner` and a reconnecting status uses `error-reconnect-status`; both clear when the connection returns. Detect: the test toggles the connection and asserts the messages.
- O-6 The rest of the page stays interactive and one failed region never replaces the page. Detect: the test asserts the other regions keep their state.
- O-7 The offline cache and install behaviour of the PWA is deferred to P32; this model defines the request-failure pattern only. Detect: the scope review names P32.

## Long-running job failures

- L-1 A failed job raises a notification addressed to the person who started it, using `error-job-failed-notification`. Detect: the worker test asserts the notification target.
- L-2 The job inline status switches to failed with `error-job-failed-inline` and the last successful result stays visible. Detect: the test reads the inline status and the retained result.
- L-3 The notification names the event reference and the Ray ID or request id, so support can look it up. Detect: the test reads the reference from the message.
- L-4 Retrying a failed job starts a new job and never reuses the old job id. Detect: the test compares the two job ids.
- L-5 A job failure shows the notification and the inline status; a toast may repeat the same sentence but never carries the news alone. Detect: the test asserts the notification and the inline channel.

## Logging of errors

- LG-1 Client-side: nothing is logged. No error text, code, request id or form value goes to the console, a client log or client telemetry. Detect: the browser test stubs the console and the beacon and asserts zero calls.
- LG-2 Server-side: one structured record per error with `request_id`, code, status, route template and duration, and never the raw message text. Detect: the log schema test parses the record.
- LG-3 No request or response body is logged in full; redacted evidence is capped at 512 bytes (R-25). Detect: the log corpus test measures the capped field.
- LG-4 No secret, token, cookie, password, Authorization header or PII is logged. Detect: the log corpus scan for these patterns.
- LG-5 A stack trace stays server-side and never enters the API document or the visitor page. Detect: the contract test reads the problem document keys.

## Accessibility of errors

The rules follow [ACCESSIBILITY.md](ACCESSIBILITY.md) and [SECURITY-UX.md](SECURITY-UX.md).

| Pattern | Focus | Role | Text not colour | Component |
| --- | --- | --- | --- | --- |
| inline | focus stays in the field and the message is linked with aria-describedby | aria-describedby | the message is text and the icon is decoration, never colour only | FormField |
| summary | focus moves to the summary heading | role="alert" | every item is a link with text, never colour only | ErrorSummary |
| toast | focus never moves into the toast | role="alert" | the outcome is text and the icon is decoration, never colour only | Toast |
| banner | focus moves to the banner text | role="alert" | the condition is text and it is never colour only | Banner |
| page | focus moves to the page heading | main landmark | the failure is text and it is never colour only | ErrorState |

The accessibility criteria are 3.3.1, 3.3.3 and 4.1.3 of the B11.11 contract.

## Security notes

- SEC-1 No stack trace or internals detail appears in an API document or a visitor page. Detect: the contract test reads the problem document keys.
- SEC-2 Permission denied never reveals whether a resource exists: a cross-tenant read is 404 `ERR-PERM-002`, not 403, and the message is the generic not found text (R-20). Detect: the BOLA test reads a foreign resource and asserts 404.
- SEC-3 Authentication errors do not enumerate accounts: an unknown email and a wrong password both return `ERR-AUTH-002`. Detect: the two answers are compared byte for byte.
- SEC-4 No internal hostname or dependency name appears in a user-facing error. Detect: the value scan of the error copy.
- SEC-5 A 403 names the permission only to members (`ERR-PERM-001`) and never names the resource. Detect: the response test of the permission message.
- SEC-6 The absent and the forbidden case use the same text and the same time budget outside the tenant (R-20). Detect: the enumeration test compares both.

## Journey error-path coverage

| Class | Error codes |
| --- | --- |
| validation | none in the delivered journeys |
| permission | none in the delivered journeys |
| authentication | ERR-AUTH-002 |
| not found | none in the delivered journeys |
| conflict | none in the delivered journeys |
| rate limit | none in the delivered journeys |
| quota | none in the delivered journeys |
| upstream | none in the delivered journeys |
| system | none in the delivered journeys |
| maintenance | none in the delivered journeys |

## Copy inventory

| Key | Source | Exact English text |
| --- | --- | --- |
| visitor-block-page-title | errors.ftl | Access denied |
| visitor-block-page-body | errors.ftl | Your request looked like an attack, so it was blocked. |
| visitor-block-page-ray | errors.ftl | Reference: { $ray_id } |
| visitor-challenge-title | errors.ftl | Checking your browser |
| visitor-challenge-progress | errors.ftl | The check finishes automatically. |
| visitor-rate-limit-title | errors.ftl | Too many requests |
| visitor-rate-limit-body | errors.ftl | Too many requests reached this site from your network. |
| error-retry-after | errors.ftl | Try again after { $seconds } seconds. |
| visitor-origin-error-title | errors.ftl | This website is unavailable |
| visitor-origin-error-body | errors.ftl | The site could not be reached. Try again in a moment. |
| visitor-unknown-host-title | errors.ftl | Site not found |
| visitor-unknown-host-body | errors.ftl | No website is configured at this address. |
| visitor-appeal-title | errors.ftl | Report a mistaken block |
| visitor-appeal-sent | errors.ftl | Thank you. The site owner can review your report. |
| visitor-under-attack-title | errors.ftl | A quick check is running |
| visitor-under-attack-body | errors.ftl | The check finishes automatically and then the site opens. |
| visitor-suspended-title | errors.ftl | Website unavailable |
| visitor-suspended-body | errors.ftl | This website is paused. Contact the site owner if it continues. |
| error-validation-inline | errors.ftl | Enter a valid value for this field. |
| error-summary-title | errors.ftl | Check the highlighted fields. |
| error-toast-retry | errors.ftl | The change was not saved. Try again. |
| error-banner-persistent | errors.ftl | Part of this page is unavailable until the problem clears. |
| error-page-title | errors.ftl | Something went wrong |
| error-page-body | errors.ftl | The action did not complete. The reference below helps support find the cause. |
| error-request-id-label | errors.ftl | Request ID: { $request_id } |
| error-ray-id-label | errors.ftl | Ray ID: { $ray_id } |
| error-copy-ray-id | errors.ftl | Copy Ray ID |
| error-copy-request-id | errors.ftl | Copy request ID |
| error-retry-action | errors.ftl | Try again |
| error-offline-banner | errors.ftl | You are offline. Changes are sent when the connection returns. |
| error-reconnect-status | errors.ftl | Connection lost. Retrying in { $seconds } seconds. |
| error-stale-partial | errors.ftl | The values on screen may be out of date. |
| error-job-failed-inline | errors.ftl | This job failed. The last result stays visible. |
| error-job-failed-notification | errors.ftl | A background job failed. Open it to see the reference. |
"#,
        )
    }

    /// The fixture copy file for the fixture model document.
    pub(crate) fn copy_document() -> String {
        String::from(
            r#"# T-0020 fixture copy. Keys are lowercase semantic words joined by hyphens.
error-validation-inline = Enter a valid value for this field.
error-summary-title = Check the highlighted fields.
error-toast-retry = The change was not saved. Try again.
error-banner-persistent = Part of this page is unavailable until the problem clears.
error-page-title = Something went wrong
error-page-body = The action did not complete. The reference below helps support find the cause.
error-request-id-label = Request ID: { $request_id }
error-ray-id-label = Ray ID: { $ray_id }
error-copy-ray-id = Copy Ray ID
error-copy-request-id = Copy request ID
error-retry-action = Try again
error-retry-after = Try again after { $seconds } seconds.
error-offline-banner = You are offline. Changes are sent when the connection returns.
error-reconnect-status = Connection lost. Retrying in { $seconds } seconds.
error-stale-partial = The values on screen may be out of date.
error-job-failed-inline = This job failed. The last result stays visible.
error-job-failed-notification = A background job failed. Open it to see the reference.
visitor-block-page-title = Access denied
visitor-block-page-body = Your request looked like an attack, so it was blocked.
visitor-block-page-ray = Reference: { $ray_id }
visitor-challenge-title = Checking your browser
visitor-challenge-progress = The check finishes automatically.
visitor-rate-limit-title = Too many requests
visitor-rate-limit-body = Too many requests reached this site from your network.
visitor-origin-error-title = This website is unavailable
visitor-origin-error-body = The site could not be reached. Try again in a moment.
visitor-unknown-host-title = Site not found
visitor-unknown-host-body = No website is configured at this address.
visitor-appeal-title = Report a mistaken block
visitor-appeal-sent = Thank you. The site owner can review your report.
visitor-under-attack-title = A quick check is running
visitor-under-attack-body = The check finishes automatically and then the site opens.
visitor-suspended-title = Website unavailable
visitor-suspended-body = This website is paused. Contact the site owner if it continues.
"#,
        )
    }

    /// The fixture documents keyed by their repository path (the Lead writes them into the fixture tree).
    pub(crate) fn documents() -> Vec<(String, String)> {
        vec![
            (super::ERRORS.to_owned(), errors_document()),
            (super::ERRORS_COPY.to_owned(), copy_document()),
        ]
    }

    /// Specification rows the T-0020 fixture needs: B7 codes, B6 rows and conventions, B11.8 components, B11.11
    /// criteria, the B12.1 visitor rows and the B12.2 S-140 detail.
    pub(crate) fn spec_section() -> String {
        String::from(
            r#"### B7. Error catalog (T-0020 fixture rows)

| Code | HTTP | Title | Notes |
| --- | --- | --- | --- |
| ERR-AUTH-002 | 401 | Email or password is incorrect | Identical for unknown email and wrong password. |
| ERR-AUTH-004 | 429 | Too many attempts | With a retry hint. |
| ERR-VAL-001 | 422 | Invalid request body | `errors[]` has JSON-pointer paths. |
| ERR-PERM-002 | 404 | Not found | Used instead of 403 for cross-tenant resources. |
| ERR-SYS-001 | 503 | Service temporarily unavailable | Maintenance or dependency down. |
| ERR-PERM-001 | 403 | You do not have permission for this action | Names the permission only to members. |
| ERR-ACME-002 | 422 | Domain validation failed | The authority refused the challenge. |
| ERR-BAN-004 | 409 | Ban list limit reached | Oldest-expiry eviction explained. |
| ERR-DNS-007 | 409 | Zone size limit reached | Plan capacity. |
| ERR-DOM-006 | 422 | Domain limit reached for your plan | Plan capacity. |
| ERR-KEY-001 | 422 | Scope not permitted for your role | Authorisation refusal. |
| ERR-ORG-005 | 422 | Role not allowed for this action | Authorisation refusal. |
| ERR-SYS-004 | 503 | Signups are temporarily paused | Operator-planned state. |
| ERR-WAF-007 | 422 | Change would block your own address | Self-lockout guard. |
| ERR-CONC-001 | 412 | Resource changed, reload and retry | `If-Match` mismatch. |
| ERR-RATE-001 | 429 | Rate limit exceeded | Class and reset time in headers. |
| ERR-RATE-002 | 429 | Quota exceeded | Plan quota. |
| ERR-ORIGIN-003 | 502 | Origin did not respond | Connectivity test. |
| ERR-SYS-003 | 503 | Platform is in maintenance mode | |
| ERR-VISITOR-403 | 403 | Access denied (Ray ID) | Block page. No rule detail. |
| ERR-VISITOR-429 | 429 | Too many requests | |
| ERR-VISITOR-502 | 502 | Bad gateway | Branded. |
| ERR-VISITOR-504 | 504 | Gateway timeout | Branded. |
| ERR-AUTH-001 | 401 | Authentication required | |
| ERR-AUTH-003 | 401 | Verification code is incorrect or expired | |
| ERR-AUTH-005 | 403 | Email verification required | |
| ERR-AUTH-006 | 403 | Multi-factor setup required | |
| ERR-AUTH-007 | 401 | Session expired | |
| ERR-AUTH-008 | 403 | Re-authentication required | |
| ERR-AUTH-012 | 401 | API key invalid | |
| ERR-GATE-001 | 401 | Authentication required for this area | |
| ERR-AUTH-017 | 409 | Passkey already registered | |
| ERR-ORG-001 | 409 | Organization slug unavailable | |
| ERR-ORG-003 | 409 | Pending invitation exists | |
| ERR-ORG-004 | 409 | An organization must keep at least one owner | |
| ERR-DOM-002 | 409 | Domain is already protected by another account | |
| ERR-DOM-004 | 409 | Ownership has not been verified | |
| ERR-DOM-005 | 409 | Domain is not in a state that allows this action | |
| ERR-DOM-007 | 409 | Delegation not detected yet | |
| ERR-DNS-002 | 409 | Conflicting record (CNAME with other data) | |
| ERR-DNS-005 | 409 | Change would remove records required for the domain to work | |
| ERR-TLS-005 | 409 | CAA record forbids issuance | |
| ERR-ACME-001 | 409 | Certificate order is already in progress for this name | |
| ERR-ACME-005 | 409 | CAA record forbids this authority | |
| ERR-WAF-004 | 409 | Revision conflict | |
| ERR-WAF-006 | 409 | Safe mode is active | |
| ERR-BAN-002 | 409 | Ban would affect your own address or a never-ban entry | |
| ERR-PLAT-002 | 409 | Operation blocked by the never-ban list | |
| ERR-PLAT-003 | 409 | Rule pack rollout already in progress | |
| ERR-LOCAL-001 | 409 | This action is not available in the local runtime profile | |
| ERR-GATE-004 | 409 | This rule would lock out your current session or address | |
| ERR-SENT-002 | 409 | Sentinel promotion prerequisites are not met | |
| ERR-BYPASS-001 | 409 | This site can still be reached directly; block mode needs a verified lockdown | |
| ERR-APIDISC-002 | 409 | Enforcement would block recently observed traffic | |
| ERR-IDEMP-001 | 409 | Idempotency key reused with a different request | |
| ERR-CONC-002 | 428 | If-Match header required | |

### B6.1 Conventions (T-0020 fixture rows)

- Errors: the problem document carries `request_id`; no stack traces and no internal hostnames.
- Concurrency: `ETag` on mutable resources and `If-Match` required on PATCH, PUT and DELETE of those resources; `Idempotency-Key` on every POST that creates a resource or triggers a job.
- A 429 response carries `Retry-After`.

### B6.2 Authentication and account (T-0020 fixture rows)

| Method and path | Auth | Permission or class | Notes |
| --- | --- | --- | --- |
| `POST /auth/login` | public | auth | Returns the next step. |
| `GET O/audit` | session | audit.read | The audit log. |
| `POST O/domains` | session | domain.create | Creates a domain. |
| `PUT D/integration` | session | domain.update | Selects the integration mode. |
| `PATCH D/dns/records/{rec}` | session | dns.write | `If-Match` required. |
| `DELETE D/dns/records/{rec}` | session | dns.write | `If-Match` required. |
| `POST D/scan` | session | domain.create | Starts an async job. |
| `GET D/scan/{scan}` | session | domain.create | Polls the job. |
| `DELETE D/bans/{ip}` | session | ban.delete | 404 when the address is not banned. |
| `GET D/events/{ray}` | session | event.read | Reads one event. |
| `GET D/events/stream` | session | event.stream | SSE with Last-Event-ID. |
| `GET D/tls/acme-status` | session | tls.read | Order state. |
| `GET P/support/ray/{ray}` | admin | platform.support | Support lookup with a reason header. |
| `POST /auth/resend-verification` | public | auth | Sends the verification email again. |
| `POST /auth/forgot-password` | public | auth | Sends the reset email. |
| `POST O/webhooks/{whk}/test` | session | integration.write | Sends a test delivery. |
| `POST O/webhooks/{whk}/rotate-secret` | session | integration.write | Rotates the signing secret. |
| `POST P/emergency/safe-mode` | admin | platform.emergency | Enters emergency safe mode. |
| `POST /me/sessions/revoke-others` | session | PERM-account.self | Revokes the other sessions. |

### B11.8 Component inventory (T-0020 fixture rows)

| Component | Contract (summary) |
| --- | --- |
| FormField / ErrorSummary | Focus moves to the summary. |
| Toast | A polite live region. |
| Banner / Alert | Info, success, warning and danger. |
| EmptyState / ErrorState | An explanation and a next action. |
| CopyField / CodeBlock | Read-only monospace with a copy button. |
| RayIDChip | A monospace copyable identifier. |

### B11.11 Accessibility contract (T-0020 fixture rows)

| Criterion | Rule in HDD |
| --- | --- |
| 3.3.1 / 3.3.3 / 3.3.4 | Errors identified in text with suggestions. |
| 2.4.3 / 2.4.7 | Logical focus order and visible focus. |
| 4.1.3 | Status messages use live regions. |

### B12.1 Screen table (T-0020 fixture rows)

| ID | Name | Purpose and key content |
| --- | --- | --- |
| S-140 | Block page | The visitor block page. |
| S-141 | Challenge page | The automatic browser check. |
| S-142 | Rate-limit page | 429 with the wait time. |
| S-143 | Origin error page | A branded upstream error. |
| S-144 | Unknown host page | A neutral 404. |
| S-145 | Appeal form | The appeal form. |
| S-146 | Appeal received | The appeal confirmation. |
| S-147 | Under attack interstitial | The under-attack check. |
| S-148 | Domain suspended page | A neutral suspended notice. |

#### S-140 Block page (visitor)

Server-rendered; no external requests; elements: title, body, Ray ID with a copy button and the appeal link.
For `Accept: application/json` returns `{error:"access_denied", ray_id}`. Status 403. Content never includes which rule fired.
"#,
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]

    use super::fixtures::{copy_document, errors_document, spec_section};
    use super::*;

    /// The findings joined for assertion messages.
    fn joined(findings: &[Finding]) -> String {
        findings
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The fixture specification.
    fn fixture_spec() -> String {
        spec_section()
    }

    /// The fixture B7 catalog.
    fn catalog() -> BTreeMap<String, CatalogEntry> {
        error_catalog(&fixture_spec())
    }

    /// The fixture document.
    fn doc() -> String {
        errors_document()
    }

    /// The fixture copy file.
    fn ftl() -> String {
        copy_document()
    }

    /// The fixture copy values.
    fn values() -> BTreeMap<String, String> {
        ftl_values(&ftl())
    }

    /// A claims configuration with one phrase for the claims tests.
    fn claims_cfg() -> claims::Config {
        toml::from_str(
            "phrases = [{ text = \"absolute protection\" }]\n\
             include = [\"docs/UX/**\", \"i18n/en/**\"]\n\
             exclude = []\n\
             extensions = [\"md\", \"ftl\"]\n",
        )
        .expect("fixture claims configuration")
    }

    /// One journey text whose steps all carry `codes`.
    fn journey(codes: &str) -> String {
        format!(
            "# J-01 Fixture journey\n\nPersona: [Maya](../personas/maya.md).\n\n## Steps\n\n\
             | Step | User action | System response | Screen | Data collected | Error path | Emotional state | Copy key | Metric |\n\
             | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n\
             | 1 | Opens the page. | Renders the page. | S-001 | none | {codes}: the page shows the error. | calm | fixture-step-title | - |\n"
        )
    }

    /// The fixture journeys with `codes` on their error path.
    fn journeys(codes: &str) -> Vec<(String, String)> {
        vec![("docs/UX/journeys/J-01.md".to_owned(), journey(codes))]
    }

    #[test]
    fn t20_a_complete_fixture_passes_every_rule() {
        let spec = fixture_spec();
        let doc = doc();
        let ftl = ftl();
        let catalog = catalog();
        let b6 = b6_pairs(&spec);
        let conventions = b6_conventions(&spec);
        let components = component_names(&spec);
        let criteria = a11y_criteria(&spec);
        let screens = visitor_screens(&spec);
        let detail = s140_detail(&spec);
        let b13: BTreeMap<String, String> = b13_rows(&spec).into_iter().collect();
        let journeys = journeys("ERR-AUTH-002");
        let values = values();
        let all = [
            ("structure", structure_findings(&doc)),
            ("classes", class_table_findings(&doc, &catalog, &components)),
            ("patterns", pattern_selection_findings(&doc)),
            ("classification", classification_findings(&doc, &catalog)),
            (
                "coverage",
                journey_coverage_findings(&doc, &journeys, &catalog),
            ),
            (
                "request id",
                request_id_findings(&doc, &catalog, &b6, detail.as_deref()),
            ),
            ("retry", retry_findings(&doc, &b6, &conventions)),
            ("polls", poll_findings(&doc, &b6)),
            (
                "visitor pages",
                visitor_page_findings(&doc, &screens, &catalog, detail.as_deref()),
            ),
            (
                "visitor constraints",
                visitor_constraint_findings(&doc, &values),
            ),
            (
                "copy keys",
                copy_key_findings(&doc, &b13, "", &ftl, Some(&claims_cfg())),
            ),
            ("offline", offline_findings(&doc)),
            ("jobs", job_failure_findings(&doc)),
            ("logging", logging_findings(&doc)),
            (
                "accessibility",
                accessibility_findings(&doc, &components, &criteria),
            ),
            ("security", security_findings(&doc)),
            ("authentication", authentication_findings(&doc, &catalog)),
            (
                "cross table",
                cross_table_findings(&doc, &journeys, &catalog),
            ),
            ("conflict scope", conflict_scope_findings(&doc, &catalog)),
            ("consistency", consistency_findings(&doc)),
            ("citations", citation_findings(&doc, &catalog)),
        ];
        for (rule, findings) in all {
            assert!(findings.is_empty(), "{rule}:\n{}", joined(&findings));
        }
    }

    #[test]
    fn t20_missing_documents_are_findings() {
        let findings = documents_findings(Path::new("hdd-no-such-root-for-t20"));
        assert_eq!(findings.len(), 2, "{}", joined(&findings));
    }

    #[test]
    fn t20_required_sections_are_checked() {
        let broken = doc().replace("## Security notes", "## Other notes");
        let findings = structure_findings(&broken);
        assert!(
            joined(&findings).contains("Security notes"),
            "{}",
            joined(&findings)
        );
    }

    #[test]
    fn t20_class_table_requires_nine_classes() {
        let broken = doc().replace(
            "| validation | inline, summary, banner |",
            "| gone | inline, summary, banner |",
        );
        let findings = class_table_findings(&broken, &catalog(), &component_names(&fixture_spec()));
        assert!(
            joined(&findings).contains("validation"),
            "{}",
            joined(&findings)
        );
    }

    #[test]
    fn t20_pattern_values_are_real_patterns() {
        let broken = doc().replace("inline, summary", "modal, summary");
        let findings = class_table_findings(&broken, &catalog(), &component_names(&fixture_spec()));
        assert!(joined(&findings).contains("modal"), "{}", joined(&findings));
        let missing = doc().replace("inline, summary", "summary");
        let findings =
            class_table_findings(&missing, &catalog(), &component_names(&fixture_spec()));
        assert!(
            joined(&findings).contains("inline"),
            "{}",
            joined(&findings)
        );
    }

    #[test]
    fn t20_each_class_example_exists() {
        let broken = doc().replace("| ERR-VAL-001 |", "| ERR-NOPE-001 |");
        let findings = class_table_findings(&broken, &catalog(), &component_names(&fixture_spec()));
        assert!(
            joined(&findings).contains("ERR-NOPE-001"),
            "{}",
            joined(&findings)
        );
    }

    #[test]
    fn t20_example_fits_class_and_family() {
        let wrong_class = doc().replace("| ERR-RATE-002 |", "| ERR-PERM-001 |");
        let findings =
            class_table_findings(&wrong_class, &catalog(), &component_names(&fixture_spec()));
        assert!(joined(&findings).contains("quota"), "{}", joined(&findings));
        let wrong_family = doc().replace("| ERR-VAL-001 |", "| ERR-AUTH-002 |");
        let findings =
            class_table_findings(&wrong_family, &catalog(), &component_names(&fixture_spec()));
        assert!(
            joined(&findings).contains("family"),
            "{}",
            joined(&findings)
        );
    }

    #[test]
    fn t20_status_rules_match_the_check() {
        let broken = doc().replace("| 421 | not found |", "| 421 | conflict |");
        let findings = classification_findings(&broken, &catalog());
        assert!(joined(&findings).contains("421"), "{}", joined(&findings));
        let missing = doc().replace("| 422 | validation |\n", "");
        let findings = classification_findings(&missing, &catalog());
        assert!(joined(&findings).contains("422"), "{}", joined(&findings));
    }

    #[test]
    fn t20_exception_table_matches() {
        let renamed = doc().replace("| ERR-RATE-002 | quota |", "| ERR-RATE-002 | rate limit |");
        let findings = classification_findings(&renamed, &catalog());
        assert!(
            joined(&findings).contains("ERR-RATE-002"),
            "{}",
            joined(&findings)
        );
        let missing = doc().replace(
            "| ERR-WAF-007 | permission | The self-lockout policy refuses the change; the preview names the current address. |\n",
            "",
        );
        let findings = classification_findings(&missing, &catalog());
        assert!(
            joined(&findings).contains("ERR-WAF-007"),
            "{}",
            joined(&findings)
        );
        let no_reason = doc().replace(
            "| ERR-RATE-002 | quota | The plan quota is exhausted, so waiting does not clear it. |",
            "| ERR-RATE-002 | quota | |",
        );
        let findings = classification_findings(&no_reason, &catalog());
        assert!(
            joined(&findings).contains("reason"),
            "{}",
            joined(&findings)
        );
    }

    #[test]
    fn t20_journey_coverage_is_exact() {
        let catalog = catalog();
        let two = journeys("ERR-AUTH-002, ERR-VAL-001");
        let doc_two = doc().replace(
            "| validation | none in the delivered journeys |",
            "| validation | ERR-VAL-001 |",
        );
        assert!(
            journey_coverage_findings(&doc_two, &two, &catalog).is_empty(),
            "{}",
            joined(&journey_coverage_findings(&doc_two, &two, &catalog))
        );
        let missing = doc();
        assert!(
            !journey_coverage_findings(&missing, &journeys("ERR-AUTH-002, ERR-SYS-001"), &catalog)
                .is_empty()
        );
        let extra = doc_two.replace(
            "| validation | ERR-VAL-001 |",
            "| validation | ERR-RATE-001 |",
        );
        assert!(
            joined(&journey_coverage_findings(&extra, &two, &catalog)).contains("ERR-RATE-001"),
            "{}",
            joined(&journey_coverage_findings(&extra, &two, &catalog))
        );
        let wrong_class = doc_two.replace(
            "| validation | ERR-VAL-001 |",
            "| permission | ERR-VAL-001 |",
        );
        assert!(
            joined(&journey_coverage_findings(&wrong_class, &two, &catalog))
                .contains("ERR-VAL-001"),
            "{}",
            joined(&journey_coverage_findings(&wrong_class, &two, &catalog))
        );
        let marker = doc_two.replace(
            "| authentication | ERR-AUTH-002 |",
            "| authentication | none in the delivered journeys |",
        );
        assert!(
            joined(&journey_coverage_findings(&marker, &two, &catalog)).contains("ERR-AUTH-002"),
            "{}",
            joined(&journey_coverage_findings(&marker, &two, &catalog))
        );
        let wrong_class = doc_two.replace(
            "| authentication | ERR-AUTH-002 |",
            "| permission | ERR-AUTH-002 |",
        );
        assert!(
            joined(&journey_coverage_findings(&wrong_class, &two, &catalog))
                .contains("ERR-AUTH-002"),
            "{}",
            joined(&journey_coverage_findings(&wrong_class, &two, &catalog))
        );
    }

    #[test]
    fn t20_retry_table_checks_b6_rows() {
        let broken = doc().replace("`POST O/domains`", "`POST O/nope`");
        let findings = retry_findings(
            &broken,
            &b6_pairs(&fixture_spec()),
            &b6_conventions(&fixture_spec()),
        );
        assert!(
            joined(&findings).contains("POST O/nope"),
            "{}",
            joined(&findings)
        );
    }

    #[test]
    fn t20_retry_safety_follows_method() {
        let spec = fixture_spec();
        let b6 = b6_pairs(&spec);
        let conventions = b6_conventions(&spec);
        for broken in [
            doc().replace(
                "| Add a domain | POST | `POST O/domains` | safe with Idempotency-Key | required | none |",
                "| Add a domain | POST | `POST O/domains` | unsafe | required | none |",
            ),
            doc().replace(
                "| Sign in | POST | `POST /auth/login` | unsafe | not required | none |",
                "| Sign in | POST | `POST /auth/login` | safe | not required | none |",
            ),
            doc().replace(
                "| Load the audit log | GET | `GET O/audit` | safe |",
                "| Load the audit log | GET | `GET O/audit` | unsafe |",
            ),
        ] {
            let findings = retry_findings(&broken, &b6, &conventions);
            assert!(!findings.is_empty(), "mutation slipped through");
        }
    }

    #[test]
    fn t20_retry_conventions_are_read() {
        let spec = fixture_spec().replace("Idempotency-Key", "idempotency marker");
        let findings = retry_findings(&doc(), &b6_pairs(&spec), &b6_conventions(&spec));
        assert!(
            joined(&findings).contains("Idempotency-Key"),
            "{}",
            joined(&findings)
        );
    }

    #[test]
    fn t20_background_polls_are_bounded() {
        let b6 = b6_pairs(&fixture_spec());
        let broken = doc().replace(
            "| 2 s | doubles to a 30 s cap |",
            "| soon | doubles to a 30 s cap |",
        );
        assert!(
            !poll_findings(&broken, &b6).is_empty(),
            "{}",
            joined(&poll_findings(&broken, &b6))
        );
        let removed = doc().replace(
            "| Certificate order | `GET D/tls/acme-status` | 5 s | doubles to a 60 s cap | issued, failed or stopped |\n",
            "",
        );
        assert!(!poll_findings(&removed, &b6).is_empty());
    }

    #[test]
    fn t20_visitor_pages_cover_nine() {
        let spec = fixture_spec();
        let catalog = catalog();
        let screens = visitor_screens(&spec);
        let detail = s140_detail(&spec);
        let removed = doc().replace(
            "| S-148 | Domain suspended page | 503 | none in B7 | `visitor-suspended-title`, `visitor-suspended-body` | application/problem+json |\n",
            "",
        );
        assert!(
            joined(&visitor_page_findings(
                &removed,
                &screens,
                &catalog,
                detail.as_deref()
            ))
            .contains("S-148"),
            "{}",
            joined(&visitor_page_findings(
                &removed,
                &screens,
                &catalog,
                detail.as_deref()
            ))
        );
        let renamed = doc().replace(
            "| S-144 | Unknown host page |",
            "| S-144 | Some host page |",
        );
        assert!(!visitor_page_findings(&renamed, &screens, &catalog, detail.as_deref()).is_empty());
        let neutral = doc().replace(
            "| S-144 | Unknown host page | 404 |",
            "| S-144 | Unknown host page | 403 |",
        );
        assert!(!visitor_page_findings(&neutral, &screens, &catalog, detail.as_deref()).is_empty());
        let no_status_match = doc().replace(
            "| S-142 | Rate-limit page | 429 | ERR-VISITOR-429 |",
            "| S-142 | Rate-limit page | 200 | ERR-VISITOR-429 |",
        );
        assert!(
            !visitor_page_findings(&no_status_match, &screens, &catalog, detail.as_deref())
                .is_empty()
        );
        let filler = doc().replace(
            "| S-144 | Unknown host page | 404 | none in B7 (data-plane neutral 404) |",
            "| S-144 | Unknown host page | 404 | ERR-PERM-002 |",
        );
        assert!(
            joined(&visitor_page_findings(
                &filler,
                &screens,
                &catalog,
                detail.as_deref()
            ))
            .contains("VISITOR"),
            "a borrowed API problem type on a data-plane page passed"
        );
    }

    #[test]
    fn t20_visitor_pages_declare_json() {
        let spec = fixture_spec();
        let catalog = catalog();
        let screens = visitor_screens(&spec);
        let detail = s140_detail(&spec);
        let broken = doc().replace(
            "| S-143 | Origin error page | 502/504 | ERR-VISITOR-502, ERR-VISITOR-504 | `visitor-origin-error-title`, `visitor-origin-error-body` | application/problem+json |",
            "| S-143 | Origin error page | 502/504 | ERR-VISITOR-502, ERR-VISITOR-504 | `visitor-origin-error-title`, `visitor-origin-error-body` | html only |",
        );
        assert!(!visitor_page_findings(&broken, &screens, &catalog, detail.as_deref()).is_empty());
        let body = doc().replace(
            "application/problem+json {\"error\":\"access_denied\",\"ray_id\"}",
            "application/problem+json",
        );
        assert!(!visitor_page_findings(&body, &screens, &catalog, detail.as_deref()).is_empty());
        let mixed = doc().replace(
            "application/problem+json {\"error\":\"access_denied\",\"ray_id\"}",
            "application/problem+json {\"error\":\"access_denied\",\"ray_id\",\"request_id\"}",
        );
        assert!(
            joined(&visitor_page_findings(
                &mixed,
                &screens,
                &catalog,
                detail.as_deref()
            ))
            .contains("request_id"),
            "the visitor JSON variant accepted an API request id"
        );
    }

    #[test]
    fn t20_visitor_constraints_are_testable() {
        let broken = doc().replace(
            "- V-5 S-148 names no tenant detail and carries no tenant variable. Detect: the same scan of the S-148 keys.",
            "- V-5 S-148 names no tenant detail and carries no tenant variable.",
        );
        assert!(
            !visitor_constraint_findings(&broken, &values()).is_empty(),
            "{}",
            joined(&visitor_constraint_findings(&broken, &values()))
        );
    }

    #[test]
    fn t20_visitor_copy_rejects_disclosures() {
        let cases = [
            (
                "visitor-block-page-body",
                "Your request matched rule id 942100, so it was blocked.",
            ),
            (
                "visitor-origin-error-body",
                "Connection refused by postgres at 127.0.0.1.",
            ),
            (
                "visitor-unknown-host-body",
                "No website for tenant acme at this address.",
            ),
            (
                "visitor-block-page-body",
                "This is your fault and the matched payload was <script>.",
            ),
        ];
        for (key, value) in cases {
            let mut mutated = values();
            mutated.insert(key.to_owned(), value.to_owned());
            let findings = visitor_constraint_findings(&doc(), &mutated);
            assert!(
                !findings.is_empty(),
                "the disclosure in {key} was not caught: {value}"
            );
        }
    }

    #[test]
    fn t20_copy_keys_defined_once() {
        let spec = fixture_spec();
        let doc = doc();
        let b13: BTreeMap<String, String> = b13_rows(&spec).into_iter().collect();
        let ftl = ftl();
        let missing = ftl.replace("visitor-unknown-host-title = Site not found\n", "");
        assert!(
            joined(&copy_key_findings(&doc, &b13, "", &missing, None))
                .contains("visitor-unknown-host-title"),
            "{}",
            joined(&copy_key_findings(&doc, &b13, "", &missing, None))
        );
        let duplicate = format!("{ftl}visitor-unknown-host-title = Another title\n");
        assert!(!copy_key_findings(&doc, &b13, "", &duplicate, None).is_empty());
        let changed = ftl.replace(
            "visitor-unknown-host-title = Site not found",
            "visitor-unknown-host-title = Page not found",
        );
        assert!(!copy_key_findings(&doc, &b13, "", &changed, None).is_empty());
        let deck = "tagline = Put a firewall in front of your website. See what it blocks. Undo anything.\nvisitor-unknown-host-title = Site not found\n";
        assert!(
            joined(&copy_key_findings(&doc, &BTreeMap::new(), deck, &ftl, None))
                .contains("visitor-unknown-host-title"),
            "{}",
            joined(&copy_key_findings(&doc, &BTreeMap::new(), deck, &ftl, None))
        );
    }

    #[test]
    fn t20_offline_never_silent() {
        let broken = doc().replace("never fail silently", "fail sometimes");
        let findings = offline_findings(&broken);
        assert!(
            joined(&findings).contains("silent"),
            "{}",
            joined(&findings)
        );
    }

    #[test]
    fn t20_job_failure_has_three_channels() {
        let broken = doc().replace("notification", "message");
        let findings = job_failure_findings(&broken);
        assert!(
            joined(&findings).contains("notification"),
            "{}",
            joined(&findings)
        );
    }

    #[test]
    fn t20_logging_is_structured() {
        let broken = doc().replace("one structured record", "one record");
        let findings = logging_findings(&broken);
        assert!(
            joined(&findings).contains("structured"),
            "{}",
            joined(&findings)
        );
    }

    #[test]
    fn t20_accessibility_per_pattern() {
        let spec = fixture_spec();
        let components = component_names(&spec);
        let criteria = a11y_criteria(&spec);
        let broken = doc().replace(
            "| toast | focus never moves into the toast | role=\"alert\" |",
            "| toast | focus never moves into the toast | none |",
        );
        assert!(
            !accessibility_findings(&broken, &components, &criteria).is_empty(),
            "a toast without role=alert passed"
        );
        let component = doc().replace("| FormField |", "| ModalThing |");
        assert!(!accessibility_findings(&component, &components, &criteria).is_empty());
        let removed = doc().replace(
            "| page | focus moves to the page heading | main landmark | the failure is text and it is never colour only | ErrorState |\n",
            "",
        );
        assert!(!accessibility_findings(&removed, &components, &criteria).is_empty());
    }

    #[test]
    fn t20_security_notes_cover_enumeration() {
        let broken = doc().replace("(R-20)", "");
        let findings = security_findings(&broken);
        assert!(joined(&findings).contains("R-20"), "{}", joined(&findings));
        let no_code = doc().replace("`ERR-PERM-002`", "`ERR-PERM-001`");
        assert!(!security_findings(&no_code).is_empty());
    }

    #[test]
    fn t20_claims_are_scanned() {
        let cfg = claims_cfg();
        let claimed = doc().replace(
            "The fixture model:",
            "The fixture model gives absolute protection:",
        );
        assert!(!claims_doc_findings(&cfg, ERRORS, &claimed).is_empty());
        let ftl = ftl().replace(
            "visitor-unknown-host-body = No website is configured at this address.",
            "visitor-unknown-host-body = No website gives absolute protection at this address.",
        );
        let spec = fixture_spec();
        let b13: BTreeMap<String, String> = b13_rows(&spec).into_iter().collect();
        assert!(!copy_key_findings(&doc(), &b13, "", &ftl, Some(&cfg)).is_empty());
    }

    #[test]
    fn t20_whole_tokens_are_used() {
        let broken = doc().replace(
            "| S-146 | Appeal received | 200 | none in B7 |",
            "| S-146 | Appeal received | 200 | none in B7 ERR-VAL-001X |",
        );
        let findings = citation_findings(&broken, &catalog());
        assert!(
            joined(&findings).contains("ERR-VAL-001X"),
            "{}",
            joined(&findings)
        );
    }

    #[test]
    fn t20_malformed_input_gives_findings() {
        let catalog = catalog();
        let empty = structure_findings("");
        assert!(!empty.is_empty());
        assert!(!class_table_findings("", &catalog, &BTreeSet::new()).is_empty());
        assert!(!visitor_page_findings("", &BTreeMap::new(), &catalog, None).is_empty());
        assert!(!retry_findings("", &BTreeSet::new(), "").is_empty());
        assert!(!accessibility_findings("", &BTreeSet::new(), &BTreeSet::new()).is_empty());
        assert!(!authentication_findings("", &catalog).is_empty());
        assert!(!cross_table_findings("", &[], &catalog).is_empty());
        assert!(!conflict_scope_findings("", &catalog).is_empty());
        assert!(!consistency_findings("").is_empty());
    }

    #[test]
    fn t20_request_id_pattern() {
        let spec = fixture_spec();
        let catalog = catalog();
        let b6 = b6_pairs(&spec);
        let detail = s140_detail(&spec);
        let no_shape = doc().replace("`[0-9a-f]{16}-HDD1`", "`an id`");
        assert!(
            !request_id_findings(&no_shape, &catalog, &b6, detail.as_deref()).is_empty(),
            "the Ray shape is not required"
        );
        let bad_path = doc().replace("`GET P/support/ray/{ray}`", "`GET P/support/nope/{ray}`");
        assert!(
            !request_id_findings(&bad_path, &catalog, &b6, detail.as_deref()).is_empty(),
            "an unknown support path passed"
        );
        let no_never = doc().replace("Never shown: trace ids", "Sometimes shown: trace ids");
        assert!(!request_id_findings(&no_never, &catalog, &b6, detail.as_deref()).is_empty());
    }

    // Review D-1 to D-4 tests: each one reproduces the reported defect before the fix.

    #[test]
    fn t20_d1_authentication_row_is_required() {
        let broken = doc().replace("| authentication |", "| permission-extra |");
        let findings = class_table_findings(&broken, &catalog(), &component_names(&fixture_spec()));
        assert!(
            joined(&findings).contains("authentication"),
            "the matrix has no required authentication row (D-1): {}",
            joined(&findings)
        );
    }

    #[test]
    fn t20_d1_code_class_differs_between_tables() {
        let broken = doc().replace(
            "| authentication | ERR-AUTH-002 |",
            "| permission | ERR-AUTH-002 |",
        );
        let findings = cross_table_findings(&broken, &journeys("ERR-AUTH-002"), &catalog());
        assert!(
            joined(&findings).contains("ERR-AUTH-002"),
            "a code listed under two classes passed (D-1): {}",
            joined(&findings)
        );
    }

    #[test]
    fn t20_d2_conflict_default_must_be_reviewed() {
        let broken = doc().replace("| ERR-ORG-001 | validation |", "| ERR-DOM-004 | upstream |");
        let findings = conflict_scope_findings(&broken, &catalog());
        assert!(
            joined(&findings).contains("ERR-ORG-001") || joined(&findings).contains("409"),
            "a 409 code without a reviewed exception passed (D-2): {}",
            joined(&findings)
        );
    }

    #[test]
    fn t20_d3_one_cause_once_per_channel() {
        let broken = doc().replace(
            "P-8 One cause appears once per channel",
            "P-8 One cause is shown once",
        );
        let findings = consistency_findings(&broken);
        assert!(
            joined(&findings).contains("P-8") || joined(&findings).contains("channel"),
            "the old one-cause-shown-once wording passed (D-3): {}",
            joined(&findings)
        );
    }

    #[test]
    fn t20_d4_unsafe_actions_are_listed() {
        let spec = fixture_spec();
        let b6 = b6_pairs(&spec);
        let conventions = b6_conventions(&spec);
        let thin = doc()
            .replace(
                "| Send a verification email | POST | `POST /auth/resend-verification` | unsafe | not required | none |\n",
                "",
            )
            .replace(
                "| Start a password reset email | POST | `POST /auth/forgot-password` | unsafe | not required | none |\n",
                "",
            )
            .replace(
                "| Rotate a webhook signing secret | POST | `POST O/webhooks/{whk}/rotate-secret` | unsafe | not required | none |\n",
                "",
            );
        let findings = retry_findings(&thin, &b6, &conventions);
        assert!(
            joined(&findings).contains("unsafe"),
            "a thin unsafe list passed (D-4): {}",
            joined(&findings)
        );
    }

    #[test]
    fn t20_d4_unsafe_post_cannot_claim_a_key() {
        let spec = fixture_spec();
        let b6 = b6_pairs(&spec);
        let conventions = b6_conventions(&spec);
        let broken = doc().replace(
            "| Send a verification email | POST | `POST /auth/resend-verification` | unsafe | not required | none |",
            "| Send a verification email | POST | `POST /auth/resend-verification` | unsafe | required | none |",
        );
        let findings = retry_findings(&broken, &b6, &conventions);
        assert!(
            !findings.is_empty(),
            "an unsafe POST that claims an idempotency key passed (D-4)"
        );
    }
}
