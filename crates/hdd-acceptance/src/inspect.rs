//! The inspect-first gate (section 2.2, E3.1 rule 4): a live attack-shaped request is only sent after
//! `POST /api/v1/waf/inspect` says it would be blocked and the site's `config_revision` did not change underneath the test.
//!
//! The gate talks to the control plane through the typed [`InspectClient`] trait. A production client must be built on
//! [`hdd_common::egress::Client`]; this crate ships no such client, so the gate is tested with a scripted client. The only
//! value that authorises a live send is an [`InspectTicket`], which is constructed nowhere else (task acceptance A5). The
//! ticket is bound to the inspected request (site, method, path, payload class), the `config_revision` and the site's
//! enforcement state, and [`crate::guard::Connector::prepare`] requires a matching, enforcing ticket before every
//! attack-shaped request (review item A-5).

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::guard::{Method, PayloadClass};

/// How long an inspect ticket may authorise a send (review item R-5).
pub const DEFAULT_TICKET_TTL: Duration = Duration::from_secs(30);

/// The inspect endpoint path (section 2.2).
pub const INSPECT_PATH: &str = "/api/v1/waf/inspect";

/// The enforcement mode of the target site at inspection time (section 2.2: a live enforcement test needs `block`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteMode {
    /// Requests that would be blocked are blocked.
    Block,
    /// Requests are observed only; a live enforcement test cannot prove anything.
    Monitor,
}

impl SiteMode {
    /// The mode as written in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            SiteMode::Block => "block",
            SiteMode::Monitor => "monitor",
        }
    }
}

impl fmt::Display for SiteMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Largest request body the inspect API accepts (spec T-0260: body as UTF-8 text or base64 up to 64 KB).
pub const MAX_INSPECT_BODY_BYTES: usize = 64 * 1024;

/// One inspect query: the site, the request shape, and the **content** of the request that will be sent if the gate passes
/// (review item N-2: the inspect API must judge the headers, cookies and body that actually go out, not only the path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectRequest {
    /// The site the request would target, as the control plane knows it.
    pub site: String,
    /// The path of the request that will be sent if the gate passes.
    pub path: String,
    /// The method of the request that will be sent.
    pub method: Method,
    /// The actual HTTP verb, so `Method::Other` cannot hide it (review item R-5).
    pub verb: String,
    /// The payload class of the request.
    pub class: PayloadClass,
    /// The request headers exactly as they will be sent (spec T-0260 `headers`).
    pub headers: Vec<(String, String)>,
    /// The request cookies (spec T-0260 `cookies`).
    pub cookies: Vec<(String, String)>,
    /// The body when it is valid UTF-8 (spec T-0260 `body` as text); `None` when there is no body or the base64 form is used.
    pub body_text: Option<String>,
    /// The body base64-encoded when it is not valid UTF-8 (spec T-0260 `body` as base64).
    pub body_base64: Option<String>,
    /// The body's content type, when one was supplied.
    pub content_type: Option<String>,
    /// Length in bytes of the body the inspect call would carry (before any text/base64 encoding).
    pub body_bytes: usize,
    /// SHA-256 of the request body (empty body: the hash of no bytes) - the ticket-binding digest.
    pub body_sha256: String,
    /// SHA-256 of the canonical header list - the ticket-binding digest.
    pub headers_sha256: String,
}

impl InspectRequest {
    /// Build the inspect request for an attempt: headers (and their cookies) and the body are carried to the inspect API, and
    /// the digest still binds exactly the bytes that will be sent (review item N-2).
    pub fn for_attempt(
        site: impl Into<String>,
        path: impl Into<String>,
        method: Method,
        verb: impl Into<String>,
        class: PayloadClass,
        headers: &[(String, String)],
        body: &[u8],
    ) -> InspectRequest {
        let content_type = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.clone());
        let cookies = cookie_pairs(headers);
        let (body_text, body_base64) = match std::str::from_utf8(body) {
            Ok(_) => (Some(String::from_utf8_lossy(body).into_owned()), None),
            Err(_) => (None, Some(base64_encode(body))),
        };
        InspectRequest {
            site: site.into(),
            path: path.into(),
            method,
            verb: verb.into(),
            class,
            headers: headers.to_vec(),
            cookies,
            body_text: body_text.filter(|text| !text.is_empty()),
            body_base64,
            content_type,
            body_bytes: body.len(),
            body_sha256: crate::report::sha256_hex(body),
            headers_sha256: crate::report::sha256_hex(&crate::guard::canonical_headers(headers)),
        }
    }

    /// The endpoint the request must go to (always [`INSPECT_PATH`]).
    pub fn endpoint(&self) -> &'static str {
        INSPECT_PATH
    }

    /// The length of the body the inspect call would carry (0 for no body).
    pub fn body_len(&self) -> usize {
        self.body_bytes
    }

    /// True when the body is inside the spec's 64 KB inspect cap (review item N-2).
    pub fn body_within_cap(&self) -> bool {
        self.body_len() <= MAX_INSPECT_BODY_BYTES
    }

    /// SHA-256 binding the verb, path, body and headers (review items R-5 and S-3): a ticket for one request cannot
    /// authorise another with the same site and path but a different verb, body or header set. The encoding is
    /// length-prefixed so no field can swallow the separator (the previous `\n`-joined form collided).
    pub fn digest(&self) -> String {
        let mut canonical = Vec::new();
        for field in [
            self.verb.as_str(),
            self.path.as_str(),
            self.body_sha256.as_str(),
            self.headers_sha256.as_str(),
            self.method.as_str(),
            self.class.as_str(),
            self.site.as_str(),
        ] {
            let len = u64::try_from(field.len()).unwrap_or(u64::MAX);
            canonical.extend_from_slice(&len.to_le_bytes());
            canonical.extend_from_slice(field.as_bytes());
        }
        crate::report::sha256_hex(&canonical)
    }
}

/// Cookie name/value pairs from the request's `Cookie` header(s) (spec T-0260 carries cookies separately).
fn cookie_pairs(headers: &[(String, String)]) -> Vec<(String, String)> {
    let mut cookies = Vec::new();
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("cookie") {
            continue;
        }
        for pair in value.split(';') {
            if let Some((key, val)) = pair.split_once('=') {
                let key = key.trim();
                if !key.is_empty() {
                    cookies.push((key.to_owned(), val.trim().to_owned()));
                }
            }
        }
    }
    cookies
}

/// Standard base64 with padding, for a request body that is not valid UTF-8 (spec T-0260).
pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; // hdd-secret-scan:allow (public base64 alphabet)
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = chunk.get(1).copied().map(u32::from);
        let b2 = chunk.get(2).copied().map(u32::from);
        let triple = (b0 << 16) | (b1.unwrap_or(0) << 8) | b2.unwrap_or(0);
        out.push(
            ALPHABET
                .get(((triple >> 18) & 0x3f) as usize)
                .copied()
                .unwrap_or(b'A') as char,
        );
        out.push(
            ALPHABET
                .get(((triple >> 12) & 0x3f) as usize)
                .copied()
                .unwrap_or(b'A') as char,
        );
        if b1.is_some() {
            out.push(
                ALPHABET
                    .get(((triple >> 6) & 0x3f) as usize)
                    .copied()
                    .unwrap_or(b'A') as char,
            );
        } else {
            out.push('=');
        }
        if b2.is_some() {
            out.push(
                ALPHABET
                    .get((triple & 0x3f) as usize)
                    .copied()
                    .unwrap_or(b'A') as char,
            );
        } else {
            out.push('=');
        }
    }
    out
}

/// The typed answer of the inspect API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectResponse {
    /// True when the control plane would block the request.
    pub would_block: bool,
    /// The site's configuration revision at inspection time.
    pub config_revision: String,
    /// The site's enforcement mode at inspection time.
    pub mode: SiteMode,
    /// True when safe mode is on: a live enforcement test may not send.
    pub safe_mode: bool,
    /// The detected category, when the control plane names one; evidence, never a pass condition.
    pub category: Option<String>,
}

/// Why the inspect client could not produce an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectClientError {
    /// The request could not be made or the answer was not received.
    Transport {
        /// Transport detail, safe to show.
        message: String,
    },
    /// The answer was not shaped like the inspect API contract.
    Malformed {
        /// What was wrong.
        message: String,
    },
}

impl fmt::Display for InspectClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InspectClientError::Transport { message } => {
                write!(f, "inspect transport failed: {message}")
            }
            InspectClientError::Malformed { message } => {
                write!(f, "inspect answer malformed: {message}")
            }
        }
    }
}

impl std::error::Error for InspectClientError {}

/// The current configuration revision of the control plane, read again at send time (review item R-5).
pub trait RevisionSource: Send + Sync {
    /// The current revision, or why it cannot be read (the caller fails closed).
    fn current_revision(&self) -> Result<String, String>;
}

/// A revision source with a value tests can change between inspection and send.
#[derive(Debug)]
pub struct FixedRevision {
    revision: std::sync::Mutex<String>,
}

impl FixedRevision {
    /// A source that always reports ision.
    pub fn new(revision: impl Into<String>) -> FixedRevision {
        FixedRevision {
            revision: std::sync::Mutex::new(revision.into()),
        }
    }

    /// Change the reported revision (the next send sees it).
    pub fn set(&self, revision: impl Into<String>) {
        match self.revision.lock() {
            Ok(mut current) => *current = revision.into(),
            Err(poisoned) => *poisoned.into_inner() = revision.into(),
        }
    }
}

impl RevisionSource for FixedRevision {
    fn current_revision(&self) -> Result<String, String> {
        match self.revision.lock() {
            Ok(current) => Ok(current.clone()),
            Err(poisoned) => Ok(poisoned.into_inner().clone()),
        }
    }
}

/// The typed inspect client. A production implementation sends `POST /api/v1/waf/inspect` through
/// [`hdd_common::egress::Client`]; tests use a scripted implementation.
pub trait InspectClient {
    /// Ask the control plane whether `request` would be blocked.
    fn inspect(&mut self, request: &InspectRequest) -> Result<InspectResponse, InspectClientError>;
}

impl InspectClient for Box<dyn InspectClient> {
    fn inspect(&mut self, request: &InspectRequest) -> Result<InspectResponse, InspectClientError> {
        self.as_mut().inspect(request)
    }
}

impl InspectClient for Box<dyn InspectClient + Send> {
    fn inspect(&mut self, request: &InspectRequest) -> Result<InspectResponse, InspectClientError> {
        self.as_mut().inspect(request)
    }
}

/// Why the inspect-first gate refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectGateError {
    /// The control plane said the request would not be blocked, so sending it would not exercise enforcement (A5).
    WouldNotBlock {
        /// The site.
        site: String,
        /// The category the control plane reported, if any.
        category: Option<String>,
    },
    /// The configuration revision changed between inspection and send.
    ConfigRevisionChanged {
        /// The revision the test planned against.
        expected: String,
        /// The revision the inspect API reported.
        observed: String,
    },
    /// The inspect call could not be completed: fail closed, nothing is sent.
    Transport {
        /// Transport detail.
        message: String,
    },
    /// The inspect answer was malformed: fail closed, nothing is sent.
    Malformed {
        /// What was wrong.
        message: String,
    },
}

impl fmt::Display for InspectGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InspectGateError::WouldNotBlock { site, category } => write!(
                f,
                "inspect for `{site}` reports would_block=false{}: the live request is not sent (inspect-first gate)",
                category
                    .as_deref()
                    .map(|c| format!(" (category `{c}`)"))
                    .unwrap_or_default()
            ),
            InspectGateError::ConfigRevisionChanged { expected, observed } => write!(
                f,
                "config_revision changed between inspection and send ({expected} -> {observed}); the live request is not \
                 sent"
            ),
            InspectGateError::Transport { message } => write!(
                f,
                "inspect call failed ({message}); failing closed, nothing is sent"
            ),
            InspectGateError::Malformed { message } => {
                write!(
                    f,
                    "inspect answer malformed ({message}); failing closed, nothing is sent"
                )
            }
        }
    }
}

impl std::error::Error for InspectGateError {}

/// The only value that authorises the live send. Its fields are private to this module. Two tickets compare equal by what
/// they authorise (request, revision, enforcement state, digest), not by their independent consumption flags; the flag is
/// what makes a ticket single-use.
#[derive(Debug, Clone)]
pub struct InspectTicket {
    request: InspectRequest,
    revision: String,
    mode: SiteMode,
    safe_mode: bool,
    category: Option<String>,
    digest: String,
    issued_at: Instant,
    ttl: Duration,
    consumed: Arc<AtomicBool>,
}

impl PartialEq for InspectTicket {
    fn eq(&self, other: &InspectTicket) -> bool {
        self.digest == other.digest
            && self.request == other.request
            && self.revision == other.revision
            && self.mode == other.mode
            && self.safe_mode == other.safe_mode
            && self.category == other.category
            && self.ttl == other.ttl
    }
}

impl Eq for InspectTicket {}

/// Why a ticket refused to authorise a send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TicketError {
    /// The ticket already authorised a send (single use).
    Reused,
    /// The ticket is older than its TTL.
    Expired {
        /// The TTL.
        ttl: Duration,
    },
    /// The request changed after inspection.
    DigestMismatch,
}

impl fmt::Display for TicketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TicketError::Reused => f.write_str("the inspect ticket was already used once"),
            TicketError::Expired { ttl } => {
                write!(f, "the inspect ticket expired after {} ms", ttl.as_millis())
            }
            TicketError::DigestMismatch => {
                f.write_str("the inspect ticket does not match this request")
            }
        }
    }
}

impl std::error::Error for TicketError {}

impl InspectTicket {
    /// Consume the ticket for a request digest at `now`. A reused, expired or mismatched ticket is refused.
    pub fn consume(&self, digest: &str, now: Instant) -> Result<(), TicketError> {
        if digest != self.digest {
            return Err(TicketError::DigestMismatch);
        }
        if now.saturating_duration_since(self.issued_at) > self.ttl {
            let _ = self.consumed.swap(true, Ordering::SeqCst);
            return Err(TicketError::Expired { ttl: self.ttl });
        }
        if self.consumed.swap(true, Ordering::SeqCst) {
            return Err(TicketError::Reused);
        }
        Ok(())
    }

    /// The digest the ticket binds.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The request the ticket covers.
    pub fn request(&self) -> &InspectRequest {
        &self.request
    }

    /// The configuration revision the ticket was issued against.
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// The site's mode at inspection time.
    pub fn mode(&self) -> SiteMode {
        self.mode
    }

    /// Whether safe mode was on at inspection time.
    pub fn safe_mode(&self) -> bool {
        self.safe_mode
    }

    /// True when a live enforcement test may send: `block` mode with safe mode off (section 2.2).
    pub fn site_is_enforcing(&self) -> bool {
        self.mode == SiteMode::Block && !self.safe_mode
    }

    /// The detected category, as evidence.
    pub fn category(&self) -> Option<&str> {
        self.category.as_deref()
    }

    /// True when the ticket was issued for exactly this site, method, path and class.
    pub fn covers(&self, site: &str, method: Method, path: &str, class: PayloadClass) -> bool {
        self.request.site == site
            && self.request.method == method
            && self.request.path == path
            && self.request.class == class
    }
}

/// The inspect-first gate. It refuses to issue a ticket unless `would_block` is true and the revision is unchanged.
///
/// The gate is crate-internal on purpose (review item S-2): a check body cannot construct a gate, cannot implement the client
/// and cannot mint a ticket. The executor owns the one gate and exposes [`crate::runner::CheckContext::inspect`]. This is a
/// guarantee against a check written by us that makes a mistake; it is a Rust privacy convention, not a security boundary
/// against code compiled into this crate.
pub struct InspectGate<C: InspectClient> {
    client: C,
    expected_revision: String,
}

impl<C: InspectClient> InspectGate<C> {
    /// A gate for a test that planned against `expected_revision`. Crate-internal: only the executor builds a gate
    /// (review item S-2).
    pub(crate) fn new(client: C, expected_revision: impl Into<String>) -> InspectGate<C> {
        InspectGate {
            client,
            expected_revision: expected_revision.into(),
        }
    }

    /// The revision the gate was built against.
    pub fn expected_revision(&self) -> &str {
        &self.expected_revision
    }

    /// Inspect the request. On any failure the caller has no ticket and must not send. Crate-internal: only the executor's
    /// `CheckContext::inspect` calls this (review item S-2).
    pub(crate) fn check(
        &mut self,
        request: &InspectRequest,
    ) -> Result<InspectTicket, InspectGateError> {
        if request.site.trim().is_empty() {
            return Err(InspectGateError::Malformed {
                message: "the inspect request has no site".to_owned(),
            });
        }
        let response = self.client.inspect(request).map_err(|e| match e {
            InspectClientError::Transport { message } => InspectGateError::Transport { message },
            InspectClientError::Malformed { message } => InspectGateError::Malformed { message },
        })?;
        if !response.would_block {
            return Err(InspectGateError::WouldNotBlock {
                site: request.site.clone(),
                category: response.category,
            });
        }
        if response.config_revision.trim().is_empty() {
            return Err(InspectGateError::Malformed {
                message: "the inspect answer carries an empty config_revision".to_owned(),
            });
        }
        if response.config_revision != self.expected_revision {
            return Err(InspectGateError::ConfigRevisionChanged {
                expected: self.expected_revision.clone(),
                observed: response.config_revision,
            });
        }
        Ok(InspectTicket {
            request: request.clone(),
            revision: response.config_revision,
            mode: response.mode,
            safe_mode: response.safe_mode,
            category: response.category,
            digest: request.digest(),
            issued_at: Instant::now(),
            ttl: DEFAULT_TICKET_TTL,
            consumed: Arc::new(AtomicBool::new(false)),
        })
    }
}

#[cfg(test)]
impl InspectTicket {
    /// A ticket built directly by tests (the real path is [InspectGate::check]).
    pub(crate) fn for_test(
        request: InspectRequest,
        revision: &str,
        mode: SiteMode,
        safe_mode: bool,
    ) -> InspectTicket {
        InspectTicket {
            digest: request.digest(),
            request,
            revision: revision.to_owned(),
            mode,
            safe_mode,
            category: None,
            issued_at: Instant::now(),
            ttl: DEFAULT_TICKET_TTL,
            consumed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A ticket with an explicit issue time and TTL, for the expiry test (review item R-5).
    pub(crate) fn for_test_at(
        request: InspectRequest,
        revision: &str,
        mode: SiteMode,
        safe_mode: bool,
        issued_at: Instant,
        ttl: Duration,
    ) -> InspectTicket {
        InspectTicket {
            digest: request.digest(),
            request,
            revision: revision.to_owned(),
            mode,
            safe_mode,
            category: None,
            issued_at,
            ttl,
            consumed: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[cfg(test)]
mod tests;
