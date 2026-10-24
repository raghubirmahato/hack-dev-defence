//! The target guard, egress allowlist and connector seam: nothing attack-shaped leaves before every check passes.
//!
//! The allowed target set is never written here by hand. It is derived from the live profile by
//! [`hdd_common::egress::TargetGuard`] ([`TargetGuard::from_profile`]) in `live` mode (`test_hostname` and `sandbox_hostname`)
//! or `lab` mode (the lab host and CIDR). Payload classes A/B/C of section 2.2, the lifecycle stage of section 2.7, the
//! inspect-first ticket of section 2.2 and the shared rate budget of section 2.3 are enforced on the way to a
//! [`PlannedRequest`].
//!
//! A [`PlannedRequest`] is **single use**: it is not `Clone` and [`Sender::send`] takes it by value, so every send needs its own
//! [`Connector::prepare`] call and its own rate-budget token (review item A-1). The request also carries the addresses that
//! passed [`TargetGuard::check_resolved`] in this call and never follows redirects (review item A-4); a name that resolves
//! differently on a second hop is refused, which is the DNS-rebinding case of spec 2.8 step 2.
//!
//! This crate ships **no** real sender: the guard is tested before any send function exists (task acceptance A1), with a
//! recording sender.

use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hdd_common::egress::allow::{AllowEntry, AllowError, Allowlist, Scheme};
use hdd_common::egress::resolver::Resolver;
use hdd_common::egress::{KillSwitch, TargetDenied, TargetGuard, TargetMode};
use hdd_common::profile::Profile;

use crate::config::{LifecyclePolicy, StageRefusal};
use crate::control::Bannable;
use crate::inspect::{InspectTicket, RevisionSource, SiteMode, TicketError};
use crate::limits::{Lane, LimitDenial, LoadProfile, RateBudget};
use crate::runner::{AbortCause, AbortLatch, RunInvalidLatch};

/// Payload class (section 2.2). Every fixture is tagged with one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PayloadClass {
    /// Inert shapes; live to `test_hostname` as GET/HEAD only.
    A,
    /// Destructive if it reached an origin; sandbox only.
    B,
    /// Never sent live; inspect API and unit tests only.
    C,
}

impl PayloadClass {
    /// The class letter as written in fixture metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            PayloadClass::A => "A",
            PayloadClass::B => "B",
            PayloadClass::C => "C",
        }
    }

    /// True for the classes that are actually sent live (A and B): those require the inspect-first ticket.
    pub fn is_attack_shaped(self) -> bool {
        matches!(self, PayloadClass::A | PayloadClass::B)
    }
}

impl fmt::Display for PayloadClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The HTTP method of an attempt. Anything that is not read-only is body-bearing for the class A rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// `GET`.
    Get,
    /// `HEAD`.
    Head,
    /// Any other method (a body-bearing request for the class A rule).
    Other,
}

impl Method {
    /// True for `GET` and `HEAD`.
    pub fn is_read_only(self) -> bool {
        matches!(self, Method::Get | Method::Head)
    }

    /// The method name as written in the attempt.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Other => "OTHER",
        }
    }
}

/// Why a request path was refused before a [`PlannedRequest`] exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// The path is empty.
    Empty,
    /// The path does not start with `/`.
    MissingLeadingSlash,
    /// The path starts with `//`: a network-path reference, which parsers may treat as a new authority.
    NetworkPath,
    /// The path contains a control character (including CR and LF).
    ControlCharacter,
    /// The path contains whitespace.
    Whitespace,
    /// The path contains a backslash, which some parsers normalise to a separator.
    Backslash,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathError::Empty => f.write_str("the request path is empty"),
            PathError::MissingLeadingSlash => f.write_str("the request path must start with `/`"),
            PathError::NetworkPath => f.write_str(
                "the request path starts with `//` (network-path reference); it could be read as a new authority",
            ),
            PathError::ControlCharacter => {
                f.write_str("the request path contains a control character (CR/LF/NUL are refused)")
            }
            PathError::Whitespace => f.write_str("the request path contains whitespace"),
            PathError::Backslash => f.write_str("the request path contains a backslash"),
        }
    }
}

impl std::error::Error for PathError {}

/// Validate an origin-form request target before it can become a [`PlannedRequest`].
///
/// The accepted form is `"/" path-abempty [ "?" query ]`: it must start with exactly one `/`, and must not contain `//` at the
/// start, whitespace, control characters or backslashes. This refuses the userinfo trick (`@host:port` cannot start the
/// target), CR/LF request splitting, a missing leading slash and whitespace smuggling (review item A-4).
pub fn validate_path(path: &str) -> Result<(), PathError> {
    if path.is_empty() {
        return Err(PathError::Empty);
    }
    if !path.starts_with('/') {
        return Err(PathError::MissingLeadingSlash);
    }
    if path.starts_with("//") {
        return Err(PathError::NetworkPath);
    }
    for c in path.chars() {
        if c.is_ascii_control() {
            return Err(PathError::ControlCharacter);
        }
        if c.is_whitespace() {
            return Err(PathError::Whitespace);
        }
        if c == '\\' {
            return Err(PathError::Backslash);
        }
    }
    Ok(())
}

/// One attack-shaped request a check wants to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// Target host name or IP literal (checked against the profile-derived set).
    pub target: String,
    /// Origin-form request path (validated by [`validate_path`]).
    pub path: String,
    /// Payload class.
    pub class: PayloadClass,
    /// HTTP method.
    pub method: Method,
    /// The actual HTTP verb (for `Method::Other`; `GET`/`HEAD` otherwise), bound into the inspect-ticket digest so a ticket
    /// for one verb cannot authorise another (review item R-5).
    pub verb: String,
    /// Request body bytes (empty for GET/HEAD).
    pub body: Vec<u8>,
    /// Request headers (name, value), used for the inspect-ticket digest.
    pub headers: Vec<(String, String)>,
}

impl Attempt {
    /// A body-less, header-less attempt.
    pub fn new(
        target: impl Into<String>,
        path: impl Into<String>,
        class: PayloadClass,
        method: Method,
    ) -> Attempt {
        Attempt {
            target: target.into(),
            path: path.into(),
            class,
            method,
            verb: method.as_str().to_owned(),
            body: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// Set the actual HTTP verb (for `Method::Other`, which alone does not name it).
    pub fn with_verb(mut self, verb: impl Into<String>) -> Attempt {
        self.verb = verb.into();
        self
    }

    /// Add a request body.
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Attempt {
        self.body = body.into();
        self
    }

    /// Add request headers.
    pub fn with_headers(mut self, headers: Vec<(String, String)>) -> Attempt {
        self.headers = headers;
        self
    }

    /// SHA-256 of the body.
    pub fn body_sha256(&self) -> String {
        crate::report::sha256_hex(&self.body)
    }

    /// SHA-256 of the canonical header list. The encoding is **length-prefixed** (review item S-3): each name and value is
    /// preceded by its byte length, so `[("a","b\nc: d")]` and `[("a","b"),("c","d")]` cannot collide; names are compared
    /// case-insensitively in the usual HTTP sense only by the caller, here the exact bytes are bound.
    pub fn headers_sha256(&self) -> String {
        crate::report::sha256_hex(&canonical_headers(&self.headers))
    }
}

/// Length-prefixed canonical encoding of a header list (review item S-3). No ambiguity: a name or value containing `\n`,
/// `:` or the separator cannot make two different lists encode identically.
pub(crate) fn canonical_headers(headers: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in headers {
        let name_len = u64::try_from(name.len()).unwrap_or(u64::MAX);
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        let value_len = u64::try_from(value.len()).unwrap_or(u64::MAX);
        out.extend_from_slice(&value_len.to_le_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    out
}

/// Why a request verb or header was refused before a [`PlannedRequest`] exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestPartError {
    /// The verb is empty or contains bytes that are not an HTTP token.
    InvalidVerb {
        /// The offending verb, bounded for the message.
        verb: String,
    },
    /// A read-only method carries a non-empty body.
    ReadOnlyWithBody {
        /// The method.
        method: Method,
    },
    /// The verb does not match the method (`GET` must be verb `GET`, `HEAD` the verb `HEAD`).
    VerbMismatch {
        /// The method.
        method: Method,
        /// The verb.
        verb: String,
    },
    /// A header name is empty or not an HTTP token.
    InvalidHeaderName {
        /// The offending name, bounded for the message.
        name: String,
    },
    /// A header value contains a control character (CR/LF/NUL and other CTLs, except HTAB).
    InvalidHeaderValue {
        /// The name of the offending header.
        name: String,
    },
    /// A header value has leading or trailing whitespace (a sender that trims would send other bytes than the digest covers,
    /// review item N-8).
    HeaderWhitespace {
        /// The name of the offending header.
        name: String,
    },
    /// A header the sender must control itself was supplied by the check (review item N-8): `Content-Length`,
    /// `Transfer-Encoding`, `Host`, `Expect`, `Upgrade`, `Connection` or `X-HTTP-Method-Override`.
    DeniedHeader {
        /// The name of the offending header.
        name: String,
    },
    /// Too many request headers (review item N-8: at most 64).
    TooManyHeaders {
        /// How many were supplied.
        count: usize,
        /// The cap.
        max: usize,
    },
    /// The request headers are too large in total (review item N-8: at most 8 KB of names and values).
    HeadersTooLarge {
        /// The total size in bytes.
        bytes: usize,
        /// The cap.
        max: usize,
    },
    /// The body is larger than the inspect API accepts (spec T-0260, review item N-2: 64 KB).
    BodyTooLarge {
        /// The body size in bytes.
        bytes: usize,
        /// The cap.
        max: usize,
    },
}

impl fmt::Display for RequestPartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestPartError::InvalidVerb { verb } => {
                write!(f, "the HTTP verb `{verb}` is not a token")
            }
            RequestPartError::ReadOnlyWithBody { method } => write!(
                f,
                "`{}` must not carry a body (the attempt has one)",
                method.as_str()
            ),
            RequestPartError::VerbMismatch { method, verb } => write!(
                f,
                "the verb `{verb}` does not match the method `{}` (the request would not be what was ticketed)",
                method.as_str()
            ),
            RequestPartError::InvalidHeaderName { name } => {
                write!(f, "the header name `{name}` is not an HTTP token")
            }
            RequestPartError::InvalidHeaderValue { name } => write!(
                f,
                "the header `{name}` has a control character in its value (CR/LF/NUL are refused)"
            ),
            RequestPartError::HeaderWhitespace { name } => write!(
                f,
                "the header `{name}` has leading or trailing whitespace in its value; a sender may trim it, so the bytes \
                 sent would not be the bytes inspected"
            ),
            RequestPartError::DeniedHeader { name } => write!(
                f,
                "the header `{name}` is set by the sender and may not be supplied by a check"
            ),
            RequestPartError::TooManyHeaders { count, max } => {
                write!(f, "{count} request headers; at most {max} are allowed")
            }
            RequestPartError::HeadersTooLarge { bytes, max } => {
                write!(
                    f,
                    "request headers total {bytes} bytes; at most {max} are allowed"
                )
            }
            RequestPartError::BodyTooLarge { bytes, max } => write!(
                f,
                "the request body is {bytes} bytes; the inspect API accepts at most {max} bytes (spec T-0260)"
            ),
        }
    }
}

impl std::error::Error for RequestPartError {}

/// True when `text` is a non-empty RFC 7230 token.
fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|byte| {
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
        })
}

/// Most request headers a check may supply (review item N-8).
pub const MAX_REQUEST_HEADERS: usize = 64;

/// Largest total size of request header names and values (review item N-8).
pub const MAX_REQUEST_HEADER_BYTES: usize = 8 * 1024;

/// Headers the sender must control itself; a check may not supply them (review item N-8). Reaching the origin with a
/// contradictory `Content-Length`/`Transfer-Encoding` or a smuggled verb override is the request-smuggling shape.
const DENIED_HEADERS: [&str; 7] = [
    "content-length",
    "transfer-encoding",
    "host",
    "expect",
    "upgrade",
    "connection",
    "x-http-method-override",
];

/// Validate everything about an attempt that is not a path or a target: the verb, the body for read-only methods, the body cap
/// and every header (review items S-3, N-2 and N-8). A control character in a header value could split the request into two,
/// so a value with any CTL other than HTAB is refused; the sender-owned headers and the size caps are refused too.
fn validate_request_parts(attempt: &Attempt) -> Result<(), RequestPartError> {
    if !is_token(&attempt.verb) {
        return Err(RequestPartError::InvalidVerb {
            verb: attempt.verb.chars().take(16).collect(),
        });
    }
    if attempt.body.len() > crate::inspect::MAX_INSPECT_BODY_BYTES {
        return Err(RequestPartError::BodyTooLarge {
            bytes: attempt.body.len(),
            max: crate::inspect::MAX_INSPECT_BODY_BYTES,
        });
    }
    if attempt.method.is_read_only() {
        if !attempt.body.is_empty() {
            return Err(RequestPartError::ReadOnlyWithBody {
                method: attempt.method,
            });
        }
        if attempt.verb != attempt.method.as_str() {
            return Err(RequestPartError::VerbMismatch {
                method: attempt.method,
                verb: attempt.verb.chars().take(16).collect(),
            });
        }
    }
    if attempt.headers.len() > MAX_REQUEST_HEADERS {
        return Err(RequestPartError::TooManyHeaders {
            count: attempt.headers.len(),
            max: MAX_REQUEST_HEADERS,
        });
    }
    let header_bytes: usize = attempt
        .headers
        .iter()
        .map(|(name, value)| name.len() + value.len())
        .sum();
    if header_bytes > MAX_REQUEST_HEADER_BYTES {
        return Err(RequestPartError::HeadersTooLarge {
            bytes: header_bytes,
            max: MAX_REQUEST_HEADER_BYTES,
        });
    }
    for (name, value) in &attempt.headers {
        if !is_token(name) {
            return Err(RequestPartError::InvalidHeaderName {
                name: name.chars().take(32).collect(),
            });
        }
        let lower = name.to_ascii_lowercase();
        if DENIED_HEADERS.contains(&lower.as_str()) {
            return Err(RequestPartError::DeniedHeader { name: name.clone() });
        }
        if value
            .bytes()
            .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
        {
            return Err(RequestPartError::InvalidHeaderValue { name: name.clone() });
        }
        if value != value.trim() {
            return Err(RequestPartError::HeaderWhitespace { name: name.clone() });
        }
    }
    Ok(())
}

/// A request that passed every guard. Only this type is accepted by a [`Sender`], its constructor is private to this module,
/// and it is not `Clone`: one prepared request authorises exactly one send. It carries **the content the inspect ticket
/// authorised**: the verb, the body and the headers that went into the digest (review item S-3), so a sender cannot send a
/// different request than the one that was ticketed.
#[derive(Debug, PartialEq, Eq)]
pub struct PlannedRequest {
    target: String,
    path: String,
    class: PayloadClass,
    method: Method,
    verb: String,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
    resolved: Vec<IpAddr>,
    config_revision: String,
    issued_at: Instant,
    ttl: Duration,
}

impl PlannedRequest {
    /// The validated target host name.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The payload class.
    pub fn class(&self) -> PayloadClass {
        self.class
    }

    /// The method.
    pub fn method(&self) -> Method {
        self.method
    }

    /// The actual HTTP verb the ticket bound.
    pub fn verb(&self) -> &str {
        &self.verb
    }

    /// The body the ticket bound (empty for `GET`/`HEAD`).
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The headers the ticket bound.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// The addresses that passed [`TargetGuard::check_resolved`] for this request.
    pub fn resolved_addresses(&self) -> &[IpAddr] {
        &self.resolved
    }

    /// The `config_revision` the authorising inspect ticket was issued against.
    pub fn config_revision(&self) -> &str {
        &self.config_revision
    }

    /// The runner never follows redirects: a redirect is a refused hop, not a new allowlisted request.
    pub fn follow_redirects(&self) -> bool {
        false
    }

    /// True when the prepared request is older than its send window (review item R-7).
    pub fn is_expired(&self) -> bool {
        self.issued_at.elapsed() > self.ttl
    }
}

/// What a real sender would return. This skeleton has no real sender; the trait is the seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    /// Target the request went to.
    pub target: String,
    /// Path of the request.
    pub path: String,
}

/// The send seam. A production implementation must be built on [`hdd_common::egress::Client`] (section 2.1); this crate
/// deliberately has none yet, so no socket can be opened from the skeleton. The request is taken **by value** (single use) and
/// the sender receives the addresses that passed the per-hop guard: it must connect only to them and must not re-resolve the
/// name (review item R-7, DNS rebinding).
pub trait Sender {
    /// Send a request that already passed [`Connector::prepare`], connecting only to `pinned`.
    fn send(&mut self, request: PlannedRequest, pinned: &[IpAddr]) -> Sent;
}

/// Why a request was refused before anything was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// The target is not in the set derived from the profile.
    Target(TargetDenied),
    /// The request path is not an acceptable origin-form target.
    InvalidPath {
        /// The offending path.
        path: String,
        /// Why it was refused.
        reason: PathError,
    },
    /// A class C payload may never be sent live.
    ClassCNeverSent {
        /// The target of the attempt.
        target: String,
    },
    /// A class B payload must go to the sandbox (live) or the lab host (lab).
    ClassBNotSandbox {
        /// The target of the attempt.
        target: String,
    },
    /// A class A request carrying a body (not GET/HEAD) must go to the sandbox.
    ClassAWithBody {
        /// The target of the attempt.
        target: String,
    },
    /// The selected load profile may only target the sandbox.
    ProfileOnlySandbox {
        /// The profile that restricts the target.
        profile: LoadProfile,
        /// The target of the attempt.
        target: String,
    },
    /// The lifecycle stage refuses a destructive check.
    Stage(StageRefusal),
    /// The kill switch is set.
    KillSwitch,
    /// The run's abort latch is set (kill switch or operator signal).
    Aborted(AbortCause),
    /// The shared/check rate budget refused the request.
    Limit(LimitDenial),
    /// The runner IP is not known to be bannable (`test_runner.public_ip: auto` before the canary echo).
    RunnerNotBannable {
        /// The state that was reported.
        runner: Bannable,
    },
    /// An attack-shaped request has no inspect-first ticket.
    InspectRequired {
        /// The target of the attempt.
        target: String,
    },
    /// The inspect-first ticket does not cover this request.
    InspectMismatch {
        /// What did not match.
        detail: String,
    },
    /// The inspect-first ticket is stale: the configuration revision changed.
    InspectStaleRevision {
        /// The revision the ticket carries.
        expected: String,
        /// The revision the connector expects for this run.
        observed: String,
    },
    /// The site is not in `block` mode with safe mode off (section 2.2), so a live enforcement test proves nothing.
    InspectNotEnforcing {
        /// The site mode at inspection time.
        mode: SiteMode,
        /// Whether safe mode was on.
        safe_mode: bool,
    },
    /// The inspect-first ticket refused this send: it was already used, expired, or bound to another request (review R-5).
    InspectTicket(TicketError),
    /// The prepared request outlived its send window (review item R-7).
    RequestExpired {
        /// The TTL that elapsed.
        ttl: Duration,
    },
    /// The current `config_revision` could not be read at send time; fail closed (review items R-5, R-7).
    RevisionUnavailable {
        /// Why it could not be read.
        detail: String,
    },
    /// The `config_revision` changed between prepare and send; nothing is sent (review item R-5).
    RevisionChangedAtSend {
        /// The revision the request was prepared against.
        expected: String,
        /// The revision observed at send time.
        observed: String,
    },
    /// The verb, the body or a header is not what a request may contain (review item S-3).
    RequestPart(RequestPartError),
    /// The run was marked invalid by an earlier safety-envelope denial: nothing more may be prepared or sent (review item
    /// N-1). The check that tripped the latch ends `FAIL(run invalid: <denial>)`.
    RunInvalid {
        /// The check that tripped the latch.
        check_id: String,
        /// The denial that marked the run invalid.
        detail: String,
    },
}

impl Denial {
    /// True when refusing this attempt means the safety envelope was violated: the run must be marked invalid (review item
    /// S-8). These are the refusals that say a check tried to do something the envelope forbids, not a transient environment
    /// problem (a rate limit or a kill switch is not the check's mistake).
    pub fn is_safety_envelope_violation(&self) -> bool {
        matches!(
            self,
            Denial::Target(_)
                | Denial::Stage(_)
                | Denial::ClassCNeverSent { .. }
                | Denial::ClassBNotSandbox { .. }
                | Denial::ClassAWithBody { .. }
                | Denial::ProfileOnlySandbox { .. }
                | Denial::InspectRequired { .. }
                | Denial::RunnerNotBannable { .. }
        )
    }
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denial::Target(e) => write!(f, "target refused: {e}"),
            Denial::InvalidPath { path, reason } => {
                write!(f, "request path `{path}` refused: {reason}")
            }
            Denial::ClassCNeverSent { target } => write!(
                f,
                "class C payload for `{target}` is never sent live (inspect API and unit tests only)"
            ),
            Denial::ClassBNotSandbox { target } => write!(
                f,
                "class B payload for `{target}` must go to the sandbox hostname"
            ),
            Denial::ClassAWithBody { target } => write!(
                f,
                "class A request with a body for `{target}` must go to the sandbox hostname"
            ),
            Denial::ProfileOnlySandbox { profile, target } => write!(
                f,
                "the `{profile}` profile may only target the sandbox hostname, not `{target}`"
            ),
            Denial::Stage(e) => write!(f, "{e}"),
            Denial::KillSwitch => f.write_str("aborted: kill switch is set"),
            Denial::Aborted(cause) => write!(f, "aborted: {cause}"),
            Denial::Limit(e) => write!(f, "rate limit: {e}"),
            Denial::RunnerNotBannable { runner } => write!(
                f,
                "the runner is not known to be bannable ({runner}); attack-shaped traffic is refused until the runner \
                 address is known and is not in admin_cidrs"
            ),
            Denial::InspectRequired { target } => write!(
                f,
                "no inspect-first ticket for the attack-shaped request to `{target}` (section 2.2): nothing is sent"
            ),
            Denial::InspectMismatch { detail } => write!(
                f,
                "the inspect-first ticket does not cover this request: {detail}"
            ),
            Denial::InspectStaleRevision { expected, observed } => write!(
                f,
                "the inspect-first ticket is stale: ticket revision `{expected}`, run revision `{observed}`"
            ),
            Denial::InspectTicket(e) => write!(f, "inspect ticket: {e}"),
            Denial::RequestExpired { ttl } => write!(
                f,
                "the prepared request expired after {} ms; it was not sent",
                ttl.as_millis()
            ),
            Denial::RevisionUnavailable { detail } => write!(
                f,
                "cannot read the current config_revision ({detail}); failing closed, nothing is sent"
            ),
            Denial::RevisionChangedAtSend { expected, observed } => write!(
                f,
                "config_revision changed before send ({expected} -> {observed}); nothing is sent"
            ),
            Denial::InspectNotEnforcing { mode, safe_mode } => write!(
                f,
                "the site is not enforcing: mode `{mode}`, safe_mode `{safe_mode}`; a live enforcement test needs block \
                 mode with safe mode off (section 2.2)"
            ),
            Denial::RequestPart(error) => write!(f, "request refused: {error}"),
            Denial::RunInvalid { check_id, detail } => write!(
                f,
                "run invalid: the run was marked invalid by check `{check_id}` ({detail}); nothing more is sent"
            ),
        }
    }
}

impl std::error::Error for Denial {}

impl From<TargetDenied> for Denial {
    fn from(value: TargetDenied) -> Denial {
        Denial::Target(value)
    }
}

impl From<LimitDenial> for Denial {
    fn from(value: LimitDenial) -> Denial {
        Denial::Limit(value)
    }
}

/// The egress allowlist gate for infrastructure destinations (section 2.1: CA, resolvers, feeds, SMTP, the operator's own
/// control plane). The target guard is for attack-shaped traffic; this gate is for everything else that leaves the runner.
#[derive(Debug, Clone)]
pub struct EgressGate {
    allow: Allowlist,
}

/// Why an infrastructure destination was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressDenied {
    /// Scheme asked for.
    pub scheme: Scheme,
    /// Host asked for.
    pub host: String,
    /// Port asked for.
    pub port: u16,
    /// Path asked for.
    pub path: String,
}

impl fmt::Display for EgressDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}://{}:{}{} is not in the profile's egress_allowlist",
            self.scheme.as_str(),
            self.host,
            self.port,
            self.path
        )
    }
}

impl std::error::Error for EgressDenied {}

impl EgressGate {
    /// Derive the gate from the profile's `egress_allowlist`. An empty list denies everything.
    pub fn from_profile(p: &Profile) -> Result<EgressGate, Vec<(usize, AllowError)>> {
        Allowlist::parse(&p.egress_allowlist).map(|allow| EgressGate { allow })
    }

    /// An explicit allowlist (used by tests and by callers that already parsed it).
    pub fn new(allow: Allowlist) -> EgressGate {
        EgressGate { allow }
    }

    /// Entries of the gate, for reports.
    pub fn entries(&self) -> &[AllowEntry] {
        self.allow.entries()
    }

    /// Check one destination; denied unless an entry permits scheme, host, port and path.
    pub fn check(
        &self,
        scheme: Scheme,
        host: &str,
        port: u16,
        path: &str,
    ) -> Result<(), EgressDenied> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if self.allow.permits(scheme, &host, port, path) {
            Ok(())
        } else {
            Err(EgressDenied {
                scheme,
                host,
                port,
                path: path.to_owned(),
            })
        }
    }
}

/// Why the connector could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorError {
    /// The target set is not usable (empty profile, missing lab, mistyped platform address).
    Target(TargetDenied),
    /// The egress allowlist has invalid entries.
    Egress(Vec<(usize, AllowError)>),
    /// The inspect-first ticket contract needs a non-empty expected config revision.
    MissingConfigRevision,
    /// The selected load profile is not allowed in this target mode (review item R-1).
    ProfileModeMismatch {
        /// The profile.
        profile: LoadProfile,
        /// The mode.
        mode: TargetMode,
    },
}

impl fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectorError::Target(e) => write!(f, "target guard: {e}"),
            ConnectorError::Egress(errors) => {
                write!(f, "egress_allowlist has {} invalid entries", errors.len())
            }
            ConnectorError::MissingConfigRevision => f.write_str(
                "the connector needs the run's expected config_revision for the inspect-first ticket",
            ),
            ConnectorError::ProfileModeMismatch { profile, mode } => write!(
                f,
                "the {profile} profile is not allowed in {} mode (section 2.3; review item R-1)",
                match mode {
                    TargetMode::Live => "live",
                    TargetMode::Lab => "lab",
                }
            ),
        }
    }
}

impl std::error::Error for ConnectorError {}

/// The parts of a run a connector needs, separate from the profile so a check cannot invent them.
pub(crate) struct ConnectorParts {
    /// Live or lab.
    pub(crate) mode: TargetMode,
    /// The run's rate/load profile.
    pub(crate) load_profile: LoadProfile,
    /// Lifecycle rules with this run's approval.
    pub(crate) lifecycle: LifecyclePolicy,
    /// True when the owning check's `CheckSpec.destructive` is set: the executor sets this, never the check itself.
    pub(crate) destructive: bool,
    /// The kill switch.
    pub(crate) kill: KillSwitch,
    /// The run's abort latch (kill switch or operator signal), shared with the executor.
    pub(crate) abort: Arc<AbortLatch>,
    /// The run's shared limiter plus this check's own limiter.
    pub(crate) budget: Arc<Mutex<RateBudget>>,
    /// The resolver used for the per-hop address validation.
    pub(crate) resolver: Arc<dyn Resolver>,
    /// Whether the runner IP is known to be bannable.
    pub(crate) runner: Bannable,
    /// The configuration revision every live enforcement test is planned against.
    pub(crate) expected_revision: String,
    /// The current-revision source, re-read at send time (R-5).
    pub(crate) revision: Arc<dyn RevisionSource>,
    /// The run-invalid latch shared with the executor (R-8).
    pub(crate) run_invalid: Arc<RunInvalidLatch>,
    /// The id of the run, bound into the approval ticket (R-13) and the invalid-run audit record (N-1).
    pub(crate) run_id: String,
    /// The id of the check this connector was built for, recorded when it trips the run-invalid latch (N-1).
    pub(crate) check_id: String,
    /// How long a prepared request may stay valid before it must be refused at send (R-7).
    pub(crate) request_ttl: Duration,
}

/// The connector: guard, class rules, lifecycle, inspect ticket, kill switch and shared budget in front of the [`Sender`]
/// seam.
pub struct Connector {
    guard: TargetGuard,
    test_host: String,
    sandbox_host: String,
    lab_host: String,
    load_profile: LoadProfile,
    lifecycle: LifecyclePolicy,
    destructive: bool,
    kill: KillSwitch,
    abort: Arc<AbortLatch>,
    budget: Arc<Mutex<RateBudget>>,
    resolver: Arc<dyn Resolver>,
    runner: Bannable,
    expected_revision: String,
    revision: Arc<dyn RevisionSource>,
    run_invalid: Arc<RunInvalidLatch>,
    run_id: String,
    check_id: String,
    request_ttl: Duration,
}

impl fmt::Debug for Connector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connector")
            .field("guard", &self.guard)
            .field("test_host", &self.test_host)
            .field("sandbox_host", &self.sandbox_host)
            .field("lab_host", &self.lab_host)
            .field("load_profile", &self.load_profile)
            .field("lifecycle", &self.lifecycle)
            .field("destructive", &self.destructive)
            .field("runner", &self.runner)
            .finish_non_exhaustive()
    }
}

impl Connector {
    /// Build the connector from the profile and the run's parts. The allowed hosts come from the profile only. Crate-internal:
    /// a check obtains a connector through [crate::runner::CheckContext::connector] (review item R-3).
    pub(crate) fn new(p: &Profile, parts: ConnectorParts) -> Result<Connector, ConnectorError> {
        if parts.expected_revision.trim().is_empty() {
            return Err(ConnectorError::MissingConfigRevision);
        }
        if !parts.load_profile.allows_mode(parts.mode) {
            return Err(ConnectorError::ProfileModeMismatch {
                profile: parts.load_profile,
                mode: parts.mode,
            });
        }
        let guard = TargetGuard::from_profile(p, parts.mode).map_err(ConnectorError::Target)?;
        Ok(Connector {
            guard,
            test_host: normalize(&p.test_hostname),
            sandbox_host: normalize(&p.sandbox_hostname),
            lab_host: normalize(&p.lab.host),
            load_profile: parts.load_profile,
            lifecycle: parts.lifecycle,
            destructive: parts.destructive,
            kill: parts.kill,
            abort: parts.abort,
            budget: parts.budget,
            resolver: parts.resolver,
            runner: parts.runner,
            expected_revision: parts.expected_revision,
            revision: parts.revision,
            run_invalid: parts.run_invalid,
            run_id: parts.run_id,
            check_id: parts.check_id,
            request_ttl: parts.request_ttl,
        })
    }

    /// The mode of the guard.
    pub fn mode(&self) -> TargetMode {
        self.guard.mode()
    }

    /// The hosts the guard allows (for reports).
    pub fn allowed_hosts(&self) -> Vec<String> {
        self.guard.hosts().map(str::to_owned).collect()
    }

    /// The load profile in force.
    pub fn load_profile(&self) -> LoadProfile {
        self.load_profile
    }

    /// True when the owning check is destructive (from its `CheckSpec`, not from the attempt).
    pub fn destructive(&self) -> bool {
        self.destructive
    }

    /// Test-only: clear the run-invalid latch so independent probes in one test do not see another probe's denial.
    #[cfg(test)]
    pub(crate) fn reset_invalid(&self) {
        self.run_invalid.reset();
    }

    fn is_sandbox(&self, target: &str) -> bool {
        let t = normalize(target);
        !self.sandbox_host.is_empty() && t == self.sandbox_host
            || (self.guard.mode() == TargetMode::Lab
                && !self.lab_host.is_empty()
                && t == self.lab_host)
    }

    /// Validate the inspect-first ticket and return the digest it must be consumed with. The ticket is **not** consumed here
    /// (review item S-10): the consumption happens at the end of [`Connector::prepare`], after the revision, enforcement,
    /// resolution and abort checks, so a late `prepare` refusal does not burn the ticket. The caller only reaches this function
    /// for attack-shaped attempts (class C and a misplaced class B/A-with-body are refused before it), so there is no early
    /// return for non-attack classes.
    fn check_ticket(
        &self,
        attempt: &Attempt,
        ticket: Option<&InspectTicket>,
        target: &str,
    ) -> Result<String, Denial> {
        let ticket = ticket.ok_or_else(|| Denial::InspectRequired {
            target: target.to_owned(),
        })?;
        let digest = crate::inspect::InspectRequest::for_attempt(
            target.to_owned(),
            attempt.path.clone(),
            attempt.method,
            attempt.verb.clone(),
            attempt.class,
            &attempt.headers,
            &attempt.body,
        )
        .digest();
        if !ticket.covers(target, attempt.method, &attempt.path, attempt.class) {
            return Err(Denial::InspectMismatch {
                detail: format!(
                    "ticket covers {} {} `{}` class {}; attempt is {} {} `{}` class {}",
                    ticket.request().method.as_str(),
                    ticket.request().site,
                    ticket.request().path,
                    ticket.request().class,
                    attempt.method.as_str(),
                    target,
                    attempt.path,
                    attempt.class
                ),
            });
        }
        if ticket.revision() != self.expected_revision {
            return Err(Denial::InspectStaleRevision {
                expected: ticket.revision().to_owned(),
                observed: self.expected_revision.clone(),
            });
        }
        if !ticket.site_is_enforcing() {
            return Err(Denial::InspectNotEnforcing {
                mode: ticket.mode(),
                safe_mode: ticket.safe_mode(),
            });
        }
        Ok(digest)
    }

    /// Run every guard and hand back a request a sender may accept. No sender is involved here, so a refusal cannot have
    /// sent anything, and the rate-budget token is spent in [`Connector::send`], not here (review item R-7). `ticket` must be
    /// the ticket issued by [`crate::inspect::InspectGate`] for this attempt; it is consumed at the very end of this function,
    /// after every other check (review item S-10).
    ///
    /// Every refusal that is a safety-envelope violation latches the run invalid (review item S-8), so a check that swallows
    /// the `Err` cannot continue the run cleanly.
    pub async fn prepare(
        &mut self,
        attempt: &Attempt,
        ticket: Option<&InspectTicket>,
    ) -> Result<PlannedRequest, Denial> {
        // Review item N-1: once the run is invalid nothing more is prepared, so a check that swallowed an earlier denial
        // cannot keep sending.
        if let Some(record) = self.run_invalid.first_record() {
            return Err(Denial::RunInvalid {
                check_id: record.check_id,
                detail: format!("{} ({})", record.detail, record.run_id),
            });
        }
        let result = self.prepare_inner(attempt, ticket).await;
        if let Err(denial) = &result
            && denial.is_safety_envelope_violation()
        {
            self.run_invalid
                .record(&self.check_id, &self.run_id, &denial.to_string());
        }
        result
    }

    async fn prepare_inner(
        &mut self,
        attempt: &Attempt,
        ticket: Option<&InspectTicket>,
    ) -> Result<PlannedRequest, Denial> {
        // 0. the run-invalid latch: checked again here so the window between `prepare` and the body cannot widen (N-1)
        if let Some(record) = self.run_invalid.first_record() {
            return Err(Denial::RunInvalid {
                check_id: record.check_id,
                detail: format!("{} ({})", record.detail, record.run_id),
            });
        }
        // 1. abort latch and kill switch: stop even between checks (section 2.3, review item A-9)
        if let Err(cause) = self.abort.check() {
            return Err(Denial::Aborted(cause));
        }
        if self.kill.check().is_err() {
            return Err(Denial::KillSwitch);
        }
        // 2. lifecycle: production refuses destructive checks without this run's approval (section 2.7). The flag comes from
        // the check's CheckSpec via the executor, and a class B send implies destructive itself (review item R-13).
        if self.destructive || attempt.class == PayloadClass::B {
            self.lifecycle
                .allows_destructive_for(&self.run_id)
                .map_err(Denial::Stage)?;
        }
        // 3. path and request-part validation (verb, body for GET/HEAD, header names and values), before any token or packet
        // exists (review items A-4 and S-3)
        validate_path(&attempt.path).map_err(|reason| Denial::InvalidPath {
            path: attempt.path.clone(),
            reason,
        })?;
        validate_request_parts(attempt).map_err(Denial::RequestPart)?;
        // 4. the runner must be known bannable for attack-shaped traffic (section 2.4, review item A-11)
        if attempt.class.is_attack_shaped() && !self.runner.is_bannable() {
            return Err(Denial::RunnerNotBannable {
                runner: self.runner,
            });
        }
        // 5. the target must be in the set derived from the profile (section 2.1)
        self.guard.check_host(&attempt.target)?;
        // 6. payload class rules (section 2.2)
        match attempt.class {
            PayloadClass::C => {
                return Err(Denial::ClassCNeverSent {
                    target: attempt.target.clone(),
                });
            }
            PayloadClass::B => {
                if !self.is_sandbox(&attempt.target) {
                    return Err(Denial::ClassBNotSandbox {
                        target: attempt.target.clone(),
                    });
                }
            }
            PayloadClass::A => {
                if !attempt.method.is_read_only() && !self.is_sandbox(&attempt.target) {
                    return Err(Denial::ClassAWithBody {
                        target: attempt.target.clone(),
                    });
                }
            }
        }
        // 7. the load and protocol-abuse profiles target the sandbox only (section 2.3)
        if matches!(
            self.load_profile,
            LoadProfile::Load | LoadProfile::ProtocolAbuse
        ) && !self.is_sandbox(&attempt.target)
        {
            return Err(Denial::ProfileOnlySandbox {
                profile: self.load_profile,
                target: attempt.target.clone(),
            });
        }
        // 8. inspect-first gate: every attack-shaped request needs a matching, fresh, enforcing ticket; the digest is only
        // consumed at the end of this function
        let target = normalize(&attempt.target);
        let ticket_digest = self.check_ticket(attempt, ticket, &target)?;
        // 9. resolve now and validate every address and CNAME; the request carries the addresses that passed (review A-4)
        let resolved = self
            .guard
            .check_resolved(&attempt.target, self.resolver.as_ref())
            .await
            .map_err(Denial::Target)?;
        // 10. re-check the invalid latch and the abort/kill state after the await: a denial elsewhere in the run must stop
        // this check too, and an abort during resolution must not hand out a send token (review item N-1)
        if let Some(record) = self.run_invalid.first_record() {
            return Err(Denial::RunInvalid {
                check_id: record.check_id,
                detail: format!("{} ({})", record.detail, record.run_id),
            });
        }
        if let Err(cause) = self.abort.check() {
            return Err(Denial::Aborted(cause));
        }
        if self.kill.check().is_err() {
            return Err(Denial::KillSwitch);
        }
        // 11. consume the single-use ticket now that every other check has passed (review item S-10)
        if let Some(ticket) = ticket {
            ticket
                .consume(&ticket_digest, Instant::now())
                .map_err(Denial::InspectTicket)?;
        }
        Ok(PlannedRequest {
            target,
            path: attempt.path.clone(),
            class: attempt.class,
            method: attempt.method,
            verb: attempt.verb.clone(),
            body: attempt.body.clone(),
            headers: attempt.headers.clone(),
            resolved,
            config_revision: self.expected_revision.clone(),
            issued_at: Instant::now(),
            ttl: self.request_ttl,
        })
    }

    /// Send a prepared request: re-check the abort latch and kill switch, refuse a stale request (R-7), re-read the
    /// config_revision and compare it with the ticket's (R-5), spend the rate-budget token now (not in `prepare`), then hand
    /// the request and its pinned addresses to the sender.
    pub fn send<S: Sender>(
        &mut self,
        planned: PlannedRequest,
        sender: &mut S,
    ) -> Result<Sent, Denial> {
        // Review item N-1: once the run is invalid nothing is sent.
        if let Some(record) = self.run_invalid.first_record() {
            return Err(Denial::RunInvalid {
                check_id: record.check_id,
                detail: format!("{} ({})", record.detail, record.run_id),
            });
        }
        if let Err(cause) = self.abort.check() {
            return Err(Denial::Aborted(cause));
        }
        if self.kill.check().is_err() {
            return Err(Denial::KillSwitch);
        }
        if planned.is_expired() {
            return Err(Denial::RequestExpired { ttl: planned.ttl });
        }
        let current = self
            .revision
            .current_revision()
            .map_err(|detail| Denial::RevisionUnavailable { detail })?;
        if current != planned.config_revision {
            return Err(Denial::RevisionChangedAtSend {
                expected: planned.config_revision.clone(),
                observed: current,
            });
        }
        let lane = if self.load_profile == LoadProfile::ProtocolAbuse {
            Lane::Connections
        } else {
            Lane::Http
        };
        match self.budget.lock() {
            Ok(mut budget) => budget.acquire(lane, 1)?,
            Err(_) => return Err(Denial::Limit(LimitDenial::Locked)),
        }
        let pinned = planned.resolved_addresses().to_vec();
        Ok(sender.send(planned, &pinned))
    }

    /// Prepare and send in one call.
    pub async fn dispatch<S: Sender>(
        &mut self,
        attempt: &Attempt,
        ticket: Option<&InspectTicket>,
        sender: &mut S,
    ) -> Result<Sent, Denial> {
        let planned = self.prepare(attempt, ticket).await?;
        self.send(planned, sender)
    }
}
/// Normalise a host for comparison exactly as the guard does.
fn normalize(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests;
