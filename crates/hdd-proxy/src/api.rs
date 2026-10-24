//! The HTTP/JSON contract shared by the proxy pipeline, the admin API and the embedded web UI (COLLAB.md Addenda 1
//! to 5).
//!
//! The proxy owns the listeners and converts wire requests into [`ApiRequest`]; the admin handlers fill
//! [`ApiResponse`]. The web UI is static HTML/CSS/JS embedded in the binary; it talks to exactly the paths declared in
//! [`paths`] (R-27: every UI action is an API call under the same authorisation).

use serde::{Deserialize, Serialize};

use hdd_waf_core::{CustomRule, FieldKind, Strictness, Vector, Verdict};

/// The name of the session cookie (HttpOnly, SameSite=Strict, Path=/).
pub const SESSION_COOKIE: &str = "hdd_session";
/// The prefix of a script API token; the rest is never stored in clear.
pub const API_TOKEN_PREFIX: &str = "hdd_";
/// The minimum password length for the owner account and every user (Addendum 2).
pub const MIN_PASSWORD_LEN: usize = 12;
/// The maximum number of events the in-memory ring keeps (the JSONL log is not capped).
pub const EVENT_RING_CAPACITY: usize = 500;
/// The default admin listener address.
pub const DEFAULT_ADMIN_LISTEN: &str = "127.0.0.1:9090";
/// The default proxy listener address.
pub const DEFAULT_PROXY_LISTEN: &str = "127.0.0.1:8080";

/// Every path the admin API and the embedded UI use. Keep this list as the single source of truth: the server router,
/// the tests and the documentation refer to it.
pub mod paths {
    /// Liveness probe, always public.
    pub const HEALTHZ: &str = "/healthz";
    /// The login page (static shell; the form posts to [`API_LOGIN`]).
    pub const LOGIN: &str = "/login";
    /// The first-run setup page.
    pub const SETUP: &str = "/setup";
    /// The single-page app shell served for the authenticated screens.
    pub const APP: &str = "/";
    /// The static asset prefix (CSS, JS, images; no external CDN).
    pub const STATIC_PREFIX: &str = "/static/";

    /// `GET /api/setup-status` (public): whether the first-run wizard is open.
    pub const API_SETUP_STATUS: &str = "/api/setup-status";
    /// `POST /api/setup` (public while no account exists).
    pub const API_SETUP: &str = "/api/setup";
    /// `POST /api/login` (public).
    pub const API_LOGIN: &str = "/api/login";
    /// `POST /api/logout`.
    pub const API_LOGOUT: &str = "/api/logout";
    /// `GET /api/me`.
    pub const API_ME: &str = "/api/me";

    /// `GET /api/events`.
    pub const API_EVENTS: &str = "/api/events";
    /// `GET /api/bans`.
    pub const API_BANS: &str = "/api/bans";
    /// `POST /api/bans/{ip}/delete`.
    pub const API_BAN_DELETE_PREFIX: &str = "/api/bans/";
    /// `GET /api/sites`.
    pub const API_SITES: &str = "/api/sites";
    /// `GET|POST /api/sites/{host}` (details, mode, strictness, rules, lockdown check, verify).
    pub const API_SITE_PREFIX: &str = "/api/sites/";
    /// `GET /api/sites/{host}/connect/{method}`.
    pub const API_CONNECT_SUFFIX: &str = "/connect";
    /// `POST /api/inspect`: run the detector on a payload without touching a site.
    pub const API_INSPECT: &str = "/api/inspect";
    /// `GET /api/account`, `GET|POST /api/account/sessions`, `GET|POST /api/account/tokens`.
    pub const API_ACCOUNT: &str = "/api/account";
    /// `GET|POST /api/users` (owner only).
    pub const API_USERS: &str = "/api/users";
    /// `GET /api/block-preview`: the block page HTML preview.
    pub const API_BLOCK_PREVIEW: &str = "/api/block-preview";
    /// `GET /api/findings`: the finding list grouped from blocked events (Addendum 6).
    pub const API_FINDINGS: &str = "/api/findings";
    /// `/api/findings/{id}` and its sub-routes (`/confirm`, `/explain`, `/export`); the whole finding surface
    /// (Addendum 6). The UI and the tests use this prefix to keep API parity (R-27).
    pub const API_FINDING_PREFIX: &str = "/api/findings/";
}

/// The per-site protection mode. `Off` is a pure pass-through (the dashboard shows the red banner), `Monitor` records
/// `would_block` but forwards, `Block` refuses the request and bans the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Pure pass-through, no inspection verdict is enforced.
    Off,
    /// Inspect and record; forward everything.
    #[default]
    Monitor,
    /// Inspect and refuse; ban the client on a block verdict.
    Block,
}

impl Mode {
    /// The wire name used in the API, the log and the configuration.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Monitor => "monitor",
            Self::Block => "block",
        }
    }
}

/// Whether the site can honestly be called protected (R-34): only in `block` mode with the origin lockdown verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protection {
    /// Something is forwarded without inspection (mode `off`).
    Off,
    /// Requests are inspected and recorded, but nothing is refused.
    Monitoring,
    /// Inspected and refused, but the origin was not verified as locked down.
    BlockingUnverified,
    /// Inspected and refused and the origin lockdown check passed.
    BlockingLocked,
}

/// The role of an account. `Owner` may do everything; `Viewer` is read-only (no mode switch, no unban, no config).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Read-only.
    #[default]
    Viewer,
    /// Everything, including account and site management.
    Owner,
}

impl Role {
    /// Whether the role may mutate state.
    #[must_use]
    pub fn can_mutate(self) -> bool {
        matches!(self, Self::Owner)
    }
}

/// The authenticated caller of an admin request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The stable account id.
    pub user_id: String,
    /// The login name.
    pub username: String,
    /// The role.
    pub role: Role,
}

/// A request after the wire layer has buffered it. The admin surface only handles small bodies (the proxy data path
/// bypasses this type and streams).
#[derive(Debug, Clone)]
pub struct ApiRequest {
    /// The upper-case method.
    pub method: String,
    /// The path, without the query string.
    pub path: String,
    /// The parsed query pairs (repeated names preserved).
    pub query: Vec<(String, String)>,
    /// The request headers (names as received).
    pub headers: Vec<(String, String)>,
    /// The buffered body (at most the admin cap).
    pub body: Vec<u8>,
}

impl ApiRequest {
    /// The first value of a query parameter.
    #[must_use]
    pub fn query_value(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The first value of a request header (case-insensitive name match).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Deserialize the JSON body.
    ///
    /// # Errors
    /// Returns [`ApiError`] with status 400 when the body is not valid JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, ApiError> {
        serde_json::from_slice(&self.body).map_err(|_| ApiError::bad_request("invalid JSON body"))
    }
}

/// A response the admin handlers return; the wire layer turns it into a hyper response.
#[derive(Debug, Clone)]
pub struct ApiResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The `Content-Type` value.
    pub content_type: &'static str,
    /// Extra response headers.
    pub headers: Vec<(String, String)>,
    /// The response body.
    pub body: Vec<u8>,
}

impl ApiResponse {
    /// A JSON response (status 200).
    #[must_use]
    pub fn json<T: Serialize>(value: &T) -> Self {
        let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
        Self {
            status: 200,
            content_type: "application/json; charset=utf-8",
            headers: Vec::new(),
            body,
        }
    }

    /// A JSON response with an explicit status.
    #[must_use]
    pub fn json_status<T: Serialize>(status: u16, value: &T) -> Self {
        let mut response = Self::json(value);
        response.status = status;
        response
    }

    /// An empty `204 No Content` response.
    #[must_use]
    pub fn no_content() -> Self {
        Self {
            status: 204,
            content_type: "text/plain; charset=utf-8",
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// A plain-text response.
    #[must_use]
    pub fn text(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            headers: Vec::new(),
            body: body.into().into_bytes(),
        }
    }

    /// An HTML response.
    #[must_use]
    pub fn html(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            content_type: "text/html; charset=utf-8",
            headers: Vec::new(),
            body: body.into().into_bytes(),
        }
    }

    /// A redirect to `location` (the caller sets cookies separately).
    #[must_use]
    pub fn redirect(location: &str) -> Self {
        Self {
            status: 303,
            content_type: "text/plain; charset=utf-8",
            headers: vec![("Location".to_owned(), location.to_owned())],
            body: b"see other".to_vec(),
        }
    }

    /// An error response in the documented `{"error":{"code","message"}}` shape.
    #[must_use]
    pub fn error(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        let body = ErrorBody {
            error: ErrorDetail {
                code: code.to_owned(),
                message: message.into(),
            },
        };
        let mut response = Self::json_status(status, &body);
        response.content_type = "application/json; charset=utf-8";
        response
    }

    /// Append one response header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// An API error the handlers may return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    /// The HTTP status to send.
    pub status: u16,
    /// The stable machine-readable code.
    pub code: &'static str,
    /// The human message (never echoes a password or a secret).
    pub message: String,
}

impl ApiError {
    /// 400 with a message.
    #[must_use]
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: 400,
            code: "bad_request",
            message: message.into(),
        }
    }

    /// 401.
    #[must_use]
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: 401,
            code: "unauthorized",
            message: message.into(),
        }
    }

    /// 403.
    #[must_use]
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: 403,
            code: "forbidden",
            message: message.into(),
        }
    }

    /// 404.
    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: 404,
            code: "not_found",
            message: message.into(),
        }
    }

    /// 409.
    #[must_use]
    pub fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: 409,
            code: "conflict",
            message: message.into(),
        }
    }

    /// 429.
    #[must_use]
    pub fn too_many_requests(message: impl Into<String>) -> Self {
        Self {
            status: 429,
            code: "too_many_requests",
            message: message.into(),
        }
    }

    /// The response for this error.
    #[must_use]
    pub fn into_response(self) -> ApiResponse {
        ApiResponse::error(self.status, self.code, self.message)
    }
}

/// The error body shape.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    /// The error detail.
    pub error: ErrorDetail,
}

/// The error detail.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorDetail {
    /// The stable code.
    pub code: String,
    /// The human message.
    pub message: String,
}

/// The health and about data (`GET /healthz`, About screen).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthView {
    /// `"ok"`.
    pub status: String,
    /// The binary version.
    pub version: String,
    /// Seconds since start.
    pub uptime_seconds: u64,
    /// Configured sites.
    pub sites: usize,
    /// Whether an owner account exists.
    pub accounts_ready: bool,
}

/// The bearer of the demo site's protected status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteView {
    /// The public host name the proxy routes on.
    pub host: String,
    /// The origin URL requests are forwarded to.
    pub origin: String,
    /// The protection mode.
    pub mode: Mode,
    /// The detection strictness.
    pub strictness: Strictness,
    /// Whether the effective protection is honest (R-34).
    pub protection: Protection,
    /// Banning enabled.
    pub ban_enabled: bool,
    /// Progressive ban TTL ladder in seconds.
    pub ttl_ladder_seconds: Vec<u64>,
    /// The operator's field hints.
    pub field_hints: Vec<FieldHintView>,
    /// The operator's custom rules.
    pub rules: Vec<CustomRule>,
    /// The upstream `Host` override (`None` preserves or rewrites per `preserve_host`).
    pub upstream_host: Option<String>,
    /// The header name injected upstream to prove the origin is locked down.
    pub origin_secret_header: Option<String>,
    /// Whether the secret env var is present (never its value).
    pub origin_secret_configured: bool,
    /// Whether the origin lockdown check has passed.
    pub lockdown_verified: bool,
    /// The number of requests seen for this site since start.
    pub requests: u64,
    /// The number of blocked requests for this site since start.
    pub blocked: u64,
    /// The per-site stack hint that picks the remediation code example (`node`, `php`, `python`, `java`, `other`).
    pub stack: String,
}

/// One operator field hint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldHintView {
    /// The field name to match (whole token, case-insensitive).
    pub field: String,
    /// The kind to force.
    pub kind: FieldKind,
}

/// A recorded request event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventView {
    /// Monotonic sequence number in the ring.
    pub seq: u64,
    /// RFC 3339 UTC timestamp.
    pub time: String,
    /// The Ray ID (`[0-9a-f]{16}-HDD1`).
    pub ray_id: String,
    /// The site host.
    pub site: String,
    /// The client IP.
    pub client_ip: String,
    /// The request method.
    pub method: String,
    /// The request path.
    pub path: String,
    /// `allow`, `would_block` or `block`.
    pub action: String,
    /// `sqli`, `custom`, ... when the detector fired.
    pub category: Option<String>,
    /// The family subtype.
    pub subtype: Option<String>,
    /// The rule id.
    pub rule_id: Option<String>,
    /// The vector.
    pub vector: Option<String>,
    /// The field name.
    pub field: Option<String>,
    /// The inferred field kind.
    pub field_kind: Option<String>,
    /// The redacted evidence (at most 128 bytes).
    pub evidence: String,
    /// The site mode at decision time.
    pub mode: String,
    /// The configuration revision.
    pub config_revision: u64,
}

/// An active ban.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanView {
    /// The banned client IP.
    pub ip: String,
    /// The site the ban was created for.
    pub site: Option<String>,
    /// The human reason (rule, vector, redacted evidence summary).
    pub reason: String,
    /// The rule id that caused the ban.
    pub rule_id: Option<String>,
    /// The category.
    pub category: Option<String>,
    /// RFC 3339 UTC creation time.
    pub created_at: String,
    /// RFC 3339 UTC expiry time.
    pub expires_at: String,
    /// The TTL of the current step, in seconds.
    pub ttl_seconds: u64,
    /// Seconds until expiry.
    pub remaining_seconds: u64,
    /// The ladder step (1-based).
    pub step: u32,
}

/// The counters shown on the Overview screen. `window_seconds` is 3600 for the "last hour" figures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counters {
    /// Requests in the window.
    pub requests: u64,
    /// Blocked requests in the window.
    pub blocked: u64,
    /// `would_block` requests in the window (monitor mode).
    pub would_block: u64,
    /// Distinct banned IPs currently active.
    pub banned_ips: u64,
    /// The window length in seconds.
    pub window_seconds: u64,
}

/// `GET /api/events` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsResponse {
    /// The newest events first.
    pub events: Vec<EventView>,
    /// The live counters.
    pub counters: Counters,
    /// The sites (for the filter dropdown).
    pub sites: Vec<String>,
}

/// `GET /api/bans` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BansResponse {
    /// The active bans, soonest expiry first.
    pub bans: Vec<BanView>,
}

/// `GET /api/sites` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SitesResponse {
    /// The configured sites.
    pub sites: Vec<SiteView>,
    /// The global counters.
    pub counters: Counters,
}

/// A simple `{"ok": true}` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OkResponse {
    /// Always `true`.
    pub ok: bool,
}

/// `POST /api/sites/{host}/delete` body: the typed confirmation, which must equal the host (R-28).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteRemoveRequest {
    /// The host being removed, typed by the operator.
    pub confirm: String,
}

/// `POST /api/sites/{host}/mode` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeChangeRequest {
    /// The new mode.
    pub mode: Mode,
    /// Typed confirmation, required when switching to `off` (R-28, no dark patterns): the UI asks the operator to
    /// type `off` and the server requires this field to equal `"off"`.
    #[serde(default)]
    pub confirm: Option<String>,
}

/// `POST /api/sites/{host}/strictness` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrictnessChangeRequest {
    /// The new strictness.
    pub strictness: Strictness,
}

/// `POST /api/sites/{host}/rules` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCreateRequest {
    /// The rule to add.
    pub rule: CustomRule,
}

/// `POST /api/sites/{host}/rules/delete` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDeleteRequest {
    /// The rule id to delete.
    pub id: String,
}

/// `POST /api/inspect` body: run the detector without touching a site (Test console, no live traffic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectRequest {
    /// The payload to inspect.
    pub payload: String,
    /// The field kind to assume (defaults to `unknown`).
    #[serde(default)]
    pub field_kind: Option<FieldKind>,
    /// The vector to assume (defaults to `query`).
    #[serde(default)]
    pub vector: Option<Vector>,
    /// An optional site host whose settings apply.
    #[serde(default)]
    pub site: Option<String>,
}

/// `POST /api/inspect` response.
#[derive(Debug, Clone, Serialize)]
pub struct InspectResponse {
    /// The verdict.
    pub verdict: Verdict,
    /// The normalised value the detector matched against (redacted to 128 bytes).
    pub normalized: String,
}

/// `POST /api/setup-status` / `GET /api/setup-status` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupStatusView {
    /// Whether the first-run wizard is open (no account exists yet).
    pub setup_required: bool,
    /// Whether the request reached the admin listener over loopback (the wizard is loopback-only).
    pub loopback: bool,
}

/// `POST /api/setup` body: create the owner account (Addendum 2 item 1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupRequest {
    /// The owner login name.
    pub username: String,
    /// The owner email.
    pub email: String,
    /// The owner password (at least [`MIN_PASSWORD_LEN`] characters, strength-checked).
    pub password: String,
}

/// `POST /api/login` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    /// The login name.
    pub username: String,
    /// The password.
    pub password: String,
}

/// `POST /api/login` response and `GET /api/me` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionViewBody {
    /// The login name.
    pub username: String,
    /// The role.
    pub role: Role,
    /// The account email.
    pub email: String,
}

/// `GET /api/account` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountView {
    /// The login name.
    pub username: String,
    /// The email.
    pub email: String,
    /// The role.
    pub role: Role,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// Active sessions.
    pub sessions: Vec<SessionView>,
    /// Script API tokens (never the token value).
    pub tokens: Vec<TokenView>,
}

/// One active session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionView {
    /// The session id (the cookie value is a separate handle; this is the row id).
    pub id: String,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// RFC 3339 last-use time.
    pub last_seen_at: String,
    /// The client IP that created the session.
    pub ip: String,
    /// Whether this is the session of the request.
    pub current: bool,
}

/// One script API token (the value is shown once, at creation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenView {
    /// The token row id.
    pub id: String,
    /// The operator label.
    pub name: String,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// RFC 3339 last-use time, if ever used.
    pub last_used_at: Option<String>,
}

/// `POST /api/account/tokens` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenCreateRequest {
    /// The operator label.
    pub name: String,
}

/// `POST /api/account/tokens` response: the value is shown once and never stored in clear (Addendum 2 item 3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenCreateResponse {
    /// The one-time token value.
    pub token: String,
    /// The stored metadata.
    pub view: TokenView,
}

/// `POST /api/account/password` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    /// The current password (re-authentication).
    pub current_password: String,
    /// The new password.
    pub new_password: String,
}

/// `POST /api/account/email` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeEmailRequest {
    /// The current password (re-authentication).
    pub password: String,
    /// The new email.
    pub email: String,
}

/// One account row for the Users screen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserView {
    /// The stable id.
    pub id: String,
    /// The login name.
    pub username: String,
    /// The email.
    pub email: String,
    /// The role.
    pub role: Role,
    /// RFC 3339 creation time.
    pub created_at: String,
}

/// `GET /api/users` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersResponse {
    /// The accounts.
    pub users: Vec<UserView>,
}

/// `POST /api/users` body (owner only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCreateRequest {
    /// The login name.
    pub username: String,
    /// The email.
    pub email: String,
    /// The initial password.
    pub password: String,
    /// The role.
    pub role: Role,
}

/// `POST /api/users/{id}/role` body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRoleRequest {
    /// The new role.
    pub role: Role,
}

/// `POST /api/sites` body: the Add-site wizard (Addendum 2 item 5, Addendum 3, Addendum 5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteCreateRequest {
    /// The public host name.
    pub host: String,
    /// The origin URL (`http://` or `https://`).
    pub origin: String,
    /// The initial mode (default `monitor`).
    #[serde(default)]
    pub mode: Mode,
    /// The connection method that will put HDD in front.
    #[serde(default)]
    pub connection: ConnectionMethod,
    /// The upstream `Host` override for serverless origins (Addendum 5).
    #[serde(default)]
    pub upstream_host: Option<String>,
    /// The origin secret header name for serverless origins (Addendum 5).
    #[serde(default)]
    pub origin_secret_header: Option<String>,
    /// Let HDD generate the origin secret (and the default header name) instead of reading it from an environment
    /// variable. The value is returned once in the create response and kept in an owner-only file in the data directory.
    #[serde(default)]
    pub generate_origin_secret: bool,
}

/// `POST /api/sites` response: the created site plus the generated setup steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteCreateResponse {
    /// The created site.
    pub site: SiteView,
    /// The copy-paste connection instructions.
    pub setup: SetupInstructions,
    /// The generated origin secret, shown exactly once when `generate_origin_secret` was requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_secret: Option<String>,
}

/// The generated instructions for one connection method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupInstructions {
    /// The chosen method.
    pub method: ConnectionMethod,
    /// The short title.
    pub title: String,
    /// The numbered steps (plain text, copied by the operator).
    pub steps: Vec<String>,
    /// A configuration snippet (Caddy/nginx/Next.js middleware/Vercel), if the method has one.
    pub snippet: String,
    /// Known limitations that must be stated with the instructions.
    pub caveats: Vec<String>,
}

/// How HDD is put in front of the origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMethod {
    /// DNS A/CNAME of the domain to the HDD host (Caddy terminates TLS).
    #[default]
    Dns,
    /// Cloudflare tunnel or proxy in front of the HDD host.
    Cloudflare,
    /// A reverse proxy (nginx/Apache) in front of an existing origin.
    Nginx,
    /// A serverless origin (Vercel/Netlify/Render) locked down by `origin_secret_header` (Addendum 5).
    Vercel,
    /// A serverless origin reached through a front door (Addendum 7): visitors keep the Vercel address, the public host
    /// is that address, and the origin is a **second** address of the same project that only HDD uses. The front-door
    /// block forwards uninspected requests to HDD instead of serving the app, so the visitors' address never changes.
    VercelFrontDoor,
}

/// `POST /api/sites/{host}/lockdown-check` response: whether the origin refuses a direct request (R-34).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockdownCheckResponse {
    /// `reachable`, `refused` or `error`.
    pub result: String,
    /// The human explanation.
    pub detail: String,
    /// `true` only for `refused` with the secret header enforced (or an IP allowlist refusal).
    pub protected: bool,
    /// The status code seen from the direct request, if any.
    pub status_code: Option<u16>,
}

/// One check of the Verify-protection flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyCheck {
    /// The check name.
    pub name: String,
    /// `PASS`, `FAIL` or `UNVERIFIED`.
    pub status: String,
    /// The real detail line (what was sent, what came back).
    pub detail: String,
}

/// `POST /api/sites/{host}/verify` body: the typed confirmation of ownership.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    /// The host name typed by the operator (must equal the site host).
    pub confirmation: String,
}

/// `POST /api/sites/{host}/verify` response: at most two inert requests, to the registered site only (Addendum 3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    /// `true` only when the lockdown and the block check both pass.
    pub protected: bool,
    /// The checks, in order.
    pub checks: Vec<VerifyCheck>,
    /// The Ray ID of the blocked probe, if any.
    pub ray_id: Option<String>,
    /// The one-line summary.
    pub summary: String,
}

/// The block page preview payload (`GET /api/block-preview`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockPreviewResponse {
    /// The rendered HTML.
    pub html: String,
    /// A sample Ray ID in the real format.
    pub ray_id: String,
}

/// One remediation code example (Addendum 6). `language` is the render hint (`node`, `php`, `python`, `java`,
/// `other`); the UI renders it as escaped text with a copy button.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeExampleView {
    /// The language/stack label of the example.
    pub language: String,
    /// A one-line caption of what the example does.
    pub caption: String,
    /// The code, rendered as escaped text (never as HTML).
    pub code: String,
}

/// The deterministic remediation guidance for one finding (Addendum 6). Every sentence is produced from the finding
/// facts, never invented per request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationView {
    /// The fix steps, in order.
    pub steps: Vec<String>,
    /// The default code example for the site's stack hint.
    pub code_example: CodeExampleView,
    /// The honest note that a virtual patch is not a fix (R-11).
    pub virtual_patch_note: String,
}

/// One finding: a group of blocked events with the same site, method, path, vector, field and family (Addendum 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingView {
    /// The stable finding id (hex, derived from the grouping key).
    pub id: String,
    /// The site host the events were seen on.
    pub site: String,
    /// The request method.
    pub method: String,
    /// The request path.
    pub path: String,
    /// The vector (path/query/form_body/json_body/multipart_field/multipart_filename/header/cookie).
    pub vector: String,
    /// The field name.
    pub field: String,
    /// The inferred field kind.
    pub field_kind: String,
    /// The detector rule id.
    pub rule_id: String,
    /// The family/subtype (`tautology`, `union`, `subselect`, ...).
    pub family: String,
    /// The attack category (`sqli`, `custom`, `policy`).
    pub category: String,
    /// RFC 3339 UTC time of the first blocked event in this group.
    pub first_seen: String,
    /// RFC 3339 UTC time of the last blocked event in this group.
    pub last_seen: String,
    /// How many blocked events were grouped into this finding.
    pub count: u64,
    /// The most recent redacted evidence (at most 128 bytes).
    pub evidence: String,
    /// One exact sentence naming what was detected.
    pub detected: String,
    /// The inferred weakness, explicitly stated as an inference from the payload shape.
    pub inferred_weakness: String,
    /// What an attacker could do if this request had reached the application.
    pub attacker_impact: String,
    /// `attempt_observed` (only blocked attempts were seen) or `confirmed` (the owner ran the confirm probe and it
    /// reported `confirmed_injectable`).
    pub confidence: String,
    /// The remediation guidance for this finding.
    pub remediation: RemediationView,
    /// The per-site stack hint used for the code example.
    pub stack: String,
    /// The optional cached AI explanation (Addendum 6 item 3), never part of the block decision.
    pub ai: Option<AiExplanationView>,
}

/// `GET /api/findings` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsResponse {
    /// The findings, newest first.
    pub findings: Vec<FindingView>,
    /// The total number of findings (before any limit).
    pub total: u64,
    /// Whether AI explanations are configured and the API key variable is present (never the key itself).
    pub ai_enabled: bool,
    /// The AI model name when AI is enabled.
    pub ai_model: Option<String>,
}

/// `POST /api/findings/{id}/confirm` body: the typed confirmation of ownership (the site host exactly).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmRequest {
    /// The host name typed by the operator; must equal the finding's site host.
    pub confirmation: String,
}

/// One probe request and the observed result of the confirm-vulnerability flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmProbeResult {
    /// The probe label (`baseline`, `quote`, `boolean_true`, `boolean_false`).
    pub name: String,
    /// The request line that was sent (method and path only; never the body or a credential).
    pub request: String,
    /// The status code, if the origin answered.
    pub status: Option<u16>,
    /// The redirect target, if any (normalised to path only).
    pub redirect: Option<String>,
    /// The response body length in bytes, if any.
    pub body_length: Option<usize>,
    /// What the probe showed (a short human note).
    pub note: String,
}

/// `POST /api/findings/{id}/confirm` response (Addendum 6 item 2). At most four inert read-only probes are sent to the
/// registered site's origin; `confirmed_injectable` marks the finding `confirmed`, never a block decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmResponse {
    /// `confirmed_injectable`, `not_confirmed` or `inconclusive`.
    pub verdict: String,
    /// The probes and their observed results, in order.
    pub probes: Vec<ConfirmProbeResult>,
    /// The evidence comparison summary.
    pub summary: String,
    /// `true` when detection was deliberately skipped for these probes (it always is; shown for clarity).
    pub detection_skipped: bool,
    /// The audit Ray ID of the confirm flow.
    pub ray_id: String,
    /// The finding after the flow (its confidence may now be `confirmed`).
    pub finding: FindingView,
}

/// One AI-generated explanation (Addendum 6 item 3). It is advisory text only: it never decides block/ban and never
/// changes a verdict (R-33). It is rendered as escaped text and labelled "AI-generated, verify before use".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiExplanationView {
    /// A short summary of the vulnerability.
    pub summary: String,
    /// What an attacker could do.
    pub attacker_impact: Vec<String>,
    /// The remediation steps.
    pub remediation_steps: Vec<String>,
    /// The code example, when the model returned a valid one.
    pub code_example: Option<CodeExampleView>,
    /// RFC 3339 UTC generation time.
    pub generated_at: String,
    /// The model name that produced the explanation.
    pub model: String,
    /// Always "AI-generated, verify before use".
    pub label: String,
}

/// `POST /api/findings/{id}/explain` body (Addendum 6 item 3). Optional; the language only selects the wording the
/// model is asked for, it never adds request data to the prompt.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExplainRequest {
    /// The requested answer language (BCP-47-ish, e.g. `en`); the UI sends `en`.
    #[serde(default)]
    pub language: Option<String>,
}

/// `POST /api/findings/{id}/explain` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainResponse {
    /// `ok`, `disabled`, `rate_limited` or `error`.
    pub status: String,
    /// The explanation when `status == "ok"`.
    pub explanation: Option<AiExplanationView>,
    /// The human message (for `disabled`/`rate_limited`/`error`), never containing the API key.
    pub message: String,
    /// Whether the response came from the per-finding cache.
    pub cached: bool,
}

/// Whether an admin API path may be called without a session (setup and login only, while unauthenticated).
#[must_use]
pub fn is_public_admin_path(path: &str) -> bool {
    matches!(
        path,
        paths::HEALTHZ
            | paths::LOGIN
            | paths::SETUP
            | paths::API_SETUP_STATUS
            | paths::API_SETUP
            | paths::API_LOGIN
    ) || path.starts_with(paths::STATIC_PREFIX)
}

/// Whether a method mutates state and therefore needs the CSRF guard when authenticated by cookie.
#[must_use]
pub fn is_mutation(method: &str) -> bool {
    !matches!(method, "GET" | "HEAD" | "OPTIONS")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_paths_are_exact_or_the_static_prefix() {
        assert!(is_public_admin_path(paths::API_LOGIN));
        assert!(is_public_admin_path("/static/app.js"));
        assert!(!is_public_admin_path("/api/events"));
        assert!(!is_public_admin_path("/api/eventsomething"));
    }

    #[test]
    fn modes_serialize_as_documented() {
        assert_eq!(
            serde_json::to_string(&Mode::Block).ok().as_deref(),
            Some("\"block\"")
        );
        assert_eq!(
            serde_json::to_string(&Role::Owner).ok().as_deref(),
            Some("\"owner\"")
        );
        assert_eq!(
            serde_json::to_string(&ConnectionMethod::Vercel)
                .ok()
                .as_deref(),
            Some("\"vercel\"")
        );
        assert_eq!(
            serde_json::to_string(&ConnectionMethod::VercelFrontDoor)
                .ok()
                .as_deref(),
            Some("\"vercel_front_door\"")
        );
    }

    #[test]
    fn a_front_door_create_request_binds_the_snake_case_connection() {
        let request: SiteCreateRequest = serde_json::from_str(
            r#"{"host":"hdd-demo-shop.vercel.app","origin":"https://hdd-demo-shop-2.vercel.app","connection":"vercel_front_door"}"#,
        )
        .expect("the front-door connection deserializes");
        assert_eq!(request.connection, ConnectionMethod::VercelFrontDoor);
    }

    #[test]
    fn error_responses_keep_the_documented_shape() {
        let response = ApiError::unauthorized("login required").into_response();
        assert_eq!(response.status, 401);
        let body: ErrorBody = serde_json::from_slice(&response.body).unwrap_or(ErrorBody {
            error: ErrorDetail {
                code: "parse_error".to_owned(),
                message: String::new(),
            },
        });
        assert_eq!(body.error.code, "unauthorized");
        assert_eq!(body.error.message, "login required");
    }
}
