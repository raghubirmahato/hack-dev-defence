//! The egress clients (R-22): [`Client`] (allowlist) and [`UserUrlClient`] (SSRF-guarded) over one engine.
//!
//! Guarantees, each covered by a test with real local servers:
//!
//! * a destination that is not permitted is refused **before any socket is opened** (and logged);
//! * names are resolved once per hop, **every** returned address is validated, and the connection goes to the validated
//!   address (no silent re-resolution; the next hop or request resolves and validates again, which defeats DNS rebinding);
//! * redirects are not followed unless the call opts in, and every followed hop passes the full policy again;
//! * TLS certificate verification is always on (there is no switch);
//! * connect and total timeouts, a response size cap and a request size cap apply to every call;
//! * the kill switch aborts a request in flight;
//! * each denial is recorded in the rate-limited [`DenyLog`].

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http_body_util::{BodyExt, Full};
use hyper::Method;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::allow::{Allowlist, Scheme};
use super::denylog::DenyLog;
use super::killswitch::KillSwitch;
use super::resolver::{BoxFuture, Resolver, SystemResolver};
use super::ssrf::{SsrfPolicy, check_baseline};
use super::url::{ParsedUrl, UrlError, parse_url};

/// Limits applied to every call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// TCP connect (and TLS handshake) timeout.
    pub connect_timeout: Duration,
    /// Total time for the whole call including redirects.
    pub total_timeout: Duration,
    /// Largest response body accepted.
    pub max_response_bytes: usize,
    /// Largest request body accepted.
    pub max_request_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            connect_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(30),
            max_response_bytes: 1024 * 1024,
            max_request_bytes: 1024 * 1024,
        }
    }
}

/// Most redirects a call may opt into.
pub const MAX_REDIRECTS_CEILING: u8 = 5;

/// What went wrong with a call.
#[derive(Debug)]
pub enum EgressError {
    /// Policy refused the destination; nothing was sent.
    Denied {
        /// Machine-readable reason.
        reason: String,
        /// Destination as logged (no query string).
        destination: String,
    },
    /// The URL is not acceptable.
    InvalidUrl(UrlError),
    /// The request itself is not acceptable (method, header, body size).
    InvalidRequest(String),
    /// Name resolution failed.
    Resolve(String),
    /// TCP connection failed.
    Connect(String),
    /// TLS failed (including certificate verification).
    Tls(String),
    /// A timeout elapsed (`connect` or `total`).
    Timeout(&'static str),
    /// HTTP protocol error.
    Http(String),
    /// The response body exceeded the cap.
    TooLarge {
        /// The cap.
        limit: usize,
    },
    /// The kill switch was tripped.
    Aborted,
    /// More redirects than the call allowed.
    TooManyRedirects,
}

impl std::fmt::Display for EgressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EgressError::Denied {
                reason,
                destination,
            } => write!(f, "egress denied ({reason}): {destination}"),
            EgressError::InvalidUrl(e) => write!(f, "invalid URL: {e}"),
            EgressError::InvalidRequest(e) => write!(f, "invalid request: {e}"),
            EgressError::Resolve(e) => write!(f, "resolution failed: {e}"),
            EgressError::Connect(e) => write!(f, "connect failed: {e}"),
            EgressError::Tls(e) => write!(f, "TLS failed: {e}"),
            EgressError::Timeout(w) => write!(f, "{w} timeout"),
            EgressError::Http(e) => write!(f, "HTTP error: {e}"),
            EgressError::TooLarge { limit } => write!(f, "response larger than {limit} bytes"),
            EgressError::Aborted => f.write_str("aborted by the kill switch"),
            EgressError::TooManyRedirects => f.write_str("too many redirects"),
        }
    }
}

impl std::error::Error for EgressError {}

/// An outbound HTTP request.
#[derive(Debug, Clone)]
pub struct Request {
    method: Method,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    max_redirects: u8,
}

impl Request {
    /// A GET request.
    pub fn get(url: impl Into<String>) -> Self {
        Request {
            method: Method::GET,
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
            max_redirects: 0,
        }
    }

    /// A HEAD request.
    pub fn head(url: impl Into<String>) -> Self {
        Request {
            method: Method::HEAD,
            ..Request::get(url)
        }
    }

    /// A POST request with a body.
    pub fn post(url: impl Into<String>, body: Vec<u8>) -> Self {
        Request {
            method: Method::POST,
            body,
            ..Request::get(url)
        }
    }

    /// Use another method.
    pub fn method(mut self, m: Method) -> Self {
        self.method = m;
        self
    }

    /// Add a header (validated when the request is sent).
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Opt in to following up to `n` redirects (capped at [`MAX_REDIRECTS_CEILING`]); each hop is re-validated in full.
    pub fn follow_redirects(mut self, n: u8) -> Self {
        self.max_redirects = n.min(MAX_REDIRECTS_CEILING);
        self
    }
}

/// An HTTP response (the body is already bounded by the size cap).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Headers with lower-case names.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
    /// Final URL as logged (no query string).
    pub url: String,
    /// Redirects that were followed.
    pub redirects_followed: u8,
}

impl Response {
    /// First header value with this (case-insensitive) name.
    pub fn header(&self, name: &str) -> Option<&str> {
        let n = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == n)
            .map(|(_, v)| v.as_str())
    }
}

/// Opens TCP connections to **already validated** addresses.
pub trait Connector: Send + Sync {
    /// Connect to `addr`.
    fn connect<'a>(&'a self, addr: SocketAddr) -> BoxFuture<'a, io::Result<TcpStream>>;
}

/// The real connector.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpConnector;

impl Connector for TcpConnector {
    fn connect<'a>(&'a self, addr: SocketAddr) -> BoxFuture<'a, io::Result<TcpStream>> {
        Box::pin(async move { TcpStream::connect(addr).await })
    }
}

/// Everything a client needs besides its policy.
#[derive(Clone)]
pub struct EgressConfig {
    resolver: Arc<dyn Resolver>,
    connector: Arc<dyn Connector>,
    extra_roots: Vec<Vec<u8>>,
    native_roots: bool,
    limits: Limits,
    kill: Option<KillSwitch>,
    deny: Arc<DenyLog>,
    caller: String,
}

impl EgressConfig {
    /// Defaults: system resolver, real TCP, OS trust roots, default limits, stderr deny log.
    pub fn new(caller: &str) -> Self {
        EgressConfig {
            resolver: Arc::new(SystemResolver),
            connector: Arc::new(TcpConnector),
            extra_roots: Vec::new(),
            native_roots: true,
            limits: Limits::default(),
            kill: None,
            deny: Arc::new(DenyLog::stderr()),
            caller: caller.to_owned(),
        }
    }

    /// Use another resolver.
    pub fn resolver(mut self, r: Arc<dyn Resolver>) -> Self {
        self.resolver = r;
        self
    }

    /// Use another connector (tests map validated addresses to local servers).
    pub fn connector(mut self, c: Arc<dyn Connector>) -> Self {
        self.connector = c;
        self
    }

    /// Trust one more root (DER), for example a private CA of the operator's lab.
    pub fn extra_root_der(mut self, der: Vec<u8>) -> Self {
        self.extra_roots.push(der);
        self
    }

    /// Do not load the operating system roots (only the extra roots are trusted).
    pub fn without_native_roots(mut self) -> Self {
        self.native_roots = false;
        self
    }

    /// Set the limits.
    pub fn limits(mut self, l: Limits) -> Self {
        self.limits = l;
        self
    }

    /// Attach a kill switch.
    pub fn kill_switch(mut self, k: KillSwitch) -> Self {
        self.kill = Some(k);
        self
    }

    /// Use another deny log.
    pub fn deny_log(mut self, d: Arc<DenyLog>) -> Self {
        self.deny = d;
        self
    }
}

fn native_roots() -> &'static Vec<CertificateDer<'static>> {
    static ROOTS: OnceLock<Vec<CertificateDer<'static>>> = OnceLock::new();
    ROOTS.get_or_init(|| rustls_native_certs::load_native_certs().certs)
}

fn build_tls(cfg: &EgressConfig) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    if cfg.native_roots {
        let (_added, _ignored) = roots.add_parsable_certificates(native_roots().iter().cloned());
    }
    for der in &cfg.extra_roots {
        roots
            .add(CertificateDer::from(der.clone()))
            .map_err(|e| format!("bad extra root certificate: {e}"))?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(tls))
}

enum Gate {
    Allow(Allowlist),
    UserUrl(SsrfPolicy),
}

impl Gate {
    fn class(&self) -> &'static str {
        match self {
            Gate::Allow(_) => "allowlist",
            Gate::UserUrl(_) => "user_url",
        }
    }

    fn check_url(&self, u: &ParsedUrl) -> Result<(), String> {
        match self {
            Gate::Allow(list) => {
                if list.permits(u.scheme, &u.host, u.port, u.path()) {
                    Ok(())
                } else {
                    Err("not_on_allowlist".to_owned())
                }
            }
            Gate::UserUrl(policy) => policy.check_port(u.port).map_err(|e| {
                format!(
                    "port:{}",
                    match e {
                        super::ssrf::SsrfDeny::Port(p) => p,
                        _ => u.port,
                    }
                )
            }),
        }
    }

    fn check_addr(&self, ip: IpAddr) -> Result<(), String> {
        match self {
            Gate::Allow(_) => check_baseline(ip).map_err(|e| denial_reason(&e)),
            Gate::UserUrl(policy) => policy.check_ip(ip).map_err(|e| denial_reason(&e)),
        }
    }
}

fn denial_reason(e: &super::ssrf::SsrfDeny) -> String {
    match e {
        super::ssrf::SsrfDeny::Class(c) => format!("address_class:{}", c.label()),
        super::ssrf::SsrfDeny::PlatformAddress => "platform_address".to_owned(),
        super::ssrf::SsrfDeny::Port(p) => format!("port:{p}"),
        super::ssrf::SsrfDeny::Scheme => "scheme".to_owned(),
    }
}

struct Engine {
    gate: Gate,
    cfg: EgressConfig,
    tls: Arc<ClientConfig>,
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

const FORBIDDEN_REQUEST_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "proxy-authorization",
    "proxy-connection",
    "keep-alive",
    "expect",
];
/// Request headers that may follow a redirect to another origin; everything else the caller set (credentials, API keys,
/// signatures, cookies) is dropped when scheme, host or port change.
const PORTABLE_HEADERS: &[&str] = &["accept", "accept-language"];

impl Engine {
    fn new(gate: Gate, cfg: EgressConfig) -> Result<Self, String> {
        let tls = build_tls(&cfg)?;
        Ok(Engine { gate, cfg, tls })
    }

    fn deny(&self, destination: &str, reason: &str) -> EgressError {
        self.cfg
            .deny
            .record(destination, reason, &self.cfg.caller, self.gate.class());
        EgressError::Denied {
            reason: reason.to_owned(),
            destination: destination.to_owned(),
        }
    }

    async fn send(&self, req: Request) -> Result<Response, EgressError> {
        if let Some(k) = &self.cfg.kill {
            k.check().map_err(|_| EgressError::Aborted)?;
        }
        let work = tokio::time::timeout(self.cfg.limits.total_timeout, self.send_inner(req));
        match &self.cfg.kill {
            Some(k) => {
                tokio::select! {
                    r = work => r.map_err(|_| EgressError::Timeout("total"))?,
                    () = k.tripped() => Err(EgressError::Aborted),
                }
            }
            None => work.await.map_err(|_| EgressError::Timeout("total"))?,
        }
    }

    async fn send_inner(&self, req: Request) -> Result<Response, EgressError> {
        if req.body.len() > self.cfg.limits.max_request_bytes {
            return Err(EgressError::InvalidRequest(format!(
                "request body larger than {} bytes",
                self.cfg.limits.max_request_bytes
            )));
        }
        if !matches!(
            req.method,
            Method::GET
                | Method::HEAD
                | Method::POST
                | Method::PUT
                | Method::DELETE
                | Method::PATCH
                | Method::OPTIONS
        ) {
            return Err(EgressError::InvalidRequest(format!(
                "method {} is not allowed",
                req.method
            )));
        }
        let mut headers = Vec::with_capacity(req.headers.len());
        for (k, v) in &req.headers {
            let lower = k.to_ascii_lowercase();
            if FORBIDDEN_REQUEST_HEADERS.contains(&lower.as_str()) {
                return Err(EgressError::InvalidRequest(format!(
                    "header `{k}` is set by the client"
                )));
            }
            HeaderName::from_bytes(lower.as_bytes())
                .map_err(|_| EgressError::InvalidRequest(format!("bad header name `{k}`")))?;
            HeaderValue::from_str(v)
                .map_err(|_| EgressError::InvalidRequest(format!("bad value for header `{k}`")))?;
            headers.push((lower, v.clone()));
        }
        let mut url = match parse_url(&req.url) {
            Ok(u) => u,
            Err(e) => {
                self.cfg.deny.record(
                    "(invalid url)",
                    &format!("invalid_url:{e}"),
                    &self.cfg.caller,
                    self.gate.class(),
                );
                return Err(EgressError::InvalidUrl(e));
            }
        };
        let mut method = req.method.clone();
        let mut body = req.body.clone();
        let mut followed = 0u8;
        loop {
            let dest = url.display_no_query();
            self.gate
                .check_url(&url)
                .map_err(|r| self.deny(&url.display_origin(), &r))?;
            let addrs = self.resolve_validated(&url).await?;
            let resp = self
                .exchange(&url, &addrs, &method, &headers, &body)
                .await?;
            let is_redirect = matches!(resp.status, 301 | 302 | 303 | 307 | 308);
            let location = resp
                .headers
                .iter()
                .find(|(k, _)| k == "location")
                .map(|(_, v)| v.clone());
            match (is_redirect, location) {
                (true, Some(loc)) if req.max_redirects > 0 => {
                    if followed >= req.max_redirects {
                        return Err(EgressError::TooManyRedirects);
                    }
                    let next = url.join(&loc).map_err(|e| {
                        self.cfg.deny.record(
                            &url.display_origin(),
                            &format!("invalid_redirect:{e}"),
                            &self.cfg.caller,
                            self.gate.class(),
                        );
                        EgressError::InvalidUrl(e)
                    })?;
                    if (next.host.as_str(), next.port, next.scheme)
                        != (url.host.as_str(), url.port, url.scheme)
                    {
                        if !body.is_empty() && matches!(resp.status, 307 | 308) {
                            // a 307/308 would replay the body to another origin
                            return Err(
                                self.deny(&url.display_origin(), "cross_origin_redirect_with_body")
                            );
                        }
                        headers.retain(|(k, _)| PORTABLE_HEADERS.contains(&k.as_str()));
                    }
                    if resp.status == 303
                        || (matches!(resp.status, 301 | 302)
                            && method != Method::GET
                            && method != Method::HEAD)
                    {
                        method = Method::GET;
                        body.clear();
                    }
                    url = next;
                    followed += 1;
                }
                _ => {
                    return Ok(Response {
                        status: resp.status,
                        headers: resp.headers,
                        body: resp.body,
                        url: dest,
                        redirects_followed: followed,
                    });
                }
            }
        }
    }

    /// Resolve (or take the literal), validate **every** address, and return them for connecting.
    async fn resolve_validated(&self, url: &ParsedUrl) -> Result<Vec<IpAddr>, EgressError> {
        let candidates: Vec<IpAddr> = match url.ip {
            Some(ip) => vec![ip],
            None => {
                let r = self
                    .cfg
                    .resolver
                    .resolve(&url.host)
                    .await
                    .map_err(|e| EgressError::Resolve(e.to_string()))?;
                r.addrs
            }
        };
        if candidates.is_empty() {
            return Err(EgressError::Resolve("no addresses".into()));
        }
        for ip in &candidates {
            self.gate
                .check_addr(*ip)
                .map_err(|r| self.deny(&url.display_origin(), &r))?;
        }
        Ok(candidates)
    }

    async fn exchange(
        &self,
        url: &ParsedUrl,
        addrs: &[IpAddr],
        method: &Method,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<RawResponse, EgressError> {
        let connect_timeout = self.cfg.limits.connect_timeout;
        let mut last: Option<EgressError> = None;
        let mut stream: Option<TcpStream> = None;
        for ip in addrs.iter().take(3) {
            let sa = SocketAddr::new(*ip, url.port);
            match tokio::time::timeout(connect_timeout, self.cfg.connector.connect(sa)).await {
                Ok(Ok(s)) => {
                    stream = Some(s);
                    break;
                }
                Ok(Err(e)) => last = Some(EgressError::Connect(e.to_string())),
                Err(_) => last = Some(EgressError::Timeout("connect")),
            }
        }
        let Some(stream) = stream else {
            return Err(last.unwrap_or_else(|| EgressError::Connect("no address".into())));
        };
        let _ = stream.set_nodelay(true);
        if url.scheme == Scheme::Https {
            let name = ServerName::try_from(url.host.clone())
                .map_err(|e| EgressError::Tls(format!("bad server name: {e}")))?;
            let tls = tokio::time::timeout(
                connect_timeout,
                TlsConnector::from(Arc::clone(&self.tls)).connect(name, stream),
            )
            .await
            .map_err(|_| EgressError::Timeout("connect"))?
            .map_err(|e| EgressError::Tls(e.to_string()))?;
            self.http(TokioIo::new(tls), url, method, headers, body)
                .await
        } else {
            self.http(TokioIo::new(stream), url, method, headers, body)
                .await
        }
    }

    async fn http<T>(
        &self,
        io: TokioIo<T>,
        url: &ParsedUrl,
        method: &Method,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<RawResponse, EgressError>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, conn) = http1::Builder::new()
            .max_buf_size(64 * 1024)
            .handshake::<_, Full<Bytes>>(io)
            .await
            .map_err(|e| EgressError::Http(e.to_string()))?;
        let _driver = AbortOnDrop(tokio::spawn(async move {
            let _ = conn.await;
        }));
        let mut builder = hyper::Request::builder()
            .method(method.clone())
            .uri(url.path_and_query.as_str())
            .header(http::header::HOST, url.host_header())
            .header(
                http::header::USER_AGENT,
                concat!("hdd-egress/", env!("CARGO_PKG_VERSION")),
            )
            .header(http::header::ACCEPT, "*/*")
            .header(http::header::CONNECTION, "close");
        for (k, v) in headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        let request = builder
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|e| EgressError::InvalidRequest(e.to_string()))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| EgressError::Http(e.to_string()))?;
        let status = response.status().as_u16();
        let limit = self.cfg.limits.max_response_bytes;
        let hdrs: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_owned(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        // a HEAD response carries no body, so its Content-Length is only metadata
        if *method != Method::HEAD
            && let Some(len) = hdrs
                .iter()
                .find(|(k, _)| k == "content-length")
                .and_then(|(_, v)| v.parse::<usize>().ok())
            && len > limit
        {
            return Err(EgressError::TooLarge { limit });
        }
        let mut incoming = response.into_body();
        let mut out: Vec<u8> = Vec::new();
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|e| EgressError::Http(e.to_string()))?;
            if let Some(data) = frame.data_ref() {
                if out.len().saturating_add(data.len()) > limit {
                    return Err(EgressError::TooLarge { limit });
                }
                out.extend_from_slice(data);
            }
        }
        Ok(RawResponse {
            status,
            headers: hdrs,
            body: out,
        })
    }
}

struct RawResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// The allowlist client: only destinations permitted by the profile's `egress_allowlist` are contacted.
pub struct Client {
    engine: Engine,
}

impl Client {
    /// A client for `allowlist` with default configuration (system resolver, OS trust roots).
    pub fn new(allowlist: Allowlist, caller: &str) -> Result<Self, String> {
        Client::with_config(allowlist, EgressConfig::new(caller))
    }

    /// A client with explicit configuration.
    pub fn with_config(allowlist: Allowlist, cfg: EgressConfig) -> Result<Self, String> {
        Ok(Client {
            engine: Engine::new(Gate::Allow(allowlist), cfg)?,
        })
    }

    /// Send a request.
    pub async fn send(&self, req: Request) -> Result<Response, EgressError> {
        self.engine.send(req).await
    }

    /// The deny log of this client.
    pub fn deny_log(&self) -> &DenyLog {
        &self.engine.cfg.deny
    }
}

/// The SSRF-guarded client for user-supplied URLs (webhooks, origins): public unicast only, port allowlist, no redirects
/// unless the call opts in, every address validated on every connect.
pub struct UserUrlClient {
    engine: Engine,
}

impl UserUrlClient {
    /// A client with the given policy and default configuration.
    pub fn new(policy: SsrfPolicy, caller: &str) -> Result<Self, String> {
        UserUrlClient::with_config(policy, EgressConfig::new(caller))
    }

    /// A client with explicit configuration.
    pub fn with_config(policy: SsrfPolicy, cfg: EgressConfig) -> Result<Self, String> {
        Ok(UserUrlClient {
            engine: Engine::new(Gate::UserUrl(policy), cfg)?,
        })
    }

    /// Send a request.
    pub async fn send(&self, req: Request) -> Result<Response, EgressError> {
        self.engine.send(req).await
    }

    /// The deny log of this client.
    pub fn deny_log(&self) -> &DenyLog {
        &self.engine.cfg.deny
    }
}
