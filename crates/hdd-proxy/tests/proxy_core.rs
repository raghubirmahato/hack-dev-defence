//! Integration tests for the HK1 proxy data path and the core admin API.
//!
//! Every test starts a stub origin on an ephemeral loopback port and the real proxy in-process on two ephemeral
//! loopback ports, with a temporary config file and data directory. The admin authenticator is the same [`AdminAuth`]
//! seam the production binary fills with the real account store, so these tests never depend on browser state while the
//! real accounts module has its own tests (`tests/web_accounts.rs`). Requests are written as raw HTTP/1.1 so the tests
//! assert on the wire exactly as a browser or an attacker would.
//!
//! Test code may fail loudly: `unwrap`/`expect`/`panic`/indexing are allowed in integration tests only (R-01 restricts
//! them to non-test code; the library itself carries none).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "integration-test code must fail loudly; production code has no unwrap/expect/panic/indexing"
)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use hdd_proxy::api::{self, ApiRequest, ApiResponse, Principal, Role};
use hdd_proxy::config::Config;
use hdd_proxy::server::{self, Running};
use hdd_proxy::state::{AdminAuth, AppState};

/// The six mandated payloads of spec C4.1.
const MANDATED: [&str; 6] = [
    "' OR 1=1--",
    "' OR '1'='1",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' or 1=1 LIMIT 1 --",
];

/// A per-test unique counter (the test process keeps the temporary directories apart).
static COUNTER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------- the stub origin

/// One request the stub origin received (proves forwarding and header rewriting).
#[derive(Debug, Clone)]
struct Recorded {
    /// The HTTP method.
    method: String,
    /// The request path.
    path: String,
    /// The raw query string (empty when absent).
    query: String,
    /// The headers as received.
    headers: Vec<(String, String)>,
    /// The body bytes as received.
    body: Vec<u8>,
}

impl Recorded {
    /// The first value of a received header.
    fn header(&self, name: &str) -> Option<&str> {
        hdd_proxy::util::header(&self.headers, name)
    }
}

/// The configurable behavior of the stub origin.
#[derive(Debug, Clone)]
struct OriginBehavior {
    /// The status the origin answers with.
    status: u16,
    /// The body the origin answers with.
    body: String,
    /// When set, the origin answers 403 unless this header carries exactly this value (origin lockdown).
    require_header: Option<(String, String)>,
    /// Extra response headers (used to test duplicate security-header handling).
    extra_headers: Vec<(String, String)>,
}

/// A stub origin bound to an ephemeral loopback port.
struct StubOrigin {
    /// The bound address.
    addr: SocketAddr,
    /// Every request received (newest last).
    requests: Arc<Mutex<Vec<Recorded>>>,
    /// The behavior; tests change it between requests.
    behavior: Arc<Mutex<OriginBehavior>>,
}

impl StubOrigin {
    /// Start the stub origin.
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let behavior = Arc::new(Mutex::new(OriginBehavior {
            status: 200,
            body: "origin-ok".to_owned(),
            require_header: None,
            extra_headers: Vec::new(),
        }));
        let requests_task = Arc::clone(&requests);
        let behavior_task = Arc::clone(&behavior);
        tokio::spawn(async move {
            loop {
                let accepted = listener.accept().await;
                let Ok((stream, _peer)) = accepted else {
                    continue;
                };
                let requests = Arc::clone(&requests_task);
                let behavior = Arc::clone(&behavior_task);
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let requests = Arc::clone(&requests);
                        let behavior = Arc::clone(&behavior);
                        async move {
                            let (parts, body) = request.into_parts();
                            let body = body
                                .collect()
                                .await
                                .map(|data| data.to_bytes())
                                .unwrap_or_default();
                            let headers: Vec<(String, String)> = parts
                                .headers
                                .iter()
                                .map(|(name, value)| {
                                    (
                                        name.as_str().to_owned(),
                                        value.to_str().unwrap_or_default().to_owned(),
                                    )
                                })
                                .collect();
                            if let Ok(mut guard) = requests.lock() {
                                guard.push(Recorded {
                                    method: parts.method.as_str().to_owned(),
                                    path: parts.uri.path().to_owned(),
                                    query: parts.uri.query().unwrap_or_default().to_owned(),
                                    headers: headers.clone(),
                                    body: body.to_vec(),
                                });
                            }
                            let behavior = behavior.lock().map(|guard| guard.clone()).unwrap_or(
                                OriginBehavior {
                                    status: 200,
                                    body: "origin-ok".to_owned(),
                                    require_header: None,
                                    extra_headers: Vec::new(),
                                },
                            );
                            if let Some((name, expected)) = &behavior.require_header {
                                let supplied = hdd_proxy::util::header(&headers, name);
                                if supplied != Some(expected.as_str()) {
                                    return Ok::<_, std::convert::Infallible>(
                                        Response::builder()
                                            .status(403)
                                            .body(Full::new(Bytes::from_static(
                                                b"origin refused: missing or wrong origin secret header",
                                            )))
                                            .unwrap(),
                                    );
                                }
                            }
                            Ok(Response::builder()
                                .status(behavior.status)
                                .header("content-type", "text/plain; charset=utf-8")
                                .header("x-origin-marker", "stub")
                                .body(Full::new(Bytes::from(behavior.body)))
                                .unwrap())
                            .map(|mut response| {
                                for (name, value) in &behavior.extra_headers {
                                    if let (Ok(name), Ok(value)) = (
                                        hyper::header::HeaderName::from_bytes(name.as_bytes()),
                                        hyper::header::HeaderValue::from_str(value),
                                    ) {
                                        response.headers_mut().append(name, value);
                                    }
                                }
                                response
                            })
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            addr,
            requests,
            behavior,
        }
    }

    /// The requests received so far.
    fn requests(&self) -> Vec<Recorded> {
        self.requests
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// Replace the behavior for the following requests.
    fn set_behavior(&self, behavior: OriginBehavior) {
        if let Ok(mut guard) = self.behavior.lock() {
            *guard = behavior;
        }
    }
}

// ---------------------------------------------------------------- the fake authenticator

/// The test authenticator: fixed bearer tokens and one cookie identity, used only through the production
/// [`AdminAuth`] seam (the real account store is tested by `tests/web_accounts.rs`).
struct FakeAuth;

impl AdminAuth for FakeAuth {
    fn authenticate(&self, request: &ApiRequest) -> Option<Principal> {
        if hdd_proxy::util::cookie_value(&request.headers, api::SESSION_COOKIE).as_deref()
            == Some("owner-cookie")
        {
            return Some(Principal {
                user_id: "u-owner".to_owned(),
                username: "owner".to_owned(),
                role: Role::Owner,
            });
        }
        let header = hdd_proxy::util::header(&request.headers, "authorization")?;
        match header {
            "Bearer owner-token" => Some(Principal {
                user_id: "u-owner".to_owned(),
                username: "owner".to_owned(),
                role: Role::Owner,
            }),
            "Bearer viewer-token" => Some(Principal {
                user_id: "u-viewer".to_owned(),
                username: "viewer".to_owned(),
                role: Role::Viewer,
            }),
            _ => None,
        }
    }

    fn setup_required(&self) -> bool {
        false
    }

    fn handle_accounts(
        &self,
        _request: &ApiRequest,
        _principal: Option<&Principal>,
        _client_ip: &str,
        _loopback: bool,
    ) -> Option<ApiResponse> {
        None
    }
}

// ---------------------------------------------------------------- the harness

/// How one test configures its site.
#[derive(Debug, Clone)]
struct Setup {
    /// The site mode.
    mode: String,
    /// The routed host name.
    site_host: String,
    /// The trusted proxy CIDRs.
    trusted_proxies: Vec<String>,
    /// `(header name, environment variable name)` for the origin secret.
    origin_secret: Option<(String, String)>,
    /// When set, the stub origin refuses requests without this header.
    stub_require_header: Option<(String, String)>,
    /// An optional public URL for the verify probes.
    public_url: Option<String>,
    /// An optional base path appended to the origin URL (for the R1-11 review item).
    origin_base_path: Option<String>,
}

impl Setup {
    /// A setup with the given site mode and the defaults used by most tests.
    fn new(mode: &str) -> Self {
        Self {
            mode: mode.to_owned(),
            site_host: "demo.test".to_owned(),
            trusted_proxies: Vec::new(),
            origin_secret: None,
            stub_require_header: None,
            public_url: None,
            origin_base_path: None,
        }
    }
}

/// A running proxy plus stub origin plus the temporary directory (kept alive for the test).
struct Harness {
    /// The proxy listener address.
    proxy_addr: SocketAddr,
    /// The admin listener address.
    admin_addr: SocketAddr,
    /// The stub origin.
    origin: StubOrigin,
    /// The shared runtime state (counters and panic guard assertions).
    state: Arc<AppState>,
    /// The running server (dropped at the end of the test; the detached tasks die with the runtime).
    running: Running,
    /// The temporary directory, removed when the harness is dropped.
    directory: PathBuf,
    /// The data directory (for the event log assertions).
    data_dir: PathBuf,
}

impl Harness {
    /// Start the stub origin, the proxy and the admin listener.
    async fn start(setup: Setup) -> Self {
        let origin = StubOrigin::start().await;
        if let Some(require_header) = &setup.stub_require_header {
            origin.set_behavior(OriginBehavior {
                status: 200,
                body: "origin-ok".to_owned(),
                require_header: Some(require_header.clone()),
                extra_headers: Vec::new(),
            });
        }
        let unique = format!(
            "{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let directory = std::env::temp_dir().join(format!("hdd-proxy-it-{unique}"));
        std::fs::create_dir_all(&directory).unwrap();
        let data_dir = directory.join("data");
        let path = |value: &std::path::Path| value.display().to_string().replace('\\', "/");
        let mut yaml = String::new();
        yaml.push_str("listen: \"127.0.0.1:0\"\n");
        yaml.push_str("admin_listen: \"127.0.0.1:0\"\n");
        yaml.push_str(&format!("data_dir: \"{}\"\n", path(&data_dir)));
        yaml.push_str(&format!(
            "log_path: \"{}\"\n",
            path(&data_dir.join("events.jsonl"))
        ));
        yaml.push_str("admin_token_env: HDD_TEST_ADMIN_TOKEN\n");
        if setup.trusted_proxies.is_empty() {
            yaml.push_str("trusted_proxies: []\n");
        } else {
            yaml.push_str("trusted_proxies:\n");
            for cidr in &setup.trusted_proxies {
                yaml.push_str(&format!("  - \"{cidr}\"\n"));
            }
        }
        yaml.push_str("sites:\n");
        yaml.push_str(&format!("- host: \"{}\"\n", setup.site_host));
        yaml.push_str(&format!(
            "  origin: \"http://127.0.0.1:{}{}\"\n",
            origin.addr.port(),
            setup.origin_base_path.as_deref().unwrap_or_default()
        ));
        yaml.push_str(&format!("  mode: {}\n", setup.mode));
        yaml.push_str("  strictness: balanced\n");
        yaml.push_str("  preserve_host: true\n");
        yaml.push_str("  ban:\n    enabled: true\n    ttl_ladder_seconds: [1, 2, 3]\n");
        yaml.push_str("  field_hints:\n");
        yaml.push_str("    - field: \"username\"\n      kind: username\n");
        yaml.push_str("    - field: \"password\"\n      kind: password\n");
        if let Some((header, env_name)) = &setup.origin_secret {
            yaml.push_str(&format!("  origin_secret_header: \"{header}\"\n"));
            yaml.push_str(&format!("  origin_secret_env: \"{env_name}\"\n"));
        }
        if let Some(public_url) = &setup.public_url {
            yaml.push_str(&format!("  public_url: \"{public_url}\"\n"));
        }
        let config = Config::parse_str(&yaml).unwrap();
        let validated = config.validate().unwrap();
        let secrets = validated
            .resolve_secrets(|name| match name {
                "HDD_TEST_ADMIN_TOKEN" => Some("bootstrap-token".to_owned()),
                value if value.starts_with("HDD_ORIGIN_SECRET_") => {
                    Some("origin-secret-value".to_owned())
                }
                _ => Some("origin-secret-value".to_owned()),
            })
            .unwrap();
        let state = AppState::new(&validated, &secrets, Arc::new(FakeAuth)).unwrap();
        let running = server::start(Arc::clone(&state), validated.listen, validated.admin_listen)
            .await
            .unwrap();
        Self {
            proxy_addr: running.proxy_addr,
            admin_addr: running.admin_addr,
            origin,
            state,
            running,
            directory,
            data_dir,
        }
    }

    /// Send a raw HTTP/1.1 request to the proxy listener.
    async fn proxy_raw(&self, request: String) -> RawResponse {
        send_raw(self.proxy_addr, request).await
    }

    /// GET a path through the proxy with the given `Host` and extra headers.
    async fn proxy_get(&self, host: &str, path: &str, headers: &[(&str, &str)]) -> RawResponse {
        self.proxy_raw(raw_get(host, path, headers, self.proxy_addr))
            .await
    }

    /// POST a form body through the proxy.
    async fn proxy_form(
        &self,
        host: &str,
        path: &str,
        body: &str,
        headers: &[(&str, &str)],
    ) -> RawResponse {
        self.proxy_raw(raw_post(
            host,
            path,
            headers,
            body.as_bytes(),
            "application/x-www-form-urlencoded",
            self.proxy_addr,
        ))
        .await
    }

    /// Send an admin API request.
    async fn admin(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: &str,
        headers: &[(&str, &str)],
    ) -> RawResponse {
        let mut all_headers: Vec<(&str, &str)> = Vec::new();
        if let Some(token) = token {
            all_headers.push(("Authorization", token));
        }
        all_headers.extend_from_slice(headers);
        let request = if body.is_empty() {
            raw_request(method, path, &all_headers, b"", None, self.admin_addr)
        } else {
            raw_request(
                method,
                path,
                &all_headers,
                body.as_bytes(),
                Some("application/json"),
                self.admin_addr,
            )
        };
        send_raw(self.admin_addr, request).await
    }

    /// GET an admin path as the owner (bearer token).
    async fn admin_owner(&self, path: &str) -> RawResponse {
        self.admin("GET", path, Some("Bearer owner-token"), "", &[])
            .await
    }

    /// The JSON body of an admin response.
    async fn admin_json(&self, path: &str) -> serde_json::Value {
        let response = self.admin_owner(path).await;
        assert_eq!(
            response.status, 200,
            "admin GET {path} answered {}: {}",
            response.status, response.body
        );
        serde_json::from_str(&response.body).unwrap_or(serde_json::Value::Null)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = &self.directory;
        let _ = &self.data_dir;
        let _ = &self.running;
    }
}

// ---------------------------------------------------------------- raw HTTP plumbing

/// A parsed raw HTTP response.
struct RawResponse {
    /// The status code (`0` when the connection closed without a response).
    status: u16,
    /// The response headers.
    headers: Vec<(String, String)>,
    /// The response body (lossy UTF-8).
    body: String,
}

impl RawResponse {
    /// The first value of a response header.
    fn header(&self, name: &str) -> Option<&str> {
        hdd_proxy::util::header(&self.headers, name)
    }
}

/// Build a GET request with `Connection: close`.
fn raw_get(host: &str, path: &str, headers: &[(&str, &str)], addr: SocketAddr) -> String {
    raw_request("GET", path, headers, b"", None, addr).replacen(
        &format!("Host: {addr}"),
        &format!("Host: {host}"),
        1,
    )
}

/// Build a POST request with a content type and body.
fn raw_post(
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    content_type: &str,
    addr: SocketAddr,
) -> String {
    raw_request("POST", path, headers, body, Some(content_type), addr).replacen(
        &format!("Host: {addr}"),
        &format!("Host: {host}"),
        1,
    )
}

/// Build a raw HTTP request. The `Host` header defaults to the listener address; the proxy helpers replace it.
fn raw_request(
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    content_type: Option<&str>,
    addr: SocketAddr,
) -> String {
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    if let Some(content_type) = content_type {
        request.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    if !body.is_empty() || method == "POST" {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body);
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Write one raw request, half-close, read the whole response.
async fn send_raw(addr: SocketAddr, request: String) -> RawResponse {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut buffer = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buffer)).await;
    match read {
        Ok(Ok(0)) => {
            panic!("the listener closed the connection without a response; sent: {request:?}")
        }
        Ok(Ok(_)) => {}
        Ok(Err(error)) => panic!(
            "reading the response failed: {error}; sent: {request:?}; partial bytes: {:?}",
            String::from_utf8_lossy(&buffer)
        ),
        Err(_) => panic!(
            "the listener did not close the response within 10 s; partial: {:?}",
            String::from_utf8_lossy(&buffer)
        ),
    }
    parse_response(&buffer)
}

/// Write one raw request and read the response, tolerating a connection reset (used for hostile-input tests where the
/// listener may answer and close before the whole body is written).
async fn send_raw_tolerant(addr: SocketAddr, request: String) -> RawResponse {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let _ = stream.write_all(request.as_bytes()).await;
    let _ = stream.shutdown().await;
    let mut buffer = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buffer)).await;
    parse_response(&buffer)
}

/// Parse a raw HTTP/1.1 response (buffered by the tests; responses never use chunked encoding here).
fn parse_response(buffer: &[u8]) -> RawResponse {
    let text = String::from_utf8_lossy(buffer);
    let (head, body) = match text.split_once("\r\n\r\n") {
        Some(parts) => parts,
        None => (text.as_ref(), ""),
    };
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        })
        .collect();
    RawResponse {
        status,
        headers,
        body: body.to_owned(),
    }
}

// ---------------------------------------------------------------- the tests

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn benign_login_post_is_forwarded_with_the_documented_headers() {
    let harness = Harness::start(Setup::new("block")).await;
    let body = "username=alice&password=correct-horse-battery";
    let response = harness
        .proxy_form("demo.test", "/login", body, &[("Accept", "text/html")])
        .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    assert!(response.body.contains("origin-ok"));
    assert!(
        response
            .header("hdd-ray-id")
            .is_some_and(hdd_proxy::util::is_ray_id),
        "every proxy response carries a Ray ID"
    );
    let received = harness.origin.requests();
    assert_eq!(received.len(), 1);
    let request = &received[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/login");
    assert_eq!(request.body, body.as_bytes());
    assert_eq!(request.header("host"), Some("demo.test"));
    assert_eq!(request.header("x-forwarded-for"), Some("127.0.0.1"));
    assert_eq!(request.header("x-forwarded-proto"), Some("http"));
    assert_eq!(request.header("x-real-ip"), Some("127.0.0.1"));
    assert!(request.header("hdd-ray-id").is_some());
    assert_eq!(
        request.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(harness.state.caught_panics(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m1_to_m6_are_blocked_in_query_and_form_and_ban_the_client() {
    for payload in MANDATED {
        for vector in ["query", "form"] {
            let harness = Harness::start(Setup::new("block")).await;
            // The detector, not an early ban, must produce this 403: the harness starts with an empty ban list and
            // this is its first request, so the inspection pipeline is the only possible source of the 403.
            let bans_before = harness.admin_json("/api/bans").await;
            assert_eq!(
                bans_before
                    .get("bans")
                    .and_then(serde_json::Value::as_array)
                    .map(Vec::len),
                Some(0),
                "a detector-block case must start from an empty ban list"
            );
            let encoded = hdd_proxy::util::percent_encode_component(payload);
            let response = if vector == "query" {
                harness
                    .proxy_get(
                        "demo.test",
                        &format!("/login?username={encoded}"),
                        &[("Accept", "text/html")],
                    )
                    .await
            } else {
                let body = format!("username={encoded}&password=whatever");
                harness
                    .proxy_form("demo.test", "/login", &body, &[("Accept", "text/html")])
                    .await
            };
            assert_eq!(
                response.status, 403,
                "payload {payload:?} in {vector} was not blocked: {}",
                response.body
            );
            let ray_id = response
                .header("hdd-ray-id")
                .expect("a blocked response carries the Ray ID header");
            assert!(
                hdd_proxy::util::is_ray_id(ray_id),
                "Ray ID `{ray_id}` does not match [0-9a-f]{{16}}-HDD1"
            );
            assert!(
                response.body.contains("Access denied"),
                "block page text missing"
            );
            assert!(
                response.body.contains(ray_id),
                "block page does not show its Ray ID"
            );
            assert!(
                harness.origin.requests().is_empty(),
                "the origin must never see a blocked request"
            );

            let events = harness.admin_json("/api/events").await;
            let list = events
                .get("events")
                .and_then(serde_json::Value::as_array)
                .expect("events array");
            assert!(
                list.iter().any(|event| {
                    event.get("action").and_then(serde_json::Value::as_str) == Some("block")
                        && event.get("category").and_then(serde_json::Value::as_str) == Some("sqli")
                        && event
                            .get("rule_id")
                            .and_then(serde_json::Value::as_str)
                            .is_some()
                }),
                "no sqli block event recorded for {payload:?} in {vector}: {events}"
            );
            let bans = harness.admin_json("/api/bans").await;
            let banned = bans
                .get("bans")
                .and_then(serde_json::Value::as_array)
                .expect("bans array");
            assert!(
                banned
                    .iter()
                    .any(|ban| ban.get("ip").and_then(serde_json::Value::as_str)
                        == Some("127.0.0.1")),
                "the client IP was not banned: {bans}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ban_is_enforced_early_and_expires_with_the_short_test_ladder() {
    let harness = Harness::start(Setup::new("block")).await;
    let attack = harness
        .proxy_get("demo.test", "/login?username=%27%20OR%201%3D1--", &[])
        .await;
    assert_eq!(attack.status, 403);
    // A following benign request is refused by the ban, before any inspection or forwarding.
    let benign = harness.proxy_get("demo.test", "/", &[]).await;
    assert_eq!(benign.status, 403, "a banned client must get 403 early");
    assert_eq!(harness.origin.requests().len(), 0);
    let mut unbanned = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let probe = harness.proxy_get("demo.test", "/", &[]).await;
        if probe.status == 200 {
            unbanned = true;
            break;
        }
    }
    assert!(
        unbanned,
        "the 1 s first-ladder ban did not expire within 5 s"
    );
    assert_eq!(
        harness.origin.requests().len(),
        1,
        "the benign request was forwarded after the ban"
    );
    let bans = harness.admin_json("/api/bans").await;
    assert_eq!(
        bans.get("bans")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn monitor_mode_forwards_the_attack_and_records_would_block() {
    let harness = Harness::start(Setup::new("monitor")).await;
    let response = harness
        .proxy_get("demo.test", "/login?username=%27%20OR%201%3D1--", &[])
        .await;
    assert_eq!(
        response.status, 200,
        "monitor mode forwards: {}",
        response.body
    );
    assert_eq!(harness.origin.requests().len(), 1);
    let events = harness.admin_json("/api/events").await;
    let list = events
        .get("events")
        .and_then(serde_json::Value::as_array)
        .expect("events array");
    assert!(
        list.iter().any(
            |event| event.get("action").and_then(serde_json::Value::as_str) == Some("would_block")
        ),
        "no would_block event: {events}"
    );
    let bans = harness.admin_json("/api/bans").await;
    assert_eq!(
        bans.get("bans")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0),
        "monitor mode creates no bans"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn off_mode_is_a_pure_pass_through_and_reports_protection_off() {
    let harness = Harness::start(Setup::new("off")).await;
    let response = harness
        .proxy_get("demo.test", "/login?username=%27%20OR%201%3D1--", &[])
        .await;
    assert_eq!(
        response.status, 200,
        "off mode forwards the attack: {}",
        response.body
    );
    assert_eq!(harness.origin.requests().len(), 1);
    let sites = harness.admin_json("/api/sites").await;
    let site = sites
        .get("sites")
        .and_then(serde_json::Value::as_array)
        .and_then(|list| list.first())
        .expect("one site");
    assert_eq!(
        site.get("mode").and_then(serde_json::Value::as_str),
        Some("off")
    );
    assert_eq!(
        site.get("protection").and_then(serde_json::Value::as_str),
        Some("off"),
        "the dashboard must show protection OFF honestly"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_mode_switch_takes_effect_on_the_next_request() {
    let harness = Harness::start(Setup::new("block")).await;
    let attack_path = "/login?username=%27%20OR%201%3D1--";

    let switched = harness
        .admin(
            "POST",
            "/api/sites/demo.test/mode",
            Some("Bearer owner-token"),
            r#"{"mode":"monitor"}"#,
            &[],
        )
        .await;
    assert_eq!(switched.status, 200, "body: {}", switched.body);
    let forwarded = harness.proxy_get("demo.test", attack_path, &[]).await;
    assert_eq!(
        forwarded.status, 200,
        "monitor takes effect on the next request"
    );

    let unconfirmed = harness
        .admin(
            "POST",
            "/api/sites/demo.test/mode",
            Some("Bearer owner-token"),
            r#"{"mode":"off"}"#,
            &[],
        )
        .await;
    assert_eq!(
        unconfirmed.status, 400,
        "off without typed confirmation must be refused"
    );
    assert!(unconfirmed.body.contains("confirm"));

    let confirmed = harness
        .admin(
            "POST",
            "/api/sites/demo.test/mode",
            Some("Bearer owner-token"),
            r#"{"mode":"off","confirm":"off"}"#,
            &[],
        )
        .await;
    assert_eq!(confirmed.status, 200, "body: {}", confirmed.body);
    let through = harness.proxy_get("demo.test", attack_path, &[]).await;
    assert_eq!(
        through.status, 200,
        "off mode takes effect on the next request"
    );

    let back = harness
        .admin(
            "POST",
            "/api/sites/demo.test/mode",
            Some("Bearer owner-token"),
            r#"{"mode":"block"}"#,
            &[],
        )
        .await;
    assert_eq!(back.status, 200);
    let blocked = harness.proxy_get("demo.test", attack_path, &[]).await;
    assert_eq!(blocked.status, 403, "block mode takes effect again");

    let log = std::fs::read_to_string(harness.data_dir.join("events.jsonl")).unwrap_or_default();
    assert!(
        log.contains("mode.change"),
        "the mode changes must be audited in the JSONL log"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_requires_credentials_rejects_viewers_and_guards_csrf() {
    let harness = Harness::start(Setup::new("block")).await;
    let anonymous = harness.admin("GET", "/api/events", None, "", &[]).await;
    assert_eq!(anonymous.status, 401);
    let bad_token = harness
        .admin("GET", "/api/events", Some("Bearer wrong-token"), "", &[])
        .await;
    assert_eq!(bad_token.status, 401);
    let viewer_read = harness
        .admin("GET", "/api/events", Some("Bearer viewer-token"), "", &[])
        .await;
    assert_eq!(viewer_read.status, 200);
    let viewer_mutation = harness
        .admin(
            "POST",
            "/api/sites/demo.test/mode",
            Some("Bearer viewer-token"),
            r#"{"mode":"monitor"}"#,
            &[],
        )
        .await;
    assert_eq!(viewer_mutation.status, 403, "viewer must not mutate");
    assert!(viewer_mutation.body.contains("viewer"));

    // Cookie-authenticated mutation without an Origin header: refused by the CSRF guard.
    let csrf_missing = harness
        .admin(
            "POST",
            "/api/sites/demo.test/mode",
            None,
            r#"{"mode":"monitor"}"#,
            &[("Cookie", &format!("{}=owner-cookie", api::SESSION_COOKIE))],
        )
        .await;
    assert_eq!(csrf_missing.status, 403, "body: {}", csrf_missing.body);
    assert!(csrf_missing.body.contains("Origin"));
    // Same mutation with a matching Origin: accepted.
    let admin_host = format!("127.0.0.1:{}", harness.admin_addr.port());
    let csrf_ok = harness
        .admin(
            "POST",
            "/api/sites/demo.test/mode",
            None,
            r#"{"mode":"monitor"}"#,
            &[
                ("Cookie", &format!("{}=owner-cookie", api::SESSION_COOKIE)),
                ("Origin", &format!("http://{admin_host}")),
            ],
        )
        .await;
    assert_eq!(csrf_ok.status, 200, "body: {}", csrf_ok.body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_slow_and_malformed_requests_do_not_crash_the_proxy() {
    let harness = Harness::start(Setup::new("block")).await;

    // Oversized body: refused honestly with 413 (the documented inspection cap), never forwarded uninspected.
    let oversized = "a".repeat(300 * 1024);
    let response = send_raw_tolerant(
        harness.proxy_addr,
        format!(
            "POST /upload HTTP/1.1\r\nHost: demo.test\r\nConnection: close\r\n\
             Content-Type: text/plain\r\nContent-Length: {}\r\n\r\n{oversized}",
            oversized.len()
        ),
    )
    .await;
    assert_eq!(response.status, 413, "body: {}", response.body);
    assert!(response.body.contains("inspection cap"));
    assert!(harness.origin.requests().is_empty());

    // Slow client: half a request line, then the connection closes; the proxy must keep serving others.
    {
        let mut stream = TcpStream::connect(harness.proxy_addr).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: demo.test\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        drop(stream);
    }

    // Malformed request line: hyper answers 400 and the listener survives.
    {
        let mut stream = TcpStream::connect(harness.proxy_addr).await.unwrap();
        let _ = stream.write_all(b"GARBAGE\r\n\r\n").await;
        let _ = stream.shutdown().await;
        let mut buffer = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut buffer)).await;
    }

    let healthy = harness.proxy_get("demo.test", "/", &[]).await;
    assert_eq!(
        healthy.status, 200,
        "the proxy still serves after hostile input"
    );
    assert_eq!(
        harness.state.caught_panics(),
        0,
        "no handler panic was reachable"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xff_spoofing_from_an_untrusted_peer_is_ignored() {
    let untrusted = Harness::start(Setup::new("block")).await;
    let response = untrusted
        .proxy_get("demo.test", "/", &[("X-Forwarded-For", "203.0.113.7")])
        .await;
    assert_eq!(response.status, 200);
    let received = untrusted.origin.requests();
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0].header("x-forwarded-for"),
        Some("127.0.0.1"),
        "an untrusted peer's X-Forwarded-For must be ignored"
    );
    // The ban follows the real socket address, not the spoofed header.
    let attack = untrusted
        .proxy_get(
            "demo.test",
            "/login?username=%27%20OR%201%3D1--",
            &[("X-Forwarded-For", "203.0.113.7")],
        )
        .await;
    assert_eq!(attack.status, 403);
    let bans = untrusted.admin_json("/api/bans").await;
    let banned = bans
        .get("bans")
        .and_then(serde_json::Value::as_array)
        .expect("bans array");
    assert_eq!(banned.len(), 1);
    assert_eq!(
        banned[0].get("ip").and_then(serde_json::Value::as_str),
        Some("127.0.0.1")
    );

    // A trusted proxy may set the client address; the rightmost untrusted hop is used.
    let mut trusted_setup = Setup::new("block");
    trusted_setup.trusted_proxies = vec!["127.0.0.1/32".to_owned()];
    let trusted = Harness::start(trusted_setup).await;
    let forwarded = trusted
        .proxy_get("demo.test", "/", &[("X-Forwarded-For", "203.0.113.9")])
        .await;
    assert_eq!(forwarded.status, 200);
    let received = trusted.origin.requests();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].header("x-forwarded-for"), Some("203.0.113.9"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn origin_secret_is_injected_and_a_client_supplied_copy_is_stripped() {
    let mut setup = Setup::new("block");
    setup.origin_secret = Some((
        "X-Origin-Secret".to_owned(),
        "HDD_TEST_ORIGIN_SECRET".to_owned(),
    ));
    let harness = Harness::start(setup).await;
    let response = harness
        .proxy_get(
            "demo.test",
            "/",
            &[("X-Origin-Secret", "stolen-by-the-client")],
        )
        .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let received = harness.origin.requests();
    assert_eq!(received.len(), 1);
    let values: Vec<&str> = received[0]
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("x-origin-secret"))
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(
        values,
        vec!["origin-secret-value"],
        "the configured secret replaces the client copy"
    );
    // The API reports only that the secret exists, never its value.
    let sites = harness.admin_json("/api/sites").await;
    assert!(!sites.to_string().contains("origin-secret-value"));
    let site = sites
        .get("sites")
        .and_then(serde_json::Value::as_array)
        .and_then(|list| list.first())
        .expect("one site");
    assert_eq!(
        site.get("origin_secret_header")
            .and_then(serde_json::Value::as_str),
        Some("X-Origin-Secret")
    );
    assert_eq!(
        site.get("origin_secret_configured")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lockdown_check_and_verify_protection_against_a_stub_that_enforces_the_header() {
    let mut setup = Setup::new("block");
    setup.site_host = "127.0.0.1".to_owned();
    setup.origin_secret = Some((
        "X-Origin-Secret".to_owned(),
        "HDD_TEST_ORIGIN_SECRET".to_owned(),
    ));
    setup.stub_require_header = Some((
        "X-Origin-Secret".to_owned(),
        "origin-secret-value".to_owned(),
    ));
    let harness = Harness::start(setup).await;

    let check = harness
        .admin(
            "POST",
            "/api/sites/127.0.0.1/lockdown-check",
            Some("Bearer owner-token"),
            "",
            &[],
        )
        .await;
    assert_eq!(check.status, 200, "body: {}", check.body);
    let check_json: serde_json::Value = serde_json::from_str(&check.body).unwrap();
    assert_eq!(
        check_json.get("result").and_then(serde_json::Value::as_str),
        Some("refused")
    );
    assert_eq!(
        check_json
            .get("protected")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    let site = harness.admin_json("/api/sites/127.0.0.1").await;
    assert_eq!(
        site.get("lockdown_verified")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        site.get("protection").and_then(serde_json::Value::as_str),
        Some("blocking_locked")
    );

    let verify = harness
        .admin(
            "POST",
            "/api/sites/127.0.0.1/verify",
            Some("Bearer owner-token"),
            r#"{"confirmation":"127.0.0.1"}"#,
            &[],
        )
        .await;
    assert_eq!(verify.status, 200, "body: {}", verify.body);
    let verify_json: serde_json::Value = serde_json::from_str(&verify.body).unwrap();
    assert_eq!(
        verify_json
            .get("protected")
            .and_then(serde_json::Value::as_bool),
        Some(true),
        "verify body: {}",
        verify.body
    );
    let ray_id = verify_json
        .get("ray_id")
        .and_then(serde_json::Value::as_str)
        .expect("a blocked probe returns its Ray ID");
    assert!(hdd_proxy::util::is_ray_id(ray_id));
    let bans = harness.admin_json("/api/bans").await;
    assert_eq!(
        bans.get("bans")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0),
        "the verify probe must not leave the proxy's own address banned: {bans}"
    );

    // A stub that does not enforce the header: the origin is reachable directly, so it is not protected (R-34).
    let reachable = Harness::start(Setup::new("block")).await;
    let check = reachable
        .admin(
            "POST",
            "/api/sites/demo.test/lockdown-check",
            Some("Bearer owner-token"),
            "",
            &[],
        )
        .await;
    let check_json: serde_json::Value = serde_json::from_str(&check.body).unwrap();
    assert_eq!(
        check_json.get("result").and_then(serde_json::Value::as_str),
        Some("reachable")
    );
    assert_eq!(
        check_json
            .get("protected")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verify_does_not_report_protection_when_the_origin_rejects_the_secret_hdd_sends() {
    let mut setup = Setup::new("block");
    setup.site_host = "127.0.0.1".to_owned();
    setup.origin_secret = Some((
        "X-Origin-Secret".to_owned(),
        "HDD_TEST_ORIGIN_SECRET".to_owned(),
    ));
    // The origin expects a different value from the one HDD sends, like a Vercel variable that was never updated.
    setup.stub_require_header = Some((
        "X-Origin-Secret".to_owned(),
        "a-different-secret-value".to_owned(),
    ));
    let harness = Harness::start(setup).await;
    let check = harness
        .admin(
            "POST",
            "/api/sites/127.0.0.1/lockdown-check",
            Some("Bearer owner-token"),
            "",
            &[],
        )
        .await;
    assert_eq!(check.status, 200, "body: {}", check.body);
    let verify = harness
        .admin(
            "POST",
            "/api/sites/127.0.0.1/verify",
            Some("Bearer owner-token"),
            r#"{"confirmation":"127.0.0.1"}"#,
            &[],
        )
        .await;
    assert_eq!(verify.status, 200, "body: {}", verify.body);
    let verify_json: serde_json::Value = serde_json::from_str(&verify.body).unwrap();
    assert_eq!(
        verify_json
            .get("protected")
            .and_then(serde_json::Value::as_bool),
        Some(false),
        "a site HDD cannot reach must not be reported as protected: {}",
        verify.body
    );
    assert!(
        verify.body.contains("rejected HDD's secret header"),
        "the failing check must name the secret mismatch: {}",
        verify.body
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verify_refuses_a_probe_target_that_is_not_the_registered_site() {
    let mut setup = Setup::new("block");
    setup.public_url = Some("http://evil.example".to_owned());
    let harness = Harness::start(setup).await;
    let response = harness
        .admin(
            "POST",
            "/api/sites/demo.test/verify",
            Some("Bearer owner-token"),
            r#"{"confirmation":"demo.test"}"#,
            &[],
        )
        .await;
    assert_eq!(response.status, 400, "body: {}", response.body);
    assert!(response.body.contains("neither the registered host"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_host_gets_a_neutral_404_without_tenant_data() {
    let harness = Harness::start(Setup::new("block")).await;
    let response = harness.proxy_get("unknown.example", "/", &[]).await;
    assert_eq!(response.status, 404);
    assert!(
        !response.body.contains("demo.test"),
        "no tenant host may leak"
    );
    assert!(harness.origin.requests().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inspect_console_and_block_preview_answer_the_documented_dtos() {
    let harness = Harness::start(Setup::new("block")).await;
    let attack = harness
        .admin(
            "POST",
            "/api/inspect",
            Some("Bearer owner-token"),
            r#"{"payload":"' OR 1=1--"}"#,
            &[],
        )
        .await;
    assert_eq!(attack.status, 200, "body: {}", attack.body);
    let attack_json: serde_json::Value = serde_json::from_str(&attack.body).unwrap();
    assert_eq!(
        attack_json
            .get("verdict")
            .and_then(|verdict| verdict.get("action"))
            .and_then(serde_json::Value::as_str),
        Some("block")
    );
    assert!(
        attack_json
            .get("normalized")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value.contains("or 1=1"))
    );
    let benign = harness
        .admin(
            "POST",
            "/api/inspect",
            Some("Bearer owner-token"),
            r#"{"payload":"O'Brien"}"#,
            &[],
        )
        .await;
    let benign_json: serde_json::Value = serde_json::from_str(&benign.body).unwrap();
    assert_eq!(
        benign_json
            .get("verdict")
            .and_then(|verdict| verdict.get("action"))
            .and_then(serde_json::Value::as_str),
        Some("allow")
    );
    let preview = harness.admin_owner("/api/block-preview").await;
    assert_eq!(preview.status, 200);
    let preview_json: serde_json::Value = serde_json::from_str(&preview.body).unwrap();
    assert!(
        preview_json
            .get("html")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|html| html.contains("Access denied"))
    );
    assert!(
        preview_json
            .get("ray_id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(hdd_proxy::util::is_ray_id)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_malformed_admin_json_body_is_a_400_not_a_panic() {
    let harness = Harness::start(Setup::new("block")).await;
    let response = harness
        .admin(
            "POST",
            "/api/sites/demo.test/mode",
            Some("Bearer owner-token"),
            "{not json",
            &[],
        )
        .await;
    assert_eq!(response.status, 400, "body: {}", response.body);
    assert_eq!(harness.state.caught_panics(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn add_site_wizard_creates_persists_and_routes_a_new_site() {
    let harness = Harness::start(Setup::new("block")).await;
    let origin_port = harness.origin.addr.port();
    let create_body = format!(
        r#"{{"host":"new.test","origin":"http://127.0.0.1:{origin_port}","mode":"monitor","connection":"dns"}}"#
    );
    let created = harness
        .admin(
            "POST",
            "/api/sites",
            Some("Bearer owner-token"),
            &create_body,
            &[],
        )
        .await;
    assert_eq!(created.status, 201, "body: {}", created.body);
    let created_json: serde_json::Value = serde_json::from_str(&created.body).unwrap();
    assert_eq!(
        created_json
            .get("site")
            .and_then(|site| site.get("host"))
            .and_then(serde_json::Value::as_str),
        Some("new.test")
    );
    assert_eq!(
        created_json
            .get("setup")
            .and_then(|setup| setup.get("method"))
            .and_then(serde_json::Value::as_str),
        Some("dns")
    );
    assert!(
        created_json
            .get("setup")
            .and_then(|setup| setup.get("steps"))
            .and_then(serde_json::Value::as_array)
            .is_some_and(|steps| !steps.is_empty()),
        "the wizard must return copy-paste steps: {}",
        created.body
    );

    // The new site survives a restart: it is persisted in the data directory.
    let persisted =
        std::fs::read_to_string(harness.data_dir.join("sites.json")).unwrap_or_default();
    assert!(
        persisted.contains("new.test"),
        "persisted sites: {persisted}"
    );

    // The new route takes effect immediately; monitor mode forwards the attack.
    let forwarded = harness
        .proxy_get("new.test", "/login?username=%27%20OR%201%3D1--", &[])
        .await;
    assert_eq!(forwarded.status, 200, "body: {}", forwarded.body);
    assert_eq!(harness.origin.requests().len(), 1);

    // Connection instructions are generated for the created site.
    let instructions = harness
        .admin_owner("/api/sites/new.test/connect/nginx")
        .await;
    assert_eq!(instructions.status, 200, "body: {}", instructions.body);
    assert!(instructions.body.contains("nginx"));

    // A duplicate host is refused.
    let duplicate = harness
        .admin(
            "POST",
            "/api/sites",
            Some("Bearer owner-token"),
            &create_body,
            &[],
        )
        .await;
    assert_eq!(duplicate.status, 409, "body: {}", duplicate.body);

    // A serverless origin cannot be added without its secret in the environment (R-03: never over the API).
    let serverless = harness
        .admin(
            "POST",
            "/api/sites",
            Some("Bearer owner-token"),
            r#"{"host":"edge.test","origin":"https://edge.example","origin_secret_header":"X-Origin-Secret"}"#,
            &[],
        )
        .await;
    assert_eq!(serverless.status, 400, "body: {}", serverless.body);
    assert!(
        serverless.body.contains("HDD_ORIGIN_SECRET_EDGE_TEST"),
        "the error must name the environment variable: {}",
        serverless.body
    );
}

// ---------------------------------------------------------------- review round 1 (task-6)

/// R1-6: a client that sends the cross-site subresource headers must still be blocked and banned; the spoofed
/// context may only lower the ladder weight, never skip the ban.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spoofed_cross_site_fetch_headers_do_not_evade_the_ban() {
    let harness = Harness::start(Setup::new("block")).await;
    let spoof = [
        ("Sec-Fetch-Site", "cross-site"),
        ("Sec-Fetch-Dest", "image"),
    ];
    let attack = harness
        .proxy_get("demo.test", "/login?username=%27%20OR%201%3D1--", &spoof)
        .await;
    assert_eq!(attack.status, 403, "body: {}", attack.body);
    let bans = harness.admin_json("/api/bans").await;
    let list = bans
        .get("bans")
        .and_then(serde_json::Value::as_array)
        .expect("bans array");
    assert_eq!(
        list.len(),
        1,
        "spoofed cross-site headers must not evade the ban: {bans}"
    );
    assert_eq!(
        list[0].get("step").and_then(serde_json::Value::as_u64),
        Some(1),
        "the cross-site context only lowers the weight, it still creates a ban"
    );
    let benign = harness.proxy_get("demo.test", "/", &[]).await;
    assert_eq!(benign.status, 403, "the ban is enforced for later requests");
    // A direct (non-spoofed) hit after an unban escalates the ladder: the spoofed hit was still counted.
    let removed = harness
        .admin(
            "POST",
            "/api/bans/127.0.0.1/delete",
            Some("Bearer owner-token"),
            "",
            &[],
        )
        .await;
    assert_eq!(removed.status, 200);
    let direct = harness
        .proxy_get("demo.test", "/login?username=%27%20OR%201%3D1--", &[])
        .await;
    assert_eq!(direct.status, 403);
    let after = harness.admin_json("/api/bans").await;
    let step = after
        .get("bans")
        .and_then(serde_json::Value::as_array)
        .and_then(|list| list.first())
        .and_then(|ban| ban.get("step"))
        .and_then(serde_json::Value::as_u64);
    assert!(
        step.unwrap_or(0) >= 2,
        "the spoofed hit must count on the ladder (weaker weight) so a direct hit escalates: {after}"
    );
}

/// R1-7: a client that stalls during the request head or the body must be cut off; the listener keeps serving.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_header_and_slow_body_clients_are_cut_off() {
    let harness = Harness::start(Setup::new("block")).await;

    // Slow header: half a request head, no blank line; the header-read timer must close the connection.
    let mut slow_head = TcpStream::connect(harness.proxy_addr).await.unwrap();
    slow_head
        .write_all(b"GET / HTTP/1.1\r\nHost: demo.test\r\n")
        .await
        .unwrap();
    let mut head_buffer = Vec::new();
    let closed = tokio::time::timeout(
        Duration::from_secs(12),
        slow_head.read_to_end(&mut head_buffer),
    )
    .await;
    assert!(
        closed.is_ok(),
        "a slow-header client was not cut off (no header-read timeout): the read timed out"
    );

    // Slow body: headers complete with Content-Length 100, only 5 bytes arrive, then silence.
    let mut slow_body = TcpStream::connect(harness.proxy_addr).await.unwrap();
    slow_body
        .write_all(
            b"POST /login HTTP/1.1\r\nHost: demo.test\r\nContent-Type: text/plain\r\nContent-Length: 100\r\n\r\nabcde",
        )
        .await
        .unwrap();
    let mut body_buffer = Vec::new();
    let answered = tokio::time::timeout(
        Duration::from_secs(12),
        slow_body.read_to_end(&mut body_buffer),
    )
    .await;
    assert!(
        answered.is_ok(),
        "a slow-body client was not cut off (no body-read deadline): the read timed out"
    );
    let response = parse_response(&body_buffer);
    assert!(
        response.status == 408 || response.status == 400,
        "a slow body should get a timeout status, got {}: {}",
        response.status,
        response.body
    );

    // The listener still serves a normal request after the two stalls.
    let healthy = harness.proxy_get("demo.test", "/", &[]).await;
    assert_eq!(healthy.status, 200, "body: {}", healthy.body);
}

/// R1-7: the concurrent connection cap must reject overflow with an opaque 503 and recover after the load drops.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_connection_cap_returns_opaque_503() {
    // Keep this equal to `hdd_proxy::state::MAX_CONNECTIONS` (asserted in the server unit tests).
    const CAP: usize = 256;
    let harness = Harness::start(Setup::new("block")).await;
    let mut held = Vec::with_capacity(CAP);
    for _ in 0..CAP {
        match TcpStream::connect(harness.proxy_addr).await {
            Ok(stream) => held.push(stream),
            Err(_) => break,
        }
    }
    assert_eq!(
        held.len(),
        CAP,
        "could not open {CAP} loopback test connections"
    );
    // Wait (bounded) for the accept loop to count every held connection, then the next one must be refused.
    let mut overflow_status = 0_u16;
    for _ in 0..200 {
        let probe = harness.proxy_get("demo.test", "/", &[]).await;
        if probe.status == 503 {
            overflow_status = 503;
            assert!(
                probe.body.contains("Service Unavailable") || probe.body.contains("busy"),
                "the 503 page must be opaque and human: {}",
                probe.body
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        overflow_status, 503,
        "the connection cap was not enforced: overflow connections were served normally"
    );
    drop(held);
    let mut recovered = false;
    for _ in 0..200 {
        if harness.proxy_get("demo.test", "/", &[]).await.status == 200 {
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        recovered,
        "the proxy did not recover after the held connections closed"
    );
}

/// R1-8: every client-supplied forwarding/rewrite header must be stripped before the origin exchange.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reserved_forwarding_headers_are_stripped() {
    let harness = Harness::start(Setup::new("block")).await;
    let reserved = [
        "Forwarded",
        "True-Client-IP",
        "CF-Connecting-IP",
        "X-Client-IP",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Forwarded-Port",
    ];
    let headers: Vec<(&str, &str)> = reserved.iter().map(|name| (*name, "spoofed")).collect();
    let response = harness.proxy_get("demo.test", "/", &headers).await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let received = harness.origin.requests();
    assert_eq!(received.len(), 1);
    for name in reserved {
        assert_eq!(
            received[0].header(name),
            None,
            "client-supplied `{name}` reached the origin"
        );
    }
    assert_eq!(received[0].header("x-forwarded-for"), Some("127.0.0.1"));
}

/// R1-9: a non-loopback admin listener needs the explicit `admin_non_loopback_ack: true`; loopback is always fine.
#[test]
fn non_loopback_admin_listener_requires_explicit_ack() {
    let base = "data_dir: \"unused\"\nlog_path: \"unused/events.jsonl\"\nadmin_token_env: TOKEN\n\
                sites:\n  - host: \"demo.test\"\n    origin: \"http://127.0.0.1:8081\"\n    mode: block\n";
    let loopback = format!("listen: \"127.0.0.1:8080\"\nadmin_listen: \"127.0.0.1:9090\"\n{base}");
    let parsed = Config::parse_str(&loopback).and_then(|config| config.validate());
    assert!(
        parsed.is_ok(),
        "a loopback admin listener must always be accepted"
    );

    let exposed = format!("listen: \"127.0.0.1:8080\"\nadmin_listen: \"0.0.0.0:9090\"\n{base}");
    let refused = Config::parse_str(&exposed).and_then(|config| config.validate());
    let message = refused.err().map(|error| error.message).unwrap_or_default();
    assert!(
        message.contains("admin_non_loopback_ack"),
        "a non-loopback admin listener must be refused with an actionable message, got: {message:?}"
    );

    let acknowledged = format!(
        "listen: \"127.0.0.1:8080\"\nadmin_listen: \"0.0.0.0:9090\"\nadmin_non_loopback_ack: true\n{base}"
    );
    let accepted = Config::parse_str(&acknowledged).and_then(|config| config.validate());
    assert!(
        accepted.is_ok(),
        "the explicit acknowledgement must allow a non-loopback admin listener: {:?}",
        accepted.err().map(|error| error.message)
    );
}

/// R1-10: monitor mode forwards an over-cap body intact and records the truncation; block mode still refuses it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn monitor_mode_forwards_oversized_bodies_and_records_truncation() {
    let cap = hdd_waf_core::INSPECT_BODY_CAP;
    let mut body = String::from("username=alice&password=");
    while body.len() <= cap + 8192 {
        body.push('a');
    }
    let harness = Harness::start(Setup::new("monitor")).await;
    let response = harness.proxy_form("demo.test", "/login", &body, &[]).await;
    assert_eq!(
        response.status, 200,
        "monitor mode must forward an over-cap body instead of refusing it: {}",
        response.body
    );
    let received = harness.origin.requests();
    assert_eq!(
        received.len(),
        1,
        "the over-cap request must reach the origin"
    );
    assert_eq!(
        received[0].body.len(),
        body.len(),
        "the forwarded body must be complete and unmodified"
    );
    let events = harness.admin_json("/api/events").await;
    let list = events
        .get("events")
        .and_then(serde_json::Value::as_array)
        .expect("events array");
    assert!(
        list.iter().any(|event| {
            event
                .get("evidence")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|evidence| {
                    evidence.contains("inspection cap") || evidence.contains("truncated")
                })
        }),
        "the over-cap monitor request must record the truncation marker: {events}"
    );

    // Block mode keeps refusing over-cap bodies (documented limitation).
    let blocked = Harness::start(Setup::new("block")).await;
    let refused = blocked.proxy_form("demo.test", "/login", &body, &[]).await;
    assert_eq!(
        refused.status, 413,
        "block mode must still refuse an over-cap body: {}",
        refused.body
    );
}

/// R1-11: the origin base path must prefix the forwarded request path (not only the lockdown probe).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn origin_base_path_is_prefixed_on_the_upstream_request() {
    let mut setup = Setup::new("block");
    setup.origin_base_path = Some("/base".to_owned());
    let harness = Harness::start(setup).await;
    let response = harness.proxy_get("demo.test", "/login?x=1", &[]).await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let received = harness.origin.requests();
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0].path, "/base/login",
        "the origin base path must prefix the upstream path"
    );
    assert_eq!(
        received[0].query, "x=1",
        "the query string must be preserved"
    );
}

/// LOW: origin-supplied copies of our security headers must not be duplicated on the response.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn origin_security_headers_are_not_duplicated_on_responses() {
    let harness = Harness::start(Setup::new("block")).await;
    harness.origin.set_behavior(OriginBehavior {
        status: 200,
        body: "origin-ok".to_owned(),
        require_header: None,
        extra_headers: vec![
            ("Server".to_owned(), "OriginServer/1.0".to_owned()),
            (
                "X-Content-Type-Options".to_owned(),
                "origin-setting".to_owned(),
            ),
            ("HDD-Ray-ID".to_owned(), "spoofed-ray-id".to_owned()),
        ],
    });
    let response = harness.proxy_get("demo.test", "/", &[]).await;
    assert_eq!(response.status, 200);
    let count = |name: &str| {
        response
            .headers
            .iter()
            .filter(|(header, _)| header.eq_ignore_ascii_case(name))
            .count()
    };
    assert_eq!(count("server"), 1, "headers: {:?}", response.headers);
    assert_eq!(count("x-content-type-options"), 1);
    assert_eq!(count("hdd-ray-id"), 1);
    assert_eq!(response.header("server"), Some("Hack-Dev-Defence"));
    assert_eq!(response.header("x-content-type-options"), Some("nosniff"));
    assert!(
        response
            .header("hdd-ray-id")
            .is_some_and(hdd_proxy::util::is_ray_id)
    );
}

/// LOW: IPv6 bans are keyed per /64, so IPv6 rotation inside the prefix does not evade the ban.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipv6_bans_are_keyed_per_64() {
    let mut setup = Setup::new("block");
    setup.trusted_proxies = vec!["127.0.0.1/32".to_owned()];
    let harness = Harness::start(setup).await;
    let attack = harness
        .proxy_get(
            "demo.test",
            "/login?username=%27%20OR%201%3D1--",
            &[("X-Forwarded-For", "2001:db8:1:2:aaaa::1")],
        )
        .await;
    assert_eq!(attack.status, 403, "body: {}", attack.body);
    let bans = harness.admin_json("/api/bans").await;
    let list = bans
        .get("bans")
        .and_then(serde_json::Value::as_array)
        .expect("bans array");
    assert_eq!(list.len(), 1);
    let key = list[0]
        .get("ip")
        .and_then(serde_json::Value::as_str)
        .expect("ban ip");
    assert!(
        key.starts_with("2001:db8:1:2"),
        "the ban key must be the IPv6 /64, got {key}"
    );
    let same_prefix = harness
        .proxy_get(
            "demo.test",
            "/",
            &[("X-Forwarded-For", "2001:db8:1:2:bbbb::9")],
        )
        .await;
    assert_eq!(
        same_prefix.status, 403,
        "another address in the banned /64 must be denied"
    );
    let other_prefix = harness
        .proxy_get(
            "demo.test",
            "/",
            &[("X-Forwarded-For", "2001:db8:1:3:aaaa::1")],
        )
        .await;
    assert_eq!(
        other_prefix.status, 200,
        "a different /64 must not be banned: {}",
        other_prefix.body
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_a_site_needs_the_typed_host_and_the_proxy_stops_serving_it() {
    let harness = Harness::start(Setup::new("block")).await;
    let before = harness.proxy_get("demo.test", "/", &[]).await;
    assert_eq!(before.status, 200, "the site is served before removal");

    let wrong = harness
        .admin(
            "POST",
            "/api/sites/demo.test/delete",
            Some("Bearer owner-token"),
            r#"{"confirm":"not-the-host"}"#,
            &[],
        )
        .await;
    assert_eq!(wrong.status, 400, "a wrong typed confirmation is refused");
    assert!(wrong.body.contains("confirmation"));
    let viewer = harness
        .admin(
            "POST",
            "/api/sites/demo.test/delete",
            Some("Bearer viewer-token"),
            r#"{"confirm":"demo.test"}"#,
            &[],
        )
        .await;
    assert_eq!(viewer.status, 403, "a viewer must not remove a site");
    let unknown = harness
        .admin(
            "POST",
            "/api/sites/ghost.test/delete",
            Some("Bearer owner-token"),
            r#"{"confirm":"ghost.test"}"#,
            &[],
        )
        .await;
    assert_eq!(unknown.status, 404, "an unknown host is a 404");
    let still_there = harness.proxy_get("demo.test", "/", &[]).await;
    assert_eq!(still_there.status, 200, "refused removals change nothing");

    let removed = harness
        .admin(
            "POST",
            "/api/sites/demo.test/delete",
            Some("Bearer owner-token"),
            r#"{"confirm":"demo.test"}"#,
            &[],
        )
        .await;
    assert_eq!(removed.status, 200, "body: {}", removed.body);
    let after = harness.proxy_get("demo.test", "/", &[]).await;
    assert_eq!(
        after.status, 404,
        "a removed site gets the neutral not-found page"
    );
    let sites = harness.admin_json("/api/sites").await;
    let listed = sites
        .get("sites")
        .and_then(serde_json::Value::as_array)
        .map_or(usize::MAX, Vec::len);
    assert_eq!(listed, 0, "the removed site is no longer listed: {sites}");
    let again = harness
        .admin(
            "POST",
            "/api/sites/demo.test/delete",
            Some("Bearer owner-token"),
            r#"{"confirm":"demo.test"}"#,
            &[],
        )
        .await;
    assert_eq!(again.status, 404, "removing twice is a 404, not a crash");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ip_can_be_unblocked_by_address_and_the_answers_are_honest() {
    let harness = Harness::start(Setup::new("block")).await;
    let attack = harness
        .proxy_get("demo.test", "/login?username=%27%20OR%201%3D1--", &[])
        .await;
    assert_eq!(attack.status, 403);
    let bans = harness.admin_json("/api/bans").await;
    let banned = bans
        .get("bans")
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len);
    assert_eq!(banned, 1, "the attack banned the sender: {bans}");
    let invalid = harness
        .admin(
            "POST",
            "/api/bans/not-an-ip/delete",
            Some("Bearer owner-token"),
            "{}",
            &[],
        )
        .await;
    assert_eq!(invalid.status, 400, "an invalid address is refused");
    let viewer = harness
        .admin(
            "POST",
            "/api/bans/127.0.0.1/delete",
            Some("Bearer viewer-token"),
            "{}",
            &[],
        )
        .await;
    assert_eq!(viewer.status, 403, "a viewer must not unblock an address");
    let unblocked = harness
        .admin(
            "POST",
            "/api/bans/127.0.0.1/delete",
            Some("Bearer owner-token"),
            "{}",
            &[],
        )
        .await;
    assert_eq!(unblocked.status, 200, "body: {}", unblocked.body);
    let not_banned = harness
        .admin(
            "POST",
            "/api/bans/127.0.0.1/delete",
            Some("Bearer owner-token"),
            "{}",
            &[],
        )
        .await;
    assert_eq!(
        not_banned.status, 404,
        "an address that is not banned is a 404"
    );
    let benign = harness.proxy_get("demo.test", "/", &[]).await;
    assert_eq!(benign.status, 200, "the unblocked client can browse again");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_add_site_wizard_can_generate_the_origin_secret_and_shows_it_only_once() {
    let harness = Harness::start(Setup::new("block")).await;
    let created = harness
        .admin(
            "POST",
            "/api/sites",
            Some("Bearer owner-token"),
            r#"{"host":"gen.example.test","origin":"https://gen-app.vercel.app","connection":"vercel","upstream_host":"gen-app.vercel.app","generate_origin_secret":true}"#,
            &[],
        )
        .await;
    assert_eq!(created.status, 201, "body: {}", created.body);
    let body: serde_json::Value = serde_json::from_str(&created.body).expect("json body");
    let secret = body
        .get("origin_secret")
        .and_then(serde_json::Value::as_str)
        .expect("the generated secret is returned once")
        .to_owned();
    assert_eq!(secret.len(), 64, "32 random bytes, hex encoded");
    assert!(secret.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(
        body.pointer("/site/origin_secret_header")
            .and_then(serde_json::Value::as_str),
        Some("X-HDD-Origin-Secret"),
        "the default header name is used"
    );
    let again = harness.admin_json("/api/sites/gen.example.test").await;
    assert!(
        !again.to_string().contains(&secret),
        "the secret is never returned again: {again}"
    );
    assert_eq!(
        again
            .get("origin_secret_configured")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    let without = harness
        .admin(
            "POST",
            "/api/sites",
            Some("Bearer owner-token"),
            r#"{"host":"plain.example.test","origin":"https://plain.vercel.app","connection":"vercel","origin_secret_header":"X-HDD-Origin-Secret"}"#,
            &[],
        )
        .await;
    assert_eq!(
        without.status, 400,
        "a header without a secret source is still refused: {}",
        without.body
    );
}

// ---------------------------------------------------------------- Addendum 7 item 1: the trusted-proxy gate host

/// A setup whose loopback peer is inside `trusted_proxies` (the reverse-proxy / front-door case).
fn trusted_setup(mode: &str) -> Setup {
    let mut setup = Setup::new(mode);
    setup.trusted_proxies = vec!["127.0.0.1/32".to_owned()];
    setup
}

/// The `site` field of every event in an `/api/events` response.
fn event_sites(events: &serde_json::Value) -> Vec<String> {
    events
        .get("events")
        .and_then(serde_json::Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|event| event.get("site").and_then(serde_json::Value::as_str))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trusted_gate_host_routes_to_the_named_site_and_is_the_event_site() {
    let harness = Harness::start(trusted_setup("block")).await;
    let response = harness
        .proxy_get("unknown.example", "/", &[("X-HDD-Gate-Host", "demo.test")])
        .await;
    assert_eq!(
        response.status, 200,
        "a trusted gate host must route even when Host is unknown: {}",
        response.body
    );
    assert!(response.body.contains("origin-ok"));
    assert_eq!(
        harness.origin.requests().len(),
        1,
        "the named site's origin must be reached"
    );
    let events = harness.admin_json("/api/events").await;
    let sites = event_sites(&events);
    assert!(
        sites.iter().any(|site| site == "demo.test"),
        "the event site must be the gate host: {events}"
    );
    assert!(
        !sites.iter().any(|site| site == "unknown.example"),
        "the ignored Host must never be recorded as the event site: {events}"
    );
    assert_eq!(harness.state.caught_panics(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn untrusted_gate_host_is_ignored_and_the_real_host_wins() {
    // No trusted_proxies: the loopback peer is untrusted, so the header can never choose the site.
    let harness = Harness::start(Setup::new("block")).await;
    let response = harness
        .proxy_get("demo.test", "/", &[("X-HDD-Gate-Host", "other.example")])
        .await;
    assert_eq!(
        response.status, 200,
        "the real Host decides for an untrusted peer: {}",
        response.body
    );
    assert!(response.body.contains("origin-ok"));
    let received = harness.origin.requests();
    assert_eq!(received.len(), 1, "the real Host site must be served");
    assert_eq!(received[0].header("host"), Some("demo.test"));
    let events = harness.admin_json("/api/events").await;
    let sites = event_sites(&events);
    assert!(
        sites.iter().any(|site| site == "demo.test"),
        "the event site is the real Host: {events}"
    );
    assert!(
        !sites.iter().any(|site| site == "other.example"),
        "an untrusted header must never become the event site: {events}"
    );
    assert_eq!(harness.state.caught_panics(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_gate_host_values_are_ignored() {
    let harness = Harness::start(trusted_setup("block")).await;
    // Every label is valid (at most 63 bytes, no leading/trailing '-'): only the 254-byte total is over the bound.
    let long_name = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62)
    );
    assert_eq!(
        long_name.len(),
        254,
        "the fixture is one byte over the bound"
    );
    let malformed = [
        "demo.test:8080",   // a port
        "http://demo.test", // a scheme
        "demo.test/evil",   // a slash / path
        "DEMO.TEST",        // uppercase
        long_name.as_str(), // 254 bytes (> 253)
        "demo_test",        // underscore
        "",                 // empty
        "-demo.test",       // a label starts with '-'
        "demo-.test",       // a label ends with '-'
        "demo..test",       // an empty label
    ];
    for value in malformed {
        let response = harness
            .proxy_get("unknown.example", "/", &[("X-HDD-Gate-Host", value)])
            .await;
        assert_eq!(
            response.status, 404,
            "malformed gate value {value:?} must be ignored, leaving the unknown Host: {}",
            response.body
        );
        assert!(
            response
                .body
                .contains("No site is configured for this host."),
            "malformed gate value {value:?} must give the neutral unknown-host page: {}",
            response.body
        );
    }
    assert!(
        harness.origin.requests().is_empty(),
        "no malformed gate value may reach an origin"
    );
    assert_eq!(harness.state.caught_panics(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gate_host_never_reaches_the_origin() {
    let harness = Harness::start(trusted_setup("block")).await;
    let response = harness
        .proxy_get("demo.test", "/", &[("X-HDD-Gate-Host", "demo.test")])
        .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let received = harness.origin.requests();
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0].header("x-hdd-gate-host"),
        None,
        "the internal routing header must be stripped before forwarding"
    );
    assert_eq!(harness.state.caught_panics(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_gate_host_gives_the_same_neutral_404_as_an_unknown_host() {
    let harness = Harness::start(trusted_setup("block")).await;
    let baseline = harness.proxy_get("unknown.example", "/", &[]).await;
    let routed = harness
        .proxy_get("demo.test", "/", &[("X-HDD-Gate-Host", "other.example")])
        .await;
    assert_eq!(baseline.status, 404);
    assert_eq!(
        routed.status, 404,
        "an unknown gate host must not fall back to the known Host: {}",
        routed.body
    );
    assert_eq!(
        routed.body, baseline.body,
        "the unknown gate host must share the neutral unknown-Host body"
    );
    assert!(
        harness.origin.requests().is_empty(),
        "an unknown gate host must not reach the origin"
    );
    assert_eq!(harness.state.caught_panics(), 0);
}

// ---------------------------------------------- Addendum 7 item 3: the front-door site creation

/// A front-door site is created through the same Add-site API: the public host is the Vercel address visitors keep
/// using and the origin must be a **second** address of the same project (the wizard refuses an origin equal to the
/// public host, server-side, so a crafted request cannot register a site that forwards to itself).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn front_door_site_creation_refuses_an_origin_equal_to_the_public_host() {
    let harness = Harness::start(Setup::new("monitor")).await;
    let same_address = r#"{"host":"hdd-demo-shop.vercel.app","origin":"https://hdd-demo-shop.vercel.app","mode":"monitor","connection":"vercel_front_door","generate_origin_secret":true}"#;
    let refused = harness
        .admin(
            "POST",
            "/api/sites",
            Some("Bearer owner-token"),
            same_address,
            &[],
        )
        .await;
    assert_eq!(
        refused.status, 400,
        "an origin equal to the public host must be refused: {}",
        refused.body
    );
    assert!(
        refused.body.to_lowercase().contains("second address"),
        "the refusal must explain the second address of the same project: {}",
        refused.body
    );
    let sites = harness.admin_json("/api/sites").await;
    let created_hosts: Vec<String> = sites
        .get("sites")
        .and_then(serde_json::Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|site| site.get("host").and_then(serde_json::Value::as_str))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !created_hosts
            .iter()
            .any(|host| host == "hdd-demo-shop.vercel.app"),
        "a refused front-door request must not create a site: {created_hosts:?}"
    );

    let second_address = r#"{"host":"hdd-demo-shop.vercel.app","origin":"https://hdd-demo-shop-2.vercel.app","mode":"monitor","connection":"vercel_front_door","generate_origin_secret":true}"#;
    let accepted = harness
        .admin(
            "POST",
            "/api/sites",
            Some("Bearer owner-token"),
            second_address,
            &[],
        )
        .await;
    assert_eq!(
        accepted.status, 201,
        "a second address of the same project must be accepted: {}",
        accepted.body
    );
    let created: serde_json::Value = serde_json::from_str(&accepted.body).unwrap_or_default();
    assert_eq!(
        created
            .get("setup")
            .and_then(|setup| setup.get("method"))
            .and_then(serde_json::Value::as_str),
        Some("vercel_front_door"),
        "the create response carries the front-door instructions"
    );
    assert!(
        created
            .get("setup")
            .and_then(|setup| setup.get("snippet"))
            .and_then(serde_json::Value::as_str)
            .is_some_and(|snippet| snippet.contains("HDD_GATE_URL")),
        "the front-door block names the HDD_GATE_URL environment variable"
    );
    assert!(
        created
            .get("origin_secret")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "the generated origin secret is returned exactly once"
    );
    // Verify probes `public_url`; a front-door site records its public (main) Vercel address there, not the origin.
    let persisted =
        std::fs::read_to_string(harness.data_dir.join("sites.json")).unwrap_or_default();
    assert!(
        persisted.contains("https://hdd-demo-shop.vercel.app"),
        "the public host must be recorded as public_url for Verify: {persisted}"
    );
    assert_eq!(harness.state.caught_panics(), 0);
}

// ------------------------------------------ Addendum 7: the front-door lockdown check

/// A front-door origin is the wrapper itself: the direct no-secret probe is forwarded to HDD, whose neutral
/// unknown-host `404` carries an HDD Ray ID. That response shows the app was not served directly, so the check counts
/// it as a refusal (R-34) and Verify can reach "protected" through the public address.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_front_door_origin_that_forwards_the_direct_probe_to_hdd_counts_as_refused() {
    let harness = Harness::start(Setup::new("block")).await;
    harness.origin.set_behavior(OriginBehavior {
        status: 404,
        body: "No site is configured for this host.".to_owned(),
        require_header: None,
        extra_headers: vec![("hdd-ray-id".to_owned(), "0123456789abcdef-HDD1".to_owned())],
    });
    let check = harness
        .admin(
            "POST",
            "/api/sites/demo.test/lockdown-check",
            Some("Bearer owner-token"),
            "",
            &[],
        )
        .await;
    assert_eq!(check.status, 200, "body: {}", check.body);
    let check_json: serde_json::Value = serde_json::from_str(&check.body).unwrap_or_default();
    assert_eq!(
        check_json.get("result").and_then(serde_json::Value::as_str),
        Some("refused"),
        "the front-door response must count as a refusal: {}",
        check.body
    );
    assert_eq!(
        check_json
            .get("protected")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert!(
        check_json
            .get("detail")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|detail| detail.contains("front-door")),
        "the detail must name the front-door path honestly: {}",
        check.body
    );
    let site = harness.admin_json("/api/sites/demo.test").await;
    assert_eq!(
        site.get("lockdown_verified")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        site.get("protection").and_then(serde_json::Value::as_str),
        Some("blocking_locked")
    );
    assert_eq!(harness.state.caught_panics(), 0);
}

/// A plain `404` without an HDD Ray ID is not evidence of a front door: it stays an error, exactly as before Addendum
/// 7, so an app whose route answers 404 is never presented as locked down.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plain_404_from_the_origin_is_still_an_error_not_a_lockdown() {
    let harness = Harness::start(Setup::new("block")).await;
    harness.origin.set_behavior(OriginBehavior {
        status: 404,
        body: "not found".to_owned(),
        require_header: None,
        extra_headers: Vec::new(),
    });
    let check = harness
        .admin(
            "POST",
            "/api/sites/demo.test/lockdown-check",
            Some("Bearer owner-token"),
            "",
            &[],
        )
        .await;
    assert_eq!(check.status, 200, "body: {}", check.body);
    let check_json: serde_json::Value = serde_json::from_str(&check.body).unwrap_or_default();
    assert_eq!(
        check_json.get("result").and_then(serde_json::Value::as_str),
        Some("error"),
        "a Ray-ID-less 404 must not count as a refusal: {}",
        check.body
    );
    assert_eq!(
        check_json
            .get("protected")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(harness.state.caught_panics(), 0);
}
