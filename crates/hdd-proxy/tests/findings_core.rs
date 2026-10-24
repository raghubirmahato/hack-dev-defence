//! Integration tests for Addendum 6 (findings, confirm-vulnerability probes, export and the admin routes).
//!
//! A stub origin on an ephemeral loopback port stands in for the lab shop: `Vulnerable` mode answers the boolean-true
//! probe differently (a 303 to `/admin`) while every other probe gets the same failure page, and `Fixed` mode answers
//! every probe identically (the parameterised behaviour). The proxy runs in-process on ephemeral ports only.
//!
//! Test code may fail loudly: `unwrap`/`expect`/`panic`/indexing are allowed in integration tests only.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "integration-test code must fail loudly; production code has no unwrap/expect/panic/indexing"
)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use hdd_proxy::api::{ApiRequest, ApiResponse, EventView, Principal, Role};
use hdd_proxy::config::Config;
use hdd_proxy::server::{self, Running};
use hdd_proxy::state::{AdminAuth, AppState};

/// A unique temporary-directory suffix per test.
static COUNTER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------- the stub origin

/// How the stub origin answers the confirm probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OriginMode {
    /// A string-concatenated login: the boolean-true probe bypasses to `/admin`, everything else fails identically.
    Vulnerable,
    /// A parameterised login: every probe gets the same failure response.
    Fixed,
}

/// A stub origin that records the probes it receives.
struct StubOrigin {
    /// The bound loopback address.
    addr: SocketAddr,
    /// How many requests were received (must stay <= 4 per confirm flow).
    requests: Arc<AtomicU64>,
}

impl StubOrigin {
    /// Start the stub origin in the given mode.
    async fn start(mode: OriginMode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicU64::new(0));
        let requests_task = Arc::clone(&requests);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    continue;
                };
                let requests = Arc::clone(&requests_task);
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let requests = Arc::clone(&requests);
                        async move {
                            requests.fetch_add(1, Ordering::Relaxed);
                            let (parts, body) = request.into_parts();
                            let body = body
                                .collect()
                                .await
                                .map(|data| data.to_bytes())
                                .unwrap_or_default();
                            let text = String::from_utf8_lossy(&body);
                            let injected =
                                mode == OriginMode::Vulnerable && text.contains("%271%27%3D%271");
                            let response = if injected {
                                Response::builder()
                                    .status(303)
                                    .header("Location", "/admin")
                                    .header("content-type", "text/plain; charset=utf-8")
                                    .body(Full::new(Bytes::from_static(b"welcome admin")))
                                    .unwrap()
                            } else {
                                let _ = parts;
                                Response::builder()
                                    .status(200)
                                    .header("content-type", "text/plain; charset=utf-8")
                                    .body(Full::new(Bytes::from_static(b"invalid credentials")))
                                    .unwrap()
                            };
                            Ok::<_, std::convert::Infallible>(response)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self { addr, requests }
    }

    /// The number of requests the stub has seen.
    fn request_count(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------- the test authenticator

/// The test authenticator: owner/viewer bearer tokens through the production [`AdminAuth`] seam.
struct FakeAuth;

impl AdminAuth for FakeAuth {
    fn authenticate(&self, request: &ApiRequest) -> Option<Principal> {
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

/// A running proxy/admin pair plus the stub origin.
struct Harness {
    /// The admin listener address used by the tests.
    admin_addr: SocketAddr,
    /// The shared runtime state (findings engine).
    state: Arc<AppState>,
    /// The stub origin.
    origin: StubOrigin,
    /// The running server.
    running: Running,
    /// The temporary directory (kept for the test's lifetime).
    directory: PathBuf,
}

impl Harness {
    /// Start the stub origin, the proxy and the admin listener with one `block` site and `stack: node`.
    async fn start(mode: OriginMode) -> Self {
        let origin = StubOrigin::start(mode).await;
        let unique = format!(
            "{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let directory = std::env::temp_dir().join(format!("hdd-findings-{unique}"));
        std::fs::create_dir_all(&directory).unwrap();
        let data_dir = directory.join("data");
        let path = |value: &std::path::Path| value.display().to_string().replace('\\', "/");
        let yaml = format!(
            "listen: \"127.0.0.1:0\"\nadmin_listen: \"127.0.0.1:0\"\ndata_dir: \"{}\"\n\
             log_path: \"{}\"\nadmin_token_env: HDD_TEST_ADMIN_TOKEN\n\
             sites:\n  - host: \"demo.test\"\n    origin: \"http://127.0.0.1:{}\"\n    stack: node\n    \
             mode: block\n    strictness: balanced\n",
            path(&data_dir),
            path(&data_dir.join("events.jsonl")),
            origin.addr.port()
        );
        let config = Config::parse_str(&yaml).unwrap();
        let validated = config.validate().unwrap();
        let secrets = validated
            .resolve_secrets(|name| {
                (name == "HDD_TEST_ADMIN_TOKEN").then(|| "bootstrap-token".to_owned())
            })
            .unwrap();
        let state = AppState::new(&validated, &secrets, Arc::new(FakeAuth)).unwrap();
        let running = server::start(Arc::clone(&state), validated.listen, validated.admin_listen)
            .await
            .unwrap();
        Self {
            admin_addr: running.admin_addr,
            state,
            origin,
            running,
            directory,
        }
    }

    /// Build one synthetic blocked detector event (what the pipeline records for a blocked attack).
    fn synthetic_block_event(
        &self,
        site: &str,
        method: &str,
        path: &str,
        field: &str,
        vector: &str,
    ) -> EventView {
        EventView {
            seq: 0,
            time: hdd_proxy::util::rfc3339_now(),
            ray_id: hdd_proxy::util::new_ray_id(),
            site: site.to_owned(),
            client_ip: "127.0.0.1".to_owned(),
            method: method.to_owned(),
            path: path.to_owned(),
            action: "block".to_owned(),
            category: Some("sqli".to_owned()),
            subtype: Some("comment_breakout".to_owned()),
            rule_id: Some("H2-001".to_owned()),
            vector: Some(vector.to_owned()),
            field: Some(field.to_owned()),
            field_kind: Some("username".to_owned()),
            evidence: "admin' --".to_owned(),
            mode: "block".to_owned(),
            config_revision: self.state.revision(),
        }
    }

    /// Record one synthetic blocked detector event for a registered site (through the production record path).
    fn record_block(&self, site: &str, method: &str, path: &str, field: &str, vector: &str) {
        self.state
            .record_event(self.synthetic_block_event(site, method, path, field, vector));
    }

    /// Record one synthetic blocked event for a site that is **not** registered.
    ///
    /// Live traffic for an unknown host never reaches the data path (neutral 404), so this goes straight to the
    /// findings store: it lets the tests exercise the confirm refusal for an unregistered site.
    fn record_block_for_unregistered_site(&self, site: &str) {
        let recorded = self.state.findings.record(
            &self.synthetic_block_event(site, "POST", "/admin/login", "username", "form_body"),
            hdd_waf_core::Stack::Other,
        );
        assert!(recorded.is_some(), "the unregistered fixture finding");
    }

    /// The id of the only finding in the store.
    fn only_finding_id(&self) -> String {
        let findings = self.state.findings.list(None, None, None, 10);
        assert_eq!(findings.len(), 1, "expected exactly one finding");
        findings[0].id.clone()
    }

    /// Send an admin API request.
    async fn admin(&self, method: &str, path: &str, token: &str, body: &str) -> RawResponse {
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAuthorization: Bearer {token}\r\n",
            self.admin_addr
        );
        if !body.is_empty() {
            request.push_str("Content-Type: application/json\r\n");
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        request.push_str("\r\n");
        request.push_str(body);
        send_raw(self.admin_addr, request).await
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = &self.directory;
        let _ = &self.running;
    }
}

// ---------------------------------------------------------------- raw HTTP plumbing

/// A parsed raw HTTP response.
struct RawResponse {
    /// The status code (`0` when no response arrived).
    status: u16,
    /// The response headers.
    headers: Vec<(String, String)>,
    /// The response body.
    body: String,
}

impl RawResponse {
    /// The first value of a response header.
    fn header(&self, name: &str) -> Option<&str> {
        hdd_proxy::util::header(&self.headers, name)
    }

    /// The JSON body (or `Null` for a non-JSON response).
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

/// Write one raw request and read the whole response.
async fn send_raw(addr: SocketAddr, request: String) -> RawResponse {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut buffer = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(15), stream.read_to_end(&mut buffer)).await;
    assert!(
        read.is_ok(),
        "the admin listener did not answer within 15 s"
    );
    parse_response(&buffer)
}

/// Parse a raw HTTP/1.1 response.
fn parse_response(buffer: &[u8]) -> RawResponse {
    let text = String::from_utf8_lossy(buffer);
    let (head, body) = match text.split_once("\r\n\r\n") {
        Some(parts) => parts,
        None => (text.as_ref(), ""),
    };
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap_or_default()
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
async fn blocked_attack_creates_a_finding_through_the_pipeline() {
    let harness = Harness::start(OriginMode::Fixed).await;
    // Record the blocked event exactly as the pipeline does for a blocked form attack.
    harness.record_block("demo.test", "POST", "/admin/login", "username", "form_body");
    let response = harness
        .admin("GET", "/api/findings", "owner-token", "")
        .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let json = response.json();
    assert_eq!(
        json.get("total").and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        json.get("ai_enabled").and_then(serde_json::Value::as_bool),
        Some(false),
        "AI must be off without an ai block"
    );
    let finding = json
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .and_then(|list| list.first())
        .expect("one finding");
    assert_eq!(
        finding.get("site").and_then(serde_json::Value::as_str),
        Some("demo.test")
    );
    assert_eq!(
        finding.get("field").and_then(serde_json::Value::as_str),
        Some("username")
    );
    assert_eq!(
        finding.get("vector").and_then(serde_json::Value::as_str),
        Some("form_body")
    );
    assert_eq!(
        finding
            .get("confidence")
            .and_then(serde_json::Value::as_str),
        Some("attempt_observed")
    );
    assert_eq!(
        finding.get("stack").and_then(serde_json::Value::as_str),
        Some("node")
    );
    assert!(
        finding
            .get("detected")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|text| text.contains("/admin/login")),
        "detected must name the path: {finding}"
    );
    let remediation = finding.get("remediation").expect("remediation");
    assert!(
        remediation
            .get("steps")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|steps| steps.len() >= 3),
        "remediation steps: {remediation}"
    );
    assert_eq!(
        remediation
            .get("code_example")
            .and_then(|example| example.get("language"))
            .and_then(serde_json::Value::as_str),
        Some("javascript"),
        "the Node stack hint picks the JavaScript example: {remediation}"
    );
    assert!(
        remediation
            .get("virtual_patch_note")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|note| note.to_lowercase().contains("not a fix")),
        "the honest virtual-patch note: {remediation}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn findings_detail_filters_export_and_unknown_ids() {
    let harness = Harness::start(OriginMode::Fixed).await;
    harness.record_block("demo.test", "POST", "/admin/login", "username", "form_body");
    harness.record_block("demo.test", "POST", "/admin/login", "username", "form_body");
    let id = harness.only_finding_id();

    // Counts must reflect the two recorded events.
    let list = harness
        .admin("GET", "/api/findings?q=admin", "owner-token", "")
        .await;
    assert_eq!(list.status, 200);
    let json = list.json();
    assert_eq!(
        json.get("total").and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        json.get("findings")
            .and_then(serde_json::Value::as_array)
            .and_then(|items| items.first())
            .and_then(|item| item.get("count"))
            .and_then(serde_json::Value::as_u64),
        Some(2)
    );

    // Detail.
    let detail = harness
        .admin("GET", &format!("/api/findings/{id}"), "owner-token", "")
        .await;
    assert_eq!(detail.status, 200, "body: {}", detail.body);
    let detail_json = detail.json();
    assert_eq!(
        detail_json.get("id").and_then(serde_json::Value::as_str),
        Some(id.as_str())
    );
    assert!(detail_json.get("ai").is_some());

    // Markdown export.
    let markdown = harness
        .admin(
            "GET",
            &format!("/api/findings/{id}/export?format=markdown"),
            "owner-token",
            "",
        )
        .await;
    assert_eq!(markdown.status, 200, "body: {}", markdown.body);
    assert_eq!(
        markdown.header("content-type"),
        Some("text/markdown; charset=utf-8")
    );
    assert!(
        markdown
            .header("content-disposition")
            .is_some_and(|value| value.contains(&format!("finding-{id}.md"))),
        "attachment filename: {:?}",
        markdown.header("content-disposition")
    );
    for heading in [
        "## What was detected",
        "## What an attacker could do",
        "## How to fix",
        "## Confirm evidence",
    ] {
        assert!(markdown.body.contains(heading), "missing {heading}");
    }
    assert!(!markdown.body.contains("api_key"));

    // JSON export.
    let json_export = harness
        .admin(
            "GET",
            &format!("/api/findings/{id}/export?format=json"),
            "owner-token",
            "",
        )
        .await;
    assert_eq!(json_export.status, 200);
    assert_eq!(
        json_export.header("content-type"),
        Some("application/json; charset=utf-8")
    );
    let exported = json_export.json();
    assert_eq!(
        exported.get("id").and_then(serde_json::Value::as_str),
        Some(id.as_str())
    );

    // Unknown ids are 404 for detail, export and explain.
    for path in [
        "/api/findings/0000000000000000".to_owned(),
        "/api/findings/0000000000000000/export?format=markdown".to_owned(),
    ] {
        let response = harness.admin("GET", &path, "owner-token", "").await;
        assert_eq!(response.status, 404, "path {path}: {}", response.body);
    }
    let explain_unknown = harness
        .admin(
            "POST",
            "/api/findings/0000000000000000/explain",
            "owner-token",
            "{}",
        )
        .await;
    assert_eq!(explain_unknown.status, 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confirm_against_a_vulnerable_origin_is_confirmed_with_at_most_four_probes() {
    let harness = Harness::start(OriginMode::Vulnerable).await;
    harness.record_block("demo.test", "POST", "/admin/login", "username", "form_body");
    let id = harness.only_finding_id();
    let response = harness
        .admin(
            "POST",
            &format!("/api/findings/{id}/confirm"),
            "owner-token",
            r#"{"confirmation":"demo.test"}"#,
        )
        .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let json = response.json();
    assert_eq!(
        json.get("verdict").and_then(serde_json::Value::as_str),
        Some("confirmed_injectable"),
        "body: {}",
        response.body
    );
    assert_eq!(
        json.get("detection_skipped")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    let probes = json
        .get("probes")
        .and_then(serde_json::Value::as_array)
        .expect("probes");
    assert_eq!(probes.len(), 4, "at most (and here exactly) four probes");
    let names: Vec<&str> = probes
        .iter()
        .filter_map(|probe| probe.get("name").and_then(serde_json::Value::as_str))
        .collect();
    assert_eq!(
        names,
        vec!["baseline", "quote", "boolean_true", "boolean_false"]
    );
    assert_eq!(
        json.get("finding")
            .and_then(|finding| finding.get("confidence"))
            .and_then(serde_json::Value::as_str),
        Some("confirmed")
    );
    assert_eq!(
        harness.origin.request_count(),
        4,
        "exactly four inert probes"
    );
    assert!(
        json.get("ray_id")
            .and_then(serde_json::Value::as_str)
            .is_some()
    );

    // The finding detail now reports the confirmed confidence.
    let detail = harness
        .admin("GET", &format!("/api/findings/{id}"), "owner-token", "")
        .await;
    assert_eq!(
        detail
            .json()
            .get("confidence")
            .and_then(serde_json::Value::as_str),
        Some("confirmed")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confirm_against_a_fixed_origin_is_not_confirmed() {
    let harness = Harness::start(OriginMode::Fixed).await;
    harness.record_block("demo.test", "POST", "/admin/login", "username", "form_body");
    let id = harness.only_finding_id();
    let response = harness
        .admin(
            "POST",
            &format!("/api/findings/{id}/confirm"),
            "owner-token",
            r#"{"confirmation":"demo.test"}"#,
        )
        .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let json = response.json();
    assert_eq!(
        json.get("verdict").and_then(serde_json::Value::as_str),
        Some("not_confirmed"),
        "body: {}",
        response.body
    );
    assert_eq!(harness.origin.request_count(), 4);
    assert_eq!(
        json.get("finding")
            .and_then(|finding| finding.get("confidence"))
            .and_then(serde_json::Value::as_str),
        Some("attempt_observed"),
        "a not-confirmed probe leaves the confidence unchanged"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confirm_refusals_send_no_probes() {
    let harness = Harness::start(OriginMode::Vulnerable).await;
    harness.record_block("demo.test", "POST", "/admin/login", "username", "form_body");
    let id = harness.only_finding_id();

    // Wrong typed confirmation.
    let wrong = harness
        .admin(
            "POST",
            &format!("/api/findings/{id}/confirm"),
            "owner-token",
            r#"{"confirmation":"wrong.test"}"#,
        )
        .await;
    assert_eq!(wrong.status, 403, "body: {}", wrong.body);
    assert_eq!(
        wrong
            .json()
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(serde_json::Value::as_str),
        Some("confirmation_mismatch")
    );

    // Unknown finding id.
    let unknown = harness
        .admin(
            "POST",
            "/api/findings/0000000000000000/confirm",
            "owner-token",
            r#"{"confirmation":"demo.test"}"#,
        )
        .await;
    assert_eq!(unknown.status, 404);

    // A finding whose site is not registered.
    harness.record_block_for_unregistered_site("unregistered.test");
    let findings = harness.state.findings.list(None, None, None, 10);
    let unregistered = findings
        .iter()
        .find(|finding| finding.site == "unregistered.test")
        .expect("unregistered finding");
    let refused = harness
        .admin(
            "POST",
            &format!("/api/findings/{}/confirm", unregistered.id),
            "owner-token",
            r#"{"confirmation":"unregistered.test"}"#,
        )
        .await;
    assert_eq!(refused.status, 403, "body: {}", refused.body);
    assert_eq!(
        refused
            .json()
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(serde_json::Value::as_str),
        Some("site_not_registered")
    );

    // Viewer role cannot mutate.
    let viewer = harness
        .admin(
            "POST",
            &format!("/api/findings/{id}/confirm"),
            "viewer-token",
            r#"{"confirmation":"demo.test"}"#,
        )
        .await;
    assert_eq!(viewer.status, 403, "body: {}", viewer.body);

    assert_eq!(
        harness.origin.request_count(),
        0,
        "no refused confirm may send a probe"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confirm_refuses_a_finding_without_a_form_field() {
    let harness = Harness::start(OriginMode::Vulnerable).await;
    harness.record_block("demo.test", "GET", "/search", "q", "query");
    let id = harness.only_finding_id();
    let response = harness
        .admin(
            "POST",
            &format!("/api/findings/{id}/confirm"),
            "owner-token",
            r#"{"confirmation":"demo.test"}"#,
        )
        .await;
    assert_eq!(response.status, 400, "body: {}", response.body);
    assert_eq!(
        response
            .json()
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(serde_json::Value::as_str),
        Some("unsupported_vector")
    );
    assert_eq!(harness.origin.request_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explain_without_ai_is_disabled() {
    let harness = Harness::start(OriginMode::Fixed).await;
    harness.record_block("demo.test", "POST", "/admin/login", "username", "form_body");
    let id = harness.only_finding_id();
    let response = harness
        .admin(
            "POST",
            &format!("/api/findings/{id}/explain"),
            "owner-token",
            r#"{"language":"en"}"#,
        )
        .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let json = response.json();
    assert_eq!(
        json.get("status").and_then(serde_json::Value::as_str),
        Some("disabled"),
        "AI must be off without the configured key: {}",
        response.body
    );
    // The actionable message may name the environment variable (that is the hint), but no credential may be echoed.
    assert!(
        !response.body.contains("Bearer ") && !response.body.contains("sk-"),
        "the response must not echo a key value or an Authorization header: {}",
        response.body
    );
}
