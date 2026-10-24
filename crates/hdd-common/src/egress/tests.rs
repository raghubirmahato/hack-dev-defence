//! Integration tests of the egress clients against real local HTTP and TLS servers (T-0009 A1 to A3, A5 and the test list).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, SanType};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::allow::Allowlist;
use super::client::{Client, Connector, EgressConfig, EgressError, Limits, Request, UserUrlClient};
use super::denylog::DenyLog;
use super::killswitch::KillSwitch;
use super::resolver::BoxFuture;
use super::resolver::testutil::Scripted;
use super::ssrf::SsrfPolicy;

// ---------------------------------------------------------------------------------------------------------------------
// test servers
// ---------------------------------------------------------------------------------------------------------------------

struct Server {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

fn respond(
    path: &str,
    port: u16,
    head: &str,
) -> (u16, Vec<(String, String)>, Vec<u8>, Duration, bool) {
    let h = |k: &str, v: String| (k.to_owned(), v);
    match path.split('?').next().unwrap_or("") {
        "/ok" => (
            200,
            vec![h("content-type", "text/plain".into())],
            b"hello".to_vec(),
            Duration::ZERO,
            false,
        ),
        "/big" => (200, vec![], vec![b'x'; 10_000], Duration::ZERO, false),
        "/chunked-big" => (200, vec![], vec![b'y'; 5_000], Duration::ZERO, true),
        "/slow" => (200, vec![], b"late".to_vec(), Duration::from_secs(3), false),
        "/echo" => (200, vec![], head.as_bytes().to_vec(), Duration::ZERO, false),
        "/redir-meta" => (
            302,
            vec![h(
                "location",
                "http://169.254.169.254/latest/meta-data/".into(),
            )],
            vec![],
            Duration::ZERO,
            false,
        ),
        "/redir-rel" => (
            302,
            vec![h("location", "/ok".into())],
            vec![],
            Duration::ZERO,
            false,
        ),
        "/redir-loop" => (
            302,
            vec![h("location", "/redir-loop".into())],
            vec![],
            Duration::ZERO,
            false,
        ),
        "/redir-other" => (
            302,
            vec![h("location", format!("http://other-host.test:{port}/echo"))],
            vec![],
            Duration::ZERO,
            false,
        ),
        "/redir-echo" => (
            302,
            vec![h("location", "/echo".into())],
            vec![],
            Duration::ZERO,
            false,
        ),
        "/redir-307-other" => (
            307,
            vec![h("location", format!("http://other-host.test:{port}/echo"))],
            vec![],
            Duration::ZERO,
            false,
        ),
        "/redir-loopback" => (
            302,
            vec![h("location", format!("http://127.0.0.1:{port}/ok"))],
            vec![],
            Duration::ZERO,
            false,
        ),
        _ => (404, vec![], b"nope".to_vec(), Duration::ZERO, false),
    }
}

async fn serve_connection<S>(mut s: S, port: u16, hits: Arc<AtomicUsize>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        if buf.len() > 16 * 1024 {
            return;
        }
    }
    hits.fetch_add(1, Ordering::SeqCst);
    let head = String::from_utf8_lossy(&buf).into_owned();
    let path = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
    let (status, headers, body, delay, chunked) = respond(&path, port, &head);
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    let mut out = format!("HTTP/1.1 {status} X\r\nconnection: close\r\n");
    for (k, v) in &headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    if chunked {
        out.push_str("transfer-encoding: chunked\r\n\r\n");
        let mut bytes = out.into_bytes();
        for part in body.chunks(1000) {
            bytes.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            bytes.extend_from_slice(part);
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"0\r\n\r\n");
        let _ = s.write_all(&bytes).await;
    } else {
        out.push_str(&format!("content-length: {}\r\n\r\n", body.len()));
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&body);
        let _ = s.write_all(&bytes).await;
    }
    let _ = s.shutdown().await;
}

async fn spawn_http() -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let h2 = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(serve_connection(s, addr.port(), Arc::clone(&h2)));
        }
    });
    Server { addr, hits }
}

struct Pki {
    ca_der: Vec<u8>,
    server_config: Arc<rustls::ServerConfig>,
}

/// A throwaway CA and a leaf certificate with the given subject alternative names.
fn make_pki(sans: Vec<SanType>) -> Pki {
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca_params.self_signed(&ca_key).expect("ca");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(Vec::new()).expect("params");
    params.subject_alt_names = sans;
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let leaf = params.signed_by(&leaf_key, &issuer).expect("leaf");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .expect("server config");
    Pki {
        ca_der: ca.der().to_vec(),
        server_config: Arc::new(cfg),
    }
}

async fn spawn_https(pki: &Pki) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let h2 = Arc::clone(&hits);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&pki.server_config));
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let hits = Arc::clone(&h2);
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(s).await {
                    serve_connection(tls, addr.port(), hits).await;
                }
            });
        }
    });
    Server { addr, hits }
}

/// Maps validated public addresses to local servers and records every address the client really tried to connect to.
#[derive(Default)]
struct MapConnector {
    map: Mutex<HashMap<IpAddr, SocketAddr>>,
    attempts: Mutex<Vec<SocketAddr>>,
}

impl MapConnector {
    fn mapping(from: &str, to: SocketAddr) -> Arc<Self> {
        let c = MapConnector::default();
        c.map
            .lock()
            .expect("lock")
            .insert(from.parse().expect("ip"), to);
        Arc::new(c)
    }
    fn attempts(&self) -> Vec<SocketAddr> {
        self.attempts.lock().expect("lock").clone()
    }
}

impl Connector for MapConnector {
    fn connect<'a>(&'a self, addr: SocketAddr) -> BoxFuture<'a, io::Result<TcpStream>> {
        Box::pin(async move {
            self.attempts.lock().expect("lock").push(addr);
            let target = self
                .map
                .lock()
                .expect("lock")
                .get(&addr.ip())
                .copied()
                .unwrap_or(addr);
            TcpStream::connect(target).await
        })
    }
}

fn quiet_log() -> Arc<DenyLog> {
    Arc::new(DenyLog::new(
        Box::new(|_| {}),
        1000,
        Duration::from_secs(60),
    ))
}

fn cfg() -> EgressConfig {
    EgressConfig::new("test")
        .deny_log(quiet_log())
        .without_native_roots()
}

fn allow(entries: &[String]) -> Allowlist {
    Allowlist::parse(entries).expect("allowlist")
}

// ---------------------------------------------------------------------------------------------------------------------
// A1: denied before any socket is opened
// ---------------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a1_a_host_not_on_the_allowlist_is_denied_before_any_socket_is_opened() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let connector = Arc::new(MapConnector::default());
    let client = Client::with_config(
        allow(&["https://acme.example.org".to_owned()]),
        cfg().connector(connector.clone()),
    )
    .expect("client");
    let err = client
        .send(Request::get(format!("http://127.0.0.1:{port}/ok")))
        .await
        .expect_err("denied");
    assert!(
        matches!(&err, EgressError::Denied { reason, .. } if reason == "not_on_allowlist"),
        "{err}"
    );
    assert!(
        connector.attempts().is_empty(),
        "the connector must never be called"
    );
    let accepted = tokio::time::timeout(Duration::from_millis(300), listener.accept()).await;
    assert!(
        accepted.is_err(),
        "the listener saw no connection at all (not even a bare TCP connect)"
    );
    assert_eq!(client.deny_log().total(), 1);
    let ev = client.deny_log().recent();
    assert_eq!(ev[0].reason, "not_on_allowlist");
    assert_eq!(ev[0].caller, "test");
    assert_eq!(ev[0].class, "allowlist");
    // the deny log keeps the origin only: webhook URLs often carry their secret in the path (R-21)
    assert_eq!(ev[0].destination, format!("http://127.0.0.1:{port}/…"));
}

#[tokio::test]
async fn denied_events_never_contain_query_strings_or_credentials() {
    let client = Client::with_config(Allowlist::deny_all(), cfg()).expect("client");
    let _ = client
        .send(Request::get("https://evil.test/path?token=SECRET123"))
        .await;
    let _ = client
        .send(Request::get("https://user:pw@evil.test/"))
        .await;
    let all = client.deny_log().recent();
    assert_eq!(all.len(), 2);
    for e in all {
        assert!(
            !e.destination.contains("SECRET123") && !e.destination.contains("pw@"),
            "{e:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// allowed traffic, headers, limits
// ---------------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_allowed_request_succeeds_and_sends_the_expected_headers() {
    let srv = spawn_http().await;
    let client = Client::with_config(
        allow(&[format!("http://127.0.0.1:{}", srv.addr.port())]),
        cfg(),
    )
    .expect("client");
    let r = client
        .send(Request::get(format!(
            "http://127.0.0.1:{}/ok",
            srv.addr.port()
        )))
        .await
        .expect("response");
    assert_eq!((r.status, r.body.as_slice()), (200, &b"hello"[..]));
    assert_eq!(r.header("Content-Type"), Some("text/plain"));
    let echo = client
        .send(
            Request::get(format!("http://127.0.0.1:{}/echo", srv.addr.port()))
                .header("X-Custom", "1"),
        )
        .await
        .expect("echo");
    let text = String::from_utf8(echo.body).expect("utf8").to_lowercase();
    assert!(
        text.contains(&format!("host: 127.0.0.1:{}", srv.addr.port())),
        "{text}"
    );
    assert!(text.contains("user-agent: hdd-egress/"), "{text}");
    assert!(text.contains("x-custom: 1"), "{text}");
}

#[tokio::test]
async fn path_prefix_entries_restrict_paths() {
    let srv = spawn_http().await;
    let client = Client::with_config(
        allow(&[format!("http://127.0.0.1:{}/ok", srv.addr.port())]),
        cfg(),
    )
    .expect("client");
    assert!(
        client
            .send(Request::get(format!(
                "http://127.0.0.1:{}/ok",
                srv.addr.port()
            )))
            .await
            .is_ok()
    );
    let err = client
        .send(Request::get(format!(
            "http://127.0.0.1:{}/echo",
            srv.addr.port()
        )))
        .await
        .expect_err("denied");
    assert!(matches!(err, EgressError::Denied { .. }));
    assert_eq!(srv.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn forbidden_or_malformed_request_parts_are_rejected_before_connecting() {
    let srv = spawn_http().await;
    let client = Client::with_config(
        allow(&[format!("http://127.0.0.1:{}", srv.addr.port())]),
        cfg(),
    )
    .expect("client");
    let url = format!("http://127.0.0.1:{}/ok", srv.addr.port());
    for bad in [
        Request::get(&url).header("Host", "evil.test"),
        Request::get(&url).header("Content-Length", "5"),
        Request::get(&url).header("X-A", "b\r\nX-Injected: 1"),
        Request::get(&url).header("Bad Name", "x"),
        Request::get(&url).method(hyper::Method::TRACE),
        Request::get(&url).method(hyper::Method::CONNECT),
    ] {
        assert!(matches!(
            client.send(bad).await,
            Err(EgressError::InvalidRequest(_))
        ));
    }
    let big = Request::post(&url, vec![0u8; Limits::default().max_request_bytes + 1]);
    assert!(matches!(
        client.send(big).await,
        Err(EgressError::InvalidRequest(_))
    ));
    assert_eq!(srv.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_response_size_cap_applies_to_content_length_and_chunked_bodies() {
    let srv = spawn_http().await;
    let limits = Limits {
        max_response_bytes: 1024,
        ..Limits::default()
    };
    let client = Client::with_config(
        allow(&[format!("http://127.0.0.1:{}", srv.addr.port())]),
        cfg().limits(limits),
    )
    .expect("client");
    let big = client
        .send(Request::get(format!(
            "http://127.0.0.1:{}/big",
            srv.addr.port()
        )))
        .await
        .expect_err("too large");
    assert!(
        matches!(big, EgressError::TooLarge { limit: 1024 }),
        "{big}"
    );
    let chunked = client
        .send(Request::get(format!(
            "http://127.0.0.1:{}/chunked-big",
            srv.addr.port()
        )))
        .await
        .expect_err("too large");
    assert!(
        matches!(chunked, EgressError::TooLarge { limit: 1024 }),
        "{chunked}"
    );
    assert!(
        client
            .send(Request::get(format!(
                "http://127.0.0.1:{}/ok",
                srv.addr.port()
            )))
            .await
            .is_ok(),
        "small bodies still pass"
    );
}

#[tokio::test]
async fn the_total_timeout_cuts_off_a_slow_server() {
    let srv = spawn_http().await;
    let limits = Limits {
        total_timeout: Duration::from_millis(400),
        ..Limits::default()
    };
    let client = Client::with_config(
        allow(&[format!("http://127.0.0.1:{}", srv.addr.port())]),
        cfg().limits(limits),
    )
    .expect("client");
    let started = Instant::now();
    let err = client
        .send(Request::get(format!(
            "http://127.0.0.1:{}/slow",
            srv.addr.port()
        )))
        .await
        .expect_err("timeout");
    assert!(matches!(err, EgressError::Timeout("total")), "{err}");
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn a_closed_port_is_a_connect_error_not_a_hang() {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = l.local_addr().expect("addr").port();
    drop(l);
    let client =
        Client::with_config(allow(&[format!("http://127.0.0.1:{port}")]), cfg()).expect("client");
    let err = client
        .send(Request::get(format!("http://127.0.0.1:{port}/ok")))
        .await
        .expect_err("refused");
    assert!(matches!(err, EgressError::Connect(_)), "{err}");
}

#[tokio::test]
async fn metadata_addresses_are_unreachable_even_if_listed_on_the_allowlist() {
    let connector = Arc::new(MapConnector::default());
    let client = Client::with_config(
        allow(&["http://169.254.169.254".to_owned()]),
        cfg().connector(connector.clone()),
    )
    .expect("client");
    let err = client
        .send(Request::get("http://169.254.169.254/latest/meta-data/"))
        .await
        .expect_err("denied");
    assert!(
        matches!(&err, EgressError::Denied { reason, .. } if reason == "address_class:link_local"),
        "{err}"
    );
    assert!(connector.attempts().is_empty());
}

// ---------------------------------------------------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn tls_succeeds_with_a_trusted_certificate_and_fails_without_trust() {
    let pki = make_pki(vec![SanType::IpAddress("127.0.0.1".parse().expect("ip"))]);
    let srv = spawn_https(&pki).await;
    let entry = format!("https://127.0.0.1:{}", srv.addr.port());
    let trusting = Client::with_config(
        allow(std::slice::from_ref(&entry)),
        cfg().extra_root_der(pki.ca_der.clone()),
    )
    .expect("client");
    let r = trusting
        .send(Request::get(format!("{entry}/ok")))
        .await
        .expect("tls response");
    assert_eq!((r.status, r.body.as_slice()), (200, &b"hello"[..]));

    let untrusting =
        Client::with_config(allow(std::slice::from_ref(&entry)), cfg()).expect("client");
    let err = untrusting
        .send(Request::get(format!("{entry}/ok")))
        .await
        .expect_err("untrusted CA");
    assert!(matches!(err, EgressError::Tls(_)), "{err}");
}

#[tokio::test]
async fn tls_verification_rejects_a_certificate_for_another_name() {
    let pki = make_pki(vec![SanType::DnsName(
        "other.test".try_into().expect("dns name"),
    )]);
    let srv = spawn_https(&pki).await;
    let entry = format!("https://127.0.0.1:{}", srv.addr.port());
    let client = Client::with_config(
        allow(std::slice::from_ref(&entry)),
        cfg().extra_root_der(pki.ca_der.clone()),
    )
    .expect("client");
    let err = client
        .send(Request::get(format!("{entry}/ok")))
        .await
        .expect_err("name mismatch");
    // the error is a TLS error, not a successful response, and the connection never carried an HTTP request
    assert!(matches!(&err, EgressError::Tls(_)), "{err}");
    assert_eq!(
        srv.hits.load(Ordering::SeqCst),
        0,
        "no HTTP request was sent over the unverified connection"
    );
}

#[tokio::test]
async fn there_is_no_way_to_turn_verification_off() {
    // the public configuration has no "insecure" switch: the only trust inputs are the OS roots and explicit extra roots
    let pki = make_pki(vec![SanType::IpAddress("127.0.0.1".parse().expect("ip"))]);
    let srv = spawn_https(&pki).await;
    let entry = format!("https://127.0.0.1:{}", srv.addr.port());
    let other_pki = make_pki(vec![SanType::IpAddress("127.0.0.1".parse().expect("ip"))]);
    let client = Client::with_config(
        allow(std::slice::from_ref(&entry)),
        cfg().extra_root_der(other_pki.ca_der.clone()),
    )
    .expect("client");
    assert!(
        matches!(
            client.send(Request::get(format!("{entry}/ok"))).await,
            Err(EgressError::Tls(_))
        ),
        "a different CA must not be trusted"
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// redirects (A3)
// ---------------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a3_a_redirect_to_the_metadata_address_is_not_followed() {
    let srv = spawn_http().await;
    let entry = format!("http://127.0.0.1:{}", srv.addr.port());
    let connector = Arc::new(MapConnector::default());
    let client = Client::with_config(
        allow(std::slice::from_ref(&entry)),
        cfg().connector(connector.clone()),
    )
    .expect("client");
    // default: redirects are not followed, the 302 is returned as is
    let r = client
        .send(Request::get(format!("{entry}/redir-meta")))
        .await
        .expect("response");
    assert_eq!(r.status, 302);
    assert_eq!(r.redirects_followed, 0);
    assert_eq!(
        connector.attempts().len(),
        1,
        "only the allowed host was contacted"
    );
    // even when the caller opts in, the hop is re-validated and denied
    let err = client
        .send(Request::get(format!("{entry}/redir-meta")).follow_redirects(3))
        .await
        .expect_err("hop denied");
    assert!(
        matches!(&err, EgressError::Denied { destination, .. } if destination.starts_with("http://169.254.169.254:80")),
        "{err}"
    );
    assert!(
        connector
            .attempts()
            .iter()
            .all(|a| a.ip() != "169.254.169.254".parse::<IpAddr>().expect("ip")),
        "{:?}",
        connector.attempts()
    );
}

#[tokio::test]
async fn opted_in_redirects_are_followed_within_the_policy_and_limited() {
    let srv = spawn_http().await;
    let entry = format!("http://127.0.0.1:{}", srv.addr.port());
    let client = Client::with_config(allow(std::slice::from_ref(&entry)), cfg()).expect("client");
    let r = client
        .send(Request::get(format!("{entry}/redir-rel")).follow_redirects(2))
        .await
        .expect("followed");
    assert_eq!(
        (r.status, r.redirects_followed, r.body.as_slice()),
        (200, 1, &b"hello"[..])
    );
    let err = client
        .send(Request::get(format!("{entry}/redir-loop")).follow_redirects(3))
        .await
        .expect_err("loop");
    assert!(matches!(err, EgressError::TooManyRedirects), "{err}");
    let capped = client
        .send(Request::get(format!("{entry}/redir-loop")).follow_redirects(200))
        .await
        .expect_err("loop");
    assert!(matches!(capped, EgressError::TooManyRedirects));
}

#[tokio::test]
async fn caller_headers_are_dropped_when_a_redirect_changes_the_origin() {
    let srv = spawn_http().await;
    let port = srv.addr.port();
    let resolver = Arc::new(Scripted::new(&[(
        "other-host.test",
        vec![vec!["127.0.0.1".parse().expect("ip")]],
    )]));
    let list = allow(&[
        format!("http://127.0.0.1:{port}"),
        format!("http://other-host.test:{port}"),
    ]);
    let client = Client::with_config(list, cfg().resolver(resolver)).expect("client");
    let r = client
        .send(
            Request::get(format!("http://127.0.0.1:{port}/redir-other"))
                .header("Authorization", "Bearer SECRET")
                .header("X-Api-Key", "k-123")
                .header("Accept", "text/plain")
                .follow_redirects(2),
        )
        .await
        .expect("followed");
    let echoed = String::from_utf8(r.body).expect("utf8").to_lowercase();
    assert!(echoed.contains("host: other-host.test"), "{echoed}");
    assert!(
        !echoed.contains("authorization") && !echoed.contains("secret"),
        "credentials must not follow a cross-host redirect: {echoed}"
    );
    assert!(
        !echoed.contains("x-api-key") && !echoed.contains("k-123"),
        "API keys must not follow a cross-origin redirect: {echoed}"
    );
    assert!(
        echoed.contains("accept: text/plain"),
        "portable headers survive: {echoed}"
    );
}

#[tokio::test]
async fn headers_survive_a_same_origin_redirect_but_a_cross_origin_307_never_replays_a_body() {
    let srv = spawn_http().await;
    let port = srv.addr.port();
    let resolver = Arc::new(Scripted::new(&[(
        "other-host.test",
        vec![vec!["127.0.0.1".parse().expect("ip")]],
    )]));
    let list = allow(&[
        format!("http://127.0.0.1:{port}"),
        format!("http://other-host.test:{port}"),
    ]);
    let client = Client::with_config(list, cfg().resolver(resolver)).expect("client");
    let same = client
        .send(
            Request::get(format!("http://127.0.0.1:{port}/redir-echo"))
                .header("X-Keep", "1")
                .follow_redirects(2),
        )
        .await
        .expect("followed");
    assert!(
        String::from_utf8_lossy(&same.body)
            .to_lowercase()
            .contains("x-keep: 1"),
        "same-origin redirects keep caller headers"
    );
    let err = client
        .send(
            Request::post(
                format!("http://127.0.0.1:{port}/redir-307-other"),
                b"payload".to_vec(),
            )
            .follow_redirects(2),
        )
        .await
        .expect_err("body must not be replayed to another origin");
    assert!(
        matches!(&err, EgressError::Denied { reason, .. } if reason == "cross_origin_redirect_with_body"),
        "{err}"
    );
}

#[tokio::test]
async fn path_prefix_entries_cannot_be_escaped_with_dot_segments_or_encodings() {
    let srv = spawn_http().await;
    let port = srv.addr.port();
    let connector = Arc::new(MapConnector::default());
    let client = Client::with_config(
        allow(&[format!("http://127.0.0.1:{port}/ok")]),
        cfg().connector(connector.clone()),
    )
    .expect("client");
    for evil in [
        "/ok/../echo",
        "/ok/%2e%2e/echo",
        "/ok/%2E%2E/echo",
        "/ok/..%2fecho",
        "/ok//../echo",
        "/ok/./x",
        "/ok%2fx",
    ] {
        let err = client
            .send(Request::get(format!("http://127.0.0.1:{port}{evil}")))
            .await;
        assert!(
            matches!(err, Err(EgressError::Denied { .. })),
            "{evil}: {err:?}"
        );
    }
    // a backslash never gets that far: the URL parser refuses it outright
    assert!(matches!(
        client
            .send(Request::get(format!("http://127.0.0.1:{port}/ok/..\\echo")))
            .await,
        Err(EgressError::InvalidUrl(_))
    ));
    assert!(
        connector.attempts().is_empty(),
        "none of them reached the network"
    );
    assert!(
        client
            .send(Request::get(format!("http://127.0.0.1:{port}/ok")))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_head_request_is_not_rejected_for_the_content_length_of_the_resource() {
    let srv = spawn_http().await;
    let limits = Limits {
        max_response_bytes: 1024,
        ..Limits::default()
    };
    let client = Client::with_config(
        allow(&[format!("http://127.0.0.1:{}", srv.addr.port())]),
        cfg().limits(limits),
    )
    .expect("client");
    let r = client
        .send(Request::head(format!(
            "http://127.0.0.1:{}/big",
            srv.addr.port()
        )))
        .await
        .expect("HEAD succeeds");
    assert_eq!(r.status, 200);
    assert!(r.body.is_empty());
}

#[tokio::test]
async fn translation_prefixes_and_cloud_metadata_in_ordinary_ranges_are_unreachable_even_when_listed()
 {
    let connector = Arc::new(MapConnector::default());
    let listed = allow(&[
        "http://[64:ff9b::a9fe:a9fe]:80".to_owned(),
        "http://[2002:a9fe:a9fe::1]:80".to_owned(),
        "http://100.100.100.200:80".to_owned(),
        "http://168.63.129.16:80".to_owned(),
        "http://[::ffff:169.254.169.254]:80".to_owned(),
    ]);
    let client = Client::with_config(listed, cfg().connector(connector.clone())).expect("client");
    for url in [
        "http://[64:ff9b::a9fe:a9fe]/",
        "http://[2002:a9fe:a9fe::1]/",
        "http://100.100.100.200/",
        "http://168.63.129.16/",
        "http://[::ffff:169.254.169.254]/",
    ] {
        let err = client.send(Request::get(url)).await;
        assert!(
            matches!(err, Err(EgressError::Denied { .. })),
            "{url}: {err:?}"
        );
    }
    let user =
        UserUrlClient::with_config(SsrfPolicy::default(), cfg().connector(connector.clone()))
            .expect("client");
    for url in [
        "http://100.100.100.200/",
        "http://168.63.129.16/",
        "http://[64:ff9b::a9fe:a9fe]/",
    ] {
        assert!(
            matches!(
                user.send(Request::get(url)).await,
                Err(EgressError::Denied { .. })
            ),
            "{url}"
        );
    }
    assert!(connector.attempts().is_empty());
}

#[tokio::test]
async fn the_kill_switch_aborts_without_a_background_poller() {
    let srv = spawn_http().await;
    let dir = std::env::temp_dir().join(format!("hdd-egress-kill-np-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("stop");
    let ks = KillSwitch::new(&path, Duration::from_millis(100));
    let client = Client::with_config(
        allow(&[format!("http://127.0.0.1:{}", srv.addr.port())]),
        cfg().kill_switch(ks),
    )
    .expect("client");
    let url = format!("http://127.0.0.1:{}/slow", srv.addr.port());
    let task = tokio::spawn(async move { client.send(Request::get(url)).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let touched = Instant::now();
    std::fs::write(&path, b"stop").expect("touch");
    let result = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("returned within one second")
        .expect("task");
    assert!(matches!(result, Err(EgressError::Aborted)), "{result:?}");
    assert!(touched.elapsed() < Duration::from_secs(1));
}

// ---------------------------------------------------------------------------------------------------------------------
// SSRF-guarded client (A2) and DNS pinning
// ---------------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a2_a_name_that_resolves_public_then_loopback_is_rejected_at_connect_time() {
    let srv = spawn_http().await;
    let port = srv.addr.port();
    let public: IpAddr = "93.184.216.34".parse().expect("ip");
    let resolver = Arc::new(Scripted::new(&[(
        "rebind.test",
        vec![vec![public], vec!["127.0.0.1".parse().expect("ip")]],
    )]));
    let connector = MapConnector::mapping("93.184.216.34", srv.addr);
    let client = UserUrlClient::with_config(
        SsrfPolicy::default().with_ports(&[port]),
        cfg()
            .resolver(resolver.clone())
            .connector(connector.clone()),
    )
    .expect("client");
    let url = format!("http://rebind.test:{port}/ok");

    let first = client
        .send(Request::get(&url))
        .await
        .expect("first resolution is public: allowed");
    assert_eq!(first.status, 200);
    assert_eq!(
        connector.attempts(),
        vec![SocketAddr::new(public, port)],
        "the connection went to the validated address"
    );

    let second = client
        .send(Request::get(&url))
        .await
        .expect_err("second resolution is loopback: rejected");
    assert!(
        matches!(&second, EgressError::Denied { reason, .. } if reason == "address_class:loopback"),
        "{second}"
    );
    assert_eq!(
        connector.attempts().len(),
        1,
        "no connect was attempted for the rebound address"
    );
    assert_eq!(srv.hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        resolver.calls.lock().expect("lock").len(),
        2,
        "each request resolves again; nothing is cached or silently re-resolved within a request"
    );
}

#[tokio::test]
async fn one_bad_address_among_good_ones_rejects_the_whole_answer() {
    let port = 18080;
    let resolver = Arc::new(Scripted::new(&[(
        "mixed.test",
        vec![vec![
            "93.184.216.34".parse().expect("ip"),
            "10.0.0.5".parse().expect("ip"),
        ]],
    )]));
    let connector = Arc::new(MapConnector::default());
    let client = UserUrlClient::with_config(
        SsrfPolicy::default().with_ports(&[port]),
        cfg().resolver(resolver).connector(connector.clone()),
    )
    .expect("client");
    let err = client
        .send(Request::get(format!("http://mixed.test:{port}/")))
        .await
        .expect_err("denied");
    assert!(
        matches!(&err, EgressError::Denied { reason, .. } if reason == "address_class:private_rfc1918"),
        "{err}"
    );
    assert!(connector.attempts().is_empty());
}

#[tokio::test]
async fn the_user_url_client_refuses_literals_ports_and_tricky_hosts() {
    let connector = Arc::new(MapConnector::default());
    let client =
        UserUrlClient::with_config(SsrfPolicy::default(), cfg().connector(connector.clone()))
            .expect("client");
    let cases: [(&str, &str); 7] = [
        ("http://127.0.0.1/", "address_class:loopback"),
        ("http://[::1]/", "address_class:loopback"),
        (
            "http://169.254.169.254/latest/meta-data/",
            "address_class:link_local",
        ),
        ("http://[::ffff:127.0.0.1]/", "address_class:loopback"),
        ("http://[fd00:ec2::254]/", "address_class:metadata"),
        ("http://10.0.0.1:8080/", "address_class:private_rfc1918"),
        ("http://93.184.216.34:22/", "port:22"),
    ];
    for (url, reason) in cases {
        let err = client.send(Request::get(url)).await.expect_err(url);
        assert!(
            matches!(&err, EgressError::Denied { reason: r, .. } if r == reason),
            "{url}: {err}"
        );
    }
    for tricky in [
        "http://2130706433/",
        "http://0x7f.0.0.1/",
        "http://017700000001/",
        "http://127.1/",
        "ftp://example.com/",
        "http://user:pw@example.com/",
    ] {
        assert!(
            matches!(
                client.send(Request::get(tricky)).await,
                Err(EgressError::InvalidUrl(_))
            ),
            "{tricky}"
        );
    }
    assert!(
        connector.attempts().is_empty(),
        "nothing was dialed for any of them"
    );
}

#[tokio::test]
async fn private_origin_allowlist_lets_an_owner_reach_a_loopback_origin_but_never_metadata() {
    let srv = spawn_http().await;
    let port = srv.addr.port();
    let policy = SsrfPolicy::default()
        .with_ports(&[port, 80])
        .with_private_origin_allowlist(
            vec![
                "127.0.0.0/8".parse().expect("cidr"),
                "169.254.0.0/16".parse().expect("cidr"),
            ],
            crate::profile::types::DeploymentMode::OwnerOnly,
        )
        .expect("owner_only");
    let client = UserUrlClient::with_config(policy, cfg()).expect("client");
    assert_eq!(
        client
            .send(Request::get(format!("http://127.0.0.1:{port}/ok")))
            .await
            .expect("allowed")
            .status,
        200
    );
    assert!(matches!(
        client.send(Request::get("http://169.254.169.254/")).await,
        Err(EgressError::Denied { .. })
    ));
}

#[tokio::test]
async fn user_url_redirects_default_off_and_a_followed_redirect_to_loopback_is_denied() {
    let srv = spawn_http().await;
    let port = srv.addr.port();
    let public: IpAddr = "93.184.216.34".parse().expect("ip");
    let resolver = Arc::new(Scripted::new(&[("origin.test", vec![vec![public]])]));
    let connector = MapConnector::mapping("93.184.216.34", srv.addr);
    let client = UserUrlClient::with_config(
        SsrfPolicy::default().with_ports(&[port]),
        cfg().resolver(resolver).connector(connector.clone()),
    )
    .expect("client");
    let plain = client
        .send(Request::get(format!(
            "http://origin.test:{port}/redir-loopback"
        )))
        .await
        .expect("response");
    assert_eq!(plain.status, 302, "never followed unless asked");
    let err = client
        .send(Request::get(format!("http://origin.test:{port}/redir-loopback")).follow_redirects(2))
        .await
        .expect_err("hop denied");
    assert!(
        matches!(&err, EgressError::Denied { reason, .. } if reason == "address_class:loopback"),
        "{err}"
    );
}

// ---------------------------------------------------------------------------------------------------------------------
// kill switch in flight (A5, integration)
// ---------------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_kill_switch_aborts_a_request_in_flight_within_one_second() {
    let srv = spawn_http().await;
    let dir = std::env::temp_dir().join(format!("hdd-egress-kill-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("stop");
    let ks = KillSwitch::new(&path, Duration::from_millis(100));
    let poller = ks.spawn_poller(Duration::from_millis(50));
    let client = Client::with_config(
        allow(&[format!("http://127.0.0.1:{}", srv.addr.port())]),
        cfg().kill_switch(ks),
    )
    .expect("client");
    let url = format!("http://127.0.0.1:{}/slow", srv.addr.port());
    let task = tokio::spawn(async move { client.send(Request::get(url)).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let touched = Instant::now();
    std::fs::write(&path, b"stop").expect("touch");
    let result = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("returned within one second")
        .expect("task");
    assert!(matches!(result, Err(EgressError::Aborted)), "{result:?}");
    assert!(touched.elapsed() < Duration::from_secs(1));
    poller.abort();
    // once tripped, new requests are refused immediately
    let again = Client::with_config(
        allow(&[format!("http://127.0.0.1:{}", srv.addr.port())]),
        cfg().kill_switch(KillSwitch::new(&path, Duration::from_millis(10))),
    )
    .expect("client");
    assert!(matches!(
        again
            .send(Request::get(format!(
                "http://127.0.0.1:{}/ok",
                srv.addr.port()
            )))
            .await,
        Err(EgressError::Aborted)
    ));
}
