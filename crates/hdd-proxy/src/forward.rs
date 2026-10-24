//! Origin forwarding: one HTTP/1.1 connection per request over a fresh TCP connection (plain or TLS), with a 3 s
//! connect timeout and a 30 s total origin-exchange timeout, hop-by-hop header stripping, the forwarded-address headers
//! set from the *resolved* client IP (never from an untrusted `X-Forwarded-For`), `Host` preserved or rewritten per
//! site config, the optional origin secret header injected while any client-supplied copy is removed, and redirects
//! never followed.
//!
//! TLS verification is per the platform trust store (`rustls-native-certs`); there is no disable switch, so a failed
//! verification is a 502 at the caller. TLS **termination** is out of scope for HK1 (the proxy runs behind Caddy or
//! Cloudflare), but forwarding **to** an `https://` origin is in scope.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::RootCertStore;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::util::{self, BoxError, Origin, ResBody};

/// The connect timeout (spec C14/T-0208: 3 s connect timeout).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// The total origin-exchange timeout (spec C14/T-0208: 30 s read timeout).
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
/// The trusted reverse-proxy routing header: it names the site HDD must serve while the original `Host` stays
/// untouched for the origin. The pipeline consumes it for routing and it is never forwarded upstream.
pub const GATE_HOST_HEADER: &str = "x-hdd-gate-host";
/// The largest response prefix the verify/lockdown probes read (they only need the status and headers).
const PROBE_BODY_CAP: usize = 64 * 1024;

/// Why an origin exchange failed. The caller turns this into a branded 502/504 page.
#[derive(Debug, Clone)]
pub enum ForwardError {
    /// The origin could not be reached (DNS, connect, TLS handshake).
    Connect(String),
    /// The origin exchange exceeded [`TOTAL_TIMEOUT`].
    Timeout(String),
    /// The origin answered a malformed HTTP exchange.
    Protocol(String),
    /// The request could not be built (a bug in the caller, never caused by network input).
    Request(String),
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(message)
            | Self::Timeout(message)
            | Self::Protocol(message)
            | Self::Request(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ForwardError {}

/// The routed upstream target (scheme, host, port) derived from a site's origin.
#[derive(Debug, Clone)]
pub struct Upstream {
    /// Whether TLS is used.
    pub https: bool,
    /// The origin host (no brackets for IPv6).
    pub host: String,
    /// The origin port.
    pub port: u16,
}

impl Upstream {
    /// Derive the upstream from a parsed origin.
    #[must_use]
    pub fn from_origin(origin: &Origin) -> Self {
        Self {
            https: origin.https,
            host: origin.host.clone(),
            port: origin.port,
        }
    }
}

/// The response of one probe request (status and headers only; the body prefix is discarded).
#[derive(Debug, Clone)]
pub struct ProbeResponse {
    /// The status code.
    pub status: StatusCode,
    /// The response headers (order preserved).
    pub headers: Vec<(String, String)>,
}

impl ProbeResponse {
    /// The first value of a response header (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        util::header(&self.headers, name)
    }
}

/// The origin client used by the proxy data path and the lockdown/verify probes.
pub struct Forwarder {
    /// The TLS client configuration, built lazily from the platform trust store.
    tls: OnceLock<Result<Arc<ClientConfig>, String>>,
}

impl Forwarder {
    /// Create a forwarder; the TLS configuration is built on the first `https://` exchange.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tls: OnceLock::new(),
        }
    }

    /// Exchange one request with the origin.
    ///
    /// # Errors
    /// Returns a [`ForwardError`] for every failure class the caller maps to a branded 502/504 page.
    pub async fn send(
        &self,
        origin: &Origin,
        request: Request<ResBody>,
    ) -> Result<Response<hyper::body::Incoming>, ForwardError> {
        let upstream = Upstream::from_origin(origin);
        let stream = self.connect(&upstream, CONNECT_TIMEOUT).await?;
        match stream {
            Stream::Plain(tcp) => exchange(tcp, request).await,
            Stream::Tls(tcp) => exchange(*tcp, request).await,
        }
    }

    /// Send a direct probe request to the site's origin without the secret header (lockdown check, R-34).
    ///
    /// # Errors
    /// Returns a [`ForwardError`] when the origin cannot be reached or does not answer.
    pub async fn probe_origin(
        &self,
        origin: &Origin,
        host_header: &str,
        path: &str,
    ) -> Result<ProbeResponse, ForwardError> {
        let headers = vec![
            ("Host".to_owned(), host_header.to_owned()),
            ("User-Agent".to_owned(), "HDD-lockdown-check/1.0".to_owned()),
            ("Accept".to_owned(), "*/*".to_owned()),
            ("Connection".to_owned(), "close".to_owned()),
        ];
        self.probe(origin, test_path(path), headers).await
    }

    /// Send one inert probe request to an absolute `http(s)://` base URL and a request target (verify flow).
    ///
    /// # Errors
    /// Returns a [`ForwardError`] when the URL cannot be parsed, reached or answered.
    pub async fn probe_url(
        &self,
        url: &str,
        path_and_query: &str,
        headers: &[(String, String)],
    ) -> Result<ProbeResponse, ForwardError> {
        let origin = Origin::parse(url).map_err(ForwardError::Request)?;
        let mut request_headers = Vec::with_capacity(headers.len() + 3);
        request_headers.push(("Host".to_owned(), origin.authority()));
        request_headers.push(("User-Agent".to_owned(), "HDD-verify-probe/1.0".to_owned()));
        request_headers.push(("Connection".to_owned(), "close".to_owned()));
        request_headers.extend(headers.iter().cloned());
        let target = test_path(path_and_query);
        self.probe(&origin, target, request_headers).await
    }

    /// Send one GET probe and keep only the status and headers.
    async fn probe(
        &self,
        origin: &Origin,
        path: String,
        headers: Vec<(String, String)>,
    ) -> Result<ProbeResponse, ForwardError> {
        let mut builder = Request::builder()
            .method("GET")
            .uri(path)
            .header("Accept-Encoding", "identity");
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let request = builder.body(util::empty_body()).map_err(|error| {
            ForwardError::Request(format!("cannot build the probe request: {error}"))
        })?;
        let response = self.send(origin, request).await?;
        let status = response.status();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().unwrap_or("<non-utf8 header>").to_owned(),
                )
            })
            .collect();
        // Drain a bounded prefix so the connection task finishes; the probe never needs the body.
        let mut body = response.into_body();
        let mut read = 0_usize;
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => {
                    if let Some(data) = frame.data_ref() {
                        read = read.saturating_add(data.len());
                    }
                    if read >= PROBE_BODY_CAP {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        Ok(ProbeResponse { status, headers })
    }

    /// Open the TCP (and TLS) stream to one upstream with the connect timeout.
    async fn connect(
        &self,
        upstream: &Upstream,
        timeout: Duration,
    ) -> Result<Stream, ForwardError> {
        let address = format!(
            "{}:{}",
            if upstream.host.contains(':') {
                format!("[{}]", upstream.host)
            } else {
                upstream.host.clone()
            },
            upstream.port
        );
        let connect = tokio::time::timeout(timeout, TcpStream::connect(address.as_str()));
        let tcp = match connect.await {
            Err(_) => {
                return Err(ForwardError::Connect(format!(
                    "connecting to the origin {address} timed out after {timeout:?}"
                )));
            }
            Ok(Err(error)) => {
                return Err(ForwardError::Connect(format!(
                    "cannot connect to the origin {address}: {error}"
                )));
            }
            Ok(Ok(tcp)) => tcp,
        };
        let _ = tcp.set_nodelay(true);
        if !upstream.https {
            return Ok(Stream::Plain(tcp));
        }
        let config = self.tls_config()?;
        let server_name = rustls::pki_types::ServerName::try_from(upstream.host.as_str())
            .map_err(|_| {
                ForwardError::Connect(format!(
                    "origin host `{}` is not a valid TLS name",
                    upstream.host
                ))
            })?
            .to_owned();
        let tls = tokio::time::timeout(
            timeout,
            TlsConnector::from(config).connect(server_name, tcp),
        )
        .await
        .map_err(|_| {
            ForwardError::Connect(format!("TLS handshake with the origin {address} timed out"))
        })?
        .map_err(|error| {
            ForwardError::Connect(format!(
                "TLS handshake with the origin {address} failed: {error}"
            ))
        })?;
        Ok(Stream::Tls(Box::new(tls)))
    }

    /// The TLS client configuration, built once from the platform trust store.
    fn tls_config(&self) -> Result<Arc<ClientConfig>, ForwardError> {
        let result = self.tls.get_or_init(build_tls_config);
        match result {
            Ok(config) => Ok(Arc::clone(config)),
            Err(message) => Err(ForwardError::Connect(message.clone())),
        }
    }
}

impl Default for Forwarder {
    fn default() -> Self {
        Self::new()
    }
}

/// One connected stream: plain TCP or TLS over TCP. The TLS stream is boxed because it is much larger than a plain
/// socket and the enum is moved per request.
enum Stream {
    /// Plain HTTP.
    Plain(TcpStream),
    /// HTTPS over TLS.
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

/// Build the trust-store-backed TLS client configuration (no disable switch).
fn build_tls_config() -> Result<Arc<ClientConfig>, String> {
    let native = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    let mut added = 0_usize;
    for certificate in native.certs {
        if roots.add(certificate).is_ok() {
            added += 1;
        }
    }
    if added == 0 {
        return Err(
            "no trusted CA certificates were found in the platform trust store, so HTTPS origins cannot be \
             verified; HTTPS forwarding is unavailable on this host"
                .to_owned(),
        );
    }
    let provider = rustls::crypto::ring::default_provider();
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("cannot build the TLS client configuration: {error}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Run one HTTP/1.1 exchange over an established stream.
async fn exchange<S>(
    stream: S,
    request: Request<ResBody>,
) -> Result<Response<hyper::body::Incoming>, ForwardError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|error| {
            ForwardError::Protocol(format!("HTTP handshake with the origin failed: {error}"))
        })?;
    tokio::spawn(async move {
        // The connection driver ends when the origin closes; a send error is reported by the request side.
        let _ = connection.await;
    });
    match tokio::time::timeout(TOTAL_TIMEOUT, sender.send_request(request)).await {
        Err(_) => Err(ForwardError::Timeout(format!(
            "the origin did not answer within {TOTAL_TIMEOUT:?}"
        ))),
        Ok(Err(error)) => Err(ForwardError::Protocol(format!(
            "the origin exchange failed: {error}"
        ))),
        Ok(Ok(response)) => Ok(response),
    }
}

/// Build the request headers forwarded upstream.
///
/// Removes hop-by-hop headers (and the ones `Connection` names), drops every client-supplied forwarding/secret
/// header, then sets the documented upstream headers from the resolved client IP.
// The parameters are the complete upstream context (what to strip, what to set, and the resolved addressing facts);
// grouping them into a struct would only move the same list one level down for a single call site.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn upstream_headers(
    incoming: &[(String, String)],
    origin: &Origin,
    preserve_host: bool,
    upstream_host: Option<&str>,
    origin_secret: Option<(&str, &str)>,
    original_host: &str,
    client_ip: IpAddr,
    forwarded_proto: &str,
    ray_id: &str,
) -> Vec<(String, String)> {
    let mut headers = util::strip_hop_by_hop(incoming);
    headers.retain(|(name, _)| {
        !matches!(
            name.to_ascii_lowercase().as_str(),
            "host"
                | "x-forwarded-for"
                | "x-forwarded-proto"
                | "x-forwarded-host"
                | "x-real-ip"
                | "hdd-ray-id"
                // Review R1-8: client-supplied forwarding/rewrite headers are never trusted or forwarded.
                | "forwarded"
                | "true-client-ip"
                | "cf-connecting-ip"
                | "x-client-ip"
                | "x-original-url"
                | "x-rewrite-url"
                | "x-forwarded-port"
                // Addendum 7 item 1: the gate routing header is consumed by the pipeline, never forwarded upstream.
                | GATE_HOST_HEADER
                // The rebuilt request lets hyper set the framing headers from the body (review LOW).
                | "content-length"
        ) && origin_secret
            .is_none_or(|(secret_header, _)| !name.eq_ignore_ascii_case(secret_header))
    });
    let host_value = match (upstream_host, preserve_host) {
        (Some(upstream), _) => upstream.to_owned(),
        (None, true) if !original_host.trim().is_empty() => original_host.trim().to_owned(),
        (None, _) => origin.authority(),
    };
    headers.push(("Host".to_owned(), host_value));
    headers.push(("X-Forwarded-For".to_owned(), client_ip.to_string()));
    headers.push(("X-Real-IP".to_owned(), client_ip.to_string()));
    headers.push(("X-Forwarded-Proto".to_owned(), forwarded_proto.to_owned()));
    headers.push(("HDD-Ray-ID".to_owned(), ray_id.to_owned()));
    if let Some((secret_header, secret_value)) = origin_secret {
        headers.push((secret_header.to_owned(), secret_value.to_owned()));
    }
    headers
}

/// Build the upstream request from a method, request target and headers.
///
/// # Errors
/// Returns [`ForwardError::Request`] when the request line or a header value cannot be represented.
pub fn build_request(
    method: &str,
    path_and_query: &str,
    headers: Vec<(String, String)>,
    body: ResBody,
) -> Result<Request<ResBody>, ForwardError> {
    let target = if path_and_query.starts_with('/') {
        path_and_query.to_owned()
    } else {
        format!("/{path_and_query}")
    };
    let mut builder = Request::builder().method(method).uri(target);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder.body(body).map_err(|error| {
        ForwardError::Request(format!("cannot build the upstream request: {error}"))
    })
}

/// Normalise a probe path: absolute paths keep their leading slash, anything else is treated as an absolute path.
fn test_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

/// The forwarded-protocol value from an optional trusted-proxy header and the local listener scheme.
#[must_use]
pub fn forwarded_proto(
    peer: SocketAddr,
    trusted: &[util::Cidr],
    headers: &[(String, String)],
) -> String {
    if util::peer_is_trusted(peer.ip(), trusted)
        && let Some(proto) = util::header(headers, "x-forwarded-proto")
    {
        let proto = proto.trim();
        if proto.eq_ignore_ascii_case("https") || proto.eq_ignore_ascii_case("http") {
            return proto.to_ascii_lowercase();
        }
    }
    "http".to_owned()
}

/// Decode an origin response into the boxed-body type the listeners return while stripping hop-by-hop headers.
#[must_use]
pub fn prepare_response(
    response: Response<hyper::body::Incoming>,
    ray_id: &str,
) -> Response<ResBody> {
    let (parts, incoming) = response.into_parts();
    let mut headers = parts.headers;
    remove_headers(&mut headers, |name| !util::is_hop_by_hop(name.as_str()));
    sanitise_response_headers(&mut headers, ray_id);
    let mut prepared = Response::new(util::stream_body(incoming));
    *prepared.status_mut() = parts.status;
    *prepared.headers_mut() = headers;
    prepared
}

/// Remove every header whose name does not satisfy `keep` (`HeaderMap` has no `retain` in http 1.x).
fn remove_headers(headers: &mut HeaderMap, keep: impl Fn(&HeaderName) -> bool) {
    let names: Vec<HeaderName> = headers.keys().filter(|name| !keep(name)).cloned().collect();
    for name in names {
        headers.remove(&name);
    }
}

/// Replace (never duplicate) the security headers the proxy owns and strip origin identity headers.
///
/// Review LOW: the old builder path appended `Server`, `X-Content-Type-Options` and `HDD-Ray-ID`, so an origin that
/// set any of them produced duplicate values. `Server`/`X-Powered-By` are stripped per spec C14 item 5 and the three
/// proxy-owned headers are inserted exactly once.
pub(crate) fn sanitise_response_headers(headers: &mut HeaderMap, ray_id: &str) {
    let owned = [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-content-type-options",
        "hdd-ray-id",
    ];
    remove_headers(headers, |name| {
        !owned.contains(&name.as_str().to_ascii_lowercase().as_str())
    });
    headers.insert(
        hyper::header::SERVER,
        HeaderValue::from_static("Hack-Dev-Defence"),
    );
    headers.insert(
        hyper::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(value) = HeaderValue::from_str(ray_id) {
        headers.insert(HeaderName::from_static("hdd-ray-id"), value);
    }
}

/// Convert a byte body into the boxed type.
#[must_use]
pub fn bytes_body(bytes: impl Into<Bytes>) -> ResBody {
    util::full_body(bytes)
}

/// A short error summary safe to put in a log line (no body, no header value).
#[must_use]
pub fn error_summary(error: &ForwardError) -> String {
    match error {
        ForwardError::Connect(message)
        | ForwardError::Timeout(message)
        | ForwardError::Protocol(message) => util::truncate_utf8(message, 200).to_owned(),
        ForwardError::Request(_) => "request construction failed".to_owned(),
    }
}

/// Box an arbitrary error into the response-body error type (kept here so callers stay tidy).
#[must_use]
pub fn boxed(error: impl std::error::Error + Send + Sync + 'static) -> BoxError {
    Box::new(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> Origin {
        Origin::parse("http://127.0.0.1:8081").expect("origin parses")
    }

    #[test]
    fn upstream_headers_strip_client_forwarding_and_secret_copies() {
        let incoming = vec![
            ("Host".to_owned(), "demo.test".to_owned()),
            ("X-Forwarded-For".to_owned(), "203.0.113.7".to_owned()),
            ("X-Forwarded-Proto".to_owned(), "https".to_owned()),
            ("X-Origin-Secret".to_owned(), "stolen".to_owned()),
            ("Connection".to_owned(), "keep-alive".to_owned()),
            ("Accept".to_owned(), "*/*".to_owned()),
        ];
        let headers = upstream_headers(
            &incoming,
            &origin(),
            true,
            None,
            Some(("X-Origin-Secret", "the-real-secret")),
            "demo.test",
            "198.51.100.4"
                .parse()
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            "http",
            "0123456789abcdef-HDD1",
        );
        assert_eq!(util::header(&headers, "host"), Some("demo.test"));
        assert_eq!(
            util::header(&headers, "x-forwarded-for"),
            Some("198.51.100.4")
        );
        assert_eq!(util::header(&headers, "x-forwarded-proto"), Some("http"));
        assert_eq!(
            util::header(&headers, "x-origin-secret"),
            Some("the-real-secret")
        );
        assert_eq!(
            headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("x-origin-secret"))
                .count(),
            1
        );
        assert!(headers.iter().all(|(name, _)| name != "Connection"));
        assert_eq!(
            util::header(&headers, "hdd-ray-id"),
            Some("0123456789abcdef-HDD1")
        );
    }

    #[test]
    fn host_is_rewritten_to_the_origin_when_preserve_host_is_false_or_overridden() {
        let incoming = vec![("Host".to_owned(), "demo.test".to_owned())];
        let rewritten = upstream_headers(
            &incoming,
            &origin(),
            false,
            None,
            None,
            "demo.test",
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            "http",
            "0123456789abcdef-HDD1",
        );
        assert_eq!(util::header(&rewritten, "host"), Some("127.0.0.1:8081"));
        let overridden = upstream_headers(
            &incoming,
            &origin(),
            true,
            Some("app.vercel.app"),
            None,
            "demo.test",
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            "http",
            "0123456789abcdef-HDD1",
        );
        assert_eq!(util::header(&overridden, "host"), Some("app.vercel.app"));
    }

    #[test]
    fn reserved_forwarding_headers_and_client_content_length_are_dropped() {
        let reserved = [
            "Forwarded",
            "True-Client-IP",
            "CF-Connecting-IP",
            "X-Client-IP",
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-Forwarded-Port",
            "Content-Length",
        ];
        let mut incoming = vec![("Host".to_owned(), "demo.test".to_owned())];
        for name in reserved {
            incoming.push((name.to_owned(), "spoofed".to_owned()));
        }
        let headers = upstream_headers(
            &incoming,
            &origin(),
            true,
            None,
            None,
            "demo.test",
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            "http",
            "0123456789abcdef-HDD1",
        );
        for name in reserved {
            assert_eq!(
                util::header(&headers, name),
                None,
                "reserved header `{name}` must be stripped"
            );
        }
        assert_eq!(
            util::header(&headers, "x-forwarded-for"),
            Some("127.0.0.1"),
            "the resolved client IP is still set"
        );
    }

    #[test]
    fn response_security_headers_are_single_and_owned_by_the_proxy() {
        let mut headers = HeaderMap::new();
        headers.append(
            hyper::header::SERVER,
            HeaderValue::from_static("OriginServer/1.0"),
        );
        headers.append("hdd-ray-id", HeaderValue::from_static("spoofed-ray"));
        headers.append(
            hyper::header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("origin-setting"),
        );
        headers.append(
            HeaderName::from_static("x-powered-by"),
            HeaderValue::from_static("PHP/8"),
        );
        sanitise_response_headers(&mut headers, "0123456789abcdef-HDD1");
        assert_eq!(headers.get_all(hyper::header::SERVER).iter().count(), 1);
        assert_eq!(
            headers
                .get_all(hyper::header::X_CONTENT_TYPE_OPTIONS)
                .iter()
                .count(),
            1
        );
        assert_eq!(headers.get_all("hdd-ray-id").iter().count(), 1);
        assert_eq!(
            headers
                .get(hyper::header::SERVER)
                .and_then(|value| value.to_str().ok()),
            Some("Hack-Dev-Defence")
        );
        assert_eq!(
            headers
                .get(hyper::header::X_CONTENT_TYPE_OPTIONS)
                .and_then(|value| value.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            headers
                .get("hdd-ray-id")
                .and_then(|value| value.to_str().ok()),
            Some("0123456789abcdef-HDD1")
        );
        assert!(
            headers
                .get(HeaderName::from_static("x-powered-by"))
                .is_none()
        );
    }

    #[test]
    fn forwarded_proto_is_taken_only_from_a_trusted_peer() {
        let peer = SocketAddr::from(([127, 0, 0, 1], 4000));
        let headers = vec![("X-Forwarded-Proto".to_owned(), "https".to_owned())];
        assert_eq!(forwarded_proto(peer, &[], &headers), "http");
        let trusted = vec![util::Cidr::parse("127.0.0.1/32").expect("cidr")];
        assert_eq!(forwarded_proto(peer, &trusted, &headers), "https");
    }
}
