//! Integration tests of the `hdd-canary` sidecar against real TCP sockets and hostile clients (A2, A3 of T-0210).
//!
//! Every test starts its own sidecar on `127.0.0.1:0`, generates the C16.1 files into a fresh temporary directory and talks
//! to it with raw bytes, so the assertions are about what is actually on the wire, not about an in-process mock.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers"
)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use hdd_canary::{
    Config, DEFAULT_BASE_PATH, ECHO_HEADERS_SEGMENT, FILES, MAX_ECHO_JSON_BYTES, Running,
};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hdd-canary-it-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn start(name: &str) -> (PathBuf, Running) {
    let dir = temp_dir(name);
    hdd_canary::generate(&dir, DEFAULT_BASE_PATH).expect("generate");
    let mut config = Config::new(
        "127.0.0.1:0".parse().expect("addr"),
        &dir,
        DEFAULT_BASE_PATH,
    )
    .expect("config");
    config.read_timeout = Duration::from_millis(300);
    config.manifest = Some(dir.join(hdd_canary::MANIFEST_NAME));
    let running = hdd_canary::start(config).expect("start");
    (dir, running)
}

fn start_with(
    name: &str,
    timeout: Duration,
    adjust: impl FnOnce(&mut Config),
) -> (PathBuf, Running) {
    let dir = temp_dir(name);
    hdd_canary::generate(&dir, DEFAULT_BASE_PATH).expect("generate");
    let mut config = Config::new(
        "127.0.0.1:0".parse().expect("addr"),
        &dir,
        DEFAULT_BASE_PATH,
    )
    .expect("config");
    config.read_timeout = timeout;
    config.manifest = Some(dir.join(hdd_canary::MANIFEST_NAME));
    adjust(&mut config);
    let running = hdd_canary::start(config).expect("start");
    (dir, running)
}

/// Send raw bytes, half-close the write side, and read the whole response.
fn raw(addr: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read timeout");
    let _ = stream.write_all(request);
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    out
}

fn get(addr: SocketAddr, path_and_query: &str) -> Vec<u8> {
    raw(
        addr,
        format!("GET {path_and_query} HTTP/1.1\r\nHost: canary.test\r\n\r\n").as_bytes(),
    )
}

fn status(response: &[u8]) -> u16 {
    let head = String::from_utf8_lossy(response);
    let first = head.lines().next().unwrap_or("");
    first
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn head_text(response: &[u8]) -> String {
    let whole = String::from_utf8_lossy(response);
    match whole.find("\r\n\r\n") {
        Some(i) => whole[..i].to_owned(),
        None => whole.into_owned(),
    }
}

fn body(response: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i + 3 < response.len() {
        if &response[i..i + 4] == b"\r\n\r\n" {
            return response[i + 4..].to_vec();
        }
        i += 1;
    }
    Vec::new()
}

#[test]
fn a1_the_sidecar_serves_exactly_the_c16_1_files() {
    let (dir, running) = start("contract");
    let addr = running.local_addr();
    for file in &FILES {
        let path = format!("{DEFAULT_BASE_PATH}{}", file.name);
        let response = get(addr, &path);
        assert_eq!(status(&response), 200, "{path}: {}", head_text(&response));
        assert_eq!(
            body(&response),
            file.content,
            "{path} is served byte for byte"
        );
        let head = head_text(&response);
        let lower = head.to_ascii_lowercase();
        assert!(
            lower.contains("x-content-type-options: nosniff"),
            "{path}: {head}"
        );
        assert!(!lower.contains("set-cookie"), "{path}: {head}");
        assert!(
            lower.contains(&format!("content-length: {}", file.content.len())),
            "{path}: {head}"
        );
        assert!(lower.contains("content-type: "), "{path}: {head}");
        // exactly one response, one file: the manifest is not served
    }
    // nothing else is served: no directory listing, no manifest, no index
    for path in [
        "/".to_owned(),
        DEFAULT_BASE_PATH.to_owned(),
        format!("{DEFAULT_BASE_PATH}{}", hdd_canary::MANIFEST_NAME),
        format!("{DEFAULT_BASE_PATH}index.html"),
        format!("{DEFAULT_BASE_PATH}echo-headers-ish"),
    ] {
        let response = get(addr, &path);
        assert_eq!(status(&response), 404, "{path}: {}", head_text(&response));
    }
    // HEAD returns the same headers with no body
    let head_response = raw(
        addr,
        format!("HEAD {DEFAULT_BASE_PATH}ok.txt HTTP/1.1\r\n\r\n").as_bytes(),
    );
    assert_eq!(status(&head_response), 200);
    assert!(head_response.is_ascii());
    assert!(
        head_text(&head_response)
            .to_ascii_lowercase()
            .contains("content-length: 13"),
        "{}",
        head_text(&head_response)
    );
    assert!(body(&head_response).is_empty(), "HEAD has no body");

    // the metrics show real work: 5 GETs + 1 HEAD served, the five rejections counted
    let m = running.metrics();
    assert_eq!(m.served, FILES.len() as u64 + 1, "{m:?}");
    assert_eq!(m.rejected, 5, "{m:?}");
    assert!(m.bytes_out > 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a2_hostile_requests_get_one_opaque_response_and_no_reflection() {
    let (dir, running) = start("hostile");
    let addr = running.local_addr();
    let marker = "HDDREFLECT7f3a";
    let base = DEFAULT_BASE_PATH;
    let long_value = "H".repeat(10_000);
    let requests: Vec<(&str, Vec<u8>)> = vec![
        (
            "very long header",
            format!("GET {base}ok.txt HTTP/1.1\r\nX-Long: {long_value}\r\n\r\n").into_bytes(),
        ),
        (
            "odd method",
            format!("PROPFIND {base}ok.txt HTTP/1.1\r\n\r\n").into_bytes(),
        ),
        (
            "post with a body",
            format!("POST {base}ok.txt HTTP/1.1\r\nContent-Length: 5\r\n\r\n{marker}").into_bytes(),
        ),
        (
            "path traversal",
            format!("GET {base}../etc/passwd HTTP/1.1\r\n\r\n").into_bytes(),
        ),
        (
            "encoded slashes",
            format!("GET {base}%2fok.txt HTTP/1.1\r\n\r\n").into_bytes(),
        ),
        (
            "encoded dots",
            format!("GET {base}%2e%2e/ok.txt HTTP/1.1\r\n\r\n").into_bytes(),
        ),
        (
            "base path itself",
            format!("GET {base} HTTP/1.1\r\n\r\n").into_bytes(),
        ),
        (
            "absolute-form target",
            format!("GET http://{marker}/ HTTP/1.1\r\n\r\n").into_bytes(),
        ),
        (
            "nul byte in target",
            format!("GET {base}ok.txt\x00 HTTP/1.1\r\n\r\n").into_bytes(),
        ),
        (
            "bad version",
            format!("GET {base}ok.txt HTTP/9.9\r\n\r\n").into_bytes(),
        ),
        (
            "marker in a header on an unknown path",
            format!("GET {base}{marker} HTTP/1.1\r\nX-Marker: {marker}\r\n\r\n").into_bytes(),
        ),
        (
            "query to an unknown path",
            format!("GET {marker}?{marker} HTTP/1.1\r\n\r\n").into_bytes(),
        ),
    ];
    let mut first: Option<Vec<u8>> = None;
    for (label, request) in &requests {
        let response = raw(addr, request);
        assert_eq!(status(&response), 404, "{label}: {}", head_text(&response));
        assert!(
            !String::from_utf8_lossy(&response).contains(marker)
                && !response
                    .windows(marker.len())
                    .any(|w| w == marker.as_bytes()),
            "{label}: the response must not reflect the input"
        );
        match &first {
            None => first = Some(response),
            Some(want) => assert_eq!(
                want, &response,
                "{label}: every rejected request gets the byte-identical response"
            ),
        }
    }
    // the sidecar is still healthy after the hostile batch
    let ok = get(addr, &format!("{base}ok.txt"));
    assert_eq!(status(&ok), 200);
    assert_eq!(body(&ok), b"hdd-canary-ok");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a2_query_strings_do_not_change_what_is_served_and_are_not_echoed() {
    let (dir, running) = start("query");
    let addr = running.local_addr();
    let base = DEFAULT_BASE_PATH;
    let plain_html = get(addr, &format!("{base}search.html"));
    let plain_ok = get(addr, &format!("{base}ok.txt"));
    assert_eq!(status(&plain_html), 200);
    let marker = "hddquerymarker9c2";
    for query in [
        format!("?q={marker}"),
        format!("?q=%2e%2e%2f{marker}"),
        format!("?q=<script>alert('{marker}')</script>"),
        "?".to_owned(),
        format!("?a=1&{marker}=2"),
    ] {
        let response = get(addr, &format!("{base}search.html{query}"));
        assert_eq!(status(&response), 200, "{query}: {}", head_text(&response));
        assert_eq!(
            body(&response),
            body(&plain_html),
            "{query}: the query string does not change the served bytes"
        );
        assert!(
            !String::from_utf8_lossy(&response).contains(marker),
            "{query}: the query string is never reflected"
        );
        let ok = get(addr, &format!("{base}ok.txt{query}"));
        assert_eq!(status(&ok), 200);
        assert_eq!(body(&ok), body(&plain_ok), "{query}: ok.txt unchanged");
    }
    // a very long query string is still inside the request-line limit and changes nothing
    let long_query = format!("?q={}", "q".repeat(900));
    let response = get(addr, &format!("{base}search.html{long_query}"));
    assert_eq!(status(&response), 200);
    assert_eq!(body(&response), body(&plain_html));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a3_echo_headers_returns_only_received_headers_with_a_size_cap() {
    let (dir, running) = start("echo");
    let addr = running.local_addr();
    let mut request = format!(
        "GET {DEFAULT_BASE_PATH}{ECHO_HEADERS_SEGMENT} HTTP/1.1\r\nHost: canary.test\r\nX-HDD-Probe: token-1234\r\nCookie: session=supersecret\r\nAuthorization: Bearer topsecret\r\nX-Quote: a\"b\\c\r\n"
    );
    for i in 0..20 {
        request.push_str(&format!("X-Forwarded-For: 198.51.100.{i}\r\n"));
    }
    request.push_str("\r\n");
    let response = raw(addr, request.as_bytes());
    assert_eq!(status(&response), 200, "{}", head_text(&response));
    let head = head_text(&response).to_ascii_lowercase();
    assert!(head.contains("content-type: application/json"), "{head}");
    assert!(head.contains("x-content-type-options: nosniff"), "{head}");
    assert!(!head.contains("set-cookie"), "{head}");
    let text = String::from_utf8(body(&response)).expect("JSON body is UTF-8");
    assert!(text.starts_with(r#"{"headers":["#), "{text}");
    assert!(text.ends_with("\"truncated\":false}"), "{text}");
    // P-9: non-forwarding headers keep neither name nor value; they are one `[not-echoed-name]` count.
    for unknown in ["x-hdd-probe", "cookie", "authorization", "x-quote"] {
        assert!(
            !text.contains(unknown),
            "P-9: {unknown} must not be echoed by name: {text}"
        );
    }
    assert!(!text.contains("supersecret"), "{text}");
    assert!(!text.contains("topsecret"), "{text}");
    assert!(
        text.contains(r#"{"name":"[not-echoed-name]","value":"4"}"#),
        "the unknown headers are one count: {text}"
    );
    assert!(
        !text.contains("\"path\"") && !text.contains("\"method\""),
        "only names and values: {text}"
    );
    assert!(body(&response).len() <= MAX_ECHO_JSON_BYTES);

    // the cap: many headers whose escaped values would exceed 16 KiB yield a truncated but valid body
    let mut big = format!("GET {DEFAULT_BASE_PATH}{ECHO_HEADERS_SEGMENT} HTTP/1.1\r\n");
    // 90 forwarding values of 70 quotes each stay under the 8 KiB head limit but escape to more than the 16 KiB JSON cap.
    for _ in 0..95 {
        big.push_str(&format!("Connection: {}\r\n", "\"".repeat(70)));
    }
    big.push_str("\r\n");
    let response = raw(addr, big.as_bytes());
    assert_eq!(status(&response), 200);
    let text = String::from_utf8(body(&response)).expect("UTF-8");
    assert!(text.len() <= MAX_ECHO_JSON_BYTES, "{} bytes", text.len());
    assert!(text.contains("\"truncated\":true"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a2_a_body_is_never_read_and_the_server_keeps_serving() {
    let (dir, running) = start("body");
    let addr = running.local_addr();
    // a GET that declares a body is refused before the body is read
    let response = raw(
        addr,
        format!(
            "GET {DEFAULT_BASE_PATH}ok.txt HTTP/1.1\r\nContent-Length: 20\r\n\r\n01234567890123456789"
        )
        .as_bytes(),
    );
    assert_eq!(status(&response), 404, "{}", head_text(&response));
    // the next request is served normally
    let ok = get(addr, &format!("{DEFAULT_BASE_PATH}ok.txt"));
    assert_eq!(status(&ok), 200);
    assert_eq!(body(&ok), b"hdd-canary-ok");
    // echo-headers is GET-only: HEAD and POST are rejected uniformly
    let head = raw(
        addr,
        format!("HEAD {DEFAULT_BASE_PATH}{ECHO_HEADERS_SEGMENT} HTTP/1.1\r\n\r\n").as_bytes(),
    );
    assert_eq!(status(&head), 404);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a2_a_slow_client_is_bounded_by_the_read_timeout() {
    let (dir, running) = start("slow");
    let addr = running.local_addr();
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let started = Instant::now();
    stream.write_all(b"GET /__hdd_canary/ok").expect("partial");
    stream.flush().expect("flush");
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "a half-open request must not hold the sidecar forever: {elapsed:?}"
    );
    // at the absolute deadline the sidecar may close before a rejection response fits; either is a bounded end
    assert!(
        out.is_empty() || status(&out) == 404,
        "an incomplete head ends with the uniform rejection or a close: {}",
        head_text(&out)
    );
    // and the server is free for the next client
    let ok = get(addr, &format!("{DEFAULT_BASE_PATH}ok.txt"));
    assert_eq!(status(&ok), 200);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a2_an_oversized_request_line_is_rejected_and_serving_continues() {
    let (dir, running) = start("longline");
    let addr = running.local_addr();
    let long_path = format!("/{}", "a".repeat(5000));
    let response = get(addr, &long_path);
    assert_eq!(status(&response), 404, "{}", head_text(&response));
    let ok = get(addr, &format!("{DEFAULT_BASE_PATH}ok.txt"));
    assert_eq!(status(&ok), 200);
    assert_eq!(body(&ok), b"hdd-canary-ok");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Connect, wait `delay`, then send the request: the bytes arrive after the sidecar has accepted the connection.
fn raw_delayed(addr: SocketAddr, request: &[u8], delay: Duration) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read timeout");
    std::thread::sleep(delay);
    let _ = stream.write_all(request);
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    out
}

#[test]
fn a2_a_request_that_arrives_after_accept_is_served_not_rejected() {
    // F-B2-0 root cause: an accepted stream inherited the listener's non-blocking mode on Windows, so a request that
    // arrived a few milliseconds after accept() made read() return WouldBlock, which read_head treated as a reject and
    // answered with the opaque 404. Under load that is a valid file fetch answered with 404 -> the test flake.
    let (dir, running) = start("late-request");
    let addr = running.local_addr();
    for attempt in 0..5 {
        let response = raw_delayed(
            addr,
            format!("GET {DEFAULT_BASE_PATH}ok.txt HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes(),
            Duration::from_millis(60),
        );
        assert_eq!(
            status(&response),
            200,
            "attempt {attempt}: a request arriving 60 ms after accept must be read, not rejected: {}",
            head_text(&response)
        );
        assert_eq!(body(&response), b"hdd-canary-ok");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Drip one byte every `interval` after `prefix`, then read the response until EOF; returns response and elapsed.
fn drip_exchange(
    addr: SocketAddr,
    prefix: &[u8],
    interval: Duration,
    max: Duration,
) -> (Vec<u8>, Duration) {
    let stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(6)))
        .expect("read timeout");
    let mut writer = stream.try_clone().expect("clone");
    let started = Instant::now();
    if !prefix.is_empty() {
        let _ = writer.write_all(prefix);
        let _ = writer.flush();
    }
    let writer_thread = std::thread::spawn(move || {
        let begin = Instant::now();
        while begin.elapsed() < max {
            std::thread::sleep(interval);
            if writer.write_all(b"x").is_err() {
                break;
            }
        }
        let _ = writer.shutdown(std::net::Shutdown::Write);
    });
    let mut reader = stream;
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    let elapsed = started.elapsed();
    let _ = writer_thread.join();
    (out, elapsed)
}

#[test]
fn a_connection_deadline_closes_a_dripping_client_at_the_deadline() {
    // C-1: one byte per 0.8 x timeout must not hold the sidecar. The per-connection deadline is 300 ms in this test
    // harness; the old per-read timeout would let the client drip forever (each byte resets the per-read timeout).
    let (dir, running) = start("drip-head");
    let addr = running.local_addr();
    let timeout = Duration::from_millis(300);
    let (response, elapsed) = drip_exchange(
        addr,
        format!("GET {DEFAULT_BASE_PATH}ok").as_bytes(),
        timeout.mul_f64(0.8),
        Duration::from_secs(4),
    );
    assert!(
        elapsed >= Duration::from_millis(150),
        "a dripping client must reach the absolute deadline, not be answered immediately: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "a dripping client must be disconnected at the deadline: {elapsed:?}"
    );
    assert!(
        response.is_empty() || status(&response) == 404,
        "an incomplete head at the deadline gets the uniform rejection or a close, not a file: {}",
        head_text(&response)
    );
    // the sidecar is still healthy
    let ok = get(addr, &format!("{DEFAULT_BASE_PATH}ok.txt"));
    assert_eq!(status(&ok), 200);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_rejected_connection_is_closed_at_the_deadline_while_dripping() {
    // C-1, reject path: the drain that lets a client read the rejection must also stop at the same absolute deadline,
    // not run per read.
    let (dir, running) = start("drip-reject");
    let addr = running.local_addr();
    let timeout = Duration::from_millis(300);
    let (response, elapsed) = drip_exchange(
        addr,
        b"POST /__hdd_canary/ok.txt HTTP/1.1\r\nContent-Length: 1000\r\n\r\n",
        timeout.mul_f64(0.8),
        Duration::from_secs(4),
    );
    assert_eq!(status(&response), 404, "{}", head_text(&response));
    assert!(
        elapsed < Duration::from_secs(2),
        "a rejected client is disconnected, not held indefinitely: {elapsed:?}"
    );
    // the drain is still bounded by the connection deadline: the single-threaded sidecar serves the next request soon
    let second = Instant::now();
    let ok = get(addr, &format!("{DEFAULT_BASE_PATH}ok.txt"));
    assert_eq!(status(&ok), 200);
    assert!(
        second.elapsed() < Duration::from_secs(2),
        "the drain must release the single connection promptly: {:?}",
        second.elapsed()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a2_a_rejected_head_gets_no_response_body() {
    // C-8: a HEAD request that is rejected (no echo-headers for HEAD) must not carry a body.
    let (dir, running) = start("head-reject");
    let response = raw(
        running.local_addr(),
        format!("HEAD {DEFAULT_BASE_PATH}echo-headers HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes(),
    );
    assert_eq!(status(&response), 404, "{}", head_text(&response));
    let head = head_text(&response).to_ascii_lowercase();
    assert!(head.contains("content-length: 10"), "{head}");
    assert!(
        body(&response).is_empty(),
        "a HEAD response carries no body, got {:?}",
        body(&response)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_echo_headers_never_leaks_secret_bearing_request_headers() {
    // K-1: HDD-Origin-Auth is injected on every upstream request and the echo endpoint is reachable through HDD.
    let (dir, running) = start("echo-secrets");
    let addr = running.local_addr();
    let request = concat!(
        "GET /__hdd_canary/echo-headers HTTP/1.1\r\n",
        "Host: canary.test\r\n",
        "HDD-Origin-Auth: v1;k9;1700000000;0123456789abcdef;AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n",
        "X-Api-Key: api-key-value-planted\r\n",
        "X-Secret-Thing: secret-value-planted\r\n",
        "X-Session-Token: token-value-planted\r\n",
        "X-Auth-Token: auth-value-planted\r\n",
        "X-Signature: signature-value-planted\r\n",
        "X-Key-Id: key-value-planted\r\n",
        "X-HDD-Canary-Probe: hdd-canary-probe\r\n",
        "\r\n"
    );
    let response = raw(addr, request.as_bytes());
    assert_eq!(status(&response), 200, "{}", head_text(&response));
    let body = String::from_utf8_lossy(&body(&response)).into_owned();
    for planted in [
        "api-key-value-planted",
        "secret-value-planted",
        "token-value-planted",
        "auth-value-planted",
        "signature-value-planted",
        "key-value-planted",
        "1700000000",
        "0123456789abcdef",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert!(
            !body.contains(planted),
            "the sidecar leaked `{planted}`:\n{body}"
        );
    }
    assert!(
        body.contains(r#"{"name":"hdd-origin-auth","value":"v1;k9"}"#),
        "the origin auth header keeps only presence + version + key id:\n{body}"
    );
    assert!(
        body.contains(r#"{"name":"x-hdd-canary-probe","value":"hdd-canary-probe"}"#),
        "the probe header still round-trips:\n{body}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_rejected_client_sees_the_response_close_before_the_deadline() {
    // K-8: after a rejection the sidecar shuts its write side down, so a client that reads the response gets EOF
    // immediately instead of waiting for the connection deadline while the server drains.
    let (dir, running) = start("reject-eof");
    let addr = running.local_addr();
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let started = Instant::now();
    stream
        .write_all(b"POST /__hdd_canary/ok.txt HTTP/1.1\r\nContent-Length: 100\r\n\r\n")
        .expect("write");
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    let elapsed = started.elapsed();
    assert_eq!(status(&out), 404, "{}", head_text(&out));
    let deadline = Duration::from_millis(300);
    assert!(
        elapsed < deadline,
        "EOF must arrive before the connection deadline; took {elapsed:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_served_response_survives_trailing_client_bytes() {
    // Q-4: a served 200 with trailing request bytes must deliver the full body (shutdown(Write) + bounded drain), not a
    // connection reset.
    let (dir, running) = start("trailing-bytes");
    let addr = running.local_addr();
    for trailing in [5_000usize, 60_000] {
        let mut request =
            format!("GET {DEFAULT_BASE_PATH}ok.txt HTTP/1.1\r\nHost: x\r\n\r\n").into_bytes();
        request.extend(std::iter::repeat_n(b'x', trailing));
        let response = raw(addr, &request);
        assert_eq!(
            status(&response),
            200,
            "trailing {trailing}: {}",
            head_text(&response)
        );
        assert_eq!(
            body(&response),
            b"hdd-canary-ok",
            "trailing {trailing}: the served body must arrive intact"
        );
    }
    // Content-Length: 0 with trailing data is also a served request (the client declared no body but sent bytes)
    let mut request =
        format!("GET {DEFAULT_BASE_PATH}ok.txt HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
            .into_bytes();
    request.extend(std::iter::repeat_n(b'y', 5_000));
    let response = raw(addr, &request);
    assert_eq!(status(&response), 200, "{}", head_text(&response));
    assert_eq!(body(&response), b"hdd-canary-ok");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_worker_panic_is_counted_and_the_service_continues() {
    // P-1: a panic inside one connection handler is caught, counted, and the worker (and service) keep running.
    let (dir, running) = start_with("worker-panic", Duration::from_millis(300), |config| {
        config.panic_connection = true;
    });
    let addr = running.local_addr();
    let first = get(addr, &format!("{DEFAULT_BASE_PATH}ok.txt"));
    assert!(
        first.is_empty() || status(&first) != 200,
        "the panicking connection is not answered"
    );
    let mut waited = 0;
    while running.metrics().worker_panics == 0 && waited < 100 {
        std::thread::sleep(Duration::from_millis(10));
        waited += 1;
    }
    assert_eq!(running.metrics().worker_panics, 1, "the panic is counted");
    let second = get(addr, &format!("{DEFAULT_BASE_PATH}ok.txt"));
    assert_eq!(
        status(&second),
        200,
        "the service continues after the panic"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_failed_worker_spawn_fails_start() {
    // P-1: a failed worker spawn is an error at start, not a silently smaller pool.
    let dir = temp_dir("spawn-fail");
    hdd_canary::generate(&dir, DEFAULT_BASE_PATH).expect("generate");
    let mut config = Config::new(
        "127.0.0.1:0".parse().expect("addr"),
        &dir,
        DEFAULT_BASE_PATH,
    )
    .expect("config");
    config.fail_worker_spawn = true;
    let error = hdd_canary::start(config).expect_err("a failed spawn must fail start()");
    assert!(
        error
            .to_string()
            .contains("cannot start a connection worker"),
        "{error}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn all_workers_gone_is_fatal() {
    // P-1: when every worker is gone, the run is fatal (the process exits 2), not a silently dead service.
    let (dir, running) = start_with("all-workers-gone", Duration::from_millis(300), |config| {
        config.kill_workers = true;
    });
    let error = running.wait().expect_err("no workers must be fatal");
    assert!(
        error
            .to_string()
            .contains("all connection workers are gone"),
        "{error}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_32_probe_burst_is_served() {
    // P-2: the bounded queue serves a 32-probe burst without shedding.
    let (dir, running) = start("burst32");
    let addr = running.local_addr();
    let handles: Vec<_> = (0..32)
        .map(|_| std::thread::spawn(move || get(addr, &format!("{DEFAULT_BASE_PATH}ok.txt"))))
        .collect();
    for handle in handles {
        let response = handle.join().expect("join");
        assert_eq!(status(&response), 200, "{}", head_text(&response));
    }
    assert_eq!(running.metrics().connections_shed, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_full_accept_queue_sheds_with_the_fixed_503() {
    // P-2: a connection that cannot be queued gets the fixed opaque 503, counted separately.
    let (dir, running) = start_with("shed-503", Duration::from_secs(3), |_| {});
    let addr = running.local_addr();
    let mut idle = Vec::new();
    for _ in 0..80 {
        idle.push(TcpStream::connect(addr).expect("idle connect"));
    }
    std::thread::sleep(Duration::from_millis(200));
    let response = raw(
        addr,
        b"GET /__hdd_canary/ok.txt HTTP/1.1\r\nHost: canary.test\r\n\r\n",
    );
    assert_eq!(status(&response), 503, "{}", head_text(&response));
    let head = head_text(&response).to_ascii_lowercase();
    assert!(head.contains("retry-after: 1"), "{head}");
    assert!(head.contains("connection: close"), "{head}");
    assert!(
        !head.contains("ok.txt"),
        "the shed response reflects no input: {head}"
    );
    assert!(running.metrics().connections_shed >= 1);
    drop(idle);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn twenty_connections_are_served() {
    // P-10: 20 concurrent connections are all served.
    let (dir, running) = start("twenty");
    let addr = running.local_addr();
    let handles: Vec<_> = (0..20)
        .map(|_| std::thread::spawn(move || get(addr, &format!("{DEFAULT_BASE_PATH}ok.txt"))))
        .collect();
    for handle in handles {
        assert_eq!(status(&handle.join().expect("join")), 200);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_connection_past_its_accept_deadline_is_closed_without_work() {
    // P-3: the deadline starts at accept; a request that waited too long is closed instead of served late.
    let (dir, running) = start_with("accept-deadline", Duration::from_millis(200), |_| {});
    let addr = running.local_addr();
    let mut idle = Vec::new();
    for _ in 0..19 {
        idle.push(TcpStream::connect(addr).expect("idle"));
    }
    let started = Instant::now();
    let response = get(addr, &format!("{DEFAULT_BASE_PATH}ok.txt"));
    assert!(
        response.is_empty() || status(&response) != 200,
        "an expired connection must not be served: {}",
        head_text(&response)
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "no 19-deadline wait"
    );
    drop(idle);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn non_closing_clients_do_not_delay_a_fifth() {
    // P-4: after the response the short drain cap frees the worker, even when clients keep their connections open.
    let (dir, running) = start_with("non-closing", Duration::from_millis(1000), |_| {});
    let addr = running.local_addr();
    let request = format!("GET {DEFAULT_BASE_PATH}ok.txt HTTP/1.1\r\nHost: canary.test\r\n\r\n");
    let mut keep = Vec::new();
    for _ in 0..4 {
        let mut stream = TcpStream::connect(addr).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        stream.write_all(request.as_bytes()).expect("write");
        stream.flush().expect("flush");
        let mut buffer = [0u8; 256];
        let read = stream.read(&mut buffer).expect("read response");
        assert!(read > 0, "the four clients get their response");
        keep.push(stream);
    }
    let started = Instant::now();
    let response = get(addr, &format!("{DEFAULT_BASE_PATH}ok.txt"));
    assert_eq!(status(&response), 200);
    assert!(
        started.elapsed() < Duration::from_millis(700),
        "a fifth client is served after the drain cap, took {:?}",
        started.elapsed()
    );
    assert_eq!(
        running.metrics().read_timeouts,
        0,
        "a served response is not a read timeout"
    );
    drop(keep);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_500kb_trailing_body_does_not_lose_the_served_response() {
    // P-10: a large trailing body is drained with the short cap and the served body arrives intact.
    let (dir, running) = start("trailing-500k");
    let addr = running.local_addr();
    let mut request =
        format!("GET {DEFAULT_BASE_PATH}ok.txt HTTP/1.1\r\nHost: canary.test\r\n\r\n").into_bytes();
    request.extend(std::iter::repeat_n(b'x', 500_000));
    let response = raw(addr, &request);
    assert_eq!(status(&response), 200, "{}", head_text(&response));
    assert_eq!(body(&response), b"hdd-canary-ok");
    let _ = std::fs::remove_dir_all(&dir);
}
