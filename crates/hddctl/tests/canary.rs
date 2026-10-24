//! End-to-end tests of `hddctl canary generate|verify` as an operator runs them.
//!
//! The live profile (`hdd.live.yaml`) is never present in this repository, so the tests exercise the local and direct
//! halves against a real `hdd-canary` sidecar and a controlled fake origin on `127.0.0.1:0`, and assert that the
//! profile-dependent halves are reported honestly instead of a fabricated PASS.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers"
)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use hdd_canary::{DEFAULT_BASE_PATH, ECHO_HEADERS_SEGMENT, FILES, MANIFEST_NAME};

fn hddctl() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hddctl"))
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hddctl-canary-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn line_with<'a>(output: &'a str, rule: &str) -> &'a str {
    output
        .lines()
        .find(|l| l.trim_start().starts_with(rule))
        .unwrap_or_else(|| panic!("no `{rule}` line in:\n{output}"))
}

fn generate(dir: &Path) -> Output {
    hddctl()
        .args(["canary", "generate", "--dir"])
        .arg(dir)
        .output()
        .expect("run")
}

fn start_sidecar(root: &Path) -> hdd_canary::Running {
    let mut config = hdd_canary::Config::new(
        "127.0.0.1:0".parse().expect("addr"),
        root,
        DEFAULT_BASE_PATH,
    )
    .expect("config");
    config.manifest = None;
    hdd_canary::start(config).expect("sidecar starts")
}

fn example_profile_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("hdd.live.example.yaml")
}

/// The committed example profile, with the declarations a canary test needs replaced.
fn write_profile_full(
    dir: &Path,
    origin_url: &str,
    test_hostname: &str,
    use_agent: bool,
    lockdown: &str,
) -> PathBuf {
    let example = std::fs::read_to_string(example_profile_path()).expect("example");
    let text = example
        .replace(
            "  url: https://203.0.113.10",
            &format!("  url: {origin_url}"),
        )
        .replace(
            "test_hostname: hddtest.example.com",
            &format!("test_hostname: {test_hostname}"),
        )
        .replace(
            "use_hdd_canary_agent: true",
            if use_agent {
                "use_hdd_canary_agent: true"
            } else {
                "use_hdd_canary_agent: false"
            },
        )
        .replace(
            "lockdown_state: pending",
            &format!("lockdown_state: {lockdown}"),
        );
    let path = dir.join("hdd.live.yaml");
    std::fs::write(&path, text).expect("write profile");
    path
}

fn write_profile(dir: &Path, origin_url: &str, test_hostname: &str, use_agent: bool) -> PathBuf {
    write_profile_full(dir, origin_url, test_hostname, use_agent, "pending")
}

/// One HTTP response the fake origin hands out.
struct Reply {
    status: u16,
    content_type: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn ok_file(file: &hdd_canary::CanaryFile, nosniff: bool, extra: &[(String, String)]) -> Reply {
        let mut headers = extra.to_vec();
        if nosniff {
            headers.push(("X-Content-Type-Options".to_owned(), "nosniff".to_owned()));
        }
        Reply {
            status: 200,
            content_type: file.media_type,
            headers,
            body: file.content.to_vec(),
        }
    }

    fn echo(extra: &[(String, String)], nosniff: bool, probe: &str) -> Reply {
        let mut headers = Vec::new();
        if nosniff {
            headers.push(("X-Content-Type-Options".to_owned(), "nosniff".to_owned()));
        }
        let mut json = String::from("{\"headers\":[");
        json.push_str(&format!(
            "{{\"name\":\"x-hdd-canary-probe\",\"value\":\"{probe}\"}}"
        ));
        for (name, value) in extra {
            json.push_str(&format!(
                ",{{\"name\":\"{}\",\"value\":\"{}\"}}",
                name, value
            ));
        }
        json.push_str("],\"truncated\":false}");
        Reply {
            status: 200,
            content_type: "application/json; charset=utf-8",
            headers,
            body: json.into_bytes(),
        }
    }

    fn not_found() -> Reply {
        Reply {
            status: 404,
            content_type: "text/plain; charset=utf-8",
            headers: Vec::new(),
            body: b"not found\n".to_vec(),
        }
    }
}

/// What the fake origin does: it stands in for the origin (or for HDD in front of it) in the controlled tests.
#[derive(Clone)]
struct FakeOrigin {
    /// Loopback address to bind (different from 127.0.0.1 to test that a different host is not HDD evidence).
    bind_ip: &'static str,
    /// Extra response headers on the five contract files (for example HDD's `Server`/`HDD-Ray-ID`).
    file_headers: Vec<(String, String)>,
    /// Answer file requests with a body larger than the canary response cap.
    oversize: bool,
    /// Serve the five contract files.
    files: bool,
    /// Serve `echo-headers` at all.
    echo: bool,
    /// Send `X-Content-Type-Options: nosniff` on the contract files.
    files_nosniff: bool,
    /// Send `X-Content-Type-Options: nosniff` on the echo JSON.
    echo_nosniff: bool,
    /// Extra request headers the echo reports (for example the HDD forwarding headers).
    extra_echo: Vec<(String, String)>,
    /// Drop the first connection without a response (a transient network reset).
    drop_first: bool,
    /// Reflect the request's forwarding headers into the echo (simulates an origin TLS terminator that copies them).
    reflect_forwarding: bool,
    /// Append this token to the reflected X-Forwarded-For (simulates nginx `$proxy_add_x_forwarded_for`).
    append_to_reflected_xff: Option<String>,
}

impl Default for FakeOrigin {
    fn default() -> Self {
        FakeOrigin {
            bind_ip: "127.0.0.1",
            file_headers: Vec::new(),
            oversize: false,
            files: false,
            echo: false,
            files_nosniff: false,
            echo_nosniff: false,
            extra_echo: Vec::new(),
            drop_first: false,
            reflect_forwarding: false,
            append_to_reflected_xff: None,
        }
    }
}

/// A small controlled HTTP origin for the canary checks. Returns its address; the thread lives with the test process.
fn fake_origin(config: FakeOrigin) -> SocketAddr {
    let bind = format!("{}:0", config.bind_ip);
    let listener = TcpListener::bind(&bind).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let dropped = std::sync::Arc::new(AtomicBool::new(false));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            if config.drop_first && !dropped.swap(true, Ordering::SeqCst) {
                continue;
            }
            let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
            let mut head = Vec::new();
            let mut buffer = [0u8; 1024];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Some(part) = buffer.get(..n) {
                            head.extend_from_slice(part);
                        }
                        if head.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let request = String::from_utf8_lossy(&head).into_owned();
            let target = request
                .lines()
                .next()
                .unwrap_or("")
                .split_whitespace()
                .nth(1)
                .unwrap_or("");
            let path = target.split('?').next().unwrap_or("");
            let name = path.rsplit('/').next().unwrap_or("");
            let probe = request
                .lines()
                .find_map(|line| {
                    let (header, value) = line.split_once(':')?;
                    if header.eq_ignore_ascii_case("x-hdd-canary-probe") {
                        Some(value.trim().to_owned())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();
            let reply = if name == ECHO_HEADERS_SEGMENT && config.echo {
                let mut extras = config.extra_echo.clone();
                if config.reflect_forwarding {
                    for line in request.lines().skip(1) {
                        if let Some((header, value)) = line.split_once(':') {
                            let lower = header.trim().to_ascii_lowercase();
                            if matches!(
                                lower.as_str(),
                                "x-forwarded-for" | "forwarded" | "x-real-ip"
                            ) {
                                extras.push((lower, value.trim().to_owned()));
                            }
                        }
                    }
                }
                if let Some(append) = &config.append_to_reflected_xff {
                    match extras
                        .iter_mut()
                        .find(|(name, _)| name == "x-forwarded-for")
                    {
                        Some((_, value)) => value.push_str(&format!(", {append}")),
                        None => extras.push(("x-forwarded-for".to_owned(), append.clone())),
                    }
                }
                Reply::echo(&extras, config.echo_nosniff, &probe)
            } else if config.files {
                match FILES.iter().find(|f| f.name == name) {
                    Some(file) => {
                        if config.oversize {
                            Reply {
                                status: 200,
                                content_type: file.media_type,
                                headers: vec![(
                                    "X-Content-Type-Options".to_owned(),
                                    "nosniff".to_owned(),
                                )],
                                body: vec![b'x'; 300 * 1024],
                            }
                        } else {
                            Reply::ok_file(file, config.files_nosniff, &config.file_headers)
                        }
                    }
                    None => Reply::not_found(),
                }
            } else {
                Reply::not_found()
            };
            let mut response = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                reply.status,
                if reply.status == 200 {
                    "OK"
                } else {
                    "Not Found"
                },
                reply.content_type,
                reply.body.len()
            );
            for (name, value) in &reply.headers {
                response.push_str(&format!("{name}: {value}\r\n"));
            }
            response.push_str("\r\n");
            let mut bytes = response.into_bytes();
            bytes.extend_from_slice(&reply.body);
            let _ = stream.write_all(&bytes);
            let _ = stream.flush();
        }
    });
    addr
}

/// A server that accepts every connection and closes it at once: a transport failure, not a wrong response.
fn resetting_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            drop(stream);
        }
    });
    addr
}

// ---------------------------------------------------------------------------------------------------------------------
// A1: generate / manifest
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn t0210_generate_writes_the_contract_files_with_real_hashes() {
    let dir = temp_dir("generate");
    let out = generate(&dir);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    for file in &FILES {
        let on_disk = std::fs::read(dir.join(file.name)).expect("file written");
        assert_eq!(on_disk, file.content, "{}", file.name);
        assert!(
            t.contains(file.name) && t.contains(&hdd_canary::sha256_hex(&on_disk)),
            "the command prints the real hash of {}:\n{t}",
            file.name
        );
    }
    let manifest = std::fs::read_to_string(dir.join(MANIFEST_NAME)).expect("manifest");
    for file in &FILES {
        let hash = hdd_canary::sha256_hex(file.content);
        assert!(
            manifest.contains(&format!("{hash}  {}", file.name)),
            "manifest line for {}: {manifest}",
            file.name
        );
    }
    assert_eq!(
        std::fs::read_to_string(dir.join("ok.txt")).expect("ok.txt"),
        "hdd-canary-ok"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("leak.txt")).expect("leak.txt"),
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    );
    assert!(t.contains(DEFAULT_BASE_PATH), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_generate_is_idempotent_and_rejects_a_bad_base_path() {
    let dir = temp_dir("idempotent");
    let first = generate(&dir);
    assert_eq!(first.status.code(), Some(0), "{}", text(&first));
    let manifest_first = std::fs::read_to_string(dir.join(MANIFEST_NAME)).expect("manifest");
    let second = generate(&dir);
    assert_eq!(second.status.code(), Some(0), "{}", text(&second));
    let manifest_second = std::fs::read_to_string(dir.join(MANIFEST_NAME)).expect("manifest");
    assert_eq!(manifest_first, manifest_second, "generate is idempotent");

    let bad = hddctl()
        .args(["canary", "generate", "--dir"])
        .arg(&dir)
        .args(["--base-path", "/a/../b/"])
        .output()
        .expect("run");
    let t = text(&bad);
    assert_eq!(bad.status.code(), Some(1), "{t}");
    assert!(t.to_ascii_lowercase().contains("base path"), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------------------------------------
// C-7: the manifest base path must match the base path in use
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn t0210_verify_fails_when_the_manifest_base_path_differs() {
    let dir = temp_dir("manifest-base-path");
    let out = hddctl()
        .args(["canary", "generate", "--dir"])
        .arg(&dir)
        .args(["--base-path", "/a/"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args(["--base-path", "/b/"])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    let manifest = line_with(&t, "CANARY-MANIFEST");
    assert!(manifest.contains("FAIL"), "{t}");
    assert!(
        manifest.contains("/a/") && manifest.contains("/b/"),
        "the failure names both base paths:\n{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------------------------------------
// C-3: override targets must be named by the profile, or be explicit loopback literals with --local-only
// ---------------------------------------------------------------------------------------------------------------------

fn sidecar_origin(dir: &Path) -> (hdd_canary::Running, String) {
    let sidecar = start_sidecar(dir);
    let origin = format!("http://{}", sidecar.local_addr());
    (sidecar, origin)
}

#[test]
fn t0210_verify_without_a_profile_requires_local_only_for_overrides() {
    let dir = temp_dir("needs-local-only");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let (_sidecar, origin) = sidecar_origin(&dir);
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args(["--direct-url", &origin])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    let target = line_with(&t, "CANARY-TARGET");
    assert!(target.contains("FAIL"), "{t}");
    assert!(target.contains("--local-only"), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_verify_refuses_a_profile_override_host_the_profile_does_not_name() {
    let dir = temp_dir("profile-host-mismatch");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let (_sidecar, origin) = sidecar_origin(&dir);
    let profile_dir = temp_dir("profile-host-mismatch-profile");
    let profile = write_profile(&profile_dir, &origin, "''", true);
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args([
            "--file",
            profile.to_str().expect("utf-8"),
            "--direct-url",
            "http://third-party.example",
        ])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    let target = line_with(&t, "CANARY-TARGET");
    assert!(target.contains("FAIL"), "{t}");
    assert!(
        target.contains("third-party.example") && target.contains("profile"),
        "the refusal names the host and says why:\n{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&profile_dir);
}

#[test]
fn t0210_verify_local_only_refuses_a_public_name() {
    let dir = temp_dir("local-only-public");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args(["--local-only", "--direct-url", "http://third-party.example"])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(line_with(&t, "CANARY-TARGET").contains("FAIL"), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_verify_local_only_refuses_a_metadata_address() {
    let dir = temp_dir("local-only-metadata");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args(["--local-only", "--direct-url", "http://169.254.169.254"])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    let target = line_with(&t, "CANARY-TARGET");
    assert!(target.contains("FAIL"), "{t}");
    assert!(target.contains("loopback"), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_verify_local_only_refuses_a_private_address() {
    let dir = temp_dir("local-only-private");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args(["--local-only", "--direct-url", "http://10.0.0.1"])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(line_with(&t, "CANARY-TARGET").contains("FAIL"), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_verify_refuses_a_userinfo_trick() {
    let dir = temp_dir("local-only-userinfo");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args([
            "--local-only",
            "--direct-url",
            "http://127.0.0.1@evil.example/",
        ])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    let target = line_with(&t, "CANARY-TARGET");
    assert!(target.contains("FAIL"), "{t}");
    assert!(
        target.contains("credentials in URLs"),
        "the userinfo form is refused by the URL parser:\n{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_verify_local_only_refuses_the_name_localhost() {
    let dir = temp_dir("local-only-localhost");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args(["--local-only", "--direct-url", "http://localhost:9"])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(line_with(&t, "CANARY-TARGET").contains("FAIL"), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------------------------------------
// A5 / C-4 / C-5 / C-6: honest statuses, HDD evidence, whole-token runner IP, transport failure
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn t0210_verify_without_a_profile_is_honest() {
    let dir = temp_dir("verify-noprofile");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let (_sidecar, origin) = sidecar_origin(&dir);
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args(["--local-only", "--direct-url", &origin])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(line_with(&t, "CANARY-MANIFEST").contains("PASS"), "{t}");
    assert!(line_with(&t, "CANARY-DIRECT").contains("PASS"), "{t}");
    assert!(line_with(&t, "CANARY-QUERY").contains("PASS"), "{t}");
    assert!(line_with(&t, "CANARY-ECHO").contains("PASS"), "{t}");
    let hdd = line_with(&t, "CANARY-HDD");
    assert!(hdd.contains("UNVERIFIED(human_step_pending)"), "{t}");
    assert!(t.contains("hdd.live.example.yaml"), "{t}");
    assert!(t.contains("hdd.live.yaml"), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_verify_checks_the_through_path_and_query_invariance_when_overridden() {
    // K-2: the same local server for direct and through is NOT HDD-specific evidence, so the through check must be
    // UNVERIFIED(capability_not_supplied), never PASS.
    let dir = temp_dir("verify-overrides");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let (_sidecar, origin) = sidecar_origin(&dir);
    let direct = format!("{origin}{DEFAULT_BASE_PATH}");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args([
            "--local-only",
            "--direct-url",
            &origin,
            "--through-url",
            &origin,
        ])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(line_with(&t, "CANARY-DIRECT").contains("PASS"), "{t}");
    let hdd = line_with(&t, "CANARY-HDD");
    assert!(
        hdd.contains("UNVERIFIED(capability_not_supplied)"),
        "a through check without HDD evidence is honestly unverified (closed reason set):\n{t}"
    );
    assert!(
        hdd.contains("HDD evidence")
            || hdd.contains("Server: Hack-Dev-Defence")
            || hdd.contains("HDD-Ray-ID"),
        "the message names the missing evidence and how to supply it:\n{t}"
    );
    assert!(line_with(&t, "CANARY-QUERY").contains("PASS"), "{t}");
    assert!(t.contains(&format!("direct: {direct}")), "{t}");
    assert!(t.contains(&format!("through: {direct}")), "{t}");
    assert!(
        t.find(&format!("direct: {direct}")).unwrap()
            < t.find(line_with(&t, "CANARY-MANIFEST")).unwrap(),
        "targets are announced before the first check line:\n{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_parsing_verify_reports_a_runner_ip_that_the_echo_does_not_show() {
    // C-5: 198.51.100.7 must not match the whole-token value 198.51.100.77.
    let dir = temp_dir("verify-runner-ip");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let origin = fake_origin(FakeOrigin {
        files: true,
        echo: true,
        files_nosniff: true,
        echo_nosniff: true,
        extra_echo: vec![("x-forwarded-for".to_owned(), "198.51.100.77".to_owned())],
        drop_first: false,
        ..FakeOrigin::default()
    });
    let base = format!("http://{origin}");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args([
            "--local-only",
            "--through-url",
            &base,
            "--runner-ip",
            "198.51.100.7",
        ])
        .output()
        .expect("run");
    let t = text(&out);
    let echo = line_with(&t, "CANARY-ECHO");
    assert!(
        echo.contains("UNVERIFIED(capability_not_supplied)"),
        "Q-2: the runner claim is UNVERIFIED for a value that is not HDD-specific:\n{t}"
    );
    assert!(echo.contains("198.51.100.7"), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_parsing_verify_whole_token_runner_ip_match_accepts_the_exact_address() {
    // C-5: the exact IPv6 address is a whole token of the forwarding header, so the check passes.
    let dir = temp_dir("verify-runner-ip-exact");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let origin = fake_origin(FakeOrigin {
        files: true,
        echo: true,
        files_nosniff: true,
        echo_nosniff: true,
        extra_echo: vec![(
            "x-forwarded-for".to_owned(),
            "198.51.100.77, 2001:db8::1".to_owned(),
        )],
        drop_first: false,
        ..FakeOrigin::default()
    });
    let base = format!("http://{origin}");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args([
            "--local-only",
            "--through-url",
            &base,
            "--runner-ip",
            "2001:db8::1",
        ])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    // P-7/P-8: without --with-spoof-probe the echo claim is shown, not asserted.
    assert!(
        line_with(&t, "CANARY-ECHO").contains("UNVERIFIED(capability_not_supplied)"),
        "{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_verify_does_not_assert_the_runner_ip_on_a_direct_only_echo() {
    let dir = temp_dir("direct-runner-ip");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let (_sidecar, origin) = sidecar_origin(&dir);
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args([
            "--local-only",
            "--direct-url",
            &origin,
            "--runner-ip",
            "198.51.100.77",
        ])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    let echo = line_with(&t, "CANARY-ECHO");
    assert!(echo.contains("PASS"), "{t}");
    assert!(echo.contains("only asserted through HDD"), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_verify_override_transport_failure_is_a_fail_not_a_pending_step() {
    // Q-1: an explicit --through-url with no live profile has nothing to delegate; a refused connection to a loopback
    // literal is a FAIL (and must not print "delegate the pilot subzones").
    let dir = temp_dir("through-transport");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let resetting = resetting_server();
    let base = format!("http://{resetting}");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args(["--local-only", "--through-url", &base])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    let hdd = line_with(&t, "CANARY-HDD");
    assert!(
        hdd.contains("FAIL"),
        "an override target with no profile is a FAIL:\n{t}"
    );
    assert!(
        !hdd.contains("Delegate the pilot subzones"),
        "a loopback literal has nothing to delegate:\n{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------------------------------------
// C-8(d): nosniff is required for the echo JSON (C16) and advisory on the contract files (C16.1)
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn t0210_parsing_verify_warns_when_the_contract_files_lack_nosniff() {
    // C16.1 does not require nosniff on the five files; the documented static snippet sets it. WARN, not FAIL.
    let dir = temp_dir("warn-files-nosniff");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let origin = fake_origin(FakeOrigin {
        files: true,
        echo: true,
        files_nosniff: false,
        echo_nosniff: true,
        extra_echo: Vec::new(),
        drop_first: false,
        ..FakeOrigin::default()
    });
    let base = format!("http://{origin}");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args(["--local-only", "--direct-url", &base])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a WARN does not fail the run:\n{t}"
    );
    let direct = line_with(&t, "CANARY-DIRECT");
    assert!(direct.contains("WARN"), "{t}");
    assert!(direct.contains("C16.1"), "{t}");
    assert!(line_with(&t, "CANARY-ECHO").contains("PASS"), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_parsing_verify_fails_the_echo_without_nosniff() {
    // C16 (docs/SPEC.md line 3877) requires nosniff on the echo JSON itself.
    let dir = temp_dir("fail-echo-nosniff");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let origin = fake_origin(FakeOrigin {
        files: true,
        echo: true,
        files_nosniff: true,
        echo_nosniff: false,
        extra_echo: Vec::new(),
        drop_first: false,
        ..FakeOrigin::default()
    });
    let base = format!("http://{origin}");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args(["--local-only", "--through-url", &base])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    let echo = line_with(&t, "CANARY-ECHO");
    assert!(echo.contains("FAIL"), "{t}");
    assert!(echo.contains("nosniff"), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------------------------------------
// Static install declaration (C16 intro): the echo endpoint legitimately does not exist
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn t0210_parsing_verify_reports_a_static_install_echo_as_unverified() {
    let dir = temp_dir("static-echo");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let origin = fake_origin(FakeOrigin {
        files: true,
        echo: false,
        files_nosniff: true,
        echo_nosniff: true,
        file_headers: vec![("Server".to_owned(), "Hack-Dev-Defence".to_owned())],
        ..FakeOrigin::default()
    });
    let base = format!("http://{origin}");
    let profile_dir = temp_dir("static-echo-profile");
    let profile = write_profile(&profile_dir, &base, "''", false);
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args([
            "--file",
            profile.to_str().expect("utf-8"),
            "--direct-url",
            &base,
            "--through-url",
            &base,
        ])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "UNVERIFIED keeps exit 0:\n{t}");
    let echo = line_with(&t, "CANARY-ECHO");
    assert!(echo.contains("UNVERIFIED(capability_not_supplied)"), "{t}");
    assert!(echo.contains("origin_access_log"), "{t}");
    assert!(
        line_with(&t, "CANARY-HDD").contains("PASS"),
        "the files themselves are a static-install capability:\n{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&profile_dir);
}

#[test]
fn t0210_parsing_verify_a_missing_echo_endpoint_fails_when_the_sidecar_is_expected() {
    let dir = temp_dir("expected-echo");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let origin = fake_origin(FakeOrigin {
        files: true,
        echo: false,
        files_nosniff: true,
        echo_nosniff: true,
        extra_echo: Vec::new(),
        drop_first: false,
        ..FakeOrigin::default()
    });
    let base = format!("http://{origin}");
    let profile_dir = temp_dir("expected-echo-profile");
    let profile = write_profile(&profile_dir, &base, "''", true);
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args([
            "--file",
            profile.to_str().expect("utf-8"),
            "--direct-url",
            &base,
        ])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    let echo = line_with(&t, "CANARY-ECHO");
    assert!(echo.contains("FAIL"), "{t}");
    assert!(echo.contains("sidecar"), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&profile_dir);
}

// ---------------------------------------------------------------------------------------------------------------------
// Remaining A1/A5 checks
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn t0210_verify_detects_served_bytes_that_differ_from_the_contract() {
    // manifest directory A is clean; the sidecar serves a tampered copy B
    let clean = temp_dir("verify-clean");
    let served = temp_dir("verify-tampered-served");
    assert_eq!(generate(&clean).status.code(), Some(0));
    assert_eq!(generate(&served).status.code(), Some(0));
    std::fs::write(served.join("static.js"), b"tampered").expect("tamper");
    let sidecar = start_sidecar(&served);
    let origin = format!("http://{}", sidecar.local_addr());
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&clean)
        .args(["--local-only", "--direct-url", &origin])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(line_with(&t, "CANARY-MANIFEST").contains("PASS"), "{t}");
    let direct_line = line_with(&t, "CANARY-DIRECT");
    assert!(direct_line.contains("FAIL"), "{t}");
    assert!(direct_line.contains("static.js"), "{t}");
    let _ = std::fs::remove_dir_all(&clean);
    let _ = std::fs::remove_dir_all(&served);
}

#[test]
fn t0210_verify_detects_a_tampered_or_missing_manifest() {
    let dir = temp_dir("verify-tampered-dir");
    assert_eq!(generate(&dir).status.code(), Some(0));
    std::fs::write(dir.join("leak.txt"), b"edited").expect("tamper");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    let manifest = line_with(&t, "CANARY-MANIFEST");
    assert!(manifest.contains("FAIL"), "{t}");
    assert!(manifest.contains("leak.txt"), "{t}");

    let none = temp_dir("verify-no-dir");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&none)
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(line_with(&t, "CANARY-MANIFEST").contains("FAIL"), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&none);
}

#[test]
fn t0210_verify_without_a_dir_reports_the_manifest_half_unverified() {
    let dir = temp_dir("verify-nodir");
    let out = hddctl()
        .args([
            "canary",
            "verify",
            "--file",
            dir.join("absent.yaml").to_str().expect("utf-8"),
        ])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    let manifest = line_with(&t, "CANARY-MANIFEST");
    assert!(
        manifest.contains("UNVERIFIED(capability_not_supplied)"),
        "{t}"
    );
    assert!(manifest.contains("--dir"), "says what to pass: {t}");
    for rule in ["CANARY-DIRECT", "CANARY-HDD", "CANARY-QUERY", "CANARY-ECHO"] {
        let line = line_with(&t, rule);
        assert!(
            line.contains("UNVERIFIED(human_step_pending)"),
            "{rule}: {t}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_verify_fails_a_broken_profile_instead_of_a_fake_pass() {
    let dir = temp_dir("verify-bad-profile");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let profile = dir.join("hdd.live.yaml");
    std::fs::write(&profile, "this: [is not a profile\n").expect("write");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args(["--file", profile.to_str().expect("utf-8")])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(
        line_with(&t, "CANARY-PROFILE").contains("FAIL"),
        "a profile that exists but cannot be read is a FAIL:\n{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_parsing_verify_retries_one_transient_connection_error() {
    let dir = temp_dir("retry-transient");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let origin = fake_origin(FakeOrigin {
        files: true,
        echo: false,
        files_nosniff: true,
        echo_nosniff: true,
        extra_echo: Vec::new(),
        drop_first: true,
        ..FakeOrigin::default()
    });
    let base = format!("http://{origin}");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args(["--local-only", "--direct-url", &base])
        .output()
        .expect("run");
    let t = text(&out);
    assert!(
        line_with(&t, "CANARY-DIRECT").contains("PASS"),
        "one transient reset is retried once, so the direct check passes:\n{t}"
    );
    assert!(line_with(&t, "CANARY-QUERY").contains("PASS"), "{t}");
    assert_eq!(
        out.status.code(),
        Some(0),
        "a retried transient error is not a FAIL:\n{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------------------------------------
// K-2 / K-5: HDD-specific evidence only (these are parsing tests: the fake origin prints what it is told, so they prove
// the evidence rules, not that a real HDD edge handled anything)
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn t0210_parsing_verify_a_different_host_is_not_hdd_evidence() {
    // Two loopback addresses (127.0.0.1 and 127.0.0.2) serve the same bytes and the through echo even reports an
    // X-Forwarded-For; none of that is HDD-specific evidence, so CANARY-HDD must be UNVERIFIED(capability_not_supplied).
    let dir = temp_dir("host-differs");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let direct = fake_origin(FakeOrigin {
        files: true,
        files_nosniff: true,
        ..FakeOrigin::default()
    });
    let through = fake_origin(FakeOrigin {
        bind_ip: "127.0.0.2",
        files: true,
        echo: true,
        files_nosniff: true,
        echo_nosniff: true,
        extra_echo: vec![("x-forwarded-for".to_owned(), "198.51.100.7".to_owned())],
        ..FakeOrigin::default()
    });
    let direct_url = format!("http://{direct}");
    let through_url = format!("http://{through}");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args([
            "--local-only",
            "--direct-url",
            &direct_url,
            "--through-url",
            &through_url,
        ])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    let hdd = line_with(&t, "CANARY-HDD");
    assert!(
        hdd.contains("UNVERIFIED(capability_not_supplied)"),
        "a different host is not HDD evidence:\n{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_parsing_verify_through_hdd_passes_on_a_server_header() {
    let dir = temp_dir("hdd-server-header");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let through = fake_origin(FakeOrigin {
        files: true,
        files_nosniff: true,
        file_headers: vec![("Server".to_owned(), "Hack-Dev-Defence".to_owned())],
        ..FakeOrigin::default()
    });
    let through_url = format!("http://{through}");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args(["--local-only", "--through-url", &through_url])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    let hdd = line_with(&t, "CANARY-HDD");
    assert!(hdd.contains("PASS"), "{t}");
    assert!(
        hdd.contains("Server: Hack-Dev-Defence") || hdd.contains("Hack-Dev-Defence"),
        "the PASS names the response header evidence:\n{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_parsing_verify_through_hdd_passes_on_a_ray_id_header() {
    let dir = temp_dir("hdd-ray-id");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let through = fake_origin(FakeOrigin {
        files: true,
        files_nosniff: true,
        file_headers: vec![("HDD-Ray-ID".to_owned(), "ray-012345".to_owned())],
        ..FakeOrigin::default()
    });
    let through_url = format!("http://{through}");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args(["--local-only", "--through-url", &through_url])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    let hdd = line_with(&t, "CANARY-HDD");
    assert!(hdd.contains("PASS"), "{t}");
    assert!(hdd.contains("HDD-Ray-ID"), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_parsing_verify_through_hdd_passes_on_correlated_connecting_ip() {
    let dir = temp_dir("hdd-connecting-ip");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let through = fake_origin(FakeOrigin {
        files: true,
        echo: true,
        files_nosniff: true,
        echo_nosniff: true,
        extra_echo: vec![("hdd-connecting-ip".to_owned(), "198.51.100.7".to_owned())],
        ..FakeOrigin::default()
    });
    let through_url = format!("http://{through}");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args([
            "--local-only",
            "--through-url",
            &through_url,
            "--runner-ip",
            "198.51.100.7",
        ])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    let hdd = line_with(&t, "CANARY-HDD");
    // P-7: a connecting-IP echo alone is shown and compared, not a PASS; only response headers make it evidence.
    assert!(hdd.contains("UNVERIFIED(capability_not_supplied)"), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_parsing_verify_static_install_passes_through_hdd_on_a_server_header() {
    // K-5: a static install has no echo endpoint, but the HDD response headers on the files are still evidence.
    let dir = temp_dir("static-hdd-evidence");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let origin = fake_origin(FakeOrigin {
        files: true,
        echo: false,
        files_nosniff: true,
        file_headers: vec![("Server".to_owned(), "Hack-Dev-Defence".to_owned())],
        ..FakeOrigin::default()
    });
    let base = format!("http://{origin}");
    let profile_dir = temp_dir("static-hdd-evidence-profile");
    let profile = write_profile(&profile_dir, &base, "127.0.0.1", false);
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args([
            "--file",
            profile.to_str().expect("utf-8"),
            "--direct-url",
            &base,
            "--through-url",
            &base,
        ])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(
        line_with(&t, "CANARY-HDD").contains("PASS"),
        "the HDD response header is the evidence a static install can supply:\n{t}"
    );
    assert!(
        line_with(&t, "CANARY-ECHO").contains("UNVERIFIED(capability_not_supplied)"),
        "without the sidecar the per-request header echo stays unverified:\n{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&profile_dir);
}

#[test]
fn t0210_parsing_verify_reports_the_origin_auth_presence_without_its_value() {
    // K-1: `canary verify` recognises that HDD-Origin-Auth is present (the sidecar already reduced it to v1;<kid>).
    let dir = temp_dir("origin-auth-presence");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let through = fake_origin(FakeOrigin {
        files: true,
        echo: true,
        files_nosniff: true,
        echo_nosniff: true,
        extra_echo: vec![("hdd-origin-auth".to_owned(), "v1;k1".to_owned())],
        ..FakeOrigin::default()
    });
    let through_url = format!("http://{through}");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args(["--local-only", "--through-url", &through_url])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    let echo = line_with(&t, "CANARY-ECHO");
    assert!(echo.contains("PASS"), "{t}");
    assert!(
        echo.contains("HDD-Origin-Auth") && echo.contains("v1;k1"),
        "the presence and key id are reported, the rest never is:\n{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------------------------------------
// K-6: transport error classes
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn t0210_verify_kill_switch_abort_is_skipped_by_operator() {
    let dir = temp_dir("kill-switch");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let sidecar = start_sidecar(&dir);
    let origin = format!("http://{}", sidecar.local_addr());
    let kill = dir.join("hdd-acceptance.stop");
    std::fs::write(&kill, b"stop").expect("kill switch");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args([
            "--local-only",
            "--direct-url",
            &origin,
            "--kill-switch",
            kill.to_str().expect("utf-8"),
        ])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(
        out.status.code(),
        Some(0),
        "an operator kill-switch stop is UNVERIFIED, not a FAIL:\n{t}"
    );
    assert!(
        line_with(&t, "CANARY-DIRECT").contains("UNVERIFIED(skipped_by_operator)"),
        "{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_verify_response_too_large_is_its_own_failure() {
    let dir = temp_dir("too-large");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let origin = fake_origin(FakeOrigin {
        files: true,
        files_nosniff: true,
        oversize: true,
        ..FakeOrigin::default()
    });
    let base = format!("http://{origin}");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args(["--local-only", "--direct-url", &base])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    let direct = line_with(&t, "CANARY-DIRECT");
    assert!(direct.contains("FAIL"), "{t}");
    assert!(
        direct.contains("larger than") || direct.contains("response size"),
        "the too-large class has its own message:\n{t}"
    );
    assert!(
        !direct.contains("Fix the origin/reverse proxy"),
        "a size-cap violation is not an origin defect:\n{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_verify_uses_only_the_closed_reason_set() {
    // The spec closes the reason set (section 0.4 / E3.1): exactly these eight codes, anything else is FAIL.
    const CLOSED: &[&str] = &[
        "capability_not_supplied",
        "human_step_pending",
        "environment_unsupported",
        "oracle_unavailable",
        "tool_unavailable",
        "stage_not_reached",
        "stage_forbids",
        "skipped_by_operator",
    ];
    let dir = temp_dir("reason-set");
    let out = hddctl()
        .args([
            "canary",
            "verify",
            "--file",
            dir.join("absent.yaml").to_str().expect("utf-8"),
        ])
        .output()
        .expect("run");
    let t = text(&out);
    let mut seen = 0usize;
    for line in t.lines() {
        let mut rest = line;
        while let Some(start) = rest.find("UNVERIFIED(") {
            let after = &rest[start + "UNVERIFIED(".len()..];
            let Some(end) = after.find(')') else { break };
            let reason = &after[..end];
            assert!(
                CLOSED.contains(&reason),
                "reason `{reason}` is outside the closed set:\n{line}"
            );
            seen += 1;
            rest = &after[end..];
        }
    }
    assert!(seen >= 4, "the run must exercise UNVERIFIED lines: {t}");
}

// ---------------------------------------------------------------------------------------------------------------------
// Round 3: Q-1 (delegation semantics), Q-2 (HDD-specific runner evidence), Q-5 (scheme/port), Q-7 (symlinked dir)
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn t0210_verify_non_200_through_response_does_not_claim_no_response_arrived() {
    // Q-1: a response arrived (HTTP 404) but the files are not served there; that is a FAIL and the message must not say
    // "no response arrived".
    let dir = temp_dir("non-200-through");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let through = fake_origin(FakeOrigin {
        files: false,
        ..FakeOrigin::default()
    });
    let base = format!("http://{through}");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args(["--local-only", "--through-url", &base])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    let hdd = line_with(&t, "CANARY-HDD");
    assert!(hdd.contains("FAIL"), "{t}");
    assert!(
        hdd.contains("HTTP 404") || hdd.contains("HTTP 4"),
        "the message reports the arrived status:\n{t}"
    );
    assert!(
        !hdd.contains("no response arrived"),
        "a response did arrive; that phrase is wrong here:\n{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_parsing_echo_and_hdd_agree_on_the_runner_claim() {
    // P-7/P-8: without --with-spoof-probe the forwarding claim is shown but not asserted; with it, a HDD-built chain
    // agrees with a response-header proof. Neither an X-Real-IP (erroneous) nor a connecting-IP echo alone is a PASS.
    let dir = temp_dir("echo-hdd-agree");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let run = |origin: std::net::SocketAddr, spoof: bool| {
        let base = format!("http://{origin}");
        let mut command = hddctl();
        command.args(["canary", "verify", "--dir"]).arg(&dir);
        command.args([
            "--local-only",
            "--through-url",
            &base,
            "--runner-ip",
            "198.51.100.7",
        ]);
        if spoof {
            command.arg("--with-spoof-probe");
        }
        command.output().expect("run")
    };
    let with_x_real_ip = fake_origin(FakeOrigin {
        files: true,
        echo: true,
        files_nosniff: true,
        echo_nosniff: true,
        extra_echo: vec![("x-real-ip".to_owned(), "198.51.100.7".to_owned())],
        ..FakeOrigin::default()
    });
    let t = text(&run(with_x_real_ip, false));
    assert!(
        t.contains("spoof probe (--with-spoof-probe): disabled"),
        "P-8 prints the disabled default before sending:\n{t}"
    );
    assert!(
        line_with(&t, "CANARY-ECHO").contains("UNVERIFIED(capability_not_supplied)"),
        "{t}"
    );
    assert!(
        line_with(&t, "CANARY-HDD").contains("UNVERIFIED(capability_not_supplied)"),
        "{t}"
    );
    let connecting = fake_origin(FakeOrigin {
        files: true,
        echo: true,
        files_nosniff: true,
        echo_nosniff: true,
        extra_echo: vec![("hdd-connecting-ip".to_owned(), "198.51.100.7".to_owned())],
        ..FakeOrigin::default()
    });
    let t = text(&run(connecting, false));
    assert!(
        line_with(&t, "CANARY-ECHO").contains("UNVERIFIED(capability_not_supplied)"),
        "{t}"
    );
    assert!(
        line_with(&t, "CANARY-HDD").contains("UNVERIFIED(capability_not_supplied)"),
        "{t}"
    );
    let proven = fake_origin(FakeOrigin {
        files: true,
        echo: true,
        files_nosniff: true,
        echo_nosniff: true,
        file_headers: vec![("Server".to_owned(), "Hack-Dev-Defence".to_owned())],
        extra_echo: vec![("x-forwarded-for".to_owned(), "198.51.100.7".to_owned())],
        ..FakeOrigin::default()
    });
    let t = text(&run(proven, true));
    assert!(line_with(&t, "CANARY-ECHO").contains("PASS"), "{t}");
    assert!(line_with(&t, "CANARY-HDD").contains("PASS"), "{t}");
    assert!(
        t.contains("spoof probe (--with-spoof-probe): enabled"),
        "{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
#[test]
fn t0210_verify_profile_overrides_must_match_scheme_and_port() {
    // Q-5: with a profile, an override must use the profile's own scheme and port for that host.
    let dir = temp_dir("scheme-port");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let origin = fake_origin(FakeOrigin {
        files: true,
        files_nosniff: true,
        ..FakeOrigin::default()
    });
    let origin_url = format!("http://{origin}");
    let profile_dir = temp_dir("scheme-port-profile");
    let profile = write_profile(&profile_dir, &origin_url, "''", true);
    // wrong scheme: https to a plain-HTTP profile origin
    let wrong_scheme = origin_url.replace("http://", "https://");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args([
            "--file",
            profile.to_str().expect("utf-8"),
            "--direct-url",
            &wrong_scheme,
        ])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(
        line_with(&t, "CANARY-TARGET").contains("FAIL"),
        "the scheme must match the profile:\n{t}"
    );
    // wrong port: another port on the profile origin host
    let wrong_port = format!("http://{}:9", origin.ip());
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args([
            "--file",
            profile.to_str().expect("utf-8"),
            "--direct-url",
            &wrong_port,
        ])
        .output()
        .expect("run");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(
        line_with(&t, "CANARY-TARGET").contains("FAIL"),
        "the port must match the profile origin URL:\n{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&profile_dir);
}

#[test]
fn t0210_verify_lockdown_applied_direct_reason_is_stage_not_reached() {
    // Q-8: skipping the direct probe because the origin lockdown (STOP #2) is applied is a stage condition.
    let dir = temp_dir("stage-not-reached");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let profile_dir = temp_dir("stage-not-reached-profile");
    let profile = write_profile_full(&profile_dir, "http://127.0.0.1:9", "''", true, "applied");
    let out = hddctl()
        .args(["canary", "verify", "--dir"])
        .arg(&dir)
        .args(["--file", profile.to_str().expect("utf-8")])
        .output()
        .expect("run");
    let t = text(&out);
    assert!(
        line_with(&t, "CANARY-DIRECT").contains("UNVERIFIED(stage_not_reached)"),
        "the applied lockdown is a stage condition:\n{t}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&profile_dir);
}

#[cfg(windows)]
#[test]
fn t0210_start_refuses_a_symlinked_root_directory_when_the_privilege_exists() {
    // Q-7: a symlinked --root is checked. Creating a directory symlink needs a privilege on Windows; when it is not
    // available the check reports UNVERIFIED(environment_unsupported) instead of pretending to run.
    let real = temp_dir("root-real");
    hdd_canary::generate(&real, DEFAULT_BASE_PATH).expect("generate");
    let link_parent = temp_dir("root-link");
    let link = link_parent.join("canary-root");
    if std::os::windows::fs::symlink_dir(&real, &link).is_err() {
        eprintln!(
            "UNVERIFIED(environment_unsupported): cannot create a directory symlink on this host (Q-7)"
        );
        return;
    }
    let config = hdd_canary::Config::new(
        "127.0.0.1:0".parse().expect("addr"),
        &link,
        DEFAULT_BASE_PATH,
    )
    .expect("config");
    let error = hdd_canary::start(config).expect_err("a symlinked root must be refused");
    assert!(error.to_string().contains("symbolic link"), "{error}");
    let _ = std::fs::remove_dir_all(&real);
    let _ = std::fs::remove_dir_all(&link_parent);
}

#[test]
fn t0210_parsing_spoof_probe_requires_a_hdd_rebuilt_forwarded_chain() {
    // P-7/P-8: the spoof probe is opt-in. A HDD-built XFF shape is shown but UNVERIFIED without a response-header proof;
    // a surviving spoof is a FAIL; a response header plus the rebuilt shape is a PASS.
    let dir = temp_dir("spoof-probe");
    assert_eq!(generate(&dir).status.code(), Some(0));
    let run = |origin: std::net::SocketAddr| {
        let base = format!("http://{origin}");
        hddctl()
            .args(["canary", "verify", "--dir"])
            .arg(&dir)
            .args([
                "--local-only",
                "--through-url",
                &base,
                "--runner-ip",
                "198.51.100.7",
                "--with-spoof-probe",
            ])
            .output()
            .expect("run")
    };
    let hdd_built = fake_origin(FakeOrigin {
        files: true,
        echo: true,
        files_nosniff: true,
        echo_nosniff: true,
        extra_echo: vec![("x-forwarded-for".to_owned(), "198.51.100.7".to_owned())],
        ..FakeOrigin::default()
    });
    let t = text(&run(hdd_built));
    assert!(
        line_with(&t, "CANARY-ECHO").contains("UNVERIFIED(capability_not_supplied)"),
        "{t}"
    );
    assert!(
        line_with(&t, "CANARY-HDD").contains("UNVERIFIED(capability_not_supplied)"),
        "{t}"
    );
    let spoof_survived = fake_origin(FakeOrigin {
        files: true,
        echo: true,
        files_nosniff: true,
        echo_nosniff: true,
        extra_echo: vec![(
            "x-forwarded-for".to_owned(),
            "198.51.100.7, 203.0.113.99".to_owned(),
        )],
        ..FakeOrigin::default()
    });
    let t = text(&run(spoof_survived));
    assert!(line_with(&t, "CANARY-ECHO").contains("FAIL"), "{t}");
    assert!(line_with(&t, "CANARY-HDD").contains("FAIL"), "{t}");
    assert!(
        t.contains("203.0.113.99"),
        "the failing condition is named:\n{t}"
    );
    let terminator = fake_origin(FakeOrigin {
        files: true,
        echo: true,
        files_nosniff: true,
        echo_nosniff: true,
        reflect_forwarding: true,
        append_to_reflected_xff: Some("198.51.100.7".to_owned()),
        ..FakeOrigin::default()
    });
    let t = text(&run(terminator));
    assert!(line_with(&t, "CANARY-ECHO").contains("FAIL"), "{t}");
    assert!(line_with(&t, "CANARY-HDD").contains("FAIL"), "{t}");
    let proven = fake_origin(FakeOrigin {
        files: true,
        echo: true,
        files_nosniff: true,
        echo_nosniff: true,
        file_headers: vec![("Server".to_owned(), "Hack-Dev-Defence".to_owned())],
        extra_echo: vec![("x-forwarded-for".to_owned(), "198.51.100.7".to_owned())],
        ..FakeOrigin::default()
    });
    let t = text(&run(proven));
    assert!(line_with(&t, "CANARY-ECHO").contains("PASS"), "{t}");
    assert!(line_with(&t, "CANARY-HDD").contains("PASS"), "{t}");
    let _ = std::fs::remove_dir_all(&dir);
}
