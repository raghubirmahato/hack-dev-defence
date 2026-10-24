//! Stub-server tests for the advisory DeepSeek AI client and the explain handler contract (COLLAB.md Addendum 6 item 3).
//!
//! Every test uses a local stub HTTP server and a fake key lookup with a canary value: no real API key exists anywhere in
//! the tree and no test ever writes the canary to a file. The tests assert the pinned behaviour: only allowed finding
//! facts reach the model, the answer is validated/capped and stays plain text, network and HTTP failures degrade to an
//! error (never a panic), the per-finding cache and the sliding-hour rate limit work, and the key never appears in the
//! response body, the runtime's debug output, an error message or a file on disk.
//! R-33 stays the rule behind all of it: the AI text is advisory, it never decides a block or a ban, and the
//! deterministic verdict remains authoritative.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use hdd_proxy::ai::{AI_LABEL, AiRuntime, KeyLookup};
use hdd_proxy::api::{CodeExampleView, FindingView, RemediationView};
use hdd_proxy::config::Config;

/// The canary "API key" the fake lookup returns; it must never reach an output or a file.
const CANARY_KEY: &str = "sk-canary-0123456789abcdef-DO-NOT-LEAK"; // hdd-secret-scan:allow (test-only canary value, never a real key)
/// The environment variable name the test configuration points at (the value is injected, never set in the process).
const KEY_ENV: &str = "HDD_AI_TEST_KEY";

static UNIQUE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
enum StubResponse {
    Json(String),
    Http500,
    Delay(Duration, String),
}

#[derive(Clone, Debug)]
struct Captured {
    head: String,
    body: String,
}

struct Stub {
    address: SocketAddr,
    hits: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Captured>>>,
}

impl Stub {
    fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn captured(&self) -> Vec<Captured> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .unwrap_or_default()
    }
}

fn start_stub(response: StubResponse) -> Result<Stub, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let hits = Arc::new(AtomicUsize::new(0));
    let requests: Arc<Mutex<Vec<Captured>>> = Arc::new(Mutex::new(Vec::new()));
    let thread_hits = Arc::clone(&hits);
    let thread_requests = Arc::clone(&requests);
    std::thread::spawn(move || {
        loop {
            let Ok((mut stream, _peer)) = listener.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let Some(captured) = read_request(&mut stream) else {
                return;
            };
            thread_hits.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut list) = thread_requests.lock() {
                list.push(captured);
            }
            let (status, body, delay) = match &response {
                StubResponse::Json(body) => ("HTTP/1.1 200 OK", body.clone(), Duration::ZERO),
                StubResponse::Http500 => (
                    "HTTP/1.1 500 Internal Server Error",
                    "{\"error\":\"stub failure\"}".to_owned(),
                    Duration::ZERO,
                ),
                StubResponse::Delay(delay, body) => ("HTTP/1.1 200 OK", body.clone(), *delay),
            };
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            let header = format!(
                "{status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
    });
    Ok(Stub {
        address,
        hits,
        requests,
    })
}

fn read_request(stream: &mut TcpStream) -> Option<Captured> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = find_header_end(&buffer) {
            let head = String::from_utf8_lossy(buffer.get(..end)?).into_owned();
            let content_length = parse_content_length(&head)?;
            let body_start = end + 4;
            while buffer.len() < body_start.saturating_add(content_length) {
                let read = stream.read(&mut chunk).ok()?;
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(chunk.get(..read)?);
            }
            let body = String::from_utf8_lossy(buffer.get(body_start..)?).into_owned();
            return Some(Captured { head, body });
        }
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(chunk.get(..read)?);
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(head: &str) -> Option<usize> {
    head.split("\r\n").find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse::<usize>().ok()
        } else {
            None
        }
    })
}

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let unique = UNIQUE.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("hdd-ai-client-{tag}-{nanos}-{unique}"))
}

/// Build an `AiRuntime` whose `ai.base_url` points at the local stub and whose key comes from the fake lookup.
fn runtime_for_stub(
    stub: &Stub,
    timeout_s: u32,
    max_calls_per_hour: u32,
    key: Option<&str>,
) -> Result<(AiRuntime, PathBuf), String> {
    let directory = temp_dir("config");
    std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let data_dir = directory.join("data");
    std::fs::create_dir_all(&data_dir).map_err(|error| error.to_string())?;
    let config_path = directory.join("hdd.yaml");
    let data = data_dir.to_string_lossy().replace('\\', "/");
    let log_path = directory
        .join("events.jsonl")
        .to_string_lossy()
        .replace('\\', "/");
    let yaml = format!(
        "listen: \"127.0.0.1:0\"\n\
         admin_listen: \"127.0.0.1:0\"\n\
         data_dir: \"{data}\"\n\
         log_path: \"{log_path}\"\n\
         admin_token_env: \"HDD_AI_TEST_ADMIN_TOKEN\"\n\
         ai:\n\
         \x20 provider: deepseek\n\
         \x20 base_url: \"{base}\"\n\
         \x20 model: deepseek-flash\n\
         \x20 api_key_env: \"{KEY_ENV}\"\n\
         \x20 timeout_s: {timeout_s}\n\
         \x20 max_calls_per_hour: {max_calls_per_hour}\n\
         sites:\n\
         \x20 - host: \"demo.example.com\"\n\
         \x20   origin: \"http://127.0.0.1:9\"\n\
         \x20   mode: block\n",
        base = stub.url(),
    );
    std::fs::write(&config_path, yaml).map_err(|error| error.to_string())?;
    let config = Config::load(&config_path).map_err(|error| error.message)?;
    let validated = config.validate().map_err(|error| error.message)?;
    let key_owned = key.map(str::to_owned);
    let lookup: KeyLookup = Arc::new(move |name: &str| {
        if name == KEY_ENV {
            key_owned.clone()
        } else {
            None
        }
    });
    Ok((AiRuntime::new(&validated, lookup), directory))
}

fn finding(id: &str) -> FindingView {
    FindingView {
        id: id.to_owned(),
        site: "demo.example.com".to_owned(),
        method: "POST".to_owned(),
        path: "/admin/login".to_owned(),
        vector: "form_body".to_owned(),
        field: "username".to_owned(),
        field_kind: "username".to_owned(),
        rule_id: "H1-001".to_owned(),
        family: "tautology".to_owned(),
        category: "sqli".to_owned(),
        first_seen: "2026-10-23T20:00:00.000Z".to_owned(),
        last_seen: "2026-10-23T20:05:00.000Z".to_owned(),
        count: 3,
        evidence: "admin'--".to_owned(),
        detected:
            "SQL injection by comment break-out in form field `username` of POST /admin/login"
                .to_owned(),
        inferred_weakness: "the backend probably concatenates this field into the WHERE clause"
            .to_owned(),
        attacker_impact: "login bypass to an administrator session".to_owned(),
        confidence: "attempt_observed".to_owned(),
        remediation: RemediationView {
            steps: vec!["use a parameterised query".to_owned()],
            code_example: CodeExampleView {
                language: "node".to_owned(),
                caption: "parameterised query".to_owned(),
                code: "db.query('SELECT 1 WHERE name = ?', [name])".to_owned(),
            },
            virtual_patch_note: "a virtual patch is not a fix".to_owned(),
        },
        stack: "node".to_owned(),
        ai: None,
    }
}

fn envelope(summary: &str, impact: &[&str], steps: &[&str], code: Option<&str>) -> String {
    let content = json!({
        "summary": summary,
        "attacker_impact": impact,
        "remediation_steps": steps,
        "code_example": code.map(|code| json!({
            "language": "node",
            "caption": "parameterised query",
            "code": code,
        })),
    });
    json!({ "choices": [ { "message": { "content": content.to_string() } } ] }).to_string()
}

fn body_of(captured: &Captured) -> Result<Value, String> {
    serde_json::from_str(&captured.body).map_err(|error| error.to_string())
}

fn failures(directory: &Path) -> Result<Vec<(PathBuf, String)>, String> {
    let mut files = Vec::new();
    collect_files(directory, &mut files)?;
    let mut contents = Vec::new();
    for file in files {
        if let Ok(bytes) = std::fs::read(&file) {
            contents.push((file, String::from_utf8_lossy(&bytes).into_owned()));
        }
    }
    Ok(contents)
}

fn collect_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(directory).map_err(|error| error.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, files)?;
        } else {
            files.push(path);
        }
    }
    Ok(())
}

#[test]
fn a_valid_answer_is_parsed_and_the_prompt_carries_only_allowed_facts() {
    let stub = start_stub(StubResponse::Json(envelope(
        "The username field is concatenated into the SQL query.",
        &["Log in as an administrator."],
        &["Use a parameterised query."],
        Some("db.query('SELECT * FROM users WHERE name = ?', [name])"),
    )))
    .expect("stub server starts");
    let (runtime, _directory) = runtime_for_stub(&stub, 10, 30, Some(CANARY_KEY)).expect("runtime");

    assert!(runtime.enabled());
    assert_eq!(runtime.model(), Some("deepseek-flash"));
    let explanation = runtime
        .explain(&finding("finding-1"), "en")
        .expect("a valid answer parses");
    assert_eq!(explanation.label, AI_LABEL);
    assert_eq!(explanation.model, "deepseek-flash");
    assert!(explanation.generated_at.ends_with('Z'));
    assert!(explanation.summary.contains("concatenated"));
    assert_eq!(explanation.attacker_impact.len(), 1);
    assert_eq!(explanation.remediation_steps.len(), 1);
    assert!(explanation.code_example.is_some());

    assert_eq!(stub.hits(), 1, "exactly one model call was made");
    let captured = stub
        .captured()
        .first()
        .cloned()
        .expect("one captured request");
    assert!(
        captured.head.contains("POST /chat/completions"),
        "request target: {}",
        captured.head
    );
    let body = body_of(&captured).expect("request body is JSON");
    assert_eq!(
        body.get("model").and_then(Value::as_str),
        Some("deepseek-flash")
    );
    assert_eq!(
        body.get("response_format")
            .and_then(|format| format.get("type"))
            .and_then(Value::as_str),
        Some("json_object")
    );
    let messages = body
        .get("messages")
        .and_then(Value::as_array)
        .expect("messages array");
    assert_eq!(messages.len(), 2);
    let facts = messages
        .get(1)
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .expect("user facts string");
    for allowed in [
        "\"family\":\"tautology\"",
        "\"rule_id\":\"H1-001\"",
        "\"vector\":\"form_body\"",
        "\"field_kind\":\"username\"",
        "\"method\":\"POST\"",
        "\"path\":\"/admin/login\"",
        "\"evidence_redacted\":\"admin'--\"",
        "\"stack_hint\":\"node\"",
        "\"language\":\"en\"",
    ] {
        assert!(
            facts.contains(allowed),
            "the prompt must carry the allowed fact {allowed}"
        );
    }
    for forbidden in [
        "cookie",
        "session",
        "authorization",
        "password",
        "demo.example.com",
        CANARY_KEY,
    ] {
        assert!(
            !facts.to_lowercase().contains(&forbidden.to_lowercase()),
            "the prompt must not carry {forbidden}"
        );
    }
    // The key is in the Authorization header by design, but never in the body.
    assert!(
        captured
            .head
            .to_lowercase()
            .contains("authorization: bearer sk-canary-"),
        "the request must authenticate with the looked-up key"
    );
    assert!(
        !captured.body.contains(CANARY_KEY),
        "the key must never be in the request body"
    );
}

#[test]
fn oversize_parts_are_capped_before_they_leave_the_runtime() {
    let long_summary = "a".repeat(5000);
    let long_items: Vec<String> = vec!["b".repeat(900); 20];
    let long_code = "c".repeat(10_000);
    let content = json!({
        "summary": long_summary,
        "attacker_impact": long_items,
        "remediation_steps": long_items,
        "code_example": { "language": "node", "caption": "cap", "code": long_code },
    });
    let stub = start_stub(StubResponse::Json(
        json!({ "choices": [ { "message": { "content": content.to_string() } } ] }).to_string(),
    ))
    .expect("stub server starts");
    let (runtime, _directory) = runtime_for_stub(&stub, 10, 30, Some(CANARY_KEY)).expect("runtime");
    let explanation = runtime
        .explain(&finding("finding-oversize"), "en")
        .expect("oversize answer is capped, not rejected");
    assert!(explanation.summary.chars().count() <= 1000);
    assert!(explanation.attacker_impact.len() <= 8);
    assert!(explanation.remediation_steps.len() <= 10);
    assert!(
        explanation
            .attacker_impact
            .iter()
            .all(|item| item.chars().count() <= 500)
    );
    assert!(
        explanation
            .remediation_steps
            .iter()
            .all(|item| item.chars().count() <= 500)
    );
    if let Some(code_example) = explanation.code_example {
        assert!(code_example.code.chars().count() <= 4000);
    }
}

#[test]
fn html_and_script_text_stays_plain_text() {
    let stub = start_stub(StubResponse::Json(envelope(
        "<script>alert('xss')</script>",
        &["<img src=x onerror=alert(1)>"],
        &["<b>escape output</b>"],
        None,
    )))
    .expect("stub server starts");
    let (runtime, _directory) = runtime_for_stub(&stub, 10, 30, Some(CANARY_KEY)).expect("runtime");
    let explanation = runtime
        .explain(&finding("finding-html"), "en")
        .expect("HTML-looking text is accepted as plain text");
    assert!(
        explanation
            .summary
            .contains("<script>alert('xss')</script>")
    );
    let serialized = serde_json::to_string(&explanation).expect("serialises");
    assert!(
        serialized.contains("<script>alert('xss')</script>"),
        "the text is data, never interpreted markup"
    );
    assert!(
        !serialized.contains("\\u003c"),
        "no double escaping was added by the runtime"
    );
}

#[test]
fn a_timeout_is_an_error_never_a_panic() {
    let stub = start_stub(StubResponse::Delay(
        Duration::from_secs(4),
        envelope("late", &[], &[], None),
    ))
    .expect("stub server starts");
    let (runtime, _directory) = runtime_for_stub(&stub, 1, 30, Some(CANARY_KEY)).expect("runtime");
    let started = Instant::now();
    let result = runtime.explain(&finding("finding-timeout"), "en");
    let elapsed = started.elapsed();
    assert!(result.is_err(), "a timeout must be an error, not a verdict");
    assert!(
        elapsed < Duration::from_secs(4),
        "the total timeout must fire before the stub answers"
    );
    let message = result.err().unwrap_or_default();
    assert!(
        message.to_lowercase().contains("timeout"),
        "unexpected error: {message}"
    );
    assert!(!message.contains(CANARY_KEY));
}

#[test]
fn an_http_error_degrades_to_an_error_without_leaking_the_key() {
    let stub = start_stub(StubResponse::Http500).expect("stub server starts");
    let (runtime, _directory) = runtime_for_stub(&stub, 10, 30, Some(CANARY_KEY)).expect("runtime");
    let result = runtime.explain(&finding("finding-http"), "en");
    assert!(result.is_err());
    let message = result.err().unwrap_or_default();
    assert!(message.contains("500"), "unexpected error: {message}");
    assert!(!message.contains(CANARY_KEY));
    assert!(!message.to_lowercase().contains("authorization"));
}

#[test]
fn ai_is_disabled_without_the_key_and_makes_no_call() {
    let stub = start_stub(StubResponse::Json(envelope("unused", &[], &[], None)))
        .expect("stub server starts");
    let (runtime, _directory) = runtime_for_stub(&stub, 10, 30, None).expect("runtime");
    assert!(!runtime.enabled());
    assert_eq!(runtime.model(), None);
    assert_eq!(
        runtime.explain(&finding("finding-disabled"), "en").err(),
        Some("disabled".to_owned())
    );
    assert_eq!(
        stub.hits(),
        0,
        "a disabled runtime never touches the network"
    );
}

#[test]
fn the_cache_avoids_a_second_model_call() {
    let stub = start_stub(StubResponse::Json(envelope(
        "cached answer",
        &["impact"],
        &["fix"],
        None,
    )))
    .expect("stub server starts");
    let (runtime, _directory) = runtime_for_stub(&stub, 10, 30, Some(CANARY_KEY)).expect("runtime");
    let first = runtime
        .explain(&finding("finding-cache"), "en")
        .expect("first call");
    let second = runtime
        .explain(&finding("finding-cache"), "en")
        .expect("second call");
    assert_eq!(first, second);
    assert_eq!(
        stub.hits(),
        1,
        "the second call must come from the per-finding cache"
    );
    assert!(runtime.cached("finding-cache").is_some());
    assert!(runtime.cached("finding-unknown").is_none());
}

#[test]
fn the_sliding_hour_rate_limit_stops_extra_calls() {
    let stub = start_stub(StubResponse::Json(envelope("once", &[], &[], None)))
        .expect("stub server starts");
    let (runtime, _directory) = runtime_for_stub(&stub, 10, 1, Some(CANARY_KEY)).expect("runtime");
    runtime
        .explain(&finding("finding-rate-1"), "en")
        .expect("the first call is within budget");
    let second = runtime.explain(&finding("finding-rate-2"), "en");
    assert_eq!(second.err(), Some("rate_limited".to_owned()));
    assert_eq!(
        stub.hits(),
        1,
        "the rate-limited call must not reach the provider"
    );
}

#[test]
fn the_key_never_reaches_an_output_log_or_file() {
    let stub = start_stub(StubResponse::Json(envelope(
        "safe answer",
        &["impact"],
        &["fix"],
        Some("db.query('?', [name])"),
    )))
    .expect("stub server starts");
    let (runtime, directory) = runtime_for_stub(&stub, 10, 30, Some(CANARY_KEY)).expect("runtime");
    let explanation = runtime
        .explain(&finding("finding-key"), "en")
        .expect("call succeeds");

    // API-shaped outputs: the explanation itself, its JSON, the runtime debug output and an error path.
    let json = serde_json::to_string(&explanation).expect("serialises");
    let debug = format!("{explanation:?}");
    let runtime_debug = format!("{runtime:?}");
    for output in [&json, &debug, &runtime_debug] {
        assert!(
            !output.contains(CANARY_KEY),
            "the key must never appear in an output"
        );
    }
    assert!(!runtime_debug.contains(KEY_ENV) || runtime_debug.contains("configured"));

    // Network artefacts: the request body and all captured request bodies must not carry the value.
    for captured in stub.captured() {
        assert!(
            !captured.body.contains(CANARY_KEY),
            "the request body must never contain the key"
        );
    }

    // Files written by the proxy: the test configuration directory is the only place state could land.
    for (path, contents) in failures(&directory).expect("walks the test directory") {
        assert!(
            !contents.contains(CANARY_KEY),
            "the key must never be written to {}",
            path.display()
        );
    }

    // The same holds for error paths.
    let failing_stub = start_stub(StubResponse::Http500).expect("stub server starts");
    let (failing_runtime, _directory) =
        runtime_for_stub(&failing_stub, 10, 30, Some(CANARY_KEY)).expect("runtime");
    let error = failing_runtime
        .explain(&finding("finding-key-error"), "en")
        .err()
        .unwrap_or_default();
    assert!(!error.contains(CANARY_KEY));
}

/// The live admin route calls `ai_api::handle` from `tokio::task::spawn_blocking`; that worker has a `Handle` in its
/// thread-local context but is not an async executor. `explain` must work there (end-to-end regression).
#[tokio::test]
async fn explain_works_inside_spawn_blocking_like_the_admin_route() {
    let stub = start_stub(StubResponse::Json(envelope(
        "explained from the blocking worker",
        &["impact"],
        &["fix"],
        None,
    )))
    .expect("stub server starts");
    let (runtime, _directory) = runtime_for_stub(&stub, 10, 30, Some(CANARY_KEY)).expect("runtime");
    let runtime = Arc::new(runtime);
    let runtime_for_job = Arc::clone(&runtime);
    let finding = finding("finding-spawn-blocking");
    let joined = tokio::task::spawn_blocking(move || runtime_for_job.explain(&finding, "en")).await;
    let explanation = joined
        .expect("the blocking task completes")
        .expect("explain must succeed from spawn_blocking, not report a context error");
    assert_eq!(explanation.label, AI_LABEL);
    assert!(explanation.summary.contains("blocking worker"));
    assert_eq!(stub.hits(), 1);
}

/// Calling `explain` from inside an async task is a misuse (the admin route never does it): it must return a sanitized
/// error instead of panicking the worker.
#[tokio::test]
async fn explain_from_an_async_task_returns_an_error_instead_of_panicking() {
    let stub = start_stub(StubResponse::Json(envelope("unused", &[], &[], None)))
        .expect("stub server starts");
    let (runtime, _directory) = runtime_for_stub(&stub, 10, 30, Some(CANARY_KEY)).expect("runtime");
    let result = runtime.explain(&finding("finding-misuse"), "en");
    assert!(result.is_err(), "an async-context misuse must be an error");
    let message = result.err().unwrap_or_default();
    assert!(
        message.to_lowercase().contains("blocking"),
        "the error should point at the blocking-worker requirement: {message}"
    );
    assert!(!message.contains(CANARY_KEY));
    assert_eq!(
        stub.hits(),
        0,
        "no provider call is attempted from the misuse path"
    );
}
