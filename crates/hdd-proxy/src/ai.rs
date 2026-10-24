//! The optional DeepSeek advisory explanation client (COLLAB.md Addendum 6 item 3).
//!
//! The AI never decides block/ban and never changes a verdict (R-33): it only turns the already-deterministic facts of
//! one finding into advisory prose that the operator is told to verify. The model is called through the one egress path
//! ([`hdd_common::egress::Client`], R-22) with an allowlist built from exactly the configured `ai.base_url` host/port, never
//! from caller data.
//!
//! Secret handling: [`AiRuntime`] stores only the *name* of the environment variable (`api_key_env`, default
//! `DEEPSEEK_API_KEY`) and the injected lookup closure. The key value is read at call time, used for one
//! `Authorization: Bearer` header and then dropped; it is never stored in the runtime, never written to a file or the
//! event log, never logged, and never included in an error message or API response.
//!
//! The prompt carries only the allowed finding facts (family, rule id, vector, field kind, method, path, redacted
//! evidence, stack hint, requested language): no cookies, tokens, bodies, other fields, query strings or values.
//! The answer is parsed as JSON, validated and capped, and handed back as plain data so the UI can render it as escaped
//! text only.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hdd_common::egress::allow::Allowlist;
use hdd_common::egress::{Client, EgressConfig, Limits, Request};
use serde::Deserialize;

use crate::api::{AiExplanationView, CodeExampleView, FindingView};
use crate::config::Validated;

/// The label every AI explanation carries in the API and the UI.
pub const AI_LABEL: &str = "AI-generated, verify before use";

/// The default environment variable holding the DeepSeek API key (the configuration may rename it).
pub const DEFAULT_API_KEY_ENV: &str = "DEEPSEEK_API_KEY";

/// Maximum characters kept from the model's summary.
const MAX_SUMMARY_CHARS: usize = 1000;
/// Maximum number of attacker-impact bullets kept.
const MAX_IMPACT_ITEMS: usize = 8;
/// Maximum number of remediation steps kept.
const MAX_STEPS_ITEMS: usize = 10;
/// Maximum characters kept from one bullet or step.
const MAX_ITEM_CHARS: usize = 500;
/// Maximum characters kept from the code example.
const MAX_CODE_CHARS: usize = 4000;
/// Maximum characters kept across the whole explanation.
const MAX_TOTAL_CHARS: usize = 20_000;
/// Maximum characters kept from the code-example caption.
const MAX_CAPTION_CHARS: usize = 240;
/// Maximum characters kept from the code language label.
const MAX_LANGUAGE_CHARS: usize = 32;
/// The bounded per-finding explanation cache size.
const CACHE_CAPACITY: usize = 128;
/// The sliding window of the call rate limit, in seconds.
const RATE_WINDOW_SECONDS: u64 = 60 * 60;
/// The instruction given to the model; it must answer with the documented JSON shape only.
const SYSTEM_PROMPT: &str = "You explain a detected SQL-injection finding to the owner of the affected website. \
Answer with one JSON object only, no markdown and no prose outside it, with exactly these keys: \
\"summary\" (one short paragraph), \"attacker_impact\" (an array of short bullets describing what an attacker could do \
if the request had reached the application), \"remediation_steps\" (an ordered array of concrete fix steps), and \
\"code_example\" (an object with \"language\", \"caption\" and \"code\", or null). Base every statement only on the \
provided facts; do not invent data, do not claim the application is definitely vulnerable, and do not decide whether \
the request should be blocked.";

/// The resolved, non-secret AI settings extracted from one validated configuration.
#[derive(Debug, Clone)]
struct AiSettings {
    base_url: String,
    model: String,
    api_key_env: String,
    timeout: Duration,
    max_calls_per_hour: u32,
}

impl AiSettings {
    fn from_config(config: &Validated) -> Option<Self> {
        let ai = config.ai.as_ref()?;
        if ai.provider != "deepseek" || ai.base_url.trim().is_empty() || ai.model.trim().is_empty()
        {
            return None;
        }
        Some(Self {
            base_url: ai.base_url.trim_end_matches('/').to_owned(),
            model: ai.model.clone(),
            api_key_env: ai.api_key_env.clone(),
            timeout: Duration::from_secs(u64::from(ai.timeout_s)),
            max_calls_per_hour: ai.max_calls_per_hour,
        })
    }
}

/// The per-finding cache and the sliding-hour call limiter, both bounded.
#[derive(Debug, Default)]
struct AiState {
    cache: VecDeque<(String, AiExplanationView)>,
    calls: VecDeque<u64>,
}

/// The injected environment lookup: given the configured environment-variable name, return its value (or `None`).
///
/// The lookup is called at use time; the runtime never stores the returned value.
pub type KeyLookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The advisory AI explanation runtime. Construct once and share it through `AppState`.
pub struct AiRuntime {
    settings: Option<AiSettings>,
    key_lookup: KeyLookup,
    client: Option<Result<Client, String>>,
    state: Mutex<AiState>,
}

impl AiRuntime {
    /// Build the runtime from the validated configuration and the environment lookup.
    ///
    /// The lookup is called with `ai.api_key_env` at use time, so a key set after start-up is picked up and the runtime
    /// never holds the value. A configuration without an `ai` block (or a non-DeepSeek configuration) is a valid,
    /// permanently disabled runtime.
    #[must_use]
    pub fn new(config: &Validated, key_lookup: KeyLookup) -> AiRuntime {
        let settings = AiSettings::from_config(config);
        let client = settings.as_ref().map(|settings| {
            let allowlist =
                Allowlist::parse(std::slice::from_ref(&settings.base_url)).map_err(|errors| {
                    let detail = errors
                        .first()
                        .map(|(index, error)| format!("entry {index}: {error}"))
                        .unwrap_or_else(|| "empty allowlist".to_owned());
                    format!(
                        "the ai.base_url `{}` is not a usable egress destination: {detail}",
                        settings.base_url
                    )
                })?;
            let limits = Limits {
                connect_timeout: settings.timeout,
                total_timeout: settings.timeout,
                max_response_bytes: 256 * 1024,
                max_request_bytes: 64 * 1024,
            };
            Client::with_config(allowlist, EgressConfig::new("hdd-proxy-ai").limits(limits))
        });
        Self {
            settings,
            key_lookup,
            client,
            state: Mutex::new(AiState::default()),
        }
    }

    /// Whether AI explanations are configured, the provider is DeepSeek and the API key variable is set.
    ///
    /// The lookup is evaluated on every call; the value is not kept here.
    #[must_use]
    pub fn enabled(&self) -> bool {
        let Some(settings) = self.settings.as_ref() else {
            return false;
        };
        self.key_present(settings)
    }

    /// The configured model name, or `None` when AI explanations are off.
    #[must_use]
    pub fn model(&self) -> Option<&str> {
        let settings = self.settings.as_ref()?;
        if self.key_present(settings) {
            Some(settings.model.as_str())
        } else {
            None
        }
    }

    /// The cached explanation for one finding, if a previous call succeeded.
    #[must_use]
    pub fn cached(&self, finding_id: &str) -> Option<AiExplanationView> {
        let state = self.state.lock().ok()?;
        state
            .cache
            .iter()
            .find(|(cached_id, _)| cached_id == finding_id)
            .map(|(_, explanation)| explanation.clone())
    }

    /// Ask the model to explain one finding. Advisory text only; this never touches a verdict, ban or block decision.
    ///
    /// The call is synchronous (the frozen interface around the async egress client). The caller must run it on a
    /// blocking worker, for example `tokio::task::spawn_blocking` as the admin route does; a blocking-pool thread is not
    /// an async executor, so the private request runtime is legal there. Calling it directly from inside an async task
    /// is a misuse that returns a sanitized error instead of panicking the worker (R-09).
    ///
    /// # Errors
    /// Returns `"disabled"` when no `ai` block is configured or the key variable is unset, `"rate_limited"` when the
    /// configured calls-per-hour budget is exhausted, and a human message (never containing the API key) for network,
    /// HTTP or answer-validation failures.
    pub fn explain(
        &self,
        finding: &FindingView,
        language: &str,
    ) -> Result<AiExplanationView, String> {
        let settings = self
            .settings
            .as_ref()
            .ok_or_else(|| "disabled".to_owned())?;
        let key = self
            .lookup_key(settings)
            .ok_or_else(|| "disabled".to_owned())?;
        if let Some(cached) = self.cached(&finding.id) {
            return Ok(cached);
        }
        self.check_rate_limit(settings.max_calls_per_hour)?;
        let client = match self.client.as_ref() {
            Some(Ok(client)) => client,
            Some(Err(reason)) => return Err(reason.clone()),
            None => return Err("disabled".to_owned()),
        };
        let request = self.build_request(settings, finding, language, &key)?;
        self.record_call();
        let outcome = run_blocking(client.send(request))?;
        let response = outcome.map_err(|error| format!("the AI request failed: {error}"))?;
        if response.status != 200 {
            return Err(format!("the AI provider returned HTTP {}", response.status));
        }
        let explanation = parse_explanation(&response.body, &settings.model)?;
        self.store_cached(&finding.id, &explanation);
        Ok(explanation)
    }

    fn key_present(&self, settings: &AiSettings) -> bool {
        self.lookup_key(settings).is_some()
    }

    fn lookup_key(&self, settings: &AiSettings) -> Option<String> {
        let key = (self.key_lookup)(&settings.api_key_env)?;
        let key = key.trim().to_owned();
        if key.is_empty() { None } else { Some(key) }
    }

    fn build_request(
        &self,
        settings: &AiSettings,
        finding: &FindingView,
        language: &str,
        key: &str,
    ) -> Result<Request, String> {
        let facts = allowed_facts(finding, language);
        let facts_json = serde_json::to_string(&facts)
            .map_err(|error| format!("cannot serialise the AI prompt facts: {error}"))?;
        let body = serde_json::json!({
            "model": settings.model,
            "messages": [
                { "role": "system", "content": SYSTEM_PROMPT },
                { "role": "user", "content": facts_json },
            ],
            "response_format": { "type": "json_object" },
            "temperature": 0.2,
            "max_tokens": 1200,
        });
        let body = serde_json::to_vec(&body)
            .map_err(|error| format!("cannot serialise the AI request body: {error}"))?;
        let url = format!("{}/chat/completions", settings.base_url);
        Ok(Request::post(url, body)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Authorization", &format!("Bearer {key}")))
    }

    fn check_rate_limit(&self, max_calls_per_hour: u32) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "the AI state lock was poisoned".to_owned())?;
        let now = now_unix();
        while state
            .calls
            .front()
            .is_some_and(|started| now.saturating_sub(*started) >= RATE_WINDOW_SECONDS)
        {
            state.calls.pop_front();
        }
        let budget = usize::try_from(max_calls_per_hour).unwrap_or(usize::MAX);
        if state.calls.len() >= budget {
            return Err("rate_limited".to_owned());
        }
        Ok(())
    }

    fn record_call(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.calls.push_back(now_unix());
        }
    }

    fn store_cached(&self, finding_id: &str, explanation: &AiExplanationView) {
        if let Ok(mut state) = self.state.lock() {
            state.cache.retain(|(cached_id, _)| cached_id != finding_id);
            state
                .cache
                .push_back((finding_id.to_owned(), explanation.clone()));
            while state.cache.len() > CACHE_CAPACITY {
                state.cache.pop_front();
            }
        }
    }
}

impl std::fmt::Debug for AiRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AiRuntime")
            .field("configured", &self.settings.is_some())
            .field("enabled", &self.enabled())
            .field(
                "model",
                &self
                    .settings
                    .as_ref()
                    .map(|settings| settings.model.as_str()),
            )
            .finish_non_exhaustive()
    }
}

/// The only facts that may be sent to the model. Anything else about the request stays local.
fn allowed_facts(finding: &FindingView, language: &str) -> serde_json::Value {
    let evidence = finding.evidence.chars().take(128).collect::<String>();
    serde_json::json!({
        "family": finding.family,
        "rule_id": finding.rule_id,
        "vector": finding.vector,
        "field_kind": finding.field_kind,
        "method": finding.method,
        "path": finding.path,
        "evidence_redacted": evidence,
        "stack_hint": finding.stack,
        "language": sanitize_language(language),
    })
}

/// Keep the requested language to a short, safe label (it is only a prompt fact).
fn sanitize_language(language: &str) -> String {
    let filtered = language
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .take(16)
        .collect::<String>();
    if filtered.is_empty() {
        "en".to_owned()
    } else {
        filtered
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Run the async egress call from the synchronous interface.
///
/// The pinned interface is synchronous, so this builds a private single-threaded runtime and drives the egress future on
/// it. That is legal from a blocking worker (`tokio::task::spawn_blocking`, which is how `admin.rs` calls the handler):
/// a blocking-pool thread only has a current `Handle`, it is not an async executor, so a nested runtime is allowed.
/// Calling `explain` directly from an async task is a misuse; rather than panicking the caller's worker (R-09), the
/// whole nested-runtime call is caught and turned into a sanitized error.
fn run_blocking<F>(future: F) -> Result<F::Output, String>
where
    F: std::future::Future,
{
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("cannot start the AI request runtime: {error}"))?;
        Ok::<F::Output, String>(runtime.block_on(future))
    }));
    match outcome {
        Ok(result) => result,
        Err(_) => Err(
            "the AI explanation could not run in this context; it must be called from a blocking worker"
                .to_owned(),
        ),
    }
}

#[derive(Debug, Deserialize)]
struct RawEnvelope {
    #[serde(default)]
    choices: Vec<RawChoice>,
}

#[derive(Debug, Deserialize)]
struct RawChoice {
    #[serde(default)]
    message: Option<RawMessage>,
}

#[derive(Debug, Deserialize)]
struct RawMessage {
    #[serde(default)]
    content: String,
}

#[derive(Debug, Default, Deserialize)]
struct RawExplanation {
    #[serde(default)]
    summary: String,
    #[serde(default)]
    attacker_impact: Vec<String>,
    #[serde(default)]
    remediation_steps: Vec<String>,
    #[serde(default)]
    code_example: Option<RawCodeExample>,
}

#[derive(Debug, Default, Deserialize)]
struct RawCodeExample {
    #[serde(default)]
    language: String,
    #[serde(default)]
    caption: String,
    #[serde(default)]
    code: String,
}

/// Parse, sanitise and cap one model answer. Malformed or empty answers are rejected; oversize parts are cut.
fn parse_explanation(body: &[u8], model: &str) -> Result<AiExplanationView, String> {
    let envelope: RawEnvelope = serde_json::from_slice(body).map_err(|_| {
        "the AI provider returned a response that is not the documented JSON envelope".to_owned()
    })?;
    let content = envelope
        .choices
        .first()
        .and_then(|choice| choice.message.as_ref())
        .map(|message| message.content.as_str())
        .filter(|content| !content.trim().is_empty())
        .ok_or_else(|| "the AI provider returned an empty answer".to_owned())?;
    let raw: RawExplanation = serde_json::from_str(content).map_err(|_| {
        "the AI provider returned an answer that is not the documented JSON object".to_owned()
    })?;
    let summary = cap_text(&sanitize_text(&raw.summary, false), MAX_SUMMARY_CHARS);
    if summary.is_empty() {
        return Err("the AI provider returned an empty summary".to_owned());
    }
    let attacker_impact = cap_items(&raw.attacker_impact, MAX_IMPACT_ITEMS);
    let remediation_steps = cap_items(&raw.remediation_steps, MAX_STEPS_ITEMS);
    let code_example = raw
        .code_example
        .as_ref()
        .map(sanitize_code_example)
        .filter(|code_example| !code_example.code.is_empty());
    let total = summary.chars().count()
        + attacker_impact
            .iter()
            .map(|item| item.chars().count())
            .sum::<usize>()
        + remediation_steps
            .iter()
            .map(|item| item.chars().count())
            .sum::<usize>()
        + code_example
            .as_ref()
            .map(|code_example| code_example.code.chars().count())
            .unwrap_or(0);
    if total > MAX_TOTAL_CHARS {
        return Err("the AI answer is larger than the allowed size".to_owned());
    }
    Ok(AiExplanationView {
        summary,
        attacker_impact,
        remediation_steps,
        code_example,
        generated_at: crate::util::rfc3339_now(),
        model: model.to_owned(),
        label: AI_LABEL.to_owned(),
    })
}

fn sanitize_text(value: &str, keep_layout: bool) -> String {
    let filtered = value
        .chars()
        .filter(|character| {
            !character.is_control() || (keep_layout && matches!(character, '\n' | '\r' | '\t'))
        })
        .collect::<String>();
    filtered.trim().to_owned()
}

fn cap_text(value: &str, maximum: usize) -> String {
    value
        .chars()
        .take(maximum)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn cap_items(items: &[String], maximum_items: usize) -> Vec<String> {
    items
        .iter()
        .map(|item| cap_text(&sanitize_text(item, false), MAX_ITEM_CHARS))
        .filter(|item| !item.is_empty())
        .take(maximum_items)
        .collect()
}

fn sanitize_code_example(raw: &RawCodeExample) -> CodeExampleView {
    let language = cap_text(&sanitize_text(&raw.language, false), MAX_LANGUAGE_CHARS);
    let caption = cap_text(&sanitize_text(&raw.caption, false), MAX_CAPTION_CHARS);
    let code = cap_text(&sanitize_text(&raw.code, true), MAX_CODE_CHARS);
    CodeExampleView {
        language: if language.is_empty() {
            "other".to_owned()
        } else {
            language
        },
        caption,
        code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn explanation_content(
        summary: &str,
        impact: &[&str],
        steps: &[&str],
        code: Option<&str>,
    ) -> String {
        let payload = serde_json::json!({
            "summary": summary,
            "attacker_impact": impact,
            "remediation_steps": steps,
            "code_example": code.map(|code| serde_json::json!({
                "language": "node",
                "caption": "parameterised query",
                "code": code,
            })),
        });
        let envelope = serde_json::json!({
            "choices": [ { "message": { "content": payload.to_string() } } ],
        });
        envelope.to_string()
    }

    #[test]
    fn a_valid_answer_is_parsed_and_labelled() {
        let body = explanation_content(
            "The username field is concatenated into a SQL query.",
            &["Log in as an administrator."],
            &["Use a parameterised query."],
            Some("db.query('SELECT * FROM users WHERE name = ?', [name])"),
        );
        let parsed = parse_explanation(body.as_bytes(), "deepseek-flash");
        assert!(parsed.is_ok());
        if let Ok(view) = parsed {
            assert_eq!(
                view.summary,
                "The username field is concatenated into a SQL query."
            );
            assert_eq!(view.attacker_impact.len(), 1);
            assert_eq!(view.remediation_steps.len(), 1);
            assert!(view.code_example.is_some());
            assert_eq!(view.model, "deepseek-flash");
            assert_eq!(view.label, AI_LABEL);
            assert!(view.generated_at.ends_with('Z'));
        }
    }

    #[test]
    fn oversize_parts_are_capped() {
        let long_summary = "a".repeat(5000);
        let long_items = vec!["b".repeat(900); 20];
        let long_code = "c".repeat(10_000);
        let content = serde_json::json!({
            "summary": long_summary,
            "attacker_impact": long_items,
            "remediation_steps": long_items,
            "code_example": { "language": "node", "caption": "x", "code": long_code },
        });
        let envelope =
            serde_json::json!({ "choices": [ { "message": { "content": content.to_string() } } ] });
        let parsed = parse_explanation(envelope.to_string().as_bytes(), "deepseek-flash");
        assert!(parsed.is_ok());
        if let Ok(view) = parsed {
            assert!(view.summary.chars().count() <= MAX_SUMMARY_CHARS);
            assert!(view.attacker_impact.len() <= MAX_IMPACT_ITEMS);
            assert!(view.remediation_steps.len() <= MAX_STEPS_ITEMS);
            assert!(
                view.attacker_impact
                    .iter()
                    .all(|item| item.chars().count() <= MAX_ITEM_CHARS)
            );
            if let Some(code_example) = view.code_example {
                assert!(code_example.code.chars().count() <= MAX_CODE_CHARS);
            }
        }
    }

    #[test]
    fn html_looking_text_stays_plain_text() {
        let body = explanation_content(
            "<script>alert('xss')</script> and <b>bold</b>",
            &["<img src=x onerror=alert(1)>"],
            &["escape output"],
            None,
        );
        let parsed = parse_explanation(body.as_bytes(), "deepseek-flash");
        assert!(parsed.is_ok());
        if let Ok(view) = parsed {
            assert!(view.summary.contains("<script>alert('xss')</script>"));
            assert!(
                view.attacker_impact
                    .first()
                    .is_some_and(|item| item.contains("<img"))
            );
        }
    }

    #[test]
    fn malformed_envelopes_and_empty_answers_are_rejected() {
        assert!(parse_explanation(b"not json", "m").is_err());
        let empty = serde_json::json!({ "choices": [] });
        assert!(parse_explanation(empty.to_string().as_bytes(), "m").is_err());
        let no_summary = serde_json::json!({
            "choices": [ { "message": { "content": "{\"summary\":\"\",\"attacker_impact\":[]}" } } ],
        });
        assert!(parse_explanation(no_summary.to_string().as_bytes(), "m").is_err());
        let bad_content = serde_json::json!({ "choices": [ { "message": { "content": "[]" } } ] });
        assert!(parse_explanation(bad_content.to_string().as_bytes(), "m").is_err());
    }

    #[test]
    fn the_requested_language_is_sanitised_to_a_short_label() {
        assert_eq!(sanitize_language("en"), "en");
        assert_eq!(sanitize_language("pt-BR"), "pt-BR");
        assert_eq!(sanitize_language(""), "en");
        assert_eq!(sanitize_language("en\ninjected: true"), "eninjectedtrue");
        assert!(sanitize_language("x".repeat(100).as_str()).chars().count() <= 16);
    }
}
