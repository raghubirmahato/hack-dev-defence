//! The `POST /api/findings/{id}/explain` handler (COLLAB.md Addendum 6 item 3).
//!
//! The handler is deliberately thin: it looks up the deterministic finding, answers from the bounded per-finding cache
//! when possible, reports `disabled`/`rate_limited` as documented states, and otherwise asks the advisory AI runtime.
//! The API key is never part of any request or response here; the runtime reads it from the environment lookup at call
//! time and the key never appears in a message this module returns.

use crate::api::{self, ApiError, ApiResponse, ExplainRequest, ExplainResponse};
use crate::state::AppState;

/// The message shown when no `ai` block is configured or the key environment variable is unset.
const DISABLED_MESSAGE: &str = "AI explanations are off. Set the configured API key environment variable (DEEPSEEK_API_KEY by default) and the \
     deterministic finding text stays available without it.";
/// The message shown when the configured calls-per-hour budget is exhausted.
const RATE_LIMITED_MESSAGE: &str = "AI explanation rate limit reached for this hour. The deterministic finding text is still available.";

/// Handle one explain request. `principal` is the authenticated caller (the admin gate has already enforced auth and
/// the viewer rules; an explanation is advisory read-only output, so any authenticated role may ask for it).
#[must_use]
pub fn handle(
    state: &AppState,
    principal: &api::Principal,
    finding_id: &str,
    body: &[u8],
) -> api::ApiResponse {
    let _ = principal;
    let request: ExplainRequest = if body.is_empty() {
        ExplainRequest::default()
    } else {
        match serde_json::from_slice(body) {
            Ok(request) => request,
            Err(_) => return ApiError::bad_request("invalid JSON body").into_response(),
        }
    };
    let language = request.language.unwrap_or_else(|| "en".to_owned());
    let Some(finding) = state.findings.get(finding_id) else {
        return ApiError::not_found("no such finding").into_response();
    };
    if let Some(explanation) = state.ai.cached(finding_id) {
        return ApiResponse::json(&ExplainResponse {
            status: "ok".to_owned(),
            explanation: Some(explanation),
            message: "cached explanation".to_owned(),
            cached: true,
        });
    }
    if !state.ai.enabled() {
        return ApiResponse::json(&disabled_response());
    }
    match state.ai.explain(&finding, &language) {
        Ok(explanation) => ApiResponse::json(&ExplainResponse {
            status: "ok".to_owned(),
            explanation: Some(explanation),
            message: String::new(),
            cached: false,
        }),
        Err(error) if error == "rate_limited" => ApiResponse::json(&rate_limited_response()),
        Err(error) if error == "disabled" => ApiResponse::json(&disabled_response()),
        Err(error) => ApiResponse::json(&ExplainResponse {
            status: "error".to_owned(),
            explanation: None,
            // The runtime's error messages never contain the API key or request headers (ai.rs returns fixed wording
            // plus the HTTP status / egress reason only).
            message: format!("AI explanation failed: {error}"),
            cached: false,
        }),
    }
}

/// The documented `disabled` response shape (HTTP 200; the UI shows the hint and keeps the deterministic text).
#[must_use]
pub fn disabled_response() -> ExplainResponse {
    ExplainResponse {
        status: "disabled".to_owned(),
        explanation: None,
        message: DISABLED_MESSAGE.to_owned(),
        cached: false,
    }
}

/// The documented `rate_limited` response shape (HTTP 200; no model call was made).
#[must_use]
pub fn rate_limited_response() -> ExplainResponse {
    ExplainResponse {
        status: "rate_limited".to_owned(),
        explanation: None,
        message: RATE_LIMITED_MESSAGE.to_owned(),
        cached: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_and_rate_limited_responses_are_honest_and_leak_nothing() {
        let disabled = disabled_response();
        assert_eq!(disabled.status, "disabled");
        assert!(disabled.explanation.is_none());
        assert!(disabled.message.contains("DEEPSEEK_API_KEY"));
        assert!(!disabled.message.to_lowercase().contains("bearer"));
        let limited = rate_limited_response();
        assert_eq!(limited.status, "rate_limited");
        assert!(limited.explanation.is_none());
        assert!(!limited.message.is_empty());
        assert!(!limited.message.to_lowercase().contains("key="));
    }

    #[test]
    fn the_status_strings_match_the_frozen_contract() {
        // ExplainResponse documents exactly these four statuses.
        for status in [disabled_response().status, rate_limited_response().status] {
            assert!(
                matches!(
                    status.as_str(),
                    "ok" | "disabled" | "rate_limited" | "error"
                ),
                "unexpected status {status}"
            );
        }
    }
}
