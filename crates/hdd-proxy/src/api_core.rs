//! The core admin API handlers (events, bans, sites, mode/strictness/rules, inspect, block preview).
//!
//! Every handler is synchronous and returns an [`ApiResponse`]; the async endpoints (lock-down check and verify) live in
//! [`crate::admin`] because they send probe requests. Every mutation bumps the configuration revision and writes an
//! audit line; responses never echo a secret value.

use std::net::IpAddr;
use std::sync::Arc;

use hdd_waf_core::{FieldKind, InspectInput, SiteSettings, Vector};
use serde::de::DeserializeOwned;

use crate::api::{
    self, ApiError, ApiResponse, BansResponse, BlockPreviewResponse, ConnectionMethod,
    EventsResponse, InspectRequest, InspectResponse, Mode, ModeChangeRequest, OkResponse,
    RuleCreateRequest, RuleDeleteRequest, SetupInstructions, SiteCreateRequest, SiteCreateResponse,
    SiteRemoveRequest, SitesResponse, StrictnessChangeRequest,
};
use crate::config;
use crate::events::EventFilter;
use crate::state::{AppState, SiteRuntime};
use crate::util::{self, Origin};

/// The default `GET /api/events` limit.
pub const DEFAULT_EVENT_LIMIT: usize = 200;
/// The largest `GET /api/events` limit.
pub const MAX_EVENT_LIMIT: usize = api::EVENT_RING_CAPACITY;

/// The `{"ok": true}` response.
#[must_use]
pub fn ok() -> ApiResponse {
    ApiResponse::json(&OkResponse { ok: true })
}

/// A 404 for a host that is not configured.
#[must_use]
pub fn host_not_found(host: &str) -> ApiResponse {
    ApiError::not_found(format!("no site is configured for host `{host}`")).into_response()
}

/// Deserialize a JSON request body, turning a parse failure into a typed API error.
///
/// # Errors
/// Returns [`ApiError::bad_request`] when the body is not valid JSON for `T`.
pub fn parse_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|_| ApiError::bad_request("invalid JSON request body"))
}

/// Write one audit line for an admin mutation (the target and detail never contain a secret).
pub fn audit(state: &AppState, actor: &str, action: &str, target: &str, detail: &str) {
    state
        .events
        .audit(actor, action, target, util::truncate_utf8(detail, 512));
}

/// Finish a mutation: bump the revision, persist wizard-created sites and audit.
pub fn finish_mutation(state: &AppState, actor: &str, action: &str, target: &str, detail: &str) {
    state.bump_revision();
    audit(state, actor, action, target, detail);
    if let Err(error) = state.persist_dynamic_sites_if_any() {
        audit(state, "system", "persist_error", target, &error.message);
    }
}

/// `GET /healthz`.
#[must_use]
pub fn health(state: &AppState) -> ApiResponse {
    ApiResponse::json(&state.health())
}

/// `GET /api/events?site=&action=&q=&limit=`.
#[must_use]
pub fn events(state: &AppState, query: &[(String, String)]) -> ApiResponse {
    let value = |name: &str| {
        query
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    let limit = value("limit")
        .and_then(|text| text.parse::<usize>().ok())
        .unwrap_or(DEFAULT_EVENT_LIMIT)
        .clamp(1, MAX_EVENT_LIMIT);
    let events = state.events.query(&EventFilter {
        site: value("site"),
        action: value("action"),
        q: value("q"),
        limit,
    });
    ApiResponse::json(&EventsResponse {
        events,
        counters: state.counters(),
        sites: state.hosts(),
    })
}

/// `GET /api/bans`.
#[must_use]
pub fn bans(state: &AppState) -> ApiResponse {
    ApiResponse::json(&BansResponse {
        bans: state.bans.list(),
    })
}

/// `POST /api/bans/{ip}/delete`.
#[must_use]
pub fn delete_ban(state: &AppState, ip_text: &str, actor: &str) -> ApiResponse {
    let Ok(ip) = ip_text.trim().parse::<IpAddr>() else {
        return ApiError::bad_request(format!("`{ip_text}` is not a valid IP address"))
            .into_response();
    };
    if !state.bans.remove(ip) {
        return ApiError::not_found(format!("no active ban for `{ip}`")).into_response();
    }
    finish_mutation(
        state,
        actor,
        "ban.removed",
        &ip.to_string(),
        "ban removed through the admin API",
    );
    ok()
}

/// `GET /api/sites`.
#[must_use]
pub fn sites(state: &AppState) -> ApiResponse {
    ApiResponse::json(&SitesResponse {
        sites: state.site_views(),
        counters: state.counters(),
    })
}

/// `GET /api/sites/{host}`.
#[must_use]
pub fn site(state: &AppState, host: &str) -> ApiResponse {
    match state.site(host) {
        Some(site) => ApiResponse::json(&site.view()),
        None => host_not_found(host),
    }
}

/// `POST /api/sites/{host}/mode`.
#[must_use]
pub fn change_mode(state: &AppState, host: &str, body: &[u8], actor: &str) -> ApiResponse {
    let Some(site) = state.site(host) else {
        return host_not_found(host);
    };
    let request: ModeChangeRequest = match parse_body(body) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    if request.mode == Mode::Off && request.confirm.as_deref() != Some("off") {
        return ApiError::bad_request(
            "switching protection to `off` requires the typed confirmation {\"confirm\":\"off\"} (R-28)",
        )
        .into_response();
    }
    let previous = site.mode();
    site.set_mode(request.mode);
    finish_mutation(
        state,
        actor,
        "mode.change",
        site.host(),
        &format!(
            "{} -> {} by {actor}",
            previous.as_str(),
            request.mode.as_str()
        ),
    );
    ok()
}

/// `POST /api/sites/{host}/strictness`.
#[must_use]
pub fn change_strictness(state: &AppState, host: &str, body: &[u8], actor: &str) -> ApiResponse {
    let Some(site) = state.site(host) else {
        return host_not_found(host);
    };
    let request: StrictnessChangeRequest = match parse_body(body) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let previous = site.set_strictness(request.strictness);
    finish_mutation(
        state,
        actor,
        "strictness.change",
        site.host(),
        &format!("{:?} -> {:?} by {actor}", previous, request.strictness),
    );
    ok()
}

/// `POST /api/sites/{host}/rules`.
#[must_use]
pub fn add_rule(state: &AppState, host: &str, body: &[u8], actor: &str) -> ApiResponse {
    let Some(site) = state.site(host) else {
        return host_not_found(host);
    };
    let request: RuleCreateRequest = match parse_body(body) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = config::validate_custom_rule(&request.rule) {
        return ApiError::bad_request(error.message).into_response();
    }
    let rule_id = request.rule.id.clone();
    if !site.add_rule(request.rule) {
        return ApiError::conflict(format!("a rule with id `{rule_id}` already exists"))
            .into_response();
    }
    finish_mutation(
        state,
        actor,
        "rule.create",
        site.host(),
        &format!("rule `{rule_id}` added by {actor}"),
    );
    ok()
}

/// `POST /api/sites/{host}/rules/delete`.
#[must_use]
pub fn delete_rule(state: &AppState, host: &str, body: &[u8], actor: &str) -> ApiResponse {
    let Some(site) = state.site(host) else {
        return host_not_found(host);
    };
    let request: RuleDeleteRequest = match parse_body(body) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    if !site.remove_rule(&request.id) {
        return ApiError::not_found(format!("no custom rule with id `{}`", request.id))
            .into_response();
    }
    finish_mutation(
        state,
        actor,
        "rule.delete",
        site.host(),
        &format!("rule `{}` removed by {actor}", request.id),
    );
    ok()
}

/// `POST /api/sites` (the add-site wizard).
#[must_use]
pub fn create_site(state: &AppState, request: &SiteCreateRequest, actor: &str) -> ApiResponse {
    // "Generate the secret for me" implies the default header name.
    let mut effective = request.clone();
    if effective.generate_origin_secret && effective.origin_secret_header.is_none() {
        effective.origin_secret_header = Some(config::DEFAULT_ORIGIN_SECRET_HEADER.to_owned());
    }
    let request = &effective;
    let mut generated_secret: Option<String> = None;
    let host = match config::validate_host(&request.host) {
        Ok(host) => host,
        Err(error) => return ApiError::bad_request(error.message).into_response(),
    };
    if state.site(&host).is_some() {
        return ApiError::conflict(format!("a site for host `{host}` already exists"))
            .into_response();
    }
    if let Err(message) = Origin::parse(&request.origin) {
        return ApiError::bad_request(message).into_response();
    }
    // The front door works only when the origin is a second address of the same project: with origin == public host
    // visitors would reach the app without HDD, so the server refuses regardless of what the browser checked (Addendum 7).
    if request.connection == ConnectionMethod::VercelFrontDoor
        && let Err(error) = config::validate_front_door_origin(&host, &request.origin)
    {
        return ApiError::bad_request(error.message).into_response();
    }
    // A serverless origin secret is never accepted over the API: it must already exist in the environment (R-03).
    let secret_value = match request.origin_secret_header.as_deref() {
        Some(header) => {
            if let Err(error) = config::validate_header_name(header) {
                return ApiError::bad_request(error.message).into_response();
            }
            let env_name = config::default_origin_secret_env(&host);
            match std::env::var(&env_name)
                .ok()
                .filter(|value| !value.trim().is_empty())
            {
                Some(value) => Some(value),
                None if request.generate_origin_secret => {
                    let value = match config::generate_origin_secret() {
                        Ok(value) => value,
                        Err(error) => {
                            return ApiError::bad_request(error.message).into_response();
                        }
                    };
                    let path = config::origin_secret_path(state.data_dir(), &host);
                    if let Err(error) = config::write_origin_secret(&path, &value) {
                        return ApiError::bad_request(error.message).into_response();
                    }
                    generated_secret = Some(value.clone());
                    Some(value)
                }
                None => {
                    return ApiError::bad_request(format!(
                        "the serverless origin needs the secret value in the environment variable `{env_name}` \
                         before the site is added; the value is never accepted over the API (R-03)"
                    ))
                    .into_response();
                }
            }
        }
        None => None,
    };
    let mut site_config = config::site_config_from_create(request);
    site_config.host.clone_from(&host);
    let validated_site = match state.validate_site(site_config) {
        Ok(site) => site,
        Err(error) => return ApiError::bad_request(error.message).into_response(),
    };
    let runtime = Arc::new(SiteRuntime::new(&validated_site, secret_value));
    let view = runtime.view();
    if let Err(error) = state.add_site(runtime) {
        return ApiError::conflict(error.message).into_response();
    }
    let setup = crate::wizard::instructions(
        request.connection,
        &host,
        &request.origin,
        request.origin_secret_header.as_deref(),
    );
    audit(
        state,
        actor,
        "site.create",
        &host,
        &format!("site `{host}` created through the wizard by {actor}"),
    );
    ApiResponse::json_status(
        201,
        &SiteCreateResponse {
            site: view,
            setup,
            origin_secret: generated_secret,
        },
    )
}

/// `POST /api/sites/{host}/delete`: remove a site from HDD. The origin itself is never touched.
#[must_use]
pub fn remove_site(state: &AppState, host: &str, body: &[u8], actor: &str) -> ApiResponse {
    let request: SiteRemoveRequest = match parse_body(body) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let Some(site) = state.site(host) else {
        return host_not_found(host);
    };
    let canonical = site.host().to_owned();
    if !request.confirm.trim().eq_ignore_ascii_case(&canonical) {
        return ApiError::bad_request(
            "removing a site requires the typed confirmation {\"confirm\":\"<the site host>\"} (R-28)",
        )
        .into_response();
    }
    if let Err(error) = state.remove_site(&canonical) {
        return ApiError::bad_request(error.message).into_response();
    }
    audit(
        state,
        actor,
        "site.remove",
        &canonical,
        &format!("site `{canonical}` removed by {actor}; the origin was not changed"),
    );
    ok()
}

/// `GET /api/sites/{host}/connect/{method}`.
#[must_use]
pub fn connect_instructions(state: &AppState, host: &str, method_key: &str) -> ApiResponse {
    let Some(site) = state.site(host) else {
        return host_not_found(host);
    };
    let Some(method) = config::connection_method_from_key(method_key) else {
        return ApiError::bad_request(format!(
            "unknown connection method `{method_key}`; use dns, cloudflare, nginx, vercel or vercel_front_door"
        ))
        .into_response();
    };
    let instructions: SetupInstructions = crate::wizard::instructions(
        method,
        site.host(),
        site.origin_display(),
        site.origin_secret_header(),
    );
    ApiResponse::json(&instructions)
}

/// `POST /api/inspect`: run the detector on a synthetic request without touching any site.
#[must_use]
pub fn inspect(state: &AppState, body: &[u8]) -> ApiResponse {
    let request: InspectRequest = match parse_body(body) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let vector = request.vector.unwrap_or(Vector::Query);
    let kind = request.field_kind.unwrap_or(FieldKind::Unknown);
    let field_name = String::from("payload");
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut body_bytes: Vec<u8> = Vec::new();
    let mut path = String::from("/");
    let mut query: Option<String> = None;
    let mut content_type: Option<String> = None;
    let encoded = util::percent_encode_component(&request.payload);
    match vector {
        Vector::Path => path = format!("/{encoded}"),
        Vector::Query => query = Some(format!("payload={encoded}")),
        Vector::FormBody => {
            content_type = Some("application/x-www-form-urlencoded".to_owned());
            body_bytes = format!("payload={encoded}").into_bytes();
        }
        Vector::JsonBody => {
            content_type = Some("application/json".to_owned());
            body_bytes = serde_json::json!({ "payload": request.payload })
                .to_string()
                .into_bytes();
        }
        Vector::MultipartField => {
            let boundary = "HDDINSPECTBOUNDARY";
            content_type = Some(format!("multipart/form-data; boundary={boundary}"));
            body_bytes = format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"payload\"\r\n\r\n{}\r\n--{boundary}--\r\n",
                request.payload
            )
            .into_bytes();
        }
        Vector::MultipartFilename => {
            let boundary = "HDDINSPECTBOUNDARY";
            content_type = Some(format!("multipart/form-data; boundary={boundary}"));
            body_bytes = format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n\
                 Content-Type: text/plain\r\n\r\nx\r\n--{boundary}--\r\n",
                request.payload
            )
            .into_bytes();
        }
        Vector::Header => headers.push(("X-Test-Payload".to_owned(), request.payload.clone())),
        Vector::Cookie => headers.push(("Cookie".to_owned(), format!("payload={encoded}"))),
    }
    let mut settings: SiteSettings = match request.site.as_deref().and_then(|host| state.site(host))
    {
        Some(site) => site.settings_snapshot(),
        None => SiteSettings::default(),
    };
    settings.field_hints.insert(0, (field_name.clone(), kind));
    let input = InspectInput {
        method: "POST",
        path: &path,
        query: query.as_deref(),
        headers: &headers,
        content_type: content_type.as_deref(),
        body: &body_bytes,
    };
    let verdict = hdd_waf_core::inspect(&input, &settings);
    ApiResponse::json(&InspectResponse {
        verdict,
        normalized: util::display_normalized(&request.payload),
    })
}

/// `GET /api/block-preview`: the exact branded block page the proxy serves.
#[must_use]
pub fn block_preview(state: &AppState) -> ApiResponse {
    let ray_id = util::new_ray_id();
    let host = state
        .hosts()
        .first()
        .cloned()
        .unwrap_or_else(|| "example.com".to_owned());
    let (_status, _content_type, html) = crate::ui::block_page(&ray_id, &host, false);
    ApiResponse::json(&BlockPreviewResponse { html, ray_id })
}

/// Split `/api/sites/{host}/{rest}` into the decoded host and the remaining route.
#[must_use]
pub fn split_site_route(rest: &str) -> Option<(String, String)> {
    let (host_part, action) = rest.split_once('/')?;
    if host_part.is_empty() || action.is_empty() {
        return None;
    }
    let host = util::percent_decode(host_part);
    Some((host, action.to_owned()))
}
