//! The loopback admin listener: authentication, the CSRF and role gates, the static UI, and the admin API router.
//!
//! Order of decisions for every admin request:
//! 1. Serve the public UI shells and `/static/*` (public per [`crate::api::is_public_admin_path`]).
//! 2. For mutations authenticated by the session cookie (not by a bearer token) require an `Origin` header whose host
//!    matches the request `Host` (CSRF; the session cookie is `SameSite=Strict` as a second layer).
//! 3. Dispatch the accounts routes ([`crate::accounts_api::handle`]) first; they own setup/login/logout/account/users.
//! 4. `/healthz` is public and answered here.
//! 5. Everything else needs a principal; a viewer may read but not mutate (the accounts routes have their own
//!    self-service permissions and were dispatched before this gate).
//! 6. The core admin routes answer exactly the DTOs of [`crate::api`]; every mutation bumps the configuration revision
//!    and writes an audit line.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use http_body_util::BodyExt;
use hyper::{Request, Response};

use crate::api::{
    self, ApiError, ApiRequest, ApiResponse, Principal, SiteCreateRequest, VerifyRequest,
};
use crate::api_core::{self};
use crate::blockpage;
use crate::finding_export;
use crate::lockdown;
use crate::server;
use crate::state::AppState;
use crate::util::{self, ResBody};

/// Handle one request on the admin listener.
pub async fn handle(
    request: Request<hyper::body::Incoming>,
    peer: SocketAddr,
    state: Arc<AppState>,
) -> Response<ResBody> {
    let ray_id = util::new_ray_id();
    let headers = collect_headers(&request);
    let client_ip = util::resolve_client_ip(peer, &headers, &state.trusted_proxies);
    let loopback = util::is_loopback(client_ip);
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let query = util::parse_query(request.uri().query());
    let body = match read_body(request.into_body()).await {
        Ok(body) => body,
        Err(message) => return server::error_response(ApiError::bad_request(message), &ray_id),
    };
    let api_request = ApiRequest {
        method: method.clone(),
        path: path.clone(),
        query,
        headers: headers.clone(),
        body,
    };

    // Public UI shells and assets.
    if let Some(response) = serve_ui(&state, &method, &path, &ray_id) {
        return response;
    }

    let public = api::is_public_admin_path(&path);
    let principal = if public {
        None
    } else {
        state.auth.authenticate(&api_request)
    };

    // CSRF: a mutation authenticated by the session cookie needs an Origin header naming this admin host.
    if api::is_mutation(&method)
        && let Some(principal) = principal.as_ref()
        && util::cookie_value(&headers, api::SESSION_COOKIE).is_some()
    {
        let origin_ok = util::header(&headers, "origin")
            .and_then(origin_authority)
            .is_some_and(|authority| {
                util::authority_matches_host(
                    authority,
                    util::header(&headers, "host").unwrap_or_default(),
                )
            });
        if !origin_ok {
            state.events.audit(
                &principal.username,
                "admin.refused",
                &path,
                "cookie-authenticated mutation without a matching Origin header (CSRF guard)",
            );
            return server::error_response(
                ApiError::forbidden(
                    "the Origin header is missing or does not match this admin host (CSRF guard)",
                ),
                &ray_id,
            );
        }
    }

    // The accounts routes are dispatched first for every admin request.
    if let Some(response) = state.auth.handle_accounts(
        &api_request,
        principal.as_ref(),
        &client_ip.to_string(),
        loopback,
    ) {
        return server::api_response(response, &ray_id);
    }

    // Liveness is public.
    if method == "GET" && path == api::paths::HEALTHZ {
        return server::api_response(api_core::health(&state), &ray_id);
    }

    let Some(principal) = principal else {
        if is_api_path(&path) {
            return server::error_response(
                ApiError::unauthorized("login or an API token is required"),
                &ray_id,
            );
        }
        return server::redirect_response(api::paths::LOGIN);
    };

    // A viewer may read but not mutate the protection configuration or bans (R-27).
    if api::is_mutation(&method) && !principal.role.can_mutate() {
        state.events.audit(
            &principal.username,
            "admin.refused",
            &path,
            "viewer role attempted a mutation",
        );
        return server::error_response(
            ApiError::forbidden("the viewer role is read-only; ask an owner to make this change"),
            &ray_id,
        );
    }

    if !is_api_path(&path) {
        return server::page_response(&blockpage::not_found(false), &ray_id);
    }

    match dispatch(&state, &api_request, &principal, client_ip).await {
        Ok(response) => server::api_response(response, &ray_id),
        Err(error) => server::error_response(error, &ray_id),
    }
}

/// Route one authenticated admin API request.
async fn dispatch(
    state: &Arc<AppState>,
    request: &ApiRequest,
    principal: &Principal,
    client_ip: IpAddr,
) -> Result<ApiResponse, ApiError> {
    let method = request.method.as_str();
    let path = request.path.as_str();
    let actor = principal.username.as_str();
    match (method, path) {
        ("GET", api::paths::API_EVENTS) => Ok(api_core::events(state, &request.query)),
        ("GET", api::paths::API_BANS) => Ok(api_core::bans(state)),
        ("GET", api::paths::API_GUARDS) => Ok(api_core::guards(state)),
        ("GET", api::paths::API_SITES) => Ok(api_core::sites(state)),
        ("POST", api::paths::API_SITES) => {
            let create: SiteCreateRequest = api_core::parse_body(&request.body)?;
            Ok(api_core::create_site(state, &create, actor))
        }
        ("POST", api::paths::API_INSPECT) => Ok(api_core::inspect(state, &request.body)),
        ("GET", api::paths::API_BLOCK_PREVIEW) => Ok(api_core::block_preview(state)),
        _ if path == api::paths::API_FINDINGS
            || path.starts_with(api::paths::API_FINDING_PREFIX) =>
        {
            dispatch_findings(state, request, principal, client_ip).await
        }
        _ => dispatch_sites(state, request, actor, method, path).await,
    }
}

/// The 404 for an unknown finding id.
fn finding_not_found(id: &str) -> ApiError {
    ApiError {
        status: 404,
        code: "finding_not_found",
        message: format!("no finding with id `{}`", util::truncate_utf8(id, 64)),
    }
}

/// A 400 with a stable code (used by the findings routes for unsupported requests).
fn bad_finding_request(code: &'static str, message: impl Into<String>) -> ApiError {
    ApiError {
        status: 400,
        code,
        message: message.into(),
    }
}

/// Route the Addendum 6 findings endpoints: list, detail, export, confirm-vulnerability and AI explanation.
async fn dispatch_findings(
    state: &Arc<AppState>,
    request: &ApiRequest,
    principal: &Principal,
    client_ip: IpAddr,
) -> Result<ApiResponse, ApiError> {
    let method = request.method.as_str();
    let path = request.path.as_str();
    if path == api::paths::API_FINDINGS {
        if method != "GET" {
            return Err(bad_finding_request(
                "method_not_allowed",
                "use GET /api/findings to list findings",
            ));
        }
        let value = |name: &str| {
            request
                .query
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        };
        let limit = value("limit")
            .and_then(|text| text.parse::<usize>().ok())
            .unwrap_or(crate::findings::DEFAULT_FINDING_LIMIT)
            .clamp(1, crate::findings::MAX_FINDING_LIMIT);
        let findings = state
            .findings
            .list(value("site"), value("family"), value("q"), limit);
        return Ok(ApiResponse::json(&api::FindingsResponse {
            findings,
            total: state.findings.total(),
            ai_enabled: state.ai.enabled(),
            ai_model: state.ai.model().map(str::to_owned),
        }));
    }
    let Some(rest) = path.strip_prefix(api::paths::API_FINDING_PREFIX) else {
        return Err(ApiError::not_found(format!("no such admin route: {path}")));
    };
    let (id_part, action) = match rest.split_once('/') {
        Some((id, action)) => (id, action),
        None => (rest, ""),
    };
    let id = util::percent_decode(id_part);
    if id.is_empty() {
        return Err(finding_not_found(""));
    }
    match (method, action) {
        ("GET", "") => {
            let Some(mut finding) = state.findings.get(&id) else {
                return Err(finding_not_found(&id));
            };
            finding.ai = state.ai.cached(&id);
            Ok(ApiResponse::json(&finding))
        }
        ("GET", "export") => {
            let Some(mut finding) = state.findings.get(&id) else {
                return Err(finding_not_found(&id));
            };
            finding.ai = state.ai.cached(&id);
            let format_value = request
                .query
                .iter()
                .find(|(key, _)| key == "format")
                .map(|(_, value)| value.as_str());
            let Some(format) = finding_export::ExportFormat::parse(format_value) else {
                return Err(bad_finding_request(
                    "unsupported_export_format",
                    "use `format=markdown` or `format=json`",
                ));
            };
            let body = finding_export::render(&finding, format);
            Ok(ApiResponse {
                status: 200,
                content_type: format.content_type(),
                headers: vec![(
                    "Content-Disposition".to_owned(),
                    format!("attachment; filename=\"{}\"", format.filename(&id)),
                )],
                body: body.into_bytes(),
            })
        }
        ("POST", "confirm") => {
            let Some(finding) = state.findings.get(&id) else {
                return Err(finding_not_found(&id));
            };
            let confirmation: api::ConfirmRequest = api_core::parse_body(&request.body)?;
            match crate::confirm::run(
                state,
                &finding,
                &confirmation,
                &principal.username,
                client_ip,
            )
            .await
            {
                Ok(response) => Ok(ApiResponse::json(&response)),
                Err(error) => Err(ApiError {
                    status: error.status(),
                    code: error.code(),
                    message: error.message(),
                }),
            }
        }
        ("POST", "explain") => {
            if state.findings.get(&id).is_none() {
                return Err(finding_not_found(&id));
            }
            // D's AI runtime is synchronous (it owns a current-thread runtime for the egress client), so it must run on
            // the blocking pool, never directly on an async worker.
            let state_for_job = Arc::clone(state);
            let principal_for_job = principal.clone();
            let id_for_job = id.clone();
            let body_for_job = request.body.clone();
            let joined = tokio::task::spawn_blocking(move || {
                crate::ai_api::handle(
                    &state_for_job,
                    &principal_for_job,
                    &id_for_job,
                    &body_for_job,
                )
            })
            .await;
            match joined {
                Ok(response) => Ok(response),
                Err(_) => Ok(ApiResponse::error(
                    500,
                    "internal",
                    "the AI explanation worker failed",
                )),
            }
        }
        _ => Err(ApiError::not_found(format!(
            "no such admin route: {} {path}",
            request.method
        ))),
    }
}

/// Route the nested `/api/sites/...`, `/api/bans/...` endpoints.
async fn dispatch_sites(
    state: &Arc<AppState>,
    request: &ApiRequest,
    actor: &str,
    method: &str,
    path: &str,
) -> Result<ApiResponse, ApiError> {
    if let Some(ip_segment) = path
        .strip_prefix(api::paths::API_BAN_DELETE_PREFIX)
        .and_then(|rest| rest.strip_suffix("/delete"))
        && method == "POST"
    {
        let ip = util::percent_decode(ip_segment);
        return Ok(api_core::delete_ban(state, &ip, actor));
    }
    let Some(rest) = path.strip_prefix(api::paths::API_SITE_PREFIX) else {
        return Err(ApiError::not_found(format!("no such admin route: {path}")));
    };
    let Some((host, action)) = api_core::split_site_route(rest) else {
        // GET /api/sites/{host} (the host is the whole remainder).
        if method == "GET" && !rest.is_empty() && !rest.contains('/') {
            let host = util::percent_decode(rest);
            return Ok(api_core::site(state, &host));
        }
        return Err(ApiError::not_found(format!("no such admin route: {path}")));
    };
    let site = state
        .site(&host)
        .ok_or_else(|| ApiError::not_found(format!("no site is configured for host `{host}`")))?;
    match (method, action.as_str()) {
        ("GET", "connect") => {
            Ok(ApiError::bad_request("missing connection method").into_response())
        }
        ("GET", action) if action.starts_with("connect/") => {
            let method_key = action.trim_start_matches("connect/");
            Ok(api_core::connect_instructions(state, &host, method_key))
        }
        ("POST", "delete") => Ok(api_core::remove_site(state, &host, &request.body, actor)),
        ("POST", "mode") => Ok(api_core::change_mode(state, &host, &request.body, actor)),
        ("POST", "strictness") => Ok(api_core::change_strictness(
            state,
            &host,
            &request.body,
            actor,
        )),
        ("POST", "rules") => Ok(api_core::add_rule(state, &host, &request.body, actor)),
        ("POST", "rules/delete") => Ok(api_core::delete_rule(state, &host, &request.body, actor)),
        ("POST", "lockdown-check") => {
            let outcome = lockdown::check_lockdown(state, &site, actor).await;
            state.bump_revision();
            Ok(ApiResponse::json(&outcome))
        }
        ("POST", "verify") => {
            let verification: VerifyRequest = api_core::parse_body(&request.body)?;
            match lockdown::verify(state, &site, &verification, actor).await {
                Ok(outcome) => {
                    state.bump_revision();
                    Ok(ApiResponse::json(&outcome))
                }
                Err(message) => Err(ApiError::bad_request(message)),
            }
        }
        ("GET", _) if !action.contains('/') => Ok(api_core::site(state, &host)),
        _ => Err(ApiError::not_found(format!(
            "no such admin route: {} {path}",
            request.method
        ))),
    }
}

/// Serve the embedded UI shells and static assets (public; no session required to download the login page).
fn serve_ui(state: &AppState, method: &str, path: &str, ray_id: &str) -> Option<Response<ResBody>> {
    if !matches!(method, "GET" | "HEAD") {
        return None;
    }
    // `/` is the public landing page; the control panel shell lives at `/app` (it redirects to `/login` without a session).
    if path == api::paths::APP || path.is_empty() || path == "/app" {
        let page = if path == "/app" {
            "/app"
        } else {
            api::paths::APP
        };
        return Some(match crate::ui::page_asset(page) {
            Some(asset) => server::asset_response(&asset, ray_id),
            None => server::page_response(&blockpage::not_found(false), ray_id),
        });
    }
    if path == api::paths::LOGIN {
        return Some(match crate::ui::page_asset(api::paths::LOGIN) {
            Some(asset) => server::asset_response(&asset, ray_id),
            None => server::page_response(&blockpage::not_found(false), ray_id),
        });
    }
    if path == api::paths::SETUP {
        if state.auth.setup_required() {
            return Some(match crate::ui::page_asset(api::paths::SETUP) {
                Some(asset) => server::asset_response(&asset, ray_id),
                None => server::page_response(&blockpage::not_found(false), ray_id),
            });
        }
        // Addendum 2 item 1: once the first account exists, /setup returns 404.
        return Some(server::page_response(&blockpage::not_found(false), ray_id));
    }
    if path.starts_with(api::paths::STATIC_PREFIX) || path == "/favicon.ico" {
        return Some(match crate::ui::asset(path) {
            Some(asset) => server::asset_response(&asset, ray_id),
            None => server::page_response(&blockpage::not_found(false), ray_id),
        });
    }
    None
}

/// Collect the request headers into name/value strings (non-UTF-8 values become empty rather than panicking).
fn collect_headers(request: &Request<hyper::body::Incoming>) -> Vec<(String, String)> {
    request
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

/// Read an admin request body up to [`server::ADMIN_BODY_CAP`].
async fn read_body(mut body: hyper::body::Incoming) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::with_capacity(1024);
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| format!("reading the request body failed: {error}"))?;
        if let Some(data) = frame.data_ref() {
            if out.len().saturating_add(data.len()) > server::ADMIN_BODY_CAP {
                return Err(format!(
                    "the admin request body is larger than {} bytes",
                    server::ADMIN_BODY_CAP
                ));
            }
            out.extend_from_slice(data);
        }
    }
    Ok(out)
}

/// Extract the authority from an `Origin` header value (`https://admin.example.com:9090`).
fn origin_authority(origin: &str) -> Option<&str> {
    let (_, rest) = origin.split_once("://")?;
    Some(rest.split('/').next().unwrap_or(rest))
}

/// Whether a path belongs to the JSON admin API.
fn is_api_path(path: &str) -> bool {
    path.starts_with("/api/") || path == api::paths::HEALTHZ
}
