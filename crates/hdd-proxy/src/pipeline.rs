//! The proxy data path: route by `Host`, resolve the client IP, enforce an active ban early, buffer the request body
//! up to [`hdd_waf_core::INSPECT_BODY_CAP`], run the detector, decide by the site mode, create the progressive ban on a
//! block verdict, record the explainable event and forward.
//!
//! `off` is a pure pass-through: no inspection, no ban enforcement, the body is streamed as received. `monitor`
//! forwards everything and records `would_block`; a body above the inspection cap is forwarded unmodified while only
//! its inspected prefix is recorded as truncated (review R1-10). `block` refuses a blocked request with the branded 403
//! page and refuses an over-cap body with the honest 413 (documented limitation). The body read has a deadline
//! (review R1-7). Cross-site browser context only lowers the ladder weight of a ban; it never skips it (review R1-6).
//! Request bodies are never logged: only the detector's redacted evidence (at most 128 bytes) reaches the event store.
//! Addendum 7 adds gate-host routing: a peer inside `trusted_proxies` may name the site with `X-HDD-Gate-Host` (a
//! strict lower-case DNS name), and the header is stripped before forwarding so it never reaches an origin.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::{Request, Response};

use hdd_waf_core::{Action, FieldKind, InspectInput, SiteSettings, Vector, Verdict};

use crate::api::Mode;
use crate::ban;
use crate::blockpage;
use crate::forward::{self, ForwardError};
use crate::state::{AppState, SiteRuntime, event_view};
use crate::util::{self, ResBody};

/// How long the proxy waits for more request-body bytes before abandoning the request with a 408 page.
pub const BODY_READ_DEADLINE: Duration = Duration::from_secs(5);
/// The wall-clock deadline for one inspection run (review R1-2: a pathological input must not block the async worker).
pub const INSPECTION_DEADLINE: Duration = Duration::from_secs(5);

/// Handle one request on the proxy listener.
pub async fn handle(
    request: Request<hyper::body::Incoming>,
    peer: SocketAddr,
    state: Arc<AppState>,
) -> Response<ResBody> {
    let ray_id = util::new_ray_id();
    let headers = collect_headers(&request);
    let json = blockpage::wants_json(util::header(&headers, "accept"));
    let Some(host) = gate_or_host(peer, &headers, &state.trusted_proxies) else {
        // No usable routing host: a neutral 404, no tenant data and no logging of a request we cannot attribute.
        return crate::server::page_response(&blockpage::not_found(json), &ray_id);
    };
    let Some(site) = state.site(&host) else {
        return crate::server::page_response(&blockpage::not_found(json), &ray_id);
    };
    let client_ip = util::resolve_client_ip(peer, &headers, &state.trusted_proxies);
    let mode = site.mode();
    let forwarded_proto = forward::forwarded_proto(peer, &state.trusted_proxies, &headers);
    site.note_request();
    state
        .counters
        .requests
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (parts, body) = request.into_parts();
    let method = parts.method.as_str().to_owned();
    let path = parts.uri.path().to_owned();
    let request_target = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    // R1-11: an origin may be mounted under a base path (`https://app.example.com/base`); the data path prefixes it
    // exactly like the lockdown probe already does.
    let target = upstream_target(&site, &request_target);
    let query = parts.uri.query().map(str::to_owned);

    // `off`: pure pass-through. No inspection, no event enforcement; the body is streamed without buffering.
    if mode == Mode::Off {
        let allow = Verdict::allow();
        let event = event_view(
            &state,
            &site,
            &ray_id,
            client_ip,
            &method,
            &path,
            "allow",
            &allow,
            Mode::Off,
            None,
        );
        state.record_event(event);
        return forward_request(
            &state,
            &site,
            &headers,
            &method,
            &target,
            client_ip,
            &forwarded_proto,
            &ray_id,
            util::stream_body(body),
            json,
        )
        .await;
    }

    // An active ban refuses every request from this client before any inspection or forwarding.
    if let Some(active) = state.bans.active(client_ip) {
        site.note_blocked();
        state
            .counters
            .blocked
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let allow = Verdict::allow();
        let detail = format!("temporary ban active: {}", active.reason);
        let event = event_view(
            &state,
            &site,
            &ray_id,
            client_ip,
            &method,
            &path,
            "block",
            &allow,
            Mode::Block,
            Some(&detail),
        );
        state.record_event(event);
        return crate::server::page_response(
            &blockpage::banned_page(&ray_id, site.host(), json),
            &ray_id,
        );
    }

    // Request-rate guard: a client far above any human or normal client rate (a script loop) is slowed down first.
    if state.rate.exceeded(site.host(), client_ip) {
        let allow = Verdict::allow();
        let detail = format!(
            "rate limit exceeded: more than {} requests in 10 seconds from this address",
            state.rate.limit()
        );
        if mode == Mode::Block {
            site.note_blocked();
            state
                .counters
                .blocked
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let event = event_view(
                &state,
                &site,
                &ray_id,
                client_ip,
                &method,
                &path,
                "block",
                &allow,
                mode,
                Some(&detail),
            );
            state.record_event(event);
            let mut response =
                crate::server::page_response(&blockpage::rate_limited(&ray_id, json, 10), &ray_id);
            response
                .headers_mut()
                .insert("retry-after", hyper::header::HeaderValue::from_static("10"));
            return response;
        }
        let event = event_view(
            &state,
            &site,
            &ray_id,
            client_ip,
            &method,
            &path,
            "would_block",
            &allow,
            mode,
            Some(&detail),
        );
        state.record_event(event);
    }

    let read = match read_body(body, mode).await {
        Ok(read) => read,
        Err(BodyError::TooLarge) => {
            site.note_blocked();
            state
                .counters
                .blocked
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let allow = Verdict::allow();
            let event = event_view(
                &state,
                &site,
                &ray_id,
                client_ip,
                &method,
                &path,
                "block",
                &allow,
                mode,
                Some("request body is larger than the inspection cap"),
            );
            state.record_event(event);
            state.events.audit(
                "system",
                "body_cap_refused",
                site.host(),
                &format!(
                    "ray {ray_id}: request body exceeded the inspection cap (block mode refuses it)"
                ),
            );
            return crate::server::page_response(
                &blockpage::payload_too_large(&ray_id, json, hdd_waf_core::INSPECT_BODY_CAP),
                &ray_id,
            );
        }
        Err(BodyError::Timeout) => {
            state.events.audit(
                "system",
                "body_read_timeout",
                site.host(),
                &format!(
                    "ray {ray_id}: the request body did not complete within {BODY_READ_DEADLINE:?}"
                ),
            );
            return crate::server::page_response(
                &blockpage::request_timeout(&ray_id, json),
                &ray_id,
            );
        }
        Err(BodyError::Read(message)) => {
            state
                .events
                .audit("system", "body_read_error", site.host(), &message);
            return crate::server::page_response(&blockpage::bad_gateway(&ray_id, json), &ray_id);
        }
    };

    let content_type = util::header(&headers, "content-type");
    let settings = site.settings_snapshot();
    let (verdict, forward_body, truncation) = match read {
        BodyRead::Buffered(buffered) => {
            let verdict = inspect_bytes(
                &settings,
                &method,
                &path,
                query.as_deref(),
                &headers,
                content_type,
                &buffered,
            )
            .await;
            (verdict, util::full_body(Bytes::from(buffered)), None)
        }
        BodyRead::Oversized { prefix, rest } => {
            // R1-10: monitor mode forwards the complete body; only the inspected prefix is cut at the cap.
            let cap = hdd_waf_core::INSPECT_BODY_CAP;
            let inspected = prefix.get(..cap.min(prefix.len())).unwrap_or_default();
            let verdict = inspect_bytes(
                &settings,
                &method,
                &path,
                query.as_deref(),
                &headers,
                content_type,
                inspected,
            )
            .await;
            let would_block = verdict.action == Action::Block;
            let marker = if would_block {
                "request body exceeded the inspection cap; would_block verdict applies to the inspected prefix (truncated)"
            } else {
                "request body exceeded the inspection cap; forwarded unmodified (truncated for inspection)"
            };
            (
                verdict,
                prefixed_body(prefix, rest),
                Some((marker, would_block)),
            )
        }
    };
    let evidence_override = truncation.map(|(marker, _)| marker);
    let truncated_would_block = truncation
        .map(|(_, would_block)| would_block)
        .unwrap_or(false);
    // R1-2: an inspection that exceeded its deadline failed closed; record that explicitly for the operator.
    if verdict.rule_id == Some("LIMIT-002") {
        state.events.audit(
            "system",
            "inspection_timeout",
            site.host(),
            &format!(
                "ray {ray_id}: inspection exceeded {INSPECTION_DEADLINE:?}; the request failed closed"
            ),
        );
    }

    if mode == Mode::Block && verdict.action == Action::Block {
        site.note_blocked();
        state
            .counters
            .blocked
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let event = event_view(
            &state, &site, &ray_id, client_ip, &method, &path, "block", &verdict, mode, None,
        );
        state.record_event(event);
        if site.ban_enabled() {
            // R1-6: the Sec-Fetch-* headers are client-controlled, so cross-site context only lowers the ladder
            // weight of the offence; the request is still blocked and the client is still banned.
            let context = if ban::is_cross_site_subresource(&headers) {
                ban::BanContext::CrossSite
            } else {
                ban::BanContext::Direct
            };
            let reason = ban_reason(&verdict);
            let created = state.bans.create(
                client_ip,
                Some(site.host()),
                &reason,
                verdict.rule_id,
                verdict.category,
                site.ladder(),
                context,
            );
            state.events.audit(
                "system",
                "ban.created",
                &format!("{} ({})", client_ip, site.host()),
                &format!(
                    "ray {ray_id}: step {}, ttl {}s, rule {}, weight {}, reason: {}",
                    created.step,
                    created.ttl_seconds,
                    created.rule_id.as_deref().unwrap_or("none"),
                    match context {
                        ban::BanContext::Direct => "direct",
                        ban::BanContext::CrossSite => "cross-site (lower ladder weight)",
                    },
                    created.reason
                ),
            );
        }
        return crate::server::page_response(
            &blockpage::block_page(&ray_id, site.host(), json),
            &ray_id,
        );
    }

    let would_block = verdict.action == Action::Block;
    if mode == Mode::Monitor && (would_block || truncated_would_block) {
        state
            .counters
            .would_block
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    let action = if would_block || truncated_would_block {
        "would_block"
    } else {
        "allow"
    };
    let event = event_view(
        &state,
        &site,
        &ray_id,
        client_ip,
        &method,
        &path,
        action,
        &verdict,
        mode,
        evidence_override,
    );
    state.record_event(event);

    forward_request(
        &state,
        &site,
        &headers,
        &method,
        &target,
        client_ip,
        &forwarded_proto,
        &ray_id,
        forward_body,
        json,
    )
    .await
}

/// The routing host for one request: a trusted proxy's validated gate header, otherwise the normalised `Host`.
///
/// Addendum 7 item 1: a reverse proxy inside `trusted_proxies` may name the site HDD must serve while the browser's
/// original `Host` stays untouched for the origin. The header is honoured only from a trusted peer and only as a strict
/// lower-case DNS name; every other value is ignored completely and `Host` decides exactly as before, so an untrusted
/// peer can never choose the site this way.
fn gate_or_host(
    peer: SocketAddr,
    headers: &[(String, String)],
    trusted_proxies: &[util::Cidr],
) -> Option<String> {
    if util::peer_is_trusted(peer.ip(), trusted_proxies)
        && let Some(gate_host) =
            util::header(headers, forward::GATE_HOST_HEADER).and_then(normalize_gate_host)
    {
        return Some(gate_host);
    }
    util::header(headers, "host").and_then(util::normalize_host)
}

/// Validate a gate-header value as a strict lower-case DNS name for routing.
///
/// Unlike [`util::normalize_host`] this never strips a port: a value carrying one is rejected outright. The value must
/// be 1..=253 bytes, use only `[a-z0-9.-]`, and every label must be 1..=63 bytes and start and end with a letter or
/// digit. That rejects uppercase, underscores, a scheme, a path, an empty label and a trailing dot.
fn normalize_gate_host(value: &str) -> Option<String> {
    let host = value.trim();
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    if !host.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
    }) {
        return None;
    }
    let invalid_label = host.split('.').any(|label| {
        label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
    });
    if invalid_label {
        return None;
    }
    Some(host.to_owned())
}

/// Build the origin request, forward it, and convert either the origin response or the failure into a branded page.
#[allow(clippy::too_many_arguments)]
async fn forward_request(
    state: &AppState,
    site: &SiteRuntime,
    incoming_headers: &[(String, String)],
    method: &str,
    target: &str,
    client_ip: std::net::IpAddr,
    forwarded_proto: &str,
    ray_id: &str,
    body: ResBody,
    json: bool,
) -> Response<ResBody> {
    let original_host = util::header(incoming_headers, "host").unwrap_or("");
    let secret = match (site.origin_secret_header(), site.origin_secret_value()) {
        (Some(header), Some(value)) => Some((header, value)),
        _ => None,
    };
    let headers = forward::upstream_headers(
        incoming_headers,
        site.origin(),
        site.preserve_host(),
        site.upstream_host(),
        secret,
        original_host,
        client_ip,
        forwarded_proto,
        ray_id,
    );
    let request = match forward::build_request(method, target, headers, body) {
        Ok(request) => request,
        Err(error) => {
            state.events.audit(
                "system",
                "request_build_error",
                site.host(),
                &forward::error_summary(&error),
            );
            return crate::server::page_response(&blockpage::bad_gateway(ray_id, json), ray_id);
        }
    };
    match state.forwarder.send(site.origin(), request).await {
        Ok(response) => forward::prepare_response(response, ray_id),
        Err(error) => {
            let page = match error {
                ForwardError::Timeout(_) => blockpage::gateway_timeout(ray_id, json),
                _ => blockpage::bad_gateway(ray_id, json),
            };
            state.events.audit(
                "system",
                "origin_error",
                site.host(),
                &format!("ray {ray_id}: {}", forward::error_summary(&error)),
            );
            crate::server::page_response(&page, ray_id)
        }
    }
}

/// The request body read for inspection.
enum BodyRead {
    /// The complete body fit under the inspection cap.
    Buffered(Vec<u8>),
    /// The body is larger than the cap: the bytes read so far and the unread remainder for forwarding (monitor mode).
    Oversized {
        /// Every byte read so far (at least the cap, plus the frame that crossed it).
        prefix: Vec<u8>,
        /// The unread remainder of the request body.
        rest: Incoming,
    },
}

/// Why the request body could not be read for inspection.
enum BodyError {
    /// The body exceeds [`hdd_waf_core::INSPECT_BODY_CAP`] and the site is in block mode.
    TooLarge,
    /// The client did not finish the body within [`BODY_READ_DEADLINE`].
    Timeout,
    /// The client connection failed while the body was being read.
    Read(String),
}

/// Read an incoming body under the inspection cap and the body-read deadline.
///
/// In monitor mode an oversized body is not an error: the complete body stays forwardable (the read prefix plus the
/// remaining `Incoming`), only inspection is truncated at the cap. In block mode an oversized body is refused.
async fn read_body(mut body: Incoming, mode: Mode) -> Result<BodyRead, BodyError> {
    let cap = hdd_waf_core::INSPECT_BODY_CAP;
    let mut out: Vec<u8> = Vec::with_capacity(8 * 1024);
    loop {
        let frame = match tokio::time::timeout(BODY_READ_DEADLINE, body.frame()).await {
            Err(_) => return Err(BodyError::Timeout),
            Ok(None) => return Ok(BodyRead::Buffered(out)),
            Ok(Some(Err(error))) => {
                return Err(BodyError::Read(format!(
                    "reading the request body failed: {error}"
                )));
            }
            Ok(Some(Ok(frame))) => frame,
        };
        if let Some(data) = frame.data_ref() {
            if out.len().saturating_add(data.len()) > cap {
                if mode == Mode::Monitor {
                    out.extend_from_slice(data);
                    return Ok(BodyRead::Oversized {
                        prefix: out,
                        rest: body,
                    });
                }
                return Err(BodyError::TooLarge);
            }
            out.extend_from_slice(data);
        }
    }
}

/// A body that yields the already-read prefix first, then streams the unread remainder of the client body.
///
/// This keeps an over-cap `monitor` request forwardable without buffering the whole body: only the inspection prefix is
/// held in memory (review R1-10).
struct PrefixedBody {
    /// The bytes already read (yielded as the first data frame, then dropped).
    prefix: Option<Bytes>,
    /// The unread remainder of the request body.
    rest: Pin<Box<Incoming>>,
}

impl Body for PrefixedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(prefix) = this.prefix.take()
            && !prefix.is_empty()
        {
            return Poll::Ready(Some(Ok(Frame::data(prefix))));
        }
        this.rest.as_mut().poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.prefix.as_ref().is_none_or(Bytes::is_empty) && self.rest.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        // The remainder length is not known to this wrapper, so hyper picks chunked framing for the upstream request.
        SizeHint::default()
    }
}

/// Wrap a prefix plus the unread request remainder into the boxed response/request body type.
fn prefixed_body(prefix: Vec<u8>, rest: Incoming) -> ResBody {
    PrefixedBody {
        prefix: Some(Bytes::from(prefix)),
        rest: Box::pin(rest),
    }
    .map_err(|error| -> util::BoxError { Box::new(error) })
    .boxed()
}

/// The fail-closed verdict returned when inspection cannot finish within [`INSPECTION_DEADLINE`].
///
/// `policy` / `inspection_timeout` / `LIMIT-002`: block mode refuses the request and creates the ban, monitor mode
/// records `would_block` (review R1-2, R-26: inspection never fails open). The pair is documented by the Lead in the
/// shared detector types.
fn inspection_timeout_verdict() -> Verdict {
    Verdict::block(
        "policy",
        "inspection_timeout",
        "LIMIT-002",
        Vector::Path,
        "",
        FieldKind::Unknown,
        "",
        100,
    )
}

/// Run one pure inspection job on the blocking pool, bounded by `deadline` (review R1-2).
///
/// The pure detector is CPU work; running it on the tokio worker would stall unrelated requests. A job that refuses to
/// finish (or panics) fails closed instead of forwarding: the caller then blocks/bans in block mode and records
/// `would_block` in monitor mode.
async fn run_inspection(
    job: impl FnOnce() -> Verdict + Send + 'static,
    deadline: Duration,
) -> Verdict {
    match tokio::time::timeout(deadline, tokio::task::spawn_blocking(job)).await {
        // The blocking job cannot be cancelled; it finishes on the blocking pool, but the request path stops waiting
        // and fails closed after the deadline (review R1-2).
        Err(_) => inspection_timeout_verdict(),
        // A panic inside the pure detector also fails closed instead of becoming an allow (R-09/R-26).
        Ok(Err(_join_error)) => inspection_timeout_verdict(),
        Ok(Ok(verdict)) => verdict,
    }
}

/// Run the detector on one request body slice, off the async worker and deadline-bounded.
async fn inspect_bytes(
    settings: &SiteSettings,
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &[(String, String)],
    content_type: Option<&str>,
    body: &[u8],
) -> Verdict {
    // `spawn_blocking` needs an owned, `'static` job; the inspected slice is at most `INSPECT_BODY_CAP`.
    let settings = settings.clone();
    let method = method.to_owned();
    let path = path.to_owned();
    let query = query.map(str::to_owned);
    let headers = headers.to_vec();
    let content_type = content_type.map(str::to_owned);
    let body = body.to_vec();
    run_inspection(
        move || {
            let input = InspectInput {
                method: &method,
                path: &path,
                query: query.as_deref(),
                headers: &headers,
                content_type: content_type.as_deref(),
                body: &body,
            };
            hdd_waf_core::inspect(&input, &settings)
        },
        INSPECTION_DEADLINE,
    )
    .await
}

/// Prefix an origin base path onto the forwarded request target (review R1-11).
fn upstream_target(site: &SiteRuntime, request_target: &str) -> String {
    let base = site.origin().base_path.as_str();
    if base.is_empty() {
        request_target.to_owned()
    } else {
        format!("{base}{request_target}")
    }
}

/// Collect the request headers into name/value strings (non-UTF-8 header values become empty rather than panicking).
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

/// The human ban reason (explainable: category, subtype, vector, field, rule and redacted evidence; spec R-24).
fn ban_reason(verdict: &Verdict) -> String {
    let mut reason = String::from("block verdict");
    if let Some(category) = verdict.category {
        reason.push_str(": ");
        reason.push_str(category);
    }
    if let Some(subtype) = verdict.subtype {
        reason.push('/');
        reason.push_str(subtype);
    }
    if let Some(vector) = verdict.vector {
        reason.push_str(" via ");
        reason.push_str(util::vector_name(vector));
    }
    if let Some(field) = verdict.field.as_deref() {
        reason.push_str(", field `");
        reason.push_str(util::truncate_utf8(field, 64));
        reason.push('`');
    }
    if let Some(rule) = verdict.rule_id {
        reason.push_str(", rule ");
        reason.push_str(rule);
    }
    if !verdict.evidence.is_empty() {
        reason.push_str(", evidence: ");
        reason.push_str(&verdict.evidence);
    }
    util::truncate_utf8(&reason, 512).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fast inspection job keeps its own verdict (the wrapper adds no policy of its own).
    #[tokio::test]
    async fn fast_inspection_returns_its_own_verdict() {
        let verdict = run_inspection(Verdict::allow, Duration::from_secs(1)).await;
        assert_eq!(
            verdict.action,
            Action::Allow,
            "a fast job keeps its own verdict"
        );
    }

    /// A job that outlives the deadline must fail closed with the documented policy verdict (review R1-2, R-26).
    #[tokio::test]
    async fn slow_inspection_fails_closed_on_the_deadline() {
        let verdict = run_inspection(
            || {
                std::thread::sleep(Duration::from_secs(2));
                Verdict::allow()
            },
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(
            verdict.action,
            Action::Block,
            "a stalled inspection must fail closed, never allow"
        );
        assert_eq!(verdict.category, Some("policy"));
        assert_eq!(verdict.subtype, Some("inspection_timeout"));
        assert_eq!(verdict.rule_id, Some("LIMIT-002"));
        assert_eq!(verdict.score, 100);
    }

    /// The gate header is honoured only for a trusted proxy peer, and only when the value is a strict DNS name.
    #[test]
    fn gate_host_is_honoured_only_from_a_trusted_peer_and_only_when_valid() {
        let trusted = vec![util::Cidr::parse("127.0.0.2/32").expect("cidr")];
        let trusted_peer = SocketAddr::from(([127, 0, 0, 2], 4000));
        let untrusted_peer = SocketAddr::from(([127, 0, 0, 1], 4000));
        let headers = |gate: &str| {
            vec![
                ("Host".to_owned(), "public.example".to_owned()),
                (forward::GATE_HOST_HEADER.to_owned(), gate.to_owned()),
            ]
        };

        assert_eq!(
            gate_or_host(trusted_peer, &headers("site.example"), &trusted),
            Some("site.example".to_owned()),
            "a trusted peer's valid gate host routes"
        );
        assert_eq!(
            gate_or_host(untrusted_peer, &headers("site.example"), &trusted),
            Some("public.example".to_owned()),
            "an untrusted peer can never choose the site"
        );
        assert_eq!(
            gate_or_host(trusted_peer, &headers("site.example:8443"), &trusted),
            Some("public.example".to_owned()),
            "a value with a port is ignored and Host decides"
        );
    }

    /// The gate-host validator is strict (Addendum 7 item 1: lower-case DNS name, at most 253 bytes, no port/slash).
    #[test]
    fn gate_host_validator_is_strict() {
        for valid in ["site.example", "a-b.c0.example", "localhost"] {
            assert_eq!(
                normalize_gate_host(valid),
                Some(valid.to_owned()),
                "`{valid}` is a valid gate host"
            );
        }
        let over_len = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        let at_len = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(at_len.len(), 253, "the fixture is exactly at the bound");
        assert!(
            normalize_gate_host(&at_len).is_some(),
            "a 253-byte name is inside the bound"
        );
        let rejected = [
            "",
            "  ",
            "site.example:8443",
            "site.example:443",
            "http://site.example",
            "https://site.example/",
            "site.example/evil",
            "SITE.EXAMPLE",
            "site_example.test",
            "site..example",
            ".site.example",
            "site.example.",
            "-site.example",
            "site-.example",
            "site example.example",
            over_len.as_str(),
        ];
        for value in rejected {
            assert_eq!(
                normalize_gate_host(value),
                None,
                "`{value}` must be rejected as a gate host"
            );
        }
    }
}
