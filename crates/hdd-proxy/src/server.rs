//! The two hyper listeners and the response plumbing shared by the proxy data path and the admin surface.
//!
//! Both listeners run the same HTTP/1.1 connection driver; every request handler is spawned and joined so that a
//! panicking handler becomes a counted 500 page instead of a process abort (R-09: no panic reachable from the
//! network, release builds unwind, caught panics are counted and alerted). Handlers return boxed bodies, so the proxy
//! can stream an origin response and the admin API can answer JSON from one type.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::api::ApiResponse;
use crate::blockpage::Page;
use crate::state::AppState;
use crate::ui::Asset;
use crate::util::{self, ResBody};

/// The largest request body the admin listener accepts (JSON commands and login forms are far smaller).
pub const ADMIN_BODY_CAP: usize = 64 * 1024;
/// How long a client may take to send the request head before the connection is closed (review R1-7 slowloris).
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// How often expired bans and quiet offence counters are pruned in the background (review LOW).
const PRUNE_INTERVAL: Duration = Duration::from_secs(60);

/// Which behavior a listener runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerKind {
    /// The public proxy listener (site routing and inspection).
    Proxy,
    /// The loopback admin listener (session/API-token authenticated).
    Admin,
}

/// A running server: the bound addresses, the shutdown handle and the accept-loop tasks.
pub struct Running {
    /// The bound proxy listener address (an ephemeral port when the config asked for `:0`).
    pub proxy_addr: SocketAddr,
    /// The bound admin listener address.
    pub admin_addr: SocketAddr,
    /// Broadcasts shutdown to the accept loops.
    shutdown: watch::Sender<bool>,
    /// The two accept-loop tasks.
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Running {
    /// Stop accepting new connections and wait (bounded) for the accept loops to finish.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
        }
    }
}

/// Bind both listeners and start serving.
///
/// # Errors
/// Returns a message when a listener address cannot be bound.
pub async fn start(
    state: Arc<AppState>,
    proxy_bind: SocketAddr,
    admin_bind: SocketAddr,
) -> Result<Running, String> {
    let proxy_listener = TcpListener::bind(proxy_bind)
        .await
        .map_err(|error| format!("cannot bind the proxy listener {proxy_bind}: {error}"))?;
    let admin_listener = TcpListener::bind(admin_bind)
        .await
        .map_err(|error| format!("cannot bind the admin listener {admin_bind}: {error}"))?;
    let proxy_addr = proxy_listener
        .local_addr()
        .map_err(|error| format!("cannot read the proxy listener address: {error}"))?;
    let admin_addr = admin_listener
        .local_addr()
        .map_err(|error| format!("cannot read the admin listener address: {error}"))?;
    state.set_listener_addrs(proxy_addr, admin_addr);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let proxy_task = tokio::spawn(accept_loop(
        proxy_listener,
        Arc::clone(&state),
        shutdown_rx.clone(),
        ListenerKind::Proxy,
    ));
    let admin_task = tokio::spawn(accept_loop(
        admin_listener,
        Arc::clone(&state),
        shutdown_rx.clone(),
        ListenerKind::Admin,
    ));
    let prune_task = tokio::spawn(prune_loop(Arc::clone(&state), shutdown_rx));
    Ok(Running {
        proxy_addr,
        admin_addr,
        shutdown: shutdown_tx,
        tasks: vec![proxy_task, admin_task, prune_task],
    })
}

/// Periodically release expired bans and quiet offence counters until shutdown (review LOW).
async fn prune_loop(state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(PRUNE_INTERVAL);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = interval.tick() => {
                state.bans.prune();
            }
        }
    }
}

/// Accept connections until shutdown.
async fn accept_loop(
    listener: TcpListener,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
    kind: ListenerKind,
) {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            serve_connection(stream, peer, state, kind).await;
                        });
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }
            }
        }
    }
}

/// Serve one HTTP/1.1 connection, catching handler panics per request.
async fn serve_connection(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    state: Arc<AppState>,
    kind: ListenerKind,
) {
    // Review R1-7: bound the number of concurrently served connections; overflow gets an opaque 503 and is closed.
    let Some(_connection_slot) = state.try_connection() else {
        write_busy_response(stream).await;
        return;
    };
    let service = service_fn(move |request: Request<Incoming>| {
        let handler_state = Arc::clone(&state);
        let panic_state = Arc::clone(&state);
        async move {
            let joined = tokio::spawn(async move {
                match kind {
                    ListenerKind::Proxy => {
                        crate::pipeline::handle(request, peer, handler_state).await
                    }
                    ListenerKind::Admin => crate::admin::handle(request, peer, handler_state).await,
                }
            })
            .await;
            match joined {
                Ok(response) => Ok::<Response<ResBody>, Infallible>(response),
                Err(error) => {
                    let ray_id = util::new_ray_id();
                    panic_state.note_caught_panic();
                    let panicked = error.is_panic();
                    panic_state.events.audit(
                        "system",
                        "panic_caught",
                        "request-handler",
                        &format!(
                            "ray {ray_id}: a request handler {}; the panic was caught and counted (R-09)",
                            if panicked { "panicked" } else { "was cancelled" }
                        ),
                    );
                    let json = false;
                    Ok(page_response(
                        &crate::blockpage::internal_error(&ray_id, json),
                        &ray_id,
                    ))
                }
            }
        }
    });
    // `half_close(true)`: a client may shut down its write side after sending the request (a normal way to signal
    // "end of request" for tools and for the tests' raw sockets); without this hyper closes before answering when it
    // sees that EOF while still reading.
    // `timer` + `header_read_timeout`: a client that stalls while sending the request head is cut off (review R1-7).
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .half_close(true)
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    let _ = builder
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

/// Answer an overflow connection with an opaque 503 page, then close it (review R1-7).
///
/// The page deliberately reveals nothing about the proxy's internals (no Ray ID, no counters, no tenant data).
async fn write_busy_response(mut stream: tokio::net::TcpStream) {
    const BODY: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
                        <title>Service Unavailable</title></head><body><h1>503 Service Unavailable</h1>\
                        <p>The proxy is busy. Please try again shortly.</p></body></html>";
    let response = format!(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{BODY}",
        BODY.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
    // Drain a bounded amount of whatever the client already sent before the socket is closed. On Windows, closing a
    // socket that still has unread inbound data resets the connection and the client can lose the 503 page.
    let mut sink = [0_u8; 1024];
    let mut drained = 0_usize;
    let drain = async {
        while drained < 16 * 1024 {
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(count) => drained = drained.saturating_add(count),
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_millis(100), drain).await;
}

/// Turn a rendered [`Page`] into a hyper response (adds the Ray ID and hardens the headers).
#[must_use]
pub fn page_response(page: &Page, ray_id: &str) -> Response<ResBody> {
    let status = StatusCode::from_u16(page.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = Response::new(util::full_body(page.body.clone()));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static(page.content_type),
    );
    headers.insert(
        hyper::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        hyper::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    if let Ok(value) = HeaderValue::from_str(ray_id) {
        headers.insert(HeaderName::from_static("hdd-ray-id"), value);
    }
    response
}

/// Turn an [`ApiResponse`] into a hyper response, copying every header (this is how the session cookie reaches the
/// browser) and adding the admin hardening headers.
#[must_use]
pub fn api_response(response: ApiResponse, ray_id: &str) -> Response<ResBody> {
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut wire = Response::new(util::full_body(response.body));
    *wire.status_mut() = status;
    {
        let headers = wire.headers_mut();
        for (name, value) in &response.headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.append(name, value);
            }
        }
        headers.insert(
            hyper::header::CONTENT_TYPE,
            HeaderValue::from_static(response.content_type),
        );
        headers.insert(
            hyper::header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        headers.insert(
            hyper::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        );
        if let Ok(value) = HeaderValue::from_str(ray_id) {
            headers.insert(HeaderName::from_static("hdd-ray-id"), value);
        }
    }
    wire
}

/// Serve one embedded UI asset (CSS/JS/image or page shell).
#[must_use]
pub fn asset_response(asset: &Asset, ray_id: &str) -> Response<ResBody> {
    let mut response = Response::new(util::full_body(Bytes::from_static(asset.body)));
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static(asset.content_type),
    );
    headers.insert(
        hyper::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        hyper::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    if let Ok(value) = HeaderValue::from_str(ray_id) {
        headers.insert(HeaderName::from_static("hdd-ray-id"), value);
    }
    response
}

/// A 303 redirect (used for the login/setup gates of the HTML surface).
#[must_use]
pub fn redirect_response(location: &str) -> Response<ResBody> {
    let mut response = Response::new(util::full_body("see other"));
    *response.status_mut() = StatusCode::SEE_OTHER;
    if let Ok(value) = HeaderValue::from_str(location) {
        response
            .headers_mut()
            .insert(hyper::header::LOCATION, value);
    }
    response
}

/// Build an error response from an [`crate::api::ApiError`].
#[must_use]
pub fn error_response(error: crate::api::ApiError, ray_id: &str) -> Response<ResBody> {
    api_response(error.into_response(), ray_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::MAX_CONNECTIONS;

    #[test]
    fn api_responses_copy_headers_and_add_hardening() {
        let response = ApiResponse::json(&serde_json::json!({"ok": true}))
            .with_header("Set-Cookie", "hdd_session=abc; HttpOnly; SameSite=Strict");
        let wire = api_response(response, "0123456789abcdef-HDD1");
        assert_eq!(wire.status(), StatusCode::OK);
        assert_eq!(
            wire.headers()
                .get(hyper::header::SET_COOKIE)
                .and_then(|value| value.to_str().ok()),
            Some("hdd_session=abc; HttpOnly; SameSite=Strict")
        );
        assert_eq!(
            wire.headers()
                .get(hyper::header::X_CONTENT_TYPE_OPTIONS)
                .and_then(|value| value.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            wire.headers()
                .get("hdd-ray-id")
                .and_then(|value| value.to_str().ok()),
            Some("0123456789abcdef-HDD1")
        );
    }

    #[test]
    fn pages_carry_the_ray_id_header_and_no_store() {
        let page = Page {
            status: 403,
            content_type: "text/html; charset=utf-8",
            body: "blocked".to_owned(),
        };
        let wire = page_response(&page, "0123456789abcdef-HDD1");
        assert_eq!(wire.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            wire.headers()
                .get(hyper::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
    }

    #[test]
    fn connection_cap_and_header_timeout_match_the_documented_bounds() {
        // `tests/proxy_core.rs` opens exactly this many held connections to test the overflow 503.
        assert_eq!(MAX_CONNECTIONS, 256);
        assert_eq!(HEADER_READ_TIMEOUT, Duration::from_secs(5));
        assert!(PRUNE_INTERVAL >= Duration::from_secs(1));
    }
}
