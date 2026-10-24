//! The branded, self-contained HTML/JSON pages the proxy and the admin listener return for refusals and errors.
//!
//! The 403 block page is owned by teammate D ([`crate::ui::block_page`]) so the demo has one branded page for both the
//! proxy path and the preview endpoint. The remaining pages (neutral 404 for an unknown host, 413 for the honest body
//! cap, 500/502/504) are rendered here with inline CSS and no external requests: a block or error page must never leak
//! a tenant or need the network to render.

use crate::ui;

/// A rendered page: status, content type and body.
#[derive(Debug, Clone)]
pub struct Page {
    /// The HTTP status code.
    pub status: u16,
    /// The `Content-Type` value.
    pub content_type: &'static str,
    /// The response body.
    pub body: String,
}

/// Whether the client asked for a machine-readable response (`Accept: application/json`).
#[must_use]
pub fn wants_json(accept: Option<&str>) -> bool {
    accept.is_some_and(|value| {
        value
            .to_ascii_lowercase()
            .split(',')
            .any(|part| part.trim().starts_with("application/json"))
    })
}

/// The branded 403 block page (delegated to the UI module so HTML and preview are identical).
#[must_use]
pub fn block_page(ray_id: &str, host: &str, json: bool) -> Page {
    let (status, content_type, body) = ui::block_page(ray_id, host, json);
    Page {
        status,
        content_type,
        body,
    }
}

/// The 403 for a client that is currently banned: same branded page, the decision happened earlier.
#[must_use]
pub fn banned_page(ray_id: &str, host: &str, json: bool) -> Page {
    block_page(ray_id, host, json)
}

/// A neutral 404 for a request whose `Host` is not configured; it carries no tenant data at all.
#[must_use]
pub fn not_found(json: bool) -> Page {
    if json {
        Page {
            status: 404,
            content_type: "application/problem+json",
            body: problem_json(
                "Not Found",
                404,
                "No site is configured for this host.",
                None,
            ),
        }
    } else {
        Page {
            status: 404,
            content_type: "text/html; charset=utf-8",
            body: shell(
                "Not found",
                "404 Not Found",
                "No site is configured for this host.",
                None,
            ),
        }
    }
}

/// The 413 page for a request body larger than [`hdd_waf_core::INSPECT_BODY_CAP`] (the documented hard cap).
#[must_use]
pub fn payload_too_large(ray_id: &str, json: bool, cap: usize) -> Page {
    let detail = format!(
        "The request body is larger than the {cap} byte inspection cap of this proxy; bodies above the cap are \
         refused rather than forwarded uninspected."
    );
    if json {
        Page {
            status: 413,
            content_type: "application/problem+json",
            body: problem_json("Payload Too Large", 413, &detail, Some(ray_id)),
        }
    } else {
        Page {
            status: 413,
            content_type: "text/html; charset=utf-8",
            body: shell(
                "Request too large",
                "413 Request too large",
                &detail,
                Some(ray_id),
            ),
        }
    }
}

/// The branded 408 page for a request body that did not arrive within the body-read deadline (review R1-7).
#[must_use]
pub fn request_timeout(ray_id: &str, json: bool) -> Page {
    let detail = "The request body did not arrive in time, so the request was abandoned before it was inspected or \
                  forwarded.";
    if json {
        Page {
            status: 408,
            content_type: "application/problem+json",
            body: problem_json("Request Timeout", 408, detail, Some(ray_id)),
        }
    } else {
        Page {
            status: 408,
            content_type: "text/html; charset=utf-8",
            body: shell(
                "Request timeout",
                "408 Request timeout",
                detail,
                Some(ray_id),
            ),
        }
    }
}

/// The branded 502 page when the origin cannot be reached or answers with a broken exchange.
#[must_use]
pub fn bad_gateway(ray_id: &str, json: bool) -> Page {
    let detail = "Hack Dev Defence could not get a valid response from the origin of this site. \
                  The site owner can check the origin health.";
    if json {
        Page {
            status: 502,
            content_type: "application/problem+json",
            body: problem_json("Bad Gateway", 502, detail, Some(ray_id)),
        }
    } else {
        Page {
            status: 502,
            content_type: "text/html; charset=utf-8",
            body: shell(
                "Origin unavailable",
                "502 Origin unavailable",
                detail,
                Some(ray_id),
            ),
        }
    }
}

/// The branded 504 page when the origin exchange exceeds the total timeout.
#[must_use]
pub fn gateway_timeout(ray_id: &str, json: bool) -> Page {
    let detail = "The origin of this site did not answer within the proxy timeout.";
    if json {
        Page {
            status: 504,
            content_type: "application/problem+json",
            body: problem_json("Gateway Timeout", 504, detail, Some(ray_id)),
        }
    } else {
        Page {
            status: 504,
            content_type: "text/html; charset=utf-8",
            body: shell(
                "Origin timed out",
                "504 Origin timed out",
                detail,
                Some(ray_id),
            ),
        }
    }
}

/// The branded 500 page for a handler failure (including a caught panic, R-09).
#[must_use]
pub fn internal_error(ray_id: &str, json: bool) -> Page {
    let detail =
        "The proxy hit an internal problem while handling this request. Nothing was forwarded.";
    if json {
        Page {
            status: 500,
            content_type: "application/problem+json",
            body: problem_json("Internal Server Error", 500, detail, Some(ray_id)),
        }
    } else {
        Page {
            status: 500,
            content_type: "text/html; charset=utf-8",
            body: shell("Internal error", "500 Internal error", detail, Some(ray_id)),
        }
    }
}

/// The documented RFC 7807 problem body (no tenant data, no stack trace).
fn problem_json(title: &str, status: u16, detail: &str, ray_id: Option<&str>) -> String {
    let mut value = serde_json::json!({
        "type": "about:blank",
        "title": title,
        "status": status,
        "detail": detail,
    });
    if let Some(ray_id) = ray_id
        && let Some(map) = value.as_object_mut()
    {
        map.insert(
            "ray_id".to_owned(),
            serde_json::Value::String(ray_id.to_owned()),
        );
    }
    value.to_string()
}

/// A minimal self-contained error page with inline CSS (no external request, no tenant data).
fn shell(title: &str, heading: &str, detail: &str, ray_id: Option<&str>) -> String {
    let reference = ray_id.map_or_else(String::new, |ray_id| {
        format!(
            "<p class=\"ref\">Reference: <code>{}</code></p>",
            crate::util::html_escape(ray_id)
        )
    });
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title} · Hack Dev Defence</title>\
         <style>body{{margin:0;font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#0b1020;color:#e8ecf8;\
         display:flex;min-height:100vh;align-items:center;justify-content:center}}\
         .card{{max-width:34rem;padding:2.5rem;border:1px solid #26314f;border-radius:16px;background:#111a33}}\
         h1{{margin:0 0 .75rem;font-size:1.6rem}}p{{line-height:1.6;color:#b9c3dc}}\
         .ref{{margin-top:1.5rem;font-size:.85rem;color:#8a97b8}}code{{color:#9fd1ff}}a{{color:#9fd1ff}}\
         </style></head><body><main class=\"card\"><p style=\"letter-spacing:.12em;font-size:.75rem;\
         text-transform:uppercase;color:#7f8db1\">Hack Dev Defence</p>\
         <h1>{heading}</h1><p>{detail}</p>{reference}\
         <p class=\"ref\">This page is generated by the proxy itself and makes no external requests.</p>\
         </main></body></html>",
        title = crate::util::html_escape(title),
        heading = crate::util::html_escape(heading),
        detail = crate::util::html_escape(detail),
        reference = reference,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_pages_are_self_contained_and_escape_input() {
        let page = bad_gateway("0123456789abcdef-HDD1", false);
        assert_eq!(page.status, 502);
        assert!(page.body.contains("0123456789abcdef-HDD1"));
        assert!(!page.body.contains("http://"));
        assert!(!page.body.contains("https://"));
        let escaped = shell("x", "<script>", "a & b", None);
        assert!(!escaped.contains("<script>"));
        assert!(escaped.contains("&lt;script&gt;"));
    }

    #[test]
    fn json_errors_use_problem_json() {
        let page = not_found(true);
        assert_eq!(page.content_type, "application/problem+json");
        let parsed: serde_json::Value =
            serde_json::from_str(&page.body).expect("problem json parses");
        assert_eq!(
            parsed.get("status").and_then(serde_json::Value::as_u64),
            Some(404)
        );
    }

    #[test]
    fn accept_header_negotiation_is_case_insensitive() {
        assert!(wants_json(Some("application/json")));
        assert!(wants_json(Some("text/html, Application/JSON")));
        assert!(!wants_json(Some("text/html")));
        assert!(!wants_json(None));
    }
}
