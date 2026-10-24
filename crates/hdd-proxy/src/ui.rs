//! The embedded web UI (COLLAB.md Addendum 1) and the proxy's self-contained block page.
//!
//! Everything is compiled into the binary with `include_str!`: no external CDN, no build step, no files to deploy. The
//! demo server serves [`page_asset`] for the three page shells and [`asset`] for `/static/*`; the proxy data path uses
//! [`block_page`] for a 403 so a blocked request never depends on any other resource.

/// One embedded asset: the content type the server must send and the bytes themselves.
#[derive(Debug, Clone, Copy)]
pub struct Asset {
    /// The `Content-Type` value for the response.
    pub content_type: &'static str,
    /// The embedded body.
    pub body: &'static [u8],
}

const INDEX_HTML: &str = include_str!("ui/index.html");
const LANDING_HTML: &str = include_str!("ui/landing.html");
const LOGIN_HTML: &str = include_str!("ui/login.html");
const SETUP_HTML: &str = include_str!("ui/setup.html");
const APP_CSS: &str = include_str!("ui/app.css");
const APP_JS: &str = include_str!("ui/app.js");
const LOGIN_JS: &str = include_str!("ui/login.js");
const LANDING_JS: &str = include_str!("ui/landing.js");
const THEME_JS: &str = include_str!("ui/theme.js");
const SETUP_JS: &str = include_str!("ui/setup.js");
const FAVICON_SVG: &str = include_str!("ui/favicon.svg");
const FONT_BRICOLAGE: &[u8] = include_bytes!("ui/fonts/BricolageGrotesque-var.woff2");
const FONT_INSTRUMENT: &[u8] = include_bytes!("ui/fonts/InstrumentSans-var.woff2");
const FONT_PLEX_400: &[u8] = include_bytes!("ui/fonts/IBMPlexMono-400-normal.woff2");
const FONT_PLEX_500: &[u8] = include_bytes!("ui/fonts/IBMPlexMono-500-normal.woff2");
const WOFF2: &str = "font/woff2";

const HTML: &str = "text/html; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";
const JAVASCRIPT: &str = "text/javascript; charset=utf-8";
const SVG: &str = "image/svg+xml";

const fn asset_of(body: &'static str, content_type: &'static str) -> Asset {
    Asset {
        content_type,
        body: body.as_bytes(),
    }
}

/// The static asset for a `/static/*` path, or `None` for anything else.
///
/// The match is exact: there is no filesystem access, so path traversal, query strings and unknown files all return
/// `None` and the server answers 404.
#[must_use]
pub fn asset(path: &str) -> Option<Asset> {
    match path {
        "/static/app.css" => Some(asset_of(APP_CSS, CSS)),
        "/static/app.js" => Some(asset_of(APP_JS, JAVASCRIPT)),
        "/static/login.js" => Some(asset_of(LOGIN_JS, JAVASCRIPT)),
        "/static/landing.js" => Some(asset_of(LANDING_JS, JAVASCRIPT)),
        "/static/theme.js" => Some(asset_of(THEME_JS, JAVASCRIPT)),
        "/static/setup.js" => Some(asset_of(SETUP_JS, JAVASCRIPT)),
        "/static/favicon.svg" => Some(asset_of(FAVICON_SVG, SVG)),
        "/static/fonts/BricolageGrotesque-var.woff2" => Some(Asset {
            content_type: WOFF2,
            body: FONT_BRICOLAGE,
        }),
        "/static/fonts/InstrumentSans-var.woff2" => Some(Asset {
            content_type: WOFF2,
            body: FONT_INSTRUMENT,
        }),
        "/static/fonts/IBMPlexMono-400-normal.woff2" => Some(Asset {
            content_type: WOFF2,
            body: FONT_PLEX_400,
        }),
        "/static/fonts/IBMPlexMono-500-normal.woff2" => Some(Asset {
            content_type: WOFF2,
            body: FONT_PLEX_500,
        }),
        _ => None,
    }
}

/// The static HTML shell for a page path (`/` landing page, `/app` control panel, `/login`, `/setup`), or `None` otherwise.
#[must_use]
pub fn page_asset(path: &str) -> Option<Asset> {
    match path {
        "/" => Some(asset_of(LANDING_HTML, HTML)),
        "/app" => Some(asset_of(INDEX_HTML, HTML)),
        "/login" => Some(asset_of(LOGIN_HTML, HTML)),
        "/setup" => Some(asset_of(SETUP_HTML, HTML)),
        _ => None,
    }
}

const BLOCK_PAGE_DETAIL: &str = "Your request looked like an attack on this website, so it was blocked. If you \
                                 believe this is a mistake, you can tell the site owner.";

/// Escape a value for embedding in HTML text or an attribute.
fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

/// The response for a blocked request: status, `Content-Type` and body.
///
/// `json` selects the `application/problem+json` variant (used when the client sends `Accept: application/json`);
/// otherwise the body is a self-contained HTML page with inline CSS and no subresource requests. Both carry the same
/// documented text and the Ray ID.
#[must_use]
pub fn block_page(ray_id: &str, host: &str, json: bool) -> (u16, &'static str, String) {
    let ray = escape_html(ray_id);
    let site = escape_html(host);
    if json {
        let problem = serde_json::json!({
            "type": "about:blank",
            "title": "Access denied",
            "status": 403,
            "detail": BLOCK_PAGE_DETAIL,
            "ray_id": ray_id,
            "host": host,
            "category": "sqli",
        });
        let body = serde_json::to_string(&problem).unwrap_or_else(|_| {
            "{\"type\":\"about:blank\",\"title\":\"Access denied\",\"status\":403}".to_owned()
        });
        return (403, "application/problem+json", body);
    }
    let body = format!(
        "<!doctype html>\n\
<html lang=\"en\">\n\
<head>\n\
<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<meta name=\"color-scheme\" content=\"dark\">\n\
<title>Access denied</title>\n\
<style>\n\
:root{{color-scheme:dark}}\n\
*{{box-sizing:border-box}}\n\
body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#0a0f1c;color:#e9eef9;\n\
font-family:system-ui,-apple-system,\"Segoe UI\",Roboto,Arial,sans-serif;line-height:1.55;padding:1.5rem}}\n\
.card{{width:min(560px,100%);background:#151e33;border:1px solid #2c3b5e;border-radius:12px;padding:1.6rem}}\n\
.brand{{margin:0 0 .2rem;color:#7fb0ff;font-weight:800;letter-spacing:.12em;font-size:.85rem}}\n\
h1{{margin:.2rem 0 .7rem;font-size:1.6rem}}\n\
p{{margin:.5rem 0}}\n\
.detail{{font-size:1.02rem}}\n\
.ref{{margin-top:1.1rem;padding:.7rem .9rem;background:#060a13;border:1px solid #2c3b5e;border-radius:8px;\n\
font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.92rem;overflow-wrap:anywhere}}\n\
.site{{color:#a9b6d0;font-size:.88rem}}\n\
.fine{{margin-top:1.1rem;color:#a9b6d0;font-size:.82rem}}\n\
</style>\n\
</head>\n\
<body>\n\
<main class=\"card\" role=\"main\">\n\
<p class=\"brand\">HDD</p>\n\
<h1>Access denied</h1>\n\
<p class=\"detail\">{detail}</p>\n\
<p class=\"ref\">Reference: {ray}</p>\n\
<p class=\"site\">Site: {site}</p>\n\
<p class=\"fine\">The request was stopped before it reached the website. The reference number lets the site owner \n\
find the matching entry in the protection log; it is not a support address.</p>\n\
</main>\n\
</body>\n\
</html>\n",
        detail = BLOCK_PAGE_DETAIL,
        ray = ray,
        site = site,
    );
    (403, "text/html; charset=utf-8", body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assets_are_embedded_and_exact() {
        assert!(asset("/static/app.css").is_some());
        assert!(asset("/static/../src/api.rs").is_none());
        assert!(page_asset("/").is_some());
        assert!(page_asset("/app").is_some());
        assert!(page_asset("/login").is_some());
        assert!(page_asset("/setup").is_some());
        assert!(page_asset("/static/app.css").is_none());
    }

    #[test]
    fn block_page_escapes_the_host() {
        let (status, content_type, body) =
            block_page("0123456789abcdef-HDD1", "<script>alert(1)</script>", false);
        assert_eq!(status, 403);
        assert_eq!(content_type, "text/html; charset=utf-8");
        assert!(!body.contains("<script>alert(1)</script>"));
        assert!(body.contains("&lt;script&gt;"));
    }

    #[test]
    fn block_page_json_keeps_the_documented_fields() {
        let (status, content_type, body) = block_page("0123456789abcdef-HDD1", "example.com", true);
        assert_eq!(status, 403);
        assert_eq!(content_type, "application/problem+json");
        assert!(body.contains("\"ray_id\":\"0123456789abcdef-HDD1\""));
        assert!(body.contains("\"category\":\"sqli\""));
    }
}
