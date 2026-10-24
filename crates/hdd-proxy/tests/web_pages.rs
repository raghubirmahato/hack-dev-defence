//! Page, static-asset, block-page and setup-instruction tests for the HK1 web UI (COLLAB.md Addenda 1, 3, 5).
//!
//! The UI ships inside the binary, so these tests are the only realistic way to check it without a browser: every page
//! must be fetchable, every asset must be same-origin (no CDN), the block page must carry the exact documented copy in
//! both HTML and `application/problem+json` form, and every generated connection snippet must contain the real host,
//! origin and secret plus the honest "not protected until the origin is locked down" caveat (R-34).

use hdd_proxy::api::ConnectionMethod;
use hdd_proxy::snippets;
use hdd_proxy::ui::{self, Asset};
use hdd_proxy::wizard;

const HOST: &str = "demo.example.com";
const ORIGIN: &str = "http://127.0.0.1:8081";
const SECRET_HEADER: &str = "x-hdd-origin-secret";

fn text(asset: &Asset) -> String {
    String::from_utf8_lossy(asset.body).into_owned()
}

fn joined(values: &[String]) -> String {
    values.join("\n").to_lowercase()
}

fn assert_same_origin(label: &str, body: &str) {
    // The SVG XML namespace is an identifier, not a network request: ignore that one well-known URI.
    let without_namespace = body.replace("http://www.w3.org/2000/svg", "");
    assert!(
        !without_namespace.contains("http://") && !without_namespace.contains("https://"),
        "{label} must not reference an external origin (no CDN); offending body starts with: {}",
        body.chars().take(120).collect::<String>()
    );
}

#[test]
fn every_page_is_served_as_html() {
    for (path, key_strings) in [
        (
            "/",
            vec![
                "HDD",
                "How it works",
                "SQL injection",
                "What HDD does not do",
            ],
        ),
        (
            "/app",
            vec!["HDD", "Overview", "Events", "Sites", "Test console"],
        ),
        ("/login", vec!["Sign in", "Username", "Password"]),
        (
            "/setup",
            vec!["First-run setup", "Owner", "Username", "Email", "Password"],
        ),
    ] {
        let asset = ui::page_asset(path).expect("documented page path is embedded");
        assert!(
            asset.content_type.starts_with("text/html"),
            "{path} must be text/html, got {}",
            asset.content_type
        );
        assert!(!asset.body.is_empty(), "{path} must have a body");
        let body = text(&asset);
        for key in key_strings {
            assert!(body.contains(key), "{path} must contain {key:?}");
        }
        assert_same_origin(path, &body);
    }
    assert!(ui::page_asset("/nope").is_none());
    assert!(
        ui::page_asset("/static/app.css").is_none(),
        "page_asset only serves the page shells"
    );
}

#[test]
fn every_static_asset_is_served_with_its_content_type() {
    for (path, content_type) in [
        ("/static/app.css", "text/css"),
        ("/static/app.js", "text/javascript"),
        ("/static/login.js", "text/javascript"),
        ("/static/setup.js", "text/javascript"),
        ("/static/landing.js", "text/javascript"),
        ("/static/theme.js", "text/javascript"),
        ("/static/favicon.svg", "image/svg+xml"),
    ] {
        let asset = ui::asset(path).expect("documented asset is embedded");
        assert!(
            asset.content_type.starts_with(content_type),
            "{path} content type {} must start with {content_type}",
            asset.content_type
        );
        assert!(!asset.body.is_empty());
        assert_same_origin(path, &text(&asset));
    }
    // Exact-match only: no traversal, no unknown files, no query strings.
    for path in [
        "/static/",
        "/static/missing.js",
        "/static/../src/main.rs",
        "/static/app.js?cache=1",
        "/static/app.js/",
        "/app.js",
    ] {
        assert!(ui::asset(path).is_none(), "{path} must not be served");
    }
}

#[test]
fn pages_are_accessible_and_responsive_by_construction() {
    let index = text(&ui::page_asset("/app").expect("app shell"));
    assert!(
        index.contains("lang=\"en\""),
        "the document language is declared"
    );
    assert!(
        index.contains("name=\"viewport\""),
        "mobile viewport is declared"
    );
    assert!(
        index.contains("Skip to content"),
        "there is a skip link (WCAG 2.2 AA)"
    );
    assert!(index.contains("<main"), "the shell has a main landmark");
    assert!(
        index.contains("aria-current"),
        "navigation marks the current screen"
    );
    for landmark in ["<header", "<nav", "<main"] {
        assert!(index.contains(landmark), "missing landmark {landmark}");
    }
    let landing = text(&ui::page_asset("/").expect("landing page"));
    assert!(landing.contains("lang=\"en\"") && landing.contains("name=\"viewport\""));
    assert!(
        landing.contains("Skip to content")
            && landing.contains("<main")
            && landing.contains("<header")
    );
    let login = text(&ui::page_asset("/login").expect("login page"));
    assert!(login.contains("<label"), "the login form has labels");
    assert!(
        login.contains("autocomplete"),
        "the login form helps password managers"
    );
    let setup = text(&ui::page_asset("/setup").expect("setup page"));
    assert!(setup.contains("<label"), "the setup form has labels");
    assert!(
        setup.contains("aria-live") || login.contains("aria-live"),
        "errors are announced"
    );

    let css = text(&ui::asset("/static/app.css").expect("stylesheet"));
    assert!(css.contains(":focus-visible"), "keyboard focus is visible");
    assert!(css.contains("@media"), "the layout is responsive");
    assert!(
        css.contains("prefers-reduced-motion"),
        "motion respects the user preference"
    );
    assert!(css.contains("var(--bg)"), "the dark theme is token-driven");
}

#[test]
fn the_web_ui_only_calls_documented_api_paths() {
    let script = text(&ui::asset("/static/app.js").expect("app script"));
    let allowed_prefixes = [
        "/api/events",
        "/api/bans",
        "/api/guards",
        "/api/sites",
        "/api/inspect",
        "/api/block-preview",
        "/api/account",
        "/api/users",
        "/api/me",
        "/api/login",
        "/api/logout",
        "/api/setup-status",
        "/api/setup",
    ];
    let mut seen = Vec::new();
    let mut rest = script.as_str();
    while let Some(position) = rest.find("/api/") {
        let after = rest.get(position..).unwrap_or_default();
        let end = after
            .char_indices()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.')))
            .map(|(index, _)| index)
            .unwrap_or(after.len());
        let path = after.get(..end).unwrap_or_default().to_owned();
        seen.push(path);
        rest = after.get(end..).unwrap_or_default();
    }
    assert!(
        seen.len() >= 12,
        "the UI must exercise the API, found {seen:?}"
    );
    for path in &seen {
        assert!(
            allowed_prefixes
                .iter()
                .any(|prefix| path.starts_with(prefix)),
            "the UI calls {path:?}, which is not a documented api::paths route"
        );
    }
    // The login and setup pages call the public endpoints too, under the same API (R-27).
    for asset in ["/static/login.js", "/static/setup.js"] {
        let script = text(&ui::asset(asset).expect("script"));
        for required in ["/api/login", "/api/setup"] {
            if asset == "/static/setup.js" && required == "/api/login" {
                continue;
            }
            assert!(script.contains(required), "{asset} must call {required}");
        }
        assert!(
            !script.contains("XMLHttpRequest"),
            "{asset} uses fetch(), not a second transport"
        );
    }
}

#[test]
fn empty_states_are_honest_and_never_fabricate_numbers() {
    let script = text(&ui::asset("/static/app.js").expect("app script"));
    for honest_empty_state in [
        "No events yet",
        "No bans",
        "No sites configured",
        "No custom rules",
        "No API tokens",
        "No active sessions",
    ] {
        assert!(
            script.contains(honest_empty_state),
            "missing honest empty state: {honest_empty_state}"
        );
    }
    assert!(
        !script.contains("sample data"),
        "the UI must not ship sample rows"
    );
    assert!(
        !script.contains("Math.random"),
        "the UI must not invent numbers"
    );
}

#[test]
fn block_page_html_carries_the_documented_copy() {
    let (status, content_type, body) = ui::block_page("0123456789abcdef-HDD1", HOST, false);
    assert_eq!(status, 403);
    assert_eq!(content_type, "text/html; charset=utf-8");
    assert!(
        body.contains("<style"),
        "the block page styles itself inline"
    );
    assert!(!body.contains("<script"), "the block page runs no script");
    assert!(
        !body.contains("src="),
        "the block page makes no subresource request"
    );
    assert!(body.contains("Access denied"));
    assert!(body.contains(
        "Your request looked like an attack on this website, so it was blocked. If you believe this is a mistake, you can tell the site owner."
    ));
    assert!(body.contains("Reference: 0123456789abcdef-HDD1"));
    assert!(body.contains(HOST), "the page names the site");
    assert_same_origin("block page", &body);
}

#[test]
fn block_page_json_is_application_problem_json() {
    let (status, content_type, body) = ui::block_page("fedcba9876543210-HDD1", HOST, true);
    assert_eq!(status, 403);
    assert_eq!(content_type, "application/problem+json");
    let value: serde_json::Value =
        serde_json::from_str(&body).expect("problem detail is valid JSON");
    assert_eq!(
        value.get("title").and_then(serde_json::Value::as_str),
        Some("Access denied")
    );
    assert_eq!(
        value.get("status").and_then(serde_json::Value::as_u64),
        Some(403)
    );
    assert_eq!(
        value.get("ray_id").and_then(serde_json::Value::as_str),
        Some("fedcba9876543210-HDD1")
    );
    assert_eq!(
        value.get("host").and_then(serde_json::Value::as_str),
        Some(HOST)
    );
    assert_eq!(
        value.get("category").and_then(serde_json::Value::as_str),
        Some("sqli")
    );
    assert!(
        value
            .get("detail")
            .and_then(serde_json::Value::as_str)
            .is_some()
    );
}

#[test]
fn block_page_has_no_literal_backslash_n_in_styles_or_attributes() {
    // Regression (HK1 review round 1, LOW): the Rust format string double-escaped `\n`, so the shipped
    // page contained a visible literal backslash-n that broke `font-family`/`line-height`.
    for json in [false, true] {
        let (_, _, body) = ui::block_page("0123456789abcdef-HDD1", HOST, json);
        assert!(
            !body.contains("\\n"),
            "the block page must not contain a literal backslash-n sequence (json={json})"
        );
    }
    let (_, _, html) = ui::block_page("0123456789abcdef-HDD1", HOST, false);
    let style = html
        .split_once("<style>")
        .and_then(|(_, rest)| rest.split_once("</style>"))
        .map(|(style, _)| style)
        .expect("the block page has an inline style block");
    assert!(
        !style.contains('\\'),
        "no literal backslash may appear in the inline CSS: {style}"
    );
    assert!(
        html.contains("font-family:system-ui") && html.contains("line-height:1.55"),
        "the body CSS declarations must survive the formatting"
    );
    assert!(
        html.contains("font-family:ui-monospace") && html.contains("overflow-wrap:anywhere"),
        "the reference CSS declarations must survive the formatting"
    );
}

#[test]
fn block_page_escapes_host_input() {
    let evil_host = "evil.example.com\" onload=\"alert(1)";
    let (_, _, body) = ui::block_page("0123456789abcdef-HDD1", evil_host, false);
    assert!(
        !body.contains("onload=\"alert(1)\""),
        "host must be HTML-escaped"
    );
    assert!(body.contains("evil.example.com"));
}

#[test]
fn dns_instructions_include_caddy_and_the_lockdown_helper() {
    let instructions = wizard::instructions(ConnectionMethod::Dns, HOST, ORIGIN, None);
    assert_eq!(instructions.method, ConnectionMethod::Dns);
    assert!(
        instructions.steps.len() >= 3,
        "the operator gets numbered real steps"
    );
    assert!(instructions.title.contains("DNS") || instructions.title.contains("dns"));
    let all = format!(
        "{}\n{}\n{}",
        instructions.title,
        instructions.steps.join("\n"),
        instructions.snippet
    );
    assert!(all.contains(HOST));
    assert!(instructions.snippet.contains("reverse_proxy"));
    assert!(
        instructions.snippet.contains("127.0.0.1:8080") || instructions.snippet.contains("HDD")
    );
    assert!(
        all.to_lowercase().contains("lock"),
        "the DNS method must mention the origin lockdown (R-34)"
    );
    let caveats = joined(&instructions.caveats);
    assert!(
        caveats.contains("not protected"),
        "honesty caveat is mandatory"
    );
    assert!(caveats.contains("locked down") || caveats.contains("lock down"));
}

#[test]
fn cloudflare_instructions_include_a_tunnel_config() {
    let instructions = wizard::instructions(ConnectionMethod::Cloudflare, HOST, ORIGIN, None);
    assert_eq!(instructions.method, ConnectionMethod::Cloudflare);
    let all = format!(
        "{}\n{}\n{}",
        instructions.title,
        instructions.steps.join("\n"),
        instructions.snippet
    );
    assert!(all.contains(HOST));
    assert!(all.contains("cloudflared") || all.to_lowercase().contains("tunnel"));
    assert!(instructions.snippet.to_lowercase().contains("ingress"));
    assert!(joined(&instructions.caveats).contains("not protected"));
}

#[test]
fn nginx_instructions_include_the_proxy_block_and_origin_allowlist() {
    let instructions = wizard::instructions(ConnectionMethod::Nginx, HOST, ORIGIN, None);
    assert_eq!(instructions.method, ConnectionMethod::Nginx);
    let all = format!(
        "{}\n{}",
        instructions.steps.join("\n"),
        instructions.snippet
    );
    assert!(all.contains(HOST));
    assert!(
        all.contains(ORIGIN),
        "the generated snippets name the real origin"
    );
    assert!(all.contains("proxy_pass"));
    assert!(
        all.contains("allow"),
        "the origin allowlist is part of the instructions"
    );
    assert!(
        all.contains("deny"),
        "the origin allowlist is part of the instructions"
    );
    assert!(joined(&instructions.caveats).contains("not protected"));
}

#[test]
fn vercel_instructions_generate_nextjs_middleware_and_state_the_edge_limitation() {
    let instructions =
        wizard::instructions(ConnectionMethod::Vercel, HOST, ORIGIN, Some(SECRET_HEADER));
    assert_eq!(instructions.method, ConnectionMethod::Vercel);
    let all = format!(
        "{}\n{}\n{}",
        instructions.title,
        instructions.steps.join("\n"),
        instructions.snippet
    );
    assert!(all.contains(HOST));
    assert!(
        instructions
            .steps
            .iter()
            .any(|step| step.contains(".vercel.app")),
        "the serverless origin is explained"
    );
    assert!(
        instructions.snippet.contains("middleware.ts"),
        "a Next.js middleware.ts snippet is generated"
    );
    assert!(
        instructions.snippet.contains("NextResponse"),
        "the snippet is real Next.js code"
    );
    assert!(
        instructions.snippet.contains(SECRET_HEADER),
        "the snippet enforces the configured secret header"
    );
    assert!(
        instructions.snippet.contains("process.env"),
        "the secret comes from the environment"
    );
    assert!(
        instructions
            .snippet
            .to_lowercase()
            .contains("constant-time"),
        "the edge middleware documents the missing constant-time compare"
    );
    let caveats = joined(&instructions.caveats);
    assert!(
        caveats.contains("not protected"),
        "honesty caveat is mandatory"
    );
    assert!(caveats.contains("vercel"));
    assert!(
        caveats.contains("deployment protection") || caveats.contains("authentication"),
        "the Vercel auth limitation is documented"
    );
    // The serverless method must warn when the site has no secret header configured at all.
    let unconfigured = wizard::instructions(ConnectionMethod::Vercel, HOST, ORIGIN, None);
    let caveats = joined(&unconfigured.caveats);
    assert!(
        caveats.contains("origin_secret_header") || caveats.contains("secret header"),
        "a missing secret header is called out: {caveats}"
    );
}

#[test]
fn every_connection_method_is_honest_about_not_being_protected_yet() {
    for method in [
        ConnectionMethod::Dns,
        ConnectionMethod::Cloudflare,
        ConnectionMethod::Nginx,
        ConnectionMethod::Vercel,
    ] {
        let instructions = wizard::instructions(method, HOST, ORIGIN, Some(SECRET_HEADER));
        assert!(!instructions.steps.is_empty());
        assert!(!instructions.snippet.is_empty());
        let all = format!(
            "{}\n{}\n{}\n{}",
            instructions.title,
            instructions.steps.join("\n"),
            instructions.snippet,
            instructions.caveats.join("\n")
        );
        let lower = all.to_lowercase();
        assert!(
            lower.contains("not protected"),
            "{method:?} must say the site is not protected yet (R-34)"
        );
        assert!(
            !lower.contains("fully protected"),
            "{method:?} must not make an absolute claim (R-32)"
        );
        assert!(
            !lower.contains("complete protection"),
            "{method:?} must not make an absolute claim"
        );
        assert!(
            !lower.contains("100%"),
            "{method:?} must not make an absolute claim"
        );
        assert!(
            lower.contains("lock"),
            "{method:?} must mention the origin lockdown"
        );
    }
}

// ---------------------------------------------------------------- Addendum 7 item 3: the Vercel front door

/// The public host of a front-door site is the main Vercel address visitors keep using.
const FRONT_HOST: &str = "hdd-demo-shop.vercel.app";
/// The second address of the same Vercel project, used only as the origin HDD forwards inspected requests to.
const FRONT_ORIGIN: &str = "https://hdd-demo-shop-git-main-team.vercel.app";

#[test]
fn front_door_instructions_explain_the_two_addresses_the_gate_url_and_the_checks() {
    let instructions = wizard::instructions(
        ConnectionMethod::VercelFrontDoor,
        FRONT_HOST,
        FRONT_ORIGIN,
        Some(SECRET_HEADER),
    );
    assert_eq!(instructions.method, ConnectionMethod::VercelFrontDoor);
    assert!(
        instructions.title.to_lowercase().contains("front door"),
        "the title names the front-door mode: {}",
        instructions.title
    );
    assert!(instructions.title.contains(FRONT_HOST));
    assert!(!instructions.steps.is_empty());

    let steps = instructions.steps.join("\n");
    let lower = steps.to_lowercase();
    // (1) the two addresses and where to find the second one.
    assert!(steps.contains(FRONT_HOST), "the public host is named");
    assert!(steps.contains(FRONT_ORIGIN), "the second address is named");
    assert!(
        lower.contains("second address"),
        "the origin is explained as a second address: {steps}"
    );
    assert!(
        lower.contains("same vercel project"),
        "the origin must belong to the same Vercel project: {steps}"
    );
    assert!(
        lower.contains("main address"),
        "the public host is the main address visitors keep: {steps}"
    );
    assert!(
        lower.contains("domains"),
        "the guide says where to find or add the second address: {steps}"
    );
    assert!(
        lower.contains("public host"),
        "the guide says which address is public: {steps}"
    );
    // (2) the front-door block goes at the very END of the Node handler file.
    assert!(lower.contains("very end"), "paste at the very END: {steps}");
    assert!(
        lower.contains("handler"),
        "the front-door block is for a Node handler: {steps}"
    );
    // (3) the two environment variables, the honesty caveat and the tunnel helper for demos.
    assert!(
        lower.contains("hdd_gate_url"),
        "the HDD_GATE_URL variable is explained: {steps}"
    );
    assert!(
        lower.contains("reachable from the internet"),
        "the guide admits HDD must be reachable from the internet: {steps}"
    );
    assert!(
        lower.contains("scripts/hdd-tunnel.mjs"),
        "the tunnel helper is named for demos: {steps}"
    );
    assert!(
        lower.contains("temporary"),
        "the tunnel URL is stated to be temporary: {steps}"
    );
    // (4) redeploy.
    assert!(
        lower.contains("redeploy"),
        "the guide says to redeploy: {steps}"
    );
    // (5) the same checks as today, run against the public host.
    assert!(lower.contains("check lockdown"));
    assert!(lower.contains("verify protection"));
    assert!(
        lower.contains("not the second address"),
        "the checks run against the public host, not the second address: {steps}"
    );
    assert!(
        lower.contains("not protected"),
        "the steps state the site is not protected until the checks pass: {steps}"
    );

    // Step 2 pastes the shared front-door block, one self-contained CommonJS block, never the lock/lock split.
    assert_eq!(
        instructions.snippet,
        snippets::node_front_door(SECRET_HEADER),
        "the front-door guide pastes the shared front-door block"
    );
    let snippet = instructions.snippet.to_lowercase();
    assert!(snippet.contains("hdd_gate_url"));
    assert!(
        snippet.contains("module.exports"),
        "a CommonJS handler is wrapped"
    );
    assert!(snippet.contains(snippets::ORIGIN_SECRET_ENV.to_ascii_lowercase().as_str()));
    assert!(
        snippet.contains("x-hdd-gate-hop"),
        "the front-door block marks the forwarded hop"
    );
    assert!(
        snippet.contains("hack dev defence"),
        "the front-door block keeps the honest refusal message"
    );
    assert!(
        !snippet.contains("middleware.ts"),
        "no Next.js lock in front-door mode"
    );
    assert!(
        !snippet.contains("nextresponse"),
        "no Next.js lock in front-door mode"
    );
    assert!(
        !snippet.contains("node esm lock"),
        "no ES-module lock in front-door mode"
    );

    let caveats = joined(&instructions.caveats);
    assert!(
        caveats.contains("not protected"),
        "honesty caveat is mandatory"
    );
    assert!(
        caveats.contains("hdd_origin_secret"),
        "the wrapper is off while the secret variable is empty"
    );
    assert!(
        caveats.contains("503"),
        "the front door answers 503 rather than serving the app when HDD is unreachable"
    );
    assert!(
        caveats.contains("trusted_proxies"),
        "the gateway hop must be trusted for gate-host routing"
    );
    assert!(
        caveats.contains("internet") && caveats.contains("public url"),
        "HDD's public URL must stay reachable from the internet"
    );
    assert!(
        caveats.contains("commonjs"),
        "the block is for CommonJS Node handlers"
    );
    assert!(
        caveats.contains("next.js"),
        "a Next.js app must use the default mode instead"
    );
    for forbidden in ["fully protected", "complete protection", "100%"] {
        assert!(
            !caveats.contains(forbidden),
            "the front-door caveats must not make an absolute claim: {forbidden}"
        );
    }
}

#[test]
fn the_default_vercel_mode_still_generates_the_lock_block() {
    let instructions =
        wizard::instructions(ConnectionMethod::Vercel, HOST, ORIGIN, Some(SECRET_HEADER));
    assert_eq!(instructions.method, ConnectionMethod::Vercel);
    // (b) the existing default path is unchanged: the Next.js middleware plus the lock block are still generated.
    assert!(instructions.snippet.contains("middleware.ts"));
    assert!(instructions.snippet.contains("NextResponse"));
    assert!(instructions.snippet.contains("process.env"));
    assert!(
        instructions
            .snippet
            .to_lowercase()
            .contains("constant-time")
    );
    assert!(
        instructions.snippet.contains("Node function lock"),
        "the CommonJS lock block is still part of the default guide"
    );
    assert!(
        !instructions.snippet.contains("HDD_GATE_URL"),
        "the default Vercel mode does not mention the front door"
    );
}

#[test]
fn the_vercel_quick_mode_offers_the_front_door_choice_and_the_second_address() {
    let script = text(&ui::asset("/static/app.js").expect("app script"));
    for required in [
        // The exact choice text next to the default.
        "Keep visitors on my Vercel address (front door)",
        // The second address of the same project, where to find it and why it exists.
        "Second address of the same project",
        "second production domain",
        "Vercel → your project → Domains",
        // The API contract: the front-door connection key and host/origin wiring.
        "vercel_front_door",
        "HDD_GATE_URL",
        "scripts/hdd-tunnel.mjs",
        "very END",
        // Client-side refusal that mirrors the server-side refusal wording.
        "front door needs a second address of the same Vercel project",
    ] {
        assert!(
            script.contains(required),
            "the Vercel quick mode must contain {required:?}"
        );
    }
    // The server refuses an origin that equals the public host; the browser says so before sending the request.
    assert!(
        script.contains("same address"),
        "the browser explains that the public host and the second address cannot be the same"
    );
    // The default (no front door) quick path is unchanged: it still creates a plain `vercel` site.
    assert!(
        script.contains("connection: \"vercel\""),
        "the default Vercel path still sends connection vercel"
    );
    assert!(
        script.contains("generate_origin_secret: true"),
        "both quick paths still let HDD generate the origin secret"
    );
}

#[test]
fn the_lumina_fonts_are_self_hosted_and_wired_into_the_stylesheet() {
    let css = text(&ui::asset("/static/app.css").expect("stylesheet"));
    assert!(css.contains("@font-face"));
    for family in [
        "\"Bricolage Grotesque\"",
        "\"Instrument Sans\"",
        "\"IBM Plex Mono\"",
    ] {
        assert!(css.contains(family), "{family} is declared");
    }
    assert!(
        !css.contains("fonts.googleapis") && !css.contains("http://") && !css.contains("https://")
    );
    for (path, minimum) in [
        ("/static/fonts/BricolageGrotesque-var.woff2", 40_000),
        ("/static/fonts/InstrumentSans-var.woff2", 15_000),
        ("/static/fonts/IBMPlexMono-400-normal.woff2", 8_000),
        ("/static/fonts/IBMPlexMono-500-normal.woff2", 8_000),
    ] {
        let font = ui::asset(path).unwrap_or_else(|| panic!("{path} is embedded"));
        assert_eq!(font.content_type, "font/woff2");
        assert!(font.body.len() > minimum, "{path} is a real font file");
        assert_eq!(
            font.body.get(..4),
            Some(&b"wOF2"[..]),
            "{path} is a WOFF2 file"
        );
        assert!(css.contains(path), "the stylesheet loads {path}");
    }
    assert!(
        ui::asset("/static/fonts/../app.js").is_none(),
        "no path traversal"
    );
    assert!(ui::asset("/static/fonts/unknown.woff2").is_none());
}

#[test]
fn every_page_asks_the_browser_not_to_keep_a_copy() {
    for path in ["/", "/app", "/login", "/setup"] {
        let page = text(&ui::page_asset(path).expect("page"));
        assert!(page.contains("http-equiv=\"Cache-Control\""), "{path}");
        assert!(page.contains("no-store"), "{path}");
        assert!(page.contains("http-equiv=\"Pragma\""), "{path}");
    }
}
