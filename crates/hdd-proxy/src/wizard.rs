//! The Add-site wizard's connection instructions (COLLAB.md Addenda 3 and 5).
//!
//! [`instructions`] turns the operator's site values into a numbered, copy-paste setup guide plus a configuration
//! snippet and the limitations that must be stated with it. The guide is deliberately honest: every method ends with
//! the "not protected yet" caveat, because HDD is only in front of the site once DNS/Cloudflare/nginx actually routes
//! traffic through the proxy, and the origin is only out of reach once the lockdown check has verified it (R-34).

use crate::api::{ConnectionMethod, SetupInstructions};
use crate::snippets;

/// The shared honesty caveat: HDD is one hop, the origin is another, and the site is not protected until both hold.
fn honesty(origin: &str) -> String {
    format!(
        "Not protected yet: while {origin} (or an address that reaches it) still answers directly, anyone can bypass \
         HDD. The site is only presented as protected after the origin is locked down and both the lockdown check and \
         the protection verification pass (R-34); HDD never claims more than the checks it has actually run."
    )
}

/// The limitation that applies to every method: the inspector is plain HTTP on loopback.
fn loopback_caveat() -> String {
    "The HDD inspector itself serves plain HTTP on loopback and must never be exposed directly: TLS is terminated by \
     Caddy, Cloudflare or nginx in front of it."
        .to_owned()
}

/// The origin allowlist caveat, naming the placeholder the operator must replace.
fn allowlist_caveat() -> String {
    format!(
        "Replace {} with the public IP of the HDD host (the TLS terminator) in the origin allowlist. If a CDN sits in \
         front of the origin, allow the CDN's egress ranges instead and keep the secret header check in place.",
        snippets::PROXY_IP_PLACEHOLDER
    )
}

fn lockdown_snippet(origin_secret_header: Option<&str>) -> String {
    let mut snippet =
        String::from("\n# ---- origin lockdown (R-34): allow only the HDD proxy IP ----\n");
    snippet.push_str(&snippets::origin_lockdown_htaccess());
    snippet.push('\n');
    snippet.push_str(&snippets::origin_lockdown_nginx());
    if let Some(header) = origin_secret_header {
        snippet.push_str(
            "\n# ---- or, when the origin has no fixed IP, a shared secret header ----\n",
        );
        snippet.push_str(&snippets::origin_secret_htaccess(header));
    }
    snippet
}

/// Generate the instructions for one connection method for a site with the given `host` and `origin`.
#[must_use]
pub fn instructions(
    method: ConnectionMethod,
    host: &str,
    origin: &str,
    origin_secret_header: Option<&str>,
) -> SetupInstructions {
    let host = snippets::one_line(host);
    let origin = snippets::one_line(origin);
    match method {
        ConnectionMethod::Dns => dns(&host, &origin, origin_secret_header),
        ConnectionMethod::Cloudflare => cloudflare(&host, &origin, origin_secret_header),
        ConnectionMethod::Nginx => nginx(&host, &origin, origin_secret_header),
        ConnectionMethod::Vercel => vercel(&host, &origin, origin_secret_header),
        ConnectionMethod::VercelFrontDoor => {
            vercel_front_door(&host, &origin, origin_secret_header)
        }
    }
}

fn dns(host: &str, origin: &str, origin_secret_header: Option<&str>) -> SetupInstructions {
    let mut snippet = snippets::dns_caddyfile(host);
    snippet.push_str(&lockdown_snippet(origin_secret_header));
    let mut caveats = vec![
        honesty(origin),
        loopback_caveat(),
        allowlist_caveat(),
        "DNS propagation and the certificate issuance happen outside HDD: run the check-lockdown and verify steps \
         after `dig +short` and the browser certificate look right."
            .to_owned(),
    ];
    if origin_secret_header.is_some() {
        caveats.push(
            "The secret header check on the origin is an alternative to the IP allowlist only when the origin has no \
             stable IP; never rely on the header alone if the origin could be reached without it."
                .to_owned(),
        );
    }
    SetupInstructions {
        method: ConnectionMethod::Dns,
        title: format!("DNS: point {host} at the HDD host and terminate TLS with Caddy"),
        steps: vec![
            format!(
                "Create an A record (or a CNAME) for {host} pointing at the public IP address of the HDD host, then \
                 wait for propagation: `dig +short {host}` must show the HDD address."
            ),
            "Install HDD on that host. The inspector listens on 127.0.0.1:8080 and is never exposed directly; Caddy \
             faces the internet and terminates TLS on ports 80/443."
                .to_owned(),
            "Add the Caddyfile snippet below and reload Caddy with `caddy reload --config /etc/caddy/Caddyfile`."
                .to_owned(),
            format!(
                "Lock the origin {origin} down with the allowlist snippet in the same block so only the HDD proxy's \
                 IP can reach it."
            ),
            "Open the Sites screen, press Check lockdown, then Verify protection with the typed host name: the site \
             is not protected until both checks pass."
                .to_owned(),
        ],
        snippet,
        caveats,
    }
}

fn cloudflare(host: &str, origin: &str, origin_secret_header: Option<&str>) -> SetupInstructions {
    let mut snippet = snippets::cloudflared_config(host);
    snippet.push_str(&lockdown_snippet(origin_secret_header));
    SetupInstructions {
        method: ConnectionMethod::Cloudflare,
        title: format!("Cloudflare: tunnel or orange-cloud proxy in front of {host}"),
        steps: vec![
            "Install `cloudflared` on the HDD host and create the tunnel: `cloudflared tunnel create hdd-demo`."
                .to_owned(),
            format!(
                "Write the config file from the snippet (replace the tunnel id) and route the DNS record with \
                 `cloudflared tunnel route dns hdd-demo {host}`."
            ),
            "Run the tunnel as a service: `cloudflared service install`, then `cloudflared tunnel run hdd-demo`."
                .to_owned(),
            "In the Cloudflare dashboard set SSL/TLS mode to Full (strict) so Cloudflare validates the HDD host's \
             certificate, and keep the record proxied (orange cloud)."
                .to_owned(),
            format!(
                "Lock the origin {origin} down with the allowlist snippet: a Cloudflare tunnel protects the tunnel \
                 path, not direct requests to the origin."
            ),
            "Press Check lockdown, then Verify protection with the typed host name."
                .to_owned(),
        ],
        snippet,
        caveats: vec![
            honesty(origin),
            loopback_caveat(),
            allowlist_caveat(),
            "Cloudflare sees the client connection; the HDD proxy sees the tunnel's loopback traffic. Configure \
             `trusted_proxies` for the X-Forwarded-For header or the client IP in HDD's events and bans will be the \
             tunnel address."
                .to_owned(),
            "An origin bound to a Cloudflare-only hostname still needs the lockdown check: a request that reaches the \
             origin without Cloudflare and without HDD is a bypass."
                .to_owned(),
        ],
    }
}

fn nginx(host: &str, origin: &str, origin_secret_header: Option<&str>) -> SetupInstructions {
    let mut snippet = snippets::nginx_public_front(host);
    snippet.push_str("\n# ---- origin lockdown (R-34): allow only the HDD proxy IP ----\n");
    snippet.push_str(&snippets::origin_lockdown_nginx());
    snippet.push_str(&snippets::origin_lockdown_htaccess());
    if let Some(header) = origin_secret_header {
        snippet.push('\n');
        snippet.push_str(&snippets::origin_secret_htaccess(header));
    }
    SetupInstructions {
        method: ConnectionMethod::Nginx,
        title: format!("nginx/Apache: proxy {host} through HDD in front of your existing origin"),
        steps: vec![
            format!(
                "Keep the existing origin at {origin} where it is; HDD becomes the new public entry point for {host}."
            ),
            "On the public host, add the nginx server block below (or the equivalent Apache reverse-proxy vhost). It \
             terminates TLS and proxies to the HDD inspector on 127.0.0.1:8080."
                .to_owned(),
            format!(
                "Point the {host} DNS record at that public host and verify the certificate covers the domain."
            ),
            format!(
                "On the origin server at {origin}, apply the allowlist snippet below so only the HDD proxy's IP can \
                 reach it; replace <HDD_PROXY_IP> with the HDD host's public address."
            ),
            "Press Check lockdown, then Verify protection with the typed host name: a site whose origin is still \
             reachable directly is not protected."
                .to_owned(),
        ],
        snippet,
        caveats: vec![
            honesty(origin),
            loopback_caveat(),
            allowlist_caveat(),
            "If the existing nginx already terminates TLS for the domain, add the HDD proxy_pass to that server block \
             instead of creating a second listener."
                .to_owned(),
        ],
    }
}

fn vercel(host: &str, origin: &str, origin_secret_header: Option<&str>) -> SetupInstructions {
    let header = origin_secret_header.unwrap_or(snippets::DEFAULT_ORIGIN_SECRET_HEADER);
    let mut snippet = snippets::nextjs_middleware(header);
    snippet.push('\n');
    snippet.push_str(&snippets::edge_middleware_alternative(header));
    snippet.push('\n');
    snippet.push_str(&snippets::node_function_lock(header));
    snippet.push('\n');
    snippet.push_str(&snippets::node_esm_lock(header));
    let mut caveats = vec![
        honesty(origin),
        "Constant-time comparison is not available in the Vercel edge runtime: the generated middleware uses a plain \
         equality check. Keep the secret long and random (32+ bytes) and rotate it if it may have leaked."
            .to_owned(),
        "Vercel Deployment Protection / Vercel Authentication must be off for the proxied path (or the bypass-secret \
         feature configured), otherwise the proxy's own requests are refused."
            .to_owned(),
        "Vercel sees only the HDD proxy's egress IPs and the X-Forwarded-For header HDD sets; log and rate-limit on \
         the forwarded client address if the app depends on client IPs."
            .to_owned(),
        "Your `*.vercel.app` address always points straight at Vercel, never at HDD. Visitors are protected only when \
         they arrive through the address that points at HDD, so share that address, not the Vercel one."
            .to_owned(),
        "Vercel's own documentation discourages putting a proxy in front of deployments: the extra hop costs latency \
         and Vercel caching sees the proxy as the client."
            .to_owned(),
        loopback_caveat(),
    ];
    if origin_secret_header.is_none() {
        caveats.push(format!(
            "This site has no origin_secret_header configured: set one (for example {}) and its environment variable \
             on both the HDD host and the Vercel project before enabling block mode.",
            snippets::DEFAULT_ORIGIN_SECRET_HEADER
        ));
    }
    SetupInstructions {
        method: ConnectionMethod::Vercel,
        title: format!("Protect {host}: connect your Vercel app in 6 simple steps"),
        steps: vec![
            format!(
                "Keep your app on Vercel. The Origin is your Vercel address ({origin}). Do not move the app and do not \
                 point your domain at Vercel. HDD already sends the right name to Vercel for you."
            ),
            format!(
                "Point {host} at the server that runs HDD, so visitors reach HDD first and HDD passes clean requests \
                 on to Vercel. (Testing on your own computer with 127.0.0.1? Skip this step.)"
            ),
            format!(
                "Give Vercel the secret. In Vercel open your project, then Settings, then Environment Variables, and \
                 add one named HDD_ORIGIN_SECRET with the secret value from HDD (the guided Add site screen shows it \
                 once). HDD sends the same secret in the `{header}` header on every request it forwards."
            ),
            "Add the lock. Next.js app: create a file named middleware.ts in your project, next to package.json, \
             paste only the first (main) version of the code below, and deploy again. Plain Node function (not \
             Next.js): paste the Node snippet at the very end of your handler file, nothing else changes. Never \
             add middleware.ts to a project that is not Next.js: it would fail every request. Either way, a request \
             without the secret must be refused."
                .to_owned(),
            "Let HDD in. In Vercel open Settings, then Deployment Protection, and turn Vercel Authentication off for \
             Production, otherwise Vercel refuses HDD's own requests."
                .to_owned(),
            "Check it. Press Check lockdown. Opening your .vercel.app address directly must now answer 403 \
             Forbidden. Until that works, the site is not protected."
                .to_owned(),
        ],
        snippet,
        caveats,
    }
}

/// The Vercel front-door guide (Addendum 7 item 3).
///
/// Visitors keep using the main Vercel address; the front-door block pasted at the very end of the Node handler sends
/// every request that did not come through HDD to HDD (instead of serving the app), and the origin is a **second**
/// address of the same project that only HDD uses. The lock/lock-split snippets of the default Vercel mode do not
/// apply here: this mode pastes exactly one self-contained block.
fn vercel_front_door(
    host: &str,
    origin: &str,
    origin_secret_header: Option<&str>,
) -> SetupInstructions {
    let header = origin_secret_header.unwrap_or(snippets::DEFAULT_ORIGIN_SECRET_HEADER);
    let environment = snippets::ORIGIN_SECRET_ENV;
    SetupInstructions {
        method: ConnectionMethod::VercelFrontDoor,
        title: format!("Front door: keep visitors on {host} and let HDD decide every request"),
        steps: vec![
            format!(
                "Keep visitors on {host}. The public host is your main address (the Vercel address visitors keep \
                 using, for example {host}). The Vercel address (origin) must be a SECOND address of the same \
                 Vercel project: use {origin}, for example a second production domain of that project. In Vercel \
                 open your project, then Domains, and add or keep a second production domain for the same project \
                 (or use another address of that same project, such as a deployment address). HDD forwards inspected \
                 requests only to that second address; never share it with visitors and never make it the public \
                 host."
            ),
            "Paste the front-door block at the very END of the file Vercel runs (the Node handler, usually \
             api/index.js or api/app.js): one self-contained block, no new file, and your own code stays exactly as \
             it is. A request that came through HDD is served; every other request is passed on to HDD (or refused \
             with a short page) instead of being served uninspected."
                .to_owned(),
            format!(
                "Add both environment variables in Vercel, then your project, then Settings, then Environment \
                 Variables (Production). {environment} = the secret value for this site (the Add site screen shows \
                 it once). HDD_GATE_URL = the public URL of HDD, for example the HTTPS address your tunnel or server \
                 serves: Vercel's servers call it, so HDD must be reachable from the internet. For demos, run \
                 `node scripts/hdd-tunnel.mjs --port 8080` from the repository root and use the URL it prints; the \
                 tunnel URL is temporary and changes when the tunnel restarts."
            ),
            "Redeploy the project so the new environment variables and the front-door block go live; the previous \
             deployment keeps answering until the redeploy finishes."
                .to_owned(),
            format!(
                "Check it. On the Sites screen press Check lockdown, then Verify protection with the typed host name \
                 {host}. Both checks run against the public host {host}, not the second address. The site is not \
                 protected until both checks pass."
            ),
        ],
        snippet: snippets::node_front_door(header),
        caveats: vec![
            "Not protected yet: the front-door block is only on after the environment variables are set and the \
             project is redeployed, the origin is only reached through that block while it is deployed, and the site \
             is only presented as protected after the lockdown check and the protection verification pass (R-34). \
             HDD never claims more than the checks it has actually run."
                .to_owned(),
            format!(
                "While {environment} is empty or unset the front-door block is off and the app answers everyone \
                 directly: set the variable and redeploy before calling the site protected."
            ),
            "When HDD cannot be reached the front door answers 503 with a short HTML page and never serves the app \
             uninspected; visitors see that page while HDD's public URL is down."
                .to_owned(),
            "Visitors stay on the Vercel address, so HDD's public URL (HDD_GATE_URL) must stay up and be reachable \
             from the internet: if it stops answering, the front door fails closed for every visitor."
                .to_owned(),
            "The gateway hop must be trusted: add the address Vercel reaches HDD from to `trusted_proxies`, otherwise \
             HDD cannot use the X-HDD-Gate-Host header for the site lookup and answers the neutral 404."
                .to_owned(),
            "The front-door block is for CommonJS Node handlers that export a request handler with module.exports. A \
             Next.js app should use the default (non-front-door) Vercel mode instead: the block does not run in \
             middleware or through an ES module export."
                .to_owned(),
            "Vercel Deployment Protection / Vercel Authentication must be off for the proxied path (or the \
             bypass-secret feature configured), otherwise the front door's own requests are refused."
                .to_owned(),
            loopback_caveat(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_method_generates_steps_and_caveats() {
        for method in [
            ConnectionMethod::Dns,
            ConnectionMethod::Cloudflare,
            ConnectionMethod::Nginx,
            ConnectionMethod::Vercel,
            ConnectionMethod::VercelFrontDoor,
        ] {
            let instructions =
                instructions(method, "demo.example.com", "http://127.0.0.1:8081", None);
            assert_eq!(instructions.method, method);
            assert!(!instructions.steps.is_empty());
            assert!(!instructions.title.is_empty());
            assert!(!instructions.caveats.is_empty());
        }
    }

    #[test]
    fn the_wizard_never_emits_a_control_character_from_the_host() {
        let instructions = instructions(
            ConnectionMethod::Nginx,
            "demo.example.com\nserver_name evil",
            "http://127.0.0.1:8081",
            None,
        );
        assert!(!instructions.snippet.contains("\nserver_name evil"));
    }
}
