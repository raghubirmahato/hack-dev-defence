# Information architecture and URL scheme

Status: v1, written for T-0014 (REQ-UXR-04). Sources: spec B2.1 (surfaces and hosts), B2.2 (URL map), B2.3
(navigation), B4.2 (permission catalog), B6.1 (API conventions and rate-limit classes) and B12.1 (screen table). The
machine-readable companion is [routes.toml](routes.toml); `cargo xtask ux-docs` checks it and this document together.

The route table is the contract for T-0073 (`xtask routes check`, which compares it with the router) and for T-0125
(the route permission test). A screen that is not in the table is not routable, and a route without a permission is not
authorised.

## Surfaces and hosts

Six surfaces exist, and each has its own host and exposure.

| Surface | Host | Who uses it | Exposure |
| --- | --- | --- | --- |
| `public` | `www.{{PLATFORM_DOMAIN}}` | Anyone, including search engines | Public, and proxied by HDD itself when the platform is dogfooded |
| `app` | `app.{{PLATFORM_DOMAIN}}` | Signed-in tenant users, and the authentication pages | Public in `saas`; an allowlist or a tunnel in `owner_only` |
| `admin` | `admin.{{PLATFORM_DOMAIN}}` | Platform staff only | Never public by default: tunnel or WireGuard, else `admin_cidrs` plus MFA and step-up |
| `api` | `api.{{PLATFORM_DOMAIN}}` | API clients with bearer keys | Public in `saas`; bearer keys only, and the host never accepts or sets a session cookie |
| `status` | `status.{{PLATFORM_DOMAIN}}` | Anyone | Hosted away from the VPS where the operator can arrange it |
| `data-plane` | A customer's own host names | The visitors of a protected site | Served by HDD for every request path on that host |

The admin host serves only platform-scoped routes and the admin API mount; the tenant API is mounted same-origin on
`app` so that cookie sessions and CSRF checks work without cross-origin requests. The `api` host serves the same
OpenAPI document and accepts bearer credentials only; a request carrying a session cookie is rejected instead of
silently downgraded.

In the local profile (`runtime.profile: local`) the platform domain is `hdd.localhost`, the surfaces keep their
prefixes, the admin surface is loopback-only, and a protected local site is reached at `<slug>.hdd.localhost`.

## URL rules

1. A path is lowercase, and words inside a segment are separated by a hyphen rather than an underscore.
   Test: a pattern with an uppercase letter or a stray underscore fails `cargo xtask ux-docs`.
2. No path ends in a slash; the root path `/` is the only exception.
   Test: a pattern with a trailing slash fails the route check.
3. A record is addressed by an opaque prefixed identifier, never by a name or an e-mail address.
   Test: a pattern with an `{email}` placeholder fails the route check.
4. A token never travels in a query string, and no route takes a credential in the path except the token routes listed
   below.
   Test: a `{token}` parameter on an unlisted route fails the route check.
5. Query parameters carry filters, sort order and deep-link state only; they never carry identity, secrets or full
   payloads.
   Test: a pattern containing a question mark fails the route check, because routing matches the path only.
6. A redirect is canonical, single-hop and audited: one permanent target per retired path, no chains.
   Test: the redirect table has exactly one source and one target per row (`T-0024` implements the table check).
7. The route table is the single source of paths; a router change without a table change fails the build.
   Test: `xtask routes check` compares the table with the router from T-0073 and fails on a difference.
8. The reserved data-plane prefix `/__hdd/` is the only place where an underscore appears in a literal pattern.
   Test: the underscore rule in the route check exempts that prefix and nothing else.

## Identifier format

Every stored object gets a prefixed identifier. The prefixes are `org_`, `dom_`, `usr_`, `rule_`, `ban_`, `evt_`,
`whk_`, `key_`, `cert_`, `rpt_`, `inv_` and `apl_`. The part after the underscore is 26 characters of lowercase
base32 (the RFC 4648 alphabet without padding, lowercase) encoding the object's UUIDv7.

Regex: `^(org|dom|usr|rule|ban|evt|whk|key|cert|rpt|inv|apl)_[a-z2-7]{26}$`

Example: `org_ab2cd3ef4gh5jk6mn7pq2rs3tu`

Validation rejects an unknown prefix, a wrong length, an uppercase character and characters outside the base32
alphabet. Organizations are the one exception in a URL: a tenant is addressed by its slug, and the slug is validated
separately.

## Deep linking

State that a reader would want to keep goes in the query string. State that is ephemeral stays out of it.

| State | Where it lives | Why |
| --- | --- | --- |
| Selected tab | `?tab=waf` | A link to the same screen opens the same tab |
| Wizard step | `?step=3` | A wizard can be resumed, and Back moves one step |
| List filters and sort | `?category=sqli&from=...&sort=...` | A filtered view is shareable and survives a reload |
| Detail drawer | `?event=evt_...` or `?panel=rules` | The URL names the open panel, so it can be linked |
| Saved view | `?view=...` | A named view renders the same filters for everyone who can read it |

A drawer closes with `Esc`, returns focus to the control that opened it, and removes its parameter from the URL. The
live feed's pause state is not linked; it is a per-session preference.

## Redirects

- After login, a return URL is accepted only when it is a relative same-origin path that begins with `/app/` or
  `/admin/`. Absolute URLs, protocol-relative targets, backslashes, a scheme or a host are rejected. A rejected target
  falls back to the last organisation overview, and the redirect is a 303 so the POST is not replayed.
- Renaming an organisation slug keeps the old slug working with a 301 for 30 days; the redirect is recorded and the
  old slug is not issued to another tenant during that window.
- A retired path redirects once, in one hop, to its permanent replacement. Chains are not allowed.
- A trailing slash on a real path returns a 301 to the canonical path; the router does not rewrite silently.
- HTTP is redirected to HTTPS with a 308 at the edge before HDD sees the request.
- When the status host is configured, `/status` on www redirects to it with a 301.

## Not found and forbidden

An unmatched path renders S-015 with a 404 status. The page offers search, the home page and the docs, and it names
the request id. It never echoes the missing path back into HTML.

A resource that belongs to another tenant answers 404, using the same page as a missing resource, so that a probe
cannot learn whether an object exists (ERR-PERM-002). The 403 response is reserved for a request that is
authenticated but not allowed: a missing permission (ERR-PERM-001), a failed CSRF check (ERR-AUTH-016), a required
step-up (ERR-AUTH-008) or a blocked admin network (ERR-AUTH-015).

A forbidden page never lists the permission IDs to a visitor; it does show the permission ID to a member of the
organisation, because the member can ask an owner for it.

## Titles and headings

The browser title follows B2.3: `Screen · Domain · Org · Hack Dev Defence`, with the parts that do not apply
left out. An organisation-scoped page shows the screen, the organisation and the product; a domain page adds the
domain.

Every page has exactly one `h1`, matching the screen's name, and sections use `h2` without skipping a level. A public
page uses the same pattern with the product name only.

## Token routes

Five routes carry a single-use token in the path:

- `/verify-email/{token}`
- `/reset-password/{token}`
- `/invite/{token}`
- `/.well-known/acme-challenge/{token}`
- `/.well-known/hdd-verification/{token}`

The first three carry a link that arrives by e-mail, so the token has to travel in the path even though a POST body
would be safer. The last two are read by an ACME server or by the verification probe, which only fetch a URL.
`/setup` takes its one-time bootstrap token in the form body and is not a token route.

Mitigations for the three user-facing token routes: the GET only renders a confirm page and changes no state; the
POST consumes the token exactly once; tokens are short-lived and hashed at rest; the response carries
`Referrer-Policy: no-referrer` and `Cache-Control: no-store`; an invalid and an expired token produce the same
neutral page; the token is never written to a log or to analytics. The ACME and verification routes serve only the
challenge value and never a session.

## Permission rule

The route table derives each permission by one rule, so that a reviewer can recompute it from the specification:

1. Take the first endpoint in the screen's "Depends on" column of spec B12.1.
2. If that endpoint is public or an authentication endpoint (B6.2 or B6.10), the route permission is `public`.
3. Otherwise map the endpoint through the B6 tables to a permission ID of B4.2, using the read permission when the
   endpoint row lists a read and a write permission.
4. When the first endpoint is a shorthand rather than a path (`analytics`, `search`), use the read permission of the
   resource it names.
5. A screen with no data source uses `public` on the public, auth, status or data-plane surface, and the weakest
   permission that can reach it on the app or admin surface.
6. A support route uses `public` unless the action requires a session; the exceptions are listed under Assumptions.

## Assumptions

The specification is silent on the points below. Each choice is conservative and is reviewed here rather than hidden.

- **Two paths, one screen.** Spec B2.2 serves eight screens at two paths each: S-046 (`/dns/new` and `/dns/{rec}`),
  S-059 (`/rules/new` and `/rules/{rule}`), S-065 (domain and organisation events), S-067 (domain and organisation
  bans), S-070 (domain-wide and organisation-wide analytics), S-074 (`/reports/new` and `/reports/{rpt}`), S-134
  (`/coverage` and `/security/coverage`) and S-136 (`/setup` and `/admin/hosting`). Each path is one route row; no
  other screen may appear twice.
- **Screens without a B2.2 path.** S-015, S-016 and S-017 are served on `/not-found`, `/error` and `/maintenance`; the
  router selects them for an unmatched path, a server error and a maintenance window. S-137, S-138 and S-139 have no
  route in B2.2, so this document records `/security/sentinel`, `/origin/bypass-guard` and
  `/security/known-vulnerabilities` under the domain. The component gallery of T-0047 is `/admin/design-system`.
- **The data-plane catch-all.** A blocked, rate-limited, unknown-host, under-attack or suspended visitor request has
  no fixed path. The catch-all `/{path}` row marks those six screens as data-plane in its note, and the specific
  `/__hdd/` routes take precedence when the router matches.
- **The `/__hdd/` underscore.** The reserved prefix is part of the data-plane contract, so the URL rule that forbids
  underscores allows it and nothing else.
- **The `status` surface.** B2.2 lists `/status` under the public table and allows the status host, so the row is
  recorded on the `status` surface with the public permission.
- **The OpenAPI document.** `/openapi.json` comes from B6.10 and is recorded as a support route with the public
  surface, because the document is public; the `api` host serves the same document.
- **Rate-limit classes follow the route's own methods.** A GET/HEAD-only route uses `read` (or `public`, `auth`,
  `export` or `stream` where its content is public, an authentication step, a download or a live feed). A route that
  takes POST, PUT, PATCH or DELETE uses `write`, `auth` or `export`. The visitor-facing catch-all is recorded in two
  rows for this reason: GET and HEAD are `public`, and the mutating methods are `write`. An exception would be listed
  under a `Rate-class exceptions` section with pattern, method and reason; no exception is needed for this table.
- **Permission shorthands.** `analytics` maps to `PERM-analytics.read`; `search` maps to `PERM-org.read` because its
  result filter is finer than a route guard; the domain settings route has no B12.1 screen and uses
  `PERM-domain.update`; the component gallery uses `PERM-platform.runtime.read`; the `/app` redirect uses `public`
  because the session middleware checks the login before the redirect, and its class is `auth` because a `public`
  permission on the app surface is only allowed for pre-login classes.
- **Support routes with a session.** `/logout` uses `PERM-account.self`. The robots file, the security contact file,
  the sitemap, the health probe, the CSP report intake, the asset paths and the two well-known token routes are
  public. `/offline` is S-018, not a support route.
