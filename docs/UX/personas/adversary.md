# Adversary A (design for them, never for their convenience)

**Fictional composite.** Adversary A is not a real person and stands for no single attacker: it is a composite of the
attackers described in spec [B1.7](../../SPEC.md#b17-adversary-a-design-for-them-never-for-their-convenience) - scanners,
credential stuffers, scrapers, botnets, a curious attacker reading error pages, an attacker who tries to poison bans by
luring victims, an attacker who tries to hijack signup or password reset, and an attacker who tries to claim someone
else's domain. Its abuse stories are design inputs, not observed incidents.

The adversary is designed for explicitly and is never a convenience user: every flow is reviewed against the abuse
stories below (rule B1.7), and the block page, error pages and API errors give attackers no rule names, no stack traces,
no internal hostnames and no confirmation of account existence. It is not the pilot's assumed primary persona (that is
Maya until the [primary-persona question](../../OPERATOR-QUESTIONS.md#primary-persona-for-the-pilot-added-by-t-0012) is
answered). The [UX charter](../CHARTER.md) applies to every page it receives.

## Context of use

| Aspect | Detail |
| --- | --- |
| Device | Automated tooling (sqlmap, nuclei, nikto, custom scripts) and a browser with developer tools; sometimes a rented botnet or a proxy pool. |
| Connectivity | Proxy, VPN and Tor rotation; bandwidth from a few hosts up to a botnet. |
| Interruptions | None: the tooling runs unattended and retries. |
| Vocabulary | Payloads, CVE ids, WAF bypass, error strings, stack traces, version banners. |
| First check of the day | Which responses differ - 200, 403 or 500 - and what the error page, headers or body reveal. |

## Abuse stories

Each story is mapped to a row of the attack coverage matrix (spec C5, `docs/spec/C2.md`). The row is the requirement that
the detection and response exist; this file adds the question security UX has to answer.

| # | Abuse story (B1.7) | ATK id | What the design must do |
| --- | --- | --- | --- |
| 1 | Probe a login form with tautologies and quote break-outs. | ATK-001 | Block and ban on the hard hit; the response is the same generic error whatever the payload. |
| 2 | Try UNION-based extraction against a query parameter. | ATK-003 | Block and ban; evidence stays redacted and never shows the payload back. |
| 3 | Sweep the site with sqlmap, nuclei or nikto. | ATK-189 | Detect the tool fingerprint; challenge or block without naming the rule that matched. |
| 4 | Brute-force paths, backups and configuration files. | ATK-191 | 404 burst detection and honeypot paths; the 404 for a real path looks like the 404 for a fake one. |
| 5 | Guess one account's password from one address. | ATK-157 | Per-IP per-path limit with progressive backoff, then a ban with a short TTL. |
| 6 | Stuff leaked username and password pairs across many accounts. | ATK-158 | Distinct-username rate and failure-ratio signals; the response never confirms which pairs are valid. |
| 7 | Burn through one-time codes on a single account. | ATK-163 | Strict per-account limits on the MFA endpoints, uniform errors and a lockout that does not leak account state. |
| 8 | Enumerate object identifiers on the API. | ATK-173 | Sequential-ID access limits; a foreign object is answered 404, never 403, so existence is not confirmed. |
| 9 | Bomb signup and verification mail to exhaust resources. | ATK-286 | Per-IP, per-email and per-domain limits plus proof of work; resend cooldowns; the same page for every address. |
| 10 | Abuse password reset to enumerate accounts or guess tokens. | ATK-287 | Uniform "if an account exists" message, single-use tokens exchanged by POST, rate limits. |
| 11 | Claim someone else's domain, or take over a dangling name. | ATK-290 | Ownership proof, periodic re-verification and a dispute flow; the error does not reveal the current owner. |
| 12 | Poison the ban list by luring a victim's browser into attacks. | ATK-291 | The cross-site context rule: hard hits from a victim's browser do not ban the victim; AC-34 proves it. |
| 13 | Reach another tenant's data through HDD's own API. | ATK-293 | RLS and permission checks, 404 on foreign ids, the BOLA test suite (AC-36) before exposure. |
| 14 | Escalate from a member role to owner or platform scope. | ATK-294 | The permission matrix is tested; role changes are audited; the UI never hides an action the API refuses. |

## Scenarios

### 1. Learn from the response

When I find a site behind a security product, I want to see which payload shapes pass and what the error page reveals, so
I can choose a technique before the target notices.

Measurable outcome: the request is blocked or challenged and the page leaks no rule name, stack trace or internal
hostname; AC-48 (scanner and bot-tool detection) and AC-40 (accessible, honest visitor pages) pass.

### 2. Turn the site's defences against its own visitors

When I want to hurt a site's customers, I want to lure their browsers into requests that look like attacks, so I can turn
the site's own defences against its visitors.

Measurable outcome: no ban is issued for a cross-site context (ATK-291) and AC-34 (ban-poisoning resistance) passes.

### 3. Abuse the account flows instead of the site

When I want an account without paying, I want to abuse signup, password reset and invitation flows at machine speed, so I
can get in with the least effort.

Measurable outcome: rate limits, proof of work and uniform responses hold; AC-35 (identity end to end) passes and the
flows are exercised against ATK-286 and ATK-287.

## Anti-goals

- A target whose rejected and accepted requests look alike: no rule name, stack trace, internal hostname or version
  banner to learn from (B1.7).
- Defences whose cost rises with every attempt: an unpredictable challenge and ban ladder, and no free retry through a
  fresh identity.
- An origin that cannot be reached directly, because the Bypass Guard checks the path rather than assuming the proxy is
  used (AC-60).
- An appeal or contact path that cannot be automated cheaply.
- A site where a successful attack would take longer than the next target, so attention moves on.

## Accessibility

HDD designs for no adversary convenience and assumes no assistive technology on their side. The pages the adversary
receives are the same visitor pages Vi receives, so they meet the
[B11.11](../../SPEC.md#b1111-accessibility-contract-summary-of-wcag-22-aa-obligations-the-components-encode) contract:
3.3.8 (no cognitive puzzle as the only gate; the proof of work is automatic), 1.1.1 (text alternatives) and 2.1.1
(keyboard). Two honest limits: HDD never relies on an attacker's disability, and an inaccessible CAPTCHA is not an
acceptable defence because it would also exclude Vi.

## Journeys and screens

The adversary is never a journey owner. Its abuse stories are reviewed against every journey; the journeys where they
matter most are [J-16](../../SPEC.md#j-16-owner-enables-protection-in-monitor-mode-reviews-switches-to-block),
[J-18](../../SPEC.md#j-18-analyst-investigates-an-attack),
[J-22](../../SPEC.md#j-22-blocked-visitor-files-an-appeal) and
[J-34](../../SPEC.md#j-34-incident-attack-spike).

Screens the adversary sees: [S-140](../../SPEC.md#s-140-block-page-visitor) Block page,
[S-141](../../SPEC.md#b121-screen-table) Challenge page,
[S-142](../../SPEC.md#b121-screen-table) Rate-limit page,
[S-143](../../SPEC.md#b121-screen-table) Origin error page and
[S-144](../../SPEC.md#b121-screen-table) Unknown host page. The app screens where its stories are reviewed are
[S-065](../../SPEC.md#s-065-live-threat-monitor) Live threat monitor,
[S-066](../../SPEC.md#b121-screen-table) Event detail,
[S-067](../../SPEC.md#s-067-ip-jail) IP jail and
[S-134](../../SPEC.md#s-134-coverage-map) Coverage map. Every one of them is also a page Vi may see, so the visitor
content rules apply first.
