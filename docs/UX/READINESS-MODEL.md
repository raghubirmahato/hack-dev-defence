# Protection readiness model

Status: design deliverable for T-0026 (REQ-UXR-16), step 2 and acceptance A1, A2 and A5. The onboarding stages and
the next-best-action card that read this model are in [ONBOARDING.md](ONBOARDING.md). The check that enforces this
document is `cargo xtask ux-docs` (module `ux_docs::onboarding`).

The score answers one question honestly: how completely has the owner configured this domain? It does not answer
whether the domain is safe. The model is for configuration completeness only and is not a security measure. The six
categories and their weights come from B12.2; the checks and their individual weights match the readiness table of the
[J-25 journey](journeys/J-25.md), and the weights sum to 100.

## Categories

| Category | Weight | What the checks cover |
| --- | --- | --- |
| Traffic | 20 | Requests reach HDD, the integration is verified, and no grey record keeps a direct path open. |
| Encryption | 15 | Certificate lifetime, HTTPS redirect, strict origin verification and HSTS. |
| Origin | 20 | Lockdown, the secret header, origin exposure (DNS, mail records and headers) and origin health. |
| Detection | 25 | WAF mode, the SQL injection shield, hard categories, declared auth endpoints and the outbound filter. |
| Abuse controls | 10 | Rate limits on authentication paths, the challenge and the scanner policy. |
| Operations | 10 | A tested alert channel, required MFA, an exported DNS backup and appeals. |

The category weights sum to 100. Each check belongs to exactly one category, and the checks of a category sum to that
category's weight (A2).

## Check catalog

Each row names the stable check id used by the decision list and the scoring example. The data source is a table or an
audit event of the B5 data model; the refresh interval is a duration or an event-driven refresh; the remediation link
is a real B12.1 screen.

| Check | Category | Weight | Data source | Refresh interval | Remediation link |
| --- | --- | --- | --- | --- | --- |
| RD-TRAFFIC · Traffic flows through HDD | Traffic | 8 | `waf_events` (the last proxied request for the site) | 60 s | S-043 |
| RD-DELEGATION · Delegation or CNAME verified | Traffic | 7 | `delegation_checks` (`matches`) and `domain_verifications` | 5 min | S-099 |
| RD-GREY · No grey web record exposes a hostname | Traffic | 5 | `dns_records` (`proxied`) | on change, then 15 min | S-045 |
| RD-CERT · Certificate valid beyond a quarter of its lifetime | Encryption | 5 | `certificates` (`not_after`, `status`) | hourly | S-051 |
| RD-HTTPS · HTTPS redirect is on | Encryption | 3 | `sites` (`ssl_mode`, `min_tls`) | on change | S-050 |
| RD-ORIGIN-VERIFY · Origin verification is strict | Encryption | 3 | `origins` (`tls_verify_mode`) | on change | S-052 |
| RD-HSTS · HSTS is enabled | Encryption | 4 | `sites` (`hsts`) | on change | S-050 |
| RD-LOCKDOWN · Origin lockdown applied | Origin | 6 | `config_revisions` snapshot (`lockdown_state`) and `audit_log` (`AUD-origin.lockdown_applied`) | on change | S-098 |
| RD-SECRET · Secret origin header verified | Origin | 5 | `origins` (`secret_header_enc`, `secret_rotated_at`) and `audit_log` (`AUD-origin.secret_verified`) | on change, then 24 h | S-052 |
| RD-ORIGIN-EXPOSURE · Origin address absent from own DNS and headers | Origin | 5 | `dns_records` (MX, SPF and DKIM), `zone_versions` (published A and AAAA values) and `mail_outbox` (mail headers of recorded mail) | on change, then 6 h | S-138 |
| RD-ORIGIN-HEALTH · Origin health check passing | Origin | 4 | `origin_health` (`ok`) | 5 min | S-053 |
| RD-WAF-MODE · WAF in block mode | Detection | 8 | `sites` (`waf_mode`) | on change | S-055 |
| RD-SHIELD · SQL injection shield enabled | Detection | 6 | `waf_policies` (`shield`) | on change | S-057 |
| RD-HARD-CATEGORIES · All hard categories on | Detection | 5 | `waf_policies` (`category_actions`) | on change | S-056 |
| RD-AUTH-ENDPOINTS · Authentication endpoints declared | Detection | 3 | `auth_endpoints` | on change | S-057 |
| RD-OUTBOUND · Outbound filter on | Detection | 3 | `sites` (`outbound_mode`) and `waf_policies` (`outbound`) | on change | S-097 |
| RD-RATE-LIMITS · Rate limits on authentication endpoints | Abuse controls | 4 | `rate_limit_rules` | on change | S-061 |
| RD-CHALLENGE · Challenge configured | Abuse controls | 3 | `waf_policies` (`challenge`) | on change | S-062 |
| RD-SCANNER · Scanner policy on | Abuse controls | 3 | `waf_policies` (`bots`) | on change | S-062 |
| RD-ALERT-TESTED · Alert channel tested | Operations | 3 | `alert_rules` and `integrations` (`last_ok_at`) | hourly | S-076 |
| RD-MFA · MFA required for the organisation | Operations | 2 | `orgs` (`require_mfa`) | on change | S-086 |
| RD-DNS-BACKUP · DNS backup exported | Operations | 2 | `zone_versions` (`snapshot_hash`) and `audit_log` (`AUD-dns.exported`) | on change, then 24 h | S-048 |
| RD-APPEALS · Appeals enabled | Operations | 3 | `block_page_settings` (`appeals_enabled`) | on change | S-069 |

The weights are 8+7+5+5+3+3+4+6+5+5+4+8+6+5+3+3+4+3+3+3+2+2+3 = 100 (A2).

## B12.2 mapping

Each phrase of the six B12.2 S-044 bullet lists maps to exactly one check above, and every check is the
mapping of exactly one phrase. `cargo xtask ux-docs` reads the bullet lists from the master text and fails
when a phrase is missing, duplicated or mapped to a check of another category.

| B12.2 check phrase | B12.2 category | Model check |
| --- | --- | --- |
| traffic flows through HDD (last proxied request within 24 h) | Traffic | RD-TRAFFIC |
| delegation or CNAME verified | Traffic | RD-DELEGATION |
| no grey web records that expose the same hostnames | Traffic | RD-GREY |
| valid certificate with more than one quarter lifetime remaining | Encryption | RD-CERT |
| HTTPS redirect on | Encryption | RD-HTTPS |
| origin verification mode strict | Encryption | RD-ORIGIN-VERIFY |
| HSTS enabled (partial credit by max-age) | Encryption | RD-HSTS |
| lockdown applied | Origin | RD-LOCKDOWN |
| secret header verified | Origin | RD-SECRET |
| origin IP not found in own DNS/headers/mail | Origin | RD-ORIGIN-EXPOSURE |
| origin health check passing | Origin | RD-ORIGIN-HEALTH |
| WAF in block mode (monitor gives partial) | Detection | RD-WAF-MODE |
| SQLi shield enabled | Detection | RD-SHIELD |
| all hard categories on | Detection | RD-HARD-CATEGORIES |
| auth endpoints declared | Detection | RD-AUTH-ENDPOINTS |
| outbound filter on | Detection | RD-OUTBOUND |
| rate limits on auth endpoints | Abuse controls | RD-RATE-LIMITS |
| challenge configured | Abuse controls | RD-CHALLENGE |
| scanner policy on | Abuse controls | RD-SCANNER |
| alert channel tested | Operations | RD-ALERT-TESTED |
| MFA required for org | Operations | RD-MFA |
| DNS backup exported | Operations | RD-DNS-BACKUP |
| appeals enabled | Operations | RD-APPEALS |

## Scoring rules

Each check returns exactly one status: `Pass`, `Partial(ratio)`, `Fail` or `Unknown(reason)`. The score is a pure
function of the catalog:

1. A `Pass` scores the full weight; a `Fail` scores 0.
2. A `Partial` scores weight times its ratio, where the ratio is between 0 and 1. The ratio is part of the check
   definition: the HSTS max-age tier sets the ratio of RD-HSTS, and RD-WAF-MODE scores 0.5 when `waf_mode` is
   `monitor` (a `block` mode is `Pass`, while `log` and `off` are `Fail`). The monitor-mode ratio is a design
   value of this model, confirmed in T-0172 when the engine implements the check.
3. An `Unknown` scores 0 and is counted separately; it is not a pass and it is not a fail.
4. The weighted total is rounded down to a whole number from 0 to 100. The score never rounds up.
5. Fixing a failed check never lowers the score; the property test of T-0172 checks monotonicity.

When a check does not apply to an integration mode, T-0172 removes it and renormalises the remaining weights to 100:
each remaining weight is multiplied by 100 and divided by the remaining total, the results are rounded down, and the
largest remainders receive the remaining points in row order. The base catalog above stays the sum of 100.

## Unknown handling

An Unknown check never counts as a pass and it scores 0. The page shows it as `Unknown ({reason})`, using the B13
`unknown-value` string, with the reason beside it; a missing source is stated, not replaced by zero or by a green
tick. The score ring shows the count of Unknown checks next to the score, so a low score with many unknowns is read
as missing data rather than as a bad configuration. The checklist keeps the fixing link for an Unknown row.

## Honesty footnote

The text below is copied from B13 `readiness-footnote` and compared as a whole string, case-sensitive, by the
`ux-docs` check:

> Measures configuration completeness, not security.

S-044 shows it directly below the readiness ring, before the checklist, so it stays visible while the checks are read.
The `ReadinessRing` component's footnote slot carries the same string, so no renderer can drop it silently. The page
title and the ring label never use the word "secure" as a synonym for the score.

## Worked scoring example

These are arithmetic examples, not product data. Every check not named in a row is `Pass`, so the base score is 100.
The `ux-docs` check evaluates the table with the pure function above and fails when an expected value disagrees.

| Case | Status overrides (all other checks Pass) | Expected score | Unknown count |
| --- | --- | --- | --- |
| A | none | 100 | 0 |
| B | RD-WAF-MODE Fail | 92 | 0 |
| C | RD-HSTS Partial(0.5) | 98 | 0 |
| D | RD-LOCKDOWN Unknown; RD-ALERT-TESTED Unknown | 91 | 2 |
| E | every check Unknown | 0 | 23 |
| F | RD-WAF-MODE Partial(0.5) | 96 | 0 |

Example B subtracts the 8 points of the WAF mode check. Example C subtracts half of the 4 HSTS points. Example D
subtracts the 6 lockdown points and the 3 alert points and counts two Unknown checks. Example E scores 0 with 23
Unknown checks, which is the honest floor, not a measured security value. Example F is monitor mode: the WAF mode
check keeps half of its 8 points, so the score is 96 rather than the 92 of a failed check.

## References

- [Onboarding and activation](ONBOARDING.md): stages, checklist, next-best action, nudges, empty states, measures and
  activation emails.
- [J-25](journeys/J-25.md): the journey record with the same readiness table.
- [UX charter](CHARTER.md) and [experience measures](MEASURES.md).
