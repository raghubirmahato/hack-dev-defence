# Security UX: lockout prevention, previews, confirmations and honest warnings

T-0025 steps 3 to 8 (`REQ-UXR-15`). The catalog of dangerous actions and their copy is in
[dangerous-actions.md](dangerous-actions.md); the confirmation strings are in
[security-ux.ftl](../../i18n/en/security-ux.ftl). This document states the guard and
pattern requirements the UI and the API must meet, and names the task that tests each one.

Status of the evidence: the requirements are design requirements until their tasks land. T-0327
implements the self-lockout guard, T-0235 the time-boxed emergency controls and T-0094 the browser
security suite; T-0069 step 5 checks that every catalog entry exists in the designs. Nothing in this
document is claimed as tested today.

## Self-lockout guard requirements

The guard is one server-side decision shared by the API and the UI (R-27). Each requirement below is
testable; `GL-` is the requirement id used by the tests of T-0327.

1. **GL-1 Acting IP.** The guard reads the acting IP exactly as the request pipeline resolves it: the
   rightmost trusted hop of `X-Forwarded-For` on the tunnel listener, otherwise the direct peer. The
   preview names the resolved value.
2. **GL-2 Session identity.** The guard reads the session's user, organisation, role, authentication
   level, age, impersonation flag and runner-token presence from the server-side session, never from
   a request body or a query parameter.
3. **GL-3 Admin CIDR collision.** The guard compares the proposed effect with the organisation's
   admin CIDR list, the platform never-ban list, the platform data-plane addresses, the site origin
   address and the acting session, and reports every collision with the name of the list that holds
   it. A collision with a platform key or the never-ban list cannot be acknowledged at all.
4. **GL-4 Proposed effect, not the form.** The guard evaluates the effect of the change: a ban (the
   exact key and its IPv6 /64), an access entry (IP, CIDR, country or ASN), a custom rule (replayed
   against the caller's recent requests), a geo or ASN policy, a mode switch (the recent would-block
   events from the caller's address), a DNS or platform-zone edit, an origin lockdown and an MFA
   enforcement change.
5. **GL-5 IPv6 equivalence.** A ban or deny of the caller's /64 counts as a collision even when the
   exact address differs.
6. **GL-6 Acceptance runner.** The runner is recognised only by its signed runner token. With the
   token, a runner self-ban is allowed with a TTL of at most 60 seconds; a spoofed or missing header
   never produces the runner exception (T-0327 A3).
7. **GL-7 No acknowledgment for platform and never-ban keys.** A platform or never-ban key cannot be
   overridden by any flag; the guard refuses the change rather than asking for a second confirmation
   (T-0327 A2).
8. **GL-8 Where the check runs.** The check is server-side and mandatory in every mutation path. The
   browser warning is an enhancement: it explains the refusal and carries the dry-run link, but a
   client that skips it receives the same refusal. There is no UI-only path to the action (R-27).
9. **GL-9 How it is displayed.** The refusal opens a blocking warning dialog that names the exact
   rule or scope and the affected keys, and carries the `Run as dry-run first` link of B11.9 item 3.
   The destructive control stays disabled until the preview has been rendered, and focus starts on
   the safe action (R-28).
10. **GL-10 Acknowledged changes.** An acknowledgment is an explicit flag on the request
    (`acknowledge_self_ban`, `acknowledge_self_lockout` or the documented equivalent), returned with
    `ERR-WAF-007` or `ERR-BAN-002` and the preview. The acknowledged change is audited with the
    preview that was shown (T-0327 A5).
11. **GL-11 Fail safe.** If the acting IP, the session identity or the admin CIDR list cannot be
    resolved, the guard blocks the action or requires step-up. It never silently proceeds and never
    treats an unavailable list as empty. The refusal names the missing source, not a generic error.
12. **GL-12 Break-glass stays.** The guard never removes the break-glass path: `hddctl unban`, safe
    mode, `hddctl gate disable --site`, the SSH tunnel and the VPS console. The warning says where
    the nearest break-glass is.
13. **GL-13 API and UI parity.** The API returns the same preview object the dialog renders, and the
    preview is recomputed at submit; a stale preview is refused (`ERR-CONC-001`) instead of being
    applied.
14. **GL-14 Tests.** Table tests per mutation path, a header-spoofing test, an IPv6 /64 test, a
    runner-TTL test and a browser test of the dialog (T-0327; the browser part in T-0094).

### When detection is unavailable

The detection inputs can be missing: a resolver failure for the ASN or country, a session without a
recorded address, a malformed admin CIDR list, or an impersonation session whose own address is
unknown. The behaviour is fail safe in every case: the action is refused or requires step-up, the
dialog names the source that is unavailable, and the refusal is audited like any other guard
refusal. The only exception is a platform operator using the documented break-glass, which is a
separate audited path (GL-12).

## Preview patterns

A preview answers one question: what would change, and what would it cost? The API computes it, the
UI renders it, and both show the same object (R-27). A preview is recomputed at submit; a stale
preview is refused (`ERR-CONC-001`) and re-rendered before the user can confirm.

| Area | What the preview must show | What it must not hide |
| --- | --- | --- |
| DNS | Every record added, changed or removed with its before and after value, type, TTL and proxied or paused state; the records on the mail path by name; the exact records to create at the provider (S-042); the current and new nameserver pair; the propagation check (S-099). | Records that stay unchanged but affect mail; the nameserver values; unsupported types that need an acknowledgment; origin-leak warnings for an MX or CNAME. |
| Rules | The plain-language sentence from the rule builder ("Block when the path starts with /admin and the country is not NL"); the scope and conditions; the dry-run match count and sample Ray IDs (S-060); the self-lockout result; the required expiry for an allow rule; the revision the save would create. | Estimated false positives; categories with unreviewed would-blocks; the rule expiry; the priority the rule would take. |
| Access lists | The exact value and kind (IP, CIDR, country, ASN), the action, the expiry and the overlap with existing entries; the recent sessions the entry affects; the self-lockout result ("your current address would be allowed, blocked or asked to sign in"). | Overlapping entries; the source of an imported row; the expiry default; the number of sessions behind a shared address. |
| Policies | The before and after values for mode, threshold, paranoia level, shield strictness, rate limits and the under-attack state; the review window used for a block switch; the would-block counts by category; the shared-address collateral; the scheduled time or auto-revert time. | The length of the review window; categories with no data ("Unknown (reason)"); how the visitor estimate was produced when it is not measured. |

The dry-run link of B11.9 item 3 opens the relevant surface (`/dns/preview`, `/rules/test` or
`/waf/inspect`), and the preview is available before the confirmation, not after it. A missing
measurement is shown as "Unknown (reason)" and never as zero (R-16).

## Typed-confirmation rules

The dialog is the B11.8 ConfirmDialog (T-0042): a labelled heading, the consequences list, a focus
trap and focus returned to the opener. The typed value is the only way to enable the destructive
control.

- **TC-1 Exact resource name.** The user types the resource name exactly as the server stores it: the
  domain name for DA-01 and DA-24, the organisation slug for DA-14, the setting name for DA-15, the
  address for DA-16, the pack name for DA-17, the CIDR for DA-23, the emergency control name for DA-30
  and the tenant name for DA-31. Copying the name from the page is allowed; the dialog shows the
  required string beside the field.
- **TC-2 Case sensitivity.** The comparison is case-sensitive and does not normalise case, Unicode
  or trailing spaces. A value that differs in case does not enable the control.
- **TC-3 Paste allowed.** Pasting into the confirmation field is allowed and is not blocked by a
  script (WCAG 3.3.8 applies to authentication; this rule extends the same courtesy to the dialog).
- **TC-4 No checkbox substitute.** A checkbox, a second click or a typed "yes" must not replace the
  exact name. The typed confirmation is mandatory for the rows TC-7 lists; every other destructive
  action needs the consequences list and the undo path the catalog names.
- **TC-5 Disabled until match.** The destructive control stays disabled until the value matches and
  the focus starts on the safe action (R-28); the destructive action is never the default.
- **TC-6 No prefill.** The field starts empty; the name is not autofilled, not put in a URL and not
  logged (R-21). The value is discarded after the request.
- **TC-7 Scope.** Typed confirmation is required for the specification set: the domain removal
  (DA-01), the organisation deletion (DA-14), the global changes (DA-15, DA-16, DA-17, DA-23) and the
  platform emergency controls of S-122 (DA-30, T-0068 A5, spec line 6017). Two deliberate extensions
  are recorded here: the under-attack mode (DA-24, so the J-34 incident journey and its checklist stay
  consistent) and the tenant suspension or deletion (DA-31, so J-29 stays consistent). Every other
  dangerous action uses the consequences list, the undo path and the time box where the catalog names
  one.
- **TC-8 Keyboard and screen reader.** The dialog is fully keyboard operable, the field has a
  programmatic label and the error is announced (R-17, AC-40).

## Time box and auto-revert

A time box is a change with a stated end. The end is enforced by the server, not by the open page.

- **TB-1 Stated end.** Every time-boxed control has a duration chosen from the documented range,
  auto-reverts at the stated time and shows the end time with the offset: under attack (DA-24),
  pause (DA-25), safe mode (DA-10), a scheduled block switch (DA-05), a secret rotation window, a ban
  TTL (DA-06) and an impersonation session (DA-19).
- **TB-2 Visible countdown.** The banner on every domain page shows the remaining time and the
  action's own pages repeat it. The countdown is a display of server state; under reduced motion and
  for screen readers it updates at most every 30 seconds and remains readable as static text.
- **TB-3 If the browser closes.** The timer is a server-side timer and the revert job is scheduled
  when the control is enabled. If the browser closes, the tab sleeps, the network drops or the
  operator signs out, the change still reverts at the stated time (T-0235 A1). The client countdown
  never schedules the revert.
- **TB-4 Extend is explicit.** Extending requires a new duration and an explicit confirmation, then
  writes an audit event. A page reload, a second click or a new session never extends a time box.
- **TB-5 Revert is audited.** Ending early and the automatic revert each write the matching B8 event:
  `AUD-waf.safe_mode_off`, `AUD-waf.under_attack_off`, `AUD-domain.resumed`,
  `AUD-waf.revision_rolled_back` (the auto-revert branch of the config-revision row) or
  `AUD-platform.impersonation_ended`. The banner and the page state change at the same time.
- **TB-6 End now.** An explicit "End now" action is always available beside the countdown; the
  countdown is never the only way to end the state.
- **TB-7 Tests.** T-0235 covers expiry, early end, extend and concurrent toggles with the test clock
  and a server-side test that asserts the revert after the browser is closed.

## Honest limits

The limit is placed where the action is taken and stays visible; it is never hidden in a tooltip or
collapsed by default. The exact copy is the B13 string.

| Placement | Screen | Copy key | Exact copy |
| --- | --- | --- | --- |
| Shield | S-057 | `shield-limit` | Signature-based detection can miss new techniques. Keep your software updated. |
| Virtual patches | S-126 | `virtual-patch-banner` | A virtual patch is not a fix. The vulnerability remains open until the component is updated. |
| Readiness | S-044 | `readiness-footnote` | Measures configuration completeness, not security. |
| Block-mode collateral | S-055 | `block-confirm-body` | HDD will block matching requests and ban the sending IP address. Visitors sharing an address with an attacker can be affected. You can switch back at any time. |

- **Shield.** The explainer card of S-057 uses `shield-title`, `shield-body` and `shield-limit`; the
  limit line stays below the ban editor while the shield is on.
- **Virtual patches.** The banner sits at the top of S-126 and on every virtual-patch transition; the
  exposure stays open until the component is patched or a VEX `not_affected` statement is recorded
  (R-11).
- **Readiness.** The footnote is under the score ring and above the checklist, and an `Unknown`
  check never counts as a pass (AC-53).
- **Block-mode collateral.** The switch dialog shows the shared-address sentence before the confirm;
  the same sentence appears in the switch copy, not in a details drawer.

## Abuse cases of this UI

The UI is an attack surface: it carries the operator's session and it performs destructive actions.
The counter-requirements below are design requirements; the table says which ones become tests.

| Abuse case | ATK | C5 attack | Counter-requirement | Test |
| --- | --- | --- | --- | --- |
| Clickjacking of a destructive control | ATK-171 | Clickjacking | The surface sends `frame-ancestors 'none'` and `X-Frame-Options`; the dialog is a native modal with a focus trap; a typed-confirmation row needs the typed name; no destructive action fires on hover or on a single click. | design-only until T-0094 |
| CSRF on a confirmation request | ATK-296 | Session theft, fixation, CSRF on dashboard | A CSRF token on every mutation, `Origin` and `Sec-Fetch-Site` checks, same-origin API mounts and no mutation on GET; the confirmation is bound to the previewed diff and a single-use nonce. | T-0327 API tests; T-0094 browser suite |
| UI redress around the safe default (no exact C5 class; ATK-171 is the nearest) | ATK-171 | Clickjacking | The safe action is the default focus; the destructive button is not the primary style; the consequences are plain text, not an image; a hostile overlay cannot replace the dialog content. | design-only until T-0094 |
| Confused deputy in impersonation | ATK-298 | Impersonation misuse | Impersonation is read-only, every non-GET request fails with `ERR-AUTH-014`, the banner shows the remaining time, and support cannot type-confirm as the tenant; `AUD-platform.impersonation_blocked_write` records the attempt. | T-0327; T-0422 |
| Stored XSS through event evidence in a preview | ATK-297 | Stored XSS in dashboard via attacker-controlled event payloads | Evidence is rendered through the escaped PayloadViewer, the CSP allows only the nonce script, and the preview never renders markup from a request. | T-0094 browser suite |
| Privilege escalation through a hidden action | ATK-294 | Privilege escalation (role/scopes) | Hidden or absent controls are not the authorisation: every action is a permission-checked API call (R-27), and the confirmation cannot skip step-up. | T-0327 |
| Cross-tenant confirmation replay (BOLA) | ATK-293 | Cross-tenant data access (BOLA) | The confirmation binds the organisation and resource id; the API resolves the resource inside the caller's organisation and foreign ids return 404 (R-18). | T-0327 |
| Ban poisoning through victim browsers | ATK-291 | Ban poisoning through victim browsers | A victim browser cannot trigger a ban of its own network; a cross-site context rule keeps the ban decision server-side. | T-0327 |
| Formula or markup injection in an export (J-28 exports and reports) | ATK-300 | Formula or markup injection in exports and reports | Export and report cells are escaped for CSV and for HTML; a leading formula character is neutralised. | T-0094 |
| Admin panel access from an untrusted network (platform rows DA-15, DA-23, DA-30) | ATK-295 | Admin panel access from untrusted networks | The admin surface needs an allowed CIDR, MFA and step-up; the platform routes are never reachable from the tenant surface. | T-0327 |
| Tenant rules that stress the rule engine (DA-09) | ATK-292 | Tenant rules that DoS the engine or evade others | Regex limits, a per-site evaluation budget and isolation bound a broad or catastrophic rule set. | T-0327 |

### Registry mapping

C5 holds the generic clickjacking class ATK-171 and the generic CSRF class ATK-172. Clickjacking in
this UI is the generic class, so its row cites ATK-171; ATK-296 is the session and CSRF class and
stays on the CSRF row. UI redress has no exact C5 class: the row says so and cites ATK-171 as the
nearest class instead of inventing an id or borrowing the ban-poisoning row ATK-291. The other rows
cite the HDD-surface rows this UI exercises: ATK-296 for CSRF, ATK-291 for ban poisoning through a
victim browser, ATK-292 for tenant rules that stress the engine (DA-09), ATK-293 for cross-tenant
access, ATK-294 for privilege escalation, ATK-295 for admin panel access from untrusted networks,
ATK-297 for stored script in evidence, ATK-298 for impersonation and ATK-300 for exports and reports
(J-28). The `C5 attack` column copies each cited row's name whole so the check can compare it with
C5. Where a counter-requirement is not implemented yet, the row says `design-only` instead of
implying a test.

## R-19 and R-28 mapping

| Rule | Requirements in this document | Where it is enforced |
| --- | --- | --- |
| R-19 No self-lockout | GL-1 to GL-14, every catalog row with a self-lockout preview or a time box | T-0327 (guard and tests), T-0235 (time boxes) |
| R-28 No dark patterns | TC-1 to TC-8, GL-9, the time-box countdown and "End now" in TB-2 and TB-6 | T-0042 (dialog), T-0069 step 5 (design review), T-0327 |
| R-17 and AC-40 accessibility | TC-8, TB-2 (static equivalent), GL-9 (focus on the safe action) | T-0069, T-0091, T-0151 |
| R-11 virtual patches are not fixes | The virtual-patch row of the honest limits and DA-18 | The B13 banner check, T-0485 |

The catalog is the input of the review, not proof that a screen implements it. T-0069 A4 checks each
entry against the designs, and T-0327 A1 to A5 check the guard behaviour; until those run, the status
is an honest `UNVERIFIED(task_not_run)` rather than a pass.
