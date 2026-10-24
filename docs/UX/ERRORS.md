# Error-handling UX model

This document defines how HDD shows an error, what the error reveals and how a person recovers. It is the
reference for the design (T-0065, T-0067), for the API problem documents (B6.1, B7) and for the data-plane
visitor pages (S-140 to S-148). The `ux-docs` check in `crates/hdd-xtask/src/ux_docs/errors.rs` enforces the
rules stated here.

The model has the nine task classes plus an explicit `authentication` row (review D-1) and five UI patterns.
Every class has a primary pattern and may use the others the matrix allows. A message states what happened, what
it means and the next action (B11.12).

## Class and pattern matrix

| Class | Patterns | Where it appears | Clears | Focus | Example |
| --- | --- | --- | --- | --- | --- |
| validation | inline, summary, banner | Each field via FormField, the top of the form via ErrorSummary and the acknowledgement banner via Banner | when the field becomes valid or the acknowledgement is given | focus moves to the summary and then to the first invalid field | ERR-VAL-001 |
| permission | page, banner | The page frame via ErrorState and a problem bar via Banner | when the role, the session or the resource state changes | focus moves to the page heading | ERR-PERM-001 |
| authentication | inline, summary, page, banner | The credential field and the form via FormField and ErrorSummary, the sign-in page via ErrorState and the step-up notice via Banner | when the credential, the code or the session succeeds | focus moves to the credential field or the summary and the page names the next step | ERR-AUTH-002 |
| not found | page | The response page via ErrorState | never for the same address | focus moves to the page heading | ERR-PERM-002 |
| conflict | banner, toast | The edited region via Banner and a transient notice via Toast | when the resource is reloaded after a version or key conflict | focus stays on the reload control in the banner | ERR-CONC-001 |
| rate limit | banner, toast | The affected region via Banner and a transient notice via Toast | when the reset time passes | focus stays on the retry control in the banner | ERR-RATE-001 |
| quota | page, banner | The plan section via Banner and the plan page via ErrorState | when the plan changes | focus moves to the plan heading | ERR-RATE-002 |
| upstream | page, banner | The response page via ErrorState and a problem bar via Banner | when the dependency answers again | focus moves to the page heading | ERR-ORIGIN-003 |
| system | page, toast | The response page via ErrorState and a transient notice via Toast | when the next request succeeds | focus moves to the page heading | ERR-SYS-002 |
| maintenance | page, banner | The app frame via Banner and the maintenance page via ErrorState | when the maintenance window ends | focus moves to the maintenance heading | ERR-SYS-003 |

The `Example` column names a real B7 code whose family and HTTP status fit the class. The example is a
representative row and not the only code of the class; the classification tables below cover the rest.

## Classification rules

The class of an API error is a function of the B7 code. The status gives the default class; the exception table
refines the codes whose semantics differ from their status.

| HTTP status | Class |
| --- | --- |
| 400 | validation |
| 413 | validation |
| 415 | validation |
| 422 | validation |
| 401 | permission |
| 403 | permission |
| 404 | not found |
| 421 | not found |
| 409 | conflict |
| 412 | conflict |
| 428 | conflict |
| 429 | rate limit |
| 500 | system |
| 503 | system |
| 502 | upstream |
| 504 | upstream |

A 421 answer is the misdirected-request case: the host has no site on this edge, so the response is the neutral
unknown-host page. That is why it shares the not-found class rather than a class of its own.

Conflict means a version or key conflict only. The reload control belongs to ERR-CONC-001, ERR-CONC-002,
ERR-IDEMP-001, ERR-ACME-001, ERR-WAF-004 and ERR-PLAT-003; every other 409 cause appears in the exception table
below with its own reason and class (review D-2).

## Classification exceptions

| Code | Class | Why |
| --- | --- | --- |
| ERR-AUTH-001 | authentication | The remedy is to sign in; a credential challenge is not an authorisation role decision. |
| ERR-AUTH-002 | authentication | The remedy is to correct the credential; the message is field-level and identical for an unknown account. |
| ERR-AUTH-003 | authentication | The remedy is a fresh verification code; the message is field-level. |
| ERR-AUTH-005 | authentication | The remedy is to verify the email address first; the page names the next step. |
| ERR-AUTH-006 | authentication | The remedy is to set up the second factor; the page redirects to enrolment. |
| ERR-AUTH-007 | authentication | The remedy is to sign in again; the session redirect carries a return URL. |
| ERR-AUTH-008 | authentication | The remedy is step-up re-authentication for this action. |
| ERR-AUTH-012 | authentication | The remedy is a valid API key; the message says nothing about the key prefix. |
| ERR-GATE-001 | authentication | The remedy is to authenticate to the protected area; no application detail is revealed. |
| ERR-AUTH-017 | validation | This passkey is already on the account, so the message is inline on the credential field. |
| ERR-ORG-001 | validation | The slug is a field value the person changes; nothing has a version or a key. |
| ERR-ORG-003 | validation | A pending invitation is an inline condition on the email field that the person resends or revokes. |
| ERR-ORG-004 | validation | The last-owner rule is a form rule the person fixes before saving. |
| ERR-DOM-002 | validation | The claim failure is a field problem with a dispute path, not a version conflict. |
| ERR-DOM-004 | upstream | Ownership proof waits on an external DNS or HTTP check; the interface re-checks. |
| ERR-DOM-005 | system | The domain is in an internal lifecycle state; the interface waits and re-checks. |
| ERR-DOM-007 | upstream | Delegation is observed by external resolvers; the interface shows the observed NS and re-checks. |
| ERR-DNS-002 | validation | The record set conflicts on the form; the person edits the record before saving. |
| ERR-DNS-005 | validation | The change would remove required records; the person adjusts it after the preview. |
| ERR-TLS-005 | upstream | The authority refuses because an external CAA record forbids issuance; the person fixes DNS. |
| ERR-ACME-005 | upstream | The authority is blocked by an external CAA set; the message shows the offending records. |
| ERR-WAF-006 | maintenance | Safe mode is a deliberate time-boxed operator state; the person waits or ends it. |
| ERR-BAN-002 | permission | The self-lockout policy refuses the ban; the preview names the address and the exemption path. |
| ERR-PLAT-002 | permission | The never-ban policy refuses the action; the person changes the exemption with step-up. |
| ERR-LOCAL-001 | system | The local runtime profile does not supply this capability; the page explains the profile. |
| ERR-GATE-004 | permission | The self-lockout guard refuses the rule; the person acknowledges it after the preview. |
| ERR-SENT-002 | validation | The promotion request is incomplete; the message lists the missing prerequisites. |
| ERR-BYPASS-001 | upstream | The lockdown proof depends on the external path to the origin; the interface offers verification steps. |
| ERR-APIDISC-002 | validation | The change must be acknowledged after the preview; there is no version or key to reload. |
| ERR-ACME-002 | upstream | The certificate authority refused the challenge, so the cause is upstream of HDD. |
| ERR-BAN-004 | quota | The ban list limit is a plan capacity, so waiting does not clear it. |
| ERR-DNS-007 | quota | The zone size limit is a plan capacity, so deleting a record is the remedy. |
| ERR-DOM-006 | quota | The domain limit is a plan capacity, so the plan page is the next stop. |
| ERR-KEY-001 | permission | A scope the role lacks is an authorisation refusal with a 422 status. |
| ERR-ORG-005 | permission | A role this action excludes is an authorisation refusal, not a field mistake. |
| ERR-RATE-002 | quota | The plan quota is exhausted, so waiting does not clear it and the plan page is the next stop. |
| ERR-SYS-003 | maintenance | Maintenance is an operator-planned state, so the message names the window. |
| ERR-SYS-004 | maintenance | A paused signup window is an operator-planned state, not a fault. |
| ERR-WAF-007 | permission | The self-lockout policy refuses the change; the preview names the current address. |

## Authentication class

Authentication is a named subset of the permission family: the errors whose remedy is to authenticate, verify or
re-authenticate. Credential mistakes use the inline message and the summary; a required verification or step-up
uses a page or a banner that names the next step. Role, scope and suspension refusals stay in the permission
class, so the two rows never disagree about a code.

| Code | Status | Pattern | Remedy |
| --- | --- | --- | --- |
| ERR-AUTH-001 | 401 | page | Redirect to sign-in with a return URL and no account hint. |
| ERR-AUTH-002 | 401 | inline | Correct the email or password; both fields share one message. |
| ERR-AUTH-003 | 401 | inline | Request a fresh verification code and enter it. |
| ERR-AUTH-005 | 403 | page | Verify the email address through the link that was sent. |
| ERR-AUTH-006 | 403 | page | Enrol a second factor before continuing to the console. |
| ERR-AUTH-007 | 401 | page | Sign in again and return to the interrupted action. |
| ERR-AUTH-008 | 403 | banner | Re-authenticate for this action and continue where it stopped. |
| ERR-AUTH-012 | 401 | banner | Replace the API key or use a key with the required scope. |
| ERR-GATE-001 | 401 | page | Authenticate to the protected area through its own sign-in form. |

The R-20 enumeration rule stays scoped to the permission-denied and not-found answers, where a 403 or 404 must not
differ between an absent and a forbidden resource. A wrong credential (`ERR-AUTH-002`) also keeps one identical
message for an unknown account and a wrong password, because either answer would enumerate the account.

## Pattern selection

- P-1 One response carries one B7 code, so the interface derives one class from that code and the status table.
- P-2 When several classes are present at once, the page-level message shows the highest class in this order: maintenance, system, upstream, quota, rate limit, conflict, authentication, permission, not found, validation.
- P-3 Validation never becomes a page: the fields show inline messages and the form shows the ErrorSummary.
- P-4 A toast carries a transient notice only; a banner carries a persistent condition; a page carries an error when no screen is left to return to.
- P-5 Focus goes to the summary after a validation failure and to the page heading after a page error; focus never moves into a toast or a banner by itself.
- P-6 Inline messages persist until the field is valid; toasts clear after 8 seconds or on dismissal; banners persist until the condition clears or the session ends; pages persist.
- P-7 A class never renders with a lower pattern than the matrix allows: when in doubt the more persistent pattern wins.
- P-8 One cause appears once per channel and every repeat uses the same text: a validation failure may show the summary, the inline message and a toast that repeats the sentence, and a job failure may show a notification, an inline status and a repeating toast. A second explanation of the same cause in different words is the defect the rule forbids.

### Pattern copy

| Pattern | Copy keys |
| --- | --- |
| inline | `error-validation-inline` |
| summary | `error-summary-title` |
| toast | `error-toast-retry` |
| banner | `error-banner-persistent` |
| page | `error-page-title`, `error-page-body` |

## Request ID and Ray ID

Every API problem document carries `request_id` (B6.1). A visitor page shows a Ray ID whose shape is
`[0-9a-f]{16}-HDD1` (section 0.10). The two identifiers serve different audiences and never mix.

- RID-1 The API surface shows `request_id` in a CopyField labelled with `error-request-id-label`.
- RID-2 A console error carries the Ray ID for an event via RayIDChip and the request id beside it.
- RAY-1 The block page S-140 and the origin error page S-143 show a Ray ID with `error-ray-id-label`; the copy button carries `error-copy-ray-id`.
- RAY-2 Copying is progressive enhancement: `error-copy-request-id` copies the request id and `error-copy-ray-id` copies the Ray ID, and a polite live region announces the result (B11.8 CopyField).
- RAY-3 Support looks up a Ray ID with `GET P/support/ray/{ray}` and reads the request with `GET D/events/{ray}`; the organisation audit log holds the actor and the configuration revision of the same request.
- RAY-4 The Ray ID on S-140 is prefilled into the appeal form S-145, so the owner can review the block from the report alone.
- RAY-5 Never shown: trace ids, span ids, an internal hostname, a stack trace and a rule id.
- RAY-6 A page carries one identifier only: the S-140 JSON variant returns `error` and `ray_id` and never `request_id`, while a console error shows `request_id` and links a Ray ID only when an event exists.

## Retry and idempotency

B6.1 requires `Idempotency-Key` on every POST that creates a resource or triggers a job, `If-Match` on updates
and `Retry-After` on a 429 answer. The table classifies real B6 actions and separates the safe ones from the
unsafe ones.

| User action | Method | B6 row | Retry | Idempotency-Key | Precondition |
| --- | --- | --- | --- | --- | --- |
| Load the audit log | GET | `GET O/audit` | safe | not required | none |
| Set the integration mode | PUT | `PUT D/integration` | safe | not required | If-Match |
| Delete a DNS record | DELETE | `DELETE D/dns/records/{rec}` | safe | not required | If-Match |
| Update a DNS record | PATCH | `PATCH D/dns/records/{rec}` | safe with If-Match | not required | If-Match |
| Add a domain | POST | `POST O/domains` | safe with Idempotency-Key | required | none |
| Start an existing-DNS scan | POST | `POST D/scan` | safe with Idempotency-Key | required | none |
| Sign in | POST | `POST /auth/login` | unsafe | not required | none |
| Send a verification email | POST | `POST /auth/resend-verification` | unsafe | not required | none |
| Start a password reset email | POST | `POST /auth/forgot-password` | unsafe | not required | none |
| Test a webhook delivery | POST | `POST O/webhooks/{whk}/test` | unsafe | not required | none |
| Rotate a webhook signing secret | POST | `POST O/webhooks/{whk}/rotate-secret` | unsafe | not required | none |
| Enter platform emergency safe mode | POST | `POST P/emergency/safe-mode` | unsafe | not required | none |
| Revoke all other sessions | POST | `POST /me/sessions/revoke-others` | unsafe | not required | none |
| Remove a ban | DELETE | `DELETE D/bans/{ip}` | safe | not required | none (the ban set has no ETag) |

- RT-1 A 429 answer carries `Retry-After`; the interface shows a countdown with `error-retry-after` and sends nothing before it.
- RT-2 A retried mutation reuses the same Idempotency-Key; a new intent gets a new key, and the button carries `error-retry-action`.
- RT-3 An `If-Match` mismatch returns ERR-CONC-001: the user reloads the resource and repeats the edit, and the form keeps the entered values (B11.9 item 1).
- RT-4 An unsafe action is never retried by the interface. The person reads the outcome and decides; a POST that sends email or a webhook, rotates a secret, enters an emergency state or has no idempotency key waits for that decision.
- RT-5 A background poll backs off and stops at a terminal state, as the next table states.

### Background polls

| Poll | Method and path | First interval | Backoff | Stop |
| --- | --- | --- | --- | --- |
| Domain scan progress | `GET D/scan/{scan}` | 2 s | doubles to a 30 s cap | a terminal state or 15 min |
| Certificate order state | `GET D/tls/acme-status` | 5 s | doubles to a 60 s cap | issued, failed or stopped |
| Live event stream | `GET D/events/stream` | 1 s connect | reconnect doubles to a 30 s cap | the page is hidden or the stream is closed |

The poll stops on a 401 or 403 answer instead of backing off further, because retrying a session that ended
cannot succeed. A failed poll shows the stale marking described in the offline section.

## Visitor pages S-140 to S-148

The nine data-plane pages are owned by T-0065. Each renders server-side, loads no third-party resource and
carries a tenant brand slot where B12.1 allows it. This table is the model the templates follow.

| Page | Name | Status | B7 code | Copy keys | JSON variant |
| --- | --- | --- | --- | --- | --- |
| S-140 | Block page | 403 | ERR-VISITOR-403 | `block-page-title`, `block-page-body`, `block-page-ray` | application/problem+json {"error":"access_denied","ray_id"} |
| S-141 | Challenge page | 403 interstitial (HDD-Challenge: 1), 200 direct page | none in B7 | `visitor-challenge-title`, `visitor-challenge-progress` | application/problem+json |
| S-142 | Rate-limit page | 429 | ERR-VISITOR-429 | `visitor-rate-limit-title`, `visitor-rate-limit-body`, `error-retry-after` | application/problem+json |
| S-143 | Origin error page | 502, 504 | ERR-VISITOR-502, ERR-VISITOR-504 | `visitor-origin-error-title`, `visitor-origin-error-body` | application/problem+json |
| S-144 | Unknown host page | 404 | none in B7 (data-plane neutral 404) | `visitor-unknown-host-title`, `visitor-unknown-host-body` | application/problem+json |
| S-145 | Appeal form | 200 | none in B7 | `appeal-title` | application/problem+json |
| S-146 | Appeal received | 200 | none in B7 | `appeal-sent` | application/problem+json |
| S-147 | Under attack interstitial | 403 interstitial (HDD-Challenge: 1), 200 direct page | none in B7 | `visitor-under-attack-title`, `visitor-under-attack-body` | application/problem+json |
| S-148 | Domain suspended page | 503 | none in B7 | `visitor-suspended-title`, `visitor-suspended-body` | application/problem+json |

A status in the table is a design decision of T-0065 when B7 has no visitor code for the page. The block page,
the rate-limit page and the origin error page follow their B7 visitor codes exactly. The unknown host page has
no B7 code: C2 stage 3 produces its branded 404 during host resolution, so the table says so instead of borrowing
an API problem type. The challenge and under-attack interstitials answer a challenged request with status 403
and the header `HDD-Challenge: 1`; a direct fetch of the page itself is 200 (T-0337 step 2, T-0338 step 4).

## Visitor page constraints

Each constraint is a testable statement and names how a test detects a violation. The copy-key scan runs the
values of the page table above.

- V-1 No rule name or rule id appears in any visitor copy string. Detect: the copy scan fails when a cited page value contains a rule word.
- V-2 No stack trace, exception text or source path appears in visitor copy. Detect: the copy scan looks for trace words.
- V-3 No internal hostname, private address or dependency name appears. Detect: the copy scan looks for internal words.
- V-4 S-144 is a neutral 404 whose copy carries no tenant variable and no brand slot. Detect: the scan of the S-144 keys rejects `$` and tenant words.
- V-5 S-148 names no tenant detail and carries no tenant variable. Detect: the same scan of the S-148 keys.
- V-6 No visitor copy blames the person or repeats the matched payload. Detect: the scan looks for blame words and payload words.
- V-7 The Ray ID appears on S-140 and matches the Ray shape. Detect: the S-140 key set must include a value carrying `ray_id`.
- V-8 The JSON variant is `application/problem+json` and S-140 names `error` and `ray_id`. Detect: the page table column check and the B12.2 body check.
- V-9 Every visitor page loads no external request and stays inside the 20 KB page budget. Detect: the page-weight test named by T-0065 A4.
- V-10 Every visitor page uses inline CSS with a nonce and dark or light from `prefers-color-scheme`. Detect: the CSP test named by T-0065 step 4.
- V-11 The S-140 JSON variant carries `error` and `ray_id` only; it never carries `request_id`, a trace id or a rule id. Detect: the JSON contract test parses the body keys.

`UNVERIFIED(capability_not_supplied)`: the page-weight and CSP tests belong to T-0065 and the frontend phase, so
this document states the constraints without claiming a measured result.

## Offline and flaky networks

These rules cover a failed HTMX partial update. The offline cache and install behaviour of the PWA is deferred
to P32; this section defines the request-failure pattern those pages will reuse.

- O-1 An HTMX partial update never fails silently: a failed swap shows an inline message or a toast in the same region. Detect: a browser test forces an offline answer and asserts a visible message and an announcement.
- O-2 The last confirmed values stay on screen and are marked stale with `error-stale-partial`; a failed optimistic value is reverted. Detect: the test asserts the stale marking and the reverted value.
- O-3 The failed region shows `error-retry-action` and only that region is retried. Detect: the test forces one region to fail and asserts the retry target.
- O-4 Automatic retry applies to GET and poll swaps with backoff; a mutation is never re-sent automatically and waits for the person. Detect: the test forces a POST failure and asserts no second request.
- O-5 An offline banner uses `error-offline-banner` and a reconnecting status uses `error-reconnect-status`; both clear when the connection returns. Detect: the test toggles the connection and asserts both messages.
- O-6 The rest of the page stays interactive and one failed region never replaces the page. Detect: the test asserts the other regions keep their state.
- O-7 A failure inside a small partial update is announced politely and the stale marking is visible. Detect: the test reads the live region and the stale text together.

## Long-running job failures

A background job is any action that returns a job id instead of a result: a DNS scan, a certificate order, an
export or a report run. Its failure is more than an error page, because nobody is watching the page.

- L-1 A failed job raises a notification addressed to the person who started it, using `error-job-failed-notification`. Detect: the worker test asserts the notification target.
- L-2 The job inline status switches to failed with `error-job-failed-inline` and the last successful result stays visible. Detect: the test reads the inline status and the retained result.
- L-3 The notification names the event reference and the Ray ID or request id, so support can find the same request. Detect: the test reads the reference from the message.
- L-4 Retrying a failed job starts a new job and never reuses the old job id. Detect: the test compares the two job ids.
- L-5 A job failure shows the notification and the inline status; a toast may repeat the same sentence but never carries the news alone. Detect: the test asserts the notification and the inline channel.

The three channels are the durable notification, the inline status of the job row and the event reference. A
toast may repeat the news but never carries it alone.

## Logging of errors

The client logs nothing. The server writes one structured record per error. The rule is data minimisation
(R-25): no body, no PII and no secret enters a log line.

- LG-1 Client-side: nothing is logged. No error text, code, request id or form value goes to the console, a client log or client telemetry. Detect: the browser test stubs the console and the beacon and asserts zero calls.
- LG-2 Server-side: one structured record per error with `request_id`, code, status, route template and duration, and never the raw message text. Detect: the log schema test parses the record.
- LG-3 No request or response body is logged in full; redacted evidence is capped at 512 bytes (R-25). Detect: the log corpus test measures the capped field.
- LG-4 No secret, token, cookie, password, Authorization header or PII is logged. Detect: the log corpus scan for these patterns.
- LG-5 A stack trace stays server-side and never enters the API document or the visitor page. Detect: the contract test reads the problem document keys.

## Accessibility of errors

The rules below follow [ACCESSIBILITY.md](ACCESSIBILITY.md) and [SECURITY-UX.md](SECURITY-UX.md). Every error
change is announced, focus lands somewhere sensible and the message is text.

| Pattern | Focus | Role | Text not colour | Component |
| --- | --- | --- | --- | --- |
| inline | focus stays in the field and the message is linked with aria-describedby | aria-describedby | the message is text and the icon is decoration, never colour only | FormField |
| summary | focus moves to the summary heading | role="alert" | every item is a link with text, never colour only | ErrorSummary |
| toast | focus never moves into the toast | role="alert" | the outcome is text and the icon is decoration, never colour only | Toast |
| banner | focus moves to the banner text | role="alert" | the condition is text and it is never colour only | Banner |
| page | focus moves to the page heading | main landmark | the failure is text and it is never colour only | ErrorState |

The relevant WCAG 2.2 criteria are 3.3.1, 3.3.3 and 4.1.3 of the B11.11 contract, with 2.4.3 and 2.4.7 for the
focus order. The visitor pages add the B12.1 rule that a challenge announces progress in a live region and has a
`noscript` fallback (T-0065 step 6).

## Security notes

- SEC-1 No stack trace or internals detail appears in an API document or a visitor page. Detect: the contract test reads the problem document keys.
- SEC-2 Permission denied never reveals whether a resource exists: a cross-tenant read is 404 `ERR-PERM-002`, not a 403, and the text is the generic not-found message (R-20). Detect: the BOLA test reads a foreign resource and asserts 404.
- SEC-3 Authentication errors do not enumerate accounts: an unknown email and a wrong password both return `ERR-AUTH-002`. Detect: the two answers are compared byte for byte.
- SEC-4 No internal hostname or dependency name appears in a user-facing error. Detect: the copy scan of the error strings.
- SEC-5 A 403 names the permission only to organisation members (`ERR-PERM-001`) and never names the resource. Detect: the permission response test.
- SEC-6 The absent and the forbidden case use the same text and the same time budget outside the tenant (R-20). Detect: the enumeration test compares both answers.

The visitor pages never show a rule, a signature, a paranoia level or a detection threshold. The block page
says a request looked like an attack; it does not say which rule fired (B7, B12.2 S-140).

## Journey error-path coverage

The journeys J-01 to J-34 carry an `Error path` column. Every distinct code in that column is listed below under
the class the classification rules give it. The `ux-docs` check collects the codes from the journeys with a
script and fails when this table drifts.

| Class | Error codes |
| --- | --- |
| validation | ERR-ANALYTICS-001, ERR-AUTH-009, ERR-AUTH-010, ERR-AUTH-017, ERR-AUTH-018, ERR-DNS-001, ERR-DNS-002, ERR-DNS-003, ERR-DNS-004, ERR-DNS-005, ERR-DNS-006, ERR-DOM-001, ERR-HOOK-001, ERR-HOSTING-001, ERR-ORG-001, ERR-ORG-003, ERR-ORG-004, ERR-ORIGIN-001, ERR-ORIGIN-002, ERR-REPORT-001, ERR-TLS-002, ERR-TLS-003, ERR-TLS-006, ERR-VAL-001, ERR-VAL-002, ERR-VAL-003, ERR-VAL-005, ERR-WAF-001, ERR-WAF-002, ERR-WAF-005 |
| permission | ERR-BAN-002, ERR-BYPASS-002, ERR-KEY-001, ERR-ORG-002, ERR-ORG-005, ERR-PERM-001, ERR-PLAT-001, ERR-PLAT-002, ERR-TENANT-001, ERR-VISITOR-403, ERR-WAF-007 |
| authentication | ERR-AUTH-002, ERR-AUTH-003, ERR-AUTH-006, ERR-AUTH-007, ERR-AUTH-008, ERR-AUTH-012 |
| not found | ERR-APPEAL-001, ERR-BAN-001, ERR-PERM-002 |
| conflict | ERR-CONC-001, ERR-CONC-002, ERR-IDEMP-001, ERR-WAF-004 |
| rate limit | ERR-APPEAL-002, ERR-AUTH-004, ERR-GATE-003, ERR-RATE-001 |
| quota | ERR-BAN-004, ERR-DNS-007, ERR-DOM-006, ERR-RATE-002 |
| upstream | ERR-ACME-002, ERR-ACME-006, ERR-BYPASS-001, ERR-DOM-004, ERR-DOM-007, ERR-HOOK-002, ERR-ORIGIN-003, ERR-ORIGIN-004, ERR-TLS-005 |
| system | ERR-DOM-005, ERR-LOCAL-001, ERR-SYS-001, ERR-SYS-002 |
| maintenance | ERR-SYS-003, ERR-SYS-004, ERR-WAF-006 |

## Copy inventory

Every key the model cites is defined exactly once: the five B13 keys in `i18n/en/copy-deck.ftl` and the rest in
`i18n/en/errors.ftl`. The `Exact English text` column repeats the definition and the check compares it.

A backticked placeholder is quoted in the form of its defining source. B13 and the deck write `{ray_id}`; the new
`errors.ftl` keys use the Fluent form `{ $ray_id }` and `{ $request_id }`. The check compares each quoted value
with the file that defines that key, so the two forms never drift apart.

| Key | Source | Exact English text |
| --- | --- | --- |
| block-page-title | B13 | Access denied |
| block-page-body | B13 | Your request looked like an attack on this website, so it was blocked. If you believe this is a mistake, you can tell the site owner. |
| block-page-ray | B13 | Reference: {ray_id} |
| appeal-title | B13 | Report a mistaken block |
| appeal-sent | B13 | Thank you. The site owner can review your report using the reference above. |
| error-validation-inline | errors.ftl | Enter a valid value for this field. |
| error-summary-title | errors.ftl | Check the highlighted fields. |
| error-toast-retry | errors.ftl | The change was not saved. Try again. |
| error-banner-persistent | errors.ftl | Part of this page is unavailable until the problem clears. |
| error-page-title | errors.ftl | Something went wrong |
| error-page-body | errors.ftl | The action did not complete. The reference below helps support find the cause. |
| error-request-id-label | errors.ftl | Request ID: { $request_id } |
| error-ray-id-label | errors.ftl | Ray ID: { $ray_id } |
| error-copy-ray-id | errors.ftl | Copy Ray ID |
| error-copy-request-id | errors.ftl | Copy request ID |
| error-retry-action | errors.ftl | Try again |
| error-retry-after | errors.ftl | Try again after { $seconds } seconds. |
| error-offline-banner | errors.ftl | You are offline. Changes are sent when the connection returns. |
| error-reconnect-status | errors.ftl | Connection lost. Retrying in { $seconds } seconds. |
| error-stale-partial | errors.ftl | The values on screen may be out of date. |
| error-job-failed-inline | errors.ftl | This job failed. The last result stays visible. |
| error-job-failed-notification | errors.ftl | A background job failed. Open it to see the reference. |
| visitor-challenge-title | errors.ftl | Checking your browser |
| visitor-challenge-progress | errors.ftl | The check finishes automatically. |
| visitor-rate-limit-title | errors.ftl | Too many requests |
| visitor-rate-limit-body | errors.ftl | Too many requests reached this site from your network. |
| visitor-origin-error-title | errors.ftl | This website is unavailable |
| visitor-origin-error-body | errors.ftl | The site could not be reached. Try again in a moment. |
| visitor-unknown-host-title | errors.ftl | Site not found |
| visitor-unknown-host-body | errors.ftl | No website is configured at this address. |
| visitor-under-attack-title | errors.ftl | A quick check is running |
| visitor-under-attack-body | errors.ftl | The check finishes automatically and then the site opens. |
| visitor-suspended-title | errors.ftl | Website unavailable |
| visitor-suspended-body | errors.ftl | This website is paused. Contact the site owner if it continues. |
