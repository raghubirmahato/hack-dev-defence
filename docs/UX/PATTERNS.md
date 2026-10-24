# Pattern review of comparable consoles

Status: UNVERIFIED(capability_not_supplied) - there is no network access and no operator-supplied screenshots or exports
for this review, so every entry below is first-principles reasoning about consoles for DNS, CDNs and web application
firewalls. No third-party text or asset was fetched or copied (A3).

This document is the pattern input for `docs/UX/design-requirements.md`. It answers the review questions below for each
topic before any screen is specified. It names product categories, not products: no third-party wording is quoted.

## Review questions

1. How does the console present onboarding to someone who has never changed DNS records?
2. How does it import existing DNS records, and how does it show what will change?
3. How does it explain a proxy toggle, and what state does it show per record?
4. How does it present firewall modes and the consequence of each mode?
5. How does it let an analyst read a live event log and reach the evidence for one request?
6. How does it make a rule builder understandable and safe to test?
7. How does it explain a ban, show how long it lasts and offer a way back?
8. How does it present analytics without implying precision the data does not have?
9. How does it manage API keys and show scopes, expiry and revocation?
10. How does it manage team members, roles and the last-owner risk?
11. How does a blocked visitor understand the block and file an appeal?
12. How are alerts and durable notifications kept useful rather than noisy?

## Topic: Onboarding

Source: first principles

Problem: A new owner has not yet learned the product's vocabulary, and every extra step is a reason to stop.

Common solutions: A wizard with one question per step, a saved checklist, one highlighted next action, and a summary
that says what is already working. Progress is stored on the server so a session can be resumed.

Pitfalls: A tour that covers features instead of the first task; a wizard that cannot be left and resumed; a checklist
that hides the one action that matters; copy that assumes the reader knows what a nameserver is.

Accessibility and clarity pitfalls: A progress ring that is the only sign of completion; focus lost when a step loads;
a wizard that cannot be completed by keyboard; a "skip" link that is invisible until hover.

## Topic: DNS import

Source: first principles

Problem: Records move between providers, and one dropped mail record costs the owner more than the whole security setup
is worth.

Common solutions: Scan the current zone, show it grouped by purpose, print a source and target diff, let the owner
acknowledge each unsupported type, and keep mail records unproxied by default.

Pitfalls: Importing silently; treating an unsupported record as removed; losing the previous state so rollback needs
support; hiding the parity report behind a later step.

Accessibility and clarity pitfalls: A diff shown only with red and green; record tables without header cells; values
that can only be read by hovering; a confirmation whose consequence list is collapsed by default.

## Topic: Proxy toggles

Source: first principles

Problem: A proxy toggle changes which server answers a name, and the reader often does not know that.

Common solutions: A toggle pair with explicit text ("Proxied" and "DNS only"), a consequence sentence next to it, and a
per-record state in the table. Changing a record shows what will resolve before the change is saved.

Pitfalls: A switch with no label beyond colour; proxying a mail or verification record by accident; no warning that a
direct record exposes the origin address; an undo path that only appears after the fact.

Accessibility and clarity pitfalls: Colour as the only state signal; a switch whose label is not associated with it; a
target smaller than the minimum touch size; a consequence tooltip that cannot be reached by keyboard.

## Topic: WAF modes

Source: first principles

Problem: Mode names (off, log, monitor, block) each change what visitors experience, and the difference is not obvious.

Common solutions: One selector with a sentence per mode, a count of requests the stricter mode would have blocked, a
scheduled switch, and a single undo action. New sites start in a mode that blocks nothing until the owner has seen the
preview.

Pitfalls: A default that blocks traffic before anyone has reviewed it; a confirmation without the consequence list;
fear wording that pushes a quick switch; an undo buried in settings.

Accessibility and clarity pitfalls: A mode badge that carries meaning only through colour; a confirmation that cannot
be reached by keyboard; a status change announced to nobody; a mode difference explained only in a tooltip.

## Topic: Event logs

Source: first principles

Problem: A live feed produces more rows than one person can read, and a row is useless without the decision behind it.

Common solutions: Filter chips stored in the URL, saved views, a pause control, a buffered "N new" count, and a detail
view that shows the rule, the field vector and redacted evidence for a Ray ID.

Pitfalls: Auto-scrolling that moves focus and loses the row being read; a feed that cannot be paused; evidence that shows
the payload without redaction; a detail view with no stable request identifier to quote in a report.

Accessibility and clarity pitfalls: A table built from div elements with no row semantics; auto-scroll that hijacks a
screen reader; a pause button that is not reachable by keyboard; announcements for every event instead of a batch.

## Topic: Rule builders

Source: first principles

Problem: A rule is a small program, and a row of dropdowns can express a condition the author did not intend.

Common solutions: A sentence preview of the rule as it is edited, field and operator validation on blur, a test panel
with sample requests, a dry-run against recent traffic, and move up and down buttons for ordering.

Pitfalls: Nested groups whose logic is not visible; saving before validating; losing a draft on navigation; reordering
only by drag; no record of who changed what.

Accessibility and clarity pitfalls: Drag-and-drop as the only way to reorder; group nesting announced as a flat list;
errors shown only as a red border; a preview that updates without a live-region notice.

## Topic: Bans

Source: first principles

Problem: A ban is a punishment applied to an address, and the reader needs to know why it happened and how it ends.

Common solutions: Each ban shows the rule, the vector, a redacted evidence excerpt, the TTL step, a countdown with
text, an unban action and a link to the appeal inbox. Shared-address warnings appear before a long ban is confirmed.

Pitfalls: Permanent bans by default; no appeal path; a countdown that is the only explanation of the expiry; a manual
ban that does not record the operator's reason.

Accessibility and clarity pitfalls: Time shown only as a shrinking bar; an unban action reachable only by pointer; a
reason that is hidden in a tooltip; a live countdown that interrupts a screen reader every second.

## Topic: Analytics

Source: first principles

Problem: A chart can look exact while hiding units, missing periods and sparse data.

Common solutions: Label the axes and units, state the time zone, add a one-line text summary, offer a "View as table"
toggle, and show gaps as gaps instead of interpolated zeros.

Pitfalls: Treating a missing day as zero; a legend that needs a second screen; colour-only series; a number whose
denominator is not shown.

Accessibility and clarity pitfalls: No text alternative for a chart; series distinguished only by hue; a table view
that is a separate screen; tooltips that carry the only copy of a value.

## Topic: API keys

Source: first principles

Problem: A key is a secret, and scope and expiry are easy to leave out of the interface.

Common solutions: The secret is shown once, in a copy field with an announcement, with scopes, an expiry and an IP
restriction chosen up front; a usage view and a revoke action live beside it.

Pitfalls: Putting the secret in a URL; a key with no expiry; a copy button blocked by script or permissions; scopes
described by name only.

Accessibility and clarity pitfalls: Copy confirmation that is visual only; a key dialog that traps focus on creation
and never returns it; status shown as colour only.

## Topic: Team management

Source: first principles

Problem: Roles decide who can change protection, and a confident click can remove the last owner.

Common solutions: Role cards with plain descriptions, a permission matrix, an invitation expiry, an audit entry per
change, and a guard that stops the last owner from removing themselves.

Pitfalls: Privilege on by default; no history of role changes; a self-removal without a warning; invitations that never
expire.

Accessibility and clarity pitfalls: A matrix that is a picture; a remove dialog without a consequence list; an error
announced only by colour; a table without header cells.

## Topic: Appeals

Source: first principles

Problem: A blocked visitor needs a way back, often on a phone, and cannot be asked to create an account.

Common solutions: A block page with a calm explanation and a Ray ID; an appeal form with optional contact and a short
note; a light proof of work; an owner inbox that links each appeal to its evidence.

Pitfalls: Copy that blames the visitor; revealing which rule matched; a puzzle as the only way through; an appeal with
no reference number.

Accessibility and clarity pitfalls: A page that needs script to be read; a form without labels; a challenge with no
explanation; focus lost when the error appears.

## Topic: Notifications

Source: first principles

Problem: Alerts fail in two directions: too many to read, or absent for the event that mattered.

Common solutions: Channel choice per severity, quiet hours, a test send, a delivery log with retry outcomes, and a
durable notification centre beside transient toasts.

Pitfalls: The same event sent to every channel; no visibility of a failed delivery; webhook secrets in the URL; a toast
as the only record of a critical event.

Accessibility and clarity pitfalls: A toast that covers the focused control; an alert that is not announced; content
that disappears before it can be read; an error state that relies on red alone.

## Topic: Protection readiness

Source: first principles

Problem: Owners cannot tell whether the setup is finished, so they either stop early or keep changing a working setup.

Common solutions: A weighted checklist where each item states why it matters and links to the screen that fixes it; a
score computed from real checks; a history so a drop is explainable.

Pitfalls: A score that reads as a security guarantee; checks computed from assumptions rather than state; no route from
a failing item to its remedy; the list hidden behind a summary ring.

Accessibility and clarity pitfalls: The ring as the only representation of the score; items announced as a flat list; no
text for the reason an item failed; the score animated without respect for reduced motion.

## Topic: Origin lockdown

Source: first principles

Problem: A web application firewall is optional while visitors can still reach the origin address directly.

Common solutions: A wizard that adapts to the origin stack, copies a firewall allowlist and a secret header snippet,
runs verification probes, and shows the lockdown state and the last verification time.

Pitfalls: Calling a site protected while a bypass path is open; snippets that cannot be copied; steps that cannot be
undone; a state that only the operator can see.

Accessibility and clarity pitfalls: Code shown in a canvas or image; copy-only interactions; a risk explained in
security jargon; a modal wizard that drops focus on close.

## Non-goals

These are features of comparable consoles that this product will not copy, with the reason.

- We will not chase feature parity for its own sake; every screen is backed by a test and an owner.
- We will not copy wording, layout or assets from another console; the review describes patterns, not products.
- We will not use colour alone for state, because it fails readers and screenshots.
- We will not make a blocking mode the default before the owner has seen the preview.
- We will not hide an undo behind a settings page.
- We will not show a score, chart or count that the product cannot compute from real data.

## Honesty-test review

Each answer applies to this document, as T-0013 step 7 requires.

| # | Honesty test (charter wording is in `CHARTER.md`) | Answer | Reason |
| --- | --- | --- | --- |
| 1 | Real data only | Yes | The document shows no screen, chart or value; it records patterns and states no measurement. |
| 2 | Limits stated | Yes | The status line says no source was fetched, and the non-goals list what is out of scope. |
| 3 | Claims backed | Yes | Each requirement in the companion document links a topic here and a screen or component. |
| 4 | Safe option first | Yes | Requirements for modes and imports put the non-blocking preview first and the change second. |
| 5 | Undo or typed confirmation | Yes | Requirements for DNS, modes and rules ask for an undo; destructive steps ask for confirmation. |
