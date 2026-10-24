# Vi, the blocked visitor

**Fictional composite.** Vi is not a real person and stands for no single person: she is a composite of the legitimate
visitors described in spec [B1.5](../../SPEC.md#b15-vi-the-blocked-visitor). Her scenarios are design inputs, not measured
results; a measurable outcome below names a real test, audit event or metric.

She is not the pilot's assumed primary persona (that is Maya until the
[primary-persona question](../../OPERATOR-QUESTIONS.md#primary-persona-for-the-pilot-added-by-t-0012) is answered), but she
is the one person who meets HDD without ever having signed up. The [UX charter](../CHARTER.md) applies to every page she
sees.

## Context of use

| Aspect | Detail |
| --- | --- |
| Device | An older phone or a work laptop with privacy extensions; JavaScript may be disabled. |
| Connectivity | Mobile data, sometimes slow or behind a captive portal. |
| Interruptions | Blocked in the middle of a task, often in a hurry, and unlikely to try twice. |
| Vocabulary | None of the security terms; understands "blocked", "try again" and "contact the site owner". |
| First check of the day | The block page text: what happened, what to do next and where to appeal. She may meet HDD only once. |

## Scenarios

### 1. Understand what happened

When a site I use returns a block page, I want to see a calm page with a reference number and no technical blame, so I can tell
the site owner what happened and decide whether to retry.

Measurable outcome: AC-43 (appeals) passes and the page shows the Ray ID while showing no rule name; the path is
[J-22](../../SPEC.md#j-22-blocked-visitor-files-an-appeal).

### 2. Appeal without creating an account

When I believe the block is wrong, I want to submit an appeal with an optional email address and keep a reference, so I
can get back in without signing up for a security product I do not use.

Measurable outcome: `AUD-appeal.submitted` is written with the Ray ID and AC-43 passes for the submitted, received and
resolved states (S-145 and S-146).

### 3. Use the site on an old phone or without JavaScript

When my phone or browser cannot run the challenge, I want to get the page text and a working contact path, so I can still
finish what I was doing.

Measurable outcome: AC-44 (challenge and bots) and AC-40 (accessibility) pass; the reading page works without
JavaScript and offers an explanation plus the alternative contact path (S-141).

## Anti-goals

- A CAPTCHA puzzle as the only way through.
- A page that blames me or prints a rule name, an internal hostname or a stack trace (B1.7).
- An appeal that requires an account, an app or JavaScript.
- A page that fails to render on an old phone or at 200% zoom.
- Being told to contact an address that does not exist.

## Accessibility

B1.5 names Vi's needs: screen readers, no CAPTCHA puzzle, old phones, and reading the page without JavaScript. Mapped to
the [B11.11](../../SPEC.md#b1111-accessibility-contract-summary-of-wcag-22-aa-obligations-the-components-encode) criteria:
1.1.1 and 1.3.x (text alternatives and semantic structure), 1.4.4 and 1.4.10 (resize and reflow on an old phone), 2.1.1
(keyboard on a work laptop), 3.3.8 (accessible authentication: no cognitive test; the proof of work is automatic) and
4.1.2 (names, roles and values on the appeal form).

Assistive technology assumptions: VoiceOver or TalkBack on an older phone, 200% zoom, keyboard-only operation on a work
laptop, and JavaScript disabled; the challenge may need JavaScript, so the page must explain that and give the
alternative.

## Journeys and screens

- Journeys: [J-22](../../SPEC.md#j-22-blocked-visitor-files-an-appeal).
- Screens: [S-140](../../SPEC.md#s-140-block-page-visitor) Block page,
  [S-141](../../SPEC.md#b121-screen-table) Challenge page,
  [S-142](../../SPEC.md#b121-screen-table) Rate-limit page,
  [S-145](../../SPEC.md#b121-screen-table) Appeal form and
  [S-146](../../SPEC.md#b121-screen-table) Appeal received.
- Success, from B1.5: she understands what happened, gets back in through the appeal, and can tell the site owner - and
  the block page never teaches an attacker how the decision was made.
