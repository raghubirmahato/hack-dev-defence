# Maya, the site owner (primary)

**Fictional composite.** Maya is not a real person and stands for no single customer: she is a composite of the site
owners described in spec [B1.1](../../SPEC.md#b11-maya-the-site-owner-primary). Her scenarios are design inputs, not
measured results; a measurable outcome below names a real test, audit event or metric instead of a promise.

She is the assumed primary persona for the pilot until the operator answers the
[primary-persona question](../../OPERATOR-QUESTIONS.md#primary-persona-for-the-pilot-added-by-t-0012). The
[UX charter](../CHARTER.md) applies to every screen she uses.

## Context of use

| Aspect | Detail |
| --- | --- |
| Device | A laptop for DNS work and a phone for the first look; the phone is the usual device in the shop. |
| Connectivity | Shop broadband, sometimes a phone hotspot; expects text before images on a slow link. |
| Interruptions | Customers arrive mid-task; a session lasts a few minutes between customers and is resumed later. |
| Vocabulary | Nameservers, CNAME and TTL learned from a registrar help page; does not use WAF, paranoia level or CIDR. |
| First check of the day | The organization overview: is the shop up, and did anything get blocked overnight? |

## Scenarios

### 1. Connect the first site without becoming a DNS expert

When I have just created my account and my shop runs on WordPress, I want to use a wizard that finds my current DNS records and
offers the simplest connection that does not break mail, so I can finish while the shop is quiet.

Measurable outcome: `AUD-domain.activated` is written with mode `monitor` in the same session and `AUD-dns.imported`
records the import; the flow is the acceptance check AC-37 and the `completion rate of the add-domain wizard` measure in
[MEASURES.md](../MEASURES.md).

### 2. Move from monitor to block without risking an order

When the security overview shows requests it would have blocked but no customer complaints, I want to see the count, one
example and a clear way back, so I can switch to block mode without risking a sale.

Measurable outcome: the switch writes `AUD-waf.mode_changed` and the undo is one action; AC-13 (modes, safe mode and
automatic rollback) passes, and AC-06 supports the false-positive side.

### 3. Recover from a change that broke the shop or caught my own connection

When a DNS or protection change stops the shop loading, or a ban catches the shop's own connection, I want to have the page
name what changed and offer exactly one way back, so I can recover before I lose orders.

Measurable outcome: the previous configuration is restored in one recorded action (`AUD-dns.rolled_back` or
`AUD-waf.revision_applied`) and the self-lockout guard of AC-13 and rule R-19 is exercised.

## Anti-goals

- Jargon I have to look up before I can act.
- A change that cannot be undone without contacting support.
- Numbers I cannot verify, or a page that hides what is not covered.
- Being locked out of my own site or my own account.
- One task that needs two DNS provider pages.

## Accessibility

B1.1 names Maya's needs: screen magnification, large text, keyboard use after an injury and reduced motion. Mapped to the
[B11.11](../../SPEC.md#b1111-accessibility-contract-summary-of-wcag-22-aa-obligations-the-components-encode) criteria:
1.4.4 (200% text resize) and 1.4.10 (reflow at 320 CSS px), 2.1.1 (all functionality by keyboard), 2.4.7 (visible focus)
and 3.3.7 (redundant entry: the wizard keeps values she already typed). Reduced motion is honored by the motion tokens
(B11.5) and is not a substitute for any criterion above.

Assistive technology assumptions: browser zoom at 200% and Windows Magnifier; a keyboard after a hand injury; no screen
reader is expected, but nothing may depend on a pointer.

## Journeys and screens

- Journeys: [J-02](../../SPEC.md#j-02-visitor-signs-up-and-verifies-email),
  [J-07](../../SPEC.md#j-07-owner-completes-the-onboarding-checklist),
  [J-08](../../SPEC.md#j-08-owner-adds-a-domain-using-full-nameserver-delegation),
  [J-09](../../SPEC.md#j-09-owner-adds-a-domain-using-cname-partial-setup),
  [J-12](../../SPEC.md#j-12-owner-configures-and-tests-the-origin),
  [J-15](../../SPEC.md#j-15-owner-issues-tls-and-enables-hsts),
  [J-16](../../SPEC.md#j-16-owner-enables-protection-in-monitor-mode-reviews-switches-to-block),
  [J-22](../../SPEC.md#j-22-blocked-visitor-files-an-appeal),
  [J-23](../../SPEC.md#j-23-owner-handles-an-appeal),
  [J-25](../../SPEC.md#j-25-owner-views-protection-readiness-and-fixes-items) and
  [J-32](../../SPEC.md#j-32-owner-removes-a-domain-safely).
- Screens: [S-001](../../SPEC.md#b121-screen-table) Landing, [S-020](../../SPEC.md#b121-screen-table) Sign up,
  [S-035](../../SPEC.md#b121-screen-table) Onboarding wizard, [S-040](../../SPEC.md#b121-screen-table) Organization
  overview, [S-041](../../SPEC.md#b121-screen-table) Domains,
  [S-042](../../SPEC.md#s-042-add-domain-wizard) Add-domain wizard,
  [S-043](../../SPEC.md#b121-screen-table) Domain overview,
  [S-044](../../SPEC.md#s-044-protection-readiness) Protection readiness,
  [S-045](../../SPEC.md#b121-screen-table) DNS records,
  [S-054](../../SPEC.md#b121-screen-table) Security overview,
  [S-065](../../SPEC.md#s-065-live-threat-monitor) Live threat monitor,
  [S-140](../../SPEC.md#s-140-block-page-visitor) Block page and
  [S-145](../../SPEC.md#b121-screen-table) Appeal form.
- Success, from B1.1: the site is proxied in monitor mode for a few days, then in block mode, with an email when
  something serious happens.
