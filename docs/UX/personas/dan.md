# Dan, the developer / DevOps engineer

**Fictional composite.** Dan is not a real person and stands for no single customer: he is a composite of the developers
and DevOps engineers described in spec [B1.2](../../SPEC.md#b12-dan-the-developer--devops-engineer). His scenarios are
design inputs, not measured results; a measurable outcome below names a real test, audit event or metric.

He is not the pilot's assumed primary persona (that is Maya until the
[primary-persona question](../../OPERATOR-QUESTIONS.md#primary-persona-for-the-pilot-added-by-t-0012) is answered), but no
screen is done if only Maya can use it. The [UX charter](../CHARTER.md) applies to every screen he uses.

## Context of use

| Aspect | Detail |
| --- | --- |
| Device | Laptop with two screens and a terminal; uses the API and CLI more often than the dashboard. |
| Connectivity | Office fibre and a CI runner; automation runs unattended and retries. |
| Interruptions | Deploys and pages break his flow; he works in short bursts and resumes from logs. |
| Vocabulary | HTTP, JSON, CIDR, YAML, CI; expects exact names, stable ids and copyable examples. |
| First check of the day | CI status, then the API and event stream for protection or rule changes made overnight. |

## Scenarios

### 1. Provision a new client site from code

When a new site needs the same baseline as the others, I want to create the domain, rules and API key from a script with
copyable examples, so I can repeat the setup without clicking through the UI.

Measurable outcome: AC-45 (public API, scoped keys and webhooks) passes; `AUD-apikey.created` and `AUD-waf.rule_created`
are written, and the OpenAPI document at [S-007](../../SPEC.md#b121-screen-table) describes every call used.

### 2. Understand exactly why a request was blocked

When a request I did not expect is blocked, I want to see the rule, field, vector and redacted evidence for its Ray ID, so I can
fix my application instead of turning protection off.

Measurable outcome: AC-07 (detection matrix) and AC-08 (ban persistence, enforcement and unban) pass;
`MET-hdd_waf_blocks_total` counts the block and it can be found by Ray ID.

### 3. Change a rule in production without a support call

When I need a custom rule in production, I want to dry-run it against recent traffic and roll it back with one call, so
I can ship it during a deploy window.

Measurable outcome: AC-12 (dynamic rules and dry-run) and AC-16 (config revisions and convergence) pass;
`AUD-waf.inspect_run` records the dry run and `AUD-waf.revision_applied` records the change.

## Anti-goals

- A UI-only feature with no API under the same authorisation (R-27).
- An opaque decision: a block without the rule, field or evidence.
- Webhooks without signatures, retry visibility or a delivery log.
- Rotating a key or secret that silently breaks the pipeline.
- Documentation that is stale relative to the OpenAPI document.

## Accessibility

B1.2 names Dan's needs: keyboard-first operation, a command palette, copy buttons and readable monospace text. Mapped to
the [B11.11](../../SPEC.md#b1111-accessibility-contract-summary-of-wcag-22-aa-obligations-the-components-encode) criteria:
2.1.1 (all functionality by keyboard), 2.4.3 (logical focus order), 2.4.7 (visible focus), 3.3.7 (redundant entry: tokens
and values are copied, not retyped) and 4.1.2 (names, roles and values for copy buttons and command results).

Assistive technology assumptions: keyboard and command palette; no screen reader is expected while reading logs, but code
blocks, tables and copy buttons must carry names and roles so a screen reader can read them.

## Journeys and screens

- Journeys: [J-19](../../SPEC.md#j-19-owner-builds-a-custom-rule),
  [J-20](../../SPEC.md#j-20-owner-configures-rate-limits-for-login),
  [J-21](../../SPEC.md#j-21-owner-configures-alerts-and-webhooks),
  [J-27](../../SPEC.md#j-27-developer-creates-an-api-key-and-uses-the-api) and
  [J-28](../../SPEC.md#j-28-owner-exports-reports-and-audit-logs).
- Screens: [S-007](../../SPEC.md#b121-screen-table) API reference,
  [S-058](../../SPEC.md#b121-screen-table) Rules,
  [S-059](../../SPEC.md#s-059-rule-builder) Rule builder,
  [S-060](../../SPEC.md#b121-screen-table) Rule dry-run,
  [S-065](../../SPEC.md#s-065-live-threat-monitor) Live threat monitor,
  [S-066](../../SPEC.md#b121-screen-table) Event detail,
  [S-078](../../SPEC.md#b121-screen-table) Webhooks,
  [S-079](../../SPEC.md#b121-screen-table) Webhook deliveries,
  [S-080](../../SPEC.md#b121-screen-table) API keys,
  [S-084](../../SPEC.md#b121-screen-table) Audit log,
  [S-092](../../SPEC.md#b121-screen-table) Config revisions and
  [S-134](../../SPEC.md#s-134-coverage-map) Coverage map.
- Success, from B1.2: the same change is possible from code and from the UI, with the same authorisation and the same
  audit trail.
