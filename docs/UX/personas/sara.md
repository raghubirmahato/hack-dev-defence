# Sara, the security analyst

**Fictional composite.** Sara is not a real person and stands for no single customer: she is a composite of the security
analysts described in spec [B1.3](../../SPEC.md#b13-sara-the-security-analyst). Her scenarios are design inputs, not
evidence; a measurable outcome below names a real test, audit event or metric.

She is not the pilot's assumed primary persona (that is Maya until the
[primary-persona question](../../OPERATOR-QUESTIONS.md#primary-persona-for-the-pilot-added-by-t-0012) is answered), but no
screen is done if only Maya can use it. The [UX charter](../CHARTER.md) applies to every screen she uses.

## Context of use

| Aspect | Detail |
| --- | --- |
| Device | A large monitor and a keyboard; sometimes a second screen for the incident channel. |
| Connectivity | Office network, sometimes a VDI session with lag; the screen must stay usable when data arrives slowly. |
| Interruptions | Alerts, management requests and incidents interrupt triage; her filters and place must survive. |
| Vocabulary | Rule ids, policy branch, ATK categories, CWE, ASN, Ray ID; she expects the same words in the UI and the docs. |
| First check of the day | The live threat monitor and the would-block count, then the ban list and the appeals inbox. |

## Scenarios

### 1. Triage a spike and decide in one screen

When the alert fires and the dashboard shows elevated attacks, I want to filter by category and open one event with its
evidence, so I can decide quickly whether it is an attack or a false positive.

Measurable outcome: AC-07 (detection matrix) and AC-08 (ban persistence, enforcement and unban) pass;
`MET-hdd_waf_blocks_total` and `MET-hdd_waf_would_block_total` carry the category and vector the screen shows.

### 2. Ban an attacker without taking out a shared address

When one source is clearly attacking, I want to see a ban whose reason, rule and TTL step are visible and whose release path is
one click, so I can contain the attack without guessing whether a shared address will be hit.

Measurable outcome: AC-08 and AC-43 (appeals) pass; `AUD-ban.created` and `AUD-ban.released` record both actions, and the
ban explains itself as rule R-24 requires.

### 3. Report to management from real events

When the week ends, I want to produce a report built from real events with stated periods and gaps, so I can explain what was
blocked and what was not covered without inventing a number.

Measurable outcome: AC-47 (audit log, data export and deletion) and AC-52 (analytics correctness) pass;
`AUD-report.run` and `AUD-export.events` record the run and the export.

## Anti-goals

- Alert fatigue: a screen that says "many attacks" without the rule, path or evidence.
- A rule change that silently opens a hole.
- A ban with no visible reason and no appeal path.
- Color as the only signal in a dense table.
- Evidence that a screen reader cannot read, or a table that collapses under zoom.

## Accessibility

B1.3 names Sara's needs: dense data tables with a density control, screen-reader-friendly table semantics, and colour
never the only signal. Mapped to the
[B11.11](../../SPEC.md#b1111-accessibility-contract-summary-of-wcag-22-aa-obligations-the-components-encode) criteria:
1.3.x (semantic structure and reading order), 1.4.3 and 1.4.11 (contrast of text and control boundaries), 1.4.10 (data
tables are exempt, but each scrolls in one region), 2.1.1 (keyboard), 2.4.7 (visible focus) and 4.1.2 (names, roles and
values for sortable and expandable tables).

Assistive technology assumptions: NVDA or JAWS on tables, the high-contrast theme, a density control and keyboard
traversal of rows and filters.

## Journeys and screens

- Journeys: [J-16](../../SPEC.md#j-16-owner-enables-protection-in-monitor-mode-reviews-switches-to-block),
  [J-17](../../SPEC.md#j-17-owner-enables-the-vulnerable-origin-shield),
  [J-18](../../SPEC.md#j-18-analyst-investigates-an-attack),
  [J-19](../../SPEC.md#j-19-owner-builds-a-custom-rule),
  [J-23](../../SPEC.md#j-23-owner-handles-an-appeal) and
  [J-34](../../SPEC.md#j-34-incident-attack-spike).
- Screens: [S-054](../../SPEC.md#b121-screen-table) Security overview,
  [S-056](../../SPEC.md#b121-screen-table) Attack categories,
  [S-057](../../SPEC.md#s-057-vulnerable-origin-shield) Vulnerable-Origin Shield,
  [S-064](../../SPEC.md#b121-screen-table) Exceptions,
  [S-065](../../SPEC.md#s-065-live-threat-monitor) Live threat monitor,
  [S-066](../../SPEC.md#b121-screen-table) Event detail,
  [S-067](../../SPEC.md#s-067-ip-jail) IP jail,
  [S-068](../../SPEC.md#b121-screen-table) Ban detail,
  [S-069](../../SPEC.md#b121-screen-table) Appeals inbox,
  [S-073](../../SPEC.md#b121-screen-table) Reports and
  [S-134](../../SPEC.md#s-134-coverage-map) Coverage map.
- Success, from B1.3: an attack is seen live, pivoted by IP or path, and handled with a scoped decision that is written
  down, without a false positive becoming a support ticket.
