# HDD experience measures

Status: v1, written for T-0011 (REQ-UXR-01). Part of the [UX charter](CHARTER.md); the decision that rules out outside
analytics is [UXD-003](decisions/UXD-003.md).

These measures tell us whether the UX works. They are measured inside the product, from data HDD already holds for its
own operation, and they are never sent to a third party (rule R-22: one egress path; no analytics script ships).

## Measures

| Measure | Definition | Data source | Privacy treatment |
| --- | --- | --- | --- |
| Time to first domain in monitor mode | Seconds from the creation of the account (the creation time of the user record) to the first `AUD-domain.activated` event whose mode is `monitor`. Reported as the median and the 90th percentile over a stated window. | The user record and audit log events already written for security reasons (`AUD-domain.created`, `AUD-domain.activated`); no extra tracking. | Timestamps and an organization id only; no page views, no IP address, no free text. Shown only as an aggregate for the installation's own operator; a window with fewer than 5 accounts shows "not enough data". |
| Completion rate of the add-domain wizard | Domains that reach `AUD-domain.activated` divided by domains that reach `AUD-domain.created`, per week, plus the step where the unfinished ones stopped. | A server-side counter of the wizard step stored on the domain record (the wizard is server-rendered, so no browser script is needed). | Step number and domain id only; no hostnames in the metric labels. Aggregates below 5 domains are not shown. |
| Support-worthy errors per 100 sessions | Responses carrying an `ERR-` code that the error catalog marks as needing help (internal faults, failed verification after retries, lockout warnings), divided by sessions, times 100. | The error catalog and the request log of the installation (local counters keyed by `ERR-` code). | Error code and count only; messages, user ids and request bodies are not stored in the metric (rule R-25). |
| False-positive appeal rate | Appeals that end `AUD-appeal.resolved` with outcome "released as false positive", divided by all bans issued in the period. Reported with the number of appeals, not only the ratio. | `AUD-ban.*` and `AUD-appeal.submitted` / `AUD-appeal.resolved` audit events. | Counts per rule and per period; no visitor addresses or evidence in the report (the evidence stays redacted, at most 512 bytes, rule R-25). |
| Time to unban | Seconds from `AUD-appeal.submitted` (or from the owner's unban request) to `AUD-ban.released`, median and 90th percentile; the effect time reuses `MET-hdd_unban_effect_seconds` and `MET-hdd_ban_propagation_seconds`. | Audit events and the existing ban propagation metrics. | Durations only; no addresses. |
| Accessibility defects open | Number of open defects against WCAG 2.2 AA recorded in the accessibility register, by severity, plus the age of the oldest. The target is zero open defects of severity "blocks a task" at release (AC-40). | The accessibility register in the repository (created with T-0022) and the results of the automated audits (AC-40). | Contains no user data: defects are about screens and components. |

## How each measure stays honest in a self-hosted product

- **Local counters, no third-party analytics.** Every number comes from the audit log, the error catalog, the request log
  or the repository. There is no script from another origin and no tracking cookie ([UXD-003](decisions/UXD-003.md)).
- **Small numbers are hidden, not rounded up.** A self-hosted installation may have one user. Where a measure would
  identify a person or rest on fewer than 5 cases, the screen says "not enough data" instead of printing a ratio.
- **Counts next to ratios.** A rate always shows its numerator and denominator, so a 100 percent over two events is not
  mistaken for a trend.
- **Stated window and definition.** Each figure shows its period and links to the definition above.
- **No target is claimed before it is measured.** These measures have no goal values yet. Goals are set after the
  first pilot with real data and recorded as a decision; until then the screens show the measured value only.
- **Only legitimately collectable measures reach operators.** T-0139 (overview KPIs) uses a measure only when the data
  above exists for the installation. A measure whose source is missing is shown as "not available", never as zero.

## What is not measured

We do not measure how long a person looks at a page, where the pointer goes, or which links are clicked. We do not link
sessions across sites. Satisfaction is collected only when the operator chooses to ask users, through their own
channel, and is not part of the product.
