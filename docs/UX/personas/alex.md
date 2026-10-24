# Alex, the agency manager

**Fictional composite.** Alex is not a real person and stands for no single customer: Alex is a composite of the agency
managers described in spec [B1.6](../../SPEC.md#b16-alex-the-agency-manager). Their scenarios are design inputs, not
measured results; a measurable outcome below names a real test, audit event or metric.

They are not the pilot's assumed primary persona (that is Maya until the
[primary-persona question](../../OPERATOR-QUESTIONS.md#primary-persona-for-the-pilot-added-by-t-0012) is answered), but the
multi-tenant screens are not done if only a single-site owner can use them. The [UX charter](../CHARTER.md) applies to
every screen they use.

## Context of use

| Aspect | Detail |
| --- | --- |
| Device | Laptop with many browser tabs; reviews client accounts in batches. |
| Connectivity | Office network; a client site may be slow while their domain is being changed. |
| Interruptions | Client calls and context switches; work moves between organizations several times a day. |
| Vocabulary | Organizations, members, roles, client names, reports and invoices; not rule ids or policy branches. |
| First check of the day | The domains list across clients, then any client with an alert or an unfinished onboarding. |

## Scenarios

### 1. Move between client accounts without leaking context

When I manage several clients, I want to use an organization switcher that lists only my memberships and remembers the last one,
so I can move between clients without losing my place or seeing another client's data.

Measurable outcome: AC-36 (tenant isolation, RLS and BOLA) and AC-35 (identity end to end) pass; the switcher offers only
organizations where the session holds a membership.

### 2. Apply one preset across several client domains

When several client domains need the same preset, I want to apply a bulk change with a preview of every target, so I can
apply the preset without risking the wrong client.

Measurable outcome: AC-37 (onboarding in every integration mode) and AC-13 (modes, safe mode and rollback) pass; each
affected domain writes `AUD-domain.updated`, and the preview lists every target before the change.

### 3. Report to a client from real events

When a client asks what was blocked last month, I want to generate a per-client report for a stated period, exported to a file, so I
can send it without copy-pasting numbers.

Measurable outcome: AC-47 (audit log, export and deletion) and AC-52 (analytics correctness) pass; `AUD-report.run` and
`AUD-export.events` record the run and the export.

## Anti-goals

- Seeing another client's data, or being one click away from it.
- A bulk action without a preview of every target.
- A role model that cannot be scoped per client.
- Reports that mix tenants or invent numbers (R-16).
- A plan or seat model that hides security controls from some members (R-28).

## Accessibility

B1.6 names no accessibility needs for Alex, so these are derived from their duties and are the design assumption, not a
quotation: switching and bulk actions must be operable by keyboard, and client status must not be conveyed by colour
alone. Mapped to the
[B11.11](../../SPEC.md#b1111-accessibility-contract-summary-of-wcag-22-aa-obligations-the-components-encode) criteria:
2.1.1 (all functionality by keyboard), 2.4.7 (visible focus through the switcher and the domain list), 3.3.4 (bulk and
destructive actions are reversible or confirmed), 1.4.3 (contrast), and 1.3.x (semantic structure of grouped domain
lists).

Assistive technology assumptions: 200% zoom and a keyboard; a screen reader used occasionally on lists; no pointer-only
bulk selection.

## Journeys and screens

- Journeys: [J-26](../../SPEC.md#j-26-owner-invites-teammates-and-assigns-roles) and
  [J-28](../../SPEC.md#j-28-owner-exports-reports-and-audit-logs).
- Screens: [S-040](../../SPEC.md#b121-screen-table) Organization overview,
  [S-041](../../SPEC.md#b121-screen-table) Domains,
  [S-073](../../SPEC.md#b121-screen-table) Reports,
  [S-074](../../SPEC.md#b121-screen-table) Report builder and schedule,
  [S-081](../../SPEC.md#b121-screen-table) Team members,
  [S-083](../../SPEC.md#b121-screen-table) Roles and permissions,
  [S-084](../../SPEC.md#b121-screen-table) Audit log,
  [S-086](../../SPEC.md#b121-screen-table) Organization settings,
  [S-091](../../SPEC.md#b121-screen-table) Command palette and search and
  [S-094](../../SPEC.md#b121-screen-table) Decommission domain.
- Success, from B1.6: each client stays separated, bulk work is visible before it is applied, and the per-client report is
  built from that client's events only.
