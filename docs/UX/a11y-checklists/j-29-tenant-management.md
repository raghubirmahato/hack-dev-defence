# J-29 Platform admin onboards and manages tenants

Checklist for the flow `j-29-tenant-management` (T-0022 A2).
Screens: S-101, S-102.
Journey: [J-29](../journeys/J-29.md). Strategy: [ACCESSIBILITY.md](../ACCESSIBILITY.md).

## Keyboard path

1. On S-101, Tab reaches the search field and the filter list. Enter opens a tenant.
2. On S-102, Tab moves through the detail tabs; the arrow keys change the tab.
3. Tab reaches the plan change button; the step-up dialog takes focus.
4. In the suspend dialog, Tab reaches the reason field and the notice preview.
5. In the delete dialog, Tab reaches the typed tenant-name field; the confirm stays disabled until it matches.
6. Esc closes a dialog and returns focus to the action that opened it.
7. After a decision, the tenant row reads the new state and the audit row.

## Screen-reader script

Run with NVDA on Firefox and JAWS if available on Chrome; VoiceOver covers the tab list.

| Step | Screen | Expected announcement |
| --- | --- | --- |
| 1 | S-101 | The tenant count and the active filter. |
| 2 | S-102 | The organisation name, plan and status. |
| 3 | S-102 | The step-up dialog purpose and the plan difference. |
| 4 | S-102 | The suspension notice preview and the grace period. |
| 5 | S-102 | The typed-confirmation field and the delete consequence. |
| 6 | S-102 | The audit row for the decision and the actor. |

## Failure criteria

- Critical: the typed confirmation can be submitted with an empty field.
- Serious: the step-up dialog does not return focus after Esc.
- Serious: the tab list does not move with the arrow keys.
- Moderate: the plan difference is shown only in a chart.
- Minor: the tenant count omits the filter in text.

## Human step

Owner: human_step_pending — the operator runs the tenant script.

1. Walk the plan change and the suspend dialog with NVDA on a sandbox tenant; do not delete a tenant.
2. Record whether the typed confirmation and the notice preview were announced.
3. Keep the record under `acceptance-ui/a11y-manual/` and report the open rows to the Lead.
