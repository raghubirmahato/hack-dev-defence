# J-34 Incident: attack spike

Checklist for the flow `j-34-incident-spike` (T-0022 A2).
Screens: S-054, S-065, S-067, S-093, S-064.
Journey: [J-34](../journeys/J-34.md). Strategy: [ACCESSIBILITY.md](../ACCESSIBILITY.md).

## Keyboard path

1. On S-054, Tab reaches the alert summary and the quick actions.
2. Tab to the live-monitor link. On S-065, Space pauses the feed and the count keeps rising.
3. Tab reaches the under-attack action. On S-093, the typed dialog takes focus.
4. Tab through the dialog: the challenge preview, the excluded clients and the typed field.
5. Enter confirms; the dialog closes and the end time is read.
6. Tab reaches the ban button. On S-067, the ban form reads the guard result first.
7. Tab reaches the exception form. On S-064, the scope and expiry are read before the save.
8. On de-escalation, Enter confirms and the calm window is read before the mode changes.

## Screen-reader script

Run with NVDA on Firefox and VoiceOver on Safari; JAWS if available covers the typed confirmation.

| Step | Screen | Expected announcement |
| --- | --- | --- |
| 1 | S-054 | The alert window and the attack count. |
| 2 | S-065 | The event count and the pause state. |
| 3 | S-093 | The under-attack dialog, the challenge and the end time. |
| 4 | S-067 | The collateral hint and the self-lockout result. |
| 5 | S-064 | The exception scope and the expiry. |
| 6 | S-054 | The calm window and the de-escalation state. |

## Failure criteria

- Critical: the under-attack mode cannot be enabled or stopped with the keyboard.
- Serious: the typed confirmation is skipped when the dialog opens.
- Serious: the live-feed pause state is announced only by colour.
- Moderate: the calm window has no next-check time in text.
- Minor: the incident timeline repeats the same timestamp format.

## Human step

Owner: human_step_pending — the operator runs the incident script.

1. Rehearse the under-attack dialog and the de-escalation with NVDA on a sandbox domain.
2. Record whether the challenge, the end time and the calm window were announced.
3. File the record under `acceptance-ui/a11y-manual/` and report the open rows to the Lead.
