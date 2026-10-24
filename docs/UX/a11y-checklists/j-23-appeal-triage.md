# J-23 Owner handles an appeal

Checklist for the flow `j-23-appeal-triage` (T-0022 A2).
Screens: S-069.
Journey: [J-23](../journeys/J-23.md). Strategy: [ACCESSIBILITY.md](../ACCESSIBILITY.md).

## Keyboard path

1. On S-069, Tab enters the appeal list and moves between the rows.
2. Enter opens the selected appeal; focus moves to the detail heading.
3. Tab reaches the evidence rows and the four decision buttons.
4. Enter on unban opens the confirmation; the release time and audit record are read first.
5. Enter on allowlist asks for the number of days; the expiry is shown before the save.
6. Enter on exception opens the preview with the scope and the expiry.
7. Enter on decline focuses the reason field; the visitor message is shown beside it.
8. After any decision, focus returns to the appeal row and its new state is read.

## Screen-reader script

Run with NVDA on Firefox and VoiceOver on Safari; JAWS if available covers the decision dialogs.

| Step | Screen | Expected announcement |
| --- | --- | --- |
| 1 | S-069 | The inbox heading and the open appeal count. |
| 2 | S-069 | The Ray ID, the note as text and the evidence rule. |
| 3 | S-069 | The unban confirmation, the release time and the audit record. |
| 4 | S-069 | The allowlist expiry after the number of days. |
| 5 | S-069 | The exception scope and expiry before the save. |
| 6 | S-069 | The reason field and the neutral visitor message. |

## Failure criteria

- Critical: a decision cannot be made with the keyboard.
- Serious: the decline reason field is not focused when the dialog opens.
- Serious: the audit record is not read after a decision.
- Moderate: the appeal count omits the open decisions total.
- Minor: the evidence rows repeat the rule name on every row.

## Human step

Owner: human_step_pending — the operator runs the appeal decision script.

1. Resolve one test appeal with each of the four outcomes using NVDA; use VoiceOver for the decline path.
2. Record what was read before each confirm and where focus returned.
3. Store the record under `acceptance-ui/a11y-manual/` and send the open rows to the Lead.
