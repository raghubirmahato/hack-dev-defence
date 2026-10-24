# J-14 Owner edits DNS and toggles orange/grey

Checklist for the flow `j-14-dns-edit-proxy-toggle` (T-0022 A2).
Screens: S-045, S-046, S-048.
Journey: [J-14](../journeys/J-14.md). Strategy: [ACCESSIBILITY.md](../ACCESSIBILITY.md).

## Keyboard path

1. On S-045, Tab enters the table; the header buttons sort with Enter and announce the sort state.
2. Tab reaches the first record row and its edit button. Enter opens S-046.
3. On S-046, Tab moves through the type fields and the preview region.
4. Tab to the proxy toggle; Space changes it and the consequence text is read before the save.
5. Enter saves; focus returns to the edited row and its new value.
6. Tab reaches the history link. On S-048, Tab moves through the change rows.
7. On S-048, the undo button is reachable and names the restored value.

## Screen-reader script

Run with NVDA on Firefox and VoiceOver on Safari; JAWS if available covers the table header buttons.

| Step | Screen | Expected announcement |
| --- | --- | --- |
| 1 | S-045 | The zone name, the record count and the table caption. |
| 2 | S-045 | The sort state of the focused column header. |
| 3 | S-046 | The record type and the value field label. |
| 4 | S-046 | The proxy consequence text before the toggle applies. |
| 5 | S-048 | The previous value and the new value for the entry. |
| 6 | S-048 | The undo action and the value it restores. |

## Failure criteria

- Critical: the record table cannot be entered with the keyboard.
- Serious: the proxy consequence text is skipped before the change applies.
- Serious: the sort state is not announced on the header button.
- Moderate: the preview does not update after a value edit.
- Minor: the history rows omit the timestamp in text.

## Human step

Owner: human_step_pending — the operator runs the DNS edit script.

1. Edit a test record and toggle its proxy state with NVDA; do not save against a live zone.
2. Note whether the consequence text was read before the save, and record each row.
3. Save the record under `acceptance-ui/a11y-manual/` and report the outcome to the Lead.
