# J-16 Owner enables protection in monitor mode, reviews, switches to block

Checklist for the flow `j-16-monitor-to-block` (T-0022 A2).
Screens: S-054, S-055, S-064, S-065, S-066.
Journey: [J-16](../journeys/J-16.md). Strategy: [ACCESSIBILITY.md](../ACCESSIBILITY.md).

## Keyboard path

1. On S-054, Tab reaches the mode summary and the monitor sentence.
2. Tab to the mode choice; Enter changes the monitor state after the preview.
3. Tab reaches the live-monitor link. On S-065, the feed pauses with Space.
4. Tab moves through the event rows; Enter opens S-066.
5. On S-066, Tab moves through the evidence rows and the exception button.
6. Enter on the exception button opens S-064; the preview names the scope and the expiry.
7. Back on S-055, Tab reaches the schedule dialog. Esc closes it and returns focus.
8. Enter confirms the switch; the undo action is the next stop.

## Screen-reader script

Run with NVDA on Firefox and VoiceOver on Safari; JAWS if available covers the schedule dialog.

| Step | Screen | Expected announcement |
| --- | --- | --- |
| 1 | S-054 | The mode and the sentence that nothing is blocked yet. |
| 2 | S-054 | The would-block count and the example rule. |
| 3 | S-065 | The event count and the pause state. |
| 4 | S-066 | The matched rule, the branch and the redacted evidence. |
| 5 | S-064 | The exception scope and the expiry date. |
| 6 | S-055 | The consequences and the scheduled time. |

## Failure criteria

- Critical: the switch to block cannot be confirmed or undone from the keyboard.
- Serious: the dialog does not return focus after Esc.
- Serious: the pause state is announced only by icon colour.
- Moderate: the would-block count has no time window in text.
- Minor: the example event rule is read twice.

## Human step

Owner: human_step_pending — the operator runs the mode switch script.

1. Walk the monitor-to-block path on a test domain with NVDA, including the schedule dialog and the undo.
2. Record whether the consequences and the scheduled time were read before the confirm.
3. Write the record under `acceptance-ui/a11y-manual/` and send the open rows to the Lead.
