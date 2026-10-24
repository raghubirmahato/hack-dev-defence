# J-18 Analyst investigates an attack

Checklist for the flow `j-18-investigate-attack` (T-0022 A2).
Screens: S-064, S-065, S-066, S-067.
Journey: [J-18](../journeys/J-18.md). Strategy: [ACCESSIBILITY.md](../ACCESSIBILITY.md).

## Keyboard path

1. On S-065, Tab reaches the filter field and the filter list; Enter applies a category.
2. Tab enters the event rows; the count updates and is announced politely.
3. Enter opens S-066. Tab moves through the evidence rows.
4. Tab reaches the ban button; Enter opens the ban form.
5. In the ban form, Tab reaches the TTL choice and the self-ban guard result.
6. Enter confirms the ban; focus moves to the ban list and the new entry.
7. On S-067, Tab reaches the unban button; the audit record follows it in the reading order.
8. Tab reaches the exception button; the preview is read before the save.

## Screen-reader script

Run with NVDA on Firefox, VoiceOver on Safari and JAWS if available on Chrome.

| Step | Screen | Expected announcement |
| --- | --- | --- |
| 1 | S-065 | The active filter, the count and the time window. |
| 2 | S-065 | The new event count after the filter applies. |
| 3 | S-066 | The rule, the policy branch and the redacted bytes. |
| 4 | S-067 | The ban TTL, the scope and the self-ban guard result. |
| 5 | S-067 | The release time and the audit record after an unban. |
| 6 | S-064 | The exception scope and the expiry. |

## Failure criteria

- Critical: a ban cannot be placed or released with the keyboard.
- Serious: the self-ban guard warning is not announced before the confirm.
- Serious: the event count changes without a live-region announcement.
- Moderate: the Ray ID copy button has no feedback.
- Minor: the evidence row labels repeat the same word.

## Human step

Owner: human_step_pending — the operator runs the investigation script.

1. Investigate a test event and place a short-TTL ban with NVDA; release it with VoiceOver.
2. Record what the guard announced and whether the ban list update was read.
3. Save the record under `acceptance-ui/a11y-manual/` and tell the Lead the result.
