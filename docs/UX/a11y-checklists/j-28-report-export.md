# J-28 Owner exports reports and audit logs

Checklist for the flow `j-28-report-export` (T-0022 A2).
Screens: S-073, S-074, S-084.
Journey: [J-28](../journeys/J-28.md). Strategy: [ACCESSIBILITY.md](../ACCESSIBILITY.md).

## Keyboard path

1. On S-073, Tab reaches the template list and the generate button.
2. Enter on a template opens S-074; focus moves to the period field.
3. Tab moves through the domains, sections and recipients controls.
4. Tab reaches the preview button; the preview is read as text, not an image.
5. Tab to the schedule choice and the save button. Enter saves the schedule.
6. On S-084, Tab moves through the filter fields and the export button.
7. Tab reaches the chain-verification indicator; its state is text next to the icon.

## Screen-reader script

Run with NVDA on Firefox and VoiceOver on Safari; JAWS if available covers the audit export.

| Step | Screen | Expected announcement |
| --- | --- | --- |
| 1 | S-073 | The report list, the template name and the last run. |
| 2 | S-074 | The period field and the selected domains. |
| 3 | S-074 | The sections list and the recipient field labels. |
| 4 | S-074 | The preview summary as text. |
| 5 | S-084 | The filter state and the export format. |
| 6 | S-084 | The chain-verification state as text. |

## Failure criteria

- Critical: an export cannot be started with the keyboard.
- Serious: the preview is an image with no text alternative.
- Serious: the chain state is conveyed by colour only.
- Moderate: the schedule has no summary before the save.
- Minor: the report run time lacks a `<time>` value.

## Human step

Owner: human_step_pending — the operator runs the report script.

1. Build and preview a report with NVDA, then export the audit log with VoiceOver.
2. Record whether the preview and the chain state were read as text.
3. Save the note under `acceptance-ui/a11y-manual/` and report the outcome to the Lead.
