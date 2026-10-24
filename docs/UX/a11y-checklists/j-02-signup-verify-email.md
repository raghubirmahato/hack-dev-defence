# J-02 Visitor signs up and verifies email

Checklist for the flow `j-02-signup-verify-email` (T-0022 A2).
Screens: S-020, S-021, S-022, S-035.
Journey: [J-02](../journeys/J-02.md). Strategy: [ACCESSIBILITY.md](../ACCESSIBILITY.md).

## Keyboard path

1. On S-020, press Tab from the browser chrome: the skip link is the first stop.
2. Tab to the email field and type an address. The label must be read with the field.
3. Shift+Tab returns to the skip link; Tab again reaches the name field.
4. Tab to the password field; the strength meter text updates without moving focus.
5. Tab to the terms checkbox, then to the submit button. Enter submits.
6. On S-021, Tab reaches the resend button and the change-email link.
7. On S-022, Tab reaches the confirm button, then the resend link. Enter confirms.

## Screen-reader script

Run with NVDA on Firefox, JAWS if available, VoiceOver on Safari and TalkBack on Chrome.

| Step | Screen | Expected announcement |
| --- | --- | --- |
| 1 | S-020 | The page heading and the skip link. |
| 2 | S-020 | The email label, its required state and the strength meter as text. |
| 3 | S-020 | The error summary after a failed submit, with a link to each field. |
| 4 | S-021 | The neutral heading and the resend button. |
| 5 | S-022 | The confirm button and the masked address. |
| 6 | S-035 | The wizard heading and the current step. |

## Failure criteria

- Critical: the confirm button cannot be reached with Tab.
- Serious: a field has no programmatic label.
- Serious: the error summary does not take focus after a failed submit.
- Moderate: the strength meter is announced only by colour.
- Minor: the skip link label does not name its target.

## Human step

Owner: human_step_pending — the operator runs the signup script.

1. Run the keyboard path with NVDA and with VoiceOver; note the browser and reader versions.
2. Record pass or issue for every row, and screenshot the focus order of each issue.
3. Save the note under `acceptance-ui/a11y-manual/` and report the outcome to the Lead.
