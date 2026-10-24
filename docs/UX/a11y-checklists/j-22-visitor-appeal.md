# J-22 Blocked visitor files an appeal

Checklist for the flow `j-22-visitor-appeal` (T-0022 A2).
Screens: S-140, S-145, S-146.
Journey: [J-22](../journeys/J-22.md). Strategy: [ACCESSIBILITY.md](../ACCESSIBILITY.md).

## Keyboard path

1. On S-140, Tab reaches the Ray ID copy button and the appeal link.
2. Enter opens S-145; the prefilled Ray ID is read with the field.
3. Tab moves through the contact field and the note field.
4. Tab reaches the submit button; it stays disabled while the proof-of-work runs.
5. The proof-of-work state is text, not a spinner alone. The submit button enables when it finishes.
6. Enter submits; focus moves to the receipt heading on S-146.
7. Tab reaches the status link and the reference copy button.

## Screen-reader script

Run with TalkBack on Chrome and VoiceOver on Safari, because most blocked visitors arrive on a phone.

| Step | Screen | Expected announcement |
| --- | --- | --- |
| 1 | S-140 | The reason class, the Ray ID and the appeal link. |
| 2 | S-145 | The prefilled Ray ID and the contact field label. |
| 3 | S-145 | The proof-of-work progress as text. |
| 4 | S-146 | The receipt heading, the reference and the decision window. |
| 5 | S-146 | The status link and the current appeal state. |

## Failure criteria

- Critical: the appeal form cannot be submitted with the keyboard.
- Serious: the proof-of-work state has no text alternative.
- Serious: the receipt does not take focus after submit.
- Moderate: the note field has no visible length hint.
- Minor: the Ray ID copy button gives no copied feedback.

## Human step

Owner: human_step_pending — the operator runs the appeal script.

1. Run the appeal path on a phone with TalkBack, including a failed proof-of-work and a retry.
2. Record whether the progress text and the receipt were announced.
3. Save the note under `acceptance-ui/a11y-manual/` and report the outcome to the Lead.
