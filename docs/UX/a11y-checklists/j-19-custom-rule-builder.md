# J-19 Owner builds a custom rule

Checklist for the flow `j-19-custom-rule-builder` (T-0022 A2).
Screens: S-058, S-059, S-060.
Journey: [J-19](../journeys/J-19.md). Strategy: [ACCESSIBILITY.md](../ACCESSIBILITY.md).

## Keyboard path

1. On S-059, Tab reaches the first condition field; the group label is read with it.
2. Tab moves through the field, the operator and the value controls.
3. Tab reaches the add-condition and remove-condition buttons.
4. Each condition row has move up and move down buttons; Enter reorders it. Dragging is never required.
5. Tab reaches the action choice; the consequence text is read before the save.
6. Tab to the test panel; Enter runs the sample test and reads the decision.
7. Tab to the dry-run button. On S-060, Tab moves through the candidate rows.
8. Tab to save; Enter names the revision. On S-058, the new rule is the first row.

## Screen-reader script

Run with NVDA on Firefox and VoiceOver on Safari; JAWS if available covers the condition rows.

| Step | Screen | Expected announcement |
| --- | --- | --- |
| 1 | S-059 | The builder heading and the empty condition group. |
| 2 | S-059 | The field, operator and value labels for the focused row. |
| 3 | S-059 | The row position after a move up or move down. |
| 4 | S-059 | The action consequence text, including the ban TTL. |
| 5 | S-060 | The replay window and the candidate count. |
| 6 | S-058 | The rule count and the new rule action. |

## Failure criteria

- Critical: a condition row cannot be reordered without a mouse.
- Serious: the group label is not programmatically linked to its rows.
- Serious: the test decision is announced only by colour.
- Moderate: the dry-run candidate count has no window in text.
- Minor: the move buttons are labelled only with an arrow icon.

## Human step

Owner: human_step_pending — the operator runs the rule builder script.

1. Build a three-row rule with NVDA, reorder rows with the move buttons, and run the sample test.
2. Record whether the row position and the test decision were announced.
3. Save the note under `acceptance-ui/a11y-manual/` and report the outcome to the Lead.
