# J-08 Owner adds a domain using full nameserver delegation

Checklist for the flow `j-08-add-domain-nameservers` (T-0022 A2).
Screens: S-041, S-042, S-043, S-099.
Journey: [J-08](../journeys/J-08.md). Strategy: [ACCESSIBILITY.md](../ACCESSIBILITY.md).

## Keyboard path

1. On S-041, Tab reaches the add-domain button. Enter opens the wizard.
2. On S-042, Tab moves through the domain field and the scan result list.
3. Tab reaches the nameserver choice; the arrow keys change the radio selection.
4. Tab to each copy button. Enter copies a value and announces the copied text.
5. Tab reaches the parity acknowledgement and the origin test button.
6. Tab to the protection preset, then to the go-live checklist.
7. On S-099, Tab moves through the resolver rows; each row states its result.
8. On S-043, Tab reaches the active state, the proxy state and the next action; the readiness score is text.

## Screen-reader script

Run with NVDA on Firefox and VoiceOver on Safari; a phone run with TalkBack covers the copy step.

| Step | Screen | Expected announcement |
| --- | --- | --- |
| 1 | S-042 | The wizard heading, the step number and the domain field. |
| 2 | S-042 | The scan summary and the record count. |
| 3 | S-042 | The nameserver choice and its consequence text. |
| 4 | S-042 | The copy button label and the copied confirmation. |
| 5 | S-042 | The parity diff and the acknowledgement state. |
| 6 | S-099 | The resolver name, its result and the check time. |
| 7 | S-043 | The active state, the proxy state and the readiness score as text. |

## Failure criteria

- Critical: a copy button cannot be reached or its value cannot be selected.
- Serious: the delegation poller announces nothing when the state changes.
- Serious: the parity diff is conveyed by colour only.
- Moderate: the step number is missing from the wizard heading.
- Minor: the scan result count is read without the record type.

## Human step

Owner: human_step_pending — the operator runs the nameserver script.

1. Run the wizard to the nameserver step with NVDA and with TalkBack; do not change real DNS.
2. Record what each copy button announces, and whether the poller change was announced.
3. Store the record under `acceptance-ui/a11y-manual/` and tell the Lead which rows are open.
