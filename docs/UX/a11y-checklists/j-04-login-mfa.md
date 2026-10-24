# J-04 Returning user logs in

Checklist for the flow `j-04-login-mfa` (T-0022 A2).
Screens: S-023, S-024, S-026, S-034, S-040.
Journey: [J-04](../journeys/J-04.md). Strategy: [ACCESSIBILITY.md](../ACCESSIBILITY.md).

## Keyboard path

1. On S-023, Tab reaches the email field, the password field and the show-password toggle.
2. Enter submits; on failure focus lands in the error summary, not on the page top.
3. On S-024, the six-digit field receives focus. Paste a code with Ctrl+V.
4. Tab reaches the recovery-code link and the passkey option; Esc closes the passkey dialog.
5. On S-026, Enter accepts the device prompt; Esc cancels it and returns focus.
6. On S-034, Tab reaches the reset link; the retry time is readable without focus.
7. On S-040, Tab enters the main region and the domain list.

## Screen-reader script

Run with NVDA on Firefox and VoiceOver on Safari; JAWS if available on Chrome.

| Step | Screen | Expected announcement |
| --- | --- | --- |
| 1 | S-023 | The login heading and both field labels. |
| 2 | S-023 | The neutral error text for a wrong credential. |
| 3 | S-024 | The code field label, the paste hint and the retry time. |
| 4 | S-026 | The device name and the cancel action. |
| 5 | S-034 | The lockout heading and the wait time. |
| 6 | S-040 | The organisation name and the overview heading. |

## Failure criteria

- Critical: the code field refuses paste or keyboard entry.
- Serious: the passkey dialog traps focus after Esc.
- Serious: the error text reveals whether the address exists.
- Moderate: the retry time is shown only as colour.
- Minor: the show-password toggle has no pressed state.

## Human step

Owner: human_step_pending — the operator runs the login script.

1. Run the script with NVDA and VoiceOver, including one wrong code and one paste attempt.
2. Note the reader version and the browser, and record each row as pass or issue.
3. Store the record under `acceptance-ui/a11y-manual/` and tell the Lead which rows remain open.
