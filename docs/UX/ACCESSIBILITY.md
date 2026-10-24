# Accessibility strategy and test plan

Status: draft for T-0022 (`REQ-UXR-12`), reviewed at the T-0028 review pack. The stored criterion list is
[wcag22-criteria.toml](wcag22-criteria.toml); the per-flow checklists are in
[a11y-checklists/](a11y-checklists/j-02-signup-verify-email.md). This plan defines what is checked; the harness is
T-0091 and the product-wide acceptance is T-0502.

## Scope and status

This plan covers the product surfaces of the B12.1 screen table, the public pages, the HTML emails and the report
and audit exports. It does not cover the operator's terminal, the docs site theme or third-party pages.

The automated harness (T-0091) is not built yet. The contrast token command is a stub until T-0030, and the product
screens are prototypes (T-0069) or are not built. Every check below therefore states its current state: `live`,
`planned` with its task, or `human_step_pending`. No row claims a result that has not run.

The scope is WCAG 2.2 level A and AA, which is the AC-40 gate. Level AAA criteria are out of scope; where a component
already meets one (for example 2.5.5 Target Size (Enhanced) through the 40 px default control height in B11.4), this
plan does not count it toward the gate.

## Critical flows

The specification names 12 critical flows (B11.11, T-0069 step 3, T-0502 step 3) but does not list them. The selection
below is the design's own and is recorded here for the Lead and T-0502 to amend. The basis: every area named by T-0502
step 3 is covered (signup, login with MFA, the add-domain wizard, DNS edit, the rule builder, ban and unban, appeals,
the report builder and the admin flows), plus the monitor-to-block switch and the incident flow, where a failure has
the largest cost. The remaining journeys stay in scope for the T-0502 keyboard traversal of J-01 to J-34 and for the
per-screen axe run, but they do not get a dedicated screen-reader checklist.

| Flow id | Flow name | Checklist slug | Why critical |
| --- | --- | --- | --- |
| J-02 | Visitor signs up and verifies email | j-02-signup-verify-email | A failure stops every later journey; the form has the most error states. |
| J-04 | Returning user logs in | j-04-login-mfa | The MFA and passkey steps are the account gate and a common assistive-technology path. |
| J-08 | Owner adds a domain using full nameserver delegation | j-08-add-domain-nameservers | The wizard changes live DNS and has a copy step that screen readers must announce. |
| J-14 | Owner edits DNS and toggles orange/grey | j-14-dns-edit-proxy-toggle | The proxy toggle changes mail and traffic; the table and the preview must stay operable. |
| J-16 | Owner enables protection in monitor mode, reviews, switches to block | j-16-monitor-to-block | The switch from monitor to block changes what visitors receive. |
| J-18 | Analyst investigates an attack | j-18-investigate-attack | The live feed and the ban dialog are used under time pressure. |
| J-19 | Owner builds a custom rule | j-19-custom-rule-builder | The rule builder has reorder controls and a dry run that must not depend on dragging. |
| J-22 | Blocked visitor files an appeal | j-22-visitor-appeal | A blocked visitor may use a phone and a screen reader, often for the first time. |
| J-23 | Owner handles an appeal | j-23-appeal-triage | The decision dialog is a destructive action with four outcomes. |
| J-28 | Owner exports reports and audit logs | j-28-report-export | The report builder and the audit export are long forms with a hash-chain indicator. |
| J-29 | Platform admin onboards and manages tenants | j-29-tenant-management | Admin actions include suspension and deletion with typed confirmation. |
| J-34 | Incident: attack spike | j-34-incident-spike | The under-attack control is time-critical and uses a typed confirmation. |

## Criterion mapping

This table extends the B11.11 accessibility contract from a component summary to every WCAG 2.2 level A and AA
criterion. Each row names the component that owns the behaviour, a page pattern for a requirement a single component
cannot own, or `not applicable` with the reason the failure mode cannot occur. The ids, levels and titles come from
[wcag22-criteria.toml](wcag22-criteria.toml), which is transcribed from the W3C WCAG 2.2 Recommendation.

| Criterion | Level | Title | Owner |
| --- | --- | --- | --- |
| 1.1.1 | A | Non-text Content | Avatar; Badge / StatusDot / SeverityPill; ChartKit; WorldMap |
| 1.2.1 | A | Audio-only and Video-only (Prerecorded) | not applicable: HDD ships no audio-only or video-only media |
| 1.2.2 | A | Captions (Prerecorded) | not applicable: HDD ships no prerecorded media with audio |
| 1.2.3 | A | Audio Description or Media Alternative (Prerecorded) | not applicable: HDD ships no prerecorded video |
| 1.2.4 | AA | Captions (Live) | not applicable: HDD ships no live audio or video |
| 1.2.5 | AA | Audio Description (Prerecorded) | not applicable: HDD ships no prerecorded video |
| 1.3.1 | A | Info and Relationships | DataTable; KeyValueList; FormField / ErrorSummary; Timeline |
| 1.3.2 | A | Meaningful Sequence | page pattern: Page frame |
| 1.3.3 | A | Sensory Characteristics | page pattern: Plain-language instructions |
| 1.3.4 | AA | Orientation | page pattern: Responsive layout |
| 1.3.5 | AA | Identify Input Purpose | TextInput / Textarea; PasswordInput; OTPInput |
| 1.4.1 | A | Use of Color | Badge / StatusDot / SeverityPill; CloudToggle; DiffViewer |
| 1.4.2 | A | Audio Control | not applicable: HDD plays no audio automatically |
| 1.4.3 | AA | Contrast (Minimum) | page pattern: Colour tokens |
| 1.4.4 | AA | Resize Text | page pattern: Reflow and text resize |
| 1.4.5 | AA | Images of Text | not applicable: HDD uses no image-of-text assets |
| 1.4.10 | AA | Reflow | page pattern: Reflow and text resize |
| 1.4.11 | AA | Non-text Contrast | page pattern: Colour tokens |
| 1.4.12 | AA | Text Spacing | page pattern: Reflow and text resize |
| 1.4.13 | AA | Content on Hover or Focus | Tooltip / Popover |
| 2.1.1 | A | Keyboard | Button / IconButton; Menu / Dropdown; Tabs; Stepper / Wizard |
| 2.1.2 | A | No Keyboard Trap | Modal / Drawer / ConfirmDialog |
| 2.1.4 | A | Character Key Shortcuts | CommandPalette; Kbd |
| 2.2.1 | A | Timing Adjustable | page pattern: Session and time limits |
| 2.2.2 | A | Pause, Stop, Hide | LiveFeed (SSE); Skeleton / Spinner / ProgressBar |
| 2.3.1 | A | Three Flashes or Below Threshold | not applicable: HDD has no flashing content |
| 2.4.1 | A | Bypass Blocks | page pattern: App frame landmarks |
| 2.4.2 | A | Page Titled | page pattern: Page frame |
| 2.4.3 | A | Focus Order | Modal / Drawer / ConfirmDialog; Tabs; Menu / Dropdown |
| 2.4.4 | A | Link Purpose (In Context) | Link; Breadcrumbs |
| 2.4.5 | AA | Multiple Ways | CommandPalette; Breadcrumbs; Pagination |
| 2.4.6 | AA | Headings and Labels | FormField / ErrorSummary; DataTable; Modal / Drawer / ConfirmDialog |
| 2.4.7 | AA | Focus Visible | page pattern: Focus ring |
| 2.4.11 | AA | Focus Not Obscured (Minimum) | Banner / Alert; Toast; Modal / Drawer / ConfirmDialog |
| 2.5.1 | A | Pointer Gestures | not applicable: HDD uses no multipoint or path gestures |
| 2.5.2 | A | Pointer Cancellation | Button / IconButton |
| 2.5.3 | A | Label in Name | Button / IconButton; TextInput / Textarea |
| 2.5.4 | A | Motion Actuation | not applicable: HDD offers no device-motion operations |
| 2.5.7 | AA | Dragging Movements | RuleBuilder |
| 2.5.8 | AA | Target Size (Minimum) | page pattern: Target size tokens |
| 3.1.1 | A | Language of Page | page pattern: Locale and language |
| 3.1.2 | AA | Language of Parts | MarkdownRender; ThemeToggle / LocaleSwitcher / DensityToggle |
| 3.2.1 | A | On Focus | Menu / Dropdown; Select / Combobox / MultiSelect |
| 3.2.2 | A | On Input | Select / Combobox / MultiSelect; Checkbox / Radio / Switch |
| 3.2.3 | AA | Consistent Navigation | page pattern: App frame landmarks |
| 3.2.4 | AA | Consistent Identification | page pattern: Component inventory |
| 3.2.6 | A | Consistent Help | page pattern: Help placement |
| 3.3.1 | A | Error Identification | FormField / ErrorSummary; TextInput / Textarea |
| 3.3.2 | A | Labels or Instructions | FormField / ErrorSummary; TextInput / Textarea; TagInput |
| 3.3.3 | AA | Error Suggestion | FormField / ErrorSummary; PasswordInput |
| 3.3.4 | AA | Error Prevention (Legal, Financial, Data) | Modal / Drawer / ConfirmDialog; Toast |
| 3.3.7 | A | Redundant Entry | Stepper / Wizard |
| 3.3.8 | AA | Accessible Authentication (Minimum) | PasswordInput; OTPInput |
| 4.1.2 | A | Name, Role, Value | Button / IconButton; Checkbox / Radio / Switch; Select / Combobox / MultiSelect |
| 4.1.3 | AA | Status Messages | Toast; Banner / Alert; LiveFeed (SSE) |

### Page patterns

A page pattern is a rule of the page frame or the token set that no single component owns. Each pattern names the
components that carry it, so the mapping still points into the B11.8 inventory.

| Pattern | What it encodes | Components |
| --- | --- | --- |
| Page frame | The document title, the page language and the reading order of the page. | Breadcrumbs; Link; MarkdownRender |
| App frame landmarks | The skip link and the banner, navigation, main, complementary and contentinfo landmarks. | Link; Breadcrumbs; CommandPalette |
| Colour tokens | The B11.2 token pairs and the 4.5:1 body and 3:1 large-text and control targets. | Button / IconButton; Link; TextInput / Textarea; Checkbox / Radio / Switch |
| Reflow and text resize | The rem type scale, 200% text resize, 320 px reflow and the 1.4.12 text-spacing overrides. | DataTable; KeyValueList; Card / StatCard |
| Responsive layout | The B11.7 breakpoints, the drawer below 1024 px and the table-to-card rule below 640 px. | DataTable; Tabs; Menu / Dropdown |
| Focus ring | The B11.2 focus token, the 2 px ring with a 2 px offset and the scroll-padding rule. | Button / IconButton; Link; TextInput / Textarea; Menu / Dropdown |
| Target size tokens | The B11.4 control heights and the 24 px minimum target. | Button / IconButton; Checkbox / Radio / Switch; Pagination |
| Session and time limits | Session timeouts, resend cooldowns and the time-boxed controls. | CountdownBadge; Modal / Drawer / ConfirmDialog; Toast |
| Locale and language | The page language, the locale switcher and the language of a part. | ThemeToggle / LocaleSwitcher / DensityToggle; MarkdownRender |
| Plain-language instructions | The B11.12 wording rules and the error guidance in text. | FormField / ErrorSummary; Banner / Alert; Tooltip / Popover |
| Help placement | The consistent help link and the contextual help rows. | Link; Tooltip / Popover |
| Component inventory | The shared component contracts that keep identification consistent. | Button / IconButton; Link; Badge / StatusDot / SeverityPill |

## Assistive technology and browser matrix

The matrix is run for both themes and for every state a screen defines. A combination that has not run is recorded as
`UNVERIFIED(human_step_pending)`, never assumed.

| Modality | Coverage | How verified | Owner |
| --- | --- | --- | --- |
| Chromium-based | current and previous stable release | axe-core and CDP tests (T-0091) | qa |
| Firefox | current and previous stable release | keyboard walkthrough and axe on a sample of screens | qa |
| Safari | current stable release on macOS and iOS | keyboard walkthrough and VoiceOver | ux |
| NVDA | current stable release on Windows, Chrome and Firefox | screen-reader checklist, `human_step_pending` | ux |
| JAWS | if available: current stable release on Windows, Chrome | screen-reader checklist, `human_step_pending` | ux |
| VoiceOver | current macOS and iOS release, Safari | screen-reader checklist, `human_step_pending` | ux |
| TalkBack | current Android release, Chrome | screen-reader checklist, `human_step_pending` | ux |
| Keyboard only | every critical flow and every admin action | recorded walkthrough with the focus order | ux |
| 200% zoom | every screen, both themes | CDP emulation plus a person reading the result | qa |
| 400% zoom | every screen, both themes | CDP emulation plus a person reading the result | qa |
| High contrast | Windows high contrast themes, both product themes | manual pass on every surface category | ux |
| Forced colors | `forced-colors: active` emulation | automated emulation (T-0091 step 5) | qa |
| Reduced motion | `prefers-reduced-motion: reduce` | automated computed-duration check (T-0091 step 6) | qa |

## Automated checks

The vendored axe-core oracle runs in the CDP browser tests for every screen, state, theme and viewport (T-0091 step
1). It uses the WCAG 2.2 A and AA tags and the best-practice tag, and it stores JSON with impact, node selectors and
the local help text. The pass rule is zero serious or critical violations; every other violation is listed with an
owner in the review record.

The colour contrast token check reads the B11.2 pairs against the 4.5:1 body target and the 3:1 large-text, control
boundary and focus-ring targets. `cargo xtask contrast-check` is a stub until T-0030, so this check is defined here and
runs with that task; until then the token table is reviewed by a person and the stubbed state is stated in the gate
report.

The heading structure check requires exactly one h1 per page, no skipped heading level and a heading that names the
section it starts. The landmark check requires banner, navigation, main, complementary and contentinfo, a labelled
navigation and the skip link as the first focusable element. The form-label check requires a visible label or an
accessible name for every control, no placeholder used as a label, and a label-in-name match. The focus-order
recording presses Tab and Shift+Tab, records the accessible name of every stop and compares the order with the DOM; a
trap, an invisible focus ring or a broken skip link fails it.

Reduced motion, forced colors, high contrast, the 1.4.12 text-spacing overrides and the 24 px target size are recorded
by the same run (T-0091 steps 3 to 7).

## Manual checks

A keyboard walkthrough script exists for each of the 12 critical flows. The script lives in the flow's checklist file
and is run by a person on the real screen, because the recorded Tab order alone cannot show whether the order makes
sense.

The 12 screen-reader checklists in [a11y-checklists/](a11y-checklists/j-02-signup-verify-email.md) pair each flow with
NVDA, JAWS (if available), VoiceOver and TalkBack. Each row states the expected announcement for the focus target, so a
tester can mark a pass or an issue without inventing a criterion.

The zoom checks run at 200% and 400% and record clipping, overlap and lost controls. The reflow check runs at 320 CSS
pixels wide and permits two-dimensional scrolling only inside a data-table region that has keyboard access and a
visible scroll hint. The text-spacing check injects the 1.4.12 overrides and looks for clipped text. High contrast,
forced colors and reduced motion are also checked by a person on every surface category, beside the automated
emulation.

### Checklist screen coverage

Each checklist agrees with the journey it tests. Its `Screens:` line lists the screens it exercises, and every one of
them must be a screen of the journey's `## Steps` table. A screen the checklist exercises that the journey does not
list is named on an `Outside the journey: S-nnn - <reason>` line, and a journey screen the checklist does not
exercise is named on a `Screens not covered: S-nnn - <reason>` line; both lines need a reason. The check reads the
journey maps in [journeys/](journeys/J-02.md) and reports a disagreement, so a checklist cannot silently skip a screen
or borrow one from another flow.

## Severity and gate rule

The four severities are the ones the design review uses (T-0069 step 7). A fixed scheme keeps the gate decision out of
a discussion about wording, so the scheme is a function of four inputs rather than a judgement in prose: whether a
WCAG 2.2 A or AA criterion failed, whether a critical flow is blocked, whether a security control is unreachable, and
the axe impact. The precedence is evaluated in this order:

1. A security control is unreachable: Critical.
2. A critical flow cannot be finished: Critical.
3. A WCAG 2.2 A or AA criterion fails: Serious.
4. axe reports a serious or critical violation: Serious.
5. axe reports a moderate best-practice issue with no criterion failure: Moderate.
6. Otherwise the issue is Minor.

A WCAG 2.2 A or AA criterion failure is always Serious. That sentence is the precedence: a criterion failure is never
downgraded to Moderate because it sits outside the 12 flows or because an alternative exists. Moderate is limited to
best-practice issues with no criterion failure that block a non-critical task, so Serious and Moderate cannot overlap
and their gate effects cannot point in opposite directions. AC-40 draws the same line: a release needs zero serious or
critical axe violations, every journey keyboard-operable and the 320 px reflow and the 200% and 400% zoom checks
passing, and it allows `human_step_pending` only for the screen-reader runs.

| Severity | Definition | Gate effect |
| --- | --- | --- |
| Critical | A person cannot finish a critical flow, or a security control is unreachable. | Blocks the gate; fix before any further review. |
| Serious | A WCAG 2.2 A or AA criterion failure on any product surface, or an axe serious or critical violation. | Blocks the gate under AC-40. |
| Moderate | No criterion failure; an axe moderate best-practice issue blocks a non-critical task. | Does not block; needs an owner and a date and is listed in the known gaps. |
| Minor | A best-practice issue with no criterion failure and no blocked task. | Does not block; logged and may ship. |

### Severity examples

The example defects below are scenarios for the scheme, not recorded findings. The `ux-docs` check recomputes the
`Severity` cell from the four inputs and fails the document when a row disagrees, so this table is a test of the
precedence rather than a second statement of it. When a checklist's failure criterion names a lower severity than the
classifier returns, the classifier wins and the issue is recorded at the higher grade.

| Defect | Criterion failed | Critical flow blocked | Security control unreachable | axe impact | Severity |
| --- | --- | --- | --- | --- | --- |
| The MFA code field refuses paste in J-04. | yes | yes | no | serious | Critical |
| The under-attack control cannot be reached with the keyboard in J-34. | yes | yes | yes | critical | Critical |
| A DNS table header button does not expose its sort state in J-14. | yes | no | no | serious | Serious |
| Body text contrast is 3.9 to 1 on the sign-up form. | yes | no | no | serious | Serious |
| The audit filter panel skips a heading level in J-28. | yes | no | no | moderate | Serious |
| A toast covers the focused confirm button until it fades in J-16. | yes | no | no | moderate | Serious |
| A tenant detail landmark repeats its name, but the task still completes. | no | no | no | moderate | Moderate |
| The chart legend order differs although direct labels are present. | no | no | no | none | Minor |

The gate rule is explicit: any serious or critical issue blocks the gate. AC-40 is a release gate, and a serious issue
is never waived inside a screen review. R-17 draws the same line: a screen without keyboard operation is not done.

## Accessibility statement

This draft does not claim WCAG 2.2 conformance. It reports what the automated and manual checks have recorded, and
T-0502 uses it to write the public statement page. Where a check has not run, the text says so instead of stating a
pass.

The automated suite has not run against product screens: the screens are prototypes (T-0069) or are not built. The
manual screen-reader evidence is `human_step_pending` until the operator or a volunteer runs the 12 checklists. The
contrast token command is a stub until T-0030.

### Known gaps

| Gap | Impact | Status |
| --- | --- | --- |
| The screen-reader runs for the 12 critical flows have not been recorded. | Manual coverage of screen readers is unknown. | `human_step_pending` with the instructions under [Human steps](#human-steps). |
| JAWS needs a commercial licence this environment does not hold. | One Windows screen-reader combination is unrecorded. | `UNVERIFIED(human_step_pending)` until a licensed copy is used. |
| The contrast token check is a stub until T-0030. | Token pairs are verified by review, not by a command. | Planned with T-0030. |
| axe-core finds only part of WCAG 2.2. | Automated results cannot show conformance on their own. | The manual checks cover the rest. |
| No usability session with disabled participants has run. | Real-world task success is unmeasured. | Not scheduled; recorded as a gap. |
| The accessibility statement page has no screen id yet. | The public page cannot be built before T-0502. | T-0502 assigns the page id and the text. |

## Human steps

Owner: the operator, or a volunteer with the screen reader installed (`human_step_pending`).

When the agent cannot run a screen reader, the work is recorded as `human_step_pending` and the gate reports it as
unverified. The instructions are exact:

1. Choose a checklist in [a11y-checklists/](a11y-checklists/j-02-signup-verify-email.md); each file names its flow, screens and keyboard path.
2. Use the current stable release of the browser and of the screen reader, and write the exact versions in the record.
3. Run the keyboard path and the screen-reader script row by row; mark each row pass or issue.
4. Take a screenshot of the focus order for every issue, and record the severity from the scheme above.
5. Save the record as `acceptance-ui/a11y-manual/<flow-slug>-<at>-<YYYY-MM-DD>.md`, then tell the Lead so the gate report cites it.
6. Keep the flow `UNVERIFIED(human_step_pending)` until every row has a result, and never mark a row pass without a run.

If JAWS is not licensed, record that combination as `UNVERIFIED(human_step_pending)` and say which licence is missing.
Do not substitute a different screen reader and call the row passed.

## Regression strategy

The result for each screen, state, theme and viewport is stored per screen as JSON under `acceptance-ui/a11y/`. The
name is stable: `<screen>-<state>-<theme>-<viewport>.json`, for example `s-020-default-dark-1280.json`. The run id
lives in the directory that holds the results, never in a file name. `acceptance-ui/a11y-summary.json` aggregates the
latest result for the gate report.

The comparison reads the previous gate's result for the same stable name and reports added, removed and changed
rules. A new serious or critical violation fails the comparison even when the rest of the screen passes. The component
axe baselines arrive with T-0052, and the visual baselines arrive with T-0090; T-0022 owns the names and the storage
rule, and those tasks own the artifacts. A baseline update needs a reason and a reviewer note, and the old JSON is
never edited.
