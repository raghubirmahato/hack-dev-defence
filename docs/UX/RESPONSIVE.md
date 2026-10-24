# Responsive and device strategy

Task T-0024. This document defines how every screen of B12.1 behaves from 360 px to 1920 px. The widths,
the control sizes and the transforms come from B11.4 (space and breakpoints), B11.7 (layout), B11.9
(interaction patterns) and B11.11 (accessibility contract); the screen ids come from B12.1. Accessibility
is the gate AC-40, and the print rules below carry the audit trail of AC-47. Nothing in this document is a
measurement: the numbers under Performance budgets are test budgets, and screenshots are captured by the
harness that T-0090 builds.

## Breakpoints

The layout stays fluid between the two boundaries: a window at 900 px uses the 768 px structure and
scales its gutters with the 4 px space scale of B11.4. Each row states what changes at that width and
which content moves.

| Breakpoint | Min width | Fluid behaviour |
| --- | --- | --- |
| 360 | 360 px | Base layout at the smallest supported width. Every function stays reachable and the page reflows without horizontal scrolling, except data tables inside their own scroll region (B11.11 1.4.4 and 1.4.10). |
| 480 | 480 px | The top bar shows the search field instead of only the search button. The domain tab strip still scrolls sideways and the breadcrumbs show two levels. |
| 768 | 768 px | Tablet portrait. The sidebar is an overlay drawer, the domain tabs wrap to a second row, the card grid has four columns and the page header stays on one line. |
| 1024 | 1024 px | Tablet landscape and above. The sidebar returns as a persistent column, the grid has twelve columns, reading pages show a sticky table of contents and most tables fit without sideways scrolling. |
| 1280 | 1280 px | App content reaches the 1280 px container maximum. Extra width becomes margin, so tables, charts and forms stop stretching. |
| 1536 | 1536 px | The app container is already at its 1280 px maximum, so the extra width becomes margin. The card grid keeps its 280 px auto-fit minimum and therefore its four cards, and a reading page stays at 1100 px. |

The app container is capped at 1280 px and a reading container at 1100 px, so a 1920 px display shows the
same line length with wider margins rather than longer lines. A dense table may use the full app container
width; a form or a prose column never does.

## Layout transformations

B11.7 changes one region at a time and no change removes a function. A region that folds away keeps its
control reachable elsewhere in the same width class.

| Region | Transformation | Width | Behaviour |
| --- | --- | --- | --- |
| Sidebar | The persistent column becomes a drawer, opened by the labelled menu button in the top bar | below 1024 px | The button keeps its accessible name, the drawer traps focus, Esc closes it and focus returns to the button. |
| Tables | A table becomes stacked key-value cards, but only where horizontal scrolling would hide primary data | below 640 px | Everywhere else the table stays a table inside a focusable horizontal scroll region with a visible scroll hint and arrow-key scrolling. |
| Wizards | Single column at every width, with one step per view | every width | The step list becomes progress text above the form, and Back and Next span the available width. |
| Page header | Secondary actions fold into a labelled menu | below 768 px | The title, the status pill and the primary action stay in the header; the menu is keyboard reachable. |
| Grid | Twelve columns become four and cards use auto-fit | below 1024 px | A card keeps a 280 px minimum, so a row wraps instead of shrinking the cards. |
| Reading pages | A 65ch column with a sticky table of contents | above 1024 px | Below that width the contents list moves under the title and the column takes the full width. |

## Device matrix

Seven viewports, each captured with both themes and both directions. The matrix is the input to the visual
regression pipeline of T-0090 and to the screenshot step of T-0047, and Testing hooks fixes the file names.
Rows three and four are the tablet pair; row four is also the landscape tablet capture, which A5 requires
alongside the landscape phone case under Input modalities.

| Viewport | Device class | Themes | Direction | What is verified |
| --- | --- | --- | --- | --- |
| 360x740 | Phone portrait, smallest supported | light, dark | LTR, pseudo-RTL | Reflow at the minimum width, the drawer, the one-column wizard and the bottom action bar. |
| 390x844 | Phone portrait, common mid-range | light, dark | LTR, pseudo-RTL | Touch targets, the live feed cards and the mirrored drawer edge. |
| 768x1024 | Tablet portrait | light, dark | LTR, pseudo-RTL | Overlay drawer, wrapped tabs, the four-column grid and a report preview in print. |
| 1024x768 | Tablet landscape | light, dark | LTR, pseudo-RTL | Persistent sidebar, twelve-column grid, tables in scroll regions and the landscape footer. |
| 1280x800 | Laptop | light, dark | LTR, pseudo-RTL | App content at its 1280 px maximum, table density and chart labels. |
| 1536x864 | Laptop, large | light, dark | LTR, pseudo-RTL | The container cap, the card grid and long-form reading at 1100 px. |
| 1920x1080 | Desktop | light, dark | LTR, pseudo-RTL | Extra width becomes margin, lines stay short and the page stays centred. |

## Input modalities

A pointer is optional. Every action has a keyboard path and a touch path (B11.11 2.1.x), and nothing depends
on hover (WCAG 1.4.13). Orientation is never locked: a landscape phone keeps the phone layout and a tablet
in either orientation uses the layout of its width. A landscape phone and a tablet are part of every
release check (A5).

| Modality | Requirement | Value |
| --- | --- | --- |
| Touch targets | The smallest accepted target, the WCAG 2.2 AA floor | 24 CSS px minimum, with at least 8 px between adjacent targets |
| Touch targets | The default control height | 40 px default |
| Touch targets | The control height on a touch device | 44 px on touch |
| Hover | Hover may add detail but never carries the only path | The same tooltip opens on focus and on tap and can be dismissed with Esc (WCAG 1.4.13) |
| Keyboard | Every action has a keyboard path in DOM order | Tab reaches every control, Enter or Space activates it, Escape closes an overlay and focus returns to the opener |
| Orientation | Portrait and landscape are both supported | Portrait and landscape both work; no orientation lock, so a landscape phone keeps the phone layout and moves the action bar to the bottom edge |

## Screen categories

Each category has one defined small-screen behaviour and names the real B12.1 screens it covers. A screen
can appear in more than one row, because one screen can use more than one pattern.

| Category | Small-screen behaviour | Screens |
| --- | --- | --- |
| Wizard | Single column, one step per view, progress text above the form, Back and Next at full width. | S-042, S-094, S-098 |
| Data table | Cards below 640 px only when scrolling would hide primary data; otherwise a focusable scroll region with a visible hint. | S-041, S-045, S-067 |
| Live feed | Simplified rows, one card per event on a phone, detail in the event drawer, pause control pinned and no automatic scrolling. | S-065, S-066 |
| Analytics chart | The server-rendered chart scales to the width, the text summary and the table toggle stay, and long labels rotate or drop to a second line. | S-043, S-054, S-070 |
| Settings form | Single column, labels above the field, a sticky save bar and inline validation. | S-055, S-086, S-092 |
| Admin table | Condensed columns with a details drawer, filters in a disclosure and no destructive action without its confirmation. | S-101, S-102, S-114 |
| Report page | The print layout comes first; the controls collapse under a Controls disclosure and the report body keeps its width. | S-073, S-074 |
| Empty state | A full-width honest message with one primary action, above the fold on the smallest phone. | S-041, S-065, S-067 |
| Public surface | One reading column at every width; code and tables scroll inside a focusable region on a phone. | S-001, S-003, S-014 |
| Authentication and onboarding | Single column with labels above the field and no horizontal scroll; the six-digit code field stays full width on a phone. | S-020, S-024, S-035 |
| Customer app: overview and domains | KPI cards stack two per row; the domain table becomes cards below 640 px and the mode control stays in the header. | S-040, S-041, S-043 |
| DNS, TLS, origin | The record table scrolls horizontally inside a focusable region on a phone and the record editor is one column. | S-045, S-050, S-052 |
| Security center | The mode banner and the emergency controls stay in the first screen; category matrices scroll inside a focusable region. | S-054, S-055, S-059 |
| Events, bans, appeals, analytics | The event list uses cards on a phone, the detail opens in a drawer, and the charts keep their text summary and table toggle. | S-065, S-067, S-069 |
| Reports, notifications, integrations, team | Tables condense to key columns with a details drawer and the team actions stay reachable without hover. | S-073, S-076, S-080 |
| Platform admin surface | Dense tables keep a focusable horizontal scroll on a phone and never hide the emergency actions. | S-101, S-106, S-122 |
| Visitor-facing pages served by the data plane | The block page and appeal form are one column, readable at 200% text size on a phone without horizontal scrolling. | S-140, S-145 |

## Security-critical controls

Security-critical controls are never hidden on a small screen. They stay in the page header, the primary
action area or a labelled emergency bar; they never move into an overflow menu, a collapsed panel, a drawer
or a hover-only affordance. A small screen may shorten a label, but it may not remove the control or hide it
behind a second tap. The list below is derived from the dangerous-actions catalog: every catalog action that
carries a `time box` or sits on a security-critical screen is one of these rows or an explicit `excluded:`
row, and the Content priority table names the same set at every breakpoint.

| Control | Screens | Small-screen treatment | Why it cannot be hidden |
| --- | --- | --- | --- |
| Safe mode | S-093, S-122 | Visible in the emergency control bar at every width, with the time box and the revert time in the label. | Safe mode is the deliberate pass-through, and the operator must reach it during an incident. |
| Block mode switch | S-055 | Visible in the settings header on every width; the consequences list opens inline instead of in a sheet. | The switch changes what visitors receive and carries the self-lockout warning. |
| Ban and unban | S-067 | Both stay visible on each row card; the bulk unban is a labelled button beside the selection count. | Lifting a ban restores a blocked visitor and must not need a hidden menu. |
| Global ban | S-106 | The ban and release controls stay on the row card and in the page header at every width. | A platform-wide refusal affects every tenant, so releasing it cannot be buried. |
| Self-lockout warning | S-063, S-131 | The warning stays visible inline above the action at every width and is never a toast. | The operator must see that the action would match the current address. |
| Under attack | S-093 | Visible in the emergency control bar at every width. | The response must be one reachable action, not a setting behind a menu. |
| Pause protection | S-093 | The pause and resume controls stay in the emergency control bar with the time box. | Nothing is inspected while the pause runs, so resuming is time-critical. |
| Access-list deny and allow | S-063 | The add and remove controls stay on the list row, and the self-lockout preview opens inline. | A deny or an allow changes who reaches the origin and must be reversible from the same screen. |
| Geo-block | S-063 | The country and ASN controls stay in the list toolbar, and the preview opens inline. | A whole country or network is refused, including customers and a travelling operator. |
| Origin lockdown | S-098 | The apply control and the probe results stay in the wizard step at every width. | Requests that skip HDD are refused at the origin, so the lockdown must be reachable during an incident. |
| Origin unlock | S-052 | The unlock action stays in the origin header, and its typed confirmation opens inline. | Opening the origin again removes the bypass guard, so the action must not sit behind a second tap. |
| Platform never-ban list | S-109 | The add and remove controls stay on the list row at every width. | An exempt network is edited while an incident runs, so the list cannot be buried. |
| Platform emergency controls | S-122 | Safe mode, signup freeze and global challenge stay in the S-122 header at every width, with their end time in the label. | A platform-wide window changes what every visitor sees and has to be clearable during an incident. |
| excluded: virtual patch emergency release | S-126 | The release and rollback live in the S-126 release pipeline, not in a page control bar. | The release needs two-person approval and its expiry is enforced server-side, so there is no small-screen page control to hide. |

## Content priority

Content priority is decided at the boundaries above. Primary data and every security-critical control stay
visible; supporting actions move into a labelled overflow menu that remains keyboard reachable. The overflow
menu never contains a control that changes enforcement, removes a ban or can lock the operator out. The
`Never moves` column names the same control set as the Security-critical controls table in every row, because
a breakpoint must not hide a control that another breakpoint keeps.

| Breakpoint | Always visible | Moves to overflow | Never moves |
| --- | --- | --- | --- |
| 360 to 479 px | The title, the status pill, the primary action, each event's time and action, the pause control | Density, column visibility, saved views, export | Safe mode; block mode switch; ban and unban; global ban; self-lockout warning; under attack; pause protection; access-list deny and allow; geo-block; origin lockdown; origin unlock; platform never-ban list; platform emergency controls |
| 480 to 767 px | The 360 px set, plus the search field | Filters not yet applied, secondary sort, share | Safe mode; block mode switch; ban and unban; global ban; self-lockout warning; under attack; pause protection; access-list deny and allow; geo-block; origin lockdown; origin unlock; platform never-ban list; platform emergency controls |
| 768 to 1023 px | The title, the status pill and the row identity | Column visibility, share, help | Safe mode; block mode switch; ban and unban; global ban; self-lockout warning; under attack; pause protection; access-list deny and allow; geo-block; origin lockdown; origin unlock; platform never-ban list; platform emergency controls |
| 1024 to 1279 px | The full page header and the table toolbar | Secondary page-header actions | Safe mode; block mode switch; ban and unban; global ban; self-lockout warning; under attack; pause protection; access-list deny and allow; geo-block; origin lockdown; origin unlock; platform never-ban list; platform emergency controls |
| 1280 to 1535 px | The full page header and the table toolbar | Help and the keyboard shortcut overlay | Safe mode; block mode switch; ban and unban; global ban; self-lockout warning; under attack; pause protection; access-list deny and allow; geo-block; origin lockdown; origin unlock; platform never-ban list; platform emergency controls |
| 1536 px and up | The full page header and the table toolbar | Nothing beyond the standard menus | Safe mode; block mode switch; ban and unban; global ban; self-lockout warning; under attack; pause protection; access-list deny and allow; geo-block; origin lockdown; origin unlock; platform never-ban list; platform emergency controls |

## Data-dense screens

The live threat monitor S-065 and the other dense tables keep the question they answer on a phone: when,
who, what and what HDD did. Detail moves to the event drawer S-066, which opens from the row and returns
focus to it (B12.2 S-065). The pause control and the `N new events` count stay in a sticky bar and the view
never scrolls itself. The responsive layout adds and removes nothing: every column either persists on the
card or moves to the drawer, and the same value is in both places.

| Screen | Persistent columns | Moves to the drawer | Behaviour |
| --- | --- | --- | --- |
| S-065 | Time, IP, action, status | Ray ID, category, rule, vector, payload | Rows become stacked cards below 640 px; one card is one event and the drawer opens over the list. |
| S-067 | IP, reason, expires | Rule and subtype, hits, source | The countdown stays on the card and unban stays on the card. |
| S-084 | Time, actor, action | Target, request ID, chain position | The filter summary collapses into a disclosure and the table scrolls in a focusable region. |

## Performance budgets

These are budgets, not measurements. No number in this table was observed on a device; each is a ceiling
that a test enforces. The mobile mid-range profile is the reference: a mid-range Android phone, Chrome, a 4x
CPU slowdown and a network of 1.6 Mbps down and 750 Kbps up with a 150 ms round-trip time, recorded in
`docs/ENV.md` when the browser harness lands. Core Web Vitals are measured against that profile; the other
rows exist so that a heavy page cannot pass on fast hardware alone. The budget tests are added with the
design-system work: T-0029 ships the first brand assets whose weight can be budgeted, and T-0052 reports
the CSS and JS budgets at the gate (A2). No value here is a product claim (R-16, R-29).

| Device class | Profile | LCP (ms) | INP (ms) | CLS | JS (KiB) | CSS (KiB) | Requests |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Mobile mid-range | 4x CPU slowdown, 1.6 Mbps down, 150 ms RTT | 2500 | 200 | 0.10 | 120 | 40 | 40 |
| Tablet | Same network, no CPU slowdown | 2200 | 180 | 0.08 | 150 | 50 | 50 |
| Laptop | Wi-Fi, no throttling | 2000 | 150 | 0.05 | 180 | 60 | 60 |
| Desktop | Cable, no throttling | 1800 | 150 | 0.05 | 200 | 60 | 60 |

## Printing and PDF

Report pages S-073 and S-074 and the audit export S-084 print from the same server-rendered HTML as the
screen. The print stylesheet is part of the report template, so the browser print dialog and the PDF export
share one layout.

Page setup. The sheet is A4 portrait, 210 x 297 mm, with 12 mm margins on every edge, a 10 mm header band
and a 10 mm footer band. This is the canonical print margin: [DATAVIZ.md](DATAVIZ.md) points here for the
chart print rule instead of stating its own value. The header carries the report or export title, the
organisation, the domain and the period. The footer carries the generated timestamp in UTC, the page number,
the total page count and the product name.

Hidden in print. The navigation, the sidebar, filters, the export and schedule buttons, the pause control,
row actions, toasts, the command palette and the help launcher are hidden. Nothing that a hidden control
reveals is lost: a value that appears only in a tooltip or in a drawer on screen is printed in full, and a
chart prints its text summary and its data table.

Page breaks. A report section starts on a new page (break-before), a table row, a card or a chart never
splits across pages (break-inside avoid), and the audit export repeats its column header on every page.

Contrast. The print sheet is black on white even when the product theme is dark. Severity keeps its icon and
its text label, and no status is carried by colour alone.

| Subject | Page layout | Hidden in print | Page breaks | Contrast |
| --- | --- | --- | --- | --- |
| Report pages | S-073 and S-074 print the period, the KPI table, the charts and their text summaries on A4 portrait. | Navigation, filters, export and schedule buttons, toasts. | Each section starts a page; charts and tables do not split. | Black on white; severity keeps icon and label. |
| Audit exports | S-084 prints the filter summary, the event table and the chain verification result. | Navigation, filters, the export button and row actions. | The column header repeats; one event row never splits. | Black on white; statuses are text, not a coloured dot. |

## Testing hooks

The harness exposes one viewport helper. `ui viewport <width>x<height> --theme <light|dark> --direction
<ltr|rtl> --freeze` sets the window size, the colour scheme, the document direction and the stabilisers
before first paint. The width and height must be one of the seven matrix viewports; any other value is
rejected rather than silently captured.

Screenshots are written to `acceptance-ui/screens/<surface>/<screen>/<state>-<theme>-<viewport>.png`. That is
the naming rule of T-0090 step 3, and the same name becomes the baseline path under `design/baselines/`
when T-0052 creates the baselines. Names are stable because the screen id, the state, the theme and the
viewport are the only variables; renaming a file is a baseline change with a reason and a reviewer note.
Every capture disables animations, fixes the clock, waits for fonts and the SSE idle state, uses a device
scale factor of 1 and hides dynamic regions through test selectors, so two runs of an unchanged screen
compare equal. The device matrix above is the input list for T-0090 and for the screenshot step of T-0047.

| Helper | Argument | Effect |
| --- | --- | --- |
| Viewport helper | `<width>x<height>` | Sets the window to one matrix viewport and records it in the file name. |
| Theme flag | `--theme light` or `--theme dark` | Sets the colour scheme and the theme attribute before first paint. |
| Direction flag | `--direction ltr` or `--direction rtl` | Sets the document direction and mirrors the drawer edge. |
| Stabiliser | `--freeze` | Disables animations, fixes the clock and waits for fonts and the idle SSE state. |
