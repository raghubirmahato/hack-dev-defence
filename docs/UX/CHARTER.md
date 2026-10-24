# HDD UX charter

Status: v1, written for T-0011 (REQ-UXR-01). Source of the principles: spec B11.1. Voice rules: B11.12. Claims rules: section 4.
Measures live in [MEASURES.md](MEASURES.md). Decisions live in [decisions/](decisions/UXD-001.md).

This charter is the yardstick for every screen, message and flow. It is short on purpose: it fits four printed pages
(the `ux-docs` check enforces a word budget, so a longer charter fails `cargo xtask verify`). A principle without an
enforcement mechanism is decoration, so each row below names how it is enforced and whether that mechanism exists yet.

## Who this is for

Maya, the site owner, wants a plain summary. Dan, the developer, wants the API call. Sara, the analyst, wants the evidence.
The same screen serves all three at different depths (principle 3). Personas are written up in T-0012.

## Principles

| # | Principle | We will | We will not | Enforced by |
| --- | --- | --- | --- | --- |
| 1 | Calm, honest, expert | Write "412 requests blocked in the last hour" and say what to do next. | Write "many attacks" or add a red banner that adds no information. | `cargo xtask claims-lint` on docs, templates and catalogs (live); the honesty tests below at every design review (live); string review against the microcopy guide (T-0019, planned). |
| 2 | Show state, not decoration | Give every status chip a text label or icon as well as its color, and say what the state means. | Use color alone to tell "blocked" from "monitored", or add a graphic that encodes nothing. | `cargo xtask contrast-check` on the color tokens (stub until T-0030); a second-signal checklist item in the component review (planned, P02); accessibility audit AC-40 (T-0091, T-0151). |
| 3 | Progressive disclosure | Show a one-line summary first, with the evidence and the API call one click deeper on the same screen. | Send Sara to another product area for the evidence, or bury Maya in rule IDs by default. | Screen specification template requires three depths per screen (planned, T-0014); journey review of J-16 to J-19 (planned, T-0016 to T-0018). |
| 4 | Safe by design | Make the safe option the default and primary button; require a preview, a time box and an undo path for risky changes. | Pre-select a destructive option, hide the undo, or let a lockout happen without a warning. | Rules R-19 and R-28 in the build specification; type-to-confirm and lockout patterns (T-0025, planned); end-to-end tests of the dangerous-action patterns (planned, P04 and later). |
| 5 | Fast and light | Render on the server, keep CSS and JavaScript small, reserve space so nothing jumps. | Ship a client framework for a static page or load a third-party script. | Page-weight and layout-shift budgets as tests (R-29, AC-41, T-0104, planned); no third-party origins in the content security policy (planned). |
| 6 | Accessible by construction | Build screens from components that already carry keyboard behavior, ARIA, focus handling and 24 pixel targets. | Ship a screen that only works with a mouse, or patch accessibility on at the end. | WCAG 2.2 AA gate AC-40 (T-0091, T-0151, planned); accessibility plan (T-0022); rule R-17 (no keyboard operation, not done). |
| 7 | Dark first, light equal | Design, test and ship both themes and honor `prefers-color-scheme` and the saved choice. | Treat light as an afterthought or ignore the system preference. | Contrast check runs on both token sets (stub until T-0030); theme tests in the UI suite (planned); decision [UXD-001](decisions/UXD-001.md). |

"Live" means the mechanism runs today in `cargo xtask verify`. "Planned" names the task that delivers it; until then the
principle is enforced by review only, and the review pack (T-0028) reports it that way.

## Honesty tests

Every screen, email, report and error message must pass all five. Answer each with yes or no; a "no" blocks the change.

1. Does it show real data, never a sample, a placeholder number or an invented chart?
2. Does it state its limits, including what is not covered or not measured?
3. Is every claim backed by a test, a contract or a listed known limitation?
4. Is the safe option the default and the primary action?
5. Can the user undo the action, or is the irreversible step labeled and confirmed by typing?

Empty states are honest: "No events yet" is a valid screen, a fake chart is not (rule R-16).

## Decisions

UX decisions are recorded as `docs/UX/decisions/UXD-nnn.md` with the fields Status, Date, Context, Decision and
Consequences. A decision is never edited away: a new record supersedes the old one and both stay. The first three:

- [UXD-001](decisions/UXD-001.md): dark theme first, light theme equal.
- [UXD-002](decisions/UXD-002.md): server-rendered UI.
- [UXD-003](decisions/UXD-003.md): no third-party analytics.

## Writing rules in brief

Plain words, short sentences, active voice, second person (B11.12). Say what happened, why it matters and what to do;
errors blame the situation, not the user. Numbers over adjectives. No fear language, no emoji in the product, no humor
in errors. The claims policy (section 4.2) lists forbidden phrases, including absolute-protection wording; use the approved patterns in 4.3.
The charter itself is checked by `claims-lint`: a sentence that over-claims fails the build.

## How the charter is kept honest

- `cargo xtask verify` runs `ux-docs`: it checks that all seven principles have a "we will", a "we will not" and an
  enforcement mechanism, that there are five honesty tests phrased as questions, that every measure has a data source and
  a privacy treatment, that the decision records have their sections, and that every relative link resolves.
- A mechanism marked "planned" is listed in the review pack of T-0028 with its task, so nobody mistakes intent for coverage.
- Changing a principle needs a new decision record, not a silent edit.
