# Content strategy and microcopy guide

Status: v1, written for T-0019 (REQ-UXR-09). The voice rules come from spec B11.12; the claims rules come from spec
section 4. The interface glossary is [glossary.md](glossary.md); its translator copy is
[i18n/glossary.md](../../i18n/glossary.md). The charter that this guide serves is [CHARTER.md](CHARTER.md).

This document is the reference for later copywriting tasks: every string in the product, the console, email, reports
and the block page follows it. The `ux-docs` check enforces the structure and the examples; `claims-lint` enforces the
claims policy on the documents and on the copy deck.

## Voice and tone

Write as a calm expert: say what happened, why it matters and what to do next. Use short sentences, active voice and
second person. Prefer a measured number to an adjective, explain a security term on first use and link the glossary.
Errors blame the situation, never the reader. Keep fear language, humor and emoji out of the product; an exclamation
mark is for a success confirmation and is used sparingly.

| Rule | Good | Bad |
| --- | --- | --- |
| Plain words, short sentences | "Monitor mode records what HDD would block. Nothing is blocked yet." | "The WAF operates in a non-blocking observation state." |
| Active voice, second person | "You added example.org. HDD now answers its DNS." | "The domain has been added by the system." |
| Numbers over adjectives | "412 requests were blocked in the last hour." | "Many attacks were stopped." |
| Say what to do next | "Paste the TXT record at your DNS provider, then check again." | "The verification is incomplete." |
| No fear, no humor, no emoji | "The request was blocked. The reason is in the event detail." | "You are under attack. Act now before it is too late." |

## Vocabulary

One term per concept, in the console, the API and the documentation. The `Avoid` column lists words that mean
something else or belong to another product; a translator never sees them. Terms are matched as whole words, so
`blocklist` is not `block`.

| Concept | Canonical term | Avoid | Why |
| --- | --- | --- | --- |
| A name the owner adds | domain | site, web property | A domain is the unit whose DNS records the owner changes. |
| Traffic through HDD | proxied | orange cloud, on cloud | The state describes the record, not another product's icon. |
| One refused request | block | deny, drop | The console, the audit log and the block page use the same verb. |
| A timed address restriction | ban | jail entry, blocklist entry | A ban has a reason, a time limit and an undo path. |
| The server behind HDD | origin | backend, upstream server | Lockdown and health checks must name one thing. |
| Recording mode | monitor mode | dry run, passive mode | The selector and the events use one name. |
| Enforcement mode | block mode | active mode, firewall mode | The mode names the visitor effect, not the component. |
| A visitor proof step | challenge | captcha, puzzle | Some challenges are not visual and none is called a puzzle. |
| One request decision | event | hit, log line | Events are stored, filtered and linked to a Ray ID. |
| The request reference | Ray ID | request id, trace id | The block page and the appeal form quote it. |
| Addresses exempt from bans | never-ban list | allowlist, whitelist | An allowlist admits; this list only exempts from bans. |
| DNS servers for a domain | nameserver | name server, NS host | The wizard names the records the owner sets. |
| Setup completeness | readiness | security score, grade | Readiness measures configuration completeness, not security. |
| A group of matching rules | ruleset | signature set, policy pack | Rules ship in named groups that the owner can inspect. |
| A short state label | status label | status text | A label names the state without relying on colour. |

## Capitalization and punctuation

- Sentence case for headings, labels, buttons, table headers and menu items.
- No terminal period on a button, a label, a tab or a table cell that is a phrase; a full sentence takes one.
- One space after a period; no double spaces and no space before punctuation.
- Use the serial comma in a list of three or more items, and a colon before a list or an example.
- Prefer a full stop to a semicolon; never use more than one exclamation mark and only on a success confirmation.
- Quote an interface label in backticks in documentation; quote a user value in double quotation marks in prose.
- Do not use an emoji, an emoticon or decorative symbols in product copy; an icon is a component with a text label.

## Number, date and unit formats

| Item | Format | Example |
| --- | --- | --- |
| Requests and counts | whole number, grouped in threes | "1,204 requests" |
| Dates in the console | year, month, day, no leading zero on the day | "2026-10-19" |
| Times | 24-hour clock with the zone, on the same line | "14:05 UTC" |
| Durations | number and unit; spell the unit out under one minute | "45 seconds", "2 h 10 min" |
| Counted messages | a Fluent `$count` selector with `[one]` and `*[other]`, one message and never concatenated fragments | "1 event", "2 events" |
| Percentages | at most one decimal place | "98.6%" |
| Bytes | decimal unit with one decimal place | "1.2 MB" |
| Addresses | the address as written, in a monospace field | "203.0.113.10" |
| Relative time | the absolute time plus a relative span | "12 minutes ago (14:05 UTC)" |

## Message patterns

Every message states what happened, what it means and the next action. A success message is short and never
celebratory; an error names the field and the fix; a destructive confirmation lists the consequence, offers the safe
choice and asks for the type-to-confirm when the action cannot be undone. An empty state is honest: it says what is
missing instead of showing sample data.

| Pattern | Example text | i18n key |
| --- | --- | --- |
| Success | Domain added. DNS checks run every minute. | domain-add-success |
| Success | Two recovery codes copied. | recovery-codes-copied |
| Validation error | Enter a domain name, like example.org. | domain-name-invalid |
| Validation error | The code must be six digits. | mfa-code-format |
| System error | Something went wrong on our side. Try again in a moment. | system-error-retry |
| System error | The API is unavailable right now. The change was not saved. | api-unavailable |
| Destructive confirmation | This removes the domain and its history. Type the domain name to confirm. | domain-delete-confirm |
| Destructive confirmation | Block mode will ban the sending address. You can switch back at any time. | block-mode-confirm |
| Empty state | No events yet. Requests appear here within seconds. | no-events-empty |
| Empty state | You have not added a domain yet. Add one to start. | no-domains-empty |
| Limit reached | You reached the 10 domain limit on this plan. Remove a domain or change plan. | domains-limit-reached |
| Security notice | This account is read-only for support. Changes are disabled. | support-readonly-notice |
| Email subject line | Confirm your email address for HDD | email-verify-subject |

## Visitor errors

A block page never blames the visitor and never reveals how detection works. It says that the request looked like an
attack, gives the Ray ID, and offers the appeal form. The same rules apply to a challenge page and to an error shown
to a visitor whose request was refused.

| Forbidden disclosure | Why it is forbidden |
| --- | --- |
| The rule name or id that matched | A visitor could tune the next request to that one rule. |
| The matched payload or header value | It repeats an attack string on a public page and can break the layout. |
| The detection threshold or paranoia level | It tells an attacker how far a request may go before a block. |
| The client address or its country | It exposes data about a third party on a shared address. |
| The ban time or the next block step | It tells the reader exactly when to retry. |
| The internal event id or operator note | It leaks console-only data and the operator's assessment. |
| Whether the address is shared with an attacker | The page cannot settle that dispute and must not imply it can. |

## Translation guidance

Every string is an i18n key in `i18n/en/*.ftl`; keys are semantic stems such as `domain-add-step2-title`, never
sentences. Translators work from the English source in the copy deck and from [i18n/glossary.md](../../i18n/glossary.md).

- Never concatenate sentence fragments. One sentence is one message with its placeables, in the source language.
- Use Fluent placeables such as `{$domain}` and `{$ray_id}`; never build a sentence from two keys in code.
- A count uses a Fluent selector with `[one]` and `[other]`, and the translator writes both variants.
- Write gender-neutral wording: "the owner", never "he" or "she".
- Never put text in an image; every label is a string key and the icon is decoration.
- Do not build a plural by appending a letter in code; the selector in the message owns the plural.

```fluent
events-count = { $count ->
    [one] { $count } event
   *[other] { $count } events
}
```

## Review of B13

Every string of the B13 copy deck was read against section 4.2 and the voice rules above. `pass` means the string
needs no rewrite: it states facts without an absolute claim, names the next action where one exists, and can be
translated as one message. An `exception:` row names the owner and the reason when a string needs a decision outside
this document. The `<` and exclamation rules and the duplicate-value rule are checked on the copy deck by the style
check, and the claims rules run on the same values.

| Key stem | Result | Note |
| --- | --- | --- |
| `tagline` | pass | Landing headline; three actions and no security claim. |
| `claims-footnote` | pass | Public footnote; states exposure and names patching as the owner's job. |
| `signup-title` | pass | Sign-up heading; short, second person, no exclamation mark. |
| `signup-email-sent` | pass | Neutral wording that does not reveal whether the address exists. |
| `login-error` | pass | One reason covers both fields; enumeration-safe (R-20). |
| `login-locked` | pass | States the wait without naming a limit an attacker could use. |
| `mfa-required` | pass | Second-step prompt that says why, not only what. |
| `recovery-codes-warning` | pass | One-time display and one-use-per-code stated plainly. |
| `domain-add-title` | pass | Wizard title; names the object the owner adds. |
| `domain-add-help` | pass | Says what HDD reads and that nothing changes before consent. |
| `integration-full-ns` | pass | Scoped to proxied names; the scope word is what the claims context rule requires. |
| `integration-cname` | pass | Names one record and the alternative integration mode. |
| `integration-apex-note` | pass | Explains the root-record limit and gives three routes. |
| `verify-dns-txt` | pass | One action, one place, no jargon. |
| `verify-http-file` | pass | The alternative proof; points at the path shown. |
| `monitor-explainer` | pass | The safe first step; says every request passes. |
| `block-confirm-title` | pass | A question with the domain placeholder; the type-to-confirm step follows it. |
| `block-confirm-body` | pass | States the ban, the shared-address effect and the undo. |
| `shield-title` | pass | Names the assumption instead of a guarantee. |
| `shield-body` | pass | Names an example attack and the exposure limit. |
| `shield-limit` | pass | States the detection limit and the patching duty. |
| `block-page-title` | pass | Short refusal heading; no blame. |
| `block-page-body` | pass | Says what happened, why, and how to appeal. |
| `block-page-ray` | pass | The reference the appeal uses; no detection detail. |
| `appeal-title` | pass | Action title for the visitor. |
| `appeal-sent` | pass | Neutral confirmation that names the reference. |
| `ban-self-warning` | pass | Names the address and the access loss before the change. |
| `virtual-patch-banner` | pass | The required disclosure of section 4.4; no fix claim. |
| `readiness-footnote` | pass | The required footnote; readiness is not a security measure. |
| `empty-events` | pass | Honest empty state with the time to the first row. |
| `empty-domains` | pass | Empty state that offers the next action. |
| `unknown-value` | pass | Shows a reason placeholder instead of a guess. |
| `cutover-warning` | pass | Names the email risk and points at the checklist. |
| `rollback-instruction` | pass | Gives the exact undo and the propagation wait. |
| `under-attack-title` | pass | Feature title; no fear wording. |
| `under-attack-body` | pass | States the visitor cost and the automatic end. |
| `impersonation-banner` | pass | Names the organisation and the session limit for the support view. |
| `admin-banner` | pass | Short platform label; no data. |
