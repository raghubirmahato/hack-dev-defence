# Navigation model and wayfinding

Status: v1, written for T-0015 (REQ-UXR-05). Sources: spec B2.3 (navigation model), B11.8 (components), B11.11
(accessibility contract), B11.12 (voice and tone), [IA.md](IA.md), [routes.toml](routes.toml) and the personas. The
route and permission columns below are tied to `routes.toml` by `cargo xtask ux-docs`, so the navigation cannot drift
from the information architecture.

Every navigation element has a keyboard path and an ARIA role (A1). Nothing in the navigation depends on hover. The
focus behaviour is specified for a full page load and for a partial swap (A2). Restricted items are either hidden or
explained, never both (A3). The phone widths 360 px, 480 px and 768 px are specified (A4). The reserved table lists the
keys the product never binds, and `Documented conflicts` lists the keys it does bind despite a browser or screen-reader
default, with a mitigation for each (A5).

## Navigation elements

The org sidebar is a `navigation` landmark; the domain context header carries a `tablist`; the top bar is a `banner`
with buttons and menus. The current page is marked with `aria-current="page"` on exactly one item.

```text
+-------------------+------------------------------------------------------+
| Org sidebar       | Domain header: name  [status] [mode] [readiness]     |
|  Overview   *     +------------------------------------------------------+
|  Domains          | Overview | DNS | SSL/TLS | Security | Origin | ...    |
|  Live events      +------------------------------------------------------+
|  Bans             |                                                      |
|  Analytics        |   Content of the selected tab                        |
|  Reports          |                                                      |
|  ...              |                                                      |
+-------------------+------------------------------------------------------+
```

| Element | Route | Permission | Keyboard | ARIA role | Notes |
| --- | --- | --- | --- | --- | --- |
| Sidebar · Overview | `/app/o/{org}/overview` | `PERM-analytics.read` | Tab, Enter | navigation | The current item carries `aria-current="page"`. |
| Sidebar · Domains | `/app/o/{org}/domains` | `PERM-domain.read` | Tab, Enter | navigation | |
| Sidebar · Live events | `/app/o/{org}/events` | `PERM-event.read` | Tab, Enter | navigation | |
| Sidebar · Bans | `/app/o/{org}/bans` | `PERM-ban.read` | Tab, Enter | navigation | |
| Sidebar · Analytics | `/app/o/{org}/analytics` | `PERM-analytics.read` | Tab, Enter | navigation | |
| Sidebar · Reports | `/app/o/{org}/reports` | `PERM-report.read` | Tab, Enter | navigation | |
| Sidebar · Notifications | `/app/o/{org}/notifications` | `PERM-notify.read` | Tab, Enter | navigation | |
| Sidebar · Integrations | `/app/o/{org}/integrations` | `PERM-notify.read` | Tab, Enter | navigation | |
| Sidebar · Team | `/app/o/{org}/team` | `PERM-member.read` | Tab, Enter | navigation | |
| Sidebar · API keys | `/app/o/{org}/api-keys` | `PERM-apikey.read` | Tab, Enter | navigation | |
| Sidebar · Audit log | `/app/o/{org}/audit` | `PERM-audit.read` | Tab, Enter | navigation | |
| Sidebar · Plan and usage | `/app/o/{org}/plan` | `PERM-plan.read` | Tab, Enter | navigation | |
| Sidebar · Settings | `/app/o/{org}/settings` | `PERM-org.update` | Tab, Enter | navigation | |
| Tab · Overview | `/app/o/{org}/domains/{dom}` | `PERM-domain.read` | Arrow keys, Home, End | tab | The tab list is one stop in the tab order. |
| Tab · DNS | `/app/o/{org}/domains/{dom}/dns` | `PERM-dns.read` | Arrow keys, Home, End | tab | |
| Tab · SSL/TLS | `/app/o/{org}/domains/{dom}/tls` | `PERM-tls.read` | Arrow keys, Home, End | tab | |
| Tab · Security | `/app/o/{org}/domains/{dom}/security` | `PERM-analytics.read` | Arrow keys, Home, End | tab | |
| Tab · Origin | `/app/o/{org}/domains/{dom}/origin` | `PERM-origin.read` | Arrow keys, Home, End | tab | |
| Tab · Events | `/app/o/{org}/domains/{dom}/events` | `PERM-event.read` | Arrow keys, Home, End | tab | |
| Tab · Bans | `/app/o/{org}/domains/{dom}/bans` | `PERM-ban.read` | Arrow keys, Home, End | tab | |
| Tab · Analytics | `/app/o/{org}/domains/{dom}/analytics` | `PERM-analytics.read` | Arrow keys, Home, End | tab | |
| Tab · Settings | `/app/o/{org}/domains/{dom}/settings` | `PERM-domain.update` | Arrow keys, Home, End | tab | |
| Top bar · Org switcher | - | - | Enter opens, arrow keys move, Esc closes | button | Opened by keyboard; hover is not required. |
| Top bar · Domain switcher | - | - | Enter opens, type-ahead, Esc closes | combobox | Lists only domains the user may read. |
| Top bar · Search / command palette | - | - | Ctrl/Cmd+K | button | Opens the dialog described below. |
| Top bar · Notification bell | - | - | Tab, Enter | button | The unread count is text, not only a dot. |
| Top bar · Theme toggle | - | - | Tab, Enter | button | The state is text plus an icon. |
| Top bar · Help menu | - | - | Tab, Enter | menu | |
| Top bar · User menu | - | - | Tab, Enter | menu | |
| Global · Skip link | - | - | Tab | link | The first focusable element on every page. |

Hidden items are removed, not disabled with a mystery tooltip; the restricted-item states below say which case applies.
A domain tab that the plan limits keeps its place and shows an upgrade note, so a security control is never hidden
behind a plan.

## Org and domain switchers

Both switchers use the same pattern. The field is a combobox with `aria-expanded`, `aria-controls` and
`aria-activedescendant`. Typing filters on the display name and the slug or domain, not only on a prefix, so a user who
remembers the middle of a name still finds it. The list is ordered by recent use first, then by name; the current
organisation or domain is marked `aria-current="true"`.

Keyboard: `Enter` opens the list, `Up` and `Down` move, `Home` and `End` jump, `Enter` chooses, `Esc` closes and
returns focus to the field. The list is one stop in the tab order and never traps focus.

Empty states are honest. With no organisation the switcher says so and offers the create action the user is allowed
to take. With no domain it offers the add-domain wizard. A domain that the user may not read is absent from the list
rather than shown disabled; a domain the plan limits is listed with an upgrade note.

## Breadcrumbs

Breadcrumbs show the hierarchy of the current screen: organisation, domain, area, page. The maximum depth is four
levels; deeper pages collapse the middle levels into a menu labelled with the hidden count. The last item is the
current page and carries `aria-current="page"`; it is not a link. Separators are CSS, not text in the reading order.

On narrow screens the breadcrumbs collapse to one parent plus the current page, so the row never wraps to a second
line. The browser Back button returns to the previous screen with the query state preserved; a close action inside a
drawer removes only its own parameter, described in [IA.md](IA.md) under Deep linking.

## Command palette and shortcuts

The command palette opens with `Ctrl/Cmd+K` or the search control. Its scope is: actions the user may take on the
current screen and organisation, entities the user may read (domains, rules, Ray IDs, addresses), and recently used
commands. Ranking puts recent items first, then permitted actions, then entities; a result the user cannot use is not
shown. The palette is a dialog with a labelled search field, a result list and a polite live region for the result
count. `Enter` runs the first result, `Up`/`Down` move, `Esc` closes and restores focus to the control that opened it.

```text
+------------------------------------------+
| Find an action, domain, rule or Ray ID   |
+------------------------------------------+
| > Add a domain                     Action |
|   example.com                      Domain |
|   rule_ab2c...                     Rule   |
+------------------------------------------+
```

| Keys | Action | Scope |
| --- | --- | --- |
| `g o` | Go to Overview | Global |
| `g d` | Go to Domains | Global |
| `g e` | Go to Events | Global |
| `g b` | Go to Bans | Global |
| `/` | Focus the search field | Global |
| `c` | Copy the focused value | Global |
| `Esc` | Close the current overlay | Global |
| `?` | Open the shortcut list | Global |
| `Ctrl/Cmd+K` | Open the command palette | Global |

### Reserved by browsers and assistive technology

These keys stay with the browser or the screen reader. The product does not bind them.

| Keys | Why it is reserved |
| --- | --- |
| Ctrl/Cmd+R | Reload the page |
| Ctrl/Cmd+T | Open a new tab |
| Ctrl/Cmd+W | Close the tab |
| Ctrl/Cmd+N | Open a new window |
| Ctrl/Cmd+P | Print |
| Ctrl/Cmd+F | Find in the page |
| Ctrl/Cmd+L | Focus the address bar |
| Ctrl/Cmd+D | Bookmark the page |
| Ctrl/Cmd+Plus | Zoom in |
| Ctrl/Cmd+Minus | Zoom out |
| F5 | Reload |
| F6 | Focus the address bar |
| Insert+Down | Read all, in a screen reader |
| Caps Lock+Space | Toggle browse mode, in a screen reader |

Single-letter shortcuts do not fire while a text field, a select or a contenteditable element has focus. Every
shortcut with a letter can be turned off in the user's preferences, and the shortcut list has a switch for that
(WCAG 2.1.4). The preference is stored per user, not per browser profile.

Shortcuts are conveniences and never the only path: every function they reach has a control in the elements table, and
single-letter shortcuts can be turned off (WCAG 2.1.4 and 2.1.1).

## Documented conflicts

The specification fixes these shortcuts, so the product keeps them. Several of them also have a browser or screen-reader
default; the table records the conflict and the way to reach the same function without the key. B2.3 is the owner of
the choice; the mitigation is the product's obligation.

| Keys | Owner of the default | Effect | Mitigation |
| --- | --- | --- | --- |
| `Ctrl/Cmd+K` | The address or search bar of some browsers (for example Chrome and Firefox on Windows and Linux); the binding differs by browser and platform and is not verified here. | The browser may open its own search instead of the palette. | The Search / command palette button in the top bar opens the palette; shortcuts can be turned off in preferences. |
| `/` | The browser's quick find when no field has focus. | The search field may not receive focus from the key. | The Search / command palette button opens the search; shortcuts can be turned off in preferences. |
| `g` (the `g o`, `g d`, `g e` and `g b` chords), `c`, `?` | The screen reader's browse (virtual cursor) mode, where single keys are quick-navigation commands. | The keys reach the page only in focus mode; in browse mode they move the virtual cursor. | The Sidebar · Domains item and the copy button on the field give the same functions; shortcuts can be turned off in preferences. |

## Restricted items

| State | When | Display | Example |
| --- | --- | --- | --- |
| permission-hidden | The user's role has no concept of the feature. | The item is absent from the sidebar, the palette and the page. | An analyst does not see platform administration. |
| plan-limited | The feature exists but the current plan lacks it. | The item is shown with a short explanation and the way to upgrade; the action explains the limit instead of failing silently. | Audit export on a plan without it. |

A permission-hidden item leaves no disabled placeholder behind; a plan-limited item never hides a security control
(R-28). The distinction is decided on the server, from the permissions and the plan, so a client cannot reveal an item
the role may not use.

## Admin surface

The platform-admin surface is visually distinct without relying on colour: a persistent band with the words
"Platform admin", a distinct accent, a different icon and its own sidebar. The band is the first element in the
reading order and a staff member sees it on every admin screen.

```text
+== Platform admin ======================================+
| Tenants | Users | Domains | Jail | Runtime | ...        |
+--------------------------------------------------------+
```

The admin sidebar has its own items (overview, tenants, users, domains, jail, rules, intel, allowlists, infrastructure,
abuse, settings, audit, runtime, hosting) and no tenant navigation. Switching back to the tenant app is an explicit
link, so a staff member cannot mistake the two surfaces.

## Focus management

### Full page loads

After a full load the browser focuses the new `h1` (which gets `tabindex="-1"`), announces the document title and the
heading, and leaves scroll position at the top unless the URL carries a fragment. The skip link is the first focusable
element and scrolls to the main landmark. A sticky header uses `scroll-padding` so focus is never obscured (B11.11,
2.4.11).

### Partial swaps

After an HTMX swap the focus moves to the changed region: the new `h1` when the main content changed, or the region
that changed when the swap was local. A polite live region announces the change in one sentence, for example "Filters
applied, 12 events". Scroll position is preserved; a swap that opens a panel focuses the panel's heading and `Esc`
returns focus to the control that opened it. The Back button returns to the previous URL and the same focus target.

## Mobile

No navigation function depends on hover; every menu, tab and drawer action has a keyboard and touch path. The
minimal supported width is 360 px; below that the layout reflows but no function is removed.

### 360 px

The org sidebar becomes a drawer opened by a labelled button in the top bar. The domain tabs scroll horizontally with
a visible edge fade and each tab keeps a 24 px target at minimum. The breadcrumbs collapse to one parent and the
current page. The primary action of the screen sits in a bottom action bar that respects the safe area.

### 480 px

The drawer stays, the top bar gains the search field instead of only the search button, and the domain tabs keep the
horizontal scroll. Breadcrumbs show two levels. The notification bell shows the unread count as a number.

### 768 px

The sidebar becomes an overlay drawer instead of the persistent column. The top bar shows the org switcher, the domain
switcher and search. The domain tabs wrap to a second row instead of scrolling, and the breadcrumbs show two levels.

```text
+------------------------------------------+
| [menu] Site name        [search] [bell] |
+------------------------------------------+
| Overview | DNS | SSL/TLS | Security ...  |
+------------------------------------------+
| Content                                  |
+------------------------------------------+
| [ primary action ]                       |
+------------------------------------------+
```

## Review checklist

- Does every element in the table have a keyboard path and an ARIA role? Yes (T-0138).
- Does every sidebar and tab row name a route that exists, with the permission of `routes.toml`? Yes (`cargo xtask
  ux-docs`).
- Does the shortcut map cover B2.3, list every bound key that has a browser or screen-reader default in `Documented
  conflicts`, and allow single-letter shortcuts to be turned off? Yes (T-0151).
- Are permission-hidden and plan-limited distinguished on the server? Yes (T-0151).
- Does focus move to the new `h1` or the changed region after a load or a swap, with a polite announcement? Yes
  (T-0138, T-0151).
- Do the 360 px, 480 px and 768 px layouts keep every navigation function? Yes (T-0138).
- Does any function depend on hover? No.
