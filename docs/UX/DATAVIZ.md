# Data visualization and dashboard information design

Scope: the nine analytics screens of T-0027 (`S-040`, `S-043`, `S-054`, `S-065`, `S-070`, `S-071`, `S-072`, `S-100`,
`S-127`). This document says what each screen shows, which chart form answers each question and why, which table each
list uses, how colour and accessibility are handled, what each chart form does under downsampling, and what the screens
do when data is missing. The numbers themselves are defined in [the metrics dictionary](metrics-dictionary.md).

Sources read for this document: B11.10 (data visualization rules), B11.2 (colour tokens), B11.8 (ChartKit, WorldMap,
StatCard and DataTable contracts), B11.9 items 5 and 6 (time and numbers), B9 (metrics catalog), B12.1 and B12.2
(screens), B5.5 to B5.10 (data model), B6.3 (API routes), B8 (audit events), T-0088 (SVG chart renderer, LTTB,
2,000 points, 5 ms p95), T-0139, T-0171, T-0221, T-0437, T-0441, T-0442, T-0443, T-0444, T-0446 and Q-008. Each
selection is marked with the rule that supports it; where the specification does not decide something, the section
says so instead of inventing a value.

Status: the structure is checked by `cargo xtask ux-docs` (module `ux_docs::dataviz`). The evidence run is in
`docs/evidence/P01/T-0027-verify.txt`. The check is a document linter: it proves that a question, a metric, a KPI and
a widget exist and that the KPI is defined in the dictionary; it does not judge whether the chart answers the question
well.

## Screen questions

Each row is one question a user brings to the screen, the metric that answers it, the dictionary KPI, the chart form
and the widget that renders it. `Widget` names a row of `Chart alternatives`, `Tables` or `Unknown data`. The form
`table` means the DataTable contract of B11.8 (the text-first alternative), not a chart; every screen also has at
least one chart or stat card.

| Screen | Question | Metric | KPI | Chart form | Widget | Justification |
| --- | --- | --- | --- | --- | --- | --- |
| S-040 | How much traffic did my organisation see in the last day, and how much was blocked? | Requests and blocked requests over 24 hours | requests, blocked | line | traffic-24h | A change over time: B11.10 rule 1 assigns a line to a time series, and two series stay far below the eight-series cap. |
| S-040 | Are any bans active, and how many domains are healthy? | Active bans; healthy domains | bans-active, domains-healthy | stat card | stat-card | Two current values with a comparison to the previous period: StatCard is the B11.8 form for a single value. |
| S-040 | What needs my attention now? | Open attention items from the deterministic rules | attention-open | table | attention-list | Items are heterogeneous and carry actions, so the DataTable is the B11.8 text-first form; the count sits above it in a stat card. |
| S-043 | Is this domain's traffic normal today? | Requests and blocked requests over 24 hours | requests, blocked | line | traffic-24h | The same time-series question as the organisation view, so the line is reused at domain scope (B11.10 rule 1). |
| S-043 | Which attack categories is this domain seeing? | Blocked requests by category | blocked-by-category | ranked horizontal bar | top-categories | A top-N ranking of named categories: the ranked horizontal bar reads labels directly (B11.10 rule 1). |
| S-043 | What are the mode, readiness, certificate and origin states? | WAF mode, readiness score, certificate days, origin health | mode-state, readiness-score, cert-days, origin-health | stat card | stat-card | Four current states, each with a text label and an action; StatCard (B11.8). |
| S-043 | Which recent events matter? | The ten most recent notable events | recent-events | table | recent-events | Row detail and links into the event view: the DataTable is the text-first form (B11.8). |
| S-054 | Is the attack level rising or falling? | Blocked, would-block and allowed-suspicious requests over time | blocked-range, would-block-events, allowed-notable | line | attack-timeline | Three series of the same unit over time: line (B11.10 rule 1); in monitor mode the would-block series is the point of the page. |
| S-054 | Which categories are being blocked? | Blocked requests by category | blocked-by-category | ranked horizontal bar | top-categories | A named top-N ranking, not a trend: ranked horizontal bar (B11.10 rule 1). |
| S-054 | Which paths are attacked most? | Requests by path template, ranked | top-paths | ranked horizontal bar | top-paths | Top-N over long labels; ranking with direct labels avoids a rotated axis (B11.10 rule 1). |
| S-054 | When during the week do attacks cluster? | Blocked requests by local hour and weekday | attack-heatmap | heatmap | attack-heatmap | B11.10 rule 1 names the heatmap for hour-by-day; no other form shows a two-dimensional pattern as compactly. |
| S-054 | What would have been blocked in monitor mode? | Would-block count and the most frequent examples | would-block-events | stat card | stat-card | One count with the example list beneath it: StatCard for the number (B11.8). |
| S-054 | Is the shield doing anything? | Shield state, bans created by the shield in 24 hours, last hard hit | shield-state, shield-bans-24h, last-hard-hit | stat card | stat-card | Three current values with text labels; StatCard (B11.8). |
| S-065 | What is happening right now? | Notable and blocked events per minute | live-events-per-min, live-blocked-per-min | stat card | stat-card | Two rates that update live: StatCard with an explicit unit, because a chart of the last minute would move faster than a reader can follow (B11.8). |
| S-065 | Which category dominates this minute? | The category with the most events in the last five minutes | live-top-category | ranked horizontal bar | live-category | A live top-N ranking; the ranked bar keeps the label next to the value (B11.10 rule 1). |
| S-065 | Which events should I inspect? | The newest notable events | live-rows | table | live-table | Row-level detail and actions: the DataTable (B11.8) with the LiveFeed pause and buffered-count contract. |
| S-070 | How did requests and blocked traffic move over the range? | Requests and blocked requests per bucket | requests, blocked | line | requests-blocked | The main time series of the page; line (B11.10 rule 1). |
| S-070 | Which response status classes dominate? | Requests grouped by status class | status-classes | stacked bar | status-stacked | Composition over time: B11.10 rule 1 assigns the stacked bar; five classes stay under the eight-series cap. |
| S-070 | How much bandwidth did we serve? | Response bytes per bucket | bytes-out | line | bandwidth | Bytes per bucket over time are continuous: line (B11.10 rule 1). |
| S-070 | How fast were responses? | p50, p95 and p99 request duration | latency-percentiles | line | latency | Three percentiles over time: line, with the approximate label required by T-0441 A4 (B11.10 rule 1). |
| S-070 | Was this range better than the previous one? | Block rate, error rate and the previous-period delta | block-rate, error-rate, previous-period-delta | stat card | stat-card | A small number of ratios with deltas: StatCard (B11.8), with the comparison toggle on the page. |
| S-071 | Where does traffic come from? | Requests and blocked requests by country | geo-requests, geo-blocked | choropleth | geo-choropleth | B11.10 rule 1 allows a choropleth only with a ranked table alongside; the map orients, the table carries the numbers. |
| S-071 | Which networks send the most traffic? | Requests, blocked requests, bans and the organisation name by ASN | asn-requests, asn-blocked, asn-bans, asn-org | table | asn-table | Many columns per network with sorting and actions: the DataTable is the text-first form (B11.8). |
| S-071 | Can I trust the location data? | GeoIP database build date and age | geo-db-age | stat card | stat-card | One current value with a warning threshold at 60 days: StatCard (B11.8; T-0443 A4). |
| S-072 | Who is attacking? | Requests per source address with ban state | top-ips | table | top-ips | Address rows carry ban state, TTL, ASN and per-row actions, so a table is the honest form (B11.8). |
| S-072 | What are they hitting? | Requests by path template, ranked | top-paths | ranked horizontal bar | top-paths | A top-N ranking over long path labels: ranked horizontal bar (B11.10 rule 1). |
| S-072 | Which rules stop them? | Blocked requests by rule, ranked | top-rules | ranked horizontal bar | top-rules | A top-N ranking of rule names: ranked horizontal bar (B11.10 rule 1). |
| S-072 | How did the attack evolve by category? | Blocked requests by category over time | blocked-by-category | stacked bar | category-timeline | Composition of categories over time: stacked bar (B11.10 rule 1). T-0444 says "stacked area"; see the specification gap below. |
| S-072 | Are these addresses one campaign? | Events grouped by campaign similarity | campaign-groups | table | campaign-table | Campaign membership, first and last seen and counts: the DataTable (B11.8); the label says grouped by similarity, not attribution (T-0444). |
| S-100 | Is the platform healthy? | Service state, queue depth, added latency and config revision | admin-service-state, queue-depth, added-latency-p99, config-revision | table | admin-health | Many services with a state and a last-heartbeat column: the DataTable (B11.8); one chart per service would multiply widgets. |
| S-100 | How large is the attack right now? | Blocked requests by category and ASN in the last hour | admin-attack-summary | ranked horizontal bar | admin-attack-summary | A top-N ranking of two dimensions; the bar answers "which is biggest" (B11.10 rule 1). |
| S-100 | What needs attention on the platform? | Certificates expiring, ban set size, signups, abuse queue, pending upgrades, data store state | cert-expiring, ban-set-size, signups-24h, abuse-queue, pending-upgrades, data-store-up | stat card | stat-card | Six current values, each with its own provenance and Unknown state: StatCard (B11.8). |
| S-127 | What state is the shield in? | Shield state 0 normal to 3 saturated | shield-state | stat card | stat-card | One current state with a text label: StatCard (B11.8). |
| S-127 | How close are the signals to their thresholds? | Normalised signal values against the 50, 80 and 90 percent thresholds | shield-signals | table | shield-signals | Six signals with four numeric columns each; the table is the primary representation (T-0437 step 2; DataTable B11.8). |
| S-127 | What capacity do we actually have? | Lab-proven, provider-advertised and verified-live capacity | capacity-lab, capacity-provider, capacity-live | stat card | stat-card | Three numbers with their provenance labels; a chart would imply a precision the sources do not have, so StatCard (B11.8). |
| S-127 | What did the shield do? | State transitions, actions and their results | shield-incidents, shield-actions | table | shield-incidents | A chronological list with a result per action: the DataTable (B11.8); the state machine diagram above it is text plus shape. |

## Chart alternatives

Every chart form above has a text summary written from its data and a "View as table" toggle (B11.10 rule 5; A2).
The summary is generated server-side with the chart and carries the unit; the toggle renders the same series and the
same units as a table. The table view of any chart is `Bucket` followed by one column per series, sorted by bucket
ascending, in the compact density, with the chart's range and filters; percentage and byte columns are formatted as
B11.9 item 6 requires (locale formatting, exact numbers in tables, units in the header). CSV export downloads exactly
the displayed series. Stat cards and tables need no toggle: their label, value, unit and delta are already text
(B11.8 StatCard and DataTable).

| Widget | Text summary | View as table | CSV export |
| --- | --- | --- | --- |
| traffic-24h | Requests peaked at {peak_time} with {peak_value}; {blocked} were blocked and the busiest hour was {hour}. | View as table | CSV export of the displayed series |
| top-categories | The largest category was {category} with {blocked} blocked requests, {share} of the total. | View as table | CSV export of the displayed series |
| attack-timeline | Blocked requests peaked at {peak_time} with {blocked}; {would_block} would have been blocked and {allowed} were allowed as suspicious. | View as table | CSV export of the displayed series |
| attack-heatmap | The busiest cell was {weekday} at {hour} with {blocked} blocked requests; {empty_cells} cells had no data. | View as table | CSV export of the displayed series |
| live-category | The leading category is {category} with {events} events in the last five minutes. | View as table | CSV export of the displayed series |
| requests-blocked | Requests peaked at {peak_time} with {requests}; {blocked} were blocked, {block_rate} of the range. | View as table | CSV export of the displayed series |
| status-stacked | The largest status class was {class} with {share} of the requests in the range. | View as table | CSV export of the displayed series |
| bandwidth | Bandwidth peaked at {peak_time} with {bytes}; the range served {total_bytes}. | View as table | CSV export of the displayed series |
| latency | p95 latency peaked at {peak_time} with {p95}; the range median of p50 was {p50}. Percentiles are approximate. | View as table | CSV export of the displayed series |
| geo-choropleth | The highest country was {country} with {requests} requests; the ranked table below names every country. | View as table | CSV export of the displayed series |
| top-paths | The most attacked path was {path} with {blocked} blocked requests. | View as table | CSV export of the displayed series |
| top-rules | The rule with the most blocks was {rule} with {blocked} blocked requests. | View as table | CSV export of the displayed series |
| category-timeline | Blocked requests peaked at {peak_time} with {blocked}, led by {category}; {other} fell into Other. | View as table | CSV export of the displayed series |
| admin-attack-summary | The top category was {category} with {blocked} blocked requests, mostly from {asn}. | View as table | CSV export of the displayed series |

## Chart rules

These rules apply to every chart on every screen; each is the B11.10 rule with the implementation note that makes it
checkable.

1. The form follows the question: line for time series, bar for category comparison, stacked bar for composition over
   time, ranked horizontal bar for top-N, heatmap for hour-by-day, choropleth only with a ranked table alongside
   (B11.10 rule 1; ChartKit and WorldMap in B11.8).
2. Axes are labeled with units; bars start at a zero baseline; the time axis is in the user's time zone (B11.10 rule 2;
   B11.9 item 5). A non-zero baseline is never used for a bar, because it exaggerates a ratio.
3. A gap is drawn as a gap and is never interpolated as a zero (B11.10 rules 2 and 8). A range that overlaps a
   collector gap shows a hatched "No data" band, and the table view says "No data" in the bucket (T-0442 A2).
4. Direct labels are preferred over legends; the legend order matches the visual order; a chart carries at most 8 series and the ninth key becomes "Other" (B11.10 rule 3; the cardinality cap of T-0441 step 5).
5. Series use the colour-blind-safe palette of B11.2 and every fill also carries a pattern or dash, so a series never
   relies on colour alone (B11.10 rule 4). Severity always has an icon and a label.
6. Every chart has a text summary and a "View as table" toggle, both generated from the same series (B11.10 rule 5;
   A2).
7. Interaction is progressive: a tooltip and crosshair enhance the chart, while all information is available without
   them and from the keyboard, with an arrow-key readout in a polite live region (B11.10 rule 6; T-0442 step 6).
8. Charts are server-rendered SVG: they render without JavaScript, print cleanly in greyscale, and have no animation by default (B11.10 rule 7). A theme change re-renders on the server; reduced motion changes nothing because there is no motion.
9. Never chart fabricated or interpolated data; a sparse range shows the sparse state, and an unknown value shows
   "Unknown" with its reason (B11.10 rule 8; R-16).
10. Percentile charts are labeled approximate with the bound in the footnote, because percentiles are merged from fixed
    histograms and never averaged (T-0441 step 6 and A4, relative error at most 2 percent).
11. Forced-colors mode uses the system colours CanvasText, Canvas, LinkText and Highlight, icons use currentColor, and
    the focus ring uses Highlight (B11.2; B11.11). No encoding is colour alone.
12. Numbers follow B11.9 item 6: locale formatting, abbreviated large numbers only in cards, exact numbers in tables,
    and explicit units (requests, req/s, bytes, ms).

## Tables

A table is a DataTable (B11.8): semantic `table`, sortable headers as buttons with `aria-sort`, a column visibility
menu, a density toggle, row selection with `aria-checked`, a sticky header, an empty state, filter chips from the URL
and CSV export. Virtualisation is used only above 500 rows and keeps `aria-rowcount` and `aria-rowindex`. The default
sort is applied on first load and is visible in the header; every sort has a stable tie-break on the time column and
then the row identifier, so a re-render never reshuffles equal values. Filters live in the URL, so a filtered view can
be shared, and "Clear all" restores the default.

| Screen | Table | Columns | Default sort | Filters | Density |
| --- | --- | --- | --- | --- | --- |
| S-040 | attention-list | Item, Kind, Severity, Since, Action | Severity descending, then Since ascending | Item kind, Severity | comfortable |
| S-043 | recent-events | Time, Category, Subtype, Path template, Verdict, Ray ID | Time descending | Category, Verdict | comfortable |
| S-065 | live-table | Time, Ray ID, IP key, Country, ASN, Domain, Category and subtype, Action, Rule, Vector and field, Payload excerpt, Status | Time descending | Category, Action, Severity, IP, Rule, Vector, Country | compact |
| S-071 | asn-table | ASN, Organisation, Category, Requests, Blocked, Block rate, Bans, Actions | Requests descending | Category, Block rate, Bans | comfortable |
| S-072 | top-ips | IP key, Country, ASN, Requests, Blocked, Ban state, TTL remaining, First seen, Last seen, Categories, Actions | Blocked descending, then Requests descending | Ban state, Country, ASN, Category | compact |
| S-072 | campaign-table | Campaign, First seen, Last seen, Distinct IPs, Distinct ASNs, Categories, Status | Distinct IPs descending | Status, Category | comfortable |
| S-100 | admin-health | Service, Surface, State, p99 added latency, Last heartbeat, Config revision | State descending, then Service ascending | Surface, State | comfortable |
| S-127 | shield-signals | Signal, Current value, Elevated 50 percent, Attack 80 percent, Saturated 90 percent, Trend | Signal ascending | Signal | compact |
| S-127 | shield-incidents | Time, Event, State from, State to, Actor, Result | Time descending | Event kind, State | compact |

The live table follows the LiveFeed contract: a pause control, a "N new events" counter, no auto-scroll while focus is
inside the table, and announcements at most every 10 seconds (B11.8; T-0446 step 4). The S-065 columns are the B12.2
S-065 list; the payload column shows the redacted evidence excerpt only, escaped and capped (B12.2).

## Time range

The range picker offers exactly the six presets of T-0027 step 5, in this order. A custom range is validated before it
is applied: the end must be after the start and the span must respect the granularity guards of T-0442 step 2 (minute
at most 48 hours, hour at most 31 days, day at most 400 days). Buckets are aligned to the user's time zone; DST days
have 23 or 25 hourly buckets and leap days are handled by the date arithmetic (T-0442 A4).

| Preset | Range | Granularity | Notes |
| --- | --- | --- | --- |
| Last 15 minutes | The 15 minutes before now | minute | The smallest preset; no sub-minute bucket is ever shown. |
| Last 1 hour | The 60 minutes before now | minute | One bucket per minute. |
| Last 24 hours | The 24 hours before now | minute | The default of the overview screens. |
| Last 7 days | The 7 days before now | hour | One bucket per hour. |
| Last 30 days | The 30 days before now | hour | The largest preset; bounded by the plan retention below. |
| Custom | From and to, at most 400 days apart | auto | Minute up to 48 hours, hour up to 31 days, day up to 400 days. |

Plan limits: the only plan value that bounds an analytics range is `plans.limits.events_retention_days` (B5.2; the default is 30 days in B6). Q-008 is OPEN, and the specification states no per-plan analytics time-range limit, so this document invents none; a range that reaches beyond the organisation's retention returns `Unknown (outside plan retention)` for the missing buckets instead of zero, and the page shows the retention in the range menu. The plan's `events_retention_days` value, not the preset, decides how much history exists. Where the specification does not set a limit, the value stays "not specified".

## Comparisons

The previous period is the window of the same length immediately before the current one, compared bucket by bucket at the same granularity and in the same time zone (`compare=previous_period`, T-0442 step 1). The comparison toggle sits
next to the range picker and its state is in the URL, so a shared link compares the same windows. A KPI card shows the
current value, the previous value and the difference; a chart draws the previous period as a dashed series in the same
pattern family, never as a second axis.

When the previous window contains a gap, the comparison is `Unknown ({reason})` instead of a number: a delta is never
computed across missing buckets, and a percentage change is not shown when the previous value is zero (it would be a
division by zero dressed as infinity). Comparing across a mode change is allowed but the mode-change annotation stays
visible, so a jump caused by the mode is not read as a change in attack volume. Annotation markers are data, not
decoration: they come from the tables listed in the next section and never from a hard-coded date.

## Annotations

Annotation markers are vertical lines, dots or shaded bands on the time axis, each with a text alternative, and each is
built from a stored event rather than a guess. The annotation list required by A3 is complete: mode changes, rule
changes, bans and deployments, plus the two the screens also need.

| Annotation | Source | Marker | Text alternative |
| --- | --- | --- | --- |
| Mode change | `config_revisions` (B5.6) and `AUD-waf.mode_changed` (B8) | Solid vertical line | Mode changed to {mode} at {time} |
| Rule change | `config_revisions` (B5.6) and `AUD-waf.rule_created` or `AUD-waf.rule_updated` (B8) | Dashed vertical line | Rule {rule} created or updated at {time} |
| Rule pack change | `audit_log` rows `AUD-platform.rule_pack_published` and `AUD-platform.rule_pack_rolled_back` (B8) | Dotted vertical line | Rule pack {pack} {stage} at {time} |
| Ban | `ip_bans` (B5.7) and `AUD-ban.created` (B8) | Dot on the blocked series | Ban created at {time} |
| Deployment | `audit_log` rows `AUD-platform.release_upgraded` and `AUD-runtime.profile_started` (B8) | Shaded band | Release {version} started at {time} |
| Shield transition | `shield_events` (B5.11) plus `AUD-shield.transition` (B8) | Vertical line with a shield icon and text | Shield moved from {from} to {to} at {time} |

A bulk ban produces one marker per event within the visible range, and when more than 50 markers fall in a range they
collapse into a band labelled "{count} bans"; the table view lists every one. A marker's text alternative is part of
the chart's accessible description, so it is available without hovering (B11.10 rule 6). Markers are never fabricated:
a range with no stored change has no marker, and the annotation toggle says so.

## Colour and accessibility

The eight chart series use the colour-blind-safe palette of B11.2 (the Okabe-Ito set), dark and light, and every
series also has a pattern or dash so that hue is never the only carrier (B11.10 rule 4). The palette table below names
the B11.2 hex values; a series keeps its pattern when the theme changes, and the legend order is the visual order.

| Series | Dark | Light | Pattern |
| --- | --- | --- | --- |
| 1 | #E69F00 | #9A6200 | solid |
| 2 | #56B4E9 | #0B6FA8 | dashes 6 3 |
| 3 | #2DD4A8 | #0B7A5E | dots |
| 4 | #F0E442 | #7A6A00 | dash-dot |
| 5 | #7AA7FF | #2F55C8 | wide dashes |
| 6 | #F07B3A | #B64A00 | cross-hatch |
| 7 | #D68AB8 | #9A3E78 | diagonal hatch |
| 8 | #B4BFD6 | #4B5873 | vertical lines |

Every chart has a text summary and a "View as table" toggle, so the numbers are available as text (A2). Direct labels
are preferred over legends, and a label is never truncated without its full value in the table and the tooltip
(B11.10 rule 3). No encoding is colour alone: severity has an icon and a label, a series has a pattern, a delta has a
sign and an arrow, and the map's intensity bins have patterns as well as hues (T-0443 step 2). Forced-colors mode uses the system colours CanvasText, Canvas, LinkText and Highlight, and the focus ring uses Highlight (B11.2). Contrast is
at least 3:1 against the surface for every series (B11.2), and the `xtask contrast-check` gate covers the tokens.

Stat cards and tables are text-first: label, value, unit and delta are read directly, so they need no separate table
toggle (B11.8 StatCard and DataTable). Every widget has the four states of B11.9 item 4 (default, loading, empty,
error), plus the offline banner; a skeleton appears only after 300 ms (B11.8). The table view of a chart is reachable
from the keyboard, and the chart's accessible description is the text summary plus the annotations.

## Performance and print

The limits below are design constraints for the T-0088 renderer and the T-0442 query layer; each is a number a test can
assert, not a measured result. The renderer is deterministic: the same input yields byte-identical SVG (T-0088 A1).

| Constraint | Value | Rule |
| --- | --- | --- |
| Line points per chart | 16,000 points | At most 8 line series times 2,000 points; a denser chart is not rendered and the table view is offered (T-0088 step 6). |
| Line points per series | 2,000 points | LTTB reduces a longer line series to this count (T-0088 step 6). |
| Line downsampling threshold | 2,000 points per series | Above this count LTTB is applied to that line series; below it every point is drawn, so a short range is never smoothed. |
| Line LTTB parameters | 3-point window, gap-aware segments | Each gap-free line segment is downsampled on its own, so the algorithm never bridges a gap (T-0088 step 6). |
| Render budget | 5 ms p95 for 2,000 points | Criterion benchmark on the builder (T-0088 A5). |
| API budget | 150 ms p95 with 100M rollup rows | T-0442 A5; a query times out at 2 s with `ERR-ANALYTICS-002` (T-0442 step 3). |
| Table view rows | 10,000 rows | Above this the table view paginates and CSV export is offered in chunks. |
| Print | A4 portrait, ISO 216, page margins in [RESPONSIVE.md](RESPONSIVE.md) | One chart per page when the chart is taller than 90 mm; the header repeats the range, the time zone and the data-complete time; patterns keep the series readable in greyscale. |

Downsampling never changes a total: an LTTB point is drawn, not summed, so the axis label and the text summary report
the exact total from the rollup rows (T-0442 A1). LTTB is the line method only; every other form of the `Screen
questions` table aggregates whole rows, and the next section gives one rule per form. The print layout hides the range
picker and the toggle, prints the text summary and the annotations, and never prints a tooltip. Charts are
server-rendered SVG, so a printed page needs no script (B11.10 rule 7).

## Downsampling

LTTB is a line-series algorithm: it selects points that keep the shape of a series, so it says nothing about a bar, a
cell or a row. Every other form of `Screen questions` is reduced by aggregating whole rows instead, and the table below
gives one numeric rule per form: the maximum count, the method and whether the total stays exact. Like the performance
table, these are design constraints for T-0088 and T-0442: numbers a test can assert, not measured results. A form that
appears in `Screen questions` without a row here is a check failure, so a new chart form cannot ship without a rule
(T-0027 step 8 and A4; F-27).

| Chart form | Maximum count | Method | Totals exact |
| --- | --- | --- | --- |
| line | 2,000 points per series | LTTB with a three-point window, split at every gap; a drawn point is a selected real point, never an average (T-0088 step 6). | Yes: the peak, trough and total in the summary come from the rollup rows, not from the drawn points (T-0442 A1). |
| stacked bar | 400 buckets per chart | Re-bucket by summing adjacent rollup buckets down to 400, the bucket count of the longest day-granularity range (T-0442 step 2); no bucket is sampled or dropped. | Yes: each bar is a sum of buckets, so every series total and the stacked sum are the values the rollups hold (T-0441 A3). |
| ranked horizontal bar | 10 ranked keys plus Other (11 bars) | Top-N plus Other: the ten largest keys by the ranked value, and Other is the exact sum of the remaining keys and of the per-bucket `other` rows (T-0441 step 5 caps a dimension at 200 keys plus other). | Yes: Other closes the ranking, so the bars add up to the window total (T-0443 A1, T-0444 A1). |
| heatmap | 168 cells | Sum every hourly bucket into its local weekday and hour of a fixed 7 x 24 grid; the grid does not grow with the range, and a cell with no bucket says "No data" (T-0442 A2). | Yes: the 168 cells partition the window's blocked requests, so their sum is the exact total. |
| choropleth | 200 ranked countries plus Other and `Unknown` (202 fills) | One fill per country key, from the top 200 keys plus Other; the ranked table below the map lists the same keys and is the primary representation, so the map carries no number alone (T-0443 step 2). | Yes: every fill is a sum over whole rows, and countries plus `Unknown` equal the overall total exactly (T-0443 A1). |
| stat card | 1 value per card, at most 6 values in a screen row | Whole rows: the card shows the aggregate of its whole window or the current state, with no sampling (the largest card row, S-100, carries six values). | Yes: the value is the aggregate of every row in the window, never an estimate from a sample. |
| table | 10,000 rows per table view | Whole rows: server-side pagination reaches every row of the window (virtualisation above 500 rows keeps `aria-rowcount`), and above 10,000 rows the view paginates and CSV export is offered in chunks (T-0027 step 4). | Yes: row counts and totals come from the same query over whole rows, and the CSV export of the table holds the displayed rows. |

The table is the whole downsampling surface of the nine screens. The check reads the `Chart form` column of `Screen
questions` and reports a form that has no row here, so a new form arrives with its rule in the same change. The chart
rules of B11.10 still govern the drawn chart: a re-bucketed bar keeps a zero baseline, and a heatmap cell with no data
is a dataless cell, never an interpolated point (B11.10 rules 2 and 8).

## Unknown data

Every widget defines what it shows when its source is unavailable. The display is `Unknown ({reason})` with the reason
in plain words, never zero, and never a fabricated gap: a missing bucket is a gap (hatched "No data"), while a failed
source is Unknown with its reason (B11.9 item 12; R-16; A5). "No traffic yet" is a known empty state, not Unknown, and
it links to the verification checklist (T-0139 A1).

| Widget | When it is unknown | Display | Never |
| --- | --- | --- | --- |
| traffic-24h | The rollup has no row for the window or the collector gap covers it | Unknown ({reason}) with a hatched "No data" band | zero |
| attention-list | A source query failed, so one rule cannot be evaluated | Unknown ({reason}) on that item; the other items still render | zero |
| stat-card | The metric's source has no sample or is unreachable | Unknown ({reason}) in place of the value | zero |
| top-categories | The category dimension has no row for the bucket | Unknown ({reason}) | zero |
| recent-events | The event store read failed | Unknown ({reason}) | zero |
| attack-timeline | One of the three series has no source in the range | Unknown ({reason}) in the legend for that series; the others draw | zero |
| attack-heatmap | The hourly buckets or the time zone conversion are unavailable | Unknown ({reason}); empty cells are "No data" | zero |
| top-paths | The path group dimension has no row | Unknown ({reason}) | zero |
| live-category | Too few events in the last five minutes to rank | Unknown ({reason}) | zero |
| live-table | The stream is disconnected and the polling fallback failed | Unknown ({reason}) with the stale banner | zero |
| requests-blocked | The rollup has no row for the bucket | Unknown ({reason}) with a hatched "No data" band | zero |
| status-stacked | The status class dimension has no row | Unknown ({reason}) | zero |
| bandwidth | The rollup has no byte column row for the bucket | Unknown ({reason}) with a hatched "No data" band | zero |
| latency | The window has no histogram buckets | Unknown ({reason}); the line shows a gap | zero |
| geo-choropleth | No GeoIP database is loaded | Unknown ({reason}) with the setup instructions (T-0443 A3) | zero |
| asn-table | No ASN database is loaded | Unknown ({reason}) in the organisation and category columns | zero |
| top-ips | The range reaches beyond event retention | Unknown ({reason}) for the missing range | zero |
| top-rules | The rule dimension has no row | Unknown ({reason}) | zero |
| category-timeline | The category dimension has no row for a bucket | Unknown ({reason}) with a hatched "No data" band | zero |
| campaign-table | The campaign detection job has not run for the range | Unknown ({reason}) | zero |
| admin-health | The health probe has not run, or a service is not deployed | Unknown ({reason}); not deployed is shown as "Not deployed" (T-0437 A5) | zero |
| admin-attack-summary | No platform traffic was recorded in the last hour | Unknown ({reason}) | zero |
| shield-signals | A signal collector failed (T-0437 A3) | Unknown ({reason}) for that signal; the others render | zero |
| shield-incidents | The API is unreachable and the local queue holds the events | Unknown ({reason}) with the queued count | zero |

A gap in the data is a gap: it is never filled with an estimate or a fabricated value, and no chart draws a line
through it (R-16; B11.10 rule 8). The page header always shows the "data complete up to" time from the API response
(`data_complete_until`, T-0442 step 1), so a reader can tell a gap from an empty range.

## Spec gaps and limits

The specification does not decide everything this task needs. These are the gaps found while writing the document, the
effect on the screens, and what this document does instead. None of them is silently patched with a made-up value.

| Gap | Effect | Handling |
| --- | --- | --- |
| B5.8 has no `would_block` column and no `bans` column | The S-054 timeline and the S-071 ASN table need both, but they cannot be read from the rollups | Would-block counts come from `waf_events` where the action is would_block; ban counts come from `ip_bans`, within event retention, and the dictionary marks both as event-sourced |
| B9 has no byte counter | Bandwidth cannot come from a Prometheus metric | `bytes-out` is sourced from the rollup `bytes_out` column only, and the dictionary says so |
| T-0442 step 1 names `overview`, `status` and `bandwidth` while B6.3 names `summary`, `status-codes` and has no bandwidth route | The endpoint name is ambiguous | The dictionary cites the B6.3 route names and the screens consume `GET D/analytics/summary`, `status-codes` and `latency`; the discrepancy is recorded here for the Lead to reconcile |
| T-0444 step 4 says "stacked area" while B11.10 rule 1 selects the stacked bar | A chart form cannot be both | The screen uses the stacked bar, because B11.10 governs chart selection; the difference is recorded here rather than hidden |
| Q-008 is OPEN | No per-plan time-range limit is specified | The six presets are the same for every plan; `events_retention_days` bounds the data and the missing range is Unknown |
| The three capacity numbers have no B9 metric | S-127 cannot show them as gauges | They are labelled lab-proven, provider-advertised and verified-live, with "verified-live: not measured" until an acceptance run, and the dictionary records that there is no metric id |
| B9 has one row for two data stores (`MET-hdd_redis_up / postgres_up`) | A single citation covers both | The dictionary cites the row once and says the row names Postgres too |
| B5 has no `shield_incidents` table although T-0474 names one | The S-127 incident timeline has no model row for its own table | The timeline reads `shield_events` (B5.11) and the dictionary cites T-0474 for `shield_incidents` instead of pretending it is modelled |
| S-127's state machine is not one of the B11.10 forms | It is a diagram, not a chart | The diagram uses text plus shape and is accompanied by the signal and incident tables, so no information depends on the drawing |
